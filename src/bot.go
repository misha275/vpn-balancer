package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Telegram bot of the service. It uses the Bot API over long polling (no public address and no certificate needed), so it
// works wherever the controller can reach api.telegram.org (bot_api_url points to a proxy when it cannot).
// The bot is for the people of the service: they link their account with a code from the cabinet (/start CODE) and then
// see their term, traffic and subscription, redeem promo codes and pay for plans, all with the same functions as the site.

var (
	botNameMu sync.RWMutex
	botName   string
)

// botUsername is the name of the bot (known after the first successful getMe).
func botUsername(cfg *Config) string {
	botNameMu.RLock()
	defer botNameMu.RUnlock()
	return botName
}

type Bot struct {
	cfg    *Config
	st     *Store
	client *http.Client
	lim    *limiter
	pmu    sync.Mutex
	pend   map[int64]botPend // what the next text message of a chat means (promo code, promo code for a plan)
}

func NewBot(cfg *Config, st *Store) *Bot {
	return &Bot{cfg: cfg, st: st, client: &http.Client{Timeout: 40 * time.Second}, lim: newLimiter(40, time.Minute)}
}

type tgUpdate struct {
	ID      int64 `json:"update_id"`
	Message *struct {
		Text string `json:"text"`
		Chat struct {
			ID   int64  `json:"id"`
			Type string `json:"type"`
		} `json:"chat"`
	} `json:"message"`
	Callback *struct {
		ID      string `json:"id"`
		Data    string `json:"data"`
		Message *struct {
			ID   int64 `json:"message_id"`
			Chat struct {
				ID   int64  `json:"id"`
				Type string `json:"type"`
			} `json:"chat"`
		} `json:"message"`
	} `json:"callback_query"`
}

func (b *Bot) call(ctx context.Context, method string, in, out any) error {
	body, _ := json.Marshal(in)
	req, err := http.NewRequestWithContext(ctx, "POST", b.cfg.botAPI()+"/bot"+b.cfg.botToken()+"/"+method, bytes.NewReader(body))
	if err != nil {
		return scrubErr(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.client.Do(req)
	if err != nil {
		return scrubErr(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	var env struct {
		OK          bool            `json:"ok"`
		Result      json.RawMessage `json:"result"`
		Description string          `json:"description"`
	}
	if err := json.Unmarshal(raw, &env); err != nil || !env.OK {
		if env.Description == "" {
			env.Description = resp.Status
		}
		return fmt.Errorf("telegram %s: %s", method, env.Description)
	}
	if out != nil {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

// Btn is a button under a message: callback data, a link, or a page that opens inside Telegram (web_app).
type Btn struct {
	Text string
	Data string
	URL  string
	Web  string
}

func (x Btn) json() map[string]any {
	m := map[string]any{"text": x.Text}
	switch {
	case x.Web != "":
		m["web_app"] = map[string]string{"url": x.Web}
	case x.URL != "":
		m["url"] = x.URL
	default:
		m["callback_data"] = x.Data
	}
	return m
}

// Reply is an answer of the bot: text and rows of buttons.
type Reply struct {
	Text string
	Kb   [][]Btn
}

func (r Reply) markup() map[string]any {
	rows := [][]map[string]any{}
	for _, row := range r.Kb {
		var out []map[string]any
		for _, x := range row {
			out = append(out, x.json())
		}
		if len(out) > 0 {
			rows = append(rows, out)
		}
	}
	return map[string]any{"inline_keyboard": rows}
}

func clipText(text string) string {
	if len([]rune(text)) > 3800 {
		return string([]rune(text)[:3800]) + "…"
	}
	return text
}

func (b *Bot) send(ctx context.Context, chat int64, r Reply) {
	msg := map[string]any{"chat_id": chat, "text": clipText(r.Text), "disable_web_page_preview": true}
	if len(r.Kb) > 0 {
		msg["reply_markup"] = r.markup()
	}
	if err := b.call(ctx, "sendMessage", msg, nil); err != nil {
		log.Printf("bot: %v", err)
	}
}

// edit replaces the message under which a button was pressed (the chat stays tidy); a new message when that is impossible.
func (b *Bot) edit(ctx context.Context, chat, msgID int64, r Reply) {
	msg := map[string]any{"chat_id": chat, "message_id": msgID, "text": clipText(r.Text), "disable_web_page_preview": true, "reply_markup": r.markup()}
	if err := b.call(ctx, "editMessageText", msg, nil); err != nil {
		if strings.Contains(err.Error(), "not modified") {
			return
		}
		b.send(ctx, chat, r)
	}
}

// Run polls for messages until ctx ends. It follows the settings: a token set later starts the bot, removed stops it.
func (b *Bot) Run(ctx context.Context) {
	var offset int64
	for ctx.Err() == nil {
		if b.cfg.botToken() == "" {
			botNameMu.Lock()
			botName = ""
			botNameMu.Unlock()
			if !sleepCtx(ctx, 15*time.Second) {
				return
			}
			continue
		}
		if botUsername(b.cfg) == "" {
			var me struct {
				Username string `json:"username"`
			}
			c, cancel := context.WithTimeout(ctx, 20*time.Second)
			err := b.call(c, "getMe", map[string]any{}, &me)
			cancel()
			if err != nil {
				log.Printf("bot: %v", err)
				if !sleepCtx(ctx, 30*time.Second) {
					return
				}
				continue
			}
			botNameMu.Lock()
			botName = me.Username
			botNameMu.Unlock()
			log.Printf("bot: @%s is running", me.Username)
			b.setMenuButton(ctx)
		}
		var ups []tgUpdate
		c, cancel := context.WithTimeout(ctx, 35*time.Second)
		err := b.call(c, "getUpdates", map[string]any{"offset": offset, "timeout": botPoll, "allowed_updates": []string{"message", "callback_query"}}, &ups)
		cancel()
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("bot: %v", err)
				sleepCtx(ctx, 10*time.Second)
			}
			continue
		}
		for _, u := range ups {
			offset = u.ID + 1
			switch {
			case u.Callback != nil && u.Callback.Message != nil && u.Callback.Message.Chat.Type == "private":
				chat := u.Callback.Message.Chat.ID
				key := strconv.FormatInt(chat, 10)
				hc, hcancel := context.WithTimeout(ctx, 20*time.Second)
				_ = b.call(hc, "answerCallbackQuery", map[string]any{"callback_query_id": u.Callback.ID}, nil)
				if !b.lim.blocked(key) {
					b.lim.hit(key)
					b.edit(hc, chat, u.Callback.Message.ID, b.Callback(hc, chat, u.Callback.Data))
				}
				hcancel()
			case u.Message != nil && u.Message.Chat.Type == "private" && u.Message.Text != "":
				chat := u.Message.Chat.ID
				key := strconv.FormatInt(chat, 10)
				if b.lim.blocked(key) {
					continue
				}
				b.lim.hit(key)
				hc, hcancel := context.WithTimeout(ctx, 20*time.Second)
				reply := b.Respond(hc, chat, u.Message.Text)
				hcancel()
				if reply.Text != "" {
					b.send(ctx, chat, reply)
				}
			}
		}
	}
}

// botPoll is the long-poll time in seconds (a variable for tests).
var botPoll = 25

func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

const botHelp = `Команды:
/status — срок подписки, трафик, баланс
/sub — ссылка подписки для приложения
/plans — тарифы
/buy НОМЕР [ПРОМОКОД] — купить тариф (с баланса, если хватает)
/balance — баланс
/promo КОД — применить промокод
/ref — ссылка для приглашения друзей
/unlink — отвязать Telegram`

// Handle answers one message of a chat with text only (the commands; Respond adds the buttons).
func (b *Bot) Handle(ctx context.Context, chat int64, text string) string {
	text = strings.TrimSpace(text)
	if !strings.HasPrefix(text, "/") {
		return "Не понял. " + "Команды: /help"
	}
	f := strings.Fields(text)
	cmd := strings.ToLower(f[0])
	if i := strings.Index(cmd, "@"); i > 0 { // /status@MyBot
		cmd = cmd[:i]
	}
	args := f[1:]
	acc, err := b.st.AccountByTgChat(ctx, chat)
	if err != nil && !errors.Is(err, ErrNotFound) {
		log.Printf("bot: %v", err)
		return "Временная ошибка, попробуйте позже."
	}
	if acc == nil {
		switch cmd {
		case "/start":
			if len(args) == 0 {
				return "Это бот сервиса. Чтобы привязать аккаунт, откройте кабинет на сайте, нажмите «Получить код привязки» и отправьте мне: /start КОД"
			}
			a, err := b.st.LinkTelegram(ctx, args[0], chat)
			if err != nil {
				return "Код не подошёл или устарел (он действует 15 минут). Получите новый в кабинете на сайте."
			}
			return "Готово, аккаунт " + a.Email + " привязан.\n\n" + botHelp
		case "/help":
			return "Это бот сервиса. Привяжите аккаунт: получите код в кабинете на сайте и отправьте /start КОД"
		}
		return "Сначала привяжите аккаунт: получите код в кабинете на сайте и отправьте /start КОД"
	}
	if acc.Blocked {
		return "Аккаунт заблокирован. Напишите в поддержку."
	}
	switch cmd {
	case "/start", "/help":
		return botHelp
	case "/status", "/me":
		return b.status(ctx, acc)
	case "/balance":
		return "На балансе: " + fmtBalance(acc.Balance, b.currency(ctx))
	case "/sub":
		base := b.cfg.subBase()
		if base == "" {
			return "Адрес подписки пока не настроен, напишите в поддержку."
		}
		return "Ваша подписка (добавьте в приложение и обновите):\n" + base + "/sub/" + acc.SubToken
	case "/plans":
		return b.plans(ctx)
	case "/buy":
		return b.buy(ctx, acc, args)
	case "/promo":
		if len(args) != 1 {
			return "Использование: /promo КОД"
		}
		msg, err := b.st.RedeemPromo(ctx, acc.ID, args[0])
		if err != nil {
			if errors.Is(err, ErrNoPromo) || errors.Is(err, ErrPromoUsed) || errors.Is(err, ErrPromoKind) {
				return err.Error()
			}
			log.Printf("bot: promo: %v", err)
			return "Временная ошибка, попробуйте позже."
		}
		return msg
	case "/ref":
		code, err := b.st.EnsureRefCode(ctx, acc.ID)
		if err != nil {
			return "Временная ошибка, попробуйте позже."
		}
		base := b.cfg.siteBaseURL()
		if base == "" {
			return "Сайт пока не настроен."
		}
		out := "Ваша ссылка для друзей:\n" + base + "/r/" + code
		if rule := refRuleText(b.cfg.refReward()); rule != "" {
			out += "\n\n" + rule
		}
		return out
	case "/unlink":
		_ = b.st.UnlinkTelegram(ctx, acc.ID)
		return "Telegram отвязан от аккаунта."
	}
	return "Не знаю такой команды. " + "Команды: /help"
}

func (b *Bot) currency(ctx context.Context) string {
	if ps, err := b.st.ListPlans(ctx, false); err == nil && len(ps) > 0 && ps[0].Currency != "" {
		return ps[0].Currency
	}
	return "RUB"
}

func (b *Bot) status(ctx context.Context, acc *Account) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Аккаунт № %d, %s\n", acc.UserID, acc.User().DisplayNick())
	state, days := periodState(acc.Expires, time.Now())
	switch state {
	case "active":
		fmt.Fprintf(&sb, "Подписка до %s (осталось %d %s)\n", fmtDateRu(*acc.Expires), days, daysWord(days))
	case "unlimited":
		sb.WriteString("Подписка без срока\n")
	default:
		sb.WriteString("Подписка закончилась")
		if acc.Expires != nil {
			sb.WriteString(" " + fmtDateRu(*acc.Expires))
		}
		sb.WriteString(". Продлить: /plans\n")
	}
	if acc.BlockKind != "" {
		sb.WriteString("Доступ приостановлен")
		if acc.BlockReason != "" {
			sb.WriteString(": " + acc.BlockReason)
		}
		sb.WriteString("\n")
	}
	if t, err := b.st.UserTrafficOf(ctx, acc.UserName); err == nil {
		fmt.Fprintf(&sb, "Трафик: %s (за 30 дней %s)\n", fmtBytesRu(t.AllUp+t.AllDown), fmtBytesRu(t.D30Up+t.D30Down))
	}
	sb.WriteString("Баланс: " + fmtBalance(acc.Balance, b.currency(ctx)))
	return sb.String()
}

func (b *Bot) plans(ctx context.Context) string {
	ps, err := b.st.ListPlans(ctx, true)
	if err != nil || len(ps) == 0 {
		return "Тарифы ещё не настроены."
	}
	var sb strings.Builder
	sb.WriteString("Тарифы:\n")
	for i, p := range ps {
		fmt.Fprintf(&sb, "%d. %s — %s, %d %s\n", i+1, p.Name, fmtMoney(p.PriceCents, p.Currency), p.Days, daysWord(p.Days))
	}
	sb.WriteString("\nКупить: /buy НОМЕР [ПРОМОКОД]")
	return sb.String()
}

func (b *Bot) buy(ctx context.Context, acc *Account, args []string) string {
	ps, _ := b.st.ListPlans(ctx, true)
	if len(args) == 0 {
		return b.plans(ctx)
	}
	n, err := strconv.Atoi(args[0])
	if err != nil || n < 1 || n > len(ps) {
		return "Такого тарифа нет. Список: /plans"
	}
	plan := ps[n-1]
	promo := ""
	if len(args) > 1 {
		promo = args[1]
	}
	explain := func(err error) string {
		switch {
		case errors.Is(err, ErrNoMoney), errors.Is(err, ErrNoPromo), errors.Is(err, ErrPromoUsed), errors.Is(err, ErrPromoKind), errors.Is(err, ErrNotDiscount):
			return err.Error()
		}
		log.Printf("bot: buy: %v", err)
		return "Временная ошибка, попробуйте позже."
	}
	// with enough money on the balance the plan is paid from it, otherwise a payment of the site is started
	price := plan.PriceCents
	if promo != "" { // the discount is known only to the store; try the balance first, it checks the code too
		if pay, err := b.st.PayFromBalance(ctx, acc.ID, plan, promo); err == nil {
			return fmt.Sprintf("Оплачено с баланса: %s, %s. Подписка продлена.", pay.PlanName, fmtMoney(pay.AmountCents, pay.Currency))
		} else if !errors.Is(err, ErrNoMoney) {
			return explain(err)
		}
		price = -1
	} else if acc.Balance >= int64(price) {
		pay, err := b.st.PayFromBalance(ctx, acc.ID, plan, "")
		if err != nil {
			return explain(err)
		}
		return fmt.Sprintf("Оплачено с баланса: %s, %s. Подписка продлена.", pay.PlanName, fmtMoney(pay.AmountCents, pay.Currency))
	}
	_ = price
	var prov PaymentProvider
	switch b.cfg.getSite().Payment {
	case "stub_auto":
		prov = stubProvider{auto: true}
	case "manual":
		prov = stubProvider{}
	}
	if prov == nil {
		return "Оплата сейчас недоступна, а денег на балансе не хватает. Баланс: " + fmtBalance(acc.Balance, b.currency(ctx))
	}
	if pend, _ := b.st.ListPayments(ctx, "pending", acc.ID, 10); len(pend) >= 3 {
		return "У вас уже есть неподтверждённые заявки. Дождитесь подтверждения."
	}
	pay, err := b.st.CreatePaymentPromo(ctx, acc.ID, plan, prov.Name(), promo)
	if err != nil {
		return explain(err)
	}
	res, err := prov.Start(ctx, b.st, pay)
	if err != nil {
		return explain(err)
	}
	if res.RedirectURL != "" {
		return "Оплатите по ссылке: " + res.RedirectURL
	}
	return fmt.Sprintf("%s\nПлатёж № %d: %s, %s.", res.Message, pay.ID, pay.PlanName, fmtMoney(pay.AmountCents, pay.Currency))
}
