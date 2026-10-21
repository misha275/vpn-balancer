package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"
)

// The buttons of the bot. Everything the commands do is reachable by buttons under the messages: the main menu, plans with
// their own buttons, payment, promo code, referral link, unlinking. The only thing that needs typing is a code (a promo
// code, or the code that links the account), and the bot asks for it explicitly. The button «Открыть страницу» opens the
// main page of the site inside Telegram (a web app).

type botPend struct {
	kind string // "promo": the next text is a promo code; "buy": a promo code for the plan n
	n    int
	at   time.Time
}

func (b *Bot) setPend(chat int64, p botPend) {
	b.pmu.Lock()
	defer b.pmu.Unlock()
	if b.pend == nil {
		b.pend = map[int64]botPend{}
	}
	if p.kind == "" {
		delete(b.pend, chat)
		return
	}
	p.at = time.Now()
	b.pend[chat] = p
}

func (b *Bot) takePend(chat int64) (botPend, bool) {
	b.pmu.Lock()
	defer b.pmu.Unlock()
	p, ok := b.pend[chat]
	delete(b.pend, chat)
	return p, ok && time.Since(p.at) < 10*time.Minute
}

// pageBtn is the button that opens the main page of the site: inside Telegram when the address is https, a plain link otherwise.
func (b *Bot) pageBtn() *Btn {
	base := b.cfg.siteBaseURL()
	switch {
	case strings.HasPrefix(base, "https://"):
		return &Btn{Text: "🌐 Открыть страницу", Web: base}
	case base != "":
		return &Btn{Text: "🌐 Открыть страницу", URL: base}
	}
	return nil
}

func (b *Bot) setMenuButton(ctx context.Context) {
	base := b.cfg.siteBaseURL()
	if !strings.HasPrefix(base, "https://") {
		return
	}
	c, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	_ = b.call(c, "setChatMenuButton", map[string]any{"menu_button": map[string]any{"type": "web_app", "text": "Сайт", "web_app": map[string]string{"url": base}}}, nil)
}

var menuBtn = Btn{Text: "🏠 Меню", Data: "m"}

func (b *Bot) mainKb() [][]Btn {
	kb := [][]Btn{
		{{Text: "📊 Статус", Data: "st"}, {Text: "🔗 Подписка", Data: "sub"}},
		{{Text: "💳 Тарифы", Data: "pl"}, {Text: "💰 Баланс", Data: "bal"}},
		{{Text: "🎁 Промокод", Data: "promo"}, {Text: "👥 Пригласить друзей", Data: "ref"}},
	}
	if p := b.pageBtn(); p != nil {
		kb = append(kb, []Btn{*p})
	}
	return append(kb, []Btn{{Text: "⚙️ Отвязать Telegram", Data: "ul"}})
}

func (b *Bot) backKb(extra ...Btn) [][]Btn {
	row := append([]Btn{}, extra...)
	return [][]Btn{append(row, menuBtn)}
}

func (b *Bot) unlinkedReply(text string) Reply {
	kb := [][]Btn{}
	if p := b.pageBtn(); p != nil {
		kb = append(kb, []Btn{*p})
	}
	return Reply{Text: text, Kb: kb}
}

const botNeedLink = "Это бот сервиса. Чтобы привязать аккаунт: откройте кабинет на сайте (кнопка ниже), нажмите «Получить код привязки» и отправьте код сюда сообщением."

// Respond answers a text message of a chat with the buttons.
func (b *Bot) Respond(ctx context.Context, chat int64, text string) Reply {
	text = strings.TrimSpace(text)
	if f := strings.Fields(text); len(f) == 2 && strings.EqualFold(strings.SplitN(f[0], "@", 2)[0], "/start") && strings.HasPrefix(f[1], "lg_") {
		return b.loginPrompt(ctx, strings.TrimPrefix(f[1], "lg_"))
	}
	acc, err := b.st.AccountByTgChat(ctx, chat)
	if err != nil && !errors.Is(err, ErrNotFound) {
		log.Printf("bot: %v", err)
		return Reply{Text: "Временная ошибка, попробуйте позже."}
	}
	if acc == nil {
		out := b.Handle(ctx, chat, text)
		if !strings.HasPrefix(text, "/") { // a bare code that links the account
			if a, err := b.st.LinkTelegram(ctx, text, chat); err == nil {
				return Reply{Text: "Готово, аккаунт " + a.Username + " привязан. Выберите действие:", Kb: b.mainKb()}
			}
			return b.unlinkedReply(botNeedLink)
		}
		if strings.HasPrefix(out, "Готово, аккаунт") { // /start CODE
			return Reply{Text: out[:strings.Index(out, "\n")] + " Выберите действие:", Kb: b.mainKb()}
		}
		return b.unlinkedReply(out)
	}
	if acc.Blocked {
		return Reply{Text: "Аккаунт заблокирован. Напишите в поддержку."}
	}
	if !strings.HasPrefix(text, "/") {
		if p, ok := b.takePend(chat); ok {
			switch p.kind {
			case "promo":
				return Reply{Text: b.Handle(ctx, chat, "/promo "+firstWord(text)), Kb: b.backKb()}
			case "buy":
				return Reply{Text: b.Handle(ctx, chat, fmt.Sprintf("/buy %d %s", p.n, firstWord(text))), Kb: b.backKb()}
			}
		}
		return Reply{Text: "Выберите действие кнопкой:", Kb: b.mainKb()}
	}
	cmd := strings.ToLower(strings.Fields(text)[0])
	if i := strings.Index(cmd, "@"); i > 0 {
		cmd = cmd[:i]
	}
	if cmd == "/start" || cmd == "/help" || cmd == "/menu" {
		return Reply{Text: "Главное меню. Всё делается кнопками.", Kb: b.mainKb()}
	}
	return Reply{Text: b.Handle(ctx, chat, text), Kb: b.backKb()}
}

func firstWord(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return ""
}

// Callback answers a button press.
func (b *Bot) Callback(ctx context.Context, chat int64, data string) Reply {
	return b.CallbackAs(ctx, chat, data, "")
}

// CallbackAs is Callback that also knows the Telegram name of the sender (it names a new account made by «sign in through Telegram»).
func (b *Bot) CallbackAs(ctx context.Context, chat int64, data, name string) Reply {
	if strings.HasPrefix(data, "lgok:") || strings.HasPrefix(data, "lgno:") {
		return b.loginAnswer(ctx, chat, strings.TrimPrefix(data[4:], ":"), data[:4] == "lgok", name)
	}
	acc, err := b.st.AccountByTgChat(ctx, chat)
	if err != nil && !errors.Is(err, ErrNotFound) {
		log.Printf("bot: %v", err)
		return Reply{Text: "Временная ошибка, попробуйте позже."}
	}
	if acc == nil {
		return b.unlinkedReply(botNeedLink)
	}
	if acc.Blocked {
		return Reply{Text: "Аккаунт заблокирован. Напишите в поддержку."}
	}
	b.setPend(chat, botPend{}) // any button cancels what was being asked
	arg := ""
	if i := strings.Index(data, ":"); i > 0 {
		data, arg = data[:i], data[i+1:]
	}
	switch data {
	case "st":
		return Reply{Text: b.status(ctx, acc), Kb: [][]Btn{{{Text: "💳 Продлить", Data: "pl"}}, {menuBtn}}}
	case "bal":
		kb := [][]Btn{}
		if p := b.pageBtn(); p != nil {
			kb = append(kb, []Btn{*p})
		}
		return Reply{Text: "На балансе: " + fmtBalance(acc.Balance, b.currency(ctx)) + "\nПополнить баланс можно на сайте в кабинете.", Kb: append(kb, []Btn{menuBtn})}
	case "sub":
		return Reply{Text: b.Handle(ctx, chat, "/sub"), Kb: b.backKb()}
	case "ref":
		return Reply{Text: b.Handle(ctx, chat, "/ref"), Kb: b.backKb()}
	case "promo":
		b.setPend(chat, botPend{kind: "promo"})
		return Reply{Text: "Отправьте промокод сообщением.", Kb: [][]Btn{{{Text: "✖ Отмена", Data: "m"}}}}
	case "pl":
		ps, err := b.st.ListPlans(ctx, true)
		if err != nil || len(ps) == 0 {
			return Reply{Text: "Тарифы ещё не настроены.", Kb: b.backKb()}
		}
		kb := [][]Btn{}
		for i, p := range ps {
			kb = append(kb, []Btn{{Text: fmt.Sprintf("%s — %s, %d %s", p.Name, fmtMoney(p.PriceCents, p.Currency), p.Days, daysWord(p.Days)), Data: "p:" + strconv.Itoa(i+1)}})
		}
		return Reply{Text: "Выберите тариф:", Kb: append(kb, []Btn{menuBtn})}
	case "p", "pay", "pc":
		n, _ := strconv.Atoi(arg)
		ps, _ := b.st.ListPlans(ctx, true)
		if n < 1 || n > len(ps) {
			return Reply{Text: "Такого тарифа нет.", Kb: b.backKb(Btn{Text: "💳 Тарифы", Data: "pl"})}
		}
		p := ps[n-1]
		switch data {
		case "pay":
			return Reply{Text: b.buy(ctx, acc, []string{arg}), Kb: b.backKb()}
		case "pc":
			b.setPend(chat, botPend{kind: "buy", n: n})
			return Reply{Text: "Отправьте промокод сообщением, и я оплачу тариф «" + p.Name + "» с ним.", Kb: [][]Btn{{{Text: "✖ Отмена", Data: "pl"}}}}
		}
		txt := fmt.Sprintf("Тариф «%s»\nЦена: %s\nСрок: %d %s\nНа балансе: %s", p.Name, fmtMoney(p.PriceCents, p.Currency), p.Days, daysWord(p.Days), fmtBalance(acc.Balance, b.currency(ctx)))
		return Reply{Text: txt, Kb: [][]Btn{{{Text: "💳 Оплатить", Data: "pay:" + arg}}, {{Text: "🎁 С промокодом", Data: "pc:" + arg}}, {{Text: "← Тарифы", Data: "pl"}, menuBtn}}}
	case "ul":
		return Reply{Text: "Отвязать Telegram от аккаунта? Бот перестанет вам отвечать, пока вы не привяжете его снова кодом из кабинета.", Kb: [][]Btn{{{Text: "Да, отвязать", Data: "ul!"}, {Text: "Отмена", Data: "m"}}}}
	case "ul!":
		_ = b.st.UnlinkTelegram(ctx, acc.ID)
		return b.unlinkedReply("Telegram отвязан от аккаунта.")
	}
	return Reply{Text: "Главное меню. Всё делается кнопками.", Kb: b.mainKb()}
}

// loginPrompt answers the link «sign in through Telegram» opened from the site: it shows where the request came from.
func (b *Bot) loginPrompt(ctx context.Context, token string) Reply {
	ip, agent, err := b.st.TgLoginInfo(ctx, token)
	if err != nil {
		return Reply{Text: "Запрос входа не найден или устарел (он действует 10 минут). Нажмите «Войти через Telegram» на сайте ещё раз."}
	}
	text := "Вход на сайт\nАдрес: " + ip
	if agent != "" {
		text += "\nБраузер: " + agent
	}
	text += "\n\nЭто вы? Если вы ничего не открывали, нажмите «Нет»."
	return Reply{Text: text, Kb: [][]Btn{{{Text: "✅ Да, это я", Data: "lgok:" + token}, {Text: "❌ Нет", Data: "lgno:" + token}}}}
}

func (b *Bot) loginAnswer(ctx context.Context, chat int64, token string, ok bool, name string) Reply {
	if err := b.st.TgLoginAnswer(ctx, token, ok, chat, name); err != nil {
		return Reply{Text: "Запрос входа не найден или устарел. Нажмите «Войти через Telegram» на сайте ещё раз."}
	}
	if !ok {
		return Reply{Text: "Вход отклонён."}
	}
	return Reply{Text: "Подтверждено. Вернитесь на сайт: страница обновится сама."}
}
