package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

func svcPlan(t *testing.T, st *Store, name string, price int) Plan {
	t.Helper()
	ctx := context.Background()
	st.pool.Exec(ctx, "DELETE FROM plans")
	id, err := st.SavePlan(ctx, Plan{Name: name, Days: 30, PriceCents: price, Currency: "RUB", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	p, err := st.PlanByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return *p
}

func accountByEmail(t *testing.T, st *Store, email string) *Account {
	t.Helper()
	a, err := st.AccountByEmail(context.Background(), email)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestReferralRewardsAndBalance(t *testing.T) {
	cfg := siteTestCfg()
	cfg.SitePayment = "stub_auto"
	_, st, srv := startSite(t, cfg)
	ctx := context.Background()
	plan := svcPlan(t, st, "Месяц", 30000)
	days, pct, inv := 10, 20, 5
	cfg.RefBonusDays, cfg.RefBonusPercent, cfg.RefInviteeDays = &days, pct, inv

	a := newSiteClient(t, srv)
	a.register("inviter@example.com", "password1")
	acc := accountByEmail(t, st, "inviter@example.com")
	_, body, _ := a.get("/cabinet")
	code, _ := st.EnsureRefCode(ctx, acc.ID)
	if !strings.Contains(body, "/r/"+code) || !strings.Contains(body, "10 дней") || !strings.Contains(body, "20%") {
		t.Fatalf("the cabinet shows the link and the rules (%s)", code)
	}

	// the friend comes by the link
	b := newSiteClient(t, srv)
	if c, _, h := b.get("/r/" + code); c != 303 || h.Get("Location") != "/register?ref="+code {
		t.Fatalf("link: %d %s", c, h.Get("Location"))
	}
	_, reg, _ := b.get("/register?ref=" + code)
	if !strings.Contains(reg, `name="ref" value="`+code+`"`) {
		t.Fatal("the registration form carries the code")
	}
	b.post("/register", url.Values{"email": {"friend@example.com"}, "password": {"password1"}, "password2": {"password1"}, "ref": {code}}, true)
	friend := accountByEmail(t, st, "friend@example.com")
	if friend.ReferredBy == nil || *friend.ReferredBy != acc.ID {
		t.Fatalf("referrer: %v", friend.ReferredBy)
	}
	// nobody can invite himself, an unknown code is ignored
	if st.AttachReferral(ctx, acc.ID, code) {
		t.Error("self-invite")
	}
	if st.AttachReferral(ctx, friend.ID, "zzzzzzzz") {
		t.Error("unknown code")
	}

	before := accountByEmail(t, st, "inviter@example.com")
	fBefore := friend
	code2, body2, _ := b.post("/pay", url.Values{"plan": {fmt.Sprint(plan.ID)}, "csrf": {b.csrf()}}, true)
	if code2 != 200 || !strings.Contains(body2, "Оплачено") {
		t.Fatalf("test payment: %d", code2)
	}
	after := accountByEmail(t, st, "inviter@example.com")
	if d := after.Expires.Sub(*before.Expires); d < 9*24*time.Hour+23*time.Hour || d > 10*24*time.Hour+time.Hour {
		t.Errorf("the inviter gets 10 days: %v", d)
	}
	if after.Balance != 6000 {
		t.Errorf("20%% of 300 on the balance: %d", after.Balance)
	}
	fAfter := accountByEmail(t, st, "friend@example.com")
	// 3 trial days + 30 paid + 5 gift
	if d := fAfter.Expires.Sub(*fBefore.Expires); d < 34*24*time.Hour || d > 36*24*time.Hour {
		t.Errorf("the friend: 30 paid + 5 gift days: %v", d)
	}
	// the second payment of the friend rewards nobody
	b.post("/pay", url.Values{"plan": {fmt.Sprint(plan.ID)}, "csrf": {b.csrf()}}, true)
	if again := accountByEmail(t, st, "inviter@example.com"); again.Balance != 6000 || !again.Expires.Equal(*after.Expires) {
		t.Errorf("the reward is paid once: %d %v", again.Balance, again.Expires)
	}
	rs, _ := st.RefStatsOf(ctx, acc.ID)
	if rs.Invited != 1 || rs.Paid != 1 || rs.BonusDays != 10 || rs.BonusCents != 6000 {
		t.Errorf("stats: %+v", rs)
	}

	// the inviter pays for a plan from the balance (60 of 300 is not enough), then tops up and pays
	code3, body3, _ := a.post("/pay", url.Values{"plan": {fmt.Sprint(plan.ID)}, "use_balance": {"1"}, "csrf": {a.csrf()}}, true)
	if code3 != 402 || !strings.Contains(body3, "не хватает") {
		t.Errorf("not enough money: %d", code3)
	}
	if c, _, _ := a.post("/pay/topup", url.Values{"amount": {"250,50"}, "csrf": {a.csrf()}}, true); c != 200 {
		t.Fatalf("topup: %d", c)
	}
	if bal := accountByEmail(t, st, "inviter@example.com").Balance; bal != 6000+25050 {
		t.Errorf("balance after the top-up: %d", bal)
	}
	exp := accountByEmail(t, st, "inviter@example.com").Expires
	code3, body3, _ = a.post("/pay", url.Values{"plan": {fmt.Sprint(plan.ID)}, "use_balance": {"1"}, "csrf": {a.csrf()}}, true)
	if code3 != 200 || !strings.Contains(body3, "Оплачено с баланса") {
		t.Fatalf("pay from balance: %d %.200s", code3, body3)
	}
	end := accountByEmail(t, st, "inviter@example.com")
	if end.Balance != 1050 || end.Expires.Sub(*exp) < 29*24*time.Hour {
		t.Errorf("after: %d %v", end.Balance, end.Expires)
	}
	ops, _ := st.BalanceOps(ctx, acc.ID, 20)
	if len(ops) != 4 { // referral_days, referral, topup, purchase
		t.Errorf("history: %+v", ops)
	}
	// the balance never goes negative
	if err := st.AdjustBalance(ctx, acc.ID, -999999, "admin", "x"); err == nil {
		t.Error("a negative balance must be refused")
	}
	if err := st.AdjustBalance(ctx, acc.ID, 500, "admin", "подарок"); err != nil {
		t.Error(err)
	}
	if c, body, _ := a.get("/cabinet"); c != 200 || !strings.Contains(body, "15.50") {
		t.Errorf("cabinet shows the balance: %d", c)
	}
}

func TestPromoCodes(t *testing.T) {
	cfg := siteTestCfg()
	cfg.SitePayment = "stub_auto"
	_, st, srv := startSite(t, cfg)
	ctx := context.Background()
	plan := svcPlan(t, st, "Месяц", 10000)
	st.pool.Exec(ctx, "DELETE FROM promos")
	for _, p := range []Promo{
		{Code: "half", Kind: "percent", Value: 50, Enabled: true},
		{Code: "WEEK", Kind: "days", Value: 7, Enabled: true},
		{Code: "GIFT", Kind: "balance", Value: 5000, MaxUses: 1, Enabled: true},
		{Code: "OFF", Kind: "days", Value: 1, Enabled: false},
		{Code: "OLD", Kind: "days", Value: 1, Enabled: true, Expires: ptrTime(time.Now().Add(-time.Hour))},
	} {
		if err := st.SavePromo(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	for _, bad := range []Promo{{Code: "x", Kind: "days", Value: 1}, {Code: "GOOD", Kind: "percent", Value: 101}, {Code: "GOOD", Kind: "days", Value: 0}, {Code: "GOOD", Kind: "weird", Value: 1}} {
		if st.SavePromo(ctx, bad) == nil {
			t.Errorf("must refuse %+v", bad)
		}
	}
	a := newSiteClient(t, srv)
	a.register("promo@example.com", "password1")
	acc := accountByEmail(t, st, "promo@example.com")
	cab := func(code string) (int, string) {
		c, b, _ := a.post("/account/promo", url.Values{"promo": {code}, "csrf": {a.csrf()}}, true)
		return c, b
	}
	before := acc.Expires
	if c, b := cab("week"); c != 200 || !strings.Contains(b, "Промокод применён") {
		t.Fatalf("days code: %d", c)
	}
	if got := accountByEmail(t, st, "promo@example.com").Expires; got.Sub(*before) < 6*24*time.Hour+23*time.Hour {
		t.Errorf("+7 days: %v", got.Sub(*before))
	}
	if c, b := cab("WEEK"); c != 400 || !strings.Contains(b, "уже использовали") {
		t.Errorf("one use per account: %d", c)
	}
	if c, _ := cab("GIFT"); c != 200 {
		t.Errorf("balance code: %d", c)
	}
	if got := accountByEmail(t, st, "promo@example.com").Balance; got != 5000 {
		t.Errorf("balance: %d", got)
	}
	b := newSiteClient(t, srv)
	b.register("promo2@example.com", "password1")
	if c, _, _ := b.post("/account/promo", url.Values{"promo": {"GIFT"}, "csrf": {b.csrf()}}, true); c != 400 {
		t.Errorf("the limit of uses: %d", c)
	}
	for _, code := range []string{"OFF", "OLD", "nonexistent"} {
		if c, _ := cab(code); c != 400 {
			t.Errorf("%s must not work: %d", code, c)
		}
	}
	if c, b := cab("half"); c != 400 || !strings.Contains(b, "при оплате") {
		t.Errorf("a discount code is not for the cabinet: %d", c)
	}
	// the discount at the payment
	c1, b1, _ := a.post("/pay", url.Values{"plan": {fmt.Sprint(plan.ID)}, "promo": {"half"}, "csrf": {a.csrf()}}, true)
	if c1 != 200 || !strings.Contains(b1, "50 ₽") {
		t.Fatalf("discount: %d %.300s", c1, b1)
	}
	ps, _ := st.ListPayments(ctx, "paid", acc.ID, 5)
	if len(ps) != 1 || ps[0].AmountCents != 5000 || ps[0].PromoCode != "HALF" {
		t.Errorf("payment: %+v", ps)
	}
	if c, _, _ := a.post("/pay", url.Values{"plan": {fmt.Sprint(plan.ID)}, "promo": {"half"}, "csrf": {a.csrf()}}, true); c != 400 {
		t.Errorf("a second use of the discount: %d", c)
	}
	ls, _ := st.ListPromos(ctx)
	for _, p := range ls {
		if p.Code == "HALF" && p.Used != 1 {
			t.Errorf("counter: %+v", p)
		}
	}
	if ok, _ := st.DeletePromo(ctx, "half"); !ok {
		t.Error("delete")
	}
}

func TestPaymentWebhook(t *testing.T) {
	cfg := siteTestCfg()
	cfg.SitePayment = "manual"
	_, st, srv := startSite(t, cfg)
	ctx := context.Background()
	plan := svcPlan(t, st, "Месяц", 10000)
	a := newSiteClient(t, srv)
	a.register("hook@example.com", "password1")
	acc := accountByEmail(t, st, "hook@example.com")
	pay, err := st.CreatePayment(ctx, acc.ID, plan, "stub")
	if err != nil {
		t.Fatal(err)
	}
	send := func(prov string, body any, secret string, sign bool) int {
		raw, _ := json.Marshal(body)
		req, _ := http.NewRequest("POST", srv.URL+"/pay/webhook/"+prov, strings.NewReader(string(raw)))
		if sign {
			m := hmac.New(sha256.New, []byte(secret))
			m.Write(raw)
			req.Header.Set("X-Signature", hex.EncodeToString(m.Sum(nil)))
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	body := map[string]any{"payment_id": pay.ID, "status": "paid", "amount_cents": 10000, "ext_id": "ext-1"}
	if c := send("stub", body, "k", true); c != 404 {
		t.Errorf("without a secret the callback does not exist: %d", c)
	}
	cfg.PayWebhookKey = "topsecret"
	if c := send("stub", body, "wrong", true); c != 401 {
		t.Errorf("bad signature: %d", c)
	}
	if c := send("stub", body, "topsecret", false); c != 401 {
		t.Errorf("no signature: %d", c)
	}
	if c := send("other", body, "topsecret", true); c != 409 {
		t.Errorf("wrong provider: %d", c)
	}
	if c := send("stub", map[string]any{"payment_id": pay.ID, "status": "paid", "amount_cents": 5}, "topsecret", true); c != 409 {
		t.Errorf("amount differs: %d", c)
	}
	exp := accountByEmail(t, st, "hook@example.com").Expires
	if c := send("stub", body, "topsecret", true); c != 200 {
		t.Fatalf("paid: %d", c)
	}
	if send("stub", body, "topsecret", true) != 200 {
		t.Error("repeating is harmless")
	}
	if got := accountByEmail(t, st, "hook@example.com").Expires; got.Sub(*exp) < 29*24*time.Hour || got.Sub(*exp) > 31*24*time.Hour {
		t.Errorf("extended once: %v", got.Sub(*exp))
	}
	if p, _ := st.PaymentByID(ctx, pay.ID); p.Status != "paid" {
		t.Errorf("status %s", p.Status)
	}
	p2, _ := st.CreatePayment(ctx, acc.ID, plan, "stub")
	if c := send("stub", map[string]any{"payment_id": p2.ID, "status": "canceled"}, "topsecret", true); c != 200 {
		t.Errorf("cancel: %d", c)
	}
	if p, _ := st.PaymentByID(ctx, p2.ID); p.Status != "canceled" {
		t.Errorf("status %s", p.Status)
	}
	// a top-up confirmed by the callback goes to the balance
	tp, _ := st.CreateTopup(ctx, acc.ID, 7000, "RUB", "stub")
	send("stub", map[string]any{"payment_id": tp.ID, "status": "paid"}, "topsecret", true)
	if got := accountByEmail(t, st, "hook@example.com").Balance; got != 7000 {
		t.Errorf("top-up: %d", got)
	}
}

// ---- the bot ----

type fakeTG struct {
	mu      sync.Mutex
	updates []tgUpdate
	sent    []string
	markup  string // reply_markup of the last message
	methods []string
	srv     *httptest.Server
}

func newFakeTG(t *testing.T) *fakeTG {
	f := &fakeTG{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/getMe"):
			fmt.Fprint(w, `{"ok":true,"result":{"username":"TestVpnBot"}}`)
		case strings.HasSuffix(r.URL.Path, "/getUpdates"):
			ups := f.updates
			f.updates = nil
			raw, _ := json.Marshal(ups)
			fmt.Fprintf(w, `{"ok":true,"result":%s}`, raw)
			if len(ups) == 0 {
				time.Sleep(100 * time.Millisecond)
			}
		case strings.HasSuffix(r.URL.Path, "/sendMessage"), strings.HasSuffix(r.URL.Path, "/editMessageText"):
			var in struct {
				Text   string          `json:"text"`
				Markup json.RawMessage `json:"reply_markup"`
			}
			json.Unmarshal(b, &in)
			f.sent = append(f.sent, in.Text)
			f.markup = string(in.Markup)
			f.methods = append(f.methods, r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:])
			fmt.Fprint(w, `{"ok":true,"result":{}}`)
		case strings.HasSuffix(r.URL.Path, "/answerCallbackQuery"), strings.HasSuffix(r.URL.Path, "/setChatMenuButton"):
			fmt.Fprint(w, `{"ok":true,"result":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeTG) say(chat int64, text string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := tgUpdate{ID: int64(len(f.sent)+len(f.updates)) + 100}
	u.Message = &struct {
		Text string `json:"text"`
		Chat struct {
			ID   int64  `json:"id"`
			Type string `json:"type"`
		} `json:"chat"`
	}{Text: text}
	u.Message.Chat.ID, u.Message.Chat.Type = chat, "private"
	f.updates = append(f.updates, u)
}

// press sends the press of an inline button.
func (f *fakeTG) press(chat int64, data string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := tgUpdate{ID: int64(len(f.sent)+len(f.updates)) + 100}
	u.Callback = &struct {
		ID      string `json:"id"`
		Data    string `json:"data"`
		Message *struct {
			ID   int64 `json:"message_id"`
			Chat struct {
				ID   int64  `json:"id"`
				Type string `json:"type"`
			} `json:"chat"`
		} `json:"message"`
	}{ID: "cb1", Data: data}
	u.Callback.Message = &struct {
		ID   int64 `json:"message_id"`
		Chat struct {
			ID   int64  `json:"id"`
			Type string `json:"type"`
		} `json:"chat"`
	}{ID: 5}
	u.Callback.Message.Chat.ID, u.Callback.Message.Chat.Type = chat, "private"
	f.updates = append(f.updates, u)
}

func (f *fakeTG) lastMarkup() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.markup
}

func (f *fakeTG) last(t *testing.T, wait time.Duration) string {
	t.Helper()
	end := time.Now().Add(wait)
	for time.Now().Before(end) {
		f.mu.Lock()
		if n := len(f.sent); n > 0 {
			s := f.sent[n-1]
			f.sent = nil
			f.mu.Unlock()
			return s
		}
		f.mu.Unlock()
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatal("the bot did not answer")
	return ""
}

func TestTelegramBot(t *testing.T) {
	cfg := siteTestCfg()
	cfg.SitePayment = "stub_auto"
	cfg.SubPublicURL = "https://sub.example.com"
	cfg.SiteDomain = "vpn.example.com"
	_, st, srv := startSite(t, cfg)
	ctx := context.Background()
	_ = svcPlan(t, st, "Месяц", 10000)
	st.pool.Exec(ctx, "DELETE FROM promos")
	st.SavePromo(ctx, Promo{Code: "BOTDAYS", Kind: "days", Value: 3, Enabled: true})
	fake := newFakeTG(t)
	cfg.BotToken, cfg.BotAPI = "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef", fake.srv.URL
	botPoll = 0
	defer func() { botPoll = 25 }()

	a := newSiteClient(t, srv)
	a.register("tg@example.com", "password1")
	acc := accountByEmail(t, st, "tg@example.com")
	bctx, cancel := context.WithCancel(ctx)
	defer cancel()
	bot := NewBot(cfg, st)
	go bot.Run(bctx)
	for i := 0; i < 100 && botUsername(cfg) == ""; i++ {
		time.Sleep(50 * time.Millisecond)
	}
	if botUsername(cfg) != "TestVpnBot" {
		t.Fatalf("getMe: %q", botUsername(cfg))
	}
	if _, body, _ := a.get("/cabinet"); !strings.Contains(body, "@TestVpnBot") {
		t.Error("the cabinet offers the bot")
	}

	chat := int64(777)
	fake.say(chat, "/status")
	if r := fake.last(t, 5*time.Second); !strings.Contains(r, "привяжите аккаунт") {
		t.Errorf("unlinked: %s", r)
	}
	fake.say(chat, "/start WRONG")
	if r := fake.last(t, 5*time.Second); !strings.Contains(r, "не подошёл") {
		t.Errorf("bad code: %s", r)
	}
	// the cabinet gives a code
	_, tgBody, _ := a.post("/account/telegram", url.Values{"csrf": {a.csrf()}}, true)
	m := regexpFind(`/start ([a-z0-9]{8})`, tgBody)
	if m == "" {
		t.Fatalf("no code in the cabinet: %.400s", tgBody)
	}
	fake.say(chat, "/start "+m)
	if r := fake.last(t, 5*time.Second); !strings.Contains(r, "tg@example.com") || !strings.Contains(r, "Выберите действие") {
		t.Errorf("linked: %s", r)
	}
	if acc2, err := st.AccountByTgChat(ctx, chat); err != nil || acc2.ID != acc.ID {
		t.Fatalf("link: %v", err)
	}
	if c, _ := st.LinkTelegram(ctx, m, 555); c != nil {
		t.Error("a code works once")
	}
	fake.say(chat, "/status")
	if r := fake.last(t, 5*time.Second); !strings.Contains(r, "Аккаунт № ") || !strings.Contains(r, "Подписка до") || !strings.Contains(r, "Баланс: 0") {
		t.Errorf("status: %s", r)
	}
	fake.say(chat, "/sub")
	if r := fake.last(t, 5*time.Second); !strings.Contains(r, "https://sub.example.com/sub/"+acc.SubToken) {
		t.Errorf("sub: %s", r)
	}
	fake.say(chat, "/plans")
	if r := fake.last(t, 5*time.Second); !strings.Contains(r, "1. Месяц — 100 ₽") {
		t.Errorf("plans: %s", r)
	}
	fake.say(chat, "/promo BOTDAYS")
	if r := fake.last(t, 5*time.Second); !strings.Contains(r, "+3 дня") {
		t.Errorf("promo: %s", r)
	}
	fake.say(chat, "/promo BOTDAYS")
	if r := fake.last(t, 5*time.Second); !strings.Contains(r, "уже использовали") {
		t.Errorf("promo twice: %s", r)
	}
	exp := accountByEmail(t, st, "tg@example.com").Expires
	fake.say(chat, "/buy 1")
	if r := fake.last(t, 5*time.Second); !strings.Contains(r, "Платёж №") {
		t.Errorf("buy through the provider: %s", r)
	}
	if got := accountByEmail(t, st, "tg@example.com").Expires; got.Sub(*exp) < 29*24*time.Hour {
		t.Errorf("extended: %v", got.Sub(*exp))
	}
	st.AdjustBalance(ctx, acc.ID, 10000, "admin", "тест")
	fake.say(chat, "/buy 1")
	if r := fake.last(t, 5*time.Second); !strings.Contains(r, "Оплачено с баланса") {
		t.Errorf("buy from the balance: %s", r)
	}
	fake.say(chat, "/buy 9")
	if r := fake.last(t, 5*time.Second); !strings.Contains(r, "Такого тарифа нет") {
		t.Errorf("no such plan: %s", r)
	}
	fake.say(chat, "/ref")
	if r := fake.last(t, 5*time.Second); !strings.Contains(r, "/r/") {
		t.Errorf("ref: %s", r)
	}
	fake.say(chat, "hello")
	if r := fake.last(t, 5*time.Second); !strings.Contains(r, "Выберите действие") || !strings.Contains(fake.lastMarkup(), "Статус") {
		t.Errorf("text: %s", r)
	}
	// everything by buttons: the menu has the page of the site inside Telegram (web_app)
	fake.say(chat, "/start")
	fake.last(t, 5*time.Second)
	mk := fake.lastMarkup()
	for _, want := range []string{`"callback_data":"st"`, `"callback_data":"pl"`, `"callback_data":"promo"`, `"web_app":{"url":"https://vpn.example.com`} {
		if !strings.Contains(mk, want) {
			t.Errorf("the menu lacks %s: %s", want, mk)
		}
	}
	fake.press(chat, "st")
	if r := fake.last(t, 5*time.Second); !strings.Contains(r, "Аккаунт № ") || fake.methods[len(fake.methods)-1] != "editMessageText" {
		t.Errorf("button status: %s %v", r, fake.methods)
	}
	fake.press(chat, "pl")
	if r := fake.last(t, 5*time.Second); !strings.Contains(r, "Выберите тариф") || !strings.Contains(fake.lastMarkup(), `"callback_data":"p:1"`) {
		t.Errorf("button plans: %s %s", r, fake.lastMarkup())
	}
	fake.press(chat, "p:1")
	if r := fake.last(t, 5*time.Second); !strings.Contains(r, "Тариф «Месяц»") || !strings.Contains(fake.lastMarkup(), `"callback_data":"pay:1"`) {
		t.Errorf("button plan: %s", r)
	}
	fake.press(chat, "pay:1")
	if r := fake.last(t, 5*time.Second); !strings.Contains(r, "Оплачено") && !strings.Contains(r, "оплата прошла") {
		t.Errorf("button pay: %s", r)
	}
	fake.press(chat, "promo")
	if r := fake.last(t, 5*time.Second); !strings.Contains(r, "промокод") {
		t.Errorf("button promo: %s", r)
	}
	fake.say(chat, "NOSUCH")
	if r := fake.last(t, 5*time.Second); !strings.Contains(r, "нет") && !strings.Contains(r, "не найден") && !strings.Contains(r, "Нет") {
		t.Logf("promo reply: %s", r)
	}
	fake.press(chat, "ul")
	if r := fake.last(t, 5*time.Second); !strings.Contains(r, "Отвязать") || !strings.Contains(fake.lastMarkup(), `"callback_data":"ul!"`) {
		t.Errorf("button unlink asks: %s", r)
	}
	if _, err := st.AccountByTgChat(ctx, chat); err != nil {
		t.Fatal("asking must not unlink")
	}
	fake.say(chat, "/unlink")
	if r := fake.last(t, 5*time.Second); !strings.Contains(r, "отвязан") {
		t.Errorf("unlink: %s", r)
	}
	if _, err := st.AccountByTgChat(ctx, chat); err == nil {
		t.Error("unlinked")
	}
	// a blocked account gets nothing but the notice
	st.pool.Exec(ctx, `UPDATE accounts SET tg_chat=$2, blocked=true WHERE id=$1`, acc.ID, chat)
	fake.say(chat, "/status")
	if r := fake.last(t, 5*time.Second); !strings.Contains(r, "заблокирован") {
		t.Errorf("blocked: %s", r)
	}
	// the token must be hidden in errors
	cfg.BotAPI = "http://127.0.0.1:1"
	if err := bot.call(ctx, "getMe", map[string]any{}, nil); err == nil || strings.Contains(err.Error(), cfg.BotToken) {
		t.Errorf("error leaks the token: %v", err)
	}
}

func regexpFind(pat, s string) string {
	m := regexpMust(pat).FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return m[1]
}

func regexpMust(p string) *regexp.Regexp { return regexp.MustCompile(p) }
