package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
)

// svcData is what the cabinet and the payment pages show about the service: balance, bonuses, Telegram.
type svcData struct {
	Balance    string
	BalanceRaw int64
	Cur        string
	CanTopup   bool
	Ops        []opItem
	RefLink    string
	RefInvited int
	RefPaid    int
	RefRule    string
	RefEarned  string
	Ref        string // the code of the link the person came by (registration)
	TgBot      string
	TgLinked   bool
	TgCode     string
	HasBalance bool
	Promo      string
}

type opItem struct{ Date, Text, Amount, Class string }

// fmtBalance writes an amount in cents; unlike fmtMoney it also writes a zero.
func fmtBalance(cents int64, cur string) string {
	neg := ""
	if cents < 0 {
		neg, cents = "-", -cents
	}
	if cents == 0 {
		return "0 " + curSymbol(cur)
	}
	return neg + fmtMoney(int(cents), cur)
}

func curSymbol(cur string) string {
	if s := map[string]string{"RUB": "₽", "USD": "$", "EUR": "€", "UAH": "₴", "KZT": "₸"}[cur]; s != "" {
		return s
	}
	return cur
}

// siteCurrency is the currency of the balance: that of the first plan (RUB while there are no plans).
func (s *Site) siteCurrency(ctx context.Context) string {
	if ps, err := s.st.ListPlans(ctx, false); err == nil && len(ps) > 0 && ps[0].Currency != "" {
		return ps[0].Currency
	}
	return "RUB"
}

func refRuleText(rw RefReward) string {
	var parts []string
	if rw.Days > 0 {
		parts = append(parts, fmt.Sprintf("%d %s доступа", rw.Days, daysWord(rw.Days)))
	}
	if rw.Percent > 0 {
		parts = append(parts, fmt.Sprintf("%d%% от оплаты на баланс", rw.Percent))
	}
	if len(parts) == 0 {
		return ""
	}
	t := "За каждого друга, который оплатит подписку, вы получите " + strings.Join(parts, " и ") + "."
	if rw.InviteeDays > 0 {
		t += fmt.Sprintf(" Друг получит в подарок %d %s.", rw.InviteeDays, daysWord(rw.InviteeDays))
	}
	return t
}

var opNames = map[string]string{"topup": "пополнение", "purchase": "оплата тарифа", "referral": "бонус за друга", "referral_days": "бонус за друга",
	"promo": "промокод", "admin": "корректировка", "refund": "возврат"}

// serviceData fills the cabinet with the balance, the referral link and the Telegram link.
func (s *Site) serviceData(r *http.Request, acc *Account) svcData {
	ctx := r.Context()
	d := svcData{Cur: s.siteCurrency(ctx), BalanceRaw: acc.Balance, CanTopup: s.cfg.getSite().Payment != "off"}
	d.Balance, d.HasBalance = fmtBalance(acc.Balance, d.Cur), acc.Balance > 0
	if ops, err := s.st.BalanceOps(ctx, acc.ID, 8); err == nil {
		for _, o := range ops {
			it := opItem{Date: o.Created.UTC().Format("02.01.2006"), Text: opNames[o.Kind]}
			if o.Note != "" {
				it.Text += ": " + o.Note
			}
			switch {
			case o.Delta > 0:
				it.Amount, it.Class = "+"+fmtBalance(o.Delta, d.Cur), "ok"
			case o.Delta < 0:
				it.Amount = fmtBalance(o.Delta, d.Cur)
			}
			d.Ops = append(d.Ops, it)
		}
	}
	if code, err := s.st.EnsureRefCode(ctx, acc.ID); err == nil {
		d.RefLink = s.linkBase(r) + "/r/" + code
	}
	if st, err := s.st.RefStatsOf(ctx, acc.ID); err == nil {
		d.RefInvited, d.RefPaid = st.Invited, st.Paid
		var e []string
		if st.BonusDays > 0 {
			e = append(e, fmt.Sprintf("%d %s", st.BonusDays, daysWord(st.BonusDays)))
		}
		if st.BonusCents > 0 {
			e = append(e, fmtBalance(st.BonusCents, d.Cur))
		}
		d.RefEarned = strings.Join(e, " и ")
	}
	d.RefRule = refRuleText(s.cfg.refReward())
	d.TgLinked = acc.TgChat != nil
	if s.cfg.botToken() != "" {
		d.TgBot = botUsername(s.cfg)
	}
	return d
}

// registerRef: /r/CODE leads to the registration with the code of the one who invited.
func (s *Site) refRedirect(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	if !reRefCode.MatchString(code) {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/register?ref="+code, http.StatusSeeOther)
}

func (s *Site) renderCabinet(w http.ResponseWriter, r *http.Request, acc *Account, h string, code int, flash, errMsg string, mod func(*pageData)) {
	if fresh, err := s.st.AccountByID(r.Context(), acc.ID); err == nil {
		acc = fresh
	}
	d := s.cabinetData(r, acc, h)
	d.Flash, d.Error = flash, errMsg
	if mod != nil {
		mod(&d)
	}
	s.render(w, code, "cabinet", d)
}

func (s *Site) redeemPromo(w http.ResponseWriter, r *http.Request) {
	acc, h := s.authedPost(w, r)
	if acc == nil {
		return
	}
	if s.payAcc.blocked("promo:" + acc.Email) {
		s.renderCabinet(w, r, acc, h, 429, "", "Слишком много попыток. Попробуйте позже", nil)
		return
	}
	msg, err := s.st.RedeemPromo(r.Context(), acc.ID, r.PostForm.Get("promo"))
	if err != nil {
		if errors.Is(err, ErrNoPromo) {
			s.payAcc.hit("promo:" + acc.Email) // guessing codes is limited
		}
		code := 400
		if !errors.Is(err, ErrNoPromo) && !errors.Is(err, ErrPromoUsed) && !errors.Is(err, ErrPromoKind) {
			log.Printf("site: promo: %v", err)
			code, err = 500, errors.New("Временная ошибка, попробуйте ещё раз")
		}
		s.renderCabinet(w, r, acc, h, code, "", err.Error(), nil)
		return
	}
	s.renderCabinet(w, r, acc, h, 200, msg, "", nil)
}

// parseMoney reads "150", "150.5" or "150,50" into cents.
func parseMoney(v string) (int, bool) {
	v = strings.ReplaceAll(strings.TrimSpace(v), ",", ".")
	if v == "" || len(v) > 12 {
		return 0, false
	}
	whole, frac, _ := strings.Cut(v, ".")
	w, err := strconv.Atoi(whole)
	if err != nil || w < 0 {
		return 0, false
	}
	f := 0
	if frac != "" {
		if len(frac) > 2 {
			return 0, false
		}
		if f, err = strconv.Atoi((frac + "0")[:2]); err != nil || f < 0 {
			return 0, false
		}
	}
	return w*100 + f, true
}

func (s *Site) topupPost(w http.ResponseWriter, r *http.Request) {
	acc, h := s.authedPost(w, r)
	if acc == nil {
		return
	}
	prov := s.provider()
	if prov == nil {
		s.renderCabinet(w, r, acc, h, 403, "", "Онлайн-оплата сейчас выключена", nil)
		return
	}
	if s.payAcc.blocked(acc.Email) {
		s.renderCabinet(w, r, acc, h, 429, "", "Слишком много заявок. Попробуйте позже", nil)
		return
	}
	cents, ok := parseMoney(r.PostForm.Get("amount"))
	if !ok || cents < 100 || cents > maxTopupCents {
		s.renderCabinet(w, r, acc, h, 400, "", "Введите сумму пополнения: от 1 до 1 000 000", nil)
		return
	}
	if pend, _ := s.st.ListPayments(r.Context(), "pending", acc.ID, 10); len(pend) >= 3 {
		s.renderCabinet(w, r, acc, h, 409, "", "У вас уже есть неподтверждённые заявки. Дождитесь подтверждения", nil)
		return
	}
	s.payAcc.hit(acc.Email)
	pay, err := s.st.CreateTopup(r.Context(), acc.ID, cents, s.siteCurrency(r.Context()), prov.Name())
	if err != nil {
		log.Printf("site: topup: %v", err)
		s.renderCabinet(w, r, acc, h, 500, "", "Временная ошибка, попробуйте ещё раз", nil)
		return
	}
	res, err := prov.Start(r.Context(), s.st, pay)
	if err != nil {
		log.Printf("site: topup %d: %v", pay.ID, err)
		s.renderCabinet(w, r, acc, h, 500, "", "Не удалось провести оплату, попробуйте ещё раз", nil)
		return
	}
	if res.RedirectURL != "" {
		http.Redirect(w, r, res.RedirectURL, http.StatusSeeOther)
		return
	}
	d := s.base(r, acc, h, "Пополнение")
	d.Heading = "Заявка принята"
	if res.Paid {
		d.Heading = "Баланс пополнен"
	}
	d.Message, d.PayID, d.PayPlan, d.PayAmount = res.Message, strconv.FormatInt(pay.ID, 10), pay.PlanName, fmtMoney(pay.AmountCents, pay.Currency)
	s.render(w, 200, "paid", d)
}

func (s *Site) tgLinkPost(w http.ResponseWriter, r *http.Request) {
	acc, h := s.authedPost(w, r)
	if acc == nil {
		return
	}
	if s.cfg.botToken() == "" {
		s.renderCabinet(w, r, acc, h, 404, "", "Бот не подключён", nil)
		return
	}
	if r.PostForm.Get("op") == "unlink" {
		_ = s.st.UnlinkTelegram(r.Context(), acc.ID)
		s.renderCabinet(w, r, acc, h, 200, "Telegram отвязан", "", nil)
		return
	}
	code, err := s.st.NewTgLinkCode(r.Context(), acc.ID)
	if err != nil {
		s.renderCabinet(w, r, acc, h, 500, "", "Временная ошибка, попробуйте ещё раз", nil)
		return
	}
	s.renderCabinet(w, r, acc, h, 200, "", "", func(d *pageData) { d.Svc.TgCode = code })
}

// payWebhook is the place where a real payment system tells that a payment was made. It is a stub that already does
// the work: the body is {"payment_id":N,"status":"paid|canceled","amount_cents":N,"ext_id":"..."} and the header
// X-Signature carries the hex HMAC-SHA256 of the body with the key pay_webhook_secret. Without the secret the address does not exist.
func (s *Site) payWebhook(w http.ResponseWriter, r *http.Request) {
	secret := s.cfg.payWebhookSecret()
	if secret == "" {
		http.NotFound(w, r)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<10))
	if err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	sig, _ := hex.DecodeString(strings.TrimSpace(r.Header.Get("X-Signature")))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return
	}
	var in struct {
		PaymentID   int64  `json:"payment_id"`
		Status      string `json:"status"`
		AmountCents int    `json:"amount_cents"`
		ExtID       string `json:"ext_id"`
	}
	if json.Unmarshal(body, &in) != nil || in.PaymentID <= 0 {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	p, err := s.st.PaymentByID(r.Context(), in.PaymentID)
	if err != nil {
		http.Error(w, "unknown payment", http.StatusNotFound)
		return
	}
	if prov := r.PathValue("provider"); prov != p.Provider {
		http.Error(w, "wrong provider", http.StatusConflict)
		return
	}
	if in.AmountCents != 0 && in.AmountCents != p.AmountCents {
		http.Error(w, "amount differs", http.StatusConflict)
		return
	}
	if in.ExtID != "" {
		s.st.SetPaymentExt(r.Context(), p.ID, in.ExtID)
	}
	changed := false
	switch in.Status {
	case "paid":
		changed, err = s.st.MarkPaid(r.Context(), p.ID)
	case "canceled":
		changed, err = s.st.CancelPayment(r.Context(), p.ID)
	default:
		http.Error(w, "status: paid or canceled", http.StatusBadRequest)
		return
	}
	if err != nil {
		log.Printf("site: webhook payment %d: %v", p.ID, err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "changed": changed})
}
