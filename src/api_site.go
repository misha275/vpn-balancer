package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Administration of the public site: settings, certificate, plans, accounts, payments, subscription periods.

func (a *API) registerSite(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/site", a.auth(a.siteGet))
	mux.HandleFunc("POST /api/site/cert/check", a.auth(a.siteCertCheck))
	mux.HandleFunc("GET /api/plans", a.auth(a.plansList))
	mux.HandleFunc("POST /api/plans", a.auth(a.planSave))
	mux.HandleFunc("PUT /api/plans/{id}", a.auth(a.planSave))
	mux.HandleFunc("DELETE /api/plans/{id}", a.auth(a.planDelete))
	mux.HandleFunc("POST /api/plans/bulk-subs", a.auth(a.plansBulkSubs))
	mux.HandleFunc("GET /api/accounts", a.auth(a.accountsList))
	mux.HandleFunc("POST /api/accounts", a.auth(a.accountCreate))
	mux.HandleFunc("POST /api/accounts/{id}/{op}", a.auth(a.accountOp))
	mux.HandleFunc("GET /api/promos", a.auth(a.promosList))
	mux.HandleFunc("POST /api/promos", a.auth(a.promoSave))
	mux.HandleFunc("DELETE /api/promos/{code}", a.auth(a.promoDelete))
	mux.HandleFunc("GET /api/payments", a.auth(a.paymentsList))
	mux.HandleFunc("POST /api/payments/{id}/{op}", a.auth(a.paymentOp))
	mux.HandleFunc("POST /api/users/{name}/expiry", a.auth(a.userExpiry))
}

type siteView struct {
	Settings map[string]any `json:"settings"`
	Cert     CertStatus     `json:"cert"`
	Accounts int            `json:"accounts"`
	Active   int            `json:"active"`
	Pending  int            `json:"pending_payments"`
	Public   string         `json:"public_url"`
	HTTPS    string         `json:"https_listen"`
	HTTP     string         `json:"http_listen"`
	Dest     string         `json:"dest"`
	Ready    bool           `json:"ready"`
}

func (a *API) siteGet(w http.ResponseWriter, r *http.Request) {
	eff := a.cfg.Effective()
	set := map[string]any{}
	for k, v := range eff {
		if strings.HasPrefix(k, "site_") || strings.HasPrefix(k, "forum_") {
			set[k] = v
		}
	}
	v := siteView{Settings: set, Public: a.cfg.siteBaseURL(), HTTPS: a.cfg.SiteHTTPSListen, HTTP: a.cfg.SiteHTTPListen, Dest: a.cfg.siteDest(), Ready: a.cfg.getSiteReady()}
	if a.site != nil {
		v.Cert = a.site.Status()
	}
	if accs, err := a.store.ListAccounts(r.Context()); err == nil {
		now := time.Now()
		v.Accounts = len(accs)
		for _, ac := range accs {
			if !ac.Blocked && ac.User().Active(now) {
				v.Active++
			}
		}
	}
	if ps, err := a.store.ListPayments(r.Context(), "pending", 0, 500); err == nil {
		v.Pending = len(ps)
	}
	writeJSON(w, 200, v)
}

func (a *API) siteCertCheck(w http.ResponseWriter, r *http.Request) {
	if a.site == nil {
		apiErr(w, 503, fmt.Errorf("сайт не запущен"))
		return
	}
	a.site.CheckNow()
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// ---- plans ----

func (a *API) plansList(w http.ResponseWriter, r *http.Request) {
	ps, err := a.store.ListPlans(r.Context(), false)
	if err != nil {
		apiErr(w, 500, err)
		return
	}
	writeJSON(w, 200, ps)
}

func (a *API) planSave(w http.ResponseWriter, r *http.Request) {
	var p Plan
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&p); err != nil {
		apiErr(w, 400, fmt.Errorf("ожидается JSON тарифа"))
		return
	}
	if id := r.PathValue("id"); id != "" {
		p.ID, _ = strconv.ParseInt(id, 10, 64)
		if p.ID == 0 {
			apiErr(w, 400, fmt.Errorf("неверный номер тарифа"))
			return
		}
	} else {
		p.ID = 0
	}
	if _, err := a.store.SavePlan(r.Context(), p); err != nil {
		code := 400
		if errors.Is(err, ErrNotFound) {
			code = 404
		}
		apiErr(w, code, err)
		return
	}
	a.plansList(w, r)
}

// plansBulkSubs changes the subscriptions of all plans at once: {"mode":"set|add|remove","subs":[...],"reset_users":false}.
func (a *API) plansBulkSubs(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Mode       string   `json:"mode"`
		Subs       []string `json:"subs"`
		ResetUsers bool     `json:"reset_users"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&in); err != nil {
		apiErr(w, 400, fmt.Errorf("ожидается JSON {mode, subs, reset_users}"))
		return
	}
	keys, err := cleanSubKeys(in.Subs)
	if err != nil {
		apiErr(w, 400, err)
		return
	}
	if len(keys) == 0 {
		apiErr(w, 400, fmt.Errorf("выберите хотя бы одну подписку"))
		return
	}
	np, nu, err := a.store.BulkPlanSubs(r.Context(), in.Mode, keys, a.cfg.defaultSubs(), in.ResetUsers)
	if err != nil {
		apiErr(w, 400, err)
		return
	}
	ps, _ := a.store.ListPlans(r.Context(), false)
	writeJSON(w, 200, map[string]any{"plans": ps, "changed_plans": np, "reset_users": nu})
}

func (a *API) planDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := a.store.DeletePlan(r.Context(), id); err != nil {
		apiErr(w, 404, err)
		return
	}
	a.plansList(w, r)
}

// ---- accounts ----

type accountView struct {
	ID         int64  `json:"id"`
	Email      string `json:"email"`
	User       string `json:"user"`
	Blocked    bool   `json:"blocked"`
	State      string `json:"state"`   // active | expired | unlimited | blocked
	Expires    int64  `json:"expires"` // unix seconds, 0 = no limit
	DaysLeft   int    `json:"days_left"`
	TrafficAll int64  `json:"traffic_all"`
	Traffic30  int64  `json:"traffic_30"`
	Created    int64  `json:"created"`
	LastLogin  int64  `json:"last_login"`
	Note       string `json:"note"`
	Balance    int64  `json:"balance_cents"`
	Telegram   bool   `json:"telegram"`
}

func (a *API) accountsList(w http.ResponseWriter, r *http.Request) {
	accs, err := a.store.ListAccounts(r.Context())
	if err != nil {
		apiErr(w, 500, err)
		return
	}
	sums, _ := a.store.TrafficSummary(r.Context())
	now := time.Now()
	out := make([]accountView, 0, len(accs))
	for _, ac := range accs {
		v := accountView{ID: ac.ID, Email: ac.Email, User: ac.UserName, Blocked: ac.Blocked, Created: ac.Created.Unix(), Note: ac.Note, Balance: ac.Balance, Telegram: ac.TgChat != nil}
		v.State, v.DaysLeft = periodState(ac.Expires, now)
		if ac.Blocked {
			v.State = "blocked"
		}
		if ac.Expires != nil {
			v.Expires = ac.Expires.Unix()
		}
		if ac.LastLogin != nil {
			v.LastLogin = ac.LastLogin.Unix()
		}
		if t := sums[ac.UserName]; t != nil {
			v.TrafficAll, v.Traffic30 = t.AllUp+t.AllDown, t.D30Up+t.D30Down
		}
		out = append(out, v)
	}
	writeJSON(w, 200, out)
}

func (a *API) accountCreate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Days     int    `json:"days"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&in); err != nil {
		apiErr(w, 400, fmt.Errorf("ожидается JSON {email, password, days}"))
		return
	}
	in.Email = normEmail(in.Email)
	if len(in.Email) > 120 || !reEmail.MatchString(in.Email) {
		apiErr(w, 400, fmt.Errorf("неверный адрес почты"))
		return
	}
	if in.Password == "" {
		in.Password = randomPassword()
	} else if msg := checkPassword(in.Password, in.Email); msg != "" {
		apiErr(w, 400, errors.New(msg))
		return
	}
	if in.Days < 0 || in.Days > 3660 {
		apiErr(w, 400, fmt.Errorf("дней от 0 до 3660"))
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		apiErr(w, 500, err)
		return
	}
	if _, err := a.store.CreateAccountIn(r.Context(), in.Email, string(hash), in.Days, a.cfg.getSiteChannel()); err != nil {
		code := 500
		if errors.Is(err, ErrEmailTaken) {
			code = 409
		}
		apiErr(w, code, err)
		return
	}
	writeJSON(w, 200, map[string]string{"email": in.Email, "password": in.Password}) // the only time the password is shown
}

// expiryReq is a change of the subscription period: add days, set a date, or remove the limit.
type expiryReq struct {
	ExtendDays *int   `json:"extend_days"`
	Until      string `json:"until"` // YYYY-MM-DD (end of that day, UTC)
	Unlimited  bool   `json:"unlimited"`
}

func (a *API) applyExpiry(r *http.Request, userID int64, e expiryReq) error {
	switch {
	case e.Unlimited:
		return a.store.SetUserExpiry(r.Context(), userID, nil)
	case e.Until != "":
		t, err := time.Parse("2006-01-02", e.Until)
		if err != nil {
			return fmt.Errorf("дата в формате ГГГГ-ММ-ДД")
		}
		t = t.Add(24*time.Hour - time.Second)
		return a.store.SetUserExpiry(r.Context(), userID, &t)
	case e.ExtendDays != nil:
		if *e.ExtendDays < -3660 || *e.ExtendDays > 3660 || *e.ExtendDays == 0 {
			return fmt.Errorf("дней: от -3660 до 3660, не ноль")
		}
		if *e.ExtendDays < 0 { // shorten from the current end (or from now when it has no end)
			return a.shorten(r, userID, -*e.ExtendDays)
		}
		return a.store.ExtendUser(r.Context(), userID, *e.ExtendDays)
	}
	return fmt.Errorf("нужно extend_days, until или unlimited")
}

func (a *API) shorten(r *http.Request, userID int64, days int) error {
	_, err := a.store.pool.Exec(r.Context(), `UPDATE users SET expires_at = COALESCE(expires_at, now()) - make_interval(days => $2) WHERE id=$1`, userID, days)
	return err
}

func randomPassword() string {
	const abc = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 14)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(abc))))
		b[i] = abc[n.Int64()]
	}
	return string(b)
}

func (a *API) accountOp(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	acc, err := a.store.AccountByID(r.Context(), id)
	if err != nil {
		apiErr(w, 404, fmt.Errorf("аккаунт не найден"))
		return
	}
	fail := func(err error) {
		code := 500
		if errors.Is(err, ErrNotFound) {
			code = 404
		}
		apiErr(w, code, err)
	}
	switch op := r.PathValue("op"); op {
	case "block", "unblock":
		if err := a.store.SetAccountBlocked(r.Context(), id, op == "block"); err != nil {
			fail(err)
			return
		}
	case "delete":
		if err := a.store.DeleteAccount(r.Context(), id); err != nil {
			fail(err)
			return
		}
	case "reset-password":
		pw := randomPassword()
		hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
		if err == nil {
			err = a.store.SetAccountPassword(r.Context(), id, string(hash))
		}
		if err != nil {
			fail(err)
			return
		}
		a.store.DeleteOtherSessions(r.Context(), id, "") // every session ends
		writeJSON(w, 200, map[string]string{"email": acc.Email, "password": pw})
		return
	case "expiry":
		var e expiryReq
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&e); err != nil {
			apiErr(w, 400, fmt.Errorf("ожидается JSON"))
			return
		}
		if err := a.applyExpiry(r, acc.UserID, e); err != nil {
			apiErr(w, 400, err)
			return
		}
	case "balance":
		var in struct {
			Delta int64  `json:"delta_cents"`
			Note  string `json:"note"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
			apiErr(w, 400, fmt.Errorf("ожидается JSON {delta_cents, note}"))
			return
		}
		kind := "admin"
		if err := a.store.AdjustBalance(r.Context(), id, in.Delta, kind, strings.TrimSpace(in.Note)); err != nil {
			apiErr(w, 400, err)
			return
		}
	case "note":
		var in struct {
			Note string `json:"note"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil || len(in.Note) > 500 {
			apiErr(w, 400, fmt.Errorf("заметка до 500 символов"))
			return
		}
		if err := a.store.SetAccountNote(r.Context(), id, in.Note); err != nil {
			fail(err)
			return
		}
	default:
		apiErr(w, 400, fmt.Errorf("операции: block, unblock, delete, reset-password, expiry, note, balance"))
		return
	}
	a.accountsList(w, r)
}

// userExpiry changes the period of a user created in the panel (no account on the site).
func (a *API) userExpiry(w http.ResponseWriter, r *http.Request) {
	uid, err := a.store.UserIDByName(r.Context(), r.PathValue("name"))
	if err != nil {
		apiErr(w, 404, fmt.Errorf("пользователь не найден"))
		return
	}
	var e expiryReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&e); err != nil {
		apiErr(w, 400, fmt.Errorf("ожидается JSON"))
		return
	}
	if err := a.applyExpiry(r, uid, e); err != nil {
		apiErr(w, 400, err)
		return
	}
	a.users(w, r)
}

// ---- payments ----

func (a *API) paymentsList(w http.ResponseWriter, r *http.Request) {
	st := r.URL.Query().Get("status")
	if st != "" && st != "pending" && st != "paid" && st != "canceled" {
		apiErr(w, 400, fmt.Errorf("status: pending, paid или canceled"))
		return
	}
	ps, err := a.store.ListPayments(r.Context(), st, 0, 200)
	if err != nil {
		apiErr(w, 500, err)
		return
	}
	writeJSON(w, 200, ps)
}

func (a *API) paymentOp(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var changed bool
	var err error
	switch r.PathValue("op") {
	case "confirm":
		changed, err = a.store.MarkPaid(r.Context(), id)
	case "cancel":
		changed, err = a.store.CancelPayment(r.Context(), id)
	default:
		apiErr(w, 400, fmt.Errorf("операции: confirm, cancel"))
		return
	}
	if err != nil {
		apiErr(w, 500, err)
		return
	}
	if !changed {
		apiErr(w, 409, fmt.Errorf("платёж уже обработан или не найден"))
		return
	}
	a.paymentsList(w, r)
}

func (a *API) promosList(w http.ResponseWriter, r *http.Request) {
	ps, err := a.store.ListPromos(r.Context())
	if err != nil {
		apiErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"promos": ps})
}

// promoSave creates or changes a promo code: {"code","kind":"percent|days|balance","value","max_uses","expires":"2026-12-31T00:00:00Z","enabled","note"}.
func (a *API) promoSave(w http.ResponseWriter, r *http.Request) {
	var p Promo
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&p); err != nil {
		apiErr(w, 400, fmt.Errorf("ожидается JSON промокода"))
		return
	}
	if err := a.store.SavePromo(r.Context(), p); err != nil {
		apiErr(w, 400, err)
		return
	}
	a.promosList(w, r)
}

func (a *API) promoDelete(w http.ResponseWriter, r *http.Request) {
	if ok, err := a.store.DeletePromo(r.Context(), r.PathValue("code")); err != nil {
		apiErr(w, 500, err)
		return
	} else if !ok {
		apiErr(w, 404, fmt.Errorf("промокод не найден"))
		return
	}
	a.promosList(w, r)
}
