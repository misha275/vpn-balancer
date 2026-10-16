package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
)

// The public site: registration, login, the cabinet of a user (subscription links, traffic, days left) and the payment stub.
// It has nothing to do with the admin panel: another listener, another handler, no shared tokens.

const (
	sessionCookie = "vsid"
	sessionTTL    = 30 * 24 * time.Hour
	maxPassBytes  = 72 // bcrypt reads no more
	minPassBytes  = 8
)

// PaymentProvider is the place to plug a real payment system in. Start gets a new pending payment and says what happens next:
// the money arrived at once (Paid), the person has to go to a payment page (RedirectURL) or the payment waits for confirmation.
// A real provider confirms the payment later by calling Store.MarkPaid from its own callback.
type PaymentProvider interface {
	Name() string
	Start(ctx context.Context, st *Store, p *Payment) (PayResult, error)
}

type PayResult struct {
	Paid        bool
	RedirectURL string
	Message     string
}

// stubProvider is the placeholder: in "stub_auto" the payment succeeds at once (a test mode), in "manual" it waits for the administrator.
type stubProvider struct{ auto bool }

func (stubProvider) Name() string { return "stub" }

func (p stubProvider) Start(ctx context.Context, st *Store, pay *Payment) (PayResult, error) {
	if !p.auto {
		return PayResult{Message: "Заявка принята. Как только администратор подтвердит оплату, подписка продлится."}, nil
	}
	if _, err := st.MarkPaid(ctx, pay.ID); err != nil {
		return PayResult{}, err
	}
	return PayResult{Paid: true, Message: "Тестовая оплата прошла, подписка продлена."}, nil
}

// limiter allows n events per window for a key.
type limiter struct {
	mu     sync.Mutex
	n      int
	window time.Duration
	hits   map[string][]time.Time
}

func newLimiter(n int, window time.Duration) *limiter {
	return &limiter{n: n, window: window, hits: map[string][]time.Time{}}
}

func (l *limiter) prune(key string, now time.Time) []time.Time {
	keep := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if now.Sub(t) < l.window {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(l.hits, key)
		return nil
	}
	l.hits[key] = keep
	return keep
}

func (l *limiter) blocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.prune(key, time.Now())) >= l.n
}

func (l *limiter) hit(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.hits) > 20000 { // somebody is sweeping the address space: forget the old, keep working
		l.hits = map[string][]time.Time{}
	}
	l.hits[key] = append(l.prune(key, time.Now()), time.Now())
}

func (l *limiter) clear(key string) {
	l.mu.Lock()
	delete(l.hits, key)
	l.mu.Unlock()
}

type Site struct {
	cfg    *Config
	st     *Store
	subs   *SubServer
	secret []byte

	loginIP, loginMail, regIP, payAcc, forumLimit *limiter
	dummyHash                                     []byte
}

func NewSite(cfg *Config, st *Store) *Site {
	h, _ := bcrypt.GenerateFromPassword([]byte("dummy-password-for-timing"), bcrypt.DefaultCost)
	return &Site{cfg: cfg, st: st, subs: NewSubServer(cfg, st), secret: []byte(derive(cfg.Reality.PrivateKey+cfg.TestSecret, "site-csrf")),
		loginIP: newLimiter(15, 10*time.Minute), loginMail: newLimiter(6, 10*time.Minute), regIP: newLimiter(6, time.Hour), payAcc: newLimiter(10, time.Hour), forumLimit: newLimiter(10, 15*time.Minute), dummyHash: h}
}

func (s *Site) provider() PaymentProvider {
	switch s.cfg.getSite().Payment {
	case "stub_auto":
		return stubProvider{auto: true}
	case "manual":
		return stubProvider{}
	}
	return nil
}

// ---- sessions, CSRF ----

func tokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *Site) csrf(hash string) string {
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte("csrf|" + hash))
	return hex.EncodeToString(m.Sum(nil))[:32]
}

// current returns the logged-in account and the hash of its session token.
func (s *Site) current(r *http.Request) (*Account, string) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || len(c.Value) < 20 || len(c.Value) > 100 {
		return nil, ""
	}
	h := tokenHash(c.Value)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	a, err := s.st.SessionAccount(ctx, h)
	if err != nil {
		return nil, ""
	}
	return a, h
}

func isTLS(r *http.Request) bool { return r.TLS != nil }

func (s *Site) startSession(w http.ResponseWriter, r *http.Request, a *Account) error {
	tok, err := newToken()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := s.st.CreateSession(ctx, a.ID, tokenHash(tok), sessionTTL, clientIP(r)); err != nil {
		return err
	}
	s.st.TouchLogin(ctx, a.ID)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: tok, Path: "/", MaxAge: int(sessionTTL.Seconds()), HttpOnly: true, Secure: isTLS(r), SameSite: http.SameSiteLaxMode})
	return nil
}

// sameOrigin accepts a POST only when it comes from a page of this site.
func sameOrigin(r *http.Request) bool {
	for _, h := range []string{"Origin", "Referer"} {
		if v := r.Header.Get(h); v != "" {
			u, err := url.Parse(v)
			return err == nil && strings.EqualFold(u.Host, r.Host)
		}
	}
	return false
}

// ---- rendering ----

type pageData struct {
	Title, Site, Support string
	Nonce                string
	Email, CSRF          string
	CanRegister          bool
	Trial                string
	Error, Flash         string
	FormEmail            string
	Plans                []planView
	Payment              string
	Forum                forumData
	Help                 helpData

	// look
	Theme, Palette, CSSVer, Path string
	AccentStyle                  template.CSS
	ThemeOpts                    []themeOpt
	PaletteOpts                  []paletteOpt

	// cabinet
	State, Until, DaysWord, Created             string
	BlockKind, BlockReason                      string
	DaysLeft                                    int
	TrafficAll, Traffic30, UpAll, DownAll       string
	Links                                       []linkItem
	Hint                                        string
	Payments                                    []payItem
	Heading, Message, PayID, PayPlan, PayAmount string
}

type planView struct {
	ID    int64
	Name  string
	Days  int
	Price string
	Has   []string // what the plan includes (names of the subscriptions)
}
type linkItem struct{ Kind, Title, URL string }
type payItem struct{ Date, Plan, Amount, Status, Class string }

type themeOpt struct {
	ID, Title, Icon string
	On              bool
}
type paletteOpt struct {
	ID, Title, Color string
	On               bool
}

func (s *Site) base(r *http.Request, acc *Account, hash, title string) pageData {
	sc := s.cfg.getSite()
	d := pageData{Title: title, Site: sc.Name, Support: sc.Support, CanRegister: sc.Registration, Trial: trialText(sc.TrialDays), Payment: sc.Payment}
	pf := s.prefsOf(r)
	d.Theme, d.Palette, d.AccentStyle, d.CSSVer, d.Path = pf.Theme, pf.Palette, template.CSS(pf.AccentStyle), siteCSSVer, r.URL.Path
	for _, t := range siteThemes {
		d.ThemeOpts = append(d.ThemeOpts, themeOpt{t.ID, t.Title, t.Icon, t.ID == pf.Theme})
	}
	for _, p := range sitePalettes {
		d.PaletteOpts = append(d.PaletteOpts, paletteOpt{p.ID, p.Title, p.Light, p.ID == pf.Palette})
	}
	if acc != nil {
		d.Email, d.CSRF = acc.Email, s.csrf(hash)
	}
	return d
}

func (s *Site) render(w http.ResponseWriter, code int, name string, d pageData) {
	nonce, _ := newToken()
	d.Nonce = nonce
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'nonce-"+nonce+"'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.WriteHeader(code)
	if err := siteTpl.ExecuteTemplate(w, name, d); err != nil {
		log.Printf("site: template %s: %v", name, err)
	}
}

func (s *Site) planViews(ctx context.Context) []planView {
	ps, err := s.st.ListPlans(ctx, true)
	if err != nil {
		return nil
	}
	names := map[string]string{}
	if bs, err := s.st.ListBundles(ctx, true); err == nil {
		for _, b := range bs {
			names[bundlePrefix+b.Slug] = b.Name
		}
	}
	out := make([]planView, 0, len(ps))
	for _, p := range ps {
		keys := p.Subs
		if keys == nil {
			keys = s.cfg.defaultSubs()
		}
		var has []string
		for _, k := range keys {
			switch {
			case k == subBalancers:
				has = append(has, "балансировщики")
			case k == subServers:
				has = append(has, "конечные серверы")
			case k == subAll:
				has = append(has, "балансировщики и все серверы")
			default:
				if n, ok := names[k]; ok {
					has = append(has, n)
				}
			}
		}
		out = append(out, planView{p.ID, p.Name, p.Days, fmtMoney(p.PriceCents, p.Currency), has})
	}
	return out
}

// ---- handler ----

func (s *Site) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.home)
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginPost)
	mux.HandleFunc("GET /register", s.registerPage)
	mux.HandleFunc("POST /register", s.registerPost)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /cabinet", s.cabinet)
	mux.HandleFunc("POST /account/password", s.changePassword)
	mux.HandleFunc("GET /pay", s.payPage)
	mux.HandleFunc("POST /pay", s.payPost)
	mux.HandleFunc("GET /pay/{id}", s.payStatus)
	mux.HandleFunc("GET /qr/{kind}", s.qr)
	mux.HandleFunc("GET /site.css", s.cssPage)
	mux.HandleFunc("POST /api/sync", s.syncHandler)
	mux.HandleFunc("GET /prefs", s.prefsPage)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("User-agent: *\nDisallow: /\n"))
	})
	s.registerForum(mux)
	s.registerHelp(mux)
	mux.Handle("GET /sub/", s.subs.Handler())
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		acc, h := s.current(r)
		s.render(w, 404, "notfound", s.base(r, acc, h, "Не найдено"))
	})
	small := http.MaxBytesHandler(mux, 16<<10)
	big := http.MaxBytesHandler(mux, forumMaxRequest)
	// only the forms that carry attachments may be large
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && (strings.HasPrefix(r.URL.Path, "/forum/") || r.URL.Path == "/api/sync") {
			big.ServeHTTP(w, r)
			return
		}
		small.ServeHTTP(w, r)
	})
}

func (s *Site) cssPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write([]byte(siteCSS))
}

func (s *Site) home(w http.ResponseWriter, r *http.Request) {
	acc, h := s.current(r)
	d := s.base(r, acc, h, "Главная")
	d.Plans = s.planViews(r.Context())
	s.render(w, 200, "home", d)
}

func (s *Site) loginPage(w http.ResponseWriter, r *http.Request) {
	if acc, _ := s.current(r); acc != nil {
		http.Redirect(w, r, "/cabinet", http.StatusSeeOther)
		return
	}
	s.render(w, 200, "login", s.base(r, nil, "", "Вход"))
}

func normEmail(e string) string { return strings.ToLower(strings.TrimSpace(e)) }

func (s *Site) loginPost(w http.ResponseWriter, r *http.Request) {
	d := s.base(r, nil, "", "Вход")
	fail := func(code int, msg string) {
		d.Error = msg
		s.render(w, code, "login", d)
	}
	if !sameOrigin(r) {
		fail(403, "Запрос отклонён. Откройте страницу входа заново")
		return
	}
	if r.ParseForm() != nil {
		fail(400, "Неверный запрос")
		return
	}
	email, pass := normEmail(r.PostForm.Get("email")), r.PostForm.Get("password")
	d.FormEmail = email
	ip := clientIP(r)
	if s.loginIP.blocked(ip) || s.loginMail.blocked(email) {
		fail(429, "Слишком много попыток. Подождите 10 минут")
		return
	}
	acc, err := s.st.AccountByEmail(r.Context(), email)
	hash := s.dummyHash // the same work for an unknown address, so the answer time does not tell whether it exists
	if err == nil {
		hash = []byte(acc.PassHash)
	}
	okPass := bcrypt.CompareHashAndPassword(hash, []byte(pass)) == nil
	if err != nil || !okPass {
		s.loginIP.hit(ip)
		s.loginMail.hit(email)
		fail(401, "Неверная почта или пароль")
		return
	}
	if acc.Blocked {
		msg := "Аккаунт заблокирован."
		if acc.BlockReason != "" {
			msg += " Причина: " + acc.BlockReason + "."
		}
		fail(403, msg+" Обратитесь в поддержку")
		return
	}
	s.loginMail.clear(email)
	if err := s.startSession(w, r, acc); err != nil {
		log.Printf("site: session: %v", err)
		fail(500, "Временная ошибка, попробуйте ещё раз")
		return
	}
	http.Redirect(w, r, "/cabinet", http.StatusSeeOther)
}

func (s *Site) registerPage(w http.ResponseWriter, r *http.Request) {
	if acc, _ := s.current(r); acc != nil {
		http.Redirect(w, r, "/cabinet", http.StatusSeeOther)
		return
	}
	d := s.base(r, nil, "", "Регистрация")
	if !d.CanRegister {
		s.render(w, 200, "closed", d)
		return
	}
	s.render(w, 200, "register", d)
}

func checkPassword(p, email string) string {
	switch {
	case len(p) < minPassBytes:
		return "Пароль короче 8 символов"
	case len(p) > maxPassBytes:
		return "Пароль длиннее 72 байт"
	case strings.EqualFold(p, email):
		return "Пароль не должен совпадать с почтой"
	}
	return ""
}

func (s *Site) registerPost(w http.ResponseWriter, r *http.Request) {
	d := s.base(r, nil, "", "Регистрация")
	if !d.CanRegister {
		s.render(w, 403, "closed", d)
		return
	}
	fail := func(code int, msg string) {
		d.Error = msg
		s.render(w, code, "register", d)
	}
	if !sameOrigin(r) {
		fail(403, "Запрос отклонён. Откройте страницу регистрации заново")
		return
	}
	if r.ParseForm() != nil {
		fail(400, "Неверный запрос")
		return
	}
	email, p1, p2 := normEmail(r.PostForm.Get("email")), r.PostForm.Get("password"), r.PostForm.Get("password2")
	d.FormEmail = email
	ip := clientIP(r)
	if s.regIP.blocked(ip) {
		fail(429, "Слишком много регистраций с этого адреса. Попробуйте позже")
		return
	}
	switch {
	case len(email) > 120 || !reEmail.MatchString(email):
		fail(400, "Введите настоящий адрес почты")
		return
	case p1 != p2:
		fail(400, "Пароли не совпадают")
		return
	}
	if msg := checkPassword(p1, email); msg != "" {
		fail(400, msg)
		return
	}
	s.regIP.hit(ip)
	hash, err := bcrypt.GenerateFromPassword([]byte(p1), bcrypt.DefaultCost)
	if err != nil {
		fail(500, "Временная ошибка, попробуйте ещё раз")
		return
	}
	acc, err := s.st.CreateAccount(r.Context(), email, string(hash), s.cfg.getSite().TrialDays)
	if errors.Is(err, ErrEmailTaken) {
		fail(409, "Этот адрес уже зарегистрирован. Попробуйте войти")
		return
	}
	if err != nil {
		log.Printf("site: register: %v", err)
		fail(500, "Временная ошибка, попробуйте ещё раз")
		return
	}
	if err := s.startSession(w, r, acc); err != nil {
		log.Printf("site: session: %v", err)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/cabinet?new=1", http.StatusSeeOther)
}

// authed returns the account for a page that needs a login, or sends the visitor to the login page.
func (s *Site) authed(w http.ResponseWriter, r *http.Request) (*Account, string) {
	acc, h := s.current(r)
	if acc == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
	return acc, h
}

// authedPost is the same for a form: it also checks the origin and the CSRF token.
func (s *Site) authedPost(w http.ResponseWriter, r *http.Request) (*Account, string) {
	acc, h := s.current(r)
	if acc == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return nil, ""
	}
	var perr error
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		perr = r.ParseMultipartForm(1 << 20) // bigger parts go to temporary files
	} else {
		perr = r.ParseForm()
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	if !sameOrigin(r) || perr != nil || !hmac.Equal([]byte(r.PostForm.Get("csrf")), []byte(s.csrf(h))) {
		http.Error(w, "Запрос отклонён. Обновите страницу и повторите", http.StatusForbidden)
		return nil, ""
	}
	return acc, h
}

func (s *Site) logout(w http.ResponseWriter, r *http.Request) {
	_, h := s.authedPost(w, r)
	if h == "" {
		return
	}
	s.st.DeleteSession(r.Context(), h)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: isTLS(r), SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// linkBase is the address the subscription links start with.
func (s *Site) linkBase(r *http.Request) string {
	if b := s.cfg.subBase(); b != "" {
		return b
	}
	scheme := "http"
	if isTLS(r) {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// accountLinks is the one link of the cabinet: the subscription address. It holds everything the account may take (the categories
// chosen in the panel), so there is nothing else to copy. Servers never appear as separate links.
func (s *Site) accountLinks(r *http.Request, a *Account) []linkItem {
	return []linkItem{{"sub", "Ваша подписка", s.linkBase(r) + "/sub/" + a.SubToken}}
}

// cabinetData collects what the cabinet shows.
func (s *Site) cabinetData(r *http.Request, acc *Account, h string) pageData {
	d := s.base(r, acc, h, "Кабинет")
	d.State, d.DaysLeft = periodState(acc.Expires, time.Now())
	d.DaysWord = daysWord(d.DaysLeft)
	if acc.Expires != nil {
		d.Until = fmtDateRu(*acc.Expires)
	}
	d.Created = acc.Created.UTC().Format("02.01.2006")
	if t, err := s.st.UserTrafficOf(r.Context(), acc.UserName); err == nil {
		d.TrafficAll, d.Traffic30 = fmtBytesRu(t.AllUp+t.AllDown), fmtBytesRu(t.D30Up+t.D30Down)
		d.UpAll, d.DownAll = fmtBytesRu(t.AllUp), fmtBytesRu(t.AllDown)
	}
	d.Links = s.accountLinks(r, acc)
	d.BlockKind, d.BlockReason = acc.BlockKind, acc.BlockReason
	if d.State == "expired" {
		d.Hint = "Пока подписка не продлена, ссылки не работают. После продления они заработают снова (обновите подписку в приложении)."
	}
	if ps, err := s.st.ListPayments(r.Context(), "", acc.ID, 5); err == nil {
		for _, p := range ps {
			it := payItem{Date: p.Created.UTC().Format("02.01.2006"), Plan: p.PlanName, Amount: fmtMoney(p.AmountCents, p.Currency)}
			switch p.Status {
			case "paid":
				it.Status, it.Class = "оплачен", "ok"
			case "canceled":
				it.Status, it.Class = "отменён", "muted"
			default:
				it.Status, it.Class = "ждёт подтверждения", "warn"
			}
			d.Payments = append(d.Payments, it)
		}
	}
	return d
}

func (s *Site) cabinet(w http.ResponseWriter, r *http.Request) {
	acc, h := s.authed(w, r)
	if acc == nil {
		return
	}
	d := s.cabinetData(r, acc, h)
	switch {
	case r.URL.Query().Get("new") == "1":
		if sc := s.cfg.getSite(); sc.TrialDays > 0 {
			d.Flash = fmt.Sprintf("Аккаунт создан. Вам подарено %s доступа.", trialText(sc.TrialDays))
		} else {
			d.Flash = "Аккаунт создан. Чтобы начать, оплатите подписку."
		}
	case r.URL.Query().Get("msg") == "pw":
		d.Flash = "Пароль изменён, остальные сеансы завершены."
	}
	s.render(w, 200, "cabinet", d)
}

func (s *Site) changePassword(w http.ResponseWriter, r *http.Request) {
	acc, h := s.authedPost(w, r)
	if acc == nil {
		return
	}
	old, nw := r.PostForm.Get("old"), r.PostForm.Get("new")
	renderErr := func(code int, msg string) {
		d := s.cabinetData(r, acc, h)
		d.Error = msg
		s.render(w, code, "cabinet", d)
	}
	if s.loginMail.blocked(acc.Email) {
		renderErr(429, "Слишком много попыток. Подождите 10 минут")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(acc.PassHash), []byte(old)) != nil {
		s.loginMail.hit(acc.Email)
		renderErr(400, "Текущий пароль неверный")
		return
	}
	if msg := checkPassword(nw, acc.Email); msg != "" {
		renderErr(400, msg)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(nw), bcrypt.DefaultCost)
	if err != nil || s.st.SetAccountPassword(r.Context(), acc.ID, string(hash)) != nil {
		renderErr(500, "Временная ошибка, попробуйте ещё раз")
		return
	}
	s.st.DeleteOtherSessions(r.Context(), acc.ID, h)
	http.Redirect(w, r, "/cabinet?msg=pw", http.StatusSeeOther)
}

// ---- payment ----

func (s *Site) payPage(w http.ResponseWriter, r *http.Request) {
	acc, h := s.authed(w, r)
	if acc == nil {
		return
	}
	d := s.base(r, acc, h, "Оплата")
	if d.Payment == "off" {
		d.Error = "Онлайн-оплата сейчас выключена. Чтобы продлить подписку, свяжитесь с поддержкой."
	} else {
		d.Plans = s.planViews(r.Context())
	}
	s.render(w, 200, "pay", d)
}

func (s *Site) payPost(w http.ResponseWriter, r *http.Request) {
	acc, h := s.authedPost(w, r)
	if acc == nil {
		return
	}
	d := s.base(r, acc, h, "Оплата")
	fail := func(code int, msg string) {
		d.Error = msg
		d.Plans = s.planViews(r.Context())
		s.render(w, code, "pay", d)
	}
	prov := s.provider()
	if prov == nil {
		fail(403, "Онлайн-оплата сейчас выключена")
		return
	}
	if s.payAcc.blocked(acc.Email) {
		fail(429, "Слишком много заявок. Попробуйте позже")
		return
	}
	id, _ := strconv.ParseInt(r.PostForm.Get("plan"), 10, 64)
	plan, err := s.st.PlanByID(r.Context(), id)
	if err != nil || !plan.Enabled {
		fail(400, "Такого тарифа нет")
		return
	}
	if pend, _ := s.st.ListPayments(r.Context(), "pending", acc.ID, 10); len(pend) >= 3 {
		fail(409, "У вас уже есть неподтверждённые заявки. Дождитесь подтверждения")
		return
	}
	s.payAcc.hit(acc.Email)
	pay, err := s.st.CreatePayment(r.Context(), acc.ID, *plan, prov.Name())
	if err != nil {
		log.Printf("site: payment: %v", err)
		fail(500, "Временная ошибка, попробуйте ещё раз")
		return
	}
	res, err := prov.Start(r.Context(), s.st, pay)
	if err != nil {
		log.Printf("site: payment %d: %v", pay.ID, err)
		fail(500, "Не удалось провести оплату, попробуйте ещё раз")
		return
	}
	if res.RedirectURL != "" {
		http.Redirect(w, r, res.RedirectURL, http.StatusSeeOther)
		return
	}
	d.Heading = "Заявка принята"
	if res.Paid {
		d.Heading = "Оплачено"
	}
	d.Message, d.PayID, d.PayPlan, d.PayAmount = res.Message, strconv.FormatInt(pay.ID, 10), pay.PlanName, fmtMoney(pay.AmountCents, pay.Currency)
	s.render(w, 200, "paid", d)
}

func (s *Site) payStatus(w http.ResponseWriter, r *http.Request) {
	acc, h := s.authed(w, r)
	if acc == nil {
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	p, err := s.st.PaymentByID(r.Context(), id)
	if err != nil || p.AccountID != acc.ID {
		s.render(w, 404, "notfound", s.base(r, acc, h, "Не найдено"))
		return
	}
	d := s.base(r, acc, h, "Платёж")
	d.Heading = map[string]string{"paid": "Оплачено", "canceled": "Платёж отменён"}[p.Status]
	if d.Heading == "" {
		d.Heading = "Ждёт подтверждения"
	}
	d.PayID, d.PayPlan, d.PayAmount = strconv.FormatInt(p.ID, 10), p.PlanName, fmtMoney(p.AmountCents, p.Currency)
	s.render(w, 200, "paid", d)
}

// qr draws the QR code of one of the links of the logged-in account (the content is never taken from the request).
func (s *Site) qr(w http.ResponseWriter, r *http.Request) {
	acc, _ := s.current(r)
	if acc == nil {
		http.Error(w, "login required", http.StatusUnauthorized)
		return
	}
	kind := r.PathValue("kind")
	for _, l := range s.accountLinks(r, acc) {
		if l.Kind != kind {
			continue
		}
		png, err := qrcode.Encode(l.URL, qrcode.Medium, 320)
		if err != nil {
			http.Error(w, "qr", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "private, no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Write(png)
		return
	}
	http.NotFound(w, r)
}

// janitor removes expired sessions.
func (s *Site) janitor(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c, cancel := context.WithTimeout(ctx, 10*time.Second)
			s.st.PurgeSessions(c)
			cancel()
		}
	}
}
