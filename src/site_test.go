package main

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

func siteTestCfg() *Config {
	cfg := modesSubCfg()
	cfg.TestSecret = "test-secret"
	cfg.Reality.PrivateKey = testPriv
	cfg.SiteEnabled, cfg.SiteName, cfg.SitePayment = true, "TestVPN", "manual"
	on, trial := true, 3
	cfg.SiteRegistration, cfg.SiteTrialDays = &on, &trial
	cfg.SubPublicURL = "" // links follow the address the site is opened by
	return cfg
}

type siteClient struct {
	t   *testing.T
	srv *httptest.Server
	c   *http.Client
}

func newSiteClient(t *testing.T, srv *httptest.Server) *siteClient {
	jar, _ := cookiejar.New(nil)
	return &siteClient{t: t, srv: srv, c: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Timeout: 20 * time.Second}}
}

func (s *siteClient) get(path string) (int, string, http.Header) {
	s.t.Helper()
	resp, err := s.c.Get(s.srv.URL + path)
	if err != nil {
		s.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

func (s *siteClient) post(path string, form url.Values, origin bool) (int, string, http.Header) {
	s.t.Helper()
	req, _ := http.NewRequest("POST", s.srv.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin {
		req.Header.Set("Origin", s.srv.URL)
	}
	resp, err := s.c.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

var reCSRF = regexp.MustCompile(`name="csrf" value="([0-9a-f]+)"`)

func (s *siteClient) csrf() string {
	s.t.Helper()
	_, body, _ := s.get("/cabinet")
	m := reCSRF.FindStringSubmatch(body)
	if m == nil {
		s.t.Fatalf("no csrf token on the page: %.300s", body)
	}
	return m[1]
}

func (s *siteClient) register(email, pass string) (int, string) {
	code, body, _ := s.post("/register", url.Values{"email": {email}, "password": {pass}, "password2": {pass}}, true)
	return code, body
}

func startSite(t *testing.T, cfg *Config) (*Site, *Store, *httptest.Server) {
	st := testStore(t)
	for _, tbl := range []string{"accounts", "payments", "web_sessions"} {
		st.pool.Exec(context.Background(), "TRUNCATE "+tbl+" CASCADE")
	}
	site := NewSite(cfg, st)
	srv := httptest.NewServer(site.Handler())
	t.Cleanup(srv.Close)
	return site, st, srv
}

func TestPeriodHelpers(t *testing.T) {
	now := time.Now()
	if s, d := periodState(nil, now); s != "unlimited" || d != 0 {
		t.Error("no end = unlimited")
	}
	past := now.Add(-time.Minute)
	if s, _ := periodState(&past, now); s != "expired" {
		t.Error("past = expired")
	}
	for _, c := range []struct {
		in   time.Duration
		days int
	}{{time.Hour, 1}, {24 * time.Hour, 1}, {24*time.Hour + time.Second, 2}, {72 * time.Hour, 3}} {
		e := now.Add(c.in)
		if s, d := periodState(&e, now); s != "active" || d != c.days {
			t.Errorf("%v: %s %d, want %d", c.in, s, d, c.days)
		}
	}
	for n, w := range map[int]string{1: "день", 2: "дня", 5: "дней", 11: "дней", 21: "день", 22: "дня", 112: "дней"} {
		if daysWord(n) != w {
			t.Errorf("daysWord(%d) = %s", n, daysWord(n))
		}
	}
	if fmtBytesRu(1536) != "1.50 КБ" || fmtBytesRu(5<<30) != "5.00 ГБ" || fmtBytesRu(10) != "10 Б" {
		t.Errorf("bytes: %s %s %s", fmtBytesRu(1536), fmtBytesRu(5<<30), fmtBytesRu(10))
	}
	if fmtMoney(19900, "RUB") != "199 ₽" || fmtMoney(1999, "USD") != "19.99 $" || fmtMoney(0, "RUB") != "бесплатно" || fmtMoney(500, "CHF") != "5 CHF" {
		t.Error("money formatting")
	}
}

func TestEmailAndPasswordRules(t *testing.T) {
	for _, ok := range []string{"a@b.co", "john.doe+x@example.com"} {
		if !reEmail.MatchString(ok) {
			t.Errorf("must accept %s", ok)
		}
	}
	for _, bad := range []string{"", "a", "a@b", "a b@c.de", "a@b@c.de", "a~b@c.de", "@c.de"} {
		if reEmail.MatchString(bad) {
			t.Errorf("must reject %q", bad)
		}
	}
	if checkPassword("short", "a@b.co") == "" || checkPassword(strings.Repeat("x", 73), "a@b.co") == "" || checkPassword("a@b.co", "a@b.co") == "" || checkPassword("goodpassword", "a@b.co") != "" {
		t.Error("password rules")
	}
	for _, d := range []string{"vpn.example.com", "a.b.ru"} {
		if !validDomain(d) {
			t.Errorf("domain %s", d)
		}
	}
	for _, d := range []string{"", "localhost", "http://x.com", "x.com:443", "-a.com", "a_b.com", "1.2.3.4"} {
		if validDomain(d) {
			t.Errorf("must reject domain %q", d)
		}
	}
}

func TestExpiryControlsTheKey(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	st.AddUser(ctx, "limited")
	st.AddUser(ctx, "forever")
	id, _ := st.UserIDByName(ctx, "limited")
	names := func() []string {
		us, _ := st.EnabledUsers(ctx)
		var out []string
		for _, u := range us {
			out = append(out, u.Name)
		}
		return out
	}
	if got := strings.Join(names(), ","); got != "limited,forever" {
		t.Fatalf("users without a period work: %s", got)
	}
	past := time.Now().Add(-time.Hour)
	st.SetUserExpiry(ctx, id, &past)
	if got := strings.Join(names(), ","); got != "forever" {
		t.Fatalf("an ended period switches the key off: %s", got)
	}
	us, _ := st.ListUsers(ctx)
	var tok string
	for _, u := range us {
		if u.Name == "limited" {
			tok = u.SubToken
			if u.Active(time.Now()) {
				t.Error("User.Active must be false after the end")
			}
		}
	}
	if _, err := st.UserBySubToken(ctx, tok); err == nil {
		t.Error("the subscription of an expired user must not be served")
	}
	// extending an ended period counts from now, not from the old end
	st.ExtendUser(ctx, id, 10)
	us, _ = st.ListUsers(ctx)
	for _, u := range us {
		if u.Name == "limited" {
			if d := time.Until(*u.Expires); d < 9*24*time.Hour+23*time.Hour || d > 10*24*time.Hour+time.Minute {
				t.Errorf("extension from now: %v", d)
			}
		}
	}
	if got := strings.Join(names(), ","); got != "limited,forever" {
		t.Errorf("extended user works again: %s", got)
	}
	// an unlimited user stays unlimited when extended
	fid, _ := st.UserIDByName(ctx, "forever")
	st.ExtendUser(ctx, fid, 30)
	us, _ = st.ListUsers(ctx)
	for _, u := range us {
		if u.Name == "forever" && u.Expires != nil {
			t.Error("extending must not put a limit on an unlimited user")
		}
	}
}

func TestSiteRegistrationCabinetAndTraffic(t *testing.T) {
	cfg := siteTestCfg()
	site, st, srv := startSite(t, cfg)
	_ = site
	c := newSiteClient(t, srv)

	if code, body, _ := c.get("/"); code != 200 || !strings.Contains(body, "TestVPN") || !strings.Contains(body, "1 месяц") {
		t.Fatalf("home with plans: %d %.200s", code, body)
	}
	if code, _, h := c.get("/cabinet"); code != 303 || h.Get("Location") != "/login" {
		t.Fatalf("cabinet needs a login: %d", code)
	}
	// a form from another site is refused
	if code, _, _ := c.post("/register", url.Values{"email": {"a@b.co"}, "password": {"password1"}, "password2": {"password1"}}, false); code != 403 {
		t.Fatalf("no Origin: %d", code)
	}
	if code, body := c.register("Anna@Example.com", "short"); code != 400 || !strings.Contains(body, "короче 8") {
		t.Fatalf("short password: %d", code)
	}
	if code, body, _ := c.post("/register", url.Values{"email": {"anna@example.com"}, "password": {"password1"}, "password2": {"password2"}}, true); code != 400 || !strings.Contains(body, "не совпадают") {
		t.Fatalf("mismatch: %d", code)
	}
	if code, _, _ := c.post("/register", url.Values{"email": {"nonsense"}, "password": {"password1"}, "password2": {"password1"}}, true); code != 400 {
		t.Fatalf("bad email: %d", code)
	}
	code, _, h := c.post("/register", url.Values{"email": {"Anna@Example.com"}, "password": {"password1"}, "password2": {"password1"}}, true)
	if code != 303 || !strings.HasPrefix(h.Get("Location"), "/cabinet") {
		t.Fatalf("register: %d %v", code, h)
	}
	if ck := h.Get("Set-Cookie"); !strings.Contains(ck, "HttpOnly") || !strings.Contains(ck, "SameSite=Lax") {
		t.Errorf("session cookie must be HttpOnly and SameSite: %s", ck)
	}
	// the account owns a VPN user with a trial period
	acc, err := st.AccountByEmail(context.Background(), "anna@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if acc.Expires == nil || time.Until(*acc.Expires) < 71*time.Hour || time.Until(*acc.Expires) > 73*time.Hour || !acc.Enabled {
		t.Fatalf("trial of 3 days: %v", acc.Expires)
	}
	if acc.PassHash == "password1" || !strings.HasPrefix(acc.PassHash, "$2") {
		t.Fatal("passwords are stored as bcrypt hashes")
	}
	if code, body := c.register("anna@example.com", "password1"); code != 409 || !strings.Contains(body, "уже зарегистрирован") {
		t.Fatalf("duplicate: %d", code)
	}
	// traffic of the VPN user shows in the cabinet
	st.AddTraffic(context.Background(), time.Now(), map[string]UserDelta{acc.UserName: {Up: 1 << 20, Down: 4 << 20, Conns: 3}})
	code, body, _ := c.get("/cabinet")
	if code != 200 {
		t.Fatalf("cabinet: %d", code)
	}
	for _, want := range []string{"anna@example.com", "Активна", "осталось 3 дня", "5.00 МБ", "↑ 1.00 МБ", "↓ 4.00 МБ", "/sub/" + acc.SubToken + "\""} {
		if !strings.Contains(body, want) {
			t.Errorf("the cabinet must show %q", want)
		}
	}
	if !strings.Contains(body, "http://127.0.0.1:") {
		t.Error("without a domain the links use the address the site was opened by")
	}
	if ct := c.csrf(); len(ct) != 32 {
		t.Error("csrf token")
	}
	// QR codes: only of the own links
	for _, kind := range []string{"sub"} {
		code, body, h := c.get("/qr/" + kind)
		if code != 200 || h.Get("Content-Type") != "image/png" || !strings.HasPrefix(body, "\x89PNG") {
			t.Errorf("qr %s: %d %s", kind, code, h.Get("Content-Type"))
		}
	}
	if code, _, _ := c.get("/qr/..%2Fx"); code != 404 {
		t.Errorf("unknown qr kind: %d", code)
	}
	anon := newSiteClient(t, srv)
	if code, _, _ := anon.get("/qr/sub"); code != 401 {
		t.Errorf("qr without a login: %d", code)
	}
	// the subscription works for the active user and carries the three balancers
	if code, _, _ := anon.get("/sub/" + acc.SubToken + "/balancers"); code != 200 {
		t.Errorf("subscription of an active account: %d", code)
	}
	// logout needs the token
	if code, _, _ := c.post("/logout", url.Values{}, true); code != 403 {
		t.Errorf("logout without csrf: %d", code)
	}
	tok := c.csrf()
	if code, _, _ := c.post("/logout", url.Values{"csrf": {tok}}, true); code != 303 {
		t.Errorf("logout: %d", code)
	}
	if code, _, _ := c.get("/cabinet"); code != 303 {
		t.Errorf("after logout: %d", code)
	}
	// security headers
	_, _, hh := anon.get("/login")
	if !strings.Contains(hh.Get("Content-Security-Policy"), "script-src 'nonce-") || hh.Get("X-Frame-Options") != "DENY" || hh.Get("Cache-Control") != "no-store" {
		t.Errorf("headers: %v", hh)
	}
}

func TestSiteLoginLimitsAndBlock(t *testing.T) {
	cfg := siteTestCfg()
	_, st, srv := startSite(t, cfg)
	c := newSiteClient(t, srv)
	c.register("bob@example.com", "password1")
	other := newSiteClient(t, srv)
	if code, body, _ := other.post("/login", url.Values{"email": {"bob@example.com"}, "password": {"wrong-pass"}}, true); code != 401 || !strings.Contains(body, "Неверная почта или пароль") {
		t.Fatalf("wrong password: %d", code)
	}
	if code, body, _ := other.post("/login", url.Values{"email": {"nobody@example.com"}, "password": {"wrong-pass"}}, true); code != 401 || !strings.Contains(body, "Неверная почта или пароль") {
		t.Fatalf("unknown email gives the same answer: %d", code)
	}
	if code, _, _ := other.post("/login", url.Values{"email": {"bob@example.com"}, "password": {"password1"}}, false); code != 403 {
		t.Fatalf("login form from elsewhere: %d", code)
	}
	if code, _, h := other.post("/login", url.Values{"email": {"BOB@example.com"}, "password": {"password1"}}, true); code != 303 || h.Get("Location") != "/cabinet" {
		t.Fatalf("login: %d", code)
	}
	// a blocked account loses the session and the key at once and cannot come back
	acc, _ := st.AccountByEmail(context.Background(), "bob@example.com")
	if err := st.SetAccountBlocked(context.Background(), acc.ID, true); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := other.get("/cabinet"); code != 303 {
		t.Errorf("a blocked account has no session: %d", code)
	}
	if us, _ := st.EnabledUsers(context.Background()); len(us) != 0 {
		t.Error("a blocked account's key must not reach the gateway")
	}
	if code, body, _ := newSiteClient(t, srv).post("/login", url.Values{"email": {"bob@example.com"}, "password": {"password1"}}, true); code != 403 || !strings.Contains(body, "заблокирован") {
		t.Errorf("blocked login: %d", code)
	}
	st.SetAccountBlocked(context.Background(), acc.ID, false)
	if code, _, _ := newSiteClient(t, srv).post("/login", url.Values{"email": {"bob@example.com"}, "password": {"password1"}}, true); code != 303 {
		t.Errorf("unblocked: %d", code)
	}
	// guessing passwords is slowed down (per address)
	g := newSiteClient(t, srv)
	var last int
	for i := 0; i < 9; i++ {
		last, _, _ = g.post("/login", url.Values{"email": {"victim@example.com"}, "password": {"guess" + string(rune('a'+i))}}, true)
	}
	if last != 429 {
		t.Errorf("too many failures must be refused, got %d", last)
	}
}

func TestSitePasswordChange(t *testing.T) {
	cfg := siteTestCfg()
	_, _, srv := startSite(t, cfg)
	a, b := newSiteClient(t, srv), newSiteClient(t, srv)
	a.register("carl@example.com", "password1")
	b.post("/login", url.Values{"email": {"carl@example.com"}, "password": {"password1"}}, true)
	tok := a.csrf()
	if code, body, _ := a.post("/account/password", url.Values{"csrf": {tok}, "old": {"nope-nope"}, "new": {"password2"}}, true); code != 400 || !strings.Contains(body, "Текущий пароль неверный") {
		t.Fatalf("wrong old password: %d", code)
	}
	if code, _, _ := a.post("/account/password", url.Values{"csrf": {"deadbeef"}, "old": {"password1"}, "new": {"password2"}}, true); code != 403 {
		t.Fatalf("wrong csrf: %d", code)
	}
	if code, _, h := a.post("/account/password", url.Values{"csrf": {tok}, "old": {"password1"}, "new": {"password2"}}, true); code != 303 || !strings.Contains(h.Get("Location"), "msg=pw") {
		t.Fatalf("change: %d", code)
	}
	if code, _, _ := a.get("/cabinet"); code != 200 {
		t.Error("the current session stays")
	}
	if code, _, _ := b.get("/cabinet"); code != 303 {
		t.Error("other sessions end after a password change")
	}
	if code, _, _ := newSiteClient(t, srv).post("/login", url.Values{"email": {"carl@example.com"}, "password": {"password1"}}, true); code != 401 {
		t.Error("the old password must not work")
	}
	if code, _, _ := newSiteClient(t, srv).post("/login", url.Values{"email": {"carl@example.com"}, "password": {"password2"}}, true); code != 303 {
		t.Error("the new password works")
	}
}

func TestSitePaymentFlows(t *testing.T) {
	cfg := siteTestCfg()
	_, st, srv := startSite(t, cfg)
	ctx := context.Background()
	c := newSiteClient(t, srv)
	c.register("dina@example.com", "password1")
	acc, _ := st.AccountByEmail(ctx, "dina@example.com")
	st.pool.Exec(ctx, "DELETE FROM plans")
	st.pool.Exec(ctx, "DELETE FROM settings WHERE key='plans_seeded'")
	if err := st.seedPlans(ctx); err != nil {
		t.Fatal(err)
	}
	plans, _ := st.ListPlans(ctx, true)
	if len(plans) != 3 {
		t.Fatalf("sample plans are created on the first start: %d", len(plans))
	}
	month := plans[0]
	before := *acc.Expires

	// manual mode: a request that waits for the administrator
	if code, body, _ := c.get("/pay"); code != 200 || !strings.Contains(body, "Оставить заявку") || !strings.Contains(body, "администратор") {
		t.Fatalf("pay page: %d", code)
	}
	tok := c.csrf()
	form := url.Values{"csrf": {tok}, "plan": {itoa(month.ID)}}
	if code, _, _ := c.post("/pay", url.Values{"plan": {itoa(month.ID)}}, true); code != 403 {
		t.Fatalf("payment without csrf: %d", code)
	}
	if code, body, _ := c.post("/pay", form, true); code != 200 || !strings.Contains(body, "Заявка принята") {
		t.Fatalf("manual payment: %d %.200s", code, body)
	}
	if a2, _ := st.AccountByID(ctx, acc.ID); !a2.Expires.Equal(before) {
		t.Fatal("a request must not extend anything before the confirmation")
	}
	_, body, _ := c.get("/cabinet")
	if !strings.Contains(body, "ждёт подтверждения") {
		t.Error("the cabinet lists the pending payment")
	}
	pend, _ := st.ListPayments(ctx, "pending", 0, 10)
	if len(pend) != 1 || pend[0].Email != "dina@example.com" || pend[0].Days != 30 {
		t.Fatalf("pending: %+v", pend)
	}
	// the administrator confirms: the period grows by the days of the plan, once
	if ok, err := st.MarkPaid(ctx, pend[0].ID); !ok || err != nil {
		t.Fatalf("confirm: %v %v", ok, err)
	}
	if ok, _ := st.MarkPaid(ctx, pend[0].ID); ok {
		t.Fatal("a payment is confirmed only once")
	}
	if a2, _ := st.AccountByID(ctx, acc.ID); a2.Expires.Sub(before) < 29*24*time.Hour+23*time.Hour || a2.Expires.Sub(before) > 30*24*time.Hour+time.Minute {
		t.Fatalf("30 days added to the end of the period: %v", a2.Expires.Sub(before))
	}
	if ok, _ := st.CancelPayment(ctx, pend[0].ID); ok {
		t.Fatal("a paid payment cannot be canceled")
	}
	// the plan is copied into the payment: editing it later changes nothing
	month.Days = 1
	st.SavePlan(ctx, month)
	if p, _ := st.PaymentByID(ctx, pend[0].ID); p.Days != 30 {
		t.Error("payments keep their own copy of the plan")
	}
	// at most 3 open requests
	for i := 0; i < 3; i++ {
		c.post("/pay", form, true)
	}
	if code, body, _ := c.post("/pay", form, true); code != 409 || !strings.Contains(body, "неподтверждённые") {
		t.Errorf("too many open requests: %d", code)
	}
	// a request for somebody else's payment page
	other := newSiteClient(t, srv)
	other.register("eve@example.com", "password1")
	if code, _, _ := other.get("/pay/" + itoa(pend[0].ID)); code != 404 {
		t.Errorf("foreign payment: %d", code)
	}

	// test mode: paid at once
	cfg.SitePayment = "stub_auto"
	e := newSiteClient(t, srv)
	e.register("fred@example.com", "password1")
	fa, _ := st.AccountByEmail(ctx, "fred@example.com")
	b4 := *fa.Expires
	plans, _ = st.ListPlans(ctx, true)
	_, pb, _ := e.get("/pay")
	if !strings.Contains(pb, "Тестовый режим") {
		t.Error("the test mode must be visible on the page")
	}
	if code, body, _ := e.post("/pay", url.Values{"csrf": {e.csrf()}, "plan": {itoa(plans[1].ID)}}, true); code != 200 || !strings.Contains(body, "Оплачено") {
		t.Fatalf("auto payment: %d", code)
	}
	if fa2, _ := st.AccountByID(ctx, fa.ID); fa2.Expires.Sub(b4) < 89*24*time.Hour {
		t.Errorf("90 days: %v", fa2.Expires.Sub(b4))
	}
	// payments switched off
	cfg.SitePayment = "off"
	if code, _, _ := e.post("/pay", url.Values{"csrf": {e.csrf()}, "plan": {itoa(plans[1].ID)}}, true); code != 403 {
		t.Errorf("payments off: %d", code)
	}
}

func TestSiteRegistrationClosedAndNoTrial(t *testing.T) {
	cfg := siteTestCfg()
	off, zero := false, 0
	cfg.SiteRegistration, cfg.SiteTrialDays = &off, &zero
	_, st, srv := startSite(t, cfg)
	c := newSiteClient(t, srv)
	if code, body, _ := c.get("/register"); !strings.Contains(body, "закрыта") || code != 200 {
		t.Errorf("closed registration page: %d", code)
	}
	if code, _ := c.register("x@example.com", "password1"); code != 403 {
		t.Errorf("registration when closed: %d", code)
	}
	if code, body, _ := c.get("/"); strings.Contains(body, "Регистрация") || code != 200 {
		t.Error("no registration link when it is closed")
	}
	on := true
	cfg.SiteRegistration = &on
	if code, _ := c.register("y@example.com", "password1"); code != 303 {
		t.Fatalf("registration reopened: %d", code)
	}
	acc, _ := st.AccountByEmail(context.Background(), "y@example.com")
	if us, _ := st.EnabledUsers(context.Background()); len(us) != 0 || acc.User().Active(time.Now()) {
		t.Error("without a trial the key works only after a payment")
	}
	_, body, _ := c.get("/cabinet")
	if !strings.Contains(body, "Закончилась") || !strings.Contains(body, "Оплатить") {
		t.Error("an account without access is asked to pay")
	}
	if code, _, _ := newSiteClient(t, srv).get("/sub/" + acc.SubToken + "/balancers"); code != 404 {
		t.Errorf("an inactive account has no subscription: %d", code)
	}
}

func TestDeletingAccountRemovesTheUser(t *testing.T) {
	cfg := siteTestCfg()
	_, st, srv := startSite(t, cfg)
	ctx := context.Background()
	c := newSiteClient(t, srv)
	c.register("gone@example.com", "password1")
	acc, _ := st.AccountByEmail(ctx, "gone@example.com")
	st.AddTraffic(ctx, time.Now(), map[string]UserDelta{acc.UserName: {Up: 5}})
	if err := st.DeleteAccount(ctx, acc.ID); err != nil {
		t.Fatal(err)
	}
	if us, _ := st.ListUsers(ctx); len(us) != 0 {
		t.Error("the VPN user goes with the account")
	}
	if _, err := st.AccountByEmail(ctx, "gone@example.com"); err == nil {
		t.Error("account must be gone")
	}
	if tr, _ := st.UserTrafficOf(ctx, acc.UserName); tr.AllUp != 0 {
		t.Error("counters must be removed")
	}
	if code, _, _ := c.get("/cabinet"); code != 303 {
		t.Error("sessions go with the account")
	}
	// and deleting the user from the Users tab removes the account
	c2 := newSiteClient(t, srv)
	c2.register("two@example.com", "password1")
	a2, _ := st.AccountByEmail(ctx, "two@example.com")
	st.DeleteUser(ctx, a2.UserName)
	if _, err := st.AccountByEmail(ctx, "two@example.com"); err == nil {
		t.Error("deleting the user deletes the account")
	}
}
