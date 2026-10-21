package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func cleanNames(t *testing.T, st *Store, names ...string) {
	t.Helper()
	for _, n := range names {
		st.pool.Exec(context.Background(), "DELETE FROM users WHERE name=$1", n)
	}
}

func setBotName(n string) {
	botNameMu.Lock()
	botName = n
	botNameMu.Unlock()
}

func TestUsernameRules(t *testing.T) {
	for _, ok := range []string{"abc", "a_b", "user_123", strings.Repeat("a", 24)} {
		if !validUsername(ok) {
			t.Errorf("must accept %q", ok)
		}
	}
	for _, bad := range []string{"", "ab", "Abc", "a b", "a-b", "почта", "a@b.co", strings.Repeat("a", 25)} {
		if validUsername(bad) {
			t.Errorf("must reject %q", bad)
		}
	}
}

func TestUsernameLoginAndRegister(t *testing.T) {
	cfg := siteTestCfg()
	_, st, srv := startSite(t, cfg)
	cleanNames(t, st, "login_one")
	c := newSiteClient(t, srv)
	if _, body, _ := c.get("/login"); !strings.Contains(body, `name="username"`) || strings.Contains(body, `type="email"`) {
		t.Error("the login form asks for a login, not for e-mail")
	}
	if code, _ := c.register("ab", "password1"); code != 400 {
		t.Errorf("short login: %d", code)
	}
	if code, _ := c.register("bad name", "password1"); code != 400 {
		t.Errorf("login with a space: %d", code)
	}
	if code, _ := c.register("x@example.com", "password1"); code != 400 {
		t.Errorf("e-mail instead of a login: %d", code)
	}
	if code, body := c.register("login_one", "login_one"); code != 400 || !strings.Contains(body, "не должен совпадать") {
		t.Errorf("password equal to the login: %d", code)
	}
	if code, _ := c.register("Login_One", "password1"); code != 303 {
		t.Fatalf("register (upper case is folded): %d", code)
	}
	acc, err := st.AccountByUsername(context.Background(), "login_one")
	if err != nil || acc.UserName != "login_one" {
		t.Fatalf("the VPN user is named like the login: %v %+v", err, acc)
	}
	other := newSiteClient(t, srv)
	if code, _, h := other.post("/login", url.Values{"username": {"LOGIN_ONE"}, "password": {"password1"}}, true); code != 303 || h.Get("Location") != "/cabinet" {
		t.Errorf("login: %d %v", code, h)
	}
	if code, body, _ := newSiteClient(t, srv).post("/login", url.Values{"username": {"login_one"}, "password": {"nope-nope"}}, true); code != 401 || !strings.Contains(body, "Неверный логин или пароль") {
		t.Errorf("wrong password: %d", code)
	}
	if code, _ := newSiteClient(t, srv).register("login_one", "password1"); code != 409 {
		t.Errorf("taken login: %d", code)
	}
}

func TestTelegramLogin(t *testing.T) {
	cfg := siteTestCfg()
	cfg.SiteDomain = "vpn.example.com"
	cfg.BotToken = "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
	site, st, srv := startSite(t, cfg)
	ctx := context.Background()
	cleanNames(t, st, "petya_tg", "tg9001")
	setBotName("TestBot")
	defer setBotName("")
	bot := NewBot(cfg, st)

	c := newSiteClient(t, srv)
	if _, body, _ := c.get("/login"); !strings.Contains(body, "/auth/telegram") {
		t.Error("the button is on the login page")
	}
	if code, _, _ := c.post("/auth/telegram", url.Values{}, false); code != 403 {
		t.Errorf("no Origin: %d", code)
	}
	code, body, _ := c.post("/auth/telegram", url.Values{}, true)
	m := regexp.MustCompile(`https://t\.me/TestBot\?start=lg_([0-9a-f]{32})`).FindStringSubmatch(body)
	if code != 200 || m == nil {
		t.Fatalf("waiting page: %d %.300s", code, body)
	}
	token := m[1]
	if code, body, _ := c.get("/auth/telegram/check"); code != 200 || !strings.Contains(body, "lg_"+token) {
		t.Errorf("still waiting: %d", code)
	}

	// the bot shows where the request came from and asks
	r := bot.Respond(ctx, 4242, "/start lg_"+token)
	if !strings.Contains(r.Text, "Вход на сайт") || len(r.Kb) != 1 || r.Kb[0][0].Data != "lgok:"+token || r.Kb[0][1].Data != "lgno:"+token {
		t.Fatalf("prompt: %+v", r)
	}
	if r := bot.Respond(ctx, 4242, "/start lg_deadbeef"); !strings.Contains(r.Text, "не найден") {
		t.Errorf("unknown request: %s", r.Text)
	}
	if r := bot.CallbackAs(ctx, 4242, "lgok:"+token, "petya_tg"); !strings.Contains(r.Text, "Подтверждено") {
		t.Fatalf("confirm: %s", r.Text)
	}
	if r := bot.CallbackAs(ctx, 4242, "lgno:"+token, ""); !strings.Contains(r.Text, "не найден") {
		t.Errorf("an answer counts once: %s", r.Text)
	}
	code, _, h := c.get("/auth/telegram/check")
	if code != 303 || h.Get("Location") != "/cabinet?new=1" {
		t.Fatalf("check: %d %v", code, h)
	}
	acc, err := st.AccountByUsername(ctx, "petya_tg")
	if err != nil || acc.TgChat == nil || *acc.TgChat != 4242 || acc.PassHash != "" || acc.Expires == nil {
		t.Fatalf("new account: %v %+v", err, acc)
	}
	if code, _, _ := c.get("/cabinet"); code != 200 {
		t.Errorf("cabinet after the login: %d", code)
	}
	if code, _, _ := c.get("/auth/telegram/check"); code != 400 {
		t.Errorf("the request is used up: %d", code)
	}
	// no password: a login without one never works
	if code, _, _ := newSiteClient(t, srv).post("/login", url.Values{"username": {"petya_tg"}, "password": {""}}, true); code != 401 {
		t.Errorf("empty password: %d", code)
	}

	// the same chat signs in again: the same account
	c2 := newSiteClient(t, srv)
	_, body, _ = c2.post("/auth/telegram", url.Values{}, true)
	t2 := regexp.MustCompile(`lg_([0-9a-f]{32})`).FindStringSubmatch(body)[1]
	bot.CallbackAs(ctx, 4242, "lgok:"+t2, "other_name")
	if code, _, h := c2.get("/auth/telegram/check"); code != 303 || h.Get("Location") != "/cabinet" {
		t.Errorf("second login: %d %v", code, h)
	}
	var n int
	st.pool.QueryRow(ctx, "SELECT count(*) FROM accounts WHERE tg_chat=4242").Scan(&n)
	if n != 1 {
		t.Errorf("accounts of the chat: %d", n)
	}

	// refusal
	c3 := newSiteClient(t, srv)
	_, body, _ = c3.post("/auth/telegram", url.Values{}, true)
	t3 := regexp.MustCompile(`lg_([0-9a-f]{32})`).FindStringSubmatch(body)[1]
	if r := bot.CallbackAs(ctx, 9001, "lgno:"+t3, "x"); !strings.Contains(r.Text, "отклонён") {
		t.Errorf("deny: %s", r.Text)
	}
	if code, body, _ := c3.get("/auth/telegram/check"); code != 403 || !strings.Contains(body, "отклонён") {
		t.Errorf("denied check: %d", code)
	}

	// an old request is dead
	c4 := newSiteClient(t, srv)
	_, body, _ = c4.post("/auth/telegram", url.Values{}, true)
	t4 := regexp.MustCompile(`lg_([0-9a-f]{32})`).FindStringSubmatch(body)[1]
	st.pool.Exec(ctx, "UPDATE tg_logins SET created = now() - interval '11 minutes'")
	if r := bot.Respond(ctx, 9001, "/start lg_"+t4); !strings.Contains(r.Text, "не найден") {
		t.Errorf("expired: %s", r.Text)
	}

	// registration closed: a known chat gets in, a new one does not
	off := false
	cfg.SiteRegistration = &off
	c5 := newSiteClient(t, srv)
	_, body, _ = c5.post("/auth/telegram", url.Values{}, true)
	t5 := regexp.MustCompile(`lg_([0-9a-f]{32})`).FindStringSubmatch(body)[1]
	bot.CallbackAs(ctx, 9001, "lgok:"+t5, "newbie")
	if code, body, _ := c5.get("/auth/telegram/check"); code != 403 || !strings.Contains(body, "Регистрация закрыта") {
		t.Errorf("closed registration: %d", code)
	}
	if _, err := st.AccountByTgChat(ctx, 9001); err == nil {
		t.Error("no account was created")
	}
	on := true
	cfg.SiteRegistration = &on

	// the person without a password may set one without the old one
	if code, _, _ := c.post("/account/password", url.Values{"csrf": {c.csrf()}, "new": {"brand-new-pass"}}, true); code != 303 {
		t.Fatalf("set the first password: %d", code)
	}
	if code, _, _ := newSiteClient(t, srv).post("/login", url.Values{"username": {"petya_tg"}, "password": {"brand-new-pass"}}, true); code != 303 {
		t.Errorf("login with the new password: %d", code)
	}
	if code, body, _ := c.post("/account/password", url.Values{"csrf": {c.csrf()}, "new": {"another-pass-1"}}, true); code != 400 || !strings.Contains(body, "Текущий пароль неверный") {
		t.Errorf("the second change needs the old password: %d", code)
	}
	_ = site
}

func TestTelegramLoginUnavailable(t *testing.T) {
	cfg := siteTestCfg()
	_, _, srv := startSite(t, cfg)
	setBotName("")
	c := newSiteClient(t, srv)
	if _, body, _ := c.get("/login"); strings.Contains(body, "/auth/telegram") {
		t.Error("no button without a bot")
	}
	if code, _, _ := c.post("/auth/telegram", url.Values{}, true); code != 503 {
		t.Errorf("without a bot: %d", code)
	}
}

type fakeGoogle struct {
	srv  *httptest.Server
	user map[string]any
	code string
}

func newFakeGoogle(t *testing.T) *fakeGoogle {
	f := &fakeGoogle{code: "good-code"}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			r.ParseForm()
			if r.PostForm.Get("code") != f.code || r.PostForm.Get("client_id") != "cid" || r.PostForm.Get("client_secret") != "sec" || r.PostForm.Get("grant_type") != "authorization_code" {
				http.Error(w, `{"error":"invalid_grant"}`, 400)
				return
			}
			w.Write([]byte(`{"access_token":"at-1","token_type":"Bearer"}`))
		case "/info":
			if r.Header.Get("Authorization") != "Bearer at-1" {
				http.Error(w, "no", 401)
				return
			}
			json.NewEncoder(w).Encode(f.user)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	oa, ot, oi := googleAuthURL, googleTokenURL, googleInfoURL
	googleAuthURL, googleTokenURL, googleInfoURL = f.srv.URL+"/auth", f.srv.URL+"/token", f.srv.URL+"/info"
	t.Cleanup(func() { googleAuthURL, googleTokenURL, googleInfoURL = oa, ot, oi })
	return f
}

// googleLogin goes the whole way: the button, the redirect to Google, the return with a code.
func googleLogin(t *testing.T, c *siteClient, ref string) (int, string, http.Header) {
	t.Helper()
	path := "/auth/google"
	if ref != "" {
		path += "?ref=" + ref
	}
	code, _, h := c.get(path)
	loc, _ := url.Parse(h.Get("Location"))
	if code != 303 || loc == nil || loc.Query().Get("state") == "" || loc.Query().Get("client_id") != "cid" || !strings.HasSuffix(loc.Query().Get("redirect_uri"), "/auth/google/callback") {
		t.Fatalf("redirect to Google: %d %v", code, h)
	}
	return c.get("/auth/google/callback?code=good-code&state=" + url.QueryEscape(loc.Query().Get("state")))
}

func TestGoogleLogin(t *testing.T) {
	cfg := siteTestCfg()
	cfg.SiteDomain = "vpn.example.com"
	_, st, srv := startSite(t, cfg)
	ctx := context.Background()
	cleanNames(t, st, "gina", "gina2", "oldtimer", "other_mail")
	c := newSiteClient(t, srv)
	if _, body, _ := c.get("/login"); strings.Contains(body, "/auth/google") {
		t.Error("no Google button without keys")
	}
	if code, _, _ := c.get("/auth/google"); code != 503 {
		t.Errorf("without keys: %d", code)
	}
	cfg.GoogleID, cfg.GoogleSecret = "cid", "sec"
	if _, body, _ := c.get("/login"); !strings.Contains(body, "/auth/google") {
		t.Error("the Google button")
	}
	g := newFakeGoogle(t)

	// a new person
	g.user = map[string]any{"sub": "g-1", "email": "Gina@Example.com", "email_verified": true, "name": "Gina"}
	code, _, h := googleLogin(t, c, "")
	if code != 303 || h.Get("Location") != "/cabinet?new=1" {
		t.Fatalf("first login: %d %v", code, h)
	}
	acc, err := st.AccountByGoogle(ctx, "g-1")
	if err != nil || acc.Username != "gina" || acc.Email != "gina@example.com" || acc.PassHash != "" {
		t.Fatalf("new account: %v %+v", err, acc)
	}
	// the same person again
	g.user["email"] = "changed@example.com"
	if code, _, h := googleLogin(t, newSiteClient(t, srv), ""); code != 303 || h.Get("Location") != "/cabinet" {
		t.Errorf("second login: %d %v", code, h)
	}
	// a second Google account whose address gives the same login name
	g.user = map[string]any{"sub": "g-2", "email": "gina@other.org", "email_verified": true}
	googleLogin(t, newSiteClient(t, srv), "")
	if a2, err := st.AccountByGoogle(ctx, "g-2"); err != nil || a2.Username != "gina2" || a2.ID == acc.ID {
		t.Errorf("name is made unique: %v %+v", err, a2)
	}

	// an old account with the same verified address is linked
	old, err := st.CreateAccountFull(ctx, NewAccount{Username: "oldtimer", Email: "old@example.com", PassHash: "h", TrialDays: 3, Channel: chanAdmin})
	if err != nil {
		t.Fatal(err)
	}
	g.user = map[string]any{"sub": "g-3", "email": "OLD@example.com", "email_verified": true}
	if code, _, h := googleLogin(t, newSiteClient(t, srv), ""); code != 303 || h.Get("Location") != "/cabinet" {
		t.Errorf("link: %d %v", code, h)
	}
	if a3, err := st.AccountByGoogle(ctx, "g-3"); err != nil || a3.ID != old.ID {
		t.Errorf("linked to the old account: %v %+v", err, a3)
	}
	// an unverified address proves nothing: a new account, the old one is untouched
	st.pool.Exec(ctx, "UPDATE accounts SET google_sub=NULL WHERE id=$1", old.ID)
	g.user = map[string]any{"sub": "g-4", "email": "old@example.com", "email_verified": false}
	googleLogin(t, newSiteClient(t, srv), "")
	a4, err := st.AccountByGoogle(ctx, "g-4")
	if err != nil || a4.ID == old.ID || a4.Email != "" {
		t.Errorf("unverified address: %v %+v", err, a4)
	}

	// the state must match; the code must be good
	c2 := newSiteClient(t, srv)
	c2.get("/auth/google")
	if code, _, _ := c2.get("/auth/google/callback?code=good-code&state=forged"); code != 400 {
		t.Errorf("forged state: %d", code)
	}
	if code, _, _ := newSiteClient(t, srv).get("/auth/google/callback?code=good-code&state=x"); code != 400 {
		t.Errorf("no state cookie: %d", code)
	}
	g.code = "other"
	c3 := newSiteClient(t, srv)
	_, _, h = c3.get("/auth/google")
	loc, _ := url.Parse(h.Get("Location"))
	if code, _, _ := c3.get("/auth/google/callback?code=good-code&state=" + url.QueryEscape(loc.Query().Get("state"))); code != 502 {
		t.Errorf("Google refuses the code: %d", code)
	}
	g.code = "good-code"

	// blocked accounts do not get in; closed registration stops newcomers only
	st.SetAccountBlocked(ctx, acc.ID, true)
	g.user = map[string]any{"sub": "g-1", "email": "gina@example.com", "email_verified": true}
	if code, body, _ := googleLogin(t, newSiteClient(t, srv), ""); code != 403 || !strings.Contains(body, "заблокирован") {
		t.Errorf("blocked: %d", code)
	}
	st.SetAccountBlocked(ctx, acc.ID, false)
	off := false
	cfg.SiteRegistration = &off
	g.user = map[string]any{"sub": "g-9", "email": "other_mail@example.com", "email_verified": true}
	if code, body, _ := googleLogin(t, newSiteClient(t, srv), ""); code != 403 || !strings.Contains(body, "Регистрация закрыта") {
		t.Errorf("closed: %d", code)
	}
	g.user = map[string]any{"sub": "g-1", "email": "gina@example.com", "email_verified": true}
	if code, _, _ := googleLogin(t, newSiteClient(t, srv), ""); code != 303 {
		t.Errorf("a known person still gets in: %d", code)
	}
}

func TestLegacyAccountsKeepWorking(t *testing.T) {
	// the migration gave every old account a login made of its e-mail; the unique index keeps them apart
	cfg := siteTestCfg()
	_, st, _ := startSite(t, cfg)
	ctx := context.Background()
	cleanNames(t, st, "legacy1", "legacy1_2")
	if _, err := st.pool.Exec(ctx, `INSERT INTO users(name) VALUES('legacy1') ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateAccountFull(ctx, NewAccount{Username: "legacy1", PassHash: "h", Channel: chanAdmin}); err == nil {
		t.Error("a name taken by a VPN user is not free for a login")
	}
	if u := st.FreeUsername(ctx, "Legacy1"); u != "legacy12" {
		t.Errorf("free name: %s", u)
	}
	if u := st.FreeUsername(ctx, "!!"); !validUsername(u) {
		t.Errorf("a junk wish still gives a valid name: %s", u)
	}
}

func TestMigrationGivesOldAccountsALogin(t *testing.T) {
	cfg := siteTestCfg()
	_, st, _ := startSite(t, cfg)
	ctx := context.Background()
	var ids []int64
	for i, e := range []string{"John.Doe@a.com", "john_doe@b.com", "ab@c.com"} {
		name := "mig-old-" + string(rune('a'+i))
		st.pool.Exec(ctx, "DELETE FROM users WHERE name=$1", name)
		var uid, aid int64
		if err := st.pool.QueryRow(ctx, `INSERT INTO users(name) VALUES($1) RETURNING id`, name).Scan(&uid); err != nil {
			t.Fatal(err)
		}
		if err := st.pool.QueryRow(ctx, `INSERT INTO accounts(email, pass_hash, user_id) VALUES($1,'h',$2) RETURNING id`, e, uid).Scan(&aid); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, aid)
	}
	if _, err := st.pool.Exec(ctx, schemaSQL); err != nil { // the migration runs at every start
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, id := range ids {
		a, err := st.AccountByID(ctx, id)
		if err != nil || !validUsername(a.Username) || seen[a.Username] {
			t.Fatalf("login of an old account: %v %+v", err, a)
		}
		seen[a.Username] = true
	}
	if a, _ := st.AccountByID(ctx, ids[0]); a.Username != "john_doe" {
		t.Errorf("the login comes from the address: %s", a.Username)
	}
}
