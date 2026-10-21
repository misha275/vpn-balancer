package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Three ways to sign in: a login with a password (site.go), Telegram through the bot, and Google.
// Telegram: the browser gets a secret (cookie), the page shows a link t.me/BOT?start=lg_TOKEN; the person opens it, the bot shows
// where the request came from and asks «Да, это я»; the page (it refreshes itself) sees the answer and starts the session.
// Google: the usual OAuth2 code flow; the keys are the settings google_client_id and google_client_secret.

const (
	tgLoginCookie = "tg_login"
	gStateCookie  = "g_state"
)

// Addresses of Google (variables so that tests can point them to a fake server).
var (
	googleAuthURL  = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL = "https://oauth2.googleapis.com/token"
	googleInfoURL  = "https://openidconnect.googleapis.com/v1/userinfo"
)

func (c *Config) googleKeys() (id, secret string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.GoogleID, c.GoogleSecret
}

// authOptions says which buttons the login and registration pages show.
func (s *Site) authOptions(d *pageData) {
	id, sec := s.cfg.googleKeys()
	d.Google = id != "" && sec != "" && s.cfg.siteBaseURL() != ""
	d.Telegram = s.cfg.botToken() != "" && botUsername(s.cfg) != ""
}

// tgToken is the part of the link that the bot receives; it is derived from the browser's secret, so the secret itself never leaves the browser.
func (s *Site) tgToken(secret string) string {
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte("tglogin|" + secret))
	return hex.EncodeToString(m.Sum(nil))[:32]
}

func userAgentShort(r *http.Request) string {
	a := strings.TrimSpace(r.UserAgent())
	if len(a) > 120 {
		a = a[:120]
	}
	return a
}

func (s *Site) setAuthCookie(w http.ResponseWriter, r *http.Request, name, val string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: val, Path: "/", MaxAge: int(ttl.Seconds()), HttpOnly: true, Secure: isTLS(r), SameSite: http.SameSiteLaxMode})
}

func (s *Site) clearAuthCookie(w http.ResponseWriter, r *http.Request, name string) {
	s.setAuthCookie(w, r, name, "", -time.Hour)
}

// loginFail shows the login page with an error.
func (s *Site) loginFail(w http.ResponseWriter, r *http.Request, code int, msg string) {
	d := s.base(r, nil, "", "Вход")
	s.authOptions(&d)
	d.Error = msg
	s.render(w, code, "login", d)
}

// finishLogin starts the session of an account that has just proved who it is.
func (s *Site) finishLogin(w http.ResponseWriter, r *http.Request, acc *Account, created bool) {
	if acc.Blocked {
		msg := "Аккаунт заблокирован."
		if acc.BlockReason != "" {
			msg += " Причина: " + acc.BlockReason + "."
		}
		s.loginFail(w, r, 403, msg+" Обратитесь в поддержку")
		return
	}
	if err := s.startSession(w, r, acc); err != nil {
		log.Printf("site: session: %v", err)
		s.loginFail(w, r, 500, "Временная ошибка, попробуйте ещё раз")
		return
	}
	to := "/cabinet"
	if created {
		to += "?new=1"
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// newPerson creates the account of somebody who came through Telegram or Google.
func (s *Site) newPerson(ctx context.Context, wish string, na NewAccount, ref string) (*Account, error) {
	var err error
	for i := 0; i < 3; i++ { // another person may take the name between the check and the insert
		na.Username = s.st.FreeUsername(ctx, wish)
		na.TrialDays, na.Channel = s.cfg.getSite().TrialDays, s.cfg.getSiteChannel()
		var acc *Account
		if acc, err = s.st.CreateAccountFull(ctx, na); err == nil {
			if reRefCode.MatchString(ref) {
				s.st.AttachReferral(ctx, acc.ID, ref)
			}
			return acc, nil
		}
		if !errors.Is(err, ErrNameTaken) {
			break
		}
	}
	return nil, err
}

// ---- Telegram ----

func (s *Site) telegramStart(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		s.loginFail(w, r, 403, "Запрос отклонён. Откройте страницу входа заново")
		return
	}
	if r.ParseForm() != nil {
		s.loginFail(w, r, 400, "Неверный запрос")
		return
	}
	if s.cfg.botToken() == "" || botUsername(s.cfg) == "" {
		s.loginFail(w, r, 503, "Вход через Telegram сейчас недоступен")
		return
	}
	ip := clientIP(r)
	if s.loginIP.blocked(ip) {
		s.loginFail(w, r, 429, "Слишком много попыток. Подождите 10 минут")
		return
	}
	s.loginIP.hit(ip)
	secret, err := newToken()
	ref := r.PostForm.Get("ref")
	if !reRefCode.MatchString(ref) {
		ref = ""
	}
	if err == nil {
		err = s.st.NewTgLogin(r.Context(), s.tgToken(secret), secret, ip, userAgentShort(r), ref)
	}
	if err != nil {
		log.Printf("site: tg login: %v", err)
		s.loginFail(w, r, 500, "Временная ошибка, попробуйте ещё раз")
		return
	}
	s.setAuthCookie(w, r, tgLoginCookie, secret, 10*time.Minute)
	s.tgWaitPage(w, r, secret, 200, "")
}

func (s *Site) tgWaitPage(w http.ResponseWriter, r *http.Request, secret string, code int, msg string) {
	d := s.base(r, nil, "", "Вход через Telegram")
	d.TgLink = "https://t.me/" + botUsername(s.cfg) + "?start=lg_" + s.tgToken(secret)
	d.Error = msg
	w.Header().Set("Refresh", "4; url=/auth/telegram/check")
	s.render(w, code, "tglogin", d)
}

func (s *Site) telegramCheck(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(tgLoginCookie)
	if err != nil || c.Value == "" {
		s.loginFail(w, r, 400, "Запрос входа не найден. Нажмите «Войти через Telegram» ещё раз")
		return
	}
	state, chat, name, ref, err := s.st.TgLoginTake(r.Context(), c.Value)
	if err != nil {
		log.Printf("site: tg login: %v", err)
		s.tgWaitPage(w, r, c.Value, 200, "")
		return
	}
	switch state {
	case "wait":
		s.tgWaitPage(w, r, c.Value, 200, "")
		return
	case "ok":
	case "no":
		s.clearAuthCookie(w, r, tgLoginCookie)
		s.loginFail(w, r, 403, "Вход отклонён в Telegram")
		return
	default:
		s.clearAuthCookie(w, r, tgLoginCookie)
		s.loginFail(w, r, 400, "Запрос входа устарел. Нажмите «Войти через Telegram» ещё раз")
		return
	}
	s.clearAuthCookie(w, r, tgLoginCookie)
	acc, err := s.st.AccountByTgChat(r.Context(), chat)
	created := false
	if errors.Is(err, ErrNotFound) {
		if !s.cfg.getSite().Registration {
			s.loginFail(w, r, 403, "Регистрация закрыта. Этот Telegram не привязан ни к одному аккаунту")
			return
		}
		wish := strings.TrimPrefix(name, "@")
		if wish == "" {
			wish = "tg" + strconv.FormatInt(chat, 10)
		}
		acc, err = s.newPerson(r.Context(), wish, NewAccount{TgChat: chat}, ref)
		created = true
	}
	if err != nil {
		log.Printf("site: tg login: %v", err)
		s.loginFail(w, r, 500, "Временная ошибка, попробуйте ещё раз")
		return
	}
	s.finishLogin(w, r, acc, created)
}

// ---- Google ----

func (s *Site) googleRedirectURI() string { return s.cfg.siteBaseURL() + "/auth/google/callback" }

func (s *Site) googleStart(w http.ResponseWriter, r *http.Request) {
	id, sec := s.cfg.googleKeys()
	if id == "" || sec == "" || s.cfg.siteBaseURL() == "" {
		s.loginFail(w, r, 503, "Вход через Google сейчас недоступен")
		return
	}
	ip := clientIP(r)
	if s.loginIP.blocked(ip) {
		s.loginFail(w, r, 429, "Слишком много попыток. Подождите 10 минут")
		return
	}
	s.loginIP.hit(ip)
	state, err := newToken()
	if err != nil {
		s.loginFail(w, r, 500, "Временная ошибка, попробуйте ещё раз")
		return
	}
	ref := r.URL.Query().Get("ref")
	if !reRefCode.MatchString(ref) {
		ref = ""
	}
	s.setAuthCookie(w, r, gStateCookie, state+"|"+ref, 10*time.Minute)
	q := url.Values{"client_id": {id}, "redirect_uri": {s.googleRedirectURI()}, "response_type": {"code"}, "scope": {"openid email profile"}, "state": {state}, "prompt": {"select_account"}}
	http.Redirect(w, r, googleAuthURL+"?"+q.Encode(), http.StatusSeeOther)
}

var googleHTTP = &http.Client{Timeout: 12 * time.Second}

type googleUser struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
}

func (s *Site) googleFetch(ctx context.Context, code string) (*googleUser, error) {
	id, sec := s.cfg.googleKeys()
	form := url.Values{"code": {code}, "client_id": {id}, "client_secret": {sec}, "redirect_uri": {s.googleRedirectURI()}, "grant_type": {"authorization_code"}}
	req, _ := http.NewRequestWithContext(ctx, "POST", googleTokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := googleHTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var tok struct {
		Access string `json:"access_token"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&tok) != nil || tok.Access == "" {
		return nil, errors.New("google: token answer " + resp.Status)
	}
	req, _ = http.NewRequestWithContext(ctx, "GET", googleInfoURL, nil)
	req.Header.Set("Authorization", "Bearer "+tok.Access)
	resp2, err := googleHTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp2.Body.Close()
	var u googleUser
	if resp2.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp2.Body, 1<<16)).Decode(&u) != nil || u.Sub == "" {
		return nil, errors.New("google: userinfo answer " + resp2.Status)
	}
	return &u, nil
}

func (s *Site) googleCallback(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(gStateCookie)
	s.clearAuthCookie(w, r, gStateCookie)
	state, ref, _ := strings.Cut(func() string {
		if c != nil {
			return c.Value
		}
		return ""
	}(), "|")
	q := r.URL.Query()
	if err != nil || state == "" || !hmac.Equal([]byte(state), []byte(q.Get("state"))) {
		s.loginFail(w, r, 400, "Вход через Google не удался: запрос устарел. Попробуйте ещё раз")
		return
	}
	if q.Get("code") == "" {
		s.loginFail(w, r, 400, "Вход через Google отменён")
		return
	}
	u, err := s.googleFetch(r.Context(), q.Get("code"))
	if err != nil {
		log.Printf("site: %v", err)
		s.loginFail(w, r, 502, "Google не ответил. Попробуйте ещё раз")
		return
	}
	email := normEmail(u.Email)
	acc, err := s.st.AccountByGoogle(r.Context(), u.Sub)
	created := false
	if errors.Is(err, ErrNotFound) && u.EmailVerified && email != "" {
		// an old account that was registered with this address: Google proves the address, so it is linked
		if old, e := s.st.AccountByEmail(r.Context(), email); e == nil && old.GoogleSub == "" {
			if e := s.st.SetGoogle(r.Context(), old.ID, u.Sub, email); e == nil {
				acc, err = old, nil
			}
		}
	}
	if errors.Is(err, ErrNotFound) {
		if !s.cfg.getSite().Registration {
			s.loginFail(w, r, 403, "Регистрация закрыта. Этот Google-аккаунт не привязан ни к одному аккаунту сайта")
			return
		}
		wish := email
		if i := strings.Index(wish, "@"); i > 0 {
			wish = wish[:i]
		}
		if wish == "" {
			wish = "user"
		}
		na := NewAccount{GoogleSub: u.Sub}
		if _, e := s.st.AccountByEmail(r.Context(), email); u.EmailVerified && email != "" && errors.Is(e, ErrNotFound) {
			na.Email = email
		}
		acc, err = s.newPerson(r.Context(), wish, na, ref)
		created = true
	}
	if err != nil {
		log.Printf("site: google login: %v", err)
		s.loginFail(w, r, 500, "Временная ошибка, попробуйте ещё раз")
		return
	}
	s.finishLogin(w, r, acc, created)
}
