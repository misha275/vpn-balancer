package main

import (
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

//go:embed ui.html
var uiHTML []byte

// API is the control interface: the web panel and the command line use it.
// Reading statistics (/status, /metrics, /healthz) needs no token, as before;
// everything that shows secrets or changes something needs "Authorization: Bearer <token>".
// By default the interface listens on 127.0.0.1 only (use an SSH tunnel from outside).
type API struct {
	cfg     *Config
	store   *Store
	chk     *Checker
	core    *Core
	token   string
	refresh chan struct{}

	mu    sync.Mutex
	fails map[string][]time.Time
}

func NewAPI(cfg *Config, st *Store, chk *Checker, core *Core, token string, refresh chan struct{}) *API {
	return &API{cfg: cfg, store: st, chk: chk, core: core, token: token, refresh: refresh, fails: map[string][]time.Time{}}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func apiErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func (a *API) tooManyFails(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	cut := time.Now().Add(-10 * time.Minute)
	keep := a.fails[ip][:0]
	for _, t := range a.fails[ip] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	a.fails[ip] = keep
	return len(keep) >= 10
}

// auth wraps a handler with the token check and a brake against guessing.
func (a *API) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if a.tooManyFails(ip) {
			apiErr(w, http.StatusTooManyRequests, fmt.Errorf("слишком много неверных попыток, подождите 10 минут"))
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if a.token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(a.token)) != 1 {
			a.mu.Lock()
			a.fails[ip] = append(a.fails[ip], time.Now())
			a.mu.Unlock()
			apiErr(w, http.StatusUnauthorized, fmt.Errorf("нужен токен (команда `balancer token`)"))
			return
		}
		h(w, r)
	}
}

func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Write(uiHTML)
	})
	mux.HandleFunc("GET /api/overview", a.auth(a.overview))
	mux.HandleFunc("GET /api/settings", a.auth(a.getSettings))
	mux.HandleFunc("PUT /api/settings", a.auth(a.putSettings))
	mux.HandleFunc("DELETE /api/settings/{key}", a.auth(a.resetSetting))
	mux.HandleFunc("GET /api/users", a.auth(a.users))
	mux.HandleFunc("POST /api/users", a.auth(a.addUser))
	mux.HandleFunc("POST /api/users/{name}/{op}", a.auth(a.userOp))
	mux.HandleFunc("POST /api/pin", a.auth(a.pin))
	mux.HandleFunc("POST /api/refresh", a.auth(a.doRefresh))
	mux.HandleFunc("POST /api/recheck", a.auth(a.recheck))
}

func (a *API) overview(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	sw, _ := a.store.RecentSwitches(ctx, 20)
	writeJSON(w, 200, map[string]any{"snapshot": a.chk.Snapshot(), "switches": sw, "ready": a.core.Ready()})
}

// settingsView returns the effective values, which of them are overridden in the database, and help texts.
func (a *API) settingsView(ctx context.Context) (map[string]any, error) {
	stored, _, err := a.store.LoadSettings(ctx)
	if err != nil {
		return nil, err
	}
	over := []string{}
	help := map[string]string{}
	for _, d := range settingDefs {
		help[d.key] = d.help
		if _, ok := stored[d.key]; ok {
			over = append(over, d.key)
		}
	}
	return map[string]any{"values": a.cfg.Effective(), "overridden": over, "help": help}, nil
}

func (a *API) getSettings(w http.ResponseWriter, r *http.Request) {
	v, err := a.settingsView(r.Context())
	if err != nil {
		apiErr(w, 500, err)
		return
	}
	writeJSON(w, 200, v)
}

func (a *API) putSettings(w http.ResponseWriter, r *http.Request) {
	var m map[string]json.RawMessage
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&m); err != nil || len(m) == 0 {
		apiErr(w, 400, fmt.Errorf("ожидается JSON {настройка: значение}"))
		return
	}
	if err := ValidateSettings(m); err != nil {
		apiErr(w, 400, err)
		return
	}
	for k, raw := range m {
		if err := a.store.PutSetting(r.Context(), k, raw); err != nil {
			apiErr(w, 500, err)
			return
		}
	}
	if err := a.cfg.ApplySettings(m); err != nil {
		apiErr(w, 400, err)
		return
	}
	a.afterSettings(m)
	v, _ := a.settingsView(r.Context())
	writeJSON(w, 200, v)
}

func (a *API) resetSetting(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if settingDefFor(key) == nil {
		apiErr(w, 400, fmt.Errorf("неизвестная настройка %q", key))
		return
	}
	if err := a.store.DeleteSetting(r.Context(), key); err != nil {
		apiErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "сброшено; значение из config.yaml вернётся после перезапуска"})
}

// afterSettings triggers whatever has to happen right away after a change.
func (a *API) afterSettings(m map[string]json.RawMessage) {
	_, sub := m["subscriptions"]
	_, id := m["node_identity"]
	if sub || id {
		a.kick()
	}
	if _, ok := m["blocked_exit_countries"]; ok {
		go a.chk.evaluate(false)
	}
}

func (a *API) kick() {
	select {
	case a.refresh <- struct{}{}:
	default:
	}
}

type userView struct {
	Name         string `json:"name"`
	Enabled      bool   `json:"enabled"`
	Gateway      string `json:"gateway"`
	Subscription string `json:"subscription"`
}

func (a *API) users(w http.ResponseWriter, r *http.Request) {
	us, err := a.store.ListUsers(r.Context())
	if err != nil {
		apiErr(w, 500, err)
		return
	}
	out := []userView{}
	for _, u := range us {
		out = append(out, userView{u.Name, u.Enabled, userLink(a.cfg, a.cfg.getGatewayName(), u.UUID), subURL(a.cfg, u.SubToken)})
	}
	writeJSON(w, 200, out)
}

func (a *API) addUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil || strings.TrimSpace(in.Name) == "" || len(in.Name) > 64 {
		apiErr(w, 400, fmt.Errorf("нужно имя пользователя (до 64 символов)"))
		return
	}
	if _, err := a.store.AddUser(r.Context(), strings.TrimSpace(in.Name)); err != nil {
		apiErr(w, 409, fmt.Errorf("не удалось создать (имя занято?): %v", err))
		return
	}
	a.users(w, r)
}

func (a *API) userOp(w http.ResponseWriter, r *http.Request) {
	name, op := r.PathValue("name"), r.PathValue("op")
	if op != "enable" && op != "disable" {
		apiErr(w, 400, fmt.Errorf("операция enable или disable"))
		return
	}
	if err := a.store.SetUserEnabled(r.Context(), name, op == "enable"); err != nil {
		apiErr(w, 404, err)
		return
	}
	a.users(w, r)
}

func (a *API) pin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Node string `json:"node"`
	}
	json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in)
	if strings.TrimSpace(in.Node) == "" {
		a.chk.Unpin()
		writeJSON(w, 200, map[string]string{"ok": "закрепление снято, выбор автоматический"})
		return
	}
	n, err := a.chk.Pin(in.Node)
	if err != nil {
		apiErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "закреплён узел «" + n.Name + "»"})
}

func (a *API) doRefresh(w http.ResponseWriter, r *http.Request) {
	a.kick()
	writeJSON(w, 200, map[string]string{"ok": "подписки будут скачаны сейчас"})
}

func (a *API) recheck(w http.ResponseWriter, r *http.Request) {
	a.chk.ForceGeo(r.Context())
	writeJSON(w, 200, map[string]string{"ok": "страна выхода будет измерена заново для всех узлов"})
}

// WatchSettings applies the stored settings now and then keeps applying changes made through the
// command line (they only touch the database).
func WatchSettings(ctx context.Context, cfg *Config, st *Store, onChange func(map[string]json.RawMessage)) {
	last := ""
	apply := func() {
		m, stamp, err := st.LoadSettings(ctx)
		if err != nil || stamp == last {
			return
		}
		first := last == ""
		last = stamp
		good := map[string]json.RawMessage{}
		for k, raw := range m {
			if err := ValidateSettings(map[string]json.RawMessage{k: raw}); err != nil {
				log.Printf("settings: %s skipped: %v", k, err)
				continue
			}
			good[k] = raw
		}
		if len(good) == 0 {
			return
		}
		if err := cfg.ApplySettings(good); err != nil {
			log.Printf("settings: %v", err)
			return
		}
		keys := make([]string, 0, len(good))
		for k := range good {
			keys = append(keys, k)
		}
		log.Printf("settings: applied from database: %s", strings.Join(keys, ", "))
		if !first && onChange != nil {
			onChange(good)
		}
	}
	apply() // the first application is synchronous: the config must be right before sing-box starts
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				apply()
			}
		}
	}()
}
