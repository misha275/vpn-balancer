package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// SITE_DEMO=127.0.0.1:18990 (public site) with TEST_DATABASE_URL: the real site and panel on a scratch database, to look at the pages.
// The panel is served on the next port, token demo.
func TestSiteDemo(t *testing.T) {
	addr := os.Getenv("SITE_DEMO")
	if addr == "" {
		t.Skip("set SITE_DEMO=127.0.0.1:18990")
	}
	cfg := siteTestCfg()
	cfg.SiteAllowHTTP = true
	cfg.SiteSupport = "Telegram: @example_support"
	st := testStore(t)
	for _, tbl := range []string{"accounts", "payments", "web_sessions"} {
		st.pool.Exec(context.Background(), "TRUNCATE "+tbl+" CASCADE")
	}
	ctx := context.Background()
	hash, _ := bcrypt.GenerateFromPassword([]byte("password1"), bcrypt.MinCost)
	for i, e := range []struct {
		email string
		days  int
	}{{"anna@example.com", 21}, {"boris@example.com", 3}, {"clara@example.com", 0}} {
		acc, err := st.CreateAccount(ctx, e.email, string(hash), e.days)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			st.AddTraffic(ctx, time.Now(), map[string]UserDelta{acc.UserName: {Up: 300 << 20, Down: 12 << 30, Conns: 940}})
		}
		if e.days == 0 {
			st.SetUserExpiry(ctx, acc.UserID, nil)
		}
	}
	plans, _ := st.ListPlans(ctx, true)
	acc, _ := st.AccountByEmail(ctx, "boris@example.com")
	if len(plans) > 0 {
		st.CreatePayment(ctx, acc.ID, plans[0], "stub")
	}
	site := NewSite(cfg, st)
	a := NewAPI(cfg, st, nil, nil, "demo", make(chan struct{}, 1))
	outer := http.NewServeMux()
	outer.HandleFunc("GET /api/overview", a.auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"snapshot": map[string]any{"nodes": []any{}, "modes": []any{}}, "switches": []any{}, "ready": true})
	}))
	outer.HandleFunc("GET /api/users", a.auth(a.users))
	outer.HandleFunc("GET /api/settings", a.auth(func(w http.ResponseWriter, r *http.Request) {
		help := map[string]string{}
		for _, d := range settingDefs {
			help[d.key] = d.help
		}
		writeJSON(w, 200, map[string]any{"values": cfg.Effective(), "overridden": []string{}, "help": help})
	}))
	a2 := &API{cfg: cfg, store: st, token: "demo", fails: map[string][]time.Time{}}
	a2.site = nil
	inner := http.NewServeMux()
	a2.Register(inner)
	outer.Handle("/", inner)
	host, port, _ := net.SplitHostPort(addr)
	pl, _ := net.Listen("tcp", net.JoinHostPort(host, port))
	go http.Serve(pl, site.Handler())
	p, _ := net.LookupPort("tcp", port)
	al, err := net.Listen("tcp", net.JoinHostPort(host, itoa(int64(p+1))))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("site http://%s  panel http://%s token demo", addr, al.Addr())
	_ = http.Serve(al, outer)
}
