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
	for _, tbl := range []string{"bundles", "custom_nodes", "ext_sources"} {
		st.pool.Exec(ctx, "TRUNCATE "+tbl+" CASCADE")
	}
	ownLink := func(h string) string {
		return "vless://" + testUUID + "@" + h + ":443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=" + testPBK + "&sid=ab12&type=tcp#x"
	}
	n1, _ := st.SaveCustomNode(ctx, customNodeInput{Name: "🇳🇱 NL свой", Link: ownLink("nl.nvrk.ytc-srv.org"), Note: "Hetzner"})
	n2, _ := st.SaveCustomNode(ctx, customNodeInput{Name: "🇫🇮 FI свой", Link: ownLink("fi.nvrk.ytc-srv.org")})
	n3, _ := st.SaveCustomNode(ctx, customNodeInput{Name: "🇩🇪 DE игры", Link: ownLink("de.nvrk.ytc-srv.org")})
	n4, _ := st.SaveCustomNode(ctx, customNodeInput{Name: "🇺🇸 US партнёр", Link: ownLink("us.partner.example.com"), Mode: "via"})
	sid, _ := st.SaveExtSource(ctx, extSourceInput{Name: "Партнёр A", URL: "https://sub.partner.example.com/token", Mode: "via"})
	st.ImportSource(ctx, sid, ownLink("a1.partner.example.com")+"\n"+ownLink("a2.partner.example.com"), time.Hour)
	sid2, _ := st.SaveExtSource(ctx, extSourceInput{Name: "Резерв B", URL: "https://sub.reserve.example.com/token", Mode: "direct"})
	st.ImportSource(ctx, sid2, ownLink("b1.reserve.example.com"), time.Hour)
	st.SaveBundle(ctx, Bundle{Slug: "partner", Name: "Партнёры", Enabled: true, Sort: 2, Main: true, Nodes: []int64{n4}, Sources: []int64{sid}})
	st.SaveBundle(ctx, Bundle{Slug: "vip", Name: "VIP", Enabled: true, Nodes: []int64{n1, n2}})
	st.SaveBundle(ctx, Bundle{Slug: "games", Name: "Игры", Enabled: true, Sort: 1, Nodes: []int64{n3}})
	for d := 0; d < 30; d++ {
		if d%4 != 3 {
			st.AddTraffic(ctx, time.Now().Add(-time.Duration(d*24+d%5)*time.Hour), map[string]UserDelta{"anna@example.com": {Up: int64(20+d*7%40) << 20, Down: int64(300+d*53%900) << 20, Conns: int64(30 + d)}})
		}
	}
	st.pool.Exec(ctx, "DELETE FROM plans")
	st.pool.Exec(ctx, "DELETE FROM settings WHERE key='plans_seeded'")
	st.seedPlans(ctx)
	pl0, _ := st.ListPlans(ctx, false)
	pl0[1].Subs = []string{"balancers", "all", "b:vip"}
	pl0[2].Subs = []string{"balancers", "all", "b:vip", "b:games"}
	st.SavePlan(ctx, pl0[1])
	st.SavePlan(ctx, pl0[2])
	st.SetUserSubs(ctx, "clara@example.com", []string{"balancers", "b:games"})
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
