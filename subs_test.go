package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const customLink = "vless://" + testUUID + "@own1.example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=" + testPBK + "&sid=ab12&type=tcp#original"

func subsStore(t *testing.T) (*Store, *Config) {
	st := testStore(t)
	ctx := context.Background()
	for _, tbl := range []string{"bundles", "custom_nodes", "accounts", "payments", "web_sessions"} {
		st.pool.Exec(ctx, "TRUNCATE "+tbl+" CASCADE")
	}
	return st, modesSubCfg()
}

func fetchLines(t *testing.T, srv *httptest.Server, path string) (int, []string) {
	t.Helper()
	resp, err := http.Get(srv.URL + path + "?raw=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return resp.StatusCode, nil
	}
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l != "" {
			lines = append(lines, l)
		}
	}
	return resp.StatusCode, lines
}

func TestBundlesAreDeliveredOnlyAsSubscriptions(t *testing.T) {
	st, cfg := subsStore(t)
	ctx := context.Background()
	st.AddUser(ctx, "vip")
	us, _ := st.ListUsers(ctx)
	var u User
	for _, x := range us {
		if x.Name == "vip" {
			u = x
		}
	}
	id1, err := st.SaveCustomNode(ctx, customNodeInput{Name: "Own NL", Link: customLink})
	if err != nil {
		t.Fatal(err)
	}
	off := false
	id2, _ := st.SaveCustomNode(ctx, customNodeInput{Name: "Own off", Link: customLink, Enabled: &off})
	if _, err := st.SaveCustomNode(ctx, customNodeInput{Name: "bad", Link: "http://example.com"}); err == nil {
		t.Error("a link that is not a node must be rejected")
	}
	if _, err := st.SaveCustomNode(ctx, customNodeInput{Name: "bad", Link: customLink + "\nvless://x"}); err == nil {
		t.Error("one link per node")
	}
	if _, err := st.SaveBundle(ctx, Bundle{Slug: "all", Name: "x"}); err == nil {
		t.Error("the slug of a built-in subscription is taken")
	}
	if _, err := st.SaveBundle(ctx, Bundle{Slug: "Bad Slug", Name: "x"}); err == nil {
		t.Error("bad slug")
	}
	bid, err := st.SaveBundle(ctx, Bundle{Slug: "vip", Name: "VIP", Enabled: true, Nodes: []int64{id1, id2}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveBundle(ctx, Bundle{ID: bid, Slug: "other", Name: "VIP"}); err == nil {
		t.Error("the slug of a bundle cannot change: it is written into the lists of users")
	}

	srv := httptest.NewServer(NewSubServer(cfg, st).Handler())
	defer srv.Close()

	// by default a user has the two built-in subscriptions, not the bundle
	if code, _ := fetchLines(t, srv, "/sub/"+u.SubToken+"/b/vip"); code != 403 {
		t.Fatalf("a bundle outside the list: %d", code)
	}
	code, all := fetchLines(t, srv, "/sub/"+u.SubToken)
	if code != 200 || len(all) < 3 {
		t.Fatalf("default subscription: %d %v", code, all)
	}
	for _, l := range all {
		if strings.Contains(l, "own1.example.com") {
			t.Error("own nodes must not reach users who were not given the bundle")
		}
	}

	// own list: the bundle and nothing else
	if err := st.SetUserSubs(ctx, "vip", []string{"b:vip"}); err != nil {
		t.Fatal(err)
	}
	code, only := fetchLines(t, srv, "/sub/"+u.SubToken+"/b/vip")
	if code != 200 || len(only) != 1 || !strings.Contains(only[0], "own1.example.com") || !strings.HasSuffix(only[0], "#Own%20NL") {
		t.Fatalf("bundle: %d %v (a switched-off node stays out, the name is the administrator's)", code, only)
	}
	if code, _ := fetchLines(t, srv, "/sub/"+u.SubToken+"/all"); code != 403 {
		t.Errorf("built-in subscription outside the list: %d", code)
	}
	if code, _ := fetchLines(t, srv, "/sub/"+u.SubToken+"/balancers"); code != 403 {
		t.Errorf("balancers outside the list: %d", code)
	}
	if _, un := fetchLines(t, srv, "/sub/"+u.SubToken); len(un) != 1 {
		t.Errorf("the main address gives the union of what is allowed: %v", un)
	}
	// without the balancer there is no gateway key
	u2, _ := st.UserBySubToken(ctx, u.SubToken)
	ix2, err := st.LoadSubIndex(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := ix2.access(cfg, *u2); m {
		t.Error("a user without balancers/all must not get the gateway key")
	}
	// back to the default
	st.SetUserSubs(ctx, "vip", nil)
	u3, _ := st.UserBySubToken(ctx, u.SubToken)
	if m, _ := ix2.access(cfg, *u3); !m {
		t.Error("nil returns the default list")
	}

	// deleting the bundle removes its key everywhere
	st.SetUserSubs(ctx, "vip", []string{"balancers", "b:vip"})
	if key, err := st.DeleteBundle(ctx, bid); err != nil || key != "b:vip" {
		t.Fatalf("delete: %q %v", key, err)
	}
	u4, _ := st.UserBySubToken(ctx, u.SubToken)
	if len(u4.Subs) != 1 || u4.Subs[0] != "balancers" {
		t.Errorf("the key is removed from the list: %v", u4.Subs)
	}
	// own nodes stay (they may go into another bundle)
	if ns, _ := st.ListCustomNodes(ctx); len(ns) != 2 {
		t.Errorf("nodes after deleting the bundle: %d", len(ns))
	}
	if err := st.DeleteCustomNode(ctx, id1); err != nil {
		t.Error(err)
	}
}

func TestPlanSubscriptionsAndPriority(t *testing.T) {
	st, cfg := subsStore(t)
	ctx := context.Background()
	st.pool.Exec(ctx, "DELETE FROM plans")
	nid, _ := st.SaveCustomNode(ctx, customNodeInput{Name: "P1", Link: customLink})
	st.SaveBundle(ctx, Bundle{Slug: "premium", Name: "Premium", Enabled: true, Nodes: []int64{nid}})
	basic, err := st.SavePlan(ctx, Plan{Name: "Basic", Days: 30, PriceCents: 100, Enabled: true, Subs: []string{"balancers"}})
	if err != nil {
		t.Fatal(err)
	}
	prem, err := st.SavePlan(ctx, Plan{Name: "Premium", Days: 30, PriceCents: 500, Enabled: true, Subs: []string{"all", "b:premium"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SavePlan(ctx, Plan{Name: "Bad", Days: 30, Subs: []string{"nonsense"}}); err == nil {
		t.Error("a bad key in a plan")
	}
	hash := "x"
	acc, _ := st.CreateAccount(ctx, "plan@example.com", hash, 3)
	keys := func() ([]string, string) {
		a, _ := st.AccountByID(ctx, acc.ID)
		return effectiveSubs(cfg, a.User())
	}
	if k, src := keys(); src != "default" || !hasSub(k, "all") {
		t.Fatalf("trial: %v %s", k, src)
	}
	pay := func(plan int64) {
		ps, _ := st.ListPlans(ctx, false)
		for _, p := range ps {
			if p.ID == plan {
				pm, err := st.CreatePayment(ctx, acc.ID, p, "stub")
				if err != nil {
					t.Fatal(err)
				}
				if ok, err := st.MarkPaid(ctx, pm.ID); !ok || err != nil {
					t.Fatal(ok, err)
				}
			}
		}
	}
	pay(basic)
	if k, src := keys(); src != "plan" || len(k) != 1 || k[0] != "balancers" {
		t.Fatalf("after Basic: %v %s", k, src)
	}
	pay(prem)
	if k, src := keys(); src != "plan" || !hasSub(k, "b:premium") {
		t.Fatalf("after Premium: %v %s", k, src)
	}
	// editing the plan changes everybody who has it, at once
	st.SavePlan(ctx, Plan{ID: prem, Name: "Premium", Days: 30, PriceCents: 500, Enabled: true, Subs: []string{"all"}})
	if k, _ := keys(); hasSub(k, "b:premium") {
		t.Error("a change of the plan applies to its users")
	}
	// own list wins over the plan
	st.SetUserSubs(ctx, acc.UserName, []string{"balancers", "all"})
	if k, src := keys(); src != "user" || len(k) != 2 {
		t.Errorf("own list: %v %s", k, src)
	}
	st.SetUserSubs(ctx, acc.UserName, nil)
	// deleting the plan returns the user to the default
	st.DeletePlan(ctx, prem)
	if _, src := keys(); src != "default" {
		t.Errorf("deleted plan: %s", src)
	}
	st.SetUserPlan(ctx, acc.UserName, basic)
	if _, src := keys(); src != "plan" {
		t.Error("an administrator can assign a plan")
	}
	st.pool.Exec(ctx, "DELETE FROM plans")
	st.pool.Exec(ctx, "DELETE FROM settings WHERE key='plans_seeded'")
	st.seedPlans(ctx)
}

func TestUserStatsOf(t *testing.T) {
	st, _ := subsStore(t)
	ctx := context.Background()
	st.AddUser(ctx, "stat")
	now := time.Now()
	st.AddTraffic(ctx, now, map[string]UserDelta{"stat": {Up: 1 << 20, Down: 9 << 20, Conns: 4}})
	st.AddTraffic(ctx, now.Add(-72*time.Hour), map[string]UserDelta{"stat": {Up: 2 << 20, Down: 3 << 20, Conns: 1}})
	s, err := st.UserStatsOf(ctx, "stat", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Days) != 30 || len(s.Hours) != 48 {
		t.Fatalf("series: %d days %d hours", len(s.Days), len(s.Hours))
	}
	if s.AllUp != 3<<20 || s.AllDown != 12<<20 || s.AllConns != 5 {
		t.Errorf("totals: %+v", s)
	}
	if s.Today != 10<<20 || s.Last7 != 15<<20 || s.Last30 != 15<<20 {
		t.Errorf("periods: today=%d 7d=%d 30d=%d", s.Today, s.Last7, s.Last30)
	}
	if s.BusiestHr < 0 || s.FirstSeen == 0 {
		t.Errorf("busiest/first: %d %d", s.BusiestHr, s.FirstSeen)
	}
	last := s.Hours[len(s.Hours)-1]
	if last.Up+last.Down != 10<<20 {
		t.Errorf("the current hour: %+v", last)
	}
	if s2, err := st.UserStatsOf(ctx, "nobody", now); err != nil || s2.AllUp != 0 || s2.BusiestHr != -1 {
		t.Errorf("unknown user: %+v %v", s2, err)
	}
}

func TestAdminSubsAPI(t *testing.T) {
	st, cfg := subsStore(t)
	ctx := context.Background()
	st.AddUser(ctx, "carol")
	a := NewAPI(cfg, st, nil, nil, "tok", make(chan struct{}, 1))
	mux := http.NewServeMux()
	a.registerSite(mux)
	a.registerSubs(mux)
	mux.HandleFunc("GET /api/users", a.auth(a.users))
	h := &adminT{t: t, mux: mux}

	code, m, raw := h.do("POST", "/api/custom-nodes", map[string]any{"name": "My node", "link": customLink, "note": "hetzner"})
	if code != 200 {
		t.Fatalf("add node: %d %s", code, raw)
	}
	if strings.Contains(string(raw), "own1.example.com/") || strings.Contains(string(raw), "vless://") || strings.Contains(string(raw), testUUID) {
		t.Fatalf("the link of a node must never come back from the API: %s", raw)
	}
	nodes := m["nodes"].([]any)
	n0 := nodes[0].(map[string]any)
	if n0["server"] != "own1.example.com" || n0["type"] != "vless" {
		t.Errorf("node view: %v", n0)
	}
	nid := int64(n0["id"].(float64))
	if code, _, _ := h.do("POST", "/api/custom-nodes", map[string]any{"name": "x", "link": "nonsense"}); code != 400 {
		t.Errorf("bad link: %d", code)
	}
	// rename without resending the link keeps the link
	if code, _, _ := h.do("PUT", fmt.Sprintf("/api/custom-nodes/%d", nid), map[string]any{"name": "Renamed", "note": ""}); code != 200 {
		t.Fatalf("rename: %d", code)
	}
	if ns, _ := st.ListCustomNodes(ctx); len(ns) != 1 || ns[0].Name != "Renamed" || ns[0].Server != "own1.example.com" {
		t.Errorf("the link is kept on rename: %+v", ns)
	}

	code, m, raw = h.do("POST", "/api/bundles", map[string]any{"slug": "games", "name": "Игры", "enabled": true, "nodes": []int64{nid}})
	if code != 200 {
		t.Fatalf("bundle: %d %s", code, raw)
	}
	if subs := m["subs"].([]any); len(subs) != 3 || subs[2].(map[string]any)["key"] != "b:games" {
		t.Fatalf("catalog subs: %v", m["subs"])
	}
	if code, _, _ := h.do("POST", "/api/bundles", map[string]any{"slug": "games", "name": "dup", "enabled": true}); code != 400 {
		t.Errorf("duplicate slug: %d", code)
	}

	// subscriptions of a user
	if code, _, _ := h.do("POST", "/api/users/carol/subs", map[string]any{"subs": []string{"b:games", "b:games", "all"}}); code != 200 {
		t.Fatal("set subs")
	}
	if code, _, _ := h.do("POST", "/api/users/carol/subs", map[string]any{"subs": []string{"bogus"}}); code != 400 {
		t.Error("bogus key")
	}
	if code, _, _ := h.do("POST", "/api/users/ghost/subs", map[string]any{"subs": []string{"all"}}); code != 404 {
		t.Error("unknown user")
	}
	_, _, body := h.do("GET", "/api/users", nil)
	var uv []userView
	json.Unmarshal(body, &uv)
	if len(uv) != 1 || uv[0].SubSource != "user" || len(uv[0].SubKeys) != 2 || len(uv[0].OwnSubs) != 2 {
		t.Fatalf("user view: %+v", uv)
	}
	if !strings.Contains(uv[0].Subs[0].Title, "Игры") || !strings.HasSuffix(uv[0].Subs[0].Link, "/b/games") {
		t.Errorf("bundle subscription of the user: %+v", uv[0].Subs)
	}

	// the default list and the default term are settings
	if err := cfg.ApplySettings(map[string]json.RawMessage{"user_default_subs": json.RawMessage(`["balancers"]`), "user_default_days": json.RawMessage(`14`)}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSettings(map[string]json.RawMessage{"user_default_subs": json.RawMessage(`["x"]`)}); err == nil {
		t.Error("bad default list")
	}
	if code, _, _ := h.do("POST", "/api/users/carol/subs", map[string]any{"subs": nil}); code != 200 {
		t.Fatal("reset")
	}
	st.AddUser(ctx, "dave")
	us, _ := st.ListUsers(ctx)
	for _, u := range us {
		if u.Name == "dave" {
			if k, src := effectiveSubs(cfg, u); src != "default" || len(k) != 1 {
				t.Errorf("default list: %v %s", k, src)
			}
		}
	}
	if cfg.defaultDays() != 14 {
		t.Error("default days")
	}

	// statistics of a user
	st.AddTraffic(ctx, time.Now(), map[string]UserDelta{"carol": {Up: 100, Down: 900, Conns: 2}})
	code, m, raw = h.do("GET", "/api/users/carol/stats", nil)
	if code != 200 || m["all_down"].(float64) != 900 || len(m["days"].([]any)) != 30 || m["sub_source"] != "default" {
		t.Fatalf("stats: %d %s", code, raw)
	}
	if code, _, _ := h.do("GET", "/api/users/ghost/stats", nil); code != 404 {
		t.Error("stats of an unknown user")
	}

	// deleting the bundle through the API also takes it out of the default list
	cfg.ApplySettings(map[string]json.RawMessage{"user_default_subs": json.RawMessage(`["balancers","b:games"]`)})
	bs, _ := st.ListBundles(ctx, false)
	if code, _, _ := h.do("DELETE", fmt.Sprintf("/api/bundles/%d", bs[0].ID), nil); code != 200 {
		t.Fatal("delete bundle")
	}
	if d := cfg.defaultSubs(); len(d) != 1 || d[0] != "balancers" {
		t.Errorf("default after deleting the bundle: %v", d)
	}
}
