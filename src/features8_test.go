package main

import (
	"context"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"
)

func decodeSub(body string) string {
	b, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(body))
	return string(b)
}

func TestSubscriptionBoundToOneServer(t *testing.T) {
	cfg := siteTestCfg()
	_, st, srv := startSite(t, cfg)
	ctx := context.Background()
	st.pool.Exec(ctx, "TRUNCATE servers, server_traffic CASCADE")
	for _, n := range []string{"bs-a", "bs-b"} {
		st.pool.Exec(ctx, "DELETE FROM users WHERE name=$1", n)
		st.AddUser(ctx, n)
	}
	s1, t1, _ := st.CreateServer(ctx, "Первый", "endnode", "")
	s2, t2, _ := st.CreateServer(ctx, "Второй", "endnode", "")
	rep := func(host string) SyncReport {
		return SyncReport{Kind: "endnode", Info: ServerInfo{Links: []LinkTmpl{{Title: "T", Tmpl: "trojan://{PASS}@" + host + ":443?security=tls"}}}}
	}
	syncPost(t, srv.URL, t1, rep("one.example.com"))
	syncPost(t, srv.URL, t2, rep("two.example.com"))
	key1 := serverPrefix + itoa(s1.ID)
	st.pool.Exec(ctx, `UPDATE users SET subs=ARRAY[$1] WHERE name='bs-a'`, key1)
	st.pool.Exec(ctx, `UPDATE users SET subs=ARRAY['servers'] WHERE name='bs-b'`)

	// sync: bs-a is sent only to the first server
	if _, us := syncPost(t, srv.URL, t1, rep("one.example.com")); !hasUser(us, "bs-a") || !hasUser(us, "bs-b") {
		t.Errorf("first server: %+v", us)
	}
	if _, us := syncPost(t, srv.URL, t2, rep("two.example.com")); hasUser(us, "bs-a") || !hasUser(us, "bs-b") {
		t.Errorf("second server must not get the user bound to the first: %+v", us)
	}
	_ = s2
	st.RefreshRemote(ctx, cfg)

	us, _ := st.ListUsers(ctx)
	var a, b User
	for _, u := range us {
		switch u.Name {
		case "bs-a":
			a = u
		case "bs-b":
			b = u
		}
	}
	if l := cfg.remoteLinks(a, ""); len(l) != 1 || !strings.Contains(l[0], "one.example.com") {
		t.Errorf("bound user links: %q", l)
	}
	if l := cfg.remoteLinks(b, ""); len(l) != 2 {
		t.Errorf("kind-wide key gives both servers: %q", l)
	}

	c := newSiteClient(t, srv)
	code, body, _ := c.get("/sub/" + a.SubToken + "/s/" + itoa(s1.ID))
	if code != 200 || !strings.Contains(decodeSub(body), "one.example.com") {
		t.Errorf("server subscription: %d %s", code, decodeSub(body))
	}
	if code, _, _ := c.get("/sub/" + a.SubToken + "/s/" + itoa(s2.ID)); code != 403 {
		t.Errorf("another server's subscription must be refused: %d", code)
	}
	code, body, _ = c.get("/sub/" + a.SubToken)
	if d := decodeSub(body); code != 200 || !strings.Contains(d, "one.example.com") || strings.Contains(d, "two.example.com") {
		t.Errorf("union: %d %s", code, d)
	}
	if _, err := cleanSubKeys([]string{"s:12", "s:x"}); err == nil {
		t.Error("a bad server key is refused")
	}
	if subURLKind(cfg, "tok", key1) == "" {
		t.Log("no subscription base in the test config")
	}
}

func TestCabinetNick(t *testing.T) {
	cfg := siteTestCfg()
	_, st, srv := startSite(t, cfg)
	c := newSiteClient(t, srv)
	c.register("nick", "password1")
	ctx := context.Background()
	code, body, _ := c.get("/cabinet")
	if code != 200 || !strings.Contains(body, "Аккаунт №") {
		t.Fatalf("cabinet shows the number: %d", code)
	}
	code, body, _ = c.post("/account/nick", url.Values{"nick": {"Мишаня"}, "csrf": {c.csrf()}}, true)
	if code != 303 && code != 200 {
		t.Fatalf("nick change: %d %s", code, body)
	}
	acc, _ := st.AccountByUsername(ctx, "nick")
	if acc.Nick != "Мишаня" {
		t.Errorf("nick saved: %q", acc.Nick)
	}
	id := acc.UserID
	st.SetNick(ctx, acc.UserName, "Другой")
	acc, _ = st.AccountByUsername(ctx, "nick")
	if acc.UserID != id {
		t.Error("the number never changes")
	}
}

func TestCentralStatistics(t *testing.T) {
	cfg := siteTestCfg()
	_, st, srv := startSite(t, cfg)
	ctx := context.Background()
	st.pool.Exec(ctx, "TRUNCATE servers, server_traffic, server_traffic_hourly CASCADE")
	st.pool.Exec(ctx, "DELETE FROM users WHERE name='cs-a'")
	st.AddUser(ctx, "cs-a")
	sv1, t1, _ := st.CreateServer(ctx, "Раз", "endnode", "")
	_, t2, _ := st.CreateServer(ctx, "Два", "balancer", "")
	st.pool.Exec(ctx, `DELETE FROM traffic_hourly WHERE user_name='cs-a'`)
	st.AddTraffic(ctx, time.Now(), map[string]UserDelta{"cs-a": {Up: 100, Down: 1000, Conns: 1}})
	syncPost(t, srv.URL, t1, SyncReport{Kind: "endnode", Traffic: map[string][2]int64{"cs-a": {10, 200}}})
	syncPost(t, srv.URL, t1, SyncReport{Kind: "endnode", Traffic: map[string][2]int64{"cs-a": {30, 500}}}) // +20/+300
	syncPost(t, srv.URL, t2, SyncReport{Kind: "balancer", Traffic: map[string][2]int64{"cs-a": {1, 2}}})
	syncPost(t, srv.URL, t1, SyncReport{Kind: "endnode", Traffic: map[string][2]int64{"cs-a": {5, 7}}}) // restarted: counts from zero

	tr, _ := st.UserUsage(ctx, "cs-a")
	if tr.AllUp != 100+30+1+5 || tr.AllDown != 1000+500+2+7 {
		t.Errorf("sum over all servers: %+v", tr)
	}
	by, err := st.TrafficByServer(ctx, "cs-a")
	if err != nil || len(by) != 3 {
		t.Fatalf("per server: %v %+v", err, by)
	}
	if by[0].ID != 0 || by[0].Down != 1000 || by[1].ID != sv1.ID || by[1].Up != 35 || by[1].Down != 507 {
		t.Errorf("per server: %+v", by)
	}
	if us, _ := st.UserStatsOf(ctx, "cs-a", time.Now()); us.AllDown != 1509 || us.Today == 0 {
		t.Errorf("user statistics include the servers: %+v", us.AllDown)
	}
	if sum, _ := st.TrafficSummary(ctx); sum["cs-a"] == nil || sum["cs-a"].AllDown != 1509 {
		t.Errorf("summary: %+v", sum["cs-a"])
	}
	if all, _ := st.TrafficByServer(ctx, ""); len(all) != 3 {
		t.Errorf("network: %+v", all)
	}
	// the local totals that a balancer reports stay local (no echo of the other servers)
	if tot, _ := st.UserTotals(ctx); tot["cs-a"] != [2]int64{100, 1000} {
		t.Errorf("local totals: %v", tot["cs-a"])
	}
}
