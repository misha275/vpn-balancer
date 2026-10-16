package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func syncPost(t *testing.T, base, token string, rep SyncReport) (int, []SyncUser) {
	t.Helper()
	b, _ := json.Marshal(rep)
	req, _ := http.NewRequest("POST", base+"/api/sync", bytes.NewReader(b))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct{ Users []SyncUser }
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out.Users
}

func hasUser(us []SyncUser, name string) bool {
	for _, u := range us {
		if u.Name == name {
			return true
		}
	}
	return false
}

func TestServerSyncAccessAndBlocking(t *testing.T) {
	cfg := siteTestCfg()
	_, st, srv := startSite(t, cfg)
	ctx := context.Background()
	st.pool.Exec(ctx, "TRUNCATE servers, server_traffic CASCADE")
	for _, n := range []string{"sy-a", "sy-b", "sy-c"} {
		st.pool.Exec(ctx, "DELETE FROM users WHERE name=$1", n)
		if _, err := st.AddUser(ctx, n); err != nil {
			t.Fatal(err)
		}
	}
	// sy-b may use end nodes, sy-c has only a category (no servers)
	st.pool.Exec(ctx, `UPDATE users SET subs=ARRAY['balancers'] WHERE name='sy-a'`)
	st.pool.Exec(ctx, `UPDATE users SET subs=ARRAY['servers'] WHERE name='sy-b'`)
	st.pool.Exec(ctx, `UPDATE users SET subs=ARRAY['b:nothing'] WHERE name='sy-c'`)

	bal, btok, err := st.CreateServer(ctx, "Берлин", "balancer", "")
	if err != nil {
		t.Fatal(err)
	}
	_, etok, err := st.CreateServer(ctx, "Хельсинки", "endnode", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.CreateServer(ctx, "Берлин", "balancer", ""); err == nil {
		t.Error("duplicate name must be refused")
	}
	if _, _, err := st.CreateServer(ctx, "x", "bogus", ""); err == nil {
		t.Error("bad kind must be refused")
	}

	if code, _ := syncPost(t, srv.URL, "", SyncReport{}); code != 401 {
		t.Errorf("no token: %d", code)
	}
	if code, _ := syncPost(t, srv.URL, "vpnb_wrong", SyncReport{}); code != 401 {
		t.Errorf("wrong token: %d", code)
	}
	if code, _ := syncPost(t, srv.URL, btok, SyncReport{Kind: "endnode"}); code != 409 {
		t.Errorf("wrong kind: %d", code)
	}
	code, us := syncPost(t, srv.URL, btok, SyncReport{Kind: "balancer", Traffic: map[string][2]int64{"sy-a": {10, 20}}})
	if code != 200 || !hasUser(us, "sy-a") || hasUser(us, "sy-b") || hasUser(us, "sy-c") {
		t.Fatalf("balancer users: %d %+v", code, us)
	}
	code, us = syncPost(t, srv.URL, etok, SyncReport{Kind: "endnode"})
	if code != 200 || hasUser(us, "sy-a") || !hasUser(us, "sy-b") {
		t.Fatalf("end node users: %d %+v", code, us)
	}

	// traffic reported by the server is added to the usage of the user
	tr, _ := st.UserUsage(ctx, "sy-a")
	if tr.AllUp < 10 || tr.AllDown < 20 {
		t.Errorf("usage: %+v", tr)
	}

	// a blocked, an expired and a disabled user disappear from the answer
	if err := st.BlockUser(ctx, "sy-a", "unpaid", ""); err != nil {
		t.Fatal(err)
	}
	if _, us = syncPost(t, srv.URL, btok, SyncReport{Kind: "balancer"}); hasUser(us, "sy-a") {
		t.Error("a blocked user must not be sent to servers")
	}
	st.UnblockUser(ctx, "sy-a")
	st.pool.Exec(ctx, `UPDATE users SET expires_at=now()-interval '1 hour' WHERE name='sy-a'`)
	if _, us = syncPost(t, srv.URL, btok, SyncReport{Kind: "balancer"}); hasUser(us, "sy-a") {
		t.Error("an expired user must not be sent")
	}
	st.pool.Exec(ctx, `UPDATE users SET expires_at=NULL WHERE name='sy-a'`)
	if _, us = syncPost(t, srv.URL, btok, SyncReport{Kind: "balancer"}); !hasUser(us, "sy-a") {
		t.Error("unblocked user is back")
	}

	// a disabled server and a new token
	st.SetServerEnabled(ctx, bal.ID, false)
	if code, _ := syncPost(t, srv.URL, btok, SyncReport{}); code != 403 {
		t.Errorf("disabled server: %d", code)
	}
	st.SetServerEnabled(ctx, bal.ID, true)
	nt, err := st.RegenServerToken(ctx, bal.ID)
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := syncPost(t, srv.URL, btok, SyncReport{}); code != 401 {
		t.Errorf("old token must stop working: %d", code)
	}
	if code, _ := syncPost(t, srv.URL, nt, SyncReport{}); code != 200 {
		t.Errorf("new token: %d", code)
	}
}

func TestRemoteLinksInSubscriptions(t *testing.T) {
	cfg := siteTestCfg()
	_, st, srv := startSite(t, cfg)
	ctx := context.Background()
	st.pool.Exec(ctx, "TRUNCATE servers, server_traffic CASCADE")
	st.pool.Exec(ctx, "DELETE FROM users WHERE name='rl-a'")
	uuid, _ := st.AddUser(ctx, "rl-a")
	st.pool.Exec(ctx, `UPDATE users SET subs=ARRAY['all','balancers','servers'] WHERE name='rl-a'`)
	_, etok, _ := st.CreateServer(ctx, "Хельсинки", "endnode", "")
	_, btok, _ := st.CreateServer(ctx, "Берлин", "balancer", "")
	vm := base64.StdEncoding.EncodeToString([]byte(`{"v":"2","ps":"x","add":"h.example.com","port":"443","id":"{UUID}","aid":"0","net":"ws","tls":"tls"}`))
	syncPost(t, srv.URL, etok, SyncReport{Kind: "endnode", Info: ServerInfo{Links: []LinkTmpl{
		{Title: "Trojan", Tmpl: "trojan://{PASS}@h.example.com:443?security=tls#old"},
		{Title: "VMess", Tmpl: "vmess://" + vm},
	}}})
	syncPost(t, srv.URL, btok, SyncReport{Kind: "balancer", Info: ServerInfo{Links: []LinkTmpl{
		{Title: "лучшая скорость", Mode: modeSpeed, Tmpl: "vless://{UUID}@b.example.com:443?security=reality#z"},
	}}})
	st.RefreshRemote(ctx, cfg)

	us, _ := st.ListUsers(ctx)
	var u User
	for _, x := range us {
		if x.Name == "rl-a" {
			u = x
		}
	}
	end := cfg.remoteLinks(u, "endnode")
	if len(end) != 2 || !strings.Contains(end[0], "trojan://"+endnodePass(uuid)+"@") || !strings.Contains(end[0], "#"+"%D0%A5") {
		t.Fatalf("end node links: %q", end)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(end[1], "vmess://"))
	if err != nil || !strings.Contains(string(raw), uuid) || !strings.Contains(string(raw), "Хельсинки") {
		t.Fatalf("vmess link: %v %s", err, raw)
	}
	bl := cfg.remoteLinks(u, "balancer")
	if len(bl) != 1 || !strings.Contains(bl[0], modeUUID(uuid, modeSpeed)+"@b.example.com") {
		t.Fatalf("balancer links: %q", bl)
	}

	c := newSiteClient(t, srv)
	code, body, _ := c.get("/sub/" + u.SubToken + "/servers")
	if code != 200 {
		t.Fatalf("sub servers: %d %s", code, body)
	}
	dec, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(body))
	if !strings.Contains(string(dec), "trojan://") || strings.Contains(string(dec), "b.example.com") {
		t.Errorf("subscription servers: %s", dec)
	}
	_, body, _ = c.get("/sub/" + u.SubToken + "/balancers")
	dec, _ = base64.StdEncoding.DecodeString(strings.TrimSpace(body))
	if !strings.Contains(string(dec), "b.example.com") || strings.Contains(string(dec), "trojan://") {
		t.Errorf("subscription balancers: %s", dec)
	}
	_, body, _ = c.get("/sub/" + u.SubToken)
	dec, _ = base64.StdEncoding.DecodeString(strings.TrimSpace(body))
	if !strings.Contains(string(dec), "trojan://") || !strings.Contains(string(dec), "b.example.com") {
		t.Errorf("full subscription: %s", dec)
	}
	// a disabled server leaves the subscriptions
	list, _ := st.ListServers(ctx)
	st.SetServerEnabled(ctx, list[0].ID, false)
	st.SetServerEnabled(ctx, list[1].ID, false)
	st.RefreshRemote(ctx, cfg)
	if len(cfg.remoteLinks(u, "")) != 0 {
		t.Error("disabled servers must not give links")
	}
	// the panel role has no balancer of its own
	cfg.Role = "panel"
	if got := RenderBalancers(cfg, &u); len(got) != 0 {
		t.Errorf("panel role: %q", got)
	}
}

func TestSyncUsersFollowsThePanel(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	st.pool.Exec(ctx, "DELETE FROM users WHERE name LIKE 'su-%'")
	a := SyncUser{Name: "su-a", UUID: "11111111-1111-4111-8111-111111111111", SubToken: "tokena0000000000000000000000000000"}
	b := SyncUser{Name: "su-b", UUID: "22222222-2222-4222-8222-222222222222", SubToken: "tokenb0000000000000000000000000000"}
	if ch, err := st.SyncUsers(ctx, []SyncUser{a, b}); err != nil || !ch {
		t.Fatalf("first sync: %v %v", ch, err)
	}
	if ch, _ := st.SyncUsers(ctx, []SyncUser{a, b}); ch {
		t.Error("the same list changes nothing")
	}
	en, _ := st.EnabledUsers(ctx)
	if !hasEnabled(en, "su-a") || !hasEnabled(en, "su-b") {
		t.Fatal("both users are enabled")
	}
	// the panel blocked su-b: he is missing from the list, so he is switched off here (connections are dropped by the reconcile loop)
	if ch, _ := st.SyncUsers(ctx, []SyncUser{a}); !ch {
		t.Error("removal is a change")
	}
	en, _ = st.EnabledUsers(ctx)
	if hasEnabled(en, "su-b") || !hasEnabled(en, "su-a") {
		t.Error("su-b must be off, su-a stays")
	}
	u, err := st.UserBySubToken(ctx, a.SubToken)
	if err != nil || u.UUID != a.UUID {
		t.Errorf("subscription token and uuid are the panel's: %v %v", u, err)
	}
	if _, err := st.UserBySubToken(ctx, b.SubToken); err == nil {
		t.Error("the subscription of a removed user does not work")
	}
	st.SyncUsers(ctx, []SyncUser{a, b})
	en, _ = st.EnabledUsers(ctx)
	if !hasEnabled(en, "su-b") {
		t.Error("su-b is back after unblocking")
	}
	st.pool.Exec(ctx, "DELETE FROM users WHERE name LIKE 'su-%'")
}

func hasEnabled(us []User, name string) bool {
	for _, u := range us {
		if u.Name == name {
			return true
		}
	}
	return false
}

func TestPanelSyncClientRoundTrip(t *testing.T) {
	cfg := siteTestCfg()
	_, st, srv := startSite(t, cfg)
	ctx := context.Background()
	st.pool.Exec(ctx, "TRUNCATE servers, server_traffic CASCADE")
	st.pool.Exec(ctx, "DELETE FROM users WHERE name='rt-a'")
	st.AddUser(ctx, "rt-a")
	_, tok, _ := st.CreateServer(ctx, "Ост", "balancer", "")
	us, err := PanelSync(ctx, panelClient(false), srv.URL, tok, SyncReport{Kind: "balancer", Info: balancerInfo(cfg, 0)})
	if err != nil || !hasUser(us, "rt-a") {
		t.Fatalf("client: %v %+v", err, us)
	}
	if _, err := PanelSync(ctx, panelClient(false), srv.URL, "vpnb_bad", SyncReport{}); err == nil {
		t.Error("a wrong token is an error")
	}
	list, _ := st.ListServers(ctx)
	if list[0].LastSeen == nil || len(list[0].Info.Links) < 3 {
		t.Errorf("the panel keeps what the server told: %+v", list[0])
	}
}

func TestBalancerSyncLoopAppliesAndKicks(t *testing.T) {
	cfg := siteTestCfg()
	_, st, srv := startSite(t, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st.pool.Exec(ctx, "TRUNCATE servers, server_traffic CASCADE")
	st.pool.Exec(ctx, "DELETE FROM users WHERE name='bl-a'")
	st.AddUser(ctx, "bl-a")
	_, tok, _ := st.CreateServer(ctx, "Лес", "balancer", "")
	// the "balancer" side uses the same database here, so its users table is the panel's own: the loop must keep them equal
	bc := *siteTestCfg()
	bc.PanelURL, bc.PanelToken, bc.SyncInterval = srv.URL, tok, time.Hour
	kicked := make(chan struct{}, 1)
	go BalancerSyncLoop(ctx, &bc, st, &Notifier{}, func() {
		select {
		case kicked <- struct{}{}:
		default:
		}
	})
	time.Sleep(1500 * time.Millisecond)
	list, _ := st.ListServers(ctx)
	if list[0].LastSeen == nil || len(list[0].Info.Links) < 3 {
		t.Fatalf("the loop must report to the panel: %+v", list[0])
	}
}
