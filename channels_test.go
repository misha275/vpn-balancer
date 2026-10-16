package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestChannelModeNames(t *testing.T) {
	for _, c := range []struct{ in, ch, base string }{
		{"", chanAdmin, ""}, {modeSpeed, chanAdmin, modeSpeed}, {modeSpread, chanAdmin, modeSpread},
		{"u", chanUsers, ""}, {"u-speed", chanUsers, modeSpeed}, {"u-ping", chanUsers, modePing},
	} {
		if modeChannel(c.in) != c.ch || modeBase(c.in) != c.base {
			t.Errorf("%q: %s %q", c.in, modeChannel(c.in), modeBase(c.in))
		}
	}
	for _, in := range []string{"carol~u", "carol~u-speed", "carol~u-ping"} {
		b, m := foldUser(in)
		if b != "carol" || m != strings.TrimPrefix(in, "carol~") {
			t.Errorf("foldUser(%q) = %q,%q", in, b, m)
		}
	}
	cfg := policyCfg()
	adm, usr := User{Name: "a", UUID: testUUID}, User{Name: "b", UUID: testUUID, Channel: chanUsers}
	if n := len(modeLinks(cfg, adm)); n != 3 {
		t.Errorf("admin links: %d", n)
	}
	ul := modeLinks(cfg, usr)
	if len(ul) != 3 || strings.Contains(ul[0], testUUID) || !strings.Contains(ul[0], modeUUID(testUUID, "u")) {
		t.Errorf("users' links carry the keys of their own modes: %v", ul)
	}
	if modeTitle("u-speed") == modeTitle(modeSpeed) || modeLinkName(cfg, "u") != cfg.getGatewayName() {
		t.Errorf("titles: %q %q", modeTitle("u-speed"), modeLinkName(cfg, "u"))
	}
}

func TestBuildConfigHasBothChannels(t *testing.T) {
	cfg := policyCfg()
	cfg.TestSecret, cfg.GatewayBase = "x", 21000
	cfg.Reality.PrivateKey, cfg.Reality.HandshakeServer, cfg.Reality.HandshakePort = testPriv, "www.apple.com", 443
	nodes := []*Node{withExit(mkNode("a"), "DE"), withExit(mkNode("b"), "NL")}
	users := []User{{Name: "alice", UUID: testUUID}, {Name: "bob", UUID: "6a3a4a6c-0b1e-4b0e-9d5e-1d2f3a4b5c6d", Channel: chanUsers}}
	m := buildMap(t, cfg, nodes, users, "")
	var names []string
	for _, ib := range m["inbounds"].([]any) {
		in := ib.(map[string]any)
		if in["tag"] == "vless-in" {
			for _, u := range in["users"].([]any) {
				names = append(names, u.(map[string]any)["name"].(string))
			}
		}
	}
	if got := strings.Join(names, ","); got != "alice,alice~speed,alice~ping,alice~spread,bob~u,bob~u-speed,bob~u-ping" {
		t.Fatalf("keys per channel: %s", got)
	}
	sel := map[string]bool{}
	for _, o := range m["outbounds"].([]any) {
		if ob := o.(map[string]any); ob["type"] == "selector" {
			sel[ob["tag"].(string)] = true
		}
	}
	for _, tag := range []string{"proxy", "proxy-speed", "proxy-ping", "proxy-spread", "proxy-u", "proxy-u-speed", "proxy-u-ping"} {
		if !sel[tag] {
			t.Errorf("selector %s is missing: %v", tag, sel)
		}
	}
	routed := map[string]string{}
	for _, r := range m["route"].(map[string]any)["rules"].([]any) {
		rr := r.(map[string]any)
		if au, ok := rr["auth_user"].([]any); ok && len(au) > 0 {
			if out, _ := rr["outbound"].(string); out != "" {
				routed[au[0].(string)] = out
			}
		}
	}
	if routed["bob~u"] != "proxy-u" || routed["bob~u-ping"] != "proxy-u-ping" || routed["alice~speed"] != "proxy-speed" || routed["alice~u"] != "" {
		t.Errorf("routing by key: %v", routed)
	}
	// only the users of one channel: the other channel's rules do not appear (no empty auth_user list)
	m = buildMap(t, cfg, nodes, users[:1], "")
	for _, r := range m["route"].(map[string]any)["rules"].([]any) {
		if au, ok := r.(map[string]any)["auth_user"].([]any); ok && len(au) == 0 {
			t.Error("a rule with an empty list of users")
		}
	}
}

func TestChannelPoolsAreSeparate(t *testing.T) {
	cfg := policyCfg()
	cfg.SpeedTTL = 12 * time.Hour
	c := NewChecker(cfg, nil, NewCore(cfg), &Notifier{})
	var ns []*Node
	for _, id := range []string{"a", "b", "c", "d"} {
		ns = append(ns, withExit(mkNode(id), "DE"))
	}
	ns[0].InAdmin, ns[1].InAdmin = true, true
	ns[2].InUsers, ns[3].InUsers = true, true
	c.SyncNodes(ns)
	for id, ms := range map[string]float64{"a": 40, "b": 90, "c": 30, "d": 70} {
		feed(c.st(id), 20, true, ms)
	}
	now := time.Now()
	adm, usr := map[string]bool{}, map[string]bool{}
	for _, st := range c.modePool(now, chanAdmin) {
		adm[st.Node.Name] = true
	}
	for _, st := range c.modePool(now, chanUsers) {
		usr[st.Node.Name] = true
	}
	if !adm["a"] || !adm["b"] || adm["c"] || adm["d"] || usr["a"] || usr["b"] || !usr["c"] || !usr["d"] {
		t.Fatalf("pools: admin %v users %v", adm, usr)
	}
	if n, _ := c.decideModeLocked(modeUser0, true); n == nil || (n.Name != "c") {
		t.Errorf("the users' main balancer takes the best of its own pool: %+v", n)
	}
	if n, _ := c.decideModeLocked(modeUserPing, true); n == nil || n.Name != "c" {
		t.Errorf("users' ping: %+v", n)
	}
	if n, _ := c.decideModeLocked(modePing, true); n == nil || n.Name != "a" {
		t.Errorf("admin ping must not take a node of the users' pool: %+v", n)
	}
	if n, _, _ := c.decideLocked(true); n == nil || (n.Name != "a" && n.Name != "b") {
		t.Errorf("the main balancer works on the pool of the operator: %+v", n)
	}
	// a node of the users' pool the mode stands on is replaced when it leaves the pool
	c.modeCur[modeUser0] = c.st("a").Node.ID
	if n, r := c.decideModeLocked(modeUser0, true); n == nil || r != "failover" {
		t.Errorf("a node outside of the pool is replaced: %v %v", n, r)
	}
	// the channel falls back to the operator's pool while it has no nodes of its own
	for _, st := range c.states {
		st.Node.InUsers = false
	}
	if p := c.modePool(now, chanUsers); len(p) != 4 {
		t.Errorf("fallback to everything: %d", len(p))
	}
}

func TestChannelNodesInSubscriptionAndStore(t *testing.T) {
	cfg := policyCfg()
	a, b := withExit(mkNode("a"), "DE"), withExit(mkNode("b"), "DE")
	b.InUsers = true
	a.Link, b.Link = "trojan://pw@a.example.com:443#a", "trojan://pw@b.example.com:443#b"
	all := []*Node{a, b}
	if got := channelNodes(all, chanAdmin); len(got) != 1 || got[0] != a {
		t.Errorf("admin: %v", got)
	}
	if got := channelNodes(all, chanUsers); len(got) != 1 || got[0] != b {
		t.Errorf("users: %v", got)
	}
	b.InUsers = false
	if got := channelNodes(all, chanUsers); len(got) != 2 {
		t.Errorf("no users' pool: the channel sees all: %v", got)
	}
	b.InUsers = true
	lines := RenderSub(cfg, &User{Name: "x", UUID: testUUID, Channel: chanUsers}, all)
	joined := strings.Join(lines, "\n")
	if strings.Contains(joined, "a.example.com") || !strings.Contains(joined, "b.example.com") {
		t.Errorf("a user of the users' channel gets the nodes of that pool only:\n%s", joined)
	}

	st := testStore(t)
	ctx := context.Background()
	st.pool.Exec(ctx, "TRUNCATE nodes CASCADE")
	n1, n2 := mkNode("p"), mkNode("q")
	n1.Outbound, n2.Outbound = map[string]any{"type": "trojan"}, map[string]any{"type": "trojan"}
	if err := st.UpsertNodesPool(ctx, []*Node{n1}, "admin-list", chanAdmin); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertNodesPool(ctx, []*Node{n1, n2}, "users-list", chanUsers); err != nil {
		t.Fatal(err)
	}
	got, err := st.ActiveNodes(ctx, time.Hour)
	if err != nil || len(got) != 2 {
		t.Fatalf("%v %d", err, len(got))
	}
	pools := map[string]string{}
	for _, n := range got {
		pools[n.Name] = nodePool(n)
	}
	if pools["p"] != "both" || pools["q"] != "users" {
		t.Errorf("pools: %v", pools)
	}
	// users: a channel can be changed, and a user registered on the site lands in the configured one
	st.pool.Exec(ctx, "DELETE FROM users WHERE name IN ('ch-a','chreg@example.com')")
	st.AddUser(ctx, "ch-a")
	if err := st.SetChannel(ctx, "ch-a", chanUsers); err != nil {
		t.Fatal(err)
	}
	if err := st.SetChannel(ctx, "ch-a", "weird"); err == nil {
		t.Error("an unknown channel is refused")
	}
	if _, err := st.CreateAccountIn(ctx, "chreg@example.com", "h", 3, chanUsers); err != nil {
		t.Fatal(err)
	}
	us, _ := st.ListUsers(ctx)
	ch := map[string]string{}
	for _, u := range us {
		ch[u.Name] = u.Chan()
	}
	if ch["ch-a"] != chanUsers || ch["chreg@example.com"] != chanUsers {
		t.Errorf("channels: %v", ch)
	}
}
