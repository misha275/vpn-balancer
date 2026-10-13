package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFoldUserAndModeKeys(t *testing.T) {
	for _, c := range []struct{ in, base, mode string }{
		{"alice", "alice", ""}, {"alice~speed", "alice", "speed"}, {"bob smith~ping", "bob smith", "ping"},
		{"~speed", "~speed", ""}, {"~invalid", "~invalid", ""}, {"x~other", "x~other", ""},
	} {
		if b, m := foldUser(c.in); b != c.base || m != c.mode {
			t.Errorf("foldUser(%q) = %q,%q want %q,%q", c.in, b, m, c.base, c.mode)
		}
		if c.mode != "" && modeUser(c.base, c.mode) != c.in {
			t.Errorf("modeUser must undo foldUser: %q", c.in)
		}
	}
	a, b := modeUUID(testUUID, modeSpeed), modeUUID(testUUID, modePing)
	if a == b || a == testUUID || modeUUID(testUUID, "") != testUUID {
		t.Fatalf("keys of the modes must differ and the main one stays: %s %s", a, b)
	}
	if a != modeUUID(testUUID, modeSpeed) || modeUUID("6a3a4a6c-0b1e-4b0e-9d5e-1d2f3a4b5c6d", modeSpeed) == a {
		t.Fatal("a mode key is derived from the user key, deterministically")
	}
	if len(a) != 36 || strings.Count(a, "-") != 4 {
		t.Fatalf("must look like a UUID: %s", a)
	}
}

func TestFoldGWMergesModes(t *testing.T) {
	gs := GWStats{
		Deltas:   map[string]UserDelta{"alice": {Up: 1, Down: 2, Conns: 1}, "alice~speed": {Up: 10, Down: 20, Conns: 2}, "bob~ping": {Down: 5}},
		Sessions: []SessInfo{{ID: 1, User: "alice~ping"}, {ID: 2, User: "carol"}},
		Errs:     map[string]UserErr{"alice": {Count: 1, Last: 5, Msg: "a"}, "alice~speed": {Count: 2, Last: 9, Msg: "b"}},
	}
	foldGW(&gs)
	if d := gs.Deltas["alice"]; d.Up != 11 || d.Down != 22 || d.Conns != 3 || len(gs.Deltas) != 2 || gs.Deltas["bob"].Down != 5 {
		t.Errorf("traffic of all modes belongs to the user: %+v", gs.Deltas)
	}
	if gs.Sessions[0].User != "alice" || gs.Sessions[0].Mode != "ping" || gs.Sessions[1].Mode != "" {
		t.Errorf("sessions: %+v", gs.Sessions)
	}
	if e := gs.Errs["alice"]; e.Count != 3 || e.Msg != "b" || len(gs.Errs) != 1 {
		t.Errorf("errors: %+v", gs.Errs)
	}
}

func TestStoreRejectsTildeInName(t *testing.T) {
	s := &Store{}
	if _, err := s.AddUser(nil, "a~speed"); err == nil {
		t.Fatal("a name with ~ would collide with the mode users")
	}
}

func TestBuildConfigModes(t *testing.T) {
	cfg := policyCfg()
	cfg.TestSecret, cfg.GatewayBase = "x", 21000
	cfg.Reality.PrivateKey, cfg.Reality.HandshakeServer, cfg.Reality.HandshakePort = testPriv, "www.apple.com", 443
	cfg.Rules = []RuleCfg{{Action: "block", Match: []string{"port:25"}}, {Action: "direct", Match: []string{"suffix:.ru"}}, {Action: "proxy", Match: []string{"suffix:x.ru"}}}
	nodes := []*Node{withExit(mkNode("a"), "DE"), withExit(mkNode("b"), "NL")}
	cfg.setModeDefault(modePing, nodes[1].Tag())
	m := buildMap(t, cfg, nodes, []User{{Name: "alice", UUID: testUUID}}, "")

	// three keys for the user, one per mode
	var names []string
	for _, ib := range m["inbounds"].([]any) {
		in := ib.(map[string]any)
		if in["tag"] == "vless-in" {
			for _, u := range in["users"].([]any) {
				names = append(names, u.(map[string]any)["name"].(string))
			}
		}
	}
	if strings.Join(names, ",") != "alice,alice~speed,alice~ping" {
		t.Fatalf("users of the inbound: %v", names)
	}
	// three selectors; the ping one starts on its own node
	defaults := map[string]string{}
	for _, o := range m["outbounds"].([]any) {
		ob := o.(map[string]any)
		if ob["type"] == "selector" {
			defaults[ob["tag"].(string)] = ob["default"].(string)
		}
	}
	if len(defaults) != 3 || defaults["proxy-ping"] != nodes[1].Tag() || defaults["proxy"] != nodes[0].Tag() || defaults["proxy-speed"] != nodes[0].Tag() {
		t.Fatalf("selectors: %v", defaults)
	}
	// every mode has its own copy of the rules, in the same order, before the common ones; "proxy" rules lead to its own selector
	var seq []string
	for _, r := range m["route"].(map[string]any)["rules"].([]any) {
		rr := r.(map[string]any)
		if _, ok := rr["inbound"]; !ok {
			continue
		}
		au, _ := rr["auth_user"].([]any)
		who := "common"
		if len(au) > 0 {
			who = au[0].(string)
		}
		out, _ := rr["outbound"].(string)
		if rr["action"] == "reject" {
			out = "reject"
		}
		seq = append(seq, who+">"+out)
	}
	want := "alice~speed>reject,alice~speed>direct,alice~speed>proxy-speed,alice~ping>reject,alice~ping>direct,alice~ping>proxy-ping," +
		"common>reject,common>direct,common>proxy,alice~speed>proxy-speed,alice~ping>proxy-ping"
	if got := strings.Join(seq, ","); got != want {
		t.Fatalf("rules:\n got %s\nwant %s", got, want)
	}
	if m["route"].(map[string]any)["final"] != "proxy" {
		t.Fatal("the main mode keeps the default route")
	}
}

func modePoolChecker(t *testing.T) *Checker {
	t.Helper()
	cfg := policyCfg()
	cfg.SpeedTTL = 12 * time.Hour
	c := NewChecker(cfg, nil, NewCore(cfg), &Notifier{})
	var ns []*Node
	for _, id := range []string{"a", "b", "c", "d"} {
		ns = append(ns, withExit(mkNode(id), "DE"))
	}
	c.SyncNodes(ns)
	now := time.Now()
	set := func(id string, ms float64, kbps int) {
		st := c.st(id)
		feed(st, 20, true, ms)
		if kbps > 0 {
			st.addSpeed(kbps, now)
			st.speedKbps = kbps
		}
		st.recompute()
	}
	set("a", 50, 20000)  // balanced
	set("b", 150, 90000) // fast, high latency
	set("c", 20, 12000)  // lowest latency
	set("d", 900, 0)     // bad: far outside the best group once the others exist
	return c
}

func TestModeBestSpeedAndPing(t *testing.T) {
	c := modePoolChecker(t)
	now := time.Now()
	pool := c.modePool(now)
	if len(pool) != 4 {
		t.Fatalf("with few nodes the group is everything allowed: %d", len(pool))
	}
	if b := c.modeBest(modeSpeed, pool, now); b.Node.Name != "b" {
		t.Errorf("speed: the fastest of the group, got %s", b.Node.Name)
	}
	if b := c.modeBest(modePing, pool, now); b.Node.Name != "c" {
		t.Errorf("ping: the lowest latency, got %s", b.Node.Name)
	}
	// a node that is dead is never in the group; a node excluded by country neither
	c.st("b").score = 0
	withExit(c.st("c").Node, "RU")
	pool = c.modePool(now)
	for _, st := range pool {
		if st.Node.Name == "b" || st.Node.Name == "c" {
			t.Errorf("dead or censored node in the group: %s", st.Node.Name)
		}
	}
	if b := c.modeBest(modePing, pool, now); b.Node.Name != "a" {
		t.Errorf("ping after exclusions: %s", b.Node.Name)
	}
}

func TestModeBestIgnoresStaleSpeedAndSlowNodes(t *testing.T) {
	c := modePoolChecker(t)
	ms := 8000
	c.cfg.MinSpeedKbps = &ms
	// b was measured long ago: it does not count as the fastest any more
	c.st("b").speedHist = []SpeedPoint{{K: 90000, T: time.Now().Add(-30 * time.Hour).Unix()}}
	now := time.Now()
	if b := c.modeBest(modeSpeed, c.modePool(now), now); b.Node.Name != "a" {
		t.Errorf("an old measurement must not win: %s", b.Node.Name)
	}
	// two slow measurements exclude a node from the group (the common quality rule)
	st := c.st("a")
	st.speedHist = []SpeedPoint{{K: 1000, T: now.Add(-time.Hour).Unix()}, {K: 1200, T: now.Unix()}}
	for _, s := range c.modePool(now) {
		if s.Node.Name == "a" {
			t.Errorf("a slow node must not be in the group")
		}
	}
}

func TestDecideModeHysteresis(t *testing.T) {
	c := modePoolChecker(t)
	now := time.Now()
	// nothing chosen yet: fail over straight to the best
	n, r := c.decideModeLocked(modeSpeed, false)
	if n == nil || n.Name != "b" || r != "failover" {
		t.Fatalf("first choice: %v %s", n, r)
	}
	c.modeCur[modeSpeed] = c.st("a").Node.ID // on a (20 Mbit/s), b has 90: clearly better, but only after the confirmations
	for i := 1; i <= 2; i++ {
		if n, _ := c.decideModeLocked(modeSpeed, true); n != nil {
			t.Fatalf("cycle %d: must wait for confirmation", i)
		}
	}
	if n, r := c.decideModeLocked(modeSpeed, true); n == nil || n.Name != "b" || r != "better" {
		t.Fatalf("third cycle must switch: %v %s", n, r)
	}
	// a small gain does not move anybody
	c.st("b").speedHist = []SpeedPoint{{K: 22000, T: now.Unix()}}
	c.modeCur[modeSpeed] = c.st("a").Node.ID
	for i := 0; i < 6; i++ {
		if n, _ := c.decideModeLocked(modeSpeed, true); n != nil {
			t.Fatalf("22 vs 20 Mbit/s is not worth a switch: %v", n.Name)
		}
	}
	// ping: c (20 ms) against a (50 ms) is clearly better, against 30 ms it is not
	c.modeCur[modePing] = c.st("a").Node.ID
	for i := 0; i < 2; i++ {
		c.decideModeLocked(modePing, true)
	}
	if n, r := c.decideModeLocked(modePing, true); n == nil || n.Name != "c" || r != "better" {
		t.Fatalf("ping switch: %v %s", n, r)
	}
	c.modeCur[modePing] = c.st("a").Node.ID
	c.st("a").ewma = 24
	for i := 0; i < 6; i++ {
		if n, _ := c.decideModeLocked(modePing, true); n != nil {
			t.Fatalf("24 ms vs 20 ms: no switch, got %s", n.Name)
		}
	}
	// the node in use dies: immediate failover without waiting
	c.st("a").score = 0
	if n, r := c.decideModeLocked(modePing, false); n == nil || r != "failover" {
		t.Fatalf("dead node must be replaced at once: %v %s", n, r)
	}
}

// A real sing-box: the gateway config of BuildConfig (Reality swapped for plain VLESS, which only the test needs) and a client with
// the three keys of one user. Each mode must follow its own selector, and the filter rules must apply to all of them.
func TestModesRouteIndependentlyInSingbox(t *testing.T) {
	bin := singboxBin(t)
	dir := t.TempDir()
	run := func(name string, conf any) {
		data, _ := json.MarshalIndent(conf, "", " ")
		p := filepath.Join(dir, name+".json")
		os.WriteFile(p, data, 0o600)
		cmd := exec.Command(bin, "run", "-c", p)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	}
	wait := func(addr string) {
		for i := 0; i < 100; i++ {
			if c, err := net.Dial("tcp", addr); err == nil {
				c.Close()
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("%s did not come up", addr)
	}
	tagA, tagB := tagServer(t, "A"), tagServer(t, "B")
	// the "provider": two shadowsocks inbounds, each ends at its own tag server
	ssA, ssB := freePort(t), freePort(t)
	run("up", map[string]any{
		"log": map[string]any{"level": "error"},
		"inbounds": []any{
			map[string]any{"type": "shadowsocks", "tag": "ia", "listen": "127.0.0.1", "listen_port": ssA, "method": "aes-128-gcm", "password": "pw"},
			map[string]any{"type": "shadowsocks", "tag": "ib", "listen": "127.0.0.1", "listen_port": ssB, "method": "aes-128-gcm", "password": "pw"}},
		"outbounds": []any{
			map[string]any{"type": "direct", "tag": "da", "override_address": "127.0.0.1", "override_port": tagA},
			map[string]any{"type": "direct", "tag": "db", "override_address": "127.0.0.1", "override_port": tagB}},
		"route": map[string]any{"rules": []any{map[string]any{"inbound": []string{"ia"}, "outbound": "da"}, map[string]any{"inbound": []string{"ib"}, "outbound": "db"}}},
	})
	wait(fmt.Sprintf("127.0.0.1:%d", ssA))
	ui := "YWVzLTEyOC1nY206cHc" // aes-128-gcm:pw
	nA := ParseLinks(fmt.Sprintf("ss://%s@127.0.0.1:%d#a", ui, ssA))[0]
	nB := ParseLinks(fmt.Sprintf("ss://%s@127.0.0.1:%d#b", ui, ssB))[0]
	nA.ExitCountry, nB.ExitCountry = "DE", "NL"

	cfg := coreCfg(t)
	cfg.ClashAPI = fmt.Sprintf("127.0.0.1:%d", freePort(t))
	cfg.TestPort = freePort(t)
	cfg.GatewayBase = 0
	cfg.Rules = []RuleCfg{{Action: "block", Match: []string{"port:25"}}}
	off := false
	cfg.ExitCheck = &off
	data, err := BuildConfig(cfg, []*Node{nA, nB}, []User{{Name: "alice", UUID: testUUID}}, "")
	if err != nil {
		t.Fatal(err)
	}
	var gw map[string]any
	json.Unmarshal(data, &gw)
	gwPort := freePort(t)
	for _, ib := range gw["inbounds"].([]any) {
		in := ib.(map[string]any)
		if in["tag"] == "vless-in" { // Reality needs a real site to imitate; the routing under test is the same without it
			delete(in, "tls")
			in["listen"], in["listen_port"] = "127.0.0.1", gwPort
			for _, u := range in["users"].([]any) {
				delete(u.(map[string]any), "flow")
			}
		}
	}
	run("gw", gw)
	wait(fmt.Sprintf("127.0.0.1:%d", gwPort))

	// the client: one socks inbound per mode, each with the key of that mode
	var cin, cout, crules []any
	ports := map[string]int{}
	for _, m := range allModes {
		p := freePort(t)
		ports[m] = p
		tag := "m" + m
		cin = append(cin, map[string]any{"type": "socks", "tag": "in" + tag, "listen": "127.0.0.1", "listen_port": p})
		cout = append(cout, map[string]any{"type": "vless", "tag": "out" + tag, "server": "127.0.0.1", "server_port": gwPort, "uuid": modeUUID(testUUID, m)})
		crules = append(crules, map[string]any{"inbound": []string{"in" + tag}, "outbound": "out" + tag})
	}
	run("client", map[string]any{"log": map[string]any{"level": "error"}, "inbounds": cin, "outbounds": cout, "route": map[string]any{"rules": crules}})
	for _, p := range ports {
		wait(fmt.Sprintf("127.0.0.1:%d", p))
	}
	wait(cfg.ClashAPI)

	sel := func(group, tag string) {
		body := strings.NewReader(fmt.Sprintf(`{"name":%q}`, tag))
		req, _ := http.NewRequest("PUT", "http://"+cfg.ClashAPI+"/proxies/"+group, body)
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode >= 300 {
			t.Fatalf("select %s=%s: %v %v", group, tag, err, resp)
		}
		resp.Body.Close()
	}
	via := func(mode string, port int) string {
		c := socks5Connect(t, fmt.Sprintf("127.0.0.1:%d", ports[mode]), "10.99.9.9", port)
		defer c.Close()
		return ask(t, c, "x")
	}
	expect := func(what string, wantCur, wantSpeed, wantPing string) {
		t.Helper()
		got := []string{via("", 80), via(modeSpeed, 80), via(modePing, 80)}
		if got[0] != wantCur+":x" || got[1] != wantSpeed+":x" || got[2] != wantPing+":x" {
			t.Fatalf("%s: current/speed/ping = %v, want %s/%s/%s", what, got, wantCur, wantSpeed, wantPing)
		}
	}
	expect("start (everything on the first node)", "A", "A", "A")
	sel("proxy-speed", nB.Tag())
	expect("speed moved", "A", "B", "A")
	sel("proxy-ping", nB.Tag())
	sel("proxy", nB.Tag())
	sel("proxy-speed", nA.Tag())
	expect("each selector is independent", "B", "A", "B")

	// the filter applies to every mode
	for _, m := range allModes {
		if got := tryVia(ports[m], 25); strings.HasSuffix(got, ":x") {
			t.Errorf("port 25 must be blocked in mode %q, got %q", m, got)
		}
		if got := tryVia(ports[m], 80); !strings.HasSuffix(got, ":x") {
			t.Errorf("port 80 must work in mode %q, got %q", m, got)
		}
	}
}

// tryVia asks through a socks port and reports what came back ("" when the connection was refused or cut).
func tryVia(port, dst int) string {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
	if err != nil {
		return ""
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte{5, 1, 0})
	b := make([]byte, 16)
	if _, err := c.Read(b[:2]); err != nil {
		return ""
	}
	req := append([]byte{5, 1, 0, 1, 10, 99, 9, 9}, byte(dst>>8), byte(dst))
	c.Write(req)
	if n, err := c.Read(b[:10]); err != nil || n < 10 || b[1] != 0 {
		return ""
	}
	c.Write([]byte("x"))
	n, _ := c.Read(b)
	return string(b[:n])
}

func modesSubCfg() *Config {
	cfg := policyCfg()
	cfg.PublicHost, cfg.InboundPort, cfg.GatewayName = "gw.example.com", 443, "Balancer"
	cfg.Reality.PublicKey, cfg.Reality.ShortID, cfg.Reality.HandshakeServer = "PUB", "ab12", "www.apple.com"
	cfg.SubPublicURL = "https://sub.example.com"
	cfg.UserDefaultSubs = []string{subBalancers, subAll}
	return cfg
}

func TestUserViewHasModesAndSubscriptions(t *testing.T) {
	cfg := modesSubCfg()
	v := newUserView(cfg, User{Name: "bob", UUID: testUUID, Enabled: true, SubToken: "tok"})
	if len(v.Modes) != 3 || v.Modes[0].Kind != "current" || v.Modes[1].Kind != "speed" || v.Modes[2].Kind != "ping" {
		t.Fatalf("modes: %+v", v.Modes)
	}
	if v.Gateway != v.Modes[0].Link {
		t.Error("the main link stays the first one")
	}
	if len(v.Subs) != 2 || v.Subs[0].Link != "https://sub.example.com/sub/tok/balancers" || v.Subs[1].Link != "https://sub.example.com/sub/tok/all" || v.Subscription != "https://sub.example.com/sub/tok" {
		t.Fatalf("subscriptions: %+v (%s)", v.Subs, v.Subscription)
	}
	cfg.SubPublicURL = ""
	if v := newUserView(cfg, User{Name: "bob", UUID: testUUID}); len(v.Subs) != 0 || v.Subscription != "" {
		t.Errorf("without a subscription address there are none: %+v", v.Subs)
	}
}

func TestQRendpoint(t *testing.T) {
	a := &API{cfg: modesSubCfg(), token: "tt", fails: map[string][]time.Time{}}
	mux := http.NewServeMux()
	a.Register(mux)
	get := func(path, token string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", path, nil)
		req.RemoteAddr = "1.2.3.4:5"
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		mux.ServeHTTP(rec, req)
		return rec
	}
	if r := get("/api/qr?d=hello", ""); r.Code != 401 {
		t.Errorf("a QR code carries secrets: token required, got %d", r.Code)
	}
	r := get("/api/qr?d="+"vless%3A%2F%2Fx", "tt")
	if r.Code != 200 || !strings.HasPrefix(r.Body.String(), "\x89PNG") || r.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("png expected: %d %q", r.Code, r.Header().Get("Content-Type"))
	}
	if r := get("/api/qr", "tt"); r.Code != 400 {
		t.Errorf("empty text: %d", r.Code)
	}
}

func TestSubscriptionKinds(t *testing.T) {
	s := testStore(t)
	cfg := modesSubCfg()
	cfg.NodeGrace = time.Hour
	ctx := context.Background()
	if _, err := s.AddUser(ctx, "bob"); err != nil {
		t.Fatal(err)
	}
	u, _ := s.ListUsers(ctx)
	n := withExit(mkNode("de"), "DE")
	n.Link = "vless://x@de.example.com:443?security=reality#Germany"
	n.Outbound = map[string]any{"type": "direct"}
	if err := s.UpsertNodes(ctx, []*Node{n}, "test"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetExit(ctx, n.ID, "1.2.3.4", "DE"); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(NewSubServer(cfg, s).Handler())
	defer srv.Close()
	fetch := func(path string) []string {
		resp, err := http.Get(srv.URL + path)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("%s: %v %v", path, err, resp)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		dec, err := base64.StdEncoding.DecodeString(string(raw))
		if err != nil {
			t.Fatal(err)
		}
		return strings.Split(string(dec), "\n")
	}
	tok := u[0].SubToken
	only := fetch("/sub/" + tok + "/balancers")
	if len(only) != 3 || !strings.Contains(only[1], modeUUID(u[0].UUID, modeSpeed)) || !strings.Contains(only[2], modeUUID(u[0].UUID, modePing)) {
		t.Fatalf("balancers only: %v", only)
	}
	for _, p := range []string{"/sub/" + tok, "/sub/" + tok + "/all"} {
		if all := fetch(p); len(all) != 4 || !strings.Contains(all[3], "de.example.com") {
			t.Fatalf("%s: three balancers and the server: %v", p, all)
		}
	}
	if resp, _ := http.Get(srv.URL + "/sub/" + tok + "/nope"); resp.StatusCode != 404 {
		t.Errorf("unknown kind: %d", resp.StatusCode)
	}
}

// The controller moves the selector of a mode through the gateway and finds it again after it has restarted.
func TestCoreSelectsModesSeparately(t *testing.T) {
	cfg := coreCfg(t)
	core := NewCore(cfg)
	t.Cleanup(core.Stop)
	ns := allProtocolNodes(t)[:3]
	for i, n := range ns {
		n.ExitCountry = []string{"DE", "NL", "FI"}[i]
	}
	if _, _, err := core.Apply(ns, []User{{Name: "a", UUID: testUUID}}, ""); err != nil {
		t.Fatal(err)
	}
	if !core.WaitReady(context.Background(), 20*time.Second) {
		t.Fatal("sing-box is not ready")
	}
	if err := core.SelectMode(modeSpeed, ns[2].Tag()); err != nil {
		t.Fatal(err)
	}
	if err := core.SelectMode(modePing, ns[1].Tag()); err != nil {
		t.Fatal(err)
	}
	for mode, want := range map[string]string{"": ns[0].Tag(), modeSpeed: ns[2].Tag(), modePing: ns[1].Tag()} {
		if got, err := core.SelectedMode(mode); err != nil || got != want {
			t.Errorf("selector %q: %q %v, want %q", mode, got, err, want)
		}
	}
	// the checker adopts what the gateway already runs instead of choosing again
	chk := NewChecker(cfg, nil, core, &Notifier{})
	chk.SyncNodes(ns)
	chk.adoptModes()
	if chk.modeCur[modeSpeed] != ns[2].ID || chk.modeCur[modePing] != ns[1].ID {
		t.Fatalf("adopted: %v", chk.modeCur)
	}
}
