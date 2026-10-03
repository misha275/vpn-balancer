package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

var portRange atomic.Int32

// These tests need the real sing-box binary:
//
//	SINGBOX_BIN=/usr/local/bin/sing-box go test -run Core -v
//
// The end-to-end test additionally needs TEST_DATABASE_URL (see store_test.go).

const testPriv = "cIHXdXaiyUNj9bn7DAjQ63NlFQIA78Ndg4OPEprlnXs"

func singboxBin(t *testing.T) string {
	t.Helper()
	b := os.Getenv("SINGBOX_BIN")
	if b == "" {
		t.Skip("SINGBOX_BIN is not set")
	}
	return b
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func coreCfg(t *testing.T) *Config {
	t.Helper()
	cfg := testCfg()
	cfg.SingboxBin = singboxBin(t)
	cfg.WorkDir = t.TempDir()
	cfg.GatewayBase = 20000 + int(portRange.Add(1))*50 // below the ephemeral range, one block per test
	cfg.DrainTimeout = 30 * time.Second
	cfg.DrainUrgent = time.Second
	cfg.InboundPort = freePort(t)
	cfg.TestSecret = "s3cret-for-tests"
	cfg.MinReload = time.Millisecond
	cfg.Reality.PrivateKey = testPriv
	cfg.Reality.PublicKey = testPBK
	cfg.Reality.ShortID = "0123456789abcdef"
	cfg.Reality.HandshakeServer = "www.microsoft.com"
	cfg.Reality.HandshakePort = 443
	return cfg
}

func allProtocolNodes(t *testing.T) []*Node {
	t.Helper()
	ss := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pa55"))
	vm := base64.StdEncoding.EncodeToString([]byte(`{"ps":"vm","add":"vm.example.com","port":"443","id":"` + testUUID + `","aid":"0","net":"ws","host":"h.example.com","path":"/p","tls":"tls"}`))
	vg := base64.StdEncoding.EncodeToString([]byte(`{"ps":"vg","add":"vg.example.com","port":"443","id":"` + testUUID + `","net":"grpc","path":"svc","tls":"tls"}`))
	body := "vless://" + testUUID + "@1.2.3.4:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=" + testPBK + "&sid=ab12&type=tcp#reality\n" +
		"vless://" + testUUID + "@example.com:8443?security=tls&sni=example.com&type=ws&path=%2Fws&host=cdn.example.com&alpn=h2%2Chttp%2F1.1#ws\n" +
		"vless://" + testUUID + "@example.com:443?security=tls&type=grpc&serviceName=svc#grpc\n" +
		"vless://" + testUUID + "@example.com:443?security=tls&type=httpupgrade&path=/u&host=h.com#hu\n" +
		"vless://" + testUUID + "@[2001:db8::1]:443?security=tls&type=h2&path=/h&host=h.com#h2\n" +
		"vmess://" + vm + "\nvmess://" + vg + "\n" +
		"trojan://pw@tj.example.com:443?sni=tj.example.com&type=ws&path=%2Ft#tj\n" +
		"ss://" + ss + "@ss.example.com:8388#ss\n" +
		"hy2://pw@hy.example.com:8443?sni=hy.example.com&obfs=salamander&obfs-password=op#hy2\n"
	ns := ParseLinks(body)
	if len(ns) != 10 {
		t.Fatalf("expected 10 nodes, got %d", len(ns))
	}
	return ns
}

// Every protocol we generate must be accepted by the pinned sing-box 1.11.
func TestCoreConfigPassesSingboxCheck(t *testing.T) {
	cfg := coreCfg(t)
	users := []User{{Name: "alice", UUID: testUUID}, {Name: "bob", UUID: "6a3a4a6c-0b1e-4b0e-9d5e-1d2f3a4b5c6d"}}
	cases := map[string]struct {
		nodes []*Node
		users []User
	}{
		"all protocols + users": {allProtocolNodes(t), users},
		"nodes, no users":       {allProtocolNodes(t)[:2], nil},
		"users, no nodes":       {nil, users},
		"nothing":               {nil, nil},
	}
	for name, c := range cases {
		data, err := BuildConfig(cfg, c.nodes, c.users, "")
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), "c.json")
		os.WriteFile(p, data, 0o600)
		if out, err := exec.Command(cfg.SingboxBin, "check", "-c", p).CombinedOutput(); err != nil {
			t.Errorf("%s: sing-box check failed: %v\n%s\nconfig:\n%s", name, err, out, data)
		} else if len(out) > 0 {
			t.Errorf("%s: sing-box check printed warnings (deprecated syntax?): %s", name, out)
		}
	}
}

func TestCoreBuildConfigStructure(t *testing.T) {
	cfg := testCfg()
	cfg.TestSecret, cfg.TestPort, cfg.InboundPort, cfg.ClashAPI = "sec", 2080, 443, "127.0.0.1:9090"
	ns := []*Node{mkNode("a"), mkNode("b")}
	ns[0].Outbound = map[string]any{"type": "trojan", "server": "a", "server_port": 1, "password": "x"}
	ns[1].Outbound = map[string]any{"type": "trojan", "server": "b", "server_port": 1, "password": "x"}
	data, _ := BuildConfig(cfg, ns, []User{{Name: "u", UUID: testUUID}}, ns[1].Tag())
	var conf struct {
		Outbounds []map[string]any `json:"outbounds"`
		Route     struct {
			Rules []map[string]any `json:"rules"`
			Final string           `json:"final"`
		} `json:"route"`
		Inbounds []map[string]any `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &conf); err != nil {
		t.Fatal(err)
	}
	if conf.Route.Final != "proxy" || len(conf.Route.Rules) != 2 {
		t.Fatalf("route: %+v", conf.Route)
	}
	var sel map[string]any
	for _, o := range conf.Outbounds {
		if o["tag"] == "proxy" {
			sel = o
		}
	}
	if sel == nil || sel["type"] != "selector" || sel["default"] != ns[1].Tag() {
		t.Fatalf("selector: %v", sel)
	}
	if len(sel["outbounds"].([]any)) != 2 {
		t.Fatal("selector must list all nodes")
	}
	// user traffic must never fall through to "direct": with no nodes it must be blocked
	data, _ = BuildConfig(cfg, nil, []User{{Name: "u", UUID: testUUID}}, "")
	json.Unmarshal(data, &conf)
	if len(conf.Route.Rules) != 1 || conf.Route.Rules[0]["action"] != "reject" {
		t.Fatalf("with no nodes user traffic must be rejected (no IP leak): %+v", conf.Route)
	}
	// unknown default falls back to the first node instead of producing a broken selector
	data, _ = BuildConfig(cfg, ns, nil, "n-doesnotexist")
	json.Unmarshal(data, &conf)
	for _, o := range conf.Outbounds {
		if o["tag"] == "proxy" && o["default"] != ns[0].Tag() {
			t.Fatalf("fallback default: %v", o["default"])
		}
	}
}

func TestCoreFingerprintIgnoresOrder(t *testing.T) {
	a, b := mkNode("a"), mkNode("b")
	u1, u2 := User{Name: "x", UUID: "1"}, User{Name: "y", UUID: "2"}
	if fingerprint([]*Node{a, b}, []User{u1, u2}) != fingerprint([]*Node{b, a}, []User{u2, u1}) {
		t.Fatal("order must not change the fingerprint (would cause needless reloads)")
	}
	if fingerprint([]*Node{a}, nil) == fingerprint([]*Node{a, b}, nil) || fingerprint(nil, []User{u1}) == fingerprint(nil, []User{u2}) {
		t.Fatal("content changes must change the fingerprint")
	}
}

// One broken node from a subscription must not block updates of the whole config.
func TestCoreApplyExcludesBrokenNode(t *testing.T) {
	cfg := coreCfg(t)
	core := NewCore(cfg)
	t.Cleanup(core.Stop)
	good := allProtocolNodes(t)[:3]
	bad := ParseLinks("ss://no-such-cipher:pw@9.9.9.9:8388#broken") // sing-box rejects unknown methods
	if len(bad) != 1 {
		t.Fatal("test setup")
	}
	active, applied, err := core.Apply(append(append([]*Node{}, good...), bad...), []User{{Name: "a", UUID: testUUID}}, "")
	if err != nil || !applied {
		t.Fatalf("apply: applied=%v err=%v", applied, err)
	}
	if len(active) != 3 {
		t.Fatalf("broken node must be excluded, active=%d", len(active))
	}
	for _, n := range active {
		if n.ID == bad[0].ID {
			t.Fatal("broken node is in the active set")
		}
	}
	// same input again: nothing to do, and the active set is reported consistently
	active2, applied2, err := core.Apply(append(append([]*Node{}, good...), bad...), []User{{Name: "a", UUID: testUUID}}, "")
	if err != nil || applied2 || len(active2) != 3 {
		t.Fatalf("second apply: %v %v %d", err, applied2, len(active2))
	}
	// a problem that is not in a node (bad reality key) must surface as an error, not hide nodes
	cfg2 := coreCfg(t)
	cfg2.Reality.PrivateKey = "garbage"
	if _, _, err := NewCore(cfg2).Apply(good, []User{{Name: "a", UUID: testUUID}}, ""); err == nil {
		t.Fatal("invalid reality key must be reported")
	}
}

// End to end with real sing-box processes:
//
//	target HTTP server <- upstream sing-box (shadowsocks server) <- node "good"
//	balancer's sing-box (users inbound, selector, socks probe inbound with per-node login)
//
// Verifies: auth_user routing (probe through one specific node), Clash API
// select/selected, reload counters, the watchdog failover and the DB writes.
func TestCoreEndToEnd(t *testing.T) {
	bin := singboxBin(t)
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer target.Close()

	// upstream shadowsocks server, the "VPN provider"
	ssPort := freePort(t)
	up := fmt.Sprintf(`{"log":{"level":"error"},"inbounds":[{"type":"shadowsocks","listen":"127.0.0.1","listen_port":%d,"method":"aes-128-gcm","password":"pw"}],"outbounds":[{"type":"direct"}]}`, ssPort)
	upPath := filepath.Join(t.TempDir(), "up.json")
	os.WriteFile(upPath, []byte(up), 0o600)
	upCmd := exec.CommandContext(ctx, bin, "run", "-c", upPath)
	upCmd.Stdout, upCmd.Stderr = os.Stderr, os.Stderr
	if err := upCmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer upCmd.Wait()
	defer cancel()
	for i := 0; i < 50; i++ {
		if c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", ssPort)); err == nil {
			c.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	ui := base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:pw"))
	goodN := ParseLinks(fmt.Sprintf("ss://%s@127.0.0.1:%d#good", ui, ssPort))[0]
	deadN := ParseLinks(fmt.Sprintf("ss://%s@127.0.0.1:%d#dead", ui, freePort(t)))[0] // nothing listens there
	nodes := []*Node{goodN, deadN}
	users := []User{{Name: "alice", UUID: testUUID}}

	cfg := coreCfg(t)
	cfg.ProbeURLs = []string{target.URL + "/"}
	cfg.BaselineAddrs = []string{target.Listener.Addr().String()}
	cfg.WatchInterval = time.Second

	store, err := NewStore(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer store.pool.Close()
	store.pool.Exec(ctx, "TRUNCATE checks, switches")

	core := NewCore(cfg)
	t.Cleanup(core.Stop)
	active, _, err := core.Apply(nodes, users, "")
	if err != nil || len(active) != 2 {
		t.Fatalf("apply: %v (%d active)", err, len(active))
	}
	go core.Run(ctx)
	if !core.WaitReady(ctx, 20*time.Second) {
		t.Fatal("sing-box did not become ready")
	}
	chk := NewChecker(cfg, store, core, &Notifier{})
	chk.SyncNodes(active)

	// 1. probing through a specific node: auth_user routing works
	if ms, err := chk.probe(ctx, goodN.Tag(), target.URL+"/", 5*time.Second); err != nil {
		t.Fatalf("probe via good node must work: %v", err)
	} else {
		t.Logf("probe via good node: %.0f ms", ms)
	}
	if _, err := chk.probe(ctx, deadN.Tag(), target.URL+"/", 3*time.Second); err == nil {
		t.Fatal("probe via dead node must fail (it would pass if routing ignored auth_user)")
	}

	// 2. tier1/tier2 fill the states with real results
	chk.tier1(ctx)
	chk.tier2(ctx)
	snap := chk.Snapshot()
	var goodScore, deadScore float64
	for _, n := range snap.Nodes {
		if n.Name == "good" {
			goodScore = n.Score
		} else {
			deadScore = n.Score
		}
	}
	if goodScore <= 0 || deadScore != 0 {
		t.Fatalf("scores: good=%v dead=%v", goodScore, deadScore)
	}
	// tier1+tier2 selected the good node on their own (evaluate -> switchTo -> Clash API)
	if sel, err := core.Selected(); err != nil || sel != goodN.Tag() {
		t.Fatalf("selected=%q err=%v, want %s", sel, err, goodN.Tag())
	}

	// 3. reload (new user): counters move, config stays valid, probes keep working
	gen := core.Gen()
	active, applied, err := core.Apply(nodes, append(users, User{Name: "bob", UUID: "6a3a4a6c-0b1e-4b0e-9d5e-1d2f3a4b5c6d"}), chk.CurrentTag())
	if err != nil || !applied || core.Gen() == gen || !core.RecentlyChanged(time.Second) {
		t.Fatalf("reload: applied=%v err=%v gen %d->%d", applied, err, gen, core.Gen())
	}
	core.WaitReady(ctx, 20*time.Second)
	time.Sleep(time.Second)
	chk.SyncNodes(active)
	if _, err := chk.probe(ctx, goodN.Tag(), target.URL+"/", 5*time.Second); err != nil {
		t.Fatalf("probe after reload: %v", err)
	}
	// the selector must come back to the chosen node after a reload (default = current)
	chk.reconcileSelector()
	if sel, _ := core.Selected(); sel != goodN.Tag() {
		t.Fatalf("selector after reload: %q", sel)
	}

	// 4. failover: force the dead node to be current, the watchdog must move away
	if err := core.Select(deadN.Tag()); err != nil {
		t.Fatal(err)
	}
	chk.SetCurrent(deadN.ID)
	time.Sleep(6 * time.Second) // let RecentlyChanged(5s) expire
	for i := 0; i < 3 && chk.CurrentTag() == deadN.Tag(); i++ {
		chk.watch(ctx)
	}
	if chk.CurrentTag() != goodN.Tag() {
		t.Fatalf("watchdog did not fail over, current=%s", chk.CurrentTag())
	}
	if sel, _ := core.Selected(); sel != goodN.Tag() {
		t.Fatalf("clash selector after failover: %q", sel)
	}
	core.CloseConnections()

	// 5. the DB got the checks and the switches
	var checks, switches int
	store.pool.QueryRow(ctx, `SELECT count(*) FROM checks`).Scan(&checks)
	store.pool.QueryRow(ctx, `SELECT count(*) FROM switches WHERE reason='failover'`).Scan(&switches)
	if checks < 3 || switches < 2 { // tier1 x2, tier2 x1 (dead node is skipped by tier2: TCP failed)
		t.Fatalf("db rows: checks=%d failover switches=%d", checks, switches)
	}
}
