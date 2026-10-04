package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWGKeys(t *testing.T) {
	priv, pub, err := wgGenKey()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := wgPubFromPriv(priv); err != nil || got != pub {
		t.Fatalf("public key does not match: %v %q %q", err, got, pub)
	}
	if len(priv) != 44 || len(pub) != 44 {
		t.Fatalf("WireGuard keys are 32 bytes in base64: %d %d", len(priv), len(pub))
	}
}

func TestParseSubnets(t *testing.T) {
	cfg := testCfg()
	cfg.WGNetwork = wgDefaultNetwork
	tun := cfg.wgNetwork()
	got, err := parseSubnets([]string{" 192.168.50.7/24 ", "", "10.20.0.0/16"}, tun)
	if err != nil || len(got) != 2 || got[0] != "192.168.50.0/24" {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{"0.0.0.0/0", "10.0.0.0/7", "10.77.0.0/24", "10.77.0.128/25", "fe80::/64", "nonsense", "192.168.1.1"} {
		if _, err := parseSubnets([]string{bad}, tun); err == nil {
			t.Fatalf("%q must be rejected", bad)
		}
	}
	if _, bad := subnetsOverlap([]string{"192.168.50.0/24"}, []string{"192.168.50.128/25"}); !bad {
		t.Fatal("overlap not detected")
	}
	if _, bad := subnetsOverlap([]string{"192.168.50.0/24"}, []string{"192.168.51.0/24"}); bad {
		t.Fatal("false overlap")
	}
}

func wgTestPeers(t *testing.T) (string, []WGPeer) {
	t.Helper()
	spriv, _, _ := wgGenKey()
	p1priv, p1pub, _ := wgGenKey()
	_, p2pub, _ := wgGenKey()
	return spriv, []WGPeer{
		{Name: "office", PrivateKey: p1priv, PublicKey: p1pub, Address: "10.77.0.2", Subnets: []string{"192.168.50.0/24"}, Enabled: true},
		{Name: "phone", PrivateKey: "x", PublicKey: p2pub, Address: "10.77.0.3", Subnets: []string{}, Enabled: true},
		{Name: "off", PrivateKey: "x", PublicKey: p2pub, Address: "10.77.0.4", Enabled: false},
	}
}

func TestBuildWGConfig(t *testing.T) {
	cfg := testCfg()
	cfg.WGNetwork, cfg.WGPort = wgDefaultNetwork, 0
	spriv, peers := wgTestPeers(t)
	if data, err := buildWGConfig(cfg, spriv, nil); err != nil || data != nil {
		t.Fatalf("no peers means no tunnel: %v %v", data, err)
	}
	data, err := buildWGConfig(cfg, spriv, peers)
	if err != nil {
		t.Fatal(err)
	}
	var conf struct {
		Endpoints []struct {
			Address    []string `json:"address"`
			ListenPort int      `json:"listen_port"`
			Peers      []struct {
				PublicKey  string   `json:"public_key"`
				AllowedIPs []string `json:"allowed_ips"`
			} `json:"peers"`
		} `json:"endpoints"`
		Outbounds []map[string]any `json:"outbounds"`
		Route     struct {
			Rules []map[string]any `json:"rules"`
			Final string           `json:"final"`
		} `json:"route"`
	}
	if err := json.Unmarshal(data, &conf); err != nil {
		t.Fatal(err)
	}
	ep := conf.Endpoints[0]
	if ep.ListenPort != wgDefaultPort || ep.Address[0] != "10.77.0.1/24" || len(ep.Peers) != 2 {
		t.Fatalf("endpoint: %+v", ep)
	}
	if got := ep.Peers[0].AllowedIPs; len(got) != 2 || got[0] != "10.77.0.2/32" || got[1] != "192.168.50.0/24" {
		t.Fatalf("allowed ips: %v", got)
	}
	if len(conf.Outbounds) != 2 || conf.Outbounds[0]["username"] != "wg-office" || conf.Outbounds[0]["server_port"].(float64) != float64(cfg.wgFrontPort()) {
		t.Fatalf("outbounds: %v", conf.Outbounds)
	}
	last := conf.Route.Rules[len(conf.Route.Rules)-1]
	if last["action"] != "reject" {
		t.Fatalf("a source nobody owns must be rejected, not sent out: %v", last)
	}
	if strings.Contains(string(data), `"direct"`) {
		t.Fatal("the tunnel config must never contain a direct exit")
	}
	if bin := os.Getenv("SINGBOX_BIN"); bin != "" {
		p := filepath.Join(t.TempDir(), "wg.json")
		_ = os.WriteFile(p, data, 0o600)
		if out, err := exec.Command(bin, "check", "-c", p).CombinedOutput(); err != nil {
			t.Fatalf("sing-box check: %v: %s", err, out)
		}
	}
}

func TestBuildConfigHasWGInbound(t *testing.T) {
	cfg := coreCfgNoBin()
	ns := allProtocolNodes(t)
	cfg.setWGPeers(nil)
	data, _ := BuildConfig(cfg, ns, []User{{Name: "u", UUID: testUUID}}, "")
	if strings.Contains(string(data), "wg-in") {
		t.Fatal("no peers: no wg-in")
	}
	_, peers := wgTestPeers(t)
	cfg.setWGPeers(peers)
	data, err := BuildConfig(cfg, ns, []User{{Name: "u", UUID: testUUID}}, "")
	if err != nil {
		t.Fatal(err)
	}
	var conf struct {
		Inbounds []map[string]any `json:"inbounds"`
		Route    struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	_ = json.Unmarshal(data, &conf)
	found := 0
	for _, in := range conf.Inbounds {
		if in["tag"] == "wg-in" {
			found++
			if in["listen"] != "127.0.0.1" || len(in["users"].([]any)) != 2 {
				t.Fatalf("wg-in: %v", in)
			}
		}
	}
	if found != 1 {
		t.Fatalf("want one wg-in, got %d", found)
	}
	sniff := false
	for _, r := range conf.Route.Rules {
		if r["action"] == "sniff" {
			sniff = true
		}
	}
	if !sniff {
		t.Fatal("domain rules need the sniff rule for wg-in")
	}
	// no node may carry traffic -> the tunnel is rejected like the apps are
	data, _ = BuildConfig(cfg, nil, []User{{Name: "u", UUID: testUUID}}, "")
	if !strings.Contains(string(data), `"wg-in"`) || !strings.Contains(string(data), `"reject"`) {
		t.Fatal("without nodes the wg-in traffic must be rejected")
	}
	if cfg.wgSig() != "office,phone" {
		t.Fatalf("sig %q", cfg.wgSig())
	}
}

func coreCfgNoBin() *Config {
	cfg := testCfg()
	cfg.TestSecret = "s3cret-for-tests"
	cfg.Reality.PrivateKey = testPriv
	cfg.Reality.PublicKey = testPBK
	cfg.Reality.ShortID = "0123456789abcdef"
	cfg.Reality.HandshakeServer = "www.microsoft.com"
	cfg.Reality.HandshakePort = 443
	cfg.InboundPort = 443
	cfg.GatewayBase = 21000
	cfg.WGNetwork = wgDefaultNetwork
	return cfg
}

func TestRouterOSScriptAndProfile(t *testing.T) {
	cfg := coreCfgNoBin()
	_, peers := wgTestPeers(t)
	s := routerOSScript(cfg, "SERVERPUB=", "192.168.0.10", peers[0])
	for _, want := range []string{`private-key="` + peers[0].PrivateKey + `"`, `public-key="SERVERPUB="`, "endpoint-address=192.168.0.10", "endpoint-port=51820",
		"address=10.77.0.2/24", "192.168.50.0/24", "lookup-only-in-table", "192.168.50.1/24", "ranges=192.168.50.100-192.168.50.200", "dns-server=1.1.1.1"} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	if strings.Contains(s, "%!") || strings.Contains(s, "%[") {
		t.Fatalf("formatting error in the script:\n%s", s)
	}
	q := wgQuickConfig(cfg, "SERVERPUB=", "vpn.example.com", peers[1])
	if !strings.Contains(q, "Endpoint = vpn.example.com:51820") || !strings.Contains(q, "Address = 10.77.0.3/32") || !strings.Contains(q, "AllowedIPs = 0.0.0.0/0") {
		t.Fatalf("profile:\n%s", q)
	}
}

func TestStoreWGPeers(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	_, _ = st.pool.Exec(ctx, "TRUNCATE wg_peers")
	_, _ = st.pool.Exec(ctx, "TRUNCATE wg_server")
	cfg := coreCfgNoBin()
	priv, pub, err := st.WGServerKey(ctx)
	if err != nil || priv == "" {
		t.Fatal(err)
	}
	if p2, pub2, _ := st.WGServerKey(ctx); p2 != priv || pub2 != pub {
		t.Fatal("the server key must stay the same")
	}
	a, err := st.AddWGPeer(ctx, cfg, "office", []string{"192.168.50.0/24"})
	if err != nil || a.Address != "10.77.0.2" {
		t.Fatalf("%v %+v", err, a)
	}
	b, err := st.AddWGPeer(ctx, cfg, "phone", nil)
	if err != nil || b.Address != "10.77.0.3" || len(b.Subnets) != 0 {
		t.Fatalf("%v %+v", err, b)
	}
	if _, err := st.AddWGPeer(ctx, cfg, "office", nil); err == nil {
		t.Fatal("duplicate name")
	}
	if _, err := st.AddWGPeer(ctx, cfg, "x", []string{"192.168.50.128/25"}); err == nil {
		t.Fatal("overlapping subnet")
	}
	if _, err := st.AddWGPeer(ctx, cfg, "bad name", nil); err == nil {
		t.Fatal("bad name")
	}
	if err := st.SetWGPeerEnabled(ctx, "phone", false); err != nil {
		t.Fatal(err)
	}
	ps, _ := st.ListWGPeers(ctx)
	if len(ps) != 2 || ps[1].Enabled || ps[0].PrivateKey != a.PrivateKey || ps[0].Subnets[0] != "192.168.50.0/24" {
		t.Fatalf("%+v", ps)
	}
	if ok, err := st.DeleteWGPeer(ctx, "office"); !ok || err != nil {
		t.Fatal(ok, err)
	}
	c, err := st.AddWGPeer(ctx, cfg, "again", nil) // the freed address 10.77.0.2 is used again
	if err != nil || c.Address != "10.77.0.2" {
		t.Fatalf("%v %+v", err, c)
	}
}

// socks5Connect opens a TCP connection to ip:port through a SOCKS5 server without a login.
func socks5Connect(t *testing.T, proxy, ip string, port int) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxy, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	c.Write([]byte{5, 1, 0})
	b := make([]byte, 16)
	if _, err := io.ReadFull(c, b[:2]); err != nil {
		t.Fatal(err)
	}
	req := append([]byte{5, 1, 0, 1}, net.ParseIP(ip).To4()...)
	req = append(req, byte(port>>8), byte(port))
	c.Write(req)
	if _, err := io.ReadFull(c, b[:10]); err != nil || b[1] != 0 {
		t.Fatalf("socks connect failed: %v %v", err, b[:10])
	}
	return c
}

// The whole chain: a "router" (sing-box WireGuard client) -> UDP tunnel -> WireGuard sing-box of the gateway ->
// front -> instance (wg-in) -> upstream. It also shows that a new configuration of the gateway does not drop the
// tunnel and that the traffic is counted for the peer.
func TestWireGuardChainThroughGateway(t *testing.T) {
	bin := singboxBin(t)
	e, _, _ := newTestEngine(t)
	cfg := coreCfg(t)
	cfg.GatewayBase = e.base
	cfg.WGNetwork = wgDefaultNetwork
	cfg.WGPort = freePort(t)
	spriv, peers := wgTestPeers(t)
	spub, _ := wgPubFromPriv(spriv)
	peers = peers[:1]
	cfg.setWGPeers(peers)
	up := tagServer(t, "up")

	slotConf := func(tagPort int) []byte {
		return []byte(fmt.Sprintf(`{"log":{"level":"warn"},"inbounds":[{"type":"socks","tag":"wg-in","listen":"127.0.0.1","listen_port":1,
		"users":[{"username":"wg-office","password":%q}]}],
		"outbounds":[{"type":"direct","tag":"direct","override_address":"127.0.0.1","override_port":%d}],"route":{"rules":[{"inbound":["wg-in"],"action":"sniff"}],"final":"direct"}}`,
			cfg.wgSocksPassword(), tagPort))
	}
	if _, err := e.Apply(context.Background(), ApplyReq{Config: slotConf(up), Fingerprint: "a"}); err != nil {
		t.Fatal(err)
	}
	wgConf, err := buildWGConfig(cfg, spriv, peers)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.ApplyWG(context.Background(), wgConf, "wg1"); err != nil {
		t.Fatal(err)
	}
	if running, fp := e.wgState(); !running || fp != "wg1" {
		t.Fatal("tunnel is not running")
	}
	if err := e.ApplyWG(context.Background(), wgConf, "wg1"); err != nil { // same config again: nothing happens
		t.Fatal(err)
	}

	// the router
	clientPort := freePort(t)
	client := fmt.Sprintf(`{"log":{"level":"warn"},"endpoints":[{"type":"wireguard","tag":"wgc","system":false,"name":"wgc0","mtu":1380,
	"address":["10.77.0.2/24","192.168.50.7/32"],"private_key":%q,"peers":[{"address":"127.0.0.1","port":%d,"public_key":%q,"allowed_ips":["0.0.0.0/0"],"persistent_keepalive_interval":5}]}],
	"inbounds":[{"type":"socks","tag":"in","listen":"127.0.0.1","listen_port":%d}],"outbounds":[{"type":"direct","tag":"direct"}],
	"route":{"rules":[{"inbound":["in"],"outbound":"wgc"}],"final":"direct"}}`, peers[0].PrivateKey, cfg.wgPort(), spub, clientPort)
	cp := filepath.Join(t.TempDir(), "client.json")
	_ = os.WriteFile(cp, []byte(client), 0o600)
	cmd := exec.Command(bin, "run", "-c", cp)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	proxy := fmt.Sprintf("127.0.0.1:%d", clientPort)
	var c net.Conn
	for i := 0; i < 40; i++ { // sing-box start + WireGuard handshake
		time.Sleep(250 * time.Millisecond)
		if conn, err := net.DialTimeout("tcp", proxy, time.Second); err == nil {
			conn.Close()
			break
		}
	}
	c = socks5Connect(t, proxy, "10.99.9.9", 80)
	if got := ask(t, c, "ping"); got != "up:ping" {
		t.Fatalf("through the tunnel: %q", got)
	}

	// a new configuration of the gateway: the tunnel and the open connection survive, new connections use the new instance
	up2 := tagServer(t, "up2")
	if _, err := e.Apply(context.Background(), ApplyReq{Config: slotConf(up2), Fingerprint: "b"}); err != nil {
		t.Fatal(err)
	}
	if got := ask(t, c, "again"); got != "up:again" {
		t.Fatalf("an open connection must stay on the old instance: %q", got)
	}
	c2 := socks5Connect(t, proxy, "10.99.9.9", 80)
	if got := ask(t, c2, "new"); got != "up2:new" {
		t.Fatalf("a new connection must use the new instance: %q", got)
	}
	c2.Close()
	c.Close()

	// counted for the peer, as a WireGuard client
	time.Sleep(2 * time.Second)
	st := e.tr.drain()
	if d := st.Deltas["wg-office"]; d.Conns < 2 || d.Up == 0 || d.Down == 0 {
		t.Fatalf("traffic of the peer: %+v (all: %+v)", d, st.Deltas)
	}

	// switching the tunnel off closes the port
	if err := e.ApplyWG(context.Background(), nil, ""); err != nil {
		t.Fatal(err)
	}
	if running, _ := e.wgState(); running {
		t.Fatal("tunnel must be stopped")
	}
}
