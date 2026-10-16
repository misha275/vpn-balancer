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
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWGNodeInitPeersAndSelect(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "wgnode.yaml")
	if err := wgNodeInit(p, []string{"--subscription", "https://s.example.com/sub/x", "--endpoint", "1.2.3.4", "--lan", "192.168.0.0/24", "--work-dir", dir}); err != nil {
		t.Fatal(err)
	}
	c, err := LoadWGNode(p)
	if err != nil || len(c.Peers) != 1 || c.Peers[0].Subnets[0] != "192.168.0.0/24" || c.PrivateKey == "" {
		t.Fatalf("init: %v %+v", err, c)
	}
	ctx := context.Background()
	if err := RunWGNodeCLI(ctx, p, []string{"peer", "add", "phone"}); err != nil {
		t.Fatal(err)
	}
	if err := RunWGNodeCLI(ctx, p, []string{"peer", "add", "other", "--lan", "192.168.0.0/24"}); err == nil {
		t.Error("an overlapping network is refused")
	}
	if err := RunWGNodeCLI(ctx, p, []string{"peer", "add", "router"}); err == nil {
		t.Error("duplicate name")
	}
	c, _ = LoadWGNode(p)
	if len(c.Peers) != 2 || c.Peers[0].Address == c.Peers[1].Address {
		t.Errorf("peers: %+v", c.Peers)
	}
	// router script and profile are built from the same helpers as in the full installation
	wp := WGPeer{Name: "router", PrivateKey: c.Peers[0].PrivateKey, Address: c.Peers[0].Address, Subnets: c.Peers[0].Subnets}
	if s := routerOSScript(c.cfg(), c.PublicKey, "1.2.3.4", wp); !strings.Contains(s, "192.168.0.0/24") || !strings.Contains(s, c.PublicKey) {
		t.Error("router script")
	}

	nodes := []*Node{{ID: "1", Name: "Германия 1"}, {ID: "2", Name: "Германия 2"}, {ID: "3", Name: "Финляндия"}}
	if n, err := selectServer(nodes, "Финл"); err != nil || n.ID != "3" {
		t.Errorf("part of the name: %v %v", n, err)
	}
	if _, err := selectServer(nodes, "Герм"); err == nil || !strings.Contains(err.Error(), "несколько") {
		t.Errorf("ambiguous: %v", err)
	}
	if n, err := selectServer(nodes, "Германия 2"); err != nil || n.ID != "2" {
		t.Errorf("exact: %v", err)
	}
	if _, err := selectServer(nodes, "Япония"); err == nil {
		t.Error("unknown")
	}
	c.Server, c.ServerID = "Германия 2", "2"
	if n := c.pick(nodes); n == nil || n.ID != "2" {
		t.Error("pick by id")
	}
	nodes[1].Name = "Берлин" // renamed in the subscription: the id still finds it
	if n := c.pick(nodes); n == nil || n.ID != "2" {
		t.Error("pick survives a rename")
	}
}

func TestWGNodeNeverExitsDirectly(t *testing.T) {
	bin := singboxBin(t)
	c := &WGNodeConfig{WGPort: 51999, WGNetwork: wgDefaultNetwork, SingboxBin: bin}
	c.PrivateKey, c.PublicKey, _ = wgGenKey()
	c.addPeer("router", []string{"192.168.0.0/24"})
	cfg, err := BuildWGNodeConfig(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckConfig(bin, cfg); err != nil {
		t.Fatalf("no server: %v\n%s", err, cfg)
	}
	var m map[string]any
	json.Unmarshal(cfg, &m)
	rules := m["route"].(map[string]any)["rules"].([]any)
	if len(rules) != 1 || rules[0].(map[string]any)["action"] != "reject" {
		t.Errorf("without a server everything is rejected: %v", rules)
	}
	n := ParseLinks("trojan://pw@example.org:443?security=tls&sni=example.org#x")[0]
	cfg, _ = BuildWGNodeConfig(c, n)
	if err := CheckConfig(bin, cfg); err != nil {
		t.Fatalf("with a server: %v\n%s", err, cfg)
	}
	if !strings.Contains(string(cfg), `"final": "out"`) {
		t.Error("the final outbound is the chosen server")
	}
}

// The whole path: a client device -> WireGuard -> wgnode -> the chosen server (a trojan end node) -> a web server.
func TestWGNodeEndToEnd(t *testing.T) {
	bin := singboxBin(t)
	// the target must not be a loopback address: inside the tunnel 127.0.0.1 is the device itself
	var hostIP string
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLoopback() {
			hostIP = ipn.IP.String()
			break
		}
	}
	if hostIP == "" {
		t.Skip("no non-loopback address")
	}
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	web := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "via-wg-node") }))
	web.Listener = ln
	web.Start()
	defer web.Close()
	target := fmt.Sprintf("http://%s:%d/", hostIP, ln.Addr().(*net.TCPAddr).Port)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// the chosen server: a plain end node
	en := &EndNodeConfig{Name: "S", Host: "127.0.0.1", WorkDir: t.TempDir(), SingboxBin: bin, AllowPrivate: true}
	port := freePort(t)
	in, _ := NewInbound("trojan", "", port)
	en.Inbounds = []EndInbound{in}
	ecfg, _ := en.BuildConfig(endUsers)
	eproc := NewSBProc(ctx, bin, en.WorkDir, "endnode")
	defer eproc.Stop()
	if _, err := eproc.Apply(ecfg); err != nil {
		t.Fatal(err)
	}
	link, _ := fillTemplate(en.Templates()[0], "endnode", User{UUID: endUsers[0].UUID}, "Финляндия")
	sub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, base64.StdEncoding.EncodeToString([]byte(link)))
	}))
	defer sub.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "wgnode.yaml")
	wgPort := freeUDPPort(t)
	if err := wgNodeInit(path, []string{"--subscription", sub.URL, "--endpoint", "127.0.0.1", "--port", fmt.Sprint(wgPort), "--work-dir", dir, "--peer", "dev", "--lan", ""}); err != nil {
		t.Fatal(err)
	}
	if err := RunWGNodeCLI(ctx, path, []string{"select", "Финл"}); err != nil {
		t.Fatal(err)
	}
	c, _ := LoadWGNode(path)
	c.SingboxBin = bin
	c.save(path)
	done := make(chan struct{})
	go func() { RunWGNode(ctx, path); close(done) }()
	defer func() { cancel(); <-done }()
	time.Sleep(3 * time.Second)

	// the device: sing-box with a WireGuard endpoint
	pe := c.Peers[0]
	sp := freePort(t)
	cl, _ := json.Marshal(map[string]any{
		"log": map[string]any{"level": "error"},
		"endpoints": []any{map[string]any{"type": "wireguard", "tag": "wgc", "system": false, "mtu": wgMTU,
			"address": []string{pe.Address + "/32"}, "private_key": pe.PrivateKey,
			"peers": []any{map[string]any{"address": "127.0.0.1", "port": wgPort, "public_key": c.PublicKey, "allowed_ips": []string{"0.0.0.0/0"}, "persistent_keepalive_interval": 5}}}},
		"inbounds":  []any{map[string]any{"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": sp}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"final": "wgc"},
	})
	cp := NewSBProc(ctx, bin, t.TempDir(), "device")
	defer cp.Stop()
	if _, err := cp.Apply(cl); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	hc := &http.Client{Timeout: 6 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(mustURL("socks5://127.0.0.1:" + fmt.Sprint(sp)))}}
	var body string
	var last error
	for i := 0; i < 3 && body == ""; i++ {
		resp, err := hc.Get(target)
		if err != nil {
			last = err
			time.Sleep(time.Second)
			continue
		}
		b := make([]byte, 64)
		n, _ := resp.Body.Read(b)
		resp.Body.Close()
		body = string(b[:n])
	}
	if body != "via-wg-node" {
		t.Fatalf("through the tunnel: %q %v", body, last)
	}
	_ = os.Remove
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.LocalAddr().(*net.UDPAddr).Port
}
