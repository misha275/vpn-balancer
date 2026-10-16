package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testEndNode(t *testing.T) *EndNodeConfig {
	t.Helper()
	c := &EndNodeConfig{Name: "Тест", Host: "node.example.com", WorkDir: t.TempDir(), SingboxBin: os.Getenv("SINGBOX_BIN")}
	for i, typ := range endTypeNames() {
		in, err := NewInbound(typ, "", 20000+i)
		if err != nil {
			t.Fatal(err)
		}
		c.Inbounds = append(c.Inbounds, in)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	return c
}

var endUsers = []EndUser{{"alice", "11111111-1111-4111-8111-111111111111"}, {"bob", "22222222-2222-4222-8222-222222222222"}}

func TestEndNodeConfigPassesSingBoxCheck(t *testing.T) {
	bin := singboxBin(t)
	for _, mode := range []string{"self-signed", "acme"} {
		c := testEndNode(t)
		c.TLS.Mode = mode
		cfg, err := c.BuildConfig(endUsers)
		if err != nil {
			t.Fatal(err)
		}
		if err := CheckConfig(bin, cfg); err != nil {
			t.Errorf("tls %s: %v\n%s", mode, err, cfg)
		}
	}
	// no users at all is a valid state (the panel has nobody for the node yet)
	c := testEndNode(t)
	cfg, _ := c.BuildConfig(nil)
	if err := CheckConfig(bin, cfg); err != nil {
		t.Errorf("empty users: %v", err)
	}
}

func TestEndNodeLinksParse(t *testing.T) {
	c := testEndNode(t)
	want := map[string]string{"vless-reality": "vless", "vless-tls": "vless", "vless-ws": "vless", "vless-grpc": "vless",
		"trojan": "trojan", "trojan-ws": "trojan", "vmess-ws": "vmess", "shadowsocks": "shadowsocks", "hysteria2": "hysteria2"}
	for _, tp := range c.Templates() {
		in := tp.Title
		l, ok := fillTemplate(tp, "endnode", User{UUID: endUsers[0].UUID}, "Тест · "+in)
		if !ok {
			t.Errorf("%s: template not filled", in)
			continue
		}
		if strings.Contains(l, "{") && !strings.HasPrefix(l, "vmess://") {
			t.Errorf("%s: placeholder left in %s", in, l)
		}
		if in == "tuic" {
			continue // the pool parser has no tuic; clients do
		}
		ns := ParseLinks(l)
		if len(ns) != 1 || ns[0].Type != want[in] {
			t.Errorf("%s: parsed %+v from %s", in, ns, l)
		}
	}
}

func TestEndNodeValidate(t *testing.T) {
	c := &EndNodeConfig{Host: "h.example.com", TLS: EndTLS{Mode: "self-signed"}}
	if c.Validate() == nil {
		t.Error("no inbounds")
	}
	in1, _ := NewInbound("trojan", "a", 443)
	in2, _ := NewInbound("vless-tls", "b", 443)
	c.Inbounds = []EndInbound{in1, in2}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "порт 443") {
		t.Errorf("same tcp port: %v", err)
	}
	in3, _ := NewInbound("hysteria2", "c", 443) // udp: may share the number with tcp
	c.Inbounds = []EndInbound{in1, in3}
	if err := c.Validate(); err != nil {
		t.Errorf("udp and tcp on one port: %v", err)
	}
	if _, err := NewInbound("wireguard", "", 0); err == nil {
		t.Error("unknown type")
	}
	c.Inbounds = []EndInbound{{Name: "s", Type: "shadowsocks", Port: 1, Method: "rc4"}}
	if c.Validate() == nil {
		t.Error("legacy cipher must be refused")
	}
	c.Inbounds = []EndInbound{in1}
	c.TLS = EndTLS{Mode: "acme"}
	c.Host = "1.2.3.4"
	if c.Validate() == nil {
		t.Error("acme needs a domain")
	}
}

func TestEndNodeUsersMerge(t *testing.T) {
	got := mergeEndUsers([]EndUser{{"local", "u1"}, {"alice", "old"}}, []SyncUser{{Name: "alice", UUID: "new"}, {Name: "bob", UUID: "b"}})
	var s []string
	for _, u := range got {
		s = append(s, u.Name+"="+u.UUID)
	}
	if strings.Join(s, ",") != "alice=new,bob=b,local=u1" {
		t.Errorf("merge: %v", s)
	}
}

func TestEndNodeInitAndCLI(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "endnode.yaml")
	if err := endNodeInit(p, []string{"--name", "Хельсинки", "--host", "h.example.com", "--panel-url", "https://p.example.com", "--panel-token", "vpnb_x",
		"--inbounds", "vless-reality,hysteria2:8443,trojan", "--work-dir", dir}); err != nil {
		t.Fatal(err)
	}
	if err := endNodeInit(p, nil); err == nil {
		t.Error("an existing file is not overwritten")
	}
	c, err := LoadEndNode(p)
	if err != nil || len(c.Inbounds) != 3 || c.Inbounds[0].PrivateKey == "" || c.PanelToken != "vpnb_x" {
		t.Fatalf("load: %v %+v", err, c)
	}
	if err := RunEndNodeCLI(context.Background(), p, []string{"add", "vless-ws", "--port", "2053"}); err != nil {
		t.Fatal(err)
	}
	if err := RunEndNodeCLI(context.Background(), p, []string{"add", "vless-ws", "--port", "2053", "--name", "ws2"}); err == nil {
		t.Error("duplicate port refused")
	}
	if err := RunEndNodeCLI(context.Background(), p, []string{"del", "trojan"}); err != nil {
		t.Fatal(err)
	}
	c, _ = LoadEndNode(p)
	if len(c.Inbounds) != 3 {
		t.Errorf("after add+del: %d", len(c.Inbounds))
	}
}

// A real connection: the node runs sing-box, a second sing-box connects with the link made from the template and asks a local web server.
func TestEndNodeRealConnections(t *testing.T) {
	bin := singboxBin(t)
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "hello-from-web") }))
	defer web.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := &EndNodeConfig{Name: "T", Host: "127.0.0.1", WorkDir: t.TempDir(), SingboxBin: bin, AllowPrivate: true}
	ports := map[string]int{}
	for _, typ := range []string{"vless-tls", "vless-ws", "trojan", "vmess-ws", "shadowsocks", "hysteria2"} {
		p := freePort(t)
		in, _ := NewInbound(typ, "", p)
		ports[typ] = p
		c.Inbounds = append(c.Inbounds, in)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg, err := c.BuildConfig(endUsers)
	if err != nil {
		t.Fatal(err)
	}
	proc := NewSBProc(ctx, bin, c.WorkDir, "endnode")
	defer proc.Stop()
	if _, err := proc.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)

	for _, tp := range c.Templates() {
		tp := tp
		t.Run(tp.Title, func(t *testing.T) {
			l, _ := fillTemplate(tp, "endnode", User{UUID: endUsers[0].UUID}, "x")
			ns := ParseLinks(l)
			if len(ns) != 1 {
				t.Fatalf("parse %s", l)
			}
			sp := freePort(t)
			cl, _ := json.Marshal(map[string]any{
				"log":       map[string]any{"level": "error"},
				"inbounds":  []any{map[string]any{"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": sp}},
				"outbounds": []any{withTag(ns[0].Outbound, "out")},
				"route":     map[string]any{"final": "out"},
			})
			cp := NewSBProc(ctx, bin, t.TempDir(), "client")
			defer cp.Stop()
			if _, err := cp.Apply(cl); err != nil {
				t.Fatal(err)
			}
			var body string
			for i := 0; i < 20; i++ {
				time.Sleep(300 * time.Millisecond)
				if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", sp), time.Second); err == nil {
					c.Close()
					break
				}
			}
			hc := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(mustURL("socks5://127.0.0.1:" + fmt.Sprint(sp)))}}
			resp, err := hc.Get(web.URL)
			if err != nil {
				t.Fatalf("through %s: %v", tp.Title, err)
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			body = string(b)
			if body != "hello-from-web" {
				t.Errorf("body %q", body)
			}
		})
	}

	// a user who is not in the list cannot connect: the other password/uuid is refused
	l, _ := fillTemplate(c.Templates()[2], "endnode", User{UUID: "99999999-9999-4999-8999-999999999999"}, "x")
	if ns := ParseLinks(l); len(ns) == 1 {
		sp := freePort(t)
		cl, _ := json.Marshal(map[string]any{"log": map[string]any{"level": "error"},
			"inbounds":  []any{map[string]any{"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": sp}},
			"outbounds": []any{withTag(ns[0].Outbound, "out")}, "route": map[string]any{"final": "out"}})
		cp := NewSBProc(ctx, bin, t.TempDir(), "client2")
		defer cp.Stop()
		cp.Apply(cl)
		time.Sleep(1200 * time.Millisecond)
		hc := &http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(mustURL("socks5://127.0.0.1:" + fmt.Sprint(sp)))}}
		if resp, err := hc.Get(web.URL); err == nil {
			resp.Body.Close()
			t.Error("an unknown user must not get through")
		}
	}

	// removing a user restarts the node: the old connection is closed, the new config has only the remaining user
	cfg2, _ := c.BuildConfig(endUsers[1:])
	if restarted, err := proc.Apply(cfg2); err != nil || !restarted {
		t.Errorf("config change must restart: %v %v", restarted, err)
	}
	if restarted, _ := proc.Apply(cfg2); restarted {
		t.Error("the same config must not restart")
	}
}

func TestEndNodePrivateAddressesAreRejected(t *testing.T) {
	bin := singboxBin(t)
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "secret") }))
	defer web.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &EndNodeConfig{Name: "T", Host: "127.0.0.1", WorkDir: t.TempDir(), SingboxBin: bin}
	p := freePort(t)
	in, _ := NewInbound("trojan", "", p)
	c.Inbounds = []EndInbound{in}
	cfg, _ := c.BuildConfig(endUsers)
	proc := NewSBProc(ctx, bin, c.WorkDir, "endnode")
	defer proc.Stop()
	if _, err := proc.Apply(cfg); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	l, _ := fillTemplate(c.Templates()[0], "endnode", User{UUID: endUsers[0].UUID}, "x")
	ns := ParseLinks(l)
	sp := freePort(t)
	cl, _ := json.Marshal(map[string]any{"log": map[string]any{"level": "error"},
		"inbounds":  []any{map[string]any{"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": sp}},
		"outbounds": []any{withTag(ns[0].Outbound, "out")}, "route": map[string]any{"final": "out"}})
	cp := NewSBProc(ctx, bin, t.TempDir(), "client")
	defer cp.Stop()
	cp.Apply(cl)
	time.Sleep(1200 * time.Millisecond)
	hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(mustURL("socks5://127.0.0.1:" + fmt.Sprint(sp)))}}
	if resp, err := hc.Get(web.URL); err == nil {
		resp.Body.Close()
		t.Error("a user must not reach private addresses of the node")
	}
}

func withTag(o map[string]any, tag string) map[string]any {
	m := map[string]any{}
	for k, v := range o {
		m[k] = v
	}
	m["tag"] = tag
	return m
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

// Blocking in the panel cuts the user off every server: he disappears from the list, the node restarts without him, and
// the connection that was open is closed.
func TestEndNodeFollowsPanelBlocking(t *testing.T) {
	bin := singboxBin(t)
	cfg := siteTestCfg()
	_, st, srv := startSite(t, cfg)
	pctx := context.Background()
	st.pool.Exec(pctx, "TRUNCATE servers, server_traffic CASCADE")
	st.pool.Exec(pctx, "DELETE FROM users WHERE name='blk-a'")
	uuid, _ := st.AddUser(pctx, "blk-a")
	st.pool.Exec(pctx, `UPDATE users SET subs=ARRAY['servers'] WHERE name='blk-a'`)
	_, tok, _ := st.CreateServer(pctx, "Узел", "endnode", "")

	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer web.Close()
	dir := t.TempDir()
	path := filepath.Join(dir, "endnode.yaml")
	port := freePort(t)
	if err := endNodeInit(path, []string{"--name", "Узел", "--host", "127.0.0.1", "--panel-url", srv.URL, "--panel-token", tok,
		"--inbounds", fmt.Sprintf("trojan:%d", port), "--work-dir", dir}); err != nil {
		t.Fatal(err)
	}
	c, _ := LoadEndNode(path)
	c.SingboxBin, c.AllowPrivate, c.SyncInterval = bin, true, time.Second
	writeEndNode(path, c)
	old := endNodeTick
	endNodeTick = 300 * time.Millisecond
	defer func() { endNodeTick = old }()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { RunEndNode(ctx, path); close(done) }()
	defer func() { cancel(); <-done }()

	connect := func() error {
		l, _ := fillTemplate(c.Templates()[0], "endnode", User{UUID: uuid}, "x")
		ns := ParseLinks(l)
		sp := freePort(t)
		cl, _ := json.Marshal(map[string]any{"log": map[string]any{"level": "error"},
			"inbounds":  []any{map[string]any{"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": sp}},
			"outbounds": []any{withTag(ns[0].Outbound, "out")}, "route": map[string]any{"final": "out"}})
		cp := NewSBProc(ctx, bin, t.TempDir(), "client")
		defer cp.Stop()
		if _, err := cp.Apply(cl); err != nil {
			return err
		}
		time.Sleep(800 * time.Millisecond)
		hc := &http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(mustURL("socks5://127.0.0.1:" + fmt.Sprint(sp)))}}
		resp, err := hc.Get(web.URL)
		if err != nil {
			return err
		}
		resp.Body.Close()
		return nil
	}
	var err error
	for i := 0; i < 25; i++ { // the node starts, asks the panel, gets the user
		time.Sleep(600 * time.Millisecond)
		if err = connect(); err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("an active user must connect: %v", err)
	}
	if err := st.BlockUser(pctx, "blk-a", "unpaid", ""); err != nil {
		t.Fatal(err)
	}
	blocked := false
	for i := 0; i < 20 && !blocked; i++ {
		time.Sleep(700 * time.Millisecond)
		blocked = connect() != nil
	}
	if !blocked {
		t.Fatal("a blocked user must not connect to the node")
	}
	st.UnblockUser(pctx, "blk-a")
	for i := 0; i < 25; i++ {
		time.Sleep(700 * time.Millisecond)
		if connect() == nil {
			return
		}
	}
	t.Error("an unblocked user must be able to connect again")
}
