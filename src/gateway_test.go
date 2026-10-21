package main

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

// Tests of the seamless switching. They need the real sing-box binary (SINGBOX_BIN).

// tagServer answers every line with "<tag>:<line>" so a test can see which backend served a connection.
func tagServer(t *testing.T, tag string) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 256)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						fmt.Fprintf(c, "%s:%s", tag, buf[:n])
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

// gwConf is a minimal sing-box config: the inbound "vless-in" (the engine moves it to the port of its slot)
// forwards everything to a tag server, so no Reality or upstream node is needed.
func gwConf(target int) []byte {
	return []byte(fmt.Sprintf(`{"log":{"level":"warn"},"inbounds":[{"type":"direct","tag":"vless-in","listen":"::","listen_port":1,
	"override_address":"127.0.0.1","override_port":%d}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`, target))
}

func ask(t *testing.T, c net.Conn, word string) string {
	t.Helper()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprint(c, word); err != nil {
		return "ERR:" + err.Error()
	}
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil && n == 0 {
		return "ERR:" + err.Error()
	}
	return string(buf[:n])
}

func newTestEngine(t *testing.T) (*Engine, int, context.CancelFunc) {
	t.Helper()
	cfg := coreCfg(t)
	e := NewEngine(cfg, "127.0.0.1", false)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	for i := 0; i < 50 && !e.frontUp.Load(); i++ {
		time.Sleep(50 * time.Millisecond)
	}
	if !e.frontUp.Load() {
		t.Fatal("front did not start")
	}
	return e, cfg.InboundPort, cancel
}

func liveSlots(e *Engine) int {
	st, _ := e.State(context.Background())
	return len(st.Slots)
}

func TestGatewayKeepsOpenConnectionsAcrossSwitch(t *testing.T) {
	singboxBin(t)
	e, port, _ := newTestEngine(t)
	a, b := tagServer(t, "A"), tagServer(t, "B")
	ctx := context.Background()
	front := fmt.Sprintf("127.0.0.1:%d", port)

	if _, err := e.Apply(ctx, ApplyReq{Config: gwConf(a), Fingerprint: "v1"}); err != nil {
		t.Fatal(err)
	}
	c1, err := net.Dial("tcp", front)
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	if got := ask(t, c1, "x"); got != "A:x" {
		t.Fatalf("first connection: %q", got)
	}

	// a new configuration goes live; the open connection must not notice
	gen := e.gen.Load()
	if _, err := e.Apply(ctx, ApplyReq{Config: gwConf(b), Fingerprint: "v2"}); err != nil {
		t.Fatal(err)
	}
	if e.gen.Load() == gen {
		t.Fatal("generation must change on a switch")
	}
	if got := ask(t, c1, "y"); got != "A:y" {
		t.Fatalf("the old connection must keep working on the old instance, got %q", got)
	}
	c2, err := net.Dial("tcp", front)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if got := ask(t, c2, "z"); got != "B:z" {
		t.Fatalf("a new connection must use the new configuration, got %q", got)
	}
	if n := liveSlots(e); n != 2 {
		t.Fatalf("both instances must run while the old connection is open, got %d", n)
	}

	// when the last old connection ends, the old instance is stopped
	c1.Close()
	deadline := time.Now().Add(15 * time.Second)
	for liveSlots(e) != 1 && time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
	}
	if n := liveSlots(e); n != 1 {
		t.Fatalf("the drained instance must be stopped, %d still run", n)
	}
	if got := ask(t, c2, "w"); got != "B:w" {
		t.Fatalf("the new connection must survive the cleanup: %q", got)
	}
}

func TestGatewayUrgentSwitchCutsOldConnectionsSoon(t *testing.T) {
	singboxBin(t)
	e, port, _ := newTestEngine(t)
	a, b := tagServer(t, "A"), tagServer(t, "B")
	ctx := context.Background()
	if _, err := e.Apply(ctx, ApplyReq{Config: gwConf(a), Fingerprint: "v1"}); err != nil {
		t.Fatal(err)
	}
	c1, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	if got := ask(t, c1, "x"); got != "A:x" {
		t.Fatalf("%q", got)
	}
	if _, err := e.Apply(ctx, ApplyReq{Config: gwConf(b), Fingerprint: "v2", Urgent: true}); err != nil { // DrainUrgent = 1 s in tests
		t.Fatal(err)
	}
	time.Sleep(5 * time.Second)
	if got := ask(t, c1, "y"); got == "A:y" {
		t.Fatal("an urgent change must not leave the old connection alive")
	}
}

func TestGatewayBadConfigKeepsServing(t *testing.T) {
	singboxBin(t)
	e, port, _ := newTestEngine(t)
	a := tagServer(t, "A")
	ctx := context.Background()
	if _, err := e.Apply(ctx, ApplyReq{Config: gwConf(a), Fingerprint: "v1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Apply(ctx, ApplyReq{Config: []byte(`{"inbounds":[{"type":"no-such-type","tag":"vless-in"}]}`), Fingerprint: "v2"}); err == nil {
		t.Fatal("a broken configuration must be refused")
	}
	st, _ := e.State(ctx)
	if st.Fingerprint != "v1" || len(st.Slots) != 1 {
		t.Fatalf("the old configuration must stay live: %+v", st)
	}
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := ask(t, c, "x"); got != "A:x" {
		t.Fatalf("%q", got)
	}
}

func TestGatewayRestartsADeadInstance(t *testing.T) {
	singboxBin(t)
	e, port, _ := newTestEngine(t)
	a := tagServer(t, "A")
	if _, err := e.Apply(context.Background(), ApplyReq{Config: gwConf(a), Fingerprint: "v1"}); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	cmd := e.slots[e.active].cmd
	e.mu.Unlock()
	_ = cmd.Process.Kill()
	deadline := time.Now().Add(15 * time.Second)
	var got string
	for time.Now().Before(deadline) {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			got = ask(t, c, "x")
			c.Close()
			if got == "A:x" {
				return
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("the watchdog did not bring the instance back: %q", got)
}

// A restarted controller finds the gateway running exactly its configuration and does not switch anything.
func TestControllerAdoptsRunningGateway(t *testing.T) {
	singboxBin(t)
	cfg := coreCfg(t)
	cfg.Gateway = "external"
	p := freePort(t)
	cfg.GatewayListen = fmt.Sprintf("127.0.0.1:%d", p)
	cfg.GatewayURL = fmt.Sprintf("http://127.0.0.1:%d", p)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { RunGateway(ctx, cfg); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	users := []User{{Name: "a", UUID: testUUID}}
	nodes := allProtocolNodes(t)[:3]

	var c1 *Core
	for i := 0; i < 50; i++ {
		c1 = NewCore(cfg)
		if _, err := c1.GatewayState(); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	act1, applied, err := c1.Apply(nodes, users, "")
	if err != nil || !applied || len(act1) != 3 {
		t.Fatalf("first apply: applied=%v err=%v active=%d", applied, err, len(act1))
	}
	st1, _ := c1.GatewayState()

	c2 := NewCore(cfg) // the "new controller" after an update
	act2, applied2, err := c2.Apply(nodes, users, "")
	if err != nil || !applied2 || len(act2) != 3 {
		t.Fatalf("adopt: applied=%v err=%v active=%d", applied2, err, len(act2))
	}
	st2, _ := c2.GatewayState()
	if st2.Gen != st1.Gen || st2.Active != st1.Active || len(st2.Slots) != 1 {
		t.Fatalf("an unchanged configuration must not be switched: %+v -> %+v", st1, st2)
	}
	if c2.SocksAddr() == "" || !c2.WaitReady(context.Background(), 5*time.Second) {
		t.Fatal("the adopting controller must reach the live instance")
	}

	// a change goes through the same path and flips to a fresh instance
	users2 := append(users, User{Name: "b", UUID: "6a3a4a6c-0b1e-4b0e-9d5e-1d2f3a4b5c6d"})
	_, applied3, err := c2.Apply(nodes, users2, "")
	if err != nil || !applied3 {
		t.Fatalf("apply after adopt: %v %v", applied3, err)
	}
	st3, _ := c2.GatewayState()
	if st3.Active == st1.Active || st3.Gen == st1.Gen {
		t.Fatalf("a changed configuration must go live on another instance: %+v", st3)
	}
}

func TestTightens(t *testing.T) {
	old := []RuleCfg{{Action: "direct", Match: []string{"*.ru"}}}
	if tightens(old, append([]RuleCfg{}, old...), "proxy", "proxy") {
		t.Error("same rules are not a tightening")
	}
	if tightens(old, append(old, RuleCfg{Action: "direct", Match: []string{"*.su"}}), "proxy", "proxy") {
		t.Error("a new direct rule does not withdraw anything")
	}
	if !tightens(old, append(old, RuleCfg{Action: "block", Match: []string{"port:25"}}), "proxy", "proxy") {
		t.Error("a new block rule is a tightening")
	}
	if !tightens(nil, nil, "proxy", "block") {
		t.Error("default_action block is a tightening")
	}
}

func TestStableSecrets(t *testing.T) {
	a, b := testCfg(), testCfg()
	a.Reality.PrivateKey, b.Reality.PrivateKey = "k1", "k1"
	if a.gatewaySecret() != b.gatewaySecret() || a.gatewaySecret() == "" {
		t.Fatal("both processes must derive the same gateway secret")
	}
	if derive("k1", "probe") == derive("k1", "gateway") {
		t.Fatal("secrets for different purposes must differ")
	}
}
