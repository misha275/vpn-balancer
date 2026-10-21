package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLineSinkAttributesUsers(t *testing.T) {
	tr := newTracker()
	tr.settle = 20 * time.Millisecond
	var passed []string
	sink := &lineSink{slot: 1, t: tr, idPort: map[string]int{}, pass: func(l string) { passed = append(passed, l) }}

	s := tr.open(1, 40001, &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 5555})
	s.up.Add(100)
	s.down.Add(900)
	sink.line("+0000 2026-10-03 13:01:18 INFO [801667921 0ms] inbound/vless[vless-in]: inbound connection from 127.0.0.1:40001")
	d := tr.drain()
	if len(d.Deltas) != 0 {
		t.Fatalf("bytes of a connection with an unknown user must wait, got %+v", d.Deltas)
	}
	if len(d.Sessions) != 1 || d.Sessions[0].User != "" || d.Sessions[0].IP != "1.2.3.4" {
		t.Fatalf("session: %+v", d.Sessions)
	}
	sink.line("+0000 2026-10-03 13:01:18 INFO [801667921 2ms] inbound/vless[vless-in]: [alice] inbound connection to example.org:443")
	s.up.Add(50)
	d = tr.drain()
	if got := d.Deltas["alice"]; got.Up != 150 || got.Down != 900 || got.Conns != 1 {
		t.Fatalf("alice: %+v", got)
	}
	s.down.Add(10)
	d = tr.drain()
	if got := d.Deltas["alice"]; got.Up != 0 || got.Down != 10 || got.Conns != 0 {
		t.Fatalf("a second drain must return only the new bytes: %+v", got)
	}
	tr.end(s)
	time.Sleep(100 * time.Millisecond)
	if d = tr.drain(); len(d.Sessions) != 0 {
		t.Fatalf("a finished connection must leave the live list: %+v", d.Sessions)
	}
	if len(passed) != 0 {
		t.Fatalf("connection chatter must not reach the console: %v", passed)
	}
	sink.line("+0000 2026-10-03 13:01:18 ERROR [1 2ms] outbound/vless[x]: something broke")
	sink.line("panic: boom")
	if len(passed) != 2 {
		t.Fatalf("errors and unknown lines must pass: %v", passed)
	}
}

func TestTrackerInvalidAndUnknown(t *testing.T) {
	tr := newTracker()
	tr.settle = 10 * time.Millisecond
	sink := &lineSink{slot: 0, t: tr, idPort: map[string]int{}}

	bad := tr.open(0, 41000, &net.TCPAddr{IP: net.ParseIP("9.9.9.9"), Port: 1})
	bad.up.Add(517)
	sink.line("+0000 2026-10-03 12:49:47 ERROR [2790677166 460ms] inbound/vless[vless-in]: process connection from 127.0.0.1:41000: TLS handshake: REALITY: processed invalid connection")
	tr.end(bad)

	idle := tr.open(0, 41001, &net.TCPAddr{IP: net.ParseIP("8.8.8.8"), Port: 1})
	idle.up.Add(3)
	tr.end(idle)
	time.Sleep(80 * time.Millisecond)

	d := tr.drain()
	if got := d.Deltas[userInvalid]; got.Up != 517 || got.Conns != 1 {
		t.Fatalf("invalid: %+v", d.Deltas)
	}
	if got := d.Deltas[userUnknown]; got.Up != 3 || got.Conns != 1 {
		t.Fatalf("unknown: %+v", d.Deltas)
	}
	if len(d.Invalid) != 1 || d.Invalid[0].IP != "9.9.9.9" || d.Invalid[0].Count != 1 {
		t.Fatalf("invalid list: %+v", d.Invalid)
	}
}

func TestLogRing(t *testing.T) {
	r := NewLogRing(10)
	fmt.Fprint(r, "one\ntwo\n\x1b[31mred\x1b[0m\npart")
	fmt.Fprint(r, "ial\n")
	pg := r.Since(0, 100)
	var texts []string
	for _, l := range pg.Lines {
		texts = append(texts, l.Text)
	}
	if strings.Join(texts, "|") != "one|two|red|partial" {
		t.Fatalf("lines: %v", texts)
	}
	for i := 0; i < 50; i++ {
		r.Add(fmt.Sprintf("n%d", i))
	}
	pg = r.Since(0, 5)
	if len(pg.Lines) != 5 || pg.Lines[4].Text != "n49" || pg.Last != 54 {
		t.Fatalf("tail: %+v", pg)
	}
	pg2 := r.Since(pg.Last, 5)
	if len(pg2.Lines) != 0 {
		t.Fatalf("nothing new expected: %+v", pg2)
	}
	if got := r.Since(9999, 5); len(got.Lines) != 5 {
		t.Fatalf("a position from the future (restart) must give the tail: %+v", got)
	}
}

func TestSysParsers(t *testing.T) {
	a, ok := parseCPULine("cpu  100 0 100 800 0 0 0 0 0 0")
	b, _ := parseCPULine("cpu  150 0 150 900 0 0 0 0 0 0")
	if !ok || cpuPercent(a, b) != 50 {
		t.Fatalf("cpu: %v", cpuPercent(a, b))
	}
	tot, av := parseMeminfo("MemTotal:       2048000 kB\nMemFree: 1 kB\nMemAvailable:   1024000 kB\n")
	if tot != 2048000*1024 || av != 1024000*1024 {
		t.Fatalf("mem: %d %d", tot, av)
	}
	if _, ok := readCPUTimes(); !ok {
		t.Skip("no /proc/stat")
	}
	if u, tt := readDisk("/"); tt == 0 || u > tt {
		t.Fatalf("disk: %d/%d", u, tt)
	}
}

func TestDownsample(t *testing.T) {
	var src []SysSample
	for i := 0; i < 1000; i++ {
		src = append(src, SysSample{T: int64(i), CPU: float64(i % 2 * 100), Conns: 4})
	}
	out := downsample(src, 100)
	if len(out) != 100 || out[0].CPU != 50 || out[10].Conns != 4 || out[99].T != 999 {
		t.Fatalf("bad downsample: %d %+v", len(out), out[0])
	}
}

// The whole chain with a real sing-box: client -> front -> instance with a VLESS user.
func TestGatewayCountsTrafficPerUser(t *testing.T) {
	bin := singboxBin(t)
	e, port, _ := newTestEngine(t)
	e.tr.settle = 100 * time.Millisecond
	target := tagServer(t, "T")
	ctx := context.Background()
	const uid = "6a3a4a6c-0b1e-4b0e-9d5e-1d2f3a4b5c6d"
	server := fmt.Sprintf(`{"log":{"level":"warn"},"inbounds":[{"type":"vless","tag":"vless-in","listen":"127.0.0.1","listen_port":1,
		"users":[{"name":"alice","uuid":"%s"}]}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`, uid)
	if _, err := e.Apply(ctx, ApplyReq{Config: []byte(server), Fingerprint: "u1"}); err != nil {
		t.Fatal(err)
	}
	cport := freePort(t)
	client := fmt.Sprintf(`{"log":{"level":"warn"},"inbounds":[{"type":"direct","tag":"in","listen":"127.0.0.1","listen_port":%d,
		"override_address":"127.0.0.1","override_port":%d}],
		"outbounds":[{"type":"vless","tag":"out","server":"127.0.0.1","server_port":%d,"uuid":"%s"}],"route":{"final":"out"}}`, cport, target, port, uid)
	cf := filepath.Join(t.TempDir(), "client.json")
	if err := os.WriteFile(cf, []byte(client), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "run", "-c", cf)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })

	var c net.Conn
	var err error
	for i := 0; i < 50; i++ {
		if c, err = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", cport)); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := ask(t, c, "hello-world"); got != "T:hello-world" {
		t.Fatalf("through the chain: %q", got)
	}

	// while the connection is open the user is known and listed as online
	var st GWStats
	for i := 0; i < 30; i++ {
		st, _ = e.Stats(ctx)
		if len(st.Sessions) == 1 && st.Sessions[0].User == "alice" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(st.Sessions) != 1 || st.Sessions[0].User != "alice" || st.Sessions[0].IP != "127.0.0.1" {
		t.Fatalf("live session: %+v", st.Sessions)
	}
	c.Close()
	time.Sleep(600 * time.Millisecond)
	st2, _ := e.Stats(ctx)
	total := UserDelta{}
	for _, d := range []UserDelta{st.Deltas["alice"], st2.Deltas["alice"]} {
		total.Up, total.Down, total.Conns = total.Up+d.Up, total.Down+d.Down, total.Conns+d.Conns
	}
	if total.Conns != 1 || total.Up < 11 || total.Down < 13 {
		t.Fatalf("alice must have counted bytes of one connection: %+v / %+v", st.Deltas, st2.Deltas)
	}
	if st2.UpTotal == 0 || st2.DownTotal == 0 {
		t.Fatalf("front totals: %+v", st2)
	}
	if len(st2.Sessions) != 0 {
		t.Fatalf("closed connection is still listed: %+v", st2.Sessions)
	}
}

func TestStatsStoreAndView(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	if _, err := st.AddUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddUser(ctx, "bob"); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := st.AddTraffic(ctx, now, map[string]UserDelta{"alice": {Up: 100, Down: 1000, Conns: 2}}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddTraffic(ctx, now, map[string]UserDelta{"alice": {Up: 1, Down: 2, Conns: 1}}); err != nil { // same hour: adds up
		t.Fatal(err)
	}
	if err := st.AddTraffic(ctx, now.Add(-10*24*time.Hour), map[string]UserDelta{"alice": {Up: 5, Down: 50, Conns: 1}, "carol": {Down: 7}}); err != nil {
		t.Fatal(err)
	}
	if err := st.TouchSeen(ctx, map[string]SeenInfo{"alice": {At: now, IP: "1.1.1.1"}}); err != nil {
		t.Fatal(err)
	}
	if err := st.TouchSeen(ctx, map[string]SeenInfo{"alice": {At: now.Add(-time.Hour), IP: "2.2.2.2"}}); err != nil { // older: must not win
		t.Fatal(err)
	}
	sum, err := st.TrafficSummary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	a := sum["alice"]
	if a.H24Up != 101 || a.H24Down != 1002 || a.D7Down != 1002 || a.D30Down != 1052 || a.AllUp != 106 || a.AllConns != 4 || a.LastIP != "1.1.1.1" {
		t.Fatalf("alice: %+v", a)
	}

	// the view merges users, the database, the live data and what is not yet written
	col := NewCollector(st, nil, nil)
	col.gw = GWStats{Sessions: []SessInfo{{ID: 1, User: "bob", IP: "3.3.3.3", Since: now}, {ID: 2, User: "bob", IP: "3.3.3.4", Since: now}}}
	col.pending = map[string]UserDelta{"bob": {Up: 10, Down: 20, Conns: 2}, userInvalid: {Up: 3, Conns: 1}}
	col.speed = map[string]UserDelta{"bob": {Up: 5, Down: 6}}
	col.active = map[string]time.Time{"bob": now}
	v, err := col.View(ctx)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]UserStat{}
	for _, u := range v.Users {
		by[u.Name] = u
	}
	if !by["bob"].Online || by["bob"].Conns != 2 || len(by["bob"].IPs) != 2 || !by["bob"].Active || by["bob"].AllDown != 20 || by["bob"].DownBps != 6 || !by["bob"].Enabled {
		t.Fatalf("bob: %+v", by["bob"])
	}
	if by["alice"].Online || by["alice"].H24Down != 1002 || by["alice"].LastSeen == nil || !by["alice"].Enabled {
		t.Fatalf("alice: %+v", by["alice"])
	}
	if c, ok := by["carol"]; !ok || !c.Removed || c.AllDown != 7 {
		t.Fatalf("a name without a user record must be listed as removed: %+v", c)
	}
	if v.Users[0].Name != "bob" {
		t.Fatalf("online users go first: %+v", v.Users[0])
	}
	if len(v.Other) != 1 || v.Other[0].Name != userInvalid || v.Other[0].Label == "" {
		t.Fatalf("other: %+v", v.Other)
	}

	// flush writes the pending bytes to the database and empties the buffer
	col.flush(ctx)
	sum, _ = st.TrafficSummary(ctx)
	if sum["bob"].AllDown != 20 || sum[userInvalid].AllUp != 3 || len(col.pending) != 0 {
		t.Fatalf("flush: %+v pending=%v", sum["bob"], col.pending)
	}

	// history survives in the database
	if err := st.InsertMetric(ctx, SysSample{T: now.Unix() - 60, CPU: 12.5, Conns: 3}); err != nil {
		t.Fatal(err)
	}
	ms, err := st.LoadMetrics(ctx, now.Add(-time.Hour))
	if err != nil || len(ms) != 1 || ms[0].CPU != 12.5 {
		t.Fatalf("metrics: %v %+v", err, ms)
	}
}

// The control API of a separate gateway container serves the statistics and the console too.
func TestRemoteGatewayStatsAndLogs(t *testing.T) {
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
	c := NewCore(cfg)
	var err error
	for i := 0; i < 50; i++ {
		if _, err = c.GatewayStats(context.Background()); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	st, err := c.GatewayStats(context.Background())
	if err != nil || st.Epoch == 0 || st.Deltas == nil && false {
		t.Fatalf("stats: %+v %v", st, err)
	}
	pg, err := c.GatewayLogs(context.Background(), 0, 50)
	if err != nil || pg.Epoch == 0 {
		t.Fatalf("logs: %+v %v", pg, err)
	}
	found := false
	for _, l := range pg.Lines {
		found = found || strings.Contains(l.Text, "front listens")
	}
	if !found {
		t.Fatalf("the gateway's own messages must be in its console: %+v", pg.Lines)
	}
}

func TestUserErrorConsole(t *testing.T) {
	tr := newTracker()
	sink := &lineSink{slot: 1, t: tr, idPort: map[string]int{}, idUser: map[string]string{}}
	tr.open(1, 40001, nil)
	sink.line("+0000 2026-10-03 13:01:18 INFO [77 0ms] inbound/vless[vless-in]: inbound connection from 127.0.0.1:40001")
	sink.line("+0000 2026-10-03 13:01:18 INFO [77 2ms] inbound/vless[vless-in]: [alice] inbound connection to t.me:443")
	sink.line("+0000 2026-10-03 13:01:19 INFO [78 2ms] outbound/block[block]: blocked connection to ads.example:443") // unknown connection: not attributable
	sink.line("+0000 2026-10-03 13:01:20 INFO [77 3ms] outbound/vless[n-abc]: outbound connection to t.me:443")       // ordinary chatter: never stored
	sink.line("+0000 2026-10-03 13:01:21 ERROR [77 5.2s] inbound/vless[vless-in]: connection: open outbound connection: dial tcp 1.2.3.4:443: i/o timeout")
	sink.line("+0000 2026-10-03 13:01:22 INFO [77 5.2s] outbound/block[block]: blocked connection to x.ru:443")
	pg := tr.UserLogs("alice", 0, 100)
	if len(pg.Lines) != 2 {
		t.Fatalf("alice must have the error and the block, got %+v", pg.Lines)
	}
	if !strings.Contains(pg.Lines[0].Text, "i/o timeout") || strings.Contains(pg.Lines[0].Text, "+0000") {
		t.Fatalf("line: %q", pg.Lines[0].Text)
	}
	if !strings.Contains(pg.Lines[1].Text, "заблокировано") || !strings.Contains(pg.Lines[1].Text, "x.ru") {
		t.Fatalf("line: %q", pg.Lines[1].Text)
	}
	for _, l := range pg.Lines {
		if strings.Contains(l.Text, "outbound connection to t.me") {
			t.Fatal("ordinary connections must not be stored")
		}
	}
	if e := tr.drain().Errs["alice"]; e.Count != 2 || e.Last == 0 || e.Msg == "" {
		t.Fatalf("errs: %+v", e)
	}
	if got := tr.UserLogs("bob", 0, 10); len(got.Lines) != 0 {
		t.Fatal("bob has nothing")
	}
}
