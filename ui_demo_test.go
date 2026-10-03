package main

import (
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"testing"
	"time"
)

// UI_DEMO=addr go test -run UIDemo : serves the panel with made-up statistics (to look at the pages without a server).
func TestUIDemo(t *testing.T) {
	addr := os.Getenv("UI_DEMO")
	if addr == "" {
		t.Skip("set UI_DEMO=127.0.0.1:18999")
	}
	col := NewCollector(nil, nil, nil)
	now := time.Now()
	for i := 0; i < 360*4; i++ { // 4 hours, one point per 10 s
		ts := now.Add(-time.Duration(360*4-i) * 10 * time.Second)
		x := float64(i)
		col.hist = append(col.hist, SysSample{T: ts.Unix(), CPU: 20 + 15*math.Sin(x/40) + float64(i%7), Mem: 41 + x/300, Disk: 37, Load1: 0.4 + 0.3*math.Sin(x/60),
			Up: 40000 + 30000*math.Sin(x/30)*math.Sin(x/30), Down: 400000 + 300000*math.Sin(x/25)*math.Sin(x/25), Conns: 18 + i%9, Users: 3 + i%2})
	}
	col.last = col.hist[len(col.hist)-1]
	col.last.MemUsed, col.last.MemTotal, col.last.DiskUsed, col.last.DiskTotal = 1<<30, 2<<30, 12<<30, 30<<30
	col.static = sysStatic{CPUs: 2, Uptime: 3 * 86400}
	col.gw = GWStats{Epoch: 1, UpTotal: 5 << 30, DownTotal: 40 << 30, Conns: 3, Sessions: []SessInfo{
		{ID: 1, User: "admin", IP: "94.29.36.13", Since: now.Add(-20 * time.Minute), Up: 3 << 20, Down: 90 << 20},
		{ID: 2, User: "alice", IP: "5.6.7.8", Since: now.Add(-3 * time.Minute), Up: 1 << 10, Down: 5 << 10, Idle: 40},
		{ID: 3, User: "", IP: "5.6.7.9", Since: now.Add(-1 * time.Second)}},
		Invalid: []InvalidInfo{{IP: "94.29.36.13", Count: 2936, Last: now}, {IP: "80.94.92.65", Count: 1, Last: now.Add(-time.Hour)}}}
	col.gw.Errs = map[string]UserErr{"alice": {Count: 7, Last: now.Add(-3 * time.Minute).Unix(), Msg: "dial tcp 149.154.167.51:443: i/o timeout"}}
	col.pending = map[string]UserDelta{"admin": {Up: 5 << 20, Down: 200 << 20, Conns: 40}, "alice": {Up: 1 << 10, Down: 5 << 10, Conns: 1}, userInvalid: {Up: 900000, Conns: 2936}}
	col.speed = map[string]UserDelta{"admin": {Up: 20000, Down: 1500000}}
	col.active = map[string]time.Time{"admin": now}
	ring := NewLogRing(100)
	for i := 0; i < 30; i++ {
		ring.Add(fmt.Sprintf("2026/10/03 16:%02d:00 checker: cycle %d done, 129 alive", i, i))
	}
	ring.Add("2026/10/03 16:31:00 ERROR something went wrong with node X")
	ring.Add("+0000 2026-10-03 16:31:01 WARN [1 5ms] outbound/vless[n-1]: dial tcp: i/o timeout")
	mux := http.NewServeMux()
	a := &API{cfg: &Config{}, token: "demo", stats: col, logs: ring, fails: map[string][]time.Time{}}
	a.Register(mux)
	outer := http.NewServeMux()
	ago := func(d time.Duration) int64 { return now.Add(-d).Unix() }
	nodes := []NodeView{
		{Tag: "n-a", Name: "🇩🇪 Frankfurt 1", Server: "de1.example.com", Type: "vless", Score: 91.5, LatencyMS: 82, SuccessRate: 1, SpeedKbps: 54000, SpeedAt: ago(40 * time.Minute), SpeedTry: ago(40 * time.Minute), CheckAt: ago(2 * time.Minute),
			SpeedHist: []SpeedPoint{{K: 48000, T: ago(13 * time.Hour)}, {K: 54000, T: ago(40 * time.Minute)}}, Current: true, ExitCountry: "DE", ExitIP: "1.2.3.4", Allowed: true,
			Services: map[string]SvcRes{"telegram": {OK: true, MS: 120, T: ago(5 * time.Minute)}, "youtube": {OK: true, MS: 210, T: ago(5 * time.Minute)}, "x": {OK: true, MS: 300, T: ago(5 * time.Minute)}}},
		{Tag: "n-b", Name: "🇳🇱 Amsterdam slow", Server: "nl1.example.com", Type: "trojan", Score: 80, LatencyMS: 60, SuccessRate: 1, SpeedKbps: 3200, SpeedAt: ago(26 * time.Hour), SpeedTry: ago(3 * time.Hour), SpeedErr: "short download: 120 bytes", CheckAt: ago(1 * time.Minute),
			Quality: "slow", ExitCountry: "NL", ExitIP: "5.6.7.8", Allowed: true, Services: map[string]SvcRes{"telegram": {OK: true, MS: 100, T: ago(30 * time.Minute)}}},
		{Tag: "n-c", Name: "🇫🇮 Helsinki", Server: "fi1.example.com", Type: "vless", Score: 70, LatencyMS: 110, SuccessRate: 0.95, CheckAt: ago(3 * time.Minute), Quality: "service:telegram", ExitCountry: "FI", ExitIP: "9.9.9.9", Allowed: true,
			Services: map[string]SvcRes{"telegram": {OK: false, T: ago(10 * time.Minute), Fails: 2, Err: "tcp://149.154.167.51:443: closed right after connect: EOF"}, "youtube": {OK: true, MS: 300, T: ago(10 * time.Minute)}}},
	}
	outer.HandleFunc("GET /api/overview", a.auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"snapshot": map[string]any{"nodes": nodes}, "switches": []any{}, "ready": true})
	}))
	outer.HandleFunc("GET /api/users", a.auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, []userView{{"admin", true, "vless://x", "https://sub/x"}, {"alice", true, "vless://y", ""}})
	}))
	outer.HandleFunc("DELETE /api/users/{name}", a.auth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, []userView{{"admin", true, "vless://x", "https://sub/x"}})
	}))
	outer.HandleFunc("GET /api/settings", a.auth(func(w http.ResponseWriter, r *http.Request) {
		p := t.TempDir() + "/c.yaml"
		_ = os.WriteFile(p, []byte("database_url: postgres://x\npublic_host: 1.2.3.4\nsubscriptions: [https://a.example/x]\n"), 0o600)
		cfg, err := LoadConfig(p)
		if err != nil {
			apiErr(w, 500, err)
			return
		}
		help := map[string]string{}
		for _, d := range settingDefs {
			help[d.key] = d.help
		}
		writeJSON(w, 200, map[string]any{"values": cfg.Effective(), "overridden": []string{}, "help": help})
	}))
	userRing := NewLogRing(50)
	userRing.Add("ERROR [77 5.2s] inbound/vless[vless-in]: connection: open outbound connection: dial tcp 149.154.167.51:443: i/o timeout")
	userRing.Add("заблокировано правилами: INFO [78 0ms] outbound/block[block]: blocked connection to x.ru:443")
	outer.HandleFunc("GET /api/logs", a.auth(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("src") == "user" {
			writeJSON(w, 200, userRing.Since(0, 100))
			return
		}
		a.consoleLogs(w, r)
	}))
	outer.Handle("/", mux)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("panel on http://%s, token demo", addr)
	_ = http.Serve(ln, outer)
}
