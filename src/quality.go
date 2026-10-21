package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Quality of a node beyond "it answers": measured speed (with the date of every measurement)
// and whether the services people actually use (Telegram, YouTube, X ...) open through it.

const (
	defaultMinSpeedKbps = 8000 // 8 Mbit/s
	maxSpeedHist        = 3
)

var defaultServices = []string{
	"telegram = tcp://149.154.167.51:443, tcp://149.154.175.50:443, https://web.telegram.org, https://api.telegram.org",
	"youtube = https://www.youtube.com/generate_204, https://i.ytimg.com",
	"x = https://x.com, https://twitter.com",
	"tiktok = https://www.tiktok.com, https://www.tiktokv.com",
	"instagram = https://www.instagram.com, https://i.instagram.com",
	"facebook = https://www.facebook.com, https://graph.facebook.com",
	"whatsapp = https://web.whatsapp.com, https://www.whatsapp.com",
	"discord = https://discord.com, https://gateway.discord.gg",
	"google = https://www.google.com, https://www.gstatic.com/generate_204",
	"github = https://github.com, https://raw.githubusercontent.com",
	"openai = https://chatgpt.com, https://api.openai.com",
	"spotify = https://open.spotify.com, https://api.spotify.com",
	"netflix = https://www.netflix.com, https://api.fast.com",
}

var defaultRequiredServices = []string{"telegram"}

type svcDef struct {
	Name    string
	Targets []string
}

var reSvcName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,23}$`)

// parseServices reads lines like "telegram = tcp://149.154.167.51:443, https://web.telegram.org".
func parseServices(lines []string) ([]svcDef, error) {
	if len(lines) > 30 {
		return nil, fmt.Errorf("services: не больше 30 сервисов")
	}
	seen := map[string]bool{}
	var out []svcDef
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		name, rest, ok := strings.Cut(ln, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		if !ok || !reSvcName.MatchString(name) {
			return nil, fmt.Errorf("services: строка %q: ожидается «имя = адрес, адрес» (имя: латиница, цифры, - и _, до 24 знаков)", redactShort(ln))
		}
		if seen[name] {
			return nil, fmt.Errorf("services: имя %q повторяется", name)
		}
		seen[name] = true
		var targets []string
		for _, t := range strings.Split(rest, ",") {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			if err := checkTarget(t); err != nil {
				return nil, fmt.Errorf("services: %s: %w", name, err)
			}
			targets = append(targets, t)
		}
		if len(targets) == 0 || len(targets) > 8 {
			return nil, fmt.Errorf("services: %s: нужно от 1 до 8 адресов", name)
		}
		out = append(out, svcDef{Name: name, Targets: targets})
	}
	return out, nil
}

func checkTarget(t string) error {
	u, err := url.Parse(t)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%q не адрес", redactShort(t))
	}
	switch u.Scheme {
	case "http", "https":
		return nil
	case "tcp":
		if _, p, err := net.SplitHostPort(u.Host); err != nil {
			return fmt.Errorf("%q: для tcp:// нужен host:port", t)
		} else if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("%q: неверный порт", t)
		}
		return nil
	}
	return fmt.Errorf("%q: адрес должен начинаться с http://, https:// или tcp://", redactShort(t))
}

func (c *Config) getMinSpeed() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.MinSpeedKbps == nil {
		return defaultMinSpeedKbps
	}
	return *c.MinSpeedKbps
}
func (c *Config) getRequired() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]string(nil), c.RequiredServices...)
}
func (c *Config) getServices() []svcDef {
	c.mu.RLock()
	lines := append([]string(nil), c.Services...)
	c.mu.RUnlock()
	defs, _ := parseServices(lines)
	return defs
}

func init() {
	settingDefs = append(settingDefs,
		settingDef{
			key:  "min_speed_kbps",
			help: "минимальная скорость узла, кбит/с (8000 = 8 Мбит/с); медленнее не выбирается, пока есть быстрые; 0 = не учитывать",
			parse: func(raw json.RawMessage) (func(*Config), error) {
				var v int
				if err := json.Unmarshal(raw, &v); err != nil || v < 0 || v > 10_000_000 {
					return nil, fmt.Errorf("min_speed_kbps: целое число кбит/с от 0 до 10000000")
				}
				return func(c *Config) { c.MinSpeedKbps = &v }, nil
			},
			get: func(c *Config) any {
				if c.MinSpeedKbps == nil {
					return defaultMinSpeedKbps
				}
				return *c.MinSpeedKbps
			},
		},
		settingDef{
			key:  "required_services",
			help: "сервисы, которые должны открываться через узел (имена из services); узел, где они не открываются, не выбирается, пока есть другие",
			parse: func(raw json.RawMessage) (func(*Config), error) {
				var v []string
				if err := json.Unmarshal(raw, &v); err != nil {
					return nil, fmt.Errorf("required_services: нужен список имён")
				}
				for i := range v {
					v[i] = strings.ToLower(strings.TrimSpace(v[i]))
					if !reSvcName.MatchString(v[i]) {
						return nil, fmt.Errorf("required_services: %q не похоже на имя сервиса", v[i])
					}
				}
				return func(c *Config) { c.RequiredServices = v }, nil
			},
			get: func(c *Config) any { return append([]string{}, c.RequiredServices...) },
		},
		settingDef{
			key:  "services",
			help: "сервисы для проверки узлов, по строке «имя = адрес, адрес» (http://, https:// или tcp://host:port); сервис работает, если открылась половина адресов",
			parse: func(raw json.RawMessage) (func(*Config), error) {
				var v []string
				if err := json.Unmarshal(raw, &v); err != nil {
					return nil, fmt.Errorf("services: нужен список строк")
				}
				if _, err := parseServices(v); err != nil {
					return nil, err
				}
				return func(c *Config) { c.Services = v }, nil
			},
			get: func(c *Config) any { return append([]string{}, c.Services...) },
		},
	)
}

// ---------------------------------------------------------------- node state helpers

func (st *NodeState) lastSpeed() (kbps int, at time.Time) {
	if n := len(st.speedHist); n > 0 {
		p := st.speedHist[n-1]
		return p.K, time.Unix(p.T, 0)
	}
	return 0, time.Time{}
}

func (st *NodeState) addSpeed(kbps int, at time.Time) {
	st.speedHist = append(st.speedHist, SpeedPoint{K: kbps, T: at.Unix()})
	if len(st.speedHist) > maxSpeedHist {
		st.speedHist = st.speedHist[len(st.speedHist)-maxSpeedHist:]
	}
	st.speedKbps = kbps
}

// speedSlow: the two latest measurements are both below the minimum (one low value may be a fluke) and are not too old.
func (st *NodeState) speedSlow(min int, now time.Time, ttl time.Duration) bool {
	n := len(st.speedHist)
	if min <= 0 || n < 2 {
		return false
	}
	a, b := st.speedHist[n-1], st.speedHist[n-2]
	return a.K < min && b.K < min && now.Sub(time.Unix(a.T, 0)) < 3*ttl
}

// speedSuspect: the latest measurement is below the minimum, a second one is due soon.
func (st *NodeState) speedSuspect(min int) bool {
	n := len(st.speedHist)
	return min > 0 && n > 0 && st.speedHist[n-1].K < min
}

// svcFailed returns the first required service that failed twice in a row.
func (st *NodeState) svcFailed(required []string) (string, bool) {
	for _, name := range required {
		if r, ok := st.svc[name]; ok && !r.OK && r.Fails >= 2 {
			return name, true
		}
	}
	return "", false
}

func (st *NodeState) svcFailCount() int {
	n := 0
	for _, r := range st.svc {
		if !r.OK {
			n++
		}
	}
	return n
}

// quality returns why the node must not be chosen while there are better ones ("" = fine).
func (c *Checker) qualityIssue(st *NodeState, now time.Time, min int, required []string) string {
	if st.speedSlow(min, now, c.cfg.getSpeedTTL()) {
		return "slow"
	}
	if name, bad := st.svcFailed(required); bad {
		return "service:" + name
	}
	return ""
}

// ---------------------------------------------------------------- probes

// probeAny is an HTTPS request through a node where any answer counts (the point is to reach the service).
func (c *Checker) probeAny(ctx context.Context, tag, target string, timeout time.Duration) (float64, error) {
	cl, tr := c.client(tag, timeout)
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")
	start := time.Now()
	resp, err := cl.Do(req)
	if err != nil {
		return 0, err
	}
	ms := float64(time.Since(start).Milliseconds())
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 16<<10))
	return ms, nil
}

// tcpVia opens a TCP connection to host:port through a node (SOCKS5 CONNECT to the probe inbound).
// sing-box answers "success" before the node has dialed, so the connection must then stay open for a moment:
// a refused or unreachable destination closes it.
func (c *Checker) tcpVia(ctx context.Context, tag, hostport string, hold time.Duration) (float64, error) {
	host, ps, err := net.SplitHostPort(hostport)
	if err != nil {
		return 0, err
	}
	port, _ := strconv.Atoi(ps)
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", c.core.SocksAddr())
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	start := time.Now()
	_ = conn.SetDeadline(start.Add(hold + 5*time.Second))
	user, pass := "probe-"+tag, c.cfg.TestSecret
	if _, err := conn.Write([]byte{5, 1, 2}); err != nil {
		return 0, err
	}
	buf := make([]byte, 262)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil || buf[0] != 5 || buf[1] != 2 {
		return 0, fmt.Errorf("socks: no auth")
	}
	req := append([]byte{1, byte(len(user))}, user...)
	req = append(req, byte(len(pass)))
	req = append(req, pass...)
	if _, err := conn.Write(req); err != nil {
		return 0, err
	}
	if _, err := io.ReadFull(conn, buf[:2]); err != nil || buf[1] != 0 {
		return 0, fmt.Errorf("socks: login refused")
	}
	req = append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return 0, err
	}
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return 0, fmt.Errorf("socks: %v", err)
	}
	if buf[1] != 0 {
		return 0, fmt.Errorf("socks: connect refused (code %d)", buf[1])
	}
	switch buf[3] { // skip the bound address
	case 1:
		_, err = io.ReadFull(conn, buf[:6])
	case 4:
		_, err = io.ReadFull(conn, buf[:18])
	case 3:
		if _, err = io.ReadFull(conn, buf[:1]); err == nil {
			_, err = io.ReadFull(conn, buf[:int(buf[0])+2])
		}
	}
	if err != nil {
		return 0, err
	}
	ms := float64(time.Since(start).Milliseconds())
	_ = conn.SetReadDeadline(time.Now().Add(hold))
	if _, err := conn.Read(buf[:1]); err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return ms, nil // still open after the hold time: the destination accepted the connection
		}
		return 0, fmt.Errorf("closed right after connect: %v", err)
	}
	return ms, nil // the destination even sent data
}

type svcOutcome struct {
	ok  bool
	ms  int
	err string
}

// checkService probes every target of a service in parallel; the service works if at least half of them answer.
func (c *Checker) checkService(ctx context.Context, tag string, def svcDef) (svcOutcome, []CheckRow) {
	type one struct {
		ms  float64
		err error
	}
	res := make([]one, len(def.Targets))
	var wg sync.WaitGroup
	for i, t := range def.Targets {
		wg.Add(1)
		go func(i int, t string) {
			defer wg.Done()
			if strings.HasPrefix(t, "tcp://") {
				ms, err := c.tcpVia(ctx, tag, strings.TrimPrefix(t, "tcp://"), 4*time.Second)
				res[i] = one{ms, err}
				return
			}
			ms, err := c.probeAny(ctx, tag, t, 8*time.Second)
			res[i] = one{ms, err}
		}(i, t)
	}
	wg.Wait()
	okc, sum := 0, 0.0
	var firstErr string
	var rows []CheckRow
	for i, r := range res {
		row := CheckRow{TS: time.Now(), Tier: 4, OK: r.err == nil, LatencyMS: int32(r.ms), Target: def.Name + " " + def.Targets[i]}
		if r.err != nil {
			row.Err = r.err.Error()
			if firstErr == "" {
				firstErr = def.Targets[i] + ": " + shortErr(r.err)
			}
		} else {
			okc++
			sum += r.ms
		}
		rows = append(rows, row)
	}
	out := svcOutcome{ok: okc*2 >= len(def.Targets) && okc > 0, err: firstErr}
	if okc > 0 {
		out.ms = int(sum / float64(okc))
	}
	if out.ok {
		out.err = ""
	}
	return out, rows
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 && len(s) > 90 {
		s = s[i+2:]
	}
	if len(s) > 120 {
		s = s[:120] + "…"
	}
	return s
}

// ServicePass checks the services through the given nodes and records the results.
func (c *Checker) servicePass(ctx context.Context, nodes []*Node) {
	defs := c.cfg.getServices()
	if len(defs) == 0 || len(nodes) == 0 {
		return
	}
	gen := c.core.Gen()
	type nres struct {
		n    *Node
		by   map[string]svcOutcome
		rows []CheckRow
	}
	var mu sync.Mutex
	var all []nres
	forEach(nodes, c.cfg.Tier2Concurrency, func(n *Node) {
		r := nres{n: n, by: map[string]svcOutcome{}}
		for _, d := range defs {
			if ctx.Err() != nil {
				return
			}
			o, rows := c.checkService(ctx, n.Tag(), d)
			for i := range rows {
				rows[i].NodeID = n.ID
			}
			r.by[d.Name] = o
			r.rows = append(r.rows, rows...)
		}
		mu.Lock()
		all = append(all, r)
		mu.Unlock()
	})
	if ctx.Err() != nil || !c.baselineOK() || c.core.Gen() != gen {
		return // the server has no internet or sing-box was reloaded: do not blame the nodes
	}
	now := time.Now()
	var stats []NodeStat
	c.mu.Lock()
	for _, r := range all {
		st := c.states[r.n.ID]
		if st == nil {
			continue
		}
		if st.svc == nil {
			st.svc = map[string]SvcRes{}
		}
		names := map[string]bool{}
		for name, o := range r.by {
			names[name] = true
			prev := st.svc[name]
			nr := SvcRes{OK: o.ok, MS: o.ms, T: now.Unix(), Err: o.err}
			if !o.ok {
				nr.Fails = prev.Fails + 1
			}
			st.svc[name] = nr
		}
		for name := range st.svc { // services that are no longer configured
			if !names[name] {
				delete(st.svc, name)
			}
		}
		st.recompute()
		for _, row := range r.rows {
			c.addRow(row)
		}
		stats = append(stats, st.persisted())
	}
	c.mu.Unlock()
	c.saveStats(stats)
	c.flush()
	c.evaluate(true)
}

// persisted returns what is kept in the database. Called with c.mu held.
func (st *NodeState) persisted() NodeStat {
	svc := make(map[string]SvcRes, len(st.svc))
	for k, v := range st.svc {
		svc[k] = v
	}
	return NodeStat{ID: st.Node.ID, SpeedHist: append([]SpeedPoint(nil), st.speedHist...), SpeedTry: st.speedTry, SpeedErr: st.speedErr, CheckAt: st.checkAt, Svc: svc}
}

func (c *Checker) saveStats(list []NodeStat) {
	if len(list) == 0 || c.store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := c.store.SaveNodeStats(ctx, list); err != nil {
		log.Printf("checker: saving node quality data: %v", err)
	}
}

// services runs the pass over every node that may carry traffic.
func (c *Checker) services(ctx context.Context) {
	nodes := c.pick(func(st *NodeState) bool { return st.score > 0 && st.Node.Allowed(c.cfg) })
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	c.servicePass(ctx, nodes)
}

// servicesCurrent re-checks only the node users are on, often: "Telegram stopped working" is noticed within minutes.
func (c *Checker) servicesCurrent(ctx context.Context) {
	c.mu.RLock()
	st := c.states[c.current]
	c.mu.RUnlock()
	if st != nil {
		c.servicePass(ctx, []*Node{st.Node})
	}
}

func (st *NodeState) speedAt() time.Time { _, at := st.lastSpeed(); return at }

func unixOrZero(t time.Time) int64 {
	if t.IsZero() || t.Unix() <= 0 {
		return 0
	}
	return t.Unix()
}

func copySvc(m map[string]SvcRes) map[string]SvcRes {
	out := make(map[string]SvcRes, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func (c *Config) getSpeedTTL() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.SpeedTTL <= 0 {
		return 12 * time.Hour
	}
	return c.SpeedTTL
}

func (c *Config) getServiceInterval() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.ServiceInterval <= 0 {
		return time.Hour
	}
	return c.ServiceInterval
}
