package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type result struct {
	ok bool
	ms float64
}

type NodeState struct {
	Node       *Node
	win        []result
	ewma       float64
	tcpFail    int // consecutive tier-1 failures
	proxyFail  int // consecutive tier-2 / watchdog failures
	quarantine time.Time
	tcpOK      bool
	speedKbps  int
	score      float64
	sr         float64
	jitter     float64
}

const winSize = 20

func (st *NodeState) push(r result) {
	st.win = append(st.win, r)
	if len(st.win) > winSize {
		st.win = st.win[1:]
	}
	if r.ok {
		if st.ewma == 0 {
			st.ewma = r.ms
		} else {
			st.ewma = 0.7*st.ewma + 0.3*r.ms
		}
	}
}

func (st *NodeState) bad() int { return max(st.tcpFail, st.proxyFail) }

// exponential back-off for dead nodes: 1, 2, 4 ... 30 minutes
func (st *NodeState) maybeQuarantine() {
	if f := st.bad(); f >= 3 {
		d := time.Minute << uint(min(f-3, 5))
		if d > 30*time.Minute {
			d = 30 * time.Minute
		}
		st.quarantine = time.Now().Add(d)
	}
}

func (st *NodeState) recompute() {
	n := len(st.win)
	if n == 0 {
		st.score = 0
		return
	}
	okc := 0
	var ms []float64
	for _, r := range st.win {
		if r.ok {
			okc++
			ms = append(ms, r.ms)
		}
	}
	st.sr = float64(okc) / float64(n)
	st.jitter = 0
	if len(ms) > 1 {
		mean := 0.0
		for _, x := range ms {
			mean += x
		}
		mean /= float64(len(ms))
		for _, x := range ms {
			st.jitter += math.Abs(x - mean)
		}
		st.jitter /= float64(len(ms))
	}
	if st.sr < 0.6 || st.bad() >= 2 {
		st.score = 0 // unhealthy
		return
	}
	s := 100*st.sr - math.Min(st.ewma/10, 40) - math.Min(st.jitter/20, 10) + math.Min(float64(st.speedKbps)/1000, 40)/4
	st.score = math.Max(s, 1)
}

type Checker struct {
	cfg    *Config
	store  *Store
	core   *Core
	notify *Notifier

	mu       sync.RWMutex
	states   map[string]*NodeState
	current  string
	candID   string
	candCnt  int
	switches int

	bmu sync.Mutex
	bOK bool
	bAt time.Time

	cmu  sync.Mutex
	rows []CheckRow

	watchFails int // only touched by the watchdog goroutine

	pinned string // node ID chosen by the operator; used while it is healthy and allowed
}

func NewChecker(cfg *Config, st *Store, core *Core, n *Notifier) *Checker {
	return &Checker{cfg: cfg, store: st, core: core, notify: n, states: map[string]*NodeState{}, bOK: true}
}

func (c *Checker) SyncNodes(nodes []*Node) {
	c.mu.Lock()
	defer c.mu.Unlock()
	next := make(map[string]*NodeState, len(nodes))
	for _, n := range nodes {
		if st, ok := c.states[n.ID]; ok {
			st.Node = n
			next[n.ID] = st
		} else {
			next[n.ID] = &NodeState{Node: n, tcpOK: true}
		}
	}
	c.states = next
}

func (c *Checker) SetCurrent(id string) {
	c.mu.Lock()
	c.current = id
	c.mu.Unlock()
}

func (c *Checker) CurrentTag() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.current) >= 10 {
		return "n-" + c.current[:10]
	}
	return ""
}

func forEach[T any](items []T, limit int, fn func(T)) {
	if limit < 1 {
		limit = 1 // a zero limit would block forever on the semaphore
	}
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	for _, it := range items {
		sem <- struct{}{}
		wg.Add(1)
		go func(it T) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(it)
		}(it)
	}
	wg.Wait()
}

func (c *Checker) pick(f func(*NodeState) bool) []*Node {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []*Node
	for _, st := range c.states {
		if f(st) {
			out = append(out, st.Node)
		}
	}
	return out
}

// baselineOK protects from false alarms: if the server itself has no
// internet, nothing is recorded and no switching happens.
func (c *Checker) baselineOK() bool {
	c.bmu.Lock()
	defer c.bmu.Unlock()
	if time.Since(c.bAt) < 10*time.Second {
		return c.bOK
	}
	ok := false
	for _, a := range c.cfg.BaselineAddrs {
		conn, err := net.DialTimeout("tcp", a, 3*time.Second)
		if err == nil {
			conn.Close()
			ok = true
			break
		}
	}
	if !ok && c.bOK {
		c.notify.Notify("netdown", "⚠️ У сервера нет базовой связности, проверки приостановлены", 30*time.Minute)
	}
	c.bOK, c.bAt = ok, time.Now()
	return ok
}

func (c *Checker) addRow(r CheckRow) {
	c.cmu.Lock()
	c.rows = append(c.rows, r)
	c.cmu.Unlock()
}

func (c *Checker) flush() {
	c.cmu.Lock()
	rows := c.rows
	c.rows = nil
	c.cmu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := c.store.InsertChecks(ctx, rows); err != nil {
		log.Printf("checker: insert checks: %v", err)
	}
}

func (c *Checker) client(tag string, timeout time.Duration) (*http.Client, *http.Transport) {
	pu := &url.URL{
		Scheme: "socks5",
		User:   url.UserPassword("probe-"+tag, c.cfg.TestSecret),
		Host:   fmt.Sprintf("127.0.0.1:%d", c.cfg.TestPort),
	}
	tr := &http.Transport{Proxy: http.ProxyURL(pu), DisableKeepAlives: true, TLSHandshakeTimeout: timeout}
	cl := &http.Client{
		Transport:     tr,
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return cl, tr
}

// probe does a real HTTPS request through one specific node and returns
// the time to first response byte (includes DNS, TCP and TLS through the tunnel).
func (c *Checker) probe(ctx context.Context, tag, target string, timeout time.Duration) (float64, error) {
	cl, tr := c.client(tag, timeout)
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	resp, err := cl.Do(req)
	if err != nil {
		return 0, err
	}
	ms := float64(time.Since(start).Milliseconds())
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode >= 400 {
		return 0, fmt.Errorf("status %d", resp.StatusCode)
	}
	return ms, nil
}

func (c *Checker) speed(ctx context.Context, tag string) (int, error) {
	cl, tr := c.client(tag, 25*time.Second)
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, "GET", c.cfg.SpeedURL, nil)
	if err != nil {
		return 0, err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	start := time.Now() // after headers: excludes connection setup
	n, _ := io.Copy(io.Discard, resp.Body)
	d := time.Since(start).Seconds()
	if n < 500<<10 || d <= 0 {
		return 0, fmt.Errorf("short download: %d bytes", n)
	}
	return int(float64(n) * 8 / 1000 / d), nil
}

func (c *Checker) Run(ctx context.Context) {
	if !c.core.WaitReady(ctx, 2*time.Minute) {
		log.Println("checker: core is not ready yet, continuing anyway")
	}
	c.tier1(ctx)
	c.tier2(ctx)
	go c.loop(ctx, c.cfg.Tier1Interval, 0, c.tier1)
	go c.loop(ctx, c.cfg.Tier2Interval, c.cfg.Tier2Interval, c.tier2)
	go c.loop(ctx, c.cfg.Tier3Interval, time.Minute, c.tier3)
	go c.loop(ctx, c.cfg.WatchInterval, 0, c.watch)
	go c.loop(ctx, 15*time.Second, 0, func(context.Context) { c.evaluate(false) })
	go c.loop(ctx, 20*time.Second, 0, func(context.Context) { c.reconcileSelector() })
	go c.loop(ctx, time.Hour, 0, func(ctx context.Context) { c.store.Cleanup(ctx, 7*24*time.Hour) })
	<-ctx.Done()
}

func (c *Checker) loop(ctx context.Context, every, first time.Duration, fn func(context.Context)) {
	if first > 0 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(first):
			fn(ctx)
		}
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fn(ctx)
		}
	}
}

// Tier 1: cheap TCP connect to every node (skipped for UDP protocols).
func (c *Checker) tier1(ctx context.Context) {
	gen := c.core.Gen()
	now := time.Now()
	nodes := c.pick(func(st *NodeState) bool { return !st.Node.UDP && now.After(st.quarantine) })
	type res struct {
		n   *Node
		ok  bool
		ms  int
		err string
	}
	var mu sync.Mutex
	var all []res
	forEach(nodes, 100, func(n *Node) {
		start := time.Now()
		conn, err := (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(n.Server, strconv.Itoa(n.Port)))
		r := res{n: n, ok: err == nil, ms: int(time.Since(start).Milliseconds())}
		if err != nil {
			r.err = err.Error()
		} else {
			conn.Close()
		}
		mu.Lock()
		all = append(all, r)
		mu.Unlock()
	})
	// A sing-box reload/restart during the run makes results meaningless for tier 2
	// (probes were cut); TCP results do not depend on it, but keep one rule for both.
	if ctx.Err() != nil || !c.baselineOK() || c.core.Gen() != gen {
		return
	}
	c.mu.Lock()
	for _, r := range all {
		st := c.states[r.n.ID]
		if st == nil {
			continue
		}
		if r.ok {
			st.tcpOK, st.tcpFail = true, 0
		} else {
			st.tcpOK = false
			st.tcpFail++
			st.push(result{false, 0})
			st.maybeQuarantine()
		}
		st.recompute()
		c.addRow(CheckRow{TS: time.Now(), NodeID: r.n.ID, Tier: 1, OK: r.ok, LatencyMS: int32(r.ms), Target: "tcp", Err: r.err})
	}
	c.mu.Unlock()
}

// Tier 2: real HTTPS requests through the node to several targets.
func (c *Checker) tier2(ctx context.Context) {
	gen := c.core.Gen()
	now := time.Now()
	nodes := c.pick(func(st *NodeState) bool { return st.tcpOK && now.After(st.quarantine) })
	type res struct {
		n    *Node
		ok   bool
		lat  float64
		rows []CheckRow
	}
	var mu sync.Mutex
	var all []res
	urls := c.cfg.getProbeURLs()
	need := (len(urls) + 2) / 2 // majority of targets must answer
	forEach(nodes, c.cfg.Tier2Concurrency, func(n *Node) {
		var oks []float64
		var rows []CheckRow
		for _, u := range urls {
			ms, err := c.probe(ctx, n.Tag(), u, 6*time.Second)
			row := CheckRow{TS: time.Now(), NodeID: n.ID, Tier: 2, OK: err == nil, LatencyMS: int32(ms), Target: u}
			if err != nil {
				row.Err = err.Error()
			} else {
				oks = append(oks, ms)
			}
			rows = append(rows, row)
		}
		r := res{n: n, ok: len(oks) >= need, rows: rows}
		for _, x := range oks {
			r.lat += x
		}
		if len(oks) > 0 {
			r.lat /= float64(len(oks))
		}
		mu.Lock()
		all = append(all, r)
		mu.Unlock()
	})
	// commit only if the server itself still has internet and sing-box was not
	// reloaded meanwhile (a reload cuts probes and would blame every node)
	if ctx.Err() != nil || !c.baselineOK() || c.core.Gen() != gen {
		return
	}
	c.mu.Lock()
	for _, r := range all {
		st := c.states[r.n.ID]
		if st == nil {
			continue
		}
		if r.ok {
			st.proxyFail = 0
			st.quarantine = time.Time{}
			st.push(result{true, r.lat})
		} else {
			st.proxyFail++
			st.push(result{false, 0})
			st.maybeQuarantine()
		}
		st.recompute()
		for _, row := range r.rows {
			c.addRow(row)
		}
	}
	c.mu.Unlock()
	c.flush()
	c.geoPass(ctx)
	c.evaluate(true)
}

// Tier 3: short speed test for the top-N nodes only, one at a time.
func (c *Checker) tier3(ctx context.Context) {
	c.mu.RLock()
	var top []*NodeState
	for _, st := range c.states {
		// speed is only worth measuring for nodes that may carry user traffic; a node from a
		// forbidden country must not take one of the few speed-test slots
		if st.score > 0 && st.Node.Allowed(c.cfg) {
			top = append(top, st)
		}
	}
	sort.Slice(top, func(i, j int) bool { return top[i].score > top[j].score })
	if len(top) > c.cfg.Tier3Top {
		top = top[:c.cfg.Tier3Top]
	}
	var nodes []*Node
	for _, st := range top {
		nodes = append(nodes, st.Node)
	}
	c.mu.RUnlock()
	for _, n := range nodes {
		if ctx.Err() != nil {
			return
		}
		kbps, err := c.speed(ctx, n.Tag())
		row := CheckRow{TS: time.Now(), NodeID: n.ID, Tier: 3, OK: err == nil, SpeedKbps: int32(kbps), Target: c.cfg.SpeedURL}
		if err != nil {
			row.Err = err.Error()
		}
		c.addRow(row)
		if err == nil {
			c.mu.Lock()
			if st := c.states[n.ID]; st != nil {
				st.speedKbps = kbps
				st.recompute()
			}
			c.mu.Unlock()
		}
	}
	c.flush()
}

// watch is the fast failure detector for the node users are on right now.
// Two consecutive failed probes (each tries two targets) trigger failover in seconds.
func (c *Checker) watch(ctx context.Context) {
	c.mu.RLock()
	st := c.states[c.current]
	var tag, name string
	if st != nil {
		tag, name = st.Node.Tag(), st.Node.Name
	}
	c.mu.RUnlock()
	probeURLs := c.cfg.getProbeURLs()
	if st == nil || len(probeURLs) == 0 {
		return
	}
	gen := c.core.Gen()
	failed := true
	for i := 0; i < len(probeURLs) && i < 2; i++ {
		if _, err := c.probe(ctx, tag, probeURLs[i], 3*time.Second); err == nil {
			failed = false
			break
		}
	}
	if !failed {
		c.watchFails = 0
		return
	}
	// the probe may have been cut by a sing-box reload/restart: not the node's fault
	if !c.baselineOK() || c.core.Gen() != gen || c.core.RecentlyChanged(5*time.Second) {
		return
	}
	c.watchFails++
	if c.watchFails < 2 {
		return
	}
	c.watchFails = 0
	log.Printf("watch: current node %s is failing, failing over", name)
	c.mu.Lock()
	if st = c.states[c.current]; st != nil && st.Node.Tag() == tag {
		st.proxyFail = max(st.proxyFail, 1) + 1
		st.push(result{false, 0})
		st.maybeQuarantine()
		st.recompute()
	}
	c.mu.Unlock()
	c.evaluate(false)
}

// better reports whether a should be preferred over b (b may be nil).
// Ties are broken by latency and then by ID so the choice is deterministic.
func better(a, b *NodeState) bool {
	switch {
	case b == nil:
		return true
	case a.score != b.score:
		return a.score > b.score
	case a.ewma != b.ewma:
		return a.ewma < b.ewma
	}
	return a.Node.ID < b.Node.ID
}

func (c *Checker) decideLocked(cycle bool) (target *Node, reason string, none bool) {
	// A node pinned by the operator wins while it is healthy and allowed. If it is not,
	// automatic selection takes over (the pin stays and applies again when the node recovers).
	if c.pinned != "" {
		if ps := c.states[c.pinned]; ps != nil && ps.score > 0 && ps.Node.Allowed(c.cfg) {
			c.candID, c.candCnt = "", 0
			if c.current != c.pinned {
				return ps.Node, "pinned", false
			}
			return nil, "", false
		}
	}
	var best *NodeState
	unchecked := 0
	for _, st := range c.states {
		if len(st.win) == 0 {
			unchecked++
		}
		if st.score <= 0 || !st.Node.Allowed(c.cfg) {
			continue // dead, or its exit country is unknown/censored: never carry user traffic
		}
		if better(st, best) {
			best = st
		}
	}
	if best == nil {
		// "all nodes are down" only when every node was actually checked
		return nil, "", len(c.states) > 0 && unchecked == 0
	}
	cur := c.states[c.current]
	if cur == nil || cur.score <= 0 || !cur.Node.Allowed(c.cfg) {
		c.candID, c.candCnt = "", 0
		return best.Node, "failover", false
	}
	if best.Node.ID == cur.Node.ID {
		c.candID, c.candCnt = "", 0
		return nil, "", false
	}
	// hysteresis: a better node must be clearly better for several check cycles in a row
	margin, confirm := c.cfg.getSwitch()
	if best.score >= cur.score*margin {
		if cycle {
			if c.candID == best.Node.ID {
				c.candCnt++
			} else {
				c.candID, c.candCnt = best.Node.ID, 1
			}
		}
		if c.candCnt >= confirm {
			c.candID, c.candCnt = "", 0
			return best.Node, "better", false
		}
	} else {
		c.candID, c.candCnt = "", 0
	}
	return nil, "", false
}

func (c *Checker) evaluate(cycle bool) {
	c.mu.Lock()
	target, reason, none := c.decideLocked(cycle)
	c.mu.Unlock()
	if none && c.baselineOK() {
		c.notify.Notify("alldown", "🔴 Нет допустимых узлов: все недоступны или выходят в запрещённых странах", 15*time.Minute)
	}
	if target != nil {
		c.switchTo(target, reason)
	}
}

func (c *Checker) switchTo(n *Node, reason string) {
	if err := c.core.Select(n.Tag()); err != nil {
		log.Printf("switch: select failed: %v", err)
		return
	}
	if reason == "failover" {
		c.core.CloseConnections() // let clients reconnect immediately through the new node
	}
	c.mu.Lock()
	prev := c.current
	prevName := ""
	if st := c.states[prev]; st != nil {
		prevName = st.Node.Name
	}
	c.current = n.ID
	c.switches++
	c.mu.Unlock()
	log.Printf("switch: %s -> %s (%s)", prevName, n.Name, reason)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c.store.LogSwitch(ctx, prev, n.ID, reason)
	if reason == "failover" && prev != "" {
		c.notify.Notify("failover", fmt.Sprintf("⚠️ Failover: %s → %s", prevName, n.Name), time.Minute)
	}
}

// After a sing-box reload/restart the selector falls back to its default;
// make sure it matches the node we decided on.
func (c *Checker) reconcileSelector() {
	c.mu.RLock()
	st := c.states[c.current]
	c.mu.RUnlock()
	if st == nil {
		return
	}
	if now, err := c.core.Selected(); err == nil && now != st.Node.Tag() {
		_ = c.core.Select(st.Node.Tag())
	}
}

type NodeView struct {
	Tag         string  `json:"tag"`
	Name        string  `json:"name"`
	Server      string  `json:"server"`
	Type        string  `json:"type"`
	Score       float64 `json:"score"`
	LatencyMS   float64 `json:"latency_ms"`
	SuccessRate float64 `json:"success_rate"`
	JitterMS    float64 `json:"jitter_ms"`
	SpeedKbps   int     `json:"speed_kbps"`
	Quarantined bool    `json:"quarantined"`
	Current     bool    `json:"current"`
	Pinned      bool    `json:"pinned"`
	ExitCountry string  `json:"exit_country"`
	ExitIP      string  `json:"exit_ip"`
	Allowed     bool    `json:"allowed"` // may carry user traffic (exit country known and not censored)
}

type Snapshot struct {
	NetDown  bool       `json:"net_down"`
	Switches int        `json:"switches"`
	Current  string     `json:"current"` // name of the node users are on right now
	Pinned   string     `json:"pinned"`  // name of the node pinned by the operator ("" = automatic)
	Nodes    []NodeView `json:"nodes"`
}

func (c *Checker) Snapshot() Snapshot {
	c.bmu.Lock()
	down := !c.bOK
	c.bmu.Unlock()
	c.mu.RLock()
	defer c.mu.RUnlock()
	s := Snapshot{NetDown: down, Switches: c.switches}
	if st := c.states[c.current]; st != nil {
		s.Current = st.Node.Name
	}
	if st := c.states[c.pinned]; st != nil {
		s.Pinned = st.Node.Name
	}
	for id, st := range c.states {
		s.Nodes = append(s.Nodes, NodeView{
			Tag: st.Node.Tag(), Name: st.Node.Name, Server: st.Node.Server, Type: st.Node.Type,
			Score: st.score, LatencyMS: st.ewma, SuccessRate: st.sr, JitterMS: st.jitter,
			SpeedKbps: st.speedKbps, Current: id == c.current, Pinned: id == c.pinned,
			Quarantined: time.Now().Before(st.quarantine) || (st.Node.ExitCountry != "" && c.cfg.exitCheckOn() && c.cfg.isBlocked(st.Node.ExitCountry)),
			ExitCountry: st.Node.ExitCountry, ExitIP: st.Node.ExitIP, Allowed: st.Node.Allowed(c.cfg),
		})
	}
	sort.Slice(s.Nodes, func(i, j int) bool { return s.Nodes[i].Score > s.Nodes[j].Score })
	return s
}

func (c *Checker) WriteMetrics(w io.Writer) {
	s := c.Snapshot()
	healthy := 0
	blocked := 0
	for _, n := range s.Nodes {
		if n.Score > 0 && n.Allowed {
			healthy++
		}
		if !n.Allowed {
			blocked++
		}
	}
	down := 0
	if s.NetDown {
		down = 1
	}
	fmt.Fprintf(w, "balancer_nodes_total %d\nbalancer_nodes_healthy %d\nbalancer_switches_total %d\nbalancer_net_down %d\nbalancer_nodes_excluded_by_country %d\n",
		len(s.Nodes), healthy, s.Switches, down, blocked)
	for _, n := range s.Nodes {
		cur := 0
		if n.Current {
			cur = 1
		}
		fmt.Fprintf(w, "balancer_node_score{tag=%q} %.2f\nbalancer_node_latency_ms{tag=%q} %.0f\nbalancer_node_speed_kbps{tag=%q} %d\nbalancer_node_current{tag=%q} %d\n",
			n.Tag, n.Score, n.Tag, n.LatencyMS, n.Tag, n.SpeedKbps, n.Tag, cur)
	}
}

// FindNode resolves what the operator typed: tag, ID prefix, exact name or a unique part of the name.
func (c *Checker) FindNode(q string) (*NodeState, error) {
	q = strings.TrimSpace(q)
	if q == "" {
		return nil, errors.New("не указан узел")
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	lq := strings.ToLower(q)
	var partial []*NodeState
	for _, st := range c.states {
		n := st.Node
		if n.Tag() == q || n.ID == q || (len(q) >= 6 && strings.HasPrefix(n.ID, q)) || strings.EqualFold(n.Name, q) {
			return st, nil
		}
		if strings.Contains(strings.ToLower(n.Name), lq) || strings.Contains(strings.ToLower(n.Server), lq) {
			partial = append(partial, st)
		}
	}
	switch len(partial) {
	case 0:
		return nil, fmt.Errorf("узел %q не найден", q)
	case 1:
		return partial[0], nil
	}
	return nil, fmt.Errorf("под %q подходит %d узлов, уточните (имя целиком или tag из `nodes`)", q, len(partial))
}

// Pin makes the operator's choice the current node (if it can carry traffic).
func (c *Checker) Pin(q string) (*Node, error) {
	st, err := c.FindNode(q)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if st.score <= 0 {
		c.mu.Unlock()
		return nil, fmt.Errorf("узел «%s» сейчас не работает (оценка 0)", st.Node.Name)
	}
	if !st.Node.Allowed(c.cfg) {
		c.mu.Unlock()
		return nil, fmt.Errorf("узел «%s» не допущен: выход %q запрещён или не определён", st.Node.Name, st.Node.ExitCountry)
	}
	c.pinned = st.Node.ID
	n := st.Node
	c.mu.Unlock()
	c.evaluate(false)
	return n, nil
}

func (c *Checker) Unpin() {
	c.mu.Lock()
	c.pinned = ""
	c.mu.Unlock()
	c.evaluate(false)
}

// ForceGeo forgets every measured exit age so the countries are measured again right away.
func (c *Checker) ForceGeo(ctx context.Context) {
	if c.store != nil {
		_ = c.store.ForgetExitChecks(ctx)
	}
	c.mu.Lock()
	for _, st := range c.states {
		st.Node.ExitChecked = time.Time{}
	}
	c.mu.Unlock()
	go c.geoPass(context.Background())
}
