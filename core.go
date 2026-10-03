package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Core turns the node list and the users into a sing-box config and hands it to the
// gateway (see gateway.go), which switches to it without cutting open connections.
// It also talks to the Clash API of the instance that is live now.
type Core struct {
	cfg        *Config
	gw         Gateway
	eng        *Engine // set when the gateway runs inside this process
	mu         sync.Mutex
	applied    string
	hadProxy   bool    // the applied config had at least one node allowed to carry user traffic
	active     []*Node // nodes that are really in the applied config
	lastReload time.Time
	lastUsers  map[string]string // name -> uuid of the applied config
	lastPolicy []byte            // rules and default action of the applied config
	http       *http.Client

	addrMu sync.RWMutex
	clash  string // host:port of the Clash API of the live instance
	socks  string // host:port of its probe inbound
	gwErr  error  // last problem talking to the gateway

	gen       atomic.Int64 // bumped on every switch to a new instance and on every restart of one
	changedAt atomic.Int64 // unix nanoseconds of the last bump
	gwGen     atomic.Int64 // generation counter of the gateway as last seen
}

func (c *Core) bump() {
	c.gen.Add(1)
	c.changedAt.Store(time.Now().UnixNano())
}

// Gen changes whenever the live sing-box instance is replaced or restarted. The checker uses it to
// discard probes that were interrupted by it instead of blaming the nodes.
func (c *Core) Gen() int64 { return c.gen.Load() }

// RecentlyChanged reports whether the live instance changed within d.
func (c *Core) RecentlyChanged(d time.Duration) bool {
	return time.Since(time.Unix(0, c.changedAt.Load())) < d
}

func NewCore(cfg *Config) *Core {
	c := &Core{cfg: cfg, http: &http.Client{Timeout: 5 * time.Second}}
	if cfg.Gateway == "external" {
		g, err := newRemoteGateway(cfg)
		if err != nil {
			log.Fatalf("config: %v", err)
		}
		c.gw = g
	} else {
		c.eng = NewEngine(cfg, "127.0.0.1", false)
		c.gw = c.eng
	}
	return c
}

// Gateway returns what the gateway reports (nil when it cannot be reached).
func (c *Core) GatewayState() (GWState, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	return c.gw.State(ctx)
}

// GatewayStats returns live sessions and the traffic counted since the previous call.
func (c *Core) GatewayStats(ctx context.Context) (GWStats, error) {
	st, err := c.gw.Stats(ctx)
	if err != nil && strings.Contains(err.Error(), "http 404") {
		err = errors.New("the gateway is an older version without statistics: bash install.sh update --gateway")
	}
	return st, err
}

// GatewayLogs returns the console of the gateway.
func (c *Core) GatewayLogs(ctx context.Context, after int64, limit int) (LogPage, error) {
	pg, err := c.gw.Logs(ctx, after, limit)
	if err != nil && strings.Contains(err.Error(), "http 404") {
		err = errors.New("the gateway is an older version without a console: bash install.sh update --gateway")
	}
	return pg, err
}

// GatewayUserLogs returns the diagnostic console (errors, blocked destinations) of one user.
func (c *Core) GatewayUserLogs(ctx context.Context, user string, after int64, limit int) (LogPage, error) {
	pg, err := c.gw.UserLogs(ctx, user, after, limit)
	if err != nil && strings.Contains(err.Error(), "http 404") {
		err = errors.New("the gateway is an older version: bash install.sh update --gateway")
	}
	return pg, err
}

// Stop ends an embedded gateway (an external one keeps running on purpose).
func (c *Core) Stop() {
	if c.eng != nil {
		c.eng.Shutdown()
	}
}

func (c *Core) setAddrs(st GWState) {
	c.addrMu.Lock()
	defer c.addrMu.Unlock()
	if st.Active >= 0 && st.Clash != 0 {
		h := c.gw.Host()
		c.clash = fmt.Sprintf("%s:%d", h, st.Clash)
		c.socks = fmt.Sprintf("%s:%d", h, st.Socks)
	} else {
		c.clash, c.socks = "", ""
	}
}

// SocksAddr is where the checker reaches the probe inbound of the live instance.
func (c *Core) SocksAddr() string {
	c.addrMu.RLock()
	defer c.addrMu.RUnlock()
	return c.socks
}

func (c *Core) cfgPath() string { return filepath.Join(c.cfg.WorkDir, "config.json") }

func fingerprint(nodes []*Node, users []User) string {
	ids := make([]string, 0, len(nodes))
	for _, n := range nodes {
		ids = append(ids, n.ID)
	}
	sort.Strings(ids) // order of the DB result must not cause needless reloads
	h := sha256.New()
	h.Write([]byte(strings.Join(ids, ",")))
	h.Write([]byte("|"))
	us := make([]string, 0, len(users))
	for _, u := range users {
		us = append(us, u.Name+":"+u.UUID)
	}
	sort.Strings(us)
	h.Write([]byte(strings.Join(us, ";")))
	return hex.EncodeToString(h.Sum(nil))
}

// policySig makes a change of which nodes may carry user traffic (exit country
// result) or of the routing rules visible to Apply, so it reloads sing-box.
func (c *Core) policySig(nodes []*Node) string {
	var allowed []string
	for _, n := range nodes {
		if n.Allowed(c.cfg) {
			allowed = append(allowed, n.ID)
		}
	}
	sort.Strings(allowed)
	rules, _ := json.Marshal(c.cfg.getRules())
	h := sha256.Sum256([]byte(strings.Join(allowed, ",") + "|" + string(rules) + "|" + c.cfg.getDefaultAction()))
	return hex.EncodeToString(h[:8])
}

func (c *Core) check(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, c.cfg.SingboxBin, "check", "-c", path).CombinedOutput(); err != nil {
		return fmt.Errorf("sing-box check failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// validNodes checks every node on its own with `sing-box check`, so that one
// malformed node from a subscription cannot block config updates for all others.
func (c *Core) validNodes(nodes []*Node) (good []*Node, bad map[string]string) {
	var mu sync.Mutex
	bad = map[string]string{}
	forEach(nodes, 8, func(n *Node) {
		data, err := BuildConfig(c.cfg, []*Node{n}, nil, "")
		if err == nil {
			tmp := filepath.Join(c.cfg.WorkDir, "node-check-"+n.ID[:10]+".json")
			if err = os.WriteFile(tmp, data, 0o600); err == nil {
				err = c.check(tmp)
				_ = os.Remove(tmp)
			}
		}
		if err != nil {
			mu.Lock()
			bad[n.ID] = err.Error()
			mu.Unlock()
		}
	})
	for _, n := range nodes {
		if _, isBad := bad[n.ID]; !isBad {
			good = append(good, n)
		}
	}
	return good, bad
}

// tightens reports whether the new policy forbids something the old one allowed. Then connections that
// are already open must not live on under the old policy for long.
func tightens(oldRules, newRules []RuleCfg, oldDef, newDef string) bool {
	if newDef == "block" && oldDef != "block" {
		return true
	}
	had := map[string]bool{}
	for _, r := range oldRules {
		b, _ := json.Marshal(r)
		had[string(b)] = true
	}
	for _, r := range newRules {
		if r.Action != "block" {
			continue
		}
		b, _ := json.Marshal(r)
		if !had[string(b)] {
			return true
		}
	}
	return false
}

// Apply builds the config for the current nodes and users and hands it to the gateway if it differs from the
// one that is live. It returns the nodes that are really in it (nodes rejected by `sing-box check` are left
// out and logged) and whether something was applied. Open user connections are not cut: the gateway starts
// the new config next to the old one (see gateway.go). They are cut early (urgent) only when the change
// withdraws something: a user, the node they are using, or a new block rule.
func (c *Core) Apply(nodes []*Node, users []User, def string) (active []*Node, applied bool, err error) {
	fp := fingerprint(nodes, users) + "|" + c.policySig(nodes)
	c.mu.Lock()
	defer c.mu.Unlock()
	if fp == c.applied {
		return c.active, false, nil
	}
	// The pause between switches keeps the CPU calm (every switch starts a sing-box with all nodes). It does
	// not apply while no node may carry traffic: users are rejected anyway, so the first allowed node
	// (for example right after the exit country was measured) goes live at once.
	if c.applied != "" && c.hadProxy && time.Since(c.lastReload) < c.cfg.MinReload {
		return c.active, false, nil // retried on the next reconcile tick
	}
	// A restarted controller finds the gateway running the very same config: nothing to switch.
	if c.applied == "" {
		if st, err := c.GatewayState(); err == nil && st.Active >= 0 && st.Fingerprint == fp && st.Meta != "" {
			var ids []string
			if json.Unmarshal([]byte(st.Meta), &ids) == nil {
				want := map[string]bool{}
				for _, id := range ids {
					want[id] = true
				}
				for _, n := range nodes {
					if want[n.ID] {
						active = append(active, n)
					}
				}
				c.commit(fp, active, users, st)
				c.lastReload = st.AppliedAt
				log.Printf("core: the gateway already runs this configuration (%d nodes), nothing to switch", len(active))
				return active, true, nil
			}
		}
	}
	if err := os.MkdirAll(c.cfg.WorkDir, 0o755); err != nil {
		return c.active, false, err
	}
	tmp := c.cfgPath() + ".new"
	var data []byte
	write := func(ns []*Node) error {
		d, err := BuildConfig(c.cfg, ns, users, def)
		if err != nil {
			return err
		}
		if err := os.WriteFile(tmp, d, 0o600); err != nil {
			return err
		}
		if err := c.check(tmp); err != nil {
			return err
		}
		data = d
		return nil
	}
	active = nodes
	if err := write(active); err != nil {
		if len(nodes) == 0 {
			return c.active, false, err
		}
		good, bad := c.validNodes(nodes)
		if len(bad) == 0 {
			return c.active, false, err // the problem is not in a node (keys, port ...)
		}
		for id, msg := range bad {
			log.Printf("core: node %s rejected by sing-box check, excluded: %s", id[:10], msg)
		}
		active = good
		if err := write(active); err != nil {
			return c.active, false, err
		}
	}
	_ = os.Remove(tmp)

	// does the change withdraw something? then old connections get only a short grace period
	urgent := false
	newUsers := userMap(users)
	for name, uuid := range c.lastUsers {
		if newUsers[name] != uuid {
			urgent = true // a user was removed or got a new key
		}
	}
	if tightens(c.lastRules(), c.cfg.getRules(), c.lastDefault(), c.cfg.getDefaultAction()) {
		urgent = true
	}
	if cur, err := c.Selected(); err == nil && cur != "" {
		still := false
		for _, n := range active {
			if n.Allowed(c.cfg) && n.Tag() == cur {
				still = true
			}
		}
		if !still {
			urgent = true // the node that carries traffic now is no longer allowed
		}
	}
	ids := make([]string, 0, len(active))
	for _, n := range active {
		ids = append(ids, n.ID)
	}
	meta, _ := json.Marshal(ids)
	drain := int(c.cfg.DrainTimeout / time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 85*time.Second)
	defer cancel()
	st, err := c.gw.Apply(ctx, ApplyReq{Config: data, Fingerprint: fp, Meta: string(meta), Urgent: urgent, DrainSec: drain})
	if err != nil {
		return c.active, false, fmt.Errorf("gateway: %w", err) // the old configuration keeps serving
	}
	c.commit(fp, active, users, st)
	c.lastReload = time.Now()
	c.bump()
	log.Printf("core: new configuration is live (%d nodes, %d users, urgent=%v)", len(active), len(users), urgent)
	return active, true, nil
}

func userMap(users []User) map[string]string {
	m := make(map[string]string, len(users))
	for _, u := range users {
		m[u.Name] = u.UUID
	}
	return m
}

func (c *Core) lastRules() []RuleCfg {
	var r struct {
		Rules []RuleCfg `json:"rules"`
		Def   string    `json:"def"`
	}
	_ = json.Unmarshal(c.lastPolicy, &r)
	return r.Rules
}

func (c *Core) lastDefault() string {
	var r struct {
		Def string `json:"def"`
	}
	_ = json.Unmarshal(c.lastPolicy, &r)
	return r.Def
}

// commit records what is live now. Called with c.mu held.
func (c *Core) commit(fp string, active []*Node, users []User, st GWState) {
	c.applied = fp
	c.active = active
	c.hadProxy = false
	for _, n := range active {
		if n.Allowed(c.cfg) {
			c.hadProxy = true
			break
		}
	}
	c.lastUsers = userMap(users)
	c.lastPolicy, _ = json.Marshal(map[string]any{"rules": c.cfg.getRules(), "def": c.cfg.getDefaultAction()})
	c.gwGen.Store(st.Gen)
	c.setAddrs(st)
}

// Run follows the gateway: where the live instance listens, and whether it was restarted.
func (c *Core) Run(ctx context.Context) {
	if c.eng != nil {
		go c.eng.Run(ctx)
	}
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	warned := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		st, err := c.GatewayState()
		if err != nil {
			if !warned {
				log.Printf("core: gateway: %v", err)
				warned = true
			}
			c.addrMu.Lock()
			c.gwErr = err
			c.addrMu.Unlock()
			continue
		}
		warned = false
		c.addrMu.Lock()
		c.gwErr = nil
		c.addrMu.Unlock()
		c.setAddrs(st)
		if prev := c.gwGen.Swap(st.Gen); prev != st.Gen {
			c.bump() // the gateway changed the live instance without us (restart, recovery)
		}
	}
}

func (c *Core) api(method, path string, body any) ([]byte, error) {
	c.addrMu.RLock()
	addr := c.clash
	c.addrMu.RUnlock()
	if addr == "" {
		return nil, errors.New("no live sing-box instance yet")
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://"+addr+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.gatewaySecret())
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("clash api %s %s: %d %s", method, path, resp.StatusCode, data)
	}
	return data, nil
}

func (c *Core) Ready() bool {
	_, err := c.api("GET", "/version", nil)
	return err == nil
}

func (c *Core) WaitReady(ctx context.Context, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		if c.Ready() {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

func (c *Core) Select(tag string) error {
	_, err := c.api("PUT", "/proxies/proxy", map[string]string{"name": tag})
	return err
}

func (c *Core) Selected() (string, error) {
	data, err := c.api("GET", "/proxies/proxy", nil)
	if err != nil {
		return "", err
	}
	var r struct {
		Now string `json:"now"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return "", err
	}
	return r.Now, nil
}

func (c *Core) CloseConnections() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = c.gw.CloseAll(ctx)
}

// BuildConfig renders the sing-box config:
//   - vless+reality inbound for users (one stable address for them),
//   - selector "proxy" over all upstream nodes (the controller switches it),
//   - local socks inbound where every node has its own login; a route rule
//     maps that login to the node, so the checker can send a real request
//     through any specific node without running 100 processes.
func BuildConfig(cfg *Config, nodes []*Node, users []User, def string) ([]byte, error) {
	var outbounds, probeRules, probeUsers []any
	var tags []string // nodes allowed to carry user traffic (the selector)
	for _, n := range nodes {
		o := make(map[string]any, len(n.Outbound)+1)
		for k, v := range n.Outbound {
			o[k] = v
		}
		o["tag"] = n.Tag()
		outbounds = append(outbounds, o) // every node stays reachable for the checker
		if n.Allowed(cfg) {
			tags = append(tags, n.Tag())
		}
		probeRules = append(probeRules, map[string]any{"auth_user": []string{"probe-" + n.Tag()}, "outbound": n.Tag()})
		probeUsers = append(probeUsers, map[string]any{"username": "probe-" + n.Tag(), "password": cfg.TestSecret})
	}
	hasProxy := len(tags) > 0
	defaultAction := cfg.getDefaultAction()
	userRules, err := CompileRules(cfg.getRules(), hasProxy)
	if err != nil {
		return nil, err
	}
	rules := append(probeRules, userRules...)
	final := "direct" // only reachable by inbounds we do not create; user traffic never ends here
	if !hasProxy || defaultAction == "block" {
		// No node may carry user traffic (none yet, all dead, or all exit in censored
		// countries) or the operator asked for a whitelist: reject everything that no
		// rule above allowed. It must never leave through this server by itself.
		// "block" outbound is deprecated since sing-box 1.11 (removed in 1.13): use a rule action.
		rules = append(rules, map[string]any{"inbound": []string{"vless-in"}, "action": "reject"})
	}
	if hasProxy {
		d := tags[0]
		for _, t := range tags {
			if t == def {
				d = def
			}
		}
		outbounds = append(outbounds, map[string]any{"type": "selector", "tag": "proxy", "outbounds": tags, "default": d})
		if defaultAction != "block" {
			final = "proxy"
		}
	}
	outbounds = append(outbounds, map[string]any{"type": "direct", "tag": "direct"})

	inbounds := []any{}
	if len(users) > 0 {
		var vu []any
		for _, u := range users {
			vu = append(vu, map[string]any{"name": u.Name, "uuid": u.UUID, "flow": "xtls-rprx-vision"})
		}
		inbounds = append(inbounds, map[string]any{
			"type": "vless", "tag": "vless-in", "listen": "::", "listen_port": cfg.InboundPort,
			"users": vu,
			"tls": map[string]any{
				"enabled":     true,
				"server_name": cfg.Reality.HandshakeServer,
				"reality": map[string]any{
					"enabled":     true,
					"handshake":   map[string]any{"server": cfg.Reality.HandshakeServer, "server_port": cfg.Reality.HandshakePort},
					"private_key": cfg.Reality.PrivateKey,
					"short_id":    []string{cfg.Reality.ShortID},
				},
			},
		})
	}
	if len(probeUsers) > 0 {
		inbounds = append(inbounds, map[string]any{
			"type": "socks", "tag": "probe-in", "listen": "127.0.0.1", "listen_port": cfg.TestPort,
			"users": probeUsers,
		})
	}
	conf := map[string]any{
		"log":          map[string]any{"level": "warn", "timestamp": true},
		"inbounds":     inbounds,
		"outbounds":    outbounds,
		"route":        map[string]any{"rules": rules, "final": final},
		"experimental": map[string]any{"clash_api": map[string]any{"external_controller": cfg.ClashAPI}},
	}
	return json.MarshalIndent(conf, "", "  ")
}
