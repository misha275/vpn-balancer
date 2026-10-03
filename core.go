package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	"syscall"
	"time"
)

// Core supervises a sing-box child process and talks to its Clash API.
type Core struct {
	cfg        *Config
	mu         sync.Mutex
	cmd        *exec.Cmd
	applied    string
	hadProxy   bool    // the applied config had at least one node allowed to carry user traffic
	active     []*Node // nodes that are really in the applied config
	lastReload time.Time
	http       *http.Client

	gen       atomic.Int64 // bumped on every reload and every process (re)start
	changedAt atomic.Int64 // unix nanoseconds of the last bump
}

func (c *Core) bump() {
	c.gen.Add(1)
	c.changedAt.Store(time.Now().UnixNano())
}

// Gen changes whenever sing-box is reloaded or restarted. The checker uses it to
// discard probes that were interrupted by a reload instead of blaming the nodes.
func (c *Core) Gen() int64 { return c.gen.Load() }

// RecentlyChanged reports whether sing-box was reloaded/restarted within d.
func (c *Core) RecentlyChanged(d time.Duration) bool {
	return time.Since(time.Unix(0, c.changedAt.Load())) < d
}

func NewCore(cfg *Config) *Core {
	return &Core{cfg: cfg, http: &http.Client{Timeout: 5 * time.Second}}
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

// Apply writes a new config and reloads sing-box (SIGHUP) if the node set or
// the user list changed. It returns the nodes that are really in the running
// config (nodes rejected by `sing-box check` are left out and logged) and
// whether a new config was applied.
func (c *Core) Apply(nodes []*Node, users []User, def string) (active []*Node, applied bool, err error) {
	fp := fingerprint(nodes, users) + "|" + c.policySig(nodes)
	c.mu.Lock()
	defer c.mu.Unlock()
	if fp == c.applied {
		return c.active, false, nil
	}
	// The pause between reloads protects users from constant reconnects. It does not
	// apply while no node may carry traffic: users are rejected anyway, so the first
	// allowed node (for example right after the exit country was measured) goes live at once.
	if c.applied != "" && c.hadProxy && time.Since(c.lastReload) < c.cfg.MinReload {
		return c.active, false, nil // retried on the next reconcile tick
	}
	if err := os.MkdirAll(c.cfg.WorkDir, 0o755); err != nil {
		return c.active, false, err
	}
	tmp := c.cfgPath() + ".new"
	write := func(ns []*Node) error {
		data, err := BuildConfig(c.cfg, ns, users, def)
		if err != nil {
			return err
		}
		if err := os.WriteFile(tmp, data, 0o600); err != nil {
			return err
		}
		return c.check(tmp)
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
	if err := os.Rename(tmp, c.cfgPath()); err != nil {
		return c.active, false, err
	}
	c.applied = fp
	c.active = active
	c.hadProxy = false
	for _, n := range active {
		if n.Allowed(c.cfg) {
			c.hadProxy = true
			break
		}
	}
	c.lastReload = time.Now()
	if c.cmd != nil && c.cmd.Process != nil {
		_ = c.cmd.Process.Signal(syscall.SIGHUP)
		c.bump()
		log.Printf("core: config reloaded (%d nodes, %d users)", len(active), len(users))
	}
	return active, true, nil
}

// Run keeps sing-box alive (watchdog).
func (c *Core) Run(ctx context.Context) {
	for ctx.Err() == nil {
		cmd := exec.CommandContext(ctx, c.cfg.SingboxBin, "run", "-c", c.cfgPath())
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Start(); err != nil {
			log.Printf("core: start failed: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
			continue
		}
		c.mu.Lock()
		c.cmd = cmd
		c.mu.Unlock()
		c.bump()
		err := cmd.Wait()
		c.mu.Lock()
		c.cmd = nil
		c.mu.Unlock()
		c.bump()
		if ctx.Err() != nil {
			return
		}
		log.Printf("core: sing-box exited (%v), restarting", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func (c *Core) api(method, path string, body any) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, "http://"+c.cfg.ClashAPI+path, rd)
	if err != nil {
		return nil, err
	}
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

func (c *Core) CloseConnections() { _, _ = c.api("DELETE", "/connections", nil) }

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
