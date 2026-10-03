package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func raw(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

func TestValidateSettings(t *testing.T) {
	good := map[string]json.RawMessage{
		"subscriptions":          raw([]string{"https://a.example.com/sub/x"}),
		"blocked_exit_countries": raw([]string{"ru", "Ir"}),
		"exit_check":             raw(true),
		"rules":                  raw([]RuleCfg{{Action: "direct", Match: []string{"*.ru"}}}),
		"default_action":         raw("block"),
		"node_identity":          raw("link"),
		"gateway_name":           raw("Мой VPN"),
		"probe_urls":             raw([]string{"https://www.gstatic.com/generate_204"}),
		"switch_margin":          raw(1.3),
		"switch_confirm":         raw(4),
	}
	if err := ValidateSettings(good); err != nil {
		t.Fatal(err)
	}
	bad := map[string]json.RawMessage{
		"subscriptions":          raw([]string{"ftp://x"}),
		"blocked_exit_countries": raw([]string{"Russia"}),
		"exit_check":             raw("yes"),
		"rules":                  raw([]RuleCfg{{Action: "allow", Match: []string{"a.com"}}}),
		"default_action":         raw("direct"), // a Russian server must never be the default exit
		"node_identity":          raw("both"),
		"gateway_name":           raw(""),
		"probe_urls":             raw([]string{}),
		"switch_margin":          raw(0.5),
		"switch_confirm":         raw(0),
		"nope":                   raw(1),
	}
	for k, v := range bad {
		if err := ValidateSettings(map[string]json.RawMessage{k: v}); err == nil {
			t.Errorf("%s=%s must be rejected", k, v)
		}
	}
	// the error must not leak the token of a subscription URL
	err := ValidateSettings(map[string]json.RawMessage{"subscriptions": raw([]string{"ftp://host.example/SECRETTOKEN"})})
	if err == nil || strings.Contains(err.Error(), "SECRETTOKEN") {
		t.Errorf("error leaks the token: %v", err)
	}
}

func TestApplySettingsIsAtomicAndVisible(t *testing.T) {
	cfg := policyCfg()
	cfg.DefaultAction, cfg.NodeIdentity = "proxy", "endpoint"
	before := cfg.Effective()
	err := cfg.ApplySettings(map[string]json.RawMessage{"default_action": raw("block"), "switch_confirm": raw(99)})
	if err == nil {
		t.Fatal("one bad value must reject the whole change")
	}
	if cfg.getDefaultAction() != "proxy" || len(before) != len(cfg.Effective()) {
		t.Error("a rejected change must not be applied partially")
	}
	if err := cfg.ApplySettings(map[string]json.RawMessage{
		"default_action": raw("block"), "blocked_exit_countries": raw([]string{"de"}),
		"rules": raw([]RuleCfg{{Action: "DIRECT", Match: []string{"*.ru"}}}),
	}); err != nil {
		t.Fatal(err)
	}
	if cfg.getDefaultAction() != "block" || !cfg.isBlocked("DE") || cfg.isBlocked("RU") {
		t.Error("settings not visible through the accessors")
	}
	if r := cfg.getRules(); len(r) != 1 || r[0].Action != "direct" {
		t.Errorf("rules: %+v", r)
	}
	// a node that was blocked before is allowed now and the other way round
	if !withExit(mkNode("ru"), "RU").Allowed(cfg) || withExit(mkNode("de"), "DE").Allowed(cfg) {
		t.Error("Allowed must follow the new country list")
	}
}

func TestSettingsConcurrentAccess(t *testing.T) { // run with -race
	cfg := policyCfg()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				cfg.ApplySettings(map[string]json.RawMessage{"blocked_exit_countries": raw([]string{"RU", "UA"}), "rules": raw([]RuleCfg{{Action: "block", Match: []string{"port:25"}}})})
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = withExit(mkNode("a"), "RU").Allowed(cfg)
				_ = cfg.getRules()
				_ = cfg.Effective()
			}
		}()
	}
	wg.Wait()
}

func TestAPIRequiresToken(t *testing.T) {
	a := NewAPI(policyCfg(), nil, nil, nil, "s3cr3t", make(chan struct{}, 1))
	mux := http.NewServeMux()
	a.Register(mux)
	n := 0
	ipFor := "" // empty: a new client address for every call, so one test does not trip the limiter of another
	call := func(method, path, auth string) int {
		req := httptest.NewRequest(method, path, nil)
		n++
		if ipFor == "" {
			req.RemoteAddr = fmt.Sprintf("10.0.%d.%d:1", n/250, n%250)
		} else {
			req.RemoteAddr = ipFor + ":1"
		}
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr.Code
	}
	for _, p := range []string{"GET /api/settings", "PUT /api/settings", "GET /api/users", "POST /api/users", "POST /api/pin", "POST /api/refresh", "POST /api/recheck", "GET /api/overview"} {
		f := strings.SplitN(p, " ", 2)
		if c := call(f[0], f[1], ""); c != 401 {
			t.Errorf("%s without a token: %d", p, c)
		}
		if c := call(f[0], f[1], "Bearer wrong"); c != 401 && c != 429 {
			t.Errorf("%s with a wrong token: %d", p, c)
		}
	}
	// the page itself carries no secrets and needs no token
	if c := call("GET", "/", ""); c != 200 {
		t.Errorf("panel page: %d", c)
	}
	// repeated wrong tokens are slowed down
	got429 := false
	ipFor = "9.9.9.9"
	for i := 0; i < 15; i++ {
		if call("GET", "/api/users", "Bearer x") == 429 {
			got429 = true
		}
	}
	if !got429 {
		t.Error("guessing the token must be rate limited")
	}
}

func TestPinAndFindNode(t *testing.T) {
	cfg := policyCfg()
	c := NewChecker(cfg, nil, NewCore(cfg), &Notifier{})
	a, b, ru := withExit(mkNode("alpha"), "DE"), withExit(mkNode("beta"), "NL"), withExit(mkNode("rus"), "RU")
	a.Name, b.Name, ru.Name = "Germany 1", "Germany 2", "Russia"
	c.SyncNodes([]*Node{a, b, ru})
	feed(c.st("alpha"), 20, true, 50)
	feed(c.st("beta"), 20, true, 120)
	feed(c.st("rus"), 20, true, 10)
	if _, err := c.FindNode("germany"); err == nil || !strings.Contains(err.Error(), "2") {
		t.Errorf("an ambiguous name must ask to be more precise: %v", err)
	}
	if st, err := c.FindNode("Germany 2"); err != nil || st.Node.ID != b.ID {
		t.Errorf("exact name: %v", err)
	}
	if st, err := c.FindNode(a.Tag()); err != nil || st.Node.ID != a.ID {
		t.Errorf("by tag: %v", err)
	}
	if _, err := c.FindNode("nothing"); err == nil {
		t.Error("unknown node")
	}
	if _, err := c.Pin("Russia"); err == nil {
		t.Error("a node with a censored exit must not be pinned")
	}
	c.states[b.ID].score = 0
	if _, err := c.Pin("Germany 2"); err == nil {
		t.Error("a dead node must not be pinned")
	}
	c.states[b.ID].recompute()
	c.mu.Lock()
	c.current, c.pinned = a.ID, b.ID
	target, reason, _ := c.decideLocked(false)
	c.mu.Unlock()
	if target == nil || target.ID != b.ID || reason != "pinned" {
		t.Errorf("the pinned node must be chosen even if another is better: %v %s", target, reason)
	}
	c.mu.Lock()
	c.states[b.ID].score = 0 // the pinned node died: automatic choice takes over
	target, reason, _ = c.decideLocked(false)
	c.mu.Unlock()
	if target != nil && reason == "pinned" {
		t.Error("a dead pinned node must not hold users")
	}
}

func TestParseCLIValue(t *testing.T) {
	for in, want := range map[string]string{"true": "true", "1.25": "1.25", `["a","b"]`: `["a","b"]`, "block": `"block"`, "my vpn": `"my vpn"`} {
		if got := string(parseCLIValue(in)); got != want {
			t.Errorf("%q -> %s, want %s", in, got, want)
		}
	}
}
