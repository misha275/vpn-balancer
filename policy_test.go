package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseMatch(t *testing.T) {
	ok := []struct{ in, field, val string }{
		{"*.ru", "suffix", "ru"},
		{"*.Example.COM", "suffix", "example.com"},
		{".example.com", "suffix", "example.com"},
		{"example.com", "domain", "example.com"},
		{"domain:example.com", "domain", "example.com"},
		{"ads*.example.com", "regex", `^ads.*\.example\.com$`},
		{"100.200.255.0/24", "cidr", "100.200.255.0/24"},
		{"100.200.255.77/24", "cidr", "100.200.255.0/24"},
		{"1.2.3.4", "cidr", "1.2.3.4/32"},
		{"2001:db8::1", "cidr", "2001:db8::1/128"},
		{"2001:db8::/32", "cidr", "2001:db8::/32"},
		{"keyword:ads", "keyword", "ads"},
		{"regex:^a.+b$", "regex", "^a.+b$"},
		{"port:25", "port", "25"},
		{"port:6881-6999", "portrange", "6881:6999"},
		{"*.xn--p1ai", "suffix", "xn--p1ai"},
	}
	for _, c := range ok {
		f, v, err := parseMatch(c.in)
		if err != nil || f != c.field || v != c.val {
			t.Errorf("%q: got (%q,%q,%v), want (%q,%q)", c.in, f, v, err, c.field, c.val)
		}
	}
	bad := []string{"", "  ", "*.рф", "рф", "bad domain", "regex:(", "port:0", "port:70000", "port:9-3", "10.0.0.0/33", "a*b*[c].com", "*."}
	for _, in := range bad {
		if _, _, err := parseMatch(in); err == nil {
			t.Errorf("%q must be rejected", in)
		}
	}
}

func TestCompileRules(t *testing.T) {
	rules := []RuleCfg{
		{Action: "direct", Match: []string{"*.ru", "example.com", "100.200.255.0/24", "port:25"}},
		{Action: "block", Match: []string{"keyword:tracker"}},
		{Action: "proxy", Match: []string{"*.gov.ru"}},
	}
	out, err := CompileRules(rules, true)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(out)
	var got []map[string]any
	json.Unmarshal(raw, &got)
	// direct: suffix, domain, cidr, port (4 rule objects) + block + proxy = 6, order kept
	if len(got) != 6 {
		t.Fatalf("expected 6 rules, got %d: %s", len(got), raw)
	}
	for _, r := range got {
		if !reflect.DeepEqual(r["inbound"], []any{"vless-in"}) {
			t.Errorf("rule is not limited to the user inbound: %v", r)
		}
	}
	if got[0]["outbound"] != "direct" || got[4]["action"] != "reject" || got[5]["outbound"] != "proxy" {
		t.Errorf("actions are wrong: %s", raw)
	}
	if got[5]["domain_suffix"].([]any)[0] != "gov.ru" {
		t.Errorf("first match wins, so the more specific proxy rule must stay after: %s", raw)
	}
	// without any usable node "proxy" must become reject, never a direct exit
	out, _ = CompileRules(rules[2:], false)
	raw, _ = json.Marshal(out)
	if !strings.Contains(string(raw), `"reject"`) || strings.Contains(string(raw), `"outbound"`) {
		t.Errorf("proxy rule without nodes must reject: %s", raw)
	}
	for _, r := range []RuleCfg{{Action: "allow", Match: []string{"a.com"}}, {Action: "direct"}, {Action: "direct", Match: []string{"bad domain"}}} {
		if _, err := CompileRules([]RuleCfg{r}, true); err == nil {
			t.Errorf("%+v must be rejected", r)
		}
	}
}

func TestParseGeo(t *testing.T) {
	cases := []struct {
		body, ip, cc string
		ok           bool
	}{
		{`{"ip":"88.216.60.92","country":"SE","org":"x"}`, "88.216.60.92", "SE", true},
		{`{"ip":"1.2.3.4","country_iso":"nl"}`, "1.2.3.4", "NL", true},
		{`{"query":"1.2.3.4","countryCode":"de"}`, "1.2.3.4", "DE", true},
		{`{"country_code":"FR"}`, "", "FR", true},
		{"DE\n", "", "DE", true},
		{`{"ip":"1.2.3.4","country":"Germany"}`, "1.2.3.4", "", false},
		{`<html>blocked</html>`, "", "", false},
		{``, "", "", false},
	}
	for _, c := range cases {
		ip, cc, ok := parseGeo([]byte(c.body))
		if ip != c.ip || cc != c.cc || ok != c.ok {
			t.Errorf("%q: got (%q,%q,%v)", c.body, ip, cc, ok)
		}
	}
}

func TestPickCountrySafeSide(t *testing.T) {
	cfg := policyCfg()
	if got := pickCountry([]string{"DE", "RU"}, cfg.isBlocked); got != "RU" {
		t.Errorf("a blocked answer must win, got %s", got)
	}
	if got := pickCountry([]string{"DE", "NL"}, cfg.isBlocked); got != "DE" {
		t.Errorf("got %s", got)
	}
	if pickCountry(nil, cfg.isBlocked) != "" {
		t.Error("no answers -> unknown")
	}
}

func policyCfg() *Config {
	on := true
	c := testCfg()
	c.ExitCheck = &on
	c.blocked = map[string]bool{}
	for _, cc := range defaultBlockedCountries {
		c.blocked[cc] = true
	}
	return c
}

func withExit(n *Node, cc string) *Node { n.ExitCountry = cc; return n }

func TestAllowedFailsClosed(t *testing.T) {
	cfg := policyCfg()
	for cc, want := range map[string]bool{"": false, "DE": true, "NL": true, "RU": false, "ru": false, "UA": false, "IR": false, "SY": false, "CN": false} {
		if got := withExit(mkNode("a"), cc).Allowed(cfg); got != want {
			t.Errorf("exit %q: allowed=%v, want %v", cc, got, want)
		}
	}
	off := testCfg() // exit_check not enabled: every node is allowed (old behaviour)
	if !withExit(mkNode("a"), "RU").Allowed(off) {
		t.Error("with exit_check off nothing is filtered")
	}
}

func TestLoadConfigPolicyDefaults(t *testing.T) {
	c, err := LoadConfig(writeCfg(t, "subscriptions: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !c.exitCheckOn() || !c.isBlocked("RU") || !c.isBlocked("ua") || !c.isBlocked("IR") || !c.isBlocked("SY") || c.isBlocked("DE") {
		t.Errorf("defaults are wrong: %v", c.BlockedCountries)
	}
	if c.DefaultAction != "proxy" {
		t.Errorf("default action %q", c.DefaultAction)
	}
	c, err = LoadConfig(writeCfg(t, "blocked_exit_countries: [cn, ir]\nexit_check: false\n"))
	if err != nil || c.exitCheckOn() || !c.isBlocked("CN") || c.isBlocked("RU") {
		t.Errorf("override failed: %v %v", c, err)
	}
	c, _ = LoadConfig(writeCfg(t, "blocked_exit_countries: []\n"))
	if c.isBlocked("RU") {
		t.Error("an explicit empty list means: block nothing")
	}
	for _, bad := range []string{
		"blocked_exit_countries: [Russia]\n",
		"default_action: direct\n", // a Russian server must never be the default exit
		"rules:\n  - action: direct\n    match: [\"bad domain\"]\n",
		"rules:\n  - action: nope\n    match: [a.com]\n",
	} {
		if _, err := LoadConfig(writeCfg(t, bad)); err == nil {
			t.Errorf("config must be rejected:\n%s", bad)
		}
	}
}

func buildMap(t *testing.T, cfg *Config, nodes []*Node, users []User, def string) map[string]any {
	t.Helper()
	data, err := BuildConfig(cfg, nodes, users, def)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func selectorTags(m map[string]any) []string {
	for _, o := range m["outbounds"].([]any) {
		om := o.(map[string]any)
		if om["tag"] == "proxy" {
			var tags []string
			for _, x := range om["outbounds"].([]any) {
				tags = append(tags, x.(string))
			}
			return tags
		}
	}
	return nil
}

func TestBuildConfigKeepsCensoredExitsOutOfTheSelector(t *testing.T) {
	cfg := policyCfg()
	de, ru, unk := withExit(mkNode("de"), "DE"), withExit(mkNode("ru"), "RU"), mkNode("unk")
	users := []User{{Name: "u", UUID: testUUID}}
	m := buildMap(t, cfg, []*Node{de, ru, unk}, users, ru.Tag())
	tags := selectorTags(m)
	if !reflect.DeepEqual(tags, []string{de.Tag()}) {
		t.Fatalf("only the node with a safe exit may be in the selector, got %v", tags)
	}
	for _, o := range m["outbounds"].([]any) {
		if o.(map[string]any)["tag"] == "proxy" && o.(map[string]any)["default"] != de.Tag() {
			t.Error("the selector default must be an allowed node even if the saved current node is censored")
		}
	}
	// the checker must still be able to probe every node
	if !strings.Contains(mustJSON(m), "probe-"+ru.Tag()) || !strings.Contains(mustJSON(m), "probe-"+unk.Tag()) {
		t.Error("probe logins must exist for all nodes, including excluded ones")
	}
	// all censored/unknown: user traffic is rejected, never sent out directly
	m = buildMap(t, cfg, []*Node{ru, unk}, users, "")
	if selectorTags(m) != nil {
		t.Fatal("no selector expected")
	}
	rt := m["route"].(map[string]any)
	rules := rt["rules"].([]any)
	last := rules[len(rules)-1].(map[string]any)
	if last["action"] != "reject" || !reflect.DeepEqual(last["inbound"], []any{"vless-in"}) {
		t.Errorf("last rule must reject user traffic, got %v", last)
	}
}

func TestBuildConfigRuleOrderAndDefaults(t *testing.T) {
	cfg := policyCfg()
	cfg.Rules = []RuleCfg{{Action: "direct", Match: []string{"*.ru"}}, {Action: "block", Match: []string{"port:25"}}}
	de := withExit(mkNode("de"), "DE")
	m := buildMap(t, cfg, []*Node{de}, []User{{Name: "u", UUID: testUUID}}, "")
	rt := m["route"].(map[string]any)
	if rt["final"] != "proxy" {
		t.Errorf("default must be the balancer, got %v", rt["final"])
	}
	rules := rt["rules"].([]any)
	if rules[0].(map[string]any)["auth_user"] == nil {
		t.Error("probe rules must come first so rules cannot affect health checks")
	}
	if rules[1].(map[string]any)["domain_suffix"] == nil || rules[1].(map[string]any)["outbound"] != "direct" {
		t.Errorf("user rules follow in order: %v", rules[1])
	}
	cfg.DefaultAction = "block"
	m = buildMap(t, cfg, []*Node{de}, []User{{Name: "u", UUID: testUUID}}, "")
	rt = m["route"].(map[string]any)
	rules = rt["rules"].([]any)
	if rt["final"] == "proxy" || rules[len(rules)-1].(map[string]any)["action"] != "reject" {
		t.Errorf("whitelist mode must end with reject: %v", rt)
	}
}

func TestPolicyChangeChangesFingerprint(t *testing.T) {
	cfg := policyCfg()
	c := NewCore(cfg)
	n := mkNode("a")
	before := c.policySig([]*Node{n})
	n.ExitCountry = "DE"
	if c.policySig([]*Node{n}) == before {
		t.Error("learning the exit country must reload sing-box")
	}
	n.ExitCountry = "RU"
	if c.policySig([]*Node{n}) != before {
		t.Error("unknown and censored are both 'not allowed': no reload needed")
	}
}

func TestDecideSkipsCensoredAndFailsOverFromIt(t *testing.T) {
	cfg := policyCfg()
	c := NewChecker(cfg, nil, NewCore(cfg), &Notifier{})
	a, b := withExit(mkNode("a"), "DE"), withExit(mkNode("b"), "NL")
	c.SyncNodes([]*Node{a, b})
	feed(c.st("a"), 20, true, 50)
	feed(c.st("b"), 20, true, 300) // clearly worse but allowed
	c.current = a.ID
	a.ExitCountry = "RU" // the exit of the current node turns out to be in a censored country
	target, reason, _ := c.decideLocked(false)
	if target == nil || target.ID != b.ID || reason != "failover" {
		t.Fatalf("must fail over to the allowed node, got %v %s", target, reason)
	}
	b.ExitCountry = "" // exit unknown: not allowed either
	if target, _, _ = c.decideLocked(false); target != nil {
		t.Errorf("no allowed node: nothing may be chosen, got %v", target)
	}
}

func TestRenderSub(t *testing.T) {
	cfg := policyCfg()
	cfg.PublicHost, cfg.InboundPort = "gw.example.com", 443
	cfg.Reality.PublicKey, cfg.Reality.ShortID, cfg.Reality.HandshakeServer = "PUB", "ab12", "www.apple.com"
	cfg.GatewayName = "Balancer"
	mk := func(id, cc, name string) *Node {
		n := withExit(mkNode(id), cc)
		n.Name, n.Link = name, "vless://x@"+id+".example.com:443?security=reality#"+name
		return n
	}
	nodes := []*Node{mk("nl", "NL", "Netherlands"), mk("ru", "RU", "USA label"), mk("de", "DE", "Germany"), mk("unk", "", "Unknown"), {ID: "x" + strings.Repeat("0", 39), Name: "old", ExitCountry: "SE"}}
	lines := RenderSub(cfg, &User{Name: "bob", UUID: testUUID}, nodes)
	if len(lines) != 3 {
		t.Fatalf("balancer + 2 allowed nodes with links expected, got %d: %v", len(lines), lines)
	}
	if !strings.HasPrefix(lines[0], "vless://"+testUUID+"@gw.example.com:443") || !strings.HasSuffix(lines[0], "#Balancer") {
		t.Errorf("the balancer must be first: %s", lines[0])
	}
	if !strings.Contains(lines[1], "de.example.com") || !strings.HasSuffix(lines[1], "#%5BDE%5D%20Germany") {
		t.Errorf("nodes follow, sorted by exit country, labelled with the measured exit: %s", lines[1])
	}
	for _, l := range lines {
		if strings.Contains(l, "ru.example.com") || strings.Contains(l, "unk.example.com") {
			t.Errorf("censored or unverified exit must not be handed out: %s", l)
		}
	}
}

func TestSubHandlerLimitsAndFormat(t *testing.T) {
	s := NewSubServer(policyCfg(), nil)
	for i := 0; i < 20; i++ {
		s.fail("1.2.3.4")
	}
	if !s.limited("1.2.3.4") || s.limited("5.6.7.8") {
		t.Error("rate limit per address is wrong")
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/sub/abc", nil)
	req.RemoteAddr = "1.2.3.4:5555"
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("got %d", rr.Code)
	}
}

// The generated config with rules, excluded nodes and whitelist mode must be valid for the pinned sing-box.
func TestCorePolicyConfigPassesSingboxCheck(t *testing.T) {
	cfg := coreCfg(t)
	on := true
	cfg.ExitCheck = &on
	cfg.blocked = map[string]bool{"RU": true}
	cfg.Rules = []RuleCfg{
		{Action: "direct", Match: []string{"*.ru", "example.com", "100.200.255.0/24", "2001:db8::/32", "ads*.example.com", "keyword:yandex", "regex:^a.+b$"}},
		{Action: "block", Match: []string{"port:25", "port:6881-6999"}},
		{Action: "proxy", Match: []string{"*.gov.ru"}},
	}
	ns := allProtocolNodes(t)
	for i, n := range ns {
		if i%3 == 0 {
			n.ExitCountry = "RU"
		} else if i%3 == 1 {
			n.ExitCountry = "DE"
		}
	}
	users := []User{{Name: "alice", UUID: testUUID}}
	for name, c := range map[string]struct {
		nodes  []*Node
		action string
	}{"mixed": {ns, "proxy"}, "all excluded": {ns[:1], "proxy"}, "whitelist": {ns, "block"}} {
		cfg.DefaultAction = c.action
		data, err := BuildConfig(cfg, c.nodes, users, "")
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), "c.json")
		os.WriteFile(p, data, 0o600)
		if out, err := exec.Command(cfg.SingboxBin, "check", "-c", p).CombinedOutput(); err != nil || len(out) > 0 {
			t.Errorf("%s: sing-box check: %v\n%s\n%s", name, err, out, data)
		}
	}
}

var _ = base64.StdEncoding

func TestParseLinksPerLink(t *testing.T) {
	body := "vless://" + testUUID + "@h.example.com:443?security=reality&sni=h.example.com&pbk=" + testPBK + "&sid=ab#One\n" +
		"vless://" + testUUID + "@h.example.com:443?security=reality&sni=h.example.com&pbk=" + testPBK + "&sid=ab#Two\n" +
		"vless://" + testUUID + "@h.example.com:443?security=reality&sni=h.example.com&pbk=" + testPBK + "&sid=ab#Two\n"
	if got := len(ParseLinks(body)); got != 1 {
		t.Errorf("endpoint mode: identical parameters are one node, got %d", got)
	}
	ns := ParseLinksPerLink(body)
	if len(ns) != 2 || ns[0].ID == ns[1].ID || ns[0].Tag() == ns[1].Tag() {
		t.Fatalf("link mode: two names -> two nodes, got %d", len(ns))
	}
	if ns[0].Link == "" || ns[0].Name != "One" {
		t.Errorf("%+v", ns[0])
	}
	again := ParseLinksPerLink(body)
	if again[0].ID != ns[0].ID || again[1].ID != ns[1].ID {
		t.Error("IDs must be stable between downloads")
	}
}

func TestBlockedNodeIsLookedAtAgainSooner(t *testing.T) {
	cfg := policyCfg()
	cfg.GeoTTL, cfg.GeoBlockedTTL = 6*time.Hour, 30*time.Minute
	c := NewChecker(cfg, nil, NewCore(cfg), &Notifier{})
	ru, de := withExit(mkNode("ru"), "RU"), withExit(mkNode("de"), "DE")
	ru.ExitChecked, de.ExitChecked = time.Now().Add(-time.Hour), time.Now().Add(-time.Hour)
	c.SyncNodes([]*Node{ru, de})
	if !c.needsGeo(c.st("ru"), time.Now()) || c.needsGeo(c.st("de"), time.Now()) {
		t.Error("RU node (blocked) is re-measured after 30m, DE node only after 6h")
	}
}
