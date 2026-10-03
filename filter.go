package main

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// RuleCfg is one user-defined routing rule from config.yaml:
//
//	rules:
//	  - action: direct            # direct | block | proxy
//	    match: ["*.ru", "100.200.255.0/24", "port:25"]
//
// Rules are evaluated top to bottom, the first match wins. Traffic that matches
// no rule goes through the balancer ("proxy"), unless default_action says otherwise.
type RuleCfg struct {
	Action  string   `yaml:"action"`
	Match   []string `yaml:"match"`
	Comment string   `yaml:"comment"`
}

var domainOK = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_.-]*[a-z0-9_])?$`)

// ruleFields groups parsed matchers by sing-box field. Different fields of one
// rule object are ANDed by sing-box, values of one field are ORed, so every
// field becomes its own rule object (the entries of one config rule are ORed).
type ruleFields struct {
	domain, suffix, keyword, regex, cidr, port, portRange []string
}

// parseMatch turns one human-friendly matcher into a field and a value.
//
//	*.ru                 any domain in the .ru zone (and "ru" itself)
//	*.example.com        example.com and all of its subdomains
//	.example.com         the same
//	example.com          exactly this domain
//	ads*.example.com     wildcard inside a name (converted to a regular expression)
//	100.200.255.0/24     a network; 1.2.3.4 means a single address; IPv6 works too
//	port:25, port:6881-6999
//	domain:/suffix:/keyword:/regex:/cidr:   explicit forms
func parseMatch(entry string) (field, value string, err error) {
	e := strings.TrimSpace(entry)
	if e == "" {
		return "", "", fmt.Errorf("empty matcher")
	}
	low := strings.ToLower(e)
	switch {
	case strings.HasPrefix(low, "domain:"):
		return domainEntry("domain", e[len("domain:"):])
	case strings.HasPrefix(low, "suffix:"):
		return domainEntry("suffix", e[len("suffix:"):])
	case strings.HasPrefix(low, "keyword:"):
		k := strings.ToLower(strings.TrimSpace(e[len("keyword:"):]))
		if k == "" {
			return "", "", fmt.Errorf("%q: empty keyword", entry)
		}
		return "keyword", k, nil
	case strings.HasPrefix(low, "regex:"):
		r := strings.TrimSpace(e[len("regex:"):])
		if _, err := regexp.Compile(r); err != nil {
			return "", "", fmt.Errorf("%q: bad regular expression: %v", entry, err)
		}
		return "regex", r, nil
	case strings.HasPrefix(low, "port:"):
		return portEntry(entry, strings.TrimSpace(e[len("port:"):]))
	case strings.HasPrefix(low, "cidr:"), strings.HasPrefix(low, "ip:"):
		return cidrEntry(entry, e[strings.Index(e, ":")+1:])
	}
	if strings.Contains(e, "/") || isIP(e) {
		return cidrEntry(entry, e)
	}
	if strings.HasPrefix(low, "*.") {
		return domainEntry("suffix", e[2:])
	}
	if strings.HasPrefix(low, ".") {
		return domainEntry("suffix", e[1:])
	}
	if strings.ContainsAny(e, "*?") {
		if !wildcardOK(low) {
			return "", "", fmt.Errorf("%q: unsupported wildcard (use regex:... for complex patterns)", entry)
		}
		return "regex", globToRegex(low), nil
	}
	return domainEntry("domain", e)
}

func isIP(s string) bool { _, err := netip.ParseAddr(s); return err == nil }

func wildcardOK(s string) bool {
	for _, r := range s {
		if !(r == '*' || r == '?' || r == '.' || r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

func globToRegex(g string) string {
	var b strings.Builder
	b.WriteString("^")
	for _, r := range g {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	return b.String()
}

func domainEntry(field, raw string) (string, string, error) {
	d := strings.ToLower(strings.Trim(strings.TrimSpace(raw), "."))
	if d == "" {
		return "", "", fmt.Errorf("%q: empty domain", raw)
	}
	for _, r := range d {
		if r > 127 {
			return "", "", fmt.Errorf("%q: write internationalized domains in punycode (for example xn--p1ai instead of рф)", raw)
		}
	}
	if !domainOK.MatchString(d) {
		return "", "", fmt.Errorf("%q: not a valid domain", raw)
	}
	return field, d, nil
}

func cidrEntry(entry, raw string) (string, string, error) {
	raw = strings.TrimSpace(raw)
	if p, err := netip.ParsePrefix(raw); err == nil {
		return "cidr", p.Masked().String(), nil
	}
	if a, err := netip.ParseAddr(raw); err == nil {
		return "cidr", netip.PrefixFrom(a, a.BitLen()).String(), nil
	}
	return "", "", fmt.Errorf("%q: not an IP address or network", entry)
}

func portEntry(entry, raw string) (string, string, error) {
	ok := func(s string) (int, bool) {
		n, err := strconv.Atoi(s)
		return n, err == nil && n >= 1 && n <= 65535
	}
	if a, b, found := strings.Cut(raw, "-"); found {
		lo, ok1 := ok(strings.TrimSpace(a))
		hi, ok2 := ok(strings.TrimSpace(b))
		if !ok1 || !ok2 || lo > hi {
			return "", "", fmt.Errorf("%q: bad port range", entry)
		}
		return "portrange", fmt.Sprintf("%d:%d", lo, hi), nil
	}
	n, good := ok(raw)
	if !good {
		return "", "", fmt.Errorf("%q: bad port", entry)
	}
	return "port", strconv.Itoa(n), nil
}

// CompileRules converts the config rules to sing-box route rules for the user
// inbound. hasProxy says whether the selector "proxy" exists in this config:
// without it (no node is allowed to carry traffic) "proxy" rules become "reject",
// so traffic can never leak out of the server itself.
func CompileRules(rules []RuleCfg, hasProxy bool) ([]any, error) {
	var out []any
	for i, r := range rules {
		act := strings.ToLower(strings.TrimSpace(r.Action))
		if act != "direct" && act != "block" && act != "proxy" {
			return nil, fmt.Errorf("rules[%d]: action must be direct, block or proxy, got %q", i, r.Action)
		}
		if len(r.Match) == 0 {
			return nil, fmt.Errorf("rules[%d]: match is empty", i)
		}
		var f ruleFields
		for _, m := range r.Match {
			field, val, err := parseMatch(m)
			if err != nil {
				return nil, fmt.Errorf("rules[%d]: %w", i, err)
			}
			switch field {
			case "domain":
				f.domain = append(f.domain, val)
			case "suffix":
				f.suffix = append(f.suffix, val)
			case "keyword":
				f.keyword = append(f.keyword, val)
			case "regex":
				f.regex = append(f.regex, val)
			case "cidr":
				f.cidr = append(f.cidr, val)
			case "port":
				f.port = append(f.port, val)
			case "portrange":
				f.portRange = append(f.portRange, val)
			}
		}
		emit := func(key string, vals []string) {
			if len(vals) == 0 {
				return
			}
			rule := map[string]any{"inbound": []string{"vless-in"}, key: vals}
			switch {
			case act == "direct":
				rule["outbound"] = "direct"
			case act == "proxy" && hasProxy:
				rule["outbound"] = "proxy"
			default:
				rule["action"] = "reject"
			}
			out = append(out, rule)
		}
		emit("domain", f.domain)
		emit("domain_suffix", f.suffix)
		emit("domain_keyword", f.keyword)
		emit("domain_regex", f.regex)
		emit("ip_cidr", f.cidr)
		if len(f.port) > 0 {
			ports := make([]int, 0, len(f.port))
			for _, p := range f.port {
				n, _ := strconv.Atoi(p)
				ports = append(ports, n)
			}
			rule := map[string]any{"inbound": []string{"vless-in"}, "port": ports}
			switch {
			case act == "direct":
				rule["outbound"] = "direct"
			case act == "proxy" && hasProxy:
				rule["outbound"] = "proxy"
			default:
				rule["action"] = "reject"
			}
			out = append(out, rule)
		}
		emit("port_range", f.portRange)
	}
	return out, nil
}
