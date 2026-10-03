package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// Countries with heavy internet censorship (ISO 3166-1 alpha-2). A node whose
// last hop (exit) is in one of them is never used for users and is not
// given out in the user subscription. Override with blocked_exit_countries.
var defaultBlockedCountries = []string{"RU", "UA", "BY", "CN", "IR", "SY", "KP", "TM", "CU", "MM"}

var defaultGeoURLs = []string{
	"https://ipinfo.io/json",
	"https://api.country.is",
	"https://ifconfig.co/json",
}

func (c *Config) exitCheckOn() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ExitCheck != nil && *c.ExitCheck
}

func (c *Config) isBlocked(cc string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.blocked[strings.ToUpper(cc)]
}

// Allowed reports whether user traffic may leave through this node. With
// exit_check on, the exit country must be known (fail closed) and not blocked.
func (n *Node) Allowed(c *Config) bool {
	if !c.exitCheckOn() {
		return true
	}
	return n.ExitCountry != "" && !c.isBlocked(n.ExitCountry)
}

// parseGeo extracts the exit IP and the 2-letter country code from the answer
// of an IP-info service. It understands the common JSON shapes
// (country, country_code, countryCode, country_iso) and a bare "DE".
func parseGeo(body []byte) (ip, cc string, ok bool) {
	s := strings.TrimSpace(string(body))
	if len(s) == 2 && isAlpha2(s) {
		return "", strings.ToUpper(s), true
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return "", "", false
	}
	for _, k := range []string{"ip", "query", "ip_addr"} {
		if v, _ := m[k].(string); v != "" {
			if a, err := netip.ParseAddr(v); err == nil {
				ip = a.String()
				break
			}
		}
	}
	for _, k := range []string{"country", "country_code", "countryCode", "country_iso"} {
		if v, _ := m[k].(string); len(strings.TrimSpace(v)) == 2 && isAlpha2(strings.TrimSpace(v)) {
			return ip, strings.ToUpper(strings.TrimSpace(v)), true
		}
	}
	return ip, "", false
}

func isAlpha2(s string) bool {
	return len(s) == 2 && ((s[0]|0x20) >= 'a' && (s[0]|0x20) <= 'z') && ((s[1]|0x20) >= 'a' && (s[1]|0x20) <= 'z')
}

// pickCountry combines the answers of several services. A blocked country wins
// over everything: if any service places the exit in a censored country, the
// node is treated as such (the safe side).
func pickCountry(answers []string, blocked func(string) bool) string {
	if len(answers) == 0 {
		return ""
	}
	for _, a := range answers {
		if blocked(a) {
			return a
		}
	}
	return answers[0]
}

// geoCheck asks IP-info services through the node (so they see the node's exit
// address) and returns the exit IP and country. It stops after two valid answers.
func (c *Checker) geoCheck(ctx context.Context, n *Node) (ip, cc string, err error) {
	cl, tr := c.client(n.Tag(), 8*time.Second)
	defer tr.CloseIdleConnections()
	var answers []string
	var errs []string
	for _, u := range c.cfg.GeoURLs {
		req, e := http.NewRequestWithContext(ctx, "GET", u, nil)
		if e != nil {
			errs = append(errs, e.Error())
			continue
		}
		req.Header.Set("User-Agent", "curl/8.5.0") // some services serve JSON only to curl
		req.Header.Set("Accept", "application/json")
		resp, e := cl.Do(req)
		if e != nil {
			errs = append(errs, scrubErr(e).Error())
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
		resp.Body.Close()
		if resp.StatusCode != 200 {
			errs = append(errs, fmt.Sprintf("%s: http %d", redact(u), resp.StatusCode))
			continue
		}
		gip, gcc, ok := parseGeo(body)
		if !ok {
			errs = append(errs, redact(u)+": unrecognised answer")
			continue
		}
		if ip == "" {
			ip = gip
		}
		answers = append(answers, gcc)
		if len(answers) == 2 {
			break
		}
	}
	if len(answers) == 0 {
		return "", "", errors.New("no geo answer: " + strings.Join(errs, "; "))
	}
	return ip, pickCountry(answers, c.cfg.isBlocked), nil
}

func (c *Checker) needsGeo(st *NodeState, now time.Time) bool {
	if !c.cfg.exitCheckOn() {
		return false
	}
	ttl := c.cfg.GeoTTL
	if st.Node.ExitCountry != "" && c.cfg.isBlocked(st.Node.ExitCountry) && c.cfg.GeoBlockedTTL > 0 && c.cfg.GeoBlockedTTL < ttl {
		ttl = c.cfg.GeoBlockedTTL // a node in a blocked country is looked at again sooner
	}
	return st.Node.ExitCountry == "" || now.Sub(st.Node.ExitChecked) > ttl
}

// geoPass determines the exit country of every node that works but has no
// fresh answer yet. A failed lookup is retried on the next tier-2 cycle and
// never hurts the node's score.
func (c *Checker) geoPass(ctx context.Context) {
	if !c.cfg.exitCheckOn() {
		return
	}
	now := time.Now()
	nodes := c.pick(func(st *NodeState) bool {
		return st.tcpOK && st.proxyFail == 0 && now.After(st.quarantine) && len(st.win) > 0 && c.needsGeo(st, now)
	})
	if len(nodes) == 0 {
		return
	}
	gen := c.core.Gen()
	forEach(nodes, c.cfg.Tier2Concurrency, func(n *Node) {
		ip, cc, err := c.geoCheck(ctx, n)
		if err != nil || ctx.Err() != nil || c.core.Gen() != gen {
			return
		}
		c.setExit(ctx, n, ip, cc)
	})
}

func (c *Checker) setExit(ctx context.Context, n *Node, ip, cc string) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if c.store != nil {
		if err := c.store.SetExit(cctx, n.ID, ip, cc); err != nil {
			log.Printf("geo: store exit of %s: %v", n.Tag(), err)
		}
	}
	c.mu.Lock()
	prev := ""
	if st := c.states[n.ID]; st != nil {
		prev = st.Node.ExitCountry
		st.Node.ExitIP, st.Node.ExitCountry, st.Node.ExitChecked = ip, cc, time.Now()
	}
	c.mu.Unlock()
	if prev != cc {
		log.Printf("geo: %s (%s) exits in %s (%s)", n.Name, n.Tag(), cc, ip)
	}
	if c.cfg.isBlocked(cc) {
		c.notify.Notify("blocked:"+n.ID, fmt.Sprintf("🚫 Узел «%s» выходит в %s — исключён из пользовательского трафика", n.Name, cc), 24*time.Hour)
	}
}
