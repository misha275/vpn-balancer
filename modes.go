package main

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"
)

// Balancer modes. One gateway, one port: every user has three keys (UUIDs), one per mode, and each mode has its own
// selector in sing-box that the controller moves independently:
//
//	"" (current)  the main balancer: stable choice with hysteresis (the original behaviour)
//	"speed"       the fastest node among the best ones by the other parameters (score, quality, services)
//	"ping"        the lowest latency among the same best ones
const (
	modeSpeed = "speed"
	modePing  = "ping"
	// modeSpread spreads the traffic: the selector is moved to the node that has carried the least traffic lately.
	// The mode always exists inside the gateway; its links are shown to people only when spread_mode is on.
	modeSpread = "spread"
)

// balModes are the extra modes (the main one is the empty string).
var balModes = []string{modeSpeed, modePing, modeSpread}

// allModes lists every mode in the order they appear in links and the panel.
var allModes = []string{"", modeSpeed, modePing, modeSpread}

// linkModes are the modes people see (links, subscriptions, panel): "spread" only when it is switched on.
func linkModes(cfg *Config) []string {
	if cfg.spreadOn() {
		return allModes
	}
	return allModes[:3]
}

func modeTitle(mode string) string {
	switch mode {
	case modeSpeed:
		return "лучшая скорость"
	case modePing:
		return "лучший пинг"
	case modeSpread:
		return "по трафику"
	}
	return "текущий"
}

// modeTag is the sing-box selector of the mode.
func modeTag(mode string) string {
	if mode == "" {
		return "proxy"
	}
	return "proxy-" + mode
}

// modeUser is the sing-box user name of a user in a mode ("alice", "alice~speed", "alice~ping").
func modeUser(name, mode string) string {
	if mode == "" {
		return name
	}
	return name + "~" + mode
}

// foldUser maps the user name seen in the gateway logs back to the real user and the mode.
func foldUser(name string) (base, mode string) {
	if i := strings.LastIndex(name, "~x"); i > 0 && i+2 < len(name) {
		digits := name[i+2:]
		ok := true
		for _, r := range digits {
			if r < '0' || r > '9' {
				ok = false
			}
		}
		if ok {
			return name[:i], "x" + digits
		}
	}
	for _, m := range balModes {
		if strings.HasSuffix(name, "~"+m) && len(name) > len(m)+1 {
			return strings.TrimSuffix(name, "~"+m), m
		}
	}
	return name, ""
}

// modeUUID derives the key of a mode from the key of the user (nothing extra to store; deleting the user kills all three).
func modeUUID(uuid, mode string) string {
	if mode == "" {
		return uuid
	}
	h := sha256.Sum256([]byte("vpn-balancer|mode|" + mode + "|" + uuid))
	b := h[:16]
	b[6] = (b[6] & 0x0f) | 0x50 // version 5 layout
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// modeLinkName is the label of the balancer in the client list.
func modeLinkName(cfg *Config, mode string) string {
	n := cfg.getGatewayName()
	if mode == "" {
		return n
	}
	return n + " · " + modeTitle(mode)
}

// modeLink is the vless:// link of a user for a mode.
func modeLink(cfg *Config, u User, mode string) string {
	return userLink(cfg, modeLinkName(cfg, mode), modeUUID(u.UUID, mode))
}

// modeLinks are the links of all modes of a user, main first.
func modeLinks(cfg *Config, u User) []string {
	out := make([]string, 0, len(allModes))
	for _, m := range linkModes(cfg) {
		out = append(out, modeLink(cfg, u, m))
	}
	return out
}

// modeUsers lists the sing-box user names of the mode for the given users.
func modeUsers(users []User, mode string) []string {
	out := make([]string, 0, len(users))
	for _, u := range users {
		if u.NoBalancer {
			continue
		}
		out = append(out, modeUser(u.Name, mode))
	}
	return out
}

func (c *Config) spreadOn() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.SpreadMode != nil && *c.SpreadMode
}

func (c *Config) getSpreadInterval() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.SpreadInterval < 10*time.Second {
		return 60 * time.Second
	}
	return c.SpreadInterval
}

// foldGW merges the per-mode user names of a statistics report into the real users (for gateways that do not do it themselves).
func foldGW(gs *GWStats) {
	need := false
	for n := range gs.Deltas {
		if b, _ := foldUser(n); b != n {
			need = true
		}
	}
	for i := range gs.Sessions {
		if b, m := foldUser(gs.Sessions[i].User); b != gs.Sessions[i].User {
			gs.Sessions[i].User, gs.Sessions[i].Mode = b, m
		}
	}
	for n := range gs.Errs {
		if b, _ := foldUser(n); b != n {
			need = true
		}
	}
	if !need {
		return
	}
	d := make(map[string]UserDelta, len(gs.Deltas))
	for n, v := range gs.Deltas {
		b, _ := foldUser(n)
		x := d[b]
		x.Up, x.Down, x.Conns = x.Up+v.Up, x.Down+v.Down, x.Conns+v.Conns
		d[b] = x
	}
	gs.Deltas = d
	e := make(map[string]UserErr, len(gs.Errs))
	for n, v := range gs.Errs {
		b, _ := foldUser(n)
		if o, ok := e[b]; ok {
			v.Count += o.Count
			if o.Last > v.Last {
				v.Last, v.Msg = o.Last, o.Msg
			}
		}
		e[b] = v
	}
	gs.Errs = e
}
