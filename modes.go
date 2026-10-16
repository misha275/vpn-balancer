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

// Two channels of the balancer. "admin" is the pool of nodes of the operator (subscriptions of the provider), with all the
// modes above. "users" is the second pool for the people of the service (users_subscriptions): its own selectors "u",
// "u-speed" and "u-ping" choose among the nodes of that pool only. A user belongs to one channel (users.channel) and gets
// the links of its modes. While no node was loaded for the users' pool, that channel works on the pool of the operator.
const (
	chanAdmin = "admin"
	chanUsers = "users"

	modeUser0    = "u" // the main balancer of the users' channel
	modeUserSpd  = "u-speed"
	modeUserPing = "u-ping"
)

// balModes are the extra modes (the main one of the admin channel is the empty string).
var balModes = []string{modeSpeed, modePing, modeSpread, modeUser0, modeUserSpd, modeUserPing}

// allModes lists every mode: first the admin channel, then the users' channel.
var allModes = []string{"", modeSpeed, modePing, modeSpread, modeUser0, modeUserSpd, modeUserPing}

// userChanModes are the modes of the users' channel.
var userChanModes = []string{modeUser0, modeUserSpd, modeUserPing}

// modeChannel is the channel a mode belongs to.
func modeChannel(mode string) string {
	if mode == modeUser0 || strings.HasPrefix(mode, "u-") {
		return chanUsers
	}
	return chanAdmin
}

// modeBase is the kind of the mode without the channel: "u-speed" -> "speed", "u" -> "" (the main one).
func modeBase(mode string) string {
	switch mode {
	case modeUser0:
		return ""
	case modeUserSpd:
		return modeSpeed
	case modeUserPing:
		return modePing
	}
	return mode
}

// Chan is the channel of the user ("admin" unless it is set to "users").
func (u User) Chan() string {
	if u.Channel == chanUsers {
		return chanUsers
	}
	return chanAdmin
}

// chanModes are the modes of one channel that people see, main first: "spread" only when it is switched on.
func chanModes(cfg *Config, ch string) []string {
	if ch == chanUsers {
		return userChanModes
	}
	if cfg.spreadOn() {
		return []string{"", modeSpeed, modePing, modeSpread}
	}
	return []string{"", modeSpeed, modePing}
}

// linkModes are the modes of the admin channel (what the operator sees).
func linkModes(cfg *Config) []string { return chanModes(cfg, chanAdmin) }

// userModesOf are the modes whose links a user gets (his channel's).
func userModesOf(cfg *Config, u User) []string { return chanModes(cfg, u.Chan()) }

// panelModes are the modes the panel shows: the admin channel and, when a pool of the users' channel exists, its modes.
func panelModes(cfg *Config) []string {
	m := append([]string(nil), linkModes(cfg)...)
	if cfg.usersChannelOn() {
		m = append(m, userChanModes...)
	}
	return m
}

func modeTitle(mode string) string {
	prefix := ""
	if modeChannel(mode) == chanUsers {
		prefix = "пользователи: "
	}
	return prefix + baseTitle(modeBase(mode))
}

func baseTitle(mode string) string {
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
	if modeBase(mode) == "" {
		return n
	}
	return n + " · " + baseTitle(modeBase(mode))
}

// modeLink is the vless:// link of a user for a mode.
func modeLink(cfg *Config, u User, mode string) string {
	return userLink(cfg, modeLinkName(cfg, mode), modeUUID(u.UUID, mode))
}

// modeLinks are the links of all modes of a user (those of his channel), main first.
func modeLinks(cfg *Config, u User) []string {
	out := make([]string, 0, len(allModes))
	for _, m := range userModesOf(cfg, u) {
		out = append(out, modeLink(cfg, u, m))
	}
	return out
}

// modeUsers lists the sing-box user names of the mode for the given users.
func modeUsers(users []User, mode string) []string {
	out := make([]string, 0, len(users))
	for _, u := range users {
		if u.NoBalancer || u.Chan() != modeChannel(mode) {
			continue
		}
		out = append(out, modeUser(u.Name, mode))
	}
	return out
}

// channelNodes are the nodes of the pool of a channel (see Checker.inPool): the users' channel sees only the nodes of
// users_subscriptions, and all of them while there are none.
func channelNodes(nodes []*Node, ch string) []*Node {
	own := false
	for _, n := range nodes {
		if n.InUsers {
			own = true
			break
		}
	}
	var out []*Node
	for _, n := range nodes {
		if (ch == chanUsers && (n.InUsers || !own)) || (ch != chanUsers && (n.InAdmin || !n.InUsers)) {
			out = append(out, n)
		}
	}
	return out
}

func nodePool(n *Node) string {
	switch {
	case n.InUsers && n.InAdmin:
		return "both"
	case n.InUsers:
		return "users"
	}
	return "admin"
}

// anyBalancerUser says whether somebody uses the balancer at all.
func anyBalancerUser(users []User) bool {
	for _, u := range users {
		if !u.NoBalancer {
			return true
		}
	}
	return false
}

func (c *Config) usersChannelOn() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.UsersSubscriptions) > 0
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
