package main

import (
	"context"
	"log"
	"sort"
	"time"
)

// modeSpeedOf is the speed that counts for a node in "speed" mode: only a measurement that is not too old.
func (c *Checker) modeSpeedOf(st *NodeState, now time.Time) int {
	k, at := st.lastSpeed()
	if k <= 0 || at.IsZero() || now.Sub(at) > 2*c.cfg.getSpeedTTL() {
		return 0
	}
	return k
}

// modePool is the group of the best nodes by the common parameters (score, quality rules, required services).
// Only nodes of this group compete for the extra modes, so "fastest" never means "fast but flaky".
func (c *Checker) modePool(now time.Time) []*NodeState {
	minSpeed, required := c.cfg.getMinSpeed(), c.cfg.getRequired()
	var good, any []*NodeState
	for _, st := range c.states {
		if st.score <= 0 || !st.Node.Allowed(c.cfg) {
			continue
		}
		any = append(any, st)
		if c.qualityIssue(st, now, minSpeed, required) == "" {
			good = append(good, st)
		}
	}
	if len(good) == 0 {
		good = any // never leave a mode without a node because of quality rules
	}
	sort.Slice(good, func(i, j int) bool { return better(good[i], good[j]) })
	n := len(good) / 4
	if n < 5 {
		n = 5
	}
	if n > 15 {
		n = 15
	}
	if n > len(good) {
		n = len(good)
	}
	return good[:n]
}

// modeBest picks the node of a mode from the pool.
func (c *Checker) modeBest(mode string, pool []*NodeState, now time.Time) *NodeState {
	var best *NodeState
	for _, st := range pool {
		switch {
		case best == nil:
			best = st
		case mode == modeSpeed:
			a, b := c.modeSpeedOf(st, now), c.modeSpeedOf(best, now)
			if a > b || (a == b && better(st, best)) {
				best = st
			}
		case mode == modePing:
			a, b := st.ewma, best.ewma
			if a > 0 && (b <= 0 || a < b || (a == b && better(st, best))) {
				best = st
			}
		}
	}
	return best
}

// decideModeLocked is the choice for one extra mode (c.mu is held). A dead or unsuitable node is replaced at once;
// a better one has to be clearly better for several check cycles in a row, like for the main balancer.
func (c *Checker) decideModeLocked(mode string, cycle bool) (target *Node, reason string) {
	now := time.Now()
	pool := c.modePool(now)
	if len(pool) == 0 {
		return nil, ""
	}
	best := c.modeBest(mode, pool, now)
	cur := c.states[c.modeCur[mode]]
	if cur == nil || cur.score <= 0 || !cur.Node.Allowed(c.cfg) {
		c.modeCand[mode], c.modeCnt[mode] = "", 0
		return best.Node, "failover"
	}
	if q := c.qualityIssue(cur, now, c.cfg.getMinSpeed(), c.cfg.getRequired()); q != "" && best.Node.ID != cur.Node.ID &&
		c.qualityIssue(best, now, c.cfg.getMinSpeed(), c.cfg.getRequired()) == "" {
		c.modeCand[mode], c.modeCnt[mode] = "", 0
		return best.Node, "quality"
	}
	if best.Node.ID == cur.Node.ID {
		c.modeCand[mode], c.modeCnt[mode] = "", 0
		return nil, ""
	}
	clear := false
	switch mode {
	case modeSpeed:
		a, b := c.modeSpeedOf(best, now), c.modeSpeedOf(cur, now)
		clear = a > 0 && float64(a) >= 1.3*float64(b) && a-b >= 2000
	case modePing:
		clear = best.ewma > 0 && (cur.ewma <= 0 || (best.ewma <= 0.75*cur.ewma && cur.ewma-best.ewma >= 15))
	}
	if !clear {
		c.modeCand[mode], c.modeCnt[mode] = "", 0
		return nil, ""
	}
	_, confirm := c.cfg.getSwitch()
	if cycle {
		if c.modeCand[mode] == best.Node.ID {
			c.modeCnt[mode]++
		} else {
			c.modeCand[mode], c.modeCnt[mode] = best.Node.ID, 1
		}
	}
	if c.modeCnt[mode] >= confirm {
		c.modeCand[mode], c.modeCnt[mode] = "", 0
		return best.Node, "better"
	}
	return nil, ""
}

// adoptModes learns which node each extra selector is on (after a restart of the controller the gateway keeps its state).
func (c *Checker) adoptModes() {
	for _, m := range balModes {
		c.mu.RLock()
		have := c.modeCur[m] != ""
		c.mu.RUnlock()
		if have {
			continue
		}
		tag, err := c.core.SelectedMode(m)
		if err != nil || tag == "" {
			continue
		}
		c.mu.Lock()
		for id, st := range c.states {
			if st.Node.Tag() == tag && c.modeCur[m] == "" {
				c.modeCur[m] = id
			}
		}
		c.mu.Unlock()
	}
}

func (c *Checker) switchMode(mode string, n *Node, reason string) {
	if err := c.core.SelectMode(mode, n.Tag()); err != nil {
		log.Printf("switch[%s]: select failed: %v", mode, err)
		return
	}
	c.mu.Lock()
	prev := c.modeCur[mode]
	prevName := ""
	if st := c.states[prev]; st != nil {
		prevName = st.Node.Name
	}
	c.modeCur[mode] = n.ID
	c.mu.Unlock()
	c.cfg.setModeDefault(mode, n.Tag())
	log.Printf("switch[%s]: %s -> %s (%s)", mode, prevName, n.Name, reason)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c.store.LogSwitch(ctx, prev, n.ID, mode+":"+reason)
}
