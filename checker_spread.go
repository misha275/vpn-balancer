package main

import (
	"math"
	"time"
)

// Mode "by traffic". sing-box has no weighted balancer, so the spread is made by moving the selector of the mode:
// every spread_interval it goes to the node of the best group that has carried the least traffic lately. The traffic is
// counted by the gateway per mode and attributed here to the node that was selected while it flowed; the counters
// fade with a half-life, so an old burst does not hold a node back for ever.
//
// It is an approximation: connections that were opened before a move stay on their node until they end, and the new
// ones go to the next node, so a busy period is spread over the pool in turns.

const (
	spreadHalfLife = time.Hour
	spreadMinGap   = 1 << 20 // bytes: a smaller difference between nodes is not worth a move
	spreadRatio    = 0.8     // the new node must carry clearly less than the current one
)

// decaySpreadLocked fades the counters up to now (c.mu is held).
func (c *Checker) decaySpreadLocked(now time.Time) {
	if c.spreadLoad == nil {
		c.spreadLoad = map[string]float64{}
	}
	if !c.spreadAt.IsZero() {
		if dt := now.Sub(c.spreadAt); dt > 0 {
			f := math.Pow(0.5, float64(dt)/float64(spreadHalfLife))
			for id, v := range c.spreadLoad {
				if v *= f; v < 1 {
					delete(c.spreadLoad, id)
				} else {
					c.spreadLoad[id] = v
				}
			}
		}
	}
	c.spreadAt = now
}

// AddSpreadBytes is called with the traffic of the mode that the gateway reported (since its previous report).
func (c *Checker) AddSpreadBytes(n int64) {
	if n <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	id := c.modeCur[modeSpread]
	if id == "" {
		return
	}
	c.decaySpreadLocked(time.Now())
	c.spreadLoad[id] += float64(n)
}

// SpreadLoad returns the counters by node name (for the panel and tests).
func (c *Checker) SpreadLoad() map[string]int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := map[string]int64{}
	for id, v := range c.spreadLoad {
		if st := c.states[id]; st != nil {
			out[st.Node.Name] = int64(v)
		}
	}
	return out
}

func (c *Checker) decideSpreadLocked(best, cur *NodeState, now time.Time) (*Node, string) {
	c.modeCand[modeSpread], c.modeCnt[modeSpread] = "", 0
	if best.Node.ID == cur.Node.ID || now.Sub(c.spreadRot) < c.cfg.getSpreadInterval() {
		return nil, ""
	}
	cl, bl := c.spreadLoad[cur.Node.ID], c.spreadLoad[best.Node.ID]
	if bl <= spreadRatio*cl && cl-bl >= spreadMinGap {
		return best.Node, "spread"
	}
	return nil, ""
}
