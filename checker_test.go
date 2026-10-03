package main

import (
	"math"
	"strings"
	"sync"
	"testing"
	"time"
)

func testCfg() *Config {
	return &Config{SwitchMargin: 1.15, SwitchConfirm: 3, Tier3Top: 5, Tier2Concurrency: 4, WorkDir: "/tmp/x", MinReload: time.Minute}
}

func mkNode(id string) *Node {
	return &Node{ID: id + strings.Repeat("0", 40-len(id)), Name: id, Type: "trojan", Server: id + ".example.com", Port: 443}
}

func mkChecker(ids ...string) *Checker {
	c := NewChecker(testCfg(), nil, NewCore(testCfg()), &Notifier{})
	var ns []*Node
	for _, id := range ids {
		ns = append(ns, mkNode(id))
	}
	c.SyncNodes(ns)
	return c
}

func (c *Checker) st(id string) *NodeState { return c.states[mkNode(id).ID] }

// feed pushes n results with the given latency; ok=false pushes failures.
func feed(st *NodeState, n int, ok bool, ms float64) {
	for i := 0; i < n; i++ {
		st.push(result{ok, ms})
	}
	st.recompute()
}

func TestScoreFormula(t *testing.T) {
	st := &NodeState{}
	feed(st, 10, true, 200) // sr=1, ewma=200, jitter=0
	want := 100 - 200.0/10
	if math.Abs(st.score-want) > 0.01 {
		t.Fatalf("score=%v want %v", st.score, want)
	}
	st.addSpeed(40000, time.Now()) // 40 Mbit/s -> +10 bonus (cap)
	st.recompute()
	if math.Abs(st.score-(want+10)) > 0.01 {
		t.Fatalf("with speed score=%v want %v", st.score, want+10)
	}
	st.addSpeed(400000, time.Now()) // cap must hold
	st.recompute()
	if math.Abs(st.score-(want+10)) > 0.01 {
		t.Fatalf("speed bonus not capped: %v", st.score)
	}
}

func TestScoreCapsAndJitter(t *testing.T) {
	st := &NodeState{}
	feed(st, 10, true, 5000) // latency penalty capped at 40
	if math.Abs(st.score-60) > 0.01 {
		t.Fatalf("latency penalty must cap at 40: %v", st.score)
	}
	st2 := &NodeState{}
	for i := 0; i < 10; i++ {
		st2.push(result{true, float64(100 + (i%2)*1000)})
	}
	st2.recompute()
	wantScore := 100 - math.Min(st2.ewma/10, 40) - 10 // jitter penalty capped at 10
	if st2.jitter < 400 || math.Abs(st2.score-wantScore) > 0.01 {
		t.Fatalf("jitter penalty: jitter=%v score=%v want %v", st2.jitter, st2.score, wantScore)
	}
}

func TestScoreZeroWhenUnhealthy(t *testing.T) {
	st := &NodeState{}
	feed(st, 5, true, 100)
	feed(st, 5, false, 0) // sr = 0.5 < 0.6
	if st.score != 0 {
		t.Fatalf("sr<0.6 must give score 0, got %v", st.score)
	}
	ok := &NodeState{}
	feed(ok, 10, true, 100)
	ok.proxyFail = 2
	ok.recompute()
	if ok.score != 0 {
		t.Fatal("2 consecutive failures must give score 0 even with a good window")
	}
	ok.proxyFail = 1
	ok.recompute()
	if ok.score == 0 {
		t.Fatal("a single failure must not zero the score")
	}
	empty := &NodeState{}
	empty.recompute()
	if empty.score != 0 {
		t.Fatal("unchecked node must have score 0")
	}
}

func TestQuarantineBackoff(t *testing.T) {
	want := []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute, 30 * time.Minute, 30 * time.Minute}
	for i, w := range want {
		st := &NodeState{proxyFail: 3 + i}
		before := time.Now()
		st.maybeQuarantine()
		got := st.quarantine.Sub(before)
		if got < w-time.Second || got > w+time.Second {
			t.Errorf("fails=%d: quarantine %v want %v", 3+i, got, w)
		}
	}
	st := &NodeState{proxyFail: 2}
	st.maybeQuarantine()
	if !st.quarantine.IsZero() {
		t.Error("no quarantine before 3 failures")
	}
}

func TestWindowIsBounded(t *testing.T) {
	st := &NodeState{}
	feed(st, winSize*3, true, 100)
	if len(st.win) != winSize {
		t.Fatalf("window len %d", len(st.win))
	}
	// old failures must age out
	st2 := &NodeState{}
	feed(st2, 10, false, 0)
	feed(st2, winSize, true, 100)
	if st2.sr != 1 {
		t.Fatalf("old failures must age out, sr=%v", st2.sr)
	}
}

func TestDecideInitialAndFailover(t *testing.T) {
	c := mkChecker("a", "b")
	feed(c.st("a"), 10, true, 100)
	feed(c.st("b"), 10, true, 300)
	tgt, reason, none := c.decideLocked(true)
	if tgt == nil || tgt.Name != "a" || reason != "failover" || none {
		t.Fatalf("initial: %v %q %v", tgt, reason, none)
	}
	c.current = tgt.ID
	// current dies -> immediate failover to the healthy one, no hysteresis
	c.st("a").proxyFail = 2
	c.st("a").recompute()
	tgt, reason, _ = c.decideLocked(false)
	if tgt == nil || tgt.Name != "b" || reason != "failover" {
		t.Fatalf("failover: %v %q", tgt, reason)
	}
}

func TestDecideHysteresis(t *testing.T) {
	c := mkChecker("cur", "new")
	feed(c.st("cur"), 10, true, 300) // score 70
	feed(c.st("new"), 10, true, 100) // score 90 -> 1.28x
	c.current = c.st("cur").Node.ID

	// non-cycle evaluations (watchdog, 15s loop) must never advance the counter
	for i := 0; i < 10; i++ {
		if tgt, _, _ := c.decideLocked(false); tgt != nil {
			t.Fatal("switched without tier-2 cycles")
		}
	}
	for i := 1; i <= 2; i++ {
		if tgt, _, _ := c.decideLocked(true); tgt != nil {
			t.Fatalf("switched after only %d cycles", i)
		}
	}
	tgt, reason, _ := c.decideLocked(true)
	if tgt == nil || tgt.Name != "new" || reason != "better" {
		t.Fatalf("3rd cycle must switch: %v %q", tgt, reason)
	}
	if c.candCnt != 0 {
		t.Fatal("counter must reset after a switch")
	}
}

func TestDecideHysteresisResets(t *testing.T) {
	c := mkChecker("cur", "new")
	feed(c.st("cur"), 10, true, 300)
	feed(c.st("new"), 10, true, 100)
	c.current = c.st("cur").Node.ID
	c.decideLocked(true)
	c.decideLocked(true)
	// the advantage disappears for one cycle -> start over
	feed(c.st("new"), winSize, true, 290) // score ~71 < 70*1.15
	if tgt, _, _ := c.decideLocked(true); tgt != nil || c.candCnt != 0 {
		t.Fatalf("counter must reset when margin is lost (cnt=%d)", c.candCnt)
	}
}

func TestDecideMarginIsRespected(t *testing.T) {
	c := mkChecker("cur", "new")
	feed(c.st("cur"), 10, true, 300) // 70
	feed(c.st("new"), 10, true, 200) // 80 -> 1.14x < 1.15
	c.current = c.st("cur").Node.ID
	for i := 0; i < 10; i++ {
		if tgt, _, _ := c.decideLocked(true); tgt != nil {
			t.Fatal("must not switch for a gain below the margin")
		}
	}
}

func TestDecideStaysOnBest(t *testing.T) {
	c := mkChecker("a", "b")
	feed(c.st("a"), 10, true, 100)
	feed(c.st("b"), 10, true, 300)
	c.current = c.st("a").Node.ID
	if tgt, _, none := c.decideLocked(true); tgt != nil || none {
		t.Fatal("must stay on the best node")
	}
}

func TestDecideAllDown(t *testing.T) {
	c := mkChecker("a", "b")
	feed(c.st("a"), 10, false, 0)
	feed(c.st("b"), 10, false, 0)
	tgt, _, none := c.decideLocked(true)
	if tgt != nil || !none {
		t.Fatalf("all checked & dead: tgt=%v none=%v", tgt, none)
	}
	// never checked nodes are "unknown", not "down" (no false alarm right after a node set change)
	c2 := mkChecker("a", "b")
	if _, _, none := c2.decideLocked(true); none {
		t.Fatal("unchecked nodes must not trigger the all-down alarm")
	}
	if _, _, none := mkChecker().decideLocked(true); none {
		t.Fatal("empty pool is reported elsewhere")
	}
}

func TestDecideTieIsDeterministic(t *testing.T) {
	for i := 0; i < 50; i++ {
		c := mkChecker("a", "b", "c")
		for _, id := range []string{"a", "b", "c"} {
			feed(c.st(id), 10, true, 100)
		}
		tgt, _, _ := c.decideLocked(true)
		if tgt == nil || tgt.Name != "a" {
			t.Fatalf("tie must resolve by ID, got %v", tgt)
		}
	}
}

func TestSyncNodesKeepsStateAndDropsRemoved(t *testing.T) {
	c := mkChecker("a", "b")
	feed(c.st("a"), 10, true, 100)
	c.SyncNodes([]*Node{mkNode("a"), mkNode("c")})
	if c.st("a") == nil || len(c.st("a").win) != 10 {
		t.Fatal("existing node must keep its history")
	}
	if c.st("b") != nil || c.st("c") == nil || !c.st("c").tcpOK {
		t.Fatal("removed node dropped / new node added")
	}
}

func TestPickerTierFilters(t *testing.T) {
	c := mkChecker("a", "b", "c")
	c.st("b").quarantine = time.Now().Add(time.Hour)
	c.st("c").Node.UDP = true
	now := time.Now()
	got := c.pick(func(st *NodeState) bool { return !st.Node.UDP && now.After(st.quarantine) })
	if len(got) != 1 || got[0].Name != "a" {
		t.Fatalf("tier1 filter: %v", got)
	}
}

func TestBaselineOKUsesReachableAddr(t *testing.T) {
	cfg := testCfg()
	c := NewChecker(cfg, nil, NewCore(cfg), &Notifier{})
	cfg.BaselineAddrs = []string{"127.0.0.1:1"} // closed port: baseline is down
	if c.baselineOK() {
		t.Fatal("baseline must be down")
	}
	if !c.Snapshot().NetDown {
		t.Fatal("snapshot must report net_down")
	}
}

func TestForEachLimits(t *testing.T) {
	for _, limit := range []int{0, -1, 1, 3, 100} { // 0 and negative must not deadlock
		sum, mu := 0, sync.Mutex{}
		forEach([]int{1, 2, 3, 4, 5}, limit, func(i int) { mu.Lock(); sum += i; mu.Unlock() })
		if sum != 15 {
			t.Fatalf("limit %d: sum=%d", limit, sum)
		}
	}
}
