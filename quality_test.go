package main

import (
	"testing"
	"time"
)

func healthy(c *Checker, id string, ms float64) *NodeState {
	st := c.st(id)
	feed(st, 10, true, ms)
	return st
}

func TestSpeedHistoryKeepsLastThreeWithTime(t *testing.T) {
	st := &NodeState{}
	base := time.Now().Add(-time.Hour)
	for i := 1; i <= 5; i++ {
		st.addSpeed(i*1000, base.Add(time.Duration(i)*time.Minute))
	}
	if len(st.speedHist) != 3 || st.speedHist[0].K != 3000 || st.speedHist[2].K != 5000 {
		t.Fatalf("hist=%v", st.speedHist)
	}
	if k, at := st.lastSpeed(); k != 5000 || at.Unix() != base.Add(5*time.Minute).Unix() {
		t.Fatalf("last=%d %v", k, at)
	}
}

func TestOldSpeedGivesNoBonus(t *testing.T) {
	st := &NodeState{}
	feed(st, 10, true, 200)
	base := st.score
	st.addSpeed(40000, time.Now().Add(-30*time.Hour))
	st.recompute()
	if st.score != base {
		t.Fatalf("a 30 hour old measurement must not change the score: %v vs %v", st.score, base)
	}
}

func TestSlowNeedsTwoLowMeasurements(t *testing.T) {
	st := &NodeState{}
	now := time.Now()
	st.addSpeed(2000, now)
	if st.speedSlow(8000, now, 12*time.Hour) {
		t.Fatal("one low value is a fluke, not a verdict")
	}
	if !st.speedSuspect(8000) {
		t.Fatal("one low value must make the node a suspect (second measurement soon)")
	}
	st.addSpeed(3000, now)
	if !st.speedSlow(8000, now, 12*time.Hour) {
		t.Fatal("two low values: slow")
	}
	st.addSpeed(20000, now)
	if st.speedSlow(8000, now, 12*time.Hour) {
		t.Fatal("recovered node is not slow")
	}
	// stale verdicts expire: the node gets a new chance
	st2 := &NodeState{}
	st2.addSpeed(1000, now.Add(-40*time.Hour))
	st2.addSpeed(1000, now.Add(-39*time.Hour))
	if st2.speedSlow(8000, now, 12*time.Hour) {
		t.Fatal("a verdict older than 3 x ttl must lapse")
	}
	if st.speedSlow(0, now, time.Hour) {
		t.Fatal("min speed 0 disables the rule")
	}
}

func TestDecideSkipsSlowNodeAndFallsBack(t *testing.T) {
	c := mkChecker("fast", "slow")
	f, s := healthy(c, "fast", 400), healthy(c, "slow", 50) // the slow one has the better latency
	now := time.Now()
	s.addSpeed(1000, now)
	s.addSpeed(1500, now)
	f.addSpeed(30000, now)
	f.recompute()
	s.recompute()
	c.mu.Lock()
	n, reason, _ := c.decideLocked(true)
	c.mu.Unlock()
	if n == nil || n.Name != "fast" || reason != "failover" {
		t.Fatalf("slow node must not be chosen, got %v %q", n, reason)
	}
	// users are on the slow node: they move off it right away
	c.SetCurrent(s.Node.ID)
	c.mu.Lock()
	n, reason, _ = c.decideLocked(false)
	c.mu.Unlock()
	if n == nil || n.Name != "fast" || reason != "slow" {
		t.Fatalf("expected move to fast because of speed, got %v %q", n, reason)
	}
	// when everything is slow nobody is left without a node
	f.addSpeed(500, now)
	f.addSpeed(500, now)
	c.SetCurrent("")
	c.mu.Lock()
	n, _, _ = c.decideLocked(true)
	c.mu.Unlock()
	if n == nil {
		t.Fatal("all nodes slow: the best of them must still be used")
	}
}

func TestDecideRequiredServiceExcludesNode(t *testing.T) {
	c := mkChecker("a", "b")
	c.cfg.RequiredServices = []string{"telegram"}
	a, b := healthy(c, "a", 50), healthy(c, "b", 300)
	a.svc = map[string]SvcRes{"telegram": {OK: false, Fails: 1}}
	c.mu.Lock()
	n, _, _ := c.decideLocked(true)
	c.mu.Unlock()
	if n == nil || n.Name != "a" {
		t.Fatalf("one failed pass is not enough, got %v", n)
	}
	a.svc["telegram"] = SvcRes{OK: false, Fails: 2}
	a.recompute()
	c.mu.Lock()
	n, _, _ = c.decideLocked(true)
	c.mu.Unlock()
	if n == nil || n.Name != "b" {
		t.Fatalf("two failed passes must exclude a, got %v", n)
	}
	c.SetCurrent(a.Node.ID)
	c.mu.Lock()
	n, reason, _ := c.decideLocked(false)
	c.mu.Unlock()
	if n == nil || n.Name != "b" || reason != "service" {
		t.Fatalf("users on a must move to b: %v %q", n, reason)
	}
	b.svc = map[string]SvcRes{"telegram": {OK: false, Fails: 5}}
	c.SetCurrent("")
	c.mu.Lock()
	n, _, _ = c.decideLocked(true)
	c.mu.Unlock()
	if n == nil {
		t.Fatal("telegram fails everywhere: still must pick a node")
	}
}

func TestServiceFailureLowersScore(t *testing.T) {
	st := &NodeState{}
	feed(st, 10, true, 200)
	base := st.score
	st.svc = map[string]SvcRes{"x": {OK: false, Fails: 1}, "yt": {OK: true}}
	st.recompute()
	if base-st.score < 2.9 || base-st.score > 3.1 {
		t.Fatalf("one failed service costs 3 points: %v -> %v", base, st.score)
	}
}

func TestSyncNodesRestoresPersistedStats(t *testing.T) {
	c := NewChecker(testCfg(), nil, NewCore(testCfg()), &Notifier{})
	n := mkNode("p")
	at := time.Now().Add(-time.Hour)
	n.SpeedHist = []SpeedPoint{{K: 12000, T: at.Unix()}}
	n.Svc = map[string]SvcRes{"telegram": {OK: true, T: at.Unix()}}
	n.CheckAt = at
	c.SyncNodes([]*Node{n})
	st := c.states[n.ID]
	if st.speedKbps != 12000 || len(st.speedHist) != 1 || !st.svc["telegram"].OK || st.checkAt.IsZero() {
		t.Fatalf("persisted data not restored: %+v", st)
	}
}

func TestParseServices(t *testing.T) {
	d, err := parseServices(defaultServices)
	if err != nil || len(d) != len(defaultServices) {
		t.Fatalf("defaults must parse: %v", err)
	}
	for _, bad := range [][]string{{"nonsense"}, {"A B = https://x"}, {"x = ftp://a"}, {"x = tcp://host"}, {"x = tcp://h:99999"}, {"x ="}, {"x = https://a", "x = https://b"}} {
		if _, err := parseServices(bad); err == nil {
			t.Fatalf("%v must be rejected", bad)
		}
	}
	d, err = parseServices([]string{"My-Svc = https://a.example , tcp://b.example:443", ""})
	if err != nil || len(d) != 1 || d[0].Name != "my-svc" || len(d[0].Targets) != 2 {
		t.Fatalf("%v %v", d, err)
	}
}

func TestSettingsMinSpeedAndServices(t *testing.T) {
	c := testCfg()
	if c.getMinSpeed() != 8000 {
		t.Fatalf("default min speed is 8 Mbit/s, got %d", c.getMinSpeed())
	}
	for _, key := range []string{"min_speed_kbps", "required_services", "services"} {
		found := false
		for _, d := range settingDefs {
			found = found || d.key == key
		}
		if !found {
			t.Fatalf("setting %s is not registered", key)
		}
	}
}
