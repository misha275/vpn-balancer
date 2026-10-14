package main

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestSpreadTrackerCountsModeBytes(t *testing.T) {
	tr := newTracker()
	sink := &lineSink{slot: 1, t: tr, idPort: map[string]int{}, pass: func(string) {}}
	s1 := tr.open(1, 40001, &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 1})
	s2 := tr.open(1, 40002, &net.TCPAddr{IP: net.ParseIP("1.2.3.5"), Port: 2})
	sink.line("+0000 2026-10-03 13:01:18 INFO [1 0ms] inbound/vless[vless-in]: inbound connection from 127.0.0.1:40001")
	sink.line("+0000 2026-10-03 13:01:18 INFO [1 2ms] inbound/vless[vless-in]: [alice~spread] inbound connection to example.org:443")
	sink.line("+0000 2026-10-03 13:01:18 INFO [2 0ms] inbound/vless[vless-in]: inbound connection from 127.0.0.1:40002")
	sink.line("+0000 2026-10-03 13:01:18 INFO [2 2ms] inbound/vless[vless-in]: [bob] inbound connection to example.org:443")
	s1.up.Add(100)
	s1.down.Add(900)
	s2.down.Add(5000)
	d := tr.drain()
	if d.ModeBytes[modeSpread] != 1000 {
		t.Fatalf("mode bytes: %v", d.ModeBytes)
	}
	if d.Deltas["alice"].Down != 900 || d.Deltas["bob"].Down != 5000 {
		t.Fatalf("users are still counted by their real names: %+v", d.Deltas)
	}
	s1.down.Add(24)
	if d = tr.drain(); d.ModeBytes[modeSpread] != 24 {
		t.Fatalf("only new bytes: %v", d.ModeBytes)
	}
	if d = tr.drain(); len(d.ModeBytes) != 0 {
		t.Fatalf("nothing new: %v", d.ModeBytes)
	}
}

func TestSpreadDecision(t *testing.T) {
	c := modePoolChecker(t)
	c.cfg.SpreadInterval = 30 * time.Second
	a, b := c.st("a").Node.ID, c.st("b").Node.ID
	// nothing chosen yet: a node of the group at once
	if n, r := c.decideModeLocked(modeSpread, true); n == nil || r != "failover" {
		t.Fatalf("first choice: %v %s", n, r)
	}
	c.modeCur[modeSpread] = a
	c.spreadRot = time.Now().Add(-time.Hour)
	if n, _ := c.decideModeLocked(modeSpread, true); n != nil {
		t.Fatalf("no traffic, no move: %v", n.Name)
	}
	c.AddSpreadBytes(100 << 20)
	if got := c.SpreadLoad()["a"]; got != 100<<20 {
		t.Fatalf("load of a: %d", got)
	}
	// a has carried much, the others nothing: move to the best of the idle ones
	n, r := c.decideModeLocked(modeSpread, true)
	if n == nil || r != "spread" || n.ID == a {
		t.Fatalf("must move away from the busy node: %v %s", n, r)
	}
	// but not before spread_interval after the previous move
	c.spreadRot = time.Now()
	if n, _ := c.decideModeLocked(modeSpread, true); n != nil {
		t.Fatalf("too early: %v", n.Name)
	}
	// the next bytes go to the node that is selected now
	c.modeCur[modeSpread] = b
	c.AddSpreadBytes(60 << 20)
	ld := c.SpreadLoad()
	if d := ld["b"] - 60<<20; d < -2000 || d > 0 || ld["a"] < 100<<20-2000 {
		t.Fatalf("attribution: %v", ld)
	}
	// a small difference is not worth a move
	c.spreadRot = time.Now().Add(-time.Hour)
	c.spreadLoad = map[string]float64{a: 3 << 20, b: 2<<20 + 900<<10, c.st("c").Node.ID: 2 << 20, c.st("d").Node.ID: 2 << 20}
	c.modeCur[modeSpread] = b
	if n, _ := c.decideModeLocked(modeSpread, true); n != nil {
		t.Fatalf("below the gap: %v", n.Name)
	}
	// the loads fade with time
	c.spreadLoad = map[string]float64{a: 1 << 30}
	c.spreadAt = time.Now().Add(-time.Hour)
	c.mu.Lock()
	c.decaySpreadLocked(time.Now())
	c.mu.Unlock()
	if v := c.spreadLoad[a]; v < 0.45*(1<<30) || v > 0.55*(1<<30) {
		t.Fatalf("one half-life must halve the load: %v", v)
	}
	// a dead node is left at once, whatever the interval
	c.spreadRot = time.Now()
	c.modeCur[modeSpread] = b
	c.st("b").score = 0
	if n, r := c.decideModeLocked(modeSpread, true); n == nil || r != "failover" || n.ID == b {
		t.Fatalf("failover: %v %s", n, r)
	}
}

func TestSpreadLinksHiddenUntilEnabled(t *testing.T) {
	cfg := modesSubCfg()
	u := User{Name: "alice", UUID: testUUID}
	if got := len(modeLinks(cfg, u)); got != 3 {
		t.Fatalf("by default 3 balancers, got %d", got)
	}
	on := true
	cfg.SpreadMode = &on
	links := modeLinks(cfg, u)
	if len(links) != 4 || !strings.Contains(links[3], "%D0%BF%D0%BE%20%D1%82%D1%80%D0%B0%D1%84%D0%B8%D0%BA%D1%83") {
		t.Fatalf("with spread_mode 4 balancers: %v", links)
	}
	// the key of the mode is its own and works in the gateway whatever the setting
	if modeUUID(u.UUID, modeSpread) == u.UUID || modeUUID(u.UUID, modeSpread) == modeUUID(u.UUID, modePing) {
		t.Fatal("keys must differ")
	}
	if b, m := foldUser("alice~spread"); b != "alice" || m != modeSpread {
		t.Fatalf("fold: %s %s", b, m)
	}
}
