package main

import (
	"strings"
	"testing"
)

func TestStableModeNeverMovesWhileNodeWorks(t *testing.T) {
	c := modePoolChecker(t)
	a, b := c.st("a").Node.ID, c.st("b").Node.ID
	// the first choice: a node of the group at once
	n, r := c.decideModeLocked(modeStable, true)
	if n == nil || r != "failover" {
		t.Fatalf("first choice: %v %s", n, r)
	}
	// whatever happens to the others, a working node stays: even when another one is much better
	c.modeCur[modeStable] = b
	c.st("b").score = 1
	c.st("a").score = 1000
	for i := 0; i < 20; i++ {
		if n, r := c.decideModeLocked(modeStable, true); n != nil {
			t.Fatalf("cycle %d: moved to %s (%s)", i, n.Name, r)
		}
	}
	// a dead node is replaced at once
	c.st("b").score = 0
	if n, r := c.decideModeLocked(modeStable, true); n == nil || r != "failover" || n.ID == b {
		t.Fatalf("failover: %v %s", n, r)
	}
	_ = a
}

func TestStableLinksHiddenUntilEnabled(t *testing.T) {
	cfg := modesSubCfg()
	u := User{Name: "alice", UUID: testUUID}
	if got := len(modeLinks(cfg, u)); got != 3 {
		t.Fatalf("by default 3 balancers, got %d", got)
	}
	on := true
	cfg.StableMode = &on
	links := modeLinks(cfg, u)
	if len(links) != 4 || !strings.Contains(modeLinkName(cfg, modeStable), "стабильный IP") {
		t.Fatalf("with stable_mode 4 balancers: %v", links)
	}
	if modeUUID(u.UUID, modeStable) == modeUUID(u.UUID, modeSpread) {
		t.Fatal("the key of every mode is its own")
	}
	if b, m := foldUser(modeUser("alice", modeStable)); b != "alice" || m != modeStable {
		t.Fatalf("fold: %s %s", b, m)
	}
}
