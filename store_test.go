package main

import (
	"context"
	"os"
	"testing"
	"time"
)

// Integration test: needs a PostgreSQL, e.g.
//
//	TEST_DATABASE_URL=postgres://balancer@localhost:5432/balancer go test -run Store
//
// It works in its own schema-less way on the given database, so use a scratch one.
func testStore(t *testing.T) *Store {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := NewStore(ctx, url) // also runs schema.sql (many statements in one Exec)
	if err != nil {
		t.Fatal(err)
	}
	for _, tbl := range []string{"users", "nodes", "checks", "switches", "traffic_hourly", "user_seen", "metrics"} {
		if _, err := st.pool.Exec(ctx, "TRUNCATE "+tbl); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(st.pool.Close)
	return st
}

func TestStoreSchemaIsIdempotent(t *testing.T) {
	st := testStore(t)
	if _, err := st.pool.Exec(context.Background(), schemaSQL); err != nil {
		t.Fatalf("second run of schema.sql: %v", err)
	}
}

func TestStoreNodesRoundTripJSONB(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	in := ParseLinks("vless://" + testUUID + "@1.2.3.4:443?security=reality&sni=x.com&pbk=" + testPBK + "&sid=ab&flow=xtls-rprx-vision&type=ws&path=/w&alpn=h2,http/1.1#a\n" +
		"trojan://pw@2.2.2.2:443#b\nhy2://pw@3.3.3.3:8443?insecure=1#c")
	if len(in) != 3 {
		t.Fatalf("parsed %d", len(in))
	}
	if err := st.UpsertNodes(ctx, in, "src1"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertNodes(ctx, in, "src1"); err != nil { // upsert twice -> no duplicates
		t.Fatal(err)
	}
	out, err := st.ActiveNodes(ctx, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 {
		t.Fatalf("want 3 nodes, got %d", len(out))
	}
	byID := map[string]*Node{}
	for _, n := range out {
		byID[n.ID] = n
	}
	for _, want := range in {
		got := byID[want.ID]
		if got == nil {
			t.Fatalf("node %s lost", want.Name)
		}
		if got.Type != want.Type || got.Server != want.Server || got.Port != want.Port || got.UDP != want.UDP {
			t.Errorf("%s: fields differ: %+v vs %+v", want.Name, got, want)
		}
		// the outbound that goes into sing-box must be the same JSON as before the DB round trip
		a, b := mustJSON(want.Outbound), mustJSON(got.Outbound)
		if a != b {
			t.Errorf("%s: outbound changed by jsonb round trip:\n%s\n%s", want.Name, a, b)
		}
	}
}

func TestStoreGrace(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	ns := ParseLinks("trojan://pw@2.2.2.2:443#b")
	if err := st.UpsertNodes(ctx, ns, "s"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.pool.Exec(ctx, `UPDATE nodes SET last_seen = now() - interval '49 hours'`); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.ActiveNodes(ctx, 48*time.Hour); len(got) != 0 {
		t.Fatal("node older than grace must leave the pool")
	}
	if got, _ := st.ActiveNodes(ctx, 72*time.Hour); len(got) != 1 {
		t.Fatal("node inside grace must stay")
	}
	// reappearing in a subscription revives it
	if err := st.UpsertNodes(ctx, ns, "s"); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.ActiveNodes(ctx, 48*time.Hour); len(got) != 1 {
		t.Fatal("upsert must refresh last_seen")
	}
}

func TestStoreUsers(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	id, err := st.AddUser(ctx, "alice")
	if err != nil || len(id) != 36 {
		t.Fatalf("adduser: %q %v", id, err)
	}
	if _, err := st.AddUser(ctx, "alice"); err == nil {
		t.Fatal("duplicate name must fail")
	}
	if us, _ := st.EnabledUsers(ctx); len(us) != 1 || us[0].UUID != id {
		t.Fatalf("enabled: %+v", us)
	}
	if err := st.SetUserEnabled(ctx, "alice", false); err != nil {
		t.Fatal(err)
	}
	if us, _ := st.EnabledUsers(ctx); len(us) != 0 {
		t.Fatal("disabled user must not be in the config")
	}
	if us, _ := st.ListUsers(ctx); len(us) != 1 || us[0].Enabled {
		t.Fatalf("list: %+v", us)
	}
	if err := st.SetUserEnabled(ctx, "nobody", false); err == nil {
		t.Fatal("unknown user must be an error")
	}
}

func TestStoreChecksSwitchesCleanup(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	now := time.Now()
	rows := []CheckRow{
		{TS: now, NodeID: "n1", Tier: 1, OK: true, LatencyMS: 12, Target: "tcp"},
		{TS: now, NodeID: "n1", Tier: 2, OK: false, Target: "https://x", Err: "timeout"},
		{TS: now, NodeID: "n1", Tier: 3, OK: true, SpeedKbps: 20000, Target: "speed"},
		{TS: now.Add(-10 * 24 * time.Hour), NodeID: "old", Tier: 1, OK: true},
	}
	if err := st.InsertChecks(ctx, rows); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertChecks(ctx, nil); err != nil {
		t.Fatal("empty batch must be a no-op")
	}
	if st.LastSelected(ctx) != "" {
		t.Fatal("no switches yet")
	}
	st.LogSwitch(ctx, "", "A", "failover")
	time.Sleep(10 * time.Millisecond)
	st.LogSwitch(ctx, "A", "B", "better")
	if got := st.LastSelected(ctx); got != "B" {
		t.Fatalf("last selected %q", got)
	}
	st.Cleanup(ctx, 7*24*time.Hour)
	var n int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM checks`).Scan(&n); err != nil || n != 3 {
		t.Fatalf("cleanup: %d rows left, err=%v", n, err)
	}
}

func TestStoreExitSubTokenAndLinks(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	ns := ParseLinks("trojan://pw@a.example.com:443?sni=a.example.com#alpha\ntrojan://pw@b.example.com:443?sni=b.example.com#beta\n")
	if len(ns) != 2 {
		t.Fatal("setup")
	}
	if err := st.UpsertNodes(ctx, ns, "t"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetExit(ctx, ns[0].ID, "203.0.113.5", "DE"); err != nil {
		t.Fatal(err)
	}
	got, err := st.ActiveNodes(ctx, time.Hour)
	if err != nil || len(got) != 2 {
		t.Fatal(err, len(got))
	}
	byName := map[string]*Node{got[0].Name: got[0], got[1].Name: got[1]}
	if a := byName["alpha"]; a.ExitCountry != "DE" || a.ExitIP != "203.0.113.5" || a.ExitChecked.IsZero() || a.Link == "" || a.Link != ns[0].Link {
		t.Errorf("exit/link not stored: %+v", a)
	}
	if b := byName["beta"]; b.ExitCountry != "" || b.ExitChecked.Year() > 1971 {
		t.Errorf("unmeasured node must have no country and an ancient check time: %+v", b)
	}
	// a re-download keeps the measured exit
	if err := st.UpsertNodes(ctx, ns, "t"); err != nil {
		t.Fatal(err)
	}
	got, _ = st.ActiveNodes(ctx, time.Hour)
	for _, n := range got {
		if n.Name == "alpha" && n.ExitCountry != "DE" {
			t.Error("upsert must not erase the measured exit country")
		}
	}
	// subscription tokens: unique, found only for enabled users
	if _, err := st.AddUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddUser(ctx, "bob"); err != nil {
		t.Fatal(err)
	}
	us, _ := st.ListUsers(ctx)
	if len(us) != 2 || len(us[0].SubToken) < 32 || us[0].SubToken == us[1].SubToken {
		t.Fatalf("tokens: %+v", us)
	}
	u, err := st.UserBySubToken(ctx, us[0].SubToken)
	if err != nil || u.Name != "alice" {
		t.Fatal(err, u)
	}
	if err := st.SetUserEnabled(ctx, "alice", false); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UserBySubToken(ctx, us[0].SubToken); err == nil {
		t.Error("a disabled user must not get a subscription")
	}
	if _, err := st.UserBySubToken(ctx, "nope"); err == nil {
		t.Error("unknown token must not match")
	}
}

func TestStoreNodeStatsSurviveUpsertAndRestart(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	in := ParseLinks("trojan://pw@2.2.2.2:443#b")
	if err := st.UpsertNodes(ctx, in, "src1"); err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	ns := NodeStat{ID: in[0].ID, SpeedHist: []SpeedPoint{{K: 5000, T: at.Unix()}, {K: 9000, T: at.Unix() + 60}}, SpeedTry: at, SpeedErr: "timeout", CheckAt: at,
		Svc: map[string]SvcRes{"telegram": {OK: false, T: at.Unix(), Fails: 2, Err: "x"}}}
	if err := st.SaveNodeStats(ctx, []NodeStat{ns}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertNodes(ctx, in, "src1"); err != nil { // the subscription refresh must not wipe the measurements
		t.Fatal(err)
	}
	out, err := st.ActiveNodes(ctx, time.Hour)
	if err != nil || len(out) != 1 {
		t.Fatal(err, len(out))
	}
	n := out[0]
	if len(n.SpeedHist) != 2 || n.SpeedHist[1].K != 9000 || n.SpeedErr != "timeout" || !n.SpeedTry.Equal(at) || !n.CheckAt.Equal(at) {
		t.Fatalf("not restored: %+v", n)
	}
	if r := n.Svc["telegram"]; r.OK || r.Fails != 2 || r.Err != "x" {
		t.Fatalf("services not restored: %+v", n.Svc)
	}
}

func TestStoreDeleteUser(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	if _, err := st.AddUser(ctx, "bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddUser(ctx, "eve"); err != nil {
		t.Fatal(err)
	}
	_, _ = st.pool.Exec(ctx, `INSERT INTO traffic_hourly(hour,user_name,up,down,conns) VALUES(now(),'bob',1,2,3)`)
	_, _ = st.pool.Exec(ctx, `INSERT INTO user_seen(user_name,last_seen,last_ip) VALUES('bob',now(),'1.1.1.1')`)
	if ok, err := st.DeleteUser(ctx, "nobody"); ok || err != nil {
		t.Fatalf("unknown user: %v %v", ok, err)
	}
	if ok, err := st.DeleteUser(ctx, "bob"); !ok || err != nil {
		t.Fatalf("delete: %v %v", ok, err)
	}
	us, _ := st.ListUsers(ctx)
	if len(us) != 1 || us[0].Name != "eve" {
		t.Fatalf("users left: %+v", us)
	}
	var n int
	_ = st.pool.QueryRow(ctx, `SELECT count(*) FROM traffic_hourly WHERE user_name='bob'`).Scan(&n)
	_ = st.pool.QueryRow(ctx, `SELECT count(*)+$1 FROM user_seen WHERE user_name='bob'`, n).Scan(&n)
	if n != 0 {
		t.Fatal("the counters of a deleted user must go too")
	}
}
