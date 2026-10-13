package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const extLinkA = "vless://" + testUUID + "@ext-a.example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=" + testPBK + "&sid=ab12&type=tcp#A"
const extLinkB = "vless://" + testUUID + "@ext-b.example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=" + testPBK + "&sid=ab12&type=tcp#B"

func extUsers(t *testing.T, st *Store, names ...string) map[string]User {
	t.Helper()
	ctx := context.Background()
	for _, n := range names {
		if _, err := st.AddUser(ctx, n); err != nil {
			t.Fatal(err)
		}
	}
	us, _ := st.ListUsers(ctx)
	m := map[string]User{}
	for _, u := range us {
		m[u.Name] = u
	}
	return m
}

func TestFoldUserExternal(t *testing.T) {
	for in, want := range map[string][2]string{
		"alice~x12": {"alice", "x12"}, "alice~speed": {"alice", "speed"}, "alice": {"alice", ""},
		"a~b~x3": {"a~b", "x3"}, "alice~xy": {"alice~xy", ""}, "~x1": {"~x1", ""},
	} {
		if b, m := foldUser(in); b != want[0] || m != want[1] {
			t.Errorf("%q -> %q %q, want %v", in, b, m, want)
		}
	}
}

func TestExternalSourcesAndCategories(t *testing.T) {
	st, cfg := subsStore(t)
	ctx := context.Background()
	st.pool.Exec(ctx, "TRUNCATE ext_sources, users CASCADE")
	us := extUsers(t, st, "ann", "bob")

	// a subscription as a source: servers are imported with the mode of the source
	if _, err := st.SaveExtSource(ctx, extSourceInput{Name: "x", URL: "ftp://bad", Mode: "via"}); err == nil {
		t.Error("bad address")
	}
	if _, err := st.SaveExtSource(ctx, extSourceInput{Name: "x", URL: "https://s.example/t", Mode: "weird"}); err == nil {
		t.Error("bad mode")
	}
	sid, err := st.SaveExtSource(ctx, extSourceInput{Name: "Партнёр", URL: "https://s.example/secret-token", Mode: "via"})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := st.ImportSource(ctx, sid, extLinkA+"\n"+extLinkB, time.Hour); err != nil || n != 2 {
		t.Fatalf("import: %d %v", n, err)
	}
	if n, err := st.ImportSource(ctx, sid, extLinkA, time.Hour); err != nil || n != 1 {
		t.Fatalf("second import: %d %v", n, err)
	}
	srcs, _ := st.ListExtSources(ctx)
	if len(srcs) != 1 || srcs[0].Nodes != 2 { // the unseen one lives through the grace period
		t.Fatalf("sources: %+v", srcs)
	}
	raw, _ := json.Marshal(srcs)
	if strings.Contains(string(raw), "secret-token") {
		t.Fatalf("the address of a source must never be sent back: %s", raw)
	}
	// a single manual server in direct mode
	nid, err := st.SaveCustomNode(ctx, customNodeInput{Name: "Мой NL", Link: customLink})
	if err != nil {
		t.Fatal(err)
	}
	mans, _ := st.ListCustomNodes(ctx)
	if len(mans) != 1 || mans[0].Mode != "direct" {
		t.Fatalf("manual nodes (the imported ones are not here): %+v", mans)
	}

	// categories: A with main + the source, B without main, only the direct server
	ba, err := st.SaveBundle(ctx, Bundle{Slug: "a", Name: "A", Enabled: true, Main: true, Sources: []int64{sid}})
	if err != nil {
		t.Fatal(err)
	}
	bb, err := st.SaveBundle(ctx, Bundle{Slug: "b", Name: "B", Enabled: true, Nodes: []int64{nid}})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = ba, bb
	ix, err := st.LoadSubIndex(ctx)
	if err != nil {
		t.Fatal(err)
	}

	ann := us["ann"]
	ann.Subs = []string{"b:a"}
	bob := us["bob"]
	bob.Subs = []string{"b:b"}

	main, via := ix.access(cfg, ann)
	if !main || len(via) != 2 {
		t.Fatalf("ann: main=%v via=%v", main, via)
	}
	if main, via = ix.access(cfg, bob); main || len(via) != 0 {
		t.Fatalf("bob (a direct server only) needs no gateway key: %v %v", main, via)
	}
	// the default group: three balancers only
	if m, v := ix.access(cfg, User{Name: "z"}); !m || len(v) != 0 {
		t.Fatalf("default: %v %v", m, v)
	}
	cfg.UserDefaultSubs = []string{subBalancers}

	// subscription contents
	_, la, ok := ix.lines(cfg, ann, "a")
	if !ok || len(la) != 5 { // 3 balancers + 2 servers of the source through the gateway
		t.Fatalf("lines a: %d %v", len(la), la)
	}
	for _, l := range la[3:] {
		if !strings.Contains(l, "gw.example.com") || strings.Contains(l, "ext-") {
			t.Errorf("a server in the via mode goes through the gateway, its address stays hidden: %s", l)
		}
	}
	_, lb, _ := ix.lines(cfg, bob, "b")
	if len(lb) != 1 || !strings.Contains(lb[0], "own1.example.com") {
		t.Fatalf("lines b (direct): %v", lb)
	}

	// users for the gateway
	all := []User{ann, bob, {Name: "def", UUID: testUUID}}
	pu, ext := prepareUsers(cfg, ix, all)
	if len(pu) != 2 || len(ext) != 2 { // bob has no key at all
		t.Fatalf("prepared: %v / %d ext", pu, len(ext))
	}
	for _, u := range pu {
		if u.Name == "ann" && (u.NoBalancer || len(u.Via) != 2) {
			t.Errorf("ann: %+v", u)
		}
	}
	// an unknown server never gets into a category
	if bid, _ := st.SaveBundle(ctx, Bundle{Slug: "c", Name: "C", Enabled: true, Nodes: []int64{999999}, Sources: []int64{999999}}); bid != 0 {
		bs, _ := st.ListBundles(ctx, false)
		for _, b := range bs {
			if b.Slug == "c" && (len(b.Nodes) != 0 || len(b.Sources) != 0) {
				t.Errorf("foreign ids: %+v", b)
			}
		}
	}
	// the mode of a source changes the mode of its servers
	if _, err := st.SaveExtSource(ctx, extSourceInput{ID: sid, Name: "Партнёр", Mode: "direct"}); err != nil {
		t.Fatal(err)
	}
	ix, _ = st.LoadSubIndex(ctx)
	if _, v := ix.access(cfg, ann); len(v) != 0 {
		t.Errorf("source switched to direct: %v", v)
	}
	_, la, _ = ix.lines(cfg, ann, "a")
	if len(la) != 5 || !strings.Contains(la[3], "ext-a.example.com") {
		t.Errorf("direct servers are given as links: %v", la)
	}
	// deleting the source takes the servers with it
	if err := st.DeleteExtSource(ctx, sid); err != nil {
		t.Fatal(err)
	}
	ix, _ = st.LoadSubIndex(ctx)
	if _, la, _ = ix.lines(cfg, ann, "a"); len(la) != 3 {
		t.Errorf("after deleting: %v", la)
	}
}

func TestExternalViaGatewayConfig(t *testing.T) {
	cfg := coreCfg(t)
	cfg.setExtVia([]ExtNode{{ID: 7, Tag: extTag(7), Outbound: map[string]any{
		"type": "shadowsocks", "tag": extTag(7), "server": "ext.example.com", "server_port": 8388, "method": "aes-256-gcm", "password": "p"}}})
	nodes := []*Node{{ID: "n1aaaaaaaaaa", Name: "n1", Outbound: map[string]any{"type": "direct"}}}
	users := []User{
		{Name: "ann", UUID: testUUID, Via: []int64{7}},
		{Name: "bob", UUID: "11111111-2222-4333-8444-555555555555", NoBalancer: true, Via: []int64{7}},
	}
	data, err := BuildConfig(cfg, nodes, users, "")
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, want := range []string{`"ann~x7"`, `"bob~x7"`, `"x-7"`, `"bob"`} {
		if want == `"bob"` {
			if strings.Contains(s, want) {
				t.Errorf("a user without balancer access must not have the main key")
			}
			continue
		}
		if !strings.Contains(s, want) {
			t.Errorf("config lacks %s", want)
		}
	}
	if strings.Contains(s, `"bob~speed"`) || strings.Contains(s, `"bob~ping"`) {
		t.Error("no balancer-mode keys for bob")
	}
	p := filepath.Join(t.TempDir(), "c.json")
	os.WriteFile(p, data, 0o600)
	core := &Core{cfg: cfg}
	if err := core.check(p); err != nil {
		t.Fatal(err)
	}
	// a broken server is dropped and the others stay
	cfg.setExtVia(append(cfg.getExtVia(), ExtNode{ID: 8, Tag: extTag(8), Outbound: map[string]any{"type": "shadowsocks", "tag": extTag(8), "server": "e.example.com", "server_port": 1, "method": "no-such-cipher", "password": "p"}}))
	if !core.dropBadExt() {
		t.Fatal("the bad server must be dropped")
	}
	if got := cfg.getExtVia(); len(got) != 1 || got[0].ID != 7 {
		t.Fatalf("left: %+v", got)
	}
	if core.dropBadExt() {
		t.Error("nothing more to drop")
	}
}

// A real sing-box chain: the user key "x7" ends at the external server, the main key at the balancer pool,
// a user without balancer access gets no main key, the filter rules apply to the external server too.
func TestExternalViaRoutesInSingbox(t *testing.T) {
	bin := singboxBin(t)
	dir := t.TempDir()
	run := func(name string, conf any) {
		data, _ := json.MarshalIndent(conf, "", " ")
		p := filepath.Join(dir, name+".json")
		os.WriteFile(p, data, 0o600)
		cmd := exec.Command(bin, "run", "-c", p)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	}
	wait := func(addr string) {
		for i := 0; i < 100; i++ {
			if c, err := net.Dial("tcp", addr); err == nil {
				c.Close()
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("%s did not come up", addr)
	}
	tagPool, tagExt := tagServer(t, "P"), tagServer(t, "E")
	ssP, ssE := freePort(t), freePort(t)
	run("up", map[string]any{
		"log": map[string]any{"level": "error"},
		"inbounds": []any{
			map[string]any{"type": "shadowsocks", "tag": "ip", "listen": "127.0.0.1", "listen_port": ssP, "method": "aes-128-gcm", "password": "pw"},
			map[string]any{"type": "shadowsocks", "tag": "ie", "listen": "127.0.0.1", "listen_port": ssE, "method": "aes-128-gcm", "password": "pw"}},
		"outbounds": []any{
			map[string]any{"type": "direct", "tag": "dp", "override_address": "127.0.0.1", "override_port": tagPool},
			map[string]any{"type": "direct", "tag": "de", "override_address": "127.0.0.1", "override_port": tagExt}},
		"route": map[string]any{"rules": []any{map[string]any{"inbound": []string{"ip"}, "outbound": "dp"}, map[string]any{"inbound": []string{"ie"}, "outbound": "de"}}},
	})
	wait(fmt.Sprintf("127.0.0.1:%d", ssP))
	ui := "YWVzLTEyOC1nY206cHc"
	pool := ParseLinks(fmt.Sprintf("ss://%s@127.0.0.1:%d#p", ui, ssP))[0]
	pool.ExitCountry = "DE"
	extNode := parseLink(fmt.Sprintf("ss://%s@127.0.0.1:%d#e", ui, ssE))
	o := map[string]any{}
	for k, v := range extNode.Outbound {
		o[k] = v
	}
	o["tag"] = extTag(7)

	cfg := coreCfg(t)
	cfg.ClashAPI = fmt.Sprintf("127.0.0.1:%d", freePort(t))
	cfg.TestPort = freePort(t)
	cfg.GatewayBase = 0
	cfg.Rules = []RuleCfg{{Action: "block", Match: []string{"port:25"}}}
	off := false
	cfg.ExitCheck = &off
	cfg.setExtVia([]ExtNode{{ID: 7, Tag: extTag(7), Outbound: o}})
	bobUUID := "11111111-2222-4333-8444-555555555555"
	users := []User{{Name: "alice", UUID: testUUID, Via: []int64{7}}, {Name: "bob", UUID: bobUUID, NoBalancer: true, Via: []int64{7}}}
	data, err := BuildConfig(cfg, []*Node{pool}, users, "")
	if err != nil {
		t.Fatal(err)
	}
	var gw map[string]any
	json.Unmarshal(data, &gw)
	gwPort := freePort(t)
	for _, ib := range gw["inbounds"].([]any) {
		in := ib.(map[string]any)
		if in["tag"] == "vless-in" {
			delete(in, "tls")
			in["listen"], in["listen_port"] = "127.0.0.1", gwPort
			for _, u := range in["users"].([]any) {
				delete(u.(map[string]any), "flow")
			}
		}
	}
	run("gw", gw)
	wait(fmt.Sprintf("127.0.0.1:%d", gwPort))

	keys := map[string]string{"alice": testUUID, "alice-x": modeUUID(testUUID, extMode(7)), "bob": bobUUID, "bob-x": modeUUID(bobUUID, extMode(7))}
	var cin, cout, crules []any
	ports := map[string]int{}
	for k, id := range keys {
		p := freePort(t)
		ports[k] = p
		cin = append(cin, map[string]any{"type": "socks", "tag": "in" + k, "listen": "127.0.0.1", "listen_port": p})
		cout = append(cout, map[string]any{"type": "vless", "tag": "out" + k, "server": "127.0.0.1", "server_port": gwPort, "uuid": id})
		crules = append(crules, map[string]any{"inbound": []string{"in" + k}, "outbound": "out" + k})
	}
	run("client", map[string]any{"log": map[string]any{"level": "error"}, "inbounds": cin, "outbounds": cout, "route": map[string]any{"rules": crules}})
	for _, p := range ports {
		wait(fmt.Sprintf("127.0.0.1:%d", p))
	}
	for k, want := range map[string]string{"alice": "P:x", "alice-x": "E:x", "bob-x": "E:x"} {
		if got := tryVia(ports[k], 80); got != want {
			t.Errorf("key %s: got %q, want %q", k, got, want)
		}
	}
	if got := tryVia(ports["bob"], 80); strings.HasSuffix(got, ":x") {
		t.Errorf("a user without balancer access must not reach the pool: %q", got)
	}
	if got := tryVia(ports["alice-x"], 25); strings.HasSuffix(got, ":x") {
		t.Errorf("the filter must also block port 25 through an external server: %q", got)
	}
}

// One entry, many exits: links that differ only in the name are all kept.
func TestSourceKeepsLinksThatDifferOnlyInName(t *testing.T) {
	st, _ := subsStore(t)
	ctx := context.Background()
	st.pool.Exec(ctx, "TRUNCATE ext_sources CASCADE")
	sid, err := st.SaveExtSource(ctx, extSourceInput{Name: "alv", URL: "https://s.example/t", Mode: "direct"})
	if err != nil {
		t.Fatal(err)
	}
	body := ""
	for _, n := range []string{"DE", "NL", "FI", "US", "JP", "PL", "SE"} {
		body += strings.Replace(extLinkA, "#A", "#"+n, 1) + "\n"
	}
	if n, err := st.ImportSource(ctx, sid, body, time.Hour); err != nil || n != 7 {
		t.Fatalf("import: %d %v", n, err)
	}
	if n, err := st.ImportSource(ctx, sid, body, time.Hour); err != nil || n != 7 {
		t.Fatalf("again: %d %v", n, err)
	}
	srcs, _ := st.ListExtSources(ctx)
	if len(srcs) != 1 || srcs[0].Nodes != 7 {
		t.Fatalf("all exits must stay: %+v", srcs)
	}
}

func TestBulkPlanSubs(t *testing.T) {
	st, _ := subsStore(t)
	ctx := context.Background()
	st.pool.Exec(ctx, "DELETE FROM plans")
	a, _ := st.SavePlan(ctx, Plan{Name: "A", Days: 30, Enabled: true, Subs: []string{"balancers"}})
	b, _ := st.SavePlan(ctx, Plan{Name: "B", Days: 30, Enabled: true}) // follows the default
	_, _ = a, b
	u := extUsers(t, st, "carl")["carl"]
	st.SetUserSubs(ctx, "carl", []string{"all"})
	get := func() map[string][]string {
		ps, _ := st.ListPlans(ctx, false)
		m := map[string][]string{}
		for _, p := range ps {
			m[p.Name] = p.Subs
		}
		return m
	}
	if _, _, err := st.BulkPlanSubs(ctx, "bad", nil, nil, false); err == nil {
		t.Error("bad mode")
	}
	n, _, err := st.BulkPlanSubs(ctx, "add", []string{"b:vip"}, []string{"balancers"}, false)
	if err != nil || n != 2 {
		t.Fatal(n, err)
	}
	m := get()
	if strings.Join(m["A"], ",") != "balancers,b:vip" || strings.Join(m["B"], ",") != "balancers,b:vip" {
		t.Fatalf("add: %v", m)
	}
	st.BulkPlanSubs(ctx, "remove", []string{"balancers"}, nil, false)
	if m = get(); strings.Join(m["A"], ",") != "b:vip" {
		t.Fatalf("remove: %v", m)
	}
	_, nu, err := st.BulkPlanSubs(ctx, "set", []string{"b:games"}, nil, true)
	if err != nil || nu < 1 {
		t.Fatalf("set: %d %v", nu, err)
	}
	if m = get(); strings.Join(m["A"], ",") != "b:games" || strings.Join(m["B"], ",") != "b:games" {
		t.Fatalf("set: %v", m)
	}
	if got, _ := st.UserBySubToken(ctx, u.SubToken); got.Subs != nil {
		t.Errorf("personal list must be reset: %v", got.Subs)
	}
}
