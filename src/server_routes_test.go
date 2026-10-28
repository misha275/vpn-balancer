package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

const srvTmpl = "vless://{UUID}@fi.example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=" + testPBK + "&sid=ab12&type=tcp"

func routeServer(t *testing.T, st *Store, name string) RemoteServer {
	t.Helper()
	ctx := context.Background()
	st.pool.Exec(ctx, "DELETE FROM servers WHERE name=$1", name)
	sv, _, err := st.CreateServer(ctx, name, "endnode", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveServerReport(ctx, sv.ID, SyncReport{Kind: "endnode", Info: ServerInfo{Version: "x", Host: "fi.example.com", Links: []LinkTmpl{{Title: "Reality", Tmpl: srvTmpl}}}}); err != nil {
		t.Fatal(err)
	}
	list, _ := st.ListServers(ctx)
	for _, x := range list {
		if x.ID == sv.ID {
			return x
		}
	}
	t.Fatal("server not found")
	return sv
}

func TestEndNodeServersInCategories(t *testing.T) {
	st, cfg := subsStore(t)
	ctx := context.Background()
	cfg.Reality.PrivateKey = "route-test-key"
	cfg.UserDefaultSubs = []string{subBalancers}
	st.pool.Exec(ctx, "DELETE FROM users WHERE name IN ('rt-vip','rt-plain')")
	st.AddUser(ctx, "rt-vip")
	st.AddUser(ctx, "rt-plain")
	us, _ := st.ListUsers(ctx)
	var vip, plain User
	for _, x := range us {
		switch x.Name {
		case "rt-vip":
			vip = x
		case "rt-plain":
			plain = x
		}
	}
	sv := routeServer(t, st, "Хельсинки-маршрут")
	if sv.Route != routeDirect {
		t.Fatalf("default route: %q", sv.Route)
	}
	nodeID, err := st.SaveCustomNode(ctx, customNodeInput{Name: "Own NL", Link: customLink})
	if err != nil {
		t.Fatal(err)
	}
	// a balancer server cannot be put into a category
	bal, _, _ := st.CreateServer(ctx, "Берлин-маршрут", "balancer", "")
	defer st.DeleteServer(ctx, bal.ID)
	bid, err := st.SaveBundle(ctx, Bundle{Slug: "rt", Name: "RT", Enabled: true, Main: true, Nodes: []int64{nodeID}, Servers: []int64{sv.ID, bal.ID}})
	if err != nil {
		t.Fatal(err)
	}
	bs, _ := st.ListBundles(ctx, false)
	if len(bs) != 1 || len(bs[0].Servers) != 1 || bs[0].Servers[0] != sv.ID {
		t.Fatalf("only an end-node server joins a category: %+v", bs)
	}
	if err := st.SetUserSubs(ctx, "rt-vip", []string{"b:rt"}); err != nil {
		t.Fatal(err)
	}
	if u, err := st.UserBySubToken(ctx, vip.SubToken); err == nil {
		vip = *u // with his own list
	}
	srv := httptest.NewServer(NewSubServer(cfg, st).Handler())
	defer srv.Close()
	path := "/sub/" + vip.SubToken + "/b/rt"

	// default order: the main server, single servers, installed servers
	code, lines := fetchLines(t, srv, path)
	if code != 200 || len(lines) < 5 {
		t.Fatalf("category: %d %v", code, lines)
	}
	direct := func(ls []string) int {
		for i, l := range ls {
			if strings.Contains(l, "fi.example.com") && strings.Contains(l, vip.UUID) {
				return i
			}
		}
		return -1
	}
	if i := direct(lines); i != len(lines)-1 {
		t.Errorf("the direct link of the server comes last by default: %d of %d", i, len(lines))
	}
	// the order set by the administrator: the server above the balancers
	if _, err := st.SaveBundle(ctx, Bundle{ID: bid, Slug: "rt", Name: "RT", Enabled: true, Main: true, Nodes: []int64{nodeID}, Servers: []int64{sv.ID}, Order: []string{"s:" + itoa(sv.ID), "main", "n:" + itoa(nodeID)}}); err != nil {
		t.Fatal(err)
	}
	_, lines = fetchLines(t, srv, path)
	if direct(lines) != 0 {
		t.Errorf("the server is above the balancers: %v", lines)
	}
	if !strings.Contains(lines[len(lines)-1], "own1.example.com") {
		t.Errorf("then the balancers and the single server: %v", lines)
	}
	if bs, _ := st.ListBundles(ctx, false); len(bs[0].Order) != 3 || bs[0].Order[0] != "s:"+itoa(sv.ID) {
		t.Errorf("the order is kept: %v", bs[0].Order)
	}

	// who is on the server: the category gives access, the key of the main server appears only for the other two modes
	sv, _ = oneServer(t, st, sv.ID)
	users, _ := st.SyncUsersFor(ctx, cfg, sv)
	if !hasSyncUser(users, "rt-vip") || hasSyncUser(users, "rt-plain") || hasSyncUser(users, gwUserName) {
		t.Errorf("direct: %v", users)
	}

	// through the main server
	if err := st.SetServerRoute(ctx, sv.ID, routePanel); err != nil {
		t.Fatal(err)
	}
	sv, _ = oneServer(t, st, sv.ID)
	users, _ = st.SyncUsersFor(ctx, cfg, sv)
	if !hasSyncUser(users, gwUserName) {
		t.Errorf("the main server enters with its own key: %v", users)
	}
	_, lines = fetchLines(t, srv, path)
	if direct(lines) != -1 {
		t.Errorf("no direct link in the panel mode: %v", lines)
	}
	viaUUID := modeUUID(vip.UUID, extMode(srvNodeID(sv.ID, 0)))
	if !strings.Contains(strings.Join(lines, "\n"), viaUUID) {
		t.Errorf("the link goes to the main server with the key of the route: %v", lines)
	}
	ix, err := st.LoadSubIndex(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if main, via := ix.access(cfg, vip); !main || len(via) != 1 || via[0] != srvNodeID(sv.ID, 0) {
		t.Errorf("the gateway knows the route: %v %v", main, via)
	}
	_, ext := prepareUsers(cfg, ix, []User{vip, plain})
	if len(ext) != 1 || ext[0].Outbound["uuid"] != gwUUID(cfg, sv.ID) || ext[0].Outbound["server"] != "fi.example.com" {
		t.Errorf("the outbound enters the server with the gateway key: %+v", ext)
	}

	// into the balancer pool
	if err := st.SetServerRoute(ctx, sv.ID, routeBalancer); err != nil {
		t.Fatal(err)
	}
	st.RefreshRemote(ctx, cfg)
	var n int
	st.pool.QueryRow(ctx, `SELECT count(*) FROM nodes WHERE source=$1 AND last_seen > now() - interval '1 minute'`, serverSource(sv.ID)).Scan(&n)
	if n != 1 {
		t.Fatalf("the server is a node of the pool: %d", n)
	}
	var seenAdmin, seenUsers *time.Time
	st.pool.QueryRow(ctx, `SELECT seen_admin, seen_users FROM nodes WHERE source=$1`, serverSource(sv.ID)).Scan(&seenAdmin, &seenUsers)
	if seenAdmin == nil || seenUsers == nil {
		t.Error("the node is in both pools")
	}
	_, lines = fetchLines(t, srv, path)
	if direct(lines) != -1 || strings.Contains(strings.Join(lines, "\n"), "fi.example.com") {
		t.Errorf("no separate line in the pool mode: %v", lines)
	}
	// back to direct: the node leaves the pool at once
	if err := st.SetServerRoute(ctx, sv.ID, routeDirect); err != nil {
		t.Fatal(err)
	}
	st.pool.QueryRow(ctx, `SELECT count(*) FROM nodes WHERE source=$1`, serverSource(sv.ID)).Scan(&n)
	if n != 0 {
		t.Errorf("the node left the pool: %d", n)
	}
	if st.SetServerRoute(ctx, sv.ID, "weird") == nil {
		t.Error("an unknown route is refused")
	}
	if st.SetServerRoute(ctx, bal.ID, routePanel) == nil {
		t.Error("only end-node servers have a route")
	}
	// a category that is switched off or deleted no longer gives access
	st.DeleteBundle(ctx, bid)
	sv, _ = oneServer(t, st, sv.ID)
	if len(sv.Bundles) != 0 {
		t.Errorf("deleted category: %v", sv.Bundles)
	}
	st.DeleteServer(ctx, sv.ID)
}

func oneServer(t *testing.T, st *Store, id int64) (RemoteServer, bool) {
	t.Helper()
	list, _ := st.ListServers(context.Background())
	for _, x := range list {
		if x.ID == id {
			return x, true
		}
	}
	return RemoteServer{}, false
}

func hasSyncUser(us []SyncUser, name string) bool {
	for _, u := range us {
		if u.Name == name {
			return true
		}
	}
	return false
}

func TestServerRoutesAdminAPI(t *testing.T) {
	st, cfg := subsStore(t)
	ctx := context.Background()
	sv := routeServer(t, st, "API-маршрут")
	defer st.DeleteServer(ctx, sv.ID)
	a := NewAPI(cfg, st, nil, nil, "tok", make(chan struct{}, 1))
	mux := http.NewServeMux()
	a.registerSite(mux)
	a.registerSubs(mux)
	a.registerServers(mux)
	h := &adminT{t: t, mux: mux}
	id := strconv.FormatInt(sv.ID, 10)
	if code, _, raw := h.do("POST", "/api/servers/"+id+"/route", map[string]any{"mode": "panel"}); code != 200 {
		t.Fatalf("route: %d %s", code, raw)
	}
	if code, _, _ := h.do("POST", "/api/servers/"+id+"/route", map[string]any{"mode": "x"}); code != 400 {
		t.Errorf("bad mode: %d", code)
	}
	if code, _, _ := h.do("POST", "/api/servers/999999/route", map[string]any{"mode": "panel"}); code != 404 {
		t.Errorf("unknown server: %d", code)
	}
	code, m, raw := h.do("POST", "/api/bundles", map[string]any{"slug": "apirt", "name": "API RT", "enabled": true, "main": true, "servers": []int64{sv.ID}, "order": []string{"s:" + id, "main", "junk"}})
	if code != 200 {
		t.Fatalf("bundle: %d %s", code, raw)
	}
	cat := m["servers"].([]any)
	var found bool
	for _, x := range cat {
		if c := x.(map[string]any); int64(c["id"].(float64)) == sv.ID && c["route"] == "panel" {
			found = true
		}
	}
	if !found {
		t.Errorf("the catalog lists the server with its route: %s", raw)
	}
	bs := m["bundles"].([]any)
	b0 := bs[0].(map[string]any)
	if o := b0["order"].([]any); len(o) != 2 || o[0] != "s:"+id {
		t.Errorf("the order comes back without junk: %v", o)
	}
	if s := b0["servers"].([]any); len(s) != 1 {
		t.Errorf("the servers of the category: %v", s)
	}
	if code, _, _ := h.do("GET", "/api/servers", nil); code != 200 {
		t.Errorf("servers list: %d", code)
	}
}
