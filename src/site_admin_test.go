package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRealityFrontFollowsTheSite(t *testing.T) {
	cfg := siteTestCfg()
	cfg.Reality.HandshakeServer, cfg.Reality.HandshakePort = "www.example.org", 443
	sni, host, port := cfg.realityFront()
	if sni != "www.example.org" || host != "www.example.org" || port != 443 {
		t.Fatalf("by default the imitated site is shown: %s %s %d", sni, host, port)
	}
	cfg.ApplySettings(map[string]json.RawMessage{
		"site_domain":      json.RawMessage(`"vpn.example.com"`),
		"site_via_reality": json.RawMessage(`true`),
	})
	if sni, _, _ := cfg.realityFront(); sni != "www.example.org" {
		t.Fatal("until the certificate is in place nothing changes")
	}
	cfg.setSiteReady(true)
	sni, host, port = cfg.realityFront()
	if sni != "vpn.example.com" || host == "" || port == 0 {
		t.Fatalf("with a ready certificate the site takes port 443: %s %s %d", sni, host, port)
	}
	cfg.ApplySettings(map[string]json.RawMessage{"site_enabled": json.RawMessage(`false`)})
	if sni, _, _ := cfg.realityFront(); sni != "www.example.org" {
		t.Fatal("a disabled site returns the old front")
	}
}

func selfSigned(t *testing.T, domain string) tls.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func freeAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func TestSiteServerServesHTTPSAndRedirects(t *testing.T) {
	cfg := siteTestCfg()
	cfg.SiteHTTPListen, cfg.SiteHTTPSListen = freeAddr(t), freeAddr(t)
	cfg.ApplySettings(map[string]json.RawMessage{"site_domain": json.RawMessage(`"vpn.example.com"`)})
	st := testStore(t)
	site := NewSite(cfg, st)
	srv := NewSiteServer(cfg, st, site.Handler())
	cert := selfSigned(t, "vpn.example.com")
	srv.providerFn = func(SiteCfg, *Store) (*tlsProvider, error) {
		return &tlsProvider{cfg: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &cert, nil }}}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Run(ctx)

	deadline := time.Now().Add(15 * time.Second)
	for !srv.Status().OK && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if s := srv.Status(); !s.OK || !s.Running || s.Issuer == "" {
		t.Fatalf("the certificate must be accepted: %+v", s)
	}
	cl := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "vpn.example.com"}}}
	resp, err := cl.Get("https://" + cfg.SiteHTTPSListen + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "TestVPN") {
		t.Fatalf("site over https: %d", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Strict-Transport-Security"), "max-age") {
		t.Error("HSTS on TLS")
	}
	// plain HTTP only redirects, and only for our domain
	req, _ := http.NewRequest("GET", "http://"+cfg.SiteHTTPListen+"/login", nil)
	req.Host = "vpn.example.com"
	r2, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r2.Body.Close()
	if r2.StatusCode != 308 || !strings.HasPrefix(r2.Header.Get("Location"), "https://vpn.example.com") || !strings.HasSuffix(r2.Header.Get("Location"), "/login") {
		t.Errorf("redirect: %d %q", r2.StatusCode, r2.Header.Get("Location"))
	}
	req.Host = "evil.example"
	r3, _ := cl.Do(req)
	r3.Body.Close()
	if r3.StatusCode != 404 {
		t.Errorf("foreign Host must not be redirected: %d", r3.StatusCode)
	}
	// disabling the site closes the listeners
	cfg.ApplySettings(map[string]json.RawMessage{"site_enabled": json.RawMessage(`false`)})
	srv.reconcile(ctx)
	if _, err := cl.Get("https://" + cfg.SiteHTTPSListen + "/"); err == nil {
		t.Error("a disabled site must not answer")
	}
	if cfg.getSiteReady() {
		t.Error("ready flag must be dropped")
	}
}

func TestSiteServerWithoutDomain(t *testing.T) {
	cfg := siteTestCfg()
	cfg.SiteHTTPListen, cfg.SiteHTTPSListen = freeAddr(t), freeAddr(t)
	st := testStore(t)
	srv := NewSiteServer(cfg, st, http.NotFoundHandler())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.reconcile(ctx)
	if s := srv.Status(); s.Running || !strings.Contains(s.Message, "домен") {
		t.Fatalf("without a domain and without allow_http nothing starts: %+v", s)
	}
	cfg.SiteAllowHTTP = true
	srv.reconcile(ctx)
	if s := srv.Status(); !s.Running {
		t.Fatalf("allow_http starts plain mode: %+v", s)
	}
	srv.shutdown()
}

type adminT struct {
	t   *testing.T
	mux *http.ServeMux
	n   int
}

func (a *adminT) do(method, path string, body any) (int, map[string]any, []byte) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Authorization", "Bearer tok")
	a.n++
	req.RemoteAddr = fmt.Sprintf("10.9.0.%d:1", a.n%250)
	rr := httptest.NewRecorder()
	a.mux.ServeHTTP(rr, req)
	var m map[string]any
	json.Unmarshal(rr.Body.Bytes(), &m)
	return rr.Code, m, rr.Body.Bytes()
}

func TestAdminSiteAPI(t *testing.T) {
	cfg := siteTestCfg()
	st := testStore(t)
	for _, tbl := range []string{"accounts", "payments", "web_sessions", "plans"} {
		st.pool.Exec(context.Background(), "TRUNCATE "+tbl+" CASCADE")
	}
	t.Cleanup(func() { // other tests expect the sample plans
		st2 := st
		st2.pool.Exec(context.Background(), "DELETE FROM plans")
		st2.pool.Exec(context.Background(), "DELETE FROM settings WHERE key='plans_seeded'")
		st2.seedPlans(context.Background())
	})
	a := NewAPI(cfg, st, nil, nil, "tok", make(chan struct{}, 1))
	mux := http.NewServeMux()
	a.registerSite(mux)
	h := &adminT{t: t, mux: mux}

	// no token, no data
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/api/accounts", nil))
	if rr.Code != 401 {
		t.Fatalf("token required: %d", rr.Code)
	}
	if code, m, _ := h.do("GET", "/api/site", nil); code != 200 || m["settings"] == nil {
		t.Fatalf("site view: %d %v", code, m)
	}

	// plans
	if code, _, _ := h.do("POST", "/api/plans", map[string]any{"name": "Неделя", "days": 7, "price_cents": 5000, "currency": "RUB", "enabled": true}); code != 200 {
		t.Fatalf("create plan: %d", code)
	}
	if code, _, _ := h.do("POST", "/api/plans", map[string]any{"name": "Плохой", "days": 0, "price_cents": 1, "currency": "RUB"}); code != 400 {
		t.Errorf("plan without days: %d", code)
	}
	plans, _ := st.ListPlans(context.Background(), false)
	if len(plans) != 1 {
		t.Fatalf("plans: %d", len(plans))
	}
	if code, _, _ := h.do("PUT", fmt.Sprintf("/api/plans/%d", plans[0].ID), map[string]any{"name": "Неделя+", "days": 8, "price_cents": 5000, "currency": "RUB", "enabled": true}); code != 200 {
		t.Errorf("edit plan: %d", code)
	}
	if code, _, _ := h.do("PUT", "/api/plans/999999", map[string]any{"name": "x", "days": 1, "price_cents": 0, "currency": "RUB"}); code != 404 {
		t.Errorf("edit unknown plan: %d", code)
	}

	// accounts
	code, m, _ := h.do("POST", "/api/accounts", map[string]any{"username": "Admin_Made", "days": 10})
	if code != 200 || m["password"] == "" || m["username"] != "admin_made" {
		t.Fatalf("create account: %d %v", code, m)
	}
	if code, _, _ := h.do("POST", "/api/accounts", map[string]any{"username": "admin_made"}); code != 409 {
		t.Errorf("duplicate: %d", code)
	}
	if code, _, _ := h.do("POST", "/api/accounts", map[string]any{"username": "b a", "days": 1}); code != 400 {
		t.Errorf("bad username: %d", code)
	}
	acc, err := st.AccountByUsername(context.Background(), "admin_made")
	if err != nil || acc.Expires == nil {
		t.Fatalf("account: %v %+v", err, acc)
	}
	id := acc.ID
	op := func(o string, body any) int {
		code, _, _ := h.do("POST", fmt.Sprintf("/api/accounts/%d/%s", id, o), body)
		return code
	}
	if op("expiry", map[string]any{"extend_days": 20}) != 200 {
		t.Fatal("extend")
	}
	if a2, _ := st.AccountByID(context.Background(), id); a2.Expires.Sub(*acc.Expires) < 19*24*time.Hour {
		t.Error("extend_days adds days")
	}
	if op("expiry", map[string]any{"unlimited": true}) != 200 {
		t.Fatal("unlimited")
	}
	if a2, _ := st.AccountByID(context.Background(), id); a2.Expires != nil {
		t.Error("unlimited removes the limit")
	}
	if op("expiry", map[string]any{"until": "2020-01-01"}) != 200 {
		t.Fatal("until in the past is allowed (it ends the subscription)")
	}
	if us, _ := st.EnabledUsers(context.Background()); len(us) != 0 {
		t.Error("an expired key leaves the gateway")
	}
	if op("expiry", map[string]any{"until": "garbage"}) != 400 {
		t.Error("bad date")
	}
	if op("block", nil) != 200 {
		t.Fatal("block")
	}
	if a2, _ := st.AccountByID(context.Background(), id); !a2.Blocked {
		t.Error("blocked")
	}
	if op("unblock", nil) != 200 {
		t.Fatal("unblock")
	}
	code, m, _ = h.do("POST", fmt.Sprintf("/api/accounts/%d/reset-password", id), nil)
	if code != 200 || len(fmt.Sprint(m["password"])) < 10 {
		t.Errorf("reset: %d %v", code, m)
	}
	if code, _, _ := h.do("GET", "/api/accounts", nil); code != 200 {
		t.Errorf("list: %d", code)
	}

	// payments: the request from the site is confirmed or canceled by the administrator
	p, err := st.CreatePayment(context.Background(), id, plans[0], "stub")
	if err != nil {
		t.Fatal(err)
	}
	if code, _, _ := h.do("GET", "/api/payments?status=pending", nil); code != 200 {
		t.Errorf("payments list: %d", code)
	}
	if code, _, _ := h.do("POST", fmt.Sprintf("/api/payments/%d/confirm", p.ID), nil); code != 200 {
		t.Errorf("confirm: %d", code)
	}
	if code, _, _ := h.do("POST", fmt.Sprintf("/api/payments/%d/confirm", p.ID), nil); code == 200 {
		t.Error("second confirmation must be refused")
	}
	if code, _, _ := h.do("POST", fmt.Sprintf("/api/payments/%d/nonsense", p.ID), nil); code != 400 && code != 404 {
		t.Errorf("unknown op: %d", code)
	}

	// deleting the account removes the VPN user too
	if op("delete", nil) != 200 {
		t.Fatal("delete")
	}
	if _, err := st.UserIDByName(context.Background(), acc.UserName); err == nil {
		t.Error("the user must be gone")
	}
	if code, _, _ := h.do("POST", fmt.Sprintf("/api/accounts/%d/block", id), nil); code != 404 {
		t.Errorf("unknown account: %d", code)
	}
}

func TestBuildConfigHandsPort443ToTheSite(t *testing.T) {
	cfg := coreCfgNoBin()
	cfg.Reality.HandshakeServer, cfg.Reality.HandshakePort = "www.example.org", 443
	ns := allProtocolNodes(t)
	us := []User{{Name: "u", UUID: testUUID}}
	front := func() (string, string, float64) {
		data, err := BuildConfig(cfg, ns, us, "")
		if err != nil {
			t.Fatal(err)
		}
		var conf struct {
			Inbounds []struct {
				Tag string         `json:"tag"`
				TLS map[string]any `json:"tls"`
			} `json:"inbounds"`
		}
		json.Unmarshal(data, &conf)
		for _, in := range conf.Inbounds {
			if in.Tag == "vless-in" {
				hs := in.TLS["reality"].(map[string]any)["handshake"].(map[string]any)
				return in.TLS["server_name"].(string), hs["server"].(string), hs["server_port"].(float64)
			}
		}
		t.Fatal("no vless-in")
		return "", "", 0
	}
	if sni, host, port := front(); sni != "www.example.org" || host != "www.example.org" || port != 443 {
		t.Fatalf("default: %s %s %v", sni, host, port)
	}
	cfg.ApplySettings(map[string]json.RawMessage{"site_enabled": json.RawMessage(`true`), "site_domain": json.RawMessage(`"vpn.example.com"`), "site_via_reality": json.RawMessage(`true`)})
	cfg.setSiteReady(true)
	if sni, _, port := front(); sni != "vpn.example.com" || port != 8443 {
		t.Fatalf("via 443: %s %v", sni, port)
	}
}
