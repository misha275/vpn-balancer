package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestDDNSSync(t *testing.T) {
	var mu sync.Mutex
	content, proxied, exists := "1.1.1.1", false, true
	var puts, posts int
	cf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(403)
			w.Write([]byte(`{"success":false,"errors":[{"message":"bad token"}]}`))
			return
		}
		switch {
		case r.URL.Path == "/zones" && r.URL.Query().Get("name") == "ytc-srv.org":
			w.Write([]byte(`{"success":true,"result":[{"id":"Z1"}]}`))
		case r.URL.Path == "/zones":
			w.Write([]byte(`{"success":true,"result":[]}`))
		case r.URL.Path == "/zones/Z1/dns_records" && r.Method == "GET":
			if exists {
				b, _ := json.Marshal([]map[string]any{{"id": "R1", "content": content, "proxied": proxied}})
				w.Write([]byte(`{"success":true,"result":` + string(b) + `}`))
			} else {
				w.Write([]byte(`{"success":true,"result":[]}`))
			}
		case r.URL.Path == "/zones/Z1/dns_records" && r.Method == "POST":
			posts++
			var b map[string]any
			json.NewDecoder(r.Body).Decode(&b)
			content, exists = b["content"].(string), true
			w.Write([]byte(`{"success":true,"result":{}}`))
		case r.URL.Path == "/zones/Z1/dns_records/R1" && r.Method == "PUT":
			puts++
			var b map[string]any
			json.NewDecoder(r.Body).Decode(&b)
			content, proxied = b["content"].(string), b["proxied"].(bool)
			w.Write([]byte(`{"success":true,"result":{}}`))
		default:
			w.WriteHeader(404)
			w.Write([]byte(`{"success":false,"errors":[]}`))
		}
	}))
	defer cf.Close()
	old := cloudflareAPI
	cloudflareAPI = cf.URL
	defer func() { cloudflareAPI = old }()
	ipsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("203.0.113.9\n")) }))
	defer ipsrv.Close()

	cfg := &Config{Domain: "nvrk.ytc-srv.org", CloudflareToken: "tok"}
	d := NewDDNS(cfg, &Notifier{})
	d.ipURLs = []string{ipsrv.URL}
	ctx := context.Background()
	ip, err := d.publicIP(ctx)
	if err != nil || ip != "203.0.113.9" {
		t.Fatal(ip, err)
	}
	ch, err := d.Sync(ctx, ip)
	if err != nil || len(ch) != 1 || content != ip || puts != 1 {
		t.Fatalf("update: %v %v %q puts=%d", ch, err, content, puts)
	}
	if ch, err = d.Sync(ctx, ip); err != nil || len(ch) != 0 || puts != 1 {
		t.Fatalf("nothing to do: %v %v puts=%d", ch, err, puts)
	}
	exists = false
	if ch, err = d.Sync(ctx, "203.0.113.10"); err != nil || len(ch) != 1 || posts != 1 || content != "203.0.113.10" {
		t.Fatalf("create: %v %v posts=%d", ch, err, posts)
	}
	d.cfg.CloudflareToken = "wrong"
	if _, err = d.Sync(ctx, ip); err == nil || !strings.Contains(err.Error(), "bad token") {
		t.Fatalf("bad token: %v", err)
	}
}

func TestSubBaseIgnoresIP(t *testing.T) {
	c := &Config{Domain: "nvrk.ytc-srv.org", SubPublicURL: "http://203.0.113.5:8081"}
	if got := c.subBase(); got != "http://nvrk.ytc-srv.org:8081" {
		t.Errorf("got %q", got)
	}
	c.SubPublicURL = "https://sub.example.com/"
	if got := c.subBase(); got != "https://sub.example.com" {
		t.Errorf("got %q", got)
	}
}
