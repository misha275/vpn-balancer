package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMeterCounts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.json")
	m := NewMeter(path)
	m.Add([]connInfo{{ID: "a", Upload: 10, Download: 100, Chains: []string{"u-alice"}}, {ID: "x", Upload: 5, Download: 5, Chains: []string{"direct"}}})
	m.Add([]connInfo{{ID: "a", Upload: 30, Download: 400, Chains: []string{"u-alice"}}, {ID: "b", Upload: 1, Download: 2, Chains: []string{"u-bob"}}})
	m.Add([]connInfo{{ID: "b", Upload: 4, Download: 2, Chains: []string{"u-bob"}}}) // a is gone
	s := m.Snapshot()
	if s["alice"] != [2]int64{30, 400} || s["bob"] != [2]int64{4, 2} || len(s) != 2 {
		t.Errorf("totals: %v", s)
	}
	m.save()
	if again := NewMeter(path).Snapshot(); again["alice"] != [2]int64{30, 400} {
		t.Errorf("totals survive a restart: %v", again)
	}
}

func TestEndNodeMetersPerUser(t *testing.T) {
	bin := singboxBin(t)
	release := make(chan struct{})
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("x", 200000)))
		w.(http.Flusher).Flush()
		<-release // the connection stays open while the meter looks
	}))
	defer web.Close()
	defer close(release)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &EndNodeConfig{Name: "T", Host: "127.0.0.1", WorkDir: t.TempDir(), SingboxBin: bin, AllowPrivate: true, StatsPort: freePort(t), secret: "s3cret"}
	p := freePort(t)
	in, _ := NewInbound("trojan", "", p)
	c.Inbounds = []EndInbound{in}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg, err := c.BuildConfig(endUsers)
	if err != nil {
		t.Fatal(err)
	}
	proc := NewSBProc(ctx, bin, c.WorkDir, "endnode")
	defer proc.Stop()
	if _, err := proc.Apply(cfg); err != nil {
		t.Fatalf("%v\n%s", err, cfg)
	}
	time.Sleep(1500 * time.Millisecond)
	l, _ := fillTemplate(c.Templates()[0], "endnode", User{UUID: endUsers[0].UUID}, "x")
	ns := ParseLinks(l)
	sp := freePort(t)
	cl, _ := json.Marshal(map[string]any{"log": map[string]any{"level": "error"},
		"inbounds":  []any{map[string]any{"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": sp}},
		"outbounds": []any{withTag(ns[0].Outbound, "out")}, "route": map[string]any{"final": "out"}})
	cp := NewSBProc(ctx, bin, t.TempDir(), "client")
	defer cp.Stop()
	if _, err := cp.Apply(cl); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1200 * time.Millisecond)
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(mustURL(fmt.Sprintf("socks5://127.0.0.1:%d", sp)))}}
	resp, err := hc.Get(web.URL)
	if err != nil {
		t.Fatal(err)
	}
	io.CopyN(io.Discard, resp.Body, 150000)
	m := NewMeter(filepath.Join(t.TempDir(), "t.json"))
	if err := m.poll(c.StatsPort, c.secret); err != nil {
		t.Fatal(err)
	}
	s := m.Snapshot()
	if s["alice"][1] < 100000 || s["alice"][1] > 400000 {
		t.Errorf("alice's download: %v", s)
	}
	if _, ok := s["bob"]; ok {
		t.Errorf("bob did nothing: %v", s)
	}
	if err := m.poll(c.StatsPort, "wrong"); err == nil {
		t.Error("the stats API needs its password")
	}
	_ = url.Values{}
}
