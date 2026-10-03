package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadConfigDefaultsAndDurations(t *testing.T) {
	t.Setenv("DB_PASSWORD", "hunter2")
	t.Setenv("DATABASE_URL", "")
	c, err := LoadConfig(writeCfg(t, `
database_url: postgres://balancer:${DB_PASSWORD}@postgres:5432/balancer
subscriptions: [https://a.example/x]
sub_refresh: 10m
tier2_interval: 90s
public_host: 1.2.3.4
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.DatabaseURL != "postgres://balancer:hunter2@postgres:5432/balancer" {
		t.Fatalf("env expansion: %s", c.DatabaseURL)
	}
	if c.SubRefresh != 10*time.Minute || c.Tier2Interval != 90*time.Second {
		t.Fatalf("durations: %v %v", c.SubRefresh, c.Tier2Interval)
	}
	// defaults from the spec
	if c.Tier1Interval != time.Minute || c.Tier3Interval != 10*time.Minute || c.WatchInterval != 5*time.Second ||
		c.NodeGrace != 48*time.Hour || c.SwitchMargin != 1.15 || c.SwitchConfirm != 3 || c.Tier3Top != 5 ||
		c.InboundPort != 443 || c.TestPort != 2080 || len(c.ProbeURLs) != 3 || len(c.BaselineAddrs) != 3 || c.Tier2Concurrency < 1 {
		t.Fatalf("defaults: %+v", c)
	}
	if len(c.TestSecret) != 32 {
		t.Fatalf("probe secret must be random per start: %q", c.TestSecret)
	}
	c2, _ := LoadConfig(writeCfg(t, "subscriptions: []\n"))
	if c2.TestSecret == c.TestSecret {
		t.Fatal("probe secret must differ between starts")
	}
}

func TestLoadConfigEnvOverride(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://override")
	c, err := LoadConfig(writeCfg(t, "database_url: postgres://file\n"))
	if err != nil || c.DatabaseURL != "postgres://override" {
		t.Fatalf("%v %q", err, c.DatabaseURL)
	}
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("missing file must be an error")
	}
	if _, err := LoadConfig(writeCfg(t, "sub_refresh: [not a duration\n")); err == nil {
		t.Fatal("broken yaml must be an error")
	}
}

func TestValidateRunCatchesPlaceholders(t *testing.T) {
	ok := func() *Config {
		c := &Config{PublicHost: "1.2.3.4", Subscriptions: []string{"https://x"}}
		c.Reality.PrivateKey, c.Reality.PublicKey, c.Reality.ShortID = "a", "b", "c"
		return c
	}
	if err := ok().ValidateRun(); err != nil {
		t.Fatal(err)
	}
	c := ok()
	c.PublicHost = "<IP или домен вашего сервера>" // placeholder copied from config.example.yaml
	if err := c.ValidateRun(); err == nil || !strings.Contains(err.Error(), "public_host") {
		t.Fatalf("placeholder must be reported: %v", err)
	}
	c = ok()
	c.Reality.PrivateKey = ""
	if c.ValidateRun() == nil {
		t.Fatal("empty key must be reported")
	}
	c = ok()
	c.Subscriptions = nil
	if err := c.ValidateRun(); err != nil {
		t.Fatalf("an empty subscription list is allowed (the installer starts without one): %v", err)
	}
}

func TestUserLink(t *testing.T) {
	c := &Config{PublicHost: "vpn.example.com", InboundPort: 443}
	c.Reality.HandshakeServer, c.Reality.PublicKey, c.Reality.ShortID = "www.microsoft.com", testPBK, "ab12"
	ns := ParseLinks(userLink(c, "alice smith", testUUID)) // our own link must be parseable by our own parser
	if len(ns) != 1 || ns[0].Server != "vpn.example.com" || ns[0].Name != "alice smith" {
		t.Fatalf("user link does not round-trip: %+v", ns)
	}
}

func TestScrubErrHidesTokens(t *testing.T) {
	_, raw := http.Get("http://127.0.0.1:1/SECRET-TOKEN") // connection refused
	if raw == nil || !strings.Contains(raw.Error(), "SECRET-TOKEN") {
		t.Fatal("test premise: net/http errors contain the URL")
	}
	if err := scrubErr(raw); strings.Contains(err.Error(), "SECRET-TOKEN") {
		t.Fatalf("subscription token leaked into the error: %v", err)
	}
	if got := redact("https://host.example/path/SECRET-TOKEN?k=v"); got != "host.example" {
		t.Fatalf("redact: %q", got)
	}
}
