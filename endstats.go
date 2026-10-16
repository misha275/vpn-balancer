package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Traffic metering of an end node. sing-box (without the v2ray_api build tag) does not count bytes per user, so every
// user gets an outbound "u-<name>" (see EndNodeConfig.BuildConfig) and the local Clash API tells for each open connection
// which outbound it uses and how many bytes went through it. The meter polls that list, adds the growth of every
// connection to the total of its user and keeps the totals on disk, so a restart of the node does not lose them.
// What a connection moved between the last poll and its end is lost (a poll every 2 s: a short error, never an excess).

func meterTag(name string) string { return "u-" + name }

type connInfo struct {
	ID       string   `json:"id"`
	Upload   int64    `json:"upload"`
	Download int64    `json:"download"`
	Chains   []string `json:"chains"`
}

type Meter struct {
	path string

	mu     sync.Mutex
	total  map[string][2]int64
	seen   map[string][2]int64 // connection id -> bytes counted so far
	dirty  bool
	client *http.Client
}

func NewMeter(path string) *Meter {
	m := &Meter{path: path, total: map[string][2]int64{}, seen: map[string][2]int64{}, client: &http.Client{Timeout: 5 * time.Second}}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &m.total)
	}
	return m
}

// Add folds one list of open connections into the totals.
func (m *Meter) Add(conns []connInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := make(map[string][2]int64, len(conns))
	for _, c := range conns {
		now[c.ID] = [2]int64{c.Upload, c.Download}
		if len(c.Chains) == 0 || !strings.HasPrefix(c.Chains[0], "u-") {
			continue
		}
		user := strings.TrimPrefix(c.Chains[0], "u-")
		prev := m.seen[c.ID]
		du, dd := c.Upload-prev[0], c.Download-prev[1]
		if du < 0 || dd < 0 {
			du, dd = c.Upload, c.Download
		}
		if du == 0 && dd == 0 {
			continue
		}
		t := m.total[user]
		m.total[user] = [2]int64{t[0] + du, t[1] + dd}
		m.dirty = true
	}
	m.seen = now
}

func (m *Meter) Snapshot() map[string][2]int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string][2]int64, len(m.total))
	for k, v := range m.total {
		out[k] = v
	}
	return out
}

func (m *Meter) save() {
	m.mu.Lock()
	if !m.dirty {
		m.mu.Unlock()
		return
	}
	b, _ := json.Marshal(m.total)
	m.dirty = false
	m.mu.Unlock()
	tmp := m.path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, m.path)
	}
}

func (m *Meter) poll(port int, secret string) error {
	req, err := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/connections", port), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("clash api: %s", resp.Status)
	}
	var body struct {
		Connections []connInfo `json:"connections"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return err
	}
	m.Add(body.Connections)
	return nil
}

// Run polls until ctx ends. where returns the current API port and password.
func (m *Meter) Run(ctx context.Context, where func() (int, string)) {
	t := time.NewTicker(meterEvery)
	defer t.Stop()
	n := 0
	for {
		select {
		case <-ctx.Done():
			m.save()
			return
		case <-t.C:
		}
		if port, secret := where(); secret != "" {
			_ = m.poll(port, secret) // sing-box may be restarting
		}
		if n++; n%5 == 0 {
			m.save()
		}
	}
}

var meterEvery = 2 * time.Second

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
