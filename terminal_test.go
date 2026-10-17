package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSplitArgs(t *testing.T) {
	got, err := splitArgs(`set site_name "Мой VPN" 'a b' c\ d`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"set", "site_name", "Мой VPN", "a b", "c d"}
	if len(got) != len(want) {
		t.Fatalf("got %q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %q want %q", got, want)
		}
	}
	if _, err := splitArgs(`say "open`); err == nil {
		t.Fatal("unclosed quote must be an error")
	}
}

func TestHelpReferenceCoversCommands(t *testing.T) {
	groups := parseCLIHelp()
	all := ""
	for _, g := range groups {
		for _, c := range g.Cmds {
			all += c.Cmd + "\n"
		}
	}
	for _, want := range []string{"users", "adduser", "block", "pool admin|users", "set КЛЮЧ", "backup", "wg list"} {
		if !strings.Contains(all, want) {
			t.Errorf("the reference lacks %q", want)
		}
	}
}

func TestTerminalRunsCommands(t *testing.T) {
	st := testStore(t)
	cfg := siteTestCfg()
	ctx := context.Background()
	a := &API{cfg: cfg, store: st, token: "t", fails: map[string][]time.Time{}}
	post := func(line string) string {
		req := httptest.NewRequest("POST", "/api/terminal", strings.NewReader(`{"line":`+jsonStr(line)+`}`))
		w := httptest.NewRecorder()
		a.terminal(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d", line, w.Code)
		}
		return w.Body.String()
	}
	if out := post("version"); !strings.Contains(out, appVersion) {
		t.Fatalf("version: %s", out)
	}
	if out := post("adduser term_t1"); !strings.Contains(out, "vless://") {
		t.Fatalf("adduser: %s", out)
	}
	if out := post("users"); !strings.Contains(out, "term_t1") {
		t.Fatalf("users: %s", out)
	}
	if out := post("deluser term_t1"); !strings.Contains(out, "отключён") {
		t.Fatalf("deluser: %s", out)
	}
	if out := post("rmuser term_t1"); !strings.Contains(out, "удалён") {
		t.Fatalf("rmuser: %s", out)
	}
	if out := post("run"); !strings.Contains(out, "только в командной строке") {
		t.Fatalf("run must be refused: %s", out)
	}
	if out := post("nonsense"); !strings.Contains(out, "неизвестная команда") {
		t.Fatalf("unknown: %s", out)
	}
	_ = ctx
}

func jsonStr(s string) string { b, _ := json.Marshal(s); return string(b) }

// The panel is one embedded page: its script must at least parse.
func TestPanelScriptParses(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	i, j := strings.Index(string(uiHTML), "<script>"), strings.LastIndex(string(uiHTML), "</script>")
	if i < 0 || j < i {
		t.Fatal("no script in ui.html")
	}
	f := filepath.Join(t.TempDir(), "ui.js")
	if err := os.WriteFile(f, uiHTML[i+8:j], 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(node, "--check", f).CombinedOutput(); err != nil {
		t.Fatalf("ui.html script: %v\n%s", err, out)
	}
}

// Alerts and backups go through bot_api_url too (a proxy with a key in the path).
func TestNotifierUsesProxy(t *testing.T) {
	got := make(chan string, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.URL.Path
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	n := &Notifier{token: "123:ABC", chat: "1", api: func() string { return srv.URL + "/KEY" }}
	n.Notify("k", "hello", time.Second)
	select {
	case p := <-got:
		if p != "/KEY/bot123:ABC/sendMessage" {
			t.Fatalf("path %q", p)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no request reached the proxy")
	}
}
