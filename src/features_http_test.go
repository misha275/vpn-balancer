package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestSiteForumFlow(t *testing.T) {
	cfg := siteTestCfg()
	_, st, srv := startSite(t, cfg)
	st.pool.Exec(context.Background(), "TRUNCATE forum_topics CASCADE")
	anon := newSiteClient(t, srv)
	if code, _, h := anon.get("/forum"); code != 303 || h.Get("Location") != "/login" {
		t.Fatalf("forum without login: %d", code)
	}
	c := newSiteClient(t, srv)
	if code, _ := c.register("ann@example.com", "password1"); code != 303 {
		t.Fatalf("register: %d", code)
	}
	if code, body, _ := c.get("/cabinet"); code != 200 || !strings.Contains(body, `href="/forum"`) {
		t.Fatalf("no forum link in the cabinet: %d", code)
	}
	tok := c.csrf()
	if code, _, _ := c.post("/forum/new", url.Values{"kind": {"bug"}, "title": {"Тема без токена"}, "body": {"Текст сообщения"}}, true); code != 403 {
		t.Fatalf("no csrf: %d", code)
	}
	if code, body, _ := c.post("/forum/new", url.Values{"csrf": {tok}, "kind": {"bug"}, "title": {"x"}, "body": {"Текст сообщения"}}, true); code != 400 || !strings.Contains(body, "короткое") {
		t.Fatalf("short title: %d", code)
	}
	code, _, h := c.post("/forum/new", url.Values{"csrf": {tok}, "kind": {"bug"}, "title": {"<b>Не открывается</b> сайт"}, "body": {"Пишет <script>alert(1)</script> ошибку"}}, true)
	if code != 303 || !strings.HasPrefix(h.Get("Location"), "/forum/") {
		t.Fatalf("create: %d %s", code, h.Get("Location"))
	}
	loc := h.Get("Location")
	_, body, _ := c.get(loc)
	if strings.Contains(body, "<script>alert") || strings.Contains(body, "<b>Не") {
		t.Error("topic text is not escaped")
	}
	if !strings.Contains(body, "Пользователь #") || strings.Contains(body, "ann@example.com") {
		t.Error("author must be anonymous")
	}
	if code, _, _ := c.post(loc+"/reply", url.Values{"csrf": {tok}, "body": {"Дополнение"}}, true); code != 303 {
		t.Fatalf("reply: %d", code)
	}
	// another user sees the topic, not the e-mail
	o := newSiteClient(t, srv)
	o.register("bob@example.com", "password1")
	_, list, _ := o.get("/forum")
	if !strings.Contains(list, "Не открывается") || strings.Contains(list, "ann@example.com") {
		t.Error("list wrong")
	}
	// the administrator closes it: users cannot answer any more
	tid := strings.TrimPrefix(loc, "/forum/")
	var id int64
	fmt.Sscan(tid, &id)
	st.TopicOp(context.Background(), id, "close")
	if code, body, _ := c.post(loc+"/reply", url.Values{"csrf": {tok}, "body": {"Ещё"}}, true); code != 400 || !strings.Contains(body, "закрыта") {
		t.Fatalf("reply to closed: %d", code)
	}
	st.TopicOp(context.Background(), id, "hide")
	if code, _, _ := c.get(loc); code != 404 {
		t.Fatalf("hidden topic: %d", code)
	}
	// rate limit
	st.TopicOp(context.Background(), id, "show")
	st.TopicOp(context.Background(), id, "open")
	var last int
	for i := 0; i < 12; i++ {
		last, _, _ = c.post(loc+"/reply", url.Values{"csrf": {tok}, "body": {fmt.Sprintf("сообщение %d", i)}}, true)
	}
	if last != 429 {
		t.Errorf("limiter did not stop the flood: %d", last)
	}
}

func TestSiteBlockedAccountMessages(t *testing.T) {
	cfg := siteTestCfg()
	_, st, srv := startSite(t, cfg)
	c := newSiteClient(t, srv)
	c.register("cat@example.com", "password1")
	if err := st.BlockUser(context.Background(), "cat@example.com", "unpaid", "Нужно продлить"); err != nil {
		t.Fatal(err)
	}
	if _, body, _ := c.get("/cabinet"); !strings.Contains(body, "Нужно продлить") {
		t.Error("cabinet does not show the reason")
	}
	if err := st.BlockUser(context.Background(), "cat@example.com", "ban", "Нарушение правил"); err != nil {
		t.Fatal(err)
	}
	o := newSiteClient(t, srv)
	code, body, _ := o.post("/login", url.Values{"email": {"cat@example.com"}, "password": {"password1"}}, true)
	if code == 303 || !strings.Contains(body, "Нарушение правил") {
		t.Errorf("banned login: %d", code)
	}
}

func TestAdminForumBackupBlockAPI(t *testing.T) {
	cfg := siteTestCfg()
	cfg.BackupDir = t.TempDir()
	st := testStore(t)
	ctx := context.Background()
	st.pool.Exec(ctx, "TRUNCATE accounts, forum_topics CASCADE")
	a := NewAPI(cfg, st, nil, nil, "tok", make(chan struct{}, 1))
	mux := http.NewServeMux()
	a.Register(mux)
	h := &adminT{t: t, mux: mux}

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/api/backups", nil))
	if rr.Code != 401 {
		t.Fatalf("backups need a token: %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/api/forum/topics", nil))
	if rr.Code != 401 {
		t.Fatalf("forum needs a token: %d", rr.Code)
	}

	acc, _ := st.CreateAccount(ctx, "adm@example.com", "h", 3)
	tid, _ := st.CreateTopic(ctx, acc.ID, "idea", "Идея для панели", "Хорошая идея")
	code, m, _ := h.do("GET", "/api/forum/topics", nil)
	if code != 200 || m["topics"] == nil {
		t.Fatalf("topics: %d %v", code, m)
	}
	if code, _, _ := h.do("POST", fmt.Sprintf("/api/forum/topics/%d/reply", tid), map[string]any{"body": "Спасибо, учтём"}); code != 200 {
		t.Fatalf("staff reply: %d", code)
	}
	if code, _, _ := h.do("POST", fmt.Sprintf("/api/forum/topics/%d/close", tid), nil); code != 200 {
		t.Fatalf("close: %d", code)
	}
	if code, _, _ := h.do("POST", fmt.Sprintf("/api/forum/topics/%d/explode", tid), nil); code != 400 {
		t.Errorf("bad op: %d", code)
	}
	if code, _, _ := h.do("POST", "/api/forum/topics/999999/close", nil); code != 404 {
		t.Errorf("missing topic: %d", code)
	}
	if code, _, _ := h.do("DELETE", fmt.Sprintf("/api/forum/topics/%d", tid), nil); code != 200 {
		t.Fatalf("delete: %d", code)
	}

	// block / unblock through the API
	if code, _, _ := h.do("POST", "/api/users/adm@example.com/block", map[string]any{"kind": "ban", "reason": "тест"}); code != 200 {
		t.Fatalf("block: %d", code)
	}
	if code, _, _ := h.do("POST", "/api/users/adm@example.com/block", map[string]any{"kind": "zzz"}); code != 400 {
		t.Errorf("bad kind: %d", code)
	}
	if code, _, _ := h.do("POST", "/api/users/adm@example.com/unblock", nil); code != 200 {
		t.Fatalf("unblock: %d", code)
	}

	// backups
	code, m, _ = h.do("POST", "/api/backups", nil)
	if code != 200 {
		t.Fatalf("backup create: %d %v", code, m)
	}
	name := m["backup"].(map[string]any)["name"].(string)
	code, m, _ = h.do("GET", "/api/backups", nil)
	if code != 200 || len(m["backups"].([]any)) != 1 {
		t.Fatalf("list: %d %v", code, m)
	}
	if code, _, body := h.do("GET", "/api/backups/"+name, nil); code != 200 || len(body) < 100 {
		t.Fatalf("download: %d", code)
	}
	if code, _, _ := h.do("GET", "/api/backups/..%2Fetc%2Fpasswd", nil); code == 200 {
		t.Error("path traversal")
	}
	if code, _, _ := h.do("POST", "/api/backups/"+name+"/restore", nil); code != 200 {
		t.Fatalf("restore: %d", code)
	}
	if code, _, _ := h.do("POST", "/api/backups/restore", nil); code != 400 {
		t.Errorf("empty upload: %d", code)
	}
	if code, _, _ := h.do("DELETE", "/api/backups/"+name, nil); code != 200 {
		t.Fatalf("delete: %d", code)
	}
}
