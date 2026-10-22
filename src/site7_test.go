package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func pngBytes(w, h int) []byte {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for x := 0; x < w; x++ {
		for y := 0; y < h; y++ {
			img.Set(x, y, color.RGBA{uint8(x * 7), uint8(y * 5), uint8(x ^ y), 255})
		}
	}
	var b bytes.Buffer
	png.Encode(&b, img)
	return b.Bytes()
}

type part struct {
	field, name string
	data        []byte
}

func (s *siteClient) multipart(path string, fields map[string]string, parts []part) (int, string, http.Header) {
	s.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		mw.WriteField(k, v)
	}
	for _, p := range parts {
		fw, _ := mw.CreateFormFile(p.field, p.name)
		fw.Write(p.data)
	}
	mw.Close()
	req, _ := http.NewRequest("POST", s.srv.URL+path, &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Origin", s.srv.URL)
	resp, err := s.c.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

func (s *siteClient) raw(path string) (int, []byte, http.Header) {
	s.t.Helper()
	resp, err := s.c.Get(s.srv.URL + path)
	if err != nil {
		s.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, resp.Header
}

func TestSiteThemeAndPalette(t *testing.T) {
	cfg := siteTestCfg()
	_, _, srv := startSite(t, cfg)
	c := newSiteClient(t, srv)
	_, body, _ := c.get("/")
	if !strings.Contains(body, `data-theme="auto"`) || !strings.Contains(body, `data-palette="blue"`) || !strings.Contains(body, "/site.css?v=") {
		t.Fatalf("defaults: %.300s", body)
	}
	code, css, h := c.get("/site.css")
	if code != 200 || !strings.HasPrefix(h.Get("Content-Type"), "text/css") || !strings.Contains(css, "html[data-theme=dark]") || !strings.Contains(css, "data-palette=violet") {
		t.Fatalf("css: %d %s", code, h.Get("Content-Type"))
	}
	if code, _, h := c.get("/prefs?theme=dark&palette=green&back=/help"); code != 303 || h.Get("Location") != "/help" {
		t.Fatalf("prefs: %d %s", code, h.Get("Location"))
	}
	_, body, _ = c.get("/help")
	if !strings.Contains(body, `data-theme="dark"`) || !strings.Contains(body, `data-palette="green"`) {
		t.Fatalf("choice not applied: %.200s", body)
	}
	// nothing but a path of this site is accepted for returning
	for _, bad := range []string{"//evil.example", "https://evil.example/", "/\\evil.example", "javascript:alert(1)"} {
		if _, _, h := c.get("/prefs?back=" + url.QueryEscape(bad)); h.Get("Location") != "/" {
			t.Errorf("back=%q -> %q", bad, h.Get("Location"))
		}
	}
	c.get("/prefs?theme=evil&palette=%3Cscript%3E")
	_, body, _ = c.get("/help")
	if !strings.Contains(body, `data-theme="dark"`) || strings.Contains(body, "<script>") && strings.Contains(body, "evil") {
		t.Error("an invalid choice must change nothing")
	}
	// the default of the administrator, a custom colour
	cfg.SiteTheme, cfg.SitePalette, cfg.SiteAccent = "light", "custom", "#ffcc00"
	o := newSiteClient(t, srv)
	_, body, _ = o.get("/")
	if !strings.Contains(body, `data-theme="light"`) || !strings.Contains(body, "--accent:#ffcc00") || !strings.Contains(body, "--on-accent:#0b0f14") {
		t.Fatalf("custom accent: %.400s", body)
	}
	cfg.SiteAccent = "javascript"
	_, body, _ = newSiteClient(t, srv).get("/")
	if strings.Contains(body, "--accent:javascript") || !strings.Contains(body, `data-palette="blue"`) {
		t.Error("a bad custom colour must fall back")
	}
	for _, k := range []string{"site_theme", "site_palette", "site_accent", "forum_images", "forum_files"} {
		found := false
		for _, d := range settingDefs {
			found = found || d.key == k
		}
		if !found {
			t.Errorf("setting %s is missing", k)
		}
	}
}

func TestMarkdownIsSafe(t *testing.T) {
	out := string(renderMD("# Заголовок\n\n<script>alert(1)</script> **жирный** `код`\n- один\n- два\n\n1. первый\n2. второй\n\n[ссылка](https://example.com/a?b=1&c=2) [плохая](javascript:alert(1)) [x](https://a.com/\"onmouseover=\"alert(1))"))
	for _, want := range []string{"<h2>Заголовок</h2>", "<b>жирный</b>", "<code>код</code>", "<ul><li>один</li><li>два</li></ul>", "<ol><li>первый</li><li>второй</li></ol>", `href="https://example.com/a?b=1&amp;c=2"`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %s", want, out)
		}
	}
	if strings.Contains(out, "<script>") || strings.Contains(out, `href="javascript`) || regexp.MustCompile(`"onmouseover=`).MatchString(out) {
		t.Errorf("unsafe output: %s", out)
	}
}

func TestSiteHelpPagesAndAdminAPI(t *testing.T) {
	cfg := siteTestCfg()
	_, st, srv := startSite(t, cfg)
	ctx := context.Background()
	st.pool.Exec(ctx, "DELETE FROM site_pages")
	st.pool.Exec(ctx, "DELETE FROM settings WHERE key='pages_seeded'")
	if err := st.seedPages(ctx); err != nil {
		t.Fatal(err)
	}
	ps, _ := st.ListPages(ctx, true)
	if len(ps) < 5 {
		t.Fatalf("sample pages: %d", len(ps))
	}
	c := newSiteClient(t, srv)
	code, body, _ := c.get("/help")
	if code != 200 || !strings.Contains(body, "/help/start") || !strings.Contains(body, "Android") {
		t.Fatalf("index: %d", code)
	}
	if code, body, _ := c.get("/help/start"); code != 200 || !strings.Contains(body, "Три шага") {
		t.Fatalf("page: %d", code)
	}
	if code, _, _ := c.get("/help/nope"); code != 404 {
		t.Fatalf("missing page: %d", code)
	}

	a := NewAPI(cfg, st, nil, nil, "tok", make(chan struct{}, 1))
	mux := http.NewServeMux()
	a.Register(mux)
	h := &adminT{t: t, mux: mux}
	if code, _, _ := h.do("PUT", "/api/site/pages/draft", map[string]any{"title": "Черновик", "body": "<b>x</b>", "sort": 9, "published": false}); code != 200 {
		t.Fatalf("save: %d", code)
	}
	if code, _, _ := c.get("/help/draft"); code != 404 {
		t.Errorf("unpublished page is public: %d", code)
	}
	if code, _, _ := h.do("PUT", "/api/site/pages/Bad_Slug", map[string]any{"title": "x"}); code != 400 {
		t.Errorf("bad slug: %d", code)
	}
	if code, _, _ := h.do("PUT", "/api/site/pages/empty", map[string]any{"title": ""}); code != 400 {
		t.Errorf("empty title: %d", code)
	}
	h.do("PUT", "/api/site/pages/draft", map[string]any{"title": "Черновик", "body": "<b>x</b>", "sort": 9, "published": true})
	if _, body, _ := c.get("/help/draft"); strings.Contains(body, "<b>x</b>") || !strings.Contains(body, "&lt;b&gt;x&lt;/b&gt;") {
		t.Errorf("page text is not escaped")
	}
	if code, _, _ := h.do("DELETE", "/api/site/pages/draft", nil); code != 200 {
		t.Fatalf("delete: %d", code)
	}
	if code, _, _ := h.do("DELETE", "/api/site/pages/draft", nil); code != 404 {
		t.Errorf("delete twice: %d", code)
	}
	if code, _, _ := (&adminT{t: t, mux: mux}).do("GET", "/api/site/pages", nil); code != 200 {
		t.Errorf("list: %d", code)
	}
}

func TestForumAttachments(t *testing.T) {
	cfg := siteTestCfg()
	_, st, srv := startSite(t, cfg)
	ctx := context.Background()
	st.pool.Exec(ctx, "TRUNCATE forum_topics CASCADE")
	c := newSiteClient(t, srv)
	c.register("att", "password1")
	tok := c.csrf()
	img := pngBytes(40, 30)
	newTopic := func(parts []part) (int, string, string) {
		code, body, h := c.multipart("/forum/new", map[string]string{"csrf": tok, "kind": "bug", "title": "С картинкой", "body": "Смотрите вложение"}, parts)
		return code, body, h.Get("Location")
	}

	// defaults: pictures allowed, files not
	if _, body, _ := c.get("/forum/new"); !strings.Contains(body, `name="image"`) || strings.Contains(body, `name="file"`) {
		t.Fatalf("form must offer pictures only")
	}
	if code, body, _ := newTopic([]part{{"file", "a.zip", []byte("PK data")}}); code != 400 || !strings.Contains(body, "файлы сейчас нельзя") {
		t.Fatalf("file while forbidden: %d", code)
	}
	if code, body, _ := newTopic([]part{{"image", "x.png", []byte("not a picture at all")}}); code != 400 || !strings.Contains(body, "не картинка") {
		t.Fatalf("fake picture: %d", code)
	}
	if code, body, _ := newTopic([]part{{"image", "x.svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)}}); code != 400 {
		t.Fatalf("svg accepted: %d %s", code, body)
	}
	big := append(pngBytes(300, 300), make([]byte, forumImageMax)...) // a valid picture followed by padding, over 1 MB
	if code, body, _ := newTopic([]part{{"image", "big.png", big}}); code != 400 || !strings.Contains(body, "больше 1 МБ") {
		t.Fatalf("big picture: %d", code)
	}
	code, _, loc := newTopic([]part{{"image", "../../evil name\".png", img}})
	if code != 303 {
		t.Fatalf("picture rejected: %d", code)
	}
	_, page, _ := c.get(loc)
	m := regexp.MustCompile(`/forum/file/(\d+)`).FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no picture on the page: %.500s", page)
	}
	code, data, h := c.raw("/forum/file/" + m[1])
	if code != 200 || h.Get("Content-Type") != "image/png" || !bytes.Equal(data, img) || h.Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(h.Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("picture: %d %s", code, h.Get("Content-Type"))
	}
	if !strings.HasPrefix(h.Get("Content-Disposition"), "inline") || strings.Contains(h.Get("Content-Disposition"), "..") || strings.Contains(h.Get("Content-Disposition"), "/") {
		t.Errorf("disposition: %s", h.Get("Content-Disposition"))
	}
	// a stranger who is not logged in gets nothing
	if code, _, _ := newSiteClient(t, srv).get("/forum/file/" + m[1]); code != 303 {
		t.Errorf("anonymous access: %d", code)
	}

	// the administrator allows files
	on := true
	cfg.ForumFiles = &on
	if _, body, _ := c.get(loc); !strings.Contains(body, `name="file"`) {
		t.Fatal("form must offer files now")
	}
	payload := append([]byte("<html><script>alert(1)</script></html>"), make([]byte, 5000)...)
	id := strings.TrimPrefix(loc, "/forum/")
	if code, _, _ := c.multipart("/forum/"+id+"/reply", map[string]string{"csrf": tok, "body": "вот файл"}, []part{{"file", "страница.html", payload}}); code != 303 {
		t.Fatalf("reply with file: %d", code)
	}
	_, page, _ = c.get(loc)
	m2 := regexp.MustCompile(`href="/forum/file/(\d+)">📎`).FindStringSubmatch(page)
	if m2 == nil {
		t.Fatalf("file link missing: %.800s", page)
	}
	code, data, h = c.raw("/forum/file/" + m2[1])
	if code != 200 || h.Get("Content-Type") != "application/octet-stream" || !strings.HasPrefix(h.Get("Content-Disposition"), "attachment") || !bytes.Equal(data, payload) {
		t.Fatalf("file must download as an attachment: %d %s %s", code, h.Get("Content-Type"), h.Get("Content-Disposition"))
	}
	over := make([]byte, forumFileMax+10)
	if code, body, _ := c.multipart("/forum/"+id+"/reply", map[string]string{"csrf": tok, "body": "огромный"}, []part{{"file", "big.bin", over}}); code != 400 || !strings.Contains(body, "10 МБ") {
		t.Fatalf("file over 10 MB: %d", code)
	}
	// a request without the CSRF token is refused whatever it carries
	if code, _, _ := c.multipart("/forum/"+id+"/reply", map[string]string{"body": "без токена"}, []part{{"image", "a.png", img}}); code != 403 {
		t.Errorf("no csrf: %d", code)
	}
	// switched off again: new pictures are refused too
	off := false
	cfg.ForumImages = &off
	if code, body, _ := c.multipart("/forum/"+id+"/reply", map[string]string{"csrf": tok, "body": "ещё"}, []part{{"image", "a.png", img}}); code != 400 || !strings.Contains(body, "картинки сейчас нельзя") {
		t.Fatalf("pictures switched off: %d", code)
	}
	// hidden message: its files are not served to users
	var postID int64
	st.pool.QueryRow(ctx, `SELECT post_id FROM forum_files WHERE id=$1`, m[1]).Scan(&postID)
	st.PostOp(ctx, postID, "hide")
	if code, _, _ := c.raw("/forum/file/" + m[1]); code != 404 {
		t.Errorf("file of a hidden message: %d", code)
	}
	// the quota of an account
	var acc int64
	st.pool.QueryRow(ctx, `SELECT id FROM accounts WHERE username='att'`).Scan(&acc)
	st.pool.Exec(ctx, `UPDATE forum_files SET size=$2 WHERE id=$1`, m2[1], int64(forumUserQuota))
	if code, body, _ := c.multipart("/forum/"+id+"/reply", map[string]string{"csrf": tok, "body": "ещё"}, []part{{"file", "q.bin", []byte("1234567890")}}); code != 400 || !strings.Contains(body, "лимит вложений") {
		t.Fatalf("quota: %d %s", code, body)
	}
}

func TestAdminForumAttachmentsHaveNoLimits(t *testing.T) {
	cfg := siteTestCfg()
	_, st, _ := startSite(t, cfg)
	ctx := context.Background()
	st.pool.Exec(ctx, "TRUNCATE forum_topics CASCADE")
	acc, _ := st.CreateAccount(ctx, "adm2", "h", 3)
	tid, _ := st.CreateTopic(ctx, acc.ID, "bug", "Для админа", "Вопрос по файлам")
	a := NewAPI(cfg, st, nil, nil, "tok", make(chan struct{}, 1))
	mux := http.NewServeMux()
	a.Register(mux)
	send := func(parts []part, body string) (int, []byte) {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		mw.WriteField("body", body)
		for _, p := range parts {
			fw, _ := mw.CreateFormFile(p.field, p.name)
			fw.Write(p.data)
		}
		mw.Close()
		req := httptest.NewRequest("POST", fmt.Sprintf("/api/forum/topics/%d/reply", tid), &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("Authorization", "Bearer tok")
		req.RemoteAddr = "10.8.0.1:1"
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr.Code, rr.Body.Bytes()
	}
	bigImg := append(pngBytes(50, 50), make([]byte, 3<<20)...) // more than users may send
	bigFile := make([]byte, 12<<20)
	code, out := send([]part{{"file", "big.png", bigImg}, {"file", "huge.bin", bigFile}}, "")
	if code != 200 {
		t.Fatalf("staff upload: %d %s", code, out)
	}
	_, posts, _ := st.GetTopic(ctx, tid, true)
	last := posts[len(posts)-1]
	if !last.Staff || len(last.Files) != 2 || last.Files[0].Kind != "image" || last.Files[1].Kind != "file" {
		t.Fatalf("staff post: %+v", last)
	}
	// the answer works even with a picture only, and a bad picture is still refused for being no picture? no: it is just a file
	if code, _ := send([]part{{"file", "notes.txt", []byte("plain text")}}, ""); code != 200 {
		t.Fatalf("file only: %d", code)
	}
	if code, _ := send(nil, ""); code != 400 {
		t.Errorf("empty answer: %d", code)
	}
	h := &adminT{t: t, mux: mux}
	req := httptest.NewRequest("GET", fmt.Sprintf("/api/forum/files/%d", last.Files[0].ID), nil)
	req.Header.Set("Authorization", "Bearer tok")
	req.RemoteAddr = "10.8.0.2:1"
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != 200 || rr.Header().Get("Content-Type") != "image/png" || rr.Body.Len() != len(bigImg) {
		t.Errorf("download: %d %s", rr.Code, rr.Header().Get("Content-Type"))
	}
	if code, _, _ := h.do("DELETE", fmt.Sprintf("/api/forum/files/%d", last.Files[0].ID), nil); code != 200 {
		t.Errorf("delete file: %d", code)
	}
	// deleting the topic takes the files with it
	h.do("DELETE", fmt.Sprintf("/api/forum/topics/%d", tid), nil)
	var n int
	st.pool.QueryRow(ctx, `SELECT count(*) FROM forum_files`).Scan(&n)
	if n != 0 {
		t.Errorf("files left after the topic: %d", n)
	}
}

func TestSubscriptionHeadersShowUsageAndExpiry(t *testing.T) {
	cfg := siteTestCfg()
	_, st, srv := startSite(t, cfg)
	ctx := context.Background()
	c := newSiteClient(t, srv)
	c.register("hdr", "password1")
	acc, _ := st.AccountByUsername(ctx, "hdr")
	st.pool.Exec(ctx, `INSERT INTO traffic_hourly(hour,user_name,up,down,conns) VALUES(date_trunc('hour',now()),$1,2048,1048576,3)`, acc.Username)
	u, _ := st.UserBySubToken(ctx, acc.SubToken)
	code, _, h := c.get("/sub/" + u.SubToken)
	if code != 200 {
		t.Fatalf("sub: %d", code)
	}
	ui := h.Get("subscription-userinfo")
	if !strings.Contains(ui, "upload=2048") || !strings.Contains(ui, "download=1048576") || !strings.Contains(ui, "total=0") || !regexp.MustCompile(`expire=\d{10}`).MatchString(ui) {
		t.Fatalf("userinfo: %q", ui)
	}
	title := h.Get("profile-title")
	if !strings.HasPrefix(title, "base64:") {
		t.Fatalf("title: %q", title)
	}
	raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(title, "base64:"))
	if want := cfg.SiteName + " · hdr"; string(raw) != want {
		t.Fatalf("title %q, want %q (the VPN name, a dot, the nick; no traffic in the name)", raw, want)
	}
	if err := st.SetNick(ctx, acc.Username, "Миша"); err != nil {
		t.Fatal(err)
	}
	_, _, h = c.get("/sub/" + u.SubToken)
	raw, _ = base64.StdEncoding.DecodeString(strings.TrimPrefix(h.Get("profile-title"), "base64:"))
	if string(raw) != cfg.SiteName+" · Миша" {
		t.Fatalf("title after nick change: %q", raw)
	}
	if st.SetNick(ctx, acc.Username, "  ") == nil || st.SetNick(ctx, acc.Username, "a<b") == nil || st.SetNick(ctx, acc.Username, strings.Repeat("я", 33)) == nil {
		t.Error("bad nicks must be refused")
	}
	st.pool.Exec(ctx, `UPDATE users SET expires_at=NULL WHERE name=$1`, acc.Username)
	_, _, h = c.get("/sub/" + u.SubToken)
	if !strings.Contains(h.Get("subscription-userinfo"), "expire=0") {
		t.Errorf("no end date means expire=0: %q", h.Get("subscription-userinfo"))
	}
	if h.Get("announce") != "" || !strings.Contains(h.Get("subscription-userinfo"), "expire=0") {
		t.Errorf("an unlimited subscription is shown by the traffic line alone (no second line): %q %q", h.Get("announce"), h.Get("subscription-userinfo"))
	}
}
