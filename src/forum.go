package main

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// Forum for bug reports and questions. Only logged-in users of the site read and write; an author is shown as "Пользователь #N"
// (no e-mail, no VPN name), the answers of the administrator as "Поддержка". Moderation is in the panel.

var forumKinds = map[string]string{"bug": "Ошибка", "question": "Вопрос", "idea": "Идея", "other": "Другое"}

const (
	forumTitleMax = 120
	forumBodyMax  = 4000
	forumPage     = 20
)

type ForumTopic struct {
	ID      int64  `json:"id"`
	Kind    string `json:"kind"`
	Title   string `json:"title"`
	Status  string `json:"status"`
	Pinned  bool   `json:"pinned"`
	Hidden  bool   `json:"hidden"`
	Author  string `json:"author"`
	Created int64  `json:"created"`
	Last    int64  `json:"last"`
	Posts   int    `json:"posts"`
}

type ForumPost struct {
	ID      int64       `json:"id"`
	Author  string      `json:"author"`
	Staff   bool        `json:"staff"`
	Body    string      `json:"body"`
	Hidden  bool        `json:"hidden"`
	Created int64       `json:"created"`
	Files   []ForumFile `json:"files"`
}

func authorLabel(accID *int64, staff bool) string {
	switch {
	case staff:
		return "Поддержка"
	case accID == nil:
		return "Удалённый пользователь"
	}
	return "Пользователь #" + strconv.FormatInt(*accID, 10)
}

// cleanForumText trims, checks the length and drops control characters (new lines stay).
func cleanForumText(s string, min, max int, what string) (string, error) {
	if !utf8.ValidString(s) {
		return "", fmt.Errorf("%s: неверная кодировка", what)
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r >= 32 && r != 127 {
			return r
		}
		return -1
	}, s)
	s = strings.TrimSpace(s)
	n := utf8.RuneCountInString(s)
	if n < min {
		return "", fmt.Errorf("%s слишком короткое (минимум %d символов)", what, min)
	}
	if n > max {
		return "", fmt.Errorf("%s слишком длинное (максимум %d символов)", what, max)
	}
	return s, nil
}

func (s *Store) CreateTopic(ctx context.Context, accID int64, kind, title, body string) (int64, error) {
	return s.CreateTopicA(ctx, accID, kind, title, body, nil)
}

func (s *Store) CreateTopicA(ctx context.Context, accID int64, kind, title, body string, atts []Attachment) (int64, error) {
	if _, ok := forumKinds[kind]; !ok {
		return 0, errors.New("неизвестный вид темы")
	}
	title, err := cleanForumText(strings.ReplaceAll(title, "\n", " "), 3, forumTitleMax, "заголовок")
	if err != nil {
		return 0, err
	}
	if body, err = cleanForumText(body, 5, forumBodyMax, "сообщение"); err != nil {
		return 0, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	var id int64
	if err := tx.QueryRow(ctx, `INSERT INTO forum_topics(account_id,kind,title) VALUES($1,$2,$3) RETURNING id`, accID, kind, title).Scan(&id); err != nil {
		return 0, err
	}
	var pid int64
	if err := tx.QueryRow(ctx, `INSERT INTO forum_posts(topic_id,account_id,body) VALUES($1,$2,$3) RETURNING id`, id, accID, body).Scan(&pid); err != nil {
		return 0, err
	}
	if err := addFiles(ctx, tx, pid, &accID, atts); err != nil {
		return 0, err
	}
	return id, tx.Commit(ctx)
}

// AddPost adds an answer. A user cannot write to a closed or hidden topic; the administrator can write to a closed one.
func (s *Store) AddPost(ctx context.Context, topicID int64, accID *int64, staff bool, body string) error {
	return s.AddPostA(ctx, topicID, accID, staff, body, nil)
}

func (s *Store) AddPostA(ctx context.Context, topicID int64, accID *int64, staff bool, body string, atts []Attachment) error {
	min := 2
	if staff && len(atts) > 0 {
		min = 0 // a staff message may be just a file
	}
	body, err := cleanForumText(body, min, forumBodyMax, "сообщение")
	if err != nil {
		return err
	}
	var status string
	var hidden bool
	if err := s.pool.QueryRow(ctx, `SELECT status, hidden FROM forum_topics WHERE id=$1`, topicID).Scan(&status, &hidden); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if !staff && (hidden || status == "closed") {
		return errors.New("тема закрыта")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var pid int64
	if err := tx.QueryRow(ctx, `INSERT INTO forum_posts(topic_id,account_id,staff,body) VALUES($1,$2,$3,$4) RETURNING id`, topicID, accID, staff, body).Scan(&pid); err != nil {
		return err
	}
	if err := addFiles(ctx, tx, pid, accID, atts); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE forum_topics SET last_post=now() WHERE id=$1`, topicID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) ListTopics(ctx context.Context, withHidden bool, limit, offset int) ([]ForumTopic, error) {
	rows, err := s.pool.Query(ctx, `SELECT t.id,t.kind,t.title,t.status,t.pinned,t.hidden,t.account_id,t.created,t.last_post,
		(SELECT count(*) FROM forum_posts p WHERE p.topic_id=t.id AND (NOT p.hidden OR $1))
		FROM forum_topics t WHERE (NOT t.hidden OR $1) ORDER BY t.pinned DESC, t.last_post DESC LIMIT $2 OFFSET $3`, withHidden, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ForumTopic{}
	for rows.Next() {
		var t ForumTopic
		var acc *int64
		var cr, last time.Time
		if err := rows.Scan(&t.ID, &t.Kind, &t.Title, &t.Status, &t.Pinned, &t.Hidden, &acc, &cr, &last, &t.Posts); err != nil {
			return nil, err
		}
		t.Author, t.Created, t.Last = authorLabel(acc, false), cr.Unix(), last.Unix()
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) GetTopic(ctx context.Context, id int64, withHidden bool) (*ForumTopic, []ForumPost, error) {
	var t ForumTopic
	var acc *int64
	var cr, last time.Time
	err := s.pool.QueryRow(ctx, `SELECT id,kind,title,status,pinned,hidden,account_id,created,last_post FROM forum_topics WHERE id=$1 AND (NOT hidden OR $2)`, id, withHidden).
		Scan(&t.ID, &t.Kind, &t.Title, &t.Status, &t.Pinned, &t.Hidden, &acc, &cr, &last)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	t.Author, t.Created, t.Last = authorLabel(acc, false), cr.Unix(), last.Unix()
	rows, err := s.pool.Query(ctx, `SELECT id,account_id,staff,body,hidden,created FROM forum_posts WHERE topic_id=$1 AND (NOT hidden OR $2) ORDER BY id LIMIT 500`, id, withHidden)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	posts := []ForumPost{}
	for rows.Next() {
		var p ForumPost
		var pacc *int64
		var pc time.Time
		if err := rows.Scan(&p.ID, &pacc, &p.Staff, &p.Body, &p.Hidden, &pc); err != nil {
			return nil, nil, err
		}
		p.Author, p.Created = authorLabel(pacc, p.Staff), pc.Unix()
		posts = append(posts, p)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	rows.Close()
	ids := make([]int64, len(posts))
	for i := range posts {
		ids[i] = posts[i].ID
	}
	files, err := s.filesOfPosts(ctx, ids)
	if err != nil {
		return nil, nil, err
	}
	for i := range posts {
		posts[i].Files = files[posts[i].ID]
	}
	t.Posts = len(posts)
	return &t, posts, nil
}

// TopicOp is a moderation action: close, open, pin, unpin, hide, show.
func (s *Store) TopicOp(ctx context.Context, id int64, op string) error {
	q := map[string]string{
		"close": `UPDATE forum_topics SET status='closed' WHERE id=$1`, "open": `UPDATE forum_topics SET status='open' WHERE id=$1`,
		"pin": `UPDATE forum_topics SET pinned=true WHERE id=$1`, "unpin": `UPDATE forum_topics SET pinned=false WHERE id=$1`,
		"hide": `UPDATE forum_topics SET hidden=true WHERE id=$1`, "show": `UPDATE forum_topics SET hidden=false WHERE id=$1`,
	}[op]
	if q == "" {
		return errors.New("операция: close, open, pin, unpin, hide или show")
	}
	tag, err := s.pool.Exec(ctx, q, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) PostOp(ctx context.Context, id int64, op string) error {
	if op != "hide" && op != "show" {
		return errors.New("операция: hide или show")
	}
	tag, err := s.pool.Exec(ctx, `UPDATE forum_posts SET hidden=$2 WHERE id=$1`, id, op == "hide")
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) DeleteTopic(ctx context.Context, id int64) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM forum_topics WHERE id=$1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// OpenTopics counts the topics that wait for an answer (open, the last post is not from the staff).
func (s *Store) OpenTopics(ctx context.Context) int {
	var n int
	_ = s.pool.QueryRow(ctx, `SELECT count(*) FROM forum_topics t WHERE status='open' AND NOT hidden AND
		NOT COALESCE((SELECT staff FROM forum_posts p WHERE p.topic_id=t.id AND NOT p.hidden ORDER BY id DESC LIMIT 1), false)`).Scan(&n)
	return n
}

// ---- the site ----

type forumTopicView struct {
	ID                          int64
	Kind, Title, Status, Author string
	Pinned                      bool
	Created, Last               string
	Posts                       int
	Open                        bool
}
type forumPostView struct {
	Author, Body, Created string
	Staff                 bool
	Images, Files         []ForumFile
}
type forumData struct {
	Topics              []forumTopicView
	Topic               forumTopicView
	Posts               []forumPostView
	Page                int
	Prev                int
	Next                int
	Kinds               [][2]string
	FormKind            string
	FormTitle, FormBody string
	AllowImages         bool
	AllowFiles          bool
}

// ForumMultipart is true when the forms carry attachments.
func (f forumData) Multipart() bool { return f.AllowImages || f.AllowFiles }

var forumKindOrder = []string{"bug", "question", "idea", "other"}

func forumKindList() [][2]string {
	var out [][2]string
	for _, k := range forumKindOrder {
		out = append(out, [2]string{k, forumKinds[k]})
	}
	return out
}

func fmtForumTime(unix int64) string {
	return time.Unix(unix, 0).In(time.FixedZone("MSK", 3*3600)).Format("02.01.2006 15:04")
}

func topicView(t ForumTopic) forumTopicView {
	return forumTopicView{ID: t.ID, Kind: forumKinds[t.Kind], Title: t.Title, Status: map[string]string{"open": "открыта", "closed": "закрыта"}[t.Status], Author: t.Author,
		Pinned: t.Pinned, Created: fmtForumTime(t.Created), Last: fmtForumTime(t.Last), Posts: t.Posts, Open: t.Status == "open"}
}

func (s *Site) forumList(w http.ResponseWriter, r *http.Request) {
	acc, h := s.authed(w, r)
	if acc == nil {
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("p"))
	if page < 1 || page > 1000 {
		page = 1
	}
	ts, err := s.st.ListTopics(r.Context(), false, forumPage+1, (page-1)*forumPage)
	d := s.base(r, acc, h, "Форум")
	if err != nil {
		d.Error = "Временная ошибка, попробуйте ещё раз"
	}
	f := forumData{Page: page}
	if len(ts) > forumPage {
		ts, f.Next = ts[:forumPage], page+1
	}
	if page > 1 {
		f.Prev = page - 1
	}
	for _, t := range ts {
		f.Topics = append(f.Topics, topicView(t))
	}
	d.Forum = f
	s.render(w, 200, "forum", d)
}

func (s *Site) forumNewPage(w http.ResponseWriter, r *http.Request) {
	acc, h := s.authed(w, r)
	if acc == nil {
		return
	}
	d := s.base(r, acc, h, "Новая тема")
	d.Forum = forumData{Kinds: forumKindList(), FormKind: "bug"}
	s.forumPerms(&d.Forum)
	s.render(w, 200, "forum_new", d)
}

func (s *Site) forumNewPost(w http.ResponseWriter, r *http.Request) {
	acc, h := s.authedPost(w, r)
	if acc == nil {
		return
	}
	d := s.base(r, acc, h, "Новая тема")
	kind, title, body := r.PostForm.Get("kind"), r.PostForm.Get("title"), r.PostForm.Get("body")
	d.Forum = forumData{Kinds: forumKindList(), FormKind: kind, FormTitle: title, FormBody: body}
	s.forumPerms(&d.Forum)
	fail := func(code int, msg string) {
		d.Error = msg
		s.render(w, code, "forum_new", d)
	}
	if s.forumLimit.blocked(acc.Username) {
		fail(429, "Слишком много сообщений. Попробуйте позже")
		return
	}
	atts, err := s.formAttachments(r, acc)
	if err != nil {
		fail(400, err.Error())
		return
	}
	id, err := s.st.CreateTopicA(r.Context(), acc.ID, kind, title, body, atts)
	if err != nil {
		fail(400, err.Error())
		return
	}
	s.forumLimit.hit(acc.Username)
	http.Redirect(w, r, "/forum/"+strconv.FormatInt(id, 10), http.StatusSeeOther)
}

func (s *Site) forumTopic(w http.ResponseWriter, r *http.Request) {
	acc, h := s.authed(w, r)
	if acc == nil {
		return
	}
	s.renderTopic(w, r, acc, h, 200, "", "")
}

func (s *Site) renderTopic(w http.ResponseWriter, r *http.Request, acc *Account, h string, code int, errMsg, draft string) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	t, posts, err := s.st.GetTopic(r.Context(), id, false)
	if err != nil {
		d := s.base(r, acc, h, "Не найдено")
		s.render(w, 404, "notfound", d)
		return
	}
	d := s.base(r, acc, h, t.Title)
	d.Error = errMsg
	f := forumData{Topic: topicView(*t), FormBody: draft}
	s.forumPerms(&f)
	for _, p := range posts {
		v := forumPostView{Author: p.Author, Body: p.Body, Created: fmtForumTime(p.Created), Staff: p.Staff}
		for _, fl := range p.Files {
			if fl.Kind == "image" {
				v.Images = append(v.Images, fl)
			} else {
				v.Files = append(v.Files, fl)
			}
		}
		f.Posts = append(f.Posts, v)
	}
	d.Forum = f
	s.render(w, code, "forum_topic", d)
}

func (s *Site) forumReply(w http.ResponseWriter, r *http.Request) {
	acc, h := s.authedPost(w, r)
	if acc == nil {
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if s.forumLimit.blocked(acc.Username) {
		s.renderTopic(w, r, acc, h, 429, "Слишком много сообщений. Попробуйте позже", r.PostForm.Get("body"))
		return
	}
	atts, aerr := s.formAttachments(r, acc)
	if aerr != nil {
		s.renderTopic(w, r, acc, h, 400, aerr.Error(), r.PostForm.Get("body"))
		return
	}
	if err := s.st.AddPostA(r.Context(), id, &acc.ID, false, r.PostForm.Get("body"), atts); err != nil {
		code := 400
		if errors.Is(err, ErrNotFound) {
			code = 404
		}
		s.renderTopic(w, r, acc, h, code, err.Error(), r.PostForm.Get("body"))
		return
	}
	s.forumLimit.hit(acc.Username)
	http.Redirect(w, r, "/forum/"+strconv.FormatInt(id, 10)+"#last", http.StatusSeeOther)
}

func (s *Site) forumPerms(f *forumData) {
	sc := s.cfg.getSite()
	f.AllowImages, f.AllowFiles = sc.ForumImages, sc.ForumFiles
}

func (s *Site) registerForum(mux *http.ServeMux) {
	mux.HandleFunc("GET /forum/file/{id}", s.forumFile)
	mux.HandleFunc("GET /forum", s.forumList)
	mux.HandleFunc("GET /forum/new", s.forumNewPage)
	mux.HandleFunc("POST /forum/new", s.forumNewPost)
	mux.HandleFunc("GET /forum/{id}", s.forumTopic)
	mux.HandleFunc("POST /forum/{id}/reply", s.forumReply)
}

const forumTplText = `
{{define "forum"}}{{template "head" .}}
<div class="row" style="justify-content:space-between"><h1 style="margin:0">Форум</h1><a class="btn sm" href="/forum/new">Новая тема</a></div>
<p class="muted">Сообщайте об ошибках и задавайте вопросы. Видят только вошедшие пользователи; ваше имя другим не показывается.</p>
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}
<div class="card">{{if .Forum.Topics}}<table>{{range .Forum.Topics}}<tr><td>{{if .Pinned}}📌 {{end}}<a href="/forum/{{.ID}}">{{.Title}}</a><div class="muted" style="font-size:12px">{{.Kind}} · {{.Author}} · {{.Created}}</div></td>
<td style="white-space:nowrap" class="muted">{{.Posts}} сообщ.<br>{{if not .Open}}закрыта{{else}}{{.Last}}{{end}}</td></tr>{{end}}</table>
{{else}}<p class="muted">Пока тем нет. Начните первую.</p>{{end}}
<div class="row">{{if .Forum.Prev}}<a class="btn s sm" href="/forum?p={{.Forum.Prev}}">← Новее</a>{{end}}{{if .Forum.Next}}<a class="btn s sm" href="/forum?p={{.Forum.Next}}">Старее →</a>{{end}}</div></div>
{{template "foot" .}}{{end}}

{{define "attach"}}{{if .Forum.AllowImages}}<label for="img">Картинка (PNG, JPEG, GIF или WebP, до 1 МБ; не обязательно)</label><input id="img" type="file" name="image" accept="image/png,image/jpeg,image/gif,image/webp">{{end}}
{{if .Forum.AllowFiles}}<label for="fil">Файл (до 10 МБ; не обязательно)</label><input id="fil" type="file" name="file">{{end}}{{end}}

{{define "forum_new"}}{{template "head" .}}
<div class="card"><h1>Новая тема</h1>{{if .Error}}<div class="err">{{.Error}}</div>{{end}}
<form method="post" action="/forum/new"{{if .Forum.Multipart}} enctype="multipart/form-data"{{end}}><input type="hidden" name="csrf" value="{{.CSRF}}">
<label for="kind">Тип</label><select id="kind" name="kind" style="padding:10px;border-radius:10px;border:1px solid var(--line);background:var(--bg);color:var(--text)">{{$k := .Forum.FormKind}}{{range .Forum.Kinds}}<option value="{{index . 0}}"{{if eq (index . 0) $k}} selected{{end}}>{{index . 1}}</option>{{end}}</select>
<label for="title">Заголовок</label><input id="title" type="text" name="title" value="{{.Forum.FormTitle}}" required maxlength="120">
<label for="body">Что случилось (приложение, устройство, что делали, что увидели)</label>
<textarea id="body" name="body" required maxlength="4000" rows="8" style="width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:10px;background:var(--bg);color:var(--text);font:inherit">{{.Forum.FormBody}}</textarea>
{{template "attach" .}}
<p class="muted" style="font-size:13px">Не публикуйте ссылку подписки, ключи и пароли.</p>
<p><button class="btn">Создать</button> <a class="btn s" href="/forum">Отмена</a></p></form></div>
{{template "foot" .}}{{end}}

{{define "forum_topic"}}{{template "head" .}}
<p><a href="/forum">← Все темы</a></p>
<h1 style="margin-bottom:4px">{{if .Forum.Topic.Pinned}}📌 {{end}}{{.Forum.Topic.Title}}</h1>
<div class="muted" style="margin-bottom:14px">{{.Forum.Topic.Kind}} · {{.Forum.Topic.Author}} · {{.Forum.Topic.Created}} · {{.Forum.Topic.Status}}</div>
{{range .Forum.Posts}}<div class="post{{if .Staff}} staff{{end}}"><div class="who"><b>{{.Author}}</b>{{if .Staff}} <span class="badge acc">поддержка</span>{{end}} · {{.Created}}</div>{{if .Body}}<div class="body">{{.Body}}</div>{{end}}
{{if or .Images .Files}}<div class="att">{{range .Images}}<a href="/forum/file/{{.ID}}" target="_blank" rel="noopener"><img loading="lazy" alt="{{.Name}}" src="/forum/file/{{.ID}}"></a>{{end}}{{range .Files}}<a class="file" href="/forum/file/{{.ID}}">📎 {{.Name}} <span class="muted">{{.SizeText}}</span></a>{{end}}</div>{{end}}</div>{{end}}
<span id="last"></span>
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}
{{if .Forum.Topic.Open}}<div class="card"><form method="post" action="/forum/{{.Forum.Topic.ID}}/reply"{{if .Forum.Multipart}} enctype="multipart/form-data"{{end}}><input type="hidden" name="csrf" value="{{.CSRF}}">
<label for="body">Ответ</label><textarea id="body" name="body" required maxlength="4000" rows="5" style="width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:10px;background:var(--bg);color:var(--text);font:inherit">{{.Forum.FormBody}}</textarea>
{{template "attach" .}}
<p><button class="btn">Отправить</button></p></form></div>{{else}}<p class="muted">Тема закрыта.</p>{{end}}
{{template "foot" .}}{{end}}
`

func init() {
	template.Must(siteTpl.Parse(forumTplText))
}
