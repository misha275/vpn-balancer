package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"net/http"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
)

// The "Инструкции" section of the site: short pages written by the administrator (the panel has an editor, tab "Сайт").
// The text is plain with a few marks: "# " and "## " headings, "- " lists, "1. " numbered lists, **bold**, `code`, [text](https://link).
// Everything is escaped first, so a page can never carry markup or script.

type SitePage struct {
	Slug      string `json:"slug"`
	Title     string `json:"title"`
	Body      string `json:"body"`
	Sort      int    `json:"sort"`
	Published bool   `json:"published"`
}

var rePageSlug = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

func (s *Store) ListPages(ctx context.Context, onlyPublished bool) ([]SitePage, error) {
	rows, err := s.pool.Query(ctx, `SELECT slug,title,body,sort,published FROM site_pages WHERE (published OR NOT $1) ORDER BY sort, slug`, onlyPublished)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SitePage{}
	for rows.Next() {
		var p SitePage
		if err := rows.Scan(&p.Slug, &p.Title, &p.Body, &p.Sort, &p.Published); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetPage(ctx context.Context, slug string, onlyPublished bool) (*SitePage, error) {
	var p SitePage
	err := s.pool.QueryRow(ctx, `SELECT slug,title,body,sort,published FROM site_pages WHERE slug=$1 AND (published OR NOT $2)`, slug, onlyPublished).
		Scan(&p.Slug, &p.Title, &p.Body, &p.Sort, &p.Published)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &p, err
}

func (s *Store) SavePage(ctx context.Context, p SitePage) error {
	p.Title = strings.TrimSpace(p.Title)
	if !rePageSlug.MatchString(p.Slug) {
		return errors.New("адрес страницы: латиница, цифры и дефис, до 40 символов")
	}
	if p.Title == "" || len([]rune(p.Title)) > 100 {
		return errors.New("название: от 1 до 100 символов")
	}
	if len(p.Body) > 60000 {
		return errors.New("текст длиннее 60 000 символов")
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO site_pages(slug,title,body,sort,published) VALUES($1,$2,$3,$4,$5)
		ON CONFLICT (slug) DO UPDATE SET title=EXCLUDED.title, body=EXCLUDED.body, sort=EXCLUDED.sort, published=EXCLUDED.published, updated=now()`,
		p.Slug, p.Title, p.Body, p.Sort, p.Published)
	return err
}

func (s *Store) DeletePage(ctx context.Context, slug string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM site_pages WHERE slug=$1`, slug)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// seedPages writes the sample instructions on the first start (the administrator edits or deletes them; deleting all is respected).
func (s *Store) seedPages(ctx context.Context) error {
	var done bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM settings WHERE key='pages_seeded') OR EXISTS(SELECT 1 FROM site_pages)`).Scan(&done); err != nil {
		return err
	}
	if done {
		return nil
	}
	for _, p := range defaultPages {
		if err := s.SavePage(ctx, p); err != nil {
			return err
		}
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO settings(key,value) VALUES('pages_seeded','true') ON CONFLICT DO NOTHING`)
	return err
}

var defaultPages = []SitePage{
	{Slug: "start", Title: "Быстрый старт", Sort: 1, Published: true, Body: `## Три шага
1. Зарегистрируйтесь на сайте и откройте **Кабинет**.
2. Скопируйте **ссылку подписки** (или отсканируйте QR-код с телефона).
3. Установите приложение для вашего устройства (см. инструкции ниже), добавьте подписку по ссылке и обновите её.

После обновления в приложении появятся серверы. Выберите **Балансировщик**: он сам подбирает лучший узел и переключается, если узел перестал работать.

Ссылка личная: не передавайте её другим людям и не публикуйте на форуме.`},
	{Slug: "android", Title: "Android", Sort: 2, Published: true, Body: `Подойдут приложения **Hiddify**, **v2rayNG**, **NekoBox** или **sing-box** (названия кнопок в разных версиях могут отличаться).

1. Установите приложение из магазина или со страницы проекта.
2. Скопируйте ссылку подписки в кабинете.
3. В приложении выберите добавление подписки (кнопка с плюсом, пункт «Добавить из буфера» или «Подписка») и вставьте ссылку.
4. Обновите подписку и выберите сервер **Балансировщик**.
5. Нажмите кнопку подключения и разрешите создание VPN-соединения.`},
	{Slug: "ios", Title: "iPhone и iPad", Sort: 3, Published: true, Body: `Подойдут приложения **Streisand**, **Hiddify**, **sing-box** или **Shadowrocket** (в зависимости от региона App Store они могут быть недоступны, тогда выберите другое).

1. Установите приложение из App Store.
2. Скопируйте ссылку подписки в кабинете (или отсканируйте QR-код камерой приложения).
3. Добавьте подписку в приложении и обновите её.
4. Выберите **Балансировщик** и включите подключение. Система один раз спросит разрешение на добавление VPN-конфигурации.`},
	{Slug: "desktop", Title: "Windows, macOS и Linux", Sort: 4, Published: true, Body: `Подойдут **Hiddify** (все системы), **v2rayN** (Windows), **NekoRay / NekoBox** и **Clash Verge** с поддержкой Reality.

1. Установите приложение.
2. Добавьте подписку по ссылке из кабинета (обычно «Подписки» или «Профили», затем «Добавить»).
3. Обновите подписку.
4. Выберите сервер **Балансировщик** и включите режим VPN (TUN), если нужно, чтобы через него шли все программы, а не только браузер.`},
	{Slug: "servers", Title: "Какой сервер выбрать", Sort: 5, Published: true, Body: `В подписке несколько вариантов балансировщика. Все они подключаются к одному адресу и отличаются тем, как выбирают узел:
- **Балансировщик** (текущий): самый стабильный, держится за хороший узел и не прыгает без причины. Выбирайте его по умолчанию.
- **лучшая скорость**: узел с максимальной скоростью среди лучших по надёжности.
- **лучший пинг**: узел с минимальной задержкой, подходит для игр и звонков.

Остальные записи в списке — отдельные серверы. Балансировщик удобнее: если узел сломается, переключение произойдёт само.`},
	{Slug: "troubleshooting", Title: "Если не работает", Sort: 6, Published: true, Body: `1. **Обновите подписку** в приложении: серверы и ключи меняются.
2. Проверьте в кабинете, что подписка **активна** и срок не закончился.
3. Переключите сеть: мобильный интернет вместо Wi-Fi и наоборот. Иногда оператор или роутер блокирует соединения.
4. Попробуйте другой вариант балансировщика или другое приложение.
5. Проверьте время на устройстве: при неверных дате и времени соединение не устанавливается.
6. Если ничего не помогло, напишите на **форуме**: укажите приложение, устройство, что именно видите и во сколько это было. Ссылку подписки не публикуйте.`},
}

// ---- rendering of the text ----

var (
	reBold = regexp.MustCompile(`\*\*([^*\n]+)\*\*`)
	reCode = regexp.MustCompile("`([^`\n]+)`")
	reLink = regexp.MustCompile(`\[([^\]\n]+)\]\((https?://[^\s)<>"']+)\)`)
	reOL   = regexp.MustCompile(`^\d{1,2}\. `)
)

func inlineMD(s string) string {
	s = html.EscapeString(s)
	s = reCode.ReplaceAllString(s, "<code>$1</code>")
	s = reBold.ReplaceAllString(s, "<b>$1</b>")
	// the address was escaped with the text: &amp; stays valid inside the attribute
	s = reLink.ReplaceAllString(s, `<a href="$2" rel="noopener nofollow" target="_blank">$1</a>`)
	return s
}

func renderMD(src string) template.HTML {
	var b strings.Builder
	list := ""
	closeList := func() {
		if list != "" {
			b.WriteString("</" + list + ">")
			list = ""
		}
	}
	para := []string{}
	flush := func() {
		if len(para) > 0 {
			b.WriteString("<p>" + inlineMD(strings.Join(para, " ")) + "</p>")
			para = para[:0]
		}
	}
	for _, line := range strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n") {
		t := strings.TrimRight(line, " \t")
		switch {
		case strings.TrimSpace(t) == "":
			flush()
			closeList()
		case strings.HasPrefix(t, "## "):
			flush()
			closeList()
			b.WriteString("<h2>" + inlineMD(t[3:]) + "</h2>")
		case strings.HasPrefix(t, "# "):
			flush()
			closeList()
			b.WriteString("<h2>" + inlineMD(t[2:]) + "</h2>")
		case strings.HasPrefix(t, "- "):
			flush()
			if list != "ul" {
				closeList()
				b.WriteString("<ul>")
				list = "ul"
			}
			b.WriteString("<li>" + inlineMD(t[2:]) + "</li>")
		case reOL.MatchString(t):
			flush()
			if list != "ol" {
				closeList()
				b.WriteString("<ol>")
				list = "ol"
			}
			b.WriteString("<li>" + inlineMD(t[strings.Index(t, " ")+1:]) + "</li>")
		default:
			closeList()
			para = append(para, strings.TrimSpace(t))
		}
	}
	flush()
	closeList()
	return template.HTML(b.String())
}

// ---- the site ----

type helpItem struct{ Slug, Title string }
type helpData struct {
	Items []helpItem
	Title string
	Body  template.HTML
}

func (s *Site) helpIndex(w http.ResponseWriter, r *http.Request) {
	acc, h := s.current(r)
	d := s.base(r, acc, h, "Инструкции")
	pages, _ := s.st.ListPages(r.Context(), true)
	for _, p := range pages {
		d.Help.Items = append(d.Help.Items, helpItem{p.Slug, p.Title})
	}
	s.render(w, 200, "help", d)
}

func (s *Site) helpPage(w http.ResponseWriter, r *http.Request) {
	acc, h := s.current(r)
	p, err := s.st.GetPage(r.Context(), r.PathValue("slug"), true)
	if err != nil {
		s.render(w, 404, "notfound", s.base(r, acc, h, "Не найдено"))
		return
	}
	d := s.base(r, acc, h, p.Title)
	d.Help.Title, d.Help.Body = p.Title, renderMD(p.Body)
	pages, _ := s.st.ListPages(r.Context(), true)
	for _, x := range pages {
		d.Help.Items = append(d.Help.Items, helpItem{x.Slug, x.Title})
	}
	s.render(w, 200, "help_page", d)
}

const helpTplText = `
{{define "help"}}{{template "head" .}}
<h1>Инструкции</h1>
{{if .Help.Items}}<div class="helpgrid">{{range .Help.Items}}<a class="card" href="/help/{{.Slug}}"><b>{{.Title}}</b></a>{{end}}</div>
{{else}}<div class="card muted">Раздел пока пуст.</div>{{end}}
{{template "foot" .}}{{end}}

{{define "help_page"}}{{template "head" .}}
<p><a href="/help">← Все инструкции</a></p>
<div class="card prose"><h1>{{.Help.Title}}</h1>{{.Help.Body}}</div>
{{if .Help.Items}}<div class="row">{{range .Help.Items}}<a class="btn s sm" href="/help/{{.Slug}}">{{.Title}}</a>{{end}}</div>{{end}}
{{template "foot" .}}{{end}}
`

func init() {
	template.Must(siteTpl.Parse(helpTplText))
}

func (s *Site) registerHelp(mux *http.ServeMux) {
	mux.HandleFunc("GET /help", s.helpIndex)
	mux.HandleFunc("GET /help/{slug}", s.helpPage)
}

// ---- admin API ----

func (a *API) registerPages(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/site/pages", a.auth(a.pagesList))
	mux.HandleFunc("PUT /api/site/pages/{slug}", a.auth(a.pageSave))
	mux.HandleFunc("DELETE /api/site/pages/{slug}", a.auth(a.pageDelete))
}

func (a *API) pagesList(w http.ResponseWriter, r *http.Request) {
	ps, err := a.store.ListPages(r.Context(), false)
	if err != nil {
		apiErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"pages": ps})
}

func (a *API) pageSave(w http.ResponseWriter, r *http.Request) {
	var p SitePage
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 80000)).Decode(&p); err != nil {
		apiErr(w, 400, fmt.Errorf("ожидается JSON {title, body, sort, published}"))
		return
	}
	p.Slug = r.PathValue("slug")
	if err := a.store.SavePage(r.Context(), p); err != nil {
		apiErr(w, 400, err)
		return
	}
	a.pagesList(w, r)
}

func (a *API) pageDelete(w http.ResponseWriter, r *http.Request) {
	if err := a.store.DeletePage(r.Context(), r.PathValue("slug")); err != nil {
		code := 400
		if errors.Is(err, ErrNotFound) {
			code = 404
		}
		apiErr(w, code, err)
		return
	}
	a.pagesList(w, r)
}
