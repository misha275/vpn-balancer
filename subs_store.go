package main

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ---- own nodes ----

// CustomNode is a server added by hand. It is not checked and never carries balancer traffic: it only appears in bundles
// (subscriptions). Its link is never shown back to anybody: the panel lists the name, type and address, users see subscriptions.
type CustomNode struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Server  string `json:"server"`
	Port    int    `json:"port"`
	Note    string `json:"note"`
	Enabled bool   `json:"enabled"`
	Mode    string `json:"mode"`    // direct: users get the link; via: traffic goes through this server
	Bundles int    `json:"bundles"` // in how many categories it is used
}

// customNodeInput is what the panel sends: the link only when it is set or replaced.
type customNodeInput struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Link    string `json:"link"`
	Note    string `json:"note"`
	Enabled *bool  `json:"enabled"`
	Mode    string `json:"mode"`
}

func checkCustomLink(link string) (*Node, error) {
	link = strings.TrimSpace(link)
	if link == "" || len(link) > 4096 || strings.ContainsAny(link, "\r\n") {
		return nil, errors.New("нужна одна ссылка узла (vless://, vmess://, trojan://, ss://, hysteria2://)")
	}
	n := parseLink(link)
	if n == nil {
		return nil, errors.New("ссылка не распознана или протокол не поддерживается")
	}
	n.Link = link
	return n, nil
}

// ListCustomNodes lists the servers added by hand (those imported from a subscription belong to their source).
func (s *Store) ListCustomNodes(ctx context.Context) ([]CustomNode, error) {
	rows, err := s.pool.Query(ctx, `SELECT c.id, c.name, c.link, c.note, c.enabled, c.mode, (SELECT count(*) FROM bundle_nodes b WHERE b.node_id=c.id) FROM custom_nodes c WHERE c.source_id IS NULL ORDER BY c.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CustomNode{}
	for rows.Next() {
		var c CustomNode
		var link string
		if err := rows.Scan(&c.ID, &c.Name, &link, &c.Note, &c.Enabled, &c.Mode, &c.Bundles); err != nil {
			return nil, err
		}
		if n := parseLink(link); n != nil {
			c.Type, c.Server, c.Port = n.Type, n.Server, n.Port
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) SaveCustomNode(ctx context.Context, in customNodeInput) (int64, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.Note = strings.TrimSpace(in.Note)
	if len([]rune(in.Name)) > 80 || len([]rune(in.Note)) > 300 {
		return 0, errors.New("название до 80 символов, заметка до 300")
	}
	enabled := in.Enabled == nil || *in.Enabled
	if in.Mode == "" {
		in.Mode = modeDirect
	}
	if in.Mode != modeDirect && in.Mode != modeVia {
		return 0, errors.New("режим: direct (отдать ссылку) или via (пропускать через основной сервер)")
	}
	if in.ID == 0 {
		n, err := checkCustomLink(in.Link)
		if err != nil {
			return 0, err
		}
		if in.Name == "" {
			in.Name = n.Name
		}
		if in.Name == "" {
			in.Name = n.Server
		}
		var id int64
		err = s.pool.QueryRow(ctx, `INSERT INTO custom_nodes(name,link,note,enabled,mode) VALUES($1,$2,$3,$4,$5) RETURNING id`, in.Name, strings.TrimSpace(in.Link), in.Note, enabled, in.Mode).Scan(&id)
		return id, err
	}
	if in.Name == "" {
		return 0, errors.New("название не может быть пустым")
	}
	link := ""
	if strings.TrimSpace(in.Link) != "" {
		if _, err := checkCustomLink(in.Link); err != nil {
			return 0, err
		}
		link = strings.TrimSpace(in.Link)
	}
	tag, err := s.pool.Exec(ctx, `UPDATE custom_nodes SET name=$2, note=$3, enabled=$4, mode=$6, link=CASE WHEN $5='' THEN link ELSE $5 END WHERE id=$1 AND source_id IS NULL`, in.ID, in.Name, in.Note, enabled, link, in.Mode)
	if err == nil && tag.RowsAffected() == 0 {
		return 0, ErrNotFound
	}
	return in.ID, err
}

func (s *Store) DeleteCustomNode(ctx context.Context, id int64) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM custom_nodes WHERE id=$1 AND source_id IS NULL`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ---- bundles ----

// Bundle is a named set of own nodes, delivered as one subscription: /sub/<token>/b/<slug>.
type Bundle struct {
	ID      int64   `json:"id"`
	Slug    string  `json:"slug"`
	Name    string  `json:"name"`
	Enabled bool    `json:"enabled"`
	Sort    int     `json:"sort"`
	Main    bool    `json:"main"`    // contains the main server: its three balancers
	Nodes   []int64 `json:"nodes"`   // single servers (added by hand)
	Sources []int64 `json:"sources"` // whole subscriptions of external servers
}

func (s *Store) ListBundles(ctx context.Context, onlyEnabled bool) ([]Bundle, error) {
	q := `SELECT b.id,b.slug,b.name,b.enabled,b.sort,b.with_main, COALESCE(array_agg(n.node_id ORDER BY n.sort,n.node_id) FILTER (WHERE n.node_id IS NOT NULL), '{}'),
		COALESCE((SELECT array_agg(bs.source_id ORDER BY bs.source_id) FROM bundle_sources bs WHERE bs.bundle_id=b.id), '{}')
		FROM bundles b LEFT JOIN bundle_nodes n ON n.bundle_id=b.id`
	if onlyEnabled {
		q += ` WHERE b.enabled`
	}
	rows, err := s.pool.Query(ctx, q+` GROUP BY b.id ORDER BY b.sort, b.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Bundle{}
	for rows.Next() {
		var b Bundle
		if err := rows.Scan(&b.ID, &b.Slug, &b.Name, &b.Enabled, &b.Sort, &b.Main, &b.Nodes, &b.Sources); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

func (b *Bundle) validate() error {
	b.Name = strings.TrimSpace(b.Name)
	b.Slug = strings.ToLower(strings.TrimSpace(b.Slug))
	if b.Name == "" || len([]rune(b.Name)) > 60 {
		return errors.New("название сборки: от 1 до 60 символов")
	}
	if !reSlug.MatchString(b.Slug) {
		return errors.New("адрес сборки: латиница, цифры и дефис, до 32 символов (например vip или games)")
	}
	if b.Slug == subBalancers || b.Slug == subAll || b.Slug == subServers {
		return errors.New("этот адрес занят встроенной подпиской")
	}
	if len(b.Nodes) > 2000 || len(b.Sources) > 200 {
		return errors.New("слишком много серверов в категории")
	}
	return nil
}

func (s *Store) SaveBundle(ctx context.Context, b Bundle) (int64, error) {
	if err := b.validate(); err != nil {
		return 0, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	if b.ID == 0 {
		err = tx.QueryRow(ctx, `INSERT INTO bundles(slug,name,enabled,sort,with_main) VALUES($1,$2,$3,$4,$5) RETURNING id`, b.Slug, b.Name, b.Enabled, b.Sort, b.Main).Scan(&b.ID)
	} else {
		var old string
		if err = tx.QueryRow(ctx, `SELECT slug FROM bundles WHERE id=$1`, b.ID).Scan(&old); errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrNotFound
		} else if err == nil && old != b.Slug {
			return 0, errors.New("адрес сборки менять нельзя: он записан в списках подписок пользователей и тарифов (создайте новую сборку)")
		}
		if err == nil {
			_, err = tx.Exec(ctx, `UPDATE bundles SET name=$2, enabled=$3, sort=$4, with_main=$5 WHERE id=$1`, b.ID, b.Name, b.Enabled, b.Sort, b.Main)
		}
	}
	if err != nil {
		if strings.Contains(err.Error(), "bundles_slug_key") {
			return 0, errors.New("сборка с таким адресом уже есть")
		}
		return 0, err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM bundle_nodes WHERE bundle_id=$1`, b.ID); err != nil {
		return 0, err
	}
	seen := map[int64]bool{}
	for i, id := range b.Nodes {
		if seen[id] {
			continue
		}
		seen[id] = true
		if _, err = tx.Exec(ctx, `INSERT INTO bundle_nodes(bundle_id,node_id,sort) SELECT $1,$2,$3 WHERE EXISTS (SELECT 1 FROM custom_nodes WHERE id=$2 AND source_id IS NULL)`, b.ID, id, i); err != nil {
			return 0, err
		}
	}
	if _, err = tx.Exec(ctx, `DELETE FROM bundle_sources WHERE bundle_id=$1`, b.ID); err != nil {
		return 0, err
	}
	seenSrc := map[int64]bool{}
	for _, id := range b.Sources {
		if seenSrc[id] {
			continue
		}
		seenSrc[id] = true
		if _, err = tx.Exec(ctx, `INSERT INTO bundle_sources(bundle_id,source_id) SELECT $1,$2 WHERE EXISTS (SELECT 1 FROM ext_sources WHERE id=$2)`, b.ID, id); err != nil {
			return 0, err
		}
	}
	return b.ID, tx.Commit(ctx)
}

// DeleteBundle removes the bundle and its key from every list of users, plans and the default.
func (s *Store) DeleteBundle(ctx context.Context, id int64) (string, error) {
	var slug string
	if err := s.pool.QueryRow(ctx, `DELETE FROM bundles WHERE id=$1 RETURNING slug`, id).Scan(&slug); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	key := bundlePrefix + slug
	_, _ = s.pool.Exec(ctx, `UPDATE users SET subs=array_remove(subs,$1) WHERE subs IS NOT NULL`, key)
	_, _ = s.pool.Exec(ctx, `UPDATE plans SET subs=array_remove(subs,$1) WHERE subs IS NOT NULL`, key)
	return key, nil
}

// relabelCustom puts the administrator's name on the link (vmess keeps its name inside the encoded body).
func relabelCustom(link, name string) string {
	if strings.HasPrefix(link, "vmess://") {
		return link
	}
	if i := strings.Index(link, "#"); i >= 0 {
		link = link[:i]
	}
	return link + "#" + url.PathEscape(name)
}

// ---- subscriptions of a user ----

// SetUserSubs sets the own list of a user; nil returns him to the plan or the default.
func (s *Store) SetUserSubs(ctx context.Context, name string, subs []string) error {
	if subs != nil {
		var err error
		if subs, err = cleanSubKeys(subs); err != nil {
			return err
		}
	}
	tag, err := s.pool.Exec(ctx, `UPDATE users SET subs=$2 WHERE name=$1`, name, subs)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// SetUserPlan assigns (or clears, 0) the plan whose subscriptions a user gets.
func (s *Store) SetUserPlan(ctx context.Context, name string, planID int64) error {
	tag, err := s.pool.Exec(ctx, `UPDATE users SET plan_id=NULLIF($2::bigint,0) WHERE name=$1`, name, planID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// NoteSubFetch remembers that the user downloaded a subscription.
func (s *Store) NoteSubFetch(ctx context.Context, userID int64) {
	_, _ = s.pool.Exec(ctx, `UPDATE users SET sub_fetched=now(), sub_fetches=sub_fetches+1 WHERE id=$1`, userID)
}

// ---- statistics of one user ----

type DayStat struct {
	Day   string `json:"day"` // YYYY-MM-DD (UTC)
	Up    int64  `json:"up"`
	Down  int64  `json:"down"`
	Conns int64  `json:"conns"`
}

type HourStat struct {
	T    int64 `json:"t"`
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

type UserStats struct {
	Name      string     `json:"name"`
	Days      []DayStat  `json:"days"`  // last 30 days, every day present
	Hours     []HourStat `json:"hours"` // last 48 hours, every hour present
	AllUp     int64      `json:"all_up"`
	AllDown   int64      `json:"all_down"`
	AllConns  int64      `json:"all_conns"`
	Today     int64      `json:"today"` // up+down since 00:00 UTC
	Last7     int64      `json:"last7"`
	Last30    int64      `json:"last30"`
	FirstSeen int64      `json:"first_seen"` // first hour with traffic
	LastSeen  int64      `json:"last_seen"`
	LastIP    string     `json:"last_ip"`
	BusiestHr int        `json:"busiest_hour"` // hour of the day (UTC) with the most traffic over 30 days, -1 = none
}

func (s *Store) UserStatsOf(ctx context.Context, name string, now time.Time) (*UserStats, error) {
	st := &UserStats{Name: name, BusiestHr: -1}
	now = now.UTC()
	start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).AddDate(0, 0, -29)
	byDay := map[string]*DayStat{}
	for i := 0; i < 30; i++ {
		d := start.AddDate(0, 0, i).Format("2006-01-02")
		st.Days = append(st.Days, DayStat{Day: d})
		byDay[d] = &st.Days[len(st.Days)-1]
	}
	rows, err := s.pool.Query(ctx, `SELECT (hour AT TIME ZONE 'UTC')::date::text, SUM(up), SUM(down), SUM(conns) FROM traffic_all WHERE user_name=$1 AND hour >= $2 GROUP BY 1`, name, start)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var d string
		var up, down, conns int64
		if err := rows.Scan(&d, &up, &down, &conns); err != nil {
			rows.Close()
			return nil, err
		}
		if x := byDay[d]; x != nil {
			x.Up, x.Down, x.Conns = up, down, conns
		}
	}
	rows.Close()
	today := now.Format("2006-01-02")
	for i, d := range st.Days {
		t := d.Up + d.Down
		st.Last30 += t
		if i >= len(st.Days)-7 {
			st.Last7 += t
		}
		if d.Day == today {
			st.Today = t
		}
	}
	h0 := now.Truncate(time.Hour).Add(-47 * time.Hour)
	byHour := map[int64]*HourStat{}
	for i := 0; i < 48; i++ {
		t := h0.Add(time.Duration(i) * time.Hour)
		st.Hours = append(st.Hours, HourStat{T: t.Unix()})
		byHour[t.Unix()] = &st.Hours[len(st.Hours)-1]
	}
	hr, err := s.pool.Query(ctx, `SELECT hour, up, down FROM traffic_all WHERE user_name=$1 AND hour >= $2`, name, h0)
	if err != nil {
		return nil, err
	}
	for hr.Next() {
		var t time.Time
		var up, down int64
		if err := hr.Scan(&t, &up, &down); err != nil {
			hr.Close()
			return nil, err
		}
		if x := byHour[t.Unix()]; x != nil {
			x.Up, x.Down = x.Up+up, x.Down+down
		}
	}
	hr.Close()
	var first, last *time.Time
	if err := s.pool.QueryRow(ctx, `SELECT COALESCE(SUM(up),0), COALESCE(SUM(down),0), COALESCE(SUM(conns),0), MIN(hour) FROM traffic_all WHERE user_name=$1`, name).
		Scan(&st.AllUp, &st.AllDown, &st.AllConns, &first); err != nil {
		return nil, err
	}
	if first != nil {
		st.FirstSeen = first.Unix()
	}
	var ip *string
	if err := s.pool.QueryRow(ctx, `SELECT last_seen, last_ip FROM user_seen WHERE user_name=$1`, name).Scan(&last, &ip); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if last != nil {
		st.LastSeen = last.Unix()
	}
	if ip != nil {
		st.LastIP = *ip
	}
	var bh *int
	_ = s.pool.QueryRow(ctx, `SELECT extract(hour from hour AT TIME ZONE 'UTC')::int FROM traffic_all WHERE user_name=$1 AND hour >= $2
		GROUP BY 1 ORDER BY SUM(up+down) DESC LIMIT 1`, name, start).Scan(&bh)
	if bh != nil {
		st.BusiestHr = *bh
	}
	return st, nil
}
