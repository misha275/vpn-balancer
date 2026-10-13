package main

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// External servers (version 3.2). They live apart from the balancer pool: they are not checked and never get balancer traffic.
// Each one is in a mode:
//
//	direct  users receive the link of the server inside a subscription and connect to it themselves
//	via     users receive a link of THIS server (the gateway) with a personal key per external server; the gateway forwards
//	        that connection to the external server (its filter rules still apply)
const (
	modeDirect = "direct"
	modeVia    = "via"
)

// extMode is the "mode" of a user key that leads to the external server with this id ("x12": the name is alice~x12).
func extMode(id int64) string { return "x" + strconv.FormatInt(id, 10) }

func extTag(id int64) string { return "x-" + strconv.FormatInt(id, 10) }

// ---- sources (subscriptions of external servers) ----

type ExtSource struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	URL       string `json:"-"` // carries a secret token: never sent back
	Host      string `json:"host"`
	Mode      string `json:"mode"`
	Enabled   bool   `json:"enabled"`
	Refreshed int64  `json:"refreshed"`
	Error     string `json:"error"`
	Nodes     int    `json:"nodes"`
}

type extSourceInput struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Mode    string `json:"mode"`
	Enabled *bool  `json:"enabled"`
}

func checkSourceURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || len(raw) > 2000 {
		return errors.New("нужен адрес подписки вида https://...")
	}
	return nil
}

func (s *Store) ListExtSources(ctx context.Context) ([]ExtSource, error) {
	rows, err := s.pool.Query(ctx, `SELECT e.id,e.name,e.url,e.mode,e.enabled,e.refreshed,e.error,(SELECT count(*) FROM custom_nodes c WHERE c.source_id=e.id) FROM ext_sources e ORDER BY e.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ExtSource{}
	for rows.Next() {
		var e ExtSource
		var ref *time.Time
		if err := rows.Scan(&e.ID, &e.Name, &e.URL, &e.Mode, &e.Enabled, &ref, &e.Error, &e.Nodes); err != nil {
			return nil, err
		}
		if ref != nil {
			e.Refreshed = ref.Unix()
		}
		e.Host = redact(e.URL)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) SaveExtSource(ctx context.Context, in extSourceInput) (int64, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Mode == "" {
		in.Mode = modeDirect
	}
	if in.Mode != modeDirect && in.Mode != modeVia {
		return 0, errors.New("режим: direct (отдать ссылки) или via (пропускать через основной сервер)")
	}
	enabled := in.Enabled == nil || *in.Enabled
	if len([]rune(in.Name)) > 60 {
		return 0, errors.New("название до 60 символов")
	}
	if in.ID == 0 {
		if err := checkSourceURL(in.URL); err != nil {
			return 0, err
		}
		if in.Name == "" {
			in.Name = redact(in.URL)
		}
		var id int64
		err := s.pool.QueryRow(ctx, `INSERT INTO ext_sources(name,url,mode,enabled) VALUES($1,$2,$3,$4) RETURNING id`, in.Name, strings.TrimSpace(in.URL), in.Mode, enabled).Scan(&id)
		return id, err
	}
	if in.Name == "" {
		return 0, errors.New("название не может быть пустым")
	}
	u := ""
	if strings.TrimSpace(in.URL) != "" {
		if err := checkSourceURL(in.URL); err != nil {
			return 0, err
		}
		u = strings.TrimSpace(in.URL)
	}
	tag, err := s.pool.Exec(ctx, `UPDATE ext_sources SET name=$2, mode=$3, enabled=$4, url=CASE WHEN $5='' THEN url ELSE $5 END WHERE id=$1`, in.ID, in.Name, in.Mode, enabled, u)
	if err != nil {
		return 0, err
	}
	if tag.RowsAffected() == 0 {
		return 0, ErrNotFound
	}
	_, err = s.pool.Exec(ctx, `UPDATE custom_nodes SET mode=$2 WHERE source_id=$1`, in.ID, in.Mode)
	return in.ID, err
}

func (s *Store) DeleteExtSource(ctx context.Context, id int64) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM ext_sources WHERE id=$1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

const maxSourceNodes = 2000

func linkUniq(link string) string {
	// the whole link, the name included: providers often give many servers that differ only in the name (one entry, many exits)
	h := sha1.Sum([]byte(link))
	return hex.EncodeToString(h[:])
}

// ImportSource replaces the nodes of the source by those of the downloaded body. Nodes that disappeared stay for the grace period
// (like in the pool), so a hiccup of the provider does not take servers away from users.
func (s *Store) ImportSource(ctx context.Context, id int64, body string, grace time.Duration) (int, error) {
	var mode string
	if err := s.pool.QueryRow(ctx, `SELECT mode FROM ext_sources WHERE id=$1`, id).Scan(&mode); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrNotFound
		}
		return 0, err
	}
	nodes := ParseLinksPerLink(body)
	if len(nodes) == 0 {
		return 0, errors.New("в ответе нет поддерживаемых серверов")
	}
	if len(nodes) > maxSourceNodes {
		nodes = nodes[:maxSourceNodes]
	}
	b := &pgx.Batch{}
	for _, n := range nodes {
		if n.Link == "" {
			continue
		}
		name := n.Name
		if name == "" {
			name = n.Server
		}
		b.Queue(`INSERT INTO custom_nodes(name,link,mode,source_id,uniq,last_seen) VALUES($1,$2,$3,$4,$5,now())
			ON CONFLICT (source_id, uniq) WHERE source_id IS NOT NULL DO UPDATE SET name=EXCLUDED.name, link=EXCLUDED.link, mode=EXCLUDED.mode, last_seen=now()`,
			name, n.Link, mode, id, linkUniq(n.Link))
	}
	br := s.pool.SendBatch(ctx, b)
	for i := 0; i < b.Len(); i++ {
		if _, err := br.Exec(); err != nil {
			br.Close()
			return 0, err
		}
	}
	br.Close()
	// rows made by an older version (the key ignored the name) are replaced by the new ones
	var links []string
	for _, n := range nodes {
		links = append(links, n.Link)
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM custom_nodes WHERE source_id=$1 AND last_seen < now() - interval '1 minute' AND link = ANY($2)`, id, links); err != nil {
		return 0, err
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM custom_nodes WHERE source_id=$1 AND last_seen < $2`, id, time.Now().Add(-grace)); err != nil {
		return 0, err
	}
	return len(nodes), nil
}

func (s *Store) noteSourceResult(ctx context.Context, id int64, err error) {
	msg := ""
	if err != nil {
		msg = err.Error()
		if len(msg) > 300 {
			msg = msg[:300]
		}
	}
	_, _ = s.pool.Exec(ctx, `UPDATE ext_sources SET refreshed=now(), error=$2 WHERE id=$1`, id, msg)
}

// RefreshExtSource downloads one source now.
func (s *Store) RefreshExtSource(ctx context.Context, cfg *Config, id int64) error {
	var raw string
	if err := s.pool.QueryRow(ctx, `SELECT url FROM ext_sources WHERE id=$1`, id).Scan(&raw); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	body, err := fetchSub(ctx, raw, cfg.SubUserAgent)
	if err == nil {
		_, err = s.ImportSource(ctx, id, body, cfg.NodeGrace)
	}
	s.noteSourceResult(ctx, id, err)
	return err
}

// RefreshAllExtSources downloads every enabled source (called every sub_refresh).
func (s *Store) RefreshAllExtSources(ctx context.Context, cfg *Config) {
	rows, err := s.pool.Query(ctx, `SELECT id FROM ext_sources WHERE enabled ORDER BY id`)
	if err != nil {
		return
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		if err := s.RefreshExtSource(ctx, cfg, id); err != nil {
			log.Printf("ext: source %d: %v", id, err)
		}
	}
}

// ---- the index: who may use what ----

type extNode struct {
	ID   int64
	Name string
	Mode string
	Link string
	Out  map[string]any
}

type bundleInfo struct {
	Slug, Name string
	WithMain   bool
	Nodes      []*extNode
}

type subIndex struct {
	Bundles map[string]*bundleInfo // "b:slug" of the enabled categories
}

func (s *Store) LoadSubIndex(ctx context.Context) (*subIndex, error) {
	ix := &subIndex{Bundles: map[string]*bundleInfo{}}
	nodes := map[int64]*extNode{}
	rows, err := s.pool.Query(ctx, `SELECT c.id,c.name,c.link,c.mode FROM custom_nodes c LEFT JOIN ext_sources e ON e.id=c.source_id WHERE c.enabled AND (c.source_id IS NULL OR e.enabled)`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		n := &extNode{}
		if err := rows.Scan(&n.ID, &n.Name, &n.Link, &n.Mode); err != nil {
			rows.Close()
			return nil, err
		}
		nodes[n.ID] = n
	}
	rows.Close()
	byID := map[int64]*bundleInfo{}
	br, err := s.pool.Query(ctx, `SELECT id,slug,name,with_main FROM bundles WHERE enabled ORDER BY sort,id`)
	if err != nil {
		return nil, err
	}
	for br.Next() {
		var id int64
		b := &bundleInfo{}
		if err := br.Scan(&id, &b.Slug, &b.Name, &b.WithMain); err != nil {
			br.Close()
			return nil, err
		}
		byID[id] = b
		ix.Bundles[bundlePrefix+b.Slug] = b
	}
	br.Close()
	have := map[int64]map[int64]bool{}
	add := func(bid, nid int64) {
		b, n := byID[bid], nodes[nid]
		if b == nil || n == nil {
			return
		}
		if have[bid] == nil {
			have[bid] = map[int64]bool{}
		}
		if !have[bid][nid] {
			have[bid][nid] = true
			b.Nodes = append(b.Nodes, n)
		}
	}
	for _, q := range []string{
		`SELECT bundle_id,node_id FROM bundle_nodes ORDER BY bundle_id, sort, node_id`,
		`SELECT bs.bundle_id,c.id FROM bundle_sources bs JOIN custom_nodes c ON c.source_id=bs.source_id ORDER BY bs.bundle_id, c.id`,
	} {
		mr, err := s.pool.Query(ctx, q)
		if err != nil {
			return nil, err
		}
		for mr.Next() {
			var bid, nid int64
			if err := mr.Scan(&bid, &nid); err != nil {
				mr.Close()
				return nil, err
			}
			add(bid, nid)
		}
		mr.Close()
	}
	return ix, nil
}

// access says whether the user may use the main server (its balancers) and which external servers must go through it.
func (ix *subIndex) access(cfg *Config, u User) (main bool, via []int64) {
	keys, _ := effectiveSubs(cfg, u)
	seen := map[int64]bool{}
	for _, k := range keys {
		if k == subBalancers || k == subAll {
			main = true
			continue
		}
		b := ix.Bundles[k]
		if b == nil {
			continue
		}
		if b.WithMain {
			main = true
		}
		for _, n := range b.Nodes {
			if n.Mode == modeVia && !seen[n.ID] {
				seen[n.ID] = true
				via = append(via, n.ID)
			}
		}
	}
	sort.Slice(via, func(i, j int) bool { return via[i] < via[j] })
	return main, via
}

// lines renders a category for a user: the main server first (if the category has it), then the servers in their order.
func (ix *subIndex) lines(cfg *Config, u User, slug string) (name string, out []string, ok bool) {
	b := ix.Bundles[bundlePrefix+slug]
	if b == nil {
		return "", nil, false
	}
	if b.WithMain {
		out = append(out, RenderBalancers(cfg, &u)...)
	}
	for _, n := range b.Nodes {
		if n.Mode == modeVia {
			out = append(out, userLink(cfg, n.Name, modeUUID(u.UUID, extMode(n.ID))))
		} else {
			out = append(out, relabelCustom(n.Link, n.Name))
		}
	}
	return b.Name, dedupe(out), true
}

// prepareUsers marks every user with what he may use. Users who may use neither the balancers nor an external server through
// this one get no key in the gateway. The external servers that are in use are returned for the gateway configuration.
func prepareUsers(cfg *Config, ix *subIndex, us []User) ([]User, []ExtNode) {
	nodes := map[int64]*extNode{}
	for _, b := range ix.Bundles {
		for _, n := range b.Nodes {
			nodes[n.ID] = n
		}
	}
	used := map[int64]bool{}
	out := make([]User, 0, len(us))
	for _, u := range us {
		main, via := ix.access(cfg, u)
		u.NoBalancer, u.Via = !main, via
		if !main && len(via) == 0 {
			continue
		}
		for _, id := range via {
			used[id] = true
		}
		out = append(out, u)
	}
	var ext []ExtNode
	for id := range used {
		n := nodes[id]
		if n == nil {
			continue
		}
		pn := parseLink(n.Link)
		if pn == nil || pn.Outbound == nil {
			continue
		}
		o := make(map[string]any, len(pn.Outbound)+1)
		for k, v := range pn.Outbound {
			o[k] = v
		}
		o["tag"] = extTag(id)
		ext = append(ext, ExtNode{ID: id, Tag: extTag(id), Outbound: o})
	}
	sort.Slice(ext, func(i, j int) bool { return ext[i].ID < ext[j].ID })
	return out, ext
}

// PrepareGateway loads the index, marks the users and hands the external servers in use to the configuration.
func (s *Store) PrepareGateway(ctx context.Context, cfg *Config, us []User) ([]User, error) {
	ix, err := s.LoadSubIndex(ctx)
	if err != nil {
		return nil, err
	}
	out, ext := prepareUsers(cfg, ix, us)
	cfg.setExtVia(ext)
	return out, nil
}

// ---- configuration side ----

// ExtNode is an external server in the "via" mode, as the gateway configuration needs it.
type ExtNode struct {
	ID       int64
	Tag      string
	Outbound map[string]any
}

func (c *Config) setExtVia(e []ExtNode) {
	c.mu.Lock()
	c.extVia = e
	c.mu.Unlock()
}

func (c *Config) getExtVia() []ExtNode {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]ExtNode(nil), c.extVia...)
}

// extSig changes whenever the set or the definition of the servers in use changes (the gateway then reloads).
func (c *Config) extSig() string {
	var parts []string
	for _, e := range c.getExtVia() {
		b, _ := json.Marshal(e.Outbound)
		h := sha1.Sum(b)
		parts = append(parts, fmt.Sprintf("%d:%x", e.ID, h[:6]))
	}
	return strings.Join(parts, ",")
}

// viaSig covers what each user may use, so that a change of a list reloads the gateway.
func viaSig(us []User) string {
	var parts []string
	for _, u := range us {
		if u.NoBalancer || len(u.Via) > 0 {
			parts = append(parts, fmt.Sprintf("%s:%v:%v", u.Name, u.NoBalancer, u.Via))
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}
