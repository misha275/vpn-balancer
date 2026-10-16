package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Servers that report to the panel (version 3.7.0). Two kinds:
//
//	balancer  a full balancer without its own panel (installer --mode balancer-only): takes the users from the panel
//	endnode   a plain server with ready protocols and no balancing (installer --mode end-node)
//
// A server asks the panel (POST /api/sync, "Authorization: Bearer <token>") every sync_interval seconds: it tells its
// address, version, link templates and the traffic of users, and gets the list of users who may use it. A user who is
// blocked, disabled, expired or has no access to that kind of server is simply missing from the list, and the server
// removes him (his connections are closed). The panel keeps only the hash of the token.

// LinkTmpl is a link of a server with places for the user: {UUID} and {PASS}.
type LinkTmpl struct {
	Title string `json:"title"`          // "VLESS Reality", "Hysteria2", "лучшая скорость"...
	Tmpl  string `json:"tmpl"`           // vless://{UUID}@host:443?..., vmess://<base64 of JSON with {UUID}>
	Mode  string `json:"mode,omitempty"` // balancers: the mode, to take the key of that mode
}

// ServerInfo is what a server tells about itself.
type ServerInfo struct {
	Version string     `json:"version,omitempty"`
	Host    string     `json:"host,omitempty"`
	Links   []LinkTmpl `json:"links,omitempty"`
	Users   int        `json:"users,omitempty"`
	Note    string     `json:"note,omitempty"`
}

type RemoteServer struct {
	ID       int64      `json:"id"`
	Name     string     `json:"name"`
	Kind     string     `json:"kind"`
	Enabled  bool       `json:"enabled"`
	Info     ServerInfo `json:"info"`
	LastSeen *time.Time `json:"last_seen"`
	Created  time.Time  `json:"created"`
	Note     string     `json:"note"`
	Up       int64      `json:"up"`
	Down     int64      `json:"down"`
}

var reSSUser = regexp.MustCompile(`\{SS:([a-z0-9-]+)\}`)

var reServerName = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N} ._-]{0,39}$`)

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

func newServerToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "vpnb_" + hex.EncodeToString(b)
}

// endnodePass is the password of a user for protocols that need one (trojan, shadowsocks, hysteria2, tuic).
// Both sides compute it from the uuid, so nothing else has to travel.
func endnodePass(uuid string) string {
	h := sha256.Sum256([]byte("vpn-balancer|endnode-pass|" + uuid))
	return base64.RawURLEncoding.EncodeToString(h[:])[:22]
}

func (s *Store) CreateServer(ctx context.Context, name, kind, note string) (RemoteServer, string, error) {
	name = strings.TrimSpace(name)
	if !reServerName.MatchString(name) {
		return RemoteServer{}, "", errors.New("имя сервера: до 40 символов, буквы, цифры, пробел . _ -")
	}
	if kind != "balancer" && kind != "endnode" {
		return RemoteServer{}, "", errors.New("вид сервера: balancer или endnode")
	}
	tok := newServerToken()
	var sv RemoteServer
	err := s.pool.QueryRow(ctx, `INSERT INTO servers(name,kind,token_hash,note) VALUES($1,$2,$3,$4) RETURNING id,name,kind,enabled,created,note`,
		name, kind, hashToken(tok), note).Scan(&sv.ID, &sv.Name, &sv.Kind, &sv.Enabled, &sv.Created, &sv.Note)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") {
			return sv, "", errors.New("сервер с таким именем уже есть")
		}
		return sv, "", err
	}
	return sv, tok, nil
}

const serverCols = `s.id,s.name,s.kind,s.enabled,s.info,s.last_seen,s.created,s.note,
	COALESCE((SELECT SUM(up) FROM server_traffic t WHERE t.server_id=s.id),0),COALESCE((SELECT SUM(down) FROM server_traffic t WHERE t.server_id=s.id),0)`

func scanServer(r pgx.Row, sv *RemoteServer) error {
	var info []byte
	if err := r.Scan(&sv.ID, &sv.Name, &sv.Kind, &sv.Enabled, &info, &sv.LastSeen, &sv.Created, &sv.Note, &sv.Up, &sv.Down); err != nil {
		return err
	}
	_ = json.Unmarshal(info, &sv.Info)
	return nil
}

func (s *Store) ListServers(ctx context.Context) ([]RemoteServer, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+serverCols+` FROM servers s ORDER BY s.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RemoteServer{}
	for rows.Next() {
		var sv RemoteServer
		if err := scanServer(rows, &sv); err != nil {
			return nil, err
		}
		out = append(out, sv)
	}
	return out, rows.Err()
}

func (s *Store) ServerByToken(ctx context.Context, tok string) (*RemoteServer, error) {
	var sv RemoteServer
	err := scanServer(s.pool.QueryRow(ctx, `SELECT `+serverCols+` FROM servers s WHERE s.token_hash=$1`, hashToken(tok)), &sv)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &sv, err
}

func (s *Store) SetServerEnabled(ctx context.Context, id int64, on bool) error {
	t, err := s.pool.Exec(ctx, `UPDATE servers SET enabled=$2 WHERE id=$1`, id, on)
	if err == nil && t.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) DeleteServer(ctx context.Context, id int64) error {
	t, err := s.pool.Exec(ctx, `DELETE FROM servers WHERE id=$1`, id)
	if err == nil && t.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// RegenServerToken makes a new token; the old one stops working at once.
func (s *Store) RegenServerToken(ctx context.Context, id int64) (string, error) {
	tok := newServerToken()
	t, err := s.pool.Exec(ctx, `UPDATE servers SET token_hash=$2 WHERE id=$1`, id, hashToken(tok))
	if err == nil && t.RowsAffected() == 0 {
		return "", ErrNotFound
	}
	return tok, err
}

// SyncReport is what a server sends.
type SyncReport struct {
	Kind    string              `json:"kind"`
	Info    ServerInfo          `json:"info"`
	Traffic map[string][2]int64 `json:"traffic,omitempty"` // user -> [up, down] since the server was installed
}

func (s *Store) SaveServerReport(ctx context.Context, id int64, rep SyncReport) error {
	info, _ := json.Marshal(rep.Info)
	if _, err := s.pool.Exec(ctx, `UPDATE servers SET info=$2, last_seen=now() WHERE id=$1`, id, info); err != nil {
		return err
	}
	if len(rep.Traffic) == 0 {
		return nil
	}
	b := &pgx.Batch{}
	n := 0
	for u, t := range rep.Traffic {
		if n++; n > 20000 || t[0] < 0 || t[1] < 0 {
			continue
		}
		b.Queue(`INSERT INTO server_traffic(server_id,user_name,up,down) VALUES($1,$2,$3,$4)
			ON CONFLICT (server_id,user_name) DO UPDATE SET up=EXCLUDED.up, down=EXCLUDED.down`, id, u, t[0], t[1])
	}
	br := s.pool.SendBatch(ctx, b)
	defer br.Close()
	for i := 0; i < b.Len(); i++ {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}
	return nil
}

// SyncUser is a user in the answer to a server.
type SyncUser struct {
	Name     string     `json:"name"`
	UUID     string     `json:"uuid"`
	SubToken string     `json:"sub_token"`
	Expires  *time.Time `json:"expires,omitempty"`
}

// userMayUseServer says whether a user's subscriptions give access to a kind of remote server.
func userMayUseServer(cfg *Config, u User, kind string, now time.Time) bool {
	if !u.Active(now) {
		return false
	}
	keys, _ := effectiveSubs(cfg, u)
	if hasSub(keys, subAll) {
		return true
	}
	if kind == "balancer" {
		return hasSub(keys, subBalancers)
	}
	return hasSub(keys, subServers)
}

// SyncUsersFor lists the users who may use a server of the given kind.
func (s *Store) SyncUsersFor(ctx context.Context, cfg *Config, kind string) ([]SyncUser, error) {
	us, err := s.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	out := []SyncUser{}
	for _, u := range us {
		if userMayUseServer(cfg, u, kind, now) {
			out = append(out, SyncUser{u.Name, u.UUID, u.SubToken, u.Expires})
		}
	}
	return out, nil
}

// ---- links of remote servers in subscriptions ----

// RefreshRemote reloads the registry into the cache used to render subscriptions.
func (s *Store) RefreshRemote(ctx context.Context, cfg *Config) {
	list, err := s.ListServers(ctx)
	if err != nil {
		log.Printf("servers: %v", err)
		return
	}
	cfg.mu.Lock()
	cfg.remote = list
	cfg.remoteAt = time.Now()
	cfg.mu.Unlock()
}

func (s *Store) RemoteLoop(ctx context.Context, cfg *Config) {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for {
		c, cancel := context.WithTimeout(ctx, 10*time.Second)
		s.RefreshRemote(c, cfg)
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// fillTemplate puts a user into a link template of a server.
func fillTemplate(t LinkTmpl, kind string, u User, name string) (string, bool) {
	uuid := u.UUID
	if kind == "balancer" {
		uuid = modeUUID(u.UUID, t.Mode)
	}
	rep := strings.NewReplacer("{UUID}", uuid, "{PASS}", endnodePass(u.UUID))
	if m := reSSUser.FindStringSubmatch(t.Tmpl); m != nil { // ss://{SS:method}@host:port -> ss://base64(method:password)@host:port
		t.Tmpl = strings.Replace(t.Tmpl, m[0], base64.RawURLEncoding.EncodeToString([]byte(m[1]+":"+endnodePass(u.UUID))), 1)
	}
	if strings.HasPrefix(t.Tmpl, "vmess://") {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(t.Tmpl, "vmess://"))
		if err != nil {
			return "", false
		}
		var m map[string]any
		if json.Unmarshal([]byte(rep.Replace(string(raw))), &m) != nil {
			return "", false
		}
		m["ps"] = name
		b, _ := json.Marshal(m)
		return "vmess://" + base64.StdEncoding.EncodeToString(b), true
	}
	l := rep.Replace(t.Tmpl)
	if i := strings.Index(l, "#"); i >= 0 {
		l = l[:i]
	}
	return l + "#" + url.PathEscape(name), true
}

// remoteLinks are the links of the registered servers of one kind for a user (kind "" = both).
func (c *Config) remoteLinks(u User, kind string) []string {
	c.mu.RLock()
	list := c.remote
	c.mu.RUnlock()
	var out []string
	for _, sv := range list {
		if !sv.Enabled || sv.LastSeen == nil || (kind != "" && sv.Kind != kind) {
			continue
		}
		for _, t := range sv.Info.Links {
			name := sv.Name
			if t.Title != "" {
				name += " · " + t.Title
			}
			if l, ok := fillTemplate(t, sv.Kind, u, name); ok {
				out = append(out, l)
			}
		}
	}
	return out
}

// ---- the endpoint of the servers ----

var syncFails = newLimiter(30, 10*time.Minute)

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func (s *Site) syncHandler(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if syncFails.blocked(ip) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	tok := bearer(r)
	sv, err := s.st.ServerByToken(ctx, tok)
	if err != nil || tok == "" {
		syncFails.hit(ip)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !sv.Enabled {
		http.Error(w, "server disabled in the panel", http.StatusForbidden)
		return
	}
	var rep SyncReport
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&rep); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if rep.Kind != "" && rep.Kind != sv.Kind {
		http.Error(w, "this token belongs to a server of another kind ("+sv.Kind+")", http.StatusConflict)
		return
	}
	if len(rep.Info.Links) > 64 {
		rep.Info.Links = rep.Info.Links[:64]
	}
	if err := s.st.SaveServerReport(ctx, sv.ID, rep); err != nil {
		log.Printf("sync %s: %v", sv.Name, err)
		http.Error(w, "temporary error", http.StatusServiceUnavailable)
		return
	}
	users, err := s.st.SyncUsersFor(ctx, s.cfg, sv.Kind)
	if err != nil {
		http.Error(w, "temporary error", http.StatusServiceUnavailable)
		return
	}
	go s.st.RefreshRemote(context.Background(), s.cfg)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"users": users, "interval": int(s.cfg.SyncInterval / time.Second)})
}

// ---- admin API ----

func (a *API) registerServers(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/servers", a.auth(a.serversList))
	mux.HandleFunc("POST /api/servers", a.auth(a.serverCreate))
	mux.HandleFunc("POST /api/servers/{id}/{op}", a.auth(a.serverOp))
	mux.HandleFunc("DELETE /api/servers/{id}", a.auth(a.serverDelete))
}

func (a *API) panelAddr(r *http.Request) string {
	if b := a.cfg.siteBaseURL(); b != "" {
		return b
	}
	if a.cfg.PublicHost != "" && !strings.HasPrefix(a.cfg.PublicHost, "<") {
		return "http://" + a.cfg.PublicHost
	}
	return "https://ПАНЕЛЬ"
}

func (a *API) installCmd(r *http.Request, kind, tok string) string {
	mode := "end-node"
	if kind == "balancer" {
		mode = "balancer-only"
	}
	return fmt.Sprintf("bash install.sh --mode %s --panel-url %s --panel-token %s", mode, a.panelAddr(r), tok)
}

func (a *API) serversList(w http.ResponseWriter, r *http.Request) {
	list, err := a.store.ListServers(r.Context())
	if err != nil {
		apiErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]any{"servers": list, "role": a.cfg.Role, "panel": a.panelAddr(r)})
}

func (a *API) serverCreate(w http.ResponseWriter, r *http.Request) {
	var in struct{ Name, Kind, Note string }
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
		apiErr(w, 400, errors.New("ожидается JSON {name, kind, note}"))
		return
	}
	sv, tok, err := a.store.CreateServer(r.Context(), in.Name, in.Kind, in.Note)
	if err != nil {
		apiErr(w, 400, err)
		return
	}
	go a.store.RefreshRemote(context.Background(), a.cfg)
	writeJSON(w, 200, map[string]any{"server": sv, "token": tok, "command": a.installCmd(r, sv.Kind, tok)})
}

func (a *API) serverOp(w http.ResponseWriter, r *http.Request) {
	var id int64
	fmt.Sscan(r.PathValue("id"), &id)
	var err error
	resp := map[string]any{"ok": "готово"}
	switch op := r.PathValue("op"); op {
	case "enable", "disable":
		err = a.store.SetServerEnabled(r.Context(), id, op == "enable")
	case "token":
		var tok string
		if tok, err = a.store.RegenServerToken(r.Context(), id); err == nil {
			resp["token"] = tok
			for _, sv := range a.cachedServers(r) {
				if sv.ID == id {
					resp["command"] = a.installCmd(r, sv.Kind, tok)
				}
			}
		}
	default:
		err = ErrNotFound
	}
	if err != nil {
		code := 400
		if errors.Is(err, ErrNotFound) {
			code = 404
		}
		apiErr(w, code, err)
		return
	}
	go a.store.RefreshRemote(context.Background(), a.cfg)
	writeJSON(w, 200, resp)
}

func (a *API) cachedServers(r *http.Request) []RemoteServer {
	l, _ := a.store.ListServers(r.Context())
	return l
}

func (a *API) serverDelete(w http.ResponseWriter, r *http.Request) {
	var id int64
	fmt.Sscan(r.PathValue("id"), &id)
	if err := a.store.DeleteServer(r.Context(), id); err != nil {
		apiErr(w, 404, err)
		return
	}
	go a.store.RefreshRemote(context.Background(), a.cfg)
	writeJSON(w, 200, map[string]string{"ok": "готово"})
}
