package main

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schemaSQL string

type Store struct{ pool *pgxpool.Pool }

type User struct {
	ID       int64
	Name     string
	UUID     string
	Enabled  bool
	SubToken string
}

type CheckRow struct {
	TS        time.Time
	NodeID    string
	Tier      int16
	OK        bool
	LatencyMS int32
	SpeedKbps int32
	Target    string
	Err       string
}

func NewStore(ctx context.Context, url string) (*Store, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	// wait for postgres (compose start order is not a guarantee)
	var last error
	for i := 0; i < 30; i++ {
		if last = pool.Ping(ctx); last == nil {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	if last != nil {
		return nil, last
	}
	if _, err := pool.Exec(ctx, schemaSQL); err != nil {
		return nil, err
	}
	return &Store{pool}, nil
}

func (s *Store) UpsertNodes(ctx context.Context, nodes []*Node, source string) error {
	b := &pgx.Batch{}
	for _, n := range nodes {
		b.Queue(`INSERT INTO nodes(id,name,type,server,port,outbound,source,link)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8)
			ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, last_seen=now(), source=EXCLUDED.source, link=EXCLUDED.link`,
			n.ID, n.Name, n.Type, n.Server, n.Port, n.Outbound, source, n.Link)
	}
	br := s.pool.SendBatch(ctx, b)
	defer br.Close()
	for range nodes {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}
	return nil
}

// ActiveNodes returns nodes seen in any subscription within the grace period.
// A failed subscription download does not touch last_seen, so its nodes
// stay in the pool until the grace period ends.
func (s *Store) ActiveNodes(ctx context.Context, grace time.Duration) ([]*Node, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id,name,type,server,port,outbound,link,exit_ip,exit_country,exit_checked,speed_hist,speed_try_at,speed_err,check_at,svc FROM nodes WHERE last_seen > $1 ORDER BY id`,
		time.Now().Add(-grace))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Node
	for rows.Next() {
		n := &Node{}
		var hist, svc []byte
		if err := rows.Scan(&n.ID, &n.Name, &n.Type, &n.Server, &n.Port, &n.Outbound, &n.Link, &n.ExitIP, &n.ExitCountry, &n.ExitChecked,
			&hist, &n.SpeedTry, &n.SpeedErr, &n.CheckAt, &svc); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(hist, &n.SpeedHist)
		_ = json.Unmarshal(svc, &n.Svc)
		n.UDP = n.Type == "hysteria2" || n.Type == "tuic"
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Store) InsertChecks(ctx context.Context, cs []CheckRow) error {
	if len(cs) == 0 {
		return nil
	}
	rows := make([][]any, len(cs))
	for i, c := range cs {
		rows[i] = []any{c.TS, c.NodeID, c.Tier, c.OK, c.LatencyMS, c.SpeedKbps, c.Target, c.Err}
	}
	_, err := s.pool.CopyFrom(ctx, pgx.Identifier{"checks"},
		[]string{"ts", "node_id", "tier", "ok", "latency_ms", "speed_kbps", "target", "error"},
		pgx.CopyFromRows(rows))
	return err
}

func (s *Store) EnabledUsers(ctx context.Context) ([]User, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,name,uuid::text,enabled,sub_token FROM users WHERE enabled ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Name, &u.UUID, &u.Enabled, &u.SubToken); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,name,uuid::text,enabled,sub_token FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Name, &u.UUID, &u.Enabled, &u.SubToken); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) AddUser(ctx context.Context, name string) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx, `INSERT INTO users(name) VALUES($1) RETURNING uuid::text`, name).Scan(&id)
	return id, err
}

func (s *Store) SetUserEnabled(ctx context.Context, name string, enabled bool) error {
	tag, err := s.pool.Exec(ctx, `UPDATE users SET enabled=$2 WHERE name=$1`, name, enabled)
	if err == nil && tag.RowsAffected() == 0 {
		return errors.New("user not found")
	}
	return err
}

func (s *Store) LogSwitch(ctx context.Context, from, to, reason string) {
	_, _ = s.pool.Exec(ctx, `INSERT INTO switches(from_node,to_node,reason) VALUES($1,$2,$3)`, from, to, reason)
}

func (s *Store) LastSelected(ctx context.Context) string {
	var id string
	if err := s.pool.QueryRow(ctx, `SELECT to_node FROM switches ORDER BY ts DESC LIMIT 1`).Scan(&id); err != nil {
		return ""
	}
	return id
}

func (s *Store) Cleanup(ctx context.Context, keep time.Duration) {
	_, _ = s.pool.Exec(ctx, `DELETE FROM checks WHERE ts < $1`, time.Now().Add(-keep))
	_, _ = s.pool.Exec(ctx, `DELETE FROM switches WHERE ts < $1`, time.Now().Add(-90*24*time.Hour))
	_, _ = s.pool.Exec(ctx, `DELETE FROM traffic_hourly WHERE hour < $1`, time.Now().Add(-180*24*time.Hour))
	_, _ = s.pool.Exec(ctx, `DELETE FROM metrics WHERE ts < $1`, time.Now().Add(-14*24*time.Hour))
}

// SetExit records where a node's traffic really leaves from.
func (s *Store) SetExit(ctx context.Context, id, ip, country string) error {
	_, err := s.pool.Exec(ctx, `UPDATE nodes SET exit_ip=$2, exit_country=$3, exit_checked=now() WHERE id=$1`, id, ip, country)
	return err
}

// UserBySubToken finds an enabled user by the secret in the subscription URL.
func (s *Store) UserBySubToken(ctx context.Context, token string) (*User, error) {
	var u User
	err := s.pool.QueryRow(ctx, `SELECT id,name,uuid::text,enabled,sub_token FROM users WHERE sub_token=$1 AND enabled`, token).
		Scan(&u.ID, &u.Name, &u.UUID, &u.Enabled, &u.SubToken)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// ---- runtime settings and the admin token ----

const adminTokenKey = "admin_token"

// LoadSettings returns the editable settings stored in the database and a stamp
// that changes whenever any of them changes (the controller polls it).
func (s *Store) LoadSettings(ctx context.Context) (map[string]json.RawMessage, string, error) {
	rows, err := s.pool.Query(ctx, `SELECT key, value::text, extract(epoch from updated)::text FROM settings WHERE key <> $1 ORDER BY key`, adminTokenKey)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	out := map[string]json.RawMessage{}
	var stamp strings.Builder
	for rows.Next() {
		var k, v, ts string
		if err := rows.Scan(&k, &v, &ts); err != nil {
			return nil, "", err
		}
		out[k] = json.RawMessage(v)
		stamp.WriteString(k + "@" + ts + ";")
	}
	return out, stamp.String(), rows.Err()
}

func (s *Store) PutSetting(ctx context.Context, key string, raw json.RawMessage) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO settings(key,value,updated) VALUES($1,$2::jsonb,now())
		ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated=now()`, key, string(raw))
	return err
}

func (s *Store) DeleteSetting(ctx context.Context, key string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM settings WHERE key=$1`, key)
	return err
}

// AdminToken returns the secret for the panel/API, creating it on first use.
func (s *Store) AdminToken(ctx context.Context) (string, error) {
	var v string
	err := s.pool.QueryRow(ctx, `SELECT value #>> '{}' FROM settings WHERE key=$1`, adminTokenKey).Scan(&v)
	if err == nil && v != "" {
		return v, nil
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(b)
	raw, _ := json.Marshal(tok)
	if _, err := s.pool.Exec(ctx, `INSERT INTO settings(key,value) VALUES($1,$2::jsonb) ON CONFLICT (key) DO NOTHING`, adminTokenKey, string(raw)); err != nil {
		return "", err
	}
	err = s.pool.QueryRow(ctx, `SELECT value #>> '{}' FROM settings WHERE key=$1`, adminTokenKey).Scan(&v)
	return v, err
}

type SwitchRow struct {
	TS     time.Time `json:"ts"`
	From   string    `json:"from"`
	To     string    `json:"to"`
	Reason string    `json:"reason"`
}

// RecentSwitches returns the latest switches with node names where known.
func (s *Store) RecentSwitches(ctx context.Context, limit int) ([]SwitchRow, error) {
	rows, err := s.pool.Query(ctx, `SELECT sw.ts, COALESCE(f.name, sw.from_node), COALESCE(t.name, sw.to_node), sw.reason
		FROM switches sw LEFT JOIN nodes f ON f.id=sw.from_node LEFT JOIN nodes t ON t.id=sw.to_node
		ORDER BY sw.ts DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SwitchRow
	for rows.Next() {
		var r SwitchRow
		if err := rows.Scan(&r.TS, &r.From, &r.To, &r.Reason); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ForgetExitChecks makes every node's exit country look stale, so it is measured again soon.
func (s *Store) ForgetExitChecks(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `UPDATE nodes SET exit_checked='epoch'`)
	return err
}

// ---------------------------------------------------------------- statistics

// AddTraffic adds counters to the bucket of the given hour.
func (s *Store) AddTraffic(ctx context.Context, at time.Time, m map[string]UserDelta) error {
	if len(m) == 0 {
		return nil
	}
	hour := at.UTC().Truncate(time.Hour)
	b := &pgx.Batch{}
	for name, d := range m {
		b.Queue(`INSERT INTO traffic_hourly(hour,user_name,up,down,conns) VALUES($1,$2,$3,$4,$5)
			ON CONFLICT (hour,user_name) DO UPDATE SET up=traffic_hourly.up+EXCLUDED.up, down=traffic_hourly.down+EXCLUDED.down, conns=traffic_hourly.conns+EXCLUDED.conns`,
			hour, name, d.Up, d.Down, d.Conns)
	}
	br := s.pool.SendBatch(ctx, b)
	defer br.Close()
	for range m {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}
	return nil
}

type SeenInfo struct {
	At time.Time
	IP string
}

func (s *Store) TouchSeen(ctx context.Context, m map[string]SeenInfo) error {
	if len(m) == 0 {
		return nil
	}
	b := &pgx.Batch{}
	for name, v := range m {
		b.Queue(`INSERT INTO user_seen(user_name,last_seen,last_ip) VALUES($1,$2,$3)
			ON CONFLICT (user_name) DO UPDATE SET last_seen=GREATEST(user_seen.last_seen,EXCLUDED.last_seen), last_ip=CASE WHEN EXCLUDED.last_seen>=user_seen.last_seen THEN EXCLUDED.last_ip ELSE user_seen.last_ip END`,
			name, v.At, v.IP)
	}
	br := s.pool.SendBatch(ctx, b)
	defer br.Close()
	for range m {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}
	return nil
}

type TrafficSum struct {
	H24Up, H24Down int64
	D7Up, D7Down   int64
	D30Up, D30Down int64
	AllUp, AllDown int64
	AllConns       int64
	LastSeen       time.Time
	LastIP         string
}

// TrafficSummary returns the totals for every name that has traffic or was ever seen.
func (s *Store) TrafficSummary(ctx context.Context) (map[string]*TrafficSum, error) {
	rows, err := s.pool.Query(ctx, `SELECT user_name,
		COALESCE(SUM(up) FILTER (WHERE hour > now()-interval '24 hours'),0), COALESCE(SUM(down) FILTER (WHERE hour > now()-interval '24 hours'),0),
		COALESCE(SUM(up) FILTER (WHERE hour > now()-interval '7 days'),0),   COALESCE(SUM(down) FILTER (WHERE hour > now()-interval '7 days'),0),
		COALESCE(SUM(up) FILTER (WHERE hour > now()-interval '30 days'),0),  COALESCE(SUM(down) FILTER (WHERE hour > now()-interval '30 days'),0),
		COALESCE(SUM(up),0), COALESCE(SUM(down),0), COALESCE(SUM(conns),0)
		FROM traffic_hourly GROUP BY user_name`)
	if err != nil {
		return nil, err
	}
	out := map[string]*TrafficSum{}
	for rows.Next() {
		var n string
		t := &TrafficSum{}
		if err := rows.Scan(&n, &t.H24Up, &t.H24Down, &t.D7Up, &t.D7Down, &t.D30Up, &t.D30Down, &t.AllUp, &t.AllDown, &t.AllConns); err != nil {
			rows.Close()
			return nil, err
		}
		out[n] = t
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	r2, err := s.pool.Query(ctx, `SELECT user_name,last_seen,last_ip FROM user_seen`)
	if err != nil {
		return nil, err
	}
	defer r2.Close()
	for r2.Next() {
		var n, ip string
		var ts time.Time
		if err := r2.Scan(&n, &ts, &ip); err != nil {
			return nil, err
		}
		t := out[n]
		if t == nil {
			t = &TrafficSum{}
			out[n] = t
		}
		t.LastSeen, t.LastIP = ts, ip
	}
	return out, r2.Err()
}

func (s *Store) InsertMetric(ctx context.Context, m SysSample) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO metrics(ts,cpu,mem,disk,load1,up,down,conns,users) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (ts) DO NOTHING`, time.Unix(m.T, 0), m.CPU, m.Mem, m.Disk, m.Load1, m.Up, m.Down, m.Conns, m.Users)
	return err
}

func (s *Store) LoadMetrics(ctx context.Context, since time.Time) ([]SysSample, error) {
	rows, err := s.pool.Query(ctx, `SELECT ts,cpu,mem,disk,load1,up,down,conns,users FROM metrics WHERE ts >= $1 ORDER BY ts`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SysSample
	for rows.Next() {
		var ts time.Time
		var m SysSample
		if err := rows.Scan(&ts, &m.CPU, &m.Mem, &m.Disk, &m.Load1, &m.Up, &m.Down, &m.Conns, &m.Users); err != nil {
			return nil, err
		}
		m.T = ts.Unix()
		out = append(out, m)
	}
	return out, rows.Err()
}

// NodeStat is the quality data of one node that is kept in the database.
type NodeStat struct {
	ID        string
	SpeedHist []SpeedPoint
	SpeedTry  time.Time
	SpeedErr  string
	CheckAt   time.Time
	Svc       map[string]SvcRes
}

func (s *Store) SaveNodeStats(ctx context.Context, list []NodeStat) error {
	if len(list) == 0 {
		return nil
	}
	b := &pgx.Batch{}
	for _, n := range list {
		hist, _ := json.Marshal(n.SpeedHist)
		if n.SpeedHist == nil {
			hist = []byte("[]")
		}
		svc, _ := json.Marshal(n.Svc)
		if n.Svc == nil {
			svc = []byte("{}")
		}
		b.Queue(`UPDATE nodes SET speed_hist=$2, speed_try_at=$3, speed_err=$4, check_at=$5, svc=$6 WHERE id=$1`,
			n.ID, hist, n.SpeedTry, n.SpeedErr, n.CheckAt, svc)
	}
	br := s.pool.SendBatch(ctx, b)
	defer br.Close()
	for range list {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}
	return nil
}

// DeleteUser removes a user for good (traffic history stays under the name). It reports whether the user existed.
func (s *Store) DeleteUser(ctx context.Context, name string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM users WHERE name=$1`, name)
	if err == nil && tag.RowsAffected() > 0 { // the user's counters go with the user
		_, _ = s.pool.Exec(ctx, `DELETE FROM traffic_hourly WHERE user_name=$1`, name)
		_, _ = s.pool.Exec(ctx, `DELETE FROM user_seen WHERE user_name=$1`, name)
	}
	return tag.RowsAffected() > 0, err
}
