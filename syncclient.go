package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// The side of a server that talks to the panel (role balancer, end node): see servers.go for the protocol.

func panelClient(insecure bool) *http.Client {
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSHandshakeTimeout: 10 * time.Second}
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // the person asked for it: a self-signed panel
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: tr}
}

// PanelSync sends one report and returns the list of users.
func PanelSync(ctx context.Context, cl *http.Client, panelURL, token string, rep SyncReport) ([]SyncUser, error) {
	body, _ := json.Marshal(rep)
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(panelURL, "/")+"/api/sync", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := cl.Do(req)
	if err != nil {
		return nil, scrubErr(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("панель ответила %d: %s", resp.StatusCode, strings.TrimSpace(string(data[:min(len(data), 200)])))
	}
	var out struct {
		Users []SyncUser `json:"users"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("ответ панели: %v", err)
	}
	if out.Users == nil {
		out.Users = []SyncUser{}
	}
	return out.Users, nil
}

// SyncUsers makes the users of this server equal to the list of the panel: new ones are created with the same uuid and
// subscription token, the missing ones are switched off (the reconcile loop then removes them from the gateway and their
// connections are closed). Returns whether anything changed.
func (s *Store) SyncUsers(ctx context.Context, list []SyncUser) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	changed := false
	names := make([]string, 0, len(list))
	for _, u := range list {
		if u.Name == "" || strings.Contains(u.Name, "~") || u.UUID == "" || u.SubToken == "" {
			continue
		}
		names = append(names, u.Name)
		t, err := tx.Exec(ctx, `INSERT INTO users(name,uuid,sub_token,enabled,expires_at,synced,subs) VALUES($1,$2::uuid,$3,true,$4,true,ARRAY['balancers'])
			ON CONFLICT (name) DO UPDATE SET uuid=EXCLUDED.uuid, sub_token=EXCLUDED.sub_token, enabled=true, expires_at=EXCLUDED.expires_at, synced=true, subs=ARRAY['balancers']
			WHERE users.uuid<>EXCLUDED.uuid OR users.sub_token<>EXCLUDED.sub_token OR NOT users.enabled OR users.expires_at IS DISTINCT FROM EXCLUDED.expires_at OR NOT users.synced`,
			u.Name, u.UUID, u.SubToken, u.Expires)
		if err != nil {
			return false, fmt.Errorf("user %s: %v", u.Name, err)
		}
		if t.RowsAffected() > 0 {
			changed = true
		}
	}
	t, err := tx.Exec(ctx, `UPDATE users SET enabled=false WHERE synced AND enabled AND name <> ALL($1)`, names)
	if err != nil {
		return false, err
	}
	if t.RowsAffected() > 0 {
		changed = true
	}
	return changed, tx.Commit(ctx)
}

// UserTotals are the traffic totals per user (what the panel adds up over all servers).
func (s *Store) UserTotals(ctx context.Context) (map[string][2]int64, error) {
	rows, err := s.pool.Query(ctx, `SELECT user_name, SUM(up)::bigint, SUM(down)::bigint FROM traffic_hourly GROUP BY user_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][2]int64{}
	for rows.Next() {
		var n string
		var t [2]int64
		if err := rows.Scan(&n, &t[0], &t[1]); err != nil {
			return nil, err
		}
		if i := strings.Index(n, "~"); i >= 0 {
			n = n[:i]
		}
		o := out[n]
		out[n] = [2]int64{o[0] + t[0], o[1] + t[1]}
	}
	return out, rows.Err()
}

// balancerInfo is what a balancer server tells the panel: where it is and how to build links for a user.
func balancerInfo(cfg *Config, users int) ServerInfo {
	info := ServerInfo{Version: appVersion, Host: cfg.PublicHost, Users: users}
	for _, m := range linkModes(cfg) {
		info.Links = append(info.Links, LinkTmpl{Title: modeTitle(m), Mode: m, Tmpl: userLink(cfg, modeLinkName(cfg, m), "{UUID}")})
	}
	return info
}

// BalancerSyncLoop keeps the users of a balancer server equal to the panel's. kick is called after a change.
func BalancerSyncLoop(ctx context.Context, cfg *Config, st *Store, n *Notifier, kick func()) {
	cl := panelClient(cfg.PanelInsecure)
	if cfg.PanelInsecure {
		log.Printf("sync: panel_insecure is on: the certificate of the panel is NOT checked")
	}
	nUsers := 0
	for {
		c, cancel := context.WithTimeout(ctx, 40*time.Second)
		tot, _ := st.UserTotals(c)
		list, err := PanelSync(c, cl, cfg.PanelURL, cfg.PanelToken, SyncReport{Kind: "balancer", Info: balancerInfo(cfg, nUsers), Traffic: tot})
		if err == nil {
			var changed bool
			if changed, err = st.SyncUsers(c, list); err == nil {
				nUsers = len(list)
				if changed {
					log.Printf("sync: users of the panel applied (%d)", len(list))
					kick()
				}
			}
		}
		cancel()
		if err != nil {
			log.Printf("sync: %v (the last list of users stays in force)", err)
			n.Notify("sync", "🟠 Сервер не может связаться с панелью: "+err.Error(), time.Hour)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(cfg.SyncInterval):
		}
	}
}

// nullGateway stands in for the gateway of the panel role: the panel carries no traffic.
type nullGateway struct{}

var errNoGateway = fmt.Errorf("роль «панель»: на этом сервере нет шлюза")

func (nullGateway) Apply(context.Context, ApplyReq) (GWState, error)  { return GWState{}, errNoGateway }
func (nullGateway) State(context.Context) (GWState, error)            { return GWState{}, errNoGateway }
func (nullGateway) CloseAll(context.Context) error                    { return nil }
func (nullGateway) Stats(context.Context) (GWStats, error)            { return GWStats{}, errNoGateway }
func (nullGateway) Logs(context.Context, int64, int) (LogPage, error) { return LogPage{}, errNoGateway }
func (nullGateway) UserLogs(context.Context, string, int64, int) (LogPage, error) {
	return LogPage{}, errNoGateway
}
func (nullGateway) ApplyWG(context.Context, []byte, string) error { return errNoGateway }
func (nullGateway) Host() string                                  { return "127.0.0.1" }
