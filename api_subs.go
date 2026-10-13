package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

func (a *API) registerSubs(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/catalog", a.auth(a.catalogGet))
	mux.HandleFunc("POST /api/custom-nodes", a.auth(a.customNodeSave))
	mux.HandleFunc("PUT /api/custom-nodes/{id}", a.auth(a.customNodeSave))
	mux.HandleFunc("DELETE /api/custom-nodes/{id}", a.auth(a.customNodeDelete))
	mux.HandleFunc("POST /api/ext-sources", a.auth(a.extSourceSave))
	mux.HandleFunc("PUT /api/ext-sources/{id}", a.auth(a.extSourceSave))
	mux.HandleFunc("DELETE /api/ext-sources/{id}", a.auth(a.extSourceDelete))
	mux.HandleFunc("POST /api/ext-sources/{id}/refresh", a.auth(a.extSourceRefresh))
	mux.HandleFunc("POST /api/bundles", a.auth(a.bundleSave))
	mux.HandleFunc("PUT /api/bundles/{id}", a.auth(a.bundleSave))
	mux.HandleFunc("DELETE /api/bundles/{id}", a.auth(a.bundleDelete))
	mux.HandleFunc("POST /api/users/{name}/subs", a.auth(a.userSubs))
	mux.HandleFunc("POST /api/users/{name}/plan", a.auth(a.userPlan))
	mux.HandleFunc("GET /api/users/{name}/stats", a.auth(a.userStats))
}

// subTitle is the title of a subscription key.
func subTitle(key string, bundles map[string]string) string {
	switch key {
	case subBalancers:
		return "Основная: 3 балансировщика"
	case subAll:
		return "Основная: балансировщики и все серверы пула"
	}
	if n, ok := bundles[key]; ok {
		return "Категория: " + n
	}
	return key + " (категория удалена)"
}

type catalogSub struct {
	Key     string `json:"key"`
	Title   string `json:"title"`
	Builtin bool   `json:"builtin"`
}

type catalogView struct {
	Nodes   []CustomNode `json:"nodes"`
	Sources []ExtSource  `json:"sources"` // subscriptions of external servers
	Bundles []Bundle     `json:"bundles"` // categories
	Subs    []catalogSub `json:"subs"`    // everything that can be given to a user, a plan or the default list
	Default []string     `json:"default_subs"`
	Days    int          `json:"default_days"`
}

func (a *API) catalog(r *http.Request) (*catalogView, error) {
	ns, err := a.store.ListCustomNodes(r.Context())
	if err != nil {
		return nil, err
	}
	bs, err := a.store.ListBundles(r.Context(), false)
	if err != nil {
		return nil, err
	}
	srcs, err := a.store.ListExtSources(r.Context())
	if err != nil {
		return nil, err
	}
	v := &catalogView{Nodes: ns, Sources: srcs, Bundles: bs, Default: a.cfg.defaultSubs(), Days: a.cfg.defaultDays(),
		Subs: []catalogSub{{subBalancers, subTitle(subBalancers, nil), true}, {subAll, subTitle(subAll, nil), true}}}
	for _, b := range bs {
		t := "Категория: " + b.Name
		if !b.Enabled {
			t += " (выключена)"
		}
		v.Subs = append(v.Subs, catalogSub{bundlePrefix + b.Slug, t, false})
	}
	return v, nil
}

// bundleNames maps "b:slug" to the name of the bundle.
func (a *API) bundleNames(r *http.Request) map[string]string {
	out := map[string]string{}
	if bs, err := a.store.ListBundles(r.Context(), false); err == nil {
		for _, b := range bs {
			out[bundlePrefix+b.Slug] = b.Name
		}
	}
	return out
}

func (a *API) catalogGet(w http.ResponseWriter, r *http.Request) {
	v, err := a.catalog(r)
	if err != nil {
		apiErr(w, 500, err)
		return
	}
	writeJSON(w, 200, v)
}

func (a *API) fail(w http.ResponseWriter, err error) {
	code := 400
	if errors.Is(err, ErrNotFound) {
		code = 404
	}
	apiErr(w, code, err)
}

func (a *API) customNodeSave(w http.ResponseWriter, r *http.Request) {
	var in customNodeInput
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&in); err != nil {
		apiErr(w, 400, fmt.Errorf("ожидается JSON сервера {name, link, mode, note, enabled}"))
		return
	}
	in.ID = 0
	if id := r.PathValue("id"); id != "" {
		in.ID, _ = strconv.ParseInt(id, 10, 64)
		if in.ID == 0 {
			apiErr(w, 400, fmt.Errorf("неверный номер узла"))
			return
		}
	}
	if _, err := a.store.SaveCustomNode(r.Context(), in); err != nil {
		a.fail(w, err)
		return
	}
	a.catalogGet(w, r)
}

func (a *API) customNodeDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := a.store.DeleteCustomNode(r.Context(), id); err != nil {
		a.fail(w, err)
		return
	}
	a.catalogGet(w, r)
}

func (a *API) extSourceSave(w http.ResponseWriter, r *http.Request) {
	var in extSourceInput
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&in); err != nil {
		apiErr(w, 400, fmt.Errorf("ожидается JSON подписки {name, url, mode, enabled}"))
		return
	}
	in.ID = 0
	if id := r.PathValue("id"); id != "" {
		in.ID, _ = strconv.ParseInt(id, 10, 64)
		if in.ID == 0 {
			apiErr(w, 400, fmt.Errorf("неверный номер подписки"))
			return
		}
	}
	id, err := a.store.SaveExtSource(r.Context(), in)
	if err != nil {
		a.fail(w, err)
		return
	}
	if in.URL != "" { // new or changed address: load the servers at once (errors are shown in the list)
		ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
		_ = a.store.RefreshExtSource(ctx, a.cfg, id)
		cancel()
	}
	a.catalogGet(w, r)
}

func (a *API) extSourceDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := a.store.DeleteExtSource(r.Context(), id); err != nil {
		a.fail(w, err)
		return
	}
	a.catalogGet(w, r)
}

func (a *API) extSourceRefresh(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	if err := a.store.RefreshExtSource(ctx, a.cfg, id); err != nil && errors.Is(err, ErrNotFound) {
		a.fail(w, err)
		return
	}
	a.catalogGet(w, r)
}

func (a *API) bundleSave(w http.ResponseWriter, r *http.Request) {
	var b Bundle
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536)).Decode(&b); err != nil {
		apiErr(w, 400, fmt.Errorf("ожидается JSON категории {slug, name, enabled, sort, main, nodes: [id], sources: [id]}"))
		return
	}
	b.ID = 0
	if id := r.PathValue("id"); id != "" {
		b.ID, _ = strconv.ParseInt(id, 10, 64)
		if b.ID == 0 {
			apiErr(w, 400, fmt.Errorf("неверный номер категории"))
			return
		}
	}
	if _, err := a.store.SaveBundle(r.Context(), b); err != nil {
		a.fail(w, err)
		return
	}
	a.catalogGet(w, r)
}

func (a *API) bundleDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	key, err := a.store.DeleteBundle(r.Context(), id)
	if err != nil {
		a.fail(w, err)
		return
	}
	// the key also leaves the default list
	def := a.cfg.defaultSubs()
	keep := def[:0:0]
	for _, k := range def {
		if k != key {
			keep = append(keep, k)
		}
	}
	if len(keep) != len(def) {
		raw, _ := json.Marshal(keep)
		_ = a.cfg.ApplySettings(map[string]json.RawMessage{"user_default_subs": raw})
		_ = a.store.PutSetting(r.Context(), "user_default_subs", raw)
	}
	a.catalogGet(w, r)
}

// userSubs sets the own list of subscriptions of a user ({"subs": [...]}) or returns him to the plan/default ({"subs": null}).
func (a *API) userSubs(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Subs []string `json:"subs"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&in); err != nil {
		apiErr(w, 400, fmt.Errorf("ожидается JSON {subs: [...] или null}"))
		return
	}
	if err := a.store.SetUserSubs(r.Context(), r.PathValue("name"), in.Subs); err != nil {
		a.fail(w, err)
		return
	}
	a.users(w, r)
}

func (a *API) userPlan(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PlanID int64 `json:"plan_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&in); err != nil {
		apiErr(w, 400, fmt.Errorf("ожидается JSON {plan_id: номер или 0}"))
		return
	}
	if in.PlanID != 0 {
		if _, err := a.store.PlanByID(r.Context(), in.PlanID); err != nil {
			a.fail(w, err)
			return
		}
	}
	if err := a.store.SetUserPlan(r.Context(), r.PathValue("name"), in.PlanID); err != nil {
		a.fail(w, err)
		return
	}
	a.users(w, r)
}

type userStatsView struct {
	*UserStats
	Enabled    bool       `json:"enabled"`
	Expires    int64      `json:"expires"`
	Email      string     `json:"email,omitempty"`
	Online     bool       `json:"online"`
	Sessions   []SessInfo `json:"sessions"`
	SpeedUp    int64      `json:"speed_up"`
	SpeedDown  int64      `json:"speed_down"`
	Errors     int64      `json:"errors"`
	LastError  string     `json:"last_error,omitempty"`
	SubFetched int64      `json:"sub_fetched"`
	SubFetches int64      `json:"sub_fetches"`
	Plan       string     `json:"plan,omitempty"`
	SubKeys    []string   `json:"sub_keys"`
	SubSource  string     `json:"sub_source"`
}

func (a *API) userStats(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	us, err := a.store.ListUsers(r.Context())
	if err != nil {
		apiErr(w, 500, err)
		return
	}
	var u *User
	for i := range us {
		if us[i].Name == name {
			u = &us[i]
		}
	}
	if u == nil {
		apiErr(w, 404, fmt.Errorf("пользователь не найден"))
		return
	}
	st, err := a.store.UserStatsOf(r.Context(), name, time.Now())
	if err != nil {
		apiErr(w, 500, err)
		return
	}
	v := userStatsView{UserStats: st, Enabled: u.Enabled, Sessions: []SessInfo{}, SubFetches: u.SubFetches}
	if u.Expires != nil {
		v.Expires = u.Expires.Unix()
	}
	if u.SubFetched != nil {
		v.SubFetched = u.SubFetched.Unix()
	}
	v.SubKeys, v.SubSource = effectiveSubs(a.cfg, *u)
	if u.PlanID != nil {
		if p, err := a.store.PlanByID(r.Context(), *u.PlanID); err == nil {
			v.Plan = p.Name
		}
	}
	if acc, err := a.store.AccountByUserID(r.Context(), u.ID); err == nil {
		v.Email = acc.Email
	}
	if a.stats != nil {
		sess, e, sp := a.stats.LiveOf(name)
		v.Sessions, v.Online = sess, len(sess) > 0
		v.SpeedUp, v.SpeedDown = sp.Up, sp.Down
		if e != nil {
			v.Errors, v.LastError = e.Count, e.Msg
		}
	}
	writeJSON(w, 200, v)
}

func ptrTime(t time.Time) *time.Time { return &t }
