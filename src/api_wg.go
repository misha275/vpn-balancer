package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type wgPeerView struct {
	Name      string   `json:"name"`
	Address   string   `json:"address"`
	Subnets   []string `json:"subnets"`
	Enabled   bool     `json:"enabled"`
	PublicKey string   `json:"public_key"`
	Created   int64    `json:"created"`
}

type wgView struct {
	Port      int          `json:"port"`
	Network   string       `json:"network"`
	ServerIP  string       `json:"server_address"`
	ServerKey string       `json:"server_public_key"`
	Endpoint  string       `json:"endpoint"`
	Running   bool         `json:"running"` // the gateway runs the tunnel
	Peers     []wgPeerView `json:"peers"`
}

func (a *API) wgEndpoint() string {
	if a.cfg.WGEndpoint != "" {
		return a.cfg.WGEndpoint
	}
	return a.cfg.PublicHost
}

func (a *API) wgOverview(r *http.Request) (*wgView, error) {
	_, pub, err := a.store.WGServerKey(r.Context())
	if err != nil {
		return nil, err
	}
	peers, err := a.store.ListWGPeers(r.Context())
	if err != nil {
		return nil, err
	}
	v := &wgView{Port: a.cfg.wgPort(), Network: a.cfg.wgNetwork().String(), ServerIP: a.cfg.wgServerAddr().String(), ServerKey: pub,
		Endpoint: a.wgEndpoint(), Peers: []wgPeerView{}}
	if st, err := a.core.GatewayState(); err == nil {
		v.Running = st.WG
	}
	for _, p := range peers {
		v.Peers = append(v.Peers, wgPeerView{p.Name, p.Address, p.Subnets, p.Enabled, p.PublicKey, p.Created.Unix()})
	}
	return v, nil
}

func (a *API) wgGet(w http.ResponseWriter, r *http.Request) {
	v, err := a.wgOverview(r)
	if err != nil {
		apiErr(w, 500, err)
		return
	}
	writeJSON(w, 200, v)
}

func (a *API) wgAdd(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name    string   `json:"name"`
		Subnets []string `json:"subnets"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&in); err != nil {
		apiErr(w, 400, fmt.Errorf("ожидается JSON {name, subnets}"))
		return
	}
	if _, err := a.store.AddWGPeer(r.Context(), a.cfg, in.Name, in.Subnets); err != nil {
		apiErr(w, 400, err)
		return
	}
	a.wgGet(w, r)
}

func (a *API) wgOp(w http.ResponseWriter, r *http.Request) {
	name, op := r.PathValue("name"), r.PathValue("op")
	if op != "enable" && op != "disable" {
		apiErr(w, 400, fmt.Errorf("операция enable или disable"))
		return
	}
	if err := a.store.SetWGPeerEnabled(r.Context(), name, op == "enable"); err != nil {
		apiErr(w, 404, err)
		return
	}
	a.wgGet(w, r)
}

func (a *API) wgDelete(w http.ResponseWriter, r *http.Request) {
	ok, err := a.store.DeleteWGPeer(r.Context(), r.PathValue("name"))
	if err != nil {
		apiErr(w, 500, err)
		return
	}
	if !ok {
		apiErr(w, 404, fmt.Errorf("пара не найдена"))
		return
	}
	a.wgGet(w, r)
}

// wgConfig returns what the operator pastes into the router (format=routeros) or imports into a WireGuard app (format=wgquick).
func (a *API) wgConfig(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	peers, err := a.store.ListWGPeers(r.Context())
	if err != nil {
		apiErr(w, 500, err)
		return
	}
	var peer *WGPeer
	for i := range peers {
		if peers[i].Name == name {
			peer = &peers[i]
		}
	}
	if peer == nil {
		apiErr(w, 404, fmt.Errorf("пара не найдена"))
		return
	}
	_, pub, err := a.store.WGServerKey(r.Context())
	if err != nil {
		apiErr(w, 500, err)
		return
	}
	endpoint := strings.TrimSpace(r.URL.Query().Get("endpoint"))
	if endpoint == "" {
		endpoint = a.wgEndpoint()
	}
	if strings.ContainsAny(endpoint, "\" \n\r\\;$`'") || endpoint == "" {
		apiErr(w, 400, fmt.Errorf("адрес сервера: укажите IP или имя без пробелов"))
		return
	}
	var text string
	switch r.URL.Query().Get("format") {
	case "wgquick":
		text = wgQuickConfig(a.cfg, pub, endpoint, *peer)
	default:
		text = routerOSScript(a.cfg, pub, endpoint, *peer)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(text))
}
