package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// The gateway is what users connect to. It keeps their connections alive while
// the controller is updated, restarted or reconfigured:
//
//	user -> front (TCP, public port) -> sing-box instance ("slot") -> upstream node
//
// A new configuration never replaces the running sing-box. Instead a second
// instance is started next to it with the new config, the front sends all NEW
// connections to it, and the old instance keeps serving the connections that
// are already open until they end (or a drain timeout passes). This is
// "blue/green" at the connection level, so users do not notice a reload.
//
// The engine can run inside the controller (gateway: embedded) or in its own
// container (gateway: external, command `balancer gateway`). In the second case
// the controller can be updated or restarted without touching a single user connection.

const (
	gatewayAPIVersion = 1
	engineSlots       = 4 // ring of sing-box instances: one active, the others draining
)

// ApplyReq is one new configuration for the gateway.
type ApplyReq struct {
	Config      json.RawMessage `json:"config"`      // sing-box config produced by BuildConfig
	Fingerprint string          `json:"fingerprint"` // what the controller thinks this config is made of
	Meta        string          `json:"meta"`        // opaque for the gateway, returned in the state (lets a restarted controller adopt)
	Urgent      bool            `json:"urgent"`      // old connections must end soon (a user was removed, a block rule appeared ...)
	DrainSec    int             `json:"drain_sec"`   // 0 = the gateway's own default
}

type SlotInfo struct {
	Index      int        `json:"index"`
	Role       string     `json:"role"` // active | draining
	Conns      int64      `json:"conns"`
	Since      time.Time  `json:"since"`
	DrainUntil *time.Time `json:"drain_until,omitempty"`
}

type GWState struct {
	API         int        `json:"api"`
	Active      int        `json:"active"` // slot index, -1 = nothing runs yet
	Fingerprint string     `json:"fingerprint"`
	Meta        string     `json:"meta"`
	Gen         int64      `json:"gen"`
	Started     time.Time  `json:"started"`
	AppliedAt   time.Time  `json:"applied_at"`
	Clash       int        `json:"clash_port"`
	Socks       int        `json:"socks_port"`
	FrontUp     bool       `json:"front_up"`
	WG          bool       `json:"wg"`    // the WireGuard endpoint runs
	WGFp        string     `json:"wg_fp"` // which configuration of it
	Slots       []SlotInfo `json:"slots"`
}

// Gateway is implemented by the in-process Engine and by the client of a gateway container.
type Gateway interface {
	Apply(ctx context.Context, req ApplyReq) (GWState, error)
	State(ctx context.Context) (GWState, error)
	CloseAll(ctx context.Context) error
	Stats(ctx context.Context) (GWStats, error)                                         // live sessions and what happened since the previous call
	Logs(ctx context.Context, after int64, limit int) (LogPage, error)                  // console of the gateway
	UserLogs(ctx context.Context, user string, after int64, limit int) (LogPage, error) // errors of one user
	ApplyWG(ctx context.Context, cfg []byte, fp string) error                           // the WireGuard endpoint of the gateway (nil config = off)
	Host() string                                                                       // address under which the controller reaches the Clash API and the probe inbound
}

// gatewaySecret protects the control API and the Clash API of the gateway. Both
// processes derive the same value from config.yaml (or take gateway_secret).
func (c *Config) gatewaySecret() string {
	if c.GatewaySecret != "" {
		return c.GatewaySecret
	}
	return derive(c.Reality.PrivateKey, "gateway")
}

func derive(key, purpose string) string {
	m := hmac.New(sha256.New, []byte(key))
	m.Write([]byte("vpn-balancer|" + purpose))
	return hex.EncodeToString(m.Sum(nil))[:40]
}

// ---------------------------------------------------------------- engine

type engSlot struct {
	idx                   int
	inbound, clash, socks int
	wgIn                  int
	ready                 int // the port that tells the instance serves (set by patchConfig)
	cmd                   *exec.Cmd
	exited                chan struct{}
	stopping              bool
	state                 string // "" (free) | active | draining
	cfg                   []byte
	since                 time.Time
	drainUntil            time.Time
	conns                 atomic.Int64
}

type Engine struct {
	bin, workDir, bind, secret string
	publicPort, base           int
	drain, urgentGrace         time.Duration
	recoverLast                bool

	applyMu sync.Mutex // one Apply at a time
	mu      sync.Mutex // protects everything below
	slots   [engineSlots]*engSlot
	active  int
	fp      string
	meta    string
	applied time.Time
	started time.Time
	gen     atomic.Int64
	frontUp atomic.Bool
	stopped atomic.Bool
	wg      wgProc
	wgFront int
	tr      *tracker
	logs    *LogRing
	done    chan struct{}
	http    *http.Client
}

func NewEngine(cfg *Config, bind string, recoverLast bool) *Engine {
	e := &Engine{
		bin: cfg.SingboxBin, workDir: cfg.WorkDir, bind: bind, secret: cfg.gatewaySecret(),
		publicPort: cfg.InboundPort, base: cfg.GatewayBase,
		drain: cfg.DrainTimeout, urgentGrace: cfg.DrainUrgent, recoverLast: recoverLast,
		active: -1, started: time.Now(), done: make(chan struct{}),
		http: &http.Client{Timeout: 5 * time.Second},
		tr:   newTracker(), logs: NewLogRing(3000), wgFront: cfg.wgFrontPort(),
	}
	for i := range e.slots {
		e.slots[i] = &engSlot{idx: i, inbound: e.base + 10*i + 1, clash: e.base + 10*i + 2, socks: e.base + 10*i + 3, wgIn: e.base + 10*i + 4}
	}
	return e
}

func (e *Engine) Host() string { return "127.0.0.1" }

// patchConfig points the listeners of a generated config at the ports of one slot.
func (e *Engine) patchConfig(raw []byte, s *engSlot) ([]byte, bool, error) {
	var conf map[string]any
	if err := json.Unmarshal(raw, &conf); err != nil {
		return nil, false, fmt.Errorf("config is not JSON: %w", err)
	}
	hasUsers := false
	s.ready = 0
	ins, _ := conf["inbounds"].([]any)
	for _, in := range ins {
		m, ok := in.(map[string]any)
		if !ok {
			continue
		}
		switch m["tag"] {
		case "vless-in":
			hasUsers = true
			s.ready = s.inbound
			m["listen"], m["listen_port"] = "127.0.0.1", s.inbound // only the front may reach it
		case "probe-in":
			m["listen"], m["listen_port"] = e.bind, s.socks
		case "wg-in":
			hasUsers = true
			if s.ready == 0 {
				s.ready = s.wgIn
			}
			m["listen"], m["listen_port"] = "127.0.0.1", s.wgIn // only the front may reach it
		}
	}
	// the "info" level is what tells which user a connection belongs to (see stats_gw.go); the lines themselves are not kept
	conf["log"] = map[string]any{"level": "info", "timestamp": true}
	exp, _ := conf["experimental"].(map[string]any)
	if exp == nil {
		exp = map[string]any{}
		conf["experimental"] = exp
	}
	exp["clash_api"] = map[string]any{"external_controller": fmt.Sprintf("%s:%d", e.bind, s.clash), "secret": e.secret}
	out, err := json.MarshalIndent(conf, "", "  ")
	return out, hasUsers, err
}

func (e *Engine) clashReq(s *engSlot, method, path string) (*http.Response, error) {
	req, err := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", s.clash, path), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+e.secret)
	return e.http.Do(req)
}

// startSlot starts sing-box with an already patched config and waits until it serves.
func (e *Engine) startSlot(s *engSlot, cfg []byte, hasUsers bool) error {
	if err := os.MkdirAll(e.workDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(e.workDir, fmt.Sprintf("slot-%d.json", s.idx))
	if err := os.WriteFile(path, cfg, 0o600); err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(cctx, e.bin, "check", "-c", path).CombinedOutput(); err != nil {
		return fmt.Errorf("sing-box check failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	cmd := exec.Command(e.bin, "run", "-c", path)
	pr, pw, err := os.Pipe()
	if err != nil {
		return err
	}
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		pr.Close()
		pw.Close()
		return err
	}
	pw.Close()
	go e.readOutput(s.idx, pr)
	exited := make(chan struct{})
	e.mu.Lock()
	s.cmd, s.exited, s.stopping, s.cfg = cmd, exited, false, cfg
	e.mu.Unlock()
	go func() {
		err := cmd.Wait()
		close(exited)
		e.onExit(s, cmd, err, hasUsers)
	}()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-exited:
			return errors.New("sing-box exited right after the start")
		default:
		}
		if resp, err := e.clashReq(s, "GET", "/version"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				if !hasUsers {
					return nil
				}
				if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", s.ready), time.Second); err == nil {
					c.Close()
					return nil
				}
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	e.stopSlot(s)
	return errors.New("sing-box did not become ready in 30 s")
}

// readOutput reads the log of one sing-box instance: user lines feed the statistics, warnings and errors go to the console.
func (e *Engine) readOutput(slot int, r *os.File) {
	defer r.Close()
	sink := &lineSink{slot: slot, t: e.tr, idPort: map[string]int{}, idUser: map[string]string{}, pass: func(l string) {
		l = reANSI.ReplaceAllString(l, "")
		fmt.Fprintln(os.Stdout, "[sing-box "+strconv.Itoa(slot)+"] "+l)
		e.logs.Add("[sing-box " + strconv.Itoa(slot) + "] " + l)
	}}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		sink.line(sc.Text())
	}
	_, _ = io.Copy(io.Discard, r) // never leave the pipe unread (an unread pipe would block sing-box), e.g. after a line that is too long
}

// Stats implements Gateway.
func (e *Engine) Stats(ctx context.Context) (GWStats, error) { return e.tr.drain(), nil }

// Logs implements Gateway.
func (e *Engine) Logs(ctx context.Context, after int64, limit int) (LogPage, error) {
	return e.logs.Since(after, limit), nil
}

// UserLogs implements Gateway.
func (e *Engine) UserLogs(ctx context.Context, user string, after int64, limit int) (LogPage, error) {
	return e.tr.UserLogs(user, after, limit), nil
}

// onExit restarts the active instance if it dies by itself (watchdog).
func (e *Engine) onExit(s *engSlot, cmd *exec.Cmd, err error, hasUsers bool) {
	e.mu.Lock()
	intended := s.stopping || s.cmd != cmd
	isActive := e.active == s.idx && s.state == "active"
	cfg := s.cfg
	e.mu.Unlock()
	if intended || e.stopped.Load() {
		return
	}
	if !isActive {
		log.Printf("gateway: instance %d exited (%v)", s.idx, err)
		return
	}
	log.Printf("gateway: active sing-box (slot %d) exited (%v), restarting", s.idx, err)
	for !e.stopped.Load() {
		time.Sleep(time.Second)
		e.mu.Lock()
		still := e.active == s.idx && s.state == "active" && s.cmd == cmd
		e.mu.Unlock()
		if !still {
			return // replaced by a newer configuration meanwhile
		}
		if err := e.startSlot(s, cfg, hasUsers); err != nil {
			log.Printf("gateway: restart failed: %v", err)
			continue
		}
		e.gen.Add(1)
		return
	}
}

func (e *Engine) stopSlot(s *engSlot) {
	e.mu.Lock()
	cmd, exited := s.cmd, s.exited
	s.stopping = true
	e.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-exited:
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		<-exited
	}
}

func (e *Engine) freeSlot(s *engSlot) {
	e.stopSlot(s)
	e.mu.Lock()
	s.state, s.cmd = "", nil
	s.conns.Store(0)
	e.mu.Unlock()
}

// pickSlot chooses the instance for a new configuration: a free one, else the oldest draining one (its connections are cut).
func (e *Engine) pickSlot() (*engSlot, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	start := e.active + 1
	if e.active < 0 {
		start = 0
	}
	for i := 0; i < engineSlots; i++ {
		s := e.slots[(start+i)%engineSlots]
		if s.state == "" {
			return s, false
		}
	}
	var oldest *engSlot
	for _, s := range e.slots {
		if s.state == "draining" && (oldest == nil || s.since.Before(oldest.since)) {
			oldest = s
		}
	}
	return oldest, true
}

// Apply starts the new configuration next to the running one and switches new connections to it.
func (e *Engine) Apply(ctx context.Context, req ApplyReq) (GWState, error) {
	e.applyMu.Lock()
	defer e.applyMu.Unlock()
	s, busy := e.pickSlot()
	if s == nil {
		return GWState{}, errors.New("no free instance")
	}
	if busy {
		log.Printf("gateway: all instances are busy, cutting the oldest draining one (slot %d)", s.idx)
		e.freeSlot(s)
	}
	cfg, hasUsers, err := e.patchConfig(req.Config, s)
	if err != nil {
		return GWState{}, err
	}
	if err := e.startSlot(s, cfg, hasUsers); err != nil {
		e.freeSlot(s)
		return GWState{}, err // the old instance keeps serving
	}
	grace := e.drain
	if req.DrainSec > 0 {
		grace = time.Duration(req.DrainSec) * time.Second
	}
	if req.Urgent {
		grace = e.urgentGrace
	}
	now := time.Now()
	e.mu.Lock()
	old := (*engSlot)(nil)
	if e.active >= 0 {
		old = e.slots[e.active]
	}
	s.state, s.since = "active", now
	e.active, e.fp, e.meta, e.applied = s.idx, req.Fingerprint, req.Meta, now
	if old != nil && old.state == "active" {
		old.state, old.since, old.drainUntil = "draining", now, now.Add(grace)
	}
	e.mu.Unlock()
	e.gen.Add(1)
	e.persist(req)
	if old != nil {
		log.Printf("gateway: new configuration is live on instance %d; instance %d serves its %d open connection(s) for up to %s",
			s.idx, old.idx, old.conns.Load(), grace.Round(time.Second))
		go e.drainer(old)
	} else {
		log.Printf("gateway: configuration is live on instance %d", s.idx)
	}
	return e.State(ctx)
}

// drainer stops an old instance when its last connection ends (or on timeout).
func (e *Engine) drainer(old *engSlot) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for range t.C {
		e.mu.Lock()
		draining := old.state == "draining"
		until := old.drainUntil
		since := old.since
		e.mu.Unlock()
		if !draining || e.stopped.Load() {
			return
		}
		if time.Now().After(until) || (old.conns.Load() == 0 && time.Since(since) > 3*time.Second) {
			log.Printf("gateway: instance %d stopped (%d connection(s) were still open)", old.idx, old.conns.Load())
			e.freeSlot(old)
			return
		}
	}
}

func (e *Engine) lastPath() string { return filepath.Join(e.workDir, "gateway-last.json") }

// persist keeps the last configuration so that a restarted gateway serves again without waiting for the controller.
func (e *Engine) persist(req ApplyReq) {
	b, err := json.Marshal(req)
	if err != nil {
		return
	}
	tmp := e.lastPath() + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, e.lastPath())
	}
}

func (e *Engine) State(ctx context.Context) (GWState, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := GWState{API: gatewayAPIVersion, Active: e.active, Fingerprint: e.fp, Meta: e.meta,
		Gen: e.gen.Load(), Started: e.started, AppliedAt: e.applied, FrontUp: e.frontUp.Load()}
	st.WG, st.WGFp = e.wgState()
	if e.active >= 0 {
		st.Clash, st.Socks = e.slots[e.active].clash, e.slots[e.active].socks
	}
	for _, s := range e.slots {
		if s.state == "" {
			continue
		}
		si := SlotInfo{Index: s.idx, Role: s.state, Conns: s.conns.Load(), Since: s.since}
		if s.state == "draining" {
			d := s.drainUntil
			si.DrainUntil = &d
		}
		st.Slots = append(st.Slots, si)
	}
	return st, nil
}

// CloseAll drops the open connections of every running instance (used after a failover).
func (e *Engine) CloseAll(ctx context.Context) error {
	e.mu.Lock()
	var live []*engSlot
	for _, s := range e.slots {
		if s.state != "" {
			live = append(live, s)
		}
	}
	e.mu.Unlock()
	for _, s := range live {
		if resp, err := e.clashReq(s, "DELETE", "/connections"); err == nil {
			resp.Body.Close()
		}
	}
	return nil
}

// Run serves the front until ctx ends, then stops every instance.
func (e *Engine) Run(ctx context.Context) {
	defer close(e.done)
	go e.tr.reportLoop(ctx.Done())
	if e.recoverLast {
		go e.recover()
		go e.recoverWG()
	}
	go e.serveWGFront(ctx)
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", e.publicPort))
	if err != nil {
		log.Printf("gateway: cannot listen on :%d: %v", e.publicPort, err)
		return
	}
	e.frontUp.Store(true)
	log.Printf("gateway: front listens on :%d", e.publicPort)
	go func() {
		<-ctx.Done()
		e.stopped.Store(true)
		ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go e.handle(c)
	}
	e.frontUp.Store(false)
	e.Shutdown()
}

func (e *Engine) recover() {
	b, err := os.ReadFile(e.lastPath())
	if err != nil {
		return
	}
	var req ApplyReq
	if json.Unmarshal(b, &req) != nil || len(req.Config) == 0 {
		return
	}
	e.mu.Lock()
	has := e.active >= 0
	e.mu.Unlock()
	if has {
		return
	}
	log.Printf("gateway: restoring the last configuration")
	if _, err := e.Apply(context.Background(), req); err != nil {
		log.Printf("gateway: restore failed: %v", err)
	}
}

func (e *Engine) Shutdown() {
	e.stopped.Store(true)
	e.stopWG()
	for _, s := range e.slots {
		e.mu.Lock()
		run := s.cmd != nil
		e.mu.Unlock()
		if run {
			e.stopSlot(s)
		}
	}
}

func (e *Engine) handle(c net.Conn) {
	e.handleTo(c, func(s *engSlot) int { return s.inbound }, false)
}

func (e *Engine) handleTo(c net.Conn, portOf func(*engSlot) int, viaWG bool) {
	e.mu.Lock()
	var s *engSlot
	if e.active >= 0 {
		s = e.slots[e.active]
	}
	e.mu.Unlock()
	if s == nil {
		c.Close()
		return
	}
	d, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", portOf(s)), 3*time.Second)
	if err != nil {
		c.Close()
		return
	}
	s.conns.Add(1)
	defer s.conns.Add(-1)
	port := 0
	if la, ok := d.LocalAddr().(*net.TCPAddr); ok {
		port = la.Port
	}
	var from net.Addr = c.RemoteAddr()
	if viaWG {
		from = wgAddr{}
	}
	sess := e.tr.open(s.idx, port, from)
	defer e.tr.end(sess)
	pipe(&cconn{Conn: c, s: sess, t: e.tr}, d)
}

// pipe copies both directions and ends when both are done (a lone half-open direction is cut after a while).
func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	select {
	case <-done:
	case <-time.After(30 * time.Second):
	}
	a.Close()
	b.Close()
}

// ---------------------------------------------------------------- gateway container

// RunGateway is the command `balancer gateway`: the front, the instances and a small control API for the controller.
func RunGateway(ctx context.Context, cfg *Config) {
	e := NewEngine(cfg, "0.0.0.0", true)
	log.SetOutput(io.MultiWriter(os.Stderr, e.logs)) // the console of the gateway shows its own messages too
	go e.Run(ctx)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if e.frontUp.Load() {
			w.Write([]byte("ok"))
			return
		}
		http.Error(w, "front is down", http.StatusServiceUnavailable)
	})
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(got), []byte(cfg.gatewaySecret())) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("GET /v1/state", auth(func(w http.ResponseWriter, r *http.Request) {
		st, _ := e.State(r.Context())
		writeJSON(w, 200, st)
	}))
	mux.HandleFunc("POST /v1/apply", auth(func(w http.ResponseWriter, r *http.Request) {
		var req ApplyReq
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<20)).Decode(&req); err != nil || len(req.Config) == 0 {
			apiErr(w, 400, fmt.Errorf("bad request"))
			return
		}
		st, err := e.Apply(context.Background(), req) // not tied to the request: a dropped connection must not abort a half-done switch
		if err != nil {
			apiErr(w, 500, err)
			return
		}
		writeJSON(w, 200, st)
	}))
	mux.HandleFunc("GET /v1/stats", auth(func(w http.ResponseWriter, r *http.Request) {
		st, _ := e.Stats(r.Context())
		writeJSON(w, 200, st)
	}))
	mux.HandleFunc("GET /v1/logs", auth(func(w http.ResponseWriter, r *http.Request) {
		after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if u := r.URL.Query().Get("user"); u != "" {
			pg, _ := e.UserLogs(r.Context(), u, after, limit)
			writeJSON(w, 200, pg)
			return
		}
		pg, _ := e.Logs(r.Context(), after, limit)
		writeJSON(w, 200, pg)
	}))
	e.registerWG(mux, auth)
	mux.HandleFunc("POST /v1/closeall", auth(func(w http.ResponseWriter, r *http.Request) {
		_ = e.CloseAll(r.Context())
		writeJSON(w, 200, map[string]string{"ok": "closed"})
	}))
	srv := &http.Server{Addr: cfg.GatewayListen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(sc)
	}()
	log.Printf("gateway: control API on %s (reachable only inside the compose network)", cfg.GatewayListen)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("gateway: %v", err)
	}
	<-ctx.Done()
	select { // let Run finish stopping the instances
	case <-e.done:
	case <-time.After(10 * time.Second):
	}
}

// ---------------------------------------------------------------- client of a gateway container

type remoteGateway struct {
	base   string
	host   string
	secret string
	http   *http.Client
}

func newRemoteGateway(cfg *Config) (*remoteGateway, error) {
	u, err := url.Parse(cfg.GatewayURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("gateway_url %q is not a valid address", cfg.GatewayURL)
	}
	return &remoteGateway{base: strings.TrimRight(cfg.GatewayURL, "/"), host: u.Hostname(), secret: cfg.gatewaySecret(),
		http: &http.Client{Timeout: 90 * time.Second}}, nil
}

func (g *remoteGateway) Host() string { return g.host }

func (g *remoteGateway) do(ctx context.Context, method, path string, body any, timeout time.Duration) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, g.base+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+g.secret)
	resp, err := g.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			return nil, errors.New("gateway: " + e.Error)
		}
		return nil, fmt.Errorf("gateway: http %d", resp.StatusCode)
	}
	return data, nil
}

func (g *remoteGateway) Apply(ctx context.Context, req ApplyReq) (GWState, error) {
	data, err := g.do(ctx, "POST", "/v1/apply", req, 80*time.Second)
	if err != nil {
		return GWState{}, err
	}
	var st GWState
	return st, json.Unmarshal(data, &st)
}

func (g *remoteGateway) State(ctx context.Context) (GWState, error) {
	data, err := g.do(ctx, "GET", "/v1/state", nil, 4*time.Second)
	if err != nil {
		return GWState{}, err
	}
	var st GWState
	if err := json.Unmarshal(data, &st); err != nil {
		return GWState{}, err
	}
	if st.API != gatewayAPIVersion {
		return st, fmt.Errorf("gateway API version %d, the controller needs %d: update the gateway (bash install.sh update --gateway)", st.API, gatewayAPIVersion)
	}
	return st, nil
}

func (g *remoteGateway) CloseAll(ctx context.Context) error {
	_, err := g.do(ctx, "POST", "/v1/closeall", struct{}{}, 5*time.Second)
	return err
}

func (g *remoteGateway) Stats(ctx context.Context) (GWStats, error) {
	data, err := g.do(ctx, "GET", "/v1/stats", nil, 4*time.Second)
	if err != nil {
		return GWStats{}, err
	}
	var st GWStats
	return st, json.Unmarshal(data, &st)
}

func (g *remoteGateway) UserLogs(ctx context.Context, user string, after int64, limit int) (LogPage, error) {
	data, err := g.do(ctx, "GET", fmt.Sprintf("/v1/logs?user=%s&after=%d&limit=%d", url.QueryEscape(user), after, limit), nil, 4*time.Second)
	if err != nil {
		return LogPage{}, err
	}
	var pg LogPage
	return pg, json.Unmarshal(data, &pg)
}

func (g *remoteGateway) Logs(ctx context.Context, after int64, limit int) (LogPage, error) {
	data, err := g.do(ctx, "GET", fmt.Sprintf("/v1/logs?after=%d&limit=%d", after, limit), nil, 4*time.Second)
	if err != nil {
		return LogPage{}, err
	}
	var pg LogPage
	return pg, json.Unmarshal(data, &pg)
}

// wgAddr marks sessions that come through the WireGuard tunnel.
type wgAddr struct{}

func (wgAddr) Network() string { return "wireguard" }
func (wgAddr) String() string  { return "WireGuard" }
