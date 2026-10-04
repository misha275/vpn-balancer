package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	DatabaseURL   string        `yaml:"database_url"`
	Subscriptions []string      `yaml:"subscriptions"`
	SubUserAgent  string        `yaml:"sub_user_agent"`
	SubRefresh    time.Duration `yaml:"sub_refresh"`
	NodeGrace     time.Duration `yaml:"node_grace"`

	PublicHost  string `yaml:"public_host"`
	InboundPort int    `yaml:"inbound_port"`
	Reality     struct {
		PrivateKey      string `yaml:"private_key"`
		PublicKey       string `yaml:"public_key"`
		ShortID         string `yaml:"short_id"`
		HandshakeServer string `yaml:"handshake_server"`
		HandshakePort   int    `yaml:"handshake_port"`
		Fingerprint     string `yaml:"fingerprint"` // uTLS fingerprint written into user links
	} `yaml:"reality"`

	SingboxBin string        `yaml:"singbox_bin"`
	WorkDir    string        `yaml:"work_dir"`
	ClashAPI   string        `yaml:"clash_api"`
	TestPort   int           `yaml:"test_port"`
	TestSecret string        `yaml:"-"`
	MinReload  time.Duration `yaml:"min_reload_interval"`

	Gateway       string        `yaml:"gateway"`        // embedded (default) | external
	GatewayURL    string        `yaml:"gateway_url"`    // external: where the controller reaches the gateway, e.g. http://gateway:9000
	GatewayListen string        `yaml:"gateway_listen"` // external: control API of the gateway process
	GatewayBase   int           `yaml:"gateway_port_base"`
	GatewaySecret string        `yaml:"gateway_secret"` // optional; derived from the Reality key when empty
	DrainTimeout  time.Duration `yaml:"drain_timeout"`  // how long old connections may live on after a new config went live
	DrainUrgent   time.Duration `yaml:"drain_urgent"`   // same, when the change withdraws something (user, block rule)

	ProbeURLs        []string      `yaml:"probe_urls"`
	SpeedURL         string        `yaml:"speed_url"`
	BaselineAddrs    []string      `yaml:"baseline_addrs"`
	Tier1Interval    time.Duration `yaml:"tier1_interval"`
	Tier2Interval    time.Duration `yaml:"tier2_interval"`
	Tier3Interval    time.Duration `yaml:"tier3_interval"`
	WatchInterval    time.Duration `yaml:"watch_interval"`
	Tier3Top         int           `yaml:"tier3_top"`
	Tier2Concurrency int           `yaml:"tier2_concurrency"`
	MinSpeedKbps     *int          `yaml:"min_speed_kbps"`    // nodes slower than this are not chosen (default 8000 = 8 Mbit/s, 0 = off)
	RequiredServices []string      `yaml:"required_services"` // services that must open through a node (default telegram)
	Services         []string      `yaml:"services"`          // "name = address, address" lines; default list in quality.go
	SpeedTTL         time.Duration `yaml:"speed_ttl"`         // a speed measurement is repeated after this time
	ServiceInterval  time.Duration `yaml:"service_interval"`  // how often all nodes are checked against the services
	SwitchMargin     float64       `yaml:"switch_margin"`
	SwitchConfirm    int           `yaml:"switch_confirm"`
	TelegramToken    string        `yaml:"telegram_token"`
	TelegramChat     string        `yaml:"telegram_chat"`
	HTTPListen       string        `yaml:"http_listen"`

	// --- WireGuard for routers (see wireguard.go) ---
	WGPort     int    `yaml:"wg_port"`     // UDP port of the tunnel (default 51820)
	WGNetwork  string `yaml:"wg_network"`  // network inside the tunnel (default 10.77.0.0/24)
	WGEndpoint string `yaml:"wg_endpoint"` // address the routers connect to (default public_host)
	wgPeers    []WGPeer

	// --- country policy ---
	ExitCheck        *bool         `yaml:"exit_check"`             // measure where each node really exits (default: true)
	BlockedCountries []string      `yaml:"blocked_exit_countries"` // default: RU UA BY CN IR SY KP TM CU MM
	GeoURLs          []string      `yaml:"geo_urls"`
	GeoTTL           time.Duration `yaml:"geo_ttl"`
	GeoBlockedTTL    time.Duration `yaml:"geo_blocked_ttl"` // how soon to re-measure a node that exits in a blocked country
	blocked          map[string]bool
	mu               sync.RWMutex // guards the settings that can be changed at runtime (see settings.go)

	// node_identity: endpoint (default) merges links with identical connection parameters into one node;
	// link keeps every link of a subscription as a separate node.
	NodeIdentity string `yaml:"node_identity"`

	// --- routing rules for user traffic ---
	Rules         []RuleCfg `yaml:"rules"`
	DefaultAction string    `yaml:"default_action"` // proxy (default) | block

	// --- subscription for users ---
	GatewayName  string `yaml:"gateway_name"`
	SubListen    string `yaml:"sub_listen"` // e.g. 0.0.0.0:8081; empty = subscription endpoint off
	SubTLSCert   string `yaml:"sub_tls_cert"`
	SubTLSKey    string `yaml:"sub_tls_key"`
	SubPublicURL string `yaml:"sub_public_url"` // e.g. https://vpn.example.com:8081 (used in CLI output)
}

func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	if err := yaml.Unmarshal(raw, c); err != nil {
		return nil, err
	}
	if v := os.Getenv("DATABASE_URL"); v != "" {
		c.DatabaseURL = v
	}
	c.DatabaseURL = os.ExpandEnv(c.DatabaseURL) // allows ${DB_PASSWORD}
	def := func(p *time.Duration, v time.Duration) {
		if *p == 0 {
			*p = v
		}
	}
	defI := func(p *int, v int) {
		if *p == 0 {
			*p = v
		}
	}
	defS := func(p *string, v string) {
		if *p == "" {
			*p = v
		}
	}
	defS(&c.SubUserAgent, "sing-box")
	def(&c.SubRefresh, 30*time.Minute)
	def(&c.NodeGrace, 48*time.Hour)
	defI(&c.InboundPort, 443)
	defI(&c.Reality.HandshakePort, 443)
	defS(&c.Reality.Fingerprint, "ios")
	defS(&c.Reality.HandshakeServer, "www.microsoft.com")
	defS(&c.SingboxBin, "sing-box")
	defS(&c.WorkDir, "/var/lib/balancer")
	defS(&c.ClashAPI, "127.0.0.1:9090")
	defI(&c.TestPort, 2080)
	def(&c.MinReload, 2*time.Minute)
	defS(&c.Gateway, "embedded")
	defS(&c.GatewayListen, "0.0.0.0:9000")
	defI(&c.GatewayBase, 21000)
	defI(&c.WGPort, wgDefaultPort)
	defS(&c.WGNetwork, wgDefaultNetwork)
	def(&c.DrainTimeout, 15*time.Minute)
	def(&c.DrainUrgent, 5*time.Second)
	defS(&c.SpeedURL, "https://speed.cloudflare.com/__down?bytes=5000000")
	def(&c.Tier1Interval, time.Minute)
	def(&c.Tier2Interval, 3*time.Minute)
	def(&c.Tier3Interval, 10*time.Minute)
	def(&c.SpeedTTL, 12*time.Hour)
	def(&c.ServiceInterval, time.Hour)
	def(&c.WatchInterval, 5*time.Second)
	defI(&c.Tier3Top, 5)
	defI(&c.Tier2Concurrency, 20)
	defI(&c.SwitchConfirm, 3)
	if c.SwitchMargin == 0 {
		c.SwitchMargin = 1.15
	}
	defS(&c.HTTPListen, "127.0.0.1:8080")
	defS(&c.GatewayName, "Балансировщик")
	def(&c.GeoTTL, 6*time.Hour)
	def(&c.GeoBlockedTTL, 30*time.Minute)
	if p, err := netip.ParsePrefix(c.WGNetwork); err != nil || !p.Addr().Is4() || p.Bits() < 16 || p.Bits() > 29 {
		return nil, fmt.Errorf("wg_network must be an IPv4 network between /16 and /29, got %q", c.WGNetwork)
	}
	c.NodeIdentity = strings.ToLower(strings.TrimSpace(c.NodeIdentity))
	if c.NodeIdentity == "" {
		c.NodeIdentity = "endpoint"
	}
	if c.NodeIdentity != "endpoint" && c.NodeIdentity != "link" {
		return nil, fmt.Errorf("node_identity must be endpoint or link, got %q", c.NodeIdentity)
	}
	if c.ExitCheck == nil {
		on := true
		c.ExitCheck = &on
	}
	if c.BlockedCountries == nil {
		c.BlockedCountries = defaultBlockedCountries
	}
	c.blocked = map[string]bool{}
	for _, cc := range c.BlockedCountries {
		cc = strings.ToUpper(strings.TrimSpace(cc))
		if !isAlpha2(cc) {
			return nil, fmt.Errorf("blocked_exit_countries: %q is not a 2-letter country code", cc)
		}
		c.blocked[cc] = true
	}
	if len(c.GeoURLs) == 0 {
		c.GeoURLs = defaultGeoURLs
	}
	c.DefaultAction = strings.ToLower(strings.TrimSpace(c.DefaultAction))
	if c.DefaultAction == "" {
		c.DefaultAction = "proxy"
	}
	if c.DefaultAction != "proxy" && c.DefaultAction != "block" {
		return nil, fmt.Errorf("default_action must be proxy or block (traffic is never sent out of the server by default), got %q", c.DefaultAction)
	}
	if _, err := CompileRules(c.Rules, true); err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	if len(c.ProbeURLs) == 0 {
		c.ProbeURLs = []string{
			"https://www.gstatic.com/generate_204",
			"https://cp.cloudflare.com/generate_204",
			"https://www.youtube.com/generate_204",
		}
	}
	if c.RequiredServices == nil {
		c.RequiredServices = append([]string(nil), defaultRequiredServices...)
	}
	for i, n := range c.RequiredServices {
		c.RequiredServices[i] = strings.ToLower(strings.TrimSpace(n))
	}
	if len(c.Services) == 0 {
		c.Services = append([]string(nil), defaultServices...)
	}
	if _, err := parseServices(c.Services); err != nil {
		return nil, err
	}
	if len(c.BaselineAddrs) == 0 {
		c.BaselineAddrs = []string{"1.1.1.1:443", "8.8.8.8:443", "9.9.9.9:443"}
	}
	c.Gateway = strings.ToLower(strings.TrimSpace(c.Gateway))
	if c.Gateway != "embedded" && c.Gateway != "external" {
		return nil, fmt.Errorf("gateway must be embedded or external, got %q", c.Gateway)
	}
	if c.Gateway == "external" && strings.TrimSpace(c.GatewayURL) == "" {
		return nil, errors.New("gateway: external needs gateway_url (for example http://gateway:9000)")
	}
	if c.Reality.PrivateKey != "" && !strings.HasPrefix(c.Reality.PrivateKey, "<") {
		// stable across restarts: a gateway that outlives the controller keeps accepting the same probe logins
		c.TestSecret = derive(c.Reality.PrivateKey, "probe")
	} else {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		c.TestSecret = hex.EncodeToString(b)
	}
	return c, nil
}

// ValidateRun catches placeholders from config.example.yaml before sing-box gives a cryptic error.
func (c *Config) ValidateRun() error {
	for name, v := range map[string]string{
		"public_host": c.PublicHost, "reality.private_key": c.Reality.PrivateKey,
		"reality.public_key": c.Reality.PublicKey, "reality.short_id": c.Reality.ShortID,
	} {
		if v == "" || strings.HasPrefix(v, "<") {
			return fmt.Errorf("%s is not set", name)
		}
	}
	if len(c.Subscriptions) == 0 {
		// allowed: the installer starts without a subscription, add one with `subs add` or in the panel;
		// until then user traffic is rejected (there is no node to carry it)
		log.Printf("config: no subscriptions yet; add one with `subs add URL` or in the web panel")
	}
	return nil
}

// ---- Telegram notifications (rate limited per key) ----

type Notifier struct {
	token, chat string
	mu          sync.Mutex
	last        map[string]time.Time
}

func (n *Notifier) Notify(key, msg string, every time.Duration) {
	n.mu.Lock()
	if n.last == nil {
		n.last = map[string]time.Time{}
	}
	if time.Since(n.last[key]) < every {
		n.mu.Unlock()
		return
	}
	n.last[key] = time.Now()
	n.mu.Unlock()
	log.Printf("alert: %s", msg)
	if n.token == "" || n.chat == "" {
		return
	}
	go func() {
		cl := &http.Client{Timeout: 10 * time.Second}
		resp, err := cl.PostForm("https://api.telegram.org/bot"+n.token+"/sendMessage",
			url.Values{"chat_id": {n.chat}, "text": {msg}})
		if err != nil {
			log.Printf("telegram: %v", scrubErr(err)) // the URL contains the bot token
			return
		}
		resp.Body.Close()
	}()
}

func userLink(cfg *Config, name, uuid string) string {
	return fmt.Sprintf("vless://%s@%s:%d?encryption=none&flow=xtls-rprx-vision&security=reality&sni=%s&fp=%s&pbk=%s&sid=%s&type=tcp#%s",
		uuid, cfg.PublicHost, cfg.InboundPort, cfg.Reality.HandshakeServer, cfg.Reality.Fingerprint, cfg.Reality.PublicKey, cfg.Reality.ShortID, url.PathEscape(name))
}

// subURL is the address of the user's subscription ("" when the endpoint is not configured).
func subURL(cfg *Config, token string) string {
	if cfg.SubPublicURL == "" {
		return ""
	}
	return strings.TrimRight(cfg.SubPublicURL, "/") + "/sub/" + token
}

func printUser(cfg *Config, u User) {
	fmt.Printf("%-20s enabled=%-5v\n  gateway:      %s\n", u.Name, u.Enabled, userLink(cfg, cfg.getGatewayName(), u.UUID))
	if s := subURL(cfg, u.SubToken); s != "" {
		fmt.Printf("  subscription: %s\n", s)
	}
}

// overlayStored applies the settings saved in the database on top of config.yaml (bad keys are skipped).
func overlayStored(ctx context.Context, cfg *Config, st *Store) {
	m, _, err := st.LoadSettings(ctx)
	if err != nil {
		return
	}
	for k, raw := range m {
		one := map[string]json.RawMessage{k: raw}
		if ValidateSettings(one) == nil {
			_ = cfg.ApplySettings(one)
		}
	}
}

func main() {
	cfgPath := flag.String("c", "config.yaml", "path to config")
	flag.Parse()
	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	args := flag.Args()
	cmd := "run"
	if len(args) > 0 {
		cmd = args[0]
	}
	if cmd == "check" {
		// validates the config without touching the database or starting anything
		if err := cfg.ValidateRun(); err != nil {
			log.Fatalf("config: %v", err)
		}
		rules, _ := CompileRules(cfg.getRules(), true)
		fmt.Printf("config ok: %d rules -> %d sing-box rules, default action %q, blocked exit countries: %s\n",
			len(cfg.getRules()), len(rules), cfg.getDefaultAction(), strings.Join(cfg.getBlocked(), " "))
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if cmd == "gateway" {
		// the part users connect to: lives in its own container so that the controller can be updated without touching it
		if err := cfg.ValidateRun(); err != nil {
			log.Fatalf("config: %v", err)
		}
		RunGateway(ctx, cfg)
		return
	}
	st, err := NewStore(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("database: %v", err)
	}

	if cmd != "run" {
		overlayStored(ctx, cfg, st) // so that the command line sees the same settings as the running controller
	}
	switch cmd {
	case "run":
		if err := cfg.ValidateRun(); err != nil {
			log.Fatalf("config: %v", err)
		}
		run(ctx, cfg, st)
	case "adduser":
		if len(args) < 2 {
			log.Fatal("usage: adduser NAME")
		}
		if _, err := st.AddUser(ctx, args[1]); err != nil {
			log.Fatalf("adduser: %v", err)
		}
		us, err := st.ListUsers(ctx)
		if err != nil {
			log.Fatalf("adduser: %v", err)
		}
		for _, u := range us {
			if u.Name == args[1] {
				fmt.Println(userLink(cfg, cfg.getGatewayName(), u.UUID)) // first line stays the plain vless:// link
				if s := subURL(cfg, u.SubToken); s != "" {
					fmt.Println(s)
				}
			}
		}
	case "deluser":
		if len(args) < 2 {
			log.Fatal("usage: deluser NAME")
		}
		if err := st.SetUserEnabled(ctx, args[1], false); err != nil {
			log.Fatalf("deluser: %v", err)
		}
		fmt.Println("disabled")
	case "rmuser":
		if len(args) < 2 {
			log.Fatal("usage: rmuser NAME")
		}
		ok, err := st.DeleteUser(ctx, args[1])
		if err != nil {
			log.Fatalf("rmuser: %v", err)
		}
		if !ok {
			log.Fatalf("rmuser: user %q not found", args[1])
		}
		fmt.Println("deleted")
	case "users":
		us, err := st.ListUsers(ctx)
		if err != nil {
			log.Fatalf("users: %v", err)
		}
		for _, u := range us {
			printUser(cfg, u)
		}
	default:
		ok, err := runCLI(ctx, cfg, st, cmd, args[1:])
		if !ok {
			fmt.Fprintf(os.Stderr, "неизвестная команда %q\n\n", cmd)
			fmt.Printf(cliHelp, strings.Join(settingKeys(), ", "))
			os.Exit(2)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "ошибка:", err)
			os.Exit(1)
		}
	}
}

func run(ctx context.Context, cfg *Config, st *Store) {
	ctrlLogs := NewLogRing(3000) // the console of the panel
	log.SetOutput(io.MultiWriter(os.Stderr, ctrlLogs))
	notify := &Notifier{token: cfg.TelegramToken, chat: cfg.TelegramChat}
	core := NewCore(cfg)
	defer core.Stop()
	col := NewCollector(st, core, ctrlLogs)
	go col.Run(ctx)
	chk := NewChecker(cfg, st, core, notify)
	subs := &Subs{cfg: cfg, store: st, notify: notify, fails: map[string]int{}}
	refreshCh := make(chan struct{}, 1)
	// settings saved in the database (web panel / command line) override config.yaml and apply live
	WatchSettings(ctx, cfg, st, func(m map[string]json.RawMessage) {
		_, a := m["subscriptions"]
		_, b := m["node_identity"]
		if a || b {
			select {
			case refreshCh <- struct{}{}:
			default:
			}
		}
		go chk.evaluate(false)
	})
	adminToken, err := st.AdminToken(ctx)
	if err != nil {
		log.Fatalf("admin token: %v", err)
	}

	nodes, err := st.ActiveNodes(ctx, cfg.NodeGrace)
	if err != nil {
		log.Fatalf("nodes: %v", err)
	}
	if len(nodes) == 0 {
		// first start: nothing to work with until subscriptions are downloaded
		subs.Refresh(ctx)
		if nodes, err = st.ActiveNodes(ctx, cfg.NodeGrace); err != nil {
			log.Fatalf("nodes: %v", err)
		}
	}
	users, err := st.EnabledUsers(ctx)
	if err != nil {
		log.Fatalf("users: %v", err)
	}
	wgm := NewWGManager(cfg, st, core)
	if err := wgm.Load(ctx); err != nil {
		log.Printf("wireguard: %v", err)
	}
	if last := st.LastSelected(ctx); last != "" {
		chk.SetCurrent(last)
	}
	var active []*Node
	for i := 0; ; i++ {
		active, _, err = core.Apply(nodes, users, chk.CurrentTag())
		if err == nil {
			break
		}
		if i >= 24 || ctx.Err() != nil { // the gateway container may still be starting
			log.Fatalf("initial config: %v", err)
		}
		log.Printf("initial config: %v (retrying)", err)
		time.Sleep(5 * time.Second)
	}
	chk.SyncNodes(active)
	if len(nodes) == 0 {
		notify.Notify("nonodes", "🔴 Пул узлов пуст: проверьте подписки", time.Hour)
	}

	go core.Run(ctx)
	go chk.Run(ctx)
	go wgm.Reconcile(ctx)

	go func() {
		if len(nodes) > 0 {
			subs.Refresh(ctx) // restarts must not wait for slow subscriptions
		}
		t := time.NewTicker(cfg.SubRefresh)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				subs.Refresh(ctx)
			case <-refreshCh:
				subs.Refresh(ctx)
			}
		}
	}()

	// reconcile DB (nodes, users) -> sing-box config
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			if err := wgm.Load(ctx); err != nil {
				log.Printf("reconcile: wireguard peers: %v", err)
			}
			ns, err1 := st.ActiveNodes(ctx, cfg.NodeGrace)
			us, err2 := st.EnabledUsers(ctx)
			if err1 != nil || err2 != nil {
				log.Printf("reconcile: db error: %v %v", err1, err2)
				continue
			}
			act, applied, err := core.Apply(ns, us, chk.CurrentTag())
			wgm.Reconcile(ctx)
			if err != nil {
				log.Printf("reconcile: %v", err)
				continue
			}
			if applied {
				core.WaitReady(ctx, 30*time.Second)
				chk.SyncNodes(act)
			}
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if core.Ready() {
			w.Write([]byte("ok"))
			return
		}
		http.Error(w, "core down", http.StatusServiceUnavailable)
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(chk.Snapshot())
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		chk.WriteMetrics(w)
	})
	api := NewAPI(cfg, st, chk, core, adminToken, refreshCh)
	api.stats, api.logs = col, ctrlLogs
	api.Register(mux)
	log.Printf("panel: http://%s/ (token: `balancer token`)", cfg.HTTPListen)
	srv := &http.Server{Addr: cfg.HTTPListen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("http: %v", err)
		}
	}()

	if cfg.SubListen != "" {
		go NewSubServer(cfg, st).Serve(ctx)
	}

	<-ctx.Done()
	sc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(sc)
}
