package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// dbCache keeps the certificates and the account key of Let's Encrypt in PostgreSQL, so they survive a recreated container.
// Test and production certificates never mix: they live under different keys.
type dbCache struct {
	st     *Store
	prefix string
}

func (c dbCache) Get(ctx context.Context, key string) ([]byte, error) {
	b, err := c.st.AcmeGet(ctx, c.prefix+key)
	if errors.Is(err, ErrNotFound) {
		return nil, autocert.ErrCacheMiss
	}
	return b, err
}
func (c dbCache) Put(ctx context.Context, key string, data []byte) error {
	return c.st.AcmePut(ctx, c.prefix+key, data)
}
func (c dbCache) Delete(ctx context.Context, key string) error {
	return c.st.AcmeDelete(ctx, c.prefix+key)
}

// CertStatus is what the panel shows about the certificate of the site.
type CertStatus struct {
	Domain    string    `json:"domain"`
	OK        bool      `json:"ok"`
	NotAfter  time.Time `json:"not_after"`
	Issuer    string    `json:"issuer"`
	Err       string    `json:"error"`
	CheckedAt time.Time `json:"checked_at"`
	Staging   bool      `json:"staging"`
	Running   bool      `json:"running"` // the listeners are up
	Message   string    `json:"message"` // what is wrong with the settings (no domain ...)
	HTTPS     string    `json:"https"`   // address the site listens on for HTTPS
	HTTP      string    `json:"http"`    // ... and for HTTP
	Public    string    `json:"public"`  // how users open it
	Via443    bool      `json:"via_443"` // the gateway hands browsers over to the site on port 443
}

// tlsProvider turns the settings into a TLS configuration (autocert in production, something local in tests).
type tlsProvider struct {
	cfg      *tls.Config
	httpWrap func(http.Handler) http.Handler // handles the challenge requests on port 80
}

// SiteServer runs the public site: HTTP on port 80 (certificate challenge, redirect), HTTPS with a certificate that is issued
// and renewed automatically. It follows the settings of the panel: enabling, a new domain, the test mode take effect within seconds.
type SiteServer struct {
	cfg     *Config
	st      *Store
	handler http.Handler

	providerFn func(sc SiteCfg, st *Store) (*tlsProvider, error) // replaced in tests

	mu       sync.Mutex
	run      runKey
	httpSrv  *http.Server
	httpsSrv *http.Server
	stop     context.CancelFunc
	status   CertStatus
	checkNow chan struct{}
	lastMsg  string
}

// runKey is everything a running instance depends on; a change restarts it.
type runKey struct {
	enabled         bool
	domain, email   string
	staging, via443 bool
	httpL, httpsL   string
	allowHTTP       bool
}

func NewSiteServer(cfg *Config, st *Store, h http.Handler) *SiteServer {
	return &SiteServer{cfg: cfg, st: st, handler: h, providerFn: autocertProvider, checkNow: make(chan struct{}, 1)}
}

func autocertProvider(sc SiteCfg, st *Store) (*tlsProvider, error) {
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(sc.Domain),
		Cache:      dbCache{st, map[bool]string{true: "staging/", false: ""}[sc.Staging]},
		Email:      sc.Email,
	}
	if sc.Staging {
		m.Client = &acme.Client{DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory"}
	}
	c := m.TLSConfig()
	c.MinVersion = tls.VersionTLS12
	return &tlsProvider{cfg: c, httpWrap: func(h http.Handler) http.Handler { return m.HTTPHandler(h) }}, nil
}

// Status returns the current state for the panel.
func (s *SiteServer) Status() CertStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.status
	st.Public = s.cfg.siteBaseURL()
	return st
}

// CheckNow asks for an immediate attempt to get or verify the certificate.
func (s *SiteServer) CheckNow() {
	select {
	case s.checkNow <- struct{}{}:
	default:
	}
}

func (s *SiteServer) wanted() runKey {
	sc := s.cfg.getSite()
	return runKey{enabled: sc.Enabled, domain: sc.Domain, email: sc.Email, staging: sc.Staging, via443: sc.Via443,
		httpL: s.cfg.SiteHTTPListen, httpsL: s.cfg.SiteHTTPSListen, allowHTTP: s.cfg.SiteAllowHTTP}
}

// Run follows the settings until ctx ends.
func (s *SiteServer) Run(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		s.reconcile(ctx)
		select {
		case <-ctx.Done():
			s.shutdown()
			return
		case <-t.C:
		}
	}
}

func (s *SiteServer) reconcile(ctx context.Context) {
	want := s.wanted()
	s.mu.Lock()
	same := want == s.run && (!want.enabled || s.httpSrv != nil || s.httpsSrv != nil) // a failed start is tried again every few seconds
	s.mu.Unlock()
	if same {
		return
	}
	s.shutdown()
	s.mu.Lock()
	prev := s.run
	s.run = want
	s.status = CertStatus{Domain: want.domain, Staging: want.staging, Via443: want.via443}
	s.mu.Unlock()
	if !want.enabled || !want.via443 || want.domain != prev.domain {
		s.cfg.setSiteReady(false) // the gateway stops handing browsers over to the site (a new domain needs its own certificate)
	}
	if !want.enabled {
		return
	}
	sc := s.cfg.getSite()
	if want.domain == "" {
		if !want.allowHTTP {
			s.setMessage("Укажите домен сайта: без него нельзя получить сертификат, а пароли нельзя передавать по обычному HTTP")
			return
		}
		s.startPlain(ctx, want)
		return
	}
	prov, err := s.providerFn(sc, s.st)
	if err != nil {
		s.setMessage("Сертификат: " + err.Error())
		return
	}
	s.startTLS(ctx, want, prov)
}

func (s *SiteServer) setMessage(m string) {
	s.mu.Lock()
	s.status.Message = m
	again := s.lastMsg == m
	s.lastMsg = m
	s.mu.Unlock()
	if !again {
		log.Printf("site: %s", m)
	}
}

func (s *SiteServer) shutdown() {
	s.mu.Lock()
	hs, ss, stop := s.httpSrv, s.httpsSrv, s.stop
	s.httpSrv, s.httpsSrv, s.stop = nil, nil, nil
	s.status.Running = false
	s.mu.Unlock()
	if stop != nil {
		stop()
	}
	sc, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, srv := range []*http.Server{hs, ss} {
		if srv != nil {
			srv.Shutdown(sc)
		}
	}
}

// quietLog drops the "TLS handshake error ... EOF" lines: probes, scanners and health checks open the port and close it
// without a handshake, and that is not an error of ours. Everything else the http server complains about stays.
type quietLog struct{}

func (quietLog) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("TLS handshake error")) {
		return len(p), nil
	}
	log.Print(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

func newSrv(addr string, h http.Handler) *http.Server {
	return &http.Server{Addr: addr, Handler: h, ErrorLog: log.New(quietLog{}, "http: ", 0), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 16 << 10}
}

func serve(srv *http.Server, ln net.Listener, what string) {
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("site: %s: %v", what, err)
	}
}

// startPlain serves the site over HTTP (no domain; only when the operator allowed it).
func (s *SiteServer) startPlain(ctx context.Context, w runKey) {
	ln, err := net.Listen("tcp", w.httpL)
	if err != nil {
		s.setMessage(fmt.Sprintf("Не удалось открыть порт %s: %v", w.httpL, err))
		return
	}
	srv := newSrv(w.httpL, s.handler)
	s.mu.Lock()
	s.httpSrv = srv
	s.status.Running, s.status.HTTP = true, w.httpL
	s.status.Message = "Сайт работает по обычному HTTP без шифрования (site_allow_http). Задайте домен, чтобы включить HTTPS"
	s.mu.Unlock()
	log.Printf("site: serving over plain HTTP on %s (no domain: passwords are not encrypted)", w.httpL)
	go serve(srv, ln, "http")
}

func hostOnly(h string) string {
	if i := strings.LastIndex(h, ":"); i >= 0 && !strings.Contains(h[i:], "]") {
		h = h[:i]
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

func (s *SiteServer) startTLS(ctx context.Context, w runKey, prov *tlsProvider) {
	redirect := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		target := s.cfg.siteBaseURL()
		if target == "" || hostOnly(r.Host) != w.domain {
			http.NotFound(rw, r)
			return
		}
		http.Redirect(rw, r, target+r.URL.RequestURI(), http.StatusPermanentRedirect)
	})
	httpH := http.Handler(redirect)
	if prov.httpWrap != nil {
		httpH = prov.httpWrap(redirect)
	}
	var httpLn, tlsLn net.Listener
	var err error
	if w.httpL != "" {
		if httpLn, err = net.Listen("tcp", w.httpL); err != nil {
			s.setMessage(fmt.Sprintf("Не удалось открыть порт %s (он нужен Let's Encrypt для проверки домена): %v", w.httpL, err))
			return
		}
	}
	if tlsLn, err = net.Listen("tcp", w.httpsL); err != nil {
		if httpLn != nil {
			httpLn.Close()
		}
		s.setMessage(fmt.Sprintf("Не удалось открыть порт %s: %v", w.httpsL, err))
		return
	}
	hs := newSrv(w.httpL, httpH)
	ss := newSrv(w.httpsL, secureHeaders(s.handler))
	ss.TLSConfig = prov.cfg
	cctx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.httpSrv, s.httpsSrv, s.stop = hs, ss, cancel
	s.status.Running, s.status.HTTP, s.status.HTTPS = true, w.httpL, w.httpsL
	s.mu.Unlock()
	if httpLn != nil {
		go serve(hs, httpLn, "http")
	}
	go func() {
		if err := ss.ServeTLS(tlsLn, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("site: https: %v", err)
		}
	}()
	log.Printf("site: %s: HTTP %s, HTTPS %s", w.domain, w.httpL, w.httpsL)
	go s.certLoop(cctx, w, prov.cfg)
}

// secureHeaders adds HSTS to everything served over TLS.
func secureHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=15552000")
		h.ServeHTTP(w, r)
	})
}

// warmClientHello looks like a modern browser, so autocert issues the usual ECDSA certificate.
func warmClientHello(domain string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		ServerName:        domain,
		SupportedProtos:   []string{"h2", "http/1.1"},
		CipherSuites:      []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_AES_128_GCM_SHA256},
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256},
		SupportedCurves:   []tls.CurveID{tls.X25519, tls.CurveP256},
		SupportedPoints:   []uint8{0},
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
	}
}

// certLoop gets the certificate right after the start (and keeps checking, which also renews it before it expires), and keeps the status.
func (s *SiteServer) certLoop(ctx context.Context, w runKey, c *tls.Config) {
	backoff := []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour}
	fails := 0
	for {
		cert, err := c.GetCertificate(warmClientHello(w.domain))
		var wait time.Duration
		if err == nil && len(cert.Certificate) > 0 {
			leaf, perr := x509.ParseCertificate(cert.Certificate[0])
			if perr == nil && s.selfCheck(w) {
				s.mu.Lock()
				s.status.OK, s.status.Err, s.status.CheckedAt = true, "", time.Now()
				s.status.NotAfter, s.status.Issuer = leaf.NotAfter, leaf.Issuer.CommonName
				s.mu.Unlock()
				s.cfg.setSiteReady(true)
				log.Printf("site: certificate for %s is in place (valid until %s)", w.domain, leaf.NotAfter.Format("2006-01-02"))
				fails, wait = 0, 6*time.Hour
			} else if perr != nil {
				err = perr
			} else {
				err = errors.New("сертификат получен, но HTTPS-порт сайта не отвечает")
			}
		}
		if wait == 0 {
			if err == nil {
				err = errors.New("сертификат не получен")
			}
			s.mu.Lock()
			s.status.OK, s.status.Err, s.status.CheckedAt = false, hintFor(err, w.domain), time.Now()
			s.mu.Unlock()
			log.Printf("site: certificate for %s: %v", w.domain, err)
			wait = backoff[min(fails, len(backoff)-1)]
			fails++
		}
		select {
		case <-ctx.Done():
			return
		case <-s.checkNow:
			fails = 0
		case <-time.After(wait):
		}
	}
}

// selfCheck connects to our own HTTPS port the way a browser would.
func (s *SiteServer) selfCheck(w runKey) bool {
	_, port, err := net.SplitHostPort(w.httpsL)
	if err != nil {
		return false
	}
	addr := "127.0.0.1:" + port
	if w.via443 {
		addr = s.cfg.siteDest() // the gateway has to reach the site by this address
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(&d, "tcp", addr, &tls.Config{ServerName: w.domain, InsecureSkipVerify: true})
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// hintFor adds the usual reasons to the error of the certificate authority.
func hintFor(err error, domain string) string {
	m := err.Error()
	if len(m) > 600 {
		m = m[:600] + "…"
	}
	return m + ". Проверьте: запись DNS домена " + domain + " указывает на IP этого сервера, порт 80 (и 8443 или 443) открыт из интернета"
}

// PreloadReady tells the config, before the first configuration of the gateway is built, whether the site already has a valid
// certificate (it is kept in the database). Otherwise every restart of the controller would briefly take the site away from port 443.
func PreloadReady(ctx context.Context, cfg *Config, st *Store) {
	sc := cfg.getSite()
	if !sc.Enabled || !sc.Via443 || sc.Domain == "" {
		return
	}
	key := sc.Domain
	if sc.Staging {
		key = "staging/" + key
	}
	data, err := st.AcmeGet(ctx, key)
	if err != nil {
		return
	}
	for len(data) > 0 {
		var blk *pem.Block
		blk, data = pem.Decode(data)
		if blk == nil {
			return
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		leaf, err := x509.ParseCertificate(blk.Bytes)
		if err == nil && leaf.NotAfter.After(time.Now().Add(24*time.Hour)) && leaf.VerifyHostname(sc.Domain) == nil {
			cfg.setSiteReady(true)
		}
		return
	}
}
