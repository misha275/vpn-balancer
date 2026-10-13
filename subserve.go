package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// SubServer gives every user a personal subscription URL:
//
//	GET /sub/<token>
//
// The answer is a standard subscription (base64 of a list of links). The first
// entry is the balancer itself (the user's personal vless:// link), the others are
// all upstream nodes the balancer knows that are allowed to carry traffic
// (exit country known and not censored). A client that supports several servers
// can use the balancer by default and fall back to a direct node if needed.
type SubServer struct {
	cfg   *Config
	store *Store

	mu    sync.Mutex
	fails map[string][]time.Time // client IP -> times of failed lookups
}

func NewSubServer(cfg *Config, st *Store) *SubServer {
	return &SubServer{cfg: cfg, store: st, fails: map[string][]time.Time{}}
}

// relabel puts the real exit country in front of the original name: the label
// of the provider may be wrong, the measured exit is not.
func relabel(n *Node, cfg *Config) (string, bool) {
	if n.Link == "" {
		return "", false // not re-downloaded since the upgrade yet
	}
	link := n.Link
	if i := strings.Index(link, "#"); i >= 0 {
		link = link[:i]
	}
	name := n.Name
	if n.ExitCountry != "" {
		name = "[" + n.ExitCountry + "] " + name
	}
	return link + "#" + url.PathEscape(name), true
}

// RenderBalancers is the subscription "balancers only": one link per mode.
func RenderBalancers(cfg *Config, u *User) []string { return modeLinks(cfg, *u) }

// RenderSub builds the plain list of links for a user (before base64).
// The balancers (current, best speed, best ping) come first, then all allowed servers.
func RenderSub(cfg *Config, u *User, nodes []*Node) []string {
	lines := RenderBalancers(cfg, u)
	var ns []*Node
	for _, n := range nodes {
		if n.Allowed(cfg) {
			ns = append(ns, n)
		}
	}
	sort.Slice(ns, func(i, j int) bool {
		if ns[i].ExitCountry != ns[j].ExitCountry {
			return ns[i].ExitCountry < ns[j].ExitCountry
		}
		if ns[i].Name != ns[j].Name {
			return ns[i].Name < ns[j].Name
		}
		return ns[i].ID < ns[j].ID
	})
	for _, n := range ns {
		if l, ok := relabel(n, cfg); ok {
			lines = append(lines, l)
		}
	}
	return lines
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, l := range in {
		if !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	return out
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// limited reports whether an address made too many failed lookups recently
// (protects the tokens from guessing).
func (s *SubServer) limited(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cut := time.Now().Add(-10 * time.Minute)
	keep := s.fails[ip][:0]
	for _, t := range s.fails[ip] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	s.fails[ip] = keep
	if len(keep) == 0 {
		delete(s.fails, ip)
	}
	return len(keep) >= 20
}

func (s *SubServer) fail(ip string) {
	s.mu.Lock()
	s.fails[ip] = append(s.fails[ip], time.Now())
	s.mu.Unlock()
}

func (s *SubServer) Handler() http.Handler {
	mux := http.NewServeMux()
	serve := func(kind string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)
			if s.limited(ip) {
				http.Error(w, "too many requests", http.StatusTooManyRequests)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			defer cancel()
			u, err := s.store.UserBySubToken(ctx, r.PathValue("token"))
			if err != nil {
				s.fail(ip)
				http.NotFound(w, r) // same answer for wrong token and disabled user
				return
			}
			keys, _ := effectiveSubs(s.cfg, *u)
			title := s.cfg.getGatewayName()
			ix, err := s.store.LoadSubIndex(ctx)
			if err != nil {
				log.Printf("sub: index: %v", err)
				http.Error(w, "temporary error", http.StatusServiceUnavailable)
				return
			}
			var lines []string
			missing := false // the requested category does not exist (any more) or is switched off
			want := kind
			add := func(kind string) bool { // appends the lines of one subscription; false = temporary failure
				switch {
				case kind == subBalancers:
					lines = append(lines, RenderBalancers(s.cfg, u)...)
				case kind == subAll:
					nodes, err := s.store.ActiveNodes(ctx, s.cfg.NodeGrace)
					if err != nil {
						log.Printf("sub: nodes: %v", err)
						return false
					}
					lines = append(lines, RenderSub(s.cfg, u, nodes)...)
				case strings.HasPrefix(kind, bundlePrefix):
					name, ls, ok := ix.lines(s.cfg, *u, kind[len(bundlePrefix):])
					if !ok {
						missing = true
						break
					}
					lines = append(lines, ls...)
					if want == "bundle" {
						title += " · " + name
					}
				}
				return true
			}
			switch {
			case want == "union":
				for _, k := range keys {
					if !add(k) {
						http.Error(w, "temporary error", http.StatusServiceUnavailable)
						return
					}
				}
			default:
				key := want
				if want == "bundle" {
					key = bundlePrefix + r.PathValue("slug")
				}
				if !hasSub(keys, key) {
					http.Error(w, "this subscription is not available for the account", http.StatusForbidden)
					return
				}
				if key == subBalancers {
					title += " · балансировщики"
				}
				if !add(key) {
					http.Error(w, "temporary error", http.StatusServiceUnavailable)
					return
				}
				if missing {
					http.NotFound(w, r)
					return
				}
			}
			go s.store.NoteSubFetch(context.Background(), u.ID)
			body := strings.Join(dedupe(lines), "\n")
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("profile-update-interval", "6")
			w.Header().Set("profile-title", "base64:"+base64.StdEncoding.EncodeToString([]byte(title)))
			if r.URL.Query().Get("raw") == "1" {
				fmt.Fprint(w, body+"\n") // for humans: the same list without base64
				return
			}
			fmt.Fprint(w, base64.StdEncoding.EncodeToString([]byte(body)))
		}
	}
	mux.HandleFunc("GET /sub/{token}", serve("union")) // everything the account may take
	mux.HandleFunc("GET /sub/{token}/all", serve(subAll))
	mux.HandleFunc("GET /sub/{token}/balancers", serve(subBalancers))
	mux.HandleFunc("GET /sub/{token}/b/{slug}", serve("bundle"))
	return mux
}

func (s *SubServer) Serve(ctx context.Context) {
	srv := &http.Server{Addr: s.cfg.SubListen, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sc)
	}()
	var err error
	if s.cfg.SubTLSCert != "" && s.cfg.SubTLSKey != "" {
		err = srv.ListenAndServeTLS(s.cfg.SubTLSCert, s.cfg.SubTLSKey)
	} else {
		log.Printf("sub: plain HTTP on %s only redirects to the HTTPS site once it has a certificate (older links keep working); until then tokens are visible on the network", s.cfg.SubListen)
		inner := srv.Handler
		srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if b := s.cfg.siteBaseURL(); b != "" && s.cfg.getSiteReady() {
				http.Redirect(w, r, b+r.URL.RequestURI(), http.StatusPermanentRedirect)
				return
			}
			inner.ServeHTTP(w, r)
		})
		err = srv.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		log.Printf("sub: %v", err)
	}
}
