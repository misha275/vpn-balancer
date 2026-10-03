package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"
)

type Subs struct {
	cfg    *Config
	store  *Store
	notify *Notifier
	fails  map[string]int
}

// scrubErr strips the request URL (it contains the subscription token) from net/http errors.
func scrubErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %w", ue.Op, ue.Err)
	}
	return err
}

func redact(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		return u.Host // never log tokens from the URL
	}
	return "?"
}

func fetchSub(ctx context.Context, rawURL, ua string) (string, error) {
	cl := &http.Client{Timeout: 30 * time.Second}
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(time.Duration(attempt*attempt) * 3 * time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("User-Agent", ua)
		resp, err := cl.Do(req)
		if err != nil {
			last = scrubErr(err)
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
		resp.Body.Close()
		if err != nil {
			last = scrubErr(err)
			continue
		}
		if resp.StatusCode != 200 {
			last = fmt.Errorf("http %d", resp.StatusCode)
			continue
		}
		return string(body), nil
	}
	return "", last
}

// Refresh downloads every subscription. A failed or empty download changes
// nothing: its nodes stay in the pool until node_grace expires.
func (s *Subs) Refresh(ctx context.Context) {
	total := 0
	for _, u := range s.cfg.getSubscriptions() {
		body, err := fetchSub(ctx, u, s.cfg.SubUserAgent)
		var nodes []*Node
		if err == nil {
			if s.cfg.getNodeIdentity() == "link" {
				nodes = ParseLinksPerLink(body)
			} else {
				nodes = ParseLinks(body)
			}
			if len(nodes) == 0 {
				err = errors.New("no supported nodes in response")
			}
		}
		if err != nil {
			s.fails[u]++
			log.Printf("subs: %s: %v (fail #%d)", redact(u), err, s.fails[u])
			if s.fails[u] >= 3 { // Notify rate-limits repeats (every 6h)
				s.notify.Notify("sub:"+redact(u), "⚠️ Подписка "+redact(u)+" не обновляется: "+err.Error(), 6*time.Hour)
			}
			continue
		}
		s.fails[u] = 0
		if err := s.store.UpsertNodes(ctx, nodes, redact(u)); err != nil {
			log.Printf("subs: store: %v", err)
			continue
		}
		total += len(nodes)
		log.Printf("subs: %s: %d nodes", redact(u), len(nodes))
	}
	log.Printf("subs: refresh done, %d nodes parsed", total)
}
