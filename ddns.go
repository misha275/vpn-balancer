package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Dynamic DNS through Cloudflare: the A record of the domain (and of extra names) follows the public IP of the server.
// config.yaml: cloudflare_token (rights: Zone:Read and DNS:Edit), ddns_names (default: domain), ddns_interval, cloudflare_proxied.

var cloudflareAPI = "https://api.cloudflare.com/client/v4"

var ipServices = []string{"https://api.ipify.org", "https://ipv4.icanhazip.com", "https://ifconfig.me/ip"}

type DDNS struct {
	cfg    *Config
	notify *Notifier
	hc     *http.Client
	ipURLs []string
	zones  map[string]string
}

func NewDDNS(cfg *Config, n *Notifier) *DDNS {
	return &DDNS{cfg: cfg, notify: n, hc: &http.Client{Timeout: 15 * time.Second}, ipURLs: ipServices, zones: map[string]string{}}
}

func (c *Config) ddnsNames() []string {
	names := c.DDNSNames
	if len(names) == 0 && c.Domain != "" {
		names = []string{c.Domain}
	}
	return names
}

func (d *DDNS) publicIP(ctx context.Context) (string, error) {
	var last error
	for _, u := range d.ipURLs {
		req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
		resp, err := d.hc.Do(req)
		if err != nil {
			last = err
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		resp.Body.Close()
		ip := net.ParseIP(strings.TrimSpace(string(b)))
		if ip != nil && ip.To4() != nil && !ip.IsPrivate() && !ip.IsLoopback() {
			return ip.String(), nil
		}
		last = fmt.Errorf("%s: unexpected answer", u)
	}
	return "", fmt.Errorf("public IP is unknown: %v", last)
}

type cfResp struct {
	Success bool `json:"success"`
	Errors  []struct {
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

func (d *DDNS) call(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, cloudflareAPI+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+d.cfg.CloudflareToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.hc.Do(req)
	if err != nil {
		return errors.New(scrubErr(err).Error())
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var r cfResp
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("cloudflare: HTTP %d", resp.StatusCode)
	}
	if !r.Success {
		msg := ""
		if len(r.Errors) > 0 {
			msg = r.Errors[0].Message
		}
		return fmt.Errorf("cloudflare: HTTP %d %s", resp.StatusCode, msg)
	}
	if out != nil {
		return json.Unmarshal(r.Result, out)
	}
	return nil
}

// zoneOf finds the zone of the name: the longest suffix that is a zone of the account.
func (d *DDNS) zoneOf(ctx context.Context, name string) (string, error) {
	if z, ok := d.zones[name]; ok {
		return z, nil
	}
	labels := strings.Split(name, ".")
	for i := 0; i+1 < len(labels); i++ {
		var zs []struct {
			ID string `json:"id"`
		}
		if err := d.call(ctx, "GET", "/zones?name="+url.QueryEscape(strings.Join(labels[i:], ".")), nil, &zs); err != nil {
			return "", err
		}
		if len(zs) > 0 {
			d.zones[name] = zs[0].ID
			return zs[0].ID, nil
		}
	}
	return "", fmt.Errorf("zone of %s is not found in this Cloudflare account (check the token rights)", name)
}

// Sync makes the A record of every name point to ip. It returns the names that were changed.
func (d *DDNS) Sync(ctx context.Context, ip string) ([]string, error) {
	var changed []string
	for _, name := range d.cfg.ddnsNames() {
		zone, err := d.zoneOf(ctx, name)
		if err != nil {
			return changed, err
		}
		var recs []struct {
			ID      string `json:"id"`
			Content string `json:"content"`
			Proxied bool   `json:"proxied"`
		}
		if err := d.call(ctx, "GET", "/zones/"+zone+"/dns_records?type=A&name="+url.QueryEscape(name), nil, &recs); err != nil {
			return changed, err
		}
		rec := map[string]any{"type": "A", "name": name, "content": ip, "ttl": 60, "proxied": d.cfg.CloudflareProxied}
		switch {
		case len(recs) == 0:
			err = d.call(ctx, "POST", "/zones/"+zone+"/dns_records", rec, nil)
		case recs[0].Content != ip || recs[0].Proxied != d.cfg.CloudflareProxied:
			err = d.call(ctx, "PUT", "/zones/"+zone+"/dns_records/"+recs[0].ID, rec, nil)
		default:
			continue
		}
		if err != nil {
			return changed, err
		}
		changed = append(changed, name)
	}
	return changed, nil
}

func (d *DDNS) once(ctx context.Context) {
	ip, err := d.publicIP(ctx)
	if err == nil {
		var changed []string
		if changed, err = d.Sync(ctx, ip); len(changed) > 0 {
			log.Printf("ddns: %s -> %s", strings.Join(changed, ", "), ip)
			d.notify.Notify("ddns-change", fmt.Sprintf("🌐 DNS обновлён: %s → %s", strings.Join(changed, ", "), ip), time.Minute)
		}
	}
	if err != nil {
		log.Printf("ddns: %v", err)
		d.notify.Notify("ddns-fail", "⚠️ Не удалось обновить DNS в Cloudflare: "+err.Error(), 6*time.Hour)
	}
}

// Run checks the address at the start and then every ddns_interval.
func (d *DDNS) Run(ctx context.Context) {
	if d.cfg.CloudflareToken == "" || len(d.cfg.ddnsNames()) == 0 {
		return
	}
	d.once(ctx)
	t := time.NewTicker(d.cfg.DDNSInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.once(ctx)
		}
	}
}
