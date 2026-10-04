package main

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Node is one upstream proxy converted to a sing-box outbound.
type Node struct {
	ID       string // sha1 of canonical outbound JSON (stable across renames)
	Name     string
	Type     string
	Server   string
	Port     int
	UDP      bool // UDP-based protocol: TCP pre-check is skipped
	Outbound map[string]any

	Link        string    // the original link from the subscription (for the user subscription)
	ExitIP      string    // address the node's traffic leaves from (measured)
	ExitCountry string    // ISO country of the exit, "" until measured
	ExitChecked time.Time // when ExitCountry was measured

	// quality data restored from the database (see NodeState)
	SpeedHist []SpeedPoint
	SpeedTry  time.Time
	SpeedErr  string
	CheckAt   time.Time
	Svc       map[string]SvcRes
}

// SpeedPoint is one successful speed measurement.
type SpeedPoint struct {
	K int   `json:"k"` // kbit/s
	T int64 `json:"t"` // unix seconds
}

// SvcRes is the last result of one service check (for example "telegram") through a node.
type SvcRes struct {
	OK    bool   `json:"ok"`
	MS    int    `json:"ms"`
	T     int64  `json:"t"`
	Fails int    `json:"f"` // consecutive failed passes
	Err   string `json:"e,omitempty"`
}

func (n *Node) Tag() string { return "n-" + n.ID[:10] }

func newNode(name, typ, server string, port int, udp bool, out map[string]any) *Node {
	if server == "" || port <= 0 || port > 65535 {
		return nil
	}
	out["type"] = typ
	out["server"] = server
	out["server_port"] = port
	raw, _ := json.Marshal(out) // map keys are sorted -> deterministic
	sum := sha1.Sum(raw)
	if name == "" {
		name = server
	}
	return &Node{ID: hex.EncodeToString(sum[:]), Name: name, Type: typ, Server: server, Port: port, UDP: udp, Outbound: out}
}

func decodeB64(s string) (string, bool) {
	s = strings.Join(strings.Fields(s), "")
	s = strings.TrimRight(s, "=")
	s = strings.NewReplacer("-", "+", "_", "/").Replace(s)
	b, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return "", false
	}
	return string(b), true
}

// ParseLinks accepts a subscription body: plain list of links or base64 of it.
func ParseLinks(body string) []*Node {
	body = strings.TrimSpace(body)
	if !strings.Contains(body, "://") {
		if dec, ok := decodeB64(body); ok {
			body = dec
		}
	}
	var nodes []*Node
	seen := map[string]bool{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if n := parseLink(line); n != nil && !seen[n.ID] {
			seen[n.ID] = true
			n.Link = line
			nodes = append(nodes, n)
		}
	}
	return nodes
}

// ParseLinksPerLink is like ParseLinks, but every link of the subscription becomes its own node
// even if several links have exactly the same connection parameters and differ only in the name
// (node_identity: link). The ID then depends on the name as well; links with the same name and
// parameters still collapse into one.
func ParseLinksPerLink(body string) []*Node {
	body = strings.TrimSpace(body)
	if !strings.Contains(body, "://") {
		if dec, ok := decodeB64(body); ok {
			body = dec
		}
	}
	var nodes []*Node
	seen := map[string]bool{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		n := parseLink(line)
		if n == nil {
			continue
		}
		sum := sha1.Sum([]byte(n.ID + "|" + n.Name))
		n.ID = hex.EncodeToString(sum[:])
		if seen[n.ID] {
			continue
		}
		seen[n.ID] = true
		n.Link = line
		nodes = append(nodes, n)
	}
	return nodes
}

func parseLink(line string) *Node {
	switch {
	case strings.HasPrefix(line, "vless://"):
		return parseVLESS(line)
	case strings.HasPrefix(line, "vmess://"):
		return parseVMess(line)
	case strings.HasPrefix(line, "trojan://"):
		return parseTrojan(line)
	case strings.HasPrefix(line, "ss://"):
		return parseSS(line)
	case strings.HasPrefix(line, "hysteria2://"), strings.HasPrefix(line, "hy2://"):
		return parseHY2(line)
	}
	return nil
}

func buildTLS(q url.Values, defaultSec string) map[string]any {
	sec := q.Get("security")
	if sec == "" {
		sec = defaultSec
	}
	if sec == "none" || sec == "" {
		return nil
	}
	t := map[string]any{"enabled": true}
	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("peer")
	}
	if sni == "" && sec == "tls" {
		// v2rayN/Xray take the Host header as the TLS server name when sni is not given (typical for CDN-fronted
		// ws/httpupgrade nodes); without it sing-box would send the server address and get "tls: unrecognized name"
		switch q.Get("type") {
		case "ws", "httpupgrade", "http", "h2":
			sni = q.Get("host")
		}
	}
	if sni != "" {
		t["server_name"] = sni
	}
	if q.Get("allowInsecure") == "1" || q.Get("insecure") == "1" {
		t["insecure"] = true
	}
	if a := q.Get("alpn"); a != "" {
		t["alpn"] = strings.Split(a, ",")
	}
	fp := q.Get("fp")
	if fp == "" && sec == "reality" {
		fp = "chrome"
	}
	if fp != "" {
		t["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}
	if sec == "reality" {
		t["reality"] = map[string]any{"enabled": true, "public_key": q.Get("pbk"), "short_id": q.Get("sid")}
	}
	return t
}

// buildTransport converts the "type" query parameter into a sing-box transport.
// ok=false means the transport is not supported by sing-box (xhttp, kcp, quic ...):
// such a node must be dropped, otherwise it would silently become plain TCP.
func buildTransport(q url.Values) (t map[string]any, ok bool) {
	path := q.Get("path")
	if path == "" {
		path = "/"
	}
	host := q.Get("host")
	switch q.Get("type") {
	case "", "tcp", "none", "raw":
		if q.Get("headerType") == "http" {
			return nil, false // HTTP-obfuscated raw TCP is not supported
		}
		return nil, true
	case "ws":
		t := map[string]any{"type": "ws", "path": path}
		if host != "" {
			t["headers"] = map[string]any{"Host": host}
		}
		return t, true
	case "grpc":
		return map[string]any{"type": "grpc", "service_name": q.Get("serviceName")}, true
	case "httpupgrade":
		t := map[string]any{"type": "httpupgrade", "path": path}
		if host != "" {
			t["host"] = host
		}
		return t, true
	case "http", "h2":
		t := map[string]any{"type": "http", "path": path}
		if host != "" {
			t["host"] = []string{host}
		}
		return t, true
	}
	return nil, false
}

func parseVLESS(line string) *Node {
	u, err := url.Parse(line)
	if err != nil || u.User == nil {
		return nil
	}
	q := u.Query()
	if q.Get("security") == "reality" && q.Get("pbk") == "" {
		return nil
	}
	port, _ := strconv.Atoi(u.Port())
	out := map[string]any{"uuid": u.User.Username(), "packet_encoding": "xudp"}
	if f := q.Get("flow"); f != "" {
		out["flow"] = f
	}
	if t := buildTLS(q, "none"); t != nil {
		out["tls"] = t
	}
	tr, ok := buildTransport(q)
	if !ok {
		return nil
	}
	if tr != nil {
		out["transport"] = tr
	}
	return newNode(u.Fragment, "vless", u.Hostname(), port, false, out)
}

func parseTrojan(line string) *Node {
	u, err := url.Parse(line)
	if err != nil || u.User == nil {
		return nil
	}
	q := u.Query()
	port, _ := strconv.Atoi(u.Port())
	out := map[string]any{"password": u.User.Username()}
	if t := buildTLS(q, "tls"); t != nil {
		out["tls"] = t
	}
	tr, ok := buildTransport(q)
	if !ok {
		return nil
	}
	if tr != nil {
		out["transport"] = tr
	}
	return newNode(u.Fragment, "trojan", u.Hostname(), port, false, out)
}

func sv(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return ""
}

func parseVMess(line string) *Node {
	dec, ok := decodeB64(strings.TrimPrefix(line, "vmess://"))
	if !ok {
		return nil
	}
	var m map[string]any
	if json.Unmarshal([]byte(dec), &m) != nil {
		return nil
	}
	port, _ := strconv.Atoi(sv(m["port"]))
	q := url.Values{}
	q.Set("type", sv(m["net"]))
	q.Set("host", sv(m["host"]))
	q.Set("path", sv(m["path"]))
	q.Set("serviceName", sv(m["path"])) // vmess+grpc keeps the service name in "path"
	if sv(m["type"]) == "http" && sv(m["net"]) == "tcp" {
		q.Set("headerType", "http")
	}
	if sv(m["tls"]) == "tls" {
		q.Set("security", "tls")
		sni := sv(m["sni"])
		if sni == "" {
			sni = sv(m["host"])
		}
		q.Set("sni", sni)
		q.Set("alpn", sv(m["alpn"]))
		q.Set("fp", sv(m["fp"]))
	}
	sec := sv(m["scy"])
	if sec == "" {
		sec = "auto"
	}
	aid, _ := strconv.Atoi(sv(m["aid"]))
	out := map[string]any{"uuid": sv(m["id"]), "security": sec, "alter_id": aid}
	if t := buildTLS(q, "none"); t != nil {
		out["tls"] = t
	}
	tr, ok := buildTransport(q)
	if !ok {
		return nil
	}
	if tr != nil {
		out["transport"] = tr
	}
	return newNode(sv(m["ps"]), "vmess", sv(m["add"]), port, false, out)
}

func parseSS(line string) *Node {
	s := strings.TrimPrefix(line, "ss://")
	name := ""
	if i := strings.Index(s, "#"); i >= 0 {
		name, _ = url.PathUnescape(s[i+1:])
		s = s[:i]
	}
	if i := strings.Index(s, "?"); i >= 0 {
		if strings.Contains(s[i:], "plugin") {
			return nil // plugins are not supported
		}
		s = s[:i]
	}
	var userinfo, hostport string
	if i := strings.LastIndex(s, "@"); i >= 0 {
		userinfo, hostport = s[:i], s[i+1:]
		if un, err := url.PathUnescape(userinfo); err == nil {
			userinfo = un // handles %3D in base64 and %3A / %40 in plain method:password
		}
		if !strings.Contains(userinfo, ":") {
			if d, ok := decodeB64(userinfo); ok {
				userinfo = d
			}
		}
		hostport = strings.TrimRight(hostport, "/")
	} else {
		d, ok := decodeB64(s)
		if !ok {
			return nil
		}
		i := strings.LastIndex(d, "@")
		if i < 0 {
			return nil
		}
		userinfo, hostport = d[:i], d[i+1:]
	}
	method, pass, ok := strings.Cut(userinfo, ":")
	if !ok {
		return nil
	}
	host, ps, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil
	}
	port, _ := strconv.Atoi(ps)
	return newNode(name, "shadowsocks", host, port, false, map[string]any{"method": method, "password": pass})
}

func parseHY2(line string) *Node {
	u, err := url.Parse(line)
	if err != nil || u.User == nil {
		return nil
	}
	pass := u.User.Username()
	if pw, ok := u.User.Password(); ok {
		pass += ":" + pw
	}
	q := u.Query()
	tls := map[string]any{"enabled": true}
	if sni := q.Get("sni"); sni != "" {
		tls["server_name"] = sni
	}
	if q.Get("insecure") == "1" {
		tls["insecure"] = true
	}
	out := map[string]any{"password": pass, "tls": tls}
	if o := q.Get("obfs"); o != "" {
		out["obfs"] = map[string]any{"type": o, "password": q.Get("obfs-password")}
	}
	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 443
	}
	return newNode(u.Fragment, "hysteria2", u.Hostname(), port, true, out)
}
