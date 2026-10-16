package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// End node (version 3.7.0): a plain server with ready protocols and no balancing. It asks the panel who may connect
// (see servers.go), builds a sing-box config with the protocols of endnode.yaml and tells the panel the link templates.
//
//	balancer -c endnode.yaml endnode run | check | init | inbounds | add TYPE | del NAME | links [USER]

// EndInbound is one way to connect to the node.
type EndInbound struct {
	Name       string `yaml:"name"`
	Type       string `yaml:"type"` // vless-reality, vless-tls, vless-ws, vless-grpc, trojan, trojan-ws, vmess-ws, shadowsocks, hysteria2, tuic
	Port       int    `yaml:"port"`
	SNI        string `yaml:"sni,omitempty"`         // reality: the site it imitates; tls types: the name in the certificate (default host)
	PrivateKey string `yaml:"private_key,omitempty"` // reality
	PublicKey  string `yaml:"public_key,omitempty"`
	ShortID    string `yaml:"short_id,omitempty"`
	Path       string `yaml:"path,omitempty"`    // ws
	Service    string `yaml:"service,omitempty"` // grpc
	Method     string `yaml:"method,omitempty"`  // shadowsocks (AEAD)
	Obfs       string `yaml:"obfs,omitempty"`    // hysteria2: password of salamander
	NoTLS      bool   `yaml:"no_tls,omitempty"`  // ws types behind a reverse proxy / CDN that terminates TLS
}

type EndTLS struct {
	Mode  string `yaml:"mode"`            // self-signed (default), file, acme
	Cert  string `yaml:"cert,omitempty"`  // file
	Key   string `yaml:"key,omitempty"`   // file
	Email string `yaml:"email,omitempty"` // acme
}

type EndUser struct {
	Name string `yaml:"name"`
	UUID string `yaml:"uuid"`
}

type EndNodeConfig struct {
	Name          string        `yaml:"name"`
	Host          string        `yaml:"host"` // public address (domain or IP) that goes into the links
	PanelURL      string        `yaml:"panel_url"`
	PanelToken    string        `yaml:"panel_token"`
	PanelInsecure bool          `yaml:"panel_insecure,omitempty"`
	SyncInterval  time.Duration `yaml:"sync_interval,omitempty"`
	SingboxBin    string        `yaml:"singbox_bin,omitempty"`
	WorkDir       string        `yaml:"work_dir"`
	TLS           EndTLS        `yaml:"tls"`
	AllowPrivate  bool          `yaml:"allow_private,omitempty"` // let users reach private addresses of the server's network (off by default)
	Users         []EndUser     `yaml:"users,omitempty"`         // fixed users that work without a panel
	Inbounds      []EndInbound  `yaml:"inbounds"`
}

var endTypes = map[string]struct {
	port int
	udp  bool
	tls  bool // needs a certificate
}{
	"vless-reality": {443, false, false},
	"vless-tls":     {8443, false, true},
	"vless-ws":      {2053, false, true},
	"vless-grpc":    {2083, false, true},
	"trojan":        {2087, false, true},
	"trojan-ws":     {2096, false, true},
	"vmess-ws":      {2095, false, true},
	"shadowsocks":   {8388, false, false},
	"hysteria2":     {8443, true, true},
	"tuic":          {8444, true, true},
}

func endTypeNames() []string {
	var n []string
	for k := range endTypes {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

var reEndName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,23}$`)

func LoadEndNode(path string) (*EndNodeConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &EndNodeConfig{}
	if err := yaml.Unmarshal(raw, c); err != nil {
		return nil, err
	}
	if c.SyncInterval == 0 {
		c.SyncInterval = 30 * time.Second
	}
	if c.SingboxBin == "" {
		c.SingboxBin = "sing-box"
	}
	if c.WorkDir == "" {
		c.WorkDir = "/var/lib/endnode"
	}
	if c.TLS.Mode == "" {
		c.TLS.Mode = "self-signed"
	}
	if c.Name == "" {
		c.Name = "Узел"
	}
	return c, c.Validate()
}

func (c *EndNodeConfig) Validate() error {
	if c.TLS.Mode == "" {
		c.TLS.Mode = "self-signed"
	}
	if c.Host == "" || strings.HasPrefix(c.Host, "<") {
		return errors.New("host: укажите адрес сервера (домен или IP)")
	}
	switch c.TLS.Mode {
	case "self-signed":
	case "file":
		if c.TLS.Cert == "" || c.TLS.Key == "" {
			return errors.New("tls.cert и tls.key нужны для режима file")
		}
	case "acme":
		if net.ParseIP(c.Host) != nil {
			return errors.New("tls.mode acme требует домен в host, не IP")
		}
	default:
		return fmt.Errorf("tls.mode: self-signed, file или acme, получено %q", c.TLS.Mode)
	}
	if len(c.Inbounds) == 0 {
		return errors.New("inbounds: нужен хотя бы один протокол (endnode add vless-reality)")
	}
	names := map[string]bool{}
	ports := map[string]string{}
	for i := range c.Inbounds {
		in := &c.Inbounds[i]
		t, ok := endTypes[in.Type]
		if !ok {
			return fmt.Errorf("inbounds[%d]: неизвестный тип %q (есть: %s)", i, in.Type, strings.Join(endTypeNames(), ", "))
		}
		if in.Name == "" {
			in.Name = in.Type
		}
		if !reEndName.MatchString(in.Name) {
			return fmt.Errorf("inbounds[%d]: имя %q: строчные латинские буквы, цифры, дефис", i, in.Name)
		}
		if names[in.Name] {
			return fmt.Errorf("имя протокола %q повторяется", in.Name)
		}
		names[in.Name] = true
		if in.Port == 0 {
			in.Port = t.port
		}
		if in.Port < 1 || in.Port > 65535 {
			return fmt.Errorf("%s: порт %d", in.Name, in.Port)
		}
		key := fmt.Sprintf("%d/%v", in.Port, t.udp)
		if o, dup := ports[key]; dup {
			return fmt.Errorf("порт %d занят протоколом %s", in.Port, o)
		}
		ports[key] = in.Name
		if in.Type == "shadowsocks" && in.Method == "" {
			in.Method = "chacha20-ietf-poly1305"
		}
		if in.Type == "shadowsocks" && !strings.Contains(in.Method, "poly1305") && !strings.Contains(in.Method, "gcm") {
			return fmt.Errorf("%s: method %q: нужен AEAD (chacha20-ietf-poly1305, aes-128-gcm, aes-256-gcm)", in.Name, in.Method)
		}
		if strings.HasSuffix(in.Type, "-ws") && in.Path == "" {
			in.Path = "/" + in.Name
		}
		if in.Type == "vless-grpc" && in.Service == "" {
			in.Service = in.Name
		}
		if in.Type == "vless-reality" {
			if in.SNI == "" {
				in.SNI = "www.microsoft.com"
			}
			if in.PrivateKey == "" || in.PublicKey == "" || in.ShortID == "" {
				return fmt.Errorf("%s: нет ключей Reality (private_key, public_key, short_id): endnode add создаёт их сам", in.Name)
			}
		}
	}
	return nil
}

// ---- keys and certificate ----

func genRealityKeys() (priv, pub, sid string, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	b := make([]byte, 8)
	if _, err = rand.Read(b); err != nil {
		return
	}
	return base64.RawURLEncoding.EncodeToString(k.Bytes()), base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes()), hex.EncodeToString(b), nil
}

// NewInbound makes an inbound of a type with default values (and Reality keys when needed).
func NewInbound(typ, name string, port int) (EndInbound, error) {
	t, ok := endTypes[typ]
	if !ok {
		return EndInbound{}, fmt.Errorf("неизвестный тип %q (есть: %s)", typ, strings.Join(endTypeNames(), ", "))
	}
	if name == "" {
		name = typ
	}
	if port == 0 {
		port = t.port
	}
	in := EndInbound{Name: name, Type: typ, Port: port}
	if typ == "vless-reality" {
		var err error
		if in.PrivateKey, in.PublicKey, in.ShortID, err = genRealityKeys(); err != nil {
			return in, err
		}
		in.SNI = "www.microsoft.com"
	}
	if typ == "hysteria2" {
		b := make([]byte, 8)
		rand.Read(b)
		in.Obfs = hex.EncodeToString(b)
	}
	return in, nil
}

// ensureCert returns the certificate and the key to use (and whether the client has to skip the verification).
func (c *EndNodeConfig) ensureCert() (cert, key string, selfSigned bool, err error) {
	switch c.TLS.Mode {
	case "file":
		return c.TLS.Cert, c.TLS.Key, false, nil
	case "acme":
		return "", "", false, nil
	}
	cert, key = filepath.Join(c.WorkDir, "self.pem"), filepath.Join(c.WorkDir, "self.key")
	if _, e1 := os.Stat(cert); e1 == nil {
		if _, e2 := os.Stat(key); e2 == nil {
			return cert, key, true, nil
		}
	}
	if err = os.MkdirAll(c.WorkDir, 0o700); err != nil {
		return
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: c.Host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(10, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(c.Host); ip != nil {
		tpl.IPAddresses = []net.IP{ip}
	} else {
		tpl.DNSNames = []string{c.Host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return
	}
	kb, _ := x509.MarshalECPrivateKey(priv)
	if err = os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return
	}
	err = os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return cert, key, true, err
}

// ---- sing-box config ----

func (c *EndNodeConfig) tlsBlock(in EndInbound, cert, key string) map[string]any {
	name := in.SNI
	if name == "" {
		name = c.Host
	}
	t := map[string]any{"enabled": true, "server_name": name}
	if in.Type == "hysteria2" || in.Type == "tuic" {
		t["alpn"] = []string{"h3"}
	}
	if c.TLS.Mode == "acme" {
		a := map[string]any{"domain": []string{c.Host}, "data_directory": filepath.Join(c.WorkDir, "acme")}
		if c.TLS.Email != "" {
			a["email"] = c.TLS.Email
		}
		t["acme"] = a
	} else {
		t["certificate_path"], t["key_path"] = cert, key
	}
	return t
}

// nobodyUUID is the placeholder user of a node that has nobody yet (inbounds refuse to start without a user): random
// for this process, so nobody can use it.
var nobodyUUID = func() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6], b[8] = (b[6]&0x0f)|0x40, (b[8]&0x3f)|0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}()

// BuildConfig makes the sing-box configuration for a list of users.
func (c *EndNodeConfig) BuildConfig(users []EndUser) ([]byte, error) {
	cert, key, _, err := c.ensureCert()
	if err != nil {
		return nil, err
	}
	if len(users) == 0 {
		users = []EndUser{{"_none", nobodyUUID}}
	}
	var ins []any
	for _, in := range c.Inbounds {
		m := map[string]any{"tag": in.Name, "listen": "::", "listen_port": in.Port}
		var us []map[string]any
		for _, u := range users {
			p := endnodePass(u.UUID)
			switch in.Type {
			case "vless-reality", "vless-tls":
				us = append(us, map[string]any{"name": u.Name, "uuid": u.UUID, "flow": "xtls-rprx-vision"})
			case "vless-ws", "vless-grpc":
				us = append(us, map[string]any{"name": u.Name, "uuid": u.UUID})
			case "vmess-ws":
				us = append(us, map[string]any{"name": u.Name, "uuid": u.UUID, "alterId": 0})
			case "trojan", "trojan-ws", "hysteria2", "shadowsocks":
				us = append(us, map[string]any{"name": u.Name, "password": p})
			case "tuic":
				us = append(us, map[string]any{"name": u.Name, "uuid": u.UUID, "password": p})
			}
		}
		switch in.Type {
		case "vless-reality":
			m["type"] = "vless"
			m["tls"] = map[string]any{"enabled": true, "server_name": in.SNI, "reality": map[string]any{"enabled": true,
				"handshake": map[string]any{"server": in.SNI, "server_port": 443}, "private_key": in.PrivateKey, "short_id": []string{in.ShortID}}}
		case "vless-tls":
			m["type"] = "vless"
		case "vless-ws":
			m["type"] = "vless"
			m["transport"] = map[string]any{"type": "ws", "path": in.Path}
		case "vless-grpc":
			m["type"] = "vless"
			m["transport"] = map[string]any{"type": "grpc", "service_name": in.Service}
		case "trojan":
			m["type"] = "trojan"
		case "trojan-ws":
			m["type"] = "trojan"
			m["transport"] = map[string]any{"type": "ws", "path": in.Path}
		case "vmess-ws":
			m["type"] = "vmess"
			m["transport"] = map[string]any{"type": "ws", "path": in.Path}
		case "shadowsocks":
			m["type"] = "shadowsocks"
			m["method"] = in.Method
			m["network"] = "tcp"
		case "hysteria2":
			m["type"] = "hysteria2"
			if in.Obfs != "" {
				m["obfs"] = map[string]any{"type": "salamander", "password": in.Obfs}
			}
		case "tuic":
			m["type"] = "tuic"
			m["congestion_control"] = "bbr"
		}
		m["users"] = us
		if endTypes[in.Type].tls && !in.NoTLS {
			m["tls"] = c.tlsBlock(in, cert, key)
		}
		ins = append(ins, m)
	}
	rules := []any{map[string]any{"action": "sniff"}}
	if !c.AllowPrivate {
		rules = append(rules, map[string]any{"action": "resolve"},
			map[string]any{"ip_is_private": true, "action": "reject"}) // users must not reach the network of the server
	}
	cfg := map[string]any{
		"log":       map[string]any{"level": "warn", "timestamp": true},
		"inbounds":  ins,
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
		"route": map[string]any{
			"rules": rules,
			"final": "direct",
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// Templates are the links of the node with {UUID} / {PASS} instead of a user.
func (c *EndNodeConfig) Templates() []LinkTmpl {
	_, _, selfSigned, _ := c.ensureCert()
	var out []LinkTmpl
	for _, in := range c.Inbounds {
		out = append(out, LinkTmpl{Title: in.Name, Tmpl: c.template(in, selfSigned)})
	}
	return out
}

func (c *EndNodeConfig) template(in EndInbound, selfSigned bool) string {
	host := c.Host
	if strings.Contains(host, ":") && net.ParseIP(host) != nil {
		host = "[" + host + "]"
	}
	sni := in.SNI
	if sni == "" {
		sni = c.Host
	}
	addr := fmt.Sprintf("%s:%d", host, in.Port)
	q := url.Values{}
	insec := func(key string) {
		if selfSigned {
			q.Set(key, "1")
		}
	}
	sec := func() {
		if in.NoTLS {
			q.Set("security", "none")
		} else {
			q.Set("security", "tls")
			q.Set("sni", sni)
			q.Set("fp", "chrome")
			insec("allowInsecure")
		}
	}
	switch in.Type {
	case "vless-reality":
		q.Set("encryption", "none")
		q.Set("flow", "xtls-rprx-vision")
		q.Set("security", "reality")
		q.Set("sni", in.SNI)
		q.Set("fp", "chrome")
		q.Set("pbk", in.PublicKey)
		q.Set("sid", in.ShortID)
		q.Set("type", "tcp")
		return "vless://{UUID}@" + addr + "?" + q.Encode()
	case "vless-tls":
		q.Set("encryption", "none")
		q.Set("flow", "xtls-rprx-vision")
		q.Set("type", "tcp")
		sec()
		return "vless://{UUID}@" + addr + "?" + q.Encode()
	case "vless-ws":
		q.Set("encryption", "none")
		q.Set("type", "ws")
		q.Set("path", in.Path)
		q.Set("host", sni)
		sec()
		return "vless://{UUID}@" + addr + "?" + q.Encode()
	case "vless-grpc":
		q.Set("encryption", "none")
		q.Set("type", "grpc")
		q.Set("serviceName", in.Service)
		sec()
		return "vless://{UUID}@" + addr + "?" + q.Encode()
	case "trojan":
		q.Set("type", "tcp")
		sec()
		return "trojan://{PASS}@" + addr + "?" + q.Encode()
	case "trojan-ws":
		q.Set("type", "ws")
		q.Set("path", in.Path)
		q.Set("host", sni)
		sec()
		return "trojan://{PASS}@" + addr + "?" + q.Encode()
	case "vmess-ws":
		m := map[string]any{"v": "2", "ps": in.Name, "add": c.Host, "port": fmt.Sprint(in.Port), "id": "{UUID}", "aid": "0", "scy": "auto",
			"net": "ws", "type": "none", "host": sni, "path": in.Path, "tls": "tls", "sni": sni, "fp": "chrome"}
		if in.NoTLS {
			m["tls"] = ""
		}
		if selfSigned && !in.NoTLS {
			m["allowInsecure"] = "true"
		}
		b, _ := json.Marshal(m)
		return "vmess://" + base64.StdEncoding.EncodeToString(b)
	case "shadowsocks":
		return "ss://{SS:" + in.Method + "}@" + addr
	case "hysteria2":
		q.Set("sni", sni)
		insec("insecure")
		if in.Obfs != "" {
			q.Set("obfs", "salamander")
			q.Set("obfs-password", in.Obfs)
		}
		return "hysteria2://{PASS}@" + addr + "?" + q.Encode()
	case "tuic":
		q.Set("congestion_control", "bbr")
		q.Set("alpn", "h3")
		q.Set("sni", sni)
		insec("allow_insecure")
		return "tuic://{UUID}:{PASS}@" + addr + "?" + q.Encode()
	}
	return ""
}

// ---- running ----

func writeEndNode(path string, c *EndNodeConfig) error {
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// users merges the fixed users with those of the panel (the panel wins on a name clash).
func mergeEndUsers(local []EndUser, panel []SyncUser) []EndUser {
	seen := map[string]bool{}
	var out []EndUser
	for _, u := range panel {
		if u.Name != "" && u.UUID != "" && !seen[u.Name] {
			seen[u.Name] = true
			out = append(out, EndUser{u.Name, u.UUID})
		}
	}
	for _, u := range local {
		if u.Name != "" && u.UUID != "" && !seen[u.Name] {
			seen[u.Name] = true
			out = append(out, u)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func userNames(us []EndUser) string {
	var b strings.Builder
	for _, u := range us {
		b.WriteString(u.Name + ":" + u.UUID + ",")
	}
	return b.String()
}

// endNodeTick is how often the loop looks at the config file and the users (a variable for tests).
var endNodeTick = 5 * time.Second

// RunEndNode is the main loop of the end node.
func RunEndNode(ctx context.Context, path string) error {
	c, err := LoadEndNode(path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(c.WorkDir, 0o700); err != nil {
		return err
	}
	cache := filepath.Join(c.WorkDir, "users.json")
	var panelUsers []SyncUser
	if b, err := os.ReadFile(cache); err == nil {
		_ = json.Unmarshal(b, &panelUsers) // the last list: a restart without the panel must not lock everybody out
	}
	proc := NewSBProc(ctx, c.SingboxBin, c.WorkDir, "endnode")
	defer proc.Stop()
	cl := panelClient(c.PanelInsecure)
	var lastMod time.Time
	var lastSync time.Time
	var lastSet string
	for {
		if st, err := os.Stat(path); err == nil && st.ModTime() != lastMod {
			if lastMod != (time.Time{}) {
				if nc, err := LoadEndNode(path); err != nil {
					fmt.Fprintf(os.Stderr, "endnode: новый конфиг отвергнут: %v (работает прежний)\n", err)
				} else {
					c = nc
					lastSync = time.Time{} // tell the panel the new links at once
				}
			}
			lastMod = st.ModTime()
		}
		if c.PanelURL != "" && time.Since(lastSync) >= c.SyncInterval {
			lastSync = time.Now()
			sc, cancel := context.WithTimeout(ctx, 40*time.Second)
			us, err := PanelSync(sc, cl, c.PanelURL, c.PanelToken, SyncReport{Kind: "endnode",
				Info: ServerInfo{Version: appVersion, Host: c.Host, Links: c.Templates(), Users: len(panelUsers)}})
			cancel()
			if err != nil {
				fmt.Fprintf(os.Stderr, "endnode: панель недоступна: %v (остаётся прежний список пользователей)\n", scrubErr(err))
			} else {
				panelUsers = us
				if b, err := json.Marshal(us); err == nil {
					os.WriteFile(cache, b, 0o600)
				}
			}
		}
		users := mergeEndUsers(c.Users, panelUsers)
		set := userNames(users) + fmt.Sprint(c.Inbounds, c.TLS)
		if set != lastSet || !proc.Running() {
			cfg, err := c.BuildConfig(users)
			if err == nil {
				var restarted bool
				if restarted, err = proc.Apply(cfg); restarted {
					fmt.Fprintf(os.Stderr, "endnode: sing-box перезапущен, пользователей: %d, протоколов: %d\n", len(users), len(c.Inbounds))
				}
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "endnode: %v\n", err)
			} else {
				lastSet = set
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(endNodeTick):
		}
	}
}
