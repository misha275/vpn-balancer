package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

// WireGuard for the home network.
//
// A router (MikroTik, anything with WireGuard) connects to the balancer with one tunnel. Everything the router
// sends into the tunnel for the chosen subnet comes out through the pool of nodes: the same selection, the same
// filter rules, the same country policy and the same "never leave directly" rule as for the VPN apps.
//
// The WireGuard endpoint lives in its own long-running sing-box inside the gateway, so a new configuration of the
// gateway (new nodes, new users) does not drop the tunnel. Its flows are handed over to the active instance of the
// gateway as SOCKS5 connections (UDP inside TCP), one login per peer ("wg-NAME"), which is also what the statistics
// show as the client:
//
//	device -> router -> WireGuard (UDP) -> wg sing-box -> front 127.0.0.1:wgFront -> active instance (wg-in) -> node

const (
	wgDefaultPort    = 51820
	wgDefaultNetwork = "10.77.0.0/24"
	wgMTU            = 1380
)

var reWGName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)

// WGPeer is one router (or one device) that connects to the balancer.
type WGPeer struct {
	Name       string    `json:"name"`
	PrivateKey string    `json:"-"`
	PublicKey  string    `json:"public_key"`
	Address    string    `json:"address"` // inside the tunnel, e.g. 10.77.0.2
	Subnets    []string  `json:"subnets"` // networks behind the peer (a router); empty for a single device
	Enabled    bool      `json:"enabled"`
	Created    time.Time `json:"created"`
}

// wgSocksUser is the login of a peer on the wg-in inbound of the gateway instances.
func wgSocksUser(name string) string { return "wg-" + name }

func (c *Config) wgPort() int {
	if c.WGPort <= 0 {
		return wgDefaultPort
	}
	return c.WGPort
}

func (c *Config) wgNetwork() netip.Prefix {
	p, err := netip.ParsePrefix(c.WGNetwork)
	if err != nil || !p.Addr().Is4() {
		p = netip.MustParsePrefix(wgDefaultNetwork)
	}
	return p.Masked()
}

// wgServerAddr is the address of the balancer inside the tunnel (the first host address).
func (c *Config) wgServerAddr() netip.Addr { return c.wgNetwork().Addr().Next() }

// wgFrontPort is the local port where the wg sing-box hands its flows over; the front forwards it to the active instance.
func (c *Config) wgFrontPort() int { return c.GatewayBase + 40 }

// wgSocksPassword protects wg-in. It only listens on loopback, the secret merely keeps other local processes out.
func (c *Config) wgSocksPassword() string { return derive(c.Reality.PrivateKey, "wg-socks")[:24] }

func (c *Config) getWGPeers() []WGPeer {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]WGPeer(nil), c.wgPeers...)
}

func (c *Config) setWGPeers(p []WGPeer) {
	c.mu.Lock()
	c.wgPeers = p
	c.mu.Unlock()
}

// activeWGPeers are the peers that may use the tunnel.
func activeWGPeers(p []WGPeer) []WGPeer {
	var out []WGPeer
	for _, x := range p {
		if x.Enabled {
			out = append(out, x)
		}
	}
	return out
}

// wgSig changes when the set of peers that the gateway instances must know changes.
func (c *Config) wgSig() string {
	var names []string
	for _, p := range activeWGPeers(c.getWGPeers()) {
		names = append(names, p.Name)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// ---------------------------------------------------------------- keys

func wgGenKey() (priv, pub string, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()), base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

func wgPubFromPriv(priv string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(priv)
	if err != nil {
		return "", err
	}
	k, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// ---------------------------------------------------------------- peers

// parseSubnets validates the networks behind a router: IPv4 CIDRs, no default route, none inside the tunnel network.
func parseSubnets(in []string, tunnel netip.Prefix) ([]string, error) {
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil || !p.Addr().Is4() {
			return nil, fmt.Errorf("%q: нужна IPv4-сеть вида 192.168.50.0/24", s)
		}
		p = p.Masked()
		if p.Bits() < 8 {
			return nil, fmt.Errorf("%s: слишком большая сеть (маршрут по умолчанию нельзя)", p)
		}
		if p.Overlaps(tunnel) {
			return nil, fmt.Errorf("%s пересекается с сетью туннеля %s", p, tunnel)
		}
		out = append(out, p.String())
	}
	return out, nil
}

func subnetsOverlap(a, b []string) (string, bool) {
	for _, x := range a {
		px := netip.MustParsePrefix(x)
		for _, y := range b {
			if px.Overlaps(netip.MustParsePrefix(y)) {
				return x + " и " + y, true
			}
		}
	}
	return "", false
}

// ---------------------------------------------------------------- sing-box configs

// buildWGConfig renders the config of the wg sing-box. An empty result means "no WireGuard needed".
func buildWGConfig(cfg *Config, serverPriv string, peers []WGPeer) ([]byte, error) {
	peers = activeWGPeers(peers)
	if len(peers) == 0 {
		return nil, nil
	}
	var wgPeers, outbounds, rules []any
	for _, p := range peers {
		allowed := append([]string{p.Address + "/32"}, p.Subnets...)
		wgPeers = append(wgPeers, map[string]any{"public_key": p.PublicKey, "allowed_ips": allowed, "persistent_keepalive_interval": 25})
		tag := "to-" + p.Name
		outbounds = append(outbounds, map[string]any{
			"type": "socks", "tag": tag, "server": "127.0.0.1", "server_port": cfg.wgFrontPort(), "version": "5",
			"username": wgSocksUser(p.Name), "password": cfg.wgSocksPassword(),
			"udp_over_tcp": map[string]any{"enabled": true, "version": 2},
		})
		rules = append(rules, map[string]any{"inbound": []string{"wg"}, "source_ip_cidr": allowed, "outbound": tag})
	}
	// whatever else could arrive (a source address that no peer owns) is dropped, never sent out directly
	rules = append(rules, map[string]any{"inbound": []string{"wg"}, "action": "reject"})
	srv := cfg.wgServerAddr().String() + "/" + fmt.Sprint(cfg.wgNetwork().Bits())
	conf := map[string]any{
		"log": map[string]any{"level": "warn", "timestamp": true},
		"endpoints": []any{map[string]any{
			"type": "wireguard", "tag": "wg", "system": false, "name": "wg-vpnb", "mtu": wgMTU,
			"address": []string{srv}, "private_key": serverPriv, "listen_port": cfg.wgPort(), "peers": wgPeers,
		}},
		"outbounds": outbounds,
		"route":     map[string]any{"rules": rules, "final": "to-" + peers[0].Name},
	}
	return json.MarshalIndent(conf, "", "  ")
}

func wgConfigSig(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

// ---------------------------------------------------------------- store glue

// WGManager keeps the gateway in line with the peers stored in the database.
type WGManager struct {
	cfg  *Config
	st   *Store
	core *Core
}

func NewWGManager(cfg *Config, st *Store, core *Core) *WGManager {
	return &WGManager{cfg: cfg, st: st, core: core}
}

// Load reads the peers from the database into the config (the instances need their logins).
func (w *WGManager) Load(ctx context.Context) error {
	peers, err := w.st.ListWGPeers(ctx)
	if err != nil {
		return err
	}
	w.cfg.setWGPeers(peers)
	return nil
}

// Reconcile makes the gateway run the WireGuard endpoint that matches the database. Cheap when nothing changed.
func (w *WGManager) Reconcile(ctx context.Context) {
	if err := w.Load(ctx); err != nil {
		log.Printf("wireguard: %v", err)
		return
	}
	peers := w.cfg.getWGPeers()
	var data []byte
	if len(activeWGPeers(peers)) > 0 {
		priv, _, err := w.st.WGServerKey(ctx)
		if err != nil {
			log.Printf("wireguard: server key: %v", err)
			return
		}
		if data, err = buildWGConfig(w.cfg, priv, peers); err != nil {
			log.Printf("wireguard: config: %v", err)
			return
		}
	}
	fp := ""
	if data != nil {
		fp = wgConfigSig(data)
	}
	st, err := w.core.GatewayState()
	if err != nil {
		return // the gateway is not reachable now; the next tick retries
	}
	if st.WGFp == fp {
		return
	}
	if err := w.core.ApplyWG(ctx, data, fp); err != nil {
		log.Printf("wireguard: the gateway did not accept the configuration: %v", err)
		return
	}
	if data == nil {
		log.Printf("wireguard: no active peers, the tunnel is off")
	} else {
		log.Printf("wireguard: tunnel is up on udp/%d with %d peer(s)", w.cfg.wgPort(), len(activeWGPeers(peers)))
	}
}

// AddPeer creates a peer with new keys and the next free tunnel address.
func (s *Store) AddWGPeer(ctx context.Context, cfg *Config, name string, subnets []string) (*WGPeer, error) {
	name = strings.TrimSpace(name)
	if !reWGName.MatchString(name) {
		return nil, errors.New("имя: латиница, цифры, точка, дефис, подчёркивание, до 32 знаков")
	}
	tunnel := cfg.wgNetwork()
	subs, err := parseSubnets(subnets, tunnel)
	if err != nil {
		return nil, err
	}
	peers, err := s.ListWGPeers(ctx)
	if err != nil {
		return nil, err
	}
	used := map[netip.Addr]bool{cfg.wgServerAddr(): true}
	for _, p := range peers {
		if p.Name == name {
			return nil, fmt.Errorf("пара %q уже есть", name)
		}
		if a, err := netip.ParseAddr(p.Address); err == nil {
			used[a] = true
		}
		if pair, bad := subnetsOverlap(subs, p.Subnets); bad {
			return nil, fmt.Errorf("сеть %s уже занята парой %q", pair, p.Name)
		}
	}
	var addr netip.Addr
	for a := cfg.wgServerAddr().Next(); tunnel.Contains(a); a = a.Next() {
		if !used[a] && a != lastAddr(tunnel) {
			addr = a
			break
		}
	}
	if !addr.IsValid() {
		return nil, errors.New("в сети туннеля не осталось свободных адресов")
	}
	priv, pub, err := wgGenKey()
	if err != nil {
		return nil, err
	}
	p := &WGPeer{Name: name, PrivateKey: priv, PublicKey: pub, Address: addr.String(), Subnets: subs, Enabled: true, Created: time.Now()}
	if subs == nil {
		p.Subnets = []string{}
	}
	sj, _ := json.Marshal(p.Subnets)
	if _, err := s.pool.Exec(ctx, `INSERT INTO wg_peers(name,private_key,public_key,address,subnets,enabled) VALUES($1,$2,$3,$4,$5,true)`,
		p.Name, p.PrivateKey, p.PublicKey, p.Address, sj); err != nil {
		return nil, fmt.Errorf("не удалось сохранить: %v", err)
	}
	return p, nil
}

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr()
	b := a.As4()
	hostBits := 32 - p.Bits()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v |= (1 << hostBits) - 1
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func (s *Store) ListWGPeers(ctx context.Context) ([]WGPeer, error) {
	rows, err := s.pool.Query(ctx, `SELECT name,private_key,public_key,address,subnets,enabled,created FROM wg_peers ORDER BY created, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WGPeer
	for rows.Next() {
		var p WGPeer
		var sj []byte
		if err := rows.Scan(&p.Name, &p.PrivateKey, &p.PublicKey, &p.Address, &sj, &p.Enabled, &p.Created); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(sj, &p.Subnets)
		if p.Subnets == nil {
			p.Subnets = []string{}
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) DeleteWGPeer(ctx context.Context, name string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM wg_peers WHERE name=$1`, name)
	if err == nil && tag.RowsAffected() > 0 {
		_, _ = s.pool.Exec(ctx, `DELETE FROM traffic_hourly WHERE user_name=$1`, wgSocksUser(name))
		_, _ = s.pool.Exec(ctx, `DELETE FROM user_seen WHERE user_name=$1`, wgSocksUser(name))
	}
	return tag.RowsAffected() > 0, err
}

func (s *Store) SetWGPeerEnabled(ctx context.Context, name string, on bool) error {
	tag, err := s.pool.Exec(ctx, `UPDATE wg_peers SET enabled=$2 WHERE name=$1`, name, on)
	if err == nil && tag.RowsAffected() == 0 {
		return errors.New("пара не найдена")
	}
	return err
}

// WGServerKey returns the key pair of the balancer's WireGuard side, creating it on first use.
func (s *Store) WGServerKey(ctx context.Context) (priv, pub string, err error) {
	err = s.pool.QueryRow(ctx, `SELECT private_key, public_key FROM wg_server WHERE id=1`).Scan(&priv, &pub)
	if err == nil {
		return priv, pub, nil
	}
	priv, pub, err = wgGenKey()
	if err != nil {
		return "", "", err
	}
	if _, err = s.pool.Exec(ctx, `INSERT INTO wg_server(id,private_key,public_key) VALUES(1,$1,$2) ON CONFLICT (id) DO NOTHING`, priv, pub); err != nil {
		return "", "", err
	}
	err = s.pool.QueryRow(ctx, `SELECT private_key, public_key FROM wg_server WHERE id=1`).Scan(&priv, &pub)
	return priv, pub, err
}

// ---------------------------------------------------------------- what the operator pastes

// wgQuickConfig is a profile for a normal WireGuard client (a phone, a laptop, a Linux box).
func wgQuickConfig(cfg *Config, serverPub, endpoint string, p WGPeer) string {
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32
DNS = 1.1.1.1, 8.8.8.8
MTU = %d

[Peer]
PublicKey = %s
Endpoint = %s:%d
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`, p.PrivateKey, p.Address, wgMTU, serverPub, endpoint, cfg.wgPort())
}

// routerOSScript is a template for MikroTik RouterOS 7: the tunnel, a routing table that only has the tunnel, and a rule
// that sends the given subnet (or only the devices put on an address list) into it.
func routerOSScript(cfg *Config, serverPub, endpoint string, p WGPeer) string {
	subnet := "192.168.50.0/24"
	if len(p.Subnets) > 0 {
		subnet = p.Subnets[0]
	}
	pf := netip.MustParsePrefix(subnet)
	gw := pf.Masked().Addr().Next().String()
	return fmt.Sprintf(`# VPN-балансировщик: туннель WireGuard и отдельная сеть %[1]s, весь трафик которой идёт через балансировщик.
# Команды для RouterOS 7. Выполняйте по порядку (New Terminal). Имена wg-vpn, br-vpn, таблица vpn можно менять.

# 1. Туннель к балансировщику
/interface wireguard add name=wg-vpn mtu=%[2]d listen-port=13231 private-key="%[3]s" comment="vpn-balancer"
/ip address add address=%[4]s/%[5]d interface=wg-vpn comment="vpn-balancer"
/interface wireguard peers add interface=wg-vpn public-key="%[6]s" endpoint-address=%[7]s endpoint-port=%[8]d \
    allowed-address=0.0.0.0/0 persistent-keepalive=25s comment="vpn-balancer"

# 2. Отдельная сеть %[1]s (мост br-vpn, DHCP, DNS через туннель)
/interface bridge add name=br-vpn comment="vpn-balancer"
/ip address add address=%[9]s/%[10]d interface=br-vpn comment="vpn-balancer"
/ip pool add name=pool-vpn ranges=%[11]s comment="vpn-balancer"
/ip dhcp-server add name=dhcp-vpn interface=br-vpn address-pool=pool-vpn disabled=no comment="vpn-balancer"
/ip dhcp-server network add address=%[1]s gateway=%[9]s dns-server=1.1.1.1,8.8.8.8 comment="vpn-balancer"
# Чтобы устройство (в том числе проводное) попало в эту сеть, переставьте его порт или Wi-Fi в мост br-vpn, например:
# /interface bridge port set [find interface=ether5] bridge=br-vpn
# Вернуть в обычную сеть: переставьте порт обратно (bridge=bridge).

# 3. Маршрутизация: эта сеть выходит только через туннель
/routing table add name=vpn fib comment="vpn-balancer"
/ip route add dst-address=0.0.0.0/0 gateway=wg-vpn routing-table=vpn comment="vpn-balancer"
# к роутеру (DHCP, DNS) эта сеть ходит как обычно:
/routing rule add dst-address=%[1]s action=lookup table=main comment="vpn-balancer"
# lookup-only-in-table: если туннель упадёт, у этой сети не будет интернета совсем, прямого выхода нет
/routing rule add src-address=%[1]s action=lookup-only-in-table table=vpn comment="vpn-balancer"

# 4. Размер пакетов (иначе часть сайтов будет зависать)
/ip firewall mangle add chain=forward protocol=tcp tcp-flags=syn out-interface=wg-vpn action=change-mss new-mss=clamp-to-pmtu passthrough=yes comment="vpn-balancer"
/ip firewall mangle add chain=forward protocol=tcp tcp-flags=syn in-interface=wg-vpn action=change-mss new-mss=clamp-to-pmtu passthrough=yes comment="vpn-balancer"

# 5. Файрвол: разрешить этой сети выход в туннель и ответы (если у вас стоят запрещающие правила forward)
# /ip firewall filter add chain=forward src-address=%[1]s out-interface=wg-vpn action=accept place-before=0
# /ip firewall filter add chain=forward in-interface=wg-vpn dst-address=%[1]s action=accept place-before=0
# Не пускать эту сеть в вашу обычную сеть: /ip firewall filter add chain=forward src-address=%[1]s dst-address=192.168.0.0/16 action=drop place-before=0

# Вариант «переключать отдельные устройства, не меняя сеть»: вместо правила в пункте 3 пометьте трафик адресным списком
#   /ip firewall mangle add chain=prerouting src-address-list=vpn-devices action=mark-routing new-routing-mark=vpn passthrough=no
#   /ip firewall address-list add list=vpn-devices address=192.168.0.50   (добавить устройство)
#   /ip firewall address-list remove [find list=vpn-devices address=192.168.0.50]   (убрать)
# Проверка: /interface wireguard peers print (должен быть свежий last-handshake), с устройства в сети %[1]s откройте https://ifconfig.me
`, subnet, wgMTU, p.PrivateKey, p.Address, cfg.wgNetwork().Bits(), serverPub, endpoint, cfg.wgPort(), gw, pf.Bits(), poolRange(pf))
}

func poolRange(p netip.Prefix) string {
	a := p.Masked().Addr()
	b := a.As4()
	if p.Bits() >= 25 {
		return fmt.Sprintf("%d.%d.%d.%d-%d.%d.%d.%d", b[0], b[1], b[2], b[3]+2, b[0], b[1], b[2], b[3]+(1<<(32-p.Bits()))-2)
	}
	return fmt.Sprintf("%d.%d.%d.100-%d.%d.%d.200", b[0], b[1], b[2], b[0], b[1], b[2])
}
