package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// WireGuard node (installer --mode wg, version 3.7.0): the smallest installation. It has no database, no balancing and no
// users: it takes a subscription, lets the person choose ONE server from it and sends everything that arrives through
// WireGuard to that server:
//
//	device in 192.168.0.0/24 -> router -> WireGuard -> this node (sing-box) -> the chosen server of the subscription
//
// There is no direct exit: if the chosen server is not in the subscription (or never was) the traffic is rejected.
//
//	balancer -c wgnode.yaml wgnode run | init | servers | select NAME | status | peer add|del|list|config NAME

type WGNodeConfig struct {
	Subscription string        `yaml:"subscription"` // address of the subscription with the servers
	UserAgent    string        `yaml:"user_agent,omitempty"`
	Server       string        `yaml:"server"`              // the chosen server (its name in the subscription)
	ServerID     string        `yaml:"server_id,omitempty"` // and its stable id, to survive renames
	Refresh      time.Duration `yaml:"refresh,omitempty"`
	Endpoint     string        `yaml:"endpoint"` // address of this node for the profiles of the peers
	WGPort       int           `yaml:"wg_port"`
	WGNetwork    string        `yaml:"wg_network"`
	PrivateKey   string        `yaml:"private_key"`
	PublicKey    string        `yaml:"public_key"`
	SingboxBin   string        `yaml:"singbox_bin,omitempty"`
	WorkDir      string        `yaml:"work_dir"`
	Peers        []WGNodePeer  `yaml:"peers"`
}

type WGNodePeer struct {
	Name       string   `yaml:"name"`
	PrivateKey string   `yaml:"private_key"`
	PublicKey  string   `yaml:"public_key"`
	Address    string   `yaml:"address"`
	Subnets    []string `yaml:"subnets"` // the network behind a router, e.g. 192.168.0.0/24
}

func LoadWGNode(path string) (*WGNodeConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &WGNodeConfig{}
	if err := yaml.Unmarshal(raw, c); err != nil {
		return nil, err
	}
	if c.Refresh == 0 {
		c.Refresh = 30 * time.Minute
	}
	if c.UserAgent == "" {
		c.UserAgent = "sing-box"
	}
	if c.WGPort == 0 {
		c.WGPort = wgDefaultPort
	}
	if c.WGNetwork == "" {
		c.WGNetwork = wgDefaultNetwork
	}
	if c.SingboxBin == "" {
		c.SingboxBin = "sing-box"
	}
	if c.WorkDir == "" {
		c.WorkDir = "/var/lib/wgnode"
	}
	if p, err := netip.ParsePrefix(c.WGNetwork); err != nil || !p.Addr().Is4() || p.Bits() < 16 || p.Bits() > 29 {
		return nil, fmt.Errorf("wg_network: нужна IPv4-сеть от /16 до /29, получено %q", c.WGNetwork)
	}
	return c, nil
}

func (c *WGNodeConfig) save(path string) error {
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// cfg adapts the settings to the helpers of the full installation (profiles, RouterOS script).
func (c *WGNodeConfig) cfg() *Config { return &Config{WGPort: c.WGPort, WGNetwork: c.WGNetwork} }

func (c *WGNodeConfig) serverAddr() netip.Addr { return c.cfg().wgServerAddr() }

// serverOutbound finds the chosen server in a list of nodes.
func (c *WGNodeConfig) pick(nodes []*Node) *Node {
	if c.Server == "" && c.ServerID == "" {
		return nil
	}
	for _, n := range nodes {
		if c.ServerID != "" && n.ID == c.ServerID {
			return n
		}
	}
	for _, n := range nodes {
		if n.Name == c.Server {
			return n
		}
	}
	return nil
}

// BuildWGNodeConfig makes the sing-box config. A nil node means "reject everything".
func BuildWGNodeConfig(c *WGNodeConfig, node *Node) ([]byte, error) {
	if c.PrivateKey == "" {
		return nil, errors.New("нет ключа WireGuard (init создаёт его)")
	}
	var peers []any
	for _, p := range c.Peers {
		allowed := append([]string{p.Address + "/32"}, p.Subnets...)
		peers = append(peers, map[string]any{"public_key": p.PublicKey, "allowed_ips": allowed, "persistent_keepalive_interval": 25})
	}
	srv := c.serverAddr().String() + "/" + fmt.Sprint(c.cfg().wgNetwork().Bits())
	ep := map[string]any{"type": "wireguard", "tag": "wg", "system": false, "name": "wg-node", "mtu": wgMTU,
		"address": []string{srv}, "private_key": c.PrivateKey, "listen_port": c.WGPort, "peers": peers}
	outbounds := []any{map[string]any{"type": "direct", "tag": "direct"}}
	route := map[string]any{}
	if node != nil {
		o := map[string]any{}
		for k, v := range node.Outbound {
			o[k] = v
		}
		o["tag"] = "out"
		outbounds = []any{o, map[string]any{"type": "direct", "tag": "direct"}}
		// everything from the tunnel goes to the chosen server; there is no other way out
		route["rules"] = []any{
			map[string]any{"inbound": []string{"wg"}, "outbound": "out"},
			map[string]any{"action": "reject"},
		}
		route["final"] = "out"
	} else {
		route["rules"] = []any{map[string]any{"action": "reject"}}
		route["final"] = "direct"
	}
	conf := map[string]any{"log": map[string]any{"level": "warn", "timestamp": true},
		"endpoints": []any{ep}, "outbounds": outbounds, "route": route}
	return json.MarshalIndent(conf, "", "  ")
}

func fetchWGNodes(ctx context.Context, c *WGNodeConfig) ([]*Node, error) {
	if c.Subscription == "" {
		return nil, errors.New("subscription не задана")
	}
	body, err := fetchSub(ctx, c.Subscription, c.UserAgent)
	if err != nil {
		return nil, scrubErr(err)
	}
	nodes := ParseLinks(body)
	if len(nodes) == 0 {
		return nil, errors.New("в подписке нет поддерживаемых серверов")
	}
	sort.SliceStable(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
	return nodes, nil
}

// RunWGNode runs the node: refresh the subscription, keep sing-box in step with the file.
func RunWGNode(ctx context.Context, path string) error {
	c, err := LoadWGNode(path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(c.WorkDir, 0o700); err != nil {
		return err
	}
	cache := filepath.Join(c.WorkDir, "node.json")
	var node *Node
	if b, err := os.ReadFile(cache); err == nil { // the last known server: works without the subscription after a restart
		var n Node
		if json.Unmarshal(b, &n) == nil && n.Outbound != nil {
			node = &n
		}
	}
	proc := NewSBProc(ctx, c.SingboxBin, c.WorkDir, "wgnode")
	defer proc.Stop()
	var lastMod, lastFetch time.Time
	lastSig := "-"
	for {
		if st, err := os.Stat(path); err == nil && st.ModTime() != lastMod {
			if lastMod != (time.Time{}) {
				if nc, err := LoadWGNode(path); err != nil {
					fmt.Fprintf(os.Stderr, "wgnode: новый конфиг отвергнут: %v\n", err)
				} else {
					c = nc
					lastFetch = time.Time{}
				}
			}
			lastMod = st.ModTime()
		}
		if time.Since(lastFetch) >= c.Refresh || (node == nil && time.Since(lastFetch) > time.Minute) {
			lastFetch = time.Now()
			fc, cancel := context.WithTimeout(ctx, time.Minute)
			nodes, err := fetchWGNodes(fc, c)
			cancel()
			if err != nil {
				fmt.Fprintf(os.Stderr, "wgnode: подписка: %v (остаётся прежний сервер)\n", err)
			} else if n := c.pick(nodes); n != nil {
				node = n
				if b, err := json.Marshal(n); err == nil {
					os.WriteFile(cache, b, 0o600)
				}
			} else if c.Server != "" {
				fmt.Fprintf(os.Stderr, "wgnode: сервера %q нет в подписке (остаётся прежний)\n", c.Server)
			}
		}
		if c.pickSame(node) {
			// the cached node belongs to a server that is no longer chosen
		} else {
			node = nil
		}
		cfg, err := BuildWGNodeConfig(c, node)
		if err == nil {
			sig := string(cfg)
			if sig != lastSig || !proc.Running() {
				var restarted bool
				if restarted, err = proc.Apply(cfg); restarted {
					name := "(нет — трафик блокируется)"
					if node != nil {
						name = node.Name
					}
					fmt.Fprintf(os.Stderr, "wgnode: sing-box перезапущен, сервер: %s, устройств: %d\n", name, len(c.Peers))
				}
				if err == nil {
					lastSig = sig
				}
			}
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "wgnode: %v\n", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(5 * time.Second):
		}
	}
}

// pickSame reports whether the cached node is the chosen one.
func (c *WGNodeConfig) pickSame(n *Node) bool {
	if n == nil {
		return false
	}
	return (c.ServerID != "" && n.ID == c.ServerID) || (c.ServerID == "" && n.Name == c.Server)
}

func wgNodeInit(path string, args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	sub := fs.String("subscription", "", "адрес подписки")
	srv := fs.String("server", "", "имя сервера из подписки (можно выбрать позже: select)")
	ep := fs.String("endpoint", "", "адрес этого сервера для профилей устройств")
	lan := fs.String("lan", "192.168.0.0/24", "сеть за роутером")
	port := fs.Int("port", wgDefaultPort, "порт WireGuard (UDP)")
	netw := fs.String("network", wgDefaultNetwork, "сеть внутри туннеля")
	work := fs.String("work-dir", "/var/lib/wgnode", "каталог данных")
	peer := fs.String("peer", "router", "имя первого устройства (пусто = не создавать)")
	force := fs.Bool("force", false, "перезаписать")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil && !*force {
		return fmt.Errorf("%s уже есть (--force перезапишет)", path)
	}
	priv, pub, err := wgGenKey()
	if err != nil {
		return err
	}
	c := &WGNodeConfig{Subscription: *sub, Server: *srv, Endpoint: *ep, WGPort: *port, WGNetwork: *netw, PrivateKey: priv, PublicKey: pub, WorkDir: *work}
	if *peer != "" {
		if err := c.addPeer(*peer, []string{*lan}); err != nil {
			return err
		}
	}
	return c.save(path)
}

func (c *WGNodeConfig) addPeer(name string, subnets []string) error {
	if !reWGName.MatchString(name) {
		return errors.New("имя: латиница, цифры, точка, дефис, подчёркивание, до 32 знаков")
	}
	tunnel := c.cfg().wgNetwork()
	subs, err := parseSubnets(subnets, tunnel)
	if err != nil {
		return err
	}
	used := map[netip.Addr]bool{c.serverAddr(): true}
	for _, p := range c.Peers {
		if p.Name == name {
			return fmt.Errorf("устройство %q уже есть", name)
		}
		if a, err := netip.ParseAddr(p.Address); err == nil {
			used[a] = true
		}
		if pair, bad := subnetsOverlap(subs, p.Subnets); bad {
			return fmt.Errorf("сеть %s уже занята устройством %q", pair, p.Name)
		}
	}
	var addr netip.Addr
	for a := c.serverAddr().Next(); tunnel.Contains(a); a = a.Next() {
		if !used[a] && a != lastAddr(tunnel) {
			addr = a
			break
		}
	}
	if !addr.IsValid() {
		return errors.New("в сети туннеля не осталось свободных адресов")
	}
	priv, pub, err := wgGenKey()
	if err != nil {
		return err
	}
	c.Peers = append(c.Peers, WGNodePeer{Name: name, PrivateKey: priv, PublicKey: pub, Address: addr.String(), Subnets: subs})
	return nil
}

func (c *WGNodeConfig) peer(name string) *WGNodePeer {
	for i := range c.Peers {
		if c.Peers[i].Name == name {
			return &c.Peers[i]
		}
	}
	return nil
}

// selectServer picks one server of the subscription by exact name or by a part of the name that matches exactly one.
func selectServer(nodes []*Node, q string) (*Node, error) {
	var part []*Node
	for _, n := range nodes {
		if n.Name == q {
			return n, nil
		}
		if strings.Contains(strings.ToLower(n.Name), strings.ToLower(q)) {
			part = append(part, n)
		}
	}
	switch len(part) {
	case 0:
		return nil, fmt.Errorf("сервера %q нет в подписке (список: wgnode servers)", q)
	case 1:
		return part[0], nil
	}
	var names []string
	for _, n := range part {
		names = append(names, n.Name)
	}
	return nil, fmt.Errorf("под %q подходит несколько серверов, уточните: %s", q, strings.Join(names, "; "))
}

// RunWGNodeCLI executes `balancer -c wgnode.yaml wgnode <command>`.
func RunWGNodeCLI(ctx context.Context, path string, args []string) error {
	cmd := "run"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	if cmd == "init" {
		return wgNodeInit(path, args)
	}
	c, err := LoadWGNode(path)
	if err != nil {
		return fmt.Errorf("wgnode.yaml: %v", err)
	}
	switch cmd {
	case "run":
		return RunWGNode(ctx, path)
	case "servers":
		fc, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		nodes, err := fetchWGNodes(fc, c)
		if err != nil {
			return err
		}
		for i, n := range nodes {
			mark := " "
			if c.pickSame(&Node{ID: n.ID, Name: n.Name}) {
				mark = "*"
			}
			fmt.Printf("%s %3d  %-40s %s %s:%d\n", mark, i+1, n.Name, n.Type, n.Server, n.Port)
		}
	case "select":
		if len(args) < 1 {
			return errors.New("использование: wgnode select ИМЯ (или часть имени; список: wgnode servers)")
		}
		fc, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		nodes, err := fetchWGNodes(fc, c)
		if err != nil {
			return err
		}
		n, err := selectServer(nodes, strings.Join(args, " "))
		if err != nil {
			return err
		}
		c.Server, c.ServerID = n.Name, n.ID
		if err := c.save(path); err != nil {
			return err
		}
		fmt.Printf("выбран сервер: %s; работающий узел переключится за несколько секунд\n", n.Name)
	case "status":
		fmt.Printf("подписка: %s\nсервер:   %s\nустройств: %d\n", redact(c.Subscription), orDash(c.Server), len(c.Peers))
	case "peer":
		return wgNodePeerCLI(c, path, args)
	default:
		return errors.New("команды: run, init, servers, select, status, peer")
	}
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "— не выбран (трафик блокируется; выберите: wgnode select ИМЯ)"
	}
	return s
}

func wgNodePeerCLI(c *WGNodeConfig, path string, args []string) error {
	if len(args) == 0 {
		return errors.New("использование: wgnode peer add ИМЯ [--lan СЕТЬ] | del ИМЯ | list | config ИМЯ | router ИМЯ")
	}
	op := args[0]
	args = args[1:]
	switch op {
	case "list":
		for _, p := range c.Peers {
			fmt.Printf("%-16s %-14s сети: %s\n", p.Name, p.Address, strings.Join(p.Subnets, ", "))
		}
	case "add":
		fs := flag.NewFlagSet("peer add", flag.ContinueOnError)
		lan := fs.String("lan", "", "сеть за роутером, например 192.168.0.0/24 (пусто = одно устройство)")
		fs.Parse(reorderFlags(args))
		if fs.NArg() < 1 {
			return errors.New("использование: wgnode peer add ИМЯ [--lan СЕТЬ]")
		}
		var subs []string
		if *lan != "" {
			subs = []string{*lan}
		}
		if err := c.addPeer(fs.Arg(0), subs); err != nil {
			return err
		}
		if err := c.save(path); err != nil {
			return err
		}
		fmt.Println("добавлено; профиль: wgnode peer config", fs.Arg(0))
	case "del":
		if len(args) < 1 {
			return errors.New("использование: wgnode peer del ИМЯ")
		}
		var keep []WGNodePeer
		for _, p := range c.Peers {
			if p.Name != args[0] {
				keep = append(keep, p)
			}
		}
		if len(keep) == len(c.Peers) {
			return fmt.Errorf("устройства %q нет", args[0])
		}
		c.Peers = keep
		return c.save(path)
	case "config", "router":
		if len(args) < 1 {
			return fmt.Errorf("использование: wgnode peer %s ИМЯ", op)
		}
		p := c.peer(args[0])
		if p == nil {
			return fmt.Errorf("устройства %q нет", args[0])
		}
		if c.Endpoint == "" {
			return errors.New("endpoint не задан в wgnode.yaml (адрес этого сервера)")
		}
		wp := WGPeer{Name: p.Name, PrivateKey: p.PrivateKey, PublicKey: p.PublicKey, Address: p.Address, Subnets: p.Subnets}
		if op == "router" {
			fmt.Print(routerOSScript(c.cfg(), c.PublicKey, c.Endpoint, wp))
		} else {
			fmt.Print(wgQuickConfig(c.cfg(), c.PublicKey, c.Endpoint, wp))
		}
	default:
		return errors.New("peer: add, del, list, config, router")
	}
	return nil
}
