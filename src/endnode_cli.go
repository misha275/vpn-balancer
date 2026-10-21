package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RunEndNodeCLI executes `balancer -c endnode.yaml endnode <command>`.
func RunEndNodeCLI(ctx context.Context, path string, args []string) error {
	cmd := "run"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	if cmd == "init" {
		return endNodeInit(path, args)
	}
	c, err := LoadEndNode(path)
	if err != nil {
		return fmt.Errorf("endnode.yaml: %v", err)
	}
	switch cmd {
	case "run":
		return RunEndNode(ctx, path)
	case "check":
		cfg, err := c.BuildConfig([]EndUser{{"check", "00000000-0000-4000-8000-000000000000"}})
		if err == nil {
			err = CheckConfig(c.SingboxBin, cfg)
		}
		if err != nil {
			return err
		}
		fmt.Printf("конфиг в порядке: %d протоколов, адрес %s\n", len(c.Inbounds), c.Host)
	case "inbounds":
		for _, in := range c.Inbounds {
			fmt.Printf("%-16s %-14s порт %d\n", in.Name, in.Type, in.Port)
		}
	case "add":
		fs := flag.NewFlagSet("add", flag.ContinueOnError)
		name := fs.String("name", "", "имя протокола")
		port := fs.Int("port", 0, "порт")
		fs.Parse(reorderFlags(args))
		if fs.NArg() < 1 {
			return fmt.Errorf("использование: endnode add ТИП [--name ИМЯ] [--port ПОРТ]\nтипы: %s", strings.Join(endTypeNames(), ", "))
		}
		in, err := NewInbound(fs.Arg(0), *name, *port)
		if err != nil {
			return err
		}
		c.Inbounds = append(c.Inbounds, in)
		if err := c.Validate(); err != nil {
			return err
		}
		if err := writeEndNode(path, c); err != nil {
			return err
		}
		fmt.Printf("добавлен %s (%s, порт %d); работающий узел подхватит изменение за несколько секунд\n", in.Name, in.Type, in.Port)
	case "del":
		if len(args) < 1 {
			return fmt.Errorf("использование: endnode del ИМЯ")
		}
		var keep []EndInbound
		for _, in := range c.Inbounds {
			if in.Name != args[0] {
				keep = append(keep, in)
			}
		}
		if len(keep) == len(c.Inbounds) {
			return fmt.Errorf("протокола %q нет", args[0])
		}
		c.Inbounds = keep
		if err := c.Validate(); err != nil {
			return err
		}
		return writeEndNode(path, c)
	case "links":
		users := c.Users
		var cached []SyncUser
		if b, err := os.ReadFile(filepath.Join(c.WorkDir, "users.json")); err == nil {
			_ = json.Unmarshal(b, &cached)
		}
		all := mergeEndUsers(users, cached)
		for _, u := range all {
			if len(args) > 0 && u.Name != args[0] {
				continue
			}
			fmt.Println("#", u.Name)
			for _, t := range c.Templates() {
				if l, ok := fillTemplate(t, "endnode", User{UUID: u.UUID}, c.Name+" · "+t.Title); ok {
					fmt.Println(l)
				}
			}
		}
	default:
		return fmt.Errorf("команды: run, check, init, inbounds, add, del, links")
	}
	return nil
}

// reorderFlags lets flags follow the positional argument ("add hysteria2 --port 8443").
func reorderFlags(args []string) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			flags = append(flags, args[i])
			if !strings.Contains(args[i], "=") && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		} else {
			pos = append(pos, args[i])
		}
	}
	return append(flags, pos...)
}

func endNodeInit(path string, args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	name := fs.String("name", "", "имя узла")
	host := fs.String("host", "", "адрес сервера (домен или IP)")
	purl := fs.String("panel-url", "", "адрес панели")
	ptok := fs.String("panel-token", "", "токен сервера из панели")
	insecure := fs.Bool("insecure", false, "не проверять сертификат панели")
	ins := fs.String("inbounds", "vless-reality", "протоколы через запятую: тип[:порт]")
	tlsMode := fs.String("tls", "self-signed", "self-signed | file | acme")
	email := fs.String("email", "", "почта для acme")
	cert := fs.String("cert", "", "файл сертификата")
	key := fs.String("key", "", "файл ключа")
	work := fs.String("work-dir", "/var/lib/endnode", "каталог данных")
	force := fs.Bool("force", false, "перезаписать существующий файл")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil && !*force {
		return fmt.Errorf("%s уже есть (--force перезапишет)", path)
	}
	c := &EndNodeConfig{Name: *name, Host: *host, PanelURL: *purl, PanelToken: *ptok, PanelInsecure: *insecure, WorkDir: *work,
		TLS: EndTLS{Mode: *tlsMode, Email: *email, Cert: *cert, Key: *key}}
	if c.Name == "" {
		c.Name = "Узел"
	}
	for _, spec := range strings.Split(*ins, ",") {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}
		typ, port := spec, 0
		if i := strings.Index(spec, ":"); i > 0 {
			typ = spec[:i]
			fmt.Sscan(spec[i+1:], &port)
		}
		in, err := NewInbound(typ, "", port)
		if err != nil {
			return err
		}
		c.Inbounds = append(c.Inbounds, in)
	}
	if err := c.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return writeEndNode(path, c)
}
