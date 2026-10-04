package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
)

const wgHelp = `использование:
  wg list                               сервер и пары (роутеры, устройства)
  wg add ИМЯ [СЕТЬ…]                    новая пара; СЕТЬ - подсеть за роутером, например 192.168.50.0/24 (без неё - одно устройство)
  wg show ИМЯ [--wgquick] [--endpoint АДРЕС]   скрипт для MikroTik (по умолчанию) или профиль для приложения WireGuard
  wg off ИМЯ | wg on ИМЯ                временно отключить / включить
  wg del ИМЯ                            удалить`

func cliWG(ctx context.Context, cfg *Config, st *Store, args []string) error {
	if len(args) < 2 {
		fmt.Println(wgHelp)
		return nil
	}
	endpoint := cfg.WGEndpoint
	if endpoint == "" {
		endpoint = cfg.PublicHost
	}
	switch args[1] {
	case "list", "ls":
		_, pub, err := st.WGServerKey(ctx)
		if err != nil {
			return err
		}
		peers, err := st.ListWGPeers(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("сервер:  %s:%d/udp, адрес в туннеле %s (сеть %s)\nключ:    %s\n\n", endpoint, cfg.wgPort(), cfg.wgServerAddr(), cfg.wgNetwork(), pub)
		if len(peers) == 0 {
			fmt.Println("пар пока нет: wg add ИМЯ 192.168.50.0/24")
			return nil
		}
		tw := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ИМЯ\tАДРЕС\tСЕТИ\tСТАТУС")
		for _, p := range peers {
			state := "включена"
			if !p.Enabled {
				state = "отключена"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", p.Name, p.Address, strings.Join(p.Subnets, ", "), state)
		}
		tw.Flush()
	case "add":
		if len(args) < 3 {
			return fmt.Errorf("использование: wg add ИМЯ [СЕТЬ…]")
		}
		p, err := st.AddWGPeer(ctx, cfg, args[2], args[3:])
		if err != nil {
			return err
		}
		fmt.Printf("создана пара %s (адрес в туннеле %s). Туннель поднимется на сервере в течение 30 секунд.\nСкрипт для роутера: wg show %s\n", p.Name, p.Address, p.Name)
	case "show":
		if len(args) < 3 {
			return fmt.Errorf("использование: wg show ИМЯ [--wgquick] [--endpoint АДРЕС]")
		}
		format := "routeros"
		for i := 3; i < len(args); i++ {
			switch args[i] {
			case "--wgquick":
				format = "wgquick"
			case "--endpoint":
				if i+1 >= len(args) {
					return fmt.Errorf("--endpoint АДРЕС")
				}
				i++
				endpoint = args[i]
			default:
				return fmt.Errorf("неизвестный параметр %q", args[i])
			}
		}
		peers, err := st.ListWGPeers(ctx)
		if err != nil {
			return err
		}
		_, pub, err := st.WGServerKey(ctx)
		if err != nil {
			return err
		}
		for _, p := range peers {
			if p.Name == args[2] {
				if format == "wgquick" {
					fmt.Print(wgQuickConfig(cfg, pub, endpoint, p))
				} else {
					fmt.Print(routerOSScript(cfg, pub, endpoint, p))
				}
				return nil
			}
		}
		return fmt.Errorf("пара %q не найдена", args[2])
	case "on", "off":
		if len(args) < 3 {
			return fmt.Errorf("использование: wg %s ИМЯ", args[1])
		}
		if err := st.SetWGPeerEnabled(ctx, args[2], args[1] == "on"); err != nil {
			return err
		}
		fmt.Println("готово")
	case "del", "rm":
		if len(args) < 3 {
			return fmt.Errorf("использование: wg del ИМЯ")
		}
		ok, err := st.DeleteWGPeer(ctx, args[2])
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("пара %q не найдена", args[2])
		}
		fmt.Println("удалена")
	default:
		fmt.Println(wgHelp)
	}
	return nil
}
