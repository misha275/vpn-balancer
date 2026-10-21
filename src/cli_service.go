package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Commands of the service part (people, money, promo codes, pools of servers). They are the same in the terminal of the panel
// and on the command line; see cliHelp for the descriptions.
func runCLIService(ctx context.Context, cfg *Config, st *Store, cmd string, args []string) (bool, error) {
	switch cmd {
	case "users":
		us, err := st.ListUsers(ctx)
		if err != nil {
			return true, err
		}
		for _, u := range us {
			printUser(cfg, u)
		}
		fmt.Printf("всего: %d\n", len(us))
	case "adduser":
		if len(args) < 1 {
			return true, fmt.Errorf("использование: adduser ИМЯ")
		}
		if _, err := st.AddUser(ctx, args[0]); err != nil {
			return true, err
		}
		us, err := st.ListUsers(ctx)
		if err != nil {
			return true, err
		}
		for _, u := range us {
			if u.Name == args[0] {
				fmt.Println(userLink(cfg, cfg.getGatewayName(), u.UUID)) // first line stays the plain vless:// link
				if s := subURL(cfg, u.SubToken); s != "" {
					fmt.Println(s)
					fmt.Println(subURLKind(cfg, u.SubToken, "balancers"))
				}
			}
		}
	case "deluser":
		if len(args) < 1 {
			return true, fmt.Errorf("использование: deluser ИМЯ")
		}
		if err := st.SetUserEnabled(ctx, args[0], false); err != nil {
			return true, err
		}
		fmt.Println("отключён (включить обратно: enableuser ИМЯ)")
	case "rmuser":
		if len(args) < 1 {
			return true, fmt.Errorf("использование: rmuser ИМЯ")
		}
		ok, err := st.DeleteUser(ctx, args[0])
		if err != nil {
			return true, err
		}
		if !ok {
			return true, fmt.Errorf("пользователь %q не найден", args[0])
		}
		fmt.Println("удалён")
	case "version":
		fmt.Println(appVersion)
	case "promo":
		return true, cliPromo(ctx, st, args)
	case "accounts":
		accs, err := st.ListAccounts(ctx)
		if err != nil {
			return true, err
		}
		now := time.Now()
		for _, ac := range accs {
			state, left := periodState(ac.Expires, now)
			if ac.Blocked {
				state = "blocked"
			}
			exp := "без срока"
			if ac.Expires != nil {
				exp = ac.Expires.Format("2006-01-02") + fmt.Sprintf(" (%d дн.)", left)
			}
			fmt.Printf("%-32s %-10s %-24s баланс %s  пользователь %s\n", ac.Email, state, exp, cents(ac.Balance), ac.UserName)
		}
		fmt.Printf("всего: %d\n", len(accs))
	case "balance":
		if len(args) < 2 {
			return true, fmt.Errorf("usage: balance ПОЧТА ±СУММА [пояснение]")
		}
		amount, err := strconv.ParseFloat(strings.ReplaceAll(args[1], ",", "."), 64)
		if err != nil {
			return true, fmt.Errorf("сумма: число, например 100 или -50")
		}
		accs, err := st.ListAccounts(ctx)
		if err != nil {
			return true, err
		}
		for _, ac := range accs {
			if strings.EqualFold(ac.Email, args[0]) {
				_, err := cliCall(ctx, cfg, st, "POST", fmt.Sprintf("/api/accounts/%d/balance", ac.ID), map[string]any{"delta_cents": int64(amount * 100), "note": strings.Join(args[2:], " ")})
				if err == nil {
					fmt.Println("готово")
				}
				return true, err
			}
		}
		return true, fmt.Errorf("аккаунт не найден")
	case "expiry":
		if len(args) != 2 {
			return true, fmt.Errorf("usage: expiry ИМЯ ДНИ|ГГГГ-ММ-ДД|нет  (ДНИ: прибавить, можно отрицательное)")
		}
		body := map[string]any{}
		switch t := strings.ToLower(args[1]); {
		case t == "нет" || t == "unlimited":
			body["unlimited"] = true
		case len(t) == 10 && t[4] == '-':
			body["until"] = t
		default:
			n, err := strconv.Atoi(t)
			if err != nil || n == 0 {
				return true, fmt.Errorf("срок: число дней, дата ГГГГ-ММ-ДД или «нет»")
			}
			body["extend_days"] = n
		}
		if _, err := cliCall(ctx, cfg, st, "POST", "/api/users/"+url.PathEscape(args[0])+"/expiry", body); err != nil {
			return true, err
		}
		fmt.Println("готово")
	case "plans":
		ps, err := st.ListPlans(ctx, false)
		if err != nil {
			return true, err
		}
		for _, p := range ps {
			fmt.Printf("%3d  %-20s %4d дн.  %s %s  %s\n", p.ID, p.Name, p.Days, cents(int64(p.PriceCents)), p.Currency, map[bool]string{true: "включён", false: "выключен"}[p.Enabled])
		}
	case "servers":
		return true, cliServers(ctx, cfg, st, args)
	case "pool":
		return true, cliPool(ctx, cfg, st, args)
	default:
		return false, nil
	}
	return true, nil
}

func cents(c int64) string {
	if c%100 == 0 {
		return strconv.FormatInt(c/100, 10)
	}
	return fmt.Sprintf("%.2f", float64(c)/100)
}

func cliPromo(ctx context.Context, st *Store, args []string) error {
	if len(args) == 0 || args[0] == "list" {
		ps, err := st.ListPromos(ctx)
		if err != nil {
			return err
		}
		for _, p := range ps {
			val := strconv.Itoa(p.Value)
			switch p.Kind {
			case "percent":
				val += "%"
			case "days":
				val += " дн."
			case "balance":
				val = cents(int64(p.Value))
			}
			lim := "без лимита"
			if p.MaxUses > 0 {
				lim = fmt.Sprintf("%d из %d", p.Used, p.MaxUses)
			} else if p.Used > 0 {
				lim = fmt.Sprintf("использован %d", p.Used)
			}
			fmt.Printf("%-16s %-8s %-10s %-18s %s\n", p.Code, p.Kind, val, lim, map[bool]string{true: "действует", false: "выключен"}[p.Enabled])
		}
		fmt.Printf("всего: %d\n", len(ps))
		return nil
	}
	switch args[0] {
	case "add":
		if len(args) < 4 {
			return fmt.Errorf("usage: promo add КОД percent|days|balance ЗНАЧЕНИЕ [лимит] (для balance значение в валюте, например 100)")
		}
		v, err := strconv.ParseFloat(strings.ReplaceAll(args[3], ",", "."), 64)
		if err != nil {
			return fmt.Errorf("значение: число")
		}
		if args[2] == "balance" {
			v *= 100
		}
		max := 0
		if len(args) > 4 {
			if max, err = strconv.Atoi(args[4]); err != nil {
				return fmt.Errorf("лимит: целое число (0 — без лимита)")
			}
		}
		if err := st.SavePromo(ctx, Promo{Code: args[1], Kind: args[2], Value: int(v + 0.5), MaxUses: max, Enabled: true}); err != nil {
			return err
		}
		fmt.Println("сохранён")
	case "on", "off":
		if len(args) < 2 {
			return fmt.Errorf("usage: promo on|off КОД")
		}
		ps, err := st.ListPromos(ctx)
		if err != nil {
			return err
		}
		for _, p := range ps {
			if strings.EqualFold(p.Code, args[1]) {
				p.Enabled = args[0] == "on"
				if err := st.SavePromo(ctx, p); err != nil {
					return err
				}
				fmt.Println("готово")
				return nil
			}
		}
		return fmt.Errorf("промокод не найден")
	case "del":
		if len(args) < 2 {
			return fmt.Errorf("usage: promo del КОД")
		}
		ok, err := st.DeletePromo(ctx, args[1])
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("промокод не найден")
		}
		fmt.Println("удалён")
	default:
		return fmt.Errorf("usage: promo list | add … | on|off КОД | del КОД")
	}
	return nil
}

func cliServers(ctx context.Context, cfg *Config, st *Store, args []string) error {
	if len(args) == 0 || args[0] == "list" {
		list, err := st.ListServers(ctx)
		if err != nil {
			return err
		}
		for _, sv := range list {
			seen := "не подключался"
			if sv.LastSeen != nil {
				seen = "был в сети " + sv.LastSeen.Format("2006-01-02 15:04")
			}
			fmt.Printf("%3d  %-20s %-9s %-9s %s\n", sv.ID, sv.Name, sv.Kind, map[bool]string{true: "включён", false: "выключен"}[sv.Enabled], seen)
		}
		return nil
	}
	switch args[0] {
	case "add":
		if len(args) < 3 || (args[2] != "balancer" && args[2] != "endnode") {
			return fmt.Errorf("usage: servers add ИМЯ balancer|endnode")
		}
		out, err := cliCall(ctx, cfg, st, "POST", "/api/servers", map[string]string{"name": args[1], "kind": args[2]})
		if err != nil {
			return err
		}
		var cmd string
		_ = json.Unmarshal(out["command"], &cmd)
		fmt.Println("создан. Токен показывается один раз; команда для установки:")
		fmt.Println(cmd)
	case "on", "off", "token", "del":
		if len(args) < 2 {
			return fmt.Errorf("usage: servers on|off|token|del НОМЕР")
		}
		method, path := "POST", "/api/servers/"+url.PathEscape(args[1])
		switch args[0] {
		case "on":
			path += "/enable"
		case "off":
			path += "/disable"
		case "token":
			path += "/token"
		case "del":
			method = "DELETE"
		}
		out, err := cliCall(ctx, cfg, st, method, path, nil)
		if err != nil {
			return err
		}
		if args[0] == "token" {
			var cmd string
			_ = json.Unmarshal(out["command"], &cmd)
			fmt.Println(cmd)
			return nil
		}
		fmt.Println("готово")
	default:
		return fmt.Errorf("usage: servers list | add ИМЯ balancer|endnode | on|off|token|del НОМЕР")
	}
	return nil
}

// cliPool edits the sources of nodes of one of the two pools: pool admin|users list | add АДРЕС-ИЛИ-ССЫЛКА | del НОМЕР.
func cliPool(ctx context.Context, cfg *Config, st *Store, args []string) error {
	if len(args) < 1 || (args[0] != "admin" && args[0] != "users") {
		return fmt.Errorf("usage: pool admin|users list | add АДРЕС-ПОДПИСКИ-ИЛИ-ССЫЛКА | del НОМЕР")
	}
	key, list := "subscriptions", cfg.getSubscriptions()
	if args[0] == "users" {
		key, list = "users_subscriptions", cfg.getUsersSubscriptions()
	}
	op := "list"
	if len(args) > 1 {
		op = args[1]
	}
	switch op {
	case "list":
		for i, u := range list {
			kind := "подписка"
			if isServerLink(u) {
				kind = "сервер"
			}
			fmt.Printf("%2d  %-9s %s\n", i+1, kind, trunc(redactShort(u), 70))
		}
		fmt.Printf("всего: %d\n", len(list))
		return nil
	case "add":
		if len(args) < 3 {
			return fmt.Errorf("usage: pool %s add АДРЕС-ПОДПИСКИ-ИЛИ-ССЫЛКА", args[0])
		}
		list = append(list, strings.TrimSpace(strings.Join(args[2:], " ")))
	case "del":
		if len(args) < 3 {
			return fmt.Errorf("usage: pool %s del НОМЕР", args[0])
		}
		n, err := strconv.Atoi(args[2])
		if err != nil || n < 1 || n > len(list) {
			return fmt.Errorf("номер от 1 до %d", len(list))
		}
		list = append(list[:n-1:n-1], list[n:]...)
	default:
		return fmt.Errorf("usage: pool %s list | add … | del НОМЕР", args[0])
	}
	raw, _ := json.Marshal(list)
	if err := putSetting(ctx, cfg, st, key, raw); err != nil {
		return err
	}
	fmt.Println("готово; узлы появятся после ближайшего скачивания подписок (команда refresh)")
	return nil
}
