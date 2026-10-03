package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

const cliHelp = `Команды (внутри контейнера: docker compose exec balancer balancer -c /etc/balancer/config.yaml КОМАНДА):

Состояние
  status                      сводка: текущий узел, число узлов, страны выхода, последние переключения
  nodes [-a] [--dead] [--excluded] [--country XX] [текст]
                              список узлов (по умолчанию допущенные и живые, до 30 штук; -a все)
  node ИМЯ                    подробности об одном узле (имя целиком, часть имени или tag)

Управление
  switch ИМЯ                  закрепить узел вручную (пока он жив и допущен)
  unpin                       снять закрепление, вернуть автоматический выбор
  refresh                     скачать подписки сейчас
  recheck                     заново измерить страну выхода всех узлов

Пользователи
  users                       список пользователей и их ссылки
  adduser ИМЯ                 создать (печатает ссылку на балансировщик и адрес подписки)
  deluser ИМЯ                 отключить
  enableuser ИМЯ              включить обратно
  sub ИМЯ                     показать адрес личной подписки

Настройки (применяются на лету, хранятся в базе)
  get [КЛЮЧ]                  показать текущие настройки (все или одну)
  set КЛЮЧ ЗНАЧЕНИЕ           изменить (ЗНАЧЕНИЕ: JSON или простая строка/число)
  reset КЛЮЧ                  убрать изменение из базы (вернётся значение из config.yaml после перезапуска)
  rules list                  показать правила фильтра
  rules add ДЕЙСТВИЕ ЗАПИСЬ…  добавить правило (direct|block|proxy), например: rules add direct "*.ru" "*.su"
  rules del НОМЕР             удалить правило
  rules move НОМЕР НОВЫЙ      поменять порядок
  rules clear                 удалить все правила
  countries list              запрещённые страны выхода
  countries block XX…         добавить в запрещённые
  countries allow XX…         убрать из запрещённых
  subs list [--show]          подписки (адреса скрыты, --show показать полностью)
  subs add АДРЕС              добавить подписку
  subs del НОМЕР              удалить подписку

Прочее
  token                       токен для веб-панели
  check                       проверить config.yaml
  run                         запустить контроллер (по умолчанию)
  help                        эта справка

Ключи настроек: %s
`

func cliBase(cfg *Config) string {
	host, port, err := net.SplitHostPort(cfg.HTTPListen)
	if err != nil {
		return "http://127.0.0.1:8080"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port)
}

func cliCall(ctx context.Context, cfg *Config, st *Store, method, path string, body any) (map[string]json.RawMessage, error) {
	tok, err := st.AdminToken(ctx)
	if err != nil {
		return nil, err
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequestWithContext(ctx, method, cliBase(cfg)+path, rd)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("контроллер не отвечает на %s (запущен ли он? команда `run`): %v", cliBase(cfg), scrubErr(err))
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var out map[string]json.RawMessage
	_ = json.Unmarshal(data, &out)
	if resp.StatusCode >= 300 {
		var e string
		_ = json.Unmarshal(out["error"], &e)
		if e == "" {
			e = resp.Status
		}
		return nil, fmt.Errorf("%s", e)
	}
	return out, nil
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

type overviewDoc struct {
	Snapshot Snapshot    `json:"snapshot"`
	Switches []SwitchRow `json:"switches"`
	Ready    bool        `json:"ready"`
}

func getOverview(ctx context.Context, cfg *Config, st *Store) (*overviewDoc, error) {
	tok, err := st.AdminToken(ctx)
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", cliBase(cfg)+"/api/overview", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("контроллер не отвечает на %s (запущен ли он? команда `run`): %v", cliBase(cfg), scrubErr(err))
	}
	defer resp.Body.Close()
	var d overviewDoc
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil || resp.StatusCode != 200 {
		return nil, fmt.Errorf("неожиданный ответ контроллера: %s", resp.Status)
	}
	return &d, nil
}

func stateWord(n NodeView) string {
	switch {
	case n.Current:
		return "ТЕКУЩИЙ"
	case n.Pinned:
		return "закреплён"
	case n.ExitCountry != "" && !n.Allowed:
		return "исключён"
	case !n.Allowed:
		return "страна ?"
	case n.Quarantined:
		return "карантин"
	case n.Score <= 0:
		return "не работает"
	}
	return "резерв"
}

func printNodes(nodes []NodeView) {
	tw := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ИМЯ\tВЫХОД\tОЦЕНКА\tЗАДЕРЖКА\tСКОРОСТЬ\tСТАТУС\tTAG")
	for _, n := range nodes {
		cc := n.ExitCountry
		if cc == "" {
			cc = "?"
		}
		speed := "-"
		if n.SpeedKbps > 0 {
			speed = fmt.Sprintf("%d Мбит/с", n.SpeedKbps/1000)
		}
		fmt.Fprintf(tw, "%s\t%s\t%.1f\t%.0f мс\t%s\t%s\t%s\n", trunc(n.Name, 36), cc, n.Score, n.LatencyMS, speed, stateWord(n), n.Tag)
	}
	tw.Flush()
}

// runCLI handles every command except run, adduser, deluser, users and check (see main.go).
// It returns false if the command is unknown.
func runCLI(ctx context.Context, cfg *Config, st *Store, cmd string, args []string) (bool, error) {
	switch cmd {
	case "help", "-h", "--help":
		fmt.Printf(cliHelp, strings.Join(settingKeys(), ", "))
	case "token":
		tok, err := st.AdminToken(ctx)
		if err != nil {
			return true, err
		}
		fmt.Println(tok)
	case "status":
		d, err := getOverview(ctx, cfg, st)
		if err != nil {
			return true, err
		}
		s := d.Snapshot
		alive, excl, unknown := 0, 0, 0
		cc := map[string]int{}
		for _, n := range s.Nodes {
			if n.Score > 0 && n.Allowed {
				alive++
			}
			if !n.Allowed {
				excl++
			}
			if n.ExitCountry == "" {
				unknown++
			} else {
				cc[n.ExitCountry]++
			}
		}
		fmt.Printf("sing-box:        %v\n", map[bool]string{true: "работает", false: "НЕ отвечает"}[d.Ready])
		fmt.Printf("связь сервера:   %v\n", map[bool]string{true: "ОТСУТСТВУЕТ", false: "есть"}[s.NetDown])
		cur := s.Current
		if cur == "" {
			cur = "нет (пользователи отклоняются)"
		}
		fmt.Printf("текущий узел:    %s\n", cur)
		if s.Pinned != "" {
			fmt.Printf("закреплён:       %s\n", s.Pinned)
		}
		fmt.Printf("узлов:           всего %d, допущено и живых %d, исключено по стране %d, страна не определена %d\n", len(s.Nodes), alive, excl, unknown)
		var keys []string
		for k := range cc {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			return cc[keys[i]] > cc[keys[j]] || (cc[keys[i]] == cc[keys[j]] && keys[i] < keys[j])
		})
		var parts []string
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s=%d", k, cc[k]))
		}
		fmt.Printf("страны выхода:   %s\n", strings.Join(parts, " "))
		fmt.Printf("переключений:    %d\n", s.Switches)
		if len(d.Switches) > 0 {
			fmt.Println("последние переключения:")
			for i, r := range d.Switches {
				if i >= 5 {
					break
				}
				fmt.Printf("  %s  %s -> %s (%s)\n", r.TS.Local().Format("02.01 15:04:05"), trunc(r.From, 28), trunc(r.To, 28), r.Reason)
			}
		}
	case "nodes":
		all, dead, excluded, country, search := false, false, false, "", []string{}
		for i := 0; i < len(args); i++ {
			switch args[i] {
			case "-a", "--all":
				all = true
			case "--dead":
				dead = true
			case "--excluded", "--blocked":
				excluded = true
			case "--country":
				if i+1 < len(args) {
					country = strings.ToUpper(args[i+1])
					i++
				}
			default:
				search = append(search, args[i])
			}
		}
		d, err := getOverview(ctx, cfg, st)
		if err != nil {
			return true, err
		}
		q := strings.ToLower(strings.Join(search, " "))
		var rows []NodeView
		for _, n := range d.Snapshot.Nodes {
			switch {
			case q != "" && !strings.Contains(strings.ToLower(n.Name+" "+n.Server), q):
				continue
			case country != "" && n.ExitCountry != country:
				continue
			case dead && n.Score > 0:
				continue
			case excluded && n.Allowed:
				continue
			case !all && !dead && !excluded && country == "" && q == "" && !(n.Allowed && n.Score > 0):
				continue
			}
			rows = append(rows, n)
		}
		total := len(rows)
		if !all && len(rows) > 30 {
			rows = rows[:30]
		}
		printNodes(rows)
		fmt.Printf("показано %d из %d (всего узлов %d)\n", len(rows), total, len(d.Snapshot.Nodes))
	case "node":
		if len(args) < 1 {
			return true, fmt.Errorf("usage: node ИМЯ")
		}
		d, err := getOverview(ctx, cfg, st)
		if err != nil {
			return true, err
		}
		q := strings.ToLower(strings.Join(args, " "))
		var hit []NodeView
		for _, n := range d.Snapshot.Nodes {
			if n.Tag == strings.Join(args, " ") || strings.EqualFold(n.Name, strings.Join(args, " ")) {
				hit = []NodeView{n}
				break
			}
			if strings.Contains(strings.ToLower(n.Name+" "+n.Server), q) {
				hit = append(hit, n)
			}
		}
		if len(hit) == 0 {
			return true, fmt.Errorf("узел не найден")
		}
		if len(hit) > 1 {
			printNodes(hit)
			return true, fmt.Errorf("подходит %d узлов, уточните", len(hit))
		}
		n := hit[0]
		fmt.Printf("имя:        %s\ntag:        %s\nтип:        %s\nадрес:      %s\nвыход:      %s %s\nдопущен:    %v\nстатус:     %s\nоценка:     %.1f\nуспешность: %.0f%%\nзадержка:   %.0f мс (разброс %.0f)\nскорость:   %d кбит/с\n",
			n.Name, n.Tag, n.Type, n.Server, n.ExitCountry, n.ExitIP, n.Allowed, stateWord(n), n.Score, n.SuccessRate*100, n.LatencyMS, n.JitterMS, n.SpeedKbps)
	case "switch":
		if len(args) < 1 {
			return true, fmt.Errorf("usage: switch ИМЯ")
		}
		r, err := cliCall(ctx, cfg, st, "POST", "/api/pin", map[string]string{"node": strings.Join(args, " ")})
		if err != nil {
			return true, err
		}
		var m string
		_ = json.Unmarshal(r["ok"], &m)
		fmt.Println(m)
	case "unpin":
		if _, err := cliCall(ctx, cfg, st, "POST", "/api/pin", map[string]string{"node": ""}); err != nil {
			return true, err
		}
		fmt.Println("закрепление снято, выбор автоматический")
	case "refresh", "recheck":
		r, err := cliCall(ctx, cfg, st, "POST", "/api/"+cmd, map[string]string{})
		if err != nil {
			return true, err
		}
		var m string
		_ = json.Unmarshal(r["ok"], &m)
		fmt.Println(m)
	case "enableuser":
		if len(args) < 1 {
			return true, fmt.Errorf("usage: enableuser ИМЯ")
		}
		if err := st.SetUserEnabled(ctx, args[0], true); err != nil {
			return true, err
		}
		fmt.Println("enabled")
	case "sub":
		if len(args) < 1 {
			return true, fmt.Errorf("usage: sub ИМЯ")
		}
		us, err := st.ListUsers(ctx)
		if err != nil {
			return true, err
		}
		for _, u := range us {
			if u.Name == args[0] {
				if s := subURL(cfg, u.SubToken); s != "" {
					fmt.Println(s)
					return true, nil
				}
				return true, fmt.Errorf("подписки выключены: задайте sub_listen и sub_public_url в config.yaml")
			}
		}
		return true, fmt.Errorf("пользователь не найден")
	case "get":
		eff := cfg.Effective()
		if len(args) > 0 {
			v, ok := eff[args[0]]
			if !ok {
				return true, fmt.Errorf("неизвестная настройка %q (доступны: %s)", args[0], strings.Join(settingKeys(), ", "))
			}
			b, _ := json.MarshalIndent(v, "", "  ")
			fmt.Println(string(b))
			return true, nil
		}
		keys := settingKeys()
		for _, k := range keys {
			b, _ := json.Marshal(eff[k])
			val := string(b)
			if k == "subscriptions" {
				val = fmt.Sprintf("%d шт. (см. subs list)", len(cfg.getSubscriptions()))
			}
			fmt.Printf("%-24s %s\n", k, trunc(val, 90))
		}
	case "set":
		if len(args) < 2 {
			return true, fmt.Errorf("usage: set КЛЮЧ ЗНАЧЕНИЕ")
		}
		return true, putSetting(ctx, cfg, st, args[0], parseCLIValue(strings.Join(args[1:], " ")))
	case "reset":
		if len(args) < 1 || settingDefFor(args[0]) == nil {
			return true, fmt.Errorf("usage: reset КЛЮЧ (доступны: %s)", strings.Join(settingKeys(), ", "))
		}
		if err := st.DeleteSetting(ctx, args[0]); err != nil {
			return true, err
		}
		fmt.Println("сброшено в базе; значение из config.yaml вернётся после перезапуска контроллера")
	case "rules":
		return true, cliRules(ctx, cfg, st, args)
	case "countries":
		return true, cliCountries(ctx, cfg, st, args)
	case "subs":
		return true, cliSubs(ctx, cfg, st, args)
	default:
		return false, nil
	}
	return true, nil
}

// parseCLIValue accepts JSON (true, 1.2, ["a"]) or a bare word.
func parseCLIValue(s string) json.RawMessage {
	s = strings.TrimSpace(s)
	if json.Valid([]byte(s)) {
		return json.RawMessage(s)
	}
	b, _ := json.Marshal(s)
	return b
}

func putSetting(ctx context.Context, cfg *Config, st *Store, key string, raw json.RawMessage) error {
	if err := ValidateSettings(map[string]json.RawMessage{key: raw}); err != nil {
		return err
	}
	if err := st.PutSetting(ctx, key, raw); err != nil {
		return err
	}
	_ = cfg.ApplySettings(map[string]json.RawMessage{key: raw})
	fmt.Println("сохранено; запущенный контроллер применит это в течение 10 секунд")
	return nil
}

func cliRules(ctx context.Context, cfg *Config, st *Store, args []string) error {
	rules := cfg.getRules()
	save := func() error { b, _ := json.Marshal(rules); return putSetting(ctx, cfg, st, "rules", b) }
	num := func(s string) (int, error) {
		var n int
		if _, err := fmt.Sscanf(s, "%d", &n); err != nil || n < 1 || n > len(rules) {
			return 0, fmt.Errorf("номер правила от 1 до %d", len(rules))
		}
		return n - 1, nil
	}
	sub := "list"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "list":
		if len(rules) == 0 {
			fmt.Println("правил нет: весь трафик идёт через балансировщик (" + cfg.getDefaultAction() + ")")
			return nil
		}
		for i, r := range rules {
			fmt.Printf("%d. %-6s %s\n", i+1, r.Action, strings.Join(r.Match, " "))
		}
		fmt.Printf("остальное: %s\n", cfg.getDefaultAction())
	case "add":
		if len(args) < 3 {
			return fmt.Errorf("usage: rules add direct|block|proxy ЗАПИСЬ [ЗАПИСЬ…]")
		}
		rules = append(rules, RuleCfg{Action: strings.ToLower(args[1]), Match: args[2:]})
		return save()
	case "del":
		if len(args) < 2 {
			return fmt.Errorf("usage: rules del НОМЕР")
		}
		i, err := num(args[1])
		if err != nil {
			return err
		}
		rules = append(rules[:i], rules[i+1:]...)
		return save()
	case "move":
		if len(args) < 3 {
			return fmt.Errorf("usage: rules move НОМЕР НОВЫЙ_НОМЕР")
		}
		i, err := num(args[1])
		if err != nil {
			return err
		}
		j, err := num(args[2])
		if err != nil {
			return err
		}
		r := rules[i]
		rules = append(rules[:i], rules[i+1:]...)
		rules = append(rules[:j], append([]RuleCfg{r}, rules[j:]...)...)
		return save()
	case "clear":
		rules = []RuleCfg{}
		return save()
	default:
		return fmt.Errorf("rules list | add | del | move | clear")
	}
	return nil
}

func cliCountries(ctx context.Context, cfg *Config, st *Store, args []string) error {
	cur := cfg.getBlocked()
	sub := "list"
	if len(args) > 0 {
		sub = args[0]
	}
	set := map[string]bool{}
	for _, c := range cur {
		set[c] = true
	}
	switch sub {
	case "list":
		fmt.Printf("запрещённые страны выхода: %s\nизмерение страны выхода: %v\n", strings.Join(cur, " "), cfg.exitCheckOn())
		return nil
	case "block", "allow":
		if len(args) < 2 {
			return fmt.Errorf("usage: countries %s XX [XX…]", sub)
		}
		for _, c := range args[1:] {
			c = strings.ToUpper(strings.TrimSpace(c))
			if !isAlpha2(c) {
				return fmt.Errorf("%q: нужен двухбуквенный код страны", c)
			}
			set[c] = sub == "block"
		}
		var out []string
		for c, on := range set {
			if on {
				out = append(out, c)
			}
		}
		sort.Strings(out)
		if out == nil {
			out = []string{}
		}
		b, _ := json.Marshal(out)
		return putSetting(ctx, cfg, st, "blocked_exit_countries", b)
	}
	return fmt.Errorf("countries list | block XX… | allow XX…")
}

func cliSubs(ctx context.Context, cfg *Config, st *Store, args []string) error {
	subs := cfg.getSubscriptions()
	save := func() error { b, _ := json.Marshal(subs); return putSetting(ctx, cfg, st, "subscriptions", b) }
	sub := "list"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "list":
		show := len(args) > 1 && args[1] == "--show"
		for i, s := range subs {
			if show {
				fmt.Printf("%d. %s\n", i+1, s)
			} else {
				fmt.Printf("%d. %s\n", i+1, redactShort(s))
			}
		}
		if len(subs) == 0 {
			fmt.Println("подписок нет")
		}
	case "add":
		if len(args) < 2 {
			return fmt.Errorf("usage: subs add АДРЕС")
		}
		for _, s := range subs {
			if s == args[1] {
				return fmt.Errorf("такая подписка уже есть")
			}
		}
		subs = append(subs, args[1])
		return save()
	case "del":
		var n int
		if len(args) < 2 {
			return fmt.Errorf("usage: subs del НОМЕР")
		}
		if _, err := fmt.Sscanf(args[1], "%d", &n); err != nil || n < 1 || n > len(subs) {
			return fmt.Errorf("номер подписки от 1 до %d", len(subs))
		}
		subs = append(subs[:n-1], subs[n:]...)
		return save()
	default:
		return fmt.Errorf("subs list [--show] | add АДРЕС | del НОМЕР")
	}
	return nil
}
