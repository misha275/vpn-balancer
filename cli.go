package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
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
  stats                       сервер (процессор, память, диск, сеть) и трафик каждого пользователя: онлайн ли, сколько скачал
  logs [controller|gateway] [-n N]
                              последние строки консоли контроллера (по умолчанию) или шлюза (sing-box), 100 строк
  logs user ИМЯ               ошибки и заблокированные адреса одного пользователя (диагностика)

WireGuard (роутер MikroTik и другие устройства подключаются к балансировщику туннелем)
  wg list                     сервер и пары
  wg add ИМЯ [СЕТЬ…]          новая пара (СЕТЬ - подсеть за роутером, например 192.168.50.0/24)
  wg show ИМЯ                 скрипт для MikroTik (--wgquick: профиль для приложения WireGuard)
  wg on|off|del ИМЯ           включить, отключить, удалить

Управление
  switch ИМЯ                  закрепить узел вручную (пока он жив и допущен)
  unpin                       снять закрепление, вернуть автоматический выбор
  refresh                     скачать подписки сейчас
  recheck                     заново измерить страну выхода всех узлов

Пользователи
  users                       список пользователей и их ссылки
  adduser ИМЯ                 создать (печатает ссылку на балансировщик и адрес подписки)
  deluser ИМЯ                 отключить (можно включить обратно)
  rmuser ИМЯ                  удалить навсегда (ссылка перестаёт работать, статистика стирается)
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
	Gateway  *GWState    `json:"gateway"`
	GWError  string      `json:"gateway_error"`
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
	case n.Quality == "slow":
		return "медленный"
	case strings.HasPrefix(n.Quality, "service:"):
		return n.Quality[8:] + " не открывается"
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
		if n.SpeedAt > 0 {
			speed = fmt.Sprintf("%d Мбит/с (%s)", n.SpeedKbps/1000, time.Unix(n.SpeedAt, 0).Format("02.01 15:04"))
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
	case "stats":
		return true, cliStats(ctx, cfg, st)
	case "logs":
		return true, cliLogs(ctx, cfg, st, args)
	case "wg":
		return true, cliWG(ctx, cfg, st, args)
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
		fmt.Printf("шлюз:            %s\n", gatewayLine(d))
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
		if n.CheckAt > 0 {
			fmt.Printf("проверен:   %s\n", time.Unix(n.CheckAt, 0).Format("02.01.2006 15:04:05"))
		}
		for i := len(n.SpeedHist) - 1; i >= 0; i-- {
			p := n.SpeedHist[i]
			fmt.Printf("замер:      %d кбит/с  %s\n", p.K, time.Unix(p.T, 0).Format("02.01.2006 15:04:05"))
		}
		if n.SpeedErr != "" {
			fmt.Printf("попытка:    %s не удалась: %s\n", time.Unix(n.SpeedTry, 0).Format("02.01 15:04"), n.SpeedErr)
		}
		var names []string
		for k := range n.Services {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			r := n.Services[k]
			if r.OK {
				fmt.Printf("сервис:     %-10s открывается (%d мс)  %s\n", k, r.MS, time.Unix(r.T, 0).Format("02.01 15:04"))
			} else {
				fmt.Printf("сервис:     %-10s НЕ открывается  %s  %s\n", k, time.Unix(r.T, 0).Format("02.01 15:04"), r.Err)
			}
		}
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

// gatewayLine describes the gateway in one line: which instance is live and what still drains.
func gatewayLine(d *overviewDoc) string {
	if d.Gateway == nil {
		if d.GWError != "" {
			return "НЕ отвечает: " + d.GWError
		}
		return "нет данных"
	}
	g := d.Gateway
	if g.Active < 0 {
		return "ждёт первую конфигурацию"
	}
	var live, old int64
	var drain int
	for _, s := range g.Slots {
		if s.Role == "active" {
			live = s.Conns
		} else {
			old += s.Conns
			drain++
		}
	}
	line := fmt.Sprintf("работает, подключений %d, конфигурация с %s", live, g.AppliedAt.Local().Format("02.01 15:04:05"))
	if drain > 0 {
		line += fmt.Sprintf("; ещё доживают %d на прежней конфигурации (%d экз.)", old, drain)
	}
	return line
}

func humanBytes(n int64) string {
	u := []string{"Б", "КБ", "МБ", "ГБ", "ТБ"}
	f, i := float64(n), 0
	for f >= 1024 && i < len(u)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d %s", n, u[0])
	}
	return fmt.Sprintf("%.1f %s", f, u[i])
}

func humanBits(bytesPerSec float64) string {
	b := bytesPerSec * 8
	switch {
	case b < 1000:
		return fmt.Sprintf("%.0f бит/с", b)
	case b < 1e6:
		return fmt.Sprintf("%.0f кбит/с", b/1e3)
	default:
		return fmt.Sprintf("%.1f Мбит/с", b/1e6)
	}
}

func cliStats(ctx context.Context, cfg *Config, st *Store) error {
	out, err := cliCall(ctx, cfg, st, "GET", "/api/stats", nil)
	if err != nil {
		return err
	}
	var sys SysSample
	var static sysStatic
	var users, other []UserStat
	var gwErr string
	var inv []InvalidInfo
	_ = json.Unmarshal(out["sys"], &sys)
	_ = json.Unmarshal(out["static"], &static)
	_ = json.Unmarshal(out["users"], &users)
	_ = json.Unmarshal(out["other"], &other)
	_ = json.Unmarshal(out["gateway_error"], &gwErr)
	_ = json.Unmarshal(out["invalid"], &inv)
	fmt.Printf("процессор:  %.0f %% (%d яд.), нагрузка %.2f\n", sys.CPU, static.CPUs, sys.Load1)
	fmt.Printf("память:     %s из %s (%.0f %%)\n", humanBytes(int64(sys.MemUsed)), humanBytes(int64(sys.MemTotal)), sys.Mem)
	fmt.Printf("диск:       %s из %s (%.0f %%)\n", humanBytes(int64(sys.DiskUsed)), humanBytes(int64(sys.DiskTotal)), sys.Disk)
	fmt.Printf("сеть:       ↓ %s  ↑ %s, подключений %d, пользователей онлайн %d\n", humanBits(sys.Down), humanBits(sys.Up), sys.Conns, sys.Users)
	if gwErr != "" {
		fmt.Printf("ШЛЮЗ НЕ ОТДАЁТ СТАТИСТИКУ: %s\n", gwErr)
	}
	fmt.Println()
	fmt.Printf("%-18s %-10s %-26s %-22s %-22s %-22s %s\n", "ПОЛЬЗОВАТЕЛЬ", "СТАТУС", "СЕЙЧАС", "24 ЧАСА ↓/↑", "7 ДНЕЙ ↓/↑", "ВСЕГО ↓/↑", "БЫЛ В СЕТИ")
	for _, u := range users {
		state := "не в сети"
		if u.Active {
			state = "передаёт"
		} else if u.Online {
			state = "онлайн"
		}
		name := u.Name
		if !u.Enabled {
			name += " (откл.)"
		}
		now := "—"
		if u.Online || u.UpBps+u.DownBps > 0 {
			now = fmt.Sprintf("↓%s ↑%s", humanBits(float64(u.DownBps)), humanBits(float64(u.UpBps)))
		}
		seen := "никогда"
		if u.LastSeen != nil {
			if d := time.Since(time.Unix(*u.LastSeen, 0)); d < 15*time.Second {
				seen = "сейчас"
			} else {
				seen = time.Unix(*u.LastSeen, 0).Format("02.01 15:04")
			}
		}
		fmt.Printf("%-18s %-10s %-26s %-22s %-22s %-22s %s\n", trunc(name, 18), state, now,
			humanBytes(u.H24Down)+" / "+humanBytes(u.H24Up), humanBytes(u.D7Down)+" / "+humanBytes(u.D7Up), humanBytes(u.AllDown)+" / "+humanBytes(u.AllUp), seen)
	}
	for _, u := range other {
		fmt.Printf("%-18s %s: %d подкл., всего ↓ %s ↑ %s\n", "", u.Label, u.AllConns, humanBytes(u.AllDown), humanBytes(u.AllUp))
	}
	if len(inv) > 0 {
		fmt.Println("\nчаще всего не проходят проверку Reality:")
		for i, v := range inv {
			if i == 5 {
				break
			}
			fmt.Printf("  %-18s %d раз, последний %s\n", v.IP, v.Count, v.Last.Local().Format("02.01 15:04:05"))
		}
		fmt.Println("  (неверные ключи/short id/отпечаток в клиенте или сканеры; для свежих клиентов Xray поставьте fp=ios)")
	}
	return nil
}

func cliLogs(ctx context.Context, cfg *Config, st *Store, args []string) error {
	src, n, user := "controller", 100, ""
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "user":
			if i+1 >= len(args) {
				return fmt.Errorf("использование: logs user ИМЯ [-n N]")
			}
			i++
			src, user = "user", args[i]
		case "-n":
			if i+1 < len(args) {
				i++
				if v, err := strconv.Atoi(args[i]); err == nil && v > 0 {
					n = v
				}
			}
		case "controller", "gateway":
			src = args[i]
		default:
			return fmt.Errorf("использование: logs [controller|gateway|user ИМЯ] [-n N]")
		}
	}
	out, err := cliCall(ctx, cfg, st, "GET", fmt.Sprintf("/api/logs?src=%s&limit=%d&user=%s", src, n, url.QueryEscape(user)), nil)
	if err != nil {
		return err
	}
	var lines []LogLine
	_ = json.Unmarshal(out["lines"], &lines)
	for _, l := range lines {
		fmt.Println(l.Text)
	}
	if len(lines) == 0 {
		fmt.Println("(пока пусто)")
	}
	return nil
}
