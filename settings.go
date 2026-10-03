package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Settings that can be changed while the controller is running (from the web panel
// or from the command line). They are stored in the database table "settings" and
// override config.yaml; everything else needs a restart.
//
// Readers use the small accessors below, writers go through applySettings, so a
// change is atomic and never seen half-applied.

func (c *Config) getRules() []RuleCfg {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]RuleCfg(nil), c.Rules...)
}
func (c *Config) getDefaultAction() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.DefaultAction
}
func (c *Config) getSubscriptions() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]string(nil), c.Subscriptions...)
}
func (c *Config) getNodeIdentity() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.NodeIdentity }
func (c *Config) getGatewayName() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.GatewayName == "" {
		return "Балансировщик"
	}
	return c.GatewayName
}
func (c *Config) getProbeURLs() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]string(nil), c.ProbeURLs...)
}
func (c *Config) getSwitch() (margin float64, confirm int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.SwitchMargin, c.SwitchConfirm
}
func (c *Config) getBlocked() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]string, 0, len(c.blocked))
	for cc := range c.blocked {
		out = append(out, cc)
	}
	sort.Strings(out)
	return out
}

type settingDef struct {
	key  string
	help string
	// parse validates raw and returns the function that applies it (called under the write lock).
	parse func(raw json.RawMessage) (func(c *Config), error)
	get   func(c *Config) any // called under the read lock
}

func httpURLs(vals []string, name string, min, max int) error {
	if len(vals) < min || len(vals) > max {
		return fmt.Errorf("%s: expected %d to %d addresses, got %d", name, min, max, len(vals))
	}
	for _, v := range vals {
		u, err := url.Parse(strings.TrimSpace(v))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("%s: %q is not an http(s) address", name, redactShort(v))
		}
	}
	return nil
}

// redactShort keeps tokens of subscription URLs out of error messages.
func redactShort(v string) string {
	if u, err := url.Parse(v); err == nil && u.Host != "" {
		return u.Scheme + "://" + u.Host + "/…"
	}
	if len(v) > 12 {
		return v[:12] + "…"
	}
	return v
}

var settingDefs = []settingDef{
	{
		key:  "subscriptions",
		help: "список адресов подписок провайдеров",
		parse: func(raw json.RawMessage) (func(*Config), error) {
			var v []string
			if err := json.Unmarshal(raw, &v); err != nil {
				return nil, fmt.Errorf("subscriptions: нужен список строк")
			}
			for i := range v {
				v[i] = strings.TrimSpace(v[i])
			}
			if err := httpURLs(v, "subscriptions", 0, 100); err != nil {
				return nil, err
			}
			return func(c *Config) { c.Subscriptions = v }, nil
		},
		get: func(c *Config) any { return c.Subscriptions },
	},
	{
		key:  "blocked_exit_countries",
		help: "страны (ISO, 2 буквы), выход в которые запрещён",
		parse: func(raw json.RawMessage) (func(*Config), error) {
			var v []string
			if err := json.Unmarshal(raw, &v); err != nil {
				return nil, fmt.Errorf("blocked_exit_countries: нужен список двухбуквенных кодов")
			}
			m := map[string]bool{}
			var list []string
			for _, cc := range v {
				cc = strings.ToUpper(strings.TrimSpace(cc))
				if !isAlpha2(cc) {
					return nil, fmt.Errorf("blocked_exit_countries: %q не двухбуквенный код страны", cc)
				}
				if !m[cc] {
					m[cc] = true
					list = append(list, cc)
				}
			}
			sort.Strings(list)
			return func(c *Config) { c.blocked, c.BlockedCountries = m, list }, nil
		},
		get: func(c *Config) any {
			out := make([]string, 0, len(c.blocked))
			for cc := range c.blocked {
				out = append(out, cc)
			}
			sort.Strings(out)
			return out
		},
	},
	{
		key:  "exit_check",
		help: "измерять страну выхода узлов (true/false)",
		parse: func(raw json.RawMessage) (func(*Config), error) {
			var v bool
			if err := json.Unmarshal(raw, &v); err != nil {
				return nil, fmt.Errorf("exit_check: нужно true или false")
			}
			return func(c *Config) { c.ExitCheck = &v }, nil
		},
		get: func(c *Config) any { return c.ExitCheck != nil && *c.ExitCheck },
	},
	{
		key:  "rules",
		help: "правила фильтра трафика: [{action: direct|block|proxy, match: [...]}]",
		parse: func(raw json.RawMessage) (func(*Config), error) {
			var v []RuleCfg
			if err := json.Unmarshal(raw, &v); err != nil {
				return nil, fmt.Errorf("rules: нужен список {action, match}")
			}
			for i := range v {
				v[i].Action = strings.ToLower(strings.TrimSpace(v[i].Action))
			}
			if _, err := CompileRules(v, true); err != nil {
				return nil, err
			}
			return func(c *Config) { c.Rules = v }, nil
		},
		get: func(c *Config) any {
			if c.Rules == nil {
				return []RuleCfg{}
			}
			return c.Rules
		},
	},
	{
		key:  "default_action",
		help: "что делать с трафиком без правила: proxy или block",
		parse: func(raw json.RawMessage) (func(*Config), error) {
			var v string
			if err := json.Unmarshal(raw, &v); err != nil {
				return nil, fmt.Errorf("default_action: нужна строка")
			}
			v = strings.ToLower(strings.TrimSpace(v))
			if v != "proxy" && v != "block" {
				return nil, fmt.Errorf("default_action: только proxy или block (прямой выход по умолчанию запрещён)")
			}
			return func(c *Config) { c.DefaultAction = v }, nil
		},
		get: func(c *Config) any { return c.DefaultAction },
	},
	{
		key:  "node_identity",
		help: "endpoint (одинаковые ссылки = один узел) или link (каждая ссылка отдельный узел)",
		parse: func(raw json.RawMessage) (func(*Config), error) {
			var v string
			if err := json.Unmarshal(raw, &v); err != nil {
				return nil, fmt.Errorf("node_identity: нужна строка")
			}
			v = strings.ToLower(strings.TrimSpace(v))
			if v != "endpoint" && v != "link" {
				return nil, fmt.Errorf("node_identity: endpoint или link")
			}
			return func(c *Config) { c.NodeIdentity = v }, nil
		},
		get: func(c *Config) any { return c.NodeIdentity },
	},
	{
		key:  "gateway_name",
		help: "название балансировщика в ссылках и подписке",
		parse: func(raw json.RawMessage) (func(*Config), error) {
			var v string
			if err := json.Unmarshal(raw, &v); err != nil {
				return nil, fmt.Errorf("gateway_name: нужна строка")
			}
			v = strings.TrimSpace(v)
			if v == "" || len([]rune(v)) > 60 {
				return nil, fmt.Errorf("gateway_name: от 1 до 60 символов")
			}
			return func(c *Config) { c.GatewayName = v }, nil
		},
		get: func(c *Config) any { return c.GatewayName },
	},
	{
		key:  "probe_urls",
		help: "сайты для проверки узлов (1-10 адресов)",
		parse: func(raw json.RawMessage) (func(*Config), error) {
			var v []string
			if err := json.Unmarshal(raw, &v); err != nil {
				return nil, fmt.Errorf("probe_urls: нужен список адресов")
			}
			for i := range v {
				v[i] = strings.TrimSpace(v[i])
			}
			if err := httpURLs(v, "probe_urls", 1, 10); err != nil {
				return nil, err
			}
			return func(c *Config) { c.ProbeURLs = v }, nil
		},
		get: func(c *Config) any { return c.ProbeURLs },
	},
	{
		key:  "switch_margin",
		help: "во сколько раз новый узел должен быть лучше текущего (1.0-3.0)",
		parse: func(raw json.RawMessage) (func(*Config), error) {
			var v float64
			if err := json.Unmarshal(raw, &v); err != nil || v < 1 || v > 3 {
				return nil, fmt.Errorf("switch_margin: число от 1.0 до 3.0")
			}
			return func(c *Config) { c.SwitchMargin = v }, nil
		},
		get: func(c *Config) any { return c.SwitchMargin },
	},
	{
		key:  "switch_confirm",
		help: "сколько циклов подряд новый узел должен быть лучше (1-20)",
		parse: func(raw json.RawMessage) (func(*Config), error) {
			var v int
			if err := json.Unmarshal(raw, &v); err != nil || v < 1 || v > 20 {
				return nil, fmt.Errorf("switch_confirm: целое число от 1 до 20")
			}
			return func(c *Config) { c.SwitchConfirm = v }, nil
		},
		get: func(c *Config) any { return c.SwitchConfirm },
	},
}

func settingDefFor(key string) *settingDef {
	for i := range settingDefs {
		if settingDefs[i].key == key {
			return &settingDefs[i]
		}
	}
	return nil
}

func settingKeys() []string {
	var k []string
	for _, d := range settingDefs {
		k = append(k, d.key)
	}
	return k
}

// ValidateSettings checks a set of changes without applying them.
func ValidateSettings(m map[string]json.RawMessage) error {
	for k, raw := range m {
		d := settingDefFor(k)
		if d == nil {
			return fmt.Errorf("неизвестная настройка %q (доступны: %s)", k, strings.Join(settingKeys(), ", "))
		}
		if _, err := d.parse(raw); err != nil {
			return err
		}
	}
	return nil
}

// ApplySettings validates all changes first and then applies them atomically.
func (c *Config) ApplySettings(m map[string]json.RawMessage) error {
	var fns []func(*Config)
	for k, raw := range m {
		d := settingDefFor(k)
		if d == nil {
			return fmt.Errorf("неизвестная настройка %q (доступны: %s)", k, strings.Join(settingKeys(), ", "))
		}
		fn, err := d.parse(raw)
		if err != nil {
			return err
		}
		fns = append(fns, fn)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, fn := range fns {
		fn(c)
	}
	return nil
}

// Effective returns the current value of every editable setting.
func (c *Config) Effective() map[string]any {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := map[string]any{}
	for _, d := range settingDefs {
		out[d.key] = d.get(c)
	}
	return out
}
