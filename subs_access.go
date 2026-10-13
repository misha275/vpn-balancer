package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Subscription keys. The two built-in subscriptions come from the balancer; every bundle of own nodes is "b:<slug>".
const (
	subBalancers = "balancers" // the three balancer links (current, best speed, best ping)
	subAll       = "all"       // balancers + every allowed server of the pool
	bundlePrefix = "b:"
)

var reSlug = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)

// validSubKey checks the shape of a key (the bundle itself may have been deleted since).
func validSubKey(k string) bool {
	return k == subBalancers || k == subAll || (strings.HasPrefix(k, bundlePrefix) && reSlug.MatchString(k[len(bundlePrefix):]))
}

// cleanSubKeys validates and de-duplicates a list of keys, keeping the order.
func cleanSubKeys(in []string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, k := range in {
		k = strings.TrimSpace(k)
		if !validSubKey(k) {
			return nil, fmt.Errorf("неверный ключ подписки %q (нужно balancers, all или b:имя-категории)", k)
		}
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	if len(out) > 100 {
		return nil, fmt.Errorf("слишком много подписок")
	}
	return out, nil
}

// userDefaults are the settings applied to everybody who has no own list: user_default_subs and user_default_days.
func (c *Config) defaultSubs() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.UserDefaultSubs == nil {
		return []string{subBalancers}
	}
	return append([]string(nil), c.UserDefaultSubs...)
}

func (c *Config) defaultDays() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.UserDefaultDays
}

// effectiveSubs is what the user may take: own list, else the list of the plan paid last, else the default.
func effectiveSubs(c *Config, u User) (keys []string, source string) {
	switch {
	case u.Subs != nil:
		return u.Subs, "user"
	case u.PlanSubs != nil:
		return u.PlanSubs, "plan"
	}
	return c.defaultSubs(), "default"
}

func hasSub(keys []string, k string) bool {
	for _, x := range keys {
		if x == k {
			return true
		}
	}
	return false
}

func init() {
	settingDefs = append(settingDefs,
		settingDef{key: "user_default_subs", help: "какие подписки доступны пользователю по умолчанию (balancers, all, b:категория); у тарифа или пользователя может быть свой список",
			parse: func(raw json.RawMessage) (func(*Config), error) {
				var v []string
				if err := json.Unmarshal(raw, &v); err != nil {
					return nil, fmt.Errorf("user_default_subs: нужен список строк")
				}
				v, err := cleanSubKeys(v)
				if err != nil {
					return nil, fmt.Errorf("user_default_subs: %w", err)
				}
				return func(c *Config) { c.UserDefaultSubs = v }, nil
			},
			get: func(c *Config) any {
				if c.UserDefaultSubs == nil {
					return []string{subBalancers}
				}
				return c.UserDefaultSubs
			}},
		settingDef{key: "user_default_days", help: "срок доступа в днях для пользователей, созданных в панели или командой (0 = без срока)",
			parse: func(raw json.RawMessage) (func(*Config), error) {
				var v int
				if err := json.Unmarshal(raw, &v); err != nil || v < 0 || v > 3660 {
					return nil, fmt.Errorf("user_default_days: целое число от 0 до 3660")
				}
				return func(c *Config) { c.UserDefaultDays = v }, nil
			},
			get: func(c *Config) any { return c.UserDefaultDays }},
	)
}
