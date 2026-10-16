package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

func (c *Config) refReward() RefReward {
	c.mu.RLock()
	defer c.mu.RUnlock()
	r := RefReward{Days: 7, Percent: c.RefBonusPercent, InviteeDays: c.RefInviteeDays}
	if c.RefBonusDays != nil {
		r.Days = *c.RefBonusDays
	}
	return r
}

func (c *Config) payWebhookSecret() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.PayWebhookKey
}

func (c *Config) botToken() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.BotToken }

func (c *Config) botAPI() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.BotAPI != "" {
		return strings.TrimRight(c.BotAPI, "/")
	}
	return "https://api.telegram.org"
}

func intSetting(key, help string, lo, hi int, set func(*Config, int), get func(*Config) int) settingDef {
	return settingDef{key: key, help: help,
		parse: func(raw json.RawMessage) (func(*Config), error) {
			var v int
			if err := json.Unmarshal(raw, &v); err != nil || v < lo || v > hi {
				return nil, fmt.Errorf("%s: целое число от %d до %d", key, lo, hi)
			}
			return func(c *Config) { set(c, v) }, nil
		},
		get: func(c *Config) any { return get(c) }}
}

func init() {
	settingDefs = append(settingDefs,
		intSetting("ref_bonus_days", "реферальная программа: сколько дней получает тот, кто пригласил, когда приглашённый впервые оплатил подписку (0 — не давать)", 0, 3650,
			func(c *Config, v int) { c.RefBonusDays = &v }, func(c *Config) int {
				if c.RefBonusDays != nil {
					return *c.RefBonusDays
				}
				return 7
			}),
		intSetting("ref_bonus_percent", "реферальная программа: какой процент от первой оплаты приглашённого зачисляется на баланс пригласившего (0-100)", 0, 100,
			func(c *Config, v int) { c.RefBonusPercent = v }, func(c *Config) int { return c.RefBonusPercent }),
		intSetting("ref_invitee_days", "реферальная программа: сколько дней в подарок получает приглашённый с первой оплатой (0 — не давать)", 0, 3650,
			func(c *Config, v int) { c.RefInviteeDays = v }, func(c *Config) int { return c.RefInviteeDays }),
		strSetting("pay_webhook_secret", "секрет обратного вызова платёжной системы /pay/webhook/{провайдер} (подпись HMAC-SHA256); пусто — вызов выключен", 100, nil,
			func(c *Config, v string) { c.PayWebhookKey = v }, func(c *Config) string { return c.PayWebhookKey }),
		strSetting("bot_token", "токен Telegram-бота (от @BotFather); пусто — бота нет", 100,
			func(v string) error {
				if v != "" && !reBotToken.MatchString(v) {
					return fmt.Errorf("токен выглядит так: 123456:ABC-DEF…")
				}
				return nil
			}, func(c *Config, v string) { c.BotToken = v }, func(c *Config) string { return c.BotToken }),
		strSetting("bot_api_url", "адрес API Telegram (по умолчанию https://api.telegram.org; нужен для прокси)", 200,
			func(v string) error {
				if v != "" && !strings.HasPrefix(v, "http://") && !strings.HasPrefix(v, "https://") {
					return fmt.Errorf("нужен адрес вида https://…")
				}
				return nil
			}, func(c *Config, v string) { c.BotAPI = v }, func(c *Config) string { return c.BotAPI }),
	)
}
