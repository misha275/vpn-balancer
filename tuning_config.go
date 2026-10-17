package main

import (
	"fmt"
	"net/url"
	"time"
)

// Tuning that used to be only in config.yaml and can be changed while the controller runs (it is read each time it is needed).
// Durations are written in the unit named in the key.

func (c *Config) speedURL() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.SpeedURL }
func (c *Config) subUA() string    { c.mu.RLock(); defer c.mu.RUnlock(); return c.SubUserAgent }
func durSetting(key, help string, unit time.Duration, lo, hi int, set func(*Config, time.Duration), get func(*Config) time.Duration) settingDef {
	return intSetting(key, help, lo, hi, func(c *Config, v int) { set(c, time.Duration(v)*unit) }, func(c *Config) int { return int(get(c) / unit) })
}

func init() {
	settingDefs = append(settingDefs,
		strSetting("sub_user_agent", "как скачиватель подписок представляется провайдеру (User-Agent); некоторые отдают разные списки разным приложениям", 100, nil,
			func(c *Config, v string) {
				if v == "" {
					v = "sing-box"
				}
				c.SubUserAgent = v
			}, func(c *Config) string { return c.SubUserAgent }),
		strSetting("speed_url", "файл, по которому измеряется скорость узлов (http или https, лучше около 5 МБ)", 300,
			func(v string) error {
				u, err := url.Parse(v)
				if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
					return fmt.Errorf("нужен адрес http:// или https://")
				}
				return nil
			},
			func(c *Config, v string) {
				if v != "" {
					c.SpeedURL = v
				}
			}, func(c *Config) string { return c.SpeedURL }),
		durSetting("speed_ttl_minutes", "через сколько минут скорость узла измеряется заново", time.Minute, 5, 10080,
			func(c *Config, d time.Duration) { c.SpeedTTL = d }, func(c *Config) time.Duration { return c.SpeedTTL }),
		durSetting("service_interval_minutes", "как часто, в минутах, все узлы проверяются на открытие сервисов (Telegram, YouTube…)", time.Minute, 5, 10080,
			func(c *Config, d time.Duration) { c.ServiceInterval = d }, func(c *Config) time.Duration { return c.ServiceInterval }),
		durSetting("geo_ttl_minutes", "через сколько минут страна выхода узла определяется заново", time.Minute, 5, 10080,
			func(c *Config, d time.Duration) { c.GeoTTL = d }, func(c *Config) time.Duration { return c.GeoTTL }),
		durSetting("geo_blocked_ttl_minutes", "то же для узла, который выходит в запрещённой стране (проверяется чаще)", time.Minute, 1, 10080,
			func(c *Config, d time.Duration) { c.GeoBlockedTTL = d }, func(c *Config) time.Duration { return c.GeoBlockedTTL }),
		durSetting("node_grace_hours", "сколько часов узел, пропавший из подписки, остаётся в пуле", time.Hour, 1, 8760,
			func(c *Config, d time.Duration) { c.NodeGrace = d }, func(c *Config) time.Duration { return c.NodeGrace }),
		durSetting("spread_interval_seconds", "режим «по трафику»: как часто, в секундах, может меняться его узел (не меньше 10)", time.Second, 10, 86400,
			func(c *Config, d time.Duration) { c.SpreadInterval = d }, func(c *Config) time.Duration { return c.SpreadInterval }),
		durSetting("min_reload_seconds", "не чаще чем раз в столько секунд перезагружать конфигурацию шлюза из-за смены узла", time.Second, 10, 3600,
			func(c *Config, d time.Duration) { c.MinReload = d }, func(c *Config) time.Duration { return c.MinReload }),
		intSetting("tier3_top", "сколько лучших узлов проверяется замером скорости за раз", 1, 100,
			func(c *Config, v int) { c.Tier3Top = v }, func(c *Config) int { return c.Tier3Top }),
		intSetting("tier2_concurrency", "сколько узлов проверяется одновременно (больше — быстрее, но выше нагрузка)", 1, 200,
			func(c *Config, v int) { c.Tier2Concurrency = v }, func(c *Config) int { return c.Tier2Concurrency }),
		intSetting("backup_keep", "сколько автоматических резервных копий хранить", 1, 365,
			func(c *Config, v int) { c.BackupKeep = v }, func(c *Config) int { return c.BackupKeep }),
		boolSetting("backup_telegram", "отправлять зашифрованные копии в чат Telegram (нужны telegram_token и backup_password в config.yaml)",
			func(c *Config, v bool) { c.BackupTelegram = v }, func(c *Config) bool { return c.BackupTelegram }),
	)
}
