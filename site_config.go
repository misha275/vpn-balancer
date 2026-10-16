package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// SiteCfg is a consistent snapshot of the site settings.
type SiteCfg struct {
	Enabled      bool
	Domain       string
	Email        string
	Name         string
	Registration bool
	TrialDays    int
	Payment      string // manual | stub_auto | off
	Support      string
	Staging      bool
	Via443       bool
	Theme        string
	Palette      string
	Accent       string
	ForumImages  bool
	ForumFiles   bool
}

func (c *Config) getSite() SiteCfg {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s := SiteCfg{Enabled: c.SiteEnabled, Domain: c.SiteDomain, Email: c.SiteEmail, Name: c.SiteName, Payment: c.SitePayment,
		Support: c.SiteSupport, Staging: c.SiteACMEStaging, Via443: c.SiteVia443, Registration: true, TrialDays: 3}
	s.Theme, s.Palette, s.Accent = c.SiteTheme, c.SitePalette, c.SiteAccent
	s.ForumImages = c.ForumImages == nil || *c.ForumImages
	s.ForumFiles = c.ForumFiles != nil && *c.ForumFiles
	if c.SiteRegistration != nil {
		s.Registration = *c.SiteRegistration
	}
	if c.SiteTrialDays != nil {
		s.TrialDays = *c.SiteTrialDays
	}
	if s.Name == "" {
		s.Name = "VPN"
	}
	if s.Payment == "" {
		s.Payment = "manual"
	}
	return s
}

func (c *Config) setSiteReady(v bool) {
	c.mu.Lock()
	c.siteReady = v
	c.mu.Unlock()
}

func (c *Config) getSiteReady() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.siteReady
}

var reDomain = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
var reBotToken = regexp.MustCompile(`^[0-9]{3,20}:[A-Za-z0-9_-]{20,80}$`)
var reEmail = regexp.MustCompile(`^[^@\s~]{1,64}@[^@\s~]{1,255}\.[^@\s~]{2,24}$`)

func validDomain(d string) bool { return len(d) <= 253 && reDomain.MatchString(d) }

// siteHTTPSPort is the public port of the site's HTTPS ("" = 443).
func (c *Config) siteHTTPSPort() string {
	_, p, err := net.SplitHostPort(c.SiteHTTPSListen)
	if err != nil || p == "" || p == "443" {
		return ""
	}
	return p
}

// siteBaseURL is the address of the site as users type it ("" while the site has no domain).
func (c *Config) siteBaseURL() string {
	s := c.getSite()
	if !s.Enabled || s.Domain == "" {
		return ""
	}
	if s.Via443 && c.getSiteReady() {
		return "https://" + s.Domain
	}
	if p := c.siteHTTPSPort(); p != "" {
		return "https://" + s.Domain + ":" + p
	}
	return "https://" + s.Domain
}

// subBase is the address links to subscriptions start with: the explicit sub_public_url, else the site.
func (c *Config) subBase() string {
	// the site has a certificate: subscriptions are given over HTTPS from the site, not over the plain-HTTP listener
	if b := c.siteBaseURL(); b != "" && c.getSiteReady() && (c.SubPublicURL == "" || strings.HasPrefix(c.SubPublicURL, "http://")) {
		return b
	}
	if c.SubPublicURL != "" {
		u := strings.TrimRight(c.SubPublicURL, "/")
		// an address with an IP (older installers wrote it) is replaced by the domain
		if c.Domain != "" {
			if pu, err := url.Parse(u); err == nil && net.ParseIP(pu.Hostname()) != nil {
				if p := pu.Port(); p != "" {
					pu.Host = c.Domain + ":" + p
				} else {
					pu.Host = c.Domain
				}
				return pu.String()
			}
		}
		return u
	}
	return c.siteBaseURL()
}

// siteDestHP is where the gateway sends browsers: the HTTPS port of the site as the gateway sees it.
func (c *Config) siteDestHP() (string, int) {
	hp := c.SiteDest
	if hp == "" {
		host := "127.0.0.1"
		if c.Gateway == "external" {
			host = "balancer" // the name of the controller in docker-compose
		}
		_, port, err := net.SplitHostPort(c.SiteHTTPSListen)
		if err != nil || port == "" {
			port = "8443"
		}
		hp = host + ":" + port
	}
	h, p, err := net.SplitHostPort(hp)
	n, _ := strconv.Atoi(p)
	if err != nil || n <= 0 {
		return "balancer", 8443
	}
	return h, n
}

func (c *Config) siteDest() string {
	h, p := c.siteDestHP()
	return net.JoinHostPort(h, strconv.Itoa(p))
}

// realityFront says what the gateway shows to the world on its port: the SNI that clients use, and the site it hands everyone
// else over to. Normally an imitated site (handshake_server); with site_via_reality, once the certificate is in place, our own site:
// browsers then get the real site on port 443, while clients with the key get the VPN.
func (c *Config) realityFront() (sni, host string, port int) {
	s := c.getSite()
	if s.Enabled && s.Via443 && s.Domain != "" && c.getSiteReady() {
		h, p := c.siteDestHP()
		return s.Domain, h, p
	}
	return c.Reality.HandshakeServer, c.Reality.HandshakeServer, c.Reality.HandshakePort
}

func boolSetting(key, help string, set func(*Config, bool), get func(*Config) bool) settingDef {
	return settingDef{key: key, help: help,
		parse: func(raw json.RawMessage) (func(*Config), error) {
			var v bool
			if err := json.Unmarshal(raw, &v); err != nil {
				return nil, fmt.Errorf("%s: нужно true или false", key)
			}
			return func(c *Config) { set(c, v) }, nil
		},
		get: func(c *Config) any { return get(c) }}
}

func strSetting(key, help string, max int, check func(string) error, set func(*Config, string), get func(*Config) string) settingDef {
	return settingDef{key: key, help: help,
		parse: func(raw json.RawMessage) (func(*Config), error) {
			var v string
			if err := json.Unmarshal(raw, &v); err != nil {
				return nil, fmt.Errorf("%s: нужна строка", key)
			}
			v = strings.TrimSpace(v)
			if len([]rune(v)) > max {
				return nil, fmt.Errorf("%s: не длиннее %d символов", key, max)
			}
			if check != nil {
				if err := check(v); err != nil {
					return nil, fmt.Errorf("%s: %w", key, err)
				}
			}
			return func(c *Config) { set(c, v) }, nil
		},
		get: func(c *Config) any { return get(c) }}
}

func init() {
	settingDefs = append(settingDefs,
		boolSetting("site_enabled", "включить сайт для пользователей", func(c *Config, v bool) { c.SiteEnabled = v }, func(c *Config) bool { return c.SiteEnabled }),
		strSetting("site_domain", "домен сайта (для него автоматически выпускается сертификат)", 253,
			func(v string) error {
				v = strings.ToLower(v)
				if v != "" && !validDomain(v) {
					return fmt.Errorf("нужно имя домена без http:// и порта, например vpn.example.com")
				}
				return nil
			}, func(c *Config, v string) { c.SiteDomain = strings.ToLower(v) }, func(c *Config) string { return c.SiteDomain }),
		strSetting("site_email", "почта для Let's Encrypt (предупреждения о сроке)", 120,
			func(v string) error {
				if v != "" && !reEmail.MatchString(v) {
					return fmt.Errorf("это не адрес почты")
				}
				return nil
			}, func(c *Config, v string) { c.SiteEmail = v }, func(c *Config) string { return c.SiteEmail }),
		strSetting("site_name", "название сервиса на сайте", 40,
			func(v string) error {
				if v == "" {
					return fmt.Errorf("не может быть пустым")
				}
				return nil
			}, func(c *Config, v string) { c.SiteName = v }, func(c *Config) string { return c.SiteName }),
		strSetting("site_support", "контакты поддержки в кабинете (текст)", 300, nil, func(c *Config, v string) { c.SiteSupport = v }, func(c *Config) string { return c.SiteSupport }),
		boolSetting("site_registration", "разрешить регистрацию новых пользователей", func(c *Config, v bool) { c.SiteRegistration = &v },
			func(c *Config) bool { return c.SiteRegistration == nil || *c.SiteRegistration }),
		settingDef{key: "site_trial_days", help: "сколько дней бесплатно получает новый аккаунт (0-365)",
			parse: func(raw json.RawMessage) (func(*Config), error) {
				var v int
				if err := json.Unmarshal(raw, &v); err != nil || v < 0 || v > 365 {
					return nil, fmt.Errorf("site_trial_days: целое число от 0 до 365")
				}
				return func(c *Config) { c.SiteTrialDays = &v }, nil
			},
			get: func(c *Config) any {
				if c.SiteTrialDays == nil {
					return 3
				}
				return *c.SiteTrialDays
			}},
		strSetting("site_payment", "оплата: manual (подтверждает админ), stub_auto (тест: оплачено сразу) или off", 20,
			func(v string) error {
				if v != "manual" && v != "stub_auto" && v != "off" {
					return fmt.Errorf("только manual, stub_auto или off")
				}
				return nil
			}, func(c *Config, v string) { c.SitePayment = v }, func(c *Config) string { return c.SitePayment }),
		boolSetting("site_acme_staging", "тестовые сертификаты Let's Encrypt (браузер им не доверяет, зато нет лимитов)", func(c *Config, v bool) { c.SiteACMEStaging = v },
			func(c *Config) bool { return c.SiteACMEStaging }),
		strSetting("site_theme", "тема сайта по умолчанию: auto (как на устройстве), light или dark", 10,
			func(v string) error {
				if !validTheme(v) {
					return fmt.Errorf("только auto, light или dark")
				}
				return nil
			}, func(c *Config, v string) { c.SiteTheme = v }, func(c *Config) string { return c.SiteTheme }),
		strSetting("site_palette", "палитра сайта: blue, green, teal, violet, orange, rose, graphite или custom (цвет в site_accent)", 12,
			func(v string) error {
				if v != "custom" && !validPalette(v) {
					return fmt.Errorf("только blue, green, teal, violet, orange, rose, graphite или custom")
				}
				return nil
			}, func(c *Config, v string) { c.SitePalette = v }, func(c *Config) string { return c.SitePalette }),
		strSetting("site_accent", "свой цвет сайта вида #1a73e8 (для палитры custom)", 7,
			func(v string) error {
				if v != "" && !reHexColor.MatchString(v) {
					return fmt.Errorf("нужен цвет вида #1a73e8")
				}
				return nil
			}, func(c *Config, v string) { c.SiteAccent = v }, func(c *Config) string { return c.SiteAccent }),
		boolSetting("forum_images", "разрешить обычным пользователям прикладывать картинки (до 1 МБ) к сообщениям форума", func(c *Config, v bool) { c.ForumImages = &v },
			func(c *Config) bool { return c.ForumImages == nil || *c.ForumImages }),
		boolSetting("forum_files", "разрешить обычным пользователям прикладывать файлы (до 10 МБ) к сообщениям форума", func(c *Config, v bool) { c.ForumFiles = &v },
			func(c *Config) bool { return c.ForumFiles != nil && *c.ForumFiles }),
		boolSetting("site_via_reality", "открывать сайт и на порту 443 (шлюз передаёт браузеры сайту)", func(c *Config, v bool) { c.SiteVia443 = v },
			func(c *Config) bool { return c.SiteVia443 }),
	)
}
