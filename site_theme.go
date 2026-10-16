package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Look of the public site: a theme (light, dark, follow the device) and a colour palette. The administrator sets the default
// in the panel, every visitor can choose their own (two small cookies; the page needs no script for that).

type palette struct{ ID, Title, Light, Dark string }

var sitePalettes = []palette{
	{"blue", "Синяя", "#2563eb", "#6ea0ff"},
	{"green", "Зелёная", "#15803d", "#4ade80"},
	{"teal", "Бирюзовая", "#0f766e", "#2dd4bf"},
	{"violet", "Фиолетовая", "#7c3aed", "#a78bfa"},
	{"orange", "Оранжевая", "#c2410c", "#fb923c"},
	{"rose", "Розовая", "#e11d48", "#fb7185"},
	{"graphite", "Графит", "#374151", "#cbd5e1"},
}

var siteThemes = []struct{ ID, Title, Icon string }{{"auto", "Как на устройстве", "◐"}, {"light", "Светлая", "☀"}, {"dark", "Тёмная", "☾"}}

const (
	cookieTheme   = "vtheme"
	cookiePalette = "vpal"
)

var reHexColor = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

func validTheme(t string) bool {
	for _, x := range siteThemes {
		if x.ID == t {
			return true
		}
	}
	return false
}

func validPalette(p string) bool {
	for _, x := range sitePalettes {
		if x.ID == p {
			return true
		}
	}
	return false
}

// onColor is the text colour on an accent background: white on dark colours, near-black on light ones.
func onColor(hex string) string {
	if !reHexColor.MatchString(hex) {
		return "#ffffff"
	}
	r, _ := strconv.ParseInt(hex[1:3], 16, 32)
	g, _ := strconv.ParseInt(hex[3:5], 16, 32)
	b, _ := strconv.ParseInt(hex[5:7], 16, 32)
	if (299*r+587*g+114*b)/1000 > 150 {
		return "#0b0f14"
	}
	return "#ffffff"
}

// sitePrefs is what the visitor sees: his own choice when he made one, else the default of the administrator.
type sitePrefs struct {
	Theme, Palette string
	AccentStyle    string // inline style of <html> for a custom accent colour
}

func (s *Site) prefsOf(r *http.Request) sitePrefs {
	sc := s.cfg.getSite()
	p := sitePrefs{Theme: sc.Theme, Palette: sc.Palette}
	if p.Theme == "" || !validTheme(p.Theme) {
		p.Theme = "auto"
	}
	if p.Palette == "" || (p.Palette != "custom" && !validPalette(p.Palette)) {
		p.Palette = "blue"
	}
	if c, err := r.Cookie(cookieTheme); err == nil && validTheme(c.Value) {
		p.Theme = c.Value
	}
	if c, err := r.Cookie(cookiePalette); err == nil && validPalette(c.Value) {
		p.Palette = c.Value
	}
	if p.Palette == "custom" {
		if reHexColor.MatchString(sc.Accent) {
			p.AccentStyle = "--accent:" + sc.Accent + ";--on-accent:" + onColor(sc.Accent)
		} else {
			p.Palette = "blue"
		}
	}
	return p
}

// prefsPage stores the choice of a visitor and sends him back (only to a path of this site).
func (s *Site) prefsPage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	set := func(name, v string) {
		http.SetCookie(w, &http.Cookie{Name: name, Value: v, Path: "/", MaxAge: int(365 * 24 * time.Hour / time.Second), SameSite: http.SameSiteLaxMode, Secure: isTLS(r)})
	}
	if t := q.Get("theme"); t != "" && validTheme(t) {
		set(cookieTheme, t)
	}
	if p := q.Get("palette"); p != "" && validPalette(p) {
		set(cookiePalette, p)
	}
	if q.Get("reset") == "1" {
		for _, n := range []string{cookieTheme, cookiePalette} {
			http.SetCookie(w, &http.Cookie{Name: n, Value: "", Path: "/", MaxAge: -1})
		}
	}
	back := q.Get("back")
	if u, err := url.Parse(back); err != nil || !strings.HasPrefix(back, "/") || strings.HasPrefix(back, "//") || strings.Contains(back, "\\") || u.Host != "" {
		back = "/"
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// ---- CSS ----

const lightTokens = `--bg:#f5f7fb;--bg2:#e9eefb;--card:#ffffff;--text:#15202b;--muted:#64748b;--line:#e2e8f0;--chip:#eef2f7;--ok:#15803d;--warn:#b45309;--bad:#b91c1c;--shadow:0 1px 2px rgba(15,23,42,.05),0 8px 24px rgba(15,23,42,.06);--on-accent:#ffffff;`
const darkTokens = `--bg:#0d1117;--bg2:#131a24;--card:#161b22;--text:#e6edf3;--muted:#8b98a8;--line:#2a323d;--chip:#222a35;--ok:#4ade80;--warn:#fbbf24;--bad:#f87171;--shadow:0 1px 2px rgba(0,0,0,.4),0 8px 24px rgba(0,0,0,.35);--on-accent:#0b0f14;`

func buildSiteCSS() string {
	var b strings.Builder
	b.WriteString(":root{" + lightTokens + "--accent:" + sitePalettes[0].Light + "}\n")
	for _, p := range sitePalettes {
		fmt.Fprintf(&b, "html[data-palette=%s]{--accent:%s}\n", p.ID, p.Light)
	}
	b.WriteString("html[data-theme=dark]{" + darkTokens + "}\n")
	for _, p := range sitePalettes {
		fmt.Fprintf(&b, "html[data-theme=dark][data-palette=%s]{--accent:%s}\n", p.ID, p.Dark)
	}
	b.WriteString("@media (prefers-color-scheme:dark){html[data-theme=auto]{" + darkTokens + "}\n")
	for _, p := range sitePalettes {
		fmt.Fprintf(&b, "html[data-theme=auto][data-palette=%s]{--accent:%s}\n", p.ID, p.Dark)
	}
	b.WriteString("}\n")
	b.WriteString(siteCSSBase)
	return b.String()
}

const siteCSSBase = `
*{box-sizing:border-box}
html{color-scheme:light dark}html[data-theme=light]{color-scheme:light}html[data-theme=dark]{color-scheme:dark}
body{margin:0;background:var(--bg);background-image:radial-gradient(1200px 500px at 50% -200px,var(--bg2),transparent);background-repeat:no-repeat;color:var(--text);font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",sans-serif;-webkit-font-smoothing:antialiased}
a{color:var(--accent);text-decoration-thickness:1px;text-underline-offset:2px}
header{position:sticky;top:0;z-index:5;background:color-mix(in srgb,var(--card) 82%,transparent);backdrop-filter:saturate(1.4) blur(10px);-webkit-backdrop-filter:saturate(1.4) blur(10px);border-bottom:1px solid var(--line)}
.bar{max-width:960px;margin:0 auto;padding:10px 18px;display:flex;gap:6px 16px;align-items:center;flex-wrap:wrap}
.bar .name{font-weight:750;font-size:19px;letter-spacing:-.01em;margin-right:auto;text-decoration:none;color:var(--text);display:flex;align-items:center;gap:9px}
.bar .name::before{content:"";width:22px;height:22px;border-radius:7px;background:linear-gradient(135deg,var(--accent),color-mix(in srgb,var(--accent) 45%,#fff));box-shadow:0 2px 8px color-mix(in srgb,var(--accent) 45%,transparent)}
.bar a:not(.name):not(.btn){text-decoration:none;color:var(--muted);padding:6px 4px;font-size:15px}.bar a:not(.name):not(.btn):hover{color:var(--text)}
main{max-width:960px;margin:0 auto;padding:26px 18px 56px}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:20px 22px;margin-bottom:16px;box-shadow:var(--shadow)}
h1{font-size:28px;line-height:1.2;letter-spacing:-.02em;margin:4px 0 14px}h2{font-size:19px;letter-spacing:-.01em;margin:0 0 10px}h3{font-size:16px;margin:16px 0 6px}
.muted{color:var(--muted)}.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}
.big{font-size:24px;font-weight:750;letter-spacing:-.01em}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:16px}.grid>.card{margin-bottom:0}
label{display:block;margin:14px 0 5px;font-size:14px;color:var(--muted)}
input[type=text],input[type=email],input[type=password],select,textarea{width:100%;padding:11px 13px;border:1px solid var(--line);border-radius:11px;background:var(--bg);color:var(--text);font:inherit;transition:border-color .15s,box-shadow .15s}
input:focus,select:focus,textarea:focus{outline:0;border-color:var(--accent);box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 22%,transparent)}
input[type=file]{width:100%;padding:9px;border:1px dashed var(--line);border-radius:11px;background:var(--bg);color:var(--muted);font:inherit;font-size:14px}
.btn{display:inline-flex;align-items:center;gap:6px;background:var(--accent);color:var(--on-accent);border:0;border-radius:11px;padding:10px 20px;font:inherit;font-weight:600;cursor:pointer;text-decoration:none;transition:filter .15s,transform .05s}
.btn:hover{filter:brightness(1.08)}.btn:active{transform:translateY(1px)}
.btn.s{background:var(--chip);color:var(--text);font-weight:500}.btn.sm{padding:6px 13px;font-size:14px}
.err,.note,.okbox{padding:11px 15px;border-radius:12px;margin-bottom:14px;border:1px solid}
.err{background:color-mix(in srgb,var(--bad) 11%,transparent);border-color:color-mix(in srgb,var(--bad) 55%,transparent);color:var(--bad)}
.note{background:color-mix(in srgb,var(--warn) 11%,transparent);border-color:color-mix(in srgb,var(--warn) 55%,transparent);color:var(--warn)}
.okbox{background:color-mix(in srgb,var(--ok) 11%,transparent);border-color:color-mix(in srgb,var(--ok) 55%,transparent);color:var(--ok)}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:6px 0}.row input[readonly]{flex:1;min-width:200px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}
table{width:100%;border-collapse:collapse}td,th{padding:9px 6px;border-bottom:1px solid var(--line);text-align:left;font-size:14px}tr:last-child td{border-bottom:0}
details{margin:4px 0}summary{cursor:pointer;color:var(--accent);font-size:14px}details img{display:block;margin:10px 0;background:#fff;padding:8px;border-radius:12px;width:240px;height:240px;image-rendering:pixelated}
.plan{display:flex;flex-direction:column;gap:6px}.price{font-size:26px;font-weight:750;letter-spacing:-.02em}
.hero{padding:34px 28px;border-radius:22px;border:1px solid var(--line);background:linear-gradient(135deg,color-mix(in srgb,var(--accent) 16%,var(--card)),var(--card) 70%);box-shadow:var(--shadow);margin-bottom:22px}
.hero h1{font-size:34px;margin:0 0 10px}.hero p{font-size:17px;max-width:560px;margin:0 0 18px;color:var(--muted)}
.feat{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin:0 0 22px}.feat div{padding:14px 16px;border:1px solid var(--line);border-radius:14px;background:var(--card)}.feat b{display:block;margin-bottom:2px}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600;background:var(--chip);color:var(--muted)}
.badge.acc{background:color-mix(in srgb,var(--accent) 16%,transparent);color:var(--accent)}
footer{max-width:960px;margin:0 auto;padding:0 18px 34px;color:var(--muted);font-size:14px;display:flex;gap:6px 18px;flex-wrap:wrap}footer a{color:var(--muted)}
.prefs{position:relative}.prefs summary{list-style:none;color:var(--muted);padding:6px 4px}.prefs summary::-webkit-details-marker{display:none}
.prefs .pop{position:absolute;right:0;top:34px;min-width:230px;background:var(--card);border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow);padding:12px 14px;z-index:9}
.pop .lbl{font-size:12px;color:var(--muted);margin:8px 0 4px}.pop .opts{display:flex;gap:6px;flex-wrap:wrap}
.pop .opts a{padding:4px 10px;border:1px solid var(--line);border-radius:999px;font-size:13px;text-decoration:none;color:var(--text)}.pop .opts a.on{border-color:var(--accent);background:color-mix(in srgb,var(--accent) 14%,transparent)}
.pop .dot{display:inline-block;width:11px;height:11px;border-radius:50%;margin-right:5px;vertical-align:-1px}
.topic{display:flex;gap:12px;justify-content:space-between;align-items:flex-start;padding:12px 4px;border-bottom:1px solid var(--line)}.topic:last-child{border-bottom:0}
.topic a.t{font-weight:600;text-decoration:none;color:var(--text)}.topic a.t:hover{color:var(--accent)}
.post{border:1px solid var(--line);border-radius:14px;padding:14px 16px;margin-bottom:12px;background:var(--card)}.post.staff{border-color:var(--accent);background:color-mix(in srgb,var(--accent) 6%,var(--card))}
.post .who{font-size:13px;color:var(--muted);margin-bottom:6px}.post .body{white-space:pre-wrap;word-break:break-word}
.att{display:flex;gap:10px;flex-wrap:wrap;margin-top:10px}.att img{max-width:100%;max-height:420px;border-radius:12px;border:1px solid var(--line);display:block}
.file{display:inline-flex;gap:8px;align-items:center;padding:7px 12px;border:1px solid var(--line);border-radius:11px;text-decoration:none;color:var(--text);background:var(--chip);font-size:14px}
.prose{line-height:1.65}.prose h2{margin-top:22px}.prose code{background:var(--chip);padding:1px 6px;border-radius:6px;font-size:.92em}.prose ul,.prose ol{padding-left:22px}.prose li{margin:3px 0}
.helpgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px}.helpgrid a.card{text-decoration:none;color:var(--text);transition:border-color .15s,transform .1s}.helpgrid a.card:hover{border-color:var(--accent);transform:translateY(-1px)}
@media (max-width:560px){main{padding:18px 14px 44px}.card{padding:16px}.hero{padding:24px 18px}.hero h1{font-size:27px}h1{font-size:24px}}
`

var siteCSS = buildSiteCSS()
var siteCSSVer = func() string { h := sha256.Sum256([]byte(siteCSS)); return hex.EncodeToString(h[:4]) }()
