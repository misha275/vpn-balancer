package main

import (
	"fmt"
	"html/template"
	"strings"
	"time"
)

// The pages of the public site. Plain HTML with a little CSS; the only script copies a link to the clipboard (it carries a nonce).

const siteCSS = `
:root{--bg:#f4f6f9;--card:#fff;--text:#18202a;--muted:#667383;--line:#e1e5ea;--accent:#2563eb;--ok:#15803d;--warn:#b45309;--bad:#b91c1c;--chip:#eef1f5}
@media (prefers-color-scheme:dark){:root{--bg:#0e1216;--card:#171c22;--text:#e7eaee;--muted:#8d97a3;--line:#2a313a;--accent:#6ea0ff;--ok:#4ade80;--warn:#fbbf24;--bad:#f87171;--chip:#222a33}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
a{color:var(--accent)}header{background:var(--card);border-bottom:1px solid var(--line)}
.bar{max-width:880px;margin:0 auto;padding:12px 18px;display:flex;gap:14px;align-items:center;flex-wrap:wrap}
.bar .name{font-weight:700;font-size:18px;margin-right:auto;text-decoration:none;color:var(--text)}
main{max-width:880px;margin:0 auto;padding:22px 18px 60px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px 20px;margin-bottom:16px}
h1{font-size:26px;margin:6px 0 14px}h2{font-size:18px;margin:0 0 10px}
.muted{color:var(--muted)}.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}
.big{font-size:22px;font-weight:700}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px}
label{display:block;margin:12px 0 4px;font-size:14px;color:var(--muted)}
input[type=text],input[type=email],input[type=password]{width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:10px;background:var(--bg);color:var(--text);font:inherit}
.btn{display:inline-block;background:var(--accent);color:#fff;border:0;border-radius:10px;padding:10px 18px;font:inherit;cursor:pointer;text-decoration:none}
.btn.s{background:var(--chip);color:var(--text)}.btn.sm{padding:6px 12px;font-size:14px}
.err{background:color-mix(in srgb,var(--bad) 12%,transparent);border:1px solid var(--bad);color:var(--bad);padding:10px 14px;border-radius:10px;margin-bottom:14px}
.note{background:color-mix(in srgb,var(--warn) 12%,transparent);border:1px solid var(--warn);color:var(--warn);padding:10px 14px;border-radius:10px;margin-bottom:14px}
.okbox{background:color-mix(in srgb,var(--ok) 12%,transparent);border:1px solid var(--ok);color:var(--ok);padding:10px 14px;border-radius:10px;margin-bottom:14px}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:6px 0}.row input{flex:1;min-width:200px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}
table{width:100%;border-collapse:collapse}td,th{padding:7px 6px;border-bottom:1px solid var(--line);text-align:left;font-size:14px}
details{margin:4px 0}summary{cursor:pointer;color:var(--accent);font-size:14px}details img{display:block;margin:10px 0;background:#fff;padding:8px;border-radius:10px;width:240px;height:240px;image-rendering:pixelated}
.plan{display:flex;flex-direction:column;gap:6px}.price{font-size:24px;font-weight:700}
footer{max-width:880px;margin:0 auto;padding:0 18px 30px;color:var(--muted);font-size:14px}
`

const siteTplText = `
{{define "head"}}<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>{{.Title}} · {{.Site}}</title><style>` + siteCSS + `</style></head><body>
<header><div class="bar"><a class="name" href="/">{{.Site}}</a>
{{if .Email}}<a href="/cabinet">Кабинет</a><form method="post" action="/logout" style="margin:0"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="btn s sm">Выйти</button></form>
{{else}}<a href="/login">Войти</a>{{if .CanRegister}}<a class="btn sm" href="/register">Регистрация</a>{{end}}{{end}}</div></header><main>{{end}}
{{define "foot"}}</main>{{if .Support}}<footer>{{.Support}}</footer>{{end}}
<script nonce="{{.Nonce}}">document.addEventListener("click",function(e){var b=e.target.closest("[data-copy]");if(!b)return;var t=document.getElementById(b.dataset.copy).value;
(navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject()).then(function(){b.textContent="Скопировано"},function(){var i=document.getElementById(b.dataset.copy);i.select();document.execCommand&&document.execCommand("copy");b.textContent="Скопировано"});});</script>
</body></html>{{end}}

{{define "home"}}{{template "head" .}}
<div class="card"><h1>{{.Site}}</h1><p>Быстрый и стабильный VPN. Зарегистрируйтесь, получите ссылку на подписку и подключите её в приложении за минуту.</p>
{{if .Email}}<a class="btn" href="/cabinet">Открыть кабинет</a>{{else}}{{if .CanRegister}}<a class="btn" href="/register">Зарегистрироваться{{if .Trial}} (бесплатно {{.Trial}}){{end}}</a> {{end}}<a class="btn s" href="/login">Войти</a>{{end}}</div>
{{if .Plans}}<h2>Тарифы</h2><div class="grid">{{range .Plans}}<div class="card plan"><div>{{.Name}}</div><div class="price">{{.Price}}</div><div class="muted">{{.Days}} дн.</div></div>{{end}}</div>{{end}}
{{template "foot" .}}{{end}}

{{define "login"}}{{template "head" .}}
<div class="card" style="max-width:420px;margin:0 auto"><h1>Вход</h1>
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}
<form method="post" action="/login"><label for="email">Почта</label><input id="email" type="email" name="email" value="{{.FormEmail}}" required autocomplete="username" maxlength="120">
<label for="pw">Пароль</label><input id="pw" type="password" name="password" required autocomplete="current-password" maxlength="72">
<p><button class="btn">Войти</button></p></form>
{{if .CanRegister}}<p class="muted">Нет аккаунта? <a href="/register">Регистрация</a></p>{{end}}</div>
{{template "foot" .}}{{end}}

{{define "register"}}{{template "head" .}}
<div class="card" style="max-width:420px;margin:0 auto"><h1>Регистрация</h1>
{{if .Trial}}<p class="muted">После регистрации {{.Trial}} бесплатно.</p>{{end}}
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}
<form method="post" action="/register"><label for="email">Почта</label><input id="email" type="email" name="email" value="{{.FormEmail}}" required autocomplete="username" maxlength="120">
<label for="pw">Пароль (от 8 символов)</label><input id="pw" type="password" name="password" required minlength="8" maxlength="72" autocomplete="new-password">
<label for="pw2">Пароль ещё раз</label><input id="pw2" type="password" name="password2" required minlength="8" maxlength="72" autocomplete="new-password">
<p><button class="btn">Создать аккаунт</button></p></form>
<p class="muted">Уже есть аккаунт? <a href="/login">Войти</a></p></div>
{{template "foot" .}}{{end}}

{{define "closed"}}{{template "head" .}}<div class="card"><h1>Регистрация закрыта</h1><p>Сейчас новые аккаунты не создаются.</p><a class="btn s" href="/login">Войти</a></div>{{template "foot" .}}{{end}}

{{define "cabinet"}}{{template "head" .}}
{{if .Flash}}<div class="okbox">{{.Flash}}</div>{{end}}{{if .Error}}<div class="err">{{.Error}}</div>{{end}}
<div class="grid">
<div class="card"><div class="muted">Подписка</div>
{{if eq .State "active"}}<div class="big ok">Активна</div><div>до {{.Until}}</div><div class="{{if le .DaysLeft 3}}warn{{else}}muted{{end}}">осталось {{.DaysLeft}} {{.DaysWord}}</div>
{{else if eq .State "unlimited"}}<div class="big ok">Без срока</div><div class="muted">ограничения по времени нет</div>
{{else}}<div class="big bad">Закончилась</div><div class="muted">{{.Until}}</div>{{end}}
{{if ne .Payment "off"}}<p><a class="btn sm" href="/pay">{{if eq .State "active"}}Продлить{{else}}Оплатить{{end}}</a></p>{{else if .Support}}<p class="muted">Чтобы продлить, свяжитесь с поддержкой.</p>{{end}}</div>
<div class="card"><div class="muted">Использовано трафика</div><div class="big">{{.TrafficAll}}</div>
<div class="muted">за 30 дней: {{.Traffic30}}</div><div class="muted">↑ {{.UpAll}} · ↓ {{.DownAll}}</div></div>
<div class="card"><div class="muted">Аккаунт</div><div class="big" style="font-size:17px;word-break:break-all">{{.Email}}</div><div class="muted">создан {{.Created}}</div></div>
</div>

<div class="card"><h2>Подключение</h2>
<p class="muted">Установите приложение с поддержкой VLESS и Reality (например v2rayNG, Hiddify, Streisand, Shadowrocket), добавьте подписку по ссылке или QR-коду и обновите её. Ссылки личные, не передавайте их другим.</p>
{{range .Links}}<div class="row"><b style="min-width:230px">{{.Title}}</b></div>
<div class="row"><input id="l-{{.Kind}}" readonly value="{{.URL}}" aria-label="{{.Title}}"><button class="btn s sm" type="button" data-copy="l-{{.Kind}}">Копировать</button></div>
<details><summary>QR-код</summary><img loading="lazy" alt="QR-код: {{.Title}}" src="/qr/{{.Kind}}" width="240" height="240"></details>{{end}}
{{if .Hint}}<p class="muted">{{.Hint}}</p>{{end}}</div>

{{if .Payments}}<div class="card"><h2>Платежи</h2><table><tr><th>Дата</th><th>Тариф</th><th>Сумма</th><th>Статус</th></tr>
{{range .Payments}}<tr><td>{{.Date}}</td><td>{{.Plan}}</td><td>{{.Amount}}</td><td class="{{.Class}}">{{.Status}}</td></tr>{{end}}</table></div>{{end}}

<div class="card"><h2>Смена пароля</h2><form method="post" action="/account/password"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label for="old">Текущий пароль</label><input id="old" type="password" name="old" required autocomplete="current-password" maxlength="72">
<label for="new">Новый пароль (от 8 символов)</label><input id="new" type="password" name="new" required minlength="8" maxlength="72" autocomplete="new-password">
<p><button class="btn s">Сменить пароль</button></p></form></div>
{{template "foot" .}}{{end}}

{{define "pay"}}{{template "head" .}}
<h1>Оплата подписки</h1>
{{if eq .Payment "stub_auto"}}<div class="note"><b>Тестовый режим.</b> Деньги не списываются: оплата подтверждается сразу, чтобы можно было проверить работу сайта.</div>
{{else if eq .Payment "manual"}}<div class="note">Онлайн-оплата пока не подключена. После заявки администратор подтвердит оплату вручную, срок продлится сразу после подтверждения.</div>{{end}}
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}
{{if .Plans}}<div class="grid">{{range .Plans}}<form method="post" action="/pay" class="card plan"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="plan" value="{{.ID}}">
<div>{{.Name}}</div><div class="price">{{.Price}}</div><div class="muted">{{.Days}} дн.</div><button class="btn">{{if eq $.Payment "stub_auto"}}Оплатить (тест){{else}}Оставить заявку{{end}}</button></form>{{end}}</div>
{{else}}<div class="card">Тарифы ещё не настроены.</div>{{end}}
<p><a href="/cabinet">← В кабинет</a></p>
{{template "foot" .}}{{end}}

{{define "paid"}}{{template "head" .}}
<div class="card"><h1>{{.Heading}}</h1><p>{{.Message}}</p>
<p class="muted">Платёж № {{.PayID}}: {{.PayPlan}}, {{.PayAmount}}.</p><a class="btn" href="/cabinet">В кабинет</a></div>
{{template "foot" .}}{{end}}

{{define "notfound"}}{{template "head" .}}<div class="card"><h1>Страница не найдена</h1><a class="btn s" href="/">На главную</a></div>{{template "foot" .}}{{end}}
`

var siteTpl = template.Must(template.New("site").Parse(siteTplText))

// ---- formatting helpers ----

func fmtBytesRu(n int64) string {
	u := []string{"Б", "КБ", "МБ", "ГБ", "ТБ"}
	f, i := float64(n), 0
	for f >= 1024 && i < len(u)-1 {
		f /= 1024
		i++
	}
	switch {
	case i == 0:
		return fmt.Sprintf("%d %s", n, u[0])
	case f >= 100:
		return fmt.Sprintf("%.0f %s", f, u[i])
	case f >= 10:
		return fmt.Sprintf("%.1f %s", f, u[i])
	}
	return fmt.Sprintf("%.2f %s", f, u[i])
}

func fmtMoney(cents int, cur string) string {
	sym := map[string]string{"RUB": "₽", "USD": "$", "EUR": "€", "UAH": "₴", "KZT": "₸"}[cur]
	var amount string
	if cents%100 == 0 {
		amount = fmt.Sprintf("%d", cents/100)
	} else {
		amount = fmt.Sprintf("%d.%02d", cents/100, cents%100)
	}
	if cents == 0 {
		return "бесплатно"
	}
	if sym == "" {
		return amount + " " + cur
	}
	return amount + " " + sym
}

func fmtDateRu(t time.Time) string { return t.UTC().Format("02.01.2006 15:04") + " UTC" }

// daysWord is "день", "дня" or "дней" for a number.
func daysWord(n int) string {
	if n%100 >= 11 && n%100 <= 14 {
		return "дней"
	}
	switch n % 10 {
	case 1:
		return "день"
	case 2, 3, 4:
		return "дня"
	}
	return "дней"
}

// periodState describes the end of a subscription: "unlimited", "active" (with days left, rounded up) or "expired".
func periodState(exp *time.Time, now time.Time) (state string, daysLeft int) {
	if exp == nil {
		return "unlimited", 0
	}
	d := exp.Sub(now)
	if d <= 0 {
		return "expired", 0
	}
	return "active", int((d + 24*time.Hour - 1) / (24 * time.Hour))
}

func trialText(days int) string {
	if days <= 0 {
		return ""
	}
	return fmt.Sprintf("%d %s", days, daysWord(days))
}

var _ = strings.TrimSpace
