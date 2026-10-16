package main

import (
	"fmt"
	"html/template"
	"strings"
	"time"
)

// The pages of the public site. Plain HTML with a little CSS; the only script copies a link to the clipboard (it carries a nonce).

const siteTplText = `
{{define "head"}}<!doctype html><html lang="ru" data-theme="{{.Theme}}" data-palette="{{.Palette}}"{{if .AccentStyle}} style="{{.AccentStyle}}"{{end}}><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>{{.Title}} · {{.Site}}</title><link rel="stylesheet" href="/site.css?v={{.CSSVer}}"></head><body>
<header><div class="bar"><a class="name" href="/">{{.Site}}</a>
<a href="/help">Инструкции</a>
{{if .Email}}<a href="/cabinet">Кабинет</a><a href="/forum">Форум</a>{{else}}<a href="/login">Войти</a>{{end}}
{{template "prefs" .}}
{{if .Email}}<form method="post" action="/logout" style="margin:0"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="btn s sm">Выйти</button></form>
{{else if .CanRegister}}<a class="btn sm" href="/register">Регистрация</a>{{end}}</div></header><main>{{end}}
{{define "prefs"}}<details class="prefs"><summary title="Оформление">🎨</summary><div class="pop">
<div class="lbl">Тема</div><div class="opts">{{range .ThemeOpts}}<a{{if .On}} class="on"{{end}} href="/prefs?theme={{.ID}}&back={{$.Path}}" rel="nofollow">{{.Icon}} {{.Title}}</a>{{end}}</div>
<div class="lbl">Цвет</div><div class="opts">{{range .PaletteOpts}}<a{{if .On}} class="on"{{end}} href="/prefs?palette={{.ID}}&back={{$.Path}}" rel="nofollow"><span class="dot" style="background:{{.Color}}"></span>{{.Title}}</a>{{end}}</div>
<div class="lbl"><a href="/prefs?reset=1&back={{.Path}}" rel="nofollow">Вернуть как задумано</a></div></div></details>{{end}}
{{define "foot"}}</main><footer>{{if .Support}}<span>{{.Support}}</span>{{end}}<a href="/help">Инструкции</a>{{if .Email}}<a href="/forum">Форум</a>{{end}}</footer>
<script nonce="{{.Nonce}}">document.addEventListener("click",function(e){var b=e.target.closest("[data-copy]");if(!b)return;var t=document.getElementById(b.dataset.copy).value;
(navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject()).then(function(){b.textContent="Скопировано"},function(){var i=document.getElementById(b.dataset.copy);i.select();document.execCommand&&document.execCommand("copy");b.textContent="Скопировано"});});</script>
</body></html>{{end}}

{{define "home"}}{{template "head" .}}
<div class="hero"><h1>{{.Site}}</h1><p>Быстрый и стабильный VPN. Зарегистрируйтесь, получите ссылку на подписку и подключите её в приложении за минуту.</p>
{{if .Email}}<a class="btn" href="/cabinet">Открыть кабинет</a>{{else}}{{if .CanRegister}}<a class="btn" href="/register">Зарегистрироваться{{if .Trial}} (бесплатно {{.Trial}}){{end}}</a> {{end}}<a class="btn s" href="/login">Войти</a>{{end}}
<a class="btn s" href="/help">Как подключиться</a></div>
<div class="feat"><div><b>Сам выбирает лучший сервер</b><span class="muted">Балансировщик следит за узлами и переключается, если один из них упал.</span></div>
<div><b>Подключение за минуту</b><span class="muted">Одна ссылка-подписка для всех ваших устройств, QR-код для телефона.</span></div>
<div><b>Личный кабинет</b><span class="muted">Срок подписки, трафик и платежи на одной странице.</span></div></div>
{{if .Plans}}<h2>Тарифы</h2><div class="grid">{{range .Plans}}<div class="card plan"><div>{{.Name}}</div><div class="price">{{.Price}}</div><div class="muted">{{.Days}} дн.</div>{{if .Has}}<div class="muted" style="font-size:13px;margin-top:6px">{{range $i, $h := .Has}}{{if $i}}, {{end}}{{$h}}{{end}}</div>{{end}}</div>{{end}}</div>{{end}}
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
{{if .BlockKind}}<div class="err"><b>{{if eq .BlockKind "unpaid"}}Доступ приостановлен: нет оплаты{{else if eq .BlockKind "ban"}}Аккаунт заблокирован{{else}}Доступ приостановлен{{end}}.</b>{{if .BlockReason}} {{.BlockReason}}{{end}}{{if eq .BlockKind "unpaid"}} После оплаты доступ вернётся сам.{{else if .Support}} Вопросы: {{.Support}}{{end}}</div>{{end}}
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
{{if not .Links}}<p class="muted">Для вашего аккаунта сейчас нет доступных подписок. Напишите в поддержку.</p>{{end}}
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
<div>{{.Name}}</div><div class="price">{{.Price}}</div><div class="muted">{{.Days}} дн.</div>{{if .Has}}<div class="muted" style="font-size:13px;margin:6px 0">{{range $i, $h := .Has}}{{if $i}}, {{end}}{{$h}}{{end}}</div>{{end}}<button class="btn">{{if eq $.Payment "stub_auto"}}Оплатить (тест){{else}}Оставить заявку{{end}}</button></form>{{end}}</div>
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
