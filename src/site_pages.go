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
{{if .Login}}<a href="/cabinet">Кабинет</a><a href="/forum">Форум</a>{{else}}<a href="/login">Войти</a>{{end}}
{{template "prefs" .}}
{{if .Login}}<form method="post" action="/logout" style="margin:0"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="btn s sm">Выйти</button></form>
{{else if .CanRegister}}<a class="btn sm" href="/register">Регистрация</a>{{end}}</div></header><main>{{end}}
{{define "prefs"}}<details class="prefs"><summary title="Оформление">🎨</summary><div class="pop">
<div class="lbl">Тема</div><div class="opts">{{range .ThemeOpts}}<a{{if .On}} class="on"{{end}} href="/prefs?theme={{.ID}}&back={{$.Path}}" rel="nofollow">{{.Icon}} {{.Title}}</a>{{end}}</div>
<div class="lbl">Цвет</div><div class="opts">{{range .PaletteOpts}}<a{{if .On}} class="on"{{end}} href="/prefs?palette={{.ID}}&back={{$.Path}}" rel="nofollow"><span class="dot" style="background:{{.Color}}"></span>{{.Title}}</a>{{end}}</div>
<div class="lbl"><a href="/prefs?reset=1&back={{.Path}}" rel="nofollow">Вернуть как задумано</a></div></div></details>{{end}}
{{define "foot"}}</main><footer>{{if .Support}}<span>{{.Support}}</span>{{end}}<a href="/help">Инструкции</a>{{if .Login}}<a href="/forum">Форум</a>{{end}}</footer>
<script nonce="{{.Nonce}}">document.addEventListener("click",function(e){var b=e.target.closest("[data-copy]");if(!b)return;var t=document.getElementById(b.dataset.copy).value;
(navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject()).then(function(){b.textContent="Скопировано"},function(){var i=document.getElementById(b.dataset.copy);i.select();document.execCommand&&document.execCommand("copy");b.textContent="Скопировано"});});</script>
</body></html>{{end}}

{{define "home"}}{{template "head" .}}
<div class="hero"><h1>{{.Site}}</h1><p>Быстрый и стабильный VPN. Зарегистрируйтесь, получите ссылку на подписку и подключите её в приложении за минуту.</p>
{{if .Login}}<a class="btn" href="/cabinet">Открыть кабинет</a>{{else}}{{if .CanRegister}}<a class="btn" href="/register">Зарегистрироваться{{if .Trial}} (бесплатно {{.Trial}}){{end}}</a> {{end}}<a class="btn s" href="/login">Войти</a>{{end}}
<a class="btn s" href="/help">Как подключиться</a></div>
<div class="feat"><div><b>Сам выбирает лучший сервер</b><span class="muted">Балансировщик следит за узлами и переключается, если один из них упал.</span></div>
<div><b>Подключение за минуту</b><span class="muted">Одна ссылка-подписка для всех ваших устройств, QR-код для телефона.</span></div>
<div><b>Личный кабинет</b><span class="muted">Срок подписки, трафик и платежи на одной странице.</span></div></div>
{{if .Plans}}<h2>Тарифы</h2><div class="grid">{{range .Plans}}<div class="card plan"><div>{{.Name}}</div><div class="price">{{.Price}}</div><div class="muted">{{.Days}} дн.</div>{{if .Has}}<div class="muted" style="font-size:13px;margin-top:6px">{{range $i, $h := .Has}}{{if $i}}, {{end}}{{$h}}{{end}}</div>{{end}}</div>{{end}}</div>{{end}}
{{template "foot" .}}{{end}}

{{define "oauth"}}{{if or .Google .Telegram}}<div class="muted" style="text-align:center;margin:14px 0 8px">или</div>
{{if .Telegram}}<form method="post" action="/auth/telegram">{{if .Svc.Ref}}<input type="hidden" name="ref" value="{{.Svc.Ref}}">{{end}}<button class="btn s" style="width:100%">Войти через Telegram</button></form>{{end}}
{{if .Google}}<p style="margin:8px 0 0"><a class="btn s" style="display:block;text-align:center" href="/auth/google{{if .Svc.Ref}}?ref={{.Svc.Ref}}{{end}}">Войти через Google</a></p>{{end}}{{end}}{{end}}

{{define "tglogin"}}{{template "head" .}}
<div class="card" style="max-width:420px;margin:0 auto"><h1>Вход через Telegram</h1>
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}
<meta http-equiv="refresh" content="4;url=/auth/telegram/check">
<p>1. Нажмите кнопку и откройте бота в Telegram.<br>2. В боте нажмите «Да, это я».<br>3. Вернитесь сюда: страница обновится сама.</p>
<p><a class="btn" id="tglink" href="{{.TgLink}}" target="_blank" rel="noopener">Открыть Telegram</a></p>
<script nonce="{{.Nonce}}">(function(){var a=document.getElementById("tglink"),p=window.TelegramWebviewProxy;if(!a||!p||!p.postEvent)return;
a.addEventListener("click",function(e){e.preventDefault();try{p.postEvent("web_app_open_tg_link",JSON.stringify({path_full:a.getAttribute("href").replace("https://t.me","")}));}catch(x){location.href=a.href;}});})();</script>
<p class="muted">Ждём подтверждения… Ссылка действует 10 минут. <a href="/auth/telegram/check">Проверить сейчас</a> · <a href="/login">Отмена</a></p></div>
{{template "foot" .}}{{end}}

{{define "login"}}{{template "head" .}}
<div class="card" style="max-width:420px;margin:0 auto"><h1>Вход</h1>
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}
<form method="post" action="/login"><label for="username">Логин</label><input id="username" name="username" value="{{.FormUser}}" required autocomplete="username" maxlength="24" autocapitalize="none" spellcheck="false">
<label for="pw">Пароль</label><input id="pw" type="password" name="password" required autocomplete="current-password" maxlength="72">
<p><button class="btn">Войти</button></p></form>
{{template "oauth" .}}
{{if .CanRegister}}<p class="muted">Нет аккаунта? <a href="/register">Регистрация</a></p>{{end}}</div>
{{template "foot" .}}{{end}}

{{define "register"}}{{template "head" .}}
<div class="card" style="max-width:420px;margin:0 auto"><h1>Регистрация</h1>
{{if .Trial}}<p class="muted">После регистрации {{.Trial}} бесплатно.</p>{{end}}
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}
<form method="post" action="/register"><label for="username">Логин (3–24 символа: a–z, 0–9, _)</label><input id="username" name="username" value="{{.FormUser}}" required autocomplete="username" maxlength="24" minlength="3" pattern="[a-zA-Z0-9_]{3,24}" autocapitalize="none" spellcheck="false">
<label for="pw">Пароль (от 8 символов)</label><input id="pw" type="password" name="password" required minlength="8" maxlength="72" autocomplete="new-password">
<label for="pw2">Пароль ещё раз</label><input id="pw2" type="password" name="password2" required minlength="8" maxlength="72" autocomplete="new-password">
{{if .Svc.Ref}}<input type="hidden" name="ref" value="{{.Svc.Ref}}"><p class="muted">Вы пришли по приглашению друга.</p>{{end}}
<p><button class="btn">Создать аккаунт</button></p></form>
{{template "oauth" .}}
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
<div class="card"><div class="muted">Аккаунт № {{.UserNo}}</div><div class="big" style="font-size:17px;word-break:break-all">{{.Nick}}</div><div class="muted">{{.Login}} · создан {{.Created}}</div></div>
</div>

<div class="card"><h2>Подключение</h2>
<p class="muted">Установите приложение с поддержкой VLESS и Reality (например v2rayNG, Hiddify, Streisand, Shadowrocket), добавьте подписку по ссылке или QR-коду и обновите её. Ссылки личные, не передавайте их другим.</p>
{{range .Links}}<div class="row"><b style="min-width:230px">{{.Title}}</b></div>
<div class="row"><input id="l-{{.Kind}}" readonly value="{{.URL}}" aria-label="{{.Title}}"><button class="btn s sm" type="button" data-copy="l-{{.Kind}}">Копировать</button></div>
<details><summary>QR-код</summary><img loading="lazy" alt="QR-код: {{.Title}}" src="/qr/{{.Kind}}" width="240" height="240"></details>{{end}}
{{if not .Links}}<p class="muted">Для вашего аккаунта сейчас нет доступных подписок. Напишите в поддержку.</p>{{end}}
{{if .Hint}}<p class="muted">{{.Hint}}</p>{{end}}</div>

<div class="card"><h2>Баланс и бонусы</h2>
<div class="row"><div><div class="muted">На балансе</div><div class="big">{{.Svc.Balance}}</div></div></div>
{{if .Svc.CanTopup}}<form method="post" action="/pay/topup" class="row"><input type="hidden" name="csrf" value="{{.CSRF}}"><input name="amount" inputmode="decimal" placeholder="сумма, {{.Svc.Cur}}" required maxlength="12" aria-label="Сумма пополнения" style="max-width:160px"><button class="btn s sm">Пополнить</button></form>{{end}}
<form method="post" action="/account/promo" class="row"><input type="hidden" name="csrf" value="{{.CSRF}}"><input name="promo" placeholder="промокод" required maxlength="32" aria-label="Промокод" style="max-width:200px"><button class="btn s sm">Применить</button></form>
{{if .Svc.Ops}}<table><tr><th>Дата</th><th>Операция</th><th>Сумма</th></tr>{{range .Svc.Ops}}<tr><td>{{.Date}}</td><td>{{.Text}}</td><td class="{{.Class}}">{{.Amount}}</td></tr>{{end}}</table>{{end}}
</div>

<div class="card"><h2>Пригласить друга</h2>
{{if .Svc.RefRule}}<p>{{.Svc.RefRule}}</p>{{else}}<p class="muted">Поделитесь ссылкой: друг зарегистрируется по ней.</p>{{end}}
{{if .Svc.RefLink}}<div class="row"><input id="refl" readonly value="{{.Svc.RefLink}}" aria-label="Ваша ссылка-приглашение"><button class="btn s sm" type="button" data-copy="refl">Копировать</button></div>{{end}}
<p class="muted">Приглашено: {{.Svc.RefInvited}}, оплатили: {{.Svc.RefPaid}}{{if .Svc.RefEarned}}. Вы получили: {{.Svc.RefEarned}}{{end}}</p></div>

{{if .Svc.TgBot}}<div class="card"><h2>Telegram</h2>
{{if .Svc.TgLinked}}<p class="ok">Аккаунт привязан к Telegram: в боте @{{.Svc.TgBot}} можно смотреть срок, ссылку подписки и продлевать.</p>
<form method="post" action="/account/telegram"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="op" value="unlink"><button class="btn s sm">Отвязать</button></form>
{{else}}{{if .Svc.TgCode}}<p>Откройте бота <b>@{{.Svc.TgBot}}</b> и отправьте ему: <code>/start {{.Svc.TgCode}}</code> (код действует 15 минут).</p>{{else}}<p class="muted">Привяжите аккаунт к боту @{{.Svc.TgBot}}: срок, ссылка и оплата прямо в Telegram.</p>
<form method="post" action="/account/telegram"><input type="hidden" name="csrf" value="{{.CSRF}}"><button class="btn s sm">Получить код привязки</button></form>{{end}}{{end}}</div>{{end}}

{{if .Payments}}<div class="card"><h2>Платежи</h2><table><tr><th>Дата</th><th>Тариф</th><th>Сумма</th><th>Статус</th></tr>
{{range .Payments}}<tr><td>{{.Date}}</td><td>{{.Plan}}</td><td>{{.Amount}}</td><td class="{{.Class}}">{{.Status}}</td></tr>{{end}}</table></div>{{end}}

<div class="card"><h2>Ник</h2><form method="post" action="/account/nick"><input type="hidden" name="csrf" value="{{.CSRF}}">
<label for="nick">Как вас называть (виден в названии подписки в приложении)</label><input id="nick" name="nick" value="{{.Nick}}" required maxlength="32">
<p><button class="btn s">Сохранить ник</button></p></form></div>

<div class="card"><h2>{{if .HasPass}}Смена пароля{{else}}Пароль{{end}}</h2><form method="post" action="/account/password"><input type="hidden" name="csrf" value="{{.CSRF}}">
{{if .HasPass}}<label for="old">Текущий пароль</label><input id="old" type="password" name="old" required autocomplete="current-password" maxlength="72">{{else}}<p class="muted">Вы вошли без пароля (через Telegram или Google). Задайте пароль, чтобы входить и по логину <b>{{.Login}}</b>.</p>{{end}}
<label for="new">Новый пароль (от 8 символов)</label><input id="new" type="password" name="new" required minlength="8" maxlength="72" autocomplete="new-password">
<p><button class="btn s">Сменить пароль</button></p></form></div>
{{template "foot" .}}{{end}}

{{define "pay"}}{{template "head" .}}
<h1>Оплата подписки</h1>
{{if eq .Payment "stub_auto"}}<div class="note"><b>Тестовый режим.</b> Деньги не списываются: оплата подтверждается сразу, чтобы можно было проверить работу сайта.</div>
{{else if eq .Payment "manual"}}<div class="note">Онлайн-оплата пока не подключена. После заявки администратор подтвердит оплату вручную, срок продлится сразу после подтверждения.</div>{{end}}
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}
{{if .Plans}}<div class="grid">{{range .Plans}}<form method="post" action="/pay" class="card plan"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="plan" value="{{.ID}}">
<div>{{.Name}}</div><div class="price">{{.Price}}</div><div class="muted">{{.Days}} дн.</div>{{if .Has}}<div class="muted" style="font-size:13px;margin:6px 0">{{range $i, $h := .Has}}{{if $i}}, {{end}}{{$h}}{{end}}</div>{{end}}
<input name="promo" placeholder="промокод (скидка)" maxlength="32" aria-label="Промокод" style="margin:6px 0">
{{if ne $.Payment "off"}}<button class="btn">{{if eq $.Payment "stub_auto"}}Оплатить (тест){{else}}Оставить заявку{{end}}</button>{{end}}
{{if $.Svc.HasBalance}}<label class="muted" style="display:block;margin-top:6px"><input type="checkbox" name="use_balance" value="1" style="width:auto"> оплатить с баланса ({{$.Svc.Balance}})</label>{{if eq $.Payment "off"}}<button class="btn" name="use_balance" value="1">Оплатить с баланса</button>{{end}}{{end}}</form>{{end}}</div>
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
