#!/usr/bin/env bash
# Сквозной тест VPN-балансировщика на чистом сервере.
#
#   bash smoke-test.sh                 # тест на локальных тестовых узлах
#   bash smoke-test.sh SUB_URL         # + в конце подключить вашу реальную подписку
#   bash smoke-test.sh --cleanup       # убрать все контейнеры и данные теста
#
# Нужен root, Docker с compose v2, python3, curl. Всё работает через loopback:
# внешние порты (кроме скачивания образов и пакетов) не нужны.
# Результат: сводка на экране и архив /root/smoke-report.tgz, его пришлите разработчику.

set -u
PROJECT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
WORK="$PROJECT_DIR/.smoke"
SB_IMAGE=${SB_IMAGE:-ghcr.io/sagernet/sing-box:v1.11.4}
GO_IMAGE=${GO_IMAGE:-golang:1.23-alpine}
COMPOSE="$WORK/docker-compose.smoke.yml"
DCP=(docker compose -p smoke -f "$COMPOSE")
NATIVE=${SMOKE_NATIVE:-0}           # 1 = режим разработчика: без Docker (balancer и sing-box как процессы)
DB_PORT=55432
UP_A=18388; UP_B=18390; UP_C=18392; UP_DEAD=18399
CLIENT_PORT=18081
GEO_PORT=18095; USUB_PORT=18097; SLOW_PORT=18098; DIRECT_PORT=18099; BLOCK_PORT=18096
SUB_PORT=${SMOKE_SUB_PORT:-18080}
SUB_URL_REAL=""
FAILS=0

# curl без обхода прокси из окружения (no_proxy=127.0.0.1 заставил бы curl идти мимо SOCKS-прокси к локальным адресам)
curlx() { env -u no_proxy -u NO_PROXY curl "$@"; }

log()  { echo "[$(date +%H:%M:%S)] $*" | tee -a "$WORK/report.txt"; }
res()  { # res PASS|FAIL|INFO имя [подробности]
  [ "$1" = FAIL ] && FAILS=$((FAILS+1))
  printf '%-5s %s%s\n' "$1" "$2" "${3:+  ($3)}" | tee -a "$WORK/summary.txt" >> "$WORK/report.txt"
  printf '%-5s %s%s\n' "$1" "$2" "${3:+  ($3)}"
}
wait_for() { # wait_for СЕК "команда"
  local t=$1; shift; local end=$((SECONDS+t))
  while [ $SECONDS -lt $end ]; do eval "$*" >/dev/null 2>&1 && return 0; sleep 2; done
  return 1
}

# ---------- работа с процессами (docker или native) ----------
sb_start() { # sb_start ИМЯ КОНФИГ(в $WORK/conf)
  if [ "$NATIVE" = 1 ]; then
    nohup "$WORK/sb-bin/sing-box" run -c "$WORK/conf/$2" >"$WORK/logs/$1.log" 2>&1 &
    echo $! > "$WORK/pids/$1"
  else
    docker rm -f "smoke-$1" >/dev/null 2>&1
    docker run -d --name "smoke-$1" --network host -v "$WORK/conf:/conf:ro" "$SB_IMAGE" run -c "/conf/$2" >/dev/null
  fi
}
sb_stop()  { if [ "$NATIVE" = 1 ]; then kill "$(cat "$WORK/pids/$1" 2>/dev/null)" 2>/dev/null; else docker stop -t 2 "smoke-$1" >/dev/null 2>&1; fi; }
sb_again() { if [ "$NATIVE" = 1 ]; then sb_start "$1" "$2"; else docker start "smoke-$1" >/dev/null 2>&1; fi; }

bal_start() {
  if [ "$NATIVE" = 1 ]; then
    DB_PASSWORD=$DB_PASSWORD nohup "$BAL_BIN" -c "$WORK/config.yaml" run >>"$WORK/logs/balancer.log" 2>&1 &
    echo $! > "$WORK/pids/balancer"
  else
    DB_PASSWORD=$DB_PASSWORD "${DCP[@]}" up -d --build >"$WORK/build.log" 2>&1
  fi
}
bal_restart() {
  if [ "$NATIVE" = 1 ]; then
    kill "$(cat "$WORK/pids/balancer")" 2>/dev/null; sleep 3; bal_start
  else
    DB_PASSWORD=$DB_PASSWORD "${DCP[@]}" restart balancer >/dev/null 2>&1
  fi
}
bal_cli() {
  if [ "$NATIVE" = 1 ]; then DB_PASSWORD=$DB_PASSWORD "$BAL_BIN" -c "$WORK/config.yaml" "$@"
  else DB_PASSWORD=$DB_PASSWORD "${DCP[@]}" exec -T balancer balancer -c /etc/balancer/config.yaml "$@"; fi
}
bal_logs() {
  if [ "$NATIVE" = 1 ]; then cat "$WORK/logs/balancer.log"
  else DB_PASSWORD=$DB_PASSWORD "${DCP[@]}" logs --no-color balancer 2>&1; fi
}
db_q() {
  if [ "$NATIVE" = 1 ]; then psql "postgres://balancer:$DB_PASSWORD@127.0.0.1:$DB_PORT/${DB_NAME:-balancer}" -tAc "$1"
  else DB_PASSWORD=$DB_PASSWORD "${DCP[@]}" exec -T postgres psql -U balancer -p $DB_PORT -d "${DB_NAME:-balancer}" -tAc "$1"; fi
}

# ---------- чтение статуса ----------
status()     { curl -s -m 5 http://127.0.0.1:8080/status; }
n_nodes()    { status | jq '.nodes|length' 2>/dev/null; }
n_healthy()  { status | jq '[.nodes[]|select(.score>0)]|length' 2>/dev/null; }
cur_name()   { status | jq -r '[.nodes[]|select(.current)][0].name // ""' 2>/dev/null; }
score_of()   { status | jq -r --arg n "$1" '[.nodes[]|select(.name==$n)][0].score // -1' 2>/dev/null; }
has_node()   { status | jq -e --arg n "$1" '[.nodes[]|select(.name==$n)]|length>0' >/dev/null 2>&1; }
client_code(){ curlx -s -m 12 -x "socks5h://127.0.0.1:$CLIENT_PORT" -o /dev/null -w '%{http_code}' "${1:-https://www.gstatic.com/generate_204}" 2>/dev/null; }
client_ok()  { [ "$(client_code)" = 204 ]; }

ss_link() { # ss_link ИМЯ ПОРТ
  local ui; ui=$(printf 'aes-128-gcm:pw' | base64 | tr '+/' '-_' | tr -d '=')
  echo "ss://$ui@127.0.0.1:$2#$1"
}
ss_server_conf() { # ss_server_conf ПОРТ
  printf '{"log":{"level":"warn"},"inbounds":[{"type":"shadowsocks","listen":"127.0.0.1","listen_port":%s,"method":"aes-128-gcm","password":"pw"}],"outbounds":[{"type":"direct"}]}' "$1"
}

# ---------- очистка ----------
cleanup() {
  if [ "$NATIVE" = 1 ]; then
    for f in "$WORK"/pids/*; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null; done
  else
    # по меткам и именам, чтобы чистить и остатки прошлых запусков без каталога .smoke
    ids=$(docker ps -aq --filter label=com.docker.compose.project=smoke 2>/dev/null)
    [ -n "$ids" ] && docker rm -f $ids >/dev/null 2>&1
    for n in up-a up-b up-c client rt-server rt-client; do docker rm -f "smoke-$n" >/dev/null 2>&1; done
    docker volume rm -f smoke_balancer-data >/dev/null 2>&1
  fi
  for f in sub geo slow; do [ -f "$WORK/pids/$f" ] && kill "$(cat "$WORK/pids/$f")" 2>/dev/null; done
}
if [ "${1:-}" = "--cleanup" ]; then cleanup; rm -rf "$WORK"; echo "cleaned"; exit 0; fi
[ -n "${1:-}" ] && SUB_URL_REAL=$1

# ---------- 0. проверки окружения ----------
[ "$(id -u)" = 0 ] || { echo "запустите от root"; exit 2; }
cleanup; rm -rf "$WORK" "$WORK.old"
mkdir -p "$WORK"/{conf,logs,pids,www,data,sb-bin}
: > "$WORK/report.txt"; : > "$WORK/summary.txt"
log "== VPN-балансировщик: сквозной тест =="; log "$(date -R); $(uname -sr)"

need_pkgs=()
command -v jq      >/dev/null || need_pkgs+=(jq)
command -v python3 >/dev/null || need_pkgs+=(python3)
command -v curl    >/dev/null || need_pkgs+=(curl)
command -v openssl >/dev/null || need_pkgs+=(openssl)
if [ ${#need_pkgs[@]} -gt 0 ]; then log "ставлю пакеты: ${need_pkgs[*]}"; apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq "${need_pkgs[@]}" >/dev/null 2>&1; fi
if [ "$NATIVE" != 1 ]; then
  if ! command -v docker >/dev/null; then log "ставлю docker.io и compose из apt"; apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq docker.io docker-compose-v2 >/dev/null 2>&1; fi
  docker compose version >/dev/null 2>&1 || { res FAIL "docker compose v2 не найден" "поставьте docker-compose-v2 или docker-compose-plugin"; exit 2; }
  docker info >/dev/null 2>&1 || { res FAIL "демон Docker не запущен"; exit 2; }
  log "docker: $(docker --version); $(docker compose version --short)"
fi
for p in 443 8080 9090 2080 $DB_PORT $SUB_PORT $UP_A $UP_B $UP_C $CLIENT_PORT $GEO_PORT $USUB_PORT $SLOW_PORT $DIRECT_PORT $BLOCK_PORT 18443 18082; do
  if ss -tln 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$p$"; then res FAIL "порт $p уже занят" "освободите его или скажите, какой заменить"; exit 2; fi
done

DB_PASSWORD=${DB_PASSWORD:-$(openssl rand -hex 16)}

# ---------- 1. подготовка ----------
log "достаю бинарник sing-box из образа и генерирую ключи Reality"
if [ "$NATIVE" != 1 ]; then
  docker pull -q "$SB_IMAGE" >/dev/null 2>&1 || log "pull $SB_IMAGE не удался"
  cid=$(docker create "$SB_IMAGE") && docker cp "$cid:/usr/local/bin/sing-box" "$WORK/sb-bin/sing-box" >/dev/null && docker rm "$cid" >/dev/null
  [ -x "$WORK/sb-bin/sing-box" ] && res PASS "sing-box по пути /usr/local/bin/sing-box в образе" "$("$WORK/sb-bin/sing-box" version | head -1)" || res FAIL "в образе нет /usr/local/bin/sing-box"
else
  cp "${SB_BIN:?}" "$WORK/sb-bin/sing-box"
fi
KP=$("$WORK/sb-bin/sing-box" generate reality-keypair)
PRIV=$(echo "$KP" | awk '/PrivateKey/{print $2}'); PUB=$(echo "$KP" | awk '/PublicKey/{print $2}'); SID=$(openssl rand -hex 8)
[ -n "$PRIV" ] && [ -n "$PUB" ] || { res FAIL "не удалось сгенерировать ключи Reality"; exit 2; }

# тестовые апстримы (роль VPN-провайдера): три живых shadowsocks и один мёртвый
ss_server_conf $UP_A > "$WORK/conf/up-a.json"; ss_server_conf $UP_B > "$WORK/conf/up-b.json"; ss_server_conf $UP_C > "$WORK/conf/up-c.json"
sb_start up-a up-a.json; sb_start up-b up-b.json
{ ss_link ss-a $UP_A; ss_link ss-b $UP_B; ss_link ss-dead $UP_DEAD; } > "$WORK/www/sub.txt"
( cd "$WORK/www" && exec python3 -m http.server $SUB_PORT --bind 127.0.0.1 >"$WORK/logs/sub.log" 2>&1 ) &
echo $! > "$WORK/pids/sub"
sleep 1
curl -s -m 5 "http://127.0.0.1:$SUB_PORT/sub.txt" | grep -q ss-a && res PASS "тестовая подписка отдаётся" || res FAIL "тестовая подписка недоступна"

# вспомогательные серверы: «определитель страны» (страну можно менять файлом) и медленные сайты для проверки правил
echo NL > "$WORK/geo-country"
cat > "$WORK/geo.py" <<'PY'
import sys, json, http.server
port, path = int(sys.argv[1]), sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        cc = open(path).read().strip()
        b = json.dumps({"ip": "203.0.113.7", "country": cc}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
PY
cat > "$WORK/slow.py" <<'PY'
import sys, time, threading, http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        time.sleep(6)
        self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
    def log_message(self, *a): pass
for p in sys.argv[1:]:
    threading.Thread(target=http.server.ThreadingHTTPServer(("127.0.0.1", int(p)), H).serve_forever, daemon=True).start()
while True: time.sleep(60)
PY
python3 "$WORK/geo.py" $GEO_PORT "$WORK/geo-country" >/dev/null 2>&1 & echo $! > "$WORK/pids/geo"
python3 "$WORK/slow.py" $SLOW_PORT $DIRECT_PORT $BLOCK_PORT >/dev/null 2>&1 & echo $! > "$WORK/pids/slow"
sleep 1


# ---------- 1a. предварительная проверка Reality (без балансировщика) ----------
# Поднимает отдельный сервер и клиент sing-box с теми же ключами и проверяет рукопожатие на локальной
# странице. Так видно, работает ли Reality на этом сервере и какой сайт-маскировка (handshake_server) подходит.
RT_UUID=$(cat /proc/sys/kernel/random/uuid)
rt_try() { # rt_try САЙТ ОТПЕЧАТОК [ПОРТ, по умолчанию 443]
  local d=$1 fp=$2 port=${3:-443}
  cat > "$WORK/conf/rt-server.json" <<EOF2
{"log":{"level":"warn","timestamp":true},"inbounds":[{"type":"vless","listen":"127.0.0.1","listen_port":$port,"users":[{"uuid":"$RT_UUID","flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":"$d","reality":{"enabled":true,"handshake":{"server":"$d","server_port":443},"private_key":"$PRIV","short_id":["$SID"]}}}],"outbounds":[{"type":"direct"}]}
EOF2
  cat > "$WORK/conf/rt-client.json" <<EOF2
{"log":{"level":"warn"},"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":18082}],"outbounds":[{"type":"vless","server":"127.0.0.1","server_port":$port,"uuid":"$RT_UUID","flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"$d","utls":{"enabled":true,"fingerprint":"$fp"},"reality":{"enabled":true,"public_key":"$PUB","short_id":"$SID"}}}]}
EOF2
  sb_start rt-server rt-server.json; sb_start rt-client rt-client.json; sleep 3
  curlx -s -m 8 -x "socks5h://127.0.0.1:18082" "http://127.0.0.1:$SUB_PORT/sub.txt" | grep -q ss-a
  local rc=$?
  if [ $rc -ne 0 ]; then
    { echo "--- reality $d fp=$fp port=$port: сервер"; if [ "$NATIVE" = 1 ]; then tail -3 "$WORK/logs/rt-server.log"; else docker logs smoke-rt-server 2>&1 | tail -3; fi
      echo "--- клиент"; if [ "$NATIVE" = 1 ]; then tail -3 "$WORK/logs/rt-client.log"; else docker logs smoke-rt-client 2>&1 | tail -3; fi; } 2>&1 | sed 's/\x1b\[[0-9;]*m//g' >> "$WORK/logs/reality-diag.log"
  fi
  sb_stop rt-server; sb_stop rt-client; sleep 1
  return $rc
}
HS=""
HS_ANY=""
CTL_OK=0
HS_FP=chrome
for d in ${SMOKE_HS_CANDIDATES:-www.microsoft.com www.cloudflare.com www.apple.com dl.google.com addons.mozilla.org}; do
  tls=$(echo | timeout 15 openssl s_client -connect "$d:443" -servername "$d" -tls1_3 -groups X25519 2>&1 | grep -E 'Protocol *:|New, TLSv1.3' | head -1)
  [ -n "$tls" ] && t13=ok || t13=НЕТ
  if rt_try "$d" chrome; then
    res INFO "Reality-проверка: $d fp=chrome  РАБОТАЕТ" "TLS1.3 с сервера: $t13"
    if [ -z "$HS" ] && [ "$t13" = ok ]; then HS=$d; fi
    [ -z "$HS_ANY" ] && HS_ANY=$d
  else
    res INFO "Reality-проверка: $d fp=chrome  не работает" "TLS1.3 с сервера: $t13"
  fi
done
[ -z "$HS" ] && HS=$HS_ANY
# контроль: тот же тест на нестандартном порту. Если на 443 не работает, а на 18443 работает,
# то на сервере что-то перехватывает или фильтрует трафик на порт 443 (NAT, прокси, панель).
ctl=${HS:-${SMOKE_HS_CANDIDATES:-www.microsoft.com}}; ctl=${ctl%% *}
if rt_try "$ctl" chrome 18443; then res INFO "Reality-контроль: $ctl на порту 18443 РАБОТАЕТ"; CTL_OK=1
else res INFO "Reality-контроль: $ctl на порту 18443 не работает"; CTL_OK=0; fi
if [ -n "$HS" ]; then
  res PASS "Reality на этом сервере работает автономно" "handshake_server: $HS"
else
  # возможно дело в отпечатке клиента: пробуем остальные на первом сайте
  first=${SMOKE_HS_CANDIDATES:-www.microsoft.com}; first=${first%% *}
  for fp in firefox safari ios random; do
    if rt_try "$first" "$fp"; then res INFO "Reality-проверка: $first fp=$fp  РАБОТАЕТ (chrome нет)"; HS_FP=$fp; HS=$first; break
    else res INFO "Reality-проверка: $first fp=$fp  не работает"; fi
  done
  if [ -n "$HS" ]; then res FAIL "Reality работает только с отпечатком $HS_FP, не с chrome" "см. logs/reality-diag.log"
  else
    if [ "$CTL_OK" = 1 ]; then res FAIL "Reality работает на порту 18443, но не на 443" "на сервере что-то перехватывает порт 443: проверьте iptables -t nat -S, ss -tlnp, панели прокси"
    else res FAIL "Reality не работает даже автономно ни с одним сайтом и отпечатком" "см. logs/reality-diag.log; проблема не в балансировщике"; fi
    HS=${SMOKE_HS_CANDIDATES:-www.microsoft.com}; HS=${HS%% *}; fi
fi

cat > "$WORK/config.yaml" <<EOF
database_url: postgres://balancer:\${DB_PASSWORD}@127.0.0.1:$DB_PORT/balancer
subscriptions:
  - http://127.0.0.1:$SUB_PORT/sub.txt
sub_refresh: 30s
public_host: 127.0.0.1
inbound_port: 443
reality:
  private_key: $PRIV
  public_key: $PUB
  short_id: $SID
  handshake_server: $HS
  handshake_port: 443
tier1_interval: 10s
tier2_interval: 20s
tier3_interval: 90s
tier3_top: 2
watch_interval: 3s
switch_confirm: 2
min_reload_interval: 10s
http_listen: 127.0.0.1:8080
exit_check: true
geo_urls: ["http://127.0.0.1:$GEO_PORT/"]
geo_ttl: 25s
sub_listen: 127.0.0.1:$USUB_PORT
sub_public_url: http://127.0.0.1:$USUB_PORT
rules:
  - action: direct
    match: ["port:$DIRECT_PORT"]
  - action: block
    match: ["port:$BLOCK_PORT"]
EOF
if [ "$NATIVE" = 1 ]; then printf 'singbox_bin: %s\nwork_dir: %s\n' "$WORK/sb-bin/sing-box" "$WORK/data" >> "$WORK/config.yaml"; fi

# docker-режим: compose с host-сетью (всё общается через 127.0.0.1)
cat > "$COMPOSE" <<EOF
services:
  postgres:
    image: postgres:16-alpine
    restart: "no"
    network_mode: host
    command: ["postgres", "-p", "$DB_PORT", "-c", "listen_addresses=127.0.0.1"]
    environment:
      POSTGRES_USER: balancer
      POSTGRES_PASSWORD: \${DB_PASSWORD}
      POSTGRES_DB: balancer
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -h 127.0.0.1 -p $DB_PORT -U balancer"]
      interval: 3s
      retries: 20
  balancer:
    build:
      context: ..
      network: host
    restart: "no"
    network_mode: host
    environment:
      DB_PASSWORD: \${DB_PASSWORD}
    depends_on:
      postgres:
        condition: service_healthy
    volumes:
      - ./config.yaml:/etc/balancer/config.yaml:ro
      - balancer-data:/var/lib/balancer
volumes:
  balancer-data:
EOF

# ---------- 2. запуск ----------
log "запускаю систему (первая сборка образа занимает несколько минут)"
T0=$SECONDS
if [ "$NATIVE" = 1 ]; then : ; else
  DB_PASSWORD=$DB_PASSWORD "${DCP[@]}" up -d postgres >"$WORK/build.log" 2>&1
fi
bal_start
if [ "$NATIVE" != 1 ]; then
  if "${DCP[@]}" ps --status running --services 2>/dev/null | grep -q balancer; then res PASS "образ собирается (go mod download, go vet, go build)" "$((SECONDS-T0)) c"
  else res FAIL "образ не собрался или контейнер не запустился" "см. build.log и logs в отчёте"; fi
fi
if wait_for 120 'curl -sf -m 3 http://127.0.0.1:8080/healthz | grep -q ok'; then res PASS "/healthz отвечает ok (sing-box запущен)"
else res FAIL "/healthz не отвечает за 120 с"; fi

# ---------- 3. подписка, проверки, выбор узла ----------
wait_for 90 '[ "$(n_nodes)" -ge 3 ]' && res PASS "подписка загружена, узлов в пуле: $(n_nodes)" || res FAIL "узлы не появились в пуле" "nodes=$(n_nodes)"
if wait_for 120 '[ "$(n_healthy)" -ge 2 ] && [ -n "$(cur_name)" ]'; then res PASS "tier1/tier2 отработали: живых узлов $(n_healthy), текущий $(cur_name)"
else res FAIL "нет двух живых узлов и текущего за 120 с" "healthy=$(n_healthy) current=$(cur_name)"; fi
[ "$(score_of ss-dead)" = 0 ] && res PASS "мёртвый узел получил оценку 0" || res FAIL "мёртвый узел не обнулён" "score=$(score_of ss-dead)"
[ "$(status | jq '[.nodes[]|select(.current)]|length')" = 1 ] && res PASS "ровно один текущий узел" || res FAIL "текущих узлов не один"
[ "$(status | jq -r .net_down)" = false ] && res PASS "базовая связность сервера определяется (net_down=false)" || res FAIL "net_down=true: у сервера нет TCP до 1.1.1.1/8.8.8.8/9.9.9.9?"
curl -s -m 5 http://127.0.0.1:8080/metrics | grep -q '^balancer_nodes_total' && res PASS "/metrics отдаёт метрики" || res FAIL "/metrics пуст"
[ "$(db_q 'select count(*) from checks' 2>/dev/null | tr -d ' ')" -gt 0 ] 2>/dev/null && res PASS "результаты проверок пишутся в PostgreSQL" || res FAIL "таблица checks пуста"
[ "$(db_q 'select count(*) from switches' 2>/dev/null | tr -d ' ')" -ge 1 ] 2>/dev/null && res PASS "первый выбор узла записан в switches" || res FAIL "таблица switches пуста"

# ---------- 4. пользователь и реальный клиент VLESS+Reality ----------
ADDOUT=$(bal_cli adduser smoke-user 2>>"$WORK/logs/cli.log")
LINK=$(echo "$ADDOUT" | sed -n 1p); SUBURL=$(echo "$ADDOUT" | sed -n 2p)
case "$LINK" in vless://*) res PASS "adduser выдал ссылку vless://";; *) res FAIL "adduser не выдал ссылку" "$LINK";; esac
case "$SUBURL" in http://*/sub/*) res PASS "adduser выдал ссылку на подписку";; *) res FAIL "adduser не выдал ссылку на подписку" "$SUBURL";; esac
bal_cli check 2>&1 | grep -q 'config ok' && res PASS "balancer check: конфиг и правила валидны" || res FAIL "balancer check не прошёл"

bal_cli users 2>&1 | grep -q 'smoke-user' && res PASS "users показывает пользователя" || res FAIL "users не показывает пользователя"

python3 - "$LINK" "$CLIENT_PORT" > "$WORK/conf/client.json" <<'PY'
import sys, json
from urllib.parse import urlsplit, parse_qs
u = urlsplit(sys.argv[1]); q = {k: v[0] for k, v in parse_qs(u.query).items()}
print(json.dumps({"log": {"level": "warn"},
  "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": int(sys.argv[2])}],
  "outbounds": [{"type": "vless", "tag": "p", "server": u.hostname, "server_port": u.port, "uuid": u.username,
    "flow": q.get("flow", ""), "tls": {"enabled": True, "server_name": q.get("sni", ""),
      "utls": {"enabled": True, "fingerprint": q.get("fp", "chrome")},
      "reality": {"enabled": True, "public_key": q.get("pbk", ""), "short_id": q.get("sid", "")}}}]}))
PY
"$WORK/sb-bin/sing-box" check -c "$WORK/conf/client.json" >"$WORK/logs/client-check.log" 2>&1 && res PASS "клиентский конфиг из ссылки валиден для sing-box" || res FAIL "клиентский конфиг не прошёл check" "$(head -c 200 "$WORK/logs/client-check.log")"
sb_start client client.json

log "жду, пока пользователь появится в шлюзе (до 3 минут: перезагрузка sing-box не чаще раза в min_reload_interval)"
T1=$SECONDS
if wait_for 180 client_ok; then res PASS "клиент VLESS+Reality подключился к шлюзу и получил HTTP 204 через узел" "$((SECONDS-T1)) c после adduser"
else res FAIL "клиент не смог пройти через шлюз за 180 с" "см. client.log и balancer.log"; fi
[ "$(client_code https://cp.cloudflare.com/generate_204)" = 204 ] && res PASS "второй сайт через шлюз тоже открывается" || res FAIL "второй сайт не открывается через шлюз"

# ---------- 5. failover ----------
cur=$(cur_name); other=""
case "$cur" in ss-a) other=ss-b; stopn=up-a;; ss-b) other=ss-a; stopn=up-b;; esac
if [ -n "$other" ] && client_ok; then
  log "failover: текущий узел $cur, останавливаю его апстрим"
  sb_stop "$stopn"; TS=$SECONDS; fails=0; ok_streak=0; recovered=""
  while [ $((SECONDS-TS)) -lt 100 ]; do
    if client_ok; then ok_streak=$((ok_streak+1)); [ $ok_streak -ge 3 ] && { recovered=$((SECONDS-TS)); break; }
    else fails=$((fails+1)); ok_streak=0; fi
    sleep 1
  done
  newcur=$(cur_name)
  if [ -n "$recovered" ] && [ "$newcur" = "$other" ]; then res PASS "failover: $cur -> $newcur, трафик восстановился за ~${recovered} c" "сбойных запросов: $fails"
  else res FAIL "failover не сработал" "current=$newcur recovered=${recovered:-нет} fails=$fails"; fi
  [ "$(db_q "select count(*) from switches where reason='failover'" | tr -d ' ')" -ge 2 ] && res PASS "переключение записано в switches" || res INFO "в switches мало failover-записей"
  sb_again "$stopn" "${stopn}.json"
  if wait_for 300 "[ \"\$(score_of $cur)\" != 0 ] && [ \"\$(score_of $cur)\" != -1 ]"; then res PASS "вернувшийся узел $cur снова получил оценку > 0 (карантин снят)"
  else res INFO "узел $cur не вернулся за 5 минут" "возможно, долгий карантин"; fi
else
  res INFO "failover пропущен" "текущий узел не ss-a/ss-b: '$cur' или клиент не работает"
fi

# ---------- 6. изменение подписки ----------
sb_start up-c up-c.json; sleep 1
ss_link ss-c $UP_C >> "$WORK/www/sub.txt"
if wait_for 120 'has_node ss-c'; then res PASS "новый узел из обновлённой подписки появился в пуле"; else res FAIL "ss-c не появился за 120 с после обновления подписки"; fi
if wait_for 120 '[ "$(score_of ss-c)" != 0 ] && [ "$(score_of ss-c)" != -1 ]'; then res PASS "новый узел проверен и получил оценку"; else res INFO "ss-c ещё без оценки"; fi
sleep 12
if wait_for 90 client_ok; then res PASS "после смены набора узлов (reload sing-box) клиент продолжает работать"; else res FAIL "после reload клиент не работает"; fi
bal_logs | grep -q 'config reloaded' && res PASS "reload конфига выполнен (есть в логе)" || res INFO "строки 'config reloaded' нет в логе"

# ---------- 7. tier3 (скорость) ----------
if wait_for 150 '[ "$(status | jq "[.nodes[]|select(.speed_kbps>0)]|length")" -ge 1 ]'; then res PASS "tier3: скорость измерена" "$(status | jq -r '[.nodes[]|select(.speed_kbps>0)][0]|"\(.name) \(.speed_kbps) кбит/с"')"
else res INFO "tier3: скорость не измерена за 150 с" "возможно speed.cloudflare.com недоступен"; fi

# ---------- 8. перезапуск контроллера ----------
before=$(cur_name)
bal_restart
if wait_for 120 'curl -sf -m 3 http://127.0.0.1:8080/healthz | grep -q ok'; then res PASS "контроллер перезапустился, /healthz ok"; else res FAIL "после перезапуска /healthz не отвечает"; fi
wait_for 60 '[ -n "$(cur_name)" ]' >/dev/null
after=$(cur_name)
[ "$before" = "$after" ] && res PASS "после перезапуска продолжил с того же узла ($after)" || res INFO "после перезапуска узел сменился" "$before -> $after"
wait_for 120 client_ok && res PASS "клиент работает после перезапуска контроллера" || res FAIL "клиент не работает после перезапуска"

# ---------- 8a. подписка для пользователя ----------
SUBBODY=$(curl -s -m 10 "$SUBURL"); SUBTXT=$(echo "$SUBBODY" | base64 -d 2>/dev/null)
first=$(echo "$SUBTXT" | sed -n 1p); nlines=$(echo "$SUBTXT" | grep -c '://')
uuid_link=$(echo "$LINK" | sed -E 's#vless://([^@]+)@.*#\1#')
if echo "$first" | grep -q "^vless://$uuid_link@" && echo "$first" | grep -q '#%D0%91'; then res PASS "подписка пользователя: первым идёт балансировщик с личной ссылкой"
else res FAIL "подписка: первая строка не личная ссылка балансировщика" "${first:0:80}"; fi
if echo "$SUBTXT" | grep -q 'ss-a' && echo "$SUBTXT" | grep -q 'ss-b' && echo "$SUBTXT" | grep -q 'ss-c' && [ "$nlines" -eq 4 ]; then res PASS "подписка: следом идут все проверенные узлы ($((nlines-1))), с реальной страной выхода"
else res FAIL "подписка: нет проверенных узлов или их число не 3" "строк=$nlines"; fi
echo "$SUBTXT" | grep -q 'ss-dead' && res FAIL "подписка выдаёт непроверенный (мёртвый) узел" || res PASS "подписка не выдаёт непроверенные узлы (страна выхода неизвестна)"
echo "$SUBTXT" | grep -q '%5BNL%5D' && res PASS "в названиях узлов стоит измеренная страна выхода" || res FAIL "в подписке нет метки страны"
[ "$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$USUB_PORT/sub/deadbeef")" = 404 ] && res PASS "неверный токен подписки даёт 404" || res FAIL "неверный токен подписки не отклонён"

# ---------- 8b. правила фильтра ----------
chains() { curl -s -m 3 "http://127.0.0.1:9090/connections" | jq -c --arg p "$1" '[.connections[]|select(.metadata.destinationPort==$p)|.chains]|first // []' 2>/dev/null; }
rpids=()
for P in $SLOW_PORT $DIRECT_PORT; do
  ( curlx -s -m 14 -x "socks5h://127.0.0.1:$CLIENT_PORT" "http://127.0.0.1:$P/" > "$WORK/logs/rule-$P.out" 2>&1 ) &
  rpids+=($!)
done
sleep 3
ch_default=$(chains $SLOW_PORT); ch_direct=$(chains $DIRECT_PORT); wait "${rpids[@]}"
if echo "$ch_default" | grep -q '"proxy"'; then res PASS "по умолчанию трафик идёт через балансировщик (цепочка: $ch_default)"; else res FAIL "трафик по умолчанию идёт не через балансировщик" "$ch_default"; fi
if [ "$ch_direct" = '["direct"]' ]; then res PASS "правило direct: трафик идёт напрямую через сам сервер (цепочка: $ch_direct)"; else res FAIL "правило direct не сработало" "$ch_direct"; fi
[ "$(cat "$WORK/logs/rule-$DIRECT_PORT.out")" = ok ] && res PASS "правило direct: ответ получен" || res FAIL "правило direct: ответа нет"
bt=$SECONDS; curlx -s -m 10 -x "socks5h://127.0.0.1:$CLIENT_PORT" "http://127.0.0.1:$BLOCK_PORT/" >"$WORK/logs/rule-$BLOCK_PORT.out" 2>&1; brc=$?
if [ $brc -ne 0 ] && [ "$(cat "$WORK/logs/rule-$BLOCK_PORT.out")" != ok ] && [ $((SECONDS-bt)) -lt 5 ]; then res PASS "правило block: соединение отклонено сразу"; else res FAIL "правило block не сработало" "rc=$brc"; fi

# ---------- 8c. страна выхода: узлы с выходом в запрещённой стране не получают трафик ----------
[ "$(status | jq -r '[.nodes[]|select(.name=="ss-a")][0]|"\(.exit_country) \(.allowed)"')" = "NL true" ] && res PASS "страна выхода измерена и записана (ss-a: NL, допущен)" || res FAIL "страна выхода узла не измерена" "$(status | jq -c '[.nodes[]|{name,exit_country,allowed}]')"
echo RU > "$WORK/geo-country"
log "подменяю ответ определителя страны на RU: все выходы теперь «в России», пользователь не должен проходить"
if wait_for 300 '[ "$(status | jq "[.nodes[]|select(.allowed)]|length")" = 0 ]'; then res PASS "после смены на RU все узлы исключены из пользовательского трафика"; else res FAIL "узлы с выходом RU не исключены" "$(status | jq -c '[.nodes[]|{name,exit_country,allowed}]')"; fi
if wait_for 240 '! client_ok'; then res PASS "выход в RU: пользователь не проходит, трафик не уходит напрямую через сам сервер"; else res FAIL "при выходе в RU трафик всё ещё проходит (утечка через запрещённую страну или сервер)"; fi
[ "$(curl -s -m 10 "$SUBURL" | base64 -d 2>/dev/null | grep -c '://')" = 1 ] && res PASS "подписка пользователя без допустимых узлов содержит только балансировщик" || res FAIL "подписка при выходе в RU выдаёт узлы"
[ "$(curlx -s -m 14 -x "socks5h://127.0.0.1:$CLIENT_PORT" "http://127.0.0.1:$DIRECT_PORT/" 2>/dev/null)" = ok ] && res PASS "правило direct продолжает работать без узлов" || res FAIL "direct не работает без узлов"
echo DE > "$WORK/geo-country"
log "возвращаю страну DE: трафик должен восстановиться"
if wait_for 300 client_ok; then res PASS "после возврата допустимой страны (DE) трафик восстановился"; else res FAIL "трафик не восстановился после возврата страны"; fi

# ---------- 8d. веб-панель, API и консольные команды ----------
ATOK=$(bal_cli token 2>/dev/null | tr -d '\r\n')
[ ${#ATOK} -ge 32 ] && res PASS "команда token выдала токен панели" || res FAIL "token не выдал токен"
[ "$(curl -s -m 5 -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/api/overview)" = 401 ] && res PASS "API без токена закрыт (401)" || res FAIL "API без токена не закрыт"
[ "$(curl -s -m 5 -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer wrong' http://127.0.0.1:8080/api/settings)" = 401 ] && res PASS "API с неверным токеном закрыт" || res FAIL "API с неверным токеном не закрыт"
curl -s -m 5 http://127.0.0.1:8080/ | grep -q 'Балансировщик VPN' && res PASS "веб-панель отдаётся на /" || res FAIL "веб-панель не отдаётся"
[ "$(curl -s -m 5 -H "Authorization: Bearer $ATOK" http://127.0.0.1:8080/api/overview | jq '.snapshot.nodes|length')" -ge 3 ] && res PASS "API с токеном отдаёт обзор" || res FAIL "API с токеном не отдаёт обзор"
bal_cli status 2>&1 | grep -q 'текущий узел' && res PASS "команда status работает" || res FAIL "status не работает"
bal_cli nodes 2>&1 | grep -q 'ss-a' && res PASS "команда nodes показывает узлы" || res FAIL "nodes не показывает узлы"
bal_cli node ss-a 2>&1 | grep -qE 'выход: +(NL|DE)' && res PASS "команда node показывает страну выхода" || res FAIL "node не показывает страну выхода"
bal_cli get 2>&1 | grep -q 'blocked_exit_countries' && res PASS "команда get показывает настройки" || res FAIL "get не работает"
# закрепление узла вручную
cur=$(cur_name); want=ss-b; [ "$cur" = ss-b ] && want=ss-a
if bal_cli switch "$want" >/dev/null 2>&1 && wait_for 30 "[ \"\$(cur_name)\" = $want ]"; then res PASS "switch: узел $want закреплён вручную"; else res FAIL "switch не переключил на $want" "текущий: $(cur_name)"; fi
[ "$(status | jq -r .pinned)" = "$want" ] && res PASS "в /status видно закрепление" || res FAIL "закрепление не видно в /status"
bal_cli unpin >/dev/null 2>&1; [ "$(status | jq -r .pinned)" = "" ] && res PASS "unpin снимает закрепление" || res FAIL "unpin не снял закрепление"
# настройки на лету
bal_cli set default_action direct >/dev/null 2>&1 && res FAIL "default_action=direct принят (сервер стал бы выходом по умолчанию)" || res PASS "default_action=direct отклонён"
bal_cli set switch_confirm 99 >/dev/null 2>&1 && res FAIL "switch_confirm=99 принят" || res PASS "неверное значение настройки отклонено"
bal_cli set switch_confirm 4 >/dev/null 2>&1; sleep 1
[ "$(bal_cli get switch_confirm 2>/dev/null | tr -d ' \n')" = 4 ] && res PASS "set/get: настройка сохранена в базе" || res FAIL "set/get не работает"
curl -s -m 5 -X PUT -H "Authorization: Bearer $ATOK" -d '{"switch_confirm":3}' http://127.0.0.1:8080/api/settings | jq -e '.values.switch_confirm==3' >/dev/null && res PASS "PUT /api/settings применяет настройку сразу" || res FAIL "PUT /api/settings не работает"
curl -s -m 5 -X PUT -H "Authorization: Bearer $ATOK" -d '{"rules":[{"action":"direct","match":["bad domain"]}]}' http://127.0.0.1:8080/api/settings | jq -e '.error' >/dev/null && res PASS "неверное правило отклонено с понятной ошибкой" || res FAIL "неверное правило принято"
# правило, добавленное командой, начинает действовать без перезапуска
bal_cli rules add block "port:$SLOW_PORT" >/dev/null 2>&1
log "добавлено правило block для порта $SLOW_PORT: жду, пока оно применится в шлюзе (до 3 минут)"
blocked_now() { ! curlx -s -m 4 -x "socks5h://127.0.0.1:$CLIENT_PORT" "http://127.0.0.1:$SLOW_PORT/" >/dev/null 2>&1; }
if wait_for 180 blocked_now; then res PASS "правило, добавленное командой rules add, применилось на лету"; else res FAIL "правило из rules add не применилось за 3 минуты"; fi
bal_cli rules list 2>&1 | grep -q "port:$SLOW_PORT" && res PASS "rules list показывает правило" || res FAIL "rules list не показывает правило"
bal_cli rules del 3 >/dev/null 2>&1
bal_cli rules list 2>&1 | grep -q "port:$SLOW_PORT" && res FAIL "rules del не удалил правило" || res PASS "rules del удалил правило"
bal_cli countries block FR >/dev/null 2>&1; bal_cli countries list 2>&1 | grep -q 'FR' && res PASS "countries block добавляет страну" || res FAIL "countries block не работает"
bal_cli countries allow FR >/dev/null 2>&1; bal_cli countries list 2>&1 | grep 'запрещённые' | grep -q 'FR' && res FAIL "countries allow не убрал страну" || res PASS "countries allow убирает страну"
wait_for 120 client_ok && res PASS "после изменений настроек пользователь по-прежнему проходит" || res FAIL "после изменений настроек клиент не проходит"

# ---------- 9. отключение пользователя ----------
bal_cli deluser smoke-user >/dev/null 2>&1
log "жду, пока отключённый пользователь перестанет проходить (до 3 минут)"
if wait_for 180 '! client_ok'; then res PASS "отключённый пользователь больше не проходит через шлюз"; else res FAIL "после deluser клиент всё ещё проходит"; fi

# ---------- 10. unit и интеграционные тесты (Go) ----------
if [ "$NATIVE" != 1 ]; then
  log "запускаю go test в контейнере (юнит + интеграционные с реальными sing-box и PostgreSQL)"
  DB_NAME=balancer db_q "CREATE DATABASE scratch" >/dev/null 2>&1
  docker run --rm --network host -v "$PROJECT_DIR":/src:ro -v "$WORK/sb-bin":/sb:ro \
    -e SINGBOX_BIN=/sb/sing-box -e TEST_DATABASE_URL="postgres://balancer:$DB_PASSWORD@127.0.0.1:$DB_PORT/scratch" \
    "$GO_IMAGE" sh -c 'cp -r /src /build && cd /build && rm -rf .smoke && go vet ./... && go test -count=1 -v ./...' \
    >"$WORK/logs/gotest.log" 2>&1
  p=$(grep -c '^--- PASS' "$WORK/logs/gotest.log"); f=$(grep -c '^--- FAIL' "$WORK/logs/gotest.log"); s=$(grep -c '^--- SKIP' "$WORK/logs/gotest.log")
  if [ "$f" = 0 ] && grep -q '^ok' "$WORK/logs/gotest.log"; then res PASS "go test: все тесты прошли" "pass=$p skip=$s"; else res FAIL "go test: есть падения" "pass=$p fail=$f skip=$s, см. gotest.log"; fi
fi

# ---------- 11. реальная подписка (необязательно) ----------
if [ -n "$SUB_URL_REAL" ]; then
  log "подключаю вашу подписку (каждая ссылка как отдельный узел) и жду, пока узлы проверятся и определится страна выхода"
  sed -i "s#^subscriptions:#subscriptions:\n  - $SUB_URL_REAL#" "$WORK/config.yaml"
  sed -i '/^geo_urls:/d' "$WORK/config.yaml"   # для реальных узлов нужны настоящие сервисы определения страны
  echo "node_identity: link" >> "$WORK/config.yaml"   # каждая ссылка подписки = отдельный узел (даже с одинаковыми параметрами)
  bal_restart; wait_for 120 'curl -sf -m 3 http://127.0.0.1:8080/healthz | grep -q ok'
  # ждём, пока в пул загрузятся ВСЕ ссылки подписки, затем пока число измеренных стран перестанет расти (до 20 минут)
  want=$(curl -s -m 20 "$SUB_URL_REAL" | base64 -d 2>/dev/null | grep -c '://'); want=${want:-0}
  wait_for 300 "[ \"\$(n_nodes)\" -ge \"$want\" ]"
  geo_n() { status | jq '[.nodes[]|select(.exit_country!="")]|length' 2>/dev/null; }
  prev=-1; stable=0; end=$((SECONDS+1200))
  while [ $SECONDS -lt $end ]; do
    cur=$(geo_n); cur=${cur:-0}
    if [ "$cur" = "$prev" ] && [ "$cur" -gt 0 ]; then stable=$((stable+30)); else stable=0; fi
    [ $stable -ge 300 ] && break
    prev=$cur; sleep 30
  done
  tot=$(n_nodes); ok=$(n_healthy)
  res INFO "реальная подписка: узлов в пуле $tot, живых $ok" "см. status.json в отчёте"
  [ "${ok:-0}" -gt 3 ] && res PASS "реальные узлы проходят проверки (живых больше, чем тестовых)" || res INFO "живых реальных узлов мало: $ok из $tot"
  res INFO "реальные узлы по странам выхода" "$(status | jq -r '[.nodes[]|select(.exit_country!="")|.exit_country]|group_by(.)|map("\(.[0])=\(length)")|join(" ")')"
  res INFO "допущено к трафику пользователей" "$(status | jq '[.nodes[]|select(.allowed)]|length') из $tot; исключено по стране/без страны: $(status | jq '[.nodes[]|select(.allowed|not)]|length')"
  res INFO "серверы, у которых разные ссылки дали РАЗНУЮ страну выхода" "$(status | jq -r '[.nodes[]|select(.exit_country!="")]|group_by(.server)|map(select((map(.exit_country)|unique|length)>1))|length') хостов; хостов всего: $(status | jq -r '[.nodes[].server]|unique|length')"
  U2=$(bal_cli adduser smoke-user2 2>/dev/null | sed -n 2p)
  res INFO "подписка нового пользователя: строк $(curl -s -m 10 "$U2" | base64 -d 2>/dev/null | grep -c '://') (1 балансировщик + допущенные узлы)"
fi

# ---------- итог и отчёт ----------
status | jq . > "$WORK/status.json" 2>/dev/null
curl -s -m 5 http://127.0.0.1:8080/metrics > "$WORK/metrics.txt" 2>/dev/null
bal_logs > "$WORK/logs/balancer.full.log" 2>&1
[ "$NATIVE" != 1 ] && { "${DCP[@]}" ps -a > "$WORK/logs/compose-ps.txt" 2>&1; docker logs smoke-client > "$WORK/logs/client.log" 2>&1; tail -60 "$WORK/build.log" > "$WORK/logs/build-tail.log"; }
db_q "select to_char(ts,'HH24:MI:SS'), from_node, to_node, reason from switches order by ts" > "$WORK/logs/switches.txt" 2>&1
db_q "select tier, ok, count(*) from checks group by 1,2 order by 1,2" > "$WORK/logs/checks-summary.txt" 2>&1
db_q "select left(error,90) e, count(*) from checks where not ok group by 1 order by 2 desc limit 15" > "$WORK/logs/check-errors.txt" 2>&1
sed -e "s#private_key: .*#private_key: <скрыт>#" "$WORK/config.yaml" > "$WORK/config.scrubbed.yaml"
if [ "$NATIVE" = 1 ]; then cp "$WORK/data/config.json" "$WORK/logs/singbox-gateway.json" 2>/dev/null
else DB_PASSWORD=$DB_PASSWORD "${DCP[@]}" exec -T balancer cat /var/lib/balancer/config.json > "$WORK/logs/singbox-gateway.json" 2>/dev/null; fi
sed -i -E 's/("private_key": ")[^"]*"/\1<скрыт>"/' "$WORK/logs/singbox-gateway.json" 2>/dev/null
cp "$WORK/conf/client.json" "$WORK/logs/client-config.json" 2>/dev/null
echo "${LINK:-}" > "$WORK/logs/user-link.txt"
{ date -u; docker version --format 'docker {{.Server.Version}}' 2>/dev/null; "$WORK/sb-bin/sing-box" version | head -1; } > "$WORK/logs/versions.txt" 2>&1
{ uname -a; free -m; df -h / | tail -1; } > "$WORK/logs/system.txt" 2>&1
OUT=${SMOKE_REPORT:-/root/smoke-report.tgz}
tar czf "$OUT" -C "$WORK" summary.txt report.txt status.json metrics.txt config.scrubbed.yaml logs 2>/dev/null
echo; echo "==================== ИТОГ ===================="; cat "$WORK/summary.txt"
echo "=============================================="
echo "FAIL: $FAILS"
echo "Отчёт: $OUT  (пришлите его; секреты Reality скрыты)"
echo "Убрать за собой: bash smoke-test.sh --cleanup"
[ $FAILS -eq 0 ]
