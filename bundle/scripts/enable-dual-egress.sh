#!/usr/bin/env bash

set -Eeuo pipefail
umask 077
# shellcheck source=../scripts/target-contract.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../scripts" && pwd -P)/target-contract.sh"

# Legacy first-install/dual flow must never resurrect retired TLS8443.
if [[ -e /etc/germanyvpn-xhttp-test/promotion.json || -L /etc/germanyvpn-xhttp-test/promotion.json ]]; then
  printf 'ERROR: promoted XHTTP marker exists; use the owned promoted-six workflow, not legacy provisioning\n' >&2
  exit 1
fi

readonly SERVER_IPV4="$TARGET_IPV4"
readonly PUBLIC_FQDN="$TARGET_FQDN"
export PUBLIC_FQDN
readonly PANEL_PORT='2053'
readonly SUBSCRIPTION_PORT='2096'
readonly XHTTP_PORT='8443'
readonly runtime_root='/etc/krysyuk-standalone'
readonly runtime_env="$runtime_root/server.env"
readonly api_token_file="$runtime_root/admin-api.token"
readonly connector_env='/etc/krysyuk-warp-egress/warp-egress-nl-client.env'
readonly db='/etc/x-ui/x-ui.db'
readonly xray='/usr/local/x-ui/bin/xray-linux-amd64'

stage=$(mktemp -d -p /run krysyuk-standalone-dual-egress.XXXXXXXX)
backup="/var/backups/krysyuk-standalone/$(date -u +%Y%m%dT%H%M%SZ)-dual-egress-$$"
committed=0
backup_ready=0

die() {
  printf 'ERROR: %s\n' "$*" >&2
  return 1
}

wait_ready() {
  local ready=false
  for _ in $(seq 1 60); do
    if systemctl is-active --quiet x-ui.service \
      && ss -H -lnt | grep -Eq "127[.]0[.]0[.]1:${PANEL_PORT}[[:space:]]" \
      && ss -H -lnt | grep -Eq "${SERVER_IPV4}:443[[:space:]]" \
      && ss -H -lnt | grep -Eq "${SERVER_IPV4}:${XHTTP_PORT}[[:space:]]" \
      && ss -H -lnu | grep -Eq "${SERVER_IPV4}:443[[:space:]]" \
      && ss -H -lnt | grep -Eq "${SERVER_IPV4}:${SUBSCRIPTION_PORT}[[:space:]]"; then
      ready=true
      break
    fi
    sleep 0.5
  done
  [[ "$ready" == true ]]
}

rollback() {
  local status=$?
  local rollback_ok=1
  local -a legacy_args=()
  trap - ERR EXIT INT TERM HUP
  if [[ "$committed" -eq 0 && "$backup_ready" -eq 1 && -s "$backup/x-ui.db" ]]; then
    printf 'ROLLBACK_STARTED=1\n' >&2
    if systemctl stop x-ui.service >/dev/null 2>&1; then
      rm -f -- "${db}-wal" "${db}-shm" || rollback_ok=0
      install -o xui -g xui -m 0600 "$backup/x-ui.db" "$db" || rollback_ok=0
      install -o root -g root -m 0600 "$backup/server.env" "$runtime_env" || rollback_ok=0
      install -o xui -g xui -m 0600 "$backup/config-before.json" /usr/local/x-ui/bin/config.json || rollback_ok=0
      if ((rollback_ok)); then
        XRAY_LOCATION_ASSET=/usr/local/x-ui/bin "$xray" run -test \
          -config /usr/local/x-ui/bin/config.json >/dev/null 2>&1 || rollback_ok=0
      fi
      if ((rollback_ok)); then systemctl start x-ui.service >/dev/null 2>&1 || rollback_ok=0; fi
      wait_ready >/dev/null 2>&1 || rollback_ok=0
      sqlite3 "$db" 'PRAGMA quick_check;' 2>/dev/null | grep -qx ok || rollback_ok=0
      if ((rollback_ok)); then
        legacy_args=(--verify-legacy-rollback --rollback-snapshot "$backup")
        if [[ -s "$stage/subscription-before.body" ]]; then
          legacy_args+=(--baseline-feed "$stage/subscription-before.body")
        fi
        python3 "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/finalize-xhttp.py" \
          "${legacy_args[@]}" >/dev/null || rollback_ok=0
      fi
    else
      rollback_ok=0
    fi
    printf 'ROLLBACK_VERIFIED=%s\n' "$rollback_ok" >&2
  fi
  [[ -n "${stage:-}" && "$stage" == /run/krysyuk-standalone-dual-egress.* ]] && \
    rm -rf -- "$stage" || true
  exit "$status"
}
trap rollback ERR EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

[[ $EUID -eq 0 ]] || die 'must run as root'
[[ ${CONFIRM_STANDALONE_DUAL_EGRESS:-} == "ENABLE-WARP-AND-DIRECT-$TARGET_IPV4" ]] || \
  die 'exact CONFIRM_STANDALONE_DUAL_EGRESS value is required'
for command_name in cat chmod cp curl date grep install ip jq mktemp nft python3 rm seq sha256sum sqlite3 ss systemctl tar tr ufw; do
  command -v "$command_name" >/dev/null 2>&1 || die "missing dependency: $command_name"
done
[[ -r "$runtime_env" && -r "$api_token_file" && -s "$db" && -x "$xray" ]] || \
  die 'required standalone runtime files are absent'
[[ -r "$connector_env" ]] || die 'WARP connector client contract is absent'
grep -Fqx 'DUAL_EGRESS_SCHEMA=1' "$runtime_env" && die 'dual egress is already enabled'

# shellcheck disable=SC1090
source "$runtime_env"
# shellcheck disable=SC1090
source "$connector_env"
[[ "$PANEL_BASE_PATH" =~ ^[A-Za-z0-9_-]{16,128}$ ]] || die 'panel base path is invalid'
[[ "$SUBSCRIPTION_PATH" =~ ^[A-Za-z0-9_-]{16,128}$ ]] || die 'subscription path is invalid'
[[ "$SUBSCRIPTION_ID" =~ ^[a-f0-9]{64}$ ]] || die 'public subscription ID is invalid'
[[ "$VLESS_UUID" =~ ^[a-f0-9-]{36}$ ]] || die 'existing VLESS UUID is invalid'
[[ "$HYSTERIA2_AUTH" =~ ^[A-Za-z0-9_-]{32,128}$ ]] || die 'existing Hysteria2 auth is invalid'
[[ "$WARP_EGRESS_ADDRESS" == 127.0.0.1 && "$WARP_EGRESS_PORT" == 24443 ]] || \
  die 'WARP connector address contract mismatch'
[[ "$WARP_EGRESS_NETWORK" == raw && "$WARP_EGRESS_SECURITY" == none ]] || \
  die 'WARP connector transport contract mismatch'
[[ "$WARP_EGRESS_CLIENT_ID" =~ ^[a-f0-9-]{36}$ ]] || die 'WARP connector UUID is invalid'

systemctl is-active --quiet krysyuk-xray-warp-egress.service || \
  die 'WARP connector Xray is not active'
systemctl is-active --quiet krysyuk-warp-netns-configure.service || \
  die 'isolated WARP configuration is not active'
ss -H -lnt | grep -Eq '127[.]0[.]0[.]1:24443[[:space:]]' || \
  die 'WARP connector is not loopback-listening'
if ss -H -lnt | grep -Eq "(${SERVER_IPV4}|0[.]0[.]0[.]0|[*]|\[::\]):24443[[:space:]]"; then
  die 'WARP connector is unexpectedly public'
fi
/opt/krysyuk-warp-egress/tests/test-smoke.sh >/dev/null
/opt/krysyuk-warp-egress/tests/test-main-route-isolation.sh >/dev/null
/opt/krysyuk-warp-egress/tests/test-e2e-local.sh >/dev/null

install -d -o root -g root -m 0700 "$backup"
sqlite3 "$db" ".backup '$backup/x-ui.db'"
chmod 0600 "$backup/x-ui.db"
install -o root -g root -m 0600 "$runtime_env" "$backup/server.env"
install -o root -g root -m 0600 /usr/local/x-ui/bin/config.json "$backup/config-before.json"
tar --acls --xattrs --numeric-owner -cpf "$backup/managed-before.tar" -C / \
  etc/x-ui usr/local/x-ui etc/krysyuk-standalone etc/nginx etc/letsencrypt \
  etc/ufw etc/systemd/system
tar -tf "$backup/managed-before.tar" >/dev/null
nft -s list ruleset >"$backup/nft-before.txt"
ufw status verbose >"$backup/ufw-before.txt"
ip -4 route show table all >"$backup/ip4-routes-before.txt"
ip -4 rule show >"$backup/ip4-rules-before.txt"
(
  cd "$backup"
  sha256sum x-ui.db server.env config-before.json managed-before.tar nft-before.txt \
    ufw-before.txt ip4-routes-before.txt ip4-rules-before.txt >SHA256SUMS
  sha256sum -c SHA256SUMS >/dev/null
)
sqlite3 "$backup/x-ui.db" 'PRAGMA quick_check;' | grep -qx ok || die 'backup SQLite quick_check failed'
backup_ready=1

printf '%s\n' "$VLESS_UUID" >"$stage/direct-vless.uuid"
printf '%s\n' "$HYSTERIA2_AUTH" >"$stage/direct-hysteria.auth"
printf '%s\n' "$SUBSCRIPTION_ID" >"$stage/public-sub.id"
printf '%s\n' "$WARP_EGRESS_CLIENT_ID" >"$stage/connector.uuid"

warp_reality_uuid=$(cat /proc/sys/kernel/random/uuid)
warp_xhttp_uuid=$(cat /proc/sys/kernel/random/uuid)
warp_hysteria_auth=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
direct_subscription_id=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
printf '%s\n' "$warp_reality_uuid" >"$stage/warp-reality.uuid"
printf '%s\n' "$warp_xhttp_uuid" >"$stage/warp-xhttp.uuid"
printf '%s\n' "$warp_hysteria_auth" >"$stage/warp-hysteria.auth"
printf '%s\n' "$direct_subscription_id" >"$stage/direct-sub.id"
python3 - "$stage" <<'PY'
import pathlib
import sys
import uuid

root = pathlib.Path(sys.argv[1])
for name in ("warp-reality.uuid", "warp-xhttp.uuid"):
    value = root.joinpath(name).read_text().strip()
    parsed = uuid.UUID(value)
    if parsed.version != 4 or str(parsed) != value:
        raise SystemExit("generated UUID is not canonical UUIDv4")
for name in ("warp-hysteria.auth", "direct-sub.id"):
    value = root.joinpath(name).read_text().strip()
    if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise SystemExit("generated secret is not 64 lower-case hex")
PY

cp -- "$runtime_env" "$stage/server.env.intended"
printf '\nDUAL_EGRESS_SCHEMA=1\nDIRECT_SUBSCRIPTION_ID=%s\nWARP_REALITY_UUID=%s\nWARP_XHTTP_UUID=%s\nWARP_HYSTERIA2_AUTH=%s\n' \
  "$direct_subscription_id" "$warp_reality_uuid" "$warp_xhttp_uuid" "$warp_hysteria_auth" \
  >>"$stage/server.env.intended"
unset VLESS_UUID HYSTERIA2_AUTH WARP_EGRESS_CLIENT_ID
unset warp_reality_uuid warp_xhttp_uuid warp_hysteria_auth direct_subscription_id

token=$(tr -d '\r\n' <"$api_token_file")
[[ "$token" =~ ^[A-Za-z0-9._-]{32,256}$ ]] || die 'local API token is invalid'
printf 'Authorization: Bearer %s\n' "$token" >"$stage/api.header"
unset token
api_url="http://127.0.0.1:${PANEL_PORT}/${PANEL_BASE_PATH}/panel/api"

api_get() {
  curl --proto '=http' --fail-with-body --silent --show-error --max-time 30 \
    --header "@$stage/api.header" --header 'Host: localhost' \
    --header 'X-Requested-With: XMLHttpRequest' "$@"
}

api_post() {
  curl --proto '=http' --fail-with-body --silent --show-error --max-time 60 \
    --header "@$stage/api.header" --header 'Host: localhost' \
    --header 'X-Requested-With: XMLHttpRequest' --request POST "$@"
}

api_get --output "$stage/inbounds-before.json" "$api_url/inbounds/list"
jq --exit-status --rawfile direct_vless "$stage/direct-vless.uuid" \
  --rawfile direct_hysteria "$stage/direct-hysteria.auth" \
  --rawfile public_sub "$stage/public-sub.id" '
  def clean: rtrimstr("\n");
  .success == true and (.obj|length==3)
  and ([.obj[]|select(.remark=="VPN VLESS REALITY TCP 443")]|length==1)
  and ([.obj[]|select(.remark=="VPN VLESS XHTTP TLS 8443")]|length==1)
  and ([.obj[]|select(.remark=="VPN Hysteria2 UDP 443")]|length==1)
  and all(.obj[]; .enable == true and (.settings.clients|length)==1)
  and ([.obj[]|select(.protocol=="vless")|.settings.clients[0].id]|unique)==[($direct_vless|clean)]
  and ([.obj[]|select(.protocol=="hysteria")|.settings.clients[0].auth])==[($direct_hysteria|clean)]
  and ([.obj[].settings.clients[0].subId]|unique)==[($public_sub|clean)]
  and ([.obj[].settings.clients[0].email]|sort)==["germany-hysteria2","germany-reality","germany-xhttp"]
' "$stage/inbounds-before.json" >/dev/null || die 'current inbound precondition mismatch'
[[ $(sqlite3 -readonly "$db" 'select count(*) from client_external_links;') == 0 ]] || \
  die 'unexpected pre-existing external client links'

subscription_url="https://${PUBLIC_FQDN}:${SUBSCRIPTION_PORT}/${SUBSCRIPTION_PATH}/${SUBSCRIPTION_ID}"
curl --proto '=https' --tlsv1.2 --fail --silent --show-error --max-time 30 \
  --user-agent 'v2rayN/7' --resolve "${PUBLIC_FQDN}:${SUBSCRIPTION_PORT}:${SERVER_IPV4}" \
  --output "$stage/subscription-before.body" "$subscription_url"
DIRECT_BODY="$stage/subscription-before.body" SECRET_DIR="$stage" CHECK_FQDN="$PUBLIC_FQDN" \
  python3 - <<'PY'
import base64
import os
from pathlib import Path
from urllib.parse import parse_qs, urlparse

root = Path(os.environ["SECRET_DIR"])
raw = Path(os.environ["DIRECT_BODY"]).read_bytes().strip()
text = raw.decode("utf-8", "strict")
if "://" not in text:
    text = base64.urlsafe_b64decode(raw + b"=" * ((4 - len(raw) % 4) % 4)).decode()
links = [line.strip() for line in text.splitlines() if line.strip()]
if len(links) != 3 or len(set(links)) != 3:
    raise SystemExit("pre-migration subscription is not exact unique 3")
direct_vless = root.joinpath("direct-vless.uuid").read_text().strip()
direct_hysteria = root.joinpath("direct-hysteria.auth").read_text().strip()
mapped = {}
for link in links:
    item = urlparse(link)
    if item.hostname != os.environ["CHECK_FQDN"]:
        raise SystemExit("pre-migration subscription hostname mismatch")
    query = parse_qs(item.query)
    if item.scheme == "vless" and query.get("security") == ["reality"]:
        key = "reality"
        if item.port != 443 or item.username != direct_vless:
            raise SystemExit("direct Reality identity mismatch")
    elif item.scheme == "vless" and query.get("type") == ["xhttp"]:
        key = "xhttp"
        if item.port != 8443 or item.username != direct_vless:
            raise SystemExit("direct XHTTP identity mismatch")
    elif item.scheme == "hysteria2":
        key = "hysteria2"
        if item.port != 443 or item.username != direct_hysteria:
            raise SystemExit("direct Hysteria2 identity mismatch")
    else:
        raise SystemExit("unexpected pre-migration link")
    if key in mapped:
        raise SystemExit("duplicate pre-migration transport")
    mapped[key] = link
if set(mapped) != {"reality", "hysteria2", "xhttp"}:
    raise SystemExit("pre-migration transport set mismatch")
for key, filename in (("reality", "direct-reality.uri"),
                      ("hysteria2", "direct-hysteria2.uri"),
                      ("xhttp", "direct-xhttp.uri")):
    root.joinpath(filename).write_text(mapped[key] + "\n", encoding="utf-8")
PY

sqlite3 -readonly "$db" "select value from settings where key='xrayTemplateConfig';" \
  >"$stage/xray-global-before.json"
jq --exit-status '
  (.outbounds|map(.tag)) == ["DIRECT","BLOCK"]
  and (.outbounds[0].protocol=="freedom" and .outbounds[1].protocol=="blackhole")
  and (.routing.rules|length)==3
  and .routing.rules[0].inboundTag==["api"]
  and .routing.rules[1].protocol==["bittorrent"]
  and .routing.rules[2].ip==["geoip:private","::/0"]
' "$stage/xray-global-before.json" >/dev/null || die 'current global Xray precondition mismatch'

jq --rawfile connector "$stage/connector.uuid" '
  def clean: rtrimstr("\n");
  .outbounds = ([{
    tag:"WARP_CF", protocol:"vless",
    settings:{vnext:[{address:"127.0.0.1",port:24443,users:[{id:($connector|clean),encryption:"none"}]}]},
    streamSettings:{network:"raw",security:"none",rawSettings:{header:{type:"none"}},
      sockopt:{tcpKeepAliveIdle:60,tcpKeepAliveInterval:30}},
    mux:{enabled:false,concurrency:-1,xudpConcurrency:-1,xudpProxyUDP443:"skip"}
  }] + .outbounds)
  | .routing.rules = [
    {type:"field",inboundTag:["api"],outboundTag:"api"},
    {type:"field",protocol:["bittorrent"],outboundTag:"BLOCK"},
    {type:"field",inboundTag:["dns_cf","dns_q9"],outboundTag:"DIRECT"},
    {type:"field",ip:["geoip:private","::/0",(env.TARGET_IPV4+"/32")],outboundTag:"BLOCK"},
    {type:"field",domain:[("full:"+env.PUBLIC_FQDN)],outboundTag:"BLOCK"},
    {type:"field",user:["germany-warp-reality","germany-warp-hysteria2","germany-warp-xhttp"],outboundTag:"WARP_CF"},
    {type:"field",user:["germany-reality","germany-hysteria2","germany-xhttp"],outboundTag:"DIRECT"},
    {type:"field",network:"tcp,udp",outboundTag:"BLOCK"}
  ]
' "$stage/xray-global-before.json" >"$stage/xray-global-intended.json"

jq --rawfile warp_uuid "$stage/warp-reality.uuid" \
  --rawfile direct_sub "$stage/direct-sub.id" --rawfile public_sub "$stage/public-sub.id" '
  def clean: rtrimstr("\n");
  .obj[] | select(.remark=="VPN VLESS REALITY TCP 443")
  | .settings.clients[0] as $direct
  | .settings.clients = [
      {id:($warp_uuid|clean),email:"germany-warp-reality",flow:"",limitIp:(env.TARGET_DEVICE_LIMIT|tonumber),totalGB:0,expiryTime:0,enable:true,tgId:0,subId:($public_sub|clean),comment:(env.TARGET_LABEL+" · ☁️ Cloudflare · REALITY"),reset:0},
      ($direct|.subId=($direct_sub|clean)|.comment=(env.TARGET_LABEL+" · 🖥️ IP сервера · REALITY"))
    ]
  | .subSortIndex=1
' "$stage/inbounds-before.json" >"$stage/reality-intended.json"

jq --rawfile warp_auth "$stage/warp-hysteria.auth" \
  --rawfile direct_sub "$stage/direct-sub.id" --rawfile public_sub "$stage/public-sub.id" '
  def clean: rtrimstr("\n");
  .obj[] | select(.remark=="VPN Hysteria2 UDP 443")
  | .settings.clients[0] as $direct
  | .settings.clients = [
      {auth:($warp_auth|clean),email:"germany-warp-hysteria2",limitIp:(env.TARGET_DEVICE_LIMIT|tonumber),totalGB:0,expiryTime:0,enable:true,tgId:0,subId:($public_sub|clean),comment:(env.TARGET_LABEL+" · ☁️ Cloudflare · HYSTERIA2"),reset:0},
      ($direct|.subId=($direct_sub|clean)|.comment=(env.TARGET_LABEL+" · 🖥️ IP сервера · HYSTERIA2"))
    ]
  | .subSortIndex=2
' "$stage/inbounds-before.json" >"$stage/hysteria2-intended.json"

jq --rawfile warp_uuid "$stage/warp-xhttp.uuid" \
  --rawfile direct_sub "$stage/direct-sub.id" --rawfile public_sub "$stage/public-sub.id" '
  def clean: rtrimstr("\n");
  .obj[] | select(.remark=="VPN VLESS XHTTP TLS 8443")
  | .settings.clients[0] as $direct
  | .settings.clients = [
      {id:($warp_uuid|clean),email:"germany-warp-xhttp",flow:"",limitIp:(env.TARGET_DEVICE_LIMIT|tonumber),totalGB:0,expiryTime:0,enable:true,tgId:0,subId:($public_sub|clean),comment:(env.TARGET_LABEL+" · ☁️ Cloudflare · XHTTP"),reset:0},
      ($direct|.subId=($direct_sub|clean)|.comment=(env.TARGET_LABEL+" · 🖥️ IP сервера · XHTTP"))
    ]
  | .subSortIndex=3
' "$stage/inbounds-before.json" >"$stage/xhttp-intended.json"

jq --slurpfile global "$stage/xray-global-intended.json" \
  --slurpfile reality "$stage/reality-intended.json" \
  --slurpfile hysteria "$stage/hysteria2-intended.json" \
  --slurpfile xhttp "$stage/xhttp-intended.json" '
  .outbounds=$global[0].outbounds | .routing=$global[0].routing
  | (.inbounds[]|select(.tag=="in-443-tcp")|.settings.clients)=($reality[0].settings.clients|map({id,email,flow}))
  | (.inbounds[]|select(.tag=="in-443-udp")|.settings.clients)=($hysteria[0].settings.clients|map({auth,email}))
  | (.inbounds[]|select(.tag=="in-8443-tcp")|.settings.clients)=($xhttp[0].settings.clients|map({id,email,flow}))
' /usr/local/x-ui/bin/config.json >"$stage/xray-preflight.json"
XRAY_LOCATION_ASSET=/usr/local/x-ui/bin "$xray" run -test \
  -config "$stage/xray-preflight.json" >/dev/null

DIRECT_LINK_STAGE="$stage" python3 - <<'PY' >"$stage/external-links.json"
import json
import os
from pathlib import Path
from urllib.parse import quote, unquote

root = Path(os.environ['DIRECT_LINK_STAGE'])
label = os.environ['TARGET_LABEL']
links = []
for filename, protocol in (('direct-reality.uri', 'REALITY'),
                           ('direct-hysteria2.uri', 'HYSTERIA2'),
                           ('direct-xhttp.uri', 'XHTTP')):
    original = (root / filename).read_text().rstrip('\n')
    endpoint, separator, old_fragment = original.partition('#')
    if separator != '#' or unquote(old_fragment) != label + ' · ' + protocol:
        raise SystemExit('unexpected direct link fragment')
    remark = label + ' · 🖥️ IP сервера · ' + protocol
    links.append(dict(kind='link', value=endpoint + '#' + quote(remark, safe=''),
                      remark=remark, enable=True, expiryTime=0, namePrefix=''))
print(json.dumps({'externalLinks': links}, ensure_ascii=False, separators=(',', ':')))
PY
jq --exit-status '
  (.externalLinks|length)==3 and ([.externalLinks[].kind]|unique)==["link"]
  and ([.externalLinks[].value]|unique|length)==3 and all(.externalLinks[];.enable==true and .expiryTime==0)
' "$stage/external-links.json" >/dev/null || die 'external direct-link preflight failed'

install -o root -g root -m 0600 "$stage/server.env.intended" "$runtime_env"
api_post --data-urlencode "xraySetting@$stage/xray-global-intended.json" \
  --data-urlencode 'outboundTestUrl=https://www.cloudflare.com/cdn-cgi/trace' \
  --output "$stage/xray-update.response" "$api_url/xray/update"
jq --exit-status '.success==true' "$stage/xray-update.response" >/dev/null || \
  die '3x-ui rejected strict dual-egress routing'
wait_ready || die 'listeners did not recover after routing update'

for payload in "$stage/reality-intended.json" "$stage/hysteria2-intended.json" "$stage/xhttp-intended.json"; do
  inbound_id=$(jq -r '.id' "$payload")
  [[ "$inbound_id" =~ ^[1-9][0-9]*$ ]] || die 'managed inbound ID is invalid'
  api_post --header 'Content-Type: application/json' --data-binary "@$payload" \
    --output "$stage/inbound-${inbound_id}.response" "$api_url/inbounds/update/$inbound_id"
  jq --exit-status '.success==true' "$stage/inbound-${inbound_id}.response" >/dev/null || \
    die '3x-ui rejected dual-client inbound update'
  wait_ready || die 'listeners did not recover after inbound update'
done

api_post --header 'Content-Type: application/json' --data-binary "@$stage/external-links.json" \
  --output "$stage/external-links.response" \
  "$api_url/clients/germany-warp-reality/externalLinks"
jq --exit-status '.success==true' "$stage/external-links.response" >/dev/null || \
  die '3x-ui rejected ordered direct external links'

systemctl restart x-ui.service
wait_ready || die 'x-ui did not recover after final reconciliation'
sqlite3 "$db" 'PRAGMA quick_check;' | grep -qx ok || die 'live SQLite quick_check failed'
XRAY_LOCATION_ASSET=/usr/local/x-ui/bin "$xray" run -test \
  -config /usr/local/x-ui/bin/config.json >/dev/null

api_get --output "$stage/inbounds-after.json" "$api_url/inbounds/list"
api_get --output "$stage/client-after.json" "$api_url/clients/get/germany-warp-reality"
jq --exit-status --rawfile direct_vless "$stage/direct-vless.uuid" \
  --rawfile direct_hysteria "$stage/direct-hysteria.auth" \
  --rawfile public_sub "$stage/public-sub.id" --rawfile direct_sub "$stage/direct-sub.id" \
  --rawfile warp_reality "$stage/warp-reality.uuid" --rawfile warp_xhttp "$stage/warp-xhttp.uuid" \
  --rawfile warp_hysteria "$stage/warp-hysteria.auth" '
  def clean: rtrimstr("\n");
  .success==true and (.obj|length==3) and all(.obj[];.enable==true and (.settings.clients|length)==2)
  and ([.obj[]|select(.remark=="VPN VLESS REALITY TCP 443")|.subSortIndex])==[1]
  and ([.obj[]|select(.remark=="VPN Hysteria2 UDP 443")|.subSortIndex])==[2]
  and ([.obj[]|select(.remark=="VPN VLESS XHTTP TLS 8443")|.subSortIndex])==[3]
  and ([.obj[]|select(.remark=="VPN VLESS REALITY TCP 443")|.settings.clients[0].id])==[($warp_reality|clean)]
  and ([.obj[]|select(.remark=="VPN VLESS XHTTP TLS 8443")|.settings.clients[0].id])==[($warp_xhttp|clean)]
  and ([.obj[]|select(.remark=="VPN Hysteria2 UDP 443")|.settings.clients[0].auth])==[($warp_hysteria|clean)]
  and ([.obj[].settings.clients[0].subId]|unique)==[($public_sub|clean)]
  and ([.obj[].settings.clients[1].subId]|unique)==[($direct_sub|clean)]
  and ([.obj[]|select(.protocol=="vless")|.settings.clients[1].id]|unique)==[($direct_vless|clean)]
  and ([.obj[]|select(.protocol=="hysteria")|.settings.clients[1].auth])==[($direct_hysteria|clean)]
' "$stage/inbounds-after.json" >/dev/null || die 'dual-client inbound read-back mismatch'
jq --exit-status '
  .success==true and (.obj.externalLinks|length)==3
  and [.obj.externalLinks[].sortIndex]==[0,1,2]
  and all(.obj.externalLinks[];.kind=="link" and .enable==true and .expiryTime==0)
' "$stage/client-after.json" >/dev/null || die 'external-link read-back mismatch'

curl --proto '=https' --tlsv1.2 --fail --silent --show-error --max-time 30 \
  --user-agent 'v2rayN/7' --resolve "${PUBLIC_FQDN}:${SUBSCRIPTION_PORT}:${SERVER_IPV4}" \
  --output "$stage/subscription-after.body" "$subscription_url"
SUB_BODY="$stage/subscription-after.body" SECRET_DIR="$stage" DB_PATH="$db" CHECK_FQDN="$PUBLIC_FQDN" \
  python3 - <<'PY'
import base64
import os
from pathlib import Path
import sqlite3
from urllib.parse import parse_qs, unquote, urlparse

root = Path(os.environ["SECRET_DIR"])
raw = Path(os.environ["SUB_BODY"]).read_bytes().strip()
text = raw.decode("utf-8", "strict")
if "://" not in text:
    text = base64.urlsafe_b64decode(raw + b"=" * ((4 - len(raw) % 4) % 4)).decode()
links = [line.strip() for line in text.splitlines() if line.strip()]
names = [
    os.environ["TARGET_LABEL"] + " · ☁️ Cloudflare · REALITY",
    os.environ["TARGET_LABEL"] + " · ☁️ Cloudflare · HYSTERIA2",
    os.environ["TARGET_LABEL"] + " · ☁️ Cloudflare · XHTTP",
    os.environ["TARGET_LABEL"] + " · 🖥️ IP сервера · REALITY",
    os.environ["TARGET_LABEL"] + " · 🖥️ IP сервера · HYSTERIA2",
    os.environ["TARGET_LABEL"] + " · 🖥️ IP сервера · XHTTP",
]
if len(links) != 6 or len(set(links)) != 6:
    raise SystemExit("public subscription is not exact unique 6")
items = [urlparse(link) for link in links]
if [unquote(item.fragment) for item in items] != names:
    raise SystemExit("public subscription display order mismatch")
with sqlite3.connect('file:' + os.environ['DB_PATH'] + '?mode=ro', uri=True) as db:
    external_rows = db.execute('SELECT value, remark FROM client_external_links ORDER BY sort_index,id').fetchall()
if len(external_rows) != 3:
    raise SystemExit("stored direct links count mismatch")
for index, (value, remark) in enumerate(external_rows):
    stored = urlparse(value)
    served = items[index + 3]
    if (stored._replace(fragment='') != served._replace(fragment='') or
            unquote(stored.fragment) != names[index + 3] or remark != names[index + 3]):
        raise SystemExit("stored direct link differs from public subscription")
if any(item.hostname != os.environ["CHECK_FQDN"] for item in items):
    raise SystemExit("public subscription hostname mismatch")
wr = root.joinpath("warp-reality.uuid").read_text().strip()
wx = root.joinpath("warp-xhttp.uuid").read_text().strip()
wh = root.joinpath("warp-hysteria.auth").read_text().strip()
dv = root.joinpath("direct-vless.uuid").read_text().strip()
dh = root.joinpath("direct-hysteria.auth").read_text().strip()
expected = [
    ("vless", 443, wr, "reality"),
    ("hysteria2", 443, wh, "hysteria2"),
    ("vless", 8443, wx, "xhttp"),
    ("vless", 443, dv, "reality"),
    ("hysteria2", 443, dh, "hysteria2"),
    ("vless", 8443, dv, "xhttp"),
]
for item, (scheme, port, identity, transport) in zip(items, expected):
    if item.scheme != scheme or item.port != port or item.username != identity:
        raise SystemExit("public subscription identity/order mismatch")
    query = parse_qs(item.query)
    if transport == "reality" and query.get("security") != ["reality"]:
        raise SystemExit("Reality shape mismatch")
    if transport == "xhttp" and query.get("type") != ["xhttp"]:
        raise SystemExit("XHTTP shape mismatch")
connector = root.joinpath("connector.uuid").read_text().strip()
for forbidden in (connector, "127.0.0.1", "169.254.254.", ":24443"):
    if forbidden in text:
        raise SystemExit("private connector material leaked into subscription")
print("SUBSCRIPTION_ORDER_OK=6")
PY

jq --exit-status --rawfile connector "$stage/connector.uuid" '
  def clean: rtrimstr("\n");
  ([.outbounds[]|select(.tag=="WARP_CF" and .protocol=="vless"
    and .settings.vnext[0].address=="127.0.0.1" and .settings.vnext[0].port==24443
    and .settings.vnext[0].users[0].id==($connector|clean))]|length)==1
  and any(.routing.rules[];.user==["germany-warp-reality","germany-warp-hysteria2","germany-warp-xhttp"] and .outboundTag=="WARP_CF")
  and any(.routing.rules[];.user==["germany-reality","germany-hysteria2","germany-xhttp"] and .outboundTag=="DIRECT")
  and any(.routing.rules[];.inboundTag==["dns_cf","dns_q9"] and .outboundTag=="DIRECT")
  and .routing.rules[-1].network=="tcp,udp" and .routing.rules[-1].outboundTag=="BLOCK"
' /usr/local/x-ui/bin/config.json >/dev/null || die 'live strict routing read-back mismatch'

[[ $(sqlite3 -readonly "$db" 'select count(*) from clients;') == 6 ]] || die 'normalized client count mismatch'
[[ $(sqlite3 -readonly "$db" 'select count(*) from client_inbounds;') == 6 ]] || die 'client assignment count mismatch'
[[ $(sqlite3 -readonly "$db" 'select count(*) from client_external_links;') == 3 ]] || die 'external-link row count mismatch'
/opt/krysyuk-warp-egress/tests/test-e2e-local.sh >/dev/null

touch "$backup/COMMITTED"
chmod 0600 "$backup/COMMITTED"
committed=1
rm -rf -- "$stage"
stage=''
trap - ERR EXIT INT TERM HUP
printf 'STANDALONE_DUAL_EGRESS_OK=1\n'
printf 'BACKUP=%s\n' "$backup"
printf 'SUBSCRIPTION_ORDER=CF_REALITY,CF_HYSTERIA2,CF_XHTTP,DIRECT_REALITY,DIRECT_HYSTERIA2,DIRECT_XHTTP\n'
printf 'WARP_FAIL_CLOSED=1\n'
