#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
# shellcheck source=../scripts/target-contract.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../scripts" && pwd -P)/target-contract.sh"

readonly SERVER_IPV4="$TARGET_IPV4"
readonly PUBLIC_FQDN="$TARGET_FQDN"
export PUBLIC_FQDN
readonly REALITY_TARGET="$TARGET_REALITY_SNI"
readonly PANEL_PORT='2053'
readonly SUBSCRIPTION_PORT='2096'
readonly promotion_marker='/etc/germanyvpn-xhttp-test/promotion.json'
readonly promoted_verifier="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../scripts" && pwd -P)/finalize-xhttp.py"
require_reboot=1
case "${1:-}" in
  --live) require_reboot=0 ;;
  '') ;;
  *) printf 'Usage: postboot-verify.sh [--live]\n' >&2; exit 2 ;;
esac
promoted_xhttp=0
if [[ -e "$promotion_marker" || -L "$promotion_marker" ]]; then
  promoted_xhttp=1
fi
export PROMOTED_XHTTP="$promoted_xhttp"
if ((promoted_xhttp)); then
  readonly XHTTP_PORT='8444' expected_external_count=4
else
  readonly XHTTP_PORT='8443' expected_external_count=3
fi
readonly runtime_root='/etc/krysyuk-standalone'
readonly runtime_env="$runtime_root/server.env"
readonly connector_env='/etc/krysyuk-warp-egress/warp-egress-nl-client.env'
readonly warp_tests='/opt/krysyuk-warp-egress/tests'
readonly warp_deployed_boot='/var/lib/krysyuk-warp-egress/deployed-boot-id'
readonly backup_root='/var/backups/krysyuk-standalone'
readonly xray='/usr/local/x-ui/bin/xray-linux-amd64'

# Pipeline consumers must drain stdout: grep -q can SIGPIPE producers under
# pipefail even when the match succeeded (observed with sshd -T after reboot).
grep_drain() { command grep "$@" >/dev/null; }

stage=$(mktemp -d -p /run standalone-postboot.XXXXXXXX)
cleanup() {
  local status=$?
  trap - EXIT INT TERM HUP
  [[ -n "${stage:-}" && "$stage" == /run/standalone-postboot.* ]] && rm -rf -- "$stage"
  exit "$status"
}
trap cleanup EXIT
trap 'status=$?; printf "POSTBOOT_FAIL_LINE=%s STATUS=%s\n" "$LINENO" "$status" >&2; exit "$status"' ERR
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

[[ $EUID -eq 0 ]]
grep -Fxq 'ID=ubuntu' /etc/os-release
grep -Fxq 'VERSION_ID="24.04"' /etc/os-release
[[ $(uname -m) == x86_64 ]]
[[ $(/usr/local/x-ui/x-ui -v 2>&1) == 3.7.0 ]]
printf '%s  %s\n' '64d46afb80adea1bf97a0d467e83f4a9ac1ebd0995891e84bca3f1a1d1affb1d' "$xray" |
  sha256sum --check --strict - >/dev/null
xray_version_output=$("$xray" version 2>&1)
grep -Eq '^Xray 26[.]7[.]28 ' <<<"$xray_version_output"
unset xray_version_output
sshd_effective=$(sshd -T)
if grep -Fxq 'passwordauthentication no' <<<"$sshd_effective" &&
   grep -Fxq 'kbdinteractiveauthentication no' <<<"$sshd_effective"; then
  printf 'SSH_AUTH_POLICY=KEY_ONLY\n'
else
  printf 'SSH_HARDENING_PENDING=1\n'
fi
unset sshd_effective
for command_name in curl dig find grep ip jq mktemp nginx openssl pgrep ps python3 \
  readlink sed sort sqlite3 ss stat systemctl ufw; do
  command -v "$command_name" >/dev/null 2>&1
done
for private_file in "$runtime_env" "$runtime_root/admin-api.token" \
  "$runtime_root/access.env" "$connector_env" "$warp_deployed_boot"; do
  [[ -f "$private_file" && ! -L "$private_file" ]]
  [[ "$(stat -c '%U:%G:%a' "$private_file")" == 'root:root:600' ]]
done

# shellcheck disable=SC1090
source "$runtime_env"
# shellcheck disable=SC1090
source "$connector_env"

is_uuid() {
  [[ "$1" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]
}

[[ "${DUAL_EGRESS_SCHEMA:-}" == 1 ]]
[[ "$PANEL_BASE_PATH" =~ ^[A-Za-z0-9_-]{16,128}$ ]]
[[ "$SUBSCRIPTION_PATH" =~ ^[A-Za-z0-9_-]{16,128}$ ]]
[[ "$SUBSCRIPTION_ID" =~ ^[a-f0-9]{64}$ ]]
[[ "$DIRECT_SUBSCRIPTION_ID" =~ ^[a-f0-9]{64}$ ]]
[[ "$SUBSCRIPTION_ID" != "$DIRECT_SUBSCRIPTION_ID" ]]
is_uuid "$VLESS_UUID"
is_uuid "$WARP_REALITY_UUID"
is_uuid "$WARP_XHTTP_UUID"
[[ "$VLESS_UUID" != "$WARP_REALITY_UUID" && "$VLESS_UUID" != "$WARP_XHTTP_UUID" ]]
[[ "$WARP_REALITY_UUID" != "$WARP_XHTTP_UUID" ]]
[[ "$HYSTERIA2_AUTH" =~ ^[A-Za-z0-9_-]{32,128}$ ]]
[[ "$WARP_HYSTERIA2_AUTH" =~ ^[a-f0-9]{64}$ ]]
[[ "$HYSTERIA2_AUTH" != "$WARP_HYSTERIA2_AUTH" ]]
[[ "$REALITY_PUBLIC_KEY" =~ ^[A-Za-z0-9_-]{43}$ ]]
[[ "$REALITY_SHORT_ID" =~ ^[a-f0-9]{16}$ ]]
[[ "$XHTTP_PRIVATE_PATH" =~ ^[A-Za-z0-9_-]{16,128}$ ]]
[[ "$WARP_EGRESS_ADDRESS" == 127.0.0.1 ]]
[[ "$WARP_EGRESS_PORT" == 24443 ]]
is_uuid "$WARP_EGRESS_CLIENT_ID"
[[ "$WARP_EGRESS_NETWORK" == raw && "$WARP_EGRESS_SECURITY" == none ]]

write_secret() {
  local name="$1" value="$2"
  printf '%s\n' "$value" >"$stage/$name"
  chmod 0600 "$stage/$name"
}
write_secret public-sub.id "$SUBSCRIPTION_ID"
write_secret direct-sub.id "$DIRECT_SUBSCRIPTION_ID"
write_secret direct-vless.uuid "$VLESS_UUID"
write_secret direct-hysteria.auth "$HYSTERIA2_AUTH"
write_secret warp-reality.uuid "$WARP_REALITY_UUID"
write_secret warp-xhttp.uuid "$WARP_XHTTP_UUID"
write_secret warp-hysteria.auth "$WARP_HYSTERIA2_AUTH"
write_secret connector.uuid "$WARP_EGRESS_CLIENT_ID"
write_secret reality-public.key "$REALITY_PUBLIC_KEY"
write_secret reality-short.id "$REALITY_SHORT_ID"
write_secret xhttp.path "$XHTTP_PRIVATE_PATH"
unset PANEL_USERNAME PANEL_PASSWORD REALITY_PRIVATE_KEY
unset SUBSCRIPTION_ID DIRECT_SUBSCRIPTION_ID VLESS_UUID HYSTERIA2_AUTH
unset WARP_REALITY_UUID WARP_XHTTP_UUID WARP_HYSTERIA2_AUTH
unset WARP_EGRESS_CLIENT_ID REALITY_PUBLIC_KEY REALITY_SHORT_ID XHTTP_PRIVATE_PATH

deployed_boot=$(tr -d '\r\n' <"$warp_deployed_boot")
current_boot=$(tr -d '\r\n' </proc/sys/kernel/random/boot_id)
[[ "$deployed_boot" =~ ^[0-9a-f-]{36}$ ]]
[[ "$current_boot" =~ ^[0-9a-f-]{36}$ ]]
if ((require_reboot)); then [[ "$deployed_boot" != "$current_boot" ]]; fi
unset deployed_boot current_boot

# These connector gates are nondisruptive. The physical packet-capture and
# daemon-outage proofs remain separate maintenance-window checks because live
# DIRECT x-ui traffic legitimately uses the public interface; do not mistake it for a
# plaintext WARP escape.
for warp_test in test-smoke.sh test-main-route-isolation.sh test-e2e-local.sh test-invalid.sh; do
  [[ -x "$warp_tests/$warp_test" ]]
  "$warp_tests/$warp_test" >/dev/null
done

if [[ $TARGET_ADDRESS_MODE == domain ]]; then
for resolver in 1.1.1.1 9.9.9.9; do
  mapfile -t public_a < <(dig +time=5 +tries=2 +short "@$resolver" "$PUBLIC_FQDN" A \
    | sed '/^[[:space:]]*$/d' | sort -u)
  [[ "${#public_a[@]}" -eq 1 && "${public_a[0]}" == "$SERVER_IPV4" ]]
  mapfile -t public_aaaa < <(dig +time=5 +tries=2 +short "@$resolver" "$PUBLIC_FQDN" AAAA \
    | sed '/^[[:space:]]*$/d' | sort -u)
  [[ "${#public_aaaa[@]}" -eq 0 ]]
done
fi
unset resolver public_a public_aaaa

for unit in nginx.service x-ui.service certbot.timer krysyuk-warp-health.timer; do
  systemctl is-active --quiet "$unit"
  systemctl is-enabled --quiet "$unit"
done

main_pid=$(systemctl show -p MainPID --value x-ui.service)
[[ "$main_pid" =~ ^[1-9][0-9]*$ ]]
[[ "$(ps -o user= -p "$main_pid" | tr -d '[:space:]')" == xui ]]
xray_count=0
for candidate in $(pgrep -P "$main_pid"); do
  [[ "$(readlink -f -- "/proc/$candidate/exe" 2>/dev/null || true)" == "$xray" ]] || continue
  [[ "$(ps -o user= -p "$candidate" | tr -d '[:space:]')" == xui ]]
  ((xray_count += 1))
done
[[ "$xray_count" -eq 1 ]]

ss -H -lnt | grep_drain -E "127[.]0[.]0[.]1:${PANEL_PORT}[[:space:]]"
ss -H -lntp | grep_drain -E "${SERVER_IPV4}:${PANEL_PORT}[[:space:]].*nginx"
ss -H -lnt | grep_drain -E "${SERVER_IPV4}:443[[:space:]]"
ss -H -lnt | grep_drain -E "${SERVER_IPV4}:${SUBSCRIPTION_PORT}[[:space:]]"
ss -H -lnt | grep_drain -E "${SERVER_IPV4}:${XHTTP_PORT}[[:space:]]"
ss -H -lnu | grep_drain -E "${SERVER_IPV4}:443[[:space:]]"
for connector_port in 24443 24444; do
  ss -H -lnt | grep_drain -E "127[.]0[.]0[.]1:${connector_port}[[:space:]]"
  if ss -H -lnt | grep_drain -E "(${SERVER_IPV4}|0[.]0[.]0[.]0|[*]|\[::\]):${connector_port}[[:space:]]"; then
    exit 1
  fi
done
if ss -H -lnt | grep_drain -E "(0[.]0[.]0[.]0|[*]|\[::\]):${PANEL_PORT}[[:space:]]"; then
  exit 1
fi
if ss -H -lnt | grep_drain -E ':18080[[:space:]]'; then
  exit 1
fi

python3 "$(dirname -- "$promoted_verifier")/network-contract.py" \
  --target-ip "$TARGET_IPV4" --interface "$TARGET_INTERFACE" \
  --ssh-port "$TARGET_SSH_PORT" --promoted "$promoted_xhttp"

sqlite3 /etc/x-ui/x-ui.db 'PRAGMA quick_check;' | grep_drain -x ok
[[ "$(sqlite3 -readonly /etc/x-ui/x-ui.db 'select count(*) from clients;')" == 6 ]]
[[ "$(sqlite3 -readonly /etc/x-ui/x-ui.db 'select count(*) from client_inbounds;')" == 6 ]]
[[ "$(sqlite3 -readonly /etc/x-ui/x-ui.db 'select count(*) from client_external_links;')" == "$expected_external_count" ]]
mapfile -t committed_dual_backups < <(
  find "$backup_root" -mindepth 2 -maxdepth 2 -type f -name COMMITTED -printf '%h\n' \
    | grep -E '/[0-9]{8}T[0-9]{6}Z-dual-egress-[0-9]+$' | sort
)
[[ "${#committed_dual_backups[@]}" -ge 1 ]]
latest_dual_backup="${committed_dual_backups[$((${#committed_dual_backups[@]} - 1))]}"
for backup_file in "$latest_dual_backup/COMMITTED" "$latest_dual_backup/x-ui.db" \
  "$latest_dual_backup/server.env"; do
  [[ -f "$backup_file" && ! -L "$backup_file" ]]
  [[ "$(stat -c '%U:%G:%a' "$backup_file")" == 'root:root:600' ]]
done
sqlite3 "$latest_dual_backup/x-ui.db" 'PRAGMA quick_check;' | grep_drain -x ok
unset committed_dual_backups latest_dual_backup backup_file

XRAY_LOCATION_ASSET=/usr/local/x-ui/bin "$xray" run -test \
  -config /usr/local/x-ui/bin/config.json >/dev/null 2>&1
jq --exit-status --rawfile connector "$stage/connector.uuid" '
  def clean: rtrimstr("\n");
  ([.outbounds[] | select(.tag=="WARP_CF" and .protocol=="vless"
    and .settings.vnext==[{address:"127.0.0.1",port:24443,
      users:[{id:($connector|clean),encryption:"none"}]}]
    and .streamSettings.network=="raw" and .streamSettings.security=="none")]|length)==1
  and ([.. | strings | select(.==($connector|clean))]|length)==1
  and (.routing.rules|length)==8
  and .routing.rules[0].inboundTag==["api"] and .routing.rules[0].outboundTag=="api"
  and .routing.rules[1].protocol==["bittorrent"] and .routing.rules[1].outboundTag=="BLOCK"
  and .routing.rules[2].inboundTag==["dns_cf","dns_q9"] and .routing.rules[2].outboundTag=="DIRECT"
  and .routing.rules[3].ip==["geoip:private","::/0",(env.TARGET_IPV4+"/32")]
  and .routing.rules[3].outboundTag=="BLOCK"
  and .routing.rules[4].domain==[("full:"+env.PUBLIC_FQDN)]
  and .routing.rules[4].outboundTag=="BLOCK"
  and .routing.rules[5].user==["germany-warp-reality","germany-warp-hysteria2","germany-warp-xhttp"]
  and .routing.rules[5].outboundTag=="WARP_CF"
  and .routing.rules[6].user==["germany-reality","germany-hysteria2","germany-xhttp"]
  and .routing.rules[6].outboundTag=="DIRECT"
  and .routing.rules[7].network=="tcp,udp" and .routing.rules[7].outboundTag=="BLOCK"
  and (if env.PROMOTED_XHTTP=="1" then all(.inbounds[]; .port!=8443)
    else any(.inbounds[]; .port==8443 and .streamSettings.network=="xhttp"
      and .streamSettings.xhttpSettings.mode=="packet-up") end)
' /usr/local/x-ui/bin/config.json >/dev/null

verify_target_certificate "$runtime_root/tls/fullchain.pem"
nginx -t >/dev/null
[[ "$(stat -c '%U:%G:%a' /etc/nginx/conf.d/3x-ui-public.conf)" == 'root:root:600' ]]
[[ "$(stat -c '%U:%G:%a' /etc/letsencrypt/renewal-hooks/deploy/70-krysyuk-standalone-nginx)" == 'root:root:755' ]]
grep -Fq 'access_log off;' /etc/nginx/conf.d/3x-ui-public.conf
if find /var/log/nginx -maxdepth 1 -type f -name '*3x-ui*access*' -print -quit | grep_drain .; then
  exit 1
fi
printf '%s\n' "$PANEL_BASE_PATH" >"$stage/panel-path.pattern"
if grep -R -Fq -f "$stage/panel-path.pattern" /var/log/nginx 2>/dev/null; then
  exit 1
fi

token=$(tr -d '\r\n' <"$runtime_root/admin-api.token")
[[ "$token" =~ ^[A-Za-z0-9._-]{32,256}$ ]]
printf 'Authorization: Bearer %s\n' "$token" >"$stage/api.header"
unset token
api_url="http://127.0.0.1:${PANEL_PORT}/${PANEL_BASE_PATH}/panel/api"
curl --proto '=http' --fail --silent --show-error --max-time 30 \
  --header "@$stage/api.header" --header 'Host: localhost' \
  --header 'X-Requested-With: XMLHttpRequest' --output "$stage/inbounds.json" \
  "$api_url/inbounds/list"
curl --proto '=http' --fail --silent --show-error --max-time 30 \
  --header "@$stage/api.header" --header 'Host: localhost' \
  --header 'X-Requested-With: XMLHttpRequest' --output "$stage/hosts.json" \
  "$api_url/hosts/list"
curl --proto '=http' --fail --silent --show-error --max-time 30 \
  --header "@$stage/api.header" --header 'Host: localhost' \
  --header 'X-Requested-With: XMLHttpRequest' --output "$stage/external-links.json" \
  "$api_url/clients/get/germany-warp-reality"

jq --exit-status --arg fqdn "$PUBLIC_FQDN" --arg target "$REALITY_TARGET" \
  --rawfile public_sub "$stage/public-sub.id" --rawfile direct_sub "$stage/direct-sub.id" \
  --rawfile direct_vless "$stage/direct-vless.uuid" \
  --rawfile direct_hysteria "$stage/direct-hysteria.auth" \
  --rawfile warp_reality "$stage/warp-reality.uuid" \
  --rawfile warp_xhttp "$stage/warp-xhttp.uuid" \
  --rawfile warp_hysteria "$stage/warp-hysteria.auth" '
  def clean: rtrimstr("\n");
  ([.obj[]|select(.remark=="Germany VLESS REALITY TCP 443")]) as $rs
  | ([.obj[]|select(.remark=="Germany Hysteria2 UDP 443")]) as $hs
  | ([.obj[]|select(.remark=="Germany VLESS XHTTP TLS 8443")]) as $xs
  | .success==true and (.obj|length)==3 and ($rs|length)==1 and ($hs|length)==1 and ($xs|length)==1
  and all(.obj[]; .enable==(if .port==8443 and env.PROMOTED_XHTTP=="1" then false else true end)
    and .shareAddr==$fqdn and (.settings.clients|length)==2)
  and ($rs[0].subSortIndex==1 and $hs[0].subSortIndex==2 and $xs[0].subSortIndex==3)
  and ($rs[0].streamSettings.realitySettings.target==($target+":443")
    and $rs[0].streamSettings.realitySettings.serverNames==[$target])
  and ($rs[0].streamSettings.network=="grpc"
    and $rs[0].streamSettings.grpcSettings.serviceName=="reality-grpc"
    and ([ $rs[0].settings.clients[].flow ]|all(.=="" or .==null)))
  and ($hs[0].streamSettings.tlsSettings.serverName==$fqdn
    and $hs[0].streamSettings.tlsSettings.rejectUnknownSni==(env.TARGET_ADDRESS_MODE!="ip"))
  and ($xs[0].streamSettings.tlsSettings.serverName==$fqdn
    and $xs[0].streamSettings.tlsSettings.rejectUnknownSni==(env.TARGET_ADDRESS_MODE!="ip"))
  and ($rs[0].settings.clients[0].id==($warp_reality|clean)
    and $rs[0].settings.clients[0].email=="germany-warp-reality"
    and $rs[0].settings.clients[0].subId==($public_sub|clean)
    and $rs[0].settings.clients[0].comment==(env.TARGET_LABEL+" · ☁️ Cloudflare · REALITY"))
  and ($rs[0].settings.clients[1].id==($direct_vless|clean)
    and $rs[0].settings.clients[1].email=="germany-reality"
    and $rs[0].settings.clients[1].subId==($direct_sub|clean)
    and $rs[0].settings.clients[1].comment==(env.TARGET_LABEL+" · 🖥️ IP сервера · REALITY"))
  and ($hs[0].settings.clients[0].auth==($warp_hysteria|clean)
    and $hs[0].settings.clients[0].email=="germany-warp-hysteria2"
    and $hs[0].settings.clients[0].subId==($public_sub|clean)
    and $hs[0].settings.clients[0].comment==(env.TARGET_LABEL+" · ☁️ Cloudflare · HYSTERIA2"))
  and ($hs[0].settings.clients[1].auth==($direct_hysteria|clean)
    and $hs[0].settings.clients[1].email=="germany-hysteria2"
    and $hs[0].settings.clients[1].subId==($direct_sub|clean)
    and $hs[0].settings.clients[1].comment==(env.TARGET_LABEL+" · 🖥️ IP сервера · HYSTERIA2"))
  and ($xs[0].settings.clients[0].id==($warp_xhttp|clean)
    and $xs[0].settings.clients[0].email=="germany-warp-xhttp"
    and $xs[0].settings.clients[0].subId==($public_sub|clean)
    and $xs[0].settings.clients[0].comment==(env.TARGET_LABEL+" · ☁️ Cloudflare · XHTTP"))
  and ($xs[0].settings.clients[1].id==($direct_vless|clean)
    and $xs[0].settings.clients[1].email=="germany-xhttp"
    and $xs[0].settings.clients[1].subId==($direct_sub|clean)
    and $xs[0].settings.clients[1].comment==(env.TARGET_LABEL+" · 🖥️ IP сервера · XHTTP"))
' "$stage/inbounds.json" >/dev/null

jq --exit-status --arg fqdn "$PUBLIC_FQDN" --arg target "$REALITY_TARGET" \
  --rawfile xhttp_path "$stage/xhttp.path" '
  def clean: rtrimstr("\n");
  ([.obj[]|select(.security=="reality")]) as $rs
  | ([.obj[]|select(.security=="tls" and .port==8443)]) as $xs
  | ([.obj[]|select(.security=="tls" and .port==443)]) as $hs
  | .success==true and (.obj|length)==3 and ($rs|length)==1 and ($xs|length)==1 and ($hs|length)==1
  and ($rs[0].hosts==[($fqdn+":443")] and $rs[0].sni==$target and $rs[0].alpn==[])
  and ($xs[0].hosts==[($fqdn+":8443")] and $xs[0].sni==$fqdn
    and $xs[0].path==("/"+($xhttp_path|clean)) and $xs[0].hostHeader==$fqdn and $xs[0].alpn==["h2"])
  and ($hs[0].hosts==[($fqdn+":443")] and $hs[0].sni==$fqdn and $hs[0].alpn==["h3"])
  and all(.obj[]; .isDisabled==false)
' "$stage/hosts.json" >/dev/null

if ((promoted_xhttp)); then
  python3 -B "$promoted_verifier" --verify
else
jq --exit-status '
  .success==true and (.obj.externalLinks|length)==3
  and [.obj.externalLinks[].sortIndex]==[0,1,2]
  and [.obj.externalLinks[].remark]==[
    (env.TARGET_LABEL+" · 🖥️ IP сервера · REALITY"),
    (env.TARGET_LABEL+" · 🖥️ IP сервера · HYSTERIA2"),
    (env.TARGET_LABEL+" · 🖥️ IP сервера · XHTTP")
  ]
  and all(.obj.externalLinks[]; .kind=="link" and .enable==true and .expiryTime==0)
  and ([.obj.externalLinks[].value]|unique|length)==3
' "$stage/external-links.json" >/dev/null
fi

subscription_url="https://${PUBLIC_FQDN}:${SUBSCRIPTION_PORT}/${SUBSCRIPTION_PATH}/$(<"$stage/public-sub.id")"
for subscription_ua in v2RayTun Happ Karing; do
curl --proto '=https' --tlsv1.2 --fail --silent --show-error --max-time 30 \
  --user-agent "$subscription_ua" --resolve "${PUBLIC_FQDN}:${SUBSCRIPTION_PORT}:${SERVER_IPV4}" \
  --output "$stage/subscription" "$subscription_url"
if ((promoted_xhttp)); then
  : # finalize-xhttp --verify above validates exact subscription bytes for all three UAs.
else
SUB_BODY="$stage/subscription" SECRET_DIR="$stage" CHECK_FQDN="$PUBLIC_FQDN" \
  CHECK_TARGET="$REALITY_TARGET" python3 - <<'PY'
import base64
import json
import os
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

root = Path(os.environ["SECRET_DIR"])
def secret(name):
    return root.joinpath(name).read_text(encoding="utf-8").strip()

raw = Path(os.environ["SUB_BODY"]).read_bytes().strip()
text = raw.decode("utf-8", "strict")
if "://" not in text:
    padded = raw + b"=" * ((4 - len(raw) % 4) % 4)
    text = base64.urlsafe_b64decode(padded).decode("utf-8", "strict")
all_links = [line.strip() for line in text.splitlines() if line.strip()]
links = [
    link for link in all_links
    if link.startswith(("vless://", "hysteria2://", "hy2://"))
]
routing_links = [link for link in all_links if link not in links]
if len(links) != 6 or len(set(links)) != 6:
    raise SystemExit("subscription is not exact unique 6")
if len(routing_links) not in (0, 3) or (routing_links and [urlparse(link).scheme for link in routing_links] != [
    "routing",
    "happ",
    "incy",
]):
    raise SystemExit("subscription client-routing directives mismatch")
if all_links[:6] != links or len(all_links) not in (6, 9):
    raise SystemExit("VPN profiles must precede optional client directives")
items = [urlparse(link) for link in links]
names = [
    os.environ["TARGET_LABEL"] + " · ☁️ Cloudflare · REALITY",
    os.environ["TARGET_LABEL"] + " · ☁️ Cloudflare · HYSTERIA2",
    os.environ["TARGET_LABEL"] + " · ☁️ Cloudflare · XHTTP",
    os.environ["TARGET_LABEL"] + " · 🖥️ IP сервера · REALITY",
    os.environ["TARGET_LABEL"] + " · 🖥️ IP сервера · HYSTERIA2",
    os.environ["TARGET_LABEL"] + " · 🖥️ IP сервера · XHTTP",
]
if [unquote(item.fragment) for item in items] != names:
    raise SystemExit("subscription display order mismatch")
if any(item.hostname != os.environ["CHECK_FQDN"] for item in items):
    raise SystemExit("subscription address mismatch")
expected = [
    ("vless", 443, secret("warp-reality.uuid"), "reality"),
    ("hysteria2", 443, secret("warp-hysteria.auth"), "hysteria2"),
    ("vless", 8443, secret("warp-xhttp.uuid"), "xhttp"),
    ("vless", 443, secret("direct-vless.uuid"), "reality"),
    ("hysteria2", 443, secret("direct-hysteria.auth"), "hysteria2"),
    ("vless", 8443, secret("direct-vless.uuid"), "xhttp"),
]
for item, (scheme, port, identity, transport) in zip(items, expected):
    if item.scheme != scheme or item.port != port or item.username != identity:
        raise SystemExit("subscription identity or transport order mismatch")
    query = parse_qs(item.query)
    if transport == "reality":
        if query.get("security") != ["reality"] or query.get("sni") != [os.environ["CHECK_TARGET"]]:
            raise SystemExit("Reality security or SNI mismatch")
        if query.get("pbk") != [secret("reality-public.key")] or query.get("sid") != [secret("reality-short.id")]:
            raise SystemExit("Reality public parameter mismatch")
        if query.get("type") != ["grpc"] or query.get("serviceName") != ["reality-grpc"]:
            raise SystemExit("Reality gRPC transport mismatch")
        if any(query.get("flow", [""])):
            raise SystemExit("Reality gRPC must not advertise Vision flow")
    elif transport == "xhttp":
        if query.get("security") != ["tls"] or query.get("type") != ["xhttp"]:
            raise SystemExit("XHTTP transport mismatch")
        if query.get("sni") != [os.environ["CHECK_FQDN"]] or query.get("alpn") != ["h2"]:
            raise SystemExit("XHTTP TLS/H2 mismatch")
        if query.get("host") != [os.environ["CHECK_FQDN"]] or query.get("path") != ["/" + secret("xhttp.path")]:
            raise SystemExit("XHTTP host or path mismatch")
        if query.get("mode") != ["packet-up"]:
            raise SystemExit("XHTTP mode mismatch")
        if "extra" in query:
            extra = json.loads(query["extra"][0])
            if not isinstance(extra, dict) or extra.get("mode", "packet-up") != "packet-up":
                raise SystemExit("XHTTP extra.mode mismatch")
    else:
        if query.get("sni") != [os.environ["CHECK_FQDN"]] or query.get("alpn") != ["h3"]:
            raise SystemExit("Hysteria2 TLS/H3 mismatch")
        if query.get("insecure", ["0"])[0].lower() in {"1", "true", "yes"}:
            raise SystemExit("Hysteria2 certificate verification is disabled")
for forbidden in (secret("connector.uuid"), secret("direct-sub.id"), "127.0.0.1", "169.254.254.", ":24443", ":24444"):
    if forbidden in text:
        raise SystemExit("private connector material leaked into subscription")
PY
fi
printf 'SUBSCRIPTION_UA=%s PROFILES=6 ORDER=PASS\n' "$subscription_ua"
done
unset subscription_ua

panel_url="https://${PUBLIC_FQDN}:${PANEL_PORT}/${PANEL_BASE_PATH}/"
panel_status=$(curl --proto '=https' --tlsv1.2 --silent --show-error --max-time 30 \
  --resolve "${PUBLIC_FQDN}:${PANEL_PORT}:${SERVER_IPV4}" \
  --output /dev/null --write-out '%{http_code}' "$panel_url")
[[ "$panel_status" == 200 || "$panel_status" == 302 ]]
root_status=$(curl --proto '=https' --tlsv1.2 --silent --show-error --max-time 30 \
  --resolve "${PUBLIC_FQDN}:${PANEL_PORT}:${SERVER_IPV4}" \
  --output /dev/null --write-out '%{http_code}' \
  "https://${PUBLIC_FQDN}:${PANEL_PORT}/")
[[ "$root_status" == 404 ]]
printf 'PANEL_URL=%s\n' "$panel_url" >"$stage/panel-url.pattern"
grep -Fxq -f "$stage/panel-url.pattern" "$runtime_root/access.env"
unset panel_status root_status panel_url subscription_url api_url PANEL_BASE_PATH SUBSCRIPTION_PATH

bash "$(dirname -- "${BASH_SOURCE[0]}")/panel-login-acceptance.sh" >/dev/null
if ((require_reboot)); then
  printf 'POSTBOOT_REAL_REBOOT_SEEN=1\n'
else
  printf 'REBOOT_ACCEPTANCE_PENDING=1\n'
fi
printf 'POSTBOOT_WARP_NONDISRUPTIVE_OK=1\n'
printf 'POSTBOOT_DUAL_EGRESS_OK=1\n'
printf 'POSTBOOT_VERIFY_OK=1\n'
