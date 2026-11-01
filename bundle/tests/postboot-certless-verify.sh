#!/usr/bin/env bash
# Four REALITY profiles, HTTP management plane, no local TLS certificate.
set -Eeuo pipefail
umask 077
source "$(cd -- "$(dirname -- "$0")/../scripts" && pwd -P)/target-contract.sh"
[[ $TARGET_TLS_MODE == none && $TARGET_PUBLIC_SCHEME == http &&
   $TARGET_PROTOCOL_COUNT == 2 && $TARGET_PROFILE_COUNT == 4 ]] || exit 1
require_reboot=1
argument=''
if (($#)); then argument=$1; fi
case $argument in --live) require_reboot=0;; '') ;; *) exit 2;; esac
readonly runtime_root=/etc/krysyuk-standalone
readonly connector_env=/etc/krysyuk-warp-egress/warp-egress-nl-client.env
readonly warp_deployed_boot=/var/lib/krysyuk-warp-egress/deployed-boot-id
readonly scripts="$(cd -- "$(dirname -- "$0")/../scripts" && pwd -P)"
readonly xray=/usr/local/x-ui/bin/xray-linux-amd64
stage=$(mktemp -d -p /run standalone-postboot-none.XXXXXXXX)
cleanup() {
  local status=$?
  trap - EXIT INT TERM HUP
  rm -rf -- "$stage"
  exit "$status"
}
trap cleanup EXIT
trap 'status=$?; printf "POSTBOOT_CERTLESS_FAIL_LINE=%s STATUS=%s\n" "$LINENO" "$status" >&2; exit "$status"' ERR
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP
[[ $EUID == 0 ]]
grep -Fxq 'ID=ubuntu' /etc/os-release
grep -Fxq 'VERSION_ID="24.04"' /etc/os-release
[[ $(uname -m) == x86_64 ]]
[[ $(/usr/local/x-ui/x-ui -v 2>&1) == 3.7.0 ]]
printf '%s  %s\n' '64d46afb80adea1bf97a0d467e83f4a9ac1ebd0995891e84bca3f1a1d1affb1d' "$xray" |
  sha256sum --check --strict - >/dev/null
for file in "$runtime_root/server.env" "$runtime_root/admin-api.token" \
  "$runtime_root/access.env" "$connector_env" "$warp_deployed_boot"; do
  [[ -f $file && ! -L $file && $(stat -c '%U:%G:%a' "$file") == root:root:600 ]]
done
source "$runtime_root/server.env"
source "$connector_env"
[[ $DUAL_EGRESS_SCHEMA == 1 && $TARGET_TLS_MODE == none ]]
[[ $PANEL_BASE_PATH =~ ^[A-Za-z0-9_-]{16,128}$ &&
   $SUBSCRIPTION_PATH =~ ^[A-Za-z0-9_-]{16,128}$ ]]
[[ $HYSTERIA2_AUTH == '' && $WARP_HYSTERIA2_AUTH == '' ]]
[[ -f /etc/germanyvpn-xhttp-test/promotion.json &&
   ! -L /etc/germanyvpn-xhttp-test/promotion.json ]]
for unit in nginx.service x-ui.service krysyuk-warp-health.timer; do
  systemctl is-active --quiet "$unit"
  systemctl is-enabled --quiet "$unit"
done
for unit in certbot.timer certbot.service vpn-cert-reconcile.timer vpn-cert-reconcile.service; do
  ! systemctl is-active --quiet "$unit"
  ! systemctl is-enabled --quiet "$unit"
done
[[ ! -e /opt/vpn-certbot && ! -L /opt/vpn-certbot &&
   ! -e /usr/local/bin/certbot && ! -L /usr/local/bin/certbot &&
   ! -e /etc/letsencrypt && ! -L /etc/letsencrypt ]]
if [[ -d $runtime_root/tls ]]; then
  [[ -z $(find "$runtime_root/tls" -mindepth 1 -print -quit) ]]
fi
deployed_boot=$(tr -d '\r\n' <"$warp_deployed_boot")
current_boot=$(tr -d '\r\n' </proc/sys/kernel/random/boot_id)
[[ $deployed_boot =~ ^[0-9a-f-]{36}$ && $current_boot =~ ^[0-9a-f-]{36}$ ]]
if ((require_reboot)); then [[ $deployed_boot != "$current_boot" ]]; fi
for warp_test in test-smoke.sh test-main-route-isolation.sh test-e2e-local.sh test-invalid.sh; do
  "/opt/krysyuk-warp-egress/tests/$warp_test" >/dev/null
done
if [[ $TARGET_ADDRESS_MODE == domain ]]; then
  for resolver in 1.1.1.1 9.9.9.9; do
    [[ $(dig +time=5 +tries=2 +short "@$resolver" "$TARGET_FQDN" A) == "$TARGET_IPV4" ]]
    [[ -z $(dig +time=5 +tries=2 +short "@$resolver" "$TARGET_FQDN" AAAA) ]]
  done
fi
main_pid=$(systemctl show -p MainPID --value x-ui.service)
[[ $main_pid =~ ^[1-9][0-9]*$ && $(ps -o user= -p "$main_pid" | tr -d '[:space:]') == xui ]]
xray_count=0
for candidate in $(pgrep -P "$main_pid"); do
  [[ $(readlink -f -- "/proc/$candidate/exe" 2>/dev/null || true) == "$xray" ]] || continue
  [[ $(ps -o user= -p "$candidate" | tr -d '[:space:]') == xui ]]
  ((xray_count += 1))
done
[[ $xray_count == 1 ]]
python3 "$scripts/network-contract.py" --target-ip "$TARGET_IPV4" --interface "$TARGET_INTERFACE" \
  --ssh-port "$TARGET_SSH_PORT" --promoted 1 --tls-mode none
[[ $(sqlite3 -readonly /etc/x-ui/x-ui.db 'PRAGMA quick_check;') == ok ]]
[[ $(sqlite3 -readonly /etc/x-ui/x-ui.db 'select count(*) from clients;') == 4 ]]
[[ $(sqlite3 -readonly /etc/x-ui/x-ui.db 'select count(*) from client_inbounds;') == 4 ]]
[[ $(sqlite3 -readonly /etc/x-ui/x-ui.db 'select count(*) from client_external_links;') == 3 ]]
[[ $(sqlite3 -readonly /etc/x-ui/x-ui.db "select count(*) from inbounds where protocol in ('hysteria','hysteria2');") == 0 ]]
latest_dual_backup=$(
  find /var/backups/krysyuk-standalone -mindepth 2 -maxdepth 2 -type f -name COMMITTED -printf '%h\n' |
    grep -E '/[0-9]{8}T[0-9]{6}Z-dual-egress-[0-9]+$' | sort | tail -n 1
)
[[ -n $latest_dual_backup ]]
for file in "$latest_dual_backup/COMMITTED" "$latest_dual_backup/x-ui.db" "$latest_dual_backup/server.env"; do
  [[ -f $file && ! -L $file && $(stat -c '%U:%G:%a' "$file") == root:root:600 ]]
done
[[ $(sqlite3 -readonly "$latest_dual_backup/x-ui.db" 'PRAGMA quick_check;') == ok ]]
XRAY_LOCATION_ASSET=/usr/local/x-ui/bin "$xray" run -test -config /usr/local/x-ui/bin/config.json >/dev/null 2>&1
nginx -t >/dev/null
[[ $(stat -c '%U:%G:%a' /etc/nginx/conf.d/3x-ui-public.conf) == root:root:600 ]]
grep -Fq 'access_log off;' /etc/nginx/conf.d/3x-ui-public.conf
if grep -Eq '^[[:space:]]*ssl_|listen[^;]*[[:space:]]ssl[[:space:];]' /etc/nginx/conf.d/3x-ui-public.conf; then exit 1; fi

write_secret() { printf '%s\n' "$2" >"$stage/$1"; chmod 0600 "$stage/$1"; }
write_secret direct-vless.uuid "$VLESS_UUID"
write_secret warp-reality.uuid "$WARP_REALITY_UUID"
write_secret warp-xhttp.uuid "$WARP_XHTTP_UUID"
write_secret public-sub.id "$SUBSCRIPTION_ID"
write_secret direct-sub.id "$DIRECT_SUBSCRIPTION_ID"
write_secret connector.uuid "$WARP_EGRESS_CLIENT_ID"
token=$(tr -d '\r\n' <"$runtime_root/admin-api.token")
[[ $token =~ ^[A-Za-z0-9._-]{32,256}$ ]]
printf 'Authorization: Bearer %s\n' "$token" >"$stage/api.header"
unset token PANEL_USERNAME PANEL_PASSWORD REALITY_PRIVATE_KEY
unset VLESS_UUID WARP_REALITY_UUID WARP_XHTTP_UUID SUBSCRIPTION_ID DIRECT_SUBSCRIPTION_ID WARP_EGRESS_CLIENT_ID
api_base="http://127.0.0.1:2053/$PANEL_BASE_PATH/panel/api"
fetch_api() {
  printf 'url = "%s/%s"\n' "$api_base" "$1" >"$stage/request.conf"
  curl --noproxy '*' --proxy '' --proto '=http' --fail --silent --show-error --max-time 30 \
    --config "$stage/request.conf" --header "@$stage/api.header" --header 'Host: localhost' \
    --header 'X-Requested-With: XMLHttpRequest' --output "$stage/$2"
}
fetch_api inbounds/list inbounds.json
fetch_api hosts/list hosts.json
CONTRACT_STAGE="$stage" python3 - <<'PY'
import json,os
from pathlib import Path

root=Path(os.environ['CONTRACT_STAGE'])
def need(value,code):
    if not value: raise SystemExit(code)
def secret(name): return (root/name).read_text().strip()
def response(name):
    value=json.loads((root/name).read_bytes())
    need(value.get('success') is True and isinstance(value.get('obj'),list),'CERTLESS_API_RESPONSE')
    return value['obj']
def clients(row):
    value=row['settings']
    if isinstance(value,str): value=json.loads(value)
    return value['clients']
def stream(row):
    value=row.get('streamSettings',{})
    return json.loads(value) if isinstance(value,str) else value
source=response('inbounds.json')
hosts=response('hosts.json')
need(len(source)==2 and {row['port'] for row in source}=={443,8443},'CERTLESS_SOURCE_INBOUNDS')
need(all(row.get('protocol')=='vless' and len(clients(row))==2 for row in source),'CERTLESS_SOURCE_PROTOCOLS')
need(all(stream(row).get('security')=='reality' for row in source),'CERTLESS_SOURCE_SECURITY')
need(all(row.get('shareAddr')==os.environ['TARGET_FQDN'] for row in source),'CERTLESS_SOURCE_ADDRESS')
for row in source:
    settings=stream(row)
    target=settings.get('realitySettings',{})
    need(target.get('target',target.get('dest'))==os.environ['TARGET_REALITY_SNI']+':443'
         and target.get('serverNames')==[os.environ['TARGET_REALITY_SNI']],'CERTLESS_SOURCE_SNI')
    protocol='reality' if row['port']==443 else 'xhttp'
    need(bool(row.get('enable'))==(row['port']==443),'CERTLESS_SOURCE_ENABLEMENT')
    expected=[('germany-warp-'+protocol,secret('warp-'+protocol+'.uuid'),secret('public-sub.id')),
              ('germany-'+protocol,secret('direct-vless.uuid'),secret('direct-sub.id'))]
    for client,(email,identity,subscription) in zip(clients(row),expected):
        need(client.get('email')==email and client.get('id')==identity and client.get('subId')==subscription,
             'CERTLESS_SOURCE_CLIENTS')
        need(client.get('limitIp')==int(os.environ['TARGET_DEVICE_LIMIT'])
             and not client.get('flow'),'CERTLESS_SOURCE_CLIENT_POLICY')
need(len(hosts)==2 and {host['port'] for host in hosts}=={443,8443},'CERTLESS_HOSTS')
need(all(host.get('security')=='reality' and host.get('sni')==os.environ['TARGET_REALITY_SNI']
         and host.get('isDisabled') is False for host in hosts),'CERTLESS_HOST_SECURITY')
runtime=json.loads(Path('/usr/local/x-ui/bin/config.json').read_bytes())
public=[row for row in runtime['inbounds'] if row.get('port')==443]
need(len(public)==1 and public[0].get('protocol')=='vless'
     and stream(public[0]).get('security')=='reality','CERTLESS_RUNTIME_REALITY')
need(all(row.get('protocol') not in ('hysteria','hysteria2') and stream(row).get('security')!='tls'
         for row in runtime['inbounds']),'CERTLESS_RUNTIME_NO_TLS')
rules=runtime['routing']['rules']
need(len(rules)==8
     and rules[0].get('inboundTag')==['api'] and rules[0].get('outboundTag')=='api'
     and rules[1].get('protocol')==['bittorrent'] and rules[1].get('outboundTag')=='BLOCK'
     and rules[2].get('inboundTag')==['dns_cf','dns_q9'] and rules[2].get('outboundTag')=='DIRECT'
     and rules[3].get('ip')==['geoip:private','::/0',os.environ['TARGET_IPV4']+'/32']
     and rules[3].get('outboundTag')=='BLOCK'
     and rules[4].get('domain')==['full:'+os.environ['TARGET_FQDN']]
     and rules[4].get('outboundTag')=='BLOCK'
     and rules[5].get('user')==['germany-warp-reality','germany-warp-xhttp']
     and rules[5].get('outboundTag')=='WARP_CF'
     and rules[6].get('user')==['germany-reality','germany-xhttp']
     and rules[6].get('outboundTag')=='DIRECT'
     and rules[7].get('network')=='tcp,udp' and rules[7].get('outboundTag')=='BLOCK',
     'CERTLESS_RUNTIME_ROUTING')
connectors=[row for row in runtime['outbounds'] if row.get('tag')=='WARP_CF']
need(len(connectors)==1 and connectors[0].get('protocol')=='vless'
     and connectors[0]['settings']['vnext']==[{'address':'127.0.0.1','port':24443,
     'users':[{'id':secret('connector.uuid'),'encryption':'none'}]}],'CERTLESS_WARP_CONNECTOR')
PY

# This verifier builds clients only from the actual public four-profile feed.
# It checks independent WARP/direct payload egress and REALITY XHTTP settings.
python3 -B "$scripts/finalize-xhttp.py" --verify
bash "$(dirname -- "$0")/panel-login-acceptance.sh" >/dev/null
source "$runtime_root/access.env"
[[ $PANEL_URL == "http://$TARGET_FQDN:2053/$PANEL_BASE_PATH/" &&
   $SUBSCRIPTION_URL == "http://$TARGET_FQDN:2096/$SUBSCRIPTION_PATH/$(<"$stage/public-sub.id")" ]]
printf 'url = "http://%s:2053/"\n' "$TARGET_FQDN" >"$stage/root-request.conf"
root_status=$(curl --noproxy '*' --proxy '' --proto '=http' --silent --show-error --max-time 30 \
  --resolve "$TARGET_FQDN:2053:$TARGET_IPV4" --config "$stage/root-request.conf" \
  --output /dev/null --write-out '%{http_code}')
[[ $root_status == 404 ]]
if find /var/log/nginx -maxdepth 1 -type f -name '*3x-ui*access*' -print -quit | grep . >/dev/null; then exit 1; fi
printf '%s\n' "$PANEL_BASE_PATH" >"$stage/panel-path.pattern"
if grep -R -Fq -f "$stage/panel-path.pattern" /var/log/nginx 2>/dev/null; then exit 1; fi
if ((require_reboot)); then printf 'POSTBOOT_REAL_REBOOT_SEEN=1\n'
else printf 'REBOOT_ACCEPTANCE_PENDING=1\n'; fi
printf 'POSTBOOT_PROFILE_COUNT=4\nPOSTBOOT_CERTIFICATE_MODE=NONE\n'
printf 'POSTBOOT_WARP_NONDISRUPTIVE_OK=1\nPOSTBOOT_DUAL_EGRESS_OK=1\nPOSTBOOT_VERIFY_OK=1\n'
