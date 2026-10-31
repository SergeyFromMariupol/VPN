#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
# shellcheck source=../scripts/target-contract.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../scripts" && pwd -P)/target-contract.sh"

readonly SERVER_IPV4="$TARGET_IPV4"
readonly PUBLIC_FQDN="$TARGET_FQDN"
readonly PUBLIC_INTERFACE="$TARGET_INTERFACE"
readonly PANEL_PORT='2053'
readonly runtime_root='/etc/krysyuk-standalone'
readonly runtime_env="$runtime_root/server.env"
readonly access_file="$runtime_root/access.env"
readonly tls_fullchain="$runtime_root/tls/fullchain.pem"
readonly tls_private_key="$runtime_root/tls/privkey.pem"
readonly nginx_config='/etc/nginx/conf.d/3x-ui-public.conf'
readonly nginx_default='/etc/nginx/sites-enabled/default'
readonly renew_hook='/etc/letsencrypt/renewal-hooks/deploy/70-krysyuk-standalone-nginx'
readonly backup_root='/var/backups/krysyuk-standalone'

mode='check'

usage() {
  cat <<'EOF'
Usage:
  expose-panel-https.sh --check-only
  expose-panel-https.sh --apply

Publishes the existing loopback-only 3X-UI backend through an HTTPS nginx
listener on the explicit target FQDN at TCP/2053. Only the private panel base path is
proxied; other paths return 404. POST requests and concurrent connections are
rate-limited per source address.
EOF
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

while (($#)); do
  case "$1" in
    --check-only) mode='check' ;;
    --apply) mode='apply' ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
  shift
done

[[ "$EUID" -eq 0 ]] || die 'root is required'
for command_name in awk cp curl date dirname dpkg-query find grep install ip \
  mktemp nft nginx openssl python3 rm sed sha256sum sqlite3 ss stat systemctl tar ufw; do
  command -v "$command_name" >/dev/null 2>&1 || die "missing command: $command_name"
done

[[ -f "$runtime_env" && ! -L "$runtime_env" ]] || die 'server.env is missing or unsafe'
[[ -f "$access_file" && ! -L "$access_file" ]] || die 'access.env is missing or unsafe'
# shellcheck disable=SC1090
source "$runtime_env"
[[ "${PANEL_BASE_PATH:-}" =~ ^[A-Za-z0-9_-]{16,128}$ ]] || die 'panel base path is invalid'

[[ -f "$tls_fullchain" && ! -L "$tls_fullchain" ]] || die 'TLS full chain is missing or unsafe'
[[ -f "$tls_private_key" && ! -L "$tls_private_key" ]] || die 'TLS private key is missing or unsafe'
[[ "$(stat -c '%U:%G:%a' "$tls_private_key")" == 'root:xui-secrets:640' ]] ||
  die 'unexpected TLS private-key ownership or mode'
verify_target_certificate "$tls_fullchain" ||
  die 'TLS certificate is invalid, expires within 24 hours or does not cover the public endpoint'
cert_pub=$(openssl x509 -in "$tls_fullchain" -pubkey -noout | openssl sha256)
key_pub=$(openssl pkey -in "$tls_private_key" -pubout | openssl sha256)
[[ "$cert_pub" == "$key_pub" ]] || die 'TLS certificate/private-key mismatch'
unset cert_pub key_pub

systemctl is-active --quiet x-ui.service || die 'x-ui is not active'
systemctl is-enabled --quiet x-ui.service || die 'x-ui is not enabled'
ip -4 -o address show dev "$PUBLIC_INTERFACE" scope global | grep -Fq " $SERVER_IPV4/" ||
  die 'public IPv4 is not assigned to the expected interface'
ss -H -lnt | grep -Eq "127[.]0[.]0[.]1:${PANEL_PORT}[[:space:]]" ||
  die '3X-UI backend is not loopback-only on TCP/2053'
if ss -H -lnt | grep -Eq "${SERVER_IPV4}:${PANEL_PORT}[[:space:]]"; then
  die 'public TCP/2053 is already occupied'
fi
if ufw status | grep -Eq "(^|[[:space:]])${PANEL_PORT}(/tcp)?([[:space:]]|$).*ALLOW"; then
  die 'UFW already permits TCP/2053; reviewed merge required'
fi
[[ "$(ufw status | sed -n '1p')" == 'Status: active' ]] || die 'UFW is not active'

backend_status=$(curl --proto '=http' --silent --show-error --max-time 15 \
  --output /dev/null --write-out '%{http_code}' \
  "http://127.0.0.1:${PANEL_PORT}/${PANEL_BASE_PATH}/")
[[ "$backend_status" == 200 || "$backend_status" == 302 ]] ||
  die "unexpected loopback panel HTTP status: $backend_status"
unset backend_status

bundle_root=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
nginx_template="$bundle_root/templates/3x-ui-public.nginx.conf"
renew_hook_source="$bundle_root/templates/70-krysyuk-standalone-nginx"
[[ -f "$nginx_template" && ! -L "$nginx_template" ]] || die 'nginx template is missing or unsafe'
[[ -f "$renew_hook_source" && ! -L "$renew_hook_source" ]] || die 'renewal hook is missing or unsafe'

dpkg-query -W -f='${db:Status-Status}' nginx 2>/dev/null | grep -qx installed ||
  die 'base/install-pinned-base.sh must install nginx first'
[[ -z $(find /etc/nginx/conf.d /etc/nginx/sites-enabled -mindepth 1 -maxdepth 1 -print -quit) ]] ||
  die 'nginx contains enabled sites/configs; reviewed merge required'
! systemctl is-active --quiet nginx.service || die 'nginx must be stopped before panel transaction'
if [[ "$mode" == check ]]; then
  [[ ! -e "$nginx_config" ]] || die 'managed nginx config already exists'
  [[ ! -e "$renew_hook" ]] || die 'managed renewal hook already exists'
  printf 'PANEL_HTTPS_PREFLIGHT_OK=1\n'
  printf 'No changes made.\n'
  exit 0
fi

[[ ! -e "$nginx_config" ]] || die 'managed nginx config already exists'
[[ ! -e "$renew_hook" ]] || die 'managed renewal hook already exists'

stamp=$(date -u +%Y%m%dT%H%M%SZ)
backup="$backup_root/${stamp}-panel-public-https"
install -d -o root -g root -m 0700 "$backup"
cp -a /etc/ufw/user.rules "$backup/ufw.user.rules"
cp -a /etc/ufw/user6.rules "$backup/ufw.user6.rules"
cp -a "$access_file" "$backup/access.env"
tar --acls --xattrs --numeric-owner -cpf "$backup/nginx-before.tar" -C / etc/nginx
tar -tf "$backup/nginx-before.tar" >/dev/null
tar --acls --xattrs --numeric-owner -cpf "$backup/xui-before.tar" -C / \
  etc/x-ui usr/local/x-ui etc/krysyuk-standalone etc/letsencrypt etc/systemd/system
tar -tf "$backup/xui-before.tar" >/dev/null
systemctl is-enabled nginx.service >"$backup/nginx-enabled-before.txt" 2>/dev/null || true
nft -s list ruleset >"$backup/nft-before.txt"
sqlite3 /etc/x-ui/x-ui.db ".backup '$backup/x-ui.db'"
chmod 0600 "$backup/x-ui.db"
sqlite3 "$backup/x-ui.db" 'PRAGMA quick_check;' | grep -qx ok || die 'SQLite snapshot failed'
(
  cd "$backup"
  sha256sum access.env ufw.user.rules ufw.user6.rules x-ui.db nginx-before.tar xui-before.tar nft-before.txt >SHA256SUMS
  sha256sum -c SHA256SUMS >/dev/null
)
printf 'SNAPSHOT=%s\n' "$backup"

stage=$(mktemp -d -p /run panel-public.XXXXXXXX)
committed=0
failure_line='unknown'
transaction_exit() {
  local status=$?
  trap - EXIT INT TERM HUP
  rm -rf -- "$stage" >/dev/null 2>&1 || true
  if ((status != 0 && committed == 0)); then
    printf 'Public panel transaction failed at line %s; restoring snapshot.\n' "$failure_line" >&2
    systemctl disable --now nginx.service >/dev/null 2>&1 || true
    rm -f -- "$renew_hook" "$nginx_config"
    install -o root -g root -m 0600 "$backup/access.env" "$access_file"
    install -o root -g root -m 0640 "$backup/ufw.user.rules" /etc/ufw/user.rules
    install -o root -g root -m 0640 "$backup/ufw.user6.rules" /etc/ufw/user6.rules
    ufw reload >/dev/null 2>&1 || true
    systemctl unmask nginx.service >/dev/null 2>&1 || true
    tar --acls --xattrs --numeric-owner -xpf "$backup/nginx-before.tar" -C /
    if grep -Fxq enabled "$backup/nginx-enabled-before.txt"; then systemctl enable nginx.service >/dev/null 2>&1 || true; fi
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap 'failure_line=$LINENO' ERR
trap transaction_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

PANEL_BASE_PATH="$PANEL_BASE_PATH" NGINX_TEMPLATE="$nginx_template" \
  NGINX_RENDERED="$stage/3x-ui-public.conf" python3 - <<'PY'
import os
from pathlib import Path
text = Path(os.environ['NGINX_TEMPLATE']).read_text()
for key,value in {
    '__SERVER_IPV4__':os.environ['TARGET_IPV4'], '__PUBLIC_FQDN__':os.environ['TARGET_FQDN'],
    '__PANEL_BASE_PATH__':os.environ['PANEL_BASE_PATH']
}.items():
    text=text.replace(key,value)
Path(os.environ['NGINX_RENDERED']).write_text(text)
PY
grep -Fq '__' "$stage/3x-ui-public.conf" && die 'unresolved nginx template placeholder'
install -o root -g root -m 0600 "$stage/3x-ui-public.conf" "$nginx_config"
install -o root -g root -m 0755 "$renew_hook_source" "$renew_hook"
nginx -t

systemctl unmask nginx.service >/dev/null
systemctl enable --now nginx.service
systemctl is-active --quiet nginx.service
systemctl is-enabled --quiet nginx.service

ufw allow in on "$PUBLIC_INTERFACE" to "$SERVER_IPV4" port "$PANEL_PORT" \
  proto tcp comment '3x-ui HTTPS panel' >/dev/null
ufw status | grep -Eq "(^|[[:space:]])${PANEL_PORT}(/tcp)?([[:space:]]|$).*ALLOW" ||
  die 'UFW did not permit TCP/2053'

panel_url="https://${PUBLIC_FQDN}:${PANEL_PORT}/${PANEL_BASE_PATH}/"
PANEL_URL="$panel_url" ACCESS_SOURCE="$access_file" ACCESS_RENDERED="$stage/access.env" python3 - <<'PY'
import os
from pathlib import Path
lines = [line for line in Path(os.environ['ACCESS_SOURCE']).read_text().splitlines()
         if not line.startswith('PANEL_URL=')]
lines.append('PANEL_URL='+os.environ['PANEL_URL'])
Path(os.environ['ACCESS_RENDERED']).write_text('\n'.join(lines)+'\n')
PY
install -o root -g root -m 0600 "$stage/access.env" "$access_file"

ss -H -lnt | grep -Eq "127[.]0[.]0[.]1:${PANEL_PORT}[[:space:]]" ||
  die 'loopback 3X-UI backend disappeared'
ss -H -lnt | grep -Eq "${SERVER_IPV4}:${PANEL_PORT}[[:space:]]" ||
  die 'public HTTPS panel listener is missing'
if ss -H -lnt | grep -Eq "(0[.]0[.]0[.]0|[*]|\[::\]):${PANEL_PORT}[[:space:]]"; then
  die 'panel proxy unexpectedly listens on a wildcard address'
fi
if ss -H -lnt | grep -Eq "(0[.]0[.]0[.]0|[*]|\[::\]):80[[:space:]]"; then
  die 'nginx unexpectedly occupies public TCP/80'
fi

public_status=$(curl --proto '=https' --tlsv1.2 --silent --show-error --max-time 20 \
  --resolve "${PUBLIC_FQDN}:${PANEL_PORT}:${SERVER_IPV4}" \
  --output /dev/null --write-out '%{http_code}' "$panel_url")
[[ "$public_status" == 200 || "$public_status" == 302 ]] ||
  die "unexpected public panel HTTPS status: $public_status"
root_status=$(curl --proto '=https' --tlsv1.2 --silent --show-error --max-time 20 \
  --resolve "${PUBLIC_FQDN}:${PANEL_PORT}:${SERVER_IPV4}" \
  --output /dev/null --write-out '%{http_code}' \
  "https://${PUBLIC_FQDN}:${PANEL_PORT}/")
[[ "$root_status" == 404 ]] || die "unexpected public root HTTPS status: $root_status"
unset public_status root_status panel_url

nginx -t
sqlite3 /etc/x-ui/x-ui.db 'PRAGMA quick_check;' | grep -qx ok
systemctl is-active --quiet x-ui.service
systemctl is-active --quiet certbot.timer

bash "$bundle_root/tests/panel-login-acceptance.sh" >/dev/null
touch "$backup/PROVISION_COMMITTED"
chmod 0600 "$backup/PROVISION_COMMITTED"
committed=1
trap - ERR EXIT INT TERM HUP
rm -rf -- "$stage"
printf 'PANEL_PUBLIC_HTTPS_OK=1\n'
printf 'BACKUP=%s\n' "$backup"
printf 'ACCESS_FILE=%s\n' "$access_file"
printf 'The public URL remains in the root-only access file and was not printed.\n'
