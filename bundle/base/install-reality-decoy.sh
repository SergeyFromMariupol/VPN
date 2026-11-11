#!/usr/bin/env bash
# Prepare the local HTTPS target before generating any REALITY inbounds.
set -Eeuo pipefail
umask 077
[[ $# == 1 ]] || exit 2
case $1 in --apply|--manage-apply|--check-only|--enable-php|--reset-page|--reset-site) ;; *) exit 2;; esac
[[ $EUID == 0 ]] || exit 1
source_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
readonly source_root
source "$source_root/../scripts/target-contract.sh"
case ${TARGET_REALITY_MODE:-external} in
  external) printf 'REALITY_DECOY_NOT_REQUIRED=1\n'; exit 0;;
  self-steal|decoy) ;;
  *) exit 1;;
esac
readonly config=/etc/nginx/conf.d/vpn-reality-decoy.conf
readonly hook=/etc/letsencrypt/renewal-hooks/deploy/55-vpn-reality-decoy
readonly hook_source="$source_root/../templates/55-vpn-reality-decoy"
readonly marker_root=/etc/vpn-reality-decoy
readonly site_root=/var/www/vpn-decoy
readonly document_root="$site_root/public"
readonly lineage="/etc/letsencrypt/live/${TARGET_CERT_NAME:-$TARGET_FQDN}"
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
owned_file() { [[ -f $1 && ! -L $1 && $(stat -c '%u:%g:%a:%h' "$1") == "0:0:$2:1" ]]; }
for command_name in awk chmod cmp cp dirname find flock grep install mkdir mktemp mv nft nginx openssl python3 rm sha256sum sqlite3 ss stat systemctl tar ufw; do
  command -v "$command_name" >/dev/null || die "missing command: $command_name"
done
[[ -d /etc/nginx/conf.d && ! -L /etc/nginx/conf.d &&
   -d /etc/nginx/sites-enabled && ! -L /etc/nginx/sites-enabled ]] || die 'unsafe Nginx directories'
verify_target_certificate "$lineage/fullchain.pem" || die 'decoy certificate is not trusted for the public endpoint'
cert_pub=$(openssl x509 -in "$lineage/fullchain.pem" -pubkey -noout | openssl sha256)
key_pub=$(openssl pkey -in "$lineage/privkey.pem" -pubout | openssl sha256)
[[ $cert_pub == "$key_pub" ]] || die 'decoy certificate/private-key mismatch'
unset cert_pub key_pub
verify_site() {
  local sites probe_mode=${1:---probe-target}
  owned_file "$config" 600 && owned_file "$hook" 755 || return 1
  cmp -s "$hook_source" "$hook" || return 1
  cmp -s "$config" <(python3 -I -B "$source_root/reality-decoy.py" --nginx) || return 1
  [[ -d $site_root && ! -L $site_root && $(stat -c '%u:%g:%a' "$site_root") == 0:0:755 &&
     -d $document_root && ! -L $document_root && $(stat -c '%u:%g:%a' "$document_root") == 0:0:755 ]] || return 1
  if [[ -e $marker_root/PHP_ENABLED || -L $marker_root/PHP_ENABLED ]]; then
    owned_file "$marker_root/PHP_ENABLED" 600 && [[ $(<"$marker_root/PHP_ENABLED") == enabled ]] || return 1
    [[ -S /run/php/vpn-decoy.sock ]] && systemctl is-active --quiet php8.3-fpm.service || return 1
  fi
  # An independently managed panel may be added later. Do not adopt extra sites.
  sites=$(find /etc/nginx/conf.d /etc/nginx/sites-enabled -mindepth 1 -maxdepth 1 -print)
  while IFS= read -r site; do
    case $site in
      "$config") ;;
      /etc/nginx/conf.d/3x-ui-public.conf) owned_file "$site" 600 || return 1;;
      /etc/nginx/conf.d/vpn-ip-subscription.conf)
        owned_file "$site" 600 && cmp -s "$site" <(python3 -I -B "$source_root/reality-decoy.py" --nginx-aliases) || return 1;;
      *) return 1;;
    esac
  done <<<"$sites"
  nginx -t >/dev/null 2>&1 || return 1
  systemctl is-active --quiet nginx.service && systemctl is-enabled --quiet nginx.service || return 1
  ss -H -lnt | awk '$4 ~ /:9443$/ {if ($4 != "127.0.0.1:9443") bad=1; found=1} END {exit (!found || bad)}' || return 1
  python3 -I -B "$source_root/reality-decoy.py" "$probe_mode"
}
verify_installed() {
  local snapshot
  [[ -d $marker_root && ! -L $marker_root && $(stat -c '%u:%g:%a' "$marker_root") == 0:0:700 ]] || return 1
  owned_file "$marker_root/COMMITTED" 600 && [[ ! -s $marker_root/COMMITTED ]] || return 1
  owned_file "$marker_root/snapshot" 600 || return 1
  snapshot=$(<"$marker_root/snapshot")
  [[ $snapshot =~ ^/var/backups/vpn-reality-decoy\.[A-Za-z0-9]+$ &&
     -d $snapshot && ! -L $snapshot && $(stat -c '%u:%g:%a' "$snapshot") == 0:0:700 ]] || return 1
  owned_file "$snapshot/COMMITTED" 600 && [[ ! -s $snapshot/COMMITTED ]] &&
    owned_file "$snapshot/SHA256SUMS" 600 || return 1
  (cd -- "$snapshot"; sha256sum -c --strict SHA256SUMS >/dev/null) || return 1
  verify_site "${1:---probe-target}"
}
if [[ $1 == --check-only ]]; then
  verify_installed || die 'local REALITY target readback failed'
  printf 'REALITY_DECOY_OK=1\n'
  exit 0
fi
exec 9>/run/vpn-reality-decoy.lock
flock -n 9 || die 'another local REALITY target transaction is running'
if [[ $1 == --reset-page || $1 == --reset-site ]]; then
  verify_installed --probe-tls || die 'local REALITY target must verify before replacing its page'
  python3 -I -B "$source_root/reality-decoy-site.py" --reset-page
  exit 0
fi
if [[ $1 == --enable-php ]]; then
  # A PHP-only upload may intentionally have no working static index yet.
  # Keep all TLS/ownership checks; PHP and site payload are checked after enable.
  verify_installed --probe-tls || die 'local REALITY target must verify before enabling PHP'
  bash "$source_root/enable-reality-decoy-php.sh"
  exit 0
fi
if [[ -e $config || -L $config || -e $marker_root || -L $marker_root ]]; then
  verify_installed || die 'existing local REALITY target is not the committed managed target'
  printf 'REALITY_DECOY_RECOVERED=1\n'
  exit 0
fi
[[ ! -e $hook && ! -L $hook ]] || die 'unknown existing local REALITY renewal hook'
[[ ! -e $site_root && ! -L $site_root ]] || die 'unknown existing website directory'
[[ -d /var/www && ! -L /var/www && $(stat -c '%u:%g' /var/www) == 0:0 ]] || die 'unsafe website parent'
if [[ $1 == --manage-apply ]]; then
  while IFS= read -r site; do
    [[ -n $site ]] || continue
    case $site in
      /etc/nginx/conf.d/3x-ui-public.conf) owned_file "$site" 600 || die 'unsafe managed panel';;
      /etc/nginx/conf.d/vpn-ip-subscription.conf)
        owned_file "$site" 600 && cmp -s "$site" <(python3 -I -B "$source_root/reality-decoy.py" --nginx-aliases) || die 'unmanaged secondary-IP site';;
      *) die 'existing Nginx sites require a reviewed merge';;
    esac
  done < <(find /etc/nginx/conf.d /etc/nginx/sites-enabled -mindepth 1 -maxdepth 1 -print)
  owned_file /etc/nginx/conf.d/3x-ui-public.conf 600 || die 'managed public panel is required'
  systemctl is-active --quiet nginx.service || die 'managed public Nginx is not active'
else
  [[ -z $(find /etc/nginx/conf.d /etc/nginx/sites-enabled -mindepth 1 -maxdepth 1 -print -quit) ]] || die 'existing Nginx sites require a reviewed merge'
  ! systemctl is-active --quiet nginx.service || die 'Nginx must be stopped before preparing its first site'
fi
! ss -H -lnt | grep -E '(:|\])9443[[:space:]]' >/dev/null || die 'local REALITY target port is occupied'
[[ -f /etc/x-ui/x-ui.db && ! -L /etc/x-ui/x-ui.db ]] || die 'X-UI database missing or unsafe'
backup=$(mktemp -d -p /var/backups vpn-reality-decoy.XXXXXXXX)
chmod 0700 "$backup"
tar --acls --xattrs --numeric-owner -cpf "$backup/system-before.tar" -C / \
  etc/nginx etc/x-ui usr/local/x-ui etc/systemd/system etc/ufw etc/letsencrypt
tar -tf "$backup/system-before.tar" >/dev/null
sqlite3 -readonly /etc/x-ui/x-ui.db ".backup '$backup/x-ui.db'"
chmod 0600 "$backup/x-ui.db"
[[ $(sqlite3 "$backup/x-ui.db" 'PRAGMA quick_check;') == ok ]] || die 'SQLite snapshot failed'
{ ufw status verbose; nft -s list ruleset; } >"$backup/firewall.before"
systemctl is-enabled nginx.service >"$backup/nginx-enabled.before" 2>/dev/null || true
systemctl is-active nginx.service >"$backup/nginx-active.before" 2>/dev/null || true
(cd -- "$backup"; sha256sum system-before.tar x-ui.db firewall.before nginx-enabled.before nginx-active.before >SHA256SUMS; sha256sum -c SHA256SUMS >/dev/null)
stage=$(mktemp -d -p /run vpn-reality-decoy.XXXXXXXX)
committed=0
config_inode=''; hook_inode=''; marker_inode=''; site_inode=''
marker_stage=''; marker_stage_inode=''; site_stage=''; site_stage_inode=''
temporary_files=()
declare -A temporary_inodes=()
cleanup() {
  local status=$? rollback_ok=1 state quiesced=1 unit_state
  trap - EXIT HUP INT TERM
  set +e
  if ((committed == 0)); then
    systemctl disable --now nginx.service >/dev/null 2>&1 || quiesced=0
    unit_state=$(systemctl show nginx.service -p ActiveState -p MainPID 2>/dev/null) || quiesced=0
    unit_state=$'\n'"$unit_state"$'\n'
    [[ $unit_state == *$'\nActiveState=inactive\n'* && $unit_state == *$'\nMainPID=0\n'* ]] || quiesced=0
    if ((quiesced)); then
    for state in config hook marker site; do
      local path='' inode=''
      case $state in config) path=$config; inode=$config_inode;; hook) path=$hook; inode=$hook_inode;; marker) path=$marker_root; inode=$marker_inode;; site) path=$site_root; inode=$site_inode;; esac
      if [[ -e $path || -L $path ]]; then
        if [[ -n $inode && ! -L $path && $(stat -c '%d:%i' "$path") == "$inode" ]]; then
          mv -T -- "$path" "$backup/$state.failed" || rollback_ok=0
        else rollback_ok=0; fi
      fi
    done
    if grep -Fxq enabled "$backup/nginx-enabled.before"; then systemctl enable nginx.service >/dev/null 2>&1 || rollback_ok=0; fi
    if grep -Fxq masked "$backup/nginx-enabled.before"; then systemctl mask nginx.service >/dev/null 2>&1 || rollback_ok=0; fi
    [[ $(systemctl is-enabled nginx.service 2>/dev/null) == "$(cat "$backup/nginx-enabled.before")" ]] || rollback_ok=0
    if grep -Fxq active "$backup/nginx-active.before"; then
      nginx -t >/dev/null 2>&1 && systemctl start nginx.service >/dev/null 2>&1 || rollback_ok=0
    fi
    else
      printf 'REALITY_DECOY_ROLLBACK_RESOURCES_RETAINED=1\n' >&2
      rollback_ok=0
    fi
    printf 'REALITY_DECOY_ROLLBACK_OK=%s SNAPSHOT=%s\n' "$rollback_ok" "$backup" >&2
  fi
  for state in "${temporary_files[@]}"; do
    if [[ -e $state || -L $state ]]; then
      if [[ ! -L $state && -n ${temporary_inodes[$state]:-} && $(stat -c '%d:%i' "$state") == "${temporary_inodes[$state]}" ]]; then
        rm -f -- "$state" || rollback_ok=0
      else rollback_ok=0; fi
    fi
  done
  if [[ -n $marker_stage && -d $marker_stage && ! -L $marker_stage && $(stat -c '%d:%i' "$marker_stage") == "$marker_stage_inode" ]]; then rm -rf -- "$marker_stage"; fi
  if [[ -n $site_stage && -d $site_stage && ! -L $site_stage && $(stat -c '%d:%i' "$site_stage") == "$site_stage_inode" ]]; then rm -rf -- "$site_stage"; fi
  rm -rf -- "$stage"
  ((rollback_ok)) || status=1
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP
publish_file() {
  local source=$1 destination=$2 mode=$3 inode_name=$4 temporary
  temporary=$(mktemp "${destination%/*}/.vpn-decoy.XXXXXXXX")
  temporary_files+=("$temporary")
  install -o root -g root -m "$mode" "$source" "$temporary"
  temporary_inodes[$temporary]=$(stat -c '%d:%i' "$temporary")
  printf -v "$inode_name" '%s' "$(stat -c '%d:%i' "$temporary")"
  mv -nT -- "$temporary" "$destination"
  [[ ! -e $temporary && ! -L $temporary ]] || die 'managed file path was claimed concurrently'
}
python3 -I -B "$source_root/reality-decoy.py" --nginx >"$stage/site.conf"
publish_file "$stage/site.conf" "$config" 0600 config_inode
publish_file "$hook_source" "$hook" 0755 hook_inode
marker_stage=$(mktemp -d /etc/.vpn-reality-decoy.XXXXXXXX)
marker_stage_inode=$(stat -c '%d:%i' "$marker_stage")
marker_inode=$marker_stage_inode
printf '%s\n' "$backup" >"$marker_stage/snapshot"
chmod 0600 "$marker_stage/snapshot"
mv -nT -- "$marker_stage" "$marker_root"
[[ ! -e $marker_stage && ! -L $marker_stage ]] || die 'decoy marker path was claimed concurrently'
site_stage=$(mktemp -d /var/www/.vpn-decoy.XXXXXXXX)
site_stage_inode=$(stat -c '%d:%i' "$site_stage")
site_inode=$site_stage_inode
chmod 0755 "$site_stage"
mkdir -m 0755 "$site_stage/public"
python3 -I -B "$source_root/reality-decoy.py" --default-page >"$site_stage/public/index.html"
chmod 0644 "$site_stage/public/index.html"
mv -nT -- "$site_stage" "$site_root"
[[ ! -e $site_stage && ! -L $site_stage ]] || die 'website path was claimed concurrently'
nginx -t
systemctl unmask nginx.service >/dev/null
systemctl enable --now nginx.service
if grep -Fxq active "$backup/nginx-active.before"; then systemctl reload nginx.service; fi
verify_site || die 'local REALITY target failed live acceptance'
: >"$backup/COMMITTED"
chmod 0600 "$backup/COMMITTED"
: >"$marker_root/COMMITTED"
chmod 0600 "$marker_root/COMMITTED"
verify_installed || die 'local REALITY target commit readback failed'
committed=1
printf 'REALITY_DECOY_INSTALLED=1 SNAPSHOT=%s\n' "$backup"
