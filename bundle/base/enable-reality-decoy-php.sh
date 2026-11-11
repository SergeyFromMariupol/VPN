#!/usr/bin/env bash
# Explicit optional action. HTML-only installations do not install PHP.
# The caller holds /run/vpn-reality-decoy.lock throughout this transaction.
set -Eeuo pipefail
umask 077
[[ $# == 0 && $EUID == 0 ]] || exit 2
source_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source "$source_root/../scripts/target-contract.sh"
[[ ${TARGET_REALITY_MODE:-external} == self-steal || ${TARGET_REALITY_MODE:-external} == decoy ]] || exit 1
readonly config=/etc/nginx/conf.d/vpn-reality-decoy.conf
readonly marker=/etc/vpn-reality-decoy/PHP_ENABLED
readonly pool=/etc/php/8.3/fpm/pool.d/vpn-decoy.conf
readonly php_root=/var/lib/vpn-decoy
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
for command_name in adduser apt-cache apt-get awk cmp cp cut date dirname dpkg-query find getent grep groupdel install mkdir mktemp mv nginx nft php-fpm8.3 python3 rm sha256sum sort sqlite3 stat systemctl tar ufw userdel; do
  # php-fpm is the package installed by this action, not a prerequisite.
  [[ $command_name == php-fpm8.3 ]] || command -v "$command_name" >/dev/null || die "missing command: $command_name"
done
if [[ -e $marker || -L $marker ]]; then
  [[ -f $marker && ! -L $marker && $(stat -c '%u:%g:%a:%h' "$marker") == 0:0:600:1 && $(<"$marker") == enabled ]] || die 'unsafe PHP marker'
  [[ -f $pool && ! -L $pool && $(stat -c '%u:%g:%a:%h' "$pool") == 0:0:644:1 ]] || die 'unsafe PHP pool'
  cmp -s "$pool" <(python3 -I -B "$source_root/reality-decoy-php.py" --pool) || die 'managed PHP pool differs'
  systemctl is-active --quiet php8.3-fpm.service
  python3 -I -B "$source_root/reality-decoy-php.py" --probe-php
  exit 0
fi
source /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 ]] || die 'Ubuntu 24.04 is required for this PHP pool'
! dpkg-query -W -f='${db:Status-Status}' php8.3-fpm 2>/dev/null | grep -qx installed || die 'existing PHP-FPM requires a reviewed merge'
[[ ! -e /etc/php/8.3/fpm && ! -L /etc/php/8.3/fpm && ! -e $php_root && ! -L $php_root ]] || die 'existing PHP configuration/state requires a reviewed merge'
! getent passwd vpnsite >/dev/null || die 'vpnsite user already exists'
! getent group vpnsite >/dev/null || die 'vpnsite group already exists'
[[ ! -e /run/php/vpn-decoy.sock && ! -L /run/php/vpn-decoy.sock ]] || die 'PHP socket already exists'
backup=$(mktemp -d -p /var/backups vpn-decoy-php.XXXXXXXX)
chmod 0700 "$backup"
snapshot_paths=(etc/nginx etc/x-ui usr/local/x-ui etc/systemd/system etc/ufw etc/letsencrypt etc/krysyuk-standalone etc/vpn-reality-decoy etc/passwd etc/group etc/shadow etc/gshadow)
[[ ! -e /etc/php ]] || snapshot_paths+=(etc/php)
tar --acls --xattrs --numeric-owner -cpf "$backup/system-before.tar" -C / "${snapshot_paths[@]}"
tar -tf "$backup/system-before.tar" >/dev/null
sqlite3 -readonly /etc/x-ui/x-ui.db ".backup '$backup/x-ui.db'"
chmod 0600 "$backup/x-ui.db"
[[ $(sqlite3 "$backup/x-ui.db" 'PRAGMA quick_check;') == ok ]] || die 'SQLite snapshot failed'
cp -a "$config" "$backup/nginx.conf"
{ ufw status verbose; nft -s list ruleset; } >"$backup/firewall.before"
dpkg-query -W -f='${binary:Package}\t${db:Status-Status}\n' | awk '$2=="installed" {print $1}' | sort -u >"$backup/packages.before"
apt-cache policy php8.3-fpm >"$backup/php-source.txt"
apt-cache policy >"$backup/repositories.txt"
# The Ubuntu package repository is used; never fetch a PHP binary/install script.
python3 -I -B "$source_root/reality-decoy-php.py" --check-ubuntu-source "$backup/php-source.txt" "$backup/repositories.txt" || die 'PHP candidate is not offered exclusively by authenticated Ubuntu repositories'
apt-get --simulate --no-remove --no-upgrade --no-install-recommends install php8.3-fpm >"$backup/apt-plan.txt"
! grep -Eq '^Inst [^ ]+ \[' "$backup/apt-plan.txt" || die 'PHP installation would upgrade existing packages; update Ubuntu separately first'
awk '$1=="Inst" {print $2}' "$backup/apt-plan.txt" | sort -u >"$backup/packages.planned"
(cd -- "$backup"; sha256sum system-before.tar x-ui.db nginx.conf firewall.before packages.before php-source.txt repositories.txt apt-plan.txt packages.planned >SHA256SUMS; sha256sum -c --strict SHA256SUMS >/dev/null)
committed=0; apt_attempted=0; user_created=0; php_root_inode=''; pool_inode=''; marker_inode=''; config_inode=''
user_record=''; group_record=''
temporary=''
cleanup() {
  local status=$? rollback_ok=1 current path inode package php_quiesced=1 unit_state=''
  trap - EXIT HUP INT TERM
  set +e
  if ((committed == 0)); then
    if ((apt_attempted)); then
      systemctl disable --now php8.3-fpm.service >/dev/null 2>&1 || php_quiesced=0
      if unit_state=$(systemctl show php8.3-fpm.service -p LoadState -p ActiveState -p MainPID 2>/dev/null); then
        unit_state=$'\n'"$unit_state"$'\n'
        [[ $unit_state == *$'\nLoadState=not-found\n'* ||
           ($unit_state == *$'\nMainPID=0\n'* && ($unit_state == *$'\nActiveState=inactive\n'* || $unit_state == *$'\nActiveState=failed\n'*)) ]] || php_quiesced=0
      else php_quiesced=0; fi
    fi
    if [[ -n $config_inode && -f $config && ! -L $config && $(stat -c '%d:%i' "$config") == "$config_inode" ]]; then
      install -o root -g root -m 0600 "$backup/nginx.conf" "$config" || rollback_ok=0
      nginx -t >/dev/null 2>&1 && systemctl reload nginx.service >/dev/null 2>&1 || rollback_ok=0
    elif [[ -n $config_inode ]]; then rollback_ok=0; fi
    if ((php_quiesced)); then
    for current in marker pool; do
      case $current in marker) path=$marker; inode=$marker_inode;; pool) path=$pool; inode=$pool_inode;; esac
      if [[ -e $path || -L $path ]]; then
        if [[ ! -L $path && -n $inode && $(stat -c '%d:%i' "$path") == "$inode" ]]; then
          mv -T -- "$path" "$backup/$current.failed" || rollback_ok=0
        else rollback_ok=0; fi
      fi
    done
    if [[ -n $php_root_inode && -d $php_root && ! -L $php_root && $(stat -c '%d:%i' "$php_root") == "$php_root_inode" ]]; then
      mv -T -- "$php_root" "$backup/php-state.failed" || rollback_ok=0
    fi
    if ((user_created)); then
      if [[ $(getent passwd vpnsite) == "$user_record" && $(getent group vpnsite) == "$group_record" ]]; then
        userdel vpnsite >/dev/null 2>&1 || rollback_ok=0
        if getent group vpnsite >/dev/null; then groupdel vpnsite >/dev/null 2>&1 || rollback_ok=0; fi
      else rollback_ok=0; fi
    fi
    if ((apt_attempted)); then
      dpkg-query -W -f='${binary:Package}\t${db:Status-Status}\n' | awk '$2=="installed" {print $1}' | sort -u >"$backup/packages.after-failure"
      # Purge only packages explicitly named in the reviewed installation plan,
      # absent before this action, and still installed. Never autoremove.
      python3 -I -B - "$backup" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]); before=set((p/'packages.before').read_text().splitlines())
installed=set((p/'packages.after-failure').read_text().splitlines())
planned=set((p/'packages.planned').read_text().splitlines())
owned=sorted(name for name in installed-before if name.split(':')[0] in planned or name in planned)
(p/'packages.owned').write_text(''.join(name+'\n' for name in owned))
PY
      local -a owned_packages=()
      mapfile -t owned_packages <"$backup/packages.owned"
      if ((${#owned_packages[@]})); then
        apt-get --simulate purge "${owned_packages[@]}" >"$backup/apt-rollback-plan.txt" 2>&1
        while read -r current package _; do
          if [[ $current == Remv || $current == Purg ]]; then
            grep -Fxq "$package" "$backup/packages.owned" || rollback_ok=0
          fi
        done <"$backup/apt-rollback-plan.txt"
        if ((rollback_ok)); then DEBIAN_FRONTEND=noninteractive apt-get --yes --no-auto-remove purge "${owned_packages[@]}" >"$backup/apt-rollback.txt" 2>&1 || rollback_ok=0; fi
      fi
    fi
    else
      printf 'REALITY_DECOY_PHP_ROLLBACK_RESOURCES_RETAINED=1\n' >&2
      rollback_ok=0
    fi
    printf 'REALITY_DECOY_PHP_ROLLBACK_OK=%s SNAPSHOT=%s\n' "$rollback_ok" "$backup" >&2
  fi
  [[ -z $temporary || ! -f $temporary || -L $temporary ]] || rm -f -- "$temporary"
  ((rollback_ok)) || status=1
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP
apt_attempted=1
DEBIAN_FRONTEND=noninteractive apt-get --yes --no-remove --no-upgrade --no-install-recommends install php8.3-fpm >"$backup/apt-install.txt" 2>&1
user_created=1
adduser --system --group --no-create-home --home /var/www/vpn-decoy --shell /usr/sbin/nologin vpnsite >"$backup/user-create.txt" 2>&1
user_record=$(getent passwd vpnsite); group_record=$(getent group vpnsite)
mkdir -m 0755 "$php_root"
php_root_inode=$(stat -c '%d:%i' "$php_root")
install -d -o vpnsite -g vpnsite -m 0700 "$php_root/tmp"
temporary=$(mktemp "${pool%/*}/.vpn-decoy.XXXXXXXX")
python3 -I -B "$source_root/reality-decoy-php.py" --pool >"$temporary"
chmod 0644 "$temporary"
pool_inode=$(stat -c '%d:%i' "$temporary")
mv -nT -- "$temporary" "$pool"
[[ ! -e $temporary ]] || die 'PHP pool path was claimed concurrently'
php-fpm8.3 --test >"$backup/fpm-test.txt" 2>&1
systemctl enable --now php8.3-fpm.service
systemctl reload php8.3-fpm.service
[[ -S /run/php/vpn-decoy.sock ]] || die 'dedicated PHP socket missing'
temporary=$(mktemp "${marker%/*}/.PHP_ENABLED.XXXXXXXX")
printf 'enabled\n' >"$temporary"
chmod 0600 "$temporary"
marker_inode=$(stat -c '%d:%i' "$temporary")
mv -nT -- "$temporary" "$marker"
[[ ! -e $temporary ]] || die 'PHP marker path was claimed concurrently'
temporary=$(mktemp "${config%/*}/.vpn-decoy.XXXXXXXX")
python3 -I -B "$source_root/reality-decoy.py" --nginx >"$temporary"
chmod 0600 "$temporary"
config_inode=$(stat -c '%d:%i' "$temporary")
mv -Tf -- "$temporary" "$config"
nginx -t
systemctl reload nginx.service
bash "$source_root/install-reality-decoy.sh" --check-only
python3 -I -B "$source_root/reality-decoy-php.py" --probe-php
: >"$backup/COMMITTED"
chmod 0600 "$backup/COMMITTED"
committed=1
printf 'REALITY_DECOY_PHP_ENABLED=1 SNAPSHOT=%s\n' "$backup"
