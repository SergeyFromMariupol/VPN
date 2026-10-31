#!/usr/bin/env bash
# Clean-host base only. No ACME issuance, VPN users, public panel, WARP, or SSH edits.
set -Eeuo pipefail
umask 077

source "$(cd -- "$(dirname -- "$0")/../scripts" && pwd -P)/target-contract.sh"
readonly SERVER_IPV4="$TARGET_IPV4"
readonly PUBLIC_INTERFACE="$TARGET_INTERFACE"
readonly XUI_VERSION='3.7.0'
readonly XUI_URL='https://github.com/MHSanaei/3x-ui/releases/download/v3.7.0/x-ui-linux-amd64.tar.gz'
readonly XUI_ARCHIVE_SHA256='0f8dd7baef3458f6591574e24814f322cf7f5e1e27f0a594683745e50be84ec5'
readonly XUI_BINARY_SHA256='4738190332c5480ec96fd72e10a21157ee4bcf91c240a9b4b061d14f15092298'
readonly XRAY_BINARY_SHA256='64d46afb80adea1bf97a0d467e83f4a9ac1ebd0995891e84bca3f1a1d1affb1d'
readonly xui_root='/usr/local/x-ui'
readonly db_root='/etc/x-ui'
readonly service_path='/etc/systemd/system/x-ui.service'
readonly hardening_root='/usr/local/share/krysyuk-bootstrap'
readonly policy_path='/usr/sbin/policy-rc.d'
readonly nginx_mask='/etc/systemd/system/nginx.service'

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
[[ ${1:-} == '--apply' && $# == 1 ]] || die 'usage: install-pinned-base.sh --apply'
[[ $EUID -eq 0 ]] || die 'root is required'
# shellcheck disable=SC1091
source /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 24.04 ]] || die 'Ubuntu 24.04 is required'
[[ $(dpkg --print-architecture) == amd64 ]] || die 'amd64 is required'
ip -j -4 address show dev "$PUBLIC_INTERFACE" | python3 -c '
import json,sys
assert any(a.get("local")==sys.argv[1] for i in json.load(sys.stdin) for a in i.get("addr_info",[])), "target IPv4/interface mismatch"
' "$SERVER_IPV4"
for path in "$xui_root" "$db_root" "$service_path" "$hardening_root" \
  /var/lib/x-ui /var/log/x-ui /etc/krysyuk-standalone /etc/nginx /etc/letsencrypt \
  "$policy_path" "$nginx_mask"; do
  [[ ! -e $path && ! -L $path ]] || die "clean-host precondition failed: $path exists"
done
for identity in xui xui-secrets; do
  ! getent passwd "$identity" >/dev/null || die "unexpected existing user: $identity"
  ! getent group "$identity" >/dev/null || die "unexpected existing group: $identity"
done
for unit in x-ui.service nginx.service certbot.timer; do
  ! systemctl is-active --quiet "$unit" || die "unexpected active unit: $unit"
done
for port in 80 443 2053 2096 8443; do
  ! ss -H -lnt | grep -Eq "(:|\\])${port}[[:space:]]" || die "TCP/$port is occupied"
done
! ss -H -lnu | grep -Eq '(:|\])443[[:space:]]' || die 'UDP/443 is occupied'
[[ $(df -Pk /var/tmp | awk 'NR==2 {print $4}') -ge 1048576 ]] || die 'at least 1 GiB free staging space is required'

bundle_root=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
readonly bundle_root
readonly hardening_source="$bundle_root/templates/20-krysyuk-nonroot-hardening.conf"
[[ -f $hardening_source && ! -L $hardening_source ]] || die 'non-root hardening template is missing'
# shellcheck source=apt-options.sh
source "$bundle_root/base/apt-options.sh"
# shellcheck source=package-start-policy.sh
source "$bundle_root/base/package-start-policy.sh"

backup=$(mktemp -d -p /var/backups "germanyvpn-base-$(date -u +%Y%m%dT%H%M%SZ).XXXXXXXX")
readonly backup
chmod 0700 "$backup"
stage=$(mktemp -d -p /var/tmp germanyvpn-base.XXXXXXXX)
readonly stage
chmod 0700 "$stage"
committed=0
managed_installed=0
groups_created=0
apt_attempted=0
apt_install_attempted=0
failure_line=unknown

installed_packages() {
  dpkg-query -W -f='${binary:Package}\t${db:Status-Status}\n' |
    awk -F '\t' '$2=="installed" {print $1}' | LC_ALL=C sort -u
}
routes_snapshot() {
  ip -4 rule show
  ip -4 route show table main
  ip -6 rule show
  ip -6 route show table main
}
remove_managed_tree() {
  case "$1" in
    /usr/local/x-ui|/etc/x-ui|/var/lib/x-ui|/var/log/x-ui|/usr/local/share/krysyuk-bootstrap)
      [[ ! -L $1 ]] || return 1
      rm -rf -- "$1" ;;
    *) return 1 ;;
  esac
}
rollback_packages() {
  installed_packages >"$backup/packages.installed.after-failure"
  LC_ALL=C comm -13 "$backup/packages.installed.before" "$backup/packages.installed.after-failure" >"$backup/packages.added"
  mapfile -t added_packages <"$backup/packages.added"
  ((${#added_packages[@]})) || return 0
  # A background package operation can finish while this installer waits for
  # the dpkg lock. A post-snapshot addition alone is not proof of ownership.
  [[ -f $backup/apt-install-plan.txt && ! -L $backup/apt-install-plan.txt ]] || return 1
  awk '$1=="Inst" && $3 !~ /^\[/ {print $2}' "$backup/apt-install-plan.txt" |
    sed 's/:amd64$//' | LC_ALL=C sort -u >"$backup/packages.planned-new" || return 1
  sed 's/:amd64$//' "$backup/packages.added" |
    LC_ALL=C sort -u >"$backup/packages.added.normalized" || return 1
  LC_ALL=C comm -23 "$backup/packages.added.normalized" "$backup/packages.planned-new" \
    >"$backup/packages.unowned-additions" || return 1
  [[ ! -s $backup/packages.unowned-additions ]] || return 1
  # Never remove a package that was installed before this transaction.
  vpn_apt_get -s purge "${added_packages[@]}" >"$backup/apt-purge-plan.txt" 2>&1 || return 1
  awk '/^(Remv|Purg) / {print $2}' "$backup/apt-purge-plan.txt" |
    sed 's/:amd64$//' | LC_ALL=C sort -u >"$backup/packages.purge-plan" || return 1
  LC_ALL=C comm -23 "$backup/packages.purge-plan" "$backup/packages.added.normalized" >"$backup/packages.unsafe-removal" || return 1
  [[ ! -s $backup/packages.unsafe-removal ]] || return 1
  vpn_apt_get purge -y "${added_packages[@]}" >"$backup/apt-rollback.log" 2>&1 || return 1
}
restore_package_marks() {
  apt-mark showmanual | LC_ALL=C sort -u >"$backup/apt-manual.after-rollback" || return 1
  LC_ALL=C comm -13 "$backup/apt-manual.before" "$backup/apt-manual.after-rollback" >"$backup/apt-manual.changed" || return 1
  mapfile -t changed_marks <"$backup/apt-manual.changed"
  ((${#changed_marks[@]})) || return 0
  # Do not change metadata for a concurrent package operation merely because
  # its manual mark appeared after our snapshot. Only our actual install can
  # own these changes, including an explicitly requested preexisting package.
  : >"$backup/apt-manual.owned"
  if ((apt_install_attempted)); then
    [[ -f $backup/apt-install-plan.txt && ! -L $backup/apt-install-plan.txt ]] || return 1
    { printf '%s\n' "${base_packages[@]}"
      awk '$1=="Inst" && $3 !~ /^\[/ {print $2}' "$backup/apt-install-plan.txt"
    } | sed 's/:amd64$//' | LC_ALL=C sort -u >"$backup/apt-manual.owned" || return 1
  fi
  sed 's/:amd64$//' "$backup/apt-manual.changed" |
    LC_ALL=C sort -u >"$backup/apt-manual.changed.normalized" || return 1
  LC_ALL=C comm -23 "$backup/apt-manual.changed.normalized" "$backup/apt-manual.owned" \
    >"$backup/apt-manual.unowned" || return 1
  [[ ! -s $backup/apt-manual.unowned ]] || return 1
  apt-mark auto "${changed_marks[@]}" >/dev/null
}
transaction_exit() {
  local status=$? rollback_ok=1
  trap - EXIT ERR INT TERM HUP
  set +e
  if ((status != 0 && !committed)); then
    printf 'BASE_INSTALL_FAILED line=%s snapshot=%s\n' "$failure_line" "$backup" >&2
    if ((managed_installed)); then
      systemctl disable --now x-ui.service >/dev/null 2>&1
      rm -f -- "$service_path"
      for path in "$xui_root" "$db_root" /var/lib/x-ui /var/log/x-ui "$hardening_root"; do
        remove_managed_tree "$path" || rollback_ok=0
      done
    fi
    systemctl disable --now certbot.timer nginx.service >/dev/null 2>&1
    # Keep the temporary package start prohibition until rollback finishes.
    if ((apt_attempted)); then
      rollback_packages || rollback_ok=0
      restore_package_marks || rollback_ok=0
      dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Status}\n' >"$backup/package-versions.after-failure" || rollback_ok=0
      if [[ -f $backup/OS_UPGRADE_COMMITTED ]]; then
        if ! cmp -s "$backup/package-versions.before" "$backup/package-versions.after-os-upgrade"; then
          printf 'OS_UPGRADE_PERSISTED=1 details=%s\n' "$backup" >&2
        fi
        if ! cmp -s "$backup/package-versions.after-os-upgrade" "$backup/package-versions.after-failure"; then
          printf 'APT_INSTALL_PACKAGE_CHANGES_REMAIN=1 details=%s\n' "$backup" >&2
          rollback_ok=0
        fi
      elif ! cmp -s "$backup/package-versions.before" "$backup/package-versions.after-failure"; then
        printf 'OS_UPGRADE_INCOMPLETE=1 details=%s\n' "$backup" >&2
        rollback_ok=0
      fi
    fi
    if ((groups_created)); then
      userdel xui >/dev/null 2>&1 || rollback_ok=0
      groupdel xui >/dev/null 2>&1 || true
      groupdel xui-secrets >/dev/null 2>&1 || rollback_ok=0
    fi
  fi
  restore_start_policy || rollback_ok=0
  systemctl daemon-reload >/dev/null 2>&1 || rollback_ok=0
  if ((status != 0 && !committed)); then
    printf 'MANAGED_ROLLBACK_OK=%s\n' "$rollback_ok" >&2
    ((rollback_ok)) || printf 'Review protected snapshot before retrying.\n' >&2
  fi
  ((rollback_ok)) || status=1
  # stage was created by mktemp under this exact parent and contains no user files.
  if [[ $stage == /var/tmp/germanyvpn-base.* && -d $stage && ! -L $stage ]]; then rm -rf -- "$stage"; fi
  exit "$status"
}
trap 'failure_line=$LINENO' ERR
trap transaction_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

installed_packages >"$backup/packages.installed.before"
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Status}\n' >"$backup/package-versions.before"
apt-mark showmanual | LC_ALL=C sort -u >"$backup/apt-manual.before"
routes_snapshot >"$backup/main-routes.before"
ss -lntup >"$backup/listeners.before"
systemctl list-unit-files --no-pager >"$backup/units.before"
systemctl list-units --type=service --state=running --no-pager >"$backup/services.before"
if command -v ufw >/dev/null; then ufw status verbose >"$backup/ufw.before"; ufw show added >"$backup/ufw-added.before"; fi
if command -v nft >/dev/null; then nft list ruleset >"$backup/nftables.before"; fi
if command -v iptables-save >/dev/null; then iptables-save >"$backup/iptables.before"; fi
if command -v ip6tables-save >/dev/null; then ip6tables-save >"$backup/ip6tables.before"; fi
printf '%s\n' "$xui_root" "$db_root" "$service_path" "$hardening_root" \
  /var/lib/x-ui /var/log/x-ui /etc/krysyuk-standalone /etc/nginx /etc/letsencrypt \
  "$policy_path" "$nginx_mask" >"$backup/managed-paths-absent.before"
tar --acls --xattrs --numeric-owner -cpf "$backup/system-prestate.tar" -C / \
  etc/default etc/apt etc/systemd/system etc/ssh etc/ufw 2>"$backup/system-prestate-tar.log" || {
    # UFW may be absent on a clean image. Retry only existing explicitly scoped paths.
    snapshot_paths=()
    for path in etc/default etc/apt etc/systemd/system etc/ssh etc/ufw; do [[ -e /$path ]] && snapshot_paths+=("$path"); done
    tar --acls --xattrs --numeric-owner -cpf "$backup/system-prestate.tar" -C / "${snapshot_paths[@]}"
  }
tar -tf "$backup/system-prestate.tar" >/dev/null
(cd -- "$backup"; sha256sum -- *.before system-prestate.tar >SHA256SUMS; sha256sum -c SHA256SUMS >/dev/null)

# Block package-maintainer service starts; never alter an existing policy file.
prepare_start_policy
systemctl daemon-reload
export DEBIAN_FRONTEND=noninteractive
apt_attempted=1
vpn_apt_get update
vpn_apt_get -s --no-remove upgrade >"$backup/apt-upgrade-plan.txt"
! grep -Eq '^(Remv|Purg) ' "$backup/apt-upgrade-plan.txt" || die 'Ubuntu upgrade would remove an existing package'
vpn_apt_get upgrade -y --no-remove
vpn_apt_get check >/dev/null
[[ -z $(dpkg --audit) ]] || die 'package database is not clean after Ubuntu upgrade'
/usr/sbin/sshd -t || die 'SSH configuration failed after Ubuntu upgrade'
systemctl is-active --quiet ssh.service || die 'SSH service is inactive after Ubuntu upgrade'
ss -H -lnt | grep -Eq "(:|\\])${TARGET_SSH_PORT}[[:space:]]" || die 'SSH listener disappeared after Ubuntu upgrade'
dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Status}\n' >"$backup/package-versions.after-os-upgrade"
touch "$backup/OS_UPGRADE_COMMITTED"
base_packages=(
  ca-certificates certbot curl dnsutils gnupg iproute2 jq nftables nginx openssl \
  python3 python3-bcrypt python3-venv shellcheck sqlite3 tar tcpdump ufw unzip uuid-runtime xz-utils
)
vpn_apt_get -s --no-upgrade --no-remove --no-install-recommends install "${base_packages[@]}" >"$backup/apt-install-plan.txt"
# --no-upgrade protects explicitly requested packages, but APT may still need
# newer versions of dependencies already on an older Ubuntu cloud image (for
# example python3.12 for python3-venv). Record that bounded plan before applying
# it. The package manager must not remove any pre-existing package.
! grep -Eq '^(Remv|Purg) ' "$backup/apt-install-plan.txt" || die 'base installation would remove an existing package'
grep -E '^Inst [^ ]+ \[' "$backup/apt-install-plan.txt" >"$backup/apt-existing-upgrades.plan" || true
apt_install_attempted=1
vpn_apt_get install -y --no-upgrade --no-remove --no-install-recommends "${base_packages[@]}"
vpn_apt_get check >/dev/null
[[ -z $(dpkg --audit) ]] || die 'package database is not clean after installation'
touch "$backup/APT_PREREQUISITES_COMMITTED"

[[ $(ufw status | sed -n '1p') == 'Status: inactive' ]] || die 'UFW unexpectedly active after package installation'
ufw show added | grep -Fq '(None)' || die 'unexpected UFW user rules'
systemctl disable --now nginx.service >/dev/null 2>&1 || true
if [[ -e /etc/nginx/sites-enabled/default || -L /etc/nginx/sites-enabled/default ]]; then
  [[ -L /etc/nginx/sites-enabled/default && $(readlink -f /etc/nginx/sites-enabled/default) == /etc/nginx/sites-available/default ]] ||
    die 'unexpected nginx default-site path'
  rm -f -- /etc/nginx/sites-enabled/default
fi
[[ -z $(find /etc/nginx/sites-enabled /etc/nginx/conf.d -mindepth 1 -maxdepth 1 -type f -o -type l) ]] || die 'unexpected enabled nginx configuration'
nginx -t
! ss -H -lnt | grep -Eq '(:|\])80[[:space:]]' || die 'unexpected TCP/80 listener'

curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
  --retry 2 --connect-timeout 15 --max-time 300 --output "$stage/x-ui.tar.gz" "$XUI_URL"
printf '%s  %s\n' "$XUI_ARCHIVE_SHA256" "$stage/x-ui.tar.gz" | sha256sum --check --strict -
tar -tzf "$stage/x-ui.tar.gz" >"$stage/archive-files.txt"
python3 - "$stage/archive-files.txt" <<'PY'
from pathlib import Path, PurePosixPath
import sys
for name in Path(sys.argv[1]).read_text().splitlines():
    p = PurePosixPath(name)
    assert not p.is_absolute() and '..' not in p.parts, 'unsafe archive member'
PY
install -d -m 0700 "$stage/extracted"
tar -xzf "$stage/x-ui.tar.gz" -C "$stage/extracted"
mapfile -t xui_sources < <(find "$stage/extracted" -mindepth 1 -maxdepth 3 -type f -name x-ui -printf '%h\n' | sort -u)
[[ ${#xui_sources[@]} == 1 ]] || die 'unexpected x-ui archive layout'
xui_source=${xui_sources[0]}
[[ -f $xui_source/x-ui.service.debian && ! -L $xui_source/x-ui ]] || die 'missing/unsafe release files'
printf '%s  %s\n' "$XUI_BINARY_SHA256" "$xui_source/x-ui" | sha256sum --check --strict -
printf '%s  %s\n' "$XRAY_BINARY_SHA256" "$xui_source/bin/xray-linux-amd64" | sha256sum --check --strict -
# The official archive may store the bundled core without an executable bit.
# Set executable modes only after all pinned content digests have passed.
chmod 0755 "$xui_source/x-ui" "$xui_source/bin/xray-linux-amd64"
[[ $("$xui_source/x-ui" -v 2>&1) == "$XUI_VERSION" ]] || die 'x-ui release version mismatch'
xray_version_output=$("$xui_source/bin/xray-linux-amd64" version 2>&1) || die 'Xray version command failed'
grep -Eq '^Xray[[:space:]]+26[.]7[.]28([[:space:]]|$)' <<<"$xray_version_output" || die 'Xray release version mismatch'
unset xray_version_output

groups_created=1
groupadd --system xui-secrets
groupadd --system xui
useradd --system --home-dir /nonexistent --no-create-home --gid xui --groups xui-secrets --shell /usr/sbin/nologin xui
managed_installed=1
install -d -o root -g root -m 0755 "$xui_root" "$db_root" /var/lib/x-ui /var/log/x-ui
cp -a -- "$xui_source/." "$xui_root/"
chown -R root:root "$xui_root"
find "$xui_root" -type d -exec chmod 0755 {} +
chmod 0755 "$xui_root/x-ui" "$xui_root/x-ui.sh" "$xui_root/bin/xray-linux-amd64"
install -o root -g root -m 0644 "$xui_root/x-ui.service.debian" "$service_path"
install -d -o root -g root -m 0755 "$hardening_root/x-ui.service.d"
install -o root -g root -m 0644 "$hardening_source" "$hardening_root/x-ui.service.d/20-krysyuk-nonroot-hardening.conf"
systemctl daemon-reload
systemctl enable x-ui.service >/dev/null
# Initialize schema without a listener and without putting credentials in argv.
"$xui_root/x-ui" setting -listenIP 127.0.0.1 -port 2053 -show true >"$stage/initial-settings.txt" 2>&1
systemctl stop x-ui.service >/dev/null 2>&1 || true
find "$db_root" -maxdepth 1 -type f -name 'x-ui.db*' -exec chown root:root {} + -exec chmod 0600 {} +
sqlite3 "$db_root/x-ui.db" 'PRAGMA quick_check;' | grep -qx ok || die 'initial SQLite quick_check failed'
[[ $(sqlite3 -readonly "$db_root/x-ui.db" 'SELECT count(*) FROM inbounds;') == 0 ]] || die 'initial database is not empty'
sqlite3 "$db_root/x-ui.db" ".backup '$backup/initial-x-ui.db'"
chmod 0600 "$backup/initial-x-ui.db"
sqlite3 "$backup/initial-x-ui.db" 'PRAGMA quick_check;' | grep -qx ok

restore_start_policy
systemctl enable --now certbot.timer >/dev/null
systemctl is-enabled --quiet x-ui.service
! systemctl is-active --quiet x-ui.service || die 'x-ui must remain stopped'
systemctl is-enabled --quiet certbot.timer
systemctl is-active --quiet certbot.timer
! systemctl is-active --quiet nginx.service || die 'nginx must remain stopped'
for port in 80 443 2053 2096 8443; do
  ! ss -H -lnt | grep -Eq "(:|\\])${port}[[:space:]]" || die "unexpected final TCP/$port listener"
done
routes_snapshot >"$backup/main-routes.after"
cmp -s "$backup/main-routes.before" "$backup/main-routes.after" || die 'host main routes/rules changed'
installed_packages >"$backup/packages.installed.after"
LC_ALL=C comm -13 "$backup/packages.installed.before" "$backup/packages.installed.after" >"$backup/packages.added"
printf '%s\n' "$XUI_ARCHIVE_SHA256 x-ui-linux-amd64.tar.gz" "$XUI_BINARY_SHA256 x-ui" "$XRAY_BINARY_SHA256 xray-linux-amd64" >"$backup/PINNED_SHA256"
touch "$backup/BASE_COMMITTED"
committed=1
printf 'PINNED_BASE_OK=1 XUI=3.7.0 XRAY=26.7.28\n'
printf 'XUI_ENABLED_STOPPED=1 INBOUNDS=0 NGINX_STOPPED_NO_SITES=1 CERTBOT_TIMER=active\n'
printf 'SNAPSHOT=%s\n' "$backup"
