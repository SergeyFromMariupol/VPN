#!/usr/bin/env bash
# Install only the reviewed Nginx crash-recovery policy; never restart a healthy
# process, replace foreign drop-ins, or use TLS renewal as a service supervisor.
set -Eeuo pipefail
umask 077
[[ $# == 1 && ($1 == --apply || $1 == --check-only) ]] || exit 2
[[ $EUID == 0 ]] || exit 1
source_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
readonly source_root
readonly policy_source="$source_root/../templates/30-vpn-nginx-restart.conf"
readonly dropin_dir=/etc/systemd/system/nginx.service.d
readonly dropin="$dropin_dir/30-vpn-nginx-restart.conf"
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
for command_name in chmod cmp date dirname find flock install mktemp mv nft nginx sha256sum sqlite3 stat systemctl tar touch ufw; do
  command -v "$command_name" >/dev/null || die "missing command: $command_name"
done
[[ -f $policy_source && ! -L $policy_source ]] || die 'missing or unsafe Nginx restart policy source'
systemctl is-active --quiet nginx.service || die 'Nginx must be active before installing its recovery policy'
systemctl is-enabled --quiet nginx.service || die 'Nginx must be enabled'
nginx -t >/dev/null 2>&1 || die 'Nginx configuration is invalid'

read_policy() {
  systemctl show nginx.service -p Restart -p RestartUSec -p StartLimitIntervalUSec
}
verify_policy() {
  [[ -d $dropin_dir && ! -L $dropin_dir && $(stat -c '%u:%g:%a' "$dropin_dir") == 0:0:755 ]] || return 1
  [[ -f $dropin && ! -L $dropin && $(stat -c '%u:%g:%a:%h' "$dropin") == 0:0:644:1 ]] || return 1
  cmp -s "$policy_source" "$dropin" || return 1
  [[ $(find "$dropin_dir" -mindepth 1 -maxdepth 1 -printf '%f\n') == 30-vpn-nginx-restart.conf ]] || return 1
  [[ $(systemctl show nginx.service -p DropInPaths --value) == "$dropin" ]] || return 1
  [[ $(systemctl show nginx.service -p Restart --value) == on-failure ]] || return 1
  [[ $(systemctl show nginx.service -p RestartUSec --value) == 5s ]] || return 1
  [[ $(systemctl show nginx.service -p StartLimitIntervalUSec --value) == 0 ]]
}
if [[ $1 == --check-only ]]; then
  verify_policy || die 'Nginx restart policy differs from the reviewed source or effective unit'
  printf 'NGINX_RESTART_POLICY_OK=1\n'
  exit 0
fi
exec 9>/run/vpn-nginx-restart.lock
flock -n 9 || die 'another Nginx recovery-policy transaction is running'
if [[ -e $dropin || -L $dropin ]]; then
  verify_policy || die 'existing Nginx recovery policy is not the reviewed owned policy'
  printf 'NGINX_RESTART_POLICY_OK=1\n'
  exit 0
fi
[[ ! -e $dropin_dir && ! -L $dropin_dir ]] || die 'existing Nginx drop-in directory requires a reviewed merge'
[[ -z $(systemctl show nginx.service -p DropInPaths --value) ]] || die 'unknown effective Nginx drop-in requires a reviewed merge'
before_pid=$(systemctl show nginx.service -p MainPID --value)
[[ $before_pid =~ ^[1-9][0-9]*$ ]] || die 'Nginx has no running master'
[[ -f /etc/x-ui/x-ui.db && ! -L /etc/x-ui/x-ui.db ]] || die 'X-UI database is missing or unsafe'
backup=$(mktemp -d -p /var/backups "vpn-nginx-restart-$(date -u +%Y%m%dT%H%M%SZ).XXXXXXXX")
chmod 0700 "$backup"
systemctl cat nginx.service >"$backup/unit.before"
read_policy >"$backup/policy.before"
tar --acls --xattrs --numeric-owner -cpf "$backup/system-before.tar" -C / \
  etc/nginx etc/letsencrypt etc/x-ui usr/local/x-ui etc/systemd/system etc/ufw etc/krysyuk-standalone
tar -tf "$backup/system-before.tar" >/dev/null
sqlite3 -readonly /etc/x-ui/x-ui.db ".backup '$backup/x-ui.db'"
chmod 0600 "$backup/x-ui.db"
[[ $(sqlite3 "$backup/x-ui.db" 'PRAGMA quick_check;') == ok ]] || die 'SQLite snapshot failed'
{ ufw status verbose; nft -s list ruleset; } >"$backup/firewall.before"
(cd -- "$backup"; sha256sum unit.before policy.before system-before.tar x-ui.db firewall.before >SHA256SUMS; sha256sum -c SHA256SUMS >/dev/null)
stage=''
owned_inode=''
committed=0
owned_directory() {
  [[ -n $owned_inode && -d $1 && ! -L $1 && $(stat -c '%d:%i' "$1") == "$owned_inode" ]]
}
cleanup() {
  local status=$? rollback_ok=1
  trap - EXIT INT TERM HUP
  set +e
  if ((committed == 0)); then
    # The staged directory inode is recorded before publication. A signal in
    # mv, or a partial install into staging, cannot leave an orphan at the
    # canonical destination. Preserve the complete owned tree in the snapshot;
    # never delete or move a foreign directory that replaced it.
    if [[ -e $dropin_dir || -L $dropin_dir ]]; then
      if owned_directory "$dropin_dir"; then
        mv -T -- "$dropin_dir" "$backup/published.failed" || rollback_ok=0
      else rollback_ok=0; fi
    fi
    if [[ -n $stage && (-e $stage || -L $stage) ]]; then
      if owned_directory "$stage"; then
        mv -T -- "$stage" "$backup/staged.failed" || rollback_ok=0
      else rollback_ok=0; fi
    fi
    systemctl daemon-reload >/dev/null 2>&1 || rollback_ok=0
    read_policy >"$backup/policy.after-rollback" || rollback_ok=0
    cmp -s "$backup/policy.before" "$backup/policy.after-rollback" || rollback_ok=0
    printf 'NGINX_RESTART_ROLLBACK_OK=%s SNAPSHOT=%s\n' "$rollback_ok" "$backup" >&2
  fi
  ((rollback_ok)) || status=1
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP
stage=$(mktemp -d -p /etc/systemd/system .vpn-nginx-restart.XXXXXXXX)
owned_inode=$(stat -c '%d:%i' "$stage")
install -o root -g root -m 0644 "$policy_source" "$stage/30-vpn-nginx-restart.conf"
cmp -s "$policy_source" "$stage/30-vpn-nginx-restart.conf"
chmod 0755 "$stage"
mv -nT -- "$stage" "$dropin_dir"
[[ ! -e $stage && ! -L $stage ]] || die 'Nginx drop-in destination was claimed by another owner'
owned_directory "$dropin_dir" || die 'Nginx restart directory changed during publication'
systemctl daemon-reload
verify_policy || die 'effective Nginx restart policy failed readback'
systemctl is-active --quiet nginx.service
[[ $(systemctl show nginx.service -p MainPID --value) == "$before_pid" ]] || die 'Nginx master changed during recovery-policy installation'
touch "$backup/COMMITTED"
committed=1
printf 'NGINX_RESTART_POLICY_INSTALLED=1 SNAPSHOT=%s\n' "$backup"
