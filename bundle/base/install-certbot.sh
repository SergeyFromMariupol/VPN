#!/usr/bin/env bash
# Pinned Certbot for trusted domain and short-lived IP certificates.
# Run after install-pinned-base.sh and before acme.sh. No certificate is issued here.
set -Eeuo pipefail
umask 077
readonly CERTBOT_VERSION=5.9.0
readonly VENV=/opt/vpn-certbot
readonly SHIM=/usr/local/bin/certbot
readonly SERVICE_DIR=/etc/systemd/system/certbot.service.d
readonly TIMER_DIR=/etc/systemd/system/certbot.timer.d
readonly DROPIN=20-vpn-certbot.conf
source_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
readonly source_root
readonly lock="$source_root/certbot-requirements.txt"
readonly validator="$source_root/verify-certbot.py"
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
[[ $# == 1 && ($1 == --apply || $1 == --check-only) ]] || die 'usage: install-certbot.sh --apply|--check-only'
[[ $EUID == 0 ]] || die 'root is required'
for name in python3 systemctl stat sha256sum install flock find cmp; do command -v "$name" >/dev/null; done
# shellcheck disable=SC1091
source /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 24.04 && $(dpkg --print-architecture) == amd64 ]] || die 'Ubuntu 24.04 amd64 is required'
for path in "$lock" "$validator"; do
  [[ -f $path && ! -L $path && $(stat -c %u "$path") == 0 ]] || die 'unsafe Certbot source file'
  (( (8#$(stat -c %a "$path") & 8#022) == 0 )) || die 'writable Certbot source file'
done
lock_hash=$(sha256sum "$lock"); lock_hash=${lock_hash%% *}
readonly lock_hash
readonly certbot_lock_root=/run/vpn-certbot-install
if [[ ! -e $certbot_lock_root && ! -L $certbot_lock_root ]]; then mkdir -m 0700 "$certbot_lock_root"; fi
[[ -d $certbot_lock_root && ! -L $certbot_lock_root && $(stat -c '%u:%g:%a' "$certbot_lock_root") == 0:0:700 ]] || die 'unsafe Certbot lock directory'
if [[ -e $certbot_lock_root/install.lock || -L $certbot_lock_root/install.lock ]]; then
  [[ -f $certbot_lock_root/install.lock && ! -L $certbot_lock_root/install.lock && $(stat -c '%u:%g:%a:%h' "$certbot_lock_root/install.lock") == 0:0:600:1 ]] || die 'unsafe Certbot lock file'
fi
exec 9>"$certbot_lock_root/install.lock"
flock -n 9 || die 'another Certbot installation is in progress'

service_dropin() {
  printf '[Service]\nExecStart=\nExecStart=%s/bin/certbot -q renew\n' "$VENV"
}
timer_dropin() {
  # Short-lived IP certificates last about six days. Check every hour; Certbot
  # decides when a certificate is due using its ACME renewal information.
  printf '[Timer]\nOnCalendar=\nOnCalendar=hourly\nRandomizedDelaySec=15m\nPersistent=true\n'
}
verify_install() {
  local path
  [[ -d $VENV && ! -L $VENV && $(stat -c %u "$VENV") == 0 ]] || return 1
  [[ -f $VENV/.vpn-installer-version && ! -L $VENV/.vpn-installer-version ]] || return 1
  [[ $(stat -c '%u:%g:%a:%h' "$VENV/.vpn-installer-version") == 0:0:600:1 ]] || return 1
  cmp -s "$VENV/.vpn-installer-version" <(printf '%s\n%s\n' "$CERTBOT_VERSION" "$lock_hash") || return 1
  [[ -L $SHIM && $(stat -c %u "$SHIM") == 0 && $(readlink "$SHIM") == "$VENV/bin/certbot" ]] || return 1
  for path in "$SERVICE_DIR" "$TIMER_DIR"; do
    [[ -d $path && ! -L $path && $(stat -c '%u:%g:%a' "$path") == 0:0:755 ]] || return 1
    [[ -f $path/$DROPIN && ! -L $path/$DROPIN && $(stat -c '%u:%g:%a:%h' "$path/$DROPIN") == 0:0:644:1 ]] || return 1
  done
  cmp -s "$SERVICE_DIR/$DROPIN" <(service_dropin) || return 1
  cmp -s "$TIMER_DIR/$DROPIN" <(timer_dropin) || return 1
  [[ -z $(find -P "$VENV" ! -type l \( ! -user root -o -perm /022 \) -print -quit) ]] || return 1
  "$VENV/bin/python" -I "$validator" "$lock" "$VENV" || return 1
  "$VENV/bin/python" -I -m pip --isolated check >/dev/null || return 1
  [[ $("$VENV/bin/certbot" --version 2>/dev/null) == "certbot $CERTBOT_VERSION" ]] || return 1
  "$VENV/bin/certbot" --help all | grep -F -- '--ip-address' >/dev/null || return 1
  "$VENV/bin/certbot" --help all | grep -F -- '--required-profile' >/dev/null || return 1
  systemctl show -p ExecStart --value certbot.service | grep -F "$VENV/bin/certbot -q renew" >/dev/null || return 1
  systemctl show -p DropInPaths --value certbot.service | grep -F "$SERVICE_DIR/$DROPIN" >/dev/null || return 1
  systemctl show -p DropInPaths --value certbot.timer | grep -F "$TIMER_DIR/$DROPIN" >/dev/null || return 1
  systemctl is-enabled --quiet certbot.timer && systemctl is-active --quiet certbot.timer
}
if [[ -e $VENV/.vpn-installer-version || -L $VENV/.vpn-installer-version ]]; then
  verify_install || die 'installed pinned Certbot state differs from the reviewed contract'
  printf 'PINNED_CERTBOT_OK=1 VERSION=%s\n' "$CERTBOT_VERSION"
  exit 0
fi
[[ $1 == --apply ]] || die 'pinned Certbot has not been installed'
for path in "$VENV" "$SHIM" "$SERVICE_DIR" "$TIMER_DIR"; do
  [[ ! -e $path && ! -L $path ]] || die "unmanaged Certbot path exists: $path"
done
systemctl is-enabled --quiet certbot.timer || die 'base certbot.timer is not enabled'
systemctl is-active --quiet certbot.timer || die 'base certbot.timer is not active'
! systemctl is-active --quiet certbot.service || die 'a Certbot renewal is already active'
[[ $(python3 -I -c 'import sys; print("%d.%d" % sys.version_info[:2])') == 3.12 ]] || die 'CPython 3.12 is required'
snapshot=$(mktemp -d -p /var/backups "vpn-certbot-$(date -u +%Y%m%dT%H%M%SZ).XXXXXXXX")
readonly snapshot
chmod 0700 "$snapshot"
systemctl cat certbot.service certbot.timer >"$snapshot/units.before"
systemctl show certbot.service certbot.timer >"$snapshot/unit-state.before"
printf '%s\n' "$VENV" "$SHIM" "$SERVICE_DIR" "$TIMER_DIR" >"$snapshot/managed-paths-absent.before"
(cd -- "$snapshot"; sha256sum -- *.before >SHA256SUMS; sha256sum -c SHA256SUMS >/dev/null)
committed=0
venv_identity=''
service_identity=''
timer_identity=''
shim_created=0
timer_stopped=0
cleanup() {
  local status=$? rollback_ok=1 path identity
  trap - EXIT INT TERM HUP
  set +e
  if ((committed == 0)); then
    systemctl stop certbot.timer >/dev/null 2>&1 || rollback_ok=0
    if ((shim_created)); then
      if [[ -L $SHIM && $(readlink "$SHIM") == "$VENV/bin/certbot" ]]; then rm -- "$SHIM"; else rollback_ok=0; fi
    fi
    for path in "$SERVICE_DIR" "$TIMER_DIR"; do
      identity=$service_identity; [[ $path != "$TIMER_DIR" ]] || identity=$timer_identity
      if [[ -n $identity ]]; then
        if [[ -d $path && ! -L $path && $(stat -c '%d:%i' "$path") == "$identity" ]]; then
          mv -- "$path" "$snapshot/$(basename "$path").failed" || rollback_ok=0
        else rollback_ok=0; fi
      fi
    done
    if [[ -n $venv_identity ]]; then
      if [[ -d $VENV && ! -L $VENV && $(stat -c '%d:%i' "$VENV") == "$venv_identity" ]]; then
        mv -- "$VENV" "$snapshot/venv.failed" || rollback_ok=0
      else rollback_ok=0; fi
    fi
    systemctl daemon-reload >/dev/null 2>&1 || rollback_ok=0
    if ((timer_stopped)); then systemctl start certbot.timer >/dev/null 2>&1 || rollback_ok=0; fi
    printf 'CERTBOT_ROLLBACK_OK=%s SNAPSHOT=%s\n' "$rollback_ok" "$snapshot" >&2
    ((status != 0)) || status=1
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP
systemctl stop certbot.timer
timer_stopped=1
! systemctl is-active --quiet certbot.service || die 'a renewal began before timer quiescence'
install -d -o root -g root -m 0755 "$VENV"
venv_identity=$(stat -c '%d:%i' "$VENV")
python3 -I -m venv "$VENV"
# --isolated ignores user pip configuration. Every runtime wheel and dependency
# is pinned with an official PyPI SHA-256; source distributions are forbidden.
"$VENV/bin/python" -I -m pip --isolated install --index-url https://pypi.org/simple \
  --disable-pip-version-check --no-cache-dir --require-hashes --only-binary=:all: -r "$lock"
"$VENV/bin/python" -I "$validator" "$lock" "$VENV"
install -d -o root -g root -m 0755 "$SERVICE_DIR"
service_identity=$(stat -c '%d:%i' "$SERVICE_DIR")
install -d -o root -g root -m 0755 "$TIMER_DIR"
timer_identity=$(stat -c '%d:%i' "$TIMER_DIR")
service_dropin >"$SERVICE_DIR/$DROPIN"
timer_dropin >"$TIMER_DIR/$DROPIN"
chmod 0644 "$SERVICE_DIR/$DROPIN" "$TIMER_DIR/$DROPIN"
ln -s "$VENV/bin/certbot" "$SHIM"
shim_created=1
printf '%s\n%s\n' "$CERTBOT_VERSION" "$lock_hash" >"$VENV/.vpn-installer-version"
chmod 0600 "$VENV/.vpn-installer-version"
systemctl daemon-reload
systemctl start certbot.timer
verify_install || die 'pinned Certbot live verification failed'
touch "$snapshot/COMMITTED"
committed=1
printf 'PINNED_CERTBOT_OK=1 VERSION=%s\n' "$CERTBOT_VERSION"
