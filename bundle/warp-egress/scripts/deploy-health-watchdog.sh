#!/usr/bin/env bash

set -Eeuo pipefail
umask 077
export LC_ALL=C LANG=C LANGUAGE=C
unset PYTHONOPTIMIZE PYTHONPATH PYTHONHOME PYTHONUSERBASE PYTHONSTARTUP PYTHONINSPECT

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
readonly script_dir
bundle_root=$(cd -- "$script_dir/.." && pwd -P)
readonly bundle_root
# shellcheck source=phase-state.sh
source "$script_dir/phase-state.sh"

[[ $(id -u) -eq 0 ]] || { echo 'ERROR: run as root' >&2; exit 1; }
[[ ${CONFIRM_WARP_HEALTH_DEPLOY:-} == 'DEPLOY-STANDALONE-WARP-HEALTH-@TARGET_IPV4@' ]] || {
  echo 'ERROR: exact CONFIRM_WARP_HEALTH_DEPLOY value is required' >&2
  exit 1
}
for command_name in bash cp date find grep install rm stat systemctl systemd-analyze touch; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'ERROR: required command is missing: %s\n' "$command_name" >&2
    exit 1
  }
done

readonly backup_root=/var/backups/krysyuk-standalone
deploy_id=$(date -u +%Y%m%dT%H%M%SZ)-warp-health-watchdog
readonly deploy_id
readonly backup_dir="$backup_root/$deploy_id"
readonly targets=(
  /usr/local/libexec/krysyuk-warp-egress/warp-emergency-reconnect.sh
  /usr/local/libexec/krysyuk-warp-egress/warp-health-watchdog.sh
  /etc/systemd/system/krysyuk-warp-health.service
  /etc/systemd/system/krysyuk-warp-health.timer
  /opt/krysyuk-warp-egress/tests/test-health-watchdog.sh
  /var/lib/krysyuk-warp-health/failure-streak
  /var/lib/krysyuk-warp-health/last-recovery-epoch
  /var/lib/krysyuk-warp-health/last-success-epoch
)
readonly state_targets=(
  /var/lib/krysyuk-warp-health/failure-streak
  /var/lib/krysyuk-warp-health/last-recovery-epoch
  /var/lib/krysyuk-warp-health/last-success-epoch
)

if [[ -e /var/lib/krysyuk-warp-health || -L /var/lib/krysyuk-warp-health ]]; then
  [[ -d /var/lib/krysyuk-warp-health && ! -L /var/lib/krysyuk-warp-health ]] || {
    echo 'ERROR: unsafe WARP health state directory' >&2
    exit 1
  }
  [[ $(stat -c '%U:%G %a' /var/lib/krysyuk-warp-health) == 'root:root 700' ]] || {
    echo 'ERROR: unsafe WARP health state directory ownership/mode' >&2
    exit 1
  }
fi

install -d -o root -g root -m 0700 "$backup_root" "$backup_dir/rootfs"
systemctl is-enabled krysyuk-warp-health.timer >"$backup_dir/timer-enabled-before" 2>/dev/null || true
systemctl is-active krysyuk-warp-health.timer >"$backup_dir/timer-active-before" 2>/dev/null || true
systemctl is-active krysyuk-warp-health.service >"$backup_dir/service-active-before" 2>/dev/null || true

for target in "${targets[@]}"; do
  [[ ! -L "$target" ]] || {
    printf 'ERROR: unsafe target symlink: %s\n' "$target" >&2
    exit 1
  }
  if [[ -e "$target" ]]; then
    [[ -f "$target" ]] || {
      printf 'ERROR: unsafe non-regular target: %s\n' "$target" >&2
      exit 1
    }
  fi
done

snapshot_complete=0
committed=0
resume_original_runtime() {
  local failed=0
  if grep -Fxq active "$backup_dir/service-active-before" 2>/dev/null; then
    systemctl start krysyuk-warp-health.service >/dev/null 2>&1 || failed=1
  fi
  if grep -Fxq active "$backup_dir/timer-active-before" 2>/dev/null; then
    systemctl start krysyuk-warp-health.timer >/dev/null 2>&1 || failed=1
  fi
  return "$failed"
}
quiesce_health_units() {
  local unit state stop_status
  for unit in krysyuk-warp-health.timer krysyuk-warp-health.service; do
    stop_status=0
    systemctl stop "$unit" >/dev/null 2>&1 || stop_status=$?
    state=$(systemctl show "$unit" -p LoadState -p ActiveState -p MainPID 2>/dev/null) || return 1
    # On the first deployment these exact units do not exist yet. Only an
    # explicit missing/inactive read-back makes a failed stop harmless.
    if grep -Fxq 'LoadState=not-found' <<<"$state"; then
      grep -Fxq 'ActiveState=inactive' <<<"$state" || return 1
      continue
    fi
    (( stop_status == 0 )) || return 1
    grep -Eq '^LoadState=(loaded|masked)$' <<<"$state" || return 1
    grep -Eq '^ActiveState=(inactive|failed)$' <<<"$state" || return 1
    if [[ $unit == *.service ]]; then
      grep -Fxq 'MainPID=0' <<<"$state" || return 1
    fi
  done
}
rollback() {
  local target restore_root rollback_ok=1
  # A live probe can write the state files while they are being restored. An
  # unavailable bus or incomplete read-back cannot prove that it stopped.
  if ! quiesce_health_units; then
    printf '%s\n' 'WARP_HEALTH_ROLLBACK_RESOURCES_RETAINED=1' >&2
    return 1
  fi
  systemctl disable krysyuk-warp-health.timer >/dev/null 2>&1 || rollback_ok=0
  for target in "${targets[@]}"; do
    rm -f -- "$target" || rollback_ok=0
  done
  if [[ -d "$backup_dir/rootfs" ]]; then
    while IFS= read -r -d '' restore_root; do
      cp -a -- "$restore_root" / || rollback_ok=0
    done < <(find "$backup_dir/rootfs" -mindepth 1 -maxdepth 1 -print0)
  else
    rollback_ok=0
  fi
  systemctl daemon-reload >/dev/null 2>&1 || rollback_ok=0
  # Do not activate an incompletely restored script or timer after an I/O
  # failure. Continue all file recovery first, then report the exact outcome.
  if (( rollback_ok == 1 )); then
    if grep -Fxq enabled "$backup_dir/timer-enabled-before" 2>/dev/null; then
      systemctl enable krysyuk-warp-health.timer >/dev/null 2>&1 || rollback_ok=0
    fi
    resume_original_runtime || rollback_ok=0
  fi
  (( rollback_ok == 1 ))
}
on_exit() {
  local rc=$? rollback_ok=1
  trap - EXIT HUP INT TERM
  if (( committed == 0 )); then
    clear_uncommitted_warp_phase_marker || rollback_ok=0
    if (( snapshot_complete == 1 )); then
      rollback || rollback_ok=0
      printf 'WARP_HEALTH_AUTO_ROLLBACK_OK=%s backup=%s\n' "$rollback_ok" "$backup_dir" >&2
    else
      resume_original_runtime || rollback_ok=0
      printf '%s\n' 'WARP_HEALTH_DEPLOY_ABORTED_BEFORE_SNAPSHOT=1' >&2
    fi
    if (( rollback_ok == 0 && rc == 0 )); then rc=1; fi
  fi
  exit "$rc"
}
trap on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if ! quiesce_health_units; then
  echo 'ERROR: failed to quiesce the WARP health timer/service' >&2
  exit 1
fi

for target in "${state_targets[@]}"; do
  if [[ -e "$target" ]]; then
    [[ $(stat -c '%U:%G %a' "$target") == 'root:root 600' ]] || {
      printf 'ERROR: unsafe WARP health state ownership/mode: %s\n' "$target" >&2
      exit 1
    }
    state_value=$(<"$target")
    [[ "$state_value" =~ ^[0-9]+$ ]] || {
      printf 'ERROR: malformed WARP health state: %s\n' "$target" >&2
      exit 1
    }
  fi
done

for target in "${targets[@]}"; do
  if [[ -e "$target" ]]; then
    cp -a --parents -- "$target" "$backup_dir/rootfs"
  else
    printf '%s\n' "$target" >>"$backup_dir/absent-before.txt"
  fi
done
snapshot_complete=1

bash -n "$bundle_root/scripts/warp-emergency-reconnect.sh"
bash -n "$bundle_root/scripts/warp-health-watchdog.sh"
bash -n "$bundle_root/tests/test-health-watchdog.sh"
bash -n "$bundle_root/tests/test-health-watchdog-semantics.sh"
bash "$bundle_root/tests/test-health-watchdog-semantics.sh"
install -o root -g root -m 0755 \
  "$bundle_root/scripts/warp-emergency-reconnect.sh" \
  "$bundle_root/scripts/warp-health-watchdog.sh" \
  /usr/local/libexec/krysyuk-warp-egress/
systemd-analyze verify \
  "$bundle_root/systemd/krysyuk-warp-health.service" \
  "$bundle_root/systemd/krysyuk-warp-health.timer"
install -o root -g root -m 0644 \
  "$bundle_root/systemd/krysyuk-warp-health.service" \
  "$bundle_root/systemd/krysyuk-warp-health.timer" \
  /etc/systemd/system/
install -o root -g root -m 0755 \
  "$bundle_root/tests/test-health-watchdog.sh" \
  /opt/krysyuk-warp-egress/tests/

systemctl daemon-reload
systemctl enable --now krysyuk-warp-health.timer
/opt/krysyuk-warp-egress/tests/test-health-watchdog.sh

write_warp_phase_marker watchdog
touch "$backup_dir/COMMITTED"
committed=1
trap - EXIT HUP INT TERM
printf 'WARP_HEALTH_DEPLOY_OK=1 backup=%s\n' "$backup_dir"
