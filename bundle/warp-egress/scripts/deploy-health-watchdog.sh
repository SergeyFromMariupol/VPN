#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

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
  if grep -Fxq active "$backup_dir/service-active-before" 2>/dev/null; then
    systemctl start krysyuk-warp-health.service >/dev/null 2>&1 || true
  fi
  if grep -Fxq active "$backup_dir/timer-active-before" 2>/dev/null; then
    systemctl start krysyuk-warp-health.timer >/dev/null 2>&1 || true
  fi
}
rollback() {
  local target restore_root
  systemctl stop krysyuk-warp-health.timer krysyuk-warp-health.service >/dev/null 2>&1 || true
  systemctl disable krysyuk-warp-health.timer >/dev/null 2>&1 || true
  for target in "${targets[@]}"; do
    rm -f -- "$target"
  done
  if [[ -d "$backup_dir/rootfs" ]]; then
    while IFS= read -r -d '' restore_root; do
      cp -a -- "$restore_root" /
    done < <(find "$backup_dir/rootfs" -mindepth 1 -maxdepth 1 -print0)
  fi
  systemctl daemon-reload >/dev/null 2>&1 || true
  if grep -Fxq enabled "$backup_dir/timer-enabled-before" 2>/dev/null; then
    systemctl enable krysyuk-warp-health.timer >/dev/null 2>&1 || true
  fi
  resume_original_runtime
}
on_exit() {
  local rc=$?
  trap - EXIT HUP INT TERM
  if (( committed == 0 )); then
    clear_uncommitted_warp_phase_marker || true
    if (( snapshot_complete == 1 )); then
      rollback
      printf 'WARP_HEALTH_AUTO_ROLLBACK=1 backup=%s\n' "$backup_dir" >&2
    else
      resume_original_runtime
      printf '%s\n' 'WARP_HEALTH_DEPLOY_ABORTED_BEFORE_SNAPSHOT=1' >&2
    fi
  fi
  exit "$rc"
}
trap on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

systemctl stop krysyuk-warp-health.timer krysyuk-warp-health.service >/dev/null 2>&1 || true
if systemctl is-active --quiet krysyuk-warp-health.timer || \
   systemctl is-active --quiet krysyuk-warp-health.service; then
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
