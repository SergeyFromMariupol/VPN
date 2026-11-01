#!/usr/bin/env bash
# Called only from the rendered fresh-host installer, after the direct stack.
set -Eeuo pipefail
umask 077

[[ $(id -u) -eq 0 ]] || { printf '%s\n' 'ERROR: run as root' >&2; exit 1; }
target_env=/etc/germanyvpn-target.env
[[ -f "$target_env" && ! -L "$target_env" ]] || {
  printf '%s\n' 'ERROR: validated target contract is missing' >&2; exit 1;
}
[[ $(stat -c '%u' "$target_env") == 0 ]] || exit 1
target_mode=$(stat -c '%a' "$target_env")
(( (8#$target_mode & 8#022) == 0 )) || exit 1
TARGET_TLS_MODE=letsencrypt
# shellcheck disable=SC1090,SC1091
source "$target_env"
case $TARGET_TLS_MODE in
  letsencrypt|none) ;;
  *) printf '%s\n' 'ERROR: unsupported saved certificate mode' >&2; exit 1;;
esac
export TARGET_TLS_MODE
[[ ${TARGET_IPV4:-} == '@TARGET_IPV4@' && ${TARGET_INTERFACE:-} == '@TARGET_INTERFACE@' ]] || {
  printf '%s\n' 'ERROR: rendered WARP bundle does not match the target contract' >&2; exit 1;
}

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=phase-state.sh
source "$script_dir/phase-state.sh"
# shellcheck source=common.sh
source "$script_dir/common.sh"
[[ -d /var/lib/vpn-installer && ! -L /var/lib/vpn-installer ]] || exit 1
[[ $(stat -c '%u:%a' /var/lib/vpn-installer) == 0:700 ]] || exit 1
if [[ -e "$WARP_INSTALL_PHASE_DIR" || -L "$WARP_INSTALL_PHASE_DIR" ]]; then
  assert_warp_phase_directory
else
  install -d -o root -g root -m 0700 "$WARP_INSTALL_PHASE_DIR"
fi
export VPN_WARP_RECORD_PHASES=1

for phase in base deploy watchdog; do
  if warp_phase_exists "$phase"; then
    validate_warp_phase_marker "$phase" || die 'unsafe WARP phase checkpoint'
  fi
done
if warp_phase_exists deploy && ! warp_phase_exists base; then
  die 'WARP deploy checkpoint lacks its prerequisite base checkpoint'
fi
if warp_phase_exists watchdog && ! warp_phase_exists deploy; then
  die 'WARP health checkpoint lacks its prerequisite deploy checkpoint'
fi

validate_base() {
  assert_xray_version
  assert_warp_version
  assert_warp_apt_pin
  [[ $(systemctl is-enabled warp-svc.service 2>/dev/null || true) == masked ]] || \
    die 'host WARP service must remain masked'
  if systemctl is-active --quiet warp-svc.service; then
    die 'host WARP service must remain inactive'
  fi
  [[ $(getent passwd xraywarp | cut -d: -f6) == /nonexistent &&
     $(getent passwd xraywarp | cut -d: -f7) == /usr/sbin/nologin &&
     $(id -gn xraywarp) == xraywarp ]] || die 'WARP connector identity changed'
}

if ! warp_phase_exists base; then
  "$script_dir/bootstrap-ubuntu2404.sh"
fi
validate_warp_phase_marker base
validate_base

if ! warp_phase_exists deploy; then
  # On this fresh installation there are no user sessions yet. Quiesce the
  # public Xray only while the connector's physical leak capture runs: its
  # unrelated direct DNS traffic would otherwise contaminate that capture.
  # Always restore it, including when the WARP transaction rolls itself back.
  xui_quiesced=0
  restore_public_stack() {
    local rc=$?
    trap - EXIT HUP INT TERM
    if (( xui_quiesced == 1 )); then
      systemctl start x-ui.service || rc=1
      systemctl is-active --quiet x-ui.service || rc=1
    fi
    exit "$rc"
  }
  trap restore_public_stack EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  systemctl is-active --quiet x-ui.service
  xui_quiesced=1
  systemctl stop x-ui.service
  if systemctl is-active --quiet x-ui.service; then
    printf '%s\n' 'ERROR: could not quiesce fresh public Xray for leak capture' >&2
    exit 1
  fi
  CONFIRM_WARP_EGRESS_DEPLOY="DEPLOY-STANDALONE-WARP-NETNS-$TARGET_IPV4" \
    "$script_dir/deploy.sh" --initialize
  systemctl start x-ui.service
  systemctl is-active --quiet x-ui.service
  xui_quiesced=0
  trap - EXIT HUP INT TERM
fi
validate_warp_phase_marker deploy
/opt/krysyuk-warp-egress/tests/test-smoke.sh
/opt/krysyuk-warp-egress/tests/test-main-route-isolation.sh
/opt/krysyuk-warp-egress/tests/test-e2e-local.sh
/opt/krysyuk-warp-egress/tests/test-invalid.sh

if ! warp_phase_exists watchdog; then
  CONFIRM_WARP_HEALTH_DEPLOY="DEPLOY-STANDALONE-WARP-HEALTH-$TARGET_IPV4" \
    "$script_dir/deploy-health-watchdog.sh"
fi
validate_warp_phase_marker watchdog
/opt/krysyuk-warp-egress/tests/test-health-watchdog.sh
printf '%s\n' 'WARP_FRESH_INSTALL_OK=1'
