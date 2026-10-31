#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

test_failure_line=0
test_failure_file=test-fail-closed.sh
trap 'test_failure_line=$LINENO; test_failure_file=${BASH_SOURCE[0]##*/}' ERR

readonly lib=/usr/local/libexec/krysyuk-warp-egress/common.sh
# shellcheck source=../scripts/common.sh
source "$lib"

require_root
[[ ${I_UNDERSTAND_DISRUPTIVE:-} == YES ]] || \
  die 'set I_UNDERSTAND_DISRUPTIVE=YES and keep a second SSH session'
for command_name in curl nft systemctl systemd-run timeout; do
  require_command "$command_name"
done
load_warp_egress_env
/opt/krysyuk-warp-egress/tests/test-smoke.sh >/dev/null
assert_main_routing_unchanged

restore_unit="krysyuk-warp-egress-autorestore-$(date +%s)-$$"
readonly restore_unit
restore_required=0
recovered=0

recover_and_verify() {
  /usr/local/libexec/krysyuk-warp-egress/warp-emergency-reconnect.sh >/dev/null || return 1
  wait_for_warp 90 || return 1
  systemctl is-active --quiet krysyuk-warp-egress-guard.service || return 1
  systemctl is-active --quiet krysyuk-xray-warp-egress.service || return 1
  /opt/krysyuk-warp-egress/tests/test-smoke.sh >/dev/null || return 1
  /opt/krysyuk-warp-egress/tests/test-main-route-isolation.sh >/dev/null || return 1
  /opt/krysyuk-warp-egress/tests/test-e2e-local.sh >/dev/null || return 1
  recovered=1
}

cleanup() {
  local rc=$?
  trap - EXIT ERR
  if (( rc != 0 )); then
    printf 'WARP_FAIL_CLOSED_TEST_FAILED=1 file=%s line=%s rc=%s\n' \
      "$test_failure_file" "$test_failure_line" "$rc" >&2
  fi
  if (( restore_required == 1 && recovered == 0 )); then
    recover_and_verify || true
  fi
  if (( recovered == 1 )); then
    systemctl stop "${restore_unit}.timer" "${restore_unit}.service" \
      >/dev/null 2>&1 || true
  else
    printf 'WARP_EGRESS_AUTORESTORE_TIMER_RETAINED=%s\n' "$restore_unit" >&2
    (( rc != 0 )) || rc=1
  fi
  exit "$rc"
}
trap cleanup EXIT

systemd-run --quiet --unit="$restore_unit" --on-active=2m \
  /usr/local/libexec/krysyuk-warp-egress/warp-emergency-reconnect.sh
restore_required=1

xraywarp_drop_packets() {
  netns_exec nft list chain inet "$WARP_EGRESS_TABLE" output \
    | awk '!found && /skuid/ && /drop/ {
        for (i = 1; i <= NF; i++) if ($i == "packets") {
          print $(i + 1); found=1; break
        }
      }'
}
before_drop=$(xraywarp_drop_packets)
[[ "$before_drop" =~ ^[0-9]+$ ]] || die 'could not read the pre-outage owner-drop counter'

systemctl stop krysyuk-warp-netns-daemon.service
for _ in $(seq 1 20); do
  if ! netns_exec ip link show "$WARP_EGRESS_IFACE" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
warp_status_connected && die 'isolated WARP still reports Connected after daemon stop'
systemctl is-active --quiet krysyuk-warp-egress-guard.service || \
  die 'netns guard stopped with WARP'
systemctl is-active --quiet krysyuk-xray-warp-egress.service || \
  die 'Xray connector stopped instead of remaining fail-closed'
assert_main_routing_unchanged

if /opt/krysyuk-warp-egress/tests/test-e2e-local.sh >/dev/null 2>&1; then
  die 'traffic escaped while isolated WARP was stopped'
fi
probe_unit="krysyuk-warp-egress-outage-probe-$(date +%s)-$$"
if systemd-run --quiet --wait --collect --unit="$probe_unit" \
  --property="NetworkNamespacePath=/run/netns/${WARP_NETNS}" \
  --property=User=xraywarp --property=Group=xraywarp \
  --property=CapabilityBoundingSet=CAP_NET_RAW \
  --property=AmbientCapabilities=CAP_NET_RAW \
  /usr/bin/timeout 8 /usr/bin/curl -4kfsS --interface "$WARP_NETNS_VETH" \
  --connect-timeout 4 --max-time 6 https://1.1.1.1/cdn-cgi/trace \
  >/dev/null 2>&1; then
  die 'xraywarp escaped through the physical fallback during the WARP outage'
fi
after_drop=$(xraywarp_drop_packets)
[[ "$after_drop" =~ ^[0-9]+$ && "$after_drop" -gt "$before_drop" ]] || \
  die 'netns owner guard did not record the blocked WARP-outage attempt'
assert_main_routing_unchanged

recover_and_verify || die 'isolated WARP and connector E2E did not recover'
restore_required=0
systemctl stop "${restore_unit}.timer" "${restore_unit}.service" \
  >/dev/null 2>&1 || true
printf '%s\n' 'WARP_EGRESS_FAIL_CLOSED_OK=1'
printf '%s\n' 'WARP_EGRESS_OUTAGE_MAIN_ROUTING_UNCHANGED=1'
printf '%s\n' 'WARP_EGRESS_RECOVERY_E2E_OK=1'
