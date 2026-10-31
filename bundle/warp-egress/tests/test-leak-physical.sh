#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

leak_phase=load-library
leak_failed_line=0
leak_failed_file=test-leak-physical.sh
capture_file=''
capture_pid=''
cleanup() {
  local rc=$?
  trap - EXIT ERR HUP INT TERM
  if [[ -n "$capture_pid" ]] && kill -0 "$capture_pid" 2>/dev/null; then
    kill "$capture_pid" >/dev/null 2>&1 || true
    wait "$capture_pid" >/dev/null 2>&1 || true
  fi
  [[ -z "$capture_file" ]] || rm -f -- "$capture_file"
  if (( rc != 0 )); then
    printf 'WARP_LEAK_TEST_FAILED=1 phase=%s file=%s line=%s rc=%s\n' \
      "$leak_phase" "$leak_failed_file" "$leak_failed_line" "$rc" >&2
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'leak_failed_line=$LINENO; leak_failed_file=${BASH_SOURCE[0]##*/}' ERR
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

readonly lib=/usr/local/libexec/krysyuk-warp-egress/common.sh
# shellcheck source=../scripts/common.sh
source "$lib"

leak_phase=prerequisites
require_root
for command_name in curl getent ip nft systemd-run tcpdump timeout wc; do
  require_command "$command_name"
done
leak_phase=load-env
load_warp_egress_env
leak_phase=route-preflight
assert_main_routing_unchanged
ip link show "$PHYSICAL_IFACE" >/dev/null 2>&1 || die '@TARGET_INTERFACE@ is missing'
physical_address=$NL_PUBLIC_IPV4

leak_phase=resolve-targets
mapfile -t target_ips < <(
  getent ahostsv4 api.ipify.org www.cloudflare.com speed.cloudflare.com example.com \
    | awk '{print $1}' | sort -u
)
target_ips+=(1.1.1.1 8.8.8.8)
mapfile -t target_ips < <(printf '%s\n' "${target_ips[@]}" | sort -u)
(( ${#target_ips[@]} > 0 )) || die 'could not resolve leak-test targets'

filter="src host ${physical_address} and (((tcp or udp) and (dst port 53 or dst port 853)) or ((tcp or udp) and ("
separator=''
for address in "${target_ips[@]}"; do
  filter+="${separator}dst host ${address}"
  separator=' or '
done
filter+=')))'
leak_phase=create-capture
capture_file=$(mktemp /tmp/krysyuk-warp-egress-leak.XXXXXX.pcap)

xraywarp_drop_packets() {
  netns_exec nft list chain inet "$WARP_EGRESS_TABLE" output \
    | awk '!found && /skuid/ && /drop/ {
        for (i = 1; i <= NF; i++) if ($i == "packets") {
          print $(i + 1); found=1; break
        }
      }'
}
leak_phase=read-before-counter
before_drop=$(xraywarp_drop_packets)
[[ "$before_drop" =~ ^[0-9]+$ ]] || die 'could not read xraywarp drop counter'

leak_phase=start-capture
timeout 75 tcpdump -ni "$PHYSICAL_IFACE" -U -w "$capture_file" "$filter" \
  >/dev/null 2>&1 &
capture_pid=$!
sleep 1
kill -0 "$capture_pid" 2>/dev/null || die 'physical-interface capture did not stay active'
leak_phase=connector-e2e
/opt/krysyuk-warp-egress/tests/test-e2e-local.sh >/dev/null || \
  die 'connector E2E failed while physical-interface capture was active'

leak_phase=forced-veth-probe
probe_unit="krysyuk-warp-egress-owner-probe-$(date +%s)-$$"
if systemd-run --quiet --wait --collect --unit="$probe_unit" \
  --property="NetworkNamespacePath=/run/netns/${WARP_NETNS}" \
  --property=User=xraywarp --property=Group=xraywarp \
  --property=CapabilityBoundingSet=CAP_NET_RAW \
  --property=AmbientCapabilities=CAP_NET_RAW \
  /usr/bin/timeout 8 /usr/bin/curl -4kfsS --interface "$WARP_NETNS_VETH" \
  --connect-timeout 4 --max-time 6 https://1.1.1.1/cdn-cgi/trace \
  >/dev/null 2>&1; then
  die 'xraywarp UID escaped through the outer veth'
fi
leak_phase=read-after-counter
after_drop=$(xraywarp_drop_packets)
[[ "$after_drop" =~ ^[0-9]+$ && "$after_drop" -gt "$before_drop" ]] || \
  die 'netns owner guard did not prove the blocked outer-veth attempt'

leak_phase=finish-capture
kill "$capture_pid" >/dev/null 2>&1 || true
wait "$capture_pid" >/dev/null 2>&1 || true
capture_pid=''
leak_phase=read-capture
if ! packet_count=$(tcpdump -nnr "$capture_file" 2>/dev/null | wc -l); then
  die 'could not read the completed physical-interface capture'
fi
if (( packet_count != 0 )); then
  tcpdump -tttt -nnr "$capture_file" 2>/dev/null \
    > /run/krysyuk-warp-egress-leak-summary.txt || true
  chmod 0600 /run/krysyuk-warp-egress-leak-summary.txt
  die 'plaintext target or DNS traffic leaked onto @TARGET_INTERFACE@'
fi
leak_phase=route-postflight
assert_main_routing_unchanged

unset WARP_EGRESS_NL_CLIENT_ID WARP_EGRESS_BRIDGE_CLIENT_ID
unset physical_address filter target_ips address separator
printf '%s\n' 'WARP_EGRESS_PHYSICAL_PLAINTEXT_LEAK_PACKETS=0'
printf '%s\n' 'WARP_EGRESS_NETNS_OWNER_GUARD_BLOCKED_OUTER_VETH=1'
