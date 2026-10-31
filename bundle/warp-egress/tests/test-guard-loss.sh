#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

test_failure_line=0
test_failure_file=test-guard-loss.sh
trap 'test_failure_line=$LINENO; test_failure_file=${BASH_SOURCE[0]##*/}' ERR

readonly lib=/usr/local/libexec/krysyuk-warp-egress/common.sh
# shellcheck source=../scripts/common.sh
source "$lib"

require_root
[[ ${I_UNDERSTAND_DISRUPTIVE:-} == YES ]] || \
  die 'set I_UNDERSTAND_DISRUPTIVE=YES and keep a second SSH session'
for command_name in curl date getent ip nft python3 systemctl systemd-run tcpdump timeout wc; do
  require_command "$command_name"
done
load_warp_egress_env
/opt/krysyuk-warp-egress/tests/test-smoke.sh >/dev/null
assert_main_routing_unchanged

restore_unit="krysyuk-warp-guard-autorestore-$(date +%s)-$$"
readonly restore_unit
capture_file=''
capture_pid=''
restore_required=0
recovered=0

recover_and_verify() {
  /usr/local/libexec/krysyuk-warp-egress/warp-emergency-reconnect.sh >/dev/null || return 1
  wait_for_warp 90 || return 1
  /opt/krysyuk-warp-egress/tests/test-smoke.sh >/dev/null || return 1
  /opt/krysyuk-warp-egress/tests/test-main-route-isolation.sh >/dev/null || return 1
  /opt/krysyuk-warp-egress/tests/test-e2e-local.sh >/dev/null || return 1
  recovered=1
}

cleanup() {
  local rc=$?
  trap - EXIT ERR
  if (( rc != 0 )); then
    printf 'WARP_GUARD_LOSS_TEST_FAILED=1 file=%s line=%s rc=%s\n' \
      "$test_failure_file" "$test_failure_line" "$rc" >&2
  fi
  if [[ -n "$capture_pid" ]] && kill -0 "$capture_pid" 2>/dev/null; then
    kill "$capture_pid" >/dev/null 2>&1 || true
    wait "$capture_pid" >/dev/null 2>&1 || true
  fi
  [[ -z "$capture_file" ]] || rm -f -- "$capture_file"
  if (( restore_required == 1 && recovered == 0 )); then
    recover_and_verify || true
  fi
  if (( recovered == 1 )); then
    systemctl stop "${restore_unit}.timer" "${restore_unit}.service" \
      >/dev/null 2>&1 || true
  else
    printf 'WARP_EGRESS_GUARD_AUTORESTORE_TIMER_RETAINED=%s\n' "$restore_unit" >&2
    (( rc != 0 )) || rc=1
  fi
  exit "$rc"
}
trap cleanup EXIT

mapfile -t target_ips < <(
  getent ahostsv4 api.ipify.org www.cloudflare.com speed.cloudflare.com example.com \
    | awk '{print $1}' | sort -u
)
target_ips+=(1.1.1.1 8.8.8.8)
mapfile -t target_ips < <(printf '%s\n' "${target_ips[@]}" | sort -u)
(( ${#target_ips[@]} > 0 )) || die 'could not resolve guard-loss leak targets'
filter="src host ${NL_PUBLIC_IPV4} and (((tcp or udp) and (dst port 53 or dst port 853)) or ((tcp or udp) and ("
separator=''
for address in "${target_ips[@]}"; do
  filter+="${separator}dst host ${address}"
  separator=' or '
done
filter+=')))'

host_untagged_drop_packets() {
  nft list chain inet "$WARP_HOST_GUARD_TABLE" forward \
    | awk '!found && /iifname "kw-host"/ && /drop/ {
        for (i = 1; i <= NF; i++) if ($i == "packets") {
          print $(i + 1); found=1; break
        }
      }'
}

before_drop=$(host_untagged_drop_packets)
[[ "$before_drop" =~ ^[0-9]+$ ]] || die 'could not read host untagged-drop counter'
systemd-run --quiet --unit="$restore_unit" --on-active=2m \
  /usr/local/libexec/krysyuk-warp-egress/warp-emergency-reconnect.sh
restore_required=1

capture_file=$(mktemp /tmp/krysyuk-warp-guard-loss.XXXXXX.pcap)
timeout 90 tcpdump -ni "$PHYSICAL_IFACE" -U -w "$capture_file" "$filter" \
  >/dev/null 2>&1 &
capture_pid=$!
sleep 1

netns_exec nft delete table inet "$WARP_EGRESS_TABLE"
if netns_exec nft list table inet "$WARP_EGRESS_TABLE" >/dev/null 2>&1; then
  die 'namespace guard table survived the deletion test'
fi
systemctl is-active --quiet krysyuk-xray-warp-egress.service || \
  die 'Xray stopped before the guard-loss barrier was exercised'

udp_probe_unit="krysyuk-warp-guard-loss-udp-$(date +%s)-$$"
systemd-run --quiet --wait --collect --unit="$udp_probe_unit" \
  --property="NetworkNamespacePath=/run/netns/${WARP_NETNS}" \
  --property=User=xraywarp --property=Group=xraywarp \
  --property=CapabilityBoundingSet=CAP_NET_RAW \
  --property=AmbientCapabilities=CAP_NET_RAW \
  /usr/bin/python3 -c \
  'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b"kw-warp\0"); [s.sendto(b"Q"*1200,("8.8.8.8",443)) for _ in range(3)]; s.close()' \
  >/dev/null 2>&1 || true

tcp_probe_unit="krysyuk-warp-guard-loss-tcp-$(date +%s)-$$"
if systemd-run --quiet --wait --collect --unit="$tcp_probe_unit" \
  --property="NetworkNamespacePath=/run/netns/${WARP_NETNS}" \
  --property=User=xraywarp --property=Group=xraywarp \
  --property=CapabilityBoundingSet=CAP_NET_RAW \
  --property=AmbientCapabilities=CAP_NET_RAW \
  /usr/bin/timeout 8 /usr/bin/curl -4kfsS --interface "$WARP_NETNS_VETH" \
  --connect-timeout 4 --max-time 6 https://1.1.1.1/cdn-cgi/trace \
  >/dev/null 2>&1; then
  die 'xraywarp escaped after namespace guard deletion'
fi
if /opt/krysyuk-warp-egress/tests/test-e2e-local.sh >/dev/null 2>&1; then
  die 'connector traffic escaped after namespace guard deletion'
fi

after_drop=$(host_untagged_drop_packets)
[[ "$after_drop" =~ ^[0-9]+$ && "$after_drop" -gt "$before_drop" ]] || \
  die 'host carrier guard did not drop untagged namespace traffic'
kill "$capture_pid" >/dev/null 2>&1 || true
wait "$capture_pid" >/dev/null 2>&1 || true
capture_pid=''
packet_count=$(tcpdump -nnr "$capture_file" 2>/dev/null | wc -l)
(( packet_count == 0 )) || \
  die 'plaintext TCP/UDP target traffic leaked after namespace guard deletion'
assert_main_routing_unchanged

recover_and_verify || die 'guard reapply and connector E2E recovery failed'
restore_required=0
systemctl stop "${restore_unit}.timer" "${restore_unit}.service" \
  >/dev/null 2>&1 || true
printf '%s\n' 'WARP_EGRESS_GUARD_LOSS_HOST_MARK_FAIL_CLOSED_OK=1'
printf '%s\n' 'WARP_EGRESS_GUARD_REAPPLY_RECOVERY_E2E_OK=1'
