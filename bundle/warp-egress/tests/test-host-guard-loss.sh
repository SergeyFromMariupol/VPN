#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

test_failure_line=0
test_failure_file=test-host-guard-loss.sh
test_phase=preflight
trap 'test_failure_line=$LINENO; test_failure_file=${BASH_SOURCE[0]##*/}' ERR

readonly lib=/usr/local/libexec/krysyuk-warp-egress/common.sh
# shellcheck source=../scripts/common.sh
source "$lib"

# Explicit die exits do not trigger ERR; retain their exact caller location.
die() {
  local caller_file=${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}
  test_failure_line=${BASH_LINENO[0]:-0}
  test_failure_file=${caller_file##*/}
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_root
[[ ${I_UNDERSTAND_DISRUPTIVE:-} == YES ]] || \
  die 'set I_UNDERSTAND_DISRUPTIVE=YES and keep a second SSH session'
for command_name in chmod curl date getent install ip iptables-save mktemp nft python3 systemctl \
  systemd-run tcpdump timeout wc; do
  require_command "$command_name"
done
load_warp_egress_env
/opt/krysyuk-warp-egress/tests/test-smoke.sh >/dev/null
assert_main_routing_unchanged

restore_unit="krysyuk-warp-host-guard-autorestore-$(date +%s)-$$"
readonly restore_unit
capture_file=''
capture_pid=''
veth_capture_file=''
veth_capture_pid=''
capture_markers=''
restore_required=0
recovered=0

mark_phase() {
  test_phase=$1
  if [[ -n "$capture_markers" ]]; then
    printf '%s\t%s\n' "$(date -u +%s.%N)" "$test_phase" >>"$capture_markers"
  fi
}

save_forensics() {
  local directory spec label expression count
  [[ -n "$capture_file" && -f "$capture_file" ]] || return 0
  directory=$(mktemp -d /var/backups/germanyvpn-host-guard-forensics-XXXXXX) || return 1
  chmod 0700 "$directory" || return 1
  install -o root -g root -m 0600 "$capture_file" "$directory/physical.pcap" || return 1
  if [[ -n "$veth_capture_file" && -f "$veth_capture_file" ]]; then
    install -o root -g root -m 0600 "$veth_capture_file" "$directory/veth.pcap" || return 1
  fi
  printf 'WARP_HOST_GUARD_FORENSICS_PCAP_SAVED=1 path=%s\n' "$directory" >&2
  if [[ -n "$capture_markers" && -f "$capture_markers" ]]; then
    install -o root -g root -m 0600 "$capture_markers" "$directory/phases.tsv" || return 1
  fi
  printf 'phase=%s\nfile=%s\nline=%s\n' \
    "$test_phase" "$test_failure_file" "$test_failure_line" >"$directory/failure.txt"
  : >"$directory/flow-counts.txt"
  for spec in 'all|ip' 'tcp|tcp' 'udp|udp' 'dns_udp53|udp dst port 53' \
    'dns_tcp53|tcp dst port 53' 'dns853|dst port 853' \
    'tcp443|tcp dst port 443' 'udp443|udp dst port 443'; do
    label=${spec%%|*}
    expression=${spec#*|}
    count=$(tcpdump -nnr "$directory/physical.pcap" "$expression" 2>/dev/null | wc -l) || return 1
    printf '%s=%s\n' "$label" "$count" >>"$directory/flow-counts.txt"
  done
  systemctl show "${restore_unit}.timer" -p ActiveState -p SubState \
    -p LastTriggerUSec -p LastTriggerUSecMonotonic -p NextElapseUSecMonotonic \
    >"$directory/autorestore-timer.txt" 2>/dev/null || true
  systemctl show "${restore_unit}.service" -p ActiveState -p SubState -p Result \
    -p ExecMainStartTimestamp -p ExecMainExitTimestamp \
    -p ExecMainStartTimestampMonotonic -p ExecMainExitTimestampMonotonic \
    >"$directory/autorestore-service.txt" 2>/dev/null || true
  iptables-save -c -t filter >"$directory/host-filter.txt" 2>/dev/null || true
  nft -s list table ip "$WARP_HOST_NAT_TABLE" >"$directory/host-nat.txt" 2>/dev/null || true
  netns_exec nft -s list table inet "$WARP_EGRESS_TABLE" \
    >"$directory/namespace-guard.txt" 2>/dev/null || true
  chmod 0600 "$directory/"* || return 1
  printf 'WARP_HOST_GUARD_FORENSICS_SAVED=1 path=%s\n' "$directory" >&2
}

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
    printf 'WARP_HOST_GUARD_LOSS_TEST_FAILED=1 phase=%s file=%s line=%s rc=%s\n' \
      "$test_phase" "$test_failure_file" "$test_failure_line" "$rc" >&2
  fi
  if [[ -n "$capture_pid" ]] && kill -0 "$capture_pid" 2>/dev/null; then
    kill "$capture_pid" >/dev/null 2>&1 || true
    wait "$capture_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$veth_capture_pid" ]] && kill -0 "$veth_capture_pid" 2>/dev/null; then
    kill "$veth_capture_pid" >/dev/null 2>&1 || true
    wait "$veth_capture_pid" >/dev/null 2>&1 || true
  fi
  if (( rc != 0 )); then
    save_forensics || printf '%s\n' 'WARP_HOST_GUARD_FORENSICS_SAVE_FAILED=1' >&2
  fi
  [[ -z "$capture_file" ]] || rm -f -- "$capture_file"
  [[ -z "$veth_capture_file" ]] || rm -f -- "$veth_capture_file"
  [[ -z "$capture_markers" ]] || rm -f -- "$capture_markers"
  if (( restore_required == 1 && recovered == 0 )); then
    recover_and_verify || true
  fi
  if (( recovered == 1 )); then
    systemctl stop "${restore_unit}.timer" "${restore_unit}.service" \
      >/dev/null 2>&1 || true
  else
    printf 'WARP_EGRESS_HOST_GUARD_AUTORESTORE_TIMER_RETAINED=%s\n' "$restore_unit" >&2
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
(( ${#target_ips[@]} > 0 )) || die 'could not resolve host-guard leak targets'
filter="src host ${NL_PUBLIC_IPV4} and (((tcp or udp) and (dst port 53 or dst port 853)) or ((tcp or udp) and ("
separator=''
for address in "${target_ips[@]}"; do
  filter+="${separator}dst host ${address}"
  separator=' or '
done
filter+=')))'

ufw_untagged_drop_packets() {
  iptables-save -c -t filter \
    | awk '!found && /-A ufw-before-forward -i kw-host -j DROP/ {
        sub(/^\[/, "", $1)
        split($1, values, ":")
        print values[1]
        found=1
      }'
}

/usr/local/libexec/krysyuk-warp-egress/configure-ufw.sh --check >/dev/null
before_drop=$(ufw_untagged_drop_packets)
[[ "$before_drop" =~ ^[0-9]+$ ]] || die 'could not read UFW untagged-drop counter'
systemd-run --quiet --unit="$restore_unit" --on-active=2m \
  /usr/local/libexec/krysyuk-warp-egress/warp-emergency-reconnect.sh
restore_required=1

capture_file=$(mktemp /tmp/krysyuk-warp-host-guard-loss.XXXXXX.pcap)
veth_capture_file=$(mktemp /tmp/krysyuk-warp-host-guard-veth.XXXXXX.pcap)
capture_markers=$(mktemp /run/krysyuk-warp-host-guard-phases.XXXXXX)
mark_phase capture-start
# Preserve the exact physical filter/assertion. This additional capture only
# establishes whether a physical packet originated in the WARP namespace.
veth_filter="src host ${WARP_NETNS_IPV4} and ${filter#* and }"
timeout 150 tcpdump -ni "$WARP_HOST_VETH" -U -w "$veth_capture_file" "$veth_filter" \
  >/dev/null 2>&1 &
veth_capture_pid=$!
timeout 150 tcpdump -ni "$PHYSICAL_IFACE" -U -w "$capture_file" "$filter" \
  >/dev/null 2>&1 &
capture_pid=$!
sleep 1
kill -0 "$capture_pid" 2>/dev/null || die 'physical-interface forensic capture did not stay active'
kill -0 "$veth_capture_pid" 2>/dev/null || die 'veth provenance capture did not stay active'

# First remove only the custom host forward table. Persistent UFW must still
# translate the DSCP carrier to the mark and pass WARP outer traffic while
# rejecting untagged veth traffic, so authenticated E2E remains available.
mark_phase remove-host-guard
nft delete table inet "$WARP_HOST_GUARD_TABLE"
if nft list table inet "$WARP_HOST_GUARD_TABLE" >/dev/null 2>&1; then
  die 'custom host forward table survived the deletion test'
fi
mark_phase positive-e2e-host-guard-absent
/opt/krysyuk-warp-egress/tests/test-e2e-local.sh >/dev/null || \
  die 'persistent UFW carrier-to-mark allow did not preserve WARP E2E after host-table loss'

# Remove the namespace table as well. This deliberately leaves UFW as the only
# forwarding barrier and proves its untagged drop independently of custom nft.
mark_phase remove-namespace-guard
netns_exec nft delete table inet "$WARP_EGRESS_TABLE"
if netns_exec nft list table inet "$WARP_EGRESS_TABLE" >/dev/null 2>&1; then
  die 'namespace guard table survived the UFW-only barrier test'
fi

mark_phase forced-udp-probe
udp_probe_unit="krysyuk-warp-ufw-only-udp-$(date +%s)-$$"
systemd-run --quiet --wait --collect --unit="$udp_probe_unit" \
  --property="NetworkNamespacePath=/run/netns/${WARP_NETNS}" \
  --property=User=xraywarp --property=Group=xraywarp \
  --property=CapabilityBoundingSet=CAP_NET_RAW \
  --property=AmbientCapabilities=CAP_NET_RAW \
  /usr/bin/python3 -c \
  'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b"kw-warp\0"); [s.sendto(b"U"*1200,("8.8.8.8",443)) for _ in range(3)]; s.close()' \
  >/dev/null 2>&1 || true
mark_phase forced-tcp-probe
tcp_probe_unit="krysyuk-warp-ufw-only-tcp-$(date +%s)-$$"
if systemd-run --quiet --wait --collect --unit="$tcp_probe_unit" \
  --property="NetworkNamespacePath=/run/netns/${WARP_NETNS}" \
  --property=User=xraywarp --property=Group=xraywarp \
  --property=CapabilityBoundingSet=CAP_NET_RAW \
  --property=AmbientCapabilities=CAP_NET_RAW \
  /usr/bin/timeout 8 /usr/bin/curl -4kfsS --interface "$WARP_NETNS_VETH" \
  --connect-timeout 4 --max-time 6 https://1.1.1.1/cdn-cgi/trace \
  >/dev/null 2>&1; then
  die 'xraywarp escaped through UFW after custom guard loss'
fi
mark_phase negative-e2e-both-guards-absent
if /opt/krysyuk-warp-egress/tests/test-e2e-local.sh >/dev/null 2>&1; then
  die 'connector traffic escaped with only the UFW unmarked barrier remaining'
fi

mark_phase check-untagged-drops
after_drop=$(ufw_untagged_drop_packets)
[[ "$after_drop" =~ ^[0-9]+$ && "$after_drop" -gt "$before_drop" ]] || \
  die 'persistent UFW did not count untagged namespace drops'
mark_phase capture-stop
kill "$capture_pid" >/dev/null 2>&1 || true
wait "$capture_pid" >/dev/null 2>&1 || true
capture_pid=''
kill "$veth_capture_pid" >/dev/null 2>&1 || true
wait "$veth_capture_pid" >/dev/null 2>&1 || true
veth_capture_pid=''
mark_phase inspect-capture
packet_count=$(tcpdump -nnr "$capture_file" 2>/dev/null | wc -l)
(( packet_count == 0 )) || \
  die 'plaintext TCP/UDP target traffic leaked during host-guard loss'
assert_main_routing_unchanged

mark_phase recovery
recover_and_verify || die 'host/namespace guard reapply and E2E recovery failed'
restore_required=0
systemctl stop "${restore_unit}.timer" "${restore_unit}.service" \
  >/dev/null 2>&1 || true
printf '%s\n' 'WARP_EGRESS_HOST_GUARD_LOSS_UFW_CARRIER_MARK_E2E_OK=1'
printf '%s\n' 'WARP_EGRESS_UFW_ONLY_UNTAGGED_FAIL_CLOSED_OK=1'
printf '%s\n' 'WARP_EGRESS_HOST_GUARD_REAPPLY_RECOVERY_OK=1'
