#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
readonly script_dir
# shellcheck source=common.sh
source "$script_dir/common.sh"

require_root
for command_name in ip nft sysctl; do
  require_command "$command_name"
done
load_warp_egress_env
ip link show "$PHYSICAL_IFACE" >/dev/null 2>&1 || die '@TARGET_INTERFACE@ is missing'
ip -4 address show dev "$PHYSICAL_IFACE" | grep -F "$NL_PUBLIC_IPV4/" >/dev/null || \
  die 'expected standalone public IPv4 is not assigned to @TARGET_INTERFACE@'

ip_forward_before=$(sysctl -n net.ipv4.ip_forward)
[[ "$ip_forward_before" =~ ^[01]$ ]] || die 'could not capture host ip_forward state'
/usr/local/libexec/krysyuk-warp-egress/configure-ufw.sh --check >/dev/null
cleanup_partial() {
  nft delete table inet "$WARP_HOST_GUARD_TABLE" >/dev/null 2>&1 || true
  nft delete table ip "$WARP_HOST_NAT_TABLE" >/dev/null 2>&1 || true
  ip link delete "$WARP_HOST_VETH" >/dev/null 2>&1 || true
  ip netns delete "$WARP_NETNS" >/dev/null 2>&1 || true
  sysctl -q -w "net.ipv4.ip_forward=$ip_forward_before" >/dev/null 2>&1 || true
}
setup_complete=0
namespace_owned=0
transaction=''
cleanup_on_exit() {
  local rc=$?
  trap - EXIT
  if [[ -n "$transaction" ]]; then
    rm -f -- "$transaction"
  fi
  if (( rc != 0 && setup_complete == 0 && namespace_owned == 1 )); then
    cleanup_partial
  fi
  exit "$rc"
}
trap cleanup_on_exit EXIT

namespace_exists=0
if ip netns list | awk '{print $1}' | grep -Fx "$WARP_NETNS" >/dev/null; then
  namespace_exists=1
fi
if (( namespace_exists == 1 )); then
  ip link show "$WARP_HOST_VETH" >/dev/null 2>&1 || die 'existing netns lacks host veth'
  netns_exec ip link show "$WARP_NETNS_VETH" >/dev/null 2>&1 || die 'existing netns lacks peer veth'
  ip -4 address show dev "$WARP_HOST_VETH" | grep -F "$WARP_HOST_IPV4/30" >/dev/null || \
    die 'existing host veth address is wrong'
  netns_exec ip -4 address show dev "$WARP_NETNS_VETH" \
    | grep -F "$WARP_NETNS_IPV4/30" >/dev/null || \
      die 'existing netns veth address is wrong'
  # An active namespace belongs to the running data plane. Validate it without
  # changing routes or guards; a failed idempotent start must not tear it down.
  [[ "$ip_forward_before" == 1 ]] || die 'existing netns lacks host forwarding'
  nft list table inet "$WARP_HOST_GUARD_TABLE" >/dev/null || die 'existing host guard is absent'
  nft list table ip "$WARP_HOST_NAT_TABLE" >/dev/null || die 'existing host NAT is absent'
  netns_exec nft list table inet "$WARP_EGRESS_TABLE" >/dev/null || die 'existing namespace guard is absent'
  ip route get "$WARP_NETNS_IPV4" | grep -F "dev $WARP_HOST_VETH" >/dev/null || \
    die 'existing host route to WARP netns is absent'
  netns_exec ip -4 route get "$WARP_HOST_IPV4" | grep -F "dev $WARP_NETNS_VETH" >/dev/null || \
    die 'existing namespace route to host veth is absent'
  setup_complete=1
  trap - EXIT
  printf '%s\n' 'WARP_NETNS_READY=1'
  exit 0
else
  ! ip link show "$WARP_HOST_VETH" >/dev/null 2>&1 || die 'stale host veth exists without netns'
  ip netns add "$WARP_NETNS"
  namespace_owned=1
  ip link add "$WARP_HOST_VETH" type veth peer name "$WARP_NETNS_VETH"
  ip link set "$WARP_NETNS_VETH" netns "$WARP_NETNS"
  ip address add "$WARP_HOST_IPV4/30" dev "$WARP_HOST_VETH"
  ip link set "$WARP_HOST_VETH" up
  netns_exec ip link set lo up
  netns_exec ip address add "$WARP_NETNS_IPV4/30" dev "$WARP_NETNS_VETH"
  netns_exec ip link set "$WARP_NETNS_VETH" up
  netns_exec ip route replace default via "$WARP_HOST_IPV4" dev "$WARP_NETNS_VETH"
fi

ip link set "$WARP_HOST_VETH" up
netns_exec ip link set lo up
netns_exec ip link set "$WARP_NETNS_VETH" up
netns_exec ip route replace default via "$WARP_HOST_IPV4" dev "$WARP_NETNS_VETH"

sysctl -q -w net.ipv4.ip_forward=1
sysctl -q -w "net.ipv4.conf.${WARP_HOST_VETH}.forwarding=1"
sysctl -q -w "net.ipv4.conf.${WARP_HOST_VETH}.rp_filter=0"
netns_exec sysctl -q -w net.ipv4.conf.all.src_valid_mark=1
netns_exec sysctl -q -w net.ipv4.conf.all.rp_filter=0
netns_exec sysctl -q -w "net.ipv4.conf.${WARP_NETNS_VETH}.rp_filter=0"

host_rules=/etc/nftables.d/krysyuk-warp-netns-host.nft
[[ -f "$host_rules" && ! -L "$host_rules" ]] || die 'host netns nft rules are missing or unsafe'
transaction=$(mktemp)
if nft list table inet "$WARP_HOST_GUARD_TABLE" >/dev/null 2>&1; then
  printf 'delete table inet %s\n' "$WARP_HOST_GUARD_TABLE" >>"$transaction"
fi
if nft list table ip "$WARP_HOST_NAT_TABLE" >/dev/null 2>&1; then
  printf 'delete table ip %s\n' "$WARP_HOST_NAT_TABLE" >>"$transaction"
fi
cat "$host_rules" >>"$transaction"
nft -c -f "$transaction"
nft -f "$transaction"

# The same namespace guard that later protects xraywarp also grants the DSCP
# carrier and local fixed mark to root-owned warp-svc outer packets. It must
# exist before the daemon attempts registration; otherwise the already-active
# host barriers correctly drop every untagged bootstrap DNS/API packet.
/usr/local/libexec/krysyuk-warp-egress/apply-guard.sh >/dev/null
netns_exec nft list table inet "$WARP_EGRESS_TABLE" >/dev/null

ip route get "$WARP_NETNS_IPV4" | grep -F "dev $WARP_HOST_VETH" >/dev/null || \
  die 'host route to WARP netns is absent'
ip -4 route get 1.1.1.1 mark "$WARP_OUTER_MARK" from "$WARP_NETNS_IPV4" \
  iif "$WARP_HOST_VETH" | grep -F "dev $PHYSICAL_IFACE" >/dev/null || \
  die 'marked WARP outer route does not use the physical interface'
netns_exec ip route get 1.1.1.1 | grep -F "dev $WARP_NETNS_VETH" >/dev/null || \
  die 'pre-WARP netns default route is absent'
setup_complete=1
rm -f -- "$transaction"
transaction=''
trap - EXIT
unset ip_forward_before setup_complete transaction
printf '%s\n' 'WARP_NETNS_READY=1'
