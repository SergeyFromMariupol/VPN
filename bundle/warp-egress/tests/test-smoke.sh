#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

readonly lib=/usr/local/libexec/krysyuk-warp-egress/common.sh
[[ -r "$lib" ]] || { echo 'ERROR: installed common library is missing' >&2; exit 1; }
# shellcheck source=../scripts/common.sh
source "$lib"

require_root
for command_name in cmp dpkg-query find grep ip jq nft ss stat systemctl ufw; do
  require_command "$command_name"
done
load_warp_egress_env
assert_xray_version
assert_warp_version
assert_warp_apt_pin
/usr/local/libexec/krysyuk-warp-egress/configure-ufw.sh --check >/dev/null
require_private_root_file "$WARP_EGRESS_NL_CLIENT_ENV" 'NL-local WARP client env'
require_private_root_file "$WARP_EGRESS_RU_BRIDGE_CLIENT_ENV" 'RU-bridge WARP client env'
[[ ! -e "$WARP_EGRESS_LEGACY_CLIENT_ENV" && ! -L "$WARP_EGRESS_LEGACY_CLIENT_ENV" ]] || \
  die 'legacy shared WARP client env still exists'
require_private_root_file "$MAIN_ROUTING_BASELINE" 'main routing baseline'

systemctl is-active --quiet warp-svc.service && die 'host warp-svc is active'
systemctl is-enabled --quiet warp-svc.service 2>/dev/null && die 'host warp-svc is enabled'
[[ $(systemctl is-enabled warp-svc.service 2>/dev/null || true) == masked ]] || \
  die 'host warp-svc is not masked'

readonly required_units=(
  krysyuk-warp-netns.service
  krysyuk-warp-netns-daemon.service
  krysyuk-warp-netns-configure.service
  krysyuk-warp-egress-guard.service
  krysyuk-xray-warp-egress.service
  krysyuk-warp-egress.socket
  krysyuk-warp-bridge.socket
)
for unit in "${required_units[@]}"; do
  systemctl is-active --quiet "$unit" || die "$unit is not active"
  systemctl is-enabled --quiet "$unit" || die "$unit is not enabled"
done

ip netns list | awk '{print $1}' | grep -Fx "$WARP_NETNS" >/dev/null || \
  die 'named WARP network namespace is absent'
ip link show "$WARP_HOST_VETH" >/dev/null 2>&1 || die 'host veth is absent'
netns_exec ip link show "$WARP_NETNS_VETH" >/dev/null 2>&1 || die 'netns veth is absent'
netns_exec ip link show "$WARP_EGRESS_IFACE" >/dev/null 2>&1 || \
  die 'CloudflareWARP is absent from the isolated namespace'
ip link show "$WARP_EGRESS_IFACE" >/dev/null 2>&1 && \
  die 'CloudflareWARP exists in the main namespace'
ip -4 address show dev "$PHYSICAL_IFACE" | grep -F "$NL_PUBLIC_IPV4/" >/dev/null || \
  die 'the standalone public IPv4 is not assigned to @TARGET_INTERFACE@'
ip -4 address show dev "$WARP_HOST_VETH" | grep -F "$WARP_HOST_IPV4/30" >/dev/null || \
  die 'host veth address is wrong'
netns_exec ip -4 address show dev "$WARP_NETNS_VETH" \
  | grep -F "$WARP_NETNS_IPV4/30" >/dev/null || die 'netns veth address is wrong'
ip -4 route get "$WARP_NETNS_IPV4" | grep -F "dev $WARP_HOST_VETH" >/dev/null || \
  die 'host route to the connector namespace is wrong'
netns_exec ip -4 route get "$WARP_HOST_IPV4" | grep -F "dev $WARP_NETNS_VETH" >/dev/null || \
  die 'WARP transport route is recursive or missing'
netns_exec ip -4 route get 1.1.1.1 | grep -F "dev $WARP_EGRESS_IFACE" >/dev/null || \
  die 'foreign route inside the namespace does not use WARP'
ip -4 route get 1.1.1.1 mark "$WARP_OUTER_MARK" from "$WARP_NETNS_IPV4" \
  iif "$WARP_HOST_VETH" | grep -F "dev $PHYSICAL_IFACE" >/dev/null || \
  die 'marked WARP outer route does not use @TARGET_INTERFACE@'
ip -4 route show default | grep -F "dev $PHYSICAL_IFACE" >/dev/null || \
  die 'main namespace default route does not use @TARGET_INTERFACE@'

warp_status_connected || die 'isolated WARP status is not Connected'
assert_private_warp_directory() {
  local path="$1" label="$2"
  [[ -d "$path" && ! -L "$path" ]] || die "$label is absent or unsafe"
  [[ $(stat -c '%U:%G' "$path") == root:root ]] || die "$label owner is unsafe"
  [[ $(stat -c '%a' "$path") == 700 ]] || die "$label mode must be 0700"
}
assert_private_warp_directory "$WARP_RUNTIME_DIRECTORY" 'dedicated WARP runtime directory'
assert_private_warp_directory "$WARP_STATE_DIRECTORY" 'dedicated WARP state directory'
assert_private_warp_directory "$WARP_LOGS_DIRECTORY" 'dedicated WARP logs directory'
find "$WARP_RUNTIME_DIRECTORY" -mindepth 1 -type s -print -quit | grep . >/dev/null || \
  die 'dedicated WARP IPC socket is absent'
find "$WARP_STATE_DIRECTORY" -mindepth 1 -print -quit | grep . >/dev/null || \
  die 'dedicated WARP registration state is absent'
warp_settings=$(warp_cli settings)
grep -Eq 'Mode:[[:space:]]+(TunnelOnly|Traffic)' <<<"$warp_settings" || \
  die 'isolated WARP is not in Traffic only mode'
grep -Eiq 'WARP tunnel protocol:[[:space:]]+MASQUE|MASQUE \(' <<<"$warp_settings" || \
  die 'isolated WARP does not use MASQUE'
assert_main_routing_unchanged

host_guard=$(nft list chain inet "$WARP_HOST_GUARD_TABLE" forward)
grep -Eq 'iifname "kw-host".*ip saddr 169[.]254[.]254[.]2.*oifname "@TARGET_INTERFACE@".*ip dscp (46|0x2e|ef).*meta mark set 0x57525001.*accept' \
  <<<"$host_guard" || die 'host guard lacks the DSCP-carrier-to-mark netns allow'
grep -Eq 'iifname "@TARGET_INTERFACE@".*oifname "kw-host".*ip daddr 169[.]254[.]254[.]2.*ct state established,related.*accept' \
  <<<"$host_guard" || die 'host guard lacks the established reverse allow'
grep -Eq 'iifname "kw-host".*drop' <<<"$host_guard" || \
  die 'host guard lacks the netns source fallback drop'
grep -Eq 'oifname "kw-host".*drop' <<<"$host_guard" || \
  die 'host guard lacks the unsolicited netns destination drop'
nft list chain ip "$WARP_HOST_NAT_TABLE" postrouting \
  | grep -E 'ip saddr 169[.]254[.]254[.]2.*oifname "@TARGET_INTERFACE@".*meta mark 0x57525001.*masquerade' \
    >/dev/null || \
  die 'host NAT is not limited to the marked isolated WARP source and @TARGET_INTERFACE@'

guard_state=$(netns_exec nft list chain inet "$WARP_EGRESS_TABLE" output)
grep -Eq 'skuid[[:space:]]+0.*oifname "kw-warp".*ip saddr 169[.]254[.]254[.]2.*ip dscp set (46|0x2e|ef).*meta mark set 0x57525001.*accept' \
  <<<"$guard_state" || die 'netns guard does not tag and mark root-owned WARP outer traffic'
grep -Eq 'skuid[[:space:]]+(xraywarp|[0-9]+).*oifname "lo".*accept' \
  <<<"$guard_state" || die 'netns guard does not allow xraywarp loopback'
grep -Eq 'skuid[[:space:]]+(xraywarp|[0-9]+).*oifname "kw-warp".*ip saddr 169[.]254[.]254[.]2.*ip daddr 169[.]254[.]254[.]1.*tcp sport.*24443.*24444.*ct state established.*accept' \
  <<<"$guard_state" || die 'netns guard lacks the authenticated listener reply exception'
grep -Eq 'skuid[[:space:]]+(xraywarp|[0-9]+).*oifname "CloudflareWARP".*accept' \
  <<<"$guard_state" || die 'netns guard lacks the WARP allow'
grep -Eq 'skuid[[:space:]]+(xraywarp|[0-9]+).*drop' <<<"$guard_state" || \
  die 'netns guard lacks the final xraywarp drop'

[[ -f "$WARP_EGRESS_RUNTIME" && ! -L "$WARP_EGRESS_RUNTIME" ]] || \
  die 'runtime Xray config is missing or unsafe'
[[ $(stat -c '%U:%G' "$WARP_EGRESS_RUNTIME") == xraywarp:xraywarp ]] || \
  die 'runtime Xray config owner is unsafe'
[[ $(stat -c '%a' "$WARP_EGRESS_RUNTIME") == 600 ]] || \
  die 'runtime Xray config mode is not 0600'
env -u WARP_EGRESS_NL_CLIENT_ID -u WARP_EGRESS_BRIDGE_CLIENT_ID \
  XRAY_LOCATION_ASSET="$WARP_EGRESS_ASSETS" \
  "$WARP_EGRESS_XRAY" run -test -config "$WARP_EGRESS_RUNTIME" >/dev/null
WARP_EGRESS_NL_CLIENT_ID="$WARP_EGRESS_NL_CLIENT_ID" \
WARP_EGRESS_BRIDGE_CLIENT_ID="$WARP_EGRESS_BRIDGE_CLIENT_ID" jq \
  --exit-status --arg physical "${NL_PUBLIC_IPV4}/32" '
  (.inbounds | length) == 2
  and ([.inbounds[].tag] | sort) == ["WARP_EGRESS_BRIDGE_IN", "WARP_EGRESS_NL_IN"]
  and all(.inbounds[]; .listen == "169.254.254.2")
  and any(.inbounds[]; .tag == "WARP_EGRESS_NL_IN" and .port == 24443
    and .settings.clients == [{id: env.WARP_EGRESS_NL_CLIENT_ID}])
  and any(.inbounds[]; .tag == "WARP_EGRESS_BRIDGE_IN" and .port == 24444
    and .settings.clients == [{id: env.WARP_EGRESS_BRIDGE_CLIENT_ID}])
  and all(.inbounds[]; .protocol == "vless")
  and all(.inbounds[]; .streamSettings == {network: "raw", security: "none"})
  and ([.inbounds[].settings.clients[0].id] | unique | length) == 2
  and ([.outbounds[] | select(.protocol == "freedom") | .tag] == ["WARP_CF"])
  and ((.outbounds[] | select(.tag == "WARP_CF") | .streamSettings.sockopt?) == null)
  and any(.routing.rules[]; .inboundTag == ["DNS_WARP"] and .outboundTag == "WARP_CF")
  and any(.routing.rules[]; .ip == ["::/0"] and .outboundTag == "BLOCK")
  and any(.routing.rules[]; (.ip // []) | index($physical))
  and (.routing.rules[-1].inboundTag | sort) == ["WARP_EGRESS_BRIDGE_IN", "WARP_EGRESS_NL_IN"]
  and .routing.rules[-1].network == "tcp,udp"
  and .routing.rules[-1].outboundTag == "WARP_CF"
  and ([.. | strings | select(startswith("__") and endswith("__"))] | length) == 0
' "$WARP_EGRESS_RUNTIME" >/dev/null || die 'runtime config violates the WARP-only contract'

check_client_subset() {
  local path="$1" expected_id="$2" label="$3"
  (
    unset WARP_EGRESS_ADDRESS WARP_EGRESS_PORT WARP_EGRESS_CLIENT_ID
    unset WARP_EGRESS_NETWORK WARP_EGRESS_SECURITY
    # shellcheck disable=SC1090
    source "$path"
    [[ "$WARP_EGRESS_ADDRESS" == 127.0.0.1 ]]
    [[ "$WARP_EGRESS_PORT" == 24443 ]]
    [[ "$WARP_EGRESS_CLIENT_ID" == "$expected_id" ]]
    [[ "$WARP_EGRESS_NETWORK" == raw ]]
    [[ "$WARP_EGRESS_SECURITY" == none ]]
  ) || die "$label does not match the server env"
}
check_client_subset "$WARP_EGRESS_NL_CLIENT_ENV" \
  "$WARP_EGRESS_NL_CLIENT_ID" 'NL-local client subset'
check_client_subset "$WARP_EGRESS_RU_BRIDGE_CLIENT_ENV" \
  "$WARP_EGRESS_BRIDGE_CLIENT_ID" 'RU-bridge client subset'

ss -H -ltn | grep -E '127[.]0[.]0[.]1:24443[[:space:]]' >/dev/null || \
  die 'NL-local host socket bridge is absent'
ss -H -ltn | grep -E '127[.]0[.]0[.]1:24444[[:space:]]' >/dev/null || \
  die 'RU-only host socket bridge is absent'
for connector_port in 24443 24444; do
  if ss -H -ltn | grep -E "(0[.]0[.]0[.]0|\\*|\\[::\\]):${connector_port}[[:space:]]" \
      >/dev/null; then
    die 'a host socket bridge is exposed beyond loopback'
  fi
done
netns_exec ss -H -ltn | grep -E '169[.]254[.]254[.]2:24443[[:space:]]' >/dev/null || \
  die 'NL-local netns Xray listener is absent'
netns_exec ss -H -ltn | grep -E '169[.]254[.]254[.]2:24444[[:space:]]' >/dev/null || \
  die 'RU-bridge netns Xray listener is absent'
for connector_port in 24443 24444; do
  if netns_exec ss -H -ltn | grep -E \
      "(0[.]0[.]0[.]0|\\*|\\[::\\]):${connector_port}[[:space:]]" >/dev/null; then
    die 'a netns Xray listener is exposed on a wildcard address'
  fi
done
if ufw show added | grep -F 'route allow in on kw-host out on @TARGET_INTERFACE@' >/dev/null; then
  die 'broad UFW route allow for the WARP veth is forbidden'
fi
if ufw status | grep -E \
    '^(24443|24444)(/tcp)?([[:space:]]|$).*ALLOW([[:space:]]+IN)?' >/dev/null; then
  die 'host loopback connector has a public UFW allow rule'
fi

xray_pid=$(systemctl show -p MainPID --value krysyuk-xray-warp-egress.service)
warp_pid=$(systemctl show -p MainPID --value krysyuk-warp-netns-daemon.service)
[[ "$xray_pid" =~ ^[1-9][0-9]*$ ]] || die 'Xray connector MainPID is invalid'
[[ "$warp_pid" =~ ^[1-9][0-9]*$ ]] || die 'isolated warp-svc MainPID is invalid'
expected_ns=$(stat -Lc '%d:%i' "/run/netns/${WARP_NETNS}")
[[ $(stat -Lc '%d:%i' "/proc/${xray_pid}/ns/net") == "$expected_ns" ]] || \
  die 'Xray is not running inside the named WARP namespace'
[[ $(stat -Lc '%d:%i' "/proc/${warp_pid}/ns/net") == "$expected_ns" ]] || \
  die 'warp-svc is not running inside the named WARP namespace'
cmp -s /etc/netns/krysyuk-warp/resolv.conf \
  "/proc/${warp_pid}/root/etc/resolv.conf" || \
  die 'isolated warp-svc does not see the dedicated namespace resolver file'
service_uid=$(awk '/^Uid:/ {print $2}' "/proc/${xray_pid}/status")
[[ "$service_uid" == "$(id -u xraywarp)" ]] || \
  die 'Xray connector is not running as xraywarp'

unset WARP_EGRESS_NL_CLIENT_ID WARP_EGRESS_BRIDGE_CLIENT_ID
unset warp_settings host_guard guard_state connector_port
printf '%s\n' 'WARP_EGRESS_NETNS_SMOKE_OK=1'
