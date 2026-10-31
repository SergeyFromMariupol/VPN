#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

readonly lib=/usr/local/libexec/krysyuk-warp-egress/common.sh
# shellcheck source=../scripts/common.sh
source "$lib"

require_root
for command_name in cmp ip mktemp sha256sum stat; do
  require_command "$command_name"
done
load_warp_egress_env
require_private_root_file "$MAIN_ROUTING_BASELINE" 'main routing baseline'

current=$(mktemp)
trap 'rm -f -- "$current"' EXIT
/usr/local/libexec/krysyuk-warp-egress/capture-main-routing.sh >"$current"
cmp -s -- "$MAIN_ROUTING_BASELINE" "$current" || \
  die 'main namespace policy rules or default routes differ from the pre-netns baseline'

ip link show "$WARP_EGRESS_IFACE" >/dev/null 2>&1 && \
  die 'CloudflareWARP exists in the main namespace'
ip -4 route show default | grep -Fq "dev $PHYSICAL_IFACE" || \
  die 'main namespace IPv4 default does not use @TARGET_INTERFACE@'
ip -4 route get 1.1.1.1 from "$NL_PUBLIC_IPV4" | grep -Fq "dev $PHYSICAL_IFACE" || \
  die 'main namespace public-reply route does not use @TARGET_INTERFACE@'
ip -4 route get 1.1.1.1 mark "$WARP_OUTER_MARK" from "$WARP_NETNS_IPV4" \
  iif "$WARP_HOST_VETH" | grep -Fq "dev $PHYSICAL_IFACE" || \
  die 'main namespace marked WARP-outer route does not use @TARGET_INTERFACE@'
netns_exec ip -4 route get "$WARP_HOST_IPV4" | grep -Fq "dev $WARP_NETNS_VETH" || \
  die 'isolated WARP outer transport is not pinned to the veth'
netns_exec ip -4 route get 1.1.1.1 | grep -Fq "dev $WARP_EGRESS_IFACE" || \
  die 'isolated foreign route does not use CloudflareWARP'

host_ns=$(stat -Lc '%d:%i' /proc/1/ns/net)
warp_ns=$(stat -Lc '%d:%i' "/run/netns/${WARP_NETNS}")
[[ "$host_ns" != "$warp_ns" ]] || die 'WARP is not isolated from the main network namespace'
baseline_sha=$(sha256sum "$MAIN_ROUTING_BASELINE" | awk '{print $1}')
current_sha=$(sha256sum "$current" | awk '{print $1}')
[[ "$baseline_sha" == "$current_sha" ]] || die 'routing baseline digest mismatch'
printf 'WARP_MAIN_ROUTING_UNCHANGED=1 sha256=%s\n' "$current_sha"
printf '%s\n' 'WARP_MAIN_DEFAULT_PHYSICAL=1 WARP_NETNS_DEFAULT_CLOUDFLARE=1'
