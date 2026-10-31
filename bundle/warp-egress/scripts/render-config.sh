#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
readonly script_dir
# shellcheck source=common.sh
source "$script_dir/common.sh"

require_root
for command_name in install ip jq mktemp; do
  require_command "$command_name"
done
load_warp_egress_env
assert_xray_version
[[ -f "$WARP_EGRESS_TEMPLATE" && ! -L "$WARP_EGRESS_TEMPLATE" ]] || \
  die 'Xray template is missing or unsafe'
[[ $(stat -c '%U:%G' "$WARP_EGRESS_TEMPLATE") == root:root ]] || \
  die 'Xray template owner is unsafe'
[[ -d /run/krysyuk-warp-egress ]] || die 'systemd runtime directory is missing'

physical_address=$NL_PUBLIC_IPV4
tmp=$(mktemp /run/krysyuk-warp-egress/xray.XXXXXX.json)
trap 'rm -f -- "$tmp"' EXIT

WARP_EGRESS_NL_CLIENT_ID="$WARP_EGRESS_NL_CLIENT_ID" \
WARP_EGRESS_BRIDGE_CLIENT_ID="$WARP_EGRESS_BRIDGE_CLIENT_ID" jq \
  --arg listen "$WARP_EGRESS_NETNS_LISTEN" \
  --arg physical_ipv4 "$physical_address" \
  --argjson nl_port "$WARP_EGRESS_NL_PORT" \
  --argjson bridge_port "$WARP_EGRESS_BRIDGE_PORT" \
  '
    (.inbounds[] | select(.tag == "WARP_EGRESS_NL_IN") | .listen) = $listen
    | (.inbounds[] | select(.tag == "WARP_EGRESS_NL_IN") | .port) = $nl_port
    | (.inbounds[] | select(.tag == "WARP_EGRESS_NL_IN") | .settings.clients[0].id) = env.WARP_EGRESS_NL_CLIENT_ID
    | (.inbounds[] | select(.tag == "WARP_EGRESS_BRIDGE_IN") | .listen) = $listen
    | (.inbounds[] | select(.tag == "WARP_EGRESS_BRIDGE_IN") | .port) = $bridge_port
    | (.inbounds[] | select(.tag == "WARP_EGRESS_BRIDGE_IN") | .settings.clients[0].id) = env.WARP_EGRESS_BRIDGE_CLIENT_ID
    | walk(if type == "string" and . == "__PHYSICAL_IPV4__/32"
        then ($physical_ipv4 + "/32") else . end)
  ' "$WARP_EGRESS_TEMPLATE" >"$tmp"

jq --exit-status --arg physical "${physical_address}/32" '
  (.inbounds | length) == 2
  and ([.inbounds[].tag] | sort) == ["WARP_EGRESS_BRIDGE_IN", "WARP_EGRESS_NL_IN"]
  and all(.inbounds[]; .listen == "169.254.254.2")
  and any(.inbounds[]; .tag == "WARP_EGRESS_NL_IN" and .port == 24443)
  and any(.inbounds[]; .tag == "WARP_EGRESS_BRIDGE_IN" and .port == 24444)
  and all(.inbounds[]; .protocol == "vless")
  and all(.inbounds[]; .settings.decryption == "none")
  and all(.inbounds[]; (.settings.clients | length) == 1)
  and ([.inbounds[].settings.clients[0].id] | unique | length) == 2
  and all(.inbounds[]; .streamSettings.network == "raw")
  and all(.inbounds[]; .streamSettings.security == "none")
  and ([.outbounds[] | select(.protocol == "freedom") | .tag] == ["WARP_CF"])
  and any(.routing.rules[]; .inboundTag == ["DNS_WARP"] and .outboundTag == "WARP_CF")
  and any(.routing.rules[]; .ip == ["::/0"] and .outboundTag == "BLOCK")
  and any(.routing.rules[]; (.ip // []) | index($physical))
  and (.routing.rules[-1].inboundTag | sort) == ["WARP_EGRESS_BRIDGE_IN", "WARP_EGRESS_NL_IN"]
  and .routing.rules[-1].network == "tcp,udp"
  and .routing.rules[-1].outboundTag == "WARP_CF"
  and ([.. | strings | select(startswith("__") and endswith("__"))] | length) == 0
' "$tmp" >/dev/null || die 'rendered config violates the loopback/WARP-only contract'

unset WARP_EGRESS_NL_CLIENT_ID WARP_EGRESS_BRIDGE_CLIENT_ID
if ! validation_output=$(env -u WARP_EGRESS_NL_CLIENT_ID \
  -u WARP_EGRESS_BRIDGE_CLIENT_ID XRAY_LOCATION_ASSET="$WARP_EGRESS_ASSETS" \
  "$WARP_EGRESS_XRAY" run -test -config "$tmp" 2>&1); then
  printf '%s\n' "$validation_output" >&2
  exit 1
fi
install -o xraywarp -g xraywarp -m 0600 "$tmp" "$WARP_EGRESS_RUNTIME"
unset physical_address validation_output
printf '%s\n' 'WARP_EGRESS_CONFIG_RENDERED=1'
