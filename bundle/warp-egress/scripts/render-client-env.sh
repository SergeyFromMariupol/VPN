#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
readonly script_dir
# shellcheck source=common.sh
source "$script_dir/common.sh"

require_root
load_warp_egress_env
nl_tmp=$(mktemp /etc/krysyuk-warp-egress/nl-client.XXXXXX)
bridge_tmp=$(mktemp /etc/krysyuk-warp-egress/bridge-client.XXXXXX)
trap 'rm -f -- "$nl_tmp" "$bridge_tmp"' EXIT
printf '%s\n' \
  "WARP_EGRESS_ADDRESS=$WARP_EGRESS_HOST_LISTEN" \
  "WARP_EGRESS_PORT=$WARP_EGRESS_NL_PORT" \
  "WARP_EGRESS_CLIENT_ID=$WARP_EGRESS_NL_CLIENT_ID" \
  'WARP_EGRESS_NETWORK=raw' \
  'WARP_EGRESS_SECURITY=none' >"$nl_tmp"
printf '%s\n' \
  "WARP_EGRESS_ADDRESS=$WARP_EGRESS_HOST_LISTEN" \
  'WARP_EGRESS_PORT=24443' \
  "WARP_EGRESS_CLIENT_ID=$WARP_EGRESS_BRIDGE_CLIENT_ID" \
  'WARP_EGRESS_NETWORK=raw' \
  'WARP_EGRESS_SECURITY=none' >"$bridge_tmp"
install -o root -g root -m 0600 "$nl_tmp" "$WARP_EGRESS_NL_CLIENT_ENV"
install -o root -g root -m 0600 "$bridge_tmp" \
  "$WARP_EGRESS_RU_BRIDGE_CLIENT_ENV"
rm -f -- "$WARP_EGRESS_LEGACY_CLIENT_ENV"
unset WARP_EGRESS_NL_CLIENT_ID WARP_EGRESS_BRIDGE_CLIENT_ID
printf '%s\n' 'WARP_EGRESS_DUAL_CLIENT_ENVS_RENDERED=1'
