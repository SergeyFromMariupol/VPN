#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
readonly script_dir
# shellcheck source=common.sh
source "$script_dir/common.sh"

require_root
require_command install
require_command mktemp
require_command python3

mode=${1:---generate}
case "$mode" in
  --generate)
    [[ -z ${WARP_EGRESS_CLIENT_ID:-} ]] || \
      die 'legacy WARP_EGRESS_CLIENT_ID is forbidden; provide the two role IDs'
    nl_client_id=${WARP_EGRESS_NL_CLIENT_ID:-}
    bridge_client_id=${WARP_EGRESS_BRIDGE_CLIENT_ID:-}
    if [[ -n "$nl_client_id" || -n "$bridge_client_id" ]]; then
      [[ -n "$nl_client_id" && -n "$bridge_client_id" ]] || \
        die 'provide both role IDs or neither'
    else
      readarray -t generated_ids < <(python3 - <<'PY'
import uuid
print(uuid.uuid4())
print(uuid.uuid4())
PY
)
      (( ${#generated_ids[@]} == 2 )) || die 'could not generate two connector UUIDs'
      nl_client_id=${generated_ids[0]}
      bridge_client_id=${generated_ids[1]}
    fi
    ;;
  --stdin)
    [[ -z ${WARP_EGRESS_CLIENT_ID:-} && -z ${WARP_EGRESS_NL_CLIENT_ID:-} \
      && -z ${WARP_EGRESS_BRIDGE_CLIENT_ID:-} ]] || \
      die 'choose environment or stdin, not both'
    IFS= read -r nl_client_id || die 'could not read NL-local UUID from stdin'
    IFS= read -r bridge_client_id || die 'could not read RU-bridge UUID from stdin'
    ;;
  *)
    die 'usage: initialize-env.sh [--generate|--stdin]'
    ;;
esac

validate_uuid4 "$nl_client_id" WARP_EGRESS_NL_CLIENT_ID
validate_uuid4 "$bridge_client_id" WARP_EGRESS_BRIDGE_CLIENT_ID
[[ "$nl_client_id" != "$bridge_client_id" ]] || \
  die 'NL-local and RU-bridge UUIDs must be distinct'
if [[ -e "$WARP_EGRESS_ENV" || -L "$WARP_EGRESS_ENV" \
  || -e "$WARP_EGRESS_NL_CLIENT_ENV" || -L "$WARP_EGRESS_NL_CLIENT_ENV" \
  || -e "$WARP_EGRESS_RU_BRIDGE_CLIENT_ENV" || -L "$WARP_EGRESS_RU_BRIDGE_CLIENT_ENV" \
  || -e "$WARP_EGRESS_LEGACY_CLIENT_ENV" || -L "$WARP_EGRESS_LEGACY_CLIENT_ENV" ]]; then
  die 'WARP egress env state already exists; refusing to overwrite credentials'
fi

install -d -o root -g root -m 0700 /etc/krysyuk-warp-egress
server_tmp=$(mktemp /etc/krysyuk-warp-egress/server.XXXXXX)
nl_client_tmp=$(mktemp /etc/krysyuk-warp-egress/nl-client.XXXXXX)
bridge_client_tmp=$(mktemp /etc/krysyuk-warp-egress/bridge-client.XXXXXX)
cleanup() {
  rm -f -- "$server_tmp" "$nl_client_tmp" "$bridge_client_tmp"
}
trap cleanup EXIT
remove_partial_state() {
  local rc=$?
  trap - ERR
  rm -f -- "$WARP_EGRESS_ENV" "$WARP_EGRESS_NL_CLIENT_ENV" \
    "$WARP_EGRESS_RU_BRIDGE_CLIENT_ENV"
  exit "$rc"
}
trap remove_partial_state ERR

printf '%s\n' \
  'WARP_EGRESS_HOST_LISTEN=127.0.0.1' \
  'WARP_EGRESS_NETNS_LISTEN=169.254.254.2' \
  'WARP_EGRESS_NL_PORT=24443' \
  "WARP_EGRESS_NL_CLIENT_ID=$nl_client_id" \
  'WARP_EGRESS_BRIDGE_PORT=24444' \
  "WARP_EGRESS_BRIDGE_CLIENT_ID=$bridge_client_id" \
  'WARP_EGRESS_IFACE=CloudflareWARP' \
  'PHYSICAL_IFACE=@TARGET_INTERFACE@' \
  'NL_PUBLIC_IPV4=@TARGET_IPV4@' \
  'WARP_NETNS=krysyuk-warp' \
  'WARP_HOST_VETH=kw-host' \
  'WARP_NETNS_VETH=kw-warp' \
  'WARP_HOST_IPV4=169.254.254.1' \
  'WARP_NETNS_IPV4=169.254.254.2' \
  'WARP_VETH_CIDR=169.254.254.0/30' >"$server_tmp"
printf '%s\n' \
  'WARP_EGRESS_ADDRESS=127.0.0.1' \
  'WARP_EGRESS_PORT=24443' \
  "WARP_EGRESS_CLIENT_ID=$nl_client_id" \
  'WARP_EGRESS_NETWORK=raw' \
  'WARP_EGRESS_SECURITY=none' >"$nl_client_tmp"
printf '%s\n' \
  'WARP_EGRESS_ADDRESS=127.0.0.1' \
  'WARP_EGRESS_PORT=24443' \
  "WARP_EGRESS_CLIENT_ID=$bridge_client_id" \
  'WARP_EGRESS_NETWORK=raw' \
  'WARP_EGRESS_SECURITY=none' >"$bridge_client_tmp"

install -o root -g root -m 0600 "$server_tmp" "$WARP_EGRESS_ENV"
install -o root -g root -m 0600 "$nl_client_tmp" "$WARP_EGRESS_NL_CLIENT_ENV"
install -o root -g root -m 0600 "$bridge_client_tmp" \
  "$WARP_EGRESS_RU_BRIDGE_CLIENT_ENV"
trap - ERR
unset WARP_EGRESS_CLIENT_ID WARP_EGRESS_NL_CLIENT_ID WARP_EGRESS_BRIDGE_CLIENT_ID
unset nl_client_id bridge_client_id generated_ids
printf '%s\n' 'WARP_EGRESS_ENV_INITIALIZED=1'
