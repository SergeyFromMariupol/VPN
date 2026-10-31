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
require_private_root_file "$WARP_EGRESS_ENV" 'WARP egress server env'

unset WARP_EGRESS_CLIENT_ID WARP_EGRESS_NL_CLIENT_ID WARP_EGRESS_BRIDGE_CLIENT_ID
# shellcheck disable=SC1090
source "$WARP_EGRESS_ENV"
legacy_client_id=${WARP_EGRESS_CLIENT_ID:-}
nl_client_id=${WARP_EGRESS_NL_CLIENT_ID:-}
bridge_client_id=${WARP_EGRESS_BRIDGE_CLIENT_ID:-}
if [[ -n "$nl_client_id" || -n "$bridge_client_id" ]]; then
  [[ -n "$nl_client_id" && -n "$bridge_client_id" ]] || \
    die 'partially migrated dual-credential env is invalid'
  migration_source=dual
else
  [[ -n "$legacy_client_id" ]] || die 'no migratable connector UUID exists'
  nl_client_id=$legacy_client_id
  bridge_client_id=$(python3 - <<'PY'
import uuid
print(uuid.uuid4())
PY
)
  migration_source=legacy-single
fi
validate_uuid4 "$nl_client_id" WARP_EGRESS_NL_CLIENT_ID
validate_uuid4 "$bridge_client_id" WARP_EGRESS_BRIDGE_CLIENT_ID
[[ "$nl_client_id" != "$bridge_client_id" ]] || \
  die 'NL-local and RU-bridge UUIDs must be distinct'

server_tmp=$(mktemp /etc/krysyuk-warp-egress/server.XXXXXX)
trap 'rm -f -- "$server_tmp"' EXIT
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
install -o root -g root -m 0600 "$server_tmp" "$WARP_EGRESS_ENV"
unset WARP_EGRESS_CLIENT_ID WARP_EGRESS_NL_CLIENT_ID WARP_EGRESS_BRIDGE_CLIENT_ID
unset legacy_client_id nl_client_id bridge_client_id
"$script_dir/render-client-env.sh" >/dev/null
rm -f -- "$WARP_EGRESS_LEGACY_CLIENT_ENV"
printf 'WARP_EGRESS_ENV_MIGRATED=1 source=%s\n' "$migration_source"
