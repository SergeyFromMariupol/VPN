#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

readonly lib=/usr/local/libexec/krysyuk-warp-egress/common.sh
# shellcheck source=../scripts/common.sh
source "$lib"

require_root
for command_name in cmp curl ip jq python3 ss; do
  require_command "$command_name"
done
load_warp_egress_env
assert_xray_version
assert_main_routing_unchanged
[[ ! -e "$WARP_EGRESS_LEGACY_CLIENT_ENV" && ! -L "$WARP_EGRESS_LEGACY_CLIENT_ENV" ]] || \
  die 'legacy shared connector client env still exists'

export CURRENT_NL_ID="$WARP_EGRESS_NL_CLIENT_ID"
export CURRENT_BRIDGE_ID="$WARP_EGRESS_BRIDGE_CLIENT_ID"
invalid_id=$(python3 - <<'PY'
import os
import uuid

valid = {os.environ["CURRENT_NL_ID"].lower(), os.environ["CURRENT_BRIDGE_ID"].lower()}
while True:
    candidate = str(uuid.uuid4())
    if candidate not in valid:
        print(candidate)
        break
PY
)
unset CURRENT_NL_ID CURRENT_BRIDGE_ID

stage=$(mktemp -d /run/krysyuk-warp-egress-invalid.XXXXXX)
readonly socks_port=12180
client_pid=''
cleanup_client() {
  if [[ -n "$client_pid" ]] && kill -0 "$client_pid" 2>/dev/null; then
    kill "$client_pid" >/dev/null 2>&1 || true
    wait "$client_pid" >/dev/null 2>&1 || true
  fi
  client_pid=''
}
cleanup() {
  cleanup_client
  rm -rf -- "$stage"
}
trap cleanup EXIT
ss -H -lnt | grep -Eq ":${socks_port}[[:space:]]" && die 'invalid test port is in use'

expect_rejected() {
  local label="$1" connector_port="$2" attempted_id="$3"
  local config="$stage/${label}.json" log="$stage/${label}.log" code

  TEST_ATTEMPTED_ID="$attempted_id" jq -n \
    --argjson connector_port "$connector_port" \
    --argjson socks_port "$socks_port" '{
      log: {loglevel: "warning"},
      inbounds: [{listen: "127.0.0.1", port: $socks_port,
        protocol: "socks", settings: {auth: "noauth", udp: true}}],
      outbounds: [{protocol: "vless",
        settings: {vnext: [{address: "127.0.0.1", port: $connector_port,
          users: [{id: env.TEST_ATTEMPTED_ID, encryption: "none"}]}]},
        streamSettings: {network: "raw", security: "none"}}]
    }' >"$config"
  chmod 0600 "$config"
  unset TEST_ATTEMPTED_ID
  XRAY_LOCATION_ASSET="$WARP_EGRESS_ASSETS" \
    "$WARP_EGRESS_XRAY" run -test -config "$config" >/dev/null
  XRAY_LOCATION_ASSET="$WARP_EGRESS_ASSETS" \
    "$WARP_EGRESS_XRAY" run -config "$config" >"$log" 2>&1 &
  client_pid=$!
  for _ in $(seq 1 40); do
    kill -0 "$client_pid" 2>/dev/null || die "${label} test client exited early"
    ss -H -lnt | grep -Eq ":${socks_port}[[:space:]]" && break
    sleep 0.25
  done
  ss -H -lnt | grep -Eq ":${socks_port}[[:space:]]" || \
    die "${label} SOCKS listener did not start"

  code=$(curl -4sS --connect-timeout 5 --max-time 12 \
    --socks5-hostname "127.0.0.1:${socks_port}" --output /dev/null \
    --write-out '%{http_code}' https://www.cloudflare.com/cdn-cgi/trace || true)
  [[ "$code" != 200 ]] || die "${label} credential unexpectedly produced egress"
  cleanup_client
  printf 'WARP_EGRESS_REJECTED=%s\n' "$label"
}

# Each valid UUID is intentionally invalid at the other listener. In a legacy
# single-UUID migration this proves that the former shared credential no longer
# grants RU-bridge access.
expect_rejected nl-id-on-bridge "$WARP_EGRESS_BRIDGE_PORT" \
  "$WARP_EGRESS_NL_CLIENT_ID"
expect_rejected bridge-id-on-nl "$WARP_EGRESS_NL_PORT" \
  "$WARP_EGRESS_BRIDGE_CLIENT_ID"
expect_rejected random-id-on-nl "$WARP_EGRESS_NL_PORT" "$invalid_id"
expect_rejected random-id-on-bridge "$WARP_EGRESS_BRIDGE_PORT" "$invalid_id"

unset invalid_id WARP_EGRESS_NL_CLIENT_ID WARP_EGRESS_BRIDGE_CLIENT_ID
assert_main_routing_unchanged
printf '%s\n' 'WARP_EGRESS_CROSS_CREDENTIALS_REJECTED=1'
printf '%s\n' 'WARP_EGRESS_LEGACY_SHARED_BRIDGE_ACCESS_REVOKED=1'
