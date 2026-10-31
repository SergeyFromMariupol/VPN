#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

readonly lib=/usr/local/libexec/krysyuk-warp-egress/common.sh
# shellcheck source=../scripts/common.sh
source "$lib"

require_root
for command_name in awk cmp curl dig head ip jq python3 ss wc; do
  require_command "$command_name"
done
load_warp_egress_env
assert_xray_version
assert_main_routing_unchanged

stage=$(mktemp -d /run/krysyuk-warp-egress-e2e.XXXXXX)
readonly socks_port=12080
readonly dns_port=12053
readonly quic_port=12054
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

if ss -H -lntu | grep -Eq ":(${socks_port}|${dns_port}|${quic_port})[[:space:]]"; then
  die 'an E2E test port is already in use'
fi

probe_quic_version_negotiation() {
  QUIC_TEST_PORT="$quic_port" python3 - <<'PY'
import os
import socket
import struct

port = int(os.environ["QUIC_TEST_PORT"])
dcid = os.urandom(8)
scid = os.urandom(8)
packet = (
    bytes([0xC0])
    + struct.pack("!I", 0x0A0A0A0A)
    + bytes([len(dcid)])
    + dcid
    + bytes([len(scid)])
    + scid
)
packet += os.urandom(1200 - len(packet))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(8)
try:
    response = b""
    for _ in range(3):
        sock.sendto(packet, ("127.0.0.1", port))
        try:
            response, _ = sock.recvfrom(4096)
            break
        except TimeoutError:
            continue
finally:
    sock.close()

if len(response) < 15 or not response[0] & 0x80:
    raise SystemExit("QUIC long-header response is absent")
if struct.unpack("!I", response[1:5])[0] != 0:
    raise SystemExit("response is not QUIC Version Negotiation")
offset = 5
dcid_len = response[offset]
offset += 1
response_dcid = response[offset : offset + dcid_len]
offset += dcid_len
scid_len = response[offset]
offset += 1
response_scid = response[offset : offset + scid_len]
offset += scid_len
if response_dcid != scid or response_scid != dcid:
    raise SystemExit("QUIC connection IDs were not reflected correctly")
if len(response) <= offset or (len(response) - offset) % 4:
    raise SystemExit("QUIC Version Negotiation list is malformed")
PY
}

probe_cloudflare_warp_trace() {
  local label="$1" proxy_port="$2"
  local attempt endpoint_index body_path error_path status
  local warp_count warp_value ip_count exit_address
  local start_offset=0
  local -a curl_args=()
  local -a trace_urls=(
    'https://www.cloudflare.com/cdn-cgi/trace'
    'https://one.one.one.one/cdn-cgi/trace'
    'https://speed.cloudflare.com/cdn-cgi/trace'
    'https://one.one.one.one/cdn-cgi/trace'
  )
  local -a trace_connect_to=(
    ''
    ''
    ''
    'one.one.one.one:443:1.1.1.1:443'
  )

  # The two connector credentials are tested consecutively. Start the second
  # one at a different observer and delay it below to avoid a needless burst.
  [[ "$label" == 'ru-bridge' ]] && start_offset=2
  for attempt in 1 2 3 4; do
    endpoint_index=$(( (start_offset + attempt - 1) % ${#trace_urls[@]} ))
    body_path="$stage/${label}-trace-${attempt}.body"
    error_path="$stage/${label}-trace-${attempt}.error"
    curl_args=(
      -4sS --location --max-redirs 2
      --proto '=https' --proto-redir '=https'
      --connect-timeout 8 --max-time 20 --max-filesize 65536
      --socks5-hostname "127.0.0.1:${proxy_port}"
      --output "$body_path" --write-out '%{http_code}'
    )
    if [[ -n "${trace_connect_to[$endpoint_index]}" ]]; then
      # The URL host remains one.one.one.one, so HTTP Host and TLS SNI are
      # correct even though the network destination is pinned to 1.1.1.1.
      curl_args+=(--connect-to "${trace_connect_to[$endpoint_index]}")
    fi

    if status=$(curl "${curl_args[@]}" "${trace_urls[$endpoint_index]}" \
      2>"$error_path"); then
      [[ "$status" =~ ^[0-9]{3}$ ]] || \
        die "${label} Cloudflare trace returned a malformed HTTP status"
      if [[ "$status" == 200 ]]; then
        warp_count=$(awk '/^warp=/ { count++ } END { print count + 0 }' "$body_path")
        if [[ "$warp_count" != 1 ]]; then
          printf 'INFO: %s Cloudflare trace observer returned a malformed body (attempt %d/4)\n' \
            "$label" "$attempt" >&2
        else
          warp_value=$(awk '/^warp=/ { print substr($0, 6) }' "$body_path")
          # A valid trace is authoritative. Never hide warp=off/plus/unknown by
          # retrying another observer: that would weaken the fail-closed proof.
          [[ "$warp_value" == 'on' ]] || \
            die "${label} valid Cloudflare trace did not report warp=on"
          ip_count=$(awk '/^ip=/ { count++ } END { print count + 0 }' "$body_path")
          if [[ "$ip_count" != 1 ]]; then
            printf 'INFO: %s Cloudflare trace observer omitted a unique exit address (attempt %d/4)\n' \
              "$label" "$attempt" >&2
          else
            exit_address=$(awk '/^ip=/ { print substr($0, 4) }' "$body_path")
            if TRACE_EXIT_ADDRESS="$exit_address" python3 -c \
              'import ipaddress, os; ipaddress.ip_address(os.environ["TRACE_EXIT_ADDRESS"])' \
              >/dev/null 2>&1; then
              printf '%s\n' "$exit_address"
              return 0
            fi
            printf 'INFO: %s Cloudflare trace observer returned a malformed exit address (attempt %d/4)\n' \
              "$label" "$attempt" >&2
          fi
        fi
      elif [[ "$status" == 429 || "$status" =~ ^5[0-9]{2}$ ]]; then
        printf 'INFO: %s Cloudflare trace observer returned retryable HTTP %s (attempt %d/4)\n' \
          "$label" "$status" "$attempt" >&2
      else
        die "${label} Cloudflare trace observer rejected HTTP status ${status}"
      fi
    else
      printf 'INFO: %s Cloudflare trace observer was unreachable (attempt %d/4)\n' \
        "$label" "$attempt" >&2
    fi
    rm -f -- "$body_path" "$error_path"
    (( attempt < 4 )) && sleep "$attempt"
  done
  die "${label} Cloudflare trace observers remained unavailable after bounded retries"
}

probe_cloudflare_payload() {
  local label="$1" proxy_port="$2"
  local attempt payload_path error_path status payload_size

  # Payload throttling is independent from /cdn-cgi/trace throttling. Keep its
  # retry budget separate so a single 429 never looks like a transport failure.
  for attempt in 1 2 3; do
    payload_path="$stage/${label}-payload-${attempt}.bin"
    error_path="$stage/${label}-payload-${attempt}.error"
    if status=$(curl -4sS --location --max-redirs 2 \
      --proto '=https' --proto-redir '=https' \
      --connect-timeout 8 --max-time 20 --max-filesize 8192 \
      --socks5-hostname "127.0.0.1:${proxy_port}" \
      --output "$payload_path" --write-out '%{http_code}' \
      'https://speed.cloudflare.com/__down?bytes=4096' 2>"$error_path"); then
      [[ "$status" =~ ^[0-9]{3}$ ]] || \
        die "${label} Cloudflare payload observer returned a malformed HTTP status"
      if [[ "$status" == 200 ]]; then
        payload_size=$(wc -c <"$payload_path")
        [[ "$payload_size" == 4096 ]] || \
          die "${label} TCP payload through the WARP connector was truncated"
        return 0
      fi
      if [[ "$status" == 429 || "$status" =~ ^5[0-9]{2}$ ]]; then
        printf 'INFO: %s Cloudflare payload observer returned retryable HTTP %s (attempt %d/3)\n' \
          "$label" "$status" "$attempt" >&2
      else
        die "${label} Cloudflare payload observer rejected HTTP status ${status}"
      fi
    else
      printf 'INFO: %s Cloudflare payload observer was unreachable (attempt %d/3)\n' \
        "$label" "$attempt" >&2
    fi
    rm -f -- "$payload_path" "$error_path"
    (( attempt < 3 )) && sleep "$attempt"
  done
  die "${label} Cloudflare payload observer remained unavailable after bounded retries"
}

run_connector_e2e() {
  local label="$1" connector_id="$2" connector_port="$3"
  local config="$stage/${label}.json" log="$stage/${label}.log"
  local exit_address udp_answer tcp_answer

  TEST_CONNECTOR_ID="$connector_id" jq -n \
    --argjson connector_port "$connector_port" \
    --argjson socks_port "$socks_port" \
    --argjson dns_port "$dns_port" \
    --argjson quic_port "$quic_port" '{
      log: {loglevel: "warning"},
      inbounds: [
        {tag: "TEST_SOCKS", listen: "127.0.0.1", port: $socks_port,
         protocol: "socks", settings: {auth: "noauth", udp: true}},
        {tag: "TEST_DNS", listen: "127.0.0.1", port: $dns_port,
         protocol: "dokodemo-door",
         settings: {address: "1.1.1.1", port: 53, network: "tcp,udp", timeout: 12}},
        {tag: "TEST_QUIC", listen: "127.0.0.1", port: $quic_port,
         protocol: "dokodemo-door",
         settings: {address: "8.8.8.8", port: 443, network: "udp", timeout: 12}}
      ],
      outbounds: [
        {tag: "CONNECTOR", protocol: "vless",
         settings: {vnext: [{address: "127.0.0.1", port: $connector_port,
           users: [{id: env.TEST_CONNECTOR_ID, encryption: "none"}]}]},
         streamSettings: {network: "raw", security: "none"}}
      ],
      routing: {domainStrategy: "AsIs", rules: [
        {type: "field", inboundTag: ["TEST_SOCKS", "TEST_DNS", "TEST_QUIC"],
         outboundTag: "CONNECTOR"}
      ]}
    }' >"$config"
  chmod 0600 "$config"
  unset TEST_CONNECTOR_ID
  XRAY_LOCATION_ASSET="$WARP_EGRESS_ASSETS" \
    "$WARP_EGRESS_XRAY" run -test -config "$config" >/dev/null
  XRAY_LOCATION_ASSET="$WARP_EGRESS_ASSETS" \
    "$WARP_EGRESS_XRAY" run -config "$config" >"$log" 2>&1 &
  client_pid=$!
  for _ in $(seq 1 40); do
    kill -0 "$client_pid" 2>/dev/null || die "${label} E2E Xray client exited early"
    if ss -H -lnt | grep -Eq ":${socks_port}[[:space:]]" \
      && ss -H -lnt | grep -Eq ":${dns_port}[[:space:]]" \
      && ss -H -lnu | grep -Eq ":(${dns_port}|${quic_port})[[:space:]]"; then
      break
    fi
    sleep 0.25
  done
  ss -H -lnt | grep -Eq ":${socks_port}[[:space:]]" || \
    die "${label} E2E SOCKS listener did not start"
  ss -H -lnu | grep -Eq ":${quic_port}[[:space:]]" || \
    die "${label} E2E QUIC listener did not start"

  exit_address=$(probe_cloudflare_warp_trace "$label" "$socks_port")
  [[ "$exit_address" != "$NL_PUBLIC_IPV4" ]] || \
    die "${label} foreign target saw the physical NL address"

  udp_answer=$(dig +time=10 +tries=1 +short @127.0.0.1 -p "$dns_port" example.com A \
    | sed -n '1p')
  [[ -n "$udp_answer" ]] || die "${label} UDP DNS did not traverse the WARP connector"
  tcp_answer=$(dig +tcp +time=10 +tries=1 +short @127.0.0.1 -p "$dns_port" \
    example.com A | sed -n '1p')
  [[ -n "$tcp_answer" ]] || die "${label} TCP DNS did not traverse the WARP connector"
  sleep 1
  probe_cloudflare_payload "$label" "$socks_port"
  probe_quic_version_negotiation || \
    die "${label} generic UDP/QUIC did not traverse the WARP connector"

  cleanup_client
  assert_main_routing_unchanged
  printf 'WARP_EGRESS_PATH_OK=%s warp=on tcp=ok udp=ok dns-tcp=ok dns-udp=ok quic-vn=ok\n' \
    "$label"
}

run_connector_e2e nl-local "$WARP_EGRESS_NL_CLIENT_ID" "$WARP_EGRESS_NL_PORT"
# Avoid sending the second credential's observer requests as an immediate burst.
sleep 3
run_connector_e2e ru-bridge "$WARP_EGRESS_BRIDGE_CLIENT_ID" "$WARP_EGRESS_BRIDGE_PORT"
unset WARP_EGRESS_NL_CLIENT_ID WARP_EGRESS_BRIDGE_CLIENT_ID
printf '%s\n' 'WARP_EGRESS_DUAL_E2E_OK=1'
