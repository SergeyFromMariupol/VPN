#!/usr/bin/env bash
# shellcheck disable=SC2034 # This file is a sourced library; constants are API.

set -Eeuo pipefail
umask 077
export LC_ALL=C LANG=C LANGUAGE=C
unset PYTHONOPTIMIZE PYTHONPATH PYTHONHOME PYTHONUSERBASE PYTHONSTARTUP PYTHONINSPECT

readonly WARP_EGRESS_ENV=/etc/krysyuk-warp-egress/warp-egress.env
readonly WARP_EGRESS_NL_CLIENT_ENV=/etc/krysyuk-warp-egress/warp-egress-nl-client.env
readonly WARP_EGRESS_RU_BRIDGE_CLIENT_ENV=/etc/krysyuk-warp-egress/warp-egress-ru-bridge-client.env
readonly WARP_EGRESS_LEGACY_CLIENT_ENV=/etc/krysyuk-warp-egress/warp-egress-client.env
readonly WARP_EGRESS_TEMPLATE=/etc/krysyuk-warp-egress/xray-warp-egress.template.json
readonly WARP_EGRESS_RUNTIME=/run/krysyuk-warp-egress/xray.json
readonly WARP_EGRESS_XRAY=/opt/krysyuk-warp-egress/bin/xray
readonly WARP_EGRESS_ASSETS=/opt/krysyuk-warp-egress/share
readonly WARP_EGRESS_XRAY_VERSION=26.7.28
readonly WARP_EGRESS_XRAY_BINARY_SHA256=64d46afb80adea1bf97a0d467e83f4a9ac1ebd0995891e84bca3f1a1d1affb1d
readonly WARP_EGRESS_WARP_VERSION=2026.7.1377.0
readonly WARP_EGRESS_TABLE=krysyuk_warp_egress_guard
readonly WARP_HOST_GUARD_TABLE=krysyuk_warp_netns_host_guard
readonly WARP_HOST_NAT_TABLE=krysyuk_warp_netns_nat
readonly WARP_OUTER_MARK=0x57525001
readonly WARP_RUNTIME_DIRECTORY=/run/krysyuk-warp-egress-warp
readonly WARP_STATE_DIRECTORY=/var/lib/krysyuk-warp-egress-warp
readonly WARP_LOGS_DIRECTORY=/var/log/krysyuk-warp-egress-warp
readonly MAIN_ROUTING_BASELINE=/var/lib/krysyuk-warp-egress/main-routing.baseline
readonly WARP_APT_PIN=/etc/apt/preferences.d/90-krysyuk-cloudflare-warp

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_root() {
  [[ $(id -u) -eq 0 ]] || die 'run as root'
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command is missing: $1"
}

require_private_root_file() {
  local path="$1" label="$2" owner mode
  [[ -f "$path" && ! -L "$path" ]] || die "$label is missing or unsafe"
  owner=$(stat -c '%U:%G' "$path")
  mode=$(stat -c '%a' "$path")
  [[ "$owner" == root:root ]] || die "$label must be owned by root:root"
  (( (8#$mode & 8#077) == 0 )) || die "$label grants group/other permissions"
}

validate_uuid4() {
  local value="$1" label="$2"
  VALIDATE_UUID_VALUE="$value" VALIDATE_UUID_LABEL="$label" python3 - <<'PY'
import os
import uuid

value = os.environ["VALIDATE_UUID_VALUE"]
label = os.environ["VALIDATE_UUID_LABEL"]
try:
    parsed = uuid.UUID(value)
except ValueError as exc:
    raise SystemExit(f"{label} is not a UUID: {exc}")
if parsed.version != 4 or str(parsed) != value.lower():
    raise SystemExit(f"{label} must be canonical UUIDv4")
PY
}

validate_ipv4() {
  local value="$1" label="$2"
  VALIDATE_IPV4_VALUE="$value" VALIDATE_IPV4_LABEL="$label" python3 - <<'PY'
import ipaddress
import os

value = os.environ["VALIDATE_IPV4_VALUE"]
label = os.environ["VALIDATE_IPV4_LABEL"]
try:
    parsed = ipaddress.ip_address(value)
except ValueError:
    raise SystemExit(f"{label} is not a valid IP address")
if parsed.version != 4:
    raise SystemExit(f"{label} must be IPv4")
PY
}

load_warp_egress_env() {
  require_command python3
  require_command stat
  require_private_root_file "$WARP_EGRESS_ENV" 'WARP egress server env'

  unset WARP_EGRESS_HOST_LISTEN WARP_EGRESS_NETNS_LISTEN
  unset WARP_EGRESS_NL_PORT WARP_EGRESS_NL_CLIENT_ID
  unset WARP_EGRESS_BRIDGE_PORT WARP_EGRESS_BRIDGE_CLIENT_ID
  unset WARP_EGRESS_PORT WARP_EGRESS_CLIENT_ID
  unset WARP_EGRESS_IFACE PHYSICAL_IFACE NL_PUBLIC_IPV4
  unset WARP_NETNS WARP_HOST_VETH WARP_NETNS_VETH WARP_HOST_IPV4
  unset WARP_NETNS_IPV4 WARP_VETH_CIDR
  # shellcheck disable=SC1090
  source "$WARP_EGRESS_ENV"

  : "${WARP_EGRESS_HOST_LISTEN:?WARP_EGRESS_HOST_LISTEN is required}"
  : "${WARP_EGRESS_NETNS_LISTEN:?WARP_EGRESS_NETNS_LISTEN is required}"
  : "${WARP_EGRESS_NL_PORT:?WARP_EGRESS_NL_PORT is required}"
  : "${WARP_EGRESS_NL_CLIENT_ID:?WARP_EGRESS_NL_CLIENT_ID is required}"
  : "${WARP_EGRESS_BRIDGE_PORT:?WARP_EGRESS_BRIDGE_PORT is required}"
  : "${WARP_EGRESS_BRIDGE_CLIENT_ID:?WARP_EGRESS_BRIDGE_CLIENT_ID is required}"
  : "${WARP_EGRESS_IFACE:?WARP_EGRESS_IFACE is required}"
  : "${PHYSICAL_IFACE:?PHYSICAL_IFACE is required}"
  : "${NL_PUBLIC_IPV4:?NL_PUBLIC_IPV4 is required}"
  : "${WARP_NETNS:?WARP_NETNS is required}"
  : "${WARP_HOST_VETH:?WARP_HOST_VETH is required}"
  : "${WARP_NETNS_VETH:?WARP_NETNS_VETH is required}"
  : "${WARP_HOST_IPV4:?WARP_HOST_IPV4 is required}"
  : "${WARP_NETNS_IPV4:?WARP_NETNS_IPV4 is required}"
  : "${WARP_VETH_CIDR:?WARP_VETH_CIDR is required}"

  [[ "$WARP_EGRESS_HOST_LISTEN" == 127.0.0.1 ]] || die 'host listener must be 127.0.0.1'
  [[ "$WARP_EGRESS_NETNS_LISTEN" == 169.254.254.2 ]] || die 'netns listener address is fixed'
  [[ "$WARP_EGRESS_NL_PORT" == 24443 ]] || die 'NL-local listener port must be 24443'
  [[ "$WARP_EGRESS_BRIDGE_PORT" == 24444 ]] || die 'RU-bridge target port must be 24444'
  validate_uuid4 "$WARP_EGRESS_NL_CLIENT_ID" WARP_EGRESS_NL_CLIENT_ID
  validate_uuid4 "$WARP_EGRESS_BRIDGE_CLIENT_ID" WARP_EGRESS_BRIDGE_CLIENT_ID
  [[ "$WARP_EGRESS_NL_CLIENT_ID" != "$WARP_EGRESS_BRIDGE_CLIENT_ID" ]] || \
    die 'NL-local and RU-bridge connector UUIDs must be distinct'
  [[ "$WARP_EGRESS_IFACE" == CloudflareWARP ]] || die 'WARP interface must be CloudflareWARP'
  [[ "$PHYSICAL_IFACE" == @TARGET_INTERFACE@ ]] || die 'physical interface must be @TARGET_INTERFACE@'
  [[ "$NL_PUBLIC_IPV4" == @TARGET_IPV4@ ]] || die 'standalone public IPv4 is fixed for this bundle'
  [[ "$WARP_NETNS" == krysyuk-warp ]] || die 'network namespace name is fixed'
  [[ "$WARP_HOST_VETH" == kw-host ]] || die 'host veth name is fixed'
  [[ "$WARP_NETNS_VETH" == kw-warp ]] || die 'netns veth name is fixed'
  [[ "$WARP_HOST_IPV4" == 169.254.254.1 ]] || die 'host veth address is fixed'
  [[ "$WARP_NETNS_IPV4" == 169.254.254.2 ]] || die 'netns veth address is fixed'
  [[ "$WARP_VETH_CIDR" == 169.254.254.0/30 ]] || die 'veth subnet is fixed'
  validate_ipv4 "$NL_PUBLIC_IPV4" NL_PUBLIC_IPV4
  validate_ipv4 "$WARP_HOST_IPV4" WARP_HOST_IPV4
  validate_ipv4 "$WARP_NETNS_IPV4" WARP_NETNS_IPV4

  export WARP_EGRESS_HOST_LISTEN WARP_EGRESS_NETNS_LISTEN
  export WARP_EGRESS_NL_PORT WARP_EGRESS_BRIDGE_PORT
  export WARP_EGRESS_IFACE PHYSICAL_IFACE NL_PUBLIC_IPV4
  export WARP_NETNS WARP_HOST_VETH WARP_NETNS_VETH WARP_HOST_IPV4
  export WARP_NETNS_IPV4 WARP_VETH_CIDR
}

assert_xray_version() {
  local first_line binary_sha
  require_command sha256sum
  [[ -x "$WARP_EGRESS_XRAY" ]] || die 'private Xray binary is missing'
  binary_sha=$(sha256sum "$WARP_EGRESS_XRAY" | awk '{print $1}')
  [[ ${binary_sha,,} == "$WARP_EGRESS_XRAY_BINARY_SHA256" ]] || \
    die 'private Xray Linux binary SHA-256 does not match the audited version'
  first_line=$("$WARP_EGRESS_XRAY" version | sed -n '1p')
  grep -Eq "^Xray[[:space:]]+${WARP_EGRESS_XRAY_VERSION}([[:space:]]|$)" <<<"$first_line" || \
    die "Xray must be exactly ${WARP_EGRESS_XRAY_VERSION}"
}

assert_warp_version() {
  local installed
  installed=$(dpkg-query -W -f='${Version}' cloudflare-warp)
  [[ "$installed" == "$WARP_EGRESS_WARP_VERSION" ]] || \
    die "cloudflare-warp must be exactly ${WARP_EGRESS_WARP_VERSION}"
}

assert_warp_apt_pin() {
  local candidate
  require_command apt-cache
  require_command apt-mark
  [[ -f "$WARP_APT_PIN" && ! -L "$WARP_APT_PIN" ]] || \
    die 'Cloudflare WARP apt pin is missing or unsafe'
  [[ $(stat -c '%U:%G' "$WARP_APT_PIN") == root:root ]] || \
    die 'Cloudflare WARP apt pin owner is unsafe'
  [[ $(stat -c '%a' "$WARP_APT_PIN") == 644 ]] || \
    die 'Cloudflare WARP apt pin mode must be 0644'
  grep -Fqx 'Package: cloudflare-warp' "$WARP_APT_PIN" || \
    die 'Cloudflare WARP apt pin package is wrong'
  grep -Fqx "Pin: version ${WARP_EGRESS_WARP_VERSION}" "$WARP_APT_PIN" || \
    die 'Cloudflare WARP apt pin version is wrong'
  grep -Fqx 'Pin-Priority: 1001' "$WARP_APT_PIN" || \
    die 'Cloudflare WARP apt pin priority is wrong'
  candidate=$(apt-cache policy cloudflare-warp \
    | awk '/Candidate:/ && !found {print $2; found=1}')
  [[ "$candidate" == "$WARP_EGRESS_WARP_VERSION" ]] || \
    die 'Cloudflare WARP apt candidate is not pinned to the audited version'
  apt-mark showhold | grep -Fxq cloudflare-warp || \
    die 'Cloudflare WARP package is not held at the audited version'
}

netns_exec() {
  ip netns exec "$WARP_NETNS" "$@"
}

warp_cli() {
  netns_exec env \
    RUNTIME_DIRECTORY="$WARP_RUNTIME_DIRECTORY" \
    STATE_DIRECTORY="$WARP_STATE_DIRECTORY" \
    LOGS_DIRECTORY="$WARP_LOGS_DIRECTORY" \
    /bin/warp-cli --accept-tos "$@"
}

warp_status_connected() {
  local status
  status=$(warp_cli status 2>&1) || return 1
  grep -Eiq '(^|[[:space:]])Connected([[:space:]]|$)' <<<"$status"
}

wait_for_warp() {
  local tries=${1:-60} i
  for ((i = 1; i <= tries; i++)); do
    if warp_status_connected \
      && netns_exec ip link show "$WARP_EGRESS_IFACE" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

assert_main_routing_unchanged() {
  require_private_root_file "$MAIN_ROUTING_BASELINE" 'main routing baseline'
  /usr/local/libexec/krysyuk-warp-egress/capture-main-routing.sh \
    | cmp -s -- "$MAIN_ROUTING_BASELINE" - || \
    die 'main namespace default routes or policy rules changed'
  if ip link show CloudflareWARP >/dev/null 2>&1; then
    die 'CloudflareWARP leaked into the main namespace'
  fi
}
