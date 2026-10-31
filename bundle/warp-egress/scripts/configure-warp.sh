#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
readonly script_dir
# shellcheck source=common.sh
source "$script_dir/common.sh"

require_root
for command_name in curl dpkg-query grep ip iptables nft seq sleep systemctl; do
  require_command "$command_name"
done
load_warp_egress_env
assert_warp_version
assert_warp_apt_pin
systemctl is-active --quiet krysyuk-warp-netns.service || die 'WARP netns service is not active'
systemctl is-active --quiet krysyuk-warp-netns-daemon.service || die 'isolated warp-svc is not active'
systemctl is-active --quiet warp-svc.service && die 'host warp-svc must remain inactive'

for _ in $(seq 1 60); do
  if warp_cli status >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
warp_cli status >/dev/null 2>&1 || die 'isolated warp-svc IPC did not become ready'

# A persisted registration allows warp-svc to restore its tunnel before plain
# namespace DNS is ready.  Do not make a cold boot depend on an unnecessary
# pre-tunnel API probe.  On first registration, however, prove and retry the
# narrow carrier/re-marked namespace-to-host path before creating state.
registration_ready=false
if warp_cli registration show >/dev/null 2>&1; then
  registration_ready=true
else
  registration_api_code=
  for _ in $(seq 1 10); do
    registration_api_code=$(netns_exec curl -4 --silent --show-error \
      --connect-timeout 3 --max-time 8 --output /dev/null --write-out '%{http_code}' \
      https://api.cloudflareclient.com/ 2>/dev/null || true)
    [[ $registration_api_code =~ ^[234][0-9][0-9]$ ]] && break
    sleep 3
  done
  if [[ ! $registration_api_code =~ ^[234][0-9][0-9]$ ]]; then
    printf '%s\n' 'WARP_REGISTRATION_PATH_DIAGNOSTICS_BEGIN' >&2
    netns_exec nft list chain inet "$WARP_EGRESS_TABLE" output 2>&1 | \
      grep -E 'kw-warp|xraywarp' >&2 || true
    nft list chain inet "$WARP_HOST_GUARD_TABLE" forward 2>&1 | \
      grep -E 'kw-host|@TARGET_INTERFACE@' >&2 || true
    nft list chain ip "$WARP_HOST_NAT_TABLE" postrouting 2>&1 | \
      grep -E '169[.]254[.]254[.]2|@TARGET_INTERFACE@' >&2 || true
    iptables -w -nvx -L ufw-before-forward 2>&1 | \
      grep -E 'kw-host|@TARGET_INTERFACE@' >&2 || true
    printf '%s\n' 'WARP_REGISTRATION_PATH_DIAGNOSTICS_END' >&2
    die 'isolated namespace cannot reach the WARP registration API'
  fi

  for attempt in 1 2 3; do
    warp_cli registration new >/dev/null 2>&1 || true
    if warp_cli registration show >/dev/null 2>&1; then
      registration_ready=true
      break
    fi
    sleep $((attempt * 5))
  done
  [[ "$registration_ready" == true ]] ||
    die 'isolated WARP registration failed after bounded retries'
fi

mode_help=$(warp_cli mode --help 2>&1 || true)
grep -Eq '(^|[[:space:]])tunnel_only([[:space:]:]|$)' <<<"$mode_help" || \
  die 'exact WARP CLI lacks tunnel_only mode'
warp_cli mode tunnel_only >/dev/null

protocol_help=$(warp_cli tunnel protocol --help 2>&1 || true)
grep -Eiq '(^|[[:space:]])set([[:space:]]|$)' <<<"$protocol_help" || \
  die 'exact WARP CLI lacks tunnel protocol set'
warp_cli tunnel protocol set MASQUE >/dev/null

warp_cli tunnel ip list >/dev/null 2>&1 || \
  die 'WARP CLI does not expose a verifiable split-tunnel list'
excluded=$(warp_cli tunnel ip list)
if ! grep -Fq '169.254.0.0/16' <<<"$excluded" \
  && ! grep -Fq "$WARP_VETH_CIDR" <<<"$excluded"; then
  add_help=$(warp_cli tunnel ip --help 2>&1 || true)
  grep -Fq 'add-range' <<<"$add_help" || die 'WARP CLI cannot exclude the veth transport subnet'
  warp_cli tunnel ip add-range "$WARP_VETH_CIDR" >/dev/null
fi

warp_cli connect >/dev/null
wait_for_warp 90 || die 'isolated WARP did not become Connected'
settings=$(warp_cli settings)
grep -Eq 'Mode:[[:space:]]+TunnelOnly|Mode:[[:space:]]+Traffic' <<<"$settings" || \
  die 'isolated WARP did not retain traffic-only mode'
grep -Eiq 'WARP tunnel protocol:[[:space:]]+MASQUE|MASQUE \(' <<<"$settings" || \
  die 'isolated WARP did not retain MASQUE'

netns_route=$(netns_exec ip -4 route get 1.1.1.1)
grep -Fq "dev $WARP_EGRESS_IFACE" <<<"$netns_route" || \
  die 'netns foreign route does not use CloudflareWARP'
transport_route=$(netns_exec ip -4 route get "$WARP_HOST_IPV4")
grep -Fq "dev $WARP_NETNS_VETH" <<<"$transport_route" || \
  die 'WARP outer transport route was captured by the WARP tunnel'
if grep -Fq "dev $WARP_EGRESS_IFACE" <<<"$transport_route"; then
  die 'WARP outer transport route is recursive'
fi
assert_main_routing_unchanged

trace=$(netns_exec curl -4fsS --connect-timeout 10 --max-time 25 \
  https://www.cloudflare.com/cdn-cgi/trace)
grep -Fqx 'warp=on' <<<"$trace" || die 'isolated WARP trace did not report warp=on'
unset settings excluded add_help mode_help protocol_help netns_route transport_route trace \
  registration_api_code registration_ready attempt
printf '%s\n' 'WARP_NETNS_CONFIGURED mode=tunnel_only protocol=MASQUE connected=1'
