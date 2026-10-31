#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

readonly script_dir=/usr/local/libexec/krysyuk-warp-egress
# shellcheck source=common.sh
source "$script_dir/common.sh"

require_root
for command_name in chmod curl date flock grep install ip mv sleep systemctl; do
  require_command "$command_name"
done
load_warp_egress_env

readonly state_dir=/var/lib/krysyuk-warp-health
readonly streak_file="$state_dir/failure-streak"
readonly last_recovery_file="$state_dir/last-recovery-epoch"
readonly last_success_file="$state_dir/last-success-epoch"
readonly failure_threshold=3
readonly recovery_cooldown=120

install -d -o root -g root -m 0700 "$state_dir"
exec 9>/run/lock/krysyuk-warp-health.lock
flock -n 9 || exit 0

read_uint() {
  local path="$1" value=0
  if [[ -f "$path" && ! -L "$path" ]]; then
    value=$(<"$path")
    [[ "$value" =~ ^[0-9]+$ ]] || value=0
  fi
  printf '%s\n' "$value"
}

write_uint() {
  local path="$1" value="$2" temporary
  [[ "$value" =~ ^[0-9]+$ ]] || die 'refusing to write non-numeric health state'
  temporary="${path}.new.$$"
  printf '%s\n' "$value" >"$temporary"
  chmod 0600 "$temporary"
  mv -f -- "$temporary" "$path"
}

probe_warp_payload() {
  local unit status
  local -a required_units=(
    krysyuk-warp-netns.service
    krysyuk-warp-netns-daemon.service
    krysyuk-warp-netns-configure.service
    krysyuk-warp-egress-guard.service
    krysyuk-xray-warp-egress.service
    krysyuk-warp-egress.socket
    krysyuk-warp-bridge.socket
  )

  for unit in "${required_units[@]}"; do
    systemctl is-active --quiet "$unit" || return 1
  done
  assert_main_routing_unchanged >/dev/null 2>&1 || return 1
  warp_status_connected || return 1
  netns_exec ip link show "$WARP_EGRESS_IFACE" >/dev/null 2>&1 || return 1
  netns_exec ip -4 route get 1.1.1.1 \
    | grep -Fq "dev $WARP_EGRESS_IFACE" || return 1

  status=$(netns_exec curl -4sS --output /dev/null --write-out '%{http_code}' \
    --proto '=https' --connect-timeout 2 --max-time 3 \
    'https://cp.cloudflare.com/generate_204' 2>/dev/null) || return 1
  [[ "$status" == 204 ]] || return 1

  # The Cloudflare-owned observer can stay reachable while a stale/bad MASQUE
  # path blackholes the wider Internet. Match the client-side aggregate health
  # target first, then use a second Google-family endpoint to distinguish a
  # single-observer incident from the Google blackhole users actually see.
  status=$(netns_exec curl -4sS --output /dev/null --write-out '%{http_code}' \
    --proto '=https' --connect-timeout 2 --max-time 3 \
    'https://www.gstatic.com/generate_204' 2>/dev/null) || status=000
  [[ "$status" == 204 ]] && return 0

  status=$(netns_exec curl -4sS --output /dev/null --write-out '%{http_code}' \
    --proto '=https' --connect-timeout 2 --max-time 3 \
    'https://www.google.com/generate_204' 2>/dev/null) || return 1
  [[ "$status" == 204 ]]
}

now=$(date +%s)
if probe_warp_payload; then
  write_uint "$streak_file" 0
  write_uint "$last_success_file" "$now"
  exit 0
fi

streak=$(read_uint "$streak_file")
streak=$((streak + 1))
write_uint "$streak_file" "$streak"
printf 'WARP_HEALTH_FAILED=1 streak=%d threshold=%d\n' \
  "$streak" "$failure_threshold" >&2
(( streak >= failure_threshold )) || exit 0

last_recovery=$(read_uint "$last_recovery_file")
if (( now - last_recovery < recovery_cooldown )); then
  write_uint "$streak_file" 0
  printf 'WARP_RECOVERY_COOLDOWN=1 remaining=%d\n' \
    "$((recovery_cooldown - (now - last_recovery)))" >&2
  exit 0
fi

write_uint "$last_recovery_file" "$now"
write_uint "$streak_file" 0
printf '%s\n' 'WARP_RECOVERY_STARTED=1' >&2
if ! "$script_dir/warp-emergency-reconnect.sh"; then
  printf '%s\n' 'WARP_RECOVERY_FAILED=1 stage=reconnect' >&2
  exit 1
fi

for _ in 1 2 3 4 5; do
  if probe_warp_payload; then
    now=$(date +%s)
    write_uint "$last_success_file" "$now"
    printf '%s\n' 'WARP_RECOVERY_OK=1'
    exit 0
  fi
  sleep 3
done

printf '%s\n' 'WARP_RECOVERY_FAILED=1 stage=payload-verification' >&2
exit 1
