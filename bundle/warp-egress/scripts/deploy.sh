#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
readonly script_dir
bundle_root=$(cd -- "$script_dir/.." && pwd -P)
readonly bundle_root
# shellcheck source=common.sh
source "$script_dir/common.sh"
# shellcheck source=phase-state.sh
source "$script_dir/phase-state.sh"

require_root
case "${1:-}" in
  --initialize) initialize=1 ;;
  --apply) initialize=0 ;;
  *) die 'usage: deploy.sh [--initialize|--apply]' ;;
esac
[[ ${CONFIRM_WARP_EGRESS_DEPLOY:-} == 'DEPLOY-STANDALONE-WARP-NETNS-@TARGET_IPV4@' ]] || \
  die 'exact CONFIRM_WARP_EGRESS_DEPLOY value is required'

for command_name in apt-mark awk bash cmp cp curl date dig dpkg dpkg-query find getent grep install ip jq \
  mktemp nft python3 readlink sed sha256sum shellcheck sort ss stat sysctl systemctl \
  systemd-analyze systemd-run tcpdump timeout ufw warp-cli wc; do
  require_command "$command_name"
done
# shellcheck disable=SC1091
source /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 24.04 ]] || \
  die 'this deployment requires Ubuntu 24.04'
[[ $(dpkg --print-architecture) == amd64 ]] || die 'this deployment requires amd64'
[[ $(getent passwd xraywarp | cut -d: -f6) == /nonexistent ]] || \
  die 'xraywarp is missing or has an unexpected home directory'
[[ $(getent passwd xraywarp | cut -d: -f7) == /usr/sbin/nologin ]] || \
  die 'xraywarp has an unexpected login shell'
[[ $(id -gn xraywarp) == xraywarp ]] || die 'xraywarp has an unexpected primary group'
assert_xray_version
assert_warp_version
[[ -x /usr/lib/systemd/systemd-socket-proxyd ]] || die 'systemd-socket-proxyd is missing'

readonly rollback_root=/var/lib/krysyuk-warp-egress/rollback
deploy_id=$(date -u +%Y%m%dT%H%M%SZ)-$$
readonly deploy_id
readonly rollback_dir="$rollback_root/$deploy_id"
install -d -o root -g root -m 0700 "$rollback_root"
install -d -o root -g root -m 0700 "$rollback_dir/rootfs"

units=(
  krysyuk-warp-netns.service
  krysyuk-warp-netns-daemon.service
  krysyuk-warp-netns-configure.service
  krysyuk-warp-egress-guard.service
  krysyuk-xray-warp-egress.service
  krysyuk-warp-egress.socket
  krysyuk-warp-egress.service
  krysyuk-warp-bridge.socket
  krysyuk-warp-bridge.service
  krysyuk-warp-health.service
  warp-svc.service
)
capture_service_state() {
  local unit="$1" output="$2" present=0 active=0 enable_state
  systemctl cat "$unit" >/dev/null 2>&1 && present=1
  systemctl is-active --quiet "$unit" 2>/dev/null && active=1
  enable_state=$(systemctl is-enabled "$unit" 2>/dev/null || true)
  [[ -n "$enable_state" ]] || enable_state=not-found
  printf 'present=%s\nactive=%s\nenable_state=%s\n' \
    "$present" "$active" "$enable_state" >"$output"
}
for unit in "${units[@]}"; do
  capture_service_state "$unit" "$rollback_dir/service-${unit}.state"
done
# Refuse an orphan namespace/veth state that a file/service rollback could not
# reconstruct byte-for-byte.
# shellcheck disable=SC1090
source "$rollback_dir/service-krysyuk-warp-netns.service.state"
namespace_present=0
veth_present=0
ip netns list | awk '{print $1}' | grep -Fxq krysyuk-warp && namespace_present=1
ip link show kw-host >/dev/null 2>&1 && veth_present=1
if (( active == 1 )); then
  (( namespace_present == 1 && veth_present == 1 )) || \
    die 'active prior netns service has inconsistent namespace/veth state'
else
  (( namespace_present == 0 && veth_present == 0 )) || \
    die 'orphan prior namespace/veth state must be resolved before deploy'
fi
unset present active enable_state namespace_present veth_present

if nft -s list table inet "$WARP_HOST_GUARD_TABLE" \
  >"$rollback_dir/host-guard-table.nft" 2>/dev/null; then
  printf '%s\n' present >"$rollback_dir/host-guard-table.state"
else
  printf '%s\n' absent >"$rollback_dir/host-guard-table.state"
fi
if nft -s list table ip "$WARP_HOST_NAT_TABLE" \
  >"$rollback_dir/host-nat-table.nft" 2>/dev/null; then
  printf '%s\n' present >"$rollback_dir/host-nat-table.state"
else
  printf '%s\n' absent >"$rollback_dir/host-nat-table.state"
fi
sysctl -n net.ipv4.ip_forward >"$rollback_dir/ip-forward.state"
if ufw status | grep -Fq 'Status: active'; then
  printf '%s\n' active >"$rollback_dir/ufw.state"
else
  printf '%s\n' inactive >"$rollback_dir/ufw.state"
fi
for ufw_file in /etc/ufw/user.rules /etc/ufw/user6.rules \
  /etc/ufw/before.rules /etc/ufw/before6.rules; do
  if [[ -e "$ufw_file" ]]; then
    cp -a --parents -- "$ufw_file" "$rollback_dir/rootfs"
  else
    printf '%s\n' "$ufw_file" >>"$rollback_dir/ufw-absent-before.txt"
  fi
done
if apt-mark showhold | grep -Fxq cloudflare-warp; then
  printf '%s\n' held >"$rollback_dir/warp-apt-hold.state"
else
  printf '%s\n' unheld >"$rollback_dir/warp-apt-hold.state"
fi

snapshot_complete=0
failure_line=unknown
restore_early_services() {
  local unit state_file present active enable_state
  systemctl daemon-reload >/dev/null 2>&1 || true
  for unit in "${units[@]}"; do
    state_file="$rollback_dir/service-${unit}.state"
    [[ -f "$state_file" ]] || continue
    # shellcheck disable=SC1090
    source "$state_file"
    if (( present == 1 && active == 1 )); then
      systemctl start "$unit" >/dev/null 2>&1 || true
    fi
  done
}
restore_early_network() {
  local ip_forward state
  ip_forward=$(<"$rollback_dir/ip-forward.state")
  [[ "$ip_forward" =~ ^[01]$ ]] && \
    sysctl -q -w "net.ipv4.ip_forward=$ip_forward" >/dev/null 2>&1 || true
  nft delete table inet "$WARP_HOST_GUARD_TABLE" >/dev/null 2>&1 || true
  nft delete table ip "$WARP_HOST_NAT_TABLE" >/dev/null 2>&1 || true
  state=$(<"$rollback_dir/host-guard-table.state")
  if [[ "$state" == present ]]; then
    nft -f "$rollback_dir/host-guard-table.nft" >/dev/null 2>&1 || true
  fi
  state=$(<"$rollback_dir/host-nat-table.state")
  if [[ "$state" == present ]]; then
    nft -f "$rollback_dir/host-nat-table.nft" >/dev/null 2>&1 || true
  fi
}
on_exit() {
  local rc=$?
  trap - EXIT ERR HUP INT TERM
  if (( rc != 0 )); then
    printf 'WARP_NETNS_DEPLOY_FAILED_LINE=%s\n' "$failure_line" >&2
  fi
  if (( snapshot_complete == 0 )); then
    restore_early_network
    restore_early_services
  elif [[ ! -f "$rollback_dir/COMMITTED" ]]; then
    clear_uncommitted_warp_phase_marker || true
    if "$bundle_root/scripts/rollback-last.sh" "$rollback_dir"; then
      printf '%s\n' 'WARP_NETNS_AUTO_ROLLBACK_OK=1' >&2
    else
      printf 'WARP_NETNS_AUTO_ROLLBACK_FAILED=%s\n' "$rollback_dir" >&2
    fi
  fi
  exit "$rc"
}
trap on_exit EXIT
trap 'failure_line=$LINENO' ERR
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

systemctl stop krysyuk-warp-egress.socket krysyuk-warp-egress.service \
  krysyuk-warp-bridge.socket krysyuk-warp-bridge.service \
  krysyuk-xray-warp-egress.service krysyuk-warp-egress-guard.service \
  krysyuk-warp-netns-configure.service krysyuk-warp-netns-daemon.service \
  krysyuk-warp-netns.service >/dev/null 2>&1 || true
systemctl stop warp-svc.service >/dev/null 2>&1 || true

managed_paths=(
  /etc/krysyuk-warp-egress
  /etc/netns/krysyuk-warp
  /etc/nftables.d/krysyuk-warp-egress-guard.nft
  /etc/nftables.d/krysyuk-warp-netns-host.nft
  /etc/apt/preferences.d/90-krysyuk-cloudflare-warp
  /etc/systemd/system/krysyuk-warp-netns.service
  /etc/systemd/system/krysyuk-warp-netns-daemon.service
  /etc/systemd/system/krysyuk-warp-netns-configure.service
  /etc/systemd/system/krysyuk-warp-egress-guard.service
  /etc/systemd/system/krysyuk-xray-warp-egress.service
  /etc/systemd/system/krysyuk-warp-egress.socket
  /etc/systemd/system/krysyuk-warp-egress.service
  /etc/systemd/system/krysyuk-warp-bridge.socket
  /etc/systemd/system/krysyuk-warp-bridge.service
  /etc/systemd/system/krysyuk-warp-health.service
  /etc/systemd/system/warp-svc.service
  /usr/local/libexec/krysyuk-warp-egress
  /usr/local/sbin/krysyuk-warp-egress-rollback
  /opt/krysyuk-warp-egress/tests
  /var/lib/krysyuk-warp-egress/main-routing.baseline
  /var/lib/krysyuk-warp-egress/deployed-boot-id
  /var/lib/krysyuk-warp-egress-warp
  /var/log/krysyuk-warp-egress-warp
)
for path in "${managed_paths[@]}"; do
  if [[ "$path" == /etc/systemd/system/warp-svc.service && -L "$path" ]]; then
    [[ $(readlink -- "$path") == /dev/null ]] || die 'warp-svc mask points somewhere unsafe'
  elif [[ "$path" == /etc/systemd/system/warp-svc.service && -e "$path" ]]; then
    [[ -f "$path" ]] || die 'warp-svc override is not a regular file'
  else
    [[ ! -L "$path" ]] || die 'a managed path is an unsafe symbolic link'
  fi
  if [[ -e "$path" || -L "$path" ]]; then
    cp -a --parents -- "$path" "$rollback_dir/rootfs"
  else
    printf '%s\n' "$path" >>"$rollback_dir/absent-before.txt"
  fi
done
printf '%s\n' "$rollback_dir" >"$rollback_root/LAST_ROLLBACK"
touch "$rollback_dir/SNAPSHOT_COMPLETE"
snapshot_complete=1

if (( initialize == 1 )); then
  if [[ -e "$WARP_EGRESS_ENV" || -L "$WARP_EGRESS_ENV" \
    || -e "$WARP_EGRESS_NL_CLIENT_ENV" || -L "$WARP_EGRESS_NL_CLIENT_ENV" \
    || -e "$WARP_EGRESS_RU_BRIDGE_CLIENT_ENV" || -L "$WARP_EGRESS_RU_BRIDGE_CLIENT_ENV" \
    || -e "$WARP_EGRESS_LEGACY_CLIENT_ENV" || -L "$WARP_EGRESS_LEGACY_CLIENT_ENV" ]]; then
    die 'initialize requested but WARP egress credential state already exists'
  fi
  "$bundle_root/scripts/initialize-env.sh" --generate
else
  "$bundle_root/scripts/migrate-env.sh"
fi
load_warp_egress_env
ip link show "$PHYSICAL_IFACE" >/dev/null 2>&1 || die '@TARGET_INTERFACE@ is missing'
ip -4 address show dev "$PHYSICAL_IFACE" | grep -Fq "$NL_PUBLIC_IPV4/" || \
  die 'expected standalone public IPv4 is not assigned to @TARGET_INTERFACE@'

install -d -o root -g root -m 0700 /etc/krysyuk-warp-egress
install -d -o root -g root -m 0755 /etc/netns/krysyuk-warp
install -d -o root -g root -m 0755 \
  /etc/nftables.d /etc/apt/preferences.d /usr/local/libexec/krysyuk-warp-egress \
  /opt/krysyuk-warp-egress/tests
install -d -o root -g root -m 0700 /var/lib/krysyuk-warp-egress
install -o root -g root -m 0644 \
  "$bundle_root/config/xray-warp-egress.template.json" "$WARP_EGRESS_TEMPLATE"
install -o root -g root -m 0644 \
  "$bundle_root/config/ufw-before-forward-v4.rules" \
  "$bundle_root/config/ufw-before-forward-v6.rules" \
  /etc/krysyuk-warp-egress/
rm -f -- /etc/krysyuk-warp-egress/netns-resolv.conf
install -o root -g root -m 0644 "$bundle_root/config/netns-resolv.conf" \
  /etc/netns/krysyuk-warp/resolv.conf
install -o root -g root -m 0644 \
  "$bundle_root/nftables/krysyuk-warp-egress-guard.nft" \
  "$bundle_root/nftables/krysyuk-warp-netns-host.nft" /etc/nftables.d/
install -o root -g root -m 0644 \
  "$bundle_root/config/90-krysyuk-cloudflare-warp.pref" \
  /etc/apt/preferences.d/90-krysyuk-cloudflare-warp
apt-mark hold cloudflare-warp >/dev/null
apt-mark showhold | grep -Fxq cloudflare-warp || \
  die 'could not hold Cloudflare WARP at the audited version'
install -o root -g root -m 0644 "$bundle_root/systemd/"*.service \
  "$bundle_root/systemd/"*.socket /etc/systemd/system/
install -o root -g root -m 0755 \
  "$bundle_root/scripts/common.sh" \
  "$bundle_root/scripts/apply-guard.sh" \
  "$bundle_root/scripts/assert-main-routing.sh" \
  "$bundle_root/scripts/capture-main-routing.sh" \
  "$bundle_root/scripts/configure-warp.sh" \
  "$bundle_root/scripts/configure-ufw.sh" \
  "$bundle_root/scripts/render-config.sh" \
  "$bundle_root/scripts/render-client-env.sh" \
  "$bundle_root/scripts/setup-netns.sh" \
  "$bundle_root/scripts/teardown-netns.sh" \
  "$bundle_root/scripts/warp-emergency-reconnect.sh" \
  "$bundle_root/scripts/warp-health-watchdog.sh" \
  /usr/local/libexec/krysyuk-warp-egress/
install -o root -g root -m 0755 "$bundle_root/scripts/rollback-last.sh" \
  /usr/local/sbin/krysyuk-warp-egress-rollback
install -o root -g root -m 0755 "$bundle_root/tests/"*.sh \
  /opt/krysyuk-warp-egress/tests/

/usr/local/libexec/krysyuk-warp-egress/configure-ufw.sh --apply >/dev/null
/usr/local/libexec/krysyuk-warp-egress/render-client-env.sh >/dev/null
"$bundle_root/tests/test-static-assets.sh"
systemd-analyze verify \
  /etc/systemd/system/krysyuk-warp-netns.service \
  /etc/systemd/system/krysyuk-warp-netns-daemon.service \
  /etc/systemd/system/krysyuk-warp-netns-configure.service \
  /etc/systemd/system/krysyuk-warp-egress-guard.service \
  /etc/systemd/system/krysyuk-xray-warp-egress.service \
  /etc/systemd/system/krysyuk-warp-egress.service \
  /etc/systemd/system/krysyuk-warp-egress.socket \
  /etc/systemd/system/krysyuk-warp-bridge.service \
  /etc/systemd/system/krysyuk-warp-bridge.socket

systemctl disable warp-svc.service >/dev/null 2>&1 || true
if [[ -e /etc/systemd/system/warp-svc.service \
  || -L /etc/systemd/system/warp-svc.service ]]; then
  rm -f -- /etc/systemd/system/warp-svc.service
fi
systemctl mask warp-svc.service
systemctl daemon-reload

for _ in $(seq 1 20); do
  if ! ip link show CloudflareWARP >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
ip link show CloudflareWARP >/dev/null 2>&1 && \
  die 'host CloudflareWARP remained after stopping and masking host warp-svc'
ip -4 route show default | grep -Fq "dev $PHYSICAL_IFACE" || \
  die 'clean main namespace default route does not use @TARGET_INTERFACE@'
ip -4 route get 1.1.1.1 from "$NL_PUBLIC_IPV4" | grep -Fq "dev $PHYSICAL_IFACE" || \
  die 'clean main namespace public-reply route does not use @TARGET_INTERFACE@'

baseline_tmp=$(mktemp /var/lib/krysyuk-warp-egress/main-routing.XXXXXX)
/usr/local/libexec/krysyuk-warp-egress/capture-main-routing.sh >"$baseline_tmp"
install -o root -g root -m 0600 "$baseline_tmp" "$MAIN_ROUTING_BASELINE"
rm -f -- "$baseline_tmp"
boot_tmp=$(mktemp /var/lib/krysyuk-warp-egress/deployed-boot.XXXXXX)
cat /proc/sys/kernel/random/boot_id >"$boot_tmp"
install -o root -g root -m 0600 "$boot_tmp" \
  /var/lib/krysyuk-warp-egress/deployed-boot-id
rm -f -- "$boot_tmp"

for unit in krysyuk-warp-netns.service krysyuk-warp-netns-daemon.service \
  krysyuk-warp-netns-configure.service krysyuk-warp-egress-guard.service \
  krysyuk-xray-warp-egress.service krysyuk-warp-egress.socket \
  krysyuk-warp-bridge.socket; do
  if [[ $unit == *.socket ]]; then
    # Recreate socket enablement links when an upgrade changes their target.
    # sockets.target is too early for sockets ordered after the WARP connector
    # and creates a boot ordering cycle; these listeners belong to multi-user.
    systemctl reenable "$unit"
  else
    systemctl enable "$unit"
  fi
  systemctl start "$unit"
done

/opt/krysyuk-warp-egress/tests/test-smoke.sh
/opt/krysyuk-warp-egress/tests/test-main-route-isolation.sh
/opt/krysyuk-warp-egress/tests/test-e2e-local.sh
/opt/krysyuk-warp-egress/tests/test-invalid.sh
/opt/krysyuk-warp-egress/tests/test-leak-physical.sh

write_warp_phase_marker deploy
touch "$rollback_dir/COMMITTED"
trap - EXIT HUP INT TERM
unset WARP_EGRESS_NL_CLIENT_ID WARP_EGRESS_BRIDGE_CLIENT_ID
printf 'WARP_NETNS_DEPLOY_OK=1 rollback=%s\n' "$rollback_dir"
