#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

[[ $(id -u) -eq 0 ]] || { echo 'ERROR: run as root' >&2; exit 1; }
for command_name in apt-mark cp find grep ip nft readlink rm sort sysctl systemctl ufw wc; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'ERROR: required rollback command is missing: %s\n' "$command_name" >&2
    exit 1
  }
done

readonly rollback_root=/var/lib/krysyuk-warp-egress/rollback
rollback_dir=${1:-}
if [[ -z "$rollback_dir" ]]; then
  [[ -f "$rollback_root/LAST_ROLLBACK" && ! -L "$rollback_root/LAST_ROLLBACK" ]] || {
    echo 'ERROR: LAST_ROLLBACK is missing or unsafe' >&2
    exit 1
  }
  rollback_dir=$(<"$rollback_root/LAST_ROLLBACK")
fi
resolved_root=$(readlink -f -- "$rollback_root")
resolved_dir=$(readlink -f -- "$rollback_dir")
case "$resolved_dir" in
  "$resolved_root"/*) ;;
  *) echo 'ERROR: rollback path is outside the allowed root' >&2; exit 1 ;;
esac
[[ -d "$resolved_dir/rootfs" && ! -L "$resolved_dir/rootfs" \
  && -f "$resolved_dir/SNAPSHOT_COMPLETE" \
  && ! -L "$resolved_dir/SNAPSHOT_COMPLETE" ]] || {
  echo 'ERROR: complete rollback snapshot is missing or unsafe' >&2
  exit 1
}

readonly units=(
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
readonly managed_paths=(
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

is_managed_path() {
  local candidate="$1" managed
  for managed in "${managed_paths[@]}"; do
    [[ "$candidate" == "$managed" ]] && return 0
  done
  return 1
}

require_snapshot_file() {
  local path="$1" label="$2"
  [[ -f "$path" && ! -L "$path" ]] || {
    printf 'ERROR: %s snapshot is missing or unsafe\n' "$label" >&2
    exit 1
  }
}

declare -A absent_before=()
if [[ -e "$resolved_dir/absent-before.txt" || -L "$resolved_dir/absent-before.txt" ]]; then
  require_snapshot_file "$resolved_dir/absent-before.txt" 'absent-path list'
  while IFS= read -r path; do
    [[ -n "$path" ]] || { echo 'ERROR: empty rollback target' >&2; exit 1; }
    is_managed_path "$path" || { echo 'ERROR: unexpected rollback target' >&2; exit 1; }
    [[ -z ${absent_before[$path]+x} ]] || {
      echo 'ERROR: duplicate absent rollback target' >&2
      exit 1
    }
    absent_before[$path]=1
  done <"$resolved_dir/absent-before.txt"
fi
for path in "${managed_paths[@]}"; do
  if [[ -z ${absent_before[$path]+x} ]]; then
    [[ -e "$resolved_dir/rootfs$path" || -L "$resolved_dir/rootfs$path" ]] || {
      printf 'ERROR: rollback snapshot is incomplete for %s\n' "$path" >&2
      exit 1
    }
  fi
done

declare -A ufw_absent_before=()
if [[ -e "$resolved_dir/ufw-absent-before.txt" \
  || -L "$resolved_dir/ufw-absent-before.txt" ]]; then
  require_snapshot_file "$resolved_dir/ufw-absent-before.txt" 'UFW absent-path list'
  while IFS= read -r path; do
    case "$path" in
      /etc/ufw/user.rules|/etc/ufw/user6.rules|/etc/ufw/before.rules|/etc/ufw/before6.rules) ;;
      *) echo 'ERROR: unexpected UFW rollback target' >&2; exit 1 ;;
    esac
    [[ -z ${ufw_absent_before[$path]+x} ]] || {
      echo 'ERROR: duplicate UFW rollback target' >&2
      exit 1
    }
    ufw_absent_before[$path]=1
  done <"$resolved_dir/ufw-absent-before.txt"
fi
for path in /etc/ufw/user.rules /etc/ufw/user6.rules \
  /etc/ufw/before.rules /etc/ufw/before6.rules; do
  if [[ -z ${ufw_absent_before[$path]+x} ]]; then
    [[ -f "$resolved_dir/rootfs$path" && ! -L "$resolved_dir/rootfs$path" ]] || {
      printf 'ERROR: UFW rollback snapshot is incomplete for %s\n' "$path" >&2
      exit 1
    }
  fi
done

for metadata in ip-forward.state ufw.state host-guard-table.state host-nat-table.state \
  warp-apt-hold.state; do
  require_snapshot_file "$resolved_dir/$metadata" "$metadata"
done
warp_apt_hold_state=$(<"$resolved_dir/warp-apt-hold.state")
[[ "$warp_apt_hold_state" == held || "$warp_apt_hold_state" == unheld ]] || {
  echo 'ERROR: invalid Cloudflare WARP apt hold snapshot' >&2
  exit 1
}
ip_forward=$(<"$resolved_dir/ip-forward.state")
[[ "$ip_forward" =~ ^[01]$ ]] || { echo 'ERROR: invalid ip_forward snapshot' >&2; exit 1; }
ufw_state=$(<"$resolved_dir/ufw.state")
[[ "$ufw_state" == active || "$ufw_state" == inactive ]] || {
  echo 'ERROR: invalid UFW state snapshot' >&2
  exit 1
}
for kind in guard nat; do
  state=$(<"$resolved_dir/host-${kind}-table.state")
  [[ "$state" == present || "$state" == absent ]] || {
    printf 'ERROR: invalid host %s nft snapshot state\n' "$kind" >&2
    exit 1
  }
  if [[ "$state" == present ]]; then
    require_snapshot_file "$resolved_dir/host-${kind}-table.nft" "host ${kind} nft rules"
  fi
done

for unit in "${units[@]}"; do
  state_file="$resolved_dir/service-${unit}.state"
  require_snapshot_file "$state_file" "$unit service state"
  [[ $(wc -l <"$state_file") -eq 3 ]] || {
    printf 'ERROR: malformed service snapshot for %s\n' "$unit" >&2
    exit 1
  }
  grep -Eq '^present=[01]$' "$state_file" \
    && grep -Eq '^active=[01]$' "$state_file" \
    && grep -Eq '^enable_state=(masked|masked-runtime|enabled|enabled-runtime|linked|linked-runtime|alias|disabled|indirect|static|generated|transient|not-found)$' "$state_file" || {
      printf 'ERROR: invalid service snapshot for %s\n' "$unit" >&2
      exit 1
    }
  # Safe after the strict three-line grammar check above.
  # shellcheck disable=SC1090
  source "$state_file"
  (( present == 1 || active == 0 )) || {
    printf 'ERROR: absent service was recorded active for %s\n' "$unit" >&2
    exit 1
  }
done

# All snapshot targets and metadata are proven safe before the first mutation.
systemctl stop krysyuk-warp-egress.socket krysyuk-warp-egress.service \
  krysyuk-warp-bridge.socket krysyuk-warp-bridge.service \
  krysyuk-xray-warp-egress.service krysyuk-warp-egress-guard.service \
  krysyuk-warp-netns-configure.service krysyuk-warp-netns-daemon.service \
  krysyuk-warp-netns.service >/dev/null 2>&1 || true
systemctl stop warp-svc.service >/dev/null 2>&1 || true
nft delete table inet krysyuk_warp_netns_host_guard >/dev/null 2>&1 || true
nft delete table ip krysyuk_warp_netns_nat >/dev/null 2>&1 || true
ip link delete kw-host >/dev/null 2>&1 || true
ip netns delete krysyuk-warp >/dev/null 2>&1 || true
rm -rf -- /run/krysyuk-warp-egress /run/krysyuk-warp-egress-warp

for path in "${managed_paths[@]}"; do
  rm -rf -- "$path"
done
for path in /etc/ufw/user.rules /etc/ufw/user6.rules \
  /etc/ufw/before.rules /etc/ufw/before6.rules; do
  if [[ -n ${ufw_absent_before[$path]+x} ]]; then
    rm -f -- "$path"
  fi
done
# Restore each captured top-level entry separately. Copying `rootfs/.` onto `/`
# would also apply the private rollback directory's 0700 mode to the host root
# directory, breaking every non-root service after an otherwise successful
# rollback.
mapfile -d '' restore_roots < <(
  find "$resolved_dir/rootfs" -mindepth 1 -maxdepth 1 -print0 | sort -z
)
(( ${#restore_roots[@]} > 0 )) || {
  echo 'ERROR: rollback rootfs has no top-level entries' >&2
  exit 1
}
for restore_root in "${restore_roots[@]}"; do
  cp -a -- "$restore_root" /
done

if [[ "$warp_apt_hold_state" == held ]]; then
  apt-mark hold cloudflare-warp >/dev/null
else
  apt-mark unhold cloudflare-warp >/dev/null
fi
if [[ "$warp_apt_hold_state" == held ]]; then
  apt-mark showhold | grep -Fxq cloudflare-warp || {
    echo 'ERROR: could not restore Cloudflare WARP apt hold' >&2
    exit 1
  }
elif apt-mark showhold | grep -Fxq cloudflare-warp; then
  echo 'ERROR: could not restore Cloudflare WARP unheld state' >&2
  exit 1
fi

sysctl -q -w "net.ipv4.ip_forward=$ip_forward"
nft delete table inet krysyuk_warp_netns_host_guard >/dev/null 2>&1 || true
nft delete table ip krysyuk_warp_netns_nat >/dev/null 2>&1 || true
if [[ "$ufw_state" == active ]]; then
  ufw reload >/dev/null
fi
restore_nft_table() {
  local state_file="$1" rules_file="$2" state
  state=$(<"$state_file")
  if [[ "$state" == present ]]; then
    nft -f "$rules_file"
  fi
}
restore_nft_table "$resolved_dir/host-guard-table.state" \
  "$resolved_dir/host-guard-table.nft"
restore_nft_table "$resolved_dir/host-nat-table.state" \
  "$resolved_dir/host-nat-table.nft"

systemctl daemon-reload
restore_enable_state() {
  local unit="$1" state_file="$2" present active enable_state
  # shellcheck disable=SC1090
  source "$state_file"
  case "$enable_state" in
    masked) systemctl mask "$unit" >/dev/null ;;
    masked-runtime) systemctl mask --runtime "$unit" >/dev/null ;;
    enabled|linked|alias)
      systemctl unmask "$unit" >/dev/null 2>&1 || true
      systemctl enable "$unit" >/dev/null
      ;;
    enabled-runtime|linked-runtime)
      systemctl unmask "$unit" >/dev/null 2>&1 || true
      systemctl enable --runtime "$unit" >/dev/null
      ;;
    disabled|indirect|static|generated|transient|not-found)
      systemctl unmask "$unit" >/dev/null 2>&1 || true
      systemctl disable "$unit" >/dev/null 2>&1 || true
      ;;
  esac
}
for unit in "${units[@]}"; do
  restore_enable_state "$unit" "$resolved_dir/service-${unit}.state"
done
for unit in "${units[@]}"; do
  # shellcheck disable=SC1090
  source "$resolved_dir/service-${unit}.state"
  if (( present == 1 && active == 1 )); then
    systemctl start "$unit"
  fi
done
systemctl reset-failed "${units[@]}" >/dev/null 2>&1 || true

printf '%s\n' 'WARP_NETNS_FILE_STATE_NETWORK_ROLLBACK_OK=1'
