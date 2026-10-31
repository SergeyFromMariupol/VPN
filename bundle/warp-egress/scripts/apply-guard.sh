#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

readonly guard_file=/etc/nftables.d/krysyuk-warp-egress-guard.nft
readonly table_name=krysyuk_warp_egress_guard
readonly netns_name=krysyuk-warp

[[ $(id -u) -eq 0 ]] || { echo 'ERROR: run as root' >&2; exit 1; }
command -v ip >/dev/null 2>&1 || { echo 'ERROR: ip is missing' >&2; exit 1; }
command -v nft >/dev/null 2>&1 || { echo 'ERROR: nft is missing' >&2; exit 1; }
command -v stat >/dev/null 2>&1 || { echo 'ERROR: stat is missing' >&2; exit 1; }
getent passwd xraywarp >/dev/null || { echo 'ERROR: xraywarp is missing' >&2; exit 1; }
ip netns list | awk '{print $1}' | grep -Fx "$netns_name" >/dev/null || {
  echo 'ERROR: WARP network namespace is missing' >&2
  exit 1
}
[[ -f "$guard_file" && ! -L "$guard_file" ]] || {
  echo 'ERROR: guard ruleset is missing or unsafe' >&2
  exit 1
}

target_ns_path="/run/netns/${netns_name}"
[[ -e "$target_ns_path" ]] || { echo 'ERROR: WARP netns handle is missing' >&2; exit 1; }
current_ns=$(stat -Lc '%d:%i' /proc/self/ns/net)
target_ns=$(stat -Lc '%d:%i' "$target_ns_path")
if [[ "$current_ns" == "$target_ns" ]]; then
  netns_nft() { nft "$@"; }
else
  netns_nft() { ip netns exec "$netns_name" nft "$@"; }
fi

backup=$(mktemp)
candidate=$(mktemp)
transaction=$(mktemp)
had_previous=0
cleanup() {
  rm -f -- "$backup" "$candidate" "$transaction"
}
trap cleanup EXIT

if netns_nft -s list table inet "$table_name" >"$backup" 2>/dev/null; then
  had_previous=1
fi
validation_table="${table_name}_check_$$"
sed "s/table inet ${table_name}/table inet ${validation_table}/" \
  "$guard_file" >"$candidate"
netns_nft -c -f "$candidate"

if (( had_previous == 1 )); then
  printf 'delete table inet %s\n' "$table_name" >"$transaction"
fi
cat "$guard_file" >>"$transaction"
if ! netns_nft -f "$transaction"; then
  if ! netns_nft list table inet "$table_name" \
    >/dev/null 2>&1 && (( had_previous == 1 )); then
    netns_nft -f "$backup" || true
  fi
  echo 'ERROR: failed to atomically apply the netns owner guard' >&2
  exit 1
fi

netns_nft list chain inet "$table_name" output >/dev/null
printf '%s\n' 'WARP_EGRESS_NETNS_GUARD_APPLIED=1'
