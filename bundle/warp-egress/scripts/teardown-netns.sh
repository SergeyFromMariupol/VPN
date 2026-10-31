#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

[[ $(id -u) -eq 0 ]] || { echo 'ERROR: run as root' >&2; exit 1; }

nft delete table inet krysyuk_warp_netns_host_guard >/dev/null 2>&1 || true
nft delete table ip krysyuk_warp_netns_nat >/dev/null 2>&1 || true
ip link delete kw-host >/dev/null 2>&1 || true
ip netns delete krysyuk-warp >/dev/null 2>&1 || true
printf '%s\n' 'WARP_NETNS_REMOVED=1'
