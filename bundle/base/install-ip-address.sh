#!/usr/bin/env bash
# Install the IP-mode services only after the normal public verifier passes.
set -Eeuo pipefail
umask 077
source_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
source "$source_root/scripts/target-contract.sh"
[[ $EUID == 0 && $TARGET_ADDRESS_MODE == ip && $TARGET_TLS_MODE == letsencrypt ]] || exit 1
root=/etc/vpn-ip-addresses
library=/usr/local/lib/vpn-ip-feed
units=(vpn-ip-aliases.service vpn-ip-feed.service vpn-ip-address.service vpn-ip-address.timer)

owned_copy() {
  local source=$1 destination=$2 mode=$3
  if [[ -e $destination || -L $destination ]]; then
    [[ -f $destination && ! -L $destination &&
       $(stat -c '%u:%g:%a:%h' "$destination") == "0:0:${mode#0}:1" ]]
    cmp -s "$source" "$destination"
  else
    install -o root -g root -m "$mode" -- "$source" "$destination"
  fi
}

for directory in "$root" "$library"; do
  if [[ ! -e $directory && ! -L $directory ]]; then mkdir -m 0755 -- "$directory"; fi
  [[ -d $directory && ! -L $directory && $(stat -c '%u:%g:%a' "$directory") == 0:0:755 ]]
done
for name in ip_feed.py ip_runtime.py; do
  owned_copy "$source_root/base/$name" "$library/$name" 0644
done
for name in "${units[@]}"; do
  owned_copy "$source_root/templates/$name" "/etc/systemd/system/$name" 0644
done
stage=$(mktemp -d -p /run vpn-ip-units.XXXXXXXX)
trap 'rm -f -- "$stage/aliases.nft" "$stage/proxy.json" "$stage/renew.conf"; rmdir -- "$stage"' EXIT
printf 'destroy table ip vpn_ip_aliases\ntable ip vpn_ip_aliases {}\n' >"$stage/aliases.nft"
printf '{"primary":"%s","addresses":["%s"]}\n' "$TARGET_IPV4" "$TARGET_IPV4" >"$stage/proxy.json"
printf '[Service]\nExecStart=\nExecStart=/opt/vpn-certbot/bin/certbot -q renew --cert-name %s\n' \
  "$TARGET_CERT_NAME" >"$stage/renew.conf"
owned_copy "$stage/aliases.nft" "$root/aliases.nft" 0600
owned_copy "$stage/proxy.json" "$root/proxy.json" 0644
owned_copy "$stage/renew.conf" /etc/systemd/system/certbot.service.d/30-vpn-active-ip.conf 0644
nft -c -f "$root/aliases.nft"
systemctl daemon-reload
systemctl enable --now vpn-ip-feed.service vpn-ip-aliases.service vpn-ip-address.timer
