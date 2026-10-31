#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
[[ $EUID == 0 ]] || exit 1
readonly bundle='/var/lib/vpn-installer/bundle'
bash "$bundle/base/install-certbot.sh" --check-only
bash "$bundle/base/install-cert-reconcile.sh" --check-only
for unit in x-ui nginx certbot.timer vpn-cert-reconcile.timer krysyuk-warp-netns.service \
  krysyuk-warp-netns-daemon.service krysyuk-warp-netns-configure.service \
  krysyuk-warp-egress-guard.service krysyuk-xray-warp-egress.service \
  krysyuk-warp-egress.socket krysyuk-warp-bridge.socket krysyuk-warp-health.timer; do
  systemctl is-active --quiet "$unit"
  systemctl is-enabled --quiet "$unit"
done
[[ $(sqlite3 -readonly /etc/x-ui/x-ui.db 'PRAGMA quick_check;') == ok ]]
[[ $(ps -p "$(systemctl show x-ui -p MainPID --value)" -o user= | xargs) == xui ]]
nginx -t >/dev/null 2>&1
source "$bundle/scripts/target-contract.sh"
if [[ $TARGET_ADDRESS_MODE == domain ]]; then
  for resolver in 1.1.1.1 9.9.9.9; do
    [[ $(dig +short "@$resolver" "$TARGET_FQDN" A) == "$TARGET_IPV4" ]]
    [[ -z $(dig +short "@$resolver" "$TARGET_FQDN" AAAA) ]]
  done
fi
openssl x509 -in "/etc/letsencrypt/live/$TARGET_FQDN/fullchain.pem" -noout -checkend 86400 >/dev/null
current_boot=$(cat /proc/sys/kernel/random/boot_id)
if [[ $current_boot != "$(cat /var/lib/vpn-installer/install-boot-id)" ]]; then
  bash "$bundle/tests/postboot-verify.sh"
  printf 'REBOOT_OBSERVED=YES\n'
else
  bash "$bundle/tests/postboot-verify.sh" --live
  printf 'REBOOT_ACCEPTANCE=PENDING (run --verify after reboot)\n'
fi
if [[ $(sshd -T | awk '$1=="passwordauthentication" {print $2}') != no ]]; then
  printf 'SSH_HARDENING=PENDING (current working SSH access preserved)\n'
fi
printf 'SERVER_CHECKS=PASS CLIENT_IMPORT_AND_SPEED=PENDING\n'
