#!/usr/bin/env bash
# Verify a selected subscription without the legacy exact-six feed assertion.
set -Eeuo pipefail
umask 077
[[ $EUID == 0 ]] || exit 1
readonly bundle=/var/lib/vpn-installer/bundle
source "$bundle/scripts/target-contract.sh"
[[ $TARGET_PROFILE_SET != basic || $TARGET_EGRESS_MODE != both ]] || exit 1

for unit in x-ui nginx krysyuk-warp-netns.service \
  krysyuk-warp-netns-daemon.service krysyuk-warp-netns-configure.service \
  krysyuk-warp-egress-guard.service krysyuk-xray-warp-egress.service \
  krysyuk-warp-egress.socket krysyuk-warp-bridge.socket krysyuk-warp-health.timer \
  germanyvpn-xhttp-test.service germanyvpn-xhttp-warp.service; do
  systemctl is-active --quiet "$unit"
  systemctl is-enabled --quiet "$unit"
done
if [[ $TARGET_TLS_MODE == letsencrypt ]]; then
  bash "$bundle/base/install-certbot.sh" --check-only
  bash "$bundle/base/install-cert-reconcile.sh" --check-only
  for unit in certbot.timer vpn-cert-reconcile.timer; do
    systemctl is-active --quiet "$unit"
    systemctl is-enabled --quiet "$unit"
  done
  verify_target_certificate "/etc/letsencrypt/live/$TARGET_FQDN/fullchain.pem"
fi
bash "$bundle/base/install-nginx-restart.sh" --check-only
nginx -t >/dev/null 2>&1
[[ $(sqlite3 -readonly /etc/x-ui/x-ui.db 'PRAGMA quick_check;') == ok ]]
[[ $(ps -p "$(systemctl show x-ui -p MainPID --value)" -o user= | xargs) == xui ]]
[[ $(/usr/local/x-ui/x-ui -v 2>&1) == 3.7.0 ]]
printf '%s  %s\n' \
  64d46afb80adea1bf97a0d467e83f4a9ac1ebd0995891e84bca3f1a1d1affb1d \
  /usr/local/x-ui/bin/xray-linux-amd64 | sha256sum --check --strict - >/dev/null
XRAY_LOCATION_ASSET=/usr/local/x-ui/bin \
  /usr/local/x-ui/bin/xray-linux-amd64 run -test \
  -config /usr/local/x-ui/bin/config.json >/dev/null 2>&1
for config in /etc/germanyvpn-xhttp-test/config.json /etc/germanyvpn-xhttp-warp/config.json; do
  XRAY_LOCATION_ASSET=/usr/local/lib/germanyvpn-xhttp-test \
    /usr/local/lib/germanyvpn-xhttp-test/xray run -test -config "$config" >/dev/null 2>&1
done
if [[ $TARGET_ADDRESS_MODE == domain ]]; then
  for resolver in 1.1.1.1 9.9.9.9; do
    [[ $(dig +short "@$resolver" "$TARGET_FQDN" A) == "$TARGET_IPV4" ]]
    [[ -z $(dig +short "@$resolver" "$TARGET_FQDN" AAAA) ]]
  done
fi
bash "$bundle/tests/panel-login-acceptance.sh" >/dev/null
for warp_test in test-smoke.sh test-main-route-isolation.sh test-e2e-local.sh test-invalid.sh; do
  bash "/opt/krysyuk-warp-egress/tests/$warp_test" >/dev/null
done

network_args=(--target-ip "$TARGET_IPV4" --interface "$TARGET_INTERFACE"
  --ssh-port "$TARGET_SSH_PORT" --promoted 1 --tls-mode "$TARGET_TLS_MODE")
if [[ $TARGET_PROFILE_SET != basic ]]; then
  systemctl is-active --quiet germanyvpn-portfolio.service
  systemctl is-enabled --quiet germanyvpn-portfolio.service
  python3 -I -B "$bundle/portfolio/install.py" --verify
  network_args+=(--portfolio-state /etc/germanyvpn-portfolio/state.json)
fi
python3 "$bundle/scripts/network-contract.py" "${network_args[@]}"
python3 -I -B /opt/vpn-installer/tools/portfolio_publish.py --verify

current_boot=$(cat /proc/sys/kernel/random/boot_id)
if [[ $current_boot == "$(cat /var/lib/vpn-installer/install-boot-id)" ]]; then
  printf 'REBOOT_ACCEPTANCE=PENDING (run --verify after reboot)\n'
else
  printf 'REBOOT_OBSERVED=YES\n'
fi
if [[ $(sshd -T | awk '$1=="passwordauthentication" {print $2}') != no ]]; then
  printf 'SSH_HARDENING=PENDING (current working SSH access preserved)\n'
fi
printf 'SERVER_CHECKS=PASS PROFILE_COUNT=%s CLIENT_IMPORT=PENDING\n' \
  "$TARGET_SELECTED_PROFILE_COUNT"
