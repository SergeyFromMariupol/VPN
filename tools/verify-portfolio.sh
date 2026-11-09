#!/usr/bin/env bash
# Verify a selected subscription without the legacy exact-six feed assertion.
set -Eeuo pipefail
umask 077
[[ $EUID == 0 ]] || exit 1
readonly bundle=/var/lib/vpn-installer/bundle
source "$bundle/scripts/target-contract.sh"
[[ $TARGET_PROFILE_SET != basic || $TARGET_EGRESS_MODE != both ]] || exit 1

units=(x-ui nginx germanyvpn-xhttp-test.service)
if [[ $TARGET_EGRESS_MODE != direct ]]; then
  units+=(krysyuk-warp-netns.service krysyuk-warp-netns-daemon.service
    krysyuk-warp-netns-configure.service krysyuk-warp-egress-guard.service
    krysyuk-xray-warp-egress.service krysyuk-warp-egress.socket
    krysyuk-warp-bridge.socket krysyuk-warp-health.timer
    germanyvpn-xhttp-warp.service)
fi
for unit in "${units[@]}"; do
  systemctl is-active --quiet "$unit"
  systemctl is-enabled --quiet "$unit"
done
if [[ $TARGET_EGRESS_MODE == direct ]]; then
  for unit in krysyuk-xray-warp-egress.service krysyuk-warp-netns.service \
    germanyvpn-xhttp-warp.service; do
    ! systemctl is-active --quiet "$unit"
  done
  ! ss -H -lnt | grep -Eq '127[.]0[.]0[.]1:24443[[:space:]]'
fi
if [[ $TARGET_TLS_MODE == letsencrypt ]]; then
  bash "$bundle/base/install-certbot.sh" --check-only
  bash "$bundle/base/install-cert-reconcile.sh" --check-only
  for unit in certbot.timer vpn-cert-reconcile.timer; do
    systemctl is-active --quiet "$unit"
    systemctl is-enabled --quiet "$unit"
  done
  verify_target_certificate "/etc/letsencrypt/live/$TARGET_CERT_NAME/fullchain.pem"
fi
bash "$bundle/base/install-nginx-restart.sh" --check-only
nginx -t >/dev/null 2>&1
[[ $(sqlite3 -readonly /etc/x-ui/x-ui.db 'PRAGMA quick_check;') == ok ]]
[[ $(ps -p "$(systemctl show x-ui -p MainPID --value)" -o user= | xargs) == xui ]]
[[ $(/usr/local/x-ui/x-ui -v 2>&1) == 3.11.0 ]]
printf '%s  %s\n' \
  a27e3f95ab6ce270956d0cecd32eda4686a811afc71c64a6a734a3dede14883e \
  /usr/local/x-ui/bin/xray-linux-amd64 | sha256sum --check --strict - >/dev/null
XRAY_LOCATION_ASSET=/usr/local/x-ui/bin \
  /usr/local/x-ui/bin/xray-linux-amd64 run -test \
  -config /usr/local/x-ui/bin/config.json >/dev/null 2>&1
configs=(/etc/germanyvpn-xhttp-test/config.json)
if [[ $TARGET_EGRESS_MODE != direct ]]; then
  configs+=(/etc/germanyvpn-xhttp-warp/config.json)
fi
for config in "${configs[@]}"; do
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
if [[ $TARGET_EGRESS_MODE == direct ]]; then
  python3 -I -B "$bundle/scripts/finalize-direct-xhttp.py" --verify-selected
else
  for warp_test in test-smoke.sh test-main-route-isolation.sh test-e2e-local.sh test-invalid.sh; do
    bash "/opt/krysyuk-warp-egress/tests/$warp_test" >/dev/null
  done
fi

network_args=(--target-ip "$TARGET_IPV4" --interface "$TARGET_INTERFACE"
  --ssh-port "$TARGET_SSH_PORT" --promoted 1 --tls-mode "$TARGET_TLS_MODE"
  --egress-mode "$TARGET_EGRESS_MODE")
if (( TARGET_EXTRA_PROFILE_COUNT > 0 )); then
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
