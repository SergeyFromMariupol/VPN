#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

script_dir=/usr/local/libexec/krysyuk-warp-egress
# shellcheck source=common.sh
source "$script_dir/common.sh"

require_root
for command_name in flock ip seq sleep systemctl; do
  require_command "$command_name"
done
load_warp_egress_env

exec 8>/run/lock/krysyuk-warp-recovery.lock
flock -w 5 8 || die 'another WARP recovery is already running'
assert_main_routing_unchanged

# A stale MASQUE session can leave warp-cli reporting Connected while payload
# is blackholed.  Re-running setup against an active namespace is both
# insufficient and unsafe, so tear down the isolated stack completely first.
# The public/direct x-ui data plane is independent and remains untouched.
systemctl stop krysyuk-warp-egress.socket krysyuk-warp-bridge.socket \
  krysyuk-warp-egress.service krysyuk-warp-bridge.service \
  krysyuk-xray-warp-egress.service krysyuk-warp-egress-guard.service \
  krysyuk-warp-netns-configure.service krysyuk-warp-netns-daemon.service \
  krysyuk-warp-netns.service >/dev/null 2>&1 || true
/usr/local/libexec/krysyuk-warp-egress/teardown-netns.sh >/dev/null
systemctl reset-failed \
  krysyuk-warp-netns.service krysyuk-warp-netns-daemon.service \
  krysyuk-warp-netns-configure.service krysyuk-warp-egress-guard.service \
  krysyuk-xray-warp-egress.service krysyuk-warp-egress.service \
  krysyuk-warp-bridge.service krysyuk-warp-egress.socket \
  krysyuk-warp-bridge.socket >/dev/null 2>&1 || true

systemctl start krysyuk-warp-netns.service
systemctl start krysyuk-warp-netns-daemon.service

# warp-svc may need a few seconds to restore its persisted registration, DNS,
# and outer MASQUE transport after the namespace is recreated.  A single
# immediate configure attempt races that recovery and can fail even though the
# fail-closed guard is working.  Retry the idempotent oneshot under the guard.
configured=0
for _ in $(seq 1 20); do
  if systemctl restart krysyuk-warp-netns-configure.service >/dev/null 2>&1; then
    configured=1
    break
  fi
  sleep 3
done
((configured == 1)) || die 'isolated WARP configure did not recover'
wait_for_warp 90 || die 'isolated WARP did not become ready after configure'
systemctl start krysyuk-warp-egress-guard.service
systemctl start krysyuk-xray-warp-egress.service

# A socket-proxyd instance may still be alive from before the outage.  systemd
# refuses to restart its socket while that service is active, so quiesce both
# activation pairs, clear any outage result, and then restore the listeners.
systemctl stop krysyuk-warp-egress.socket krysyuk-warp-bridge.socket
systemctl stop krysyuk-warp-egress.service krysyuk-warp-bridge.service
systemctl reset-failed \
  krysyuk-warp-egress.service krysyuk-warp-bridge.service \
  krysyuk-warp-egress.socket krysyuk-warp-bridge.socket
systemctl start krysyuk-warp-egress.socket krysyuk-warp-bridge.socket
assert_main_routing_unchanged
systemctl is-active --quiet krysyuk-warp-egress.socket
systemctl is-active --quiet krysyuk-warp-bridge.socket
printf '%s\n' 'WARP_NETNS_EMERGENCY_RECONNECT_OK=1'
