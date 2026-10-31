#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

readonly lib=/usr/local/libexec/krysyuk-warp-egress/common.sh
# shellcheck source=../scripts/common.sh
source "$lib"

require_root
for command_name in grep stat systemctl; do
  require_command "$command_name"
done

readonly state_dir=/var/lib/krysyuk-warp-health
readonly script=/usr/local/libexec/krysyuk-warp-egress/warp-health-watchdog.sh

[[ -x "$script" && ! -L "$script" ]] || die 'installed WARP health watchdog is missing or unsafe'
[[ $(stat -c '%U:%G %a' "$script") == 'root:root 755' ]] || \
  die 'installed WARP health watchdog ownership/mode is wrong'
grep -Fq 'https://cp.cloudflare.com/generate_204' "$script" || \
  die 'Cloudflare health observer is missing'
grep -Fq 'https://www.gstatic.com/generate_204' "$script" || \
  die 'non-Cloudflare health observer is missing'
grep -Fq 'https://www.google.com/generate_204' "$script" || \
  die 'fallback Google health observer is missing'
systemctl is-enabled --quiet krysyuk-warp-health.timer
systemctl is-active --quiet krysyuk-warp-health.timer
systemctl start krysyuk-warp-health.service
[[ -f "$state_dir/failure-streak" && ! -L "$state_dir/failure-streak" ]] || \
  die 'health failure-streak state is missing or unsafe'
[[ $(<"$state_dir/failure-streak") == 0 ]] || \
  die 'live WARP payload health probe did not reset the failure streak'
[[ -f "$state_dir/last-success-epoch" && ! -L "$state_dir/last-success-epoch" ]] || \
  die 'health success marker is missing or unsafe'
grep -Eq '^[0-9]+$' "$state_dir/last-success-epoch" || \
  die 'health success marker is malformed'
assert_main_routing_unchanged
printf '%s\n' 'WARP_HEALTH_WATCHDOG_OK=1 interval=15s threshold=3 cooldown=120s'
