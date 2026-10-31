#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

readonly lib=/usr/local/libexec/krysyuk-warp-egress/common.sh
# shellcheck source=../scripts/common.sh
source "$lib"

require_root
readonly deployed_boot_file=/var/lib/krysyuk-warp-egress/deployed-boot-id
require_private_root_file "$deployed_boot_file" 'deployment boot ID'
deployed_boot=$(<"$deployed_boot_file")
current_boot=$(</proc/sys/kernel/random/boot_id)
[[ "$deployed_boot" =~ ^[0-9a-f-]{36}$ ]] || die 'stored deployment boot ID is malformed'
[[ "$current_boot" =~ ^[0-9a-f-]{36}$ ]] || die 'current boot ID is malformed'
[[ "$current_boot" != "$deployed_boot" ]] || \
  die 'real reboot proof required: this is still the deployment boot'

/opt/krysyuk-warp-egress/tests/test-smoke.sh
/opt/krysyuk-warp-egress/tests/test-main-route-isolation.sh
/opt/krysyuk-warp-egress/tests/test-e2e-local.sh
/opt/krysyuk-warp-egress/tests/test-invalid.sh
/opt/krysyuk-warp-egress/tests/test-leak-physical.sh
printf 'WARP_EGRESS_REBOOT_PERSISTENCE_OK=1 deployed_boot=%s verified_boot=%s\n' \
  "$deployed_boot" "$current_boot"
