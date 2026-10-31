#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
readonly script_dir
# shellcheck source=common.sh
source "$script_dir/common.sh"

require_root
require_command cmp
require_command ip
load_warp_egress_env
assert_main_routing_unchanged
printf '%s\n' 'WARP_MAIN_ROUTING_UNCHANGED=1'
