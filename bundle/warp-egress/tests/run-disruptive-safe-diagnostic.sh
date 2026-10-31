#!/usr/bin/env bash
set -Eeuo pipefail

[[ $# -eq 1 ]] || exit 2
case $1 in
  test-fail-closed.sh|test-guard-loss.sh|test-host-guard-loss.sh) ;;
  *) exit 2 ;;
esac

safe_err() {
  local rc=$?
  printf 'SAFE_DISRUPTIVE_FAILURE_FILE=%s LINE=%s RC=%s\n' \
    "${BASH_SOURCE[1]##*/}" "${BASH_LINENO[0]}" "$rc" >&2
  return "$rc"
}
trap safe_err ERR
export I_UNDERSTAND_DISRUPTIVE=YES
# Sourcing preserves the line-only ERR trap while the selected test keeps its
# own automatic recovery EXIT trap. No command text or secret value is logged.
# shellcheck disable=SC1090
source "/opt/krysyuk-warp-egress/tests/$1"
