#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

test_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=../scripts/bootstrap-transaction.sh
source "$test_dir/../scripts/bootstrap-transaction.sh"
BT_SNAPSHOT=$(mktemp -d)
trap 'rm -rf -- "$BT_SNAPSHOT"' EXIT
printf 'systemd\t255.4\tii \nlibc6:amd64\t2.39\tii \n' >"$BT_SNAPSHOT/packages-before.tsv"
printf '%s\n' 'Inst shellcheck (0.9.0 Ubuntu:24.04/noble [amd64])' >"$BT_SNAPSHOT/plan"
bootstrap_validate_plan "$BT_SNAPSHOT/plan" "$BT_SNAPSHOT/additions"
[[ $(<"$BT_SNAPSHOT/additions") == shellcheck ]] || { echo 'ERROR: safe new package was rejected' >&2; exit 1; }

for unsafe in \
  'Inst systemd [255.4] (255.5 Ubuntu:24.04/noble [amd64])' \
  'Inst libc6 (2.40 Ubuntu:24.04/noble [amd64])' \
  'Remv systemd [255.4]' \
  'Inst malformed'; do
  printf '%s\n' "$unsafe" >"$BT_SNAPSHOT/plan"
  if bootstrap_validate_plan "$BT_SNAPSHOT/plan" "$BT_SNAPSHOT/additions" >/dev/null 2>&1; then
    echo 'ERROR: unsafe bootstrap APT plan was accepted' >&2
    exit 1
  fi
done
printf '%s\n' 'WARP_BOOTSTRAP_APT_PLAN_SAFETY_OK=1 cases=5 network=mocked packages=untouched'
