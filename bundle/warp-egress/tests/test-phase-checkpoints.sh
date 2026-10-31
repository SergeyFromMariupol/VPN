#!/usr/bin/env bash
# Checkpoint tests touch only a private temporary directory, never live state.
set -Eeuo pipefail
umask 077
[[ $(id -u) -eq 0 ]] || { printf '%s\n' 'ERROR: run checkpoint fixtures as root' >&2; exit 1; }
test_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
mkdir -m 0700 "$stage/phases"
# The sole fixture substitution is the fixed state directory.
sed "s#^readonly WARP_INSTALL_PHASE_DIR=.*#readonly WARP_INSTALL_PHASE_DIR='$stage/phases'#" \
  "$test_dir/../scripts/phase-state.sh" >"$stage/phase-state.sh"
# shellcheck source=../scripts/phase-state.sh
source "$stage/phase-state.sh"

export VPN_WARP_RECORD_PHASES=1
write_warp_phase_marker base
validate_warp_phase_marker base
if write_warp_phase_marker base; then
  printf '%s\n' 'ERROR: existing checkpoint was overwritten' >&2; exit 1
fi
chmod 0644 "$WARP_INSTALL_PHASE_DIR/base.done"
if validate_warp_phase_marker base; then
  printf '%s\n' 'ERROR: public checkpoint accepted' >&2; exit 1
fi
chmod 0600 "$WARP_INSTALL_PHASE_DIR/base.done"
ln "$WARP_INSTALL_PHASE_DIR/base.done" "$stage/extra-link"
if validate_warp_phase_marker base; then
  printf '%s\n' 'ERROR: multiply linked checkpoint accepted' >&2; exit 1
fi
rm -- "$stage/extra-link"
clear_uncommitted_warp_phase_marker
! warp_phase_exists base

ln -s "$stage/nonexistent" "$WARP_INSTALL_PHASE_DIR/deploy.done"
warp_phase_exists deploy
if validate_warp_phase_marker deploy; then
  printf '%s\n' 'ERROR: dangling checkpoint symlink accepted' >&2; exit 1
fi
rm -- "$WARP_INSTALL_PHASE_DIR/deploy.done"
if warp_phase_path ../foreign >/dev/null; then
  printf '%s\n' 'ERROR: checkpoint path escape accepted' >&2; exit 1
fi

write_warp_phase_marker watchdog
mv -- "$WARP_INSTALL_PHASE_DIR/watchdog.done" "$stage/original"
printf '%s\n' v1 >"$WARP_INSTALL_PHASE_DIR/watchdog.done"
chmod 0600 "$WARP_INSTALL_PHASE_DIR/watchdog.done"
if clear_uncommitted_warp_phase_marker; then
  printf '%s\n' 'ERROR: foreign checkpoint inode removed during rollback' >&2; exit 1
fi
validate_warp_phase_marker watchdog
printf '%s\n' 'WARP_PHASE_CHECKPOINT_FIXTURES_OK=1 network=mocked production-state=untouched'
