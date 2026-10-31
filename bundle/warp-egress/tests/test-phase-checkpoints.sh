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

# A successful publication can be interrupted before write_warp_phase_marker
# returns. The exact production function must already have armed rollback.
mkdir -m 0700 "$stage/signal-phases"
sed "s#^readonly WARP_INSTALL_PHASE_DIR=.*#readonly WARP_INSTALL_PHASE_DIR='$stage/signal-phases'#" \
  "$test_dir/../scripts/phase-state.sh" >"$stage/signal-phase-state.sh"
set +e
PHASE_FIXTURE_LIBRARY="$stage/signal-phase-state.sh" bash -c '
  set -Eeuo pipefail
  umask 077
  source "$PHASE_FIXTURE_LIBRARY"
  export VPN_WARP_RECORD_PHASES=1
  cleanup() {
    rc=$?; trap - EXIT TERM
    clear_uncommitted_warp_phase_marker || exit 99
    exit "$rc"
  }
  trap cleanup EXIT
  trap "exit 143" TERM
  mv() { command mv "$@"; kill -TERM "$BASHPID"; }
  write_warp_phase_marker base
' >"$stage/signal.log" 2>&1
rc=$?
set -e
[[ $rc == 143 && ! -e $stage/signal-phases/base.done ]] || {
  printf '%s\n' 'ERROR: interrupted publication left an unowned-looking checkpoint' >&2
  exit 1
}

# mv --no-clobber can return success without moving. A foreign marker created
# after the initial absence check must survive and must not be accepted.
mkdir -m 0700 "$stage/race-phases"
sed "s#^readonly WARP_INSTALL_PHASE_DIR=.*#readonly WARP_INSTALL_PHASE_DIR='$stage/race-phases'#" \
  "$test_dir/../scripts/phase-state.sh" >"$stage/race-phase-state.sh"
PHASE_FIXTURE_LIBRARY="$stage/race-phase-state.sh" bash -c '
  set -Eeuo pipefail
  umask 077
  source "$PHASE_FIXTURE_LIBRARY"
  export VPN_WARP_RECORD_PHASES=1
  mv() {
    destination=${@: -1}
    printf "v1\n" >"$destination"
    chmod 0600 "$destination"
    command mv "$@"
  }
  if write_warp_phase_marker base; then exit 97; fi
  if clear_uncommitted_warp_phase_marker; then exit 98; fi
  validate_warp_phase_marker base
' >"$stage/race.log" 2>&1 || {
  printf '%s\n' 'ERROR: concurrent foreign checkpoint was replaced or accepted' >&2
  exit 1
}
printf '%s\n' 'WARP_PHASE_CHECKPOINT_FIXTURES_OK=1 network=mocked production-state=untouched'
