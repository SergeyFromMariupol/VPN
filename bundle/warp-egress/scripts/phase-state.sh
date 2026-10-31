#!/usr/bin/env bash
# Root-private checkpoints for the three independently committed WARP phases.
# shellcheck disable=SC2034 # Functions and state form the sourced phase API.

readonly WARP_INSTALL_PHASE_DIR=/var/lib/vpn-installer/warp
WARP_PHASE_MARKER_CREATED=''
WARP_PHASE_MARKER_IDENTITY=''

assert_warp_phase_directory() {
  [[ -d "$WARP_INSTALL_PHASE_DIR" && ! -L "$WARP_INSTALL_PHASE_DIR" ]] || {
    printf '%s\n' 'ERROR: unsafe WARP install checkpoint directory' >&2; return 1;
  }
  [[ $(stat -c '%u:%a' "$WARP_INSTALL_PHASE_DIR") == 0:700 ]] || return 1
}

warp_phase_path() {
  case "$1" in base|deploy|watchdog) ;; *) return 1 ;; esac
  printf '%s/%s.done\n' "$WARP_INSTALL_PHASE_DIR" "$1"
}

warp_phase_exists() {
  local path
  path=$(warp_phase_path "$1") || return 1
  [[ -e "$path" || -L "$path" ]]
}

validate_warp_phase_marker() {
  local path
  path=$(warp_phase_path "$1") || return 1
  assert_warp_phase_directory || return 1
  [[ -f "$path" && ! -L "$path" ]] || return 1
  [[ $(stat -c '%u:%a:%h' "$path") == 0:600:1 ]] || return 1
  [[ $(<"$path") == v1 ]] || return 1
}

write_warp_phase_marker() {
  [[ ${VPN_WARP_RECORD_PHASES:-0} == 1 ]] || return 0
  local path temporary identity
  path=$(warp_phase_path "$1") || return 1
  assert_warp_phase_directory || return 1
  [[ ! -e "$path" && ! -L "$path" ]] || return 1
  temporary=$(mktemp "$WARP_INSTALL_PHASE_DIR/.phase.XXXXXX") || return 1
  if ! printf '%s\n' v1 >"$temporary" || ! chmod 0600 "$temporary"; then
    rm -f -- "$temporary"
    return 1
  fi
  identity=$(stat -c '%d:%i:%h' "$temporary") || { rm -f -- "$temporary"; return 1; }
  if ! mv -T -- "$temporary" "$path"; then
    rm -f -- "$temporary"
    return 1
  fi
  WARP_PHASE_MARKER_CREATED=$path
  WARP_PHASE_MARKER_IDENTITY=$identity
}

clear_uncommitted_warp_phase_marker() {
  local phase path
  [[ -n ${WARP_PHASE_MARKER_CREATED:-} ]] || return 0
  for phase in base deploy watchdog; do
    path=$(warp_phase_path "$phase") || return 1
    if [[ "$path" == "$WARP_PHASE_MARKER_CREATED" ]]; then
      validate_warp_phase_marker "$phase" || return 1
      [[ $(stat -c '%d:%i:%h' "$path") == "$WARP_PHASE_MARKER_IDENTITY" ]] || return 1
      rm -f -- "$path"
      WARP_PHASE_MARKER_CREATED=''
      WARP_PHASE_MARKER_IDENTITY=''
      return 0
    fi
  done
  return 1
}
