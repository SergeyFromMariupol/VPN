#!/usr/bin/env bash
# Each foreground worker includes the command outcome and its checkpoint.
# A child that returned success is checkpointed before a parent signal exits.

installer_checkpoint_valid() {
  local path=$1 value normalized
  [[ -f $path && ! -L $path && $(stat -c '%u:%g:%a:%h' "$path") == 0:0:600:1 ]] || return 1
  [[ $(wc -c <"$path") == 21 ]] || return 1
  value=$(<"$path")
  [[ $value =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || return 1
  normalized=$(date -u -d "$value" +%FT%TZ 2>/dev/null) || return 1
  [[ $normalized == "$value" ]]
}

phase() (
  umask 077
  local always=0 name checkpoint marker_before='' temporary='' temporary_identity=''
  local signal_status=0 command_status
  if [[ ${1:-} == --always ]]; then always=1; shift; fi
  (($# >= 2)) || return 2
  name=$1; shift
  [[ $name =~ ^[a-z][a-z0-9-]*$ ]] || return 2
  checkpoint="$state/$name.done"
  phase_cleanup() {
    local status=$?
    trap - EXIT HUP INT TERM
    if [[ -n $temporary && (-e $temporary || -L $temporary) ]]; then
      if [[ -f $temporary && ! -L $temporary &&
            $(stat -c '%d:%i' "$temporary") == "$temporary_identity" ]]; then
        rm -f -- "$temporary" || status=1
      else status=1; fi
    fi
    ((signal_status == 0)) || status=$signal_status
    exit "$status"
  }
  trap phase_cleanup EXIT
  trap 'signal_status=129' HUP
  trap 'signal_status=130' INT
  trap 'signal_status=143' TERM

  if [[ -e $checkpoint || -L $checkpoint ]]; then
    installer_checkpoint_valid "$checkpoint" || {
      printf 'ОШИБКА: повреждённая или небезопасная отметка этапа %s\n' "$name" >&2
      return 1
    }
    marker_before=$(stat -c '%d:%i' "$checkpoint") || return 1
    if (( !always )); then printf '✓ %s (уже завершено)\n' "$name"; return 0; fi
  fi
  if [[ -e $state/$name.log || -L $state/$name.log ]]; then
    [[ -f $state/$name.log && ! -L $state/$name.log &&
       $(stat -c '%u:%g:%a:%h' "$state/$name.log") == 0:0:600:1 ]] || {
      printf 'ОШИБКА: небезопасный журнал этапа %s\n' "$name" >&2
      return 1
    }
  fi
  # Prepare owned staging before the transaction, reducing work after success.
  temporary=$(mktemp "$state/.$name.done.XXXXXXXX") || return 1
  temporary_identity=$(stat -c '%d:%i' "$temporary") || return 1
  chown root:root "$temporary" || return 1
  chmod 0600 "$temporary" || return 1
  date -u +%FT%TZ >"$temporary" || return 1
  ((signal_status == 0)) || return "$signal_status"
  printf '\n→ %s\n' "$name" || return 1
  ((signal_status == 0)) || return "$signal_status"
  # All owner answers have been collected. An unexpected child prompt must
  # receive EOF rather than silently wait while its output is in a private log.
  if "$@" </dev/null >"$state/$name.log" 2>&1; then
    # A terminal-group signal also reaches date/mv children. Ignore it through
    # this short publication window so those helpers cannot lose a successful
    # result. The foreground installer parent still handles cancellation and
    # exits after this worker; no later phase is started.
    trap '' HUP INT TERM
    date -u +%FT%TZ >"$temporary" || return 1
    installer_checkpoint_valid "$temporary" || return 1
    if [[ -n $marker_before ]]; then
      installer_checkpoint_valid "$checkpoint" &&
        [[ $(stat -c '%d:%i' "$checkpoint") == "$marker_before" ]] || return 1
      mv -Tf -- "$temporary" "$checkpoint" || return 1
    else
      mv -nT -- "$temporary" "$checkpoint" || return 1
    fi
    [[ ! -L $checkpoint && $(stat -c '%d:%i' "$checkpoint") == "$temporary_identity" ]] || {
      printf 'ОШИБКА: отметка этапа %s была изменена другой операцией\n' "$name" >&2
      return 1
    }
    temporary=''
    installer_checkpoint_valid "$checkpoint" || return 1
    trap 'signal_status=129' HUP
    trap 'signal_status=130' INT
    trap 'signal_status=143' TERM
    printf '✓ %s\n' "$name"
  else
    command_status=$?
    printf 'Этап %s остановлен (код %s). Закрытый журнал: %s/%s.log\nПосле диагностики: bash /opt/vpn-installer/install.sh --resume\n' \
      "$name" "$command_status" "$state" "$name" >&2
    return 1
  fi
)
