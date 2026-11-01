#!/usr/bin/env bash
# Cosmetic only: commands and checkpoint publication stay in the foreground.
installer_progress_stage='' installer_progress_helper='' installer_progress_pid=''
installer_progress_control='' installer_progress_control_identity=''
installer_progress_child_identity=''

_installer_progress_label() {
  case ${1-} in
    base) printf 'Подготовка Ubuntu';; certbot) printf 'Подготовка HTTPS';;
    tls) printf 'Сертификат TLS';; direct) printf 'Прямые профили';;
    panel) printf 'HTTPS-панель';; nginx-restart) printf 'Настройка Nginx';;
    cert-reconcile) printf 'Обновление сертификатов';; warp) printf 'Cloudflare WARP';;
    dual) printf 'Шесть профилей VPN';; xhttp) printf 'Транспорт XHTTP';;
    renewal) printf 'Проверка продления TLS';; verify) printf 'Итоговая проверка';;
    preflight) printf 'Проверка сервера';; bootstrap) printf 'Подготовка установки';;
    sni-check) printf 'Проверка REALITY SNI';; *) return 1;;
  esac
}

_installer_progress_identity() {
  local value fields
  [[ ${1-} =~ ^[0-9]+$ && -r /proc/$1/stat ]] || return 1
  IFS= read -r value <"/proc/$1/stat" || return 1
  value=${value##*) }
  read -r -a fields <<<"$value"
  [[ ${fields[0]-} != Z && ${fields[0]-} != X && ${fields[19]-} =~ ^[0-9]+$ ]] || return 1
  printf '%s' "${fields[19]}"
}

_installer_progress_count() {
  local active=${1-} result=${2-} name count=0
  # Preparation tasks have no measurable fraction of the installation stages.
  case $active in preflight|bootstrap|sni-check) printf '%s' -; return 0;; esac
  if [[ -n ${state-} ]] && declare -F installer_checkpoint_valid >/dev/null; then
    for name in base certbot tls direct panel nginx-restart cert-reconcile warp dual xhttp renewal verify; do
      [[ $name != "$active" || $result == 0 || $result == skip ]] || continue
      # A historical verify marker cannot replace this run's final verification.
      [[ $name != verify || ( $active == verify && $result == 0 ) ]] || continue
      if installer_checkpoint_valid "$state/$name.done" 2>/dev/null; then count=$((count + 1)); fi
    done
  fi
  printf '%s' "$count"
}

installer_progress_init() {
  installer_progress_stop
  installer_progress_stage='' installer_progress_helper=''
  if [[ -d ${1-} && ! -L $1 && $(stat -c '%u:%g:%a' "$1" 2>/dev/null) == 0:0:700 &&
        -f ${2-} && ! -L $2 ]]; then
    installer_progress_stage=$1 installer_progress_helper=$2
  fi
  return 0
}

installer_progress_stop() {
  local identity='' attempt
  if [[ -n ${installer_progress_control-} && -n ${installer_progress_control_identity-} &&
        -f $installer_progress_control && ! -L $installer_progress_control ]]; then
    identity=$(stat -c '%u:%g:%a:%h:%d:%i' "$installer_progress_control" 2>/dev/null) || identity=''
    if [[ $identity == "$installer_progress_control_identity" ]]; then
      rm -f -- "$installer_progress_control" 2>/dev/null || :
    fi
  fi
  if [[ -n ${installer_progress_pid-} && -n ${installer_progress_child_identity-} ]]; then
    for ((attempt=0; attempt<20; attempt++)); do
      identity=$(_installer_progress_identity "$installer_progress_pid") || identity=''
      if [[ $identity != "$installer_progress_child_identity" ]]; then
        wait "$installer_progress_pid" 2>/dev/null || :
        break
      fi
      sleep 0.05 || break
    done
  fi
  installer_progress_pid='' installer_progress_child_identity=''
  installer_progress_control='' installer_progress_control_identity=''
  return 0
}

installer_progress_begin() {
  local name=${1-} label count owner ticks identity
  installer_progress_stop
  label=$(_installer_progress_label "$name") || return 0
  [[ -n ${installer_progress_stage-} ]] || return 0
  count=$(_installer_progress_count "$name")
  if [[ ! -t 1 ]]; then
    if [[ $count == - ]]; then
      printf '%s — выполняется…\n' "$label" || :
    else
      printf 'Общий прогресс: %s%% [%s/12] %s — выполняется…\n' "$((count * 100 / 12))" "$count" "$label" || :
    fi
    return 0
  fi
  [[ -d $installer_progress_stage && ! -L $installer_progress_stage &&
     $(stat -c '%u:%g:%a' "$installer_progress_stage" 2>/dev/null) == 0:0:700 ]] || return 0
  owner=$BASHPID
  ticks=$(_installer_progress_identity "$owner") || return 0
  installer_progress_control=$(mktemp "$installer_progress_stage/progress.XXXXXXXX" 2>/dev/null) || return 0
  chmod 0600 "$installer_progress_control" 2>/dev/null || { installer_progress_stop; return 0; }
  identity=$(stat -c '%u:%g:%a:%h:%d:%i' "$installer_progress_control" 2>/dev/null) || identity=''
  if [[ $identity != 0:0:600:1:* ]]; then installer_progress_stop; return 0; fi
  installer_progress_control_identity=$identity
  python3 -I -B "$installer_progress_helper" "$installer_progress_control" "$identity" \
    "$owner" "$ticks" "$count" "$label" "${TERM:-dumb}" 9>&- </dev/null >/dev/null 2>&1 &
  installer_progress_pid=$!
  installer_progress_child_identity=$(_installer_progress_identity "$installer_progress_pid") || installer_progress_child_identity=''
  return 0
}

installer_progress_end() {
  local name=${1-} result=${2-1} label count outcome symbol bar='' cell
  installer_progress_stop
  label=$(_installer_progress_label "$name") || return 0
  [[ -n ${installer_progress_stage-} ]] || return 0
  count=$(_installer_progress_count "$name" "$result")
  case $result in 0) outcome='готово';; skip) outcome='уже завершено';; *) outcome='остановлено';; esac
  if [[ $count == - ]]; then
    case $result in 0|skip) symbol='✓';; *) symbol='!';; esac
    printf '%s %s — %s\n' "$symbol" "$label" "$outcome" || :
    return 0
  fi
  for ((cell=0; cell<12; cell++)); do
    if ((cell<count)); then bar+='█'; else bar+='░'; fi
  done
  # The caller prints the stage outcome separately. This is the overall count.
  printf 'Общий прогресс: [%s] %s%% [%s/12]\n' "$bar" "$((count * 100 / 12))" "$count" || :
  return 0
}
