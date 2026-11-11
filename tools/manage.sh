#!/usr/bin/env bash
# Local administration of the committed installation. Never print access data
# until the user explicitly selects that action.
set -Eeuo pipefail
umask 077
export LC_ALL=C LANG=C LANGUAGE=C
unset PYTHONOPTIMIZE PYTHONPATH PYTHONHOME PYTHONUSERBASE PYTHONSTARTUP PYTHONINSPECT
unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY
readonly destination=/opt/vpn-installer
readonly state=/var/lib/vpn-installer
readonly runtime="$state/bundle"
readonly installer_lock=/run/vpn-installer.lock
readonly website=/var/www/vpn-decoy/public

fail() { printf 'ОШИБКА: %s\n' "$*" >&2; return 1; }
help_menu() {
  printf '%s\n' 'Управление VPN: vpn' '' \
    'vpn status  — состояние сервисов и выбранный SNI' \
    'vpn verify  — проверить VPN' \
    'vpn access  — показать данные панели и ссылку подписки' \
    'vpn sni     — сменить режим REALITY и SNI' \
    'vpn recover — восстановить незавершённую смену SNI' \
    'vpn site    — файлы сайта и восстановление начальной страницы' \
    'vpn php     — установить и включить PHP для сайта'
}
case ${1:-menu} in
  help|--help|-h) help_menu; exit 0;;
  menu|status|verify|access|sni|site|php|recover) (($# <= 1)) || { help_menu >&2; exit 2; };;
  *) help_menu >&2; exit 2;;
esac
[[ $EUID == 0 ]] || { fail 'Запустите меню от root: sudo vpn'; exit 1; }

verify_tree() {
  local directory=$1 manifest=$2 expected=$3
  [[ -d $directory && ! -L $directory && $(stat -c '%u:%g:%a' "$directory") == 0:0:700 ]] || return 1
  [[ -f $directory/$manifest && ! -L $directory/$manifest ]] || return 1
  [[ -z $(find "$directory" \( -type l -o ! -user root -o ! -group root -o -perm /022 \) -print -quit) ]] || return 1
  grep -Eq "^[0-9a-f]{64}  ${expected}$" "$directory/$manifest" || return 1
  (cd -- "$directory"; sha256sum --check --strict "$manifest" >/dev/null 2>&1)
}

guard_action() {
  verify_tree "$destination" SHA256SUMS 'tools/manage[.]sh' || {
    fail 'Файлы установленного VPN изменены или имеют небезопасные права.'; return 1;
  }
  [[ -d $state && ! -L $state && $(stat -c '%u:%g:%a' "$state") == 0:0:700 ]] &&
    verify_tree "$runtime" SOURCE_SHA256SUMS 'scripts/target-contract[.]sh' || {
    fail 'Рабочие файлы VPN не прошли проверку целостности.'; return 1;
  }
  flock -n "$installer_lock" true || { fail 'Сейчас выполняется установка или изменение VPN. Дождитесь завершения.'; return 1; }
  GERMANYVPN_TARGET_CONTRACT_LOADED=0
  source "$runtime/scripts/target-contract.sh"
}

manage_read() {
  local name=$1 prompt=$2 answer
  printf '%s' "$prompt"
  IFS= read -r answer || return 1
  printf -v "$name" '%s' "$answer"
}

show_status() {
  guard_action || return 1
  pending_notice
  printf 'Адрес VPN: %s\nРежим REALITY: %s\nКлиентский SNI: %s\n' \
    "$TARGET_FQDN" "$TARGET_REALITY_MODE" "$TARGET_REALITY_SNI"
  local unit status
  for unit in x-ui nginx; do
    status=$(systemctl is-active "$unit.service" 2>/dev/null) || :
    printf '%s: %s\n' "$unit" "${status:-unknown}"
  done
}

pending_notice() {
  if [[ -e $state/reality-management.pending || -L $state/reality-management.pending ]]; then
    printf '%s\n' 'Есть незавершённая смена SNI: vpn recover'
  fi
}

recover_sni() {
  guard_action || return 1
  if [[ ! -e $state/reality-management.pending && ! -L $state/reality-management.pending ]]; then
    printf '%s\n' 'Незавершённой смены SNI нет.'
    return 0
  fi
  python3 -I -B "$runtime/scripts/manage-reality.py" --recover
}

change_sni() {
  local mode_choice mode sni='' payload
  guard_action || return 1
  printf '\nТекущий режим: %s; клиентский SNI: %s\n' "$TARGET_REALITY_MODE" "$TARGET_REALITY_SNI"
  printf '%s\n' \
    '1. Собственный сайт · self-steal' \
    '2. Собственный сайт + другой клиентский SNI' \
    '3. Внешний сайт · SNI вручную' \
    '0. Назад'
  while true; do
    manage_read mode_choice 'Выберите режим REALITY: ' || return 1
    case $mode_choice in
      0) return 0;;
      1)
        if [[ $TARGET_ADDRESS_MODE != domain ]]; then
          fail 'Для self-steal нужен доменный адрес установки. Для текущего IP выберите собственный сайт с другим SNI или внешний сайт.' || :
          continue
        fi
        mode=self-steal; break;;
      2) mode=decoy; break;;
      3) mode=external; break;;
      *) printf 'Выберите 0, 1, 2 или 3.\n' >&2;;
    esac
  done
  printf '%s\n' 'Клиентский SNI остаётся виден в сети. Смена сайта или SNI не гарантирует защиту от блокировок.'
  if [[ $mode == decoy ]]; then
    printf '%s\n' 'Проверяющий получит сертификат вашего сайта. С чужим клиентским SNI имя в сертификате не совпадёт.'
  fi
  if [[ $mode != self-steal ]]; then
    while [[ -z $sni ]]; do manage_read sni 'Введите клиентский SNI без https://, порта и пути: ' || return 1; done
  else
    printf 'SNI собственного сайта: %s\n' "$TARGET_FQDN"
  fi
  payload=$(printf '%s\n%s\n' "$mode" "$sni" | python3 -I -B -c \
    'import json,sys; mode=sys.stdin.readline().rstrip("\n"); sni=sys.stdin.readline().rstrip("\n"); print(json.dumps({"mode":mode,"sni":sni}))') || return 1
  printf '%s\n' "$payload" | python3 -I -B "$runtime/scripts/manage-reality.py" --check-only || return 1
  printf '%s\n' "$payload" | python3 -I -B "$runtime/scripts/manage-reality.py" --apply || return 1
  printf '%s\n' 'Режим REALITY обновлён. Обновите подписку в VPN-приложении.'
}

backend_action() (
  guard_action || return 1
  # Retain this descriptor in the parent shell while the backend runs. Check
  # pending recovery only AFTER taking the same lock used by SNI changes.
  exec 8>>"$installer_lock"
  flock -n 8 || { fail 'Сейчас выполняется установка или изменение VPN. Дождитесь завершения.'; return 1; }
  [[ ! -e $state/reality-management.pending && ! -L $state/reality-management.pending ]] || {
    fail 'Сначала восстановите незавершённую смену SNI: vpn recover'; return 1;
  }
  # Another completed SNI change may have happened between the initial guard
  # and lock acquisition. Use the target that is current under this lock.
  GERMANYVPN_TARGET_CONTRACT_LOADED=0
  source "$runtime/scripts/target-contract.sh"
  [[ $TARGET_REALITY_MODE != external ]] || {
    fail 'Сначала включите собственный сайт в разделе смены REALITY/SNI.'; return 1;
  }
  bash "$runtime/base/install-reality-decoy.sh" "$1"
)

enable_php() {
  printf '%s\n' 'Установка PHP-FPM и включение PHP для собственного сайта…'
  backend_action --enable-php
}

manage_site() {
  local site_choice
  guard_action || return 1
  printf '\nКаталог сайта: %s\n' "$website"
  printf '%s\n' \
    'Загрузите сюда index.html и остальные файлы сайта через SFTP от root.' \
    'Для index.php сначала включите PHP в меню.'
  if [[ $TARGET_REALITY_MODE != external ]]; then
    printf 'Адрес сайта: https://%s/\n' "$TARGET_FQDN"
  else
    printf '%s\n' 'Чтобы опубликовать сайт, включите собственный сайт в разделе REALITY/SNI.'
  fi
  printf '%s\n' '1. Восстановить начальный HTML (index.html и index.php сохранятся в закрытой резервной копии; остальные файлы останутся)' \
    '2. Установить и включить PHP' '0. Назад'
  while true; do
    manage_read site_choice 'Выберите действие: ' || return 1
    case $site_choice in
      0) return 0;;
      1) backend_action --reset-page; return $?;;
      2) enable_php; return $?;;
      *) printf 'Выберите 0, 1 или 2.\n' >&2;;
    esac
  done
}

run_action() {
  case $1 in
    status) show_status;;
    verify) guard_action && bash "$destination/install.sh" --verify;;
    access) guard_action && bash "$destination/install.sh" --show-access;;
    sni) change_sni;;
    site) manage_site;;
    php) enable_php;;
    recover) recover_sni;;
  esac
}

if [[ ${1:-menu} != menu ]]; then run_action "$1"; exit $?; fi
guard_action
while true; do
  pending_notice
  printf '\n%s\n' 'VPN — управление' \
    '1. Состояние' '2. Проверить VPN' \
    '3. Показать данные панели и подписки' '4. Сменить REALITY/SNI' \
    '5. Сайт: файлы и начальная страница' '6. Установить и включить PHP' \
    '7. Восстановить незавершённую смену SNI' '0. Выход'
  menu_choice=''
  manage_read menu_choice 'Выберите действие: ' || exit 0
  case $menu_choice in
    0) exit 0;;
    1) run_action status || :;;
    2) run_action verify || :;;
    3) run_action access || :;;
    4) run_action sni || :;;
    5) run_action site || :;;
    6) run_action php || :;;
    7) run_action recover || :;;
    *) printf 'Выберите действие от 0 до 7.\n' >&2;;
  esac
done
