#!/usr/bin/env bash
# Terminal presentation and input only; no persistent files or package changes.
wizard_init() {
  wizard_cyan='' wizard_yellow='' wizard_green='' wizard_red='' wizard_dim='' wizard_reset=''
  if [[ -t 1 && ${TERM:-dumb} != dumb && -z ${NO_COLOR+x} ]]; then
    wizard_cyan=$'\033[1;36m' wizard_yellow=$'\033[1;33m'
    wizard_green=$'\033[1;32m' wizard_red=$'\033[1;31m'
    wizard_dim=$'\033[90m' wizard_reset=$'\033[0m'
  fi
}

wizard_header() {
  printf '\n%b%s%b\n' "$wizard_cyan" 'VPN · 3X-UI' "$wizard_reset"
  printf '%b%s · Ubuntu 24.04%b\n' "$wizard_dim" "$1" "$wizard_reset"
  printf '%s\n' 'REALITY · Hysteria2 · XHTTP' '──────────────────────────────────────────────'
  printf 'Все параметры — сейчас. После последнего ответа установка пойдёт автоматически.\n\n'
}

wizard_section() {
  printf '\n%b[%s]%b %s\n\n' "$wizard_cyan" "$1" "$wizard_reset" "$2"
}

wizard_note() { printf '%b%s%b\n' "$wizard_dim" "$1" "$wizard_reset"; }
wizard_error() { printf '%b[!] %s%b\n' "$wizard_red" "$1" "$wizard_reset" >&2; }

wizard_read() {
  local target_name=$1 prompt=$2 default=${3-} reply
  printf '%b[?]%b %s' "$wizard_cyan" "$wizard_reset" "$prompt"
  if ! IFS= read -r reply </dev/tty; then
    printf '\n'
    wizard_error 'Ввод прерван. Установка не началась.'
    return 1
  fi
  printf -v "$target_name" '%s' "${reply:-$default}"
}

wizard_required() {
  local target_name=$1 prompt=$2
  while true; do
    wizard_read "$target_name" "$prompt" || return 1
    [[ -z ${!target_name} ]] || return 0
    wizard_error 'Заполните это поле.'
  done
}

collect_vpn_parameters() {
  local address_choice
  wizard_init
  wizard_header "$1"
  if [[ -n ${SSH_CONNECTION:-} ]]; then
    read -r _ _ TARGET_IPV4 TARGET_SSH_PORT <<<"$SSH_CONNECTION"
    if [[ $TARGET_IPV4 == *:* ]]; then
      TARGET_IPV4=$(ip -4 route get 1.1.1.1 | sed -n 's/.* src \([^ ]*\).*/\1/p' | head -n1)
    fi
  else
    TARGET_IPV4=$(ip -4 route get 1.1.1.1 | sed -n 's/.* src \([^ ]*\).*/\1/p' | head -n1)
  fi
  TARGET_INTERFACE=$(ip -o -4 address show | awk -v addr="$TARGET_IPV4" '{split($4,a,"/"); if(a[1]==addr) print $2}')
  printf '%b[✓]%b IPv4 сервера: %s\n' "$wizard_green" "$wizard_reset" "$TARGET_IPV4"
  if [[ -z ${SSH_CONNECTION:-} ]]; then
    wizard_read TARGET_SSH_PORT 'SSH порт [22]: ' 22 || return 1
  fi

  wizard_section '1/5' 'Адрес подключения'
  printf '  %b1. Без домена — по IP сервера (%s)%b\n' "$wizard_yellow" "$TARGET_IPV4" "$wizard_reset"
  printf '  %b2. С доменом%b\n\n' "$wizard_yellow" "$wizard_reset"
  while true; do
    wizard_read address_choice 'Выберите вариант [1]: ' 1 || return 1
    case "$address_choice" in
      1) TARGET_ADDRESS_MODE=ip; TARGET_FQDN=$TARGET_IPV4; break ;;
      2)
        TARGET_ADDRESS_MODE=domain
        wizard_note "Нужна одна DNS A-запись на $TARGET_IPV4, без AAAA и Cloudflare Proxy."
        wizard_required TARGET_FQDN 'Домен VPN: ' || return 1
        break ;;
      *) wizard_error 'Выберите 1 или 2.' ;;
    esac
  done
  printf '%b[✓]%b Адрес VPN: %s\n' "$wizard_green" "$wizard_reset" "$TARGET_FQDN"

  wizard_section '2/5' 'Сертификат HTTPS'
  wizard_note 'Доверенный сертификат для панели и подписки.'
  wizard_required ACME_EMAIL 'Ваш email для Let’s Encrypt (обязательно): ' || return 1

  wizard_section '3/5' 'Названия профилей'
  wizard_note 'Страна или любое своё имя, например: Мой VPN.'
  wizard_read TARGET_LABEL 'Начало названий [🇩🇪 Германия]: ' '🇩🇪 Германия' || return 1

  wizard_section '4/5' 'REALITY'
  wizard_note 'Если свой адрес не нужен, оставьте значение по умолчанию.'
  wizard_read TARGET_REALITY_SNI 'REALITY SNI [max.ru]: ' max.ru || return 1

  wizard_section '5/5' 'Лимит IP'
  wizard_note '0 — без ограничения IP на профиль.'
  wizard_read TARGET_DEVICE_LIMIT 'Лимит IP на профиль [0]: ' 0
}
