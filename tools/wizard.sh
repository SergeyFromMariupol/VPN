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
  printf 'Выберите адрес подключения и SNI — дальше установка пойдёт автоматически.\n\n'
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

wizard_probe_sni() {
  local probe_status
  wizard_note 'Проверка SNI…'
  if declare -F installer_progress_begin >/dev/null; then installer_progress_begin sni-check || :; fi
  if TARGET_REALITY_SNI="$TARGET_REALITY_SNI" python3 -B "$1" --check-reality-sni >/dev/null 2>&1; then
    probe_status=0
  else probe_status=$?; fi
  if declare -F installer_progress_end >/dev/null; then installer_progress_end sni-check "$probe_status" || :; fi
  return "$probe_status"
}

wizard_reality_sni() {
  local verifier=$1 sni_choice
  wizard_section 'SNI' 'REALITY'
  printf '  %b1. По умолчанию max.ru%b\n' "$wizard_yellow" "$wizard_reset"
  printf '  %b2. Свой%b\n\n' "$wizard_yellow" "$wizard_reset"
  while true; do
    wizard_read sni_choice 'Выберите SNI [1]: ' 1 || return 1
    case "$sni_choice" in
      1)
        TARGET_REALITY_SNI=max.ru
        if wizard_probe_sni "$verifier"; then return 0; fi
        wizard_error 'SNI не прошёл проверку TLS 1.3, H2 и сертификата. Выберите другой.'
        ;;
      2)
        while true; do
          wizard_required TARGET_REALITY_SNI 'Свой SNI: ' || return 1
          if wizard_probe_sni "$verifier"; then return 0; fi
          wizard_error 'SNI не подходит: нужны TLS 1.3, H2 и доверенный сертификат. Введите другой.'
        done
        ;;
      *) wizard_error 'Выберите 1 или 2.' ;;
    esac
  done
}

collect_vpn_parameters() {
  local address_choice verifier=$2
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
  if [[ -z ${SSH_CONNECTION:-} ]]; then
    wizard_read TARGET_SSH_PORT 'SSH порт [22]: ' 22 || return 1
  fi

  wizard_section 'VPN' 'Адрес подключения'
  printf '  %b1. По IP-адресу%b\n' "$wizard_yellow" "$wizard_reset"
  printf '  %b2. По доменному имени%b\n\n' "$wizard_yellow" "$wizard_reset"
  while true; do
    wizard_read address_choice 'Выберите вариант [1]: ' 1 || return 1
    case "$address_choice" in
      1) TARGET_ADDRESS_MODE=ip; TARGET_FQDN=$TARGET_IPV4; break ;;
      2)
        TARGET_ADDRESS_MODE=domain
        wizard_note 'Нужна одна DNS A-запись на этот сервер, без AAAA и Cloudflare Proxy.'
        wizard_required TARGET_FQDN 'Домен VPN: ' || return 1
        break ;;
      *) wizard_error 'Выберите 1 или 2.' ;;
    esac
  done

  wizard_reality_sni "$verifier" || return 1

  # Personal/friends defaults; no further setup questions after SNI validation.
  ACME_EMAIL=''
  TARGET_LABEL='Мой VPN'
  TARGET_DEVICE_LIMIT=0
}
