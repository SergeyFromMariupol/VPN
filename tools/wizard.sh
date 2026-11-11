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
  printf 'Выберите выход, набор профилей, адрес подключения и SNI.\n\n'
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

wizard_personal_label() {
  while true; do
    wizard_read TARGET_LABEL 'Ваше имя для названий профилей: ' || return 1
    [[ -n ${TARGET_LABEL//[[:space:]]/} ]] && return 0
    wizard_error 'Введите имя для названий профилей.'
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

wizard_validate_local_site() {
  TARGET_REALITY_MODE=self-steal TARGET_REALITY_SNI="$1" TARGET_FQDN="$1" \
    TARGET_ADDRESS_MODE=domain TARGET_TLS_MODE="$TARGET_TLS_MODE" \
    python3 -B "$2" --check-reality-selection >/dev/null 2>&1
}

wizard_reality_domain() {
  local verifier=$1 site_domain
  if [[ $TARGET_ADDRESS_MODE == domain ]] && wizard_validate_local_site "$TARGET_FQDN" "$verifier"; then
    return 0
  fi
  wizard_note 'Для self-steal нужен свой домен. Он станет адресом VPN, сайта, панели и подписки.'
  wizard_note 'Направьте одну DNS A-запись на сервер; AAAA и Cloudflare Proxy должны быть выключены.'
  while true; do
    wizard_required site_domain 'Домен сайта, VPN, панели и подписки: ' || return 1
    if wizard_validate_local_site "$site_domain" "$verifier"; then
      TARGET_FQDN=$site_domain
      TARGET_ADDRESS_MODE=domain
      return 0
    fi
    wizard_error 'Введите свой домен без https://, порта и пути; IP-адрес для self-steal не подходит.'
  done
}

wizard_reality_sni() {
  local verifier=$1 sni_choice
  wizard_section 'SNI' 'REALITY'
  printf '  %b1. Собственный сайт · self-steal%b\n' "$wizard_yellow" "$wizard_reset"
  printf '  %b2. Собственный сайт + другой клиентский SNI%b\n' "$wizard_yellow" "$wizard_reset"
  printf '  %b3. Внешний сайт · SNI вручную%b\n\n' "$wizard_yellow" "$wizard_reset"
  while true; do
    wizard_read sni_choice 'Выберите режим REALITY [1]: ' 1 || return 1
    case "$sni_choice" in
      1)
        TARGET_REALITY_MODE=self-steal
        wizard_reality_domain "$verifier" || return 1
        TARGET_REALITY_SNI=$TARGET_FQDN
        wizard_note 'SNI совпадает с вашим доменом. DNS проверится до выпуска сертификата, TLS сайта — после создания.'
        return 0
        ;;
      2)
        TARGET_REALITY_MODE=decoy
        wizard_note 'Проверяющий получит сертификат вашего сайта, в том числе при запросе по IP или без SNI.'
        wizard_note 'Клиентский SNI останется виден в сети; с чужим именем сертификат сайта не совпадёт. Защита от блокировок не гарантируется.'
        while true; do
          wizard_required TARGET_REALITY_SNI 'Клиентский SNI: ' || return 1
          if TARGET_REALITY_MODE="$TARGET_REALITY_MODE" TARGET_REALITY_SNI="$TARGET_REALITY_SNI" \
            TARGET_FQDN="$TARGET_FQDN" TARGET_IPV4="$TARGET_IPV4" TARGET_ADDRESS_MODE="$TARGET_ADDRESS_MODE" \
            TARGET_TLS_MODE="$TARGET_TLS_MODE" python3 -B "$verifier" --check-reality-selection >/dev/null 2>&1; then
            return 0
          fi
          wizard_error 'Введите DNS-имя без https://, порта и пути. Cloudflare и IP-адреса не подходят для клиентского SNI.'
        done
        ;;
      3)
        TARGET_REALITY_MODE=external
        wizard_note 'Внешний сайт должен поддерживать TLS 1.3, H2 и доверенный сертификат для выбранного SNI.'
        while true; do
          wizard_required TARGET_REALITY_SNI 'Внешний SNI: ' || return 1
          if wizard_probe_sni "$verifier"; then return 0; fi
          wizard_error 'SNI не подходит: нужны TLS 1.3, H2 и доверенный сертификат. Введите другой.'
        done
        ;;
      *) wizard_error 'Выберите 1, 2 или 3.' ;;
    esac
  done
}

wizard_custom_profiles() {
  local selector="${1%/*}/portfolio_catalog.py" numbers chosen='' profile_count status=0
  wizard_section 'Профили' 'Ручной выбор'
  if [[ ${TERM:-dumb} != dumb ]]; then
    chosen=$(LC_ALL=C.UTF-8 python3 -B "$selector" --checklist --egress "$TARGET_EGRESS_MODE" \
      3>&1 </dev/tty >/dev/tty) || status=$?
    case $status in
      0) ;;
      69) wizard_note 'Терминал не поддерживает список с галочками. Выберите по номерам.' ;;
      *) wizard_error 'Выбор прерван. Установка не началась.'; return 1 ;;
    esac
  fi
  if [[ -z $chosen ]]; then
    python3 -B "$selector" --menu --egress "$TARGET_EGRESS_MODE" || return 1
    wizard_note 'Введите номера через пробел или запятую. Диапазон можно указать как 1-3.'
    while true; do
      wizard_read numbers 'Номера профилей: ' || return 1
      if chosen=$(python3 -B "$selector" --choose="$numbers" --egress "$TARGET_EGRESS_MODE" 2>/dev/null); then
        break
      fi
      wizard_error 'Выберите хотя бы один профиль. Проверьте номера, диапазоны и повторы.'
    done
  fi
  IFS=" " read -r TARGET_EGRESS_MODE TARGET_PROFILE_IDS profile_count <<<"$chosen"
  wizard_note "Выбрано профилей: $profile_count."
}

collect_vpn_parameters() {
  local address_choice egress_choice profile_choice verifier=$2
  wizard_init
  TARGET_TLS_MODE=letsencrypt
  TARGET_PROFILE_IDS=''
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

  wizard_section 'Выход' 'Использование CloudFlare WARP'
  printf '  %b1. Использовать CloudFlare WARP%b\n' "$wizard_yellow" "$wizard_reset"
  printf '  %b2. Не использовать CloudFlare WARP%b\n' "$wizard_yellow" "$wizard_reset"
  printf '  %b3. Оба варианта профилей%b\n\n' "$wizard_yellow" "$wizard_reset"
  while true; do
    wizard_read egress_choice 'Выберите выход [3]: ' 3 || return 1
    case "$egress_choice" in
      1) TARGET_EGRESS_MODE=warp; break;;
      2) TARGET_EGRESS_MODE=direct; break;;
      3) TARGET_EGRESS_MODE=both; break;;
      *) wizard_error 'Выберите 1, 2 или 3.';;
    esac
  done

  wizard_section 'Профили' 'Сколько вариантов установить'
  printf 'Показано число профилей для выбранного выхода.\n'
  if [[ $TARGET_EGRESS_MODE == both ]]; then
    printf '  %b1. Основные 6%b\n' "$wizard_yellow" "$wizard_reset"
    printf '  %b2. Для DPI/ТСПУ — 98%b\n' "$wizard_yellow" "$wizard_reset"
    printf '  %b3. Все проверенные рабочие — 146%b\n' "$wizard_yellow" "$wizard_reset"
  else
    printf '  %b1. Основные 3%b\n' "$wizard_yellow" "$wizard_reset"
    printf '  %b2. Для DPI/ТСПУ — 49%b\n' "$wizard_yellow" "$wizard_reset"
    printf '  %b3. Все проверенные рабочие — 73%b\n' "$wizard_yellow" "$wizard_reset"
  fi
  printf '  %b4. Выбрать профили вручную%b\n\n' "$wizard_yellow" "$wizard_reset"
  while true; do
    wizard_read profile_choice 'Выберите набор [1]: ' 1 || return 1
    case "$profile_choice" in
      1) TARGET_PROFILE_SET=basic; break;;
      2) TARGET_PROFILE_SET=dpi; break;;
      3) TARGET_PROFILE_SET=all; break;;
      4) wizard_custom_profiles "$verifier" || return 1; TARGET_PROFILE_SET=custom; break;;
      *) wizard_error 'Выберите 1, 2, 3 или 4.';;
    esac
  done

  if [[ -z ${SSH_CONNECTION:-} ]]; then
    wizard_read TARGET_SSH_PORT 'SSH порт [22]: ' 22 || return 1
  fi

  wizard_section 'VPN' 'Адрес подключения'
  printf '  %b1. По IP-адресу%b\n' "$wizard_yellow" "$wizard_reset"
  printf '  %b2. По доменному имени%b\n\n' "$wizard_yellow" "$wizard_reset"
  while true; do
    wizard_read address_choice 'Выберите вариант [1]: ' 1 || return 1
    case "$address_choice" in
      1)
        TARGET_ADDRESS_MODE=ip
        TARGET_IPV4=$(ip -4 route get 1.1.1.1 | sed -n 's/.* src \([^ ]*\).*/\1/p' | head -n1)
        TARGET_INTERFACE=$(ip -o -4 address show | awk -v addr="$TARGET_IPV4" '{split($4,a,"/"); if(a[1]==addr) print $2}')
        TARGET_FQDN=$TARGET_IPV4
        break ;;
      2)
        TARGET_ADDRESS_MODE=domain
        wizard_note 'Нужна одна DNS A-запись на этот сервер, без AAAA и Cloudflare Proxy.'
        wizard_required TARGET_FQDN 'Домен VPN: ' || return 1
        break ;;
      *) wizard_error 'Выберите 1 или 2.' ;;
    esac
  done

  wizard_note 'Let’s Encrypt выпускается автоматически для IP или домена; панель и подписка будут по HTTPS.'
  wizard_reality_sni "$verifier" || return 1

  wizard_section 'Название' 'Начало названий профилей'
  wizard_personal_label || return 1

  wizard_section 'Контакт' 'Let’s Encrypt'
  wizard_note 'Email для уведомлений о сертификате можно оставить пустым.'
  wizard_read ACME_EMAIL 'Email для Let’s Encrypt (необязательно) [пусто]: ' '' || return 1

  wizard_section 'Happ' 'Обход VPN для приложений Android'
  wizard_note 'Список обхода передаётся всегда. Для автоматического применения Happ нужен премиальный Provider ID, привязанный к хосту подписки.'
  wizard_note 'С Provider ID Happ раз в сутки отправляет своему сервису ID устройства, название и версию ОС и хеш хоста подписки.'
  while true; do
    wizard_read TARGET_HAPP_PROVIDER_ID 'Happ Provider ID (необязательно) [пусто]: ' || return 1
    if [[ -z $TARGET_HAPP_PROVIDER_ID || $TARGET_HAPP_PROVIDER_ID =~ ^[A-Za-z0-9]{8}$ ]]; then
      break
    fi
    wizard_error 'Provider ID состоит из 8 латинских букв или цифр. Поле можно оставить пустым.'
  done

  # Personal/friends default.
  TARGET_DEVICE_LIMIT=0
}
