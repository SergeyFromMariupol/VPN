#!/usr/bin/env bash
# VPN installer for a clean Ubuntu 24.04 amd64 VPS.
set -Eeuo pipefail
umask 077
unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY
readonly repository='SergeyFromMariupol/VPN'
readonly release='v1.1.5'
readonly state='/var/lib/vpn-installer'
readonly destination='/opt/vpn-installer'
readonly target_file='/etc/germanyvpn-target.env'
mode=${1:-install}
case "$mode" in install|--resume|--show-access|--verify|--help) ;; *) printf 'Unknown argument\n' >&2; exit 2;; esac
if [[ $mode == --help ]]; then
  printf '%s\n' 'VPN — Ubuntu 24.04 amd64' 'bash install.sh                 interactive installation' 'bash install.sh --resume        resume completed installation phases' 'bash install.sh --show-access   show panel/subscription credentials' 'bash install.sh --verify        verify the installed server'
  exit 0
fi
die() { printf 'ОШИБКА: %s\n' "$*" >&2; exit 1; }
[[ $EUID == 0 ]] || die 'Запустите от root: sudo bash install.sh'
if [[ $mode == --show-access ]]; then
  [[ -f /etc/krysyuk-standalone/access.env && ! -L /etc/krysyuk-standalone/access.env ]] || die 'VPN ещё не установлен'
  cat /etc/krysyuk-standalone/access.env
  exit 0
fi
if [[ $mode == --verify ]]; then
  exec bash "$destination/tools/verify.sh"
fi
# Resume belongs to the installed release. A newer downloaded entrypoint must
# not combine its new phase list with an older rendered runtime, nor require a
# network download before continuing a complete local source installation.
if [[ $mode == --resume ]]; then
  current_file=$(readlink -f -- "${BASH_SOURCE[0]}")
  current_parent=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
  if [[ $current_file != "$destination/install.sh" || $current_parent != "$destination" ]]; then
    [[ -d $destination && ! -L $destination &&
       $(stat -c '%u:%g:%a' "$destination") == 0:0:700 ]] || die 'Нет безопасного установленного исходного кода для продолжения'
    for path in "$destination/install.sh" "$destination/SHA256SUMS"; do
      [[ -f $path && ! -L $path && $(stat -c '%u:%h' "$path") == 0:1 ]] || die 'Небезопасный установленный исходный код'
      (( (8#$(stat -c %a "$path") & 8#022) == 0 )) || die 'Установленный исходный код доступен для записи другим пользователям'
    done
    [[ -z $(find "$destination" \( -type l -o ! -user root -o -perm /022 \) -print -quit) ]] || die 'Небезопасные права или ссылки в установленном исходном коде'
    grep -Eq '^[0-9a-f]{64}  install[.]sh$' "$destination/SHA256SUMS" || die 'Установщик отсутствует в source manifest'
    (cd -- "$destination"; sha256sum --check --strict SHA256SUMS >/dev/null) || die 'Проверка установленного исходного кода не пройдена'
    # Dispatch precedes lock acquisition, so the installed entrypoint can take
    # the normal installer lock without inheriting a second conflicting lock.
    exec bash "$destination/install.sh" --resume
  fi
fi
# Serialize all installs, including the read-only check and download stages.
exec 9>/run/vpn-installer.lock
flock -n 9 || die 'Другая установка уже выполняется'
[[ -f /etc/os-release ]] || die 'Не найдена информация об ОС'
source /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 && $(dpkg --print-architecture) == amd64 ]] || die 'Нужна Ubuntu 24.04 LTS amd64'
for cmd in python3 curl tar sha256sum ip openssl timeout; do command -v "$cmd" >/dev/null || die "Не найдена команда $cmd"; done
[[ $(ps -p 1 -o comm=) == systemd ]] || die 'Нужен VPS/VM с systemd'
task_stage=$(mktemp -d /run/vpn-installer.XXXXXXXX)
cleanup() {
  local rc=$?
  trap - EXIT HUP INT TERM
  if declare -F cleanup_installation_bootstrap >/dev/null; then
    cleanup_installation_bootstrap || { ((rc)) || rc=1; }
  fi
  rm -rf -- "$task_stage"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
if [[ ! -f $source_dir/tools/preflight.py ]]; then
  printf 'Загрузка VPN %s…\n' "$release"
  curl --disable --proto '=https' --tlsv1.2 -fsSL --retry 2 --connect-timeout 15 --max-time 300 \
    "https://github.com/$repository/archive/refs/tags/$release.tar.gz" -o "$task_stage/source.tar.gz"
  # Reject traversal, links, devices and multiple archive roots before extraction.
  python3 - "$task_stage/source.tar.gz" <<'PY'
import sys, tarfile
from pathlib import PurePosixPath
with tarfile.open(sys.argv[1]) as archive:
    roots = set()
    for member in archive:
        path = PurePosixPath(member.name)
        assert not path.is_absolute() and '..' not in path.parts
        assert member.isfile() or member.isdir()
        roots.add(path.parts[0])
    assert len(roots) == 1
PY
  mkdir "$task_stage/source"
  tar -xzf "$task_stage/source.tar.gz" --strip-components=1 -C "$task_stage/source"
  source_dir="$task_stage/source"
fi
(cd -- "$source_dir"; sha256sum --check --strict SHA256SUMS >/dev/null)
source "$source_dir/tools/bootstrap.sh"
if [[ $mode == --resume ]]; then
  [[ -d $state && ! -L $state && $(stat -c '%U:%G:%a' "$state") == root:root:700 ]] || die 'Нет безопасного состояния для продолжения'
  [[ -f $target_file && ! -L $target_file && $(stat -c '%U:%G:%a' "$target_file") == root:root:600 ]] || die 'Небезопасный target env'
  source "$target_file"
  [[ -f $destination/SHA256SUMS ]] || die 'Отсутствует установленный bundle'
  (cd -- "$destination"; sha256sum --check --strict SHA256SUMS >/dev/null)
else
  [[ ! -e $state && ! -L $state && ! -e $destination && ! -L $destination && ! -e $target_file && ! -L $target_file ]] || die 'Есть предыдущая установка; используйте --resume'
  [[ -r /dev/tty ]] || die 'Нужен интерактивный терминал для параметров установки'
  printf '\nVPN: REALITY + Hysteria2 + XHTTP, Cloudflare WARP и прямой выход.\n'
  if [[ -n ${SSH_CONNECTION:-} ]]; then
    read -r _ _ TARGET_IPV4 TARGET_SSH_PORT <<<"$SSH_CONNECTION"
    if [[ $TARGET_IPV4 == *:* ]]; then
      # SSH may arrive over IPv6 while the public VPN endpoints use IPv4.
      TARGET_IPV4=$(ip -4 route get 1.1.1.1 | sed -n 's/.* src \([^ ]*\).*/\1/p' | head -n1)
    fi
  else
    TARGET_IPV4=$(ip -4 route get 1.1.1.1 | sed -n 's/.* src \([^ ]*\).*/\1/p' | head -n1)
    read -r -p 'SSH порт [22]: ' TARGET_SSH_PORT </dev/tty
    TARGET_SSH_PORT=${TARGET_SSH_PORT:-22}
  fi
  TARGET_INTERFACE=$(ip -o -4 address show | awk -v addr="$TARGET_IPV4" '{split($4,a,"/"); if(a[1]==addr) print $2}')
  printf 'Определён IPv4 сервера: %s\n' "$TARGET_IPV4"
  read -r -p 'Домен VPN (Enter = без домена, по IP сервера): ' TARGET_FQDN </dev/tty
  if [[ -z $TARGET_FQDN ]]; then
    TARGET_ADDRESS_MODE=ip
    TARGET_FQDN=$TARGET_IPV4
  else
    TARGET_ADDRESS_MODE=domain
    printf 'Для домена нужна одна A-запись на %s, без AAAA и Cloudflare Proxy.\n' "$TARGET_IPV4"
  fi
  read -r -p 'Ваш email для Let’s Encrypt (обязательно): ' ACME_EMAIL </dev/tty
  read -r -p 'Начало названий профилей — страна или любое имя [🇩🇪 Германия]: ' TARGET_LABEL </dev/tty
  TARGET_LABEL=${TARGET_LABEL:-🇩🇪 Германия}
  read -r -p 'REALITY SNI [max.ru]: ' TARGET_REALITY_SNI </dev/tty
  TARGET_REALITY_SNI=${TARGET_REALITY_SNI:-max.ru}
  read -r -p 'Лимит IP на профиль, 0 = без лимита [0]: ' TARGET_DEVICE_LIMIT </dev/tty
  TARGET_DEVICE_LIMIT=${TARGET_DEVICE_LIMIT:-0}
  export TARGET_ADDRESS_MODE TARGET_FQDN ACME_EMAIL TARGET_LABEL TARGET_REALITY_SNI TARGET_DEVICE_LIMIT TARGET_IPV4 TARGET_SSH_PORT TARGET_INTERFACE
  printf 'Проверка чистого сервера, адреса и TLS…\n'
  python3 "$source_dir/tools/preflight.py" | tee "$task_stage/inventory.txt"
  printf '\nСервер: %s; адрес подписки и панели: %s (режим %s).\nFirewall Ubuntu: SSH TCP/%s, TCP 80,443,2053,2096,8443,8444 и UDP443.\n' "$TARGET_IPV4" "$TARGET_FQDN" "$TARGET_ADDRESS_MODE" "$TARGET_SSH_PORT"
  printf 'Если в панели провайдера включён отдельный firewall, разрешите эти же порты там.\n'
  printf 'После подтверждения обновятся пакеты Ubuntu (apt-get update/upgrade), затем установится VPN.\n'
  read -r -p 'Установить VPN на этот чистый VPS? [yes/нет]: ' answer </dev/tty
  [[ $answer == yes ]] || die 'Установка отменена'
  prepare_installation_bootstrap
fi
TARGET_ADDRESS_MODE=${TARGET_ADDRESS_MODE:-domain}
export TARGET_ADDRESS_MODE TARGET_IPV4 TARGET_FQDN TARGET_INTERFACE TARGET_SSH_PORT TARGET_DEVICE_LIMIT TARGET_REALITY_SNI TARGET_LABEL ACME_EMAIL
runtime="$state/bundle"
if [[ ! -d $runtime ]]; then
  rendered_stage=$(mktemp -d "$state/rendered.XXXXXXXX")
  cp -a -- "$destination/bundle/." "$rendered_stage/"
  python3 "$destination/tools/render.py" "$rendered_stage"
  chmod 0700 "$rendered_stage"
  mv -T -- "$rendered_stage" "$runtime"
fi
[[ ! -L $runtime && $(stat -c '%U:%G:%a' "$runtime") == root:root:700 ]] || die 'Небезопасный runtime bundle'
(cd -- "$runtime"; sha256sum --check --strict SOURCE_SHA256SUMS >/dev/null)
# A foreground worker owns both the child result and atomic phase checkpoint.
source "$destination/tools/phases.sh"
phase base bash "$runtime/base/install-pinned-base.sh" --apply
phase certbot bash "$runtime/base/install-certbot.sh" --apply
bash "$runtime/base/install-certbot.sh" --check-only >"$state/certbot-check.log" 2>&1
phase tls bash "$runtime/base/acme.sh" --apply
phase direct bash "$runtime/scripts/configure-standalone.sh" --apply
phase panel bash "$runtime/scripts/expose-panel-https.sh" --apply
phase nginx-restart bash "$runtime/base/install-nginx-restart.sh" --apply
phase cert-reconcile bash "$runtime/base/install-cert-reconcile.sh" --apply
phase warp bash "$runtime/warp-egress/scripts/install-warp.sh"
phase dual env CONFIRM_STANDALONE_DUAL_EGRESS="ENABLE-WARP-AND-DIRECT-$TARGET_IPV4" bash "$runtime/scripts/enable-dual-egress.sh" --apply
if [[ ! -f $state/xhttp.done && -f /etc/germanyvpn-xhttp-test/promotion.json ]]; then
  # A process may have exited after committing the transaction, before the
  # outer phase marker was written. Accept only a fully verified committed state.
  phase xhttp python3 "$runtime/scripts/finalize-xhttp.py" --verify
else
  phase xhttp env CONFIRM_FRESH_XHTTP=FINALIZE-FRESH-XHTTP python3 "$runtime/scripts/finalize-xhttp.py" --apply
fi
# The production timer keeps Certbot's random spread; an interactive install
# should run its one acceptance renewal immediately.
phase renewal certbot renew --dry-run --run-deploy-hooks --no-random-sleep-on-renew
# Always recheck live state, including a resume after a later phase failed.
phase --always verify bash "$destination/tools/verify.sh"
printf '\nVPN установлен. Сохраните данные:\n\n'
cat /etc/krysyuk-standalone/access.env
printf '\nПовторный вывод: bash /opt/vpn-installer/install.sh --show-access\n'
printf 'После reboot: bash /opt/vpn-installer/install.sh --verify\n'
printf 'Проверку скорости и импорт в приложения выполните со своего подключения.\n'
