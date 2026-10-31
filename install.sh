#!/usr/bin/env bash
# VPN installer for a clean Ubuntu 24.04 amd64 VPS.
set -Eeuo pipefail
umask 077
unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY
readonly repository='SergeyFromMariupol/VPN'
readonly release='v1.0.0'
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
# Serialize all installs, including the read-only check and download stages.
exec 9>/run/vpn-installer.lock
flock -n 9 || die 'Другая установка уже выполняется'
[[ -f /etc/os-release ]] || die 'Не найдена информация об ОС'
source /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 && $(dpkg --print-architecture) == amd64 ]] || die 'Нужна Ubuntu 24.04 LTS amd64'
for cmd in python3 curl tar sha256sum ip openssl timeout; do command -v "$cmd" >/dev/null || die "Не найдена команда $cmd"; done
[[ $(ps -p 1 -o comm=) == systemd ]] || die 'Нужен VPS/VM с systemd'
task_stage=$(mktemp -d /run/vpn-installer.XXXXXXXX)
cleanup() { local rc=$?; trap - EXIT; rm -rf -- "$task_stage"; exit "$rc"; }
trap cleanup EXIT
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
if [[ $mode == --resume ]]; then
  [[ -d $state && ! -L $state && $(stat -c '%U:%G:%a' "$state") == root:root:700 ]] || die 'Нет безопасного состояния для продолжения'
  [[ -f $target_file && ! -L $target_file && $(stat -c '%U:%G:%a' "$target_file") == root:root:600 ]] || die 'Небезопасный target env'
  source "$target_file"
  [[ -f $destination/SHA256SUMS ]] || die 'Отсутствует установленный bundle'
  (cd -- "$destination"; sha256sum --check --strict SHA256SUMS >/dev/null)
else
  [[ ! -e $state && ! -L $state && ! -e $destination && ! -L $destination && ! -e $target_file && ! -L $target_file ]] || die 'Есть предыдущая установка; используйте --resume'
  [[ -r /dev/tty ]] || die 'Нужен интерактивный терминал для домена и email'
  printf '\nVPN: REALITY + Hysteria2 + XHTTP, Cloudflare WARP и прямой выход.\n'
  read -r -p 'Домен VPN (A-запись уже указывает на этот VPS, без AAAA/proxy): ' TARGET_FQDN </dev/tty
  read -r -p 'Email для Let’s Encrypt: ' ACME_EMAIL </dev/tty
  read -r -p 'Название страны с флагом [🇩🇪 Германия]: ' TARGET_LABEL </dev/tty
  TARGET_LABEL=${TARGET_LABEL:-🇩🇪 Германия}
  read -r -p 'REALITY SNI [max.ru]: ' TARGET_REALITY_SNI </dev/tty
  TARGET_REALITY_SNI=${TARGET_REALITY_SNI:-max.ru}
  read -r -p 'Лимит IP на профиль, 0 = без лимита [0]: ' TARGET_DEVICE_LIMIT </dev/tty
  TARGET_DEVICE_LIMIT=${TARGET_DEVICE_LIMIT:-0}
  if [[ -n ${SSH_CONNECTION:-} ]]; then
    read -r _ _ TARGET_IPV4 TARGET_SSH_PORT <<<"$SSH_CONNECTION"
  else
    TARGET_IPV4=$(ip -4 route get 1.1.1.1 | sed -n 's/.* src \([^ ]*\).*/\1/p' | head -n1)
    read -r -p 'SSH порт [22]: ' TARGET_SSH_PORT </dev/tty
    TARGET_SSH_PORT=${TARGET_SSH_PORT:-22}
  fi
  TARGET_INTERFACE=$(ip -o -4 address show | awk -v addr="$TARGET_IPV4" '$4 ~ ("^" addr "/") {print $2}')
  export TARGET_FQDN ACME_EMAIL TARGET_LABEL TARGET_REALITY_SNI TARGET_DEVICE_LIMIT TARGET_IPV4 TARGET_SSH_PORT TARGET_INTERFACE
  printf 'Проверка чистого сервера, DNS и TLS…\n'
  python3 "$source_dir/tools/preflight.py" | tee "$task_stage/inventory.txt"
  printf '\nСервер: %s; домен: %s. Откроются TCP 80,443,2053,2096,8443,8444 и UDP443.\n' "$TARGET_IPV4" "$TARGET_FQDN"
  read -r -p 'Установить VPN на этот чистый VPS? [yes/нет]: ' answer </dev/tty
  [[ $answer == yes ]] || die 'Установка отменена'
  install -d -m 0700 "$state" "$destination"
  cp -- "$task_stage/inventory.txt" "$state/inventory-before.txt"
  cp -a -- "$source_dir/." "$destination/"
  # Do not publish the mutable rendered copy; the verified original stays intact.
  python3 "$destination/tools/write-target.py" "$target_file"
  cat /proc/sys/kernel/random/boot_id >"$state/install-boot-id"
fi
export TARGET_IPV4 TARGET_FQDN TARGET_INTERFACE TARGET_SSH_PORT TARGET_DEVICE_LIMIT TARGET_REALITY_SNI TARGET_LABEL ACME_EMAIL
runtime="$state/bundle"
if [[ ! -d $runtime ]]; then
  rendered_stage=$(mktemp -d "$state/rendered.XXXXXXXX")
  cp -a -- "$destination/bundle/." "$rendered_stage/"
  python3 "$destination/tools/render.py" "$rendered_stage"
  mv -T -- "$rendered_stage" "$runtime"
fi
[[ ! -L $runtime && $(stat -c '%U:%G:%a' "$runtime") == root:root:700 ]] || die 'Небезопасный runtime bundle'
(cd -- "$runtime"; sha256sum --check --strict SOURCE_SHA256SUMS >/dev/null)
phase() {
  local name=$1; shift
  if [[ -f $state/$name.done ]]; then printf '✓ %s (уже завершено)\n' "$name"; return; fi
  printf '\n→ %s\n' "$name"
  # Private phase logs may contain intermediate paths or application output.
  # Never print their contents automatically after a failure.
  if "$@" >"$state/$name.log" 2>&1; then
    date -u +%FT%TZ >"$state/$name.done"
    printf '✓ %s\n' "$name"
  else
    printf 'Этап %s остановлен. Закрытый журнал: %s/%s.log\nПосле диагностики: bash /opt/vpn-installer/install.sh --resume\n' "$name" "$state" "$name" >&2
    exit 1
  fi
}
phase base bash "$runtime/base/install-pinned-base.sh" --apply
phase tls bash "$runtime/base/acme.sh" --apply
phase direct bash "$runtime/scripts/configure-standalone.sh" --apply
phase panel bash "$runtime/scripts/expose-panel-https.sh" --apply
phase warp bash "$runtime/warp-egress/scripts/install-warp.sh"
phase dual env CONFIRM_STANDALONE_DUAL_EGRESS="ENABLE-WARP-AND-DIRECT-$TARGET_IPV4" bash "$runtime/scripts/enable-dual-egress.sh" --apply
if [[ ! -f $state/xhttp.done && -f /etc/germanyvpn-xhttp-test/promotion.json ]]; then
  # A process may have exited after committing the transaction, before the
  # outer phase marker was written. Accept only a fully verified committed state.
  phase xhttp python3 "$runtime/scripts/finalize-xhttp.py" --verify
else
  phase xhttp env CONFIRM_FRESH_XHTTP=FINALIZE-FRESH-XHTTP python3 "$runtime/scripts/finalize-xhttp.py" --apply
fi
phase renewal certbot renew --dry-run --run-deploy-hooks
# Always recheck live state, including a resume after a later phase failed.
printf '\n→ verify\n'
if ! bash "$destination/tools/verify.sh" >"$state/verify.log" 2>&1; then
  die "Проверка сервера остановлена; закрытый журнал $state/verify.log"
fi
date -u +%FT%TZ >"$state/verify.done"
printf '\nVPN установлен. Сохраните данные:\n\n'
cat /etc/krysyuk-standalone/access.env
printf '\nПовторный вывод: bash /opt/vpn-installer/install.sh --show-access\n'
printf 'После reboot: bash /opt/vpn-installer/install.sh --verify\n'
printf 'Проверку скорости и импорт в приложения выполните со своего подключения.\n'
