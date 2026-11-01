#!/usr/bin/env bash
# VPN installer for a clean Ubuntu 24.04 amd64 VPS.
set -Eeuo pipefail
umask 077
# Keep parsed command output stable even in a translated root session.
export LC_ALL=C LANG=C LANGUAGE=C
unset PYTHONOPTIMIZE PYTHONPATH PYTHONHOME PYTHONUSERBASE PYTHONSTARTUP PYTHONINSPECT
unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY
readonly repository='SergeyFromMariupol/VPN'
readonly release='v1.2.1'
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
for cmd in python3 tar sha256sum ip openssl timeout; do command -v "$cmd" >/dev/null || die "Не найдена команда $cmd"; done
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
  if command -v curl >/dev/null; then
    curl --disable --proto '=https' --tlsv1.2 -fsSL --retry 2 --connect-timeout 15 --max-time 300 \
      "https://github.com/$repository/archive/refs/tags/$release.tar.gz" -o "$task_stage/source.tar.gz"
  else
    # Ubuntu already needs Python for the installer. Fetch source with its
    # trusted HTTPS client rather than installing curl before the questions.
    python3 - "https://github.com/$repository/archive/refs/tags/$release.tar.gz" "$task_stage/source.tar.gz" <<'PY'
import sys, time, urllib.parse, urllib.request
class HTTPSOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != 'https':
            raise ValueError('HTTPS source redirect required')
        return super().redirect_request(request, fp, code, msg, headers, newurl)
deadline = time.monotonic() + 300
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), HTTPSOnlyRedirectHandler())
with opener.open(sys.argv[1], timeout=30) as response, open(sys.argv[2], 'xb') as output:
    if not response.geturl().startswith('https://'):
        raise ValueError('HTTPS source required')
    size = 0
    while True:
        if time.monotonic() >= deadline:
            raise TimeoutError('Source download deadline exceeded')
        chunk = response.read1(65536)
        if time.monotonic() >= deadline:
            raise TimeoutError('Source download deadline exceeded')
        if not chunk:
            break
        size += len(chunk)
        if size > 32 * 1024 * 1024:
            raise ValueError('Source archive exceeds size limit')
        output.write(chunk)
PY
  fi
  # Reject traversal, links, devices and multiple archive roots before extraction.
  python3 - "$task_stage/source.tar.gz" <<'PY'
import sys, tarfile
from pathlib import PurePosixPath
with tarfile.open(sys.argv[1]) as archive:
    roots = set()
    for member in archive:
        path = PurePosixPath(member.name)
        if path.is_absolute() or '..' in path.parts:
            raise ValueError('Unsafe archive member path')
        if not (member.isfile() or member.isdir()):
            raise ValueError('Only regular files and directories are allowed')
        roots.add(path.parts[0])
    if len(roots) != 1:
        raise ValueError('Expected exactly one archive root')
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
  source "$source_dir/tools/wizard.sh"
  collect_vpn_parameters "$release" "$source_dir/tools/preflight.py"
  export TARGET_ADDRESS_MODE TARGET_FQDN ACME_EMAIL TARGET_LABEL TARGET_REALITY_SNI TARGET_DEVICE_LIMIT TARGET_IPV4 TARGET_SSH_PORT TARGET_INTERFACE
  # After the last answer, validate inputs and the host before publishing any
  # persistent state. No extra confirmation or interactive gate follows.
  python3 -B "$source_dir/tools/preflight.py" --inputs-only >/dev/null
  wizard_section 'Установка' 'Автоматический запуск'
  printf 'Проверка чистого сервера, адреса и TLS…\n'
  python3 "$source_dir/tools/preflight.py" | tee "$task_stage/inventory.txt"
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
phase renewal certbot renew --non-interactive --dry-run --run-deploy-hooks --no-random-sleep-on-renew
# Always recheck live state, including a resume after a later phase failed.
phase --always verify bash "$destination/tools/verify.sh"
printf '\nVPN установлен. Сохраните данные:\n\n'
cat /etc/krysyuk-standalone/access.env
printf '\nПовторный вывод: bash /opt/vpn-installer/install.sh --show-access\n'
printf 'После reboot: bash /opt/vpn-installer/install.sh --verify\n'
printf 'Проверку скорости и импорт в приложения выполните со своего подключения.\n'
