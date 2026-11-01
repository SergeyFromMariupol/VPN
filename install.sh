#!/usr/bin/env bash
# VPN installer for a clean Ubuntu 24.04 amd64 VPS.
set -Eeuo pipefail
umask 077
# Keep parsed command output stable even in a translated root session.
export LC_ALL=C LANG=C LANGUAGE=C
unset PYTHONOPTIMIZE PYTHONPATH PYTHONHOME PYTHONUSERBASE PYTHONSTARTUP PYTHONINSPECT
unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY
readonly repository='SergeyFromMariupol/VPN'
readonly release='v1.2.7'
readonly state='/var/lib/vpn-installer'
readonly destination='/opt/vpn-installer'
readonly target_file='/etc/germanyvpn-target.env'
mode=${1:-install}
case "$mode" in install|--resume|--show-access|--verify|--diagnose|--help) ;; *)
  printf '%s\n' 'Неизвестный параметр запуска.' '' 'Справка — скопируйте и выполните команду целиком:' '' \
    'bash <(curl -fsSL https://raw.githubusercontent.com/SergeyFromMariupol/VPN/main/install.sh) --help' >&2
  exit 2;;
esac

installer_success() {
  local green='' reset=''
  if [[ -t 1 && ${TERM:-dumb} != dumb && -z ${NO_COLOR+x} ]]; then
    green=$'\033[1;32m' reset=$'\033[0m'
  fi
  printf '\n%s✓ %s%s\n' "$green" "$1" "$reset"
}

if [[ $mode == --help ]]; then
  printf '%s\n' 'VPN — Ubuntu 24.04 amd64' '' \
    'Новая установка:' '' \
    'bash <(curl -fsSL https://raw.githubusercontent.com/SergeyFromMariupol/VPN/main/install.sh)' '' \
    'Продолжить прерванную установку:' '' \
    'bash /opt/vpn-installer/install.sh --resume' '' \
    'Показать данные панели и ссылку подписки:' '' \
    'bash /opt/vpn-installer/install.sh --show-access' '' \
    'Проверить установленный VPN:' '' \
    'bash /opt/vpn-installer/install.sh --verify' '' \
    'Показать безопасное пояснение ошибок без изменения сервера:' '' \
    'bash /opt/vpn-installer/install.sh --diagnose'
  exit 0
fi

installer_resume_hint_shown=0
installer_resume_hint() {
  installer_resume_hint_shown=1
  printf '\nСкопируйте и выполните команду целиком, чтобы продолжить установку:\n\nbash %q --resume\n\n' \
    "$destination/install.sh" >&2 || :
}

installer_resume_ready() {
  local path permissions
  for path in "$state" "$destination"; do
    [[ -d $path && ! -L $path && $(stat -c '%u:%g:%a' "$path" 2>/dev/null) == 0:0:700 ]] || return 1
  done
  [[ -f $target_file && ! -L $target_file &&
     $(stat -c '%u:%g:%a:%h' "$target_file" 2>/dev/null) == 0:0:600:1 ]] || return 1
  path="$destination/install.sh"
  [[ -f $path && ! -L $path && $(stat -c '%u:%h' "$path" 2>/dev/null) == 0:1 ]] || return 1
  permissions=$(stat -c %a "$path" 2>/dev/null) || return 1
  [[ $permissions =~ ^[0-7]{3,4}$ ]] || return 1
  (( (8#$permissions & 8#022) == 0 ))
}

installer_error_stage=startup
installer_error_log=''
installer_error_log_before=''
installer_error_code=''
installer_error_reporter=''
installer_cleanup_registered=0

installer_error_context() {
  installer_error_stage=$1
  installer_error_log=${2-}
  installer_error_log_before=''
  installer_error_code=''
  if [[ -n $installer_error_log && -f $installer_error_log && ! -L $installer_error_log ]]; then
    installer_error_log_before=$(stat -c '%d:%i:%y:%z:%s' "$installer_error_log" 2>/dev/null) || :
  fi
}

installer_report_failure() {
  local status=$1 identity=''
  local -a arguments=(--stage "$installer_error_stage" --status "$status" --destination "$destination")
  [[ -n $installer_error_reporter && -f $installer_error_reporter && ! -L $installer_error_reporter ]] || return 1
  [[ -z $installer_error_code ]] || arguments+=(--code "$installer_error_code")
  if [[ -n $installer_error_log && -f $installer_error_log && ! -L $installer_error_log ]]; then
    identity=$(stat -c '%d:%i:%y:%z:%s' "$installer_error_log" 2>/dev/null) || identity=''
    # A cancellation before the child starts must not reuse an older failure.
    if [[ -n $identity && $identity != "$installer_error_log_before" ]]; then
      arguments+=(--log "$installer_error_log")
    fi
  fi
  if installer_resume_ready; then arguments+=(--can-resume); fi
  python3 -I -B "$installer_error_reporter" "${arguments[@]}" >&2 2>/dev/null || return 1
  installer_resume_hint_shown=1
}

installer_native_failure() {
  local status=$1
  printf '\nУстановка остановлена (код %s).\n' "$status" >&2
  case $installer_error_code in
    SOURCE_DOWNLOAD)
      printf 'Что произошло: не удалось загрузить проверенный архив с GitHub.\nКак исправить: проверьте DNS и исходящий доступ сервера к GitHub, затем повторите полную команду запуска:\n\nbash <(curl -fsSL https://raw.githubusercontent.com/SergeyFromMariupol/VPN/main/install.sh)\n' >&2;;
    SOURCE_INTEGRITY|STATE_UNSAFE|BOOTSTRAP_RECOVERY)
      printf 'Что произошло: целостность файлов или восстановление состояния не подтверждены.\nКак исправить: сохраните файлы и снимки. Восстановите проверенные исходники из снимка; не обходите проверку хешей. Команда проверки метаданных:\n\nstat -- %q %q %q\n' "$destination" "$state" "$target_file" >&2;;
    *)
      if [[ $status == 129 || $status == 130 || $status == 143 ]]; then
        printf 'Что произошло: установка была прервана сигналом.\n' >&2
      else
        printf 'Что произошло: точная причина не определена; модуль пояснений недоступен.\n' >&2
      fi
      printf 'Как исправить: сохраните состояние. Модуль пояснений требует проверки или восстановления из проверенного снимка. Команда проверки метаданных:\n\nstat -- %q %q %q\n' "$destination" "$state" "$target_file" >&2;;
  esac
  installer_resume_hint_shown=1
}

die() {
  printf 'ОШИБКА: %s\n' "$*" >&2
  case "$*" in
    *'Ubuntu 24.04'*|*'информация об ОС'*) installer_error_code=OS_UNSUPPORTED;;
    'Запустите от root:'*) installer_error_code=ROOT_REQUIRED;;
    'Не найдена команда '*) installer_error_code=COMMAND_MISSING;;
    *'systemd'*) installer_error_code=NO_SYSTEMD;;
    'Другая установка уже выполняется') installer_error_code=INSTALL_BUSY;;
    *'manifest'*|*'исходного кода не пройдена') installer_error_code=SOURCE_INTEGRITY;;
    *'безопасн'*|*'Небезопасн'*) installer_error_code=STATE_UNSAFE;;
  esac
  if (( !installer_cleanup_registered )); then
    case $installer_error_code in
      ROOT_REQUIRED)
        printf '\nКак исправить: войдите от root либо выполните команду целиком:\n\nsudo bash -c %q\n' \
          'bash <(curl -fsSL https://raw.githubusercontent.com/SergeyFromMariupol/VPN/main/install.sh)' >&2;;
      OS_UNSUPPORTED|NO_SYSTEMD)
        printf '\nКак исправить: используйте чистый VPS/VM с Ubuntu 24.04 LTS amd64 и systemd.\n' >&2;;
      INSTALL_BUSY)
        printf '\nКак исправить: дождитесь окончания первого запуска. Файл блокировки удалять не нужно.\n' >&2;;
      STATE_UNSAFE|SOURCE_INTEGRITY)
        printf '\nКак исправить: сохраните файлы и снимки для диагностики. Не удаляйте состояние установки и не обходите проверку целостности.\n' >&2;;
      *)
        printf '\nКак исправить: проверьте полноту образа Ubuntu 24.04 и доступность системных команд. Выполните справку командой целиком:\n\nbash <(curl -fsSL https://raw.githubusercontent.com/SergeyFromMariupol/VPN/main/install.sh) --help\n' >&2;;
    esac
  fi
  exit 1
}
[[ $EUID == 0 ]] || die 'Запустите от root: sudo bash install.sh'
if [[ $mode == --show-access ]]; then
  [[ -f /etc/krysyuk-standalone/access.env && ! -L /etc/krysyuk-standalone/access.env ]] || die 'VPN ещё не установлен'
  cat /etc/krysyuk-standalone/access.env
  exit 0
fi
# Resume belongs to the installed release. A newer downloaded entrypoint must
# not combine its new phase list with an older rendered runtime, nor require a
# network download before continuing a complete local source installation.
if [[ $mode == --resume || $mode == --verify || $mode == --diagnose ]]; then
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
    exec bash "$destination/install.sh" "$mode"
  fi
fi
if [[ $mode == --diagnose ]]; then
  (cd -- "$destination"; sha256sum --check --strict SHA256SUMS >/dev/null) || die 'Проверка установленного исходного кода не пройдена'
  exec python3 -I -B "$destination/tools/errors.py" --diagnose --state "$state" --destination "$destination"
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
  if declare -F installer_progress_stop >/dev/null; then installer_progress_stop || :; fi
  if declare -F cleanup_installation_bootstrap >/dev/null; then
    cleanup_installation_bootstrap || { installer_error_code=BOOTSTRAP_RECOVERY; ((rc)) || rc=1; }
  fi
  if ((rc != 0 && installer_resume_hint_shown == 0)); then
    installer_report_failure "$rc" || installer_native_failure "$rc" || :
  fi
  rm -rf -- "$task_stage"
  # Recovery guidance must not alter the original failure/signal result. Before
  # bootstrap commits durable source/settings there is nothing safe to resume.
  if ((rc != 0 && installer_resume_hint_shown == 0)) && installer_resume_ready; then
    installer_resume_hint
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
installer_cleanup_registered=1
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
if [[ ! -f $source_dir/tools/preflight.py ]]; then
  installer_error_context download "$task_stage/download.log"
  installer_error_code=SOURCE_DOWNLOAD
  printf 'Загрузка VPN %s…\n' "$release"
  if command -v curl >/dev/null; then
    curl --disable --proto '=https' --tlsv1.2 -fsSL --retry 2 --connect-timeout 15 --max-time 300 \
      "https://github.com/$repository/archive/refs/tags/$release.tar.gz" -o "$task_stage/source.tar.gz" 2>"$task_stage/download.log"
  else
    # Ubuntu already needs Python for the installer. Fetch source with its
    # trusted HTTPS client rather than installing curl before the questions.
    python3 - "https://github.com/$repository/archive/refs/tags/$release.tar.gz" "$task_stage/source.tar.gz" 2>"$task_stage/download.log" <<'PY'
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
installer_error_context source "$task_stage/source-check.log"
installer_error_code=SOURCE_INTEGRITY
(cd -- "$source_dir"; sha256sum --check --strict SHA256SUMS >"$task_stage/source-check.log" 2>&1)
installer_error_reporter="$source_dir/tools/errors.py"
installer_error_code=''
source "$source_dir/tools/bootstrap.sh"
source "$source_dir/tools/progress.sh"
installer_progress_init "$task_stage" "$source_dir/tools/progress.py" || :
if [[ $mode == --verify ]]; then
  installer_resume_ready || die 'Небезопасное или неполное состояние для проверки VPN'
  TARGET_TLS_MODE=letsencrypt
  source "$target_file"
  [[ $TARGET_TLS_MODE == letsencrypt || $TARGET_TLS_MODE == none ]] || die 'Небезопасный режим сертификата'
  export TARGET_TLS_MODE
  if [[ -e $state/verify-command.log || -L $state/verify-command.log ]]; then
    [[ -f $state/verify-command.log && ! -L $state/verify-command.log &&
       $(stat -c '%u:%g:%a:%h' "$state/verify-command.log") == 0:0:600:1 ]] || die 'Небезопасный журнал проверки VPN'
  fi
  installer_error_context verify "$state/verify-command.log"
  bash "$destination/tools/verify.sh" >"$state/verify-command.log" 2>&1
  installer_success 'Проверка установленного VPN пройдена.'
  exit 0
fi
if [[ $mode == --resume ]]; then
  [[ -d $state && ! -L $state && $(stat -c '%U:%G:%a' "$state") == root:root:700 ]] || die 'Нет безопасного состояния для продолжения'
  [[ -f $target_file && ! -L $target_file && $(stat -c '%U:%G:%a' "$target_file") == root:root:600 ]] || die 'Небезопасный target env'
  # Old saved installations predate this setting. Never inherit a conflicting
  # certificate mode from the caller when the saved file has no such key.
  TARGET_TLS_MODE=letsencrypt
  source "$target_file"
  [[ -f $destination/SHA256SUMS ]] || die 'Отсутствует установленный bundle'
  (cd -- "$destination"; sha256sum --check --strict SHA256SUMS >/dev/null)
else
  if [[ -e $state || -L $state || -e $destination || -L $destination || -e $target_file || -L $target_file ]]; then
    printf 'Обнаружена предыдущая установка VPN.\n' >&2
    printf 'Продолжение использует сохранённые настройки. Режим сертификата выбирается при новой установке.\n' >&2
    installer_resume_hint
    exit 1
  fi
  [[ -r /dev/tty ]] || die 'Нужен интерактивный терминал для параметров установки'
  source "$source_dir/tools/wizard.sh"
  collect_vpn_parameters "$release" "$source_dir/tools/preflight.py"
  export TARGET_ADDRESS_MODE TARGET_TLS_MODE TARGET_FQDN ACME_EMAIL TARGET_LABEL TARGET_REALITY_SNI TARGET_DEVICE_LIMIT TARGET_IPV4 TARGET_SSH_PORT TARGET_INTERFACE
  # After the last answer, validate inputs and the host before publishing any
  # persistent state. No extra confirmation or interactive gate follows.
  installer_error_context preflight "$task_stage/preflight-error.txt"
  python3 -B "$source_dir/tools/preflight.py" --inputs-only >/dev/null 2>"$task_stage/preflight-error.txt"
  wizard_section 'Установка' 'Автоматический запуск'
  installer_error_context preflight "$task_stage/preflight-error.txt"
  installer_progress_begin preflight || :
  if python3 "$source_dir/tools/preflight.py" >"$task_stage/inventory.txt" 2>"$task_stage/preflight-error.txt"; then
    installer_progress_end preflight 0 || :
  else
    preflight_status=$?
    installer_progress_end preflight 1 || :
    exit "$preflight_status"
  fi
  installer_error_context bootstrap "$task_stage/bootstrap.log"
  installer_progress_begin bootstrap || :
  prepare_installation_bootstrap >"$task_stage/bootstrap.log" 2>&1
  installer_progress_end bootstrap 0 || :
fi
TARGET_ADDRESS_MODE=${TARGET_ADDRESS_MODE:-domain}
TARGET_TLS_MODE=${TARGET_TLS_MODE:-letsencrypt}
[[ $TARGET_TLS_MODE == letsencrypt || $TARGET_TLS_MODE == none ]] || die 'Небезопасный режим сертификата'
export TARGET_ADDRESS_MODE TARGET_TLS_MODE TARGET_IPV4 TARGET_FQDN TARGET_INTERFACE TARGET_SSH_PORT TARGET_DEVICE_LIMIT TARGET_REALITY_SNI TARGET_LABEL ACME_EMAIL
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
installer_error_context base "$state/base.log"
phase base bash "$runtime/base/install-pinned-base.sh" --apply
if [[ $TARGET_TLS_MODE == letsencrypt ]]; then
  installer_error_context certbot "$state/certbot.log"
  phase certbot bash "$runtime/base/install-certbot.sh" --apply
  installer_error_context certbot "$state/certbot-check.log"
  bash "$runtime/base/install-certbot.sh" --check-only >"$state/certbot-check.log" 2>&1
  installer_error_context tls "$state/tls.log"
  phase tls bash "$runtime/base/acme.sh" --apply
fi
installer_error_context direct "$state/direct.log"
phase direct bash "$runtime/scripts/configure-standalone.sh" --apply
installer_error_context panel "$state/panel.log"
phase panel bash "$runtime/scripts/expose-panel-https.sh" --apply
installer_error_context nginx-restart "$state/nginx-restart.log"
phase nginx-restart bash "$runtime/base/install-nginx-restart.sh" --apply
if [[ $TARGET_TLS_MODE == letsencrypt ]]; then
  installer_error_context cert-reconcile "$state/cert-reconcile.log"
  phase cert-reconcile bash "$runtime/base/install-cert-reconcile.sh" --apply
fi
installer_error_context warp "$state/warp.log"
phase warp bash "$runtime/warp-egress/scripts/install-warp.sh"
installer_error_context dual "$state/dual.log"
phase dual env CONFIRM_STANDALONE_DUAL_EGRESS="ENABLE-WARP-AND-DIRECT-$TARGET_IPV4" bash "$runtime/scripts/enable-dual-egress.sh" --apply
installer_error_context xhttp "$state/xhttp.log"
if [[ ! -f $state/xhttp.done && -f /etc/germanyvpn-xhttp-test/promotion.json ]]; then
  # A process may have exited after committing the transaction, before the
  # outer phase marker was written. Accept only a fully verified committed state.
  phase xhttp python3 "$runtime/scripts/finalize-xhttp.py" --verify
else
  phase xhttp env CONFIRM_FRESH_XHTTP=FINALIZE-FRESH-XHTTP python3 "$runtime/scripts/finalize-xhttp.py" --apply
fi
# The production timer keeps Certbot's random spread; an interactive install
# should run its one acceptance renewal immediately.
if [[ $TARGET_TLS_MODE == letsencrypt ]]; then
  installer_error_context renewal "$state/renewal.log"
  phase renewal certbot renew --non-interactive --dry-run --run-deploy-hooks --no-random-sleep-on-renew
fi
# Always recheck live state, including a resume after a later phase failed.
installer_error_context verify "$state/verify.log"
phase --always verify bash "$destination/tools/verify.sh"
installer_success 'VPN успешно установлен!'
printf '\nСохраните данные доступа:\n\n'
cat /etc/krysyuk-standalone/access.env
printf '\nЧтобы снова показать эти данные, выполните команду целиком:\n\nbash /opt/vpn-installer/install.sh --show-access\n'
printf '\nДля проверки VPN после перезагрузки выполните команду целиком:\n\nbash /opt/vpn-installer/install.sh --verify\n\n'
printf 'Проверку скорости и импорт в приложения выполните со своего подключения.\n'
