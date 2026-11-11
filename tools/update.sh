#!/usr/bin/env bash
# Compatible source-only update. The caller must release its installer lock.
set -Eeuo pipefail
umask 077
export LC_ALL=C LANG=C LANGUAGE=C
unset PYTHONOPTIMIZE PYTHONPATH PYTHONHOME PYTHONUSERBASE PYTHONSTARTUP PYTHONINSPECT
unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY
[[ $EUID == 0 ]] || { printf 'VPN_UPDATE_ERROR=ROOT_REQUIRED\n' >&2; exit 1; }
case ${1:-} in
  --apply) [[ $# == 2 ]] || exit 2;;
  --recover) [[ $# == 1 ]] || exit 2;;
  *) printf 'Usage: update.sh --apply CANDIDATE_DIR | --recover\n' >&2; exit 2;;
esac
script_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
[[ ! -L /run/vpn-installer.lock ]] || exit 1
exec 9>>/run/vpn-installer.lock
flock -n 9 || { printf 'VPN_UPDATE_ERROR=INSTALLER_BUSY\n' >&2; exit 1; }
exec python3 -I -B "$script_root/update.py" "$@"
