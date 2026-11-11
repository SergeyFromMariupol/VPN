#!/usr/bin/env bash
# Publish only the fixed launcher; all actions validate the installed source.
set -Eeuo pipefail
umask 077
[[ $# == 1 && ($1 == --apply || $1 == --check-only) ]] || exit 2
[[ $EUID == 0 ]] || exit 1
readonly launcher=/usr/local/sbin/vpn
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
launcher_content() {
  cat <<'VPN'
#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C LANG=C LANGUAGE=C
readonly destination=/opt/vpn-installer
[[ $EUID == 0 ]] || { printf 'Запустите от root: sudo vpn\n' >&2; exit 1; }
[[ -d $destination && ! -L $destination && $(stat -c '%u:%g:%a' "$destination") == 0:0:700 ]] || exit 1
[[ -f $destination/tools/manage.sh && ! -L $destination/tools/manage.sh &&
   $(stat -c '%u:%g:%h' "$destination/tools/manage.sh") == 0:0:1 ]] || exit 1
(( (8#$(stat -c '%a' "$destination/tools/manage.sh") & 8#022) == 0 )) || exit 1
[[ -f $destination/SHA256SUMS && ! -L $destination/SHA256SUMS &&
   -z $(find "$destination" \( -type l -o ! -user root -o ! -group root -o -perm /022 \) -print -quit) ]] || exit 1
grep -Eq '^[0-9a-f]{64}  tools/manage[.]sh$' "$destination/SHA256SUMS" || exit 1
(cd -- "$destination"; sha256sum --check --strict SHA256SUMS >/dev/null 2>&1) || exit 1
exec bash "$destination/tools/manage.sh" "$@"
VPN
}
verify_launcher() {
  [[ -f $launcher && ! -L $launcher && $(stat -c '%u:%g:%a:%h' "$launcher") == 0:0:755:1 ]] &&
    cmp -s "$launcher" <(launcher_content)
}
if [[ $1 == --check-only ]]; then
  verify_launcher || die 'VPN menu launcher differs from the managed source'
  printf 'VPN_MENU_OK=1\n'
  exit 0
fi
[[ -d /usr/local/sbin && ! -L /usr/local/sbin && $(stat -c '%u:%g' /usr/local/sbin) == 0:0 ]] || die 'unsafe launcher directory'
(( (8#$(stat -c '%a' /usr/local/sbin) & 8#022) == 0 )) || die 'launcher directory is writable by other users'
if [[ -e $launcher || -L $launcher ]]; then
  verify_launcher || die 'existing vpn command is not the managed launcher'
  printf 'VPN_MENU_OK=1\n'
  exit 0
fi
stage=$(mktemp /usr/local/sbin/.vpn.XXXXXXXX)
owned_inode=$(stat -c '%d:%i' "$stage")
committed=0
cleanup() {
  local status=$?
  trap - EXIT HUP INT TERM
  if (( !committed )) && [[ -f $launcher && ! -L $launcher && $(stat -c '%d:%i' "$launcher") == "$owned_inode" ]]; then
    rm -f -- "$launcher"
  fi
  if [[ -f $stage && ! -L $stage && $(stat -c '%d:%i' "$stage") == "$owned_inode" ]]; then rm -f -- "$stage"; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM
launcher_content >"$stage"
chmod 0755 "$stage"
mv -nT -- "$stage" "$launcher"
[[ ! -e $stage && ! -L $stage && $(stat -c '%d:%i' "$launcher") == "$owned_inode" ]] || die 'launcher destination was claimed by another owner'
verify_launcher || die 'launcher readback failed'
committed=1
printf 'VPN_MENU_INSTALLED=1\n'
