#!/usr/bin/env bash
# Exercise the reviewed policy on a disposable sleep service, never host Nginx.
set -Eeuo pipefail
umask 077
[[ $EUID == 0 && ${GITHUB_ACTIONS:-} == true && ${CI:-} == true ]] || {
  printf 'This isolated systemd fixture requires the root GitHub Actions job.\n' >&2
  exit 1
}
[[ $(ps -p 1 -o comm=) == systemd ]] || exit 1
for name in cat cmp date dirname install mktemp ps rm rmdir sleep stat systemctl; do command -v "$name" >/dev/null; done
script_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
policy="$script_root/../templates/30-vpn-nginx-restart.conf"
[[ -f $policy && ! -L $policy ]] || exit 1
stage=$(mktemp -d /run/vpn-nginx-policy-fixture.XXXXXXXX)
unit="${stage##*/}.service"
unit_path="/run/systemd/system/$unit"
dropin_dir="$unit_path.d"
[[ ! -e $unit_path && ! -L $unit_path && ! -e $dropin_dir && ! -L $dropin_dir ]] || exit 1
cleanup() {
  local status=$?
  trap - EXIT INT TERM HUP
  set +e
  systemctl stop "$unit" >/dev/null 2>&1 || true
  # These exact paths were created only by this fixture. Preserve foreign edits.
  if [[ -f $dropin_dir/30-vpn-nginx-restart.conf && ! -L $dropin_dir/30-vpn-nginx-restart.conf ]] &&
     cmp -s "$policy" "$dropin_dir/30-vpn-nginx-restart.conf"; then
    rm -f -- "$dropin_dir/30-vpn-nginx-restart.conf" || status=1
  fi
  if [[ -f $unit_path && ! -L $unit_path ]] && cmp -s "$stage/service" "$unit_path"; then
    rm -f -- "$unit_path" || status=1
  fi
  rmdir -- "$dropin_dir" 2>/dev/null || status=1
  systemctl daemon-reload >/dev/null 2>&1 || status=1
  systemctl reset-failed "$unit" >/dev/null 2>&1 || true
  rm -f -- "$stage/service"
  rmdir -- "$stage" || status=1
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP
cat >"$stage/service" <<'UNIT'
[Unit]
Description=Disposable VPN Nginx restart-policy fixture
[Service]
Type=simple
ExecStart=/usr/bin/sleep infinity
UNIT
install -m 0644 "$stage/service" "$unit_path"
install -d -m 0755 "$dropin_dir"
install -m 0644 "$policy" "$dropin_dir/30-vpn-nginx-restart.conf"
systemctl daemon-reload
[[ $(systemctl show "$unit" -p Restart --value) == on-failure ]]
[[ $(systemctl show "$unit" -p RestartUSec --value) == 5s ]]
[[ $(systemctl show "$unit" -p StartLimitIntervalUSec --value) == 0 ]]
systemctl start "$unit"
before=$(systemctl show "$unit" -p MainPID --value)
[[ $before =~ ^[1-9][0-9]*$ ]]
systemctl kill --kill-whom=main --signal=SIGKILL "$unit"
recovered=0
for ((attempt=0; attempt<20; attempt++)); do
  after=$(systemctl show "$unit" -p MainPID --value)
  if [[ $after =~ ^[1-9][0-9]*$ && $after != "$before" ]] && systemctl is-active --quiet "$unit"; then
    recovered=1; break
  fi
  sleep 1
done
((recovered))
[[ $(systemctl show "$unit" -p NRestarts --value) == 1 ]]
systemctl stop "$unit"
sleep 6
! systemctl is-active --quiet "$unit"
[[ $(systemctl show "$unit" -p MainPID --value) == 0 ]]
printf 'NGINX_RESTART_POLICY_CRASH_AND_STOP_FIXTURE_OK=1\n'
