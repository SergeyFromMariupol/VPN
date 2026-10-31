#!/usr/bin/env bash
# Install an independent retry for a Certbot deploy hook that failed after
# Certbot had already committed a renewed certificate.
set -Eeuo pipefail
umask 077
[[ $# == 1 && ($1 == --apply || $1 == --check-only) ]] || exit 2
[[ $EUID == 0 ]] || exit 1
source_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=../scripts/target-contract.sh
source "$source_root/../scripts/target-contract.sh"
readonly service=/etc/systemd/system/vpn-cert-reconcile.service
readonly timer=/etc/systemd/system/vpn-cert-reconcile.timer
readonly hook=/etc/letsencrypt/renewal-hooks/deploy/60-krysyuk-standalone-xui
readonly root=/etc/krysyuk-standalone
readonly marker="$root/tls-deployed.sha256"
readonly lineage="/etc/letsencrypt/live/$TARGET_FQDN"
readonly service_source="$source_root/../templates/vpn-cert-reconcile.service"
readonly timer_source="$source_root/../templates/vpn-cert-reconcile.timer"
for name in bash basename cmp dirname flock install mktemp mv openssl rmdir sha256sum stat systemctl tar; do command -v "$name" >/dev/null; done
for path in "$service_source" "$timer_source"; do [[ -f $path && ! -L $path ]] || exit 1; done
[[ -f $hook && ! -L $hook && $(stat -c '%u:%g:%a:%h' "$hook") == 0:0:750:1 ]] || exit 1
[[ -d $root && ! -L $root && -L $root/tls ]] || exit 1
systemctl is-active --quiet x-ui.service
systemctl is-active --quiet nginx.service
systemctl is-active --quiet certbot.timer
! systemctl is-active --quiet certbot.service

expected_hash=$(sha256sum "$lineage/fullchain.pem"); expected_hash=${expected_hash%% *}
[[ $expected_hash =~ ^[a-f0-9]{64}$ ]] || exit 1
verify_runtime() {
  local cert_pub key_pub
  verify_target_certificate "$lineage/fullchain.pem"
  cmp -s "$lineage/fullchain.pem" "$root/tls/fullchain.pem"
  cmp -s "$lineage/privkey.pem" "$root/tls/privkey.pem"
  [[ -f $marker && ! -L $marker && $(stat -c '%u:%g:%a:%h' "$marker") == 0:0:600:1 ]]
  [[ $(cat "$marker") == "$expected_hash" ]]
  cert_pub=$(openssl x509 -in "$lineage/fullchain.pem" -pubkey -noout | openssl sha256)
  key_pub=$(openssl pkey -in "$lineage/privkey.pem" -pubout | openssl sha256)
  [[ $cert_pub == "$key_pub" ]]
}
verify_units() {
  [[ -f $service && ! -L $service && $(stat -c '%u:%g:%a:%h' "$service") == 0:0:644:1 ]]
  [[ -f $timer && ! -L $timer && $(stat -c '%u:%g:%a:%h' "$timer") == 0:0:644:1 ]]
  cmp -s "$service_source" "$service"
  cmp -s "$timer_source" "$timer"
  [[ -z $(systemctl show -p DropInPaths --value vpn-cert-reconcile.service) ]]
  [[ -z $(systemctl show -p DropInPaths --value vpn-cert-reconcile.timer) ]]
  systemctl is-enabled --quiet vpn-cert-reconcile.timer
  systemctl is-active --quiet vpn-cert-reconcile.timer
}
if [[ $1 == --check-only ]]; then
  verify_units
  verify_runtime
  printf 'CERT_RECONCILE_OK=1\n'
  exit 0
fi
[[ ! -e $service && ! -L $service && ! -e $timer && ! -L $timer ]] || exit 1
[[ -z $(systemctl show -p DropInPaths --value vpn-cert-reconcile.service) ]] || exit 1
[[ -z $(systemctl show -p DropInPaths --value vpn-cert-reconcile.timer) ]] || exit 1
verify_target_certificate "$lineage/fullchain.pem"
cmp -s "$lineage/fullchain.pem" "$root/tls/fullchain.pem"
cmp -s "$lineage/privkey.pem" "$root/tls/privkey.pem"
backup=$(mktemp -d -p /var/backups "vpn-cert-reconcile-$(date -u +%Y%m%dT%H%M%SZ).XXXXXXXX")
chmod 0700 "$backup"
systemctl show certbot.service certbot.timer x-ui.service nginx.service >"$backup/units.before"
tar --acls --xattrs --numeric-owner -cpf "$backup/tls-before.tar" -C / etc/krysyuk-standalone etc/letsencrypt etc/nginx
tar -tf "$backup/tls-before.tar" >/dev/null
marker_existed=0
if [[ -e $marker || -L $marker ]]; then
  [[ -f $marker && ! -L $marker && $(stat -c '%u:%g:%a:%h' "$marker") == 0:0:600:1 ]] || exit 1
  cp -a -- "$marker" "$backup/marker.before"
  marker_existed=1
fi
snapshot_files=(units.before tls-before.tar)
if ((marker_existed)); then snapshot_files+=(marker.before); fi
(cd -- "$backup"; sha256sum -- "${snapshot_files[@]}" >SHA256SUMS; sha256sum -c SHA256SUMS >/dev/null)
committed=0
certbot_timer_stopped=0
unit_stage=''
unit_stage_identity=''
service_identity=''
timer_identity=''
owned_unit() {
  local identity=''
  case $1 in
    "$service") identity=$service_identity ;;
    "$timer") identity=$timer_identity ;;
    *) return 1 ;;
  esac
  [[ -n $identity && -f $1 && ! -L $1 && $(stat -c '%d:%i' "$1") == "$identity" ]]
}
publish_units() {
  unit_stage=$(mktemp -d -p "$(dirname -- "$service")" .vpn-cert-reconcile.XXXXXXXX)
  unit_stage_identity=$(stat -c '%d:%i' "$unit_stage")
  install -o root -g root -m 0644 "$service_source" "$unit_stage/service"
  install -o root -g root -m 0644 "$timer_source" "$unit_stage/timer"
  service_identity=$(stat -c '%d:%i' "$unit_stage/service")
  timer_identity=$(stat -c '%d:%i' "$unit_stage/timer")
  mv -nT -- "$unit_stage/service" "$service"
  owned_unit "$service"
  mv -nT -- "$unit_stage/timer" "$timer"
  owned_unit "$timer"
}
cleanup() {
  local status=$? rollback_ok=1 quiesced=1 path
  trap - EXIT INT TERM HUP
  set +e
  if ((committed == 0)); then
    if [[ -e $timer || -L $timer ]]; then
      if owned_unit "$timer"; then
        systemctl disable --now vpn-cert-reconcile.timer >/dev/null 2>&1 || rollback_ok=0
        if systemctl is-active --quiet vpn-cert-reconcile.timer; then rollback_ok=0; quiesced=0; fi
      else rollback_ok=0; quiesced=0; fi
    fi
    if [[ -e $service || -L $service ]]; then
      if owned_unit "$service"; then
        systemctl stop vpn-cert-reconcile.service >/dev/null 2>&1 || rollback_ok=0
        if systemctl is-active --quiet vpn-cert-reconcile.service; then rollback_ok=0; quiesced=0; fi
      else rollback_ok=0; quiesced=0; fi
    fi
    if ((quiesced)); then
    for path in "$service" "$timer"; do
      if [[ -e $path || -L $path ]]; then
        if owned_unit "$path"; then
          mv -T -- "$path" "$backup/$(basename -- "$path").failed" || rollback_ok=0
        else rollback_ok=0; fi
      fi
    done
    if ((marker_existed)); then
      install -o root -g root -m 0600 "$backup/marker.before" "$marker" || rollback_ok=0
    elif [[ -e $marker || -L $marker ]]; then
      if [[ -f $marker && ! -L $marker && $(cat "$marker") == "$expected_hash" ]]; then
        rm -f -- "$marker" || rollback_ok=0
      else rollback_ok=0; fi
    fi
    systemctl daemon-reload >/dev/null 2>&1 || rollback_ok=0
    fi
  fi
  if [[ -n $unit_stage && (-e $unit_stage || -L $unit_stage) ]]; then
    if [[ -d $unit_stage && ! -L $unit_stage &&
          $(stat -c '%d:%i' "$unit_stage") == "$unit_stage_identity" ]]; then
      if ((committed == 0)); then
        mv -T -- "$unit_stage" "$backup/units-staged.failed" || rollback_ok=0
      else rmdir -- "$unit_stage" || rollback_ok=0; fi
    else rollback_ok=0; fi
  fi
  if ((certbot_timer_stopped)); then
    systemctl start certbot.timer >/dev/null 2>&1 || rollback_ok=0
    systemctl is-active --quiet certbot.timer || rollback_ok=0
  fi
  if ((committed == 0)); then
    printf 'CERT_RECONCILE_ROLLBACK_OK=%s SNAPSHOT=%s\n' "$rollback_ok" "$backup" >&2
  fi
  ((rollback_ok)) || status=1
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP
certbot_timer_stopped=1
systemctl stop certbot.timer
! systemctl is-active --quiet certbot.service
publish_units
systemctl daemon-reload
systemctl start vpn-cert-reconcile.service
verify_runtime
systemctl enable --now vpn-cert-reconcile.timer >/dev/null
systemctl start certbot.timer
certbot_timer_stopped=0
verify_units
touch "$backup/COMMITTED"
committed=1
printf 'CERT_RECONCILE_INSTALLED=1 SNAPSHOT=%s\n' "$backup"
