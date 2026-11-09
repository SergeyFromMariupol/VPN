#!/usr/bin/env bash
# ACME stage after pinned base and install-certbot.sh. Trusted certificates only.
set -Eeuo pipefail
umask 077
acme_fail() {
  printf 'VPN_ERROR_CODE=%s\n' "$1" >&2
  exit 1
}
source_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
readonly source_root
unit_is_quiescent() {
  local unit=$1 state
  state=$(systemctl show "$unit" -p LoadState -p ActiveState -p MainPID) || return 1
  state=$'\n'"$state"$'\n'
  [[ $state == *$'\nLoadState=loaded\n'* ]] || return 1
  case $unit in
    *.service)
      [[ $state == *$'\nMainPID=0\n'* &&
         ($state == *$'\nActiveState=inactive\n'* || $state == *$'\nActiveState=failed\n'*) ]] ;;
    *.timer) [[ $state == *$'\nActiveState=inactive\n'* ]] ;;
    *) return 1 ;;
  esac
}
source "$source_root/../scripts/target-contract.sh"
source "$source_root/acme-identifiers.sh"
mode=check
case ${1:---check-only} in
  --check-only) ;;
  --apply) mode=apply ;;
  --verify-committed) mode=verify-committed ;;
  *) exit 2 ;;
esac
[[ $EUID == 0 ]] || exit 1
for name in certbot cmp dig ip sqlite3 systemctl openssl tar ss flock sha256sum sync; do command -v "$name" >/dev/null; done
"$source_root/install-certbot.sh" --check-only
[[ $(command -v certbot) == /usr/local/bin/certbot ]] || { printf 'ERROR: unexpected Certbot command\n' >&2; exit 1; }
readonly commit_marker=/etc/letsencrypt/.vpn-acme-bootstrap-commit
readonly lineage="/etc/letsencrypt/live/$TARGET_FQDN"
acme_commit_payload() {
  local fullchain_hash cert_hash key_hash
  fullchain_hash=$(sha256sum "$lineage/fullchain.pem"); fullchain_hash=${fullchain_hash%% *}
  cert_hash=$(sha256sum "$lineage/cert.pem"); cert_hash=${cert_hash%% *}
  key_hash=$(sha256sum "$lineage/privkey.pem"); key_hash=${key_hash%% *}
  [[ $fullchain_hash =~ ^[a-f0-9]{64}$ && $cert_hash =~ ^[a-f0-9]{64}$ &&
     $key_hash =~ ^[a-f0-9]{64}$ ]] || return 1
  printf 'VPN_ACME_BOOTSTRAP_V1\n%s\n%s\n%s\n%s\n%s\n%s\n' \
    "$TARGET_IPV4" "$TARGET_FQDN" "$TARGET_ADDRESS_MODE" \
    "$fullchain_hash" "$cert_hash" "$key_hash"
}
if [[ $mode == verify-committed ]]; then
  [[ ${TARGET_TLS_MODE:-letsencrypt} == letsencrypt ]] || acme_fail ACME_COMMIT_MODE
  [[ -f $commit_marker && ! -L $commit_marker &&
     $(stat -c '%u:%g:%a:%h' "$commit_marker") == 0:0:600:1 ]] || acme_fail ACME_COMMIT_MARKER
  [[ -d $lineage && ! -L $lineage ]] || acme_fail ACME_COMMIT_LINEAGE
  acme_verify_issued_certificate "$lineage" || acme_fail ACME_COMMIT_CERT
  verify_target_certificate "$lineage/fullchain.pem" || acme_fail ACME_COMMIT_CERT
  cmp -s "$commit_marker" <(acme_commit_payload) || acme_fail ACME_COMMIT_MISMATCH
  systemctl is-enabled --quiet certbot.timer || acme_fail ACME_COMMIT_TIMER
  systemctl is-active --quiet certbot.timer || acme_fail ACME_COMMIT_TIMER
  unit_is_quiescent certbot.service || acme_fail ACME_COMMIT_RENEWAL_BUSY
  printf 'ACME_COMMITTED_OK=1\n'
  exit 0
fi
if [[ $TARGET_ADDRESS_MODE != ip ]]; then
  [[ -z $(ip -4 -o address show dev "$TARGET_INTERFACE" scope global | grep -vF " $TARGET_IPV4/") ]] || acme_fail ACME_IP_ADDRESS
fi
ip -4 -o address show dev "$TARGET_INTERFACE" scope global | grep -Fq " $TARGET_IPV4/" || acme_fail ACME_IP_ADDRESS
systemctl is-enabled --quiet x-ui.service || acme_fail ACME_XUI_STATE
unit_is_quiescent x-ui.service || {
  printf 'ERROR: x-ui must be stopped before ACME bootstrap\n' >&2; acme_fail ACME_XUI_STATE;
}
[[ $(sqlite3 -readonly /etc/x-ui/x-ui.db 'select count(*) from inbounds;') == 0 ]] || acme_fail ACME_DATABASE_STATE
[[ $(sqlite3 -readonly /etc/x-ui/x-ui.db 'PRAGMA quick_check;') == ok ]] || acme_fail ACME_DATABASE_STATE
acme_identifier_arguments || { printf 'ERROR: invalid ACME address mode\n' >&2; acme_fail ACME_IDENTITY; }
if [[ ${TARGET_ADDRESS_MODE:-domain} == domain ]]; then
  for resolver in 1.1.1.1 9.9.9.9; do
    a_answer=$(dig +time=5 +tries=2 +noall +answer +comments "@$resolver" "$TARGET_FQDN" A) || acme_fail ACME_DNS_A
    grep -F 'status: NOERROR,' <<<"$a_answer" >/dev/null || acme_fail ACME_DNS_A
    mapfile -t records < <(awk '!/^;/ && NF {print $4 " " $5}' <<<"$a_answer" | sort -u)
    [[ ${#records[@]} == 1 && ${records[0]} == "A $TARGET_IPV4" ]] || { printf 'ERROR: target DNS A mismatch\n' >&2; acme_fail ACME_DNS_A; }
    aaaa_answer=$(dig +time=5 +tries=2 +noall +answer +comments "@$resolver" "$TARGET_FQDN" AAAA) || acme_fail ACME_DNS_AAAA
    grep -F 'status: NOERROR,' <<<"$aaaa_answer" >/dev/null || acme_fail ACME_DNS_AAAA
    [[ -z $(awk '!/^;/ && NF {print}' <<<"$aaaa_answer") ]] || acme_fail ACME_DNS_AAAA
  done
fi
acme_contact_arguments || { printf 'ERROR: invalid optional ACME_EMAIL\n' >&2; acme_fail ACME_CONTACT; }
[[ $mode == apply ]] || { printf 'ACME_PREFLIGHT_OK=1\n'; exit 0; }
[[ ! -e $lineage && ! -L $lineage ]] || { printf 'ERROR: existing certificate requires reviewed renewal\n' >&2; acme_fail ACME_EXISTING_CERT; }
[[ ! -e $commit_marker && ! -L $commit_marker ]] || acme_fail ACME_EXISTING_COMMIT
! ss -H -lnt | grep -Eq '(:|\])80[[:space:]]' || acme_fail ACME_PORT80
readonly acme_lock_root=/run/vpn-acme-bootstrap
if [[ ! -e $acme_lock_root && ! -L $acme_lock_root ]]; then mkdir -m 0700 "$acme_lock_root"; fi
[[ -d $acme_lock_root && ! -L $acme_lock_root && $(stat -c '%u:%g:%a' "$acme_lock_root") == 0:0:700 ]] || acme_fail ACME_LOCK
if [[ -e $acme_lock_root/bootstrap.lock || -L $acme_lock_root/bootstrap.lock ]]; then
  [[ -f $acme_lock_root/bootstrap.lock && ! -L $acme_lock_root/bootstrap.lock && $(stat -c '%u:%g:%a:%h' "$acme_lock_root/bootstrap.lock") == 0:0:600:1 ]] || acme_fail ACME_LOCK
fi
exec 9>"$acme_lock_root/bootstrap.lock"
flock -n 9 || { printf 'ERROR: another certificate bootstrap is active\n' >&2; acme_fail ACME_LOCK; }
systemctl is-enabled --quiet certbot.timer || acme_fail ACME_TIMER
systemctl is-active --quiet certbot.timer || acme_fail ACME_TIMER
unit_is_quiescent certbot.service || acme_fail ACME_RENEWAL_BUSY
snapshot="/var/backups/krysyuk-standalone/$(date -u +%Y%m%dT%H%M%SZ)-acme-$$"
install -d -o root -g root -m 0700 "$snapshot"
systemctl show certbot.service certbot.timer >"$snapshot/unit-state.before"
systemctl cat certbot.service certbot.timer >"$snapshot/units.before"
committed=0
commit_stage=''
timer_stopped=0
snapshot_ready=0
cleanup() {
  status=$?; trap - EXIT INT TERM HUP
  set +e
  rollback_ok=1
  if ((committed == 0 && snapshot_ready)); then
    quiesced=1
    systemctl stop certbot.timer >/dev/null 2>&1 || quiesced=0
    unit_is_quiescent certbot.timer || quiesced=0
    unit_is_quiescent certbot.service || quiesced=0
    # Preserve failure state privately, then restore the exact saved tree.
    # No unknown certificate/account path is recursively removed.
    if ((quiesced)) && mv -- /etc/letsencrypt "$snapshot/letsencrypt-failed"; then
      tar --acls --xattrs --numeric-owner -xpf "$snapshot/letsencrypt-before.tar" -C / || rollback_ok=0
    else rollback_ok=0; fi
  fi
  if ((timer_stopped)); then
    systemctl start certbot.timer >/dev/null 2>&1 || { rollback_ok=0; ((status != 0)) || status=1; }
  fi
  if ((committed == 0 && snapshot_ready)); then
    printf 'ACME_ROLLBACK_OK=%s SNAPSHOT=%s\n' "$rollback_ok" "$snapshot" >&2
  fi
  ((rollback_ok)) || { printf 'ERROR: certificate recovery needs the protected snapshot\n' >&2; ((status != 0)) || status=1; }
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP
timer_stopped=1
systemctl stop certbot.timer
unit_is_quiescent certbot.timer || acme_fail ACME_TIMER
unit_is_quiescent certbot.service || acme_fail ACME_RENEWAL_BUSY
tar --acls --xattrs --numeric-owner -cpf "$snapshot/letsencrypt-before.tar" -C / etc/letsencrypt
tar -tf "$snapshot/letsencrypt-before.tar" >/dev/null
(cd -- "$snapshot"; sha256sum -- *.before letsencrypt-before.tar >SHA256SUMS; sha256sum -c SHA256SUMS >/dev/null)
snapshot_ready=1
/opt/vpn-certbot/bin/certbot certonly --standalone --non-interactive --agree-tos "${acme_contact[@]}" \
  --server https://acme-v02.api.letsencrypt.org/directory \
  --preferred-challenges http --http-01-address "$TARGET_IPV4" "${acme_identifiers[@]}"
acme_verify_issued_certificate "$lineage" || acme_fail ACME_CERT_VERIFY
verify_target_certificate "$lineage/fullchain.pem" || acme_fail ACME_CERT_VERIFY
systemctl enable --now certbot.timer >/dev/null
systemctl is-enabled --quiet certbot.timer || acme_fail ACME_TIMER
systemctl is-active --quiet certbot.timer || acme_fail ACME_TIMER
# Publish the owner-bound receipt only after Certbot and the renewal timer are
# verified. It lets --resume accept this exact certificate after a crash in the
# short interval before the outer phase checkpoint is written.
commit_stage=$(mktemp /etc/letsencrypt/.vpn-acme-bootstrap-commit.XXXXXXXX)
commit_stage_identity=$(stat -c '%d:%i' "$commit_stage")
acme_commit_payload >"$commit_stage" || acme_fail ACME_COMMIT_PAYLOAD
chmod 0600 "$commit_stage"
sync -f "$commit_stage"
mv -nT -- "$commit_stage" "$commit_marker" || acme_fail ACME_COMMIT_PUBLISH
[[ -f $commit_marker && ! -L $commit_marker &&
   $(stat -c '%u:%g:%a:%h' "$commit_marker") == 0:0:600:1 &&
   $(stat -c '%d:%i' "$commit_marker") == "$commit_stage_identity" ]] || acme_fail ACME_COMMIT_MARKER
commit_stage=''
cmp -s "$commit_marker" <(acme_commit_payload) || acme_fail ACME_COMMIT_MISMATCH
sync -f /etc/letsencrypt
# The entrypoint already persisted the full validated target contract,
# including label and ACME contact. Do not truncate it at this phase.
touch "$snapshot/COMMITTED"
committed=1
printf 'ACME_BOOTSTRAP_OK=1\n'
