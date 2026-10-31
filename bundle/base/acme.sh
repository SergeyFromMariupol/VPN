#!/usr/bin/env bash
# ACME stage after pinned base and install-certbot.sh. Trusted certificates only.
set -Eeuo pipefail
umask 077
source_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
readonly source_root
source "$source_root/../scripts/target-contract.sh"
source "$source_root/acme-identifiers.sh"
mode=check
case ${1:---check-only} in --check-only) ;; --apply) mode=apply;; *) exit 2;; esac
[[ $EUID == 0 ]] || exit 1
for name in certbot dig ip sqlite3 systemctl openssl tar ss flock; do command -v "$name" >/dev/null; done
"$source_root/install-certbot.sh" --check-only
[[ $(command -v certbot) == /usr/local/bin/certbot ]] || { printf 'ERROR: unexpected Certbot command\n' >&2; exit 1; }
[[ -z $(ip -4 -o address show dev "$TARGET_INTERFACE" scope global | grep -vF " $TARGET_IPV4/") ]]
ip -4 -o address show dev "$TARGET_INTERFACE" scope global | grep -Fq " $TARGET_IPV4/"
systemctl is-enabled --quiet x-ui.service
! systemctl is-active --quiet x-ui.service || {
  printf 'ERROR: x-ui must be stopped before ACME bootstrap\n' >&2; exit 1;
}
[[ $(sqlite3 -readonly /etc/x-ui/x-ui.db 'select count(*) from inbounds;') == 0 ]]
[[ $(sqlite3 -readonly /etc/x-ui/x-ui.db 'PRAGMA quick_check;') == ok ]]
acme_identifier_arguments || { printf 'ERROR: invalid ACME address mode\n' >&2; exit 1; }
if [[ ${TARGET_ADDRESS_MODE:-domain} == domain ]]; then
  for resolver in 1.1.1.1 9.9.9.9; do
    a_answer=$(dig +time=5 +tries=2 +noall +answer +comments "@$resolver" "$TARGET_FQDN" A)
    grep -F 'status: NOERROR,' <<<"$a_answer" >/dev/null || exit 1
    mapfile -t records < <(awk '!/^;/ && NF {print $4 " " $5}' <<<"$a_answer" | sort -u)
    [[ ${#records[@]} == 1 && ${records[0]} == "A $TARGET_IPV4" ]] || { printf 'ERROR: target DNS A mismatch\n' >&2; exit 1; }
    aaaa_answer=$(dig +time=5 +tries=2 +noall +answer +comments "@$resolver" "$TARGET_FQDN" AAAA)
    grep -F 'status: NOERROR,' <<<"$aaaa_answer" >/dev/null || exit 1
    [[ -z $(awk '!/^;/ && NF {print}' <<<"$aaaa_answer") ]] || exit 1
  done
fi
[[ ${ACME_EMAIL:-} =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] || {
  printf 'ERROR: your ACME_EMAIL is required\n' >&2; exit 1;
}
contact=(--email "$ACME_EMAIL")
[[ $mode == apply ]] || { printf 'ACME_PREFLIGHT_OK=1\n'; exit 0; }
lineage="/etc/letsencrypt/live/$TARGET_FQDN"
[[ ! -e $lineage && ! -L $lineage ]] || { printf 'ERROR: existing certificate requires reviewed renewal\n' >&2; exit 1; }
! ss -H -lnt | grep -Eq '(:|\])80[[:space:]]' || exit 1
exec 9>/run/lock/vpn-acme-bootstrap.lock
flock -n 9 || { printf 'ERROR: another certificate bootstrap is active\n' >&2; exit 1; }
systemctl is-enabled --quiet certbot.timer
systemctl is-active --quiet certbot.timer
! systemctl is-active --quiet certbot.service || exit 1
snapshot="/var/backups/krysyuk-standalone/$(date -u +%Y%m%dT%H%M%SZ)-acme-$$"
install -d -o root -g root -m 0700 "$snapshot"
systemctl show certbot.service certbot.timer >"$snapshot/unit-state.before"
systemctl cat certbot.service certbot.timer >"$snapshot/units.before"
committed=0
timer_stopped=0
snapshot_ready=0
cleanup() {
  status=$?; trap - EXIT INT TERM HUP
  set +e
  rollback_ok=1
  if ((committed == 0 && snapshot_ready)); then
    # Preserve failure state privately, then restore the exact saved tree.
    # No unknown certificate/account path is recursively removed.
    if mv -- /etc/letsencrypt "$snapshot/letsencrypt-failed"; then
      tar --acls --xattrs --numeric-owner -xpf "$snapshot/letsencrypt-before.tar" -C / || rollback_ok=0
    else rollback_ok=0; fi
    printf 'ACME_ROLLBACK_OK=%s SNAPSHOT=%s\n' "$rollback_ok" "$snapshot" >&2
  fi
  if ((timer_stopped)); then
    systemctl start certbot.timer >/dev/null 2>&1 || { rollback_ok=0; ((status != 0)) || status=1; }
  fi
  ((rollback_ok)) || { printf 'ERROR: certificate recovery needs the protected snapshot\n' >&2; ((status != 0)) || status=1; }
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP
systemctl stop certbot.timer
timer_stopped=1
! systemctl is-active --quiet certbot.service || exit 1
tar --acls --xattrs --numeric-owner -cpf "$snapshot/letsencrypt-before.tar" -C / etc/letsencrypt
tar -tf "$snapshot/letsencrypt-before.tar" >/dev/null
(cd -- "$snapshot"; sha256sum -- *.before letsencrypt-before.tar >SHA256SUMS; sha256sum -c SHA256SUMS >/dev/null)
snapshot_ready=1
/opt/vpn-certbot/bin/certbot certonly --standalone --non-interactive --agree-tos "${contact[@]}" \
  --server https://acme-v02.api.letsencrypt.org/directory \
  --preferred-challenges http --http-01-address "$TARGET_IPV4" "${acme_identifiers[@]}"
if [[ ${TARGET_ADDRESS_MODE:-domain} == ip ]]; then
  openssl x509 -in "$lineage/cert.pem" -noout -checkip "$TARGET_IPV4" >/dev/null
  openssl x509 -in "$lineage/cert.pem" -noout -checkend 86400 >/dev/null
  openssl verify -CApath /etc/ssl/certs -untrusted "$lineage/chain.pem" -verify_ip "$TARGET_IPV4" "$lineage/cert.pem" >/dev/null
else
  openssl x509 -in "$lineage/cert.pem" -noout -checkhost "$TARGET_FQDN" >/dev/null
  openssl x509 -in "$lineage/cert.pem" -noout -checkend 2592000 >/dev/null
  openssl verify -CApath /etc/ssl/certs -untrusted "$lineage/chain.pem" -verify_hostname "$TARGET_FQDN" "$lineage/cert.pem" >/dev/null
fi
cmp -s <(openssl x509 -in "$lineage/cert.pem" -noout -pubkey) <(openssl pkey -in "$lineage/privkey.pem" -pubout)
systemctl enable --now certbot.timer >/dev/null
systemctl is-enabled --quiet certbot.timer
systemctl is-active --quiet certbot.timer
# The entrypoint already persisted the full validated target contract,
# including label and ACME contact. Do not truncate it at this phase.
touch "$snapshot/COMMITTED"
committed=1
printf 'ACME_BOOTSTRAP_OK=1\n'
