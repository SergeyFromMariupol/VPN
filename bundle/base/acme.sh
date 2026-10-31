#!/usr/bin/env bash
# ACME stage after base/install-pinned-base.sh. Package/binary install lives there.
set -Eeuo pipefail
umask 077
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/../scripts/target-contract.sh"
mode=check
case ${1:---check-only} in --check-only) ;; --apply) mode=apply;; *) exit 2;; esac
[[ $EUID == 0 ]] || exit 1
for name in certbot dig ip sqlite3 systemctl openssl tar; do command -v "$name" >/dev/null; done
[[ -z $(ip -4 -o address show dev "$TARGET_INTERFACE" scope global | grep -vF " $TARGET_IPV4/") ]]
ip -4 -o address show dev "$TARGET_INTERFACE" scope global | grep -Fq " $TARGET_IPV4/"
systemctl is-enabled --quiet x-ui.service
! systemctl is-active --quiet x-ui.service || {
  printf 'ERROR: x-ui must be stopped before ACME bootstrap\n' >&2; exit 1;
}
[[ $(sqlite3 -readonly /etc/x-ui/x-ui.db 'select count(*) from inbounds;') == 0 ]]
[[ $(sqlite3 -readonly /etc/x-ui/x-ui.db 'PRAGMA quick_check;') == ok ]]
for resolver in 1.1.1.1 9.9.9.9; do
  mapfile -t records < <(dig +time=5 +tries=2 +short "@$resolver" "$TARGET_FQDN" A | sed '/^$/d' | sort -u)
  [[ ${#records[@]} == 1 && ${records[0]} == "$TARGET_IPV4" ]] || { printf 'ERROR: target DNS A mismatch\n' >&2; exit 1; }
  [[ -z $(dig +time=5 +tries=2 +short "@$resolver" "$TARGET_FQDN" AAAA) ]] || exit 1
done
contact=()
if [[ -n ${ACME_EMAIL:-} ]]; then
  [[ $ACME_EMAIL =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] || exit 1
  contact=(--email "$ACME_EMAIL")
elif [[ ${ACME_WITHOUT_EMAIL:-no} == yes ]]; then
  contact=(--register-unsafely-without-email)
else
  printf 'ERROR: ACME_EMAIL or explicit ACME_WITHOUT_EMAIL=yes is required\n' >&2; exit 1
fi
[[ $mode == apply ]] || { printf 'ACME_PREFLIGHT_OK=1\n'; exit 0; }
lineage="/etc/letsencrypt/live/$TARGET_FQDN"
[[ ! -e $lineage ]] || { printf 'ERROR: existing certificate requires reviewed renewal\n' >&2; exit 1; }
! ss -H -lnt | grep -Eq '(:|\])80[[:space:]]' || exit 1
snapshot="/var/backups/krysyuk-standalone/$(date -u +%Y%m%dT%H%M%SZ)-acme-$$"
install -d -o root -g root -m 0700 "$snapshot"
tar --acls --xattrs --numeric-owner -cpf "$snapshot/letsencrypt-before.tar" -C / etc/letsencrypt
tar -tf "$snapshot/letsencrypt-before.tar" >/dev/null
sha256sum "$snapshot/letsencrypt-before.tar" >"$snapshot/SHA256SUMS"
committed=0
cleanup() {
  status=$?; trap - EXIT INT TERM HUP
  if ((committed == 0)); then
    # Preserve failure state privately, then restore the exact saved tree.
    # No unknown certificate/account path is recursively removed.
    mv -- /etc/letsencrypt "$snapshot/letsencrypt-failed"
    tar --acls --xattrs --numeric-owner -xpf "$snapshot/letsencrypt-before.tar" -C /
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP
certbot certonly --standalone --non-interactive --agree-tos "${contact[@]}" \
  --preferred-challenges http --http-01-address "$TARGET_IPV4" -d "$TARGET_FQDN"
openssl x509 -in "$lineage/fullchain.pem" -noout -checkhost "$TARGET_FQDN" >/dev/null
openssl x509 -in "$lineage/fullchain.pem" -noout -checkend 2592000 >/dev/null
systemctl enable --now certbot.timer >/dev/null
systemctl is-enabled --quiet certbot.timer
systemctl is-active --quiet certbot.timer
# The entrypoint already persisted the full validated target contract,
# including label and ACME contact. Do not truncate it at this phase.
touch "$snapshot/COMMITTED"
committed=1
printf 'ACME_BOOTSTRAP_OK=1\n'
