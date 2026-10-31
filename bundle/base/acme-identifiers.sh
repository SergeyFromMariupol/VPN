#!/usr/bin/env bash
# Pure argument contract, shared with the offline fixtures. No network or state.
acme_identifier_arguments() {
  acme_identifiers=(--cert-name "$TARGET_FQDN")
  case ${TARGET_ADDRESS_MODE:-domain} in
    domain) acme_identifiers+=(-d "$TARGET_FQDN");;
    ip)
      [[ $TARGET_FQDN == "$TARGET_IPV4" ]] || return 1
      acme_identifiers+=(--ip-address "$TARGET_IPV4" --required-profile shortlived)
      ;;
    *) return 1;;
  esac
}

acme_verify_issued_certificate() {
  local lineage=$1 trust_path=${2:-/etc/ssl/certs} minimum_validity
  local certificate_public_key private_public_key
  local -a identity
  case ${TARGET_ADDRESS_MODE:-domain} in
    ip) identity=(-verify_ip "$TARGET_IPV4"); minimum_validity=86400;;
    domain) identity=(-verify_hostname "$TARGET_FQDN"); minimum_validity=2592000;;
    *) return 1;;
  esac
  openssl x509 -in "$lineage/cert.pem" -noout -checkend "$minimum_validity" >/dev/null || return 1
  # x509 -checkip/-checkhost can print a mismatch and still exit successfully.
  # verify checks the identity and trusted chain with a nonzero failure status.
  openssl verify -CApath "$trust_path" -untrusted "$lineage/chain.pem" \
    -purpose sslserver "${identity[@]}" "$lineage/cert.pem" >/dev/null || return 1
  certificate_public_key=$(openssl x509 -in "$lineage/cert.pem" -noout -pubkey) || return 1
  private_public_key=$(openssl pkey -in "$lineage/privkey.pem" -pubout) || return 1
  [[ -n $certificate_public_key && $certificate_public_key == "$private_public_key" ]]
}
