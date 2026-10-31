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
