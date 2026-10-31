#!/usr/bin/env bash
# Shared non-secret target contract. Source only from this reviewed bundle.
[[ ${GERMANYVPN_TARGET_CONTRACT_LOADED:-0} == 0 ]] || return 0
GERMANYVPN_TARGET_CONTRACT_LOADED=1
if [[ -f /etc/germanyvpn-target.env ]]; then
  [[ ! -L /etc/germanyvpn-target.env && $(stat -c '%U:%G:%a' /etc/germanyvpn-target.env) == root:root:600 ]] || {
    printf 'ERROR: unsafe /etc/germanyvpn-target.env\n' >&2; return 1;
  }
  # shellcheck disable=SC1091
  source /etc/germanyvpn-target.env
fi
TARGET_FQDN=${TARGET_FQDN:?TARGET_FQDN is required}
TARGET_ADDRESS_MODE=${TARGET_ADDRESS_MODE:-domain}
[[ $TARGET_FQDN =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ && $TARGET_FQDN == *.* && $TARGET_FQDN != *..* ]] || {
  printf 'ERROR: TARGET_FQDN must be a lowercase DNS name or public IPv4\n' >&2; return 1;
}
TARGET_IPV4=${TARGET_IPV4:?TARGET_IPV4 is required}
TARGET_INTERFACE=${TARGET_INTERFACE:?TARGET_INTERFACE is required}
TARGET_SSH_PORT=${TARGET_SSH_PORT:?TARGET_SSH_PORT is required}
TARGET_REALITY_SNI=${TARGET_REALITY_SNI:?TARGET_REALITY_SNI is required}
TARGET_DEVICE_LIMIT=${TARGET_DEVICE_LIMIT:?TARGET_DEVICE_LIMIT is required}
TARGET_LABEL=${TARGET_LABEL:?TARGET_LABEL is required}
[[ $TARGET_INTERFACE =~ ^[a-zA-Z0-9_.:-]+$ && $TARGET_SSH_PORT =~ ^[0-9]+$ && $TARGET_DEVICE_LIMIT =~ ^[0-9]+$ ]] || return 1
((TARGET_SSH_PORT >= 1 && TARGET_SSH_PORT <= 65535 && TARGET_DEVICE_LIMIT <= 10000)) || return 1
[[ $TARGET_REALITY_SNI =~ ^[a-z0-9.-]+$ && $TARGET_REALITY_SNI != *cloudflare* ]] || return 1
export TARGET_IPV4 TARGET_FQDN TARGET_ADDRESS_MODE TARGET_INTERFACE TARGET_SSH_PORT TARGET_REALITY_SNI TARGET_DEVICE_LIMIT TARGET_LABEL
if ! python3 - <<'PY'
import ipaddress
import os
import re
import unicodedata
address = ipaddress.IPv4Address(os.environ['TARGET_IPV4'])
if not address.is_global:
    raise SystemExit('TARGET_IPV4 must be public IPv4')
mode = os.environ['TARGET_ADDRESS_MODE']
if mode not in ('domain', 'ip'):
    raise SystemExit('TARGET_ADDRESS_MODE must be domain or ip')
if mode == 'ip' and os.environ['TARGET_FQDN'] != str(address):
    raise SystemExit('IP endpoint must equal TARGET_IPV4')
for field in (('TARGET_FQDN', 'TARGET_REALITY_SNI') if mode == 'domain' else ('TARGET_REALITY_SNI',)):
    name = os.environ[field]
    if len(name) > 253 or len(name.split('.')) < 2 or any(
        not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
        for label in name.split('.')):
        raise SystemExit(field + ' must be a lowercase DNS hostname')
    try:
        ipaddress.ip_address(name)
    except ValueError:
        pass
    else:
        raise SystemExit(field + ' must be a DNS hostname, not an IP literal')
label = os.environ['TARGET_LABEL']
if not 1 <= len(label) <= 80 or any(unicodedata.category(c) in {'Cc', 'Zl', 'Zp'} for c in label):
    raise SystemExit('invalid TARGET_LABEL')
PY
then
  return 1
fi

# The same verification covers long-lived domain and short-lived IP certificates.
# Keep the public endpoint distinct from the independent REALITY disguise SNI.
verify_target_certificate() {
  local certificate=$1
  openssl x509 -in "$certificate" -noout -checkend 86400 >/dev/null || return 1
  if [[ $TARGET_ADDRESS_MODE == ip ]]; then
    openssl x509 -in "$certificate" -noout -checkip "$TARGET_IPV4" >/dev/null
  else
    openssl x509 -in "$certificate" -noout -checkhost "$TARGET_FQDN" >/dev/null
  fi
}

# Keep every jq string argument out of the native process command line.
# Shell function arguments stay in shell memory; rawfiles have identical string
# contents because printf adds no newline. Files exist only in private /run.
jq() (
  local jq_dir jq_status=0 jq_name jq_value
  local -a jq_args=()
  jq_dir=$(mktemp -d -p /run germanyvpn-jq.XXXXXXXX) || return 1
  trap 'rm -rf -- "$jq_dir"' EXIT
  trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP
  while (($#)); do
    if [[ $1 == --arg ]]; then
      (($# >= 3)) || { rm -rf -- "$jq_dir"; return 2; }
      jq_name=$2; jq_value=$3; shift 3
      [[ $jq_name =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]] || { rm -rf -- "$jq_dir"; return 2; }
      printf '%s' "$jq_value" >"$jq_dir/$jq_name"
      jq_args+=(--rawfile "$jq_name" "$jq_dir/$jq_name")
    else
      jq_args+=("$1"); shift
    fi
  done
  command jq "${jq_args[@]}" || jq_status=$?
  rm -rf -- "$jq_dir"
  return "$jq_status"
)

# URLs can contain private panel/subscription paths. Native curl receives only
# a private config path. Disable implicit .curlrc/proxy overrides for all calls.
curl() (
  local curl_dir curl_status=0 curl_url curl_arg
  local -a curl_args=()
  # Ignore inherited proxy settings while preserving an explicit per-call
  # --socks5-hostname/--proxy. A wildcard NO_PROXY would bypass even that proxy.
  unset http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY no_proxy NO_PROXY
  curl_dir=$(mktemp -d -p /run germanyvpn-curl.XXXXXXXX) || return 1
  trap 'rm -rf -- "$curl_dir"' EXIT
  trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP
  : >"$curl_dir/url.conf"
  while (($#)); do
    curl_arg=$1; shift
    if [[ $curl_arg == --url ]]; then
      (($#)) || { rm -rf -- "$curl_dir"; return 2; }
      curl_url=$1; shift
    elif [[ $curl_arg == http://* || $curl_arg == https://* ]]; then
      curl_url=$curl_arg
    else
      curl_args+=("$curl_arg"); continue
    fi
    [[ $curl_url != *$'\n'* && $curl_url != *$'\r'* ]] || { rm -rf -- "$curl_dir"; return 2; }
    curl_url=${curl_url//\\/\\\\}; curl_url=${curl_url//\"/\\\"}
    printf 'url = "%s"\n' "$curl_url" >>"$curl_dir/url.conf"
  done
  command curl --disable --noproxy '__germanyvpn_no_match__.invalid' --config "$curl_dir/url.conf" "${curl_args[@]}" || curl_status=$?
  rm -rf -- "$curl_dir"
  return "$curl_status"
)
