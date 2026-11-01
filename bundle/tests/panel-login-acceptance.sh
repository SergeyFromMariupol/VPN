#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
# shellcheck source=../scripts/target-contract.sh
source "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../scripts" && pwd -P)/target-contract.sh"

readonly access_file='/etc/krysyuk-standalone/access.env'
[[ $(id -u) -eq 0 && -f "$access_file" && ! -L "$access_file" ]] || exit 1
# shellcheck disable=SC1091
source "$access_file"
[[ -n ${PANEL_URL:-} && -n ${PANEL_USERNAME:-} && -n ${PANEL_PASSWORD:-} ]] || exit 1

stage=$(mktemp -d -p /run panel-login-acceptance.XXXXXXXX)
cleanup() {
  rm -rf -- "$stage"
  unset PANEL_USERNAME PANEL_PASSWORD PANEL_URL SUBSCRIPTION_URL
}
trap cleanup EXIT INT TERM HUP
chmod 0700 "$stage"

panel_base=${PANEL_URL%/}/
panel_path=$(PANEL_BASE="$panel_base" python3 - <<'PY'
import os
import urllib.parse
p = urllib.parse.urlsplit(os.environ["PANEL_BASE"])
expected_scheme = 'http' if os.environ.get('TARGET_TLS_MODE', 'letsencrypt') == 'none' else 'https'
if p.scheme != expected_scheme or p.hostname != os.environ['TARGET_FQDN'] or p.port != 2053:
    raise SystemExit('PANEL_ADDRESS_CONTRACT')
if p.username is not None or p.password is not None or p.query or p.fragment:
    raise SystemExit('PANEL_ADDRESS_CONTRACT')
value = p.path
if not value.startswith('/') or not value.endswith('/') or value == '/':
    raise SystemExit(1)
print(value, end='')
PY
)
backend_base="http://127.0.0.1:2053${panel_path}"

write_post_config() {
  local destination=$1
  local url=$2
  local host_header=$3
  local csrf_token=$4
  {
    printf 'url = "%slogin"\n' "$url"
    printf 'request = "POST"\n'
    printf 'header = "Host: %s"\n' "$host_header"
    printf 'header = "X-CSRF-Token: %s"\n' "$csrf_token"
    printf 'data-urlencode = "username=%s"\n' "$PANEL_USERNAME"
    printf 'data-urlencode = "password=%s"\n' "$PANEL_PASSWORD"
    printf 'data-urlencode = "twoFactorCode="\n'
    printf 'cookie = "%s/cookies"\n' "$stage"
    printf 'cookie-jar = "%s/cookies"\n' "$stage"
    printf 'output = "%s/body"\n' "$stage"
    printf 'write-out = "%%{http_code}"\n'
    printf 'silent\nshow-error\nmax-time = 30\n'
  } >"$destination"
  chmod 0600 "$destination"
}

test_login() {
  local label=$1
  local base=$2
  local host_header=$3
  local protocol=$4
  rm -f -- "$stage/cookies" "$stage/body"
  printf 'url = "%scsrf-token"\n' "$base" >"$stage/get.curl.conf"
  chmod 0600 "$stage/get.curl.conf"
  curl --noproxy '*' --proxy '' --proto "=$protocol" --fail --silent --show-error --max-time 30 \
    --header "Host: $host_header" --cookie-jar "$stage/cookies" \
    --output "$stage/csrf.json" --config "$stage/get.curl.conf"
  local csrf_token
  csrf_token=$(jq --exit-status --raw-output '.obj|select(type=="string" and length>=16)' "$stage/csrf.json")
  write_post_config "$stage/post.curl.conf" "$base" "$host_header" "$csrf_token"
  local status
  status=$(curl --noproxy '*' --proxy '' --proto "=$protocol" --config "$stage/post.curl.conf")
  [[ "$status" == 200 ]]
  jq --exit-status '.success==true' "$stage/body" >/dev/null
  unset csrf_token
  printf '%s_PANEL_LOGIN_OK=1\n' "$label"
}

test_login BACKEND "$backend_base" 'localhost' http
rm -f -- "$stage/cookies" "$stage/body" "$stage/post.curl.conf"
public_host=$(PANEL_BASE="$panel_base" python3 - <<'PY'
import os
import urllib.parse
p = urllib.parse.urlsplit(os.environ["PANEL_BASE"])
print(p.netloc, end='')
PY
)
test_login PUBLIC "$panel_base" "$public_host" "$TARGET_PUBLIC_SCHEME"
printf 'PANEL_LOGIN_ACCEPTANCE_OK=1\n'
