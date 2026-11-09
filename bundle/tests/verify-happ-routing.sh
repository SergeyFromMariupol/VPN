#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
readonly scripts="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../scripts" && pwd -P)"
source "$scripts/target-contract.sh"

readonly access_file='/etc/krysyuk-standalone/access.env'
[[ $EUID == 0 && -f $access_file && ! -L $access_file &&
   $(stat -c '%u:%a' -- "$access_file") == 0:600 ]]
source "$access_file"
[[ $SUBSCRIPTION_URL == "$TARGET_PUBLIC_SCHEME://$TARGET_FQDN:2096/"* ]]

curl --proto "=$TARGET_PUBLIC_SCHEME" --tlsv1.2 --fail --silent --show-error --max-time 30 \
  --user-agent Happ --resolve "$TARGET_FQDN:2096:$TARGET_IPV4" \
  --dump-header - --output /dev/null "$SUBSCRIPTION_URL" |
  python3 -I -B "$scripts/happ_routing.py" --check-headers
