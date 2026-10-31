#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

command -v ip >/dev/null 2>&1 || { echo 'ERROR: ip is missing' >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo 'ERROR: jq is missing' >&2; exit 1; }

ipv4_rules=$(ip -4 -j rule show)
ipv6_rules=$(ip -6 -j rule show)
ipv4_defaults=$(ip -4 -j route show table all default)
ipv6_defaults=$(ip -6 -j route show table all default)

jq -S -n \
  --argjson ipv4_rules "$ipv4_rules" \
  --argjson ipv6_rules "$ipv6_rules" \
  --argjson ipv4_defaults "$ipv4_defaults" \
  --argjson ipv6_defaults "$ipv6_defaults" '
  def stable:
    walk(if type == "object" then del(.expires, .used, .age, .cache) else . end);
  {
    ipv4_rules: ($ipv4_rules | stable | sort_by(.priority, .table, .from, .to, .fwmark)),
    ipv6_rules: ($ipv6_rules | stable | sort_by(.priority, .table, .from, .to, .fwmark)),
    ipv4_defaults: ($ipv4_defaults | stable | sort_by(.table, .metric, .gateway, .dev)),
    ipv6_defaults: ($ipv6_defaults | stable | sort_by(.table, .metric, .gateway, .dev))
  }
' 
