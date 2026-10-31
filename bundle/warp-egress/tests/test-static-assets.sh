#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

test_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
readonly test_dir
bundle_root=$(cd -- "$test_dir/.." && pwd -P)
readonly bundle_root

for command_name in bash cmp cut find getent grep jq nft sed shellcheck sort systemd-analyze; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'ERROR: required static tool is missing: %s\n' "$command_name" >&2
    exit 1
  }
done
getent passwd xraywarp >/dev/null || {
  echo 'ERROR: xraywarp must exist before nft/systemd static validation' >&2
  exit 1
}

if grep -R -n --exclude='test-static-assets.sh' -E -- \
    '@[A-Z0-9_]+@' \
    "$bundle_root"; then
  echo 'ERROR: unrendered target placeholder in runtime bundle' >&2
  exit 1
fi

mapfile -d '' shell_files < <(
  find "$bundle_root/scripts" "$bundle_root/tests" -type f -name '*.sh' -print0 | sort -z
)
(( ${#shell_files[@]} > 0 )) || { echo 'ERROR: no shell files found' >&2; exit 1; }
for path in "${shell_files[@]}"; do
  bash -n "$path"
  if grep -q $'\r' "$path"; then
    printf 'ERROR: CRLF found in %s\n' "$path" >&2
    exit 1
  fi
done
shellcheck --external-sources --severity=warning "${shell_files[@]}"
if grep -R -n -E -- '\|[[:space:]]*head[[:space:]]+-n[[:space:]]+1([^|]|$)' \
    "$bundle_root/scripts" "$bundle_root/tests" | \
    grep -vF 'xray.zip.dgst' >/dev/null; then
  echo 'ERROR: pipefail-unsafe head -n 1 pipeline exists' >&2
  exit 1
fi

template="$bundle_root/config/xray-warp-egress.template.json"
jq empty "$template"
jq --exit-status '
  (.inbounds | length) == 2
  and ([.inbounds[].tag] | sort) == ["WARP_EGRESS_BRIDGE_IN", "WARP_EGRESS_NL_IN"]
  and all(.inbounds[]; .listen == "__WARP_EGRESS_NETNS_LISTEN__")
  and any(.inbounds[]; .tag == "WARP_EGRESS_NL_IN" and .port == 24443
    and .settings.clients == [{id: "__WARP_EGRESS_NL_CLIENT_ID__"}])
  and any(.inbounds[]; .tag == "WARP_EGRESS_BRIDGE_IN" and .port == 24444
    and .settings.clients == [{id: "__WARP_EGRESS_BRIDGE_CLIENT_ID__"}])
  and all(.inbounds[]; .protocol == "vless")
  and all(.inbounds[]; .streamSettings == {network: "raw", security: "none"})
  and ([.outbounds[] | select(.protocol == "freedom") | .tag] == ["WARP_CF"])
  and ([.outbounds[] | select(.protocol == "socks")] | length) == 0
  and ((.outbounds[] | select(.tag == "WARP_CF") | .streamSettings?) == null)
  and any(.routing.rules[]; .inboundTag == ["DNS_WARP"] and .outboundTag == "WARP_CF")
  and any(.routing.rules[]; .ip == ["::/0"] and .outboundTag == "BLOCK")
  and any(.routing.rules[]; (.ip // []) | index("__PHYSICAL_IPV4__/32"))
  and (.routing.rules[-1].inboundTag | sort) == ["WARP_EGRESS_BRIDGE_IN", "WARP_EGRESS_NL_IN"]
  and .routing.rules[-1].network == "tcp,udp"
  and .routing.rules[-1].outboundTag == "WARP_CF"
' "$template" >/dev/null || {
  echo 'ERROR: Xray template violates the static netns/WARP-only contract' >&2
  exit 1
}

netns_guard="$bundle_root/nftables/krysyuk-warp-egress-guard.nft"
grep -Fq 'meta skuid 0 oifname "kw-warp" ip saddr 169.254.254.2 ip dscp set 46 meta mark set 0x57525001' "$netns_guard"
grep -Fq 'meta skuid xraywarp oifname "lo"' "$netns_guard"
grep -Fq 'meta skuid xraywarp oifname "kw-warp" ip saddr 169.254.254.2 ip daddr 169.254.254.1 tcp sport { 24443, 24444 } ct state established' "$netns_guard"
grep -Fq 'meta skuid xraywarp oifname "CloudflareWARP"' "$netns_guard"
grep -Eq 'meta skuid xraywarp counter drop' "$netns_guard"

host_rules="$bundle_root/nftables/krysyuk-warp-netns-host.nft"
grep -Fq 'iifname "kw-host" ip saddr 169.254.254.2 oifname "@TARGET_INTERFACE@" ip dscp 46 meta mark set 0x57525001 counter accept' "$host_rules"
grep -Fq 'iifname "@TARGET_INTERFACE@" oifname "kw-host" ip daddr 169.254.254.2 ct state established,related counter accept' "$host_rules"
grep -Fq 'iifname "kw-host" counter drop' "$host_rules"
grep -Fq 'oifname "kw-host" counter drop' "$host_rules"
grep -Fq 'ip saddr 169.254.254.2 oifname "@TARGET_INTERFACE@" meta mark 0x57525001 counter masquerade' "$host_rules"
if grep -Fq 'iifname "kw-host" ip saddr 169.254.254.2 oifname "@TARGET_INTERFACE@" counter accept' \
  "$host_rules"; then
  echo 'ERROR: untagged netns-to-@TARGET_INTERFACE@ traffic has a host allow' >&2
  exit 1
fi
ufw4="$bundle_root/config/ufw-before-forward-v4.rules"
ufw6="$bundle_root/config/ufw-before-forward-v6.rules"
grep -Fqx -- '-A ufw-before-forward -i kw-host -s 169.254.254.2/32 -o @TARGET_INTERFACE@ -m dscp --dscp 46 -j MARK --set-xmark 0x57525001/0xffffffff' "$ufw4"
grep -Fqx -- '-A ufw-before-forward -i kw-host -s 169.254.254.2/32 -o @TARGET_INTERFACE@ -m mark --mark 0x57525001/0xffffffff -j ACCEPT' "$ufw4"
grep -Fqx -- '-A ufw-before-forward -i kw-host -j DROP' "$ufw4"
grep -Fqx -- '-A ufw-before-forward -o kw-host -j DROP' "$ufw4"
mapfile -t ufw4_rules < <(grep '^-A ufw-before-forward ' "$ufw4")
(( ${#ufw4_rules[@]} == 5 )) || {
  echo 'ERROR: managed UFW IPv4 fragment must contain exactly five rules' >&2
  exit 1
}
[[ ${ufw4_rules[0]} == *'--dscp 46'* && ${ufw4_rules[0]} == *'-j MARK'* \
  && ${ufw4_rules[1]} == *'--mark 0x57525001'* && ${ufw4_rules[1]} == *'-j ACCEPT'* \
  && ${ufw4_rules[2]} == *'RELATED,ESTABLISHED'* && ${ufw4_rules[2]} == *'-j ACCEPT'* \
  && ${ufw4_rules[3]} == *'-i kw-host -j DROP'* \
  && ${ufw4_rules[4]} == *'-o kw-host -j DROP'* ]] || {
  echo 'ERROR: managed UFW carrier-to-mark rules have an unsafe order' >&2
  exit 1
}
grep -Fqx -- '-A ufw6-before-forward -i kw-host -j DROP' "$ufw6"
grep -Fqx -- '-A ufw6-before-forward -o kw-host -j DROP' "$ufw6"
grep -Fq '/etc/ufw/before.rules /etc/ufw/before6.rules' \
  "$bundle_root/scripts/deploy.sh"
if grep -R -n -E -- 'ufw[[:space:]]+route[[:space:]]+allow.*kw-host' \
  "$bundle_root/scripts" "$bundle_root/tests"; then
  echo 'ERROR: broad UFW WARP-veth route allow exists' >&2
  exit 1
fi

candidate=$(mktemp)
trap 'rm -f -- "$candidate"' EXIT
sed \
  -e "s/krysyuk_warp_egress_guard/krysyuk_warp_egress_guard_static_$$/g" \
  "$netns_guard" >"$candidate"
nft -c -f "$candidate"
sed \
  -e "s/krysyuk_warp_netns_host_guard/krysyuk_warp_netns_host_guard_static_$$/g" \
  -e "s/krysyuk_warp_netns_nat/krysyuk_warp_netns_nat_static_$$/g" \
  "$host_rules" >"$candidate"
nft -c -f "$candidate"

readonly unit_files=(
  "$bundle_root/systemd/krysyuk-warp-netns.service"
  "$bundle_root/systemd/krysyuk-warp-netns-daemon.service"
  "$bundle_root/systemd/krysyuk-warp-netns-configure.service"
  "$bundle_root/systemd/krysyuk-warp-egress-guard.service"
  "$bundle_root/systemd/krysyuk-xray-warp-egress.service"
  "$bundle_root/systemd/krysyuk-warp-egress.socket"
  "$bundle_root/systemd/krysyuk-warp-egress.service"
  "$bundle_root/systemd/krysyuk-warp-bridge.socket"
  "$bundle_root/systemd/krysyuk-warp-bridge.service"
  "$bundle_root/systemd/krysyuk-warp-health.service"
  "$bundle_root/systemd/krysyuk-warp-health.timer"
)
systemd-analyze verify "${unit_files[@]}"
grep -Fq 'NetworkNamespacePath=/run/netns/krysyuk-warp' \
  "$bundle_root/systemd/krysyuk-warp-netns-daemon.service"
grep -Fq 'ExecStopPost=/usr/local/libexec/krysyuk-warp-egress/teardown-netns.sh' \
  "$bundle_root/systemd/krysyuk-warp-netns.service"
grep -Fq 'StateDirectory=krysyuk-warp-egress-warp' \
  "$bundle_root/systemd/krysyuk-warp-netns-daemon.service"
grep -Fq 'BindReadOnlyPaths=/etc/netns/krysyuk-warp/resolv.conf:/etc/resolv.conf' \
  "$bundle_root/systemd/krysyuk-warp-netns-daemon.service"
grep -Fq 'NetworkNamespacePath=/run/netns/krysyuk-warp' \
  "$bundle_root/systemd/krysyuk-xray-warp-egress.service"
grep -Fq 'User=xraywarp' "$bundle_root/systemd/krysyuk-xray-warp-egress.service"
grep -Fq 'LogRateLimitIntervalSec=30s' \
  "$bundle_root/systemd/krysyuk-xray-warp-egress.service"
grep -Fq 'LogRateLimitIntervalSec=30s' \
  "$bundle_root/systemd/krysyuk-warp-netns-daemon.service"
grep -Fq 'ListenStream=127.0.0.1:24443' \
  "$bundle_root/systemd/krysyuk-warp-egress.socket"
grep -Fq 'WantedBy=multi-user.target' \
  "$bundle_root/systemd/krysyuk-warp-egress.socket"
if grep -Fq 'WantedBy=sockets.target' \
    "$bundle_root/systemd/krysyuk-warp-egress.socket"; then
  echo 'ERROR: NL-local socket would create a sockets.target boot cycle' >&2
  exit 1
fi
if grep -Fq 'After=krysyuk-xray-warp-egress.service' \
    "$bundle_root/systemd/krysyuk-warp-egress.socket"; then
  echo 'ERROR: NL-local socket ordering after a regular service creates a boot cycle' >&2
  exit 1
fi
grep -Fq 'systemd-socket-proxyd 169.254.254.2:24443' \
  "$bundle_root/systemd/krysyuk-warp-egress.service"
grep -Fq 'ListenStream=127.0.0.1:24444' \
  "$bundle_root/systemd/krysyuk-warp-bridge.socket"
grep -Fq 'WantedBy=multi-user.target' \
  "$bundle_root/systemd/krysyuk-warp-bridge.socket"
if grep -Fq 'WantedBy=sockets.target' \
    "$bundle_root/systemd/krysyuk-warp-bridge.socket"; then
  echo 'ERROR: RU-bridge socket would create a sockets.target boot cycle' >&2
  exit 1
fi
if grep -Fq 'After=krysyuk-xray-warp-egress.service' \
    "$bundle_root/systemd/krysyuk-warp-bridge.socket"; then
  echo 'ERROR: RU-bridge socket ordering after a regular service creates a boot cycle' >&2
  exit 1
fi
grep -Fq 'systemd-socket-proxyd 169.254.254.2:24444' \
  "$bundle_root/systemd/krysyuk-warp-bridge.service"
[[ $(grep -Fc 'ExecStartPre=+/usr/local/libexec/krysyuk-warp-egress/apply-guard.sh' \
  "$bundle_root/systemd/krysyuk-xray-warp-egress.service") -eq 1 ]] || {
  echo 'ERROR: connector does not reapply its guard before every start' >&2
  exit 1
}
grep -Fq 'ExecStartPre=+/usr/local/libexec/krysyuk-warp-egress/configure-ufw.sh --check-files' \
  "$bundle_root/systemd/krysyuk-xray-warp-egress.service"
grep -Fq 'ExecStartPre=/usr/local/libexec/krysyuk-warp-egress/configure-ufw.sh --check' \
  "$bundle_root/systemd/krysyuk-warp-egress-guard.service"

pin="$bundle_root/config/90-krysyuk-cloudflare-warp.pref"
grep -Fqx 'Package: cloudflare-warp' "$pin"
grep -Fqx 'Pin: version 2026.7.1377.0' "$pin"
grep -Fqx 'Pin-Priority: 1001' "$pin"
grep -Fq '/etc/apt/preferences.d/90-krysyuk-cloudflare-warp' \
  "$bundle_root/scripts/deploy.sh"
grep -Fq 'apt-mark hold cloudflare-warp' "$bundle_root/scripts/bootstrap-ubuntu2404.sh"
grep -Fq 'warp-apt-hold.state' "$bundle_root/scripts/deploy.sh"
grep -Fq 'warp-apt-hold.state' "$bundle_root/scripts/rollback-last.sh"
grep -Fq 'apt-mark unhold cloudflare-warp' "$bundle_root/scripts/rollback-last.sh"
grep -Fq 'for restore_root in "${restore_roots[@]}"' \
  "$bundle_root/scripts/rollback-last.sh"
if grep -Fq 'cp -a -- "$resolved_dir/rootfs/." /' \
    "$bundle_root/scripts/rollback-last.sh"; then
  echo 'ERROR: rollback can overwrite the host root-directory mode' >&2
  exit 1
fi

extract_array() {
  local path="$1" name="$2"
  awk -v name="$name" '
    $0 ~ "^(readonly[[:space:]]+)?" name "=\\(" { inside = 1; next }
    inside && $0 ~ "^[[:space:]]*\\)[[:space:]]*$" { exit }
    inside {
      line = $0
      sub(/^[[:space:]]+/, "", line)
      sub(/[[:space:]]+$/, "", line)
      if (line != "") print line
    }
  ' "$path"
}
deploy_array=$(mktemp)
rollback_array=$(mktemp)
trap 'rm -f -- "$candidate" "$deploy_array" "$rollback_array"' EXIT
for array_name in units managed_paths; do
  extract_array "$bundle_root/scripts/deploy.sh" "$array_name" >"$deploy_array"
  extract_array "$bundle_root/scripts/rollback-last.sh" "$array_name" >"$rollback_array"
  cmp -s "$deploy_array" "$rollback_array" || {
    printf 'ERROR: deploy/rollback %s arrays differ\n' "$array_name" >&2
    exit 1
  }
done
grep -Fq 'trap cleanup_on_exit EXIT' "$bundle_root/scripts/setup-netns.sh"
grep -Fq 'if (( rc != 0 && setup_complete == 0 )); then' \
  "$bundle_root/scripts/setup-netns.sh"
grep -Fq '/usr/local/libexec/krysyuk-warp-egress/apply-guard.sh' \
  "$bundle_root/scripts/setup-netns.sh"
setup_guard_line=$(grep -nF '/usr/local/libexec/krysyuk-warp-egress/apply-guard.sh' \
  "$bundle_root/scripts/setup-netns.sh" | cut -d: -f1)
setup_ready_line=$(grep -nF 'setup_complete=1' "$bundle_root/scripts/setup-netns.sh" | \
  cut -d: -f1)
[[ "$setup_guard_line" =~ ^[0-9]+$ && "$setup_ready_line" =~ ^[0-9]+$ &&
   "$setup_guard_line" -lt "$setup_ready_line" ]] || {
  echo 'ERROR: namespace carrier/mark guard is not applied before setup readiness' >&2
  exit 1
}
grep -Fq 'nft delete table inet "$WARP_HOST_GUARD_TABLE"' \
  "$bundle_root/scripts/setup-netns.sh"
grep -Fq 'sysctl -q -w "net.ipv4.ip_forward=$ip_forward_before"' \
  "$bundle_root/scripts/setup-netns.sh"

nl_client_example="$bundle_root/config/warp-egress-nl-client.env.example"
bridge_client_example="$bundle_root/config/warp-egress-ru-bridge-client.env.example"
for client_example in "$nl_client_example" "$bridge_client_example"; do
  grep -Fqx 'WARP_EGRESS_ADDRESS=127.0.0.1' "$client_example"
  grep -Fqx 'WARP_EGRESS_PORT=24443' "$client_example"
done
grep -Fq 'WARP_EGRESS_NL_CLIENT_ID=' "$bundle_root/config/warp-egress.env.example"
grep -Fq 'WARP_EGRESS_BRIDGE_CLIENT_ID=' "$bundle_root/config/warp-egress.env.example"
grep -Fq 'WARP_EGRESS_BRIDGE_PORT=24444' "$bundle_root/config/warp-egress.env.example"
grep -Fq 'address: "8.8.8.8", port: 443, network: "udp"' \
  "$bundle_root/tests/test-e2e-local.sh"
grep -Fq 'https://www.cloudflare.com/cdn-cgi/trace' \
  "$bundle_root/tests/test-e2e-local.sh"
grep -Fq 'https://one.one.one.one/cdn-cgi/trace' \
  "$bundle_root/tests/test-e2e-local.sh"
grep -Fq 'https://speed.cloudflare.com/cdn-cgi/trace' \
  "$bundle_root/tests/test-e2e-local.sh"
grep -Fq 'one.one.one.one:443:1.1.1.1:443' \
  "$bundle_root/tests/test-e2e-local.sh"
grep -Fq 'valid Cloudflare trace did not report warp=on' \
  "$bundle_root/tests/test-e2e-local.sh"
[[ $(grep -Fc '[[ "$status" == 429 || "$status" =~ ^5[0-9]{2}$ ]]' \
  "$bundle_root/tests/test-e2e-local.sh") -eq 2 ]] || {
  echo 'ERROR: trace and payload retryable HTTP classifications are missing' >&2
  exit 1
}
grep -Fq 'Cloudflare trace observers remained unavailable after bounded retries' \
  "$bundle_root/tests/test-e2e-local.sh"
grep -Fq 'Cloudflare payload observer remained unavailable after bounded retries' \
  "$bundle_root/tests/test-e2e-local.sh"
grep -Fq 'probe_cloudflare_payload "$label" "$socks_port"' \
  "$bundle_root/tests/test-e2e-local.sh"
grep -Fq 'target_ips+=(1.1.1.1 8.8.8.8)' \
  "$bundle_root/tests/test-leak-physical.sh"
grep -Fq '(tcp or udp) and (' "$bundle_root/tests/test-leak-physical.sh"
grep -Fq 'nft delete table inet "$WARP_EGRESS_TABLE"' \
  "$bundle_root/tests/test-guard-loss.sh"
grep -Fq 'host carrier guard did not drop untagged namespace traffic' \
  "$bundle_root/tests/test-guard-loss.sh"
grep -Fq 'b"Q"*1200' "$bundle_root/tests/test-guard-loss.sh"
grep -Fq 'nft delete table inet "$WARP_HOST_GUARD_TABLE"' \
  "$bundle_root/tests/test-host-guard-loss.sh"
grep -Fq 'persistent UFW did not count untagged namespace drops' \
  "$bundle_root/tests/test-host-guard-loss.sh"
grep -Fq 'b"U"*1200' "$bundle_root/tests/test-host-guard-loss.sh"
grep -Fq 'systemctl start krysyuk-warp-egress-guard.service' \
  "$bundle_root/scripts/warp-emergency-reconnect.sh"
grep -Fq 'systemctl start krysyuk-warp-netns.service' \
  "$bundle_root/scripts/warp-emergency-reconnect.sh"
grep -Fq 'teardown-netns.sh' \
  "$bundle_root/scripts/warp-emergency-reconnect.sh"
grep -Fq 'flock -w 5' \
  "$bundle_root/scripts/warp-emergency-reconnect.sh"
grep -Fq 'https://cp.cloudflare.com/generate_204' \
  "$bundle_root/scripts/warp-health-watchdog.sh"
grep -Fq 'https://www.gstatic.com/generate_204' \
  "$bundle_root/scripts/warp-health-watchdog.sh"
grep -Fq 'https://www.google.com/generate_204' \
  "$bundle_root/scripts/warp-health-watchdog.sh"
grep -Fq 'failure_threshold=3' \
  "$bundle_root/scripts/warp-health-watchdog.sh"
grep -Fq 'recovery_cooldown=120' \
  "$bundle_root/scripts/warp-health-watchdog.sh"
grep -Fq '/var/lib/krysyuk-warp-health/failure-streak' \
  "$bundle_root/scripts/deploy-health-watchdog.sh"
grep -Fq '/var/lib/krysyuk-warp-health/last-recovery-epoch' \
  "$bundle_root/scripts/deploy-health-watchdog.sh"
grep -Fq '/var/lib/krysyuk-warp-health/last-success-epoch' \
  "$bundle_root/scripts/deploy-health-watchdog.sh"
grep -Fq 'OnUnitActiveSec=14s' \
  "$bundle_root/systemd/krysyuk-warp-health.timer"
grep -Fq 'ExecStart=/usr/local/libexec/krysyuk-warp-egress/warp-health-watchdog.sh' \
  "$bundle_root/systemd/krysyuk-warp-health.service"
grep -Fq 'StateDirectory=krysyuk-warp-health' \
  "$bundle_root/systemd/krysyuk-warp-health.service"

grep -Fq 'warp_cli mode tunnel_only' "$bundle_root/scripts/configure-warp.sh"
grep -Fq 'tunnel_only([[:space:]:]|$)' "$bundle_root/scripts/configure-warp.sh"
grep -Fq 'warp_cli tunnel protocol set MASQUE' "$bundle_root/scripts/configure-warp.sh"
grep -Fq 'https://api.cloudflareclient.com/' "$bundle_root/scripts/configure-warp.sh"
grep -Fq 'for attempt in 1 2 3' "$bundle_root/scripts/configure-warp.sh"
grep -Fq 'isolated WARP registration failed after bounded retries' \
  "$bundle_root/scripts/configure-warp.sh"
if grep -R -n -E -- 'warp-cli([[:space:]]|.*[[:space:]])mode[[:space:]]+proxy|warp_cli[[:space:]]+mode[[:space:]]+proxy' \
  "$bundle_root/scripts" "$bundle_root/systemd"; then
  echo 'ERROR: TCP-only Local proxy mode exists in the full-UDP netns bundle' >&2
  exit 1
fi
if grep -R -n -E -- '^[[:space:]]*ip[[:space:]]+(-[46][[:space:]]+)?(rule|route)[[:space:]]+(add|replace|delete|del).*default' \
  "$bundle_root/scripts" "$bundle_root/tests"; then
  echo 'ERROR: a main-namespace default-route mutation exists in the bundle' >&2
  exit 1
fi

if grep -R -n -E -- '--(uuid|client-id|password|auth)(=|[[:space:]])' \
  "$bundle_root/scripts" "$bundle_root/tests"; then
  echo 'ERROR: a secret-shaped command-line option exists in the bundle' >&2
  exit 1
fi
if grep -R -n -E -- '--arg[[:space:]]+[^[:space:]]*(client|uuid|auth|password)' \
  "$bundle_root/scripts" "$bundle_root/tests"; then
  echo 'ERROR: a secret is being passed to jq through argv' >&2
  exit 1
fi
grep -Fq '/opt/krysyuk-warp-egress/tests/test-main-route-isolation.sh' \
  "$bundle_root/scripts/deploy.sh"
grep -Fq 'real reboot proof required' "$bundle_root/tests/test-reboot-persistence.sh"
bash "$bundle_root/tests/test-health-watchdog-semantics.sh" >/dev/null
bash "$bundle_root/tests/test-bootstrap-plan-safety.sh" >/dev/null
bash "$bundle_root/tests/test-partial-netns-cleanup.sh" >/dev/null
bash "$bundle_root/tests/test-phase-checkpoints.sh" >/dev/null
printf '%s\n' 'WARP_EGRESS_NETNS_STATIC_ASSETS_OK=1'
