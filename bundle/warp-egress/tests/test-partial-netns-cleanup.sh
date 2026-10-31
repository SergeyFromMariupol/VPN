#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

# The same file is used as a command dispatcher through temporary symlinks.
# This keeps the cleanup test completely away from the host network stack.
if [[ ${FAKE_NETNS_COMMAND_MODE:-} == 1 ]]; then
  : "${FAKE_NETNS_STATE:?FAKE_NETNS_STATE is required}"
  command_name=${0##*/}
  printf '%s %s\n' "$command_name" "$*" >>"$FAKE_NETNS_STATE/commands.log"
  case "$command_name" in
    ip)
      case "$*" in
        'link show @TARGET_INTERFACE@') exit 0 ;;
        '-4 address show dev @TARGET_INTERFACE@')
          printf '%s\n' '2: @TARGET_INTERFACE@ inet @TARGET_IPV4@/24 scope global @TARGET_INTERFACE@'
          exit 0
          ;;
        'netns list')
          [[ -e "$FAKE_NETNS_STATE/netns" ]] && printf '%s\n' 'krysyuk-warp'
          exit 0
          ;;
        'link show kw-host')
          [[ -e "$FAKE_NETNS_STATE/host-veth" ]]
          exit
          ;;
        'netns add krysyuk-warp')
          : >"$FAKE_NETNS_STATE/netns"
          exit 0
          ;;
        'link add kw-host type veth peer name kw-warp')
          : >"$FAKE_NETNS_STATE/host-veth"
          : >"$FAKE_NETNS_STATE/netns-veth"
          exit 0
          ;;
        'link delete kw-host')
          rm -f -- "$FAKE_NETNS_STATE/host-veth" "$FAKE_NETNS_STATE/netns-veth"
          exit 0
          ;;
        'netns delete krysyuk-warp')
          rm -f -- "$FAKE_NETNS_STATE/netns" "$FAKE_NETNS_STATE/netns-veth"
          exit 0
          ;;
        *) exit 0 ;;
      esac
      ;;
    sysctl)
      if [[ $* == '-n net.ipv4.ip_forward' ]]; then
        cat "$FAKE_NETNS_STATE/ip-forward"
      elif [[ $* == *net.ipv4.ip_forward=1* ]]; then
        printf '%s\n' 1 >"$FAKE_NETNS_STATE/ip-forward"
      elif [[ $* == *net.ipv4.ip_forward=0* ]]; then
        printf '%s\n' 0 >"$FAKE_NETNS_STATE/ip-forward"
      fi
      exit 0
      ;;
    nft|ufw) exit 0 ;;
    *) printf 'ERROR: unexpected fake command: %s\n' "$command_name" >&2; exit 2 ;;
  esac
fi

test_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
readonly test_dir
bundle_root=$(cd -- "$test_dir/.." && pwd -P)
readonly bundle_root

[[ $(id -u) -eq 0 ]] || { echo 'ERROR: run as root' >&2; exit 1; }
for command_name in chmod cp grep ln mkdir mktemp rm sed stat; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'ERROR: required cleanup-test command is missing: %s\n' "$command_name" >&2
    exit 1
  }
done

stage=$(mktemp -d)
cleanup() {
  rm -rf -- "$stage"
}
trap cleanup EXIT
mkdir -m 0700 "$stage/bin" "$stage/state"
cp "$bundle_root/scripts/common.sh" "$bundle_root/scripts/setup-netns.sh" "$stage/"
chmod 0700 "$stage/common.sh" "$stage/setup-netns.sh"

escaped_stage=${stage//&/\\&}
sed -i \
  "s#^readonly WARP_EGRESS_ENV=.*#readonly WARP_EGRESS_ENV=${escaped_stage}/warp.env#" \
  "$stage/common.sh"
sed -i \
  "s#^netns_exec sysctl -q -w net.ipv4.conf.all.src_valid_mark=1#die 'forced partial cleanup audit'#" \
  "$stage/setup-netns.sh"
sed -i \
  's#^/usr/local/libexec/krysyuk-warp-egress/configure-ufw.sh --check.*$#:#' \
  "$stage/setup-netns.sh"

printf '%s\n' \
  'WARP_EGRESS_HOST_LISTEN=127.0.0.1' \
  'WARP_EGRESS_NETNS_LISTEN=169.254.254.2' \
  'WARP_EGRESS_NL_PORT=24443' \
  'WARP_EGRESS_NL_CLIENT_ID=11111111-1111-4111-8111-111111111111' \
  'WARP_EGRESS_BRIDGE_PORT=24444' \
  'WARP_EGRESS_BRIDGE_CLIENT_ID=22222222-2222-4222-8222-222222222222' \
  'WARP_EGRESS_IFACE=CloudflareWARP' \
  'PHYSICAL_IFACE=@TARGET_INTERFACE@' \
  'NL_PUBLIC_IPV4=@TARGET_IPV4@' \
  'WARP_NETNS=krysyuk-warp' \
  'WARP_HOST_VETH=kw-host' \
  'WARP_NETNS_VETH=kw-warp' \
  'WARP_HOST_IPV4=169.254.254.1' \
  'WARP_NETNS_IPV4=169.254.254.2' \
  'WARP_VETH_CIDR=169.254.254.0/30' >"$stage/warp.env"
chmod 0600 "$stage/warp.env"
printf '%s\n' 0 >"$stage/state/ip-forward"
for command_name in ip nft sysctl ufw; do
  ln -s "$test_dir/test-partial-netns-cleanup.sh" "$stage/bin/$command_name"
done

set +e
FAKE_NETNS_COMMAND_MODE=1 FAKE_NETNS_STATE="$stage/state" \
  PATH="$stage/bin:$PATH" "$stage/setup-netns.sh" >"$stage/output.log" 2>&1
rc=$?
set -e
(( rc != 0 )) || {
  echo 'ERROR: forced partial namespace setup unexpectedly succeeded' >&2
  exit 1
}

grep -Fq 'ip netns add krysyuk-warp' "$stage/state/commands.log" || {
  echo 'ERROR: partial cleanup test never created its fake namespace' >&2
  exit 1
}
grep -Fq 'sysctl -q -w net.ipv4.ip_forward=1' "$stage/state/commands.log" || {
  echo 'ERROR: partial cleanup test never changed its fake forwarding state' >&2
  exit 1
}
grep -Fq 'ip netns delete krysyuk-warp' "$stage/state/commands.log" || {
  echo 'ERROR: failed setup did not delete its fake namespace' >&2
  exit 1
}
grep -Fq 'nft delete table inet krysyuk_warp_netns_host_guard' \
  "$stage/state/commands.log" || {
  echo 'ERROR: failed setup did not remove its fake host guard' >&2
  exit 1
}
[[ ! -e "$stage/state/netns" && ! -e "$stage/state/host-veth" \
  && ! -e "$stage/state/netns-veth" ]] || {
  echo 'ERROR: failed setup left partial fake namespace state' >&2
  exit 1
}
[[ $(<"$stage/state/ip-forward") == 0 ]] || {
  echo 'ERROR: failed setup did not restore its fake forwarding state' >&2
  exit 1
}

printf '%s\n' 'WARP_NETNS_PARTIAL_SETUP_CLEANUP_OK=1'
