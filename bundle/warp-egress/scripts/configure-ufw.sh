#!/usr/bin/env bash

set -Eeuo pipefail
umask 077
export LC_ALL=C LANG=C LANGUAGE=C
unset PYTHONOPTIMIZE PYTHONPATH PYTHONHOME PYTHONUSERBASE PYTHONSTARTUP PYTHONINSPECT

readonly before4=/etc/ufw/before.rules
readonly before6=/etc/ufw/before6.rules
readonly fragment4=/etc/krysyuk-warp-egress/ufw-before-forward-v4.rules
readonly fragment6=/etc/krysyuk-warp-egress/ufw-before-forward-v6.rules
readonly begin4='# BEGIN KRYSYUK WARP NETNS FORWARD'
readonly end4='# END KRYSYUK WARP NETNS FORWARD'
readonly begin6='# BEGIN KRYSYUK WARP NETNS FORWARD V6'
readonly end6='# END KRYSYUK WARP NETNS FORWARD V6'

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $(id -u) -eq 0 ]] || die 'run as root'
mode=${1:-}
[[ "$mode" == --apply || "$mode" == --check || "$mode" == --check-files ]] || \
  die 'usage: configure-ufw.sh [--apply|--check|--check-files]'
for command_name in awk cmp cp grep ip6tables ip6tables-restore install iptables \
  iptables-restore mktemp stat ufw; do
  command -v "$command_name" >/dev/null 2>&1 || \
    die "required UFW command is missing: $command_name"
done

assert_source_file() {
  local path="$1" label="$2"
  [[ -f "$path" && ! -L "$path" ]] || die "$label is missing or unsafe"
  [[ $(stat -c '%U:%G' "$path") == root:root ]] || die "$label owner is unsafe"
}
assert_source_file "$before4" 'UFW IPv4 before rules'
assert_source_file "$before6" 'UFW IPv6 before rules'
assert_source_file "$fragment4" 'managed UFW IPv4 fragment'
assert_source_file "$fragment6" 'managed UFW IPv6 fragment'

extract_block() {
  local path="$1" begin="$2" end="$3" output="$4"
  awk -v begin="$begin" -v end="$end" '
    $0 == begin { count_begin++; inside=1 }
    inside { print }
    $0 == end { count_end++; inside=0 }
    END {
      if (inside || count_begin != 1 || count_end != 1) exit 42
    }
  ' "$path" >"$output"
}

assert_exact_block() {
  local path="$1" fragment="$2" begin="$3" end="$4" extracted
  extracted=$(mktemp)
  if ! extract_block "$path" "$begin" "$end" "$extracted"; then
    rm -f -- "$extracted"
    die 'managed UFW block is missing, duplicated or malformed'
  fi
  cmp -s -- "$fragment" "$extracted" || {
    rm -f -- "$extracted"
    die 'managed UFW block differs from the audited fragment'
  }
  rm -f -- "$extracted"
}

assert_live_rules() {
  local -a live4 live6
  ufw status | grep -Fq 'Status: active' || die 'UFW is not active'
  iptables -C ufw-before-forward -i kw-host -s 169.254.254.2/32 -o @TARGET_INTERFACE@ \
    -m dscp --dscp 46 -j MARK --set-xmark 0x57525001/0xffffffff || \
    die 'live UFW DSCP-to-mark rule is absent'
  iptables -C ufw-before-forward -i kw-host -s 169.254.254.2/32 -o @TARGET_INTERFACE@ \
    -m mark --mark 0x57525001/0xffffffff -j ACCEPT || \
    die 'live UFW marked WARP outer allow is absent'
  iptables -C ufw-before-forward -i @TARGET_INTERFACE@ -o kw-host -d 169.254.254.2/32 \
    -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT || \
    die 'live UFW WARP reverse allow is absent'
  iptables -C ufw-before-forward -i kw-host -j DROP || \
    die 'live UFW unmarked namespace drop is absent'
  iptables -C ufw-before-forward -o kw-host -j DROP || \
    die 'live UFW unsolicited namespace drop is absent'
  ip6tables -C ufw6-before-forward -i kw-host -j DROP || \
    die 'live UFW IPv6 namespace source drop is absent'
  ip6tables -C ufw6-before-forward -o kw-host -j DROP || \
    die 'live UFW IPv6 namespace destination drop is absent'
  mapfile -t live4 < <(iptables -S ufw-before-forward | grep '^-A ')
  (( ${#live4[@]} >= 5 )) || die 'live UFW IPv4 before-forward chain is incomplete'
  [[ ${live4[0]} == *'-i kw-host'* && ${live4[0]} == *'-o @TARGET_INTERFACE@'* \
    && ${live4[0]} == *'169.254.254.2/32'* \
    && ${live4[0]} == *'--set-xmark 0x57525001'* \
    && ${live4[0]} == *'-j MARK'* ]] || \
    die 'live UFW DSCP-to-mark rule is not the first forward rule'
  grep -Eq -- '--dscp (46|0x2e)([[:space:]]|$)' <<<"${live4[0]}" || \
    die 'live UFW first forward rule has the wrong DSCP carrier'
  [[ ${live4[1]} == *'-i kw-host'* && ${live4[1]} == *'-o @TARGET_INTERFACE@'* \
    && ${live4[1]} == *'169.254.254.2/32'* \
    && ${live4[1]} == *'--mark 0x57525001'* \
    && ${live4[1]} == *'-j ACCEPT'* ]] || \
    die 'live UFW marked allow is not the second forward rule'
  [[ ${live4[2]} == *'-i @TARGET_INTERFACE@'* && ${live4[2]} == *'-o kw-host'* \
    && ${live4[2]} == *'169.254.254.2/32'* \
    && ${live4[2]} == *'RELATED,ESTABLISHED'* \
    && ${live4[2]} == *'-j ACCEPT'* ]] || \
    die 'live UFW reverse allow is not the third forward rule'
  [[ ${live4[3]} == *'-i kw-host'* && ${live4[3]} == *'-j DROP'* ]] || \
    die 'live UFW source drop is not the fourth forward rule'
  [[ ${live4[4]} == *'-o kw-host'* && ${live4[4]} == *'-j DROP'* ]] || \
    die 'live UFW destination drop is not the fifth forward rule'
  mapfile -t live6 < <(ip6tables -S ufw6-before-forward | grep '^-A ')
  (( ${#live6[@]} >= 2 )) || die 'live UFW IPv6 before-forward chain is incomplete'
  [[ ${live6[0]} == *'-i kw-host'* && ${live6[0]} == *'-j DROP'* ]] || \
    die 'live UFW IPv6 source drop is not the first forward rule'
  [[ ${live6[1]} == *'-o kw-host'* && ${live6[1]} == *'-j DROP'* ]] || \
    die 'live UFW IPv6 destination drop is not the second forward rule'
  [[ $(iptables -S FORWARD | awk '$1 == "-P" && $2 == "FORWARD" {print $3}') == DROP ]] || \
    die 'host IPv4 forward policy is not DROP'
  [[ $(ip6tables -S FORWARD | awk '$1 == "-P" && $2 == "FORWARD" {print $3}') == DROP ]] || \
    die 'host IPv6 forward policy is not DROP'
}

if [[ "$mode" == --check || "$mode" == --check-files ]]; then
  assert_exact_block "$before4" "$fragment4" "$begin4" "$end4"
  assert_exact_block "$before6" "$fragment6" "$begin6" "$end6"
  if [[ "$mode" == --check ]]; then
    assert_live_rules
    printf '%s\n' 'WARP_UFW_POSITIVE_MARK_GUARD_OK=1'
  else
    printf '%s\n' 'WARP_UFW_POSITIVE_MARK_FILES_OK=1'
  fi
  exit 0
fi

stage=$(mktemp -d)
changed=0
cleanup() {
  local rc=$?
  trap - EXIT
  if (( rc != 0 && changed == 1 )); then
    cp -a -- "$stage/before.rules" "$before4" || true
    cp -a -- "$stage/before6.rules" "$before6" || true
    ufw reload >/dev/null 2>&1 || true
  fi
  rm -rf -- "$stage"
  exit "$rc"
}
trap cleanup EXIT
cp -a -- "$before4" "$stage/before.rules"
cp -a -- "$before6" "$stage/before6.rules"

render_file() {
  local source="$1" fragment="$2" begin="$3" end="$4" anchor="$5" output="$6"
  local begin_count end_count
  begin_count=$(grep -Fxc "$begin" "$source" || true)
  end_count=$(grep -Fxc "$end" "$source" || true)
  if (( begin_count == 1 && end_count == 1 )); then
    extract_block "$source" "$begin" "$end" "$stage/extracted"
    cmp -s -- "$fragment" "$stage/extracted" || \
      die 'existing managed UFW block differs from the audited fragment'
    cp -- "$source" "$output"
  elif (( begin_count == 0 && end_count == 0 )); then
    awk -v anchor="$anchor" -v fragment="$fragment" '
      $0 ~ anchor {
        anchors++
        print
        while ((getline line < fragment) > 0) print line
        close(fragment)
        next
      }
      { print }
      END { if (anchors != 1) exit 42 }
    ' "$source" >"$output" || die 'could not insert managed UFW block at its chain anchor'
  else
    die 'partial managed UFW markers are unsafe'
  fi
}

render_file "$before4" "$fragment4" "$begin4" "$end4" \
  '^:ufw-before-forward[[:space:]]' "$stage/new-before.rules"
render_file "$before6" "$fragment6" "$begin6" "$end6" \
  '^:ufw6-before-forward[[:space:]]' "$stage/new-before6.rules"
iptables-restore --test <"$stage/new-before.rules"
ip6tables-restore --test <"$stage/new-before6.rules"

mode4=$(stat -c '%a' "$before4")
mode6=$(stat -c '%a' "$before6")
install -o root -g root -m "$mode4" "$stage/new-before.rules" "$before4"
changed=1
install -o root -g root -m "$mode6" "$stage/new-before6.rules" "$before6"
ufw reload >/dev/null
assert_exact_block "$before4" "$fragment4" "$begin4" "$end4"
assert_exact_block "$before6" "$fragment6" "$begin6" "$end6"
assert_live_rules
changed=0
printf '%s\n' 'WARP_UFW_POSITIVE_MARK_GUARD_APPLIED=1'
