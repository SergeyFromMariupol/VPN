#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

test_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
readonly test_dir
bundle_root=$(cd -- "$test_dir/.." && pwd -P)
readonly bundle_root
readonly watchdog_source="$bundle_root/scripts/warp-health-watchdog.sh"

for command_name in cat grep mkdir mktemp mv rm sed; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'ERROR: required watchdog semantic-test tool is missing: %s\n' \
      "$command_name" >&2
    exit 1
  }
done
[[ -f "$watchdog_source" && ! -L "$watchdog_source" ]] || {
  echo 'ERROR: canonical WARP health watchdog source is missing or unsafe' >&2
  exit 1
}

test_root=$(mktemp -d)
readonly test_root
cleanup() {
  rm -rf -- "$test_root"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p -- "$test_root/libexec" "$test_root/cases"

# Execute a copy of the canonical watchdog, changing only its three absolute
# filesystem bindings. All readiness and HTTP functions come from the mock
# common.sh below, so this test cannot contact systemd, a namespace, or the
# network and cannot write the production health state or lock.
sed \
  -e 's|^readonly script_dir=.*$|readonly script_dir=${WATCHDOG_TEST_ROOT:?}/libexec|' \
  -e 's|^readonly state_dir=.*$|readonly state_dir=${WATCHDOG_TEST_CASE_DIR:?}/state|' \
  -e 's|^exec 9>/run/lock/krysyuk-warp-health[.]lock$|exec 9>"${WATCHDOG_TEST_CASE_DIR:?}/health.lock"|' \
  "$watchdog_source" >"$test_root/libexec/warp-health-watchdog.sh"

grep -Fqx 'readonly script_dir=${WATCHDOG_TEST_ROOT:?}/libexec' \
  "$test_root/libexec/warp-health-watchdog.sh" || {
  echo 'ERROR: semantic harness did not isolate the watchdog script directory' >&2
  exit 1
}
grep -Fqx 'readonly state_dir=${WATCHDOG_TEST_CASE_DIR:?}/state' \
  "$test_root/libexec/warp-health-watchdog.sh" || {
  echo 'ERROR: semantic harness did not isolate the watchdog state directory' >&2
  exit 1
}
grep -Fqx 'exec 9>"${WATCHDOG_TEST_CASE_DIR:?}/health.lock"' \
  "$test_root/libexec/warp-health-watchdog.sh" || {
  echo 'ERROR: semantic harness did not isolate the watchdog lock' >&2
  exit 1
}

cat >"$test_root/libexec/common.sh" <<'MOCK_COMMON'
#!/usr/bin/env bash

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_root() {
  return 0
}

require_command() {
  return 0
}

load_warp_egress_env() {
  WARP_EGRESS_IFACE=CloudflareWARP
  export WARP_EGRESS_IFACE
}

install() {
  [[ $# -eq 8 && $1 == -d && $2 == -o && $3 == root && $4 == -g &&
     $5 == root && $6 == -m && $7 == 0700 ]]
  command mkdir -p -- "$8"
}

chmod() {
  return 0
}

flock() {
  [[ $1 == -n && $2 == 9 ]]
}

systemctl() {
  [[ $1 == is-active && $2 == --quiet && -n ${3:-} ]]
}

assert_main_routing_unchanged() {
  return 0
}

warp_status_connected() {
  return 0
}

netns_exec() {
  local command_name=$1 url status label
  shift
  case "$command_name" in
    ip)
      if [[ $* == "link show $WARP_EGRESS_IFACE" ]]; then
        return 0
      fi
      if [[ $* == '-4 route get 1.1.1.1' ]]; then
        printf '1.1.1.1 dev %s src 172.16.0.2\n' "$WARP_EGRESS_IFACE"
        return 0
      fi
      ;;
    curl)
      url=${@: -1}
      case "$url" in
        https://cp.cloudflare.com/generate_204)
          label=cloudflare
          status=${MOCK_CF_STATUS:?}
          ;;
        https://www.gstatic.com/generate_204)
          label=gstatic
          status=${MOCK_GSTATIC_STATUS:?}
          ;;
        https://www.google.com/generate_204)
          label=google
          status=${MOCK_GOOGLE_STATUS:?}
          ;;
        *)
          printf 'ERROR: unexpected mocked watchdog URL: %s\n' "$url" >&2
          return 97
          ;;
      esac
      printf '%s\n' "$label" >>"${WATCHDOG_MOCK_CALL_LOG:?}"
      if [[ $status == transport-error ]]; then
        return 7
      fi
      [[ $status =~ ^[0-9]{3}$ ]] || return 98
      printf '%s' "$status"
      return 0
      ;;
  esac
  printf 'ERROR: unexpected mocked netns command: %s %s\n' \
    "$command_name" "$*" >&2
  return 99
}
MOCK_COMMON

run_case() {
  local name=$1 cf_status=$2 gstatic_status=$3 google_status=$4
  local expected_streak=$5 expected_success=$6 expected_call_order=$7
  local case_dir call_log output_log
  local actual_streak
  local -a actual_calls=()

  case_dir="$test_root/cases/$name"
  mkdir -p -- "$case_dir"
  call_log="$case_dir/calls"
  output_log="$case_dir/output"
  : >"$call_log"

  if ! WATCHDOG_TEST_ROOT="$test_root" \
      WATCHDOG_TEST_CASE_DIR="$case_dir" \
      WATCHDOG_MOCK_CALL_LOG="$call_log" \
      MOCK_CF_STATUS="$cf_status" \
      MOCK_GSTATIC_STATUS="$gstatic_status" \
      MOCK_GOOGLE_STATUS="$google_status" \
      "$BASH" "$test_root/libexec/warp-health-watchdog.sh" \
      >"$output_log" 2>&1; then
    printf 'ERROR: watchdog semantic case %s exited nonzero\n' "$name" >&2
    sed 's/^/  /' "$output_log" >&2
    return 1
  fi

  [[ -f "$case_dir/state/failure-streak" ]] || {
    printf 'ERROR: watchdog semantic case %s did not write its streak\n' \
      "$name" >&2
    return 1
  }
  actual_streak=$(<"$case_dir/state/failure-streak")
  [[ $actual_streak == "$expected_streak" ]] || {
    printf 'ERROR: watchdog semantic case %s streak=%s, expected=%s\n' \
      "$name" "$actual_streak" "$expected_streak" >&2
    return 1
  }

  if [[ $expected_success == yes ]]; then
    [[ -f "$case_dir/state/last-success-epoch" ]] || {
      printf 'ERROR: watchdog semantic case %s did not record success\n' \
        "$name" >&2
      return 1
    }
  elif [[ -e "$case_dir/state/last-success-epoch" ]]; then
    printf 'ERROR: watchdog semantic case %s incorrectly recorded success\n' \
      "$name" >&2
    return 1
  fi

  mapfile -t actual_calls <"$call_log"
  [[ ${actual_calls[*]} == "$expected_call_order" ]] || {
    printf 'ERROR: watchdog semantic case %s calls="%s", expected="%s"\n' \
      "$name" "${actual_calls[*]}" "$expected_call_order" >&2
    sed 's/^/  /' "$output_log" >&2
    return 1
  }
}

# Cloudflare is mandatory. Once it succeeds, either exact Google-family 204 is
# sufficient; both Google-family observers failing must fail the cycle.
run_case cloudflare_failure 500 204 204 1 no 'cloudflare'
run_case gstatic_success 204 204 500 0 yes 'cloudflare gstatic'
run_case google_fallback_success 204 500 204 0 yes \
  'cloudflare gstatic google'
run_case both_google_failure 204 500 500 1 no \
  'cloudflare gstatic google'
run_case cloudflare_transport_failure transport-error 204 204 1 no \
  'cloudflare'
run_case gstatic_transport_google_success 204 transport-error 204 0 yes \
  'cloudflare gstatic google'
run_case both_google_transport_failure 204 transport-error transport-error 1 no \
  'cloudflare gstatic google'

printf '%s\n' \
  'WARP_HEALTH_WATCHDOG_SEMANTICS_OK=1 cases=7 network=mocked state=isolated'
