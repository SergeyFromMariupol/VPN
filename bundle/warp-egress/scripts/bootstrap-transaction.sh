#!/usr/bin/env bash
# shellcheck disable=SC2034 # Sourced bootstrap transaction API/state.
case ${TARGET_TLS_MODE:-letsencrypt} in
  letsencrypt|none) ;;
  *) printf '%s\n' 'ERROR: unsupported certificate mode for WARP bootstrap' >&2; return 1;;
esac

bootstrap_tls_enabled() { [[ ${TARGET_TLS_MODE:-letsencrypt} == letsencrypt ]]; }

bootstrap_snapshot_paths() {
  printf '%s\n' usr/local/x-ui etc/x-ui etc/nginx
  if bootstrap_tls_enabled; then printf '%s\n' etc/letsencrypt; fi
  printf '%s\n' etc/krysyuk-standalone etc/systemd/system etc/ufw etc/default/ufw etc/apt
}

bootstrap_capture_packages() {
  dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' | LC_ALL=C sort
}

bootstrap_capture_units() {
  local unit
  local -a units=(x-ui.service nginx.service)
  if bootstrap_tls_enabled; then units+=(certbot.timer); fi
  units+=(ssh.service ssh.socket)
  for unit in "${units[@]}"; do
    printf 'UNIT=%s\n' "$unit"
    systemctl show "$unit" -p ActiveState -p SubState -p UnitFileState -p MainPID
  done
}

bootstrap_capture_listeners() {
  ss -H -lntu | awk '{print $1, $5}' | LC_ALL=C sort
}

bootstrap_capture_app_hashes() {
  local path
  local -a paths=(/etc/krysyuk-standalone /etc/nginx)
  if bootstrap_tls_enabled; then paths+=(/etc/letsencrypt); fi
  paths+=(/usr/local/x-ui)
  for path in "${paths[@]}"; do
    find -L "$path" -type f ! -name '*.log' -print0
  done | LC_ALL=C sort -z | xargs -0 -r sha256sum
}

bootstrap_assert_direct_unchanged() {
  local suffix=$1 unit
  # shellcheck disable=SC2154 # script_dir is the readonly entrypoint API binding.
  "$script_dir/capture-main-routing.sh" >"$BT_SNAPSHOT/routing-$suffix.json" || return 1
  cmp -s "$BT_SNAPSHOT/routing-before.json" "$BT_SNAPSHOT/routing-$suffix.json" || return 1
  nft -s list ruleset >"$BT_SNAPSHOT/nft-$suffix.txt" || return 1
  cmp -s "$BT_SNAPSHOT/nft-before.txt" "$BT_SNAPSHOT/nft-$suffix.txt" || return 1
  ufw show added >"$BT_SNAPSHOT/ufw-$suffix.txt" || return 1
  cmp -s "$BT_SNAPSHOT/ufw-before.txt" "$BT_SNAPSHOT/ufw-$suffix.txt" || return 1
  bootstrap_capture_listeners >"$BT_SNAPSHOT/listeners-$suffix.txt" || return 1
  cmp -s "$BT_SNAPSHOT/listeners-before.txt" "$BT_SNAPSHOT/listeners-$suffix.txt" || return 1
  bootstrap_capture_units >"$BT_SNAPSHOT/units-$suffix.txt" || return 1
  cmp -s "$BT_SNAPSHOT/units-before.txt" "$BT_SNAPSHOT/units-$suffix.txt" || return 1
  bootstrap_capture_app_hashes >"$BT_SNAPSHOT/app-hashes-$suffix.txt" || return 1
  cmp -s "$BT_SNAPSHOT/app-hashes-before.txt" "$BT_SNAPSHOT/app-hashes-$suffix.txt" || return 1
  [[ $(sqlite3 /etc/x-ui/x-ui.db 'PRAGMA quick_check;') == ok ]] || return 1
  ! ip link show CloudflareWARP >/dev/null 2>&1 || return 1
  local -a units=(x-ui.service nginx.service)
  if bootstrap_tls_enabled; then units+=(certbot.timer); fi
  for unit in "${units[@]}"; do
    systemctl is-active --quiet "$unit" || return 1
  done
}

bootstrap_restore_policy() {
  (( BT_POLICY_CHANGED == 1 )) || return 0
  if [[ -f "$BT_SNAPSHOT/policy-rc.d-before" ]]; then
    cp -a -- "$BT_SNAPSHOT/policy-rc.d-before" /usr/sbin/policy-rc.d || return 1
  else
    rm -f -- /usr/sbin/policy-rc.d || return 1
  fi
  BT_POLICY_CHANGED=0
}

bootstrap_validate_plan() {
  local plan=$1 additions=$2
  python3 - "$BT_SNAPSHOT/packages-before.tsv" "$plan" "$additions" <<'PY'
import pathlib, re, sys
before, plan, additions = map(pathlib.Path, sys.argv[1:])
existing = {line.split("\t", 1)[0].split(":", 1)[0] for line in before.read_text().splitlines()}
new = set()
for line in plan.read_text().splitlines():
    if line.startswith("Remv "):
        raise SystemExit("ERROR: bootstrap APT plan would remove an existing package")
    if not line.startswith("Inst "):
        continue
    match = re.match(r"^Inst ([A-Za-z0-9.+:-]+) (?:\[[^\]]+\] )?\((\S+)", line)
    if not match:
        raise SystemExit("ERROR: cannot parse bootstrap APT install plan")
    package = match.group(1)
    if package.split(":", 1)[0] in existing:
        raise SystemExit("ERROR: bootstrap APT plan would change a pre-existing package")
    new.add(package)
additions.write_text("".join(name + "\n" for name in sorted(new)))
PY
}

bootstrap_apt_install() {
  local argument package status plan additions
  local -a requested=()
  for argument in "$@"; do
    if [[ "$argument" == /*.deb ]]; then
      package=$(dpkg-deb -f "$argument" Package)
      [[ "$package" == cloudflare-warp && $(dpkg-deb -f "$argument" Version) == "$WARP_VERSION" &&
         $(dpkg-deb -f "$argument" Architecture) == amd64 ]] || die 'unexpected local bootstrap package'
    else
      package=$argument
      [[ "$package" =~ ^[a-z0-9][a-z0-9+.-]*$ ]] || die 'unsafe bootstrap package name'
    fi
    status=$(dpkg-query -W -f='${db:Status-Abbrev}' "$package" 2>/dev/null || true)
    if [[ "$status" == 'ii ' ]]; then
      continue
    fi
    [[ -z "$status" || "$status" == 'un ' ]] || die 'bootstrap prerequisite has unresolved package state'
    requested+=("$argument")
  done
  (( ${#requested[@]} > 0 )) || return 0
  BT_APT_STEP=$((BT_APT_STEP + 1))
  plan="$BT_SNAPSHOT/apt-plan-$BT_APT_STEP.txt"
  additions="$BT_SNAPSHOT/apt-additions-$BT_APT_STEP.txt"
  LC_ALL=C apt-get --simulate --no-upgrade --no-remove --no-install-recommends \
    install "${requested[@]}" >"$plan"
  bootstrap_validate_plan "$plan" "$additions"
  cat "$additions" >>"$BT_SNAPSHOT/packages-allowed.txt"
  LC_ALL=C sort -u -o "$BT_SNAPSHOT/packages-allowed.txt" "$BT_SNAPSHOT/packages-allowed.txt"
  DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l NEEDRESTART_SUSPEND=1 \
    apt-get -y --no-upgrade --no-remove --no-install-recommends \
    -o DPkg::Lock::Timeout=30 install "${requested[@]}" \
    >"$BT_SNAPSHOT/apt-install-$BT_APT_STEP.log" 2>&1 || die 'guarded bootstrap package installation failed'
  bootstrap_assert_packages_unchanged
}

bootstrap_assert_packages_unchanged() {
  bootstrap_capture_packages >"$BT_SNAPSHOT/packages-current.tsv"
  python3 - "$BT_SNAPSHOT/packages-before.tsv" "$BT_SNAPSHOT/packages-current.tsv" \
    "$BT_SNAPSHOT/packages-allowed.txt" "$BT_SNAPSHOT/packages-added.txt" <<'PY'
import pathlib, sys
before_path, current_path, allowed_path, added_path = map(pathlib.Path, sys.argv[1:])
def read(path):
    return {line.split("\t", 1)[0]: line for line in path.read_text().splitlines()}
before, current = read(before_path), read(current_path)
for package, record in before.items():
    if current.get(package) != record:
        raise SystemExit("ERROR: bootstrap modified a pre-existing package")
allowed = {name.split(":", 1)[0] for name in allowed_path.read_text().splitlines()}
added = sorted(set(current) - set(before))
if any(name.split(":", 1)[0] not in allowed for name in added):
    raise SystemExit("ERROR: bootstrap installed a package outside its reviewed APT plan")
added_path.write_text("".join(name + "\n" for name in added))
PY
}

bootstrap_rollback() {
  local path record
  local -a added=()
  sha256sum --check "$BT_SNAPSHOT/SHA256SUMS" >/dev/null || return 1
  bootstrap_assert_packages_unchanged || return 1
  mapfile -t added <"$BT_SNAPSHOT/packages-added.txt"
  if (( ${#added[@]} > 0 )); then
    apt-mark unhold cloudflare-warp >/dev/null 2>&1 || true
    LC_ALL=C apt-get --simulate purge "${added[@]}" >"$BT_SNAPSHOT/apt-purge-plan.txt" || return 1
    python3 - "$BT_SNAPSHOT/packages-added.txt" "$BT_SNAPSHOT/apt-purge-plan.txt" <<'PY' || return 1
import pathlib, sys
allowed = {name.split(":", 1)[0] for name in pathlib.Path(sys.argv[1]).read_text().splitlines()}
for line in pathlib.Path(sys.argv[2]).read_text().splitlines():
    if line.startswith("Inst ") or (line.startswith("Remv ") and line.split()[1].split(":", 1)[0] not in allowed):
        raise SystemExit("ERROR: rollback APT plan would modify a pre-existing package")
PY
    DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l NEEDRESTART_SUSPEND=1 \
      apt-get -y -o DPkg::Lock::Timeout=30 purge "${added[@]}" \
      >"$BT_SNAPSHOT/apt-purge.log" 2>&1 || return 1
  fi
  if getent passwd xraywarp >/dev/null; then
    record=$(getent passwd xraywarp)
    [[ $(cut -d: -f6 <<<"$record") == /nonexistent &&
       $(cut -d: -f7 <<<"$record") == /usr/sbin/nologin ]] || return 1
    userdel xraywarp || return 1
  fi
  if getent group xraywarp >/dev/null; then
    [[ -z $(getent group xraywarp | cut -d: -f4) ]] || return 1
    groupdel xraywarp || return 1
  fi
  for path in "${BT_OWNED_PATHS[@]}"; do
    [[ ! -L "$path" || "$path" == /etc/systemd/system/warp-svc.service ||
       "$path" == /etc/systemd/system/multi-user.target.wants/warp-svc.service ]] || return 1
    # Every exact path below was checked absent before mutation; none contains
    # public/direct state. This allowlist is independent of package output.
    rm -rf -- "$path" || return 1
  done
  find /var/lib/apt/lists /var/lib/apt/lists/partial -maxdepth 1 -type f \
    -name 'pkg.cloudflareclient.com_*' -delete || return 1
  bootstrap_restore_policy || return 1
  systemctl daemon-reload || return 1
  bootstrap_capture_packages >"$BT_SNAPSHOT/packages-rolled-back.tsv" || return 1
  cmp -s "$BT_SNAPSHOT/packages-before.tsv" "$BT_SNAPSHOT/packages-rolled-back.tsv" || return 1
  apt-mark showmanual | LC_ALL=C sort >"$BT_SNAPSHOT/manual-rolled-back.txt" || return 1
  cmp -s "$BT_SNAPSHOT/manual-before.txt" "$BT_SNAPSHOT/manual-rolled-back.txt" || return 1
  apt-mark showhold | LC_ALL=C sort >"$BT_SNAPSHOT/holds-rolled-back.txt" || return 1
  cmp -s "$BT_SNAPSHOT/holds-before.txt" "$BT_SNAPSHOT/holds-rolled-back.txt" || return 1
  find /etc/apt -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum \
    >"$BT_SNAPSHOT/apt-config-hashes-rolled-back.txt" || return 1
  cmp -s "$BT_SNAPSHOT/apt-config-hashes-before.txt" "$BT_SNAPSHOT/apt-config-hashes-rolled-back.txt" || return 1
  bootstrap_assert_direct_unchanged rolled-back || return 1
  touch "$BT_SNAPSHOT/ROLLED_BACK" || return 1
  printf 'WARP_BOOTSTRAP_ROLLBACK_OK=1 snapshot=%s\n' "$BT_SNAPSHOT"
}

bootstrap_transaction_begin() {
  local command_name path
  local -a direct_units=(x-ui.service nginx.service) managed_snapshot_paths=()
  if bootstrap_tls_enabled; then direct_units+=(certbot.timer); fi
  for command_name in apt-get apt-mark awk cat cmp cp cut date diff dpkg-deb dpkg-query find flock \
    getent grep install ip jq nft python3 sha256sum sort sqlite3 ss stat systemctl tar ufw xargs; do
    command -v "$command_name" >/dev/null 2>&1 || die "bootstrap transaction tool missing: $command_name"
  done
  exec 8>/run/lock/germanyvpn-warp-bootstrap.lock
  flock -n 8 || die 'another WARP bootstrap is running'
  ip -o -4 address show dev @TARGET_INTERFACE@ | awk -v expected='@TARGET_IPV4@' 'split($4, p, "/") && p[1] == expected {found=1} END {exit !found}' ||
    die 'bootstrap target IPv4/interface does not match this bundle'
  [[ -z $(dpkg --audit) ]] || die 'resolve the pre-existing dpkg audit findings before bootstrap'
  if dpkg-query -W cloudflare-warp >/dev/null 2>&1 || command -v warp-cli >/dev/null 2>&1 ||
    getent passwd xraywarp >/dev/null || getent group xraywarp >/dev/null; then
    die 'clean-first bootstrap refuses existing WARP package, commands, or identity'
  fi
  readonly BT_OWNED_PATHS=(
    /etc/krysyuk-warp-egress /opt/krysyuk-warp-egress /usr/local/libexec/krysyuk-warp-egress
    /var/lib/krysyuk-warp-egress /var/lib/krysyuk-warp-egress-warp /var/log/krysyuk-warp-egress-warp
    /run/krysyuk-warp-egress /run/krysyuk-warp-egress-warp /etc/netns/krysyuk-warp
    /var/lib/cloudflare-warp /var/log/cloudflare-warp /run/cloudflare-warp
    /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
    /etc/apt/sources.list.d/cloudflare-client.list /etc/apt/preferences.d/90-krysyuk-cloudflare-warp
    /etc/apt/preferences.d/00-germanyvpn-warp-bootstrap-freeze
    /etc/systemd/system/warp-svc.service /etc/systemd/system/multi-user.target.wants/warp-svc.service
  )
  for path in "${BT_OWNED_PATHS[@]}"; do
    [[ ! -e "$path" && ! -L "$path" ]] || die 'clean-first bootstrap found an existing WARP-owned path'
  done
  [[ -z $(find /var/lib/apt/lists /var/lib/apt/lists/partial -maxdepth 1 -type f \
    -name 'pkg.cloudflareclient.com_*' -print -quit) ]] ||
    die 'clean-first bootstrap found prior Cloudflare APT state'
  [[ ! -L /usr/sbin/policy-rc.d && (! -e /usr/sbin/policy-rc.d || -f /usr/sbin/policy-rc.d) ]] ||
    die 'unsupported existing policy-rc.d'
  for path in "${direct_units[@]}"; do
    systemctl is-active --quiet "$path" || die 'direct stack must already be active'
  done
  BT_SNAPSHOT="/var/backups/krysyuk-standalone/$(date -u +%Y%m%dT%H%M%SZ)-warp-bootstrap-$$"
  install -d -o root -g root -m 0700 "$BT_SNAPSHOT"
  sqlite3 /etc/x-ui/x-ui.db ".backup '$BT_SNAPSHOT/x-ui.db'"
  [[ $(sqlite3 "$BT_SNAPSHOT/x-ui.db" 'PRAGMA quick_check;') == ok ]] || die 'SQLite bootstrap snapshot failed'
  mapfile -t managed_snapshot_paths < <(bootstrap_snapshot_paths)
  tar --acls --xattrs --numeric-owner --exclude='etc/x-ui/x-ui.db*' \
    -cpf "$BT_SNAPSHOT/managed-before.tar" -C / "${managed_snapshot_paths[@]}"
  tar -tf "$BT_SNAPSHOT/managed-before.tar" >/dev/null
  sha256sum "$BT_SNAPSHOT/managed-before.tar" "$BT_SNAPSHOT/x-ui.db" >"$BT_SNAPSHOT/SHA256SUMS"
  sha256sum --check "$BT_SNAPSHOT/SHA256SUMS" >/dev/null
  bootstrap_capture_packages >"$BT_SNAPSHOT/packages-before.tsv"
  apt-mark showmanual | LC_ALL=C sort >"$BT_SNAPSHOT/manual-before.txt"
  apt-mark showhold | LC_ALL=C sort >"$BT_SNAPSHOT/holds-before.txt"
  find /etc/apt -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum \
    >"$BT_SNAPSHOT/apt-config-hashes-before.txt"
  bootstrap_capture_units >"$BT_SNAPSHOT/units-before.txt"
  bootstrap_capture_listeners >"$BT_SNAPSHOT/listeners-before.txt"
  bootstrap_capture_app_hashes >"$BT_SNAPSHOT/app-hashes-before.txt"
  # shellcheck disable=SC2154 # script_dir is the readonly entrypoint API binding.
  "$script_dir/capture-main-routing.sh" >"$BT_SNAPSHOT/routing-before.json"
  nft -s list ruleset >"$BT_SNAPSHOT/nft-before.txt"
  ufw show added >"$BT_SNAPSHOT/ufw-before.txt"
  [[ ! -f /usr/sbin/policy-rc.d ]] || cp -a /usr/sbin/policy-rc.d "$BT_SNAPSHOT/policy-rc.d-before"
  printf '%s\n' "${BT_OWNED_PATHS[@]}" >"$BT_SNAPSHOT/absent-warp-paths-before.txt"
  : >"$BT_SNAPSHOT/packages-allowed.txt"
  BT_APT_STEP=0 BT_POLICY_CHANGED=0 BT_COMMITTED=0 BT_MUTATED=0
  stage=$(mktemp -d /var/tmp/germanyvpn-warp-bootstrap.XXXXXX)
  chmod 0700 "$stage"
  bootstrap_on_exit() {
    local rc=$?
    trap - EXIT HUP INT TERM
    if (( BT_COMMITTED == 0 && BT_MUTATED == 1 )); then
      clear_uncommitted_warp_phase_marker || rc=1
      if ! bootstrap_rollback; then
        printf 'WARP_BOOTSTRAP_ROLLBACK_FAILED=1 snapshot=%s\n' "$BT_SNAPSHOT" >&2
        rc=1
      fi
    fi
    bootstrap_restore_policy || rc=1
    rm -rf -- "$stage"
    exit "$rc"
  }
  trap bootstrap_on_exit EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  touch "$BT_SNAPSHOT/SNAPSHOT_COMPLETE"
  BT_MUTATED=1
  systemctl mask warp-svc.service >/dev/null
  [[ $(systemctl is-enabled warp-svc.service 2>/dev/null || true) == masked ]] || die 'host WARP mask failed'
  {
    printf '%s\n' '#!/bin/sh' 'for argument in "$@"; do' \
      '  case "$argument" in warp-svc|warp-svc.service) exit 101 ;; esac' 'done'
    if [[ -f "$BT_SNAPSHOT/policy-rc.d-before" ]]; then
      printf 'exec %s "$@"\n' "$BT_SNAPSHOT/policy-rc.d-before"
    else
      printf '%s\n' 'exit 0'
    fi
  } >"$stage/policy-rc.d"
  BT_POLICY_CHANGED=1
  install -o root -g root -m 0755 "$stage/policy-rc.d" /usr/sbin/policy-rc.d
  # Freeze every pre-existing installed package at its exact version for both
  # simulation and install. Dependency resolution must fail instead of finding
  # an upgrade path between the reviewed plan and the actual transaction.
  python3 - "$BT_SNAPSHOT/packages-before.tsv" \
    /etc/apt/preferences.d/00-germanyvpn-warp-bootstrap-freeze <<'PY'
import pathlib, sys
records = []
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    package, version, status = line.split("\t")
    if status == "ii ":
        records.append(f"Package: {package}\nPin: version {version}\nPin-Priority: 1001\n\n")
        records.append(f"Package: {package}\nPin: version *\nPin-Priority: -1\n\n")
pathlib.Path(sys.argv[2]).write_text("".join(records))
PY
  chmod 0644 /etc/apt/preferences.d/00-germanyvpn-warp-bootstrap-freeze
}

bootstrap_transaction_commit() {
  bootstrap_restore_policy
  bootstrap_assert_packages_unchanged
  rm -f -- /etc/apt/preferences.d/00-germanyvpn-warp-bootstrap-freeze
  bootstrap_assert_direct_unchanged committed || die 'bootstrap changed direct services, config, routing, firewall, or listeners'
  [[ $(systemctl is-enabled warp-svc.service 2>/dev/null || true) == masked ]] || die 'host WARP service must stay masked'
  ! systemctl is-active --quiet warp-svc.service || die 'host WARP service must stay inactive'
  apt-mark showmanual | LC_ALL=C sort >"$BT_SNAPSHOT/manual-committed.txt"
  apt-mark showhold | LC_ALL=C sort >"$BT_SNAPSHOT/holds-committed.txt"
  python3 - "$BT_SNAPSHOT/manual-before.txt" "$BT_SNAPSHOT/manual-committed.txt" \
    "$BT_SNAPSHOT/holds-before.txt" "$BT_SNAPSHOT/holds-committed.txt" <<'PY'
import pathlib, sys
before_manual, after_manual, before_holds, after_holds = [set(pathlib.Path(path).read_text().splitlines()) for path in sys.argv[1:]]
if not before_manual <= after_manual:
    raise SystemExit("ERROR: bootstrap changed pre-existing APT manual markers")
if after_holds != before_holds | {"cloudflare-warp"}:
    raise SystemExit("ERROR: bootstrap changed unrelated APT holds")
PY
  write_warp_phase_marker base
  touch "$BT_SNAPSHOT/COMMITTED"
  BT_COMMITTED=1
  printf 'WARP_BOOTSTRAP_TRANSACTION_COMMITTED=1 snapshot=%s\n' "$BT_SNAPSHOT"
}
