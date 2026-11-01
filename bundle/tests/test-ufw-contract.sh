#!/usr/bin/env bash
# Exercise real Ubuntu UFW formatting without changing the runner's firewall.
set -euo pipefail
umask 077
[[ $EUID == 0 && ${GITHUB_ACTIONS:-} == true && ${CI:-} == true ]] || {
  printf 'ERROR: this privileged fixture is restricted to an ephemeral GitHub Actions runner\n' >&2
  exit 1
}
for executable in ufw ip unshare mount python3; do command -v "$executable" >/dev/null; done
bundle=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
fixture=$(mktemp -d)
cleanup() { rm -rf -- "$fixture"; }
trap cleanup EXIT
trap 'exit 130' INT; trap 'exit 143' TERM; trap 'exit 129' HUP
cp -a /etc/ufw "$fixture/ufw"
cp -a /etc/default "$fixture/default"
original_net=$(readlink /proc/self/ns/net)
original_mount=$(readlink /proc/self/ns/mnt)

# Mounts and netfilter state are private before any UFW command runs. Binding
# copied configuration and hiding /run also isolates persistent files and locks.
unshare --mount --net --propagation private bash -xEeuo pipefail -s -- \
  "$fixture" "$bundle" "$original_net" "$original_mount" <<'ISOLATED'
fixture=$1
bundle=$2
trap 'printf "ERROR: isolated UFW fixture failed at line %s: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
[[ $(readlink /proc/self/ns/net) != "$3" && $(readlink /proc/self/ns/mnt) != "$4" ]] || exit 1
mount --bind "$fixture/ufw" /etc/ufw
mount --bind "$fixture/default" /etc/default
mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run
export LC_ALL=C
ip link set lo up
ip link add vpnfixture0 type dummy
ip address add 8.8.4.4/32 dev vpnfixture0
ip link set vpnfixture0 up
python3 - <<'PY'
from pathlib import Path
import re
path = Path('/etc/default/ufw')
text, count = re.subn(r'^IPV6=.*$', 'IPV6=yes', path.read_text(), flags=re.M)
assert count == 1, 'Missing UFW IPv6 setting'
path.write_text(text)
PY
ufw --force reset >/dev/null
# UFW uses Python gettext, where LANGUAGE can override even LC_ALL=C. Bind a
# private catalog inside this mount namespace so the check does not depend on
# language packs installed on the runner and changes no host translation files.
# The Ubuntu CLI calls gettext.install('ufw') without localedir. The backend
# uses that builtins translator, whose default catalog directory is distinct
# from the CLI's later bindtextdomain(trans_dir/messages) directory. Query the
# system interpreter used by Ubuntu's /usr/sbin/ufw, then mask only an existing
# canonical catalog directory inside this already-private mount namespace.
translation_root=$(/usr/bin/python3 -c 'import gettext; print(gettext._default_localedir)')
[[ $translation_root == /usr/share/locale && -d $translation_root &&
   ! -L $translation_root && $(readlink -f -- "$translation_root") == "$translation_root" ]] || {
  printf 'ERROR: unexpected UFW default catalog directory: %q\n' "$translation_root" >&2
  exit 1
}
python3 "$bundle/../tests/test_locale_environment.py" --write-catalog "$fixture/ufw-locales"
mount --bind "$fixture/ufw-locales" "$translation_root"
export LC_ALL=C LANG=C LANGUAGE=ru
translated_status=$(ufw status)
[[ $translated_status == FIXTURE_TRANSLATED_INACTIVE ]] || {
  printf 'ERROR: UFW translation control failed; catalog=%q actual=%q\n' \
    "$translation_root" "$translated_status" >&2
  exit 1
}
export TARGET_IPV4=8.8.4.4 TARGET_FQDN=8.8.4.4 TARGET_ADDRESS_MODE=ip
export TARGET_INTERFACE=vpnfixture0 TARGET_SSH_PORT=2222 TARGET_DEVICE_LIMIT=0
export TARGET_REALITY_SNI=max.ru TARGET_LABEL=fixture
source "$bundle/scripts/target-contract.sh"
normalized_status=$(ufw status)
[[ $normalized_status == 'Status: inactive' ]] || {
  printf 'ERROR: UFW locale normalization failed; actual=%q\n' "$normalized_status" >&2
  exit 1
}
printf 'UFW_INHERITED_LANGUAGE_NORMALIZED_OK=1\n'
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw default deny routed >/dev/null
ufw allow 2222/tcp comment 'SSH key-only' >/dev/null
ufw allow 80/tcp comment 'ACME HTTP-01' >/dev/null
ufw --force enable >/dev/null
ufw allow 2096/tcp comment '3x-ui HTTPS subscription' >/dev/null
ufw allow 443/tcp comment 'VLESS REALITY' >/dev/null
ufw allow 443/udp comment 'Hysteria2' >/dev/null
ufw allow 8443/tcp comment 'VLESS XHTTP TLS H2' >/dev/null
ufw allow in on vpnfixture0 to 8.8.4.4 port 2053 proto tcp comment '3x-ui HTTPS panel' >/dev/null
ufw reload >/dev/null

check_contract() {
  local promoted=$1 expected=$2
  ufw status verbose >"$fixture/status.txt"
  python3 - "$bundle/scripts/network-contract.py" "$fixture/status.txt" "$promoted" "$expected" <<'PY'
from pathlib import Path
import runpy
import sys
contract = runpy.run_path(sys.argv[1])
try:
    contract['validate_ufw'](Path(sys.argv[2]).read_text(), '8.8.4.4', 'vpnfixture0', 2222,
                             sys.argv[3] == '1', Path('/etc/default/ufw').read_text())
except ValueError:
    if sys.argv[4] != 'reject':
        print(Path(sys.argv[2]).read_text(), file=sys.stderr)
        raise
else:
    if sys.argv[4] != 'accept':
        raise SystemExit('The real UFW output unexpectedly passed the firewall contract')
PY
}

check_contract 0 accept
ufw allow in on vpnfixture0 to 8.8.4.4 port 8444 proto tcp comment 'Direct XHTTP REALITY' >/dev/null
check_contract 1 accept
ufw allow 22/tcp >/dev/null
check_contract 1 reject
ufw --force delete allow 22/tcp >/dev/null
ufw --force delete allow in on vpnfixture0 to 8.8.4.4 port 8444 proto tcp >/dev/null
ufw allow 8444/tcp >/dev/null
check_contract 1 reject
ufw --force delete allow 8444/tcp >/dev/null
ufw allow in on vpnfixture0 to 8.8.4.4 port 8444 proto tcp >/dev/null
ufw default allow routed >/dev/null
check_contract 1 reject
printf 'UFW_REAL_CLI_CONTRACT_OK=1\n'
ISOLATED
