"""Exercise WARP bootstrap snapshots/CAS with the certificate tree absent."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

DRIVER = r'''
set -Eeuo pipefail
umask 077
source "$BOOTSTRAP_LIBRARY"
BT_SNAPSHOT=$FIXTURE_ROOT/snapshot
mkdir "$BT_SNAPSHOT"
mkdir "$FIXTURE_ROOT/bin"
script_dir=$FIXTURE_ROOT/bin
printf '%s\n' '#!/bin/sh' 'printf "{\"fixture\":true}\n"' >"$script_dir/capture-main-routing.sh"
chmod 0700 "$script_dir/capture-main-routing.sh"
mapfile -t snapshot_paths < <(bootstrap_snapshot_paths)
for path in "${snapshot_paths[@]}"; do
  mkdir -p "$FIXTURE_ROOT/host/$path"
  printf 'preserve application bytes\n' >"$FIXTURE_ROOT/host/$path/fixture"
done
if [[ $TARGET_TLS_MODE == none ]]; then
  [[ ! -e $FIXTURE_ROOT/host/etc/letsencrypt ]]
fi
systemctl() {
  if [[ $* == *certbot.timer* && $TARGET_TLS_MODE == none ]]; then
    printf 'UNEXPECTED_CERTBOT_READ\n' >&2; return 79
  fi
  case $1 in
    show) printf 'ActiveState=active\nSubState=running\nUnitFileState=enabled\nMainPID=17\n';;
    is-active) return 0;;
    *) return 78;;
  esac
}
find() {
  [[ $1 == -L ]] || return 77
  local path=$2
  shift 2
  if [[ $path == /etc/letsencrypt && $TARGET_TLS_MODE == none ]]; then
    printf 'UNEXPECTED_CERTIFICATE_READ\n' >&2; return 76
  fi
  command find -L "$FIXTURE_ROOT/host$path" "$@"
}
sqlite3() { printf 'ok\n'; }
ip() { return 1; }
nft() { printf 'fixture nft baseline\n'; }
ufw() { printf 'fixture ufw baseline\n'; }
ss() { printf 'tcp LISTEN 0 1 198.51.100.42:443 0.0.0.0:*\n'; }

bootstrap_capture_units >"$BT_SNAPSHOT/units-before.txt"
bootstrap_capture_app_hashes >"$BT_SNAPSHOT/app-hashes-before.txt"
grep -Fq '/etc/krysyuk-standalone/fixture' "$BT_SNAPSHOT/app-hashes-before.txt"
grep -Fq '/etc/nginx/fixture' "$BT_SNAPSHOT/app-hashes-before.txt"
grep -Fq '/usr/local/x-ui/fixture' "$BT_SNAPSHOT/app-hashes-before.txt"
if [[ $TARGET_TLS_MODE == none ]]; then
  ! grep -Fq certbot.timer "$BT_SNAPSHOT/units-before.txt"
  ! grep -Fq letsencrypt "$BT_SNAPSHOT/app-hashes-before.txt"
else
  grep -Fq certbot.timer "$BT_SNAPSHOT/units-before.txt"
  grep -Fq '/etc/letsencrypt/fixture' "$BT_SNAPSHOT/app-hashes-before.txt"
fi
tar -cpf "$FIXTURE_ROOT/managed.tar" -C "$FIXTURE_ROOT/host" "${snapshot_paths[@]}"
tar -tf "$FIXTURE_ROOT/managed.tar" >"$FIXTURE_ROOT/members"
if [[ $TARGET_TLS_MODE == none ]]; then
  ! grep -Fq etc/letsencrypt "$FIXTURE_ROOT/members"
else
  grep -Fq etc/letsencrypt "$FIXTURE_ROOT/members"
fi
if [[ $TEST_CASE == cas ]]; then
  "$script_dir/capture-main-routing.sh" >"$BT_SNAPSHOT/routing-before.json"
  nft -s list ruleset >"$BT_SNAPSHOT/nft-before.txt"
  ufw show added >"$BT_SNAPSHOT/ufw-before.txt"
  bootstrap_capture_listeners >"$BT_SNAPSHOT/listeners-before.txt"
  bootstrap_assert_direct_unchanged unchanged
  printf 'foreign changed bytes\n' >"$FIXTURE_ROOT/host/usr/local/x-ui/fixture"
  if bootstrap_assert_direct_unchanged foreign; then
    printf 'FOREIGN_APPLICATION_CHANGE_ACCEPTED\n' >&2; exit 75
  fi
fi
printf 'BOOTSTRAP_CERTIFICATE_MODE_OK=%s:%s\n' "$TARGET_TLS_MODE" "$TEST_CASE"
'''


@unittest.skipIf(os.name == 'nt', 'Actual GNU tar/hash/Bash fixtures run in Ubuntu CI')
class WarpBootstrapCertificateMode(unittest.TestCase):
    def fixture(self, mode, case):
        with tempfile.TemporaryDirectory(prefix='vpn-warp-certificate-mode.') as directory:
            env = dict(os.environ, FIXTURE_ROOT=directory, TARGET_TLS_MODE=mode,
                       TEST_CASE=case, BOOTSTRAP_LIBRARY=str(ROOT / 'bundle/warp-egress/scripts/bootstrap-transaction.sh'))
            result = subprocess.run(['bash', '-s'], input=DRIVER, text=True,
                                    capture_output=True, env=env, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('BOOTSTRAP_CERTIFICATE_MODE_OK=' + mode + ':' + case, result.stdout)
            self.assertNotIn('UNEXPECTED_', result.stderr)

    def test_snapshot_hashes_and_units_allow_an_absent_certificate_tree(self):
        for mode in ('none', 'letsencrypt'):
            with self.subTest(mode=mode):
                self.fixture(mode, 'snapshot')

    def test_direct_application_cas_still_detects_changed_bytes_in_both_modes(self):
        for mode in ('none', 'letsencrypt'):
            with self.subTest(mode=mode):
                self.fixture(mode, 'cas')


if __name__ == '__main__':
    unittest.main()
