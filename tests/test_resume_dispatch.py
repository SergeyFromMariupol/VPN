"""Execute raw new-entrypoint resume against a private older source fixture."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

RUN = r'''
set -Eeuo pipefail
umask 077
cleanup() {
  local rc=$?
  trap - EXIT
  case "$FIXTURE_ROOT" in /tmp/vpn-resume-test.*) ;; *) exit 98;; esac
  [[ ! -e $FIXTURE_ROOT/network-called ]] || { printf 'NETWORK_WAS_CALLED\n'; rc=99; }
  case "$CASE" in
    valid|installed-entrypoint)
      [[ -f $FIXTURE_ROOT/flock-called && $(wc -l <"$FIXTURE_ROOT/flock-called") == 1 ]] || rc=99;;
    *) [[ ! -e $FIXTURE_ROOT/flock-called ]] || rc=99;;
  esac
  rm -rf -- "$FIXTURE_ROOT/installed" "$FIXTURE_ROOT/installed-real"
  exit "$rc"
}
trap cleanup EXIT
chown -hR root:root "$FIXTURE_ROOT/installed"
chmod 0700 "$FIXTURE_ROOT/installed"
case "$CASE" in
  missing) rm -rf -- "$FIXTURE_ROOT/installed";;
  corrupt) printf '# altered\n' >>"$FIXTURE_ROOT/installed/install.sh";;
  missing-manifest) rm -- "$FIXTURE_ROOT/installed/SHA256SUMS";;
  omitted-entrypoint) printf '' >"$FIXTURE_ROOT/installed/SHA256SUMS";;
  corrupt-tracked) printf 'changed\n' >"$FIXTURE_ROOT/installed/tracked.txt";;
  script-symlink)
    mv "$FIXTURE_ROOT/installed/install.sh" "$FIXTURE_ROOT/installed/actual.sh"
    ln -s actual.sh "$FIXTURE_ROOT/installed/install.sh";;
  directory-symlink)
    mv "$FIXTURE_ROOT/installed" "$FIXTURE_ROOT/installed-real"
    ln -s installed-real "$FIXTURE_ROOT/installed";;
  writable-script) chmod 0666 "$FIXTURE_ROOT/installed/install.sh";;
  writable-directory) chmod 0770 "$FIXTURE_ROOT/installed";;
  wrong-owner) chown 65534:65534 "$FIXTURE_ROOT/installed/install.sh";;
  extra-symlink) ln -s /etc/os-release "$FIXTURE_ROOT/installed/untracked-link";;
esac
export PATH="$FIXTURE_ROOT/bin:/usr/sbin:/usr/bin:/sbin:/bin"
if [[ $CASE == installed-entrypoint ]]; then
  bash "$FIXTURE_ROOT/installed/install.sh" --resume
else
  bash "$FIXTURE_ROOT/raw/install.sh" --resume
fi
'''


@unittest.skipIf(os.name == 'nt', 'Actual root/Bash dispatch fixture runs in Ubuntu CI')
class ResumeDispatch(unittest.TestCase):
    def setUp(self):
        if os.geteuid() == 0:
            self.prefix = []
        elif shutil.which('sudo') and subprocess.run(
                ['sudo', '-n', 'true'], stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL).returncode == 0:
            self.prefix = ['sudo', '-n']
        else:
            if os.environ.get('CI'):
                self.fail('Ubuntu CI must run root resume dispatch fixtures')
            self.skipTest('Root or passwordless sudo required')

    def fixture(self, case, expected):
        with tempfile.TemporaryDirectory(prefix='vpn-resume-test.', dir='/tmp') as temp:
            root = Path(temp)
            for name in ('installed', 'raw', 'bin'):
                (root / name).mkdir()
            source = (ROOT / 'install.sh').read_text(encoding='utf-8')
            source = source.replace("readonly destination='/opt/vpn-installer'",
                                    "readonly destination='" + str(root / 'installed') + "'")
            source = source.replace('/run/vpn-installer.lock', str(root / 'installer.lock'))
            (root / 'raw/install.sh').write_text(source, encoding='utf-8')
            # The installed fixture has the actual dispatch code and an old
            # release's phase body. It proves no recursion or inherited lock.
            preamble = source.split('# Serialize all installs,', 1)[0]
            preamble = preamble.replace("readonly release='v1.1.3'", "readonly release='v1.1.2'")
            old_body = ('\n[[ $mode == --resume ]]\n'
                        'exec 9>"' + str(root / 'installer.lock') + '"\n'
                        'flock -n 9 || exit 72\n'
                        'printf "INSTALLED_OLD_RELEASE_RESUMED=1\\n"\n')
            installed = root / 'installed/install.sh'
            installed.write_text(preamble + old_body, encoding='utf-8')
            installed.chmod(0o700)
            tracked = root / 'installed/tracked.txt'
            tracked.write_text('reviewed offline source\n')
            (root / 'installed/SHA256SUMS').write_text(''.join(
                hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.name + '\n'
                for p in (installed, tracked)))
            curl = root / 'bin/curl'
            curl.write_text('#!/bin/sh\ntouch "' + str(root / 'network-called') + '"\nexit 91\n')
            curl.chmod(0o700)
            flock = root / 'bin/flock'
            flock.write_text('#!/bin/sh\nprintf "called\\n" >>"' + str(root / 'flock-called') +
                             '"\nexec /usr/bin/flock "$@"\n')
            flock.chmod(0o700)
            command = [*self.prefix, 'env', 'FIXTURE_ROOT=' + temp, 'CASE=' + case, 'bash']
            result = subprocess.run(command, input=RUN, text=True, capture_output=True, timeout=20)
            self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
            self.assertNotIn('NETWORK_WAS_CALLED', result.stdout + result.stderr)
            if expected == 0:
                self.assertIn('INSTALLED_OLD_RELEASE_RESUMED=1', result.stdout)

    def test_new_raw_entrypoint_resumes_installed_release_offline_before_lock(self):
        self.fixture('valid', 0)

    def test_installed_entrypoint_does_not_dispatch_recursively(self):
        self.fixture('installed-entrypoint', 0)

    def test_missing_and_corrupt_installed_source_is_rejected_without_network(self):
        for case in ('missing', 'corrupt', 'missing-manifest', 'omitted-entrypoint',
                     'corrupt-tracked'):
            with self.subTest(case=case):
                self.fixture(case, 1)

    def test_installed_links_ownership_and_write_permissions_are_rejected(self):
        for case in ('script-symlink', 'directory-symlink', 'writable-script',
                     'writable-directory', 'wrong-owner', 'extra-symlink'):
            with self.subTest(case=case):
                self.fixture(case, 1)


if __name__ == '__main__':
    unittest.main()
