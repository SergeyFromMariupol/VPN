"""Exercise the real temporary policy helper in an isolated filesystem tree."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HELPER = Path(__file__).resolve().parents[1] / 'bundle/base/package-start-policy.sh'


@unittest.skipUnless(os.name == 'posix' and shutil.which('bash'), 'Linux Bash is required')
class PackageStartPolicy(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vpn-package-policy-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.policy = self.root / 'usr/sbin/policy-rc.d'
        self.mask = self.root / 'etc/systemd/system/nginx.service'
        self.policy.parent.mkdir(parents=True)
        self.mask.parent.mkdir(parents=True)
        self.fired = self.root / 'fault-fired'
        real_mv = shutil.which('mv')
        real_ln = shutil.which('ln')
        (self.bin / 'mv').write_text(f'''#!/bin/sh
last=''; previous=''
for arg do previous=$last; last=$arg; done
if [ "$last" = "$VPN_TEST_POLICY" ] && [ "$VPN_TEST_FAULT" = foreign-policy ]; then
  cp -- "$previous" "$last"
fi
if [ "$last" = "$VPN_TEST_MASK" ] && [ "$VPN_TEST_FAULT" = foreign-identical-mask ]; then
  {real_ln} -s /dev/null "$last"
fi
{real_mv} "$@" || exit $?
if [ ! -e "$VPN_TEST_FIRED" ]; then
  if {{ [ "$last" = "$VPN_TEST_POLICY" ] && [ "$VPN_TEST_FAULT" = term-policy ]; }} ||
     {{ [ "$last" = "$VPN_TEST_MASK" ] && [ "$VPN_TEST_FAULT" = term-mask ]; }}; then
    : >"$VPN_TEST_FIRED"
    kill -TERM "$PPID"
    sleep .1
  fi
fi
''')
        (self.bin / 'systemctl').write_text('''#!/bin/sh
printf '%s\\n' "$*" >>"$VPN_TEST_SYSTEMCTL"
exit "${VPN_TEST_RELOAD_EXIT:-0}"
''')
        for p in self.bin.iterdir():
            p.chmod(0o755)
        self.script = self.root / 'driver.sh'
        self.script.write_text('''#!/bin/bash
set -Eeuo pipefail
umask 077
source "$VPN_TEST_HELPER"
policy_path=$VPN_TEST_POLICY
nginx_mask=$VPN_TEST_MASK
die() { printf '%s\\n' "$*" >&2; exit 1; }
cleanup() {
  rc=$?
  trap - EXIT INT TERM HUP
  if restore_start_policy; then printf 'RESTORE_OK=1\\n'; else printf 'RESTORE_OK=0\\n'; rc=1; fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 143' TERM
prepare_start_policy
[[ -f $policy_path && ! -L $policy_path && $(stat -c %a "$policy_path") == 755 ]]
code=0
"$policy_path" || code=$?
[[ $code == 101 ]]
[[ -L $nginx_mask && $(readlink "$nginx_mask") == /dev/null ]]
restore_start_policy
printf 'POLICY_LIFECYCLE_OK=1\\n'
''')
        self.environment = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                                VPN_TEST_HELPER=str(HELPER), VPN_TEST_POLICY=str(self.policy),
                                VPN_TEST_MASK=str(self.mask), VPN_TEST_FIRED=str(self.fired),
                                VPN_TEST_SYSTEMCTL=str(self.root / 'systemctl.log'))

    def run_driver(self, fault='', reload_exit=0):
        return subprocess.run(['bash', str(self.script)], capture_output=True, text=True,
                              env=dict(self.environment, VPN_TEST_FAULT=fault,
                                       VPN_TEST_RELOAD_EXIT=str(reload_exit)), timeout=10)

    def assert_owned_artifacts_gone(self):
        self.assertFalse(self.policy.exists() or self.policy.is_symlink())
        self.assertFalse(self.mask.exists() or self.mask.is_symlink())
        self.assertEqual(list(self.root.rglob('.vpn-*')), [])

    def test_success_restores_package_starts_and_nginx_mask(self):
        result = self.run_driver()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('POLICY_LIFECYCLE_OK=1', result.stdout)
        self.assert_owned_artifacts_gone()

    def interrupted_then_retry(self, fault):
        first = self.run_driver(fault)
        self.assertTrue(self.fired.exists())
        self.assertEqual(first.returncode, 143, first.stderr)
        self.assertIn('RESTORE_OK=1', first.stdout)
        self.assert_owned_artifacts_gone()
        second = self.run_driver()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assert_owned_artifacts_gone()

    def test_signal_after_policy_publish_does_not_block_retry(self):
        self.interrupted_then_retry('term-policy')

    def test_signal_after_mask_publish_does_not_leave_nginx_masked(self):
        self.interrupted_then_retry('term-mask')

    def test_foreign_identical_policy_file_is_preserved(self):
        result = self.run_driver('foreign-policy')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('RESTORE_OK=0', result.stdout)
        self.assertEqual(self.policy.read_text(), '#!/bin/sh\nexit 101\n')
        self.assertFalse(self.mask.exists() or self.mask.is_symlink())
        self.assertEqual(list(self.root.rglob('.vpn-*')), [])

    def test_foreign_same_target_symlink_is_preserved(self):
        result = self.run_driver('foreign-identical-mask')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('RESTORE_OK=0', result.stdout)
        self.assertTrue(self.mask.is_symlink())
        self.assertEqual(self.mask.readlink(), Path('/dev/null'))
        self.assertFalse(self.policy.exists() or self.policy.is_symlink())
        self.assertEqual(list(self.root.rglob('.vpn-*')), [])

    def test_daemon_reload_failure_is_not_reported_as_restored(self):
        result = self.run_driver(reload_exit=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('RESTORE_OK=0', result.stdout)
        self.assert_owned_artifacts_gone()


if __name__ == '__main__':
    unittest.main()
