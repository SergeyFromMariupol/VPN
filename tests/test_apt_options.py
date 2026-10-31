"""Exercise the shared APT invocation without touching the package manager."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'bundle/base/apt-options.sh'


@unittest.skipUnless(os.name == 'posix' and shutil.which('bash'), 'Bash is required')
class AptOptions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vpn-apt-options-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        apt = self.root / 'apt-get'
        apt.write_text('#!/bin/sh\nprintf "%s\\0" "$DEBIAN_FRONTEND" "$@"\n'
                       'exit "${VPN_APT_EXIT:-0}"\n')
        apt.chmod(0o755)

    def invoke(self, args, code=0):
        result = subprocess.run(['bash', '-c', 'source "$1"; shift; vpn_apt_get "$@"',
                                 '_', str(HELPER), *args], capture_output=True,
                                env=dict(os.environ, PATH=str(self.root) + os.pathsep + os.environ['PATH'],
                                         DEBIAN_FRONTEND='dialog', VPN_APT_EXIT=str(code)))
        return result, result.stdout.decode().rstrip('\0').split('\0')

    def test_noninteractive_wait_and_conffile_policy_apply_to_every_operation(self):
        operations = [('update',), ('-s', '--no-remove', 'upgrade'),
                      ('upgrade', '-y', '--no-remove'), ('check',),
                      ('-s', 'purge', 'new-package'), ('purge', '-y', 'new-package'),
                      ('install', '-y', '--no-upgrade', '--no-remove', 'python3-venv')]
        prefix = ['noninteractive', '-o', 'DPkg::Lock::Timeout=180',
                  '-o', 'Dpkg::Options::=--force-confdef',
                  '-o', 'Dpkg::Options::=--force-confold']
        for args in operations:
            with self.subTest(args=args):
                result, observed = self.invoke(args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(observed, prefix + list(args))

    def test_package_manager_failure_is_not_masked(self):
        result, _ = self.invoke(('upgrade', '-y', '--no-remove'), 100)
        self.assertEqual(result.returncode, 100)

    def test_base_install_and_rollback_have_no_unguarded_apt_calls(self):
        source = (ROOT / 'bundle/base/install-pinned-base.sh').read_text()
        self.assertIn('source "$bundle_root/base/apt-options.sh"', source)
        self.assertNotIn('apt-get ', source)


if __name__ == '__main__':
    unittest.main()
