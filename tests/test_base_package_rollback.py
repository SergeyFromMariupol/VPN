"""Exercise the actual base rollback function with an inert package manager."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'bundle/base/install-pinned-base.sh'


@unittest.skipUnless(os.name == 'posix' and shutil.which('bash'), 'Linux Bash is required')
class BasePackageRollback(unittest.TestCase):
    def rollback(self, additions, plan, purge_plan=None):
        with tempfile.TemporaryDirectory(prefix='vpn-package-rollback-') as temp:
            root = Path(temp)
            (root / 'packages.installed.before').write_text('baseline\n')
            (root / 'current').write_text('baseline\n' + ''.join(p + '\n' for p in additions))
            if plan is not None:
                (root / 'apt-install-plan.txt').write_text(plan)
            (root / 'simulated-purge').write_text(purge_plan if purge_plan is not None else
                                                 ''.join('Purg ' + p + '\n' for p in additions))
            source = SOURCE.read_text()
            begin = source.index('rollback_packages() {')
            end = source.index('\nrestore_package_marks()', begin)
            function = source[begin:end]
            driver = root / 'driver.sh'
            driver.write_text('''set -Eeuo pipefail
backup=$VPN_ROLLBACK_ROOT
installed_packages() { LC_ALL=C sort -u "$backup/current"; }
vpn_apt_get() {
  printf '%s\\n' "$*" >>"$backup/apt-calls"
  if [[ $1 == -s ]]; then cat "$backup/simulated-purge"; fi
}
''' + function + '\nrollback_packages\n')
            result = subprocess.run(['bash', str(driver)], capture_output=True, text=True,
                                    env=dict(os.environ, VPN_ROLLBACK_ROOT=str(root)), timeout=10)
            calls = (root / 'apt-calls').read_text().splitlines() if (root / 'apt-calls').exists() else []
            return result, calls

    def test_only_approved_new_packages_can_be_purged(self):
        for package in ('approved', 'approved:amd64'):
            with self.subTest(package=package):
                result, calls = self.rollback([package], 'Inst approved (1.0 Ubuntu [amd64])\n')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(calls, ['-s purge ' + package, 'purge -y ' + package])

    def test_foreign_addition_blocks_all_purge_commands(self):
        for additions, plan in ((['approved', 'foreign'], 'Inst approved (1.0 Ubuntu [amd64])\n'),
                                 (['foreign'], None),
                                 (['approved:arm64'], 'Inst approved (1.0 Ubuntu [amd64])\n'),
                                 (['upgraded'], 'Inst upgraded [0.9] (1.0 Ubuntu [amd64])\n')):
            with self.subTest(additions=additions, plan=plan):
                result, calls = self.rollback(additions, plan)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [])

    def test_empty_addition_set_needs_no_install_plan_or_purge(self):
        result, calls = self.rollback([], None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [])

    def test_simulated_purge_cannot_remove_a_preexisting_package(self):
        result, calls = self.rollback(['approved'], 'Inst approved (1.0 Ubuntu [amd64])\n',
                                      'Purg approved\nPurg baseline\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, ['-s purge approved'])


if __name__ == '__main__':
    unittest.main()
