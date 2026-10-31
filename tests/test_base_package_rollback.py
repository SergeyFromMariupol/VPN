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


@unittest.skipUnless(os.name == 'posix' and shutil.which('bash'), 'Linux Bash is required')
class BaseManualMarks(unittest.TestCase):
    def restore(self, manual, requested, plan='', attempted=True):
        with tempfile.TemporaryDirectory(prefix='vpn-manual-marks-') as temp:
            root = Path(temp)
            (root / 'apt-manual.before').write_text('baseline\n')
            (root / 'current-manual').write_text('baseline\n' + ''.join(p + '\n' for p in manual))
            if plan is not None:
                (root / 'apt-install-plan.txt').write_text(plan)
            binary = root / 'apt-mark'
            binary.write_text('''#!/bin/sh
if [ "$1" = showmanual ]; then cat "$VPN_MARK_ROOT/current-manual"; else
  printf '%s\\n' "$*" >>"$VPN_MARK_ROOT/mark-calls"
fi
''')
            binary.chmod(0o755)
            source = SOURCE.read_text()
            begin = source.index('restore_package_marks() {')
            end = source.index('\ntransaction_exit()', begin)
            driver = root / 'driver.sh'
            driver.write_text('''set -Eeuo pipefail
backup=$VPN_MARK_ROOT
apt_install_attempted=$VPN_MARK_ATTEMPTED
base_packages=("$@")
''' + source[begin:end] + '\nrestore_package_marks\n')
            result = subprocess.run(['bash', str(driver), *requested], capture_output=True,
                                    text=True, env=dict(os.environ,
                                        PATH=str(root) + os.pathsep + os.environ['PATH'],
                                        VPN_MARK_ROOT=str(root), VPN_MARK_ATTEMPTED=str(int(attempted))),
                                    timeout=10)
            calls = (root / 'mark-calls').read_text().splitlines() if (root / 'mark-calls').exists() else []
            return result, calls

    def test_foreign_manual_addition_is_never_marked_auto(self):
        for manual in (['foreign'], ['curl', 'foreign']):
            with self.subTest(manual=manual):
                result, calls = self.restore(manual, ['curl'], 'Inst curl (1.0 Ubuntu [amd64])\n')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [])

    def test_explicit_preexisting_auto_package_can_be_restored_to_auto(self):
        for package in ('curl', 'curl:amd64'):
            with self.subTest(package=package):
                result, calls = self.restore([package], ['curl'])
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(calls, ['auto ' + package])

    def test_only_new_plan_dependencies_are_owned(self):
        result, calls = self.restore(['dependency'], ['curl'], 'Inst dependency (1.0 Ubuntu [amd64])\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, ['auto dependency'])
        result, calls = self.restore(['dependency'], ['curl'], 'Inst dependency [0.9] (1.0 Ubuntu [amd64])\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])

    def test_unattempted_install_or_missing_plan_cannot_own_marks(self):
        for plan, attempted in (('', False), (None, True)):
            with self.subTest(plan=plan, attempted=attempted):
                result, calls = self.restore(['curl'], ['curl'], plan, attempted)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [])

    def test_other_architecture_is_not_owned(self):
        result, calls = self.restore(['curl:arm64'], ['curl'])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])

    def test_unchanged_marks_need_no_plan_or_mutation(self):
        result, calls = self.restore([], [], None, False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [])


if __name__ == '__main__':
    unittest.main()
