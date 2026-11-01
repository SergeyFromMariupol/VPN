"""Run the production exit cleanup and rerun guard in private root fixtures."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]

WRAPPER = r'''
set -Eeuo pipefail
umask 077
case "$FIXTURE_ROOT" in /tmp/vpn-resume-guidance.*) ;; *) exit 98;; esac
[[ -d $FIXTURE_ROOT && ! -L $FIXTURE_ROOT ]] || exit 98
cleanup_fixture() {
  local rc=$?
  trap - EXIT HUP INT TERM
  # This absolute random /tmp parent was validated above. Only fixture-owned
  # children are removed, including root-private context unreadable by CI user.
  rm -rf -- "$FIXTURE_ROOT/owned"
  exit "$rc"
}
trap cleanup_fixture EXIT
mkdir -m 0700 "$FIXTURE_ROOT/owned" "$FIXTURE_ROOT/owned/task"
if [[ $TEST_CONTEXT != missing ]]; then
  mkdir -m 0700 "$FIXTURE_ROOT/owned/state" "$FIXTURE_ROOT/owned/installed"
  printf 'preserve completed fixture checkpoint\n' >"$FIXTURE_ROOT/owned/state/keep"
  printf '#!/bin/bash\nexit 0\n' >"$FIXTURE_ROOT/owned/installed/install.sh"
  chmod 0700 "$FIXTURE_ROOT/owned/installed/install.sh"
  printf 'FIXTURE_ONLY=preserve\n' >"$FIXTURE_ROOT/owned/target.env"
  chmod 0600 "$FIXTURE_ROOT/owned/target.env"
fi
case $TEST_CONTEXT in
  state-mode) chmod 0755 "$FIXTURE_ROOT/owned/state";;
  destination-mode) chmod 0770 "$FIXTURE_ROOT/owned/installed";;
  target-mode) chmod 0644 "$FIXTURE_ROOT/owned/target.env";;
  target-hardlink) ln "$FIXTURE_ROOT/owned/target.env" "$FIXTURE_ROOT/owned/target-alias";;
  source-writable) chmod 0666 "$FIXTURE_ROOT/owned/installed/install.sh";;
  source-owner) chown 65534:65534 "$FIXTURE_ROOT/owned/installed/install.sh";;
  source-hardlink) ln "$FIXTURE_ROOT/owned/installed/install.sh" "$FIXTURE_ROOT/owned/source-alias";;
  source-symlink)
    mv "$FIXTURE_ROOT/owned/installed/install.sh" "$FIXTURE_ROOT/owned/source-real"
    ln -s ../source-real "$FIXTURE_ROOT/owned/installed/install.sh";;
  missing-source) rm -- "$FIXTURE_ROOT/owned/installed/install.sh";;
esac
if bash "$FIXTURE_ROOT/driver.sh"; then rc=0; else rc=$?; fi
[[ ! -e $FIXTURE_ROOT/owned/task && ! -L $FIXTURE_ROOT/owned/task ]] || exit 99
if [[ $TEST_CONTEXT != missing ]]; then
  [[ $(cat "$FIXTURE_ROOT/owned/state/keep") == 'preserve completed fixture checkpoint' &&
     $(cat "$FIXTURE_ROOT/owned/target.env") == FIXTURE_ONLY=preserve ]] || exit 99
fi
printf 'PRODUCTION_CLEANUP_AND_CONTEXT_PRESERVATION_OK=1\n'
exit "$rc"
'''


@unittest.skipIf(os.name == 'nt', 'Actual root/Bash cleanup fixtures run in Ubuntu CI')
class ResumeGuidance(unittest.TestCase):
    def setUp(self):
        if os.geteuid() == 0:
            self.prefix = []
        elif shutil.which('sudo') and subprocess.run(
                ['sudo', '-n', 'true'], stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL).returncode == 0:
            self.prefix = ['sudo', '-n']
        else:
            if os.environ.get('CI'):
                self.fail('Ubuntu CI must run actual root resume guidance fixtures')
            self.skipTest('Root or passwordless sudo required')

    def fixture(self, action, context='saved'):
        with tempfile.TemporaryDirectory(prefix='vpn-resume-guidance.', dir='/tmp') as temporary:
            root = Path(temporary).resolve()
            self.assertEqual(root.parent, Path('/tmp'))
            self.assertTrue(root.name.startswith('vpn-resume-guidance.'))
            source = (ROOT / 'install.sh').read_text(encoding='utf-8')
            replacements = {
                "readonly state='/var/lib/vpn-installer'":
                    "readonly state='" + str(root / 'owned/state') + "'",
                "readonly destination='/opt/vpn-installer'":
                    "readonly destination='" + str(root / 'owned/installed') + "'",
                "readonly target_file='/etc/germanyvpn-target.env'":
                    "readonly target_file='" + str(root / 'owned/target.env') + "'",
            }
            for original, replacement in replacements.items():
                self.assertIn(original, source)
                source = source.replace(original, replacement)
            # Execute the actual helpers and mode preamble. Package/platform
            # probes and all network/bootstrap transactions are excluded.
            preamble = source.split('# Serialize all installs,', 1)[0]
            self.assertIn('installer_resume_hint()', preamble)
            self.assertIn('installer_resume_ready()', preamble)
            cleanup_start = source.index('\ncleanup() {') + 1
            cleanup_end = source.index('\nsource_dir=', cleanup_start)
            cleanup = source[cleanup_start:cleanup_end]
            self.assertIn('trap cleanup EXIT', cleanup)
            # Extract the real previous-install branch, including its explicit
            # hint and exit, up to the fresh questionnaire's TTY requirement.
            resume_validation = source.split(
                'if [[ $mode == --resume ]]; then\n  [[ -d $state', 1)
            self.assertEqual(len(resume_validation), 2)
            guard = resume_validation[1].split('\nelse\n', 1)[1].split(
                '  [[ -r /dev/tty ]]', 1)[0]
            self.assertIn('installer_resume_hint', guard)
            driver = (preamble + '\ntask_stage="' + str(root / 'owned/task') + '"\n' +
                      cleanup + '\ncase $TEST_ACTION in\n'
                      '  success) exit 0;;\n'
                      '  error) exit 42;;\n'
                      '  HUP|INT|TERM) kill -s "$TEST_ACTION" "$BASHPID"; exit 97;;\n'
                      '  rerun)\n' + guard + '\nexit 96;;\n'
                      '  *) exit 98;;\nesac\n')
            (root / 'driver.sh').write_text(driver, encoding='utf-8')
            result = subprocess.run(
                [*self.prefix, 'env', 'FIXTURE_ROOT=' + str(root),
                 'TEST_ACTION=' + action, 'TEST_CONTEXT=' + context, 'bash'],
                input=WRAPPER, capture_output=True, text=True, timeout=20)
            self.assertIn('PRODUCTION_CLEANUP_AND_CONTEXT_PRESERVATION_OK=1',
                          result.stdout, result.stdout + result.stderr)
            self.assertFalse((root / 'owned').exists())
            command = 'bash ' + str(root / 'owned/installed/install.sh') + ' --resume'
            return result, command

    def assert_hint(self, result, command, expected):
        lines = result.stderr.splitlines()
        self.assertEqual(lines.count(command), 1 if expected else 0, result.stderr)
        if expected:
            index = lines.index(command)
            self.assertGreaterEqual(index, 2, result.stderr)
            self.assertEqual(lines[index - 1], '', result.stderr)
            self.assertIn('Скопируйте и выполните команду целиком', lines[index - 2])
            self.assertLess(index + 1, len(lines), result.stderr)
            self.assertEqual(lines[index + 1], '', result.stderr)
        self.assertNotIn('\n--resume\n', result.stderr)

    def test_cleanup_preserves_failure_status_and_only_offers_saved_installation(self):
        for context, action, code, hint in (
                ('saved', 'error', 42, True), ('saved', 'success', 0, False),
                ('missing', 'error', 42, False), ('missing', 'success', 0, False)):
            with self.subTest(context=context, action=action):
                result, command = self.fixture(action, context)
                self.assertEqual(result.returncode, code, result.stdout + result.stderr)
                self.assert_hint(result, command, hint)

    def test_signal_cleanup_preserves_original_status_with_or_without_saved_context(self):
        for action, code in (('HUP', 129), ('INT', 130), ('TERM', 143)):
            for context in ('saved', 'missing'):
                with self.subTest(signal=action, context=context):
                    result, command = self.fixture(action, context)
                    self.assertEqual(result.returncode, code, result.stdout + result.stderr)
                    self.assert_hint(result, command, context == 'saved')

    def test_unsafe_or_incomplete_saved_context_does_not_advertise_resume(self):
        for context in ('state-mode', 'destination-mode', 'target-mode', 'target-hardlink',
                        'source-writable', 'source-owner', 'source-hardlink',
                        'source-symlink', 'missing-source'):
            with self.subTest(context=context):
                result, command = self.fixture('error', context)
                self.assertEqual(result.returncode, 42, result.stdout + result.stderr)
                self.assert_hint(result, command, False)

    def test_previous_install_guard_prints_one_separate_copyable_full_command(self):
        result, command = self.fixture('rerun')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assert_hint(result, command, True)
        self.assertNotIn('используйте --resume', result.stderr)


if __name__ == '__main__':
    unittest.main()
