"""Run ACME's actual timer-quiescence/cleanup code with a signal boundary."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'bundle/base/acme.sh'
BASH = os.environ.get('VPN_TEST_BASH') or shutil.which('bash')


@unittest.skipUnless(BASH, 'Bash is required')
class AcmeInterruption(unittest.TestCase):
    def test_term_after_timer_stop_restores_previously_active_timer(self):
        source = SOURCE.read_text(encoding='utf-8')
        cleanup = source[source.index('cleanup() {'):source.index('\ntrap cleanup EXIT')]
        begin = source.index('systemctl stop certbot.timer', source.index('trap cleanup EXIT'))
        # Include the production flag assignment regardless of which side of
        # the stop command it occupies. The mock signals before stop returns.
        if source[:begin].endswith('timer_stopped=1\n'):
            begin -= len('timer_stopped=1\n')
        end = source.index('tar --acls', begin)
        quiesce = source[begin:end]
        script = '''
set -Eeuo pipefail
exec 3>&1
committed=0
snapshot_ready=0
timer_stopped=0
systemctl() {
  if [[ $1 == stop ]]; then
    printf 'TIMER_STOPPED\\n'
    kill -TERM "$BASHPID"
  elif [[ $1 == start ]]; then
    printf 'TIMER_RESTORED\\n' >&3
  fi
}
''' + cleanup + '''
trap cleanup EXIT
trap 'exit 143' TERM
''' + quiesce
        result = subprocess.run([BASH, '--noprofile', '--norc', '-s'], input=script,
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 143, result.stdout + result.stderr)
        self.assertIn('TIMER_STOPPED', result.stdout)
        self.assertIn('TIMER_RESTORED', result.stdout)

    def test_unknown_or_running_renewal_preserves_live_certificate_tree(self):
        source = SOURCE.read_text(encoding='utf-8')
        helper = re.search(r'(?ms)^unit_is_quiescent\(\) \{.*?^\}', source)
        cleanup = source[source.index('cleanup() {'):source.index('\ntrap cleanup EXIT')]
        for state in ('timer-stop-failed', 'timer-readback-failed', 'unavailable',
                      'active', 'orphan', 'missing-pid', 'not-loaded',
                      'inactive', 'failed'):
            with self.subTest(state=state):
                script = r'''
set -Eeuo pipefail
exec 3>&1
committed=0
snapshot_ready=1
timer_stopped=1
snapshot=/private-fixture
systemctl() {
  if [[ $1 == show ]]; then
    if [[ $2 == certbot.timer ]]; then
      [[ $TEST_STATE != timer-readback-failed ]] || return 1
      printf 'LoadState=loaded\nActiveState=inactive\n'
      return 0
    fi
    [[ $TEST_STATE != unavailable ]] || return 1
    if [[ $TEST_STATE == not-loaded ]]; then printf 'LoadState=not-found\n'
    else printf 'LoadState=loaded\n'; fi
    case $TEST_STATE in active) printf 'ActiveState=active\n';;
      failed) printf 'ActiveState=failed\n';; *) printf 'ActiveState=inactive\n';; esac
    case $TEST_STATE in orphan) printf 'MainPID=321\n';;
      missing-pid) :;; *) printf 'MainPID=0\n';; esac
  elif [[ $1 == stop && $TEST_STATE == timer-stop-failed ]]; then return 1
  elif [[ $1 == start ]]; then printf 'TIMER_RESTORED\n' >&3; fi
}
mv() { printf 'CERTIFICATE_TREE_MOVED\n'; }
tar() { printf 'CERTIFICATE_TREE_RESTORED\n'; }
''' + (helper.group() + '\n' if helper else '') + cleanup + r'''
trap cleanup EXIT
exit 37
'''
                result = subprocess.run([BASH, '--noprofile', '--norc', '-s'], input=script,
                                        env=dict(os.environ, TEST_STATE=state),
                                        text=True, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 37, result.stdout + result.stderr)
                self.assertIn('TIMER_RESTORED', result.stdout)
                if state in ('inactive', 'failed'):
                    self.assertIn('CERTIFICATE_TREE_MOVED', result.stdout)
                    self.assertIn('CERTIFICATE_TREE_RESTORED', result.stdout)
                    self.assertIn('ACME_ROLLBACK_OK=1', result.stderr)
                else:
                    self.assertNotIn('CERTIFICATE_TREE_MOVED', result.stdout)
                    self.assertNotIn('CERTIFICATE_TREE_RESTORED', result.stdout)
                    self.assertIn('ACME_ROLLBACK_OK=0', result.stderr)


if __name__ == '__main__':
    unittest.main()
