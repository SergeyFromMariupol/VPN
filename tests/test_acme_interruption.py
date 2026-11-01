"""Run ACME's actual timer-quiescence/cleanup code with a signal boundary."""
import os
from pathlib import Path
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
        end = source.index('! systemctl is-active --quiet certbot.service', begin)
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


if __name__ == '__main__':
    unittest.main()
