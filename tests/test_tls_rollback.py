"""Execute the production cleanup with a virtual filesystem and failed mv.

No OpenSSL, host paths or services are touched. The Linux hook tests exercise
the complete transaction; this focused case also runs in a Windows Bash.
"""
import os
from pathlib import Path
import shutil
import subprocess
import unittest

HOOK = Path(__file__).resolve().parents[1] / 'bundle/templates/60-krysyuk-standalone-xui'
BASH = os.environ.get('VPN_TEST_BASH') or shutil.which('bash')


@unittest.skipUnless(BASH, 'Bash is required')
class TlsRollback(unittest.TestCase):
    def run_cleanup(self, mode, pointer='tls-gen.new'):
        source = HOOK.read_text(encoding='utf-8')
        begin = source.index('cleanup() {')
        end = source.index('\ntrap cleanup EXIT', begin)
        driver = '''
set -u
root=/fixture/runtime
new=$root/tls-gen.new
previous=tls-gen.old
link=$root/.tls-next
marker=$root/marker
marker_stage=''
marker_before=''
marker_written=0
marker_existed=0
committed=0
switched=1
nginx_config=/fixture/no-panel
pointer=$TEST_POINTER
basename() { printf '%s\\n' "${1##*/}"; }
tls_pointer_target() { printf '%s\\n' "$pointer"; }
readlink() { printf '%s\\n' "$pointer"; }
ln() { printf 'CREATE_ROLLBACK_LINK\\n'; }
mv() {
  printf 'MOVE_ROLLBACK_POINTER\\n'
  if [[ $TEST_MODE == failed-move ]]; then return 1; fi
  pointer=$previous
}
rm() {
  if [[ $* == *tls-gen.new* ]]; then
    printf 'DELETE_NEW_FILES\\n'
    [[ $pointer != tls-gen.new ]] || printf 'DANGLING_CURRENT_POINTER\\n'
  fi
}
rmdir() { printf 'DELETE_NEW_GENERATION\\n'; }
systemctl() { :; }
nginx() { :; }
''' + source[begin:end] + '\nfalse\ncleanup\n'
        return subprocess.run([BASH, '--noprofile', '--norc', '-s'], input=driver,
                              text=True, capture_output=True, timeout=10,
                              env=dict(os.environ, TEST_MODE=mode, TEST_POINTER=pointer))

    def test_failed_pointer_restore_keeps_the_referenced_valid_generation(self):
        result = self.run_cleanup('failed-move')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('DELETE_NEW_GENERATION', result.stdout)
        self.assertNotIn('DANGLING_CURRENT_POINTER', result.stdout)

    def test_successful_pointer_restore_removes_only_the_unreferenced_generation(self):
        result = self.run_cleanup('success')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('MOVE_ROLLBACK_POINTER', result.stdout)
        self.assertIn('DELETE_NEW_GENERATION', result.stdout)
        self.assertNotIn('DANGLING_CURRENT_POINTER', result.stdout)

    def test_foreign_pointer_is_not_overwritten_or_used_to_delete_generation(self):
        result = self.run_cleanup('success', 'tls-gen.foreign')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('MOVE_ROLLBACK_POINTER', result.stdout)
        self.assertNotIn('DELETE_NEW_GENERATION', result.stdout)


if __name__ == '__main__':
    unittest.main()
