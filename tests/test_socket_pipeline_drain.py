"""Real pipefail regression for large socket tables and quiet consumers."""
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


def production_query():
    source = (ROOT / 'bundle/warp-egress/tests/test-e2e-local.sh').read_text(encoding='utf-8')
    matches = re.findall(r'ss -H -lnt \| grep -E ":\$\{socks_port\}\[\[:space:\]\]" >/dev/null', source)
    if not matches:
        raise AssertionError('Production socket matcher not found')
    return matches[0]


class SocketConsumerAudit(unittest.TestCase):
    def test_all_shell_socket_table_consumers_drain_without_grep_quiet(self):
        for directory in ('bundle', 'tools'):
            for path in (ROOT / directory).rglob('*.sh'):
                source = path.read_text(encoding='utf-8')
                matches = re.findall(r'\bss\b[^\n|]*\|\s*grep\s+-[A-Za-z]*q[A-Za-z]*\b', source)
                self.assertEqual(matches, [], str(path.relative_to(ROOT)))


@unittest.skipUnless(os.name == 'posix' and shutil.which('bash'), 'Linux Bash pipeline regression')
class LargeSocketTablePipelines(unittest.TestCase):
    def run_pipeline(self, *, present=True, producer_status=0, old_quiet=False):
        first = b'LISTEN 0 128 127.0.0.1:12080 0.0.0.0:*\n' if present else b'LISTEN 0 128 127.0.0.1:9999 0.0.0.0:*\n'
        producer = ('import sys; sys.stdout.buffer.write(' + repr(first) + '); '
                    'sys.stdout.buffer.flush(); '
                    'sys.stdout.buffer.write(b"unrelated socket row\\n" * 500000); '
                    'sys.stdout.buffer.flush(); sys.exit(' + str(producer_status) + ')')
        query = production_query()
        if old_quiet:
            query = query.replace('grep -E ', 'grep -Eq ').replace(' >/dev/null', '')
        code = ('set -o pipefail; socks_port=12080; ss() { ' + shlex.quote(sys.executable) +
                ' -c ' + shlex.quote(producer) + '; }; ' + query)
        return subprocess.run(['bash', '-c', code], capture_output=True, timeout=15)

    def test_matching_socket_drains_entire_large_producer(self):
        result = self.run_pipeline()
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, b'')

    def test_absent_socket_still_fails(self):
        result = self.run_pipeline(present=False)
        self.assertEqual(result.returncode, 1)

    def test_real_producer_error_is_preserved(self):
        result = self.run_pipeline(producer_status=7)
        self.assertEqual(result.returncode, 7)

    def test_old_quiet_query_reproduces_sigpipe_failure(self):
        result = self.run_pipeline(old_quiet=True)
        self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
