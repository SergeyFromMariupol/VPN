"""Use real APT against a local broken repository with entirely private state."""
import http.server
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest

HELPER = Path(__file__).resolve().parents[1] / 'bundle/base/apt-options.sh'


class BrokenRepository(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(503)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def log_message(self, *_):
        pass


@unittest.skipUnless(os.name == 'posix' and shutil.which('bash') and shutil.which('apt-get'),
                     'Real Linux APT/Bash fixture is required')
class AptUpdateFailure(unittest.TestCase):
    def test_transient_index_failure_is_not_reported_as_success(self):
        with tempfile.TemporaryDirectory(prefix='vpn-apt-update-') as temporary:
            root = Path(temporary)
            for name in ('etc/apt.conf.d', 'etc/sources.list.d', 'state/lists/partial',
                         'cache/archives/partial'):
                (root / name).mkdir(parents=True)
            (root / 'status').write_text('')
            (root / 'etc/apt.conf').write_text('')
            config = root / 'initial.conf'
            # APT_CONFIG is parsed before APT reads its normal parts/main file.
            # This prevents host post-update hooks and uses no host package/list
            # locks or source files. No package action is run by this fixture.
            config.write_text('\n'.join([
                'Dir::Etc ' + json.dumps(str(root / 'etc')) + ';',
                'Dir::Etc::main "apt.conf";',
                'Dir::Etc::parts "apt.conf.d";',
                'Dir::Etc::sourcelist "sources.list";',
                'Dir::Etc::sourceparts "sources.list.d";',
                'Dir::State ' + json.dumps(str(root / 'state')) + ';',
                'Dir::State::status ' + json.dumps(str(root / 'status')) + ';',
                'Dir::State::lists ' + json.dumps(str(root / 'state/lists')) + ';',
                'Dir::Cache ' + json.dumps(str(root / 'cache')) + ';',
                'Debug::NoLocking "true";',
                'APT::Sandbox::User "";',
                'Acquire::Retries "0";',
                'Acquire::http::Timeout "1";',
                'Acquire::http::Proxy "DIRECT";',
                'Acquire::Languages "none";',
            ]) + '\n')
            with http.server.HTTPServer(('127.0.0.1', 0), BrokenRepository) as server:
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    (root / 'etc/sources.list').write_text(
                        'deb [trusted=yes] http://127.0.0.1:' + str(server.server_port) + '/repo stable main\n')
                    env = dict(os.environ, APT_CONFIG=str(config), LC_ALL='C')
                    normal = subprocess.run(['apt-get', 'update'], env=env,
                                            capture_output=True, text=True, timeout=15)
                    self.assertEqual(normal.returncode, 0, normal.stdout + normal.stderr)
                    self.assertIn('503', normal.stdout + normal.stderr)
                    self.assertIn('Failed to fetch', normal.stdout + normal.stderr)
                    guarded = subprocess.run(['bash', '-c', 'source "$1"; vpn_apt_get update',
                                              '_', str(HELPER)], env=env,
                                             capture_output=True, text=True, timeout=15)
                    self.assertEqual(guarded.returncode, 100, guarded.stdout + guarded.stderr)
                    self.assertIn('503', guarded.stdout + guarded.stderr)
                    self.assertIn('Failed to fetch', guarded.stdout + guarded.stderr)
                finally:
                    server.shutdown()
                    thread.join(timeout=5)


if __name__ == '__main__':
    unittest.main()
