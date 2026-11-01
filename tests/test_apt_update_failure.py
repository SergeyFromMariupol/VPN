"""Use real APT against a cached local repository with entirely private state."""
import email.utils
import hashlib
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


class CachedRepository(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        payload = self.server.repository_files.get(self.path)
        self.send_response(200 if payload is not None else 404)
        self.send_header('Content-Length', str(len(payload or b'')))
        self.end_headers()
        if payload is not None:
            self.wfile.write(payload)

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
            packages = b'\n'.join([
                b'Package: vpn-fixture-never-installed',
                b'Version: 1',
                b'Architecture: amd64',
                b'Maintainer: VPN installer tests <fixture@example.invalid>',
                b'Description: Private APT update fixture',
                b'Filename: pool/fixture.deb',
                b'Size: 1',
                b'SHA256: ' + b'0' * 64,
                b'', b'',
            ])
            release = ('Origin: VPN installer test\nLabel: VPN installer test\n'
                       'Suite: stable\nCodename: stable\n'
                       'Date: ' + email.utils.formatdate(usegmt=True) + '\n'
                       'Architectures: amd64\nComponents: main\nSHA256:\n '
                       + hashlib.sha256(packages).hexdigest() + ' ' + str(len(packages))
                       + ' main/binary-amd64/Packages\n').encode()
            with http.server.HTTPServer(('127.0.0.1', 0), CachedRepository) as server:
                server.repository_files = {
                    '/repo/dists/stable/Release': release,
                    '/repo/dists/stable/main/binary-amd64/Packages': packages,
                }
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    (root / 'etc/sources.list').write_text(
                        'deb [trusted=yes] http://127.0.0.1:' + str(server.server_port) + '/repo stable main\n')
                    env = dict(os.environ, APT_CONFIG=str(config), LC_ALL='C')
                    # Establish valid Release/index cache before the outage.
                    # An always-503 repository with no Release is a permanent
                    # metadata failure and returns 100 even without our guard.
                    warm = subprocess.run(['apt-get', 'update'], env=env,
                                          capture_output=True, text=True, timeout=15)
                    self.assertEqual(warm.returncode, 0, warm.stdout + warm.stderr)
                    self.assertNotIn('Failed to fetch', warm.stdout + warm.stderr)
                    cached_release = list((root / 'state/lists').glob('*_Release'))
                    self.assertEqual(len(cached_release), 1, warm.stdout + warm.stderr)
                    self.assertEqual(cached_release[0].read_bytes(), release)
                    self.assertTrue(any('_Packages' in path.name
                                        for path in (root / 'state/lists').iterdir()),
                                    warm.stdout + warm.stderr)
                    # Refuse loopback connections to the same source after a
                    # successful update. APT can reuse its valid private cache,
                    # so its default warning-only behavior is the control.
                    server.shutdown()
                    thread.join(timeout=5)
                    server.server_close()
                    normal = subprocess.run(['apt-get', 'update'], env=env,
                                            capture_output=True, text=True, timeout=15)
                    self.assertEqual(normal.returncode, 0, normal.stdout + normal.stderr)
                    self.assertIn('Failed to fetch', normal.stdout + normal.stderr)
                    self.assertIn('Could not connect', normal.stdout + normal.stderr)
                    self.assertEqual(cached_release[0].read_bytes(), release)
                    guarded = subprocess.run(['bash', '-c', 'source "$1"; vpn_apt_get update',
                                              '_', str(HELPER)], env=env,
                                             capture_output=True, text=True, timeout=15)
                    self.assertEqual(guarded.returncode, 100, guarded.stdout + guarded.stderr)
                    self.assertIn('Failed to fetch', guarded.stdout + guarded.stderr)
                    self.assertIn('Could not connect', guarded.stdout + guarded.stderr)
                    self.assertEqual(cached_release[0].read_bytes(), release)
                finally:
                    server.shutdown()
                    thread.join(timeout=5)


if __name__ == '__main__':
    unittest.main()
