"""Exercise the actual base readiness gate without touching host SSH."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'bundle/base/install-pinned-base.sh'


@unittest.skipUnless(os.name == 'posix' and shutil.which('bash'), 'Linux Bash is required')
class SshActivation(unittest.TestCase):
    def readiness(self, service=False, socket=False, listen='', port=22, show_status=0):
        with tempfile.TemporaryDirectory(prefix='vpn-ssh-readiness-') as temporary:
            root = Path(temporary)
            mock = root / 'systemctl'
            mock.write_text('''#!/bin/sh
case "$1:$2:$3" in
  is-active:--quiet:ssh.service) test "$SSH_FIXTURE_SERVICE" = 1;;
  is-active:--quiet:ssh.socket) test "$SSH_FIXTURE_SOCKET" = 1;;
  show:-p:Listen) printf '%s\\n' "$SSH_FIXTURE_LISTEN"; exit "$SSH_FIXTURE_SHOW_STATUS";;
  *) exit 98;;
esac
''')
            mock.chmod(0o755)
            source = SOURCE.read_text(encoding='utf-8')
            begin = source.index('ssh_activation_ready() {')
            end = source.index('\nrollback_packages()', begin)
            driver = root / 'driver.sh'
            driver.write_text('set -Eeuo pipefail\nTARGET_SSH_PORT=$1\n' + source[begin:end]
                              + '\nssh_activation_ready\n', encoding='utf-8')
            return subprocess.run(['bash', str(driver), str(port)], capture_output=True,
                text=True, timeout=10, env=dict(os.environ,
                    PATH=str(root) + os.pathsep + os.environ['PATH'],
                    SSH_FIXTURE_SERVICE=str(int(service)), SSH_FIXTURE_SOCKET=str(int(socket)),
                    SSH_FIXTURE_LISTEN=listen, SSH_FIXTURE_SHOW_STATUS=str(show_status)))

    def test_running_service_does_not_require_socket_activation(self):
        result = self.readiness(service=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_socket_only_console_installation_accepts_exact_stream_port(self):
        for port, listen in ((22, '0.0.0.0:22 (Stream) [::]:22 (Stream)'),
                             (2222, '[::]:2222 (Stream)'), (2222, '2222 (Stream)')):
            with self.subTest(port=port, listen=listen):
                result = self.readiness(socket=True, listen=listen, port=port)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_inactive_socket_wrong_port_and_datagram_are_not_ssh_readiness(self):
        for active, listen, port in ((False, '0.0.0.0:22 (Stream)', 22),
                                     (True, '0.0.0.0:2222 (Stream)', 22),
                                     (True, '[::]:22 (Stream)', 2222),
                                     (True, '0.0.0.0:22 (Datagram)', 22),
                                     (True, '', 22)):
            with self.subTest(active=active, listen=listen, port=port):
                self.assertNotEqual(self.readiness(socket=active, listen=listen,
                                                   port=port).returncode, 0)

    def test_failed_socket_readback_is_not_hidden_by_matching_text(self):
        self.assertNotEqual(self.readiness(socket=True, listen='22 (Stream)',
                                           show_status=1).returncode, 0)

    def test_production_keeps_config_and_actual_listener_gates(self):
        source = SOURCE.read_text(encoding='utf-8')
        self.assertIn('/usr/sbin/sshd -t', source)
        self.assertIn('ssh_activation_ready || die', source)
        self.assertIn('SSH listener disappeared after Ubuntu upgrade', source)


if __name__ == '__main__':
    unittest.main()
