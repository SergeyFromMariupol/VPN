"""Exercise reload readiness with real Unix listeners and process descriptors."""
import importlib.util
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('php_readiness', ROOT / 'bundle/base/reality-decoy-php.py')
PHP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PHP)


class BoundedReadiness(unittest.TestCase):
    def test_transient_response_is_retried_until_the_new_worker_handles_it(self):
        calls = []
        def check(remaining):
            calls.append(remaining)
            if len(calls) < 3:
                raise ValueError('REALITY_DECOY_PHP_EXECUTION')
        PHP.wait_ready(check, timeout=1, interval=0.02)
        self.assertEqual(len(calls), 3)
        self.assertTrue(all(0 < x <= 1 for x in calls))
        self.assertGreater(calls[0], calls[-1])

    def test_missing_socket_has_a_fixed_deadline_instead_of_an_unbounded_retry(self):
        def not_ready(_remaining):
            raise FileNotFoundError('pool still reloading')
        started = time.monotonic()
        with self.assertRaisesRegex(RuntimeError, 'FIXED_TIMEOUT'):
            PHP.wait_ready(not_ready, timeout=0.05, interval=0.005, error_code='FIXED_TIMEOUT')
        self.assertLess(time.monotonic() - started, 0.5)

    def test_source_code_response_is_rejected_immediately_without_retry(self):
        calls = []
        def unsafe(_remaining):
            calls.append(1)
            raise ValueError('REALITY_DECOY_PHP_SOURCE_EXPOSED')
        with self.assertRaisesRegex(ValueError, 'SOURCE_EXPOSED'):
            PHP.wait_ready(unsafe, timeout=1, interval=0.001)
        self.assertEqual(calls, [1])


@unittest.skipUnless(os.name == 'posix' and Path('/proc/net/unix').exists(), 'Linux Unix sockets and proc are required')
class ActualUnixSocketReadiness(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vpn-php-ready-')
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'pool.sock'
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(self.socket.close)
        self.state = {'LoadState': 'loaded', 'ActiveState': 'active', 'SubState': 'running',
                      'MainPID': str(os.getpid())}
        self.options = dict(read_unit=lambda _timeout: dict(self.state), socket_path=self.path,
                            executable=Path(sys.executable), web_identity=(os.getuid(), os.getgid()),
                            master_uid=os.getuid(), binary_uid=Path(sys.executable).resolve().stat().st_uid)

    def bind(self):
        self.socket.bind(str(self.path))
        self.socket.listen(1)
        self.path.chmod(0o660)

    def test_reload_can_report_active_before_its_new_pool_socket_appears(self):
        calls = []
        ready = threading.Event()
        def finish_async_reload():
            time.sleep(0.12)
            self.bind()
            ready.set()
        worker = threading.Thread(target=finish_async_reload)
        worker.start()
        self.addCleanup(worker.join)
        def check(remaining):
            calls.append(1)
            PHP.fpm_ready(timeout=remaining, **self.options)
        PHP.wait_ready(check, timeout=2, interval=0.01)
        self.assertTrue(ready.is_set())
        self.assertGreater(len(calls), 1)

    def test_existing_but_closed_socket_is_not_accepted_as_a_ready_pool(self):
        self.bind()
        self.socket.close()
        self.assertTrue(self.path.exists())
        with self.assertRaisesRegex(ValueError, 'SOCKET_NOT_HELD_BY_MASTER'):
            PHP.fpm_ready(**self.options)

    def test_wrong_socket_permissions_are_not_accepted(self):
        self.bind()
        self.path.chmod(0o666)
        with self.assertRaisesRegex(ValueError, 'SOCKET_IDENTITY'):
            PHP.fpm_ready(**self.options)

    def test_socket_not_held_by_reported_master_pid_is_rejected(self):
        self.bind()
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(10)'], close_fds=True)
        self.addCleanup(lambda: child.wait(timeout=3))
        self.addCleanup(child.terminate)
        self.state['MainPID'] = str(child.pid)
        with self.assertRaisesRegex(ValueError, 'SOCKET_NOT_HELD_BY_MASTER'):
            PHP.fpm_ready(**self.options)

    def test_master_process_must_be_the_expected_trusted_executable(self):
        self.bind()
        with self.assertRaisesRegex(ValueError, 'MASTER_BINARY'):
            PHP.fpm_ready(**{**self.options, 'executable': Path('/bin/sh')})

    def test_socket_symlink_and_inactive_service_are_rejected(self):
        self.bind()
        link = self.path.with_name('link.sock'); link.symlink_to(self.path)
        with self.assertRaisesRegex(ValueError, 'SOCKET_IDENTITY'):
            PHP.fpm_ready(**{**self.options, 'socket_path': link})
        self.state['ActiveState'] = 'inactive'
        with self.assertRaisesRegex(ValueError, 'UNIT_NOT_READY'):
            PHP.fpm_ready(**self.options)


if __name__ == '__main__':
    unittest.main()
