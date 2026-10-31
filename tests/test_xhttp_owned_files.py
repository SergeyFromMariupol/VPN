"""Exercise actual XHTTP writes and rollback in a root-private temporary tree."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]

DRIVER = r'''
import importlib.util, os, signal, sys, tempfile
from pathlib import Path
from unittest.mock import patch
spec = importlib.util.spec_from_file_location('xhttp_fixture', sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
os.umask(0o077)
case = sys.argv[2]
def interrupted(signum, frame):
    raise RuntimeError('INJECTED_TERM')
signal.signal(signal.SIGTERM, interrupted)

with tempfile.TemporaryDirectory(prefix='vpn-xhttp-files-', dir='/tmp') as temporary:
    root = Path(temporary)
    directory, path = root/'managed', root/'managed/config.json'
    created, versions = {}, {}
    if case == 'directory-signal':
        original = Path.mkdir
        def mkdir_then_signal(self, *args, **kw):
            result = original(self, *args, **kw)
            if self == directory:
                os.kill(os.getpid(), signal.SIGTERM)
            return result
        with patch.object(Path, 'mkdir', mkdir_then_signal):
            try:
                m.create_owned_directory(directory, 0o700, created, versions)
            except RuntimeError as error:
                assert str(error) == 'INJECTED_TERM'
            else:
                raise AssertionError('signal was not injected')
        assert directory in created and m.inode(directory) in versions[directory]
        m.remove_owned_paths(created, versions)
        assert not directory.exists()
    else:
        m.create_owned_directory(directory, 0o700, created, versions)
        if case in ('partial-write', 'file-fsync'):
            if case == 'partial-write':
                original = os.fdopen
                class PartialWrite:
                    def __init__(self, fd, mode): self.stream = original(fd, mode)
                    def __enter__(self): return self
                    def __exit__(self, *args): self.stream.close()
                    def fileno(self): return self.stream.fileno()
                    def write(self, raw):
                        self.stream.write(raw[:5]); self.stream.flush()
                        raise OSError('injected full disk')
                context = patch.object(m.os, 'fdopen', PartialWrite)
            else:
                context = patch.object(m.os, 'fsync', side_effect=OSError('injected fsync error'))
            with context:
                try: m.save_owned(path, b'complete expected bytes', created, versions)
                except OSError: pass
                else: raise AssertionError('write failure was hidden')
            assert not path.exists() and path not in created
            m.remove_owned_paths(created, versions)
            assert not directory.exists()
        elif case == 'write-signal':
            original = m.save
            def save_then_signal(*args, **kw):
                original(*args, **kw)
                os.kill(os.getpid(), signal.SIGTERM)
            with patch.object(m, 'save', save_then_signal):
                try: m.save_owned(path, b'complete bytes', created, versions)
                except RuntimeError as error: assert str(error) == 'INJECTED_TERM'
                else: raise AssertionError('signal was not injected')
            assert created[path] == m.sha(b'complete bytes')
            m.remove_owned_paths(created, versions)
            assert not directory.exists()
        elif case == 'failed-write-foreign-replacement':
            def replace_on_fsync(fd):
                path.rename(root/'owned-partial')
                path.write_bytes(b'foreign replacement')
                raise OSError('injected fsync error')
            with patch.object(m.os, 'fsync', replace_on_fsync):
                try: m.save(path, b'owned bytes')
                except OSError: pass
                else: raise AssertionError('write failure was hidden')
            assert path.read_bytes() == b'foreign replacement'
            assert (root/'owned-partial').read_bytes() == b'owned bytes'
        elif case == 'foreign-directory':
            directory.rename(root/'original-owned')
            directory.mkdir()
            try: m.remove_owned_paths(created, versions)
            except RuntimeError as error: assert str(error) == 'ROLLBACK_FOREIGN_PATH'
            else: raise AssertionError('foreign empty directory was removed')
            assert directory.is_dir() and (root/'original-owned').is_dir()
        else:
            m.save_owned(path, b'old complete bytes', created, versions)
            if case in ('replace-fsync', 'replace-signal'):
                if case == 'replace-fsync':
                    original = os.fsync
                    calls = 0
                    def fail_directory_fsync(fd):
                        global calls
                        calls += 1
                        if calls == 2: raise OSError('injected directory fsync error')
                        original(fd)
                    context = patch.object(m.os, 'fsync', fail_directory_fsync)
                    error_type = OSError
                else:
                    original = os.replace
                    def replace_then_signal(source, destination):
                        original(source, destination)
                        os.kill(os.getpid(), signal.SIGTERM)
                    context = patch.object(m.os, 'replace', replace_then_signal)
                    error_type = RuntimeError
                with context:
                    try: m.atomic_owned(path, b'new complete bytes', created, versions)
                    except error_type: pass
                    else: raise AssertionError('post-replace failure was hidden')
                assert path.read_bytes() == b'new complete bytes'
                assert versions[path][m.inode(path)] == m.sha(b'new complete bytes')
                m.remove_owned_paths(created, versions)
                assert not directory.exists()
            elif case in ('foreign-file', 'foreign-atomic'):
                replacement = root/'replacement'
                replacement.write_bytes(path.read_bytes())
                os.replace(replacement, path)
                try:
                    if case == 'foreign-atomic':
                        m.atomic_owned(path, b'new bytes', created, versions)
                    else: m.remove_owned_paths(created, versions)
                except RuntimeError as error:
                    assert str(error) in ('ROLLBACK_FOREIGN_PATH', 'OWNED_FILE_INODE_CAS')
                else: raise AssertionError('identical foreign inode was adopted')
                assert path.read_bytes() == b'old complete bytes'
            elif case == 'modified-owned-file':
                path.write_bytes(b'foreign modification')
                try: m.remove_owned_paths(created, versions)
                except RuntimeError as error: assert str(error) == 'ROLLBACK_FOREIGN_FILE'
                else: raise AssertionError('foreign modification was deleted')
                assert path.read_bytes() == b'foreign modification'
            else: raise AssertionError('unknown fixture')
print('XHTTP_OWNED_FILE_FIXTURE_OK='+case)
'''


@unittest.skipIf(os.name == 'nt', 'Actual Linux file/signal ownership fixtures run in Ubuntu CI')
class OwnedXhttpFiles(unittest.TestCase):
    def setUp(self):
        if os.geteuid() == 0:
            self.prefix = []
        elif shutil.which('sudo') and subprocess.run(['sudo', '-n', 'true'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            self.prefix = ['sudo', '-n']
        else:
            if os.environ.get('CI'): self.fail('Ubuntu CI must execute root ownership fixtures')
            self.skipTest('Root or passwordless sudo required')

    def fixture(self, case):
        result = subprocess.run([*self.prefix, sys.executable, '-c', DRIVER,
                                 str(ROOT/'bundle/scripts/finalize-xhttp.py'), case],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('XHTTP_OWNED_FILE_FIXTURE_OK='+case, result.stdout)

    def test_failed_write_and_fsync_remove_only_owned_partial_files(self):
        for case in ('partial-write', 'file-fsync', 'failed-write-foreign-replacement'):
            with self.subTest(case=case): self.fixture(case)

    def test_signal_between_creation_and_registration_is_deferred(self):
        for case in ('directory-signal', 'write-signal'):
            with self.subTest(case=case): self.fixture(case)

    def test_marker_post_replace_fsync_and_signal_remain_rollback_owned(self):
        for case in ('replace-fsync', 'replace-signal'):
            with self.subTest(case=case): self.fixture(case)

    def test_foreign_identical_replacements_and_mutations_are_preserved(self):
        for case in ('foreign-directory', 'foreign-file', 'foreign-atomic', 'modified-owned-file'):
            with self.subTest(case=case): self.fixture(case)


if __name__ == '__main__':
    unittest.main()
