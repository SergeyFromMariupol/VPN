"""Exercise the installer's actual archive validator under optimized Python."""
import io
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'install.sh').read_text(encoding='utf-8')
MATCH = re.search(r'python3 - "\$task_stage/source.tar.gz" <<\'PY\'\n(.*?)\nPY\n',
                  SOURCE, re.S)
if MATCH is None:
    raise RuntimeError('Installer archive validator was not found')
VALIDATOR = MATCH.group(1)


class SourceArchive(unittest.TestCase):
    def validate(self, members, optimize):
        with tempfile.TemporaryDirectory(prefix='vpn-source-archive-') as temp:
            path = Path(temp) / 'source.tar.gz'
            with tarfile.open(path, 'w:gz') as archive:
                for member in members:
                    if member.isfile():
                        member.size = 7
                        archive.addfile(member, io.BytesIO(b'fixture'))
                    else:
                        archive.addfile(member)
            return subprocess.run([sys.executable, '-', str(path)], input=VALIDATOR,
                                  env=dict(os.environ, PYTHONOPTIMIZE=optimize),
                                  text=True, capture_output=True, timeout=10)

    def test_valid_single_root_archive_is_accepted_with_or_without_optimization(self):
        directory = tarfile.TarInfo('VPN-release/tools')
        directory.type = tarfile.DIRTYPE
        for optimize in ('0', '1', '2'):
            with self.subTest(optimize=optimize):
                result = self.validate([directory, tarfile.TarInfo('VPN-release/install.sh')],
                                       optimize)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_unsafe_members_cannot_bypass_validation_with_optimization(self):
        cases = {
            'traversal': [tarfile.TarInfo('VPN-release/../escape')],
            'absolute': [tarfile.TarInfo('/escape')],
            'multiple-roots': [tarfile.TarInfo('one/install.sh'),
                               tarfile.TarInfo('two/install.sh')],
            'empty': [],
        }
        for name, kind in (('symlink', tarfile.SYMTYPE), ('hardlink', tarfile.LNKTYPE),
                           ('device', tarfile.CHRTYPE), ('fifo', tarfile.FIFOTYPE)):
            member = tarfile.TarInfo('VPN-release/' + name)
            member.type = kind
            member.linkname = '/etc'
            cases[name] = [member]
        for name, members in cases.items():
            for optimize in ('0', '1', '2'):
                with self.subTest(case=name, optimize=optimize):
                    result = self.validate(members, optimize)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn('ValueError', result.stderr)


if __name__ == '__main__':
    unittest.main()
