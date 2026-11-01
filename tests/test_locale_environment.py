"""Exercise gettext precedence and the production command environment."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
BASH = os.environ.get('VPN_TEST_BASH') or shutil.which('bash')


def write_catalog(directory):
    """A private gettext catalog also used by the real isolated UFW fixture."""
    messages = {'': 'Content-Type: text/plain; charset=UTF-8\nLanguage: ru\n',
                'Status: inactive': 'FIXTURE_TRANSLATED_INACTIVE'}
    keys = sorted(messages)
    originals = [key.encode() for key in keys]
    translations = [messages[key].encode() for key in keys]
    count = len(keys)
    offset = 28 + count * 16
    original_table, translated_table = [], []
    strings = bytearray()
    for values, table in ((originals, original_table), (translations, translated_table)):
        for value in values:
            table.append((len(value), offset + len(strings)))
            strings.extend(value + b'\0')
    header = struct.pack('<7I', 0x950412de, 0, count, 28, 28 + count * 8, 0, 0)
    tables = b''.join(struct.pack('<2I', *entry) for entry in original_table + translated_table)
    path = Path(directory) / 'ru/LC_MESSAGES/ufw.mo'
    path.parent.mkdir(parents=True)
    path.write_bytes(header + tables + strings)


def preflight_module():
    spec = importlib.util.spec_from_file_location('locale_preflight', ROOT / 'tools/preflight.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TRANSLATE = ('import gettext,sys; '
             'print(gettext.translation("ufw",localedir=sys.argv[1],fallback=True)'
             '.gettext("Status: inactive"))')


class LocaleEnvironment(unittest.TestCase):
    def test_language_overrides_lc_all_until_preflight_normalizes_it(self):
        with tempfile.TemporaryDirectory(prefix='vpn-locale-') as temporary:
            write_catalog(temporary)
            environment = dict(os.environ, LC_ALL='C', LANG='C', LANGUAGE='ru')
            control = subprocess.run([sys.executable, '-I', '-c', TRANSLATE, temporary],
                                     env=environment, text=True, capture_output=True, check=True)
            self.assertEqual(control.stdout.strip(), 'FIXTURE_TRANSLATED_INACTIVE')
            with patch.dict(os.environ, environment, clear=True):
                output = preflight_module().run(sys.executable, '-I', '-c', TRANSLATE, temporary)
            self.assertEqual(output, 'Status: inactive')

    @unittest.skipUnless(BASH, 'Bash is required')
    def test_shared_contract_clears_poisoned_python_and_locale_environment(self):
        with tempfile.TemporaryDirectory(prefix='vpn-locale-') as temporary:
            write_catalog(temporary)
            check = ('import gettext,json,os,sys; '
                     'print(json.dumps({"locale":[os.environ.get(k) for k in '
                     '("LC_ALL","LANG","LANGUAGE")],"optimized":sys.flags.optimize,'
                     '"overrides":[k for k in os.environ if k in '
                     '("PYTHONOPTIMIZE","PYTHONHOME","PYTHONPATH","PYTHONUSERBASE",'
                     '"PYTHONSTARTUP","PYTHONINSPECT")],"text":gettext.translation('
                     '"ufw",localedir=sys.argv[1],fallback=True).gettext("Status: inactive")}))')
            environment = dict(os.environ, LC_ALL='C', LANG='C', LANGUAGE='ru',
                               GERMANYVPN_TARGET_CONTRACT_LOADED='1',
                               PYTHONOPTIMIZE='2', PYTHONHOME='/invalid/vpn-fixture-python',
                               PYTHONPATH='/invalid/vpn-fixture-python',
                               PYTHONUSERBASE='/invalid/vpn-fixture-python',
                               PYTHONSTARTUP='/invalid/vpn-fixture-python', PYTHONINSPECT='1')
            result = subprocess.run([BASH, '-c', 'source "$1"; "$2" -c "$3" "$4"', '_',
                                     (ROOT / 'bundle/scripts/target-contract.sh').as_posix(),
                                     Path(sys.executable).as_posix(), check, Path(temporary).as_posix()],
                                    env=environment, text=True, capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(json.loads(result.stdout), {'locale': ['C', 'C', 'C'],
                             'optimized': 0, 'overrides': [], 'text': 'Status: inactive'})


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--write-catalog':
        write_catalog(sys.argv[2])
    else:
        unittest.main()
