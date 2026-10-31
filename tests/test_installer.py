"""Offline tests for installer boundaries; no server or credentials needed."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


preflight = module('preflight', ROOT / 'tools/preflight.py')
renderer = module('renderer', ROOT / 'tools/render.py')
GOOD = dict(TARGET_IPV4='8.8.4.4', TARGET_FQDN='vpn.example.com',
            TARGET_INTERFACE='enp1s0', TARGET_SSH_PORT='2222',
            TARGET_DEVICE_LIMIT='0', TARGET_REALITY_SNI='example.org',
            TARGET_LABEL='🇩🇪 Германия', ACME_EMAIL='admin@example.com')


class Inputs(unittest.TestCase):
    def test_valid(self):
        preflight.validate_inputs(GOOD)

    def test_bad_values_rejected(self):
        for field, values in {
            'TARGET_IPV4': ['127.0.0.1', '192.168.0.4', '::1', '999.1.1.1'],
            'TARGET_FQDN': ['vpn;id.example', '-bad.example', 'a..example', 'a' * 64 + '.com', '*.example.com'],
            'TARGET_INTERFACE': ['eth0\nid', 'eth0;id', ''],
            'TARGET_SSH_PORT': ['0', '65536', '8444', '443', '-1', '22;id'],
            'TARGET_DEVICE_LIMIT': ['-1', '10001', '0;id'],
            'TARGET_REALITY_SNI': ['cloudflare.com', 'a\nb.com'],
            'TARGET_LABEL': ['x\ny', '$(id)', '`id`', '"label"'],
            'ACME_EMAIL': ['not-email', 'a@example.com\nx'],
        }.items():
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    preflight.validate_inputs({**GOOD, field: value})


class Rendering(unittest.TestCase):
    def test_only_topology_replaced(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, GOOD):
            root = Path(temp)
            path = root / 'test.sh'
            path.write_text('@TARGET_IPV4@ @TARGET_INTERFACE@ $REALITY_PRIVATE_KEY\n', encoding='utf-8')
            renderer.render(root)
            self.assertEqual(path.read_text(), '8.8.4.4 enp1s0 $REALITY_PRIVATE_KEY\n')

    def test_no_unsafe_interface(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {**GOOD, 'TARGET_INTERFACE': 'eth0;id'}):
            with self.assertRaises(ValueError):
                renderer.render(Path(temp))


class Publication(unittest.TestCase):
    def test_no_old_target_in_executable_sources(self):
        banned = ['31.76.28.116', '31.76.9.84', 'germany.mrplhome.ru',
                  'germany.krysyuk.online', 'netherlands.mrplhome.ru', 'Z:\\VPN', '192.168.0.4']
        for path in (ROOT / 'bundle').rglob('*'):
            if path.is_file() and '__pycache__' not in path.parts:
                text = path.read_text(encoding='utf-8')
                for value in banned:
                    self.assertNotIn(value, text, f'{value} in {path}')


if __name__ == '__main__':
    unittest.main()
