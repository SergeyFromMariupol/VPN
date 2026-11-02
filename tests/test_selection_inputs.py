"""Portable validation of installer selections before server changes."""
import importlib.util
from pathlib import Path
import shlex
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PREFLIGHT = load('selection_preflight', 'tools/preflight.py')
TARGET = load('selection_target', 'tools/write-target.py')


def inputs(**overrides):
    values = dict(TARGET_ADDRESS_MODE='ip', TARGET_TLS_MODE='letsencrypt',
                  TARGET_EGRESS_MODE='both', TARGET_PROFILE_SET='basic',
                  TARGET_IPV4='8.8.4.4', TARGET_FQDN='8.8.4.4',
                  TARGET_INTERFACE='enp1s0', TARGET_SSH_PORT='22',
                  TARGET_DEVICE_LIMIT='0', TARGET_REALITY_SNI='max.ru',
                  TARGET_LABEL="Sergey's VPN", ACME_EMAIL='')
    values.update(overrides)
    return values


class SelectionInputs(unittest.TestCase):
    def test_all_supported_selections_validate_and_persist(self):
        for egress in ('warp', 'direct', 'both'):
            for profile_set in ('basic', 'dpi', 'all'):
                with self.subTest(egress=egress, profile_set=profile_set):
                    values = inputs(TARGET_EGRESS_MODE=egress, TARGET_PROFILE_SET=profile_set)
                    PREFLIGHT.validate_inputs(values)
                    with tempfile.TemporaryDirectory() as directory:
                        path = Path(directory) / 'target.env'
                        TARGET.write_target(path, values)
                        stored = dict(line.split('=', 1) for line in path.read_text().splitlines())
                        self.assertEqual(set(stored), set(TARGET.KEYS))
                        self.assertEqual({key: shlex.split(stored[key])[0] for key in stored}, values)

    def test_legacy_missing_fields_default_to_letsencrypt_and_basic(self):
        values = inputs()
        PREFLIGHT.validate_inputs(values)
        values.pop('TARGET_TLS_MODE')
        values.pop('TARGET_EGRESS_MODE')
        values.pop('TARGET_PROFILE_SET')
        PREFLIGHT.validate_inputs(values)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'target.env'
            TARGET.write_target(path, values)
            stored = dict(line.split('=', 1) for line in path.read_text().splitlines())
            self.assertEqual(shlex.split(stored['TARGET_TLS_MODE']), ['letsencrypt'])
            self.assertEqual(shlex.split(stored['TARGET_EGRESS_MODE']), ['both'])
            self.assertEqual(shlex.split(stored['TARGET_PROFILE_SET']), ['basic'])

    def test_invalid_selection_rejected_before_persistence(self):
        for changes in (dict(TARGET_EGRESS_MODE='invalid'),
                        dict(TARGET_PROFILE_SET='invalid'),
                        dict(TARGET_LABEL='   '),
                        dict(TARGET_TLS_MODE='none'),
                        dict(TARGET_TLS_MODE='none', TARGET_PROFILE_SET='dpi'),
                        dict(TARGET_TLS_MODE='none', TARGET_PROFILE_SET='all')):
            with self.subTest(changes=changes):
                values = inputs(**changes)
                with self.assertRaises(ValueError):
                    PREFLIGHT.validate_inputs(values)
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / 'target.env'
                    with self.assertRaises(ValueError):
                        TARGET.write_target(path, values)
                    self.assertFalse(path.exists())


if __name__ == '__main__':
    unittest.main()
