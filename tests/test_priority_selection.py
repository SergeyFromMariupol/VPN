"""Priority order applies to every selection without migrating saved targets."""
import importlib.util
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


C = load('priority_catalog', 'tools/portfolio_catalog.py')
INPUTS = load('priority_selection_fixtures', 'tests/test_selection_inputs.py')


class PrioritySelection(unittest.TestCase):
    def test_every_named_set_has_same_membership_and_hysteria_reality_prefix(self):
        for mode in ('warp', 'direct', 'both'):
            roles = ('warp', 'direct') if mode == 'both' else (mode,)
            for profile_set, per_exit in (('basic', 3), ('dpi', 49), ('all', 73)):
                with self.subTest(mode=mode, profile_set=profile_set):
                    legacy = C.select_profiles(profile_set, mode, 'VPN')
                    rows = C.select_profiles(profile_set, mode, 'VPN', profile_order='priority')
                    self.assertEqual({row['id'] for row in rows}, {row['id'] for row in legacy})
                    self.assertEqual(len(rows), per_exit * len(roles))
                    self.assertEqual([row['egress'] for row in rows],
                                     [role for role in roles for _ in range(per_exit)])
                    for offset, role in enumerate(roles):
                        block = rows[offset * per_exit:(offset + 1) * per_exit]
                        self.assertEqual(block[0]['protocol'], 'hysteria2')
                        self.assertEqual(block[1]['security'], 'reality')
                        if profile_set == 'basic':
                            self.assertEqual([row['name'].rsplit(' · ', 1)[1] for row in block],
                                             ['HYSTERIA2', 'REALITY', 'XHTTP'])
                        else:
                            self.assertEqual(block[0]['obfs'], 'salamander')
                            self.assertEqual(block[1]['id'], 'vless-reality-xhttp-auto-' + role)

    def test_top10_order_is_identical_to_published_preset(self):
        for mode in C.EGRESS_MODES:
            self.assertEqual(C.select_top10(mode, 'VPN', 'priority'), C.select_top10(mode, 'VPN'))

    def test_custom_selection_preserves_membership_and_is_deterministic(self):
        ids = ['vless-reality-grpc-direct', 'hysteria2-tls-hysteria-salamander-warp',
               'vless-tls-xhttp-auto-direct', 'vless-reality-xhttp-auto-warp',
               'hysteria2-tls-hysteria-direct']
        expected = ['hysteria2-tls-hysteria-salamander-warp', 'vless-reality-xhttp-auto-warp',
                    'hysteria2-tls-hysteria-direct', 'vless-reality-grpc-direct',
                    'vless-tls-xhttp-auto-direct']
        for values in (ids, list(reversed(ids))):
            rows = C.select_profiles('custom', 'both', 'VPN', ','.join(values), 'priority')
            self.assertEqual([row['id'] for row in rows], expected)
        self.assertEqual({row['id'] for row in rows}, set(ids))
        self.assertEqual(C.priority_profiles(rows), rows)

    def test_manual_subset_without_hysteria_or_reality_adds_nothing(self):
        choices = ['vless-tls-xhttp-auto-direct', 'vless-tls-xhttp-stream-one-direct']
        rows = C.select_profiles('custom', 'direct', 'VPN', ','.join(reversed(choices)), 'priority')
        self.assertEqual([row['id'] for row in rows], choices)

    def test_numbers_resolve_displayed_priority_menu_and_reorder_subset(self):
        menu = C.select_profiles('all', 'both', 'VPN', profile_order='priority')
        chosen = {menu[index]['id'] for index in (0, 3, 75, 81)}
        rows = C.select_numbers('both', '1,4,76,82', 'priority')
        self.assertEqual({row['id'] for row in rows}, chosen)
        expected = C.select_profiles('custom', 'both', 'VPN', ','.join(chosen), 'priority')
        self.assertEqual(rows, expected)

    def test_priority_selection_validates_persists_and_roundtrips(self):
        rows = C.select_profiles('basic', 'both', 'VPN', profile_order='priority')
        ids = ','.join(row['id'] for row in rows)
        values = INPUTS.inputs(TARGET_PROFILE_SET='custom', TARGET_PROFILE_IDS=ids,
                               TARGET_PROFILE_ORDER='priority')
        INPUTS.PREFLIGHT.validate_inputs(values)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'target.env'
            INPUTS.TARGET.write_target(path, values)
            saved = {key: shlex.split(value)[0] for key, value in
                     (line.split('=', 1) for line in path.read_text().splitlines())}
            self.assertEqual(saved, values)
            self.assertEqual(C.select_profiles('custom', 'both', 'VPN',
                                               saved['TARGET_PROFILE_IDS'],
                                               saved['TARGET_PROFILE_ORDER']), rows)
        with self.assertRaises(ValueError):
            INPUTS.PREFLIGHT.validate_inputs(dict(values, TARGET_PROFILE_IDS=','.join(reversed(
                [row['id'] for row in rows]))))

    def test_default_legacy_retains_saved_native_order(self):
        rows = C.select_profiles('basic', 'both', 'VPN')
        self.assertEqual([row['name'].rsplit(' · ', 1)[1] for row in rows],
                         ['REALITY', 'HYSTERIA2', 'XHTTP'] * 2)
        for mode in C.EGRESS_MODES:
            preset = C.select_top10(mode)
            self.assertEqual(C.select_profiles('custom', mode, 'VPN', ','.join(
                row['id'] for row in preset)), preset)

    def test_cli_explicit_order_and_invalid_order(self):
        result = subprocess.run([sys.executable, str(ROOT / 'tools/portfolio_catalog.py'),
                                 '--set', 'basic', '--egress', 'direct', '--label', 'VPN',
                                 '--order', 'priority'], capture_output=True, check=True)
        self.assertEqual(json.loads(result.stdout)[0]['protocol'], 'hysteria2')
        for profile_set in ('basic', 'custom'):
            with self.assertRaises(ValueError):
                C.select_profiles(profile_set, 'both', 'VPN', profile_order='wrong')


if __name__ == '__main__':
    unittest.main()
