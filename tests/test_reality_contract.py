"""REALITY target identities and legacy preservation without network access."""
import copy
import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location(
    'reality_contract_test', Path(__file__).resolve().parents[1] /
    'bundle/scripts/reality_contract.py')
CONTRACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTRACT)
TARGET = {'TARGET_FQDN': 'vpn.example.test', 'TARGET_IPV4': '45.67.89.10',
          'TARGET_ADDRESS_MODE': 'domain', 'TARGET_TLS_MODE': 'letsencrypt',
          'TARGET_REALITY_SNI': 'max.ru'}


class RealityContractTests(unittest.TestCase):
    def test_legacy_and_external_are_unchanged_and_do_not_mutate_input(self):
        for mode in (None, 'external'):
            info = dict(TARGET)
            if mode:
                info['TARGET_REALITY_MODE'] = mode
            before = copy.deepcopy(info)
            self.assertEqual(CONTRACT.reality_identity(info), ('max.ru:443', 'max.ru'))
            self.assertEqual(info, before)

    def test_self_steal_and_decoy_use_same_local_destination_with_distinct_sni(self):
        own = dict(TARGET, TARGET_REALITY_MODE='self-steal',
                   TARGET_REALITY_SNI=TARGET['TARGET_FQDN'])
        decoy = dict(TARGET, TARGET_REALITY_MODE='decoy')
        expected = ('127.0.0.1:9443', TARGET['TARGET_FQDN'])
        self.assertEqual(CONTRACT.reality_identity(own), expected)
        self.assertEqual(CONTRACT.reality_identity(decoy), expected)
        ip = dict(decoy, TARGET_ADDRESS_MODE='ip', TARGET_FQDN=TARGET['TARGET_IPV4'])
        self.assertEqual(CONTRACT.reality_identity(ip), ('127.0.0.1:9443', TARGET['TARGET_IPV4']))

    def test_derived_destination_cannot_be_overridden_by_environment(self):
        for mode, sni, expected in (('external', 'max.ru', 'max.ru:443'),
                                    ('decoy', 'max.ru', '127.0.0.1:9443'),
                                    ('self-steal', TARGET['TARGET_FQDN'], '127.0.0.1:9443')):
            info = dict(TARGET, TARGET_REALITY_MODE=mode, TARGET_REALITY_SNI=sni,
                        TARGET_REALITY_DEST='attacker.example:443',
                        TARGET_REALITY_TARGET_SNI='attacker.example')
            self.assertEqual(CONTRACT.reality_destination(info), expected)

    def test_rejects_invalid_local_mode_and_identity_combinations(self):
        invalid = [
            dict(TARGET, TARGET_REALITY_MODE='unknown'),
            dict(TARGET, TARGET_REALITY_MODE='self-steal'),
            dict(TARGET, TARGET_REALITY_MODE='self-steal', TARGET_ADDRESS_MODE='ip',
                 TARGET_FQDN=TARGET['TARGET_IPV4']),
            dict(TARGET, TARGET_REALITY_MODE='decoy', TARGET_TLS_MODE='none'),
            dict(TARGET, TARGET_REALITY_MODE='decoy', TARGET_ADDRESS_MODE='ip',
                 TARGET_FQDN='45.67.89.11'),
            dict(TARGET, TARGET_REALITY_MODE='decoy', TARGET_REALITY_SNI='45.67.89.10'),
            dict(TARGET, TARGET_REALITY_MODE='external', TARGET_REALITY_SNI='cloudflare.com'),
        ]
        for info in invalid:
            with self.subTest(info=info), self.assertRaises(ValueError):
                CONTRACT.reality_identity(info)

    def test_runtime_drift_rejected_even_if_an_old_hash_remains_valid(self):
        info = dict(TARGET, TARGET_REALITY_MODE='decoy')
        settings = {'target': '127.0.0.1:9443', 'serverNames': ['max.ru'], 'xver': 0}
        self.assertTrue(CONTRACT.reality_settings_match(settings, info))
        self.assertTrue(CONTRACT.reality_settings_match(
            {'dest': '127.0.0.1:9443', 'serverNames': ['max.ru']}, info))
        for changed in (dict(settings, target='max.ru:443'),
                        dict(settings, serverNames=['vpn.example.test']),
                        dict(settings, xver=1),
                        dict(settings, dest='max.ru:443')):
            with self.subTest(changed=changed):
                self.assertFalse(CONTRACT.reality_settings_match(changed, info))


if __name__ == '__main__':
    unittest.main()
