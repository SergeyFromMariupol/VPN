"""Preflight must reject unsupported topology before installation mutates it."""
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('preflight_environment', ROOT / 'tools/preflight.py')
preflight = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preflight)


class Environment(unittest.TestCase):
    def test_physical_host_is_inventory_success_but_command_errors_are_not(self):
        for status, output, expected in ((0, 'kvm\n', 'kvm'), (1, 'none\n', 'none')):
            with self.subTest(status=status), patch.object(preflight.subprocess, 'run',
                    return_value=subprocess.CompletedProcess(['systemd-detect-virt'], status, output, '')):
                self.assertEqual(preflight.virtualization(), expected)
        for status, output in ((1, ''), (2, 'none\n')):
            with self.subTest(status=status), patch.object(preflight.subprocess, 'run',
                    return_value=subprocess.CompletedProcess(['systemd-detect-virt'], status, output, 'error')):
                with self.assertRaises(subprocess.CalledProcessError):
                    preflight.virtualization()

    def test_late_acme_multiple_address_rejection_is_caught_in_preflight(self):
        env = {'TARGET_IPV4': '8.8.4.4'}
        good = {'local': env['TARGET_IPV4'], 'scope': 'global'}
        preflight.validate_interface_addresses([{'addr_info': [good]}], env)
        preflight.validate_interface_addresses([{'addr_info': [good,
            {'local': '169.254.1.1', 'scope': 'link'}]}], env)
        for addresses in ([], [good, {'local': '8.8.8.8', 'scope': 'global'}],
                          [{'local': '8.8.8.8', 'scope': 'global'}]):
            with self.subTest(addresses=addresses), self.assertRaises(ValueError):
                preflight.validate_interface_addresses([{'addr_info': addresses}], env)


if __name__ == '__main__':
    unittest.main()
