import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


BASE = Path(__file__).resolve().parents[1] / "bundle" / "base"


def load(name):
    spec = importlib.util.spec_from_file_location(name, BASE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ips = load("ip_addresses")
cert = load("ip_certificate")
FIRST = "8.8.4.4"
SECOND = "9.9.9.9"
PAIR = (FIRST, SECOND)


def addr(value, **attributes):
    return {"family": "inet", "local": value, "scope": "global", **attributes}


def iface(name, *addresses, flags=("UP", "LOWER_UP")):
    return {"ifname": name, "flags": flags, "addr_info": addresses}


class AddressDiscovery(unittest.TestCase):
    def test_additional_addresses_keep_previously_selected_primary(self):
        records = [iface("eth0", addr(SECOND), addr(FIRST, secondary=True))]
        with patch.object(ips, "ip_json", return_value=records) as query:
            self.assertEqual(ips.discover(SECOND), {
                "primary": SECOND, "interface": "eth0", "addresses": list(PAIR),
                "interfaces": {FIRST: "eth0", SECOND: "eth0"},
            })
        query.assert_called_once_with("address", "show")

    def test_removed_address_chooses_kernel_route_source(self):
        records = [iface("ens3", addr(FIRST), addr(SECOND))]
        routes = [{"prefsrc": SECOND, "dev": "ens3"}]
        with patch.object(ips, "ip_json", side_effect=(records, routes)):
            self.assertEqual(ips.discover("1.1.1.1")["primary"], SECOND)

    def test_no_guess_when_route_uses_unassigned_or_other_interface(self):
        addresses = {FIRST: "eth0", SECOND: "eth0"}
        for routes in ([], [{"prefsrc": FIRST, "dev": "eth1"}],
                       [{"prefsrc": "10.0.0.2", "dev": "eth0"}],
                       [{"prefsrc": FIRST, "dev": "eth0", "type": "blackhole"}],
                       [{"prefsrc": FIRST, "dev": "eth0"}] * 2):
            with self.subTest(routes=routes), self.assertRaises(ValueError):
                ips.plan(addresses, None, routes)

    def test_excludes_private_nonunicast_stale_loopback_and_down(self):
        records = [
            iface("eth0", addr(FIRST), addr("224.0.0.1"), addr("10.0.0.1"),
                  addr("100.64.0.1"), addr("240.0.0.1"), addr("192.0.2.1"),
                  addr("1.1.1.1", tentative=True), addr("1.0.0.1", deprecated=True),
                  addr("4.4.4.4", valid_life_time=0), addr("4.4.4.5", preferred_life_time=0)),
            iface("lo", addr(SECOND), flags=("UP", "LOOPBACK")),
            iface("eth1", addr(SECOND), flags=("BROADCAST",)),
        ]
        self.assertEqual(ips.assigned_addresses(records), {FIRST: "eth0"})

    def test_duplicated_local_address_fails_closed(self):
        with self.assertRaises(ValueError):
            ips.assigned_addresses([iface("eth0", addr(FIRST)), iface("eth1", addr(FIRST))])


class CandidateCertificate(unittest.TestCase):
    def test_lineage_name_matches_ip_set_independent_of_primary_and_order(self):
        self.assertEqual(cert.name_for(PAIR), cert.name_for(reversed(PAIR)))
        self.assertNotEqual(cert.name_for(PAIR), cert.name_for((SECOND,)))
        for invalid in ([], [FIRST, FIRST], ["10.1.2.3"], ["239.1.2.3"], ["::1"]):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                cert.name_for(invalid)

    def test_standalone_issues_all_ip_sans_without_deploying(self):
        with patch.object(cert.os.path, "lexists", return_value=False), \
                patch.object(cert, "record_attempt") as attempt, \
                patch.object(cert.subprocess, "run") as run, patch.object(cert, "validate") as validate:
            name = cert.issue(reversed(PAIR), "test@example.com")
        command = run.call_args.args[0]
        self.assertEqual(command[command.index("--cert-name") + 1], name)
        self.assertEqual(command[command.index("--http-01-address") + 1], "0.0.0.0")
        self.assertEqual(command[command.index("--required-profile") + 1], "shortlived")
        self.assertEqual(command[command.index("--server") + 1], cert.SERVER)
        self.assertEqual(command[-4:], ["--ip-address", FIRST, "--ip-address", SECOND])
        self.assertIn("--no-directory-hooks", command)
        for hook in ("--pre-hook", "--post-hook", "--deploy-hook"):
            self.assertEqual(command[command.index(hook) + 1], "")
        self.assertNotIn("--allow-subset-of-names", command)
        self.assertNotIn("--force-renewal", command)
        attempt.assert_called_once()
        validate.assert_called_once_with(name, PAIR)

    def test_candidate_reuse_and_expiry_paths(self):
        with patch.object(cert.os.path, "lexists", return_value=True), \
                patch.object(cert, "checked_lineage", return_value=Path("lineage")), \
                patch.object(cert, "check_material") as material, \
                patch.object(cert, "record_attempt") as attempt, \
                patch.object(cert.subprocess, "run") as run, patch.object(cert, "validate"):
            self.assertEqual(cert.issue(PAIR), cert.name_for(PAIR))
            run.assert_not_called()
            attempt.assert_not_called()
            material.side_effect = [subprocess.CalledProcessError(1, ["openssl"]), None]
            self.assertEqual(cert.issue(PAIR), cert.name_for(PAIR))
            material.assert_called_with(Path("lineage"), PAIR, ignore_time=True)
            run.assert_called_once()

    def test_wrong_chain_or_names_cannot_be_used_or_overwritten(self):
        with patch.object(cert.os.path, "lexists", return_value=True), \
                patch.object(cert, "checked_lineage", return_value=Path("lineage")), \
                patch.object(cert, "check_material", side_effect=cert.CertificateError("IP_CERT_SAN")), \
                patch.object(cert.subprocess, "run") as run, self.assertRaisesRegex(cert.CertificateError, "IP_CERT_SAN"):
            cert.issue(PAIR)
        run.assert_not_called()

    def test_material_rejects_missing_extra_and_dns_sans(self):
        for san in (f"IP Address:{FIRST}", f"IP Address:{FIRST}, IP Address:{SECOND}, DNS:bad.test",
                    f"IP Address:{FIRST}, IP Address:{SECOND}, IP Address:1.1.1.1"):
            output = f"X509v3 Subject Alternative Name:\n    {san}\n".encode()
            with self.subTest(san=san), patch.object(cert, "openssl", return_value=output), \
                    self.assertRaisesRegex(cert.CertificateError, "IP_CERT_SAN"):
                cert.check_material(Path("lineage"), PAIR)

    def test_material_requires_matching_served_leaf_key_and_trust_for_each_ip(self):
        sans = f"X509v3 Subject Alternative Name:\n    IP Address:{SECOND}, IP Address:{FIRST}\n".encode()
        good = [sans, b"leaf", b"leaf", b"public", b"public", b"valid", b"ok", b"ok"]
        with patch.object(cert, "openssl", side_effect=good) as openssl:
            cert.check_material(Path("lineage"), PAIR)
        self.assertEqual([call.args[call.args.index("-verify_ip") + 1]
                          for call in openssl.call_args_list if "-verify_ip" in call.args], list(PAIR))
        for index, code in ((2, "IP_CERT_FULLCHAIN"), (4, "IP_CERT_KEY")):
            values = good.copy()
            values[index] = b"different"
            with patch.object(cert, "openssl", side_effect=values), self.assertRaisesRegex(cert.CertificateError, code):
                cert.check_material(Path("lineage"), PAIR)

    def test_failed_acme_stops_before_acceptance(self):
        with patch.object(cert.os.path, "lexists", return_value=False), \
                patch.object(cert, "record_attempt"), patch.object(cert, "validate") as validate, \
                patch.object(cert.subprocess, "run", side_effect=subprocess.TimeoutExpired("certbot", 300)), \
                self.assertRaisesRegex(cert.CertificateError, "IP_CERT_ISSUE"):
            cert.issue(PAIR)
        validate.assert_not_called()

    def test_retry_delay_survives_new_process_attempts(self):
        with tempfile.TemporaryDirectory() as work, patch.object(cert, "safe_stat") as checked:
            checked.return_value.st_mode = 0o100600
            checked.return_value.st_nlink = 1
            checked.return_value.st_size = 5
            stamp = Path(work) / "attempt"
            with patch.object(cert, "ATTEMPT", stamp), patch.object(cert.time, "time", return_value=1000):
                cert.record_attempt()
                with self.assertRaisesRegex(cert.CertificateError, "IP_CERT_RETRY_LATER"):
                    cert.record_attempt()
            with patch.object(cert, "ATTEMPT", stamp), patch.object(cert.time, "time", return_value=1900):
                cert.record_attempt()
                self.assertEqual(stamp.read_text(), "1900\n")


if __name__ == "__main__":
    unittest.main()
