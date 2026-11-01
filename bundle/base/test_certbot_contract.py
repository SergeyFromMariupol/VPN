"""Offline certificate argument and installed dependency tamper fixtures."""
import base64
import hashlib
import importlib.util
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("certbot_validator", BASE / "verify-certbot.py")
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class IdentifierArguments(unittest.TestCase):
    def run_arguments(self, mode, endpoint="vpn.example.invalid", ip="198.51.100.55"):
        bash = os.environ.get("VPN_TEST_BASH") or shutil.which("bash")
        if not bash:
            self.skipTest("Bash is required for shell argument fixtures")
        result = subprocess.run(
            [bash, "-c", 'source "$1"; TARGET_ADDRESS_MODE=$2; TARGET_FQDN=$3; TARGET_IPV4=$4; '
             'acme_identifier_arguments || exit; printf "%s\\0" "${acme_identifiers[@]}"',
             "--", (BASE / "acme-identifiers.sh").as_posix(), mode, endpoint, ip],
            capture_output=True, check=False,
        )
        return result, result.stdout.decode().rstrip("\0").split("\0")

    def test_domain_keeps_one_named_dns_identifier(self):
        result, args = self.run_arguments("domain")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(args, ["--cert-name", "vpn.example.invalid", "-d", "vpn.example.invalid"])

    def test_ip_has_no_dns_identifier_and_requires_shortlived(self):
        result, args = self.run_arguments("ip", "198.51.100.55")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(args, ["--cert-name", "198.51.100.55", "--ip-address", "198.51.100.55",
                                "--required-profile", "shortlived"])

    def test_ip_rejects_a_different_lineage(self):
        result, _ = self.run_arguments("ip")
        self.assertNotEqual(result.returncode, 0)

    def test_unknown_address_mode_is_rejected(self):
        result, _ = self.run_arguments("other")
        self.assertNotEqual(result.returncode, 0)


class ContactArguments(unittest.TestCase):
    def run_arguments(self, email=None):
        bash = os.environ.get("VPN_TEST_BASH") or shutil.which("bash")
        if not bash:
            self.skipTest("Bash is required for shell argument fixtures")
        environment = dict(os.environ)
        if email is None:
            environment.pop('ACME_EMAIL', None)
        else:
            environment['ACME_EMAIL'] = email
        result = subprocess.run(
            [bash, "-c", 'source "$1"; '
             'acme_contact_arguments || exit; printf "%s\\0" "${acme_contact[@]}"',
             "--", (BASE / "acme-identifiers.sh").as_posix()],
            env=environment, capture_output=True, check=False,
        )
        return result, result.stdout.decode().rstrip("\0").split("\0")

    def test_empty_or_unset_email_is_an_explicit_empty_argv_element(self):
        for email in (None, ""):
            with self.subTest(email=email):
                result, arguments = self.run_arguments(email)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(arguments, ["--email", "", "--no-eff-email"])

    def test_given_email_is_preserved_and_never_shared_with_eff(self):
        email = "Admin+vpn@example.org"
        result, arguments = self.run_arguments(email)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(arguments, ["--email", email, "--no-eff-email"])

    def test_malformed_nonempty_email_is_rejected(self):
        for email in ("not-email", "owner@example.org\nother@example.org", " ",
                      "owner@example.org;id", "owner@example.org "):
            with self.subTest(email=email):
                result, _ = self.run_arguments(email)
                self.assertNotEqual(result.returncode, 0)


class IssuedCertificateIdentity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bash = os.environ.get("VPN_TEST_BASH") or shutil.which("bash")
        cls.openssl = shutil.which("openssl")
        if not cls.bash or not cls.openssl:
            raise unittest.SkipTest("Bash and OpenSSL are required for local CA fixtures")
        cls.temp = tempfile.TemporaryDirectory(prefix="acme-certificate-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        cls.lineage = cls.root / "lineage"
        cls.trust = cls.root / "trust"
        cls.empty_trust = cls.root / "untrusted"
        for path in (cls.lineage, cls.trust, cls.empty_trust):
            path.mkdir()
        config = cls.root / "fixture.cnf"
        config.write_text("""[req]
distinguished_name=dn
[dn]
CN=VPN offline fixture
[root]
basicConstraints=critical,CA:true
keyUsage=critical,keyCertSign,cRLSign
[leaf]
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:198.51.100.55,DNS:vpn.example.invalid
""", encoding="utf-8")

        def openssl(*args):
            subprocess.run([cls.openssl, *map(str, args)], check=True, capture_output=True)

        ca = cls.trust / "fixture-ca.pem"
        ca_key = cls.root / "ca.key"
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "60",
                "-keyout", ca_key, "-out", ca, "-subj", "/CN=VPN offline fixture CA",
                "-config", config, "-extensions", "root")
        openssl("rehash", cls.trust)
        csr = cls.root / "leaf.csr"
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout",
                cls.lineage / "privkey.pem", "-out", csr, "-subj", "/CN=vpn.example.invalid",
                "-config", config)
        openssl("x509", "-req", "-in", csr, "-CA", ca, "-CAkey", ca_key,
                "-CAcreateserial", "-days", "45", "-out", cls.lineage / "cert.pem",
                "-extfile", config, "-extensions", "leaf")
        shutil.copyfile(ca, cls.lineage / "chain.pem")

    def verify(self, mode, endpoint="vpn.example.invalid", ip="198.51.100.55", trust=None):
        return subprocess.run(
            [self.bash, "-c", 'source "$1"; TARGET_ADDRESS_MODE=$2; TARGET_FQDN=$3; TARGET_IPV4=$4; '
             'acme_verify_issued_certificate "$5" "$6"', "--",
             (BASE / "acme-identifiers.sh").as_posix(), mode, endpoint, ip,
             self.lineage.as_posix(), (trust or self.trust).as_posix()],
            check=False, capture_output=True,
        )

    def test_matching_ip_and_trusted_chain_pass(self):
        result = self.verify("ip", "198.51.100.55")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_mismatched_ip_is_rejected(self):
        self.assertNotEqual(self.verify("ip", "198.51.100.56", "198.51.100.56").returncode, 0)

    def test_matching_domain_and_trusted_chain_pass(self):
        result = self.verify("domain")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_mismatched_domain_is_rejected(self):
        self.assertNotEqual(self.verify("domain", "wrong.example.invalid").returncode, 0)

    def test_untrusted_chain_is_rejected(self):
        self.assertNotEqual(self.verify("ip", "198.51.100.55", trust=self.empty_trust).returncode, 0)


class FakeDistribution:
    def __init__(self, root, name, version="5.9.0"):
        self.root = root
        self.metadata = {"Name": name}
        self.version = version
        self.file = root / (name + ".py")
        self.file.write_text("# fixture\n", encoding="utf-8")
        digest = base64.urlsafe_b64encode(hashlib.sha256(self.file.read_bytes()).digest()).rstrip(b"=").decode()
        self.record = f"{name}.py,sha256={digest},{self.file.stat().st_size}\n"

    def read_text(self, name):
        assert name == "RECORD"
        return self.record

    def locate_file(self, relative):
        return self.root / relative


class InstalledDependencyIntegrity(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="certbot-contract-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.lock = self.root / "requirements.txt"
        self.lock.write_text("\n".join(name + "==5.9.0 --hash=sha256:" + "a" * 64
                                      for name in ("acme", "certbot")), encoding="utf-8")
        self.distributions = [FakeDistribution(self.root, "acme"), FakeDistribution(self.root, "certbot")]

    def verify(self):
        with patch.object(VALIDATOR.sys, "prefix", str(self.root)), \
             patch.object(VALIDATOR.importlib.metadata, "distributions", return_value=self.distributions):
            VALIDATOR.verify(self.lock, self.root)

    def test_intact_distribution_records_pass(self):
        self.verify()

    def test_modified_file_is_rejected(self):
        self.distributions[0].file.write_text("# modified\n", encoding="utf-8")
        with self.assertRaisesRegex(AssertionError, "file changed"):
            self.verify()

    def test_missing_file_is_rejected(self):
        self.distributions[0].file.unlink()
        with self.assertRaisesRegex(AssertionError, "missing or symlinked"):
            self.verify()

    def test_wrong_version_is_rejected(self):
        self.distributions[0].version = "5.8.0"
        with self.assertRaisesRegex(AssertionError, "version drift"):
            self.verify()

    def test_unexpected_distribution_is_rejected(self):
        self.distributions.append(FakeDistribution(self.root, "unreviewed"))
        with self.assertRaisesRegex(AssertionError, "dependency set drift"):
            self.verify()

    def test_record_path_escape_is_rejected(self):
        self.distributions[0].record = "../outside.py,sha256=invalid,1\n"
        with self.assertRaisesRegex(AssertionError, "escapes venv"):
            self.verify()

    def test_unhashed_source_is_rejected(self):
        self.distributions[0].record = "acme.py,,\n"
        with self.assertRaisesRegex(AssertionError, "unhashed wheel file"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
