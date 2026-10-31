"""Exercise the production deploy hook against an isolated certificate tree."""
import hashlib
import os
from pathlib import Path
try:
    import pwd
    import grp
except ImportError:  # Windows can import the suite; Linux CI runs the fixtures.
    pwd = grp = None
import shutil
import subprocess
import tempfile
import unittest


HOOK = Path(__file__).resolve().parents[1] / "bundle/templates/60-krysyuk-standalone-xui"


@unittest.skipUnless(os.name == "posix" and pwd is not None and all(shutil.which(x) for x in
                    ("bash", "openssl", "flock", "install", "sha256sum")),
                    "Linux shell and OpenSSL are required")
class ReconcileCertificate(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="vpn-cert-reconcile-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.user = pwd.getpwuid(os.getuid()).pw_name
        self.group = grp.getgrgid(os.getgid()).gr_name
        self.live = self.root / "live"
        self.trust = self.root / "trust"
        self.runtime = self.root / "runtime"
        self.bin = self.root / "bin"
        for path in (self.live, self.trust, self.runtime, self.bin):
            path.mkdir()
        self.runtime.chmod(0o750)
        self.fqdn = "vpn.example.invalid"
        self.ip = "198.51.100.55"
        self.lineage = self.live / self.fqdn
        self.lineage.mkdir()
        self.target = self.root / "target.env"
        self.target.write_text(f"TARGET_FQDN={self.fqdn}\nTARGET_IPV4={self.ip}\n"
                               "TARGET_ADDRESS_MODE=domain\n", encoding="utf-8")
        self.target.chmod(0o600)
        self._make_cert(self.lineage, f"DNS:{self.fqdn},IP:{self.ip}")
        old = self.runtime / "tls-gen.old"
        old.mkdir(mode=0o750)
        (old / "fullchain.pem").write_text("OLD_CERTIFICATE\n", encoding="ascii")
        (old / "privkey.pem").write_text("OLD_KEY\n", encoding="ascii")
        (self.runtime / "tls").symlink_to(old.name)
        self.marker = self.runtime / "tls-deployed.sha256"
        self.marker.write_text(hashlib.sha256((old / "fullchain.pem").read_bytes()).hexdigest() + "\n")
        self.marker.chmod(0o600)
        self.log = self.root / "calls.log"
        self.fail = self.root / "fail-restart"
        self.signal_after_marker = self.root / "signal-after-marker"
        self.signal_after_tls = self.root / "signal-after-tls"
        self.served = self.root / "served.pem"
        shutil.copyfile(self.lineage / "cert.pem", self.served)
        self.nginx_config = self.root / "panel.conf"
        self.nginx_config.write_text("# test\n")
        (self.bin / "systemctl").write_text(
            "#!/bin/sh\nprintf 'systemctl %s\\n' \"$*\" >>\"$VPN_TEST_LOG\"\n"
            "if [ \"$1\" = restart ] && [ -e \"$VPN_TEST_FAIL\" ]; then "
            "rm -f \"$VPN_TEST_FAIL\"; exit 1; fi\nexit 0\n")
        (self.bin / "nginx").write_text(
            "#!/bin/sh\nprintf 'nginx %s\\n' \"$*\" >>\"$VPN_TEST_LOG\"\nexit 0\n")
        (self.bin / "mv").write_text(
            "#!/bin/sh\n/bin/mv \"$@\" || exit $?\n"
            "last=''\nfor arg do last=$arg; done\n"
            "if [ \"$last\" = \"$VPN_TEST_MARKER\" ] && [ -e \"$VPN_TEST_SIGNAL\" ]; then\n"
            "  rm -f \"$VPN_TEST_SIGNAL\"\n  kill -TERM \"$PPID\"\nfi\n"
            "if [ \"$last\" = \"$VPN_TEST_TLS_LINK\" ] && [ -e \"$VPN_TEST_TLS_SIGNAL\" ]; then\n"
            "  rm -f \"$VPN_TEST_TLS_SIGNAL\"\n  kill -TERM \"$PPID\"\nfi\n")
        (self.bin / "openssl").write_text(
            "#!/bin/sh\nif [ \"$1\" = s_client ]; then "
            "cat \"$VPN_TEST_SERVED\"; exit 0; fi\n"
            f"exec {shutil.which('openssl')} \"$@\"\n")
        for path in self.bin.iterdir():
            path.chmod(0o755)
        script = HOOK.read_text(encoding="utf-8")
        replacements = {
            "/etc/germanyvpn-target.env": self.target.as_posix(),
            "/etc/letsencrypt/live/": self.live.as_posix() + "/",
            "/etc/krysyuk-standalone": self.runtime.as_posix(),
            "/etc/nginx/conf.d/3x-ui-public.conf": self.nginx_config.as_posix(),
            "/run/vpn-cert-reconcile": (self.root / "lock").as_posix(),
            "/etc/ssl/certs": self.trust.as_posix(),
            "root:xui-secrets:750": f"{self.user}:{self.group}:750",
            "root:root:600": f"{self.user}:{self.group}:600",
            "0:0:700": f"{os.getuid()}:{os.getgid()}:700",
            "0:0:600:1": f"{os.getuid()}:{os.getgid()}:600:1",
            "chown root:xui-secrets \"$new\"": ": \"$new\"",
            "install -o root -g xui-secrets -m 0640": "install -m 0640",
            "install -o root -g root -m 0600": "install -m 0600",
        }
        for source, target in replacements.items():
            self.assertIn(source, script)
            script = script.replace(source, target)
        self.script = self.root / "hook.sh"
        self.script.write_text(script, encoding="utf-8")

    def _openssl(self, *args):
        subprocess.run(["openssl", *map(str, args)], check=True, capture_output=True)

    def _make_cert(self, directory, san, days=10):
        config = self.root / "cert.cnf"
        config.write_text("[req]\ndistinguished_name=dn\n[dn]\nCN=fixture\n"
                          "[ca]\nbasicConstraints=critical,CA:true\n"
                          "keyUsage=critical,keyCertSign,cRLSign\n"
                          "[leaf]\nbasicConstraints=critical,CA:false\n"
                          "keyUsage=critical,digitalSignature,keyEncipherment\n"
                          "extendedKeyUsage=serverAuth\n"
                          f"subjectAltName={san}\n", encoding="utf-8")
        ca = self.trust / "ca.pem"
        ca_key = self.root / "ca.key"
        if not ca.exists():
            self._openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
                          "-keyout", ca_key, "-out", ca, "-subj", "/CN=fixture CA",
                          "-config", config, "-extensions", "ca")
            self._openssl("rehash", self.trust)
        key = directory / "privkey.pem"
        csr = self.root / "leaf.csr"
        self._openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                      "-out", csr, "-subj", "/CN=fixture", "-config", config)
        cert = directory / "cert.pem"
        self._openssl("x509", "-req", "-in", csr, "-CA", ca, "-CAkey", ca_key,
                      "-CAcreateserial", "-days", str(days), "-out", cert,
                      "-extfile", config, "-extensions", "leaf")
        shutil.copyfile(ca, directory / "chain.pem")
        (directory / "fullchain.pem").write_bytes(cert.read_bytes() + ca.read_bytes())

    def run_hook(self):
        return subprocess.run(["bash", str(self.script)], env=self.hook_environment(),
                              capture_output=True, text=True, check=False)

    def hook_environment(self):
        return dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                    VPN_TEST_LOG=str(self.log), VPN_TEST_FAIL=str(self.fail),
                    VPN_TEST_MARKER=str(self.marker),
                    VPN_TEST_SIGNAL=str(self.signal_after_marker),
                    VPN_TEST_TLS_LINK=str(self.runtime / "tls"),
                    VPN_TEST_TLS_SIGNAL=str(self.signal_after_tls),
                    VPN_TEST_SERVED=str(self.served))

    def test_valid_deployment_and_idempotent_followup(self):
        first = self.run_hook()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual((self.runtime / "tls/fullchain.pem").read_bytes(),
                         (self.lineage / "fullchain.pem").read_bytes())
        self.assertEqual(self.marker.read_text().strip(),
                         hashlib.sha256((self.lineage / "fullchain.pem").read_bytes()).hexdigest())
        calls = self.log.read_text()
        self.assertEqual(calls.count("systemctl restart x-ui.service"), 1)
        second = self.run_hook()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(self.log.read_text().count("systemctl restart x-ui.service"), 1)

    def test_two_concurrent_invocations_deploy_once(self):
        with subprocess.Popen(["bash", str(self.script)], env=self.hook_environment(),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE) as first, \
             subprocess.Popen(["bash", str(self.script)], env=self.hook_environment(),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE) as second:
            first.communicate(timeout=30)
            second.communicate(timeout=30)
            self.assertEqual(first.returncode, 0)
            self.assertEqual(second.returncode, 0)
        self.assertEqual(self.log.read_text().count("systemctl restart x-ui.service"), 1)

    def test_failed_restart_rolls_back_and_next_run_retries_without_certbot(self):
        self.fail.touch()
        first = self.run_hook()
        self.assertNotEqual(first.returncode, 0)
        self.assertEqual((self.runtime / "tls").readlink().as_posix(), "tls-gen.old")
        self.assertEqual((self.runtime / "tls/fullchain.pem").read_text(), "OLD_CERTIFICATE\n")
        second = self.run_hook()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertNotEqual((self.runtime / "tls").readlink().as_posix(), "tls-gen.old")

    def test_signal_after_marker_move_restores_previous_marker_and_pointer(self):
        before_marker = self.marker.read_bytes()
        self.signal_after_marker.touch()
        result = self.run_hook()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.marker.read_bytes(), before_marker)
        self.assertEqual((self.runtime / "tls").readlink().as_posix(), "tls-gen.old")
        self.assertEqual((self.runtime / "tls/fullchain.pem").read_text(), "OLD_CERTIFICATE\n")

    def test_signal_after_tls_pointer_move_does_not_leave_dangling_link(self):
        self.signal_after_tls.touch()
        result = self.run_hook()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.runtime / "tls").readlink().as_posix(), "tls-gen.old")
        self.assertEqual((self.runtime / "tls/fullchain.pem").read_text(), "OLD_CERTIFICATE\n")

    def test_wrong_served_certificate_rolls_back_pointer(self):
        self.served.write_text("NOT A CERTIFICATE\n", encoding="ascii")
        result = self.run_hook()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.runtime / "tls").readlink().as_posix(), "tls-gen.old")

    def test_mismatched_private_key_preserves_old_runtime(self):
        self._openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                      "-out", self.lineage / "privkey.pem")
        result = self.run_hook()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.runtime / "tls").readlink().as_posix(), "tls-gen.old")
        self.assertFalse(self.log.exists())

    def test_wrong_san_preserves_old_runtime(self):
        self._make_cert(self.lineage, "DNS:wrong.example.invalid")
        result = self.run_hook()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.runtime / "tls").readlink().as_posix(), "tls-gen.old")

    def test_untrusted_chain_preserves_old_runtime(self):
        (self.trust / "ca.pem").unlink()
        result = self.run_hook()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.runtime / "tls").readlink().as_posix(), "tls-gen.old")

    def test_near_expiry_preserves_old_runtime(self):
        self._make_cert(self.lineage, f"DNS:{self.fqdn},IP:{self.ip}", days=1)
        result = self.run_hook()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.runtime / "tls").readlink().as_posix(), "tls-gen.old")

    def test_ip_identity_and_missing_marker_repair(self):
        self.target.write_text(f"TARGET_FQDN={self.ip}\nTARGET_IPV4={self.ip}\n"
                               "TARGET_ADDRESS_MODE=ip\n", encoding="utf-8")
        (self.live / self.ip).symlink_to(self.lineage.name)
        self.marker.unlink()
        result = self.run_hook()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.marker.read_text().strip(),
                         hashlib.sha256((self.lineage / "fullchain.pem").read_bytes()).hexdigest())

    def test_equal_files_without_commit_marker_restarts_once(self):
        shutil.copyfile(self.lineage / "fullchain.pem", self.runtime / "tls/fullchain.pem")
        shutil.copyfile(self.lineage / "privkey.pem", self.runtime / "tls/privkey.pem")
        self.marker.unlink()
        result = self.run_hook()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.runtime / "tls").readlink().as_posix(), "tls-gen.old")
        self.assertEqual(self.log.read_text().count("systemctl restart x-ui.service"), 1)


if __name__ == "__main__":
    unittest.main()
