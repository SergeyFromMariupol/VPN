"""Exercise crash-window recovery without contacting ACME or changing services."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash")


@unittest.skipUnless(BASH, "Bash is required for the installer recovery fixture")
class ResumeRecoveryContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="vpn-resume-recovery-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.state.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()

    def executable(self, name, body):
        path = self.bin / name
        path.write_text("#!/usr/bin/env bash\nset -Eeuo pipefail\n" + body)
        path.chmod(0o755)
        return path

    def run_bash(self, script, extra_env=None):
        env = {**os.environ, "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
               "FIXTURE_ROOT": str(self.root)}
        env.update(extra_env or {})
        return subprocess.run([BASH, "-c", script], cwd=self.root, env=env,
                              capture_output=True, text=True, timeout=10)

    def test_acme_accepts_only_owned_exact_committed_lineage(self):
        source = (ROOT / "bundle/base/acme.sh").read_text()
        source = source.replace("/etc/letsencrypt", str(self.root / "letsencrypt"))
        source = source.replace("[[ $EUID == 0 ]] || exit 1", "true")
        source = source.replace("== 0:0:600:1",
                                f"== {os.getuid()}:{os.getgid()}:600:1")
        dependency_check = ("for name in certbot cmp dig ip sqlite3 systemctl "
                            "openssl tar ss flock sha256sum sync; do "
                            'command -v "$name" >/dev/null; done')
        self.assertIn(dependency_check, source)
        source = source.replace(dependency_check, "command -v sha256sum >/dev/null")
        source = source.replace("/usr/local/bin/certbot", str(self.bin / "certbot"))
        base = self.root / "bundle/base"
        scripts = self.root / "bundle/scripts"
        base.mkdir(parents=True)
        scripts.mkdir(parents=True)
        (base / "acme.sh").write_text(source)
        certbot_check = base / "install-certbot.sh"
        certbot_check.write_text("#!/usr/bin/env bash\n[[ $1 == --check-only ]]\n")
        certbot_check.chmod(0o755)
        (scripts / "target-contract.sh").write_text(
            "TARGET_TLS_MODE=letsencrypt\nTARGET_IPV4=8.8.4.4\n"
            "TARGET_FQDN=8.8.4.4\nTARGET_ADDRESS_MODE=ip\n"
            'verify_target_certificate() { [[ $(cat "$1") == FULLCHAIN_GOOD ]]; }\n')
        (base / "acme-identifiers.sh").write_text(
            'acme_verify_issued_certificate() { [[ $(cat "$1/cert.pem") == CERT_GOOD && '
            '$(cat "$1/privkey.pem") == KEY_GOOD ]]; }\n')
        self.executable("certbot", "exit 0\n")
        self.executable("systemctl", """
case "$1" in
  is-active|is-enabled) [[ ${FIXTURE_TIMER_OFF:-0} == 0 ]] ;;
  show) printf 'LoadState=loaded\\nActiveState=inactive\\nMainPID=0\\n' ;;
  *) exit 77 ;;
esac
""")
        lineage = self.root / "letsencrypt/live/8.8.4.4"
        lineage.mkdir(parents=True)
        (lineage / "fullchain.pem").write_text("FULLCHAIN_GOOD\n")
        (lineage / "cert.pem").write_text("CERT_GOOD\n")
        (lineage / "privkey.pem").write_text("KEY_GOOD\n")
        marker = self.root / "letsencrypt/.vpn-acme-bootstrap-commit"

        def receipt(ip="8.8.4.4"):
            fullchain = hashlib.sha256((lineage / "fullchain.pem").read_bytes()).hexdigest()
            cert = hashlib.sha256((lineage / "cert.pem").read_bytes()).hexdigest()
            key = hashlib.sha256((lineage / "privkey.pem").read_bytes()).hexdigest()
            marker.write_text("VPN_ACME_BOOTSTRAP_V1\n" + ip +
                              "\n8.8.4.4\nip\n" + fullchain + "\n" +
                              cert + "\n" + key + "\n")
            marker.chmod(0o600)

        command = f'{BASH} "{base / "acme.sh"}" --verify-committed'
        missing = self.run_bash(command)
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("ACME_COMMIT_MARKER", missing.stderr)
        receipt()
        accepted = self.run_bash(command)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertIn("ACME_COMMITTED_OK=1", accepted.stdout)
        receipt("8.8.4.5")
        foreign = self.run_bash(command)
        self.assertNotEqual(foreign.returncode, 0)
        self.assertIn("ACME_COMMIT_MISMATCH", foreign.stderr)
        receipt()
        (lineage / "cert.pem").write_text("CERT_CHANGED\n")
        changed = self.run_bash(command)
        self.assertNotEqual(changed.returncode, 0)
        self.assertIn("ACME_COMMIT_CERT", changed.stderr)
        (lineage / "cert.pem").write_text("CERT_GOOD\n")
        timer_off = self.run_bash(command, {"FIXTURE_TIMER_OFF": "1"})
        self.assertNotEqual(timer_off.returncode, 0)
        self.assertIn("ACME_COMMIT_TIMER", timer_off.stderr)

    def test_installer_dispatches_completed_transactions_to_verifiers(self):
        source = (ROOT / "install.sh").read_text()
        tls_start = source.index("if [[ $TARGET_TLS_MODE == letsencrypt ]]; then\n  installer_error_context certbot")
        tls_end = source.index("\ninstaller_error_context direct", tls_start)
        reconcile_start = source.index("if [[ $TARGET_TLS_MODE == letsencrypt ]]; then\n  installer_error_context cert-reconcile")
        reconcile_end = source.index("\nif [[ $TARGET_EGRESS_MODE == direct ]]", reconcile_start)
        fragment = source[tls_start:tls_end] + "\n" + source[reconcile_start:reconcile_end]
        fragment = fragment.replace("/etc/letsencrypt/.vpn-acme-bootstrap-commit",
                                    str(self.root / "acme-commit"))
        fragment = fragment.replace("/etc/systemd/system/vpn-cert-reconcile.service",
                                    str(self.root / "reconcile.service"))
        fragment = fragment.replace("/etc/systemd/system/vpn-cert-reconcile.timer",
                                    str(self.root / "reconcile.timer"))
        runtime = self.root / "runtime/base"
        runtime.mkdir(parents=True)
        (runtime / "install-certbot.sh").write_text("#!/usr/bin/env bash\nexit 0\n")
        script = ("set -Eeuo pipefail\nTARGET_TLS_MODE=letsencrypt\n"
                  f'state="{self.state}"\nruntime="{self.root / "runtime"}"\n'
                  'installer_error_context() { :; }\n'
                  'phase() { printf "%s\\n" "$*" >>"$FIXTURE_ROOT/events"; }\n' +
                  fragment)
        self.assertEqual(self.run_bash(script).returncode, 0)
        events = (self.root / "events").read_text().splitlines()
        self.assertIn("tls bash " + str(runtime / "acme.sh") + " --apply", events)
        self.assertIn("cert-reconcile bash " + str(runtime / "install-cert-reconcile.sh") + " --apply", events)
        (self.root / "events").unlink()
        (self.root / "acme-commit").write_text("owned\n")
        (self.root / "reconcile.service").write_text("owned\n")
        (self.root / "reconcile.timer").write_text("owned\n")
        self.assertEqual(self.run_bash(script).returncode, 0)
        events = (self.root / "events").read_text().splitlines()
        self.assertIn("tls bash " + str(runtime / "acme.sh") + " --verify-committed", events)
        self.assertIn("cert-reconcile bash " + str(runtime / "install-cert-reconcile.sh") + " --check-only", events)

    def test_portfolio_hook_is_idempotent_and_retries_failed_restart(self):
        spec = importlib.util.spec_from_file_location(
            "portfolio_install_fixture", ROOT / "bundle/portfolio/install.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        root = self.root / "portfolio"
        root.mkdir(mode=0o700)
        lineage = self.root / "letsencrypt/live/vpn.example.test"
        lineage.mkdir(parents=True)
        tls = self.root / "runtime-tls"
        tls.mkdir()
        for directory in (lineage, tls):
            (directory / "fullchain.pem").write_text("CERT_ONE\n")
            (directory / "privkey.pem").write_text("KEY_ONE\n")
        hook = module.hook_bytes({"TARGET_FQDN": "vpn.example.test"}).decode()
        hook = hook.replace("/etc/germanyvpn-portfolio", str(root))
        hook = hook.replace("/etc/letsencrypt/live/vpn.example.test", str(lineage))
        hook = hook.replace("/etc/krysyuk-standalone/tls", str(tls))
        hook = hook.replace("/usr/local/lib/germanyvpn-xhttp-test/xray",
                            str(self.bin / "xray"))
        hook = hook.replace("/run/vpn-portfolio-tls.lock", str(self.root / "tls.lock"))
        hook = hook.replace("0:0:700", f"{os.getuid()}:{os.getgid()}:700")
        hook = hook.replace("0:0:600:1", f"{os.getuid()}:{os.getgid()}:600:1")
        hook_file = self.executable("hook80", hook.removeprefix("#!/usr/bin/env bash\n"))
        self.executable("xray", "exit 0\n")
        self.executable("systemctl", """
if [[ $1 == is-active ]]; then exit 0; fi
[[ $1 == restart ]] || exit 77
printf 'restart\\n' >>"$FIXTURE_ROOT/events"
[[ ${FIXTURE_RESTART_FAIL:-0} == 0 ]]
""")
        env = {"RENEWED_LINEAGE": str(lineage)}
        first = self.run_bash(f'"{hook_file}"', env)
        self.assertEqual(first.returncode, 0, first.stderr)
        marker = root / "tls-deployed.sha256"
        first_hash = hashlib.sha256((lineage / "fullchain.pem").read_bytes()).hexdigest()
        self.assertEqual(marker.read_text(), first_hash + "\n")
        self.assertEqual((self.root / "events").read_text().splitlines(), ["restart"])
        second = self.run_bash(f'"{hook_file}"', env)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual((self.root / "events").read_text().splitlines(), ["restart"])
        for directory in (lineage, tls):
            (directory / "fullchain.pem").write_text("CERT_TWO\n")
            (directory / "privkey.pem").write_text("KEY_TWO\n")
        failed = self.run_bash(f'"{hook_file}"', {**env, "FIXTURE_RESTART_FAIL": "1"})
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(marker.read_text(), first_hash + "\n")
        recovered = self.run_bash(f'"{hook_file}"', env)
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        new_hash = hashlib.sha256((lineage / "fullchain.pem").read_bytes()).hexdigest()
        self.assertEqual(marker.read_text(), new_hash + "\n")
        self.assertEqual((self.root / "events").read_text().splitlines(),
                         ["restart", "restart", "restart"])

    def test_reconcile_calls_portfolio_only_after_commit(self):
        bundle = self.root / "bundle"
        (bundle / "scripts").mkdir(parents=True)
        target = bundle / "scripts/target-contract.sh"
        target.write_text("TARGET_TLS_MODE=letsencrypt\nTARGET_PROFILE_SET=all\n"
                          "TARGET_EGRESS_MODE=direct\nTARGET_FQDN=8.8.4.4\n"
                          "TARGET_IPV4=8.8.4.4\n")
        portfolio_root = self.root / "portfolio"
        portfolio_root.mkdir(mode=0o700)
        state = portfolio_root / "state.json"
        state.write_text(json.dumps({"target": "8.8.4.4", "phase": "committed",
                                     "profile_set": "all", "egress_mode": "direct"}))
        state.chmod(0o600)
        hook60 = self.executable("hook60", 'printf "60:%s\\n" "$RENEWED_LINEAGE" >>"$FIXTURE_ROOT/events"\n')
        hook80 = self.executable("hook80", 'printf "80:%s\\n" "$RENEWED_LINEAGE" >>"$FIXTURE_ROOT/events"\n'
                                 '[[ ${FIXTURE_HOOK80_FAIL:-0} == 0 ]]\n')
        hook60.chmod(0o750)
        hook80.chmod(0o750)
        script = (ROOT / "bundle/base/reconcile-tls.sh").read_text()
        script = script.replace("[[ $EUID == 0 ]] || exit 1", "true")
        script = script.replace("/var/lib/vpn-installer/bundle", str(bundle))
        script = script.replace("/etc/letsencrypt/renewal-hooks/deploy/60-krysyuk-standalone-xui", str(hook60))
        script = script.replace("/etc/letsencrypt/renewal-hooks/deploy/80-germanyvpn-portfolio", str(hook80))
        script = script.replace("/etc/germanyvpn-portfolio", str(portfolio_root))
        script = script.replace("0:0:750:1", f"{os.getuid()}:{os.getgid()}:750:1")
        script = script.replace("0:0:600:1", f"{os.getuid()}:{os.getgid()}:600:1")
        script = script.replace("0:0:700", f"{os.getuid()}:{os.getgid()}:700")
        wrapper = self.executable("reconcile", script.removeprefix("#!/usr/bin/env bash\n"))
        first = self.run_bash(f'"{wrapper}"')
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual((self.root / "events").read_text().splitlines(),
                         ["60:/etc/letsencrypt/live/8.8.4.4",
                          "80:/etc/letsencrypt/live/8.8.4.4"])
        failed = self.run_bash(f'"{wrapper}"', {"FIXTURE_HOOK80_FAIL": "1"})
        self.assertNotEqual(failed.returncode, 0)
        recovered = self.run_bash(f'"{wrapper}"')
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        self.assertEqual((self.root / "events").read_text().splitlines()[-2:],
                         ["60:/etc/letsencrypt/live/8.8.4.4",
                          "80:/etc/letsencrypt/live/8.8.4.4"])
        state.write_text(json.dumps({"target": "8.8.4.4", "phase": "pending",
                                     "profile_set": "all", "egress_mode": "direct"}))
        (self.root / "events").unlink()
        pending = self.run_bash(f'"{wrapper}"')
        self.assertEqual(pending.returncode, 0, pending.stderr)
        self.assertEqual((self.root / "events").read_text().splitlines(),
                         ["60:/etc/letsencrypt/live/8.8.4.4"])
        state.unlink()
        (self.root / "events").unlink()
        absent = self.run_bash(f'"{wrapper}"')
        self.assertEqual(absent.returncode, 0, absent.stderr)
        self.assertEqual((self.root / "events").read_text().splitlines(),
                         ["60:/etc/letsencrypt/live/8.8.4.4"])
        target.write_text("TARGET_TLS_MODE=letsencrypt\nTARGET_PROFILE_SET=basic\n"
                          "TARGET_EGRESS_MODE=direct\nTARGET_FQDN=8.8.4.4\n"
                          "TARGET_IPV4=8.8.4.4\n")
        (self.root / "events").unlink()
        basic = self.run_bash(f'"{wrapper}"')
        self.assertEqual(basic.returncode, 0, basic.stderr)
        self.assertEqual((self.root / "events").read_text().splitlines(),
                         ["60:/etc/letsencrypt/live/8.8.4.4"])


if __name__ == "__main__":
    unittest.main()
