"""Reviewed compact recipes resolve to stable IDs in the custom contract."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("top10_catalog_test", ROOT / "tools/portfolio_catalog.py")
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)
EXPECTED_STEMS = (
    "vless-reality-xhttp-packet-up",
    "vless-reality-xhttp-auto",
    "vless-reality-xhttp-stream-up",
    "vless-reality-xhttp-packet-up-mlkem",
    "trojan-reality-xhttp-auto",
    "trojan-reality-xhttp-packet-up",
    "hysteria2-tls-hysteria-salamander",
    "vless-tls-xhttp-auto",
    "vless-tls-xhttp-packet-up",
    "vless-tls-xhttp-stream-one",
)
SIGNATURE_KEYS = ("protocol", "transport", "security", "xhttp_mode", "flow", "encryption", "cipher", "obfs")
EXPECTED_SIGNATURES = (
    ("vless", "xhttp", "reality", "packet-up", "", "none", "none", "none"),
    ("vless", "xhttp", "reality", "auto", "", "none", "none", "none"),
    ("vless", "xhttp", "reality", "stream-up", "", "none", "none", "none"),
    ("vless", "xhttp", "reality", "packet-up", "", "mlkem", "mlkem", "none"),
    ("trojan", "xhttp", "reality", "auto", "", "none", "none", "none"),
    ("trojan", "xhttp", "reality", "packet-up", "", "none", "none", "none"),
    ("hysteria2", "hysteria", "tls", None, "", "none", "salamander", "salamander"),
    ("vless", "xhttp", "tls", "auto", "", "none", "none", "none"),
    ("vless", "xhttp", "tls", "packet-up", "", "none", "none", "none"),
    ("vless", "xhttp", "tls", "stream-one", "", "none", "none", "none"),
)


def expected_ids(egress):
    if egress != "both":
        return [stem + "-" + egress for stem in EXPECTED_STEMS]
    # The existing catalog keeps the native baseline first, then paired extras
    # in tier/catalog order; it does not regroup complete lists by exit.
    return [EXPECTED_STEMS[0] + "-" + role for role in ("warp", "direct")] + [
        stem + "-" + role for stem in EXPECTED_STEMS[1:] for role in ("warp", "direct")]


class Top10CatalogTests(unittest.TestCase):
    def test_exact_ids_counts_baseline_and_shared_extra_ports(self):
        self.assertEqual(C.TOP10_STEMS, EXPECTED_STEMS)
        self.assertEqual(C.PROFILE_SETS, ("basic", "dpi", "all", "custom"))
        for egress, total, extras, baseline in (("warp", 10, 9, 1), ("direct", 10, 9, 1), ("both", 20, 18, 2)):
            with self.subTest(egress=egress):
                rows = C.select_top10(egress)
                self.assertEqual([row["id"] for row in rows], expected_ids(egress))
                self.assertEqual(len(rows), total)
                self.assertEqual(sum(not row["baseline_reuse"] for row in rows), extras)
                self.assertEqual(sum(row["baseline_reuse"] for row in rows), baseline)
                self.assertEqual(len({row["port_offset"] for row in rows if not row["baseline_reuse"]}), 9)
                self.assertTrue(all(row["tier"] != "E" for row in rows))

    def test_exact_connection_signatures_and_exit_pairs(self):
        for egress in ("warp", "direct"):
            rows = C.select_top10(egress)
            self.assertEqual([tuple(row[key] for key in SIGNATURE_KEYS) for row in rows], list(EXPECTED_SIGNATURES))
            self.assertEqual({row["egress"] for row in rows}, {egress})
            self.assertEqual(len({tuple(row[key] for key in SIGNATURE_KEYS) for row in rows}), 10)
        both = C.select_top10("both")
        for stem in EXPECTED_STEMS:
            pair = [row for row in both if row["id"] in (stem + "-warp", stem + "-direct")]
            self.assertEqual({row["egress"] for row in pair}, {"warp", "direct"})
            self.assertEqual(len({tuple(row[key] for key in SIGNATURE_KEYS) for row in pair}), 1)
            self.assertEqual(len({row["port_offset"] for row in pair}), 1)

    def test_labels_change_names_only_and_returned_recipes_are_independent(self):
        label = 'Мой VPN " Европа \\ $ # & 🚀'
        original = C.select_top10("both")
        renamed = C.select_top10("both", label=label)
        self.assertEqual([{key: value for key, value in row.items() if key != "name"} for row in renamed],
                         [{key: value for key, value in row.items() if key != "name"} for row in original])
        self.assertEqual(len({row["name"] for row in renamed}), 20)
        self.assertTrue(all(row["name"].startswith(label + " · ") for row in renamed))
        self.assertTrue(all(row["name"] == C.profile_name(row, label) for row in renamed))
        renamed[0]["stream_settings_template"]["network"] = "mutated fixture"
        self.assertEqual(C.select_top10("both"), original)

    def test_custom_roundtrip_and_shared_catalog_order(self):
        for egress in C.EGRESS_MODES:
            rows = C.select_top10(egress, "Fixture")
            ids = ",".join(row["id"] for row in reversed(rows))
            self.assertEqual(C.select_profiles("custom", egress, "Fixture", ids), rows)
            selected = {row["id"] for row in rows}
            self.assertEqual([row for row in C.select_profiles("all", egress, "Fixture") if row["id"] in selected], rows)
            self.assertEqual(C.select_top10(egress, "Fixture"), rows)

    def test_preset_cli_without_label_emits_existing_three_token_selection(self):
        environment = {key: value for key, value in os.environ.items() if key != "TARGET_LABEL"}
        environment["TARGET_PROFILE_IDS"] = "inherited-custom-selection-does-not-choose-a-preset"
        for script in (ROOT / "tools/portfolio_catalog.py", ROOT / "bundle/portfolio/portfolio_catalog.py"):
            for egress, count in (("warp", 10), ("direct", 10), ("both", 20)):
                with self.subTest(script=script.name, egress=egress):
                    process = subprocess.run([sys.executable, "-I", "-B", str(script), "--preset", "top10", "--egress", egress],
                                             capture_output=True, timeout=10, env=environment)
                    self.assertEqual(process.returncode, 0, process.stderr.decode("utf-8", "replace"))
                    self.assertEqual(process.stderr, b"")
                    tokens = process.stdout.decode("utf-8").split()
                    self.assertEqual(len(tokens), 3)
                    self.assertEqual(tokens, [egress, ",".join(expected_ids(egress)), str(count)])
                    self.assertEqual(len(C.select_profiles("custom", tokens[0], "Installed label", tokens[1])), count)

    def test_invalid_inputs_and_mutually_exclusive_cli_actions(self):
        for egress in ("invalid", "", None):
            with self.subTest(egress=egress), self.assertRaises(ValueError):
                C.select_top10(egress)
        for label in ("", " ", "x" * 81, "bad\nname"):
            with self.subTest(label=label), self.assertRaises(ValueError):
                C.select_top10("direct", label)
        for arguments in (("--preset", "top10", "--set", "basic"), ("--preset", "missing")):
            process = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "tools/portfolio_catalog.py"),
                                      *arguments, "--egress", "both"], capture_output=True, timeout=10)
            self.assertEqual(process.returncode, 2)
            self.assertEqual(process.stdout, b"")


if __name__ == "__main__":
    unittest.main()
