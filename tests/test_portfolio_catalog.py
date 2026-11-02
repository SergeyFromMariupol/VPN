"""Acceptance contract for the frozen Miranda-tested protocol portfolio."""

import json
from pathlib import Path
import re
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bundle/portfolio"))
from portfolio_catalog import load_catalog, select_profiles  # noqa: E402


class PortfolioCatalogTests(unittest.TestCase):
    def test_selection_counts_and_name_uniqueness(self):
        counts = {
            "basic": (3, 3, 6),
            "dpi": (49, 49, 98),
            "all": (73, 73, 146),
        }
        for profile_set, expected in counts.items():
            for egress, count in zip(("warp", "direct", "both"), expected):
                with self.subTest(profile_set=profile_set, egress=egress):
                    rows = select_profiles(profile_set, egress, "My VPN")
                    self.assertEqual(len(rows), count)
                    self.assertEqual(len({row["id"] for row in rows}), count)
                    self.assertEqual(len({row["name"] for row in rows}), count)
                    self.assertTrue(all(row["name"].startswith("My VPN · ") for row in rows))
                    if egress != "both":
                        self.assertEqual({row["egress"] for row in rows}, {egress})
                        marker = "☁️ Cloudflare" if egress == "warp" else "🖥️ IP сервера"
                        self.assertTrue(all(f" · {marker} · " in row["name"] for row in rows))
                    self.assertTrue(all("TEST" not in row["name"] for row in rows))
                    self.assertTrue(all(not re.search(r"\bT\d{3}\b", row["name"]) for row in rows))

    def test_six_original_names_and_order(self):
        names = [row["name"] for row in select_profiles("basic", "both", "Мой VPN")]
        self.assertEqual(names, [
            "Мой VPN · ☁️ Cloudflare · REALITY",
            "Мой VPN · ☁️ Cloudflare · HYSTERIA2",
            "Мой VPN · ☁️ Cloudflare · XHTTP",
            "Мой VPN · 🖥️ IP сервера · REALITY",
            "Мой VPN · 🖥️ IP сервера · HYSTERIA2",
            "Мой VPN · 🖥️ IP сервера · XHTTP",
        ])

    def test_tiers_and_paired_inbounds(self):
        entries = load_catalog()["entries"]
        self.assertEqual({tier: sum(row["tier"] == tier for row in entries)
                          for tier in ("A", "B1", "B2", "C", "D", "E")},
                         {"A": 30, "B1": 2, "B2": 2, "C": 4, "D": 60, "E": 48})
        extra = entries[6:]
        self.assertEqual(len(extra), 140)
        offsets = {row["port_offset"] for row in extra}
        self.assertEqual(len(offsets), 70)
        for offset in offsets:
            pair = [row for row in extra if row["port_offset"] == offset]
            self.assertEqual({row["egress"] for row in pair}, {"warp", "direct"})
            self.assertEqual(len({row["tier"] for row in pair}), 1)
            self.assertEqual(len({row["protocol"] for row in pair}), 1)
            self.assertEqual(len({row["transport"] for row in pair}), 1)
            self.assertEqual(len({row["security"] for row in pair}), 1)

        # Every additional inbound changes a protocol or transport parameter.
        # The 70 WARP/direct pairs are not just 70 ports for one configuration.
        signatures = {
            (row["protocol"], row["transport"], row["security"],
             row["xhttp_mode"], row["flow"], row["encryption"],
             row["cipher"], row["obfs"])
            for row in extra
        }
        self.assertEqual(len(signatures), 70)

    def test_priority_order_and_nonblank_personal_name(self):
        rows = select_profiles("all", "both", "Сергей VPN")
        self.assertTrue(all(row["baseline_reuse"] for row in rows[:6]))
        self.assertEqual([row["tier"] for row in rows[6:]],
                         ["A"] * 30 + ["B1"] * 2 + ["C"] * 2 +
                         ["D"] * 58 + ["E"] * 48)
        self.assertTrue(all("Сергей VPN · " in row["name"] for row in rows))
        with self.assertRaises(ValueError):
            select_profiles("basic", "both", "   ")

    def test_recipe_fields_and_no_target_specific_values(self):
        data = load_catalog()
        self.assertEqual(data["pinned_3x_ui"], "v3.7.0")
        self.assertEqual(data["pinned_xray"], "26.7.28")
        for row in data["entries"]:
            self.assertIn(row["tier"], {"A", "B1", "B2", "C", "D", "E"})
            self.assertIn(row["egress"], {"warp", "direct"})
            self.assertIn("inbound_settings_template", row)
            self.assertIn("stream_settings_template", row)
            self.assertIn("uri_params_template", row)
        raw = (ROOT / "bundle/portfolio/catalog.json").read_text(encoding="utf-8")
        self.assertNotIn("miranda", raw.lower())
        self.assertNotIn("2.27.200.203", raw)
        self.assertNotIn("TEST", raw)

    def test_cli_json_utf8(self):
        process = subprocess.run(
            [sys.executable, str(ROOT / "tools/portfolio_catalog.py"),
             "--set", "dpi", "--egress", "warp", "--label", "Тестовый VPN"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
        )
        self.assertEqual(process.returncode, 0, process.stderr.decode("utf-8", "replace"))
        rows = json.loads(process.stdout.decode("utf-8"))
        self.assertEqual(len(rows), 49)
        self.assertTrue(all(row["name"].startswith("Тестовый VPN · ☁️ Cloudflare · ")
                            for row in rows))


if __name__ == "__main__":
    unittest.main()
