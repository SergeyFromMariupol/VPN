"""Offline shape checks for every extra portfolio choice."""

import json
import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch
import uuid


PORTFOLIO = Path(__file__).resolve().parents[1] / "bundle" / "portfolio"
sys.path.insert(0, str(PORTFOLIO))
from plan import build  # noqa: E402
from portfolio_catalog import select_profiles  # noqa: E402


TARGET = {"TARGET_IPV4": "198.51.100.47", "TARGET_FQDN": "vpn.example.test",
          "TARGET_ADDRESS_MODE": "domain", "TARGET_REALITY_SNI": "mask.example.test"}
MAIN = {"dns": {"servers": [{"tag": "dns_cf"}, {"tag": "dns_q9"}]},
        "outbounds": [
            {"tag": "DIRECT", "protocol": "freedom",
             "settings": {"finalRules": [
                 {"action": "block", "ip": ["geoip:private", "::/0"]},
                 {"action": "allow"}]}},
            {"tag": "BLOCK", "protocol": "blackhole"},
            {"tag": "WARP_CF", "protocol": "vless",
             "settings": {"vnext": [{"address": "127.0.0.1", "port": 24443}]}}]}


def shared(entry, offset):
    return {"cert": "/etc/example/fullchain.pem", "key": "/etc/example/key.pem",
            "path": "/privatepath", "service_name": "vpn-grpc",
            "short_id": "0123456789abcdef", "obfs_password": "obfs-password",
            "reality_private_key": "a" * 43, "reality_public_key": "b" * 43,
            "server_decryption": "d" * 150, "client_encryption": "e" * 1500}


def profile(entry, common):
    value = dict(common)
    value["uuid"] = str(uuid.uuid5(uuid.NAMESPACE_DNS, entry["id"]))
    value["password"] = "password-" + entry["id"]
    return value


class PortfolioPlanTest(unittest.TestCase):
    def test_all_six_extra_selections(self):
        for profile_set, egress, expected in (
                ("dpi", "warp", 46), ("dpi", "direct", 46),
                ("dpi", "both", 92), ("all", "warp", 70),
                ("all", "direct", 70), ("all", "both", 140)):
            with self.subTest(profile_set=profile_set, egress=egress):
                rows = select_profiles(profile_set, egress, "Sergey")
                config, manifest, ports = build(TARGET, MAIN, rows, shared, profile)
                links = manifest["entries"]
                self.assertEqual(len(links), expected)
                self.assertEqual(len(config["inbounds"]), len(ports))
                self.assertEqual({outbound["tag"] for outbound in config["outbounds"]},
                                 {"DIRECT", "BLOCK"} if egress == "direct" else
                                 {"DIRECT", "BLOCK", "WARP_CF"})
                self.assertEqual(len(ports), expected if egress != "both" else expected // 2)
                self.assertEqual({item["port"] for item in links}, set(ports))
                self.assertEqual(len({item["remark"] for item in links}), expected)
                self.assertTrue(all(item["remark"].startswith("Sergey · ")
                                    and "TEST" not in item["remark"]
                                    for item in links))
                self.assertTrue(all(item["listen"] == TARGET["TARGET_IPV4"]
                                    for item in config["inbounds"]))
                self.assertEqual(config["routing"]["rules"][-1]["outboundTag"],
                                 "BLOCK")
                user_rules = config["routing"]["rules"][4:-1]
                self.assertEqual(len(user_rules), expected)
                self.assertEqual([rule["outboundTag"] for rule in user_rules],
                                 [item["egress"] for item in links])
                if egress == "warp":
                    self.assertTrue(all(item["egress"] == "WARP_CF" for item in links))
                if egress == "direct":
                    self.assertTrue(all(item["egress"] == "DIRECT" for item in links))
                serialized = json.dumps(config)
                self.assertNotIn("Miranda", serialized)
                self.assertNotIn("<", serialized)

    def test_direct_only_does_not_require_a_warp_connector(self):
        main_without_warp = dict(MAIN, outbounds=MAIN["outbounds"][:2])
        for profile_set, expected in (("dpi", 46), ("all", 70)):
            with self.subTest(profile_set=profile_set):
                direct_rows = select_profiles(profile_set, "direct", "Sergey")
                config, manifest, _ = build(TARGET, main_without_warp,
                                            direct_rows, shared, profile)
                self.assertEqual(len(manifest["entries"]), expected)
                self.assertEqual([outbound["tag"] for outbound in config["outbounds"]],
                                 ["DIRECT", "BLOCK"])
                warp_rows = select_profiles(profile_set, "warp", "Sergey")
                with self.assertRaisesRegex(ValueError, "PORTFOLIO_BASE_OUTBOUNDS"):
                    build(TARGET, main_without_warp, warp_rows, shared, profile)

    def test_public_endpoint_does_not_replace_bind_address(self):
        rows = select_profiles("dpi", "warp", "Sergey")
        config, manifest, _ = build(TARGET, MAIN, rows, shared, profile)
        self.assertTrue(all(item["listen"] == TARGET["TARGET_IPV4"]
                            for item in config["inbounds"]))
        self.assertTrue(all("@" + TARGET["TARGET_FQDN"] + ":" in item["uri"]
                            for item in manifest["entries"]
                            if not item["uri"].startswith("vmess://")))
        self.assertEqual(config["routing"]["rules"][3]["domain"],
                         ["full:" + TARGET["TARGET_IPV4"],
                          "full:" + TARGET["TARGET_FQDN"]])
        ip_target = dict(TARGET, TARGET_FQDN=TARGET["TARGET_IPV4"],
                         TARGET_ADDRESS_MODE="ip")
        ip_config, _, _ = build(ip_target, MAIN, rows, shared, profile)
        self.assertEqual(ip_config["routing"]["rules"][3]["domain"],
                         ["full:" + TARGET["TARGET_IPV4"]])

    def test_renewal_hook_and_firewall_conflict(self):
        # Linux-only account modules are inert at import time in this focused
        # test; the production runtime uses the system's real modules.
        spec = importlib.util.spec_from_file_location("portfolio_install_test",
                                                  PORTFOLIO / "install.py")
        module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {"grp": types.ModuleType("grp"),
                                      "pwd": types.ModuleType("pwd")}):
            spec.loader.exec_module(module)
        hook = module.hook_bytes(TARGET).decode()
        self.assertIn("lineage=/etc/letsencrypt/live/vpn.example.test", hook)
        self.assertIn('RENEWED_LINEAGE:-} == "$lineage"', hook)
        self.assertTrue(module.ufw_port_conflict(
            [["ufw", "allow", "30000:30010/tcp"]], {"30005": "tcp"}))
        self.assertTrue(module.ufw_port_conflict(
            [["ufw", "allow", "in", "on", "eth0", "to", "198.51.100.47",
              "port", "30005", "proto", "udp"]], {"30005": "tcp"}))
        self.assertFalse(module.ufw_port_conflict(
            [["ufw", "allow", "22/tcp"]], {"30005": "tcp"}))


if __name__ == "__main__":
    unittest.main()
