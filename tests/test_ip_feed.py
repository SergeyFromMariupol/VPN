import base64
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch


BASE = Path(__file__).resolve().parents[1] / "bundle/base"
sys.path.insert(0, str(BASE))
from ip_feed import Handler, rewrite_feed, rewrite_header
from ip_network import nginx_aliases, nft_rules, rebind_url, uri_lines


PRIMARY = "8.8.8.8"
ALIAS = "9.9.9.9"
PREFIX = "a" * 40
ID = "b" * 64


class AliasFeedTest(unittest.TestCase):
    def test_three_protocols_preserve_tls_and_authority_and_vmess_credentials(self):
        profiles = [
            f"vless://key@{PRIMARY}:443?security=reality&sni=max.ru&type=grpc#reality",
            f"hysteria2://secret@{PRIMARY}:443?sni={PRIMARY}#hysteria2",
            f"vless://key2@{PRIMARY}:8443?sni={PRIMARY}&host={PRIMARY}#xhttp",
            "vmess://" + base64.b64encode(json.dumps({"add": PRIMARY, "id": "key3",
                                                    "host": PRIMARY, "ps": "profile"}).encode()).decode(),
        ]
        for body in ("\n".join(profiles).encode(), base64.b64encode("\n".join(profiles).encode())):
            with self.subTest(encoding=body[:6]):
                result = uri_lines(rewrite_feed(body, PRIMARY, ALIAS))
                self.assertEqual(result[:3], [p.replace(f"@{PRIMARY}:", f"@{ALIAS}:") for p in profiles[:3]])
                self.assertEqual(json.loads(base64.b64decode(result[3].split("://", 1)[1])),
                                 {"add": ALIAS, "id": "key3", "host": PRIMARY, "ps": "profile"})

    def test_reject_foreign_or_unsupported_feed(self):
        for value in (b"", b"<html>", b"vless://key@1.1.1.1:443", b"happ://routing/invalid"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                rewrite_feed(value, PRIMARY, ALIAS)

    def test_metadata_and_subscription_url(self):
        source = f"https://{PRIMARY}:2096/{PREFIX}/{ID}"
        expected = f"https://{ALIAS}:2096/{PREFIX}/{ID}"
        self.assertEqual(rebind_url(source, PRIMARY, ALIAS, 2096), expected)
        self.assertEqual(rewrite_header("Profile-Web-Page-Url", source, PRIMARY, ALIAS), expected)
        self.assertEqual(rewrite_header("Routing", "happ://routing/onadd/dGVzdA==", PRIMARY, ALIAS),
                         "happ://routing/onadd/dGVzdA==")
        with self.assertRaises(ValueError):
            rebind_url(source + "?unexpected", PRIMARY, ALIAS, 2096)

    def test_alias_response_preserves_android_application_headers(self):
        metadata = {
            "ProviderID": "provider-fixture",
            "Per-App-Proxy-Enable": "1",
            "Per-App-Proxy-Mode": "bypass",
            "Per-App-Proxy-List": "com.example.app,ru.example.app",
        }
        handler = object.__new__(Handler)
        handler.path = f"/{PREFIX}/{ID}"
        handler.command = "GET"
        handler.headers = {"X-VPN-Alias": ALIAS, "User-Agent": "INCY/1.0/android"}
        handler.server = Mock()
        handler.server.settings.read_bytes.return_value = json.dumps({
            "primary": PRIMARY, "addresses": [PRIMARY, ALIAS],
        }).encode()
        handler.send_response = Mock()
        handler.send_header = Mock()
        handler.end_headers = Mock()
        handler.wfile = io.BytesIO()
        with patch("ip_feed.http.client.HTTPSConnection") as connect:
            response = connect.return_value.getresponse.return_value.__enter__.return_value
            response.status = 200
            response.read.return_value = f"vless://key@{PRIMARY}:443#profile\n".encode()
            response.getheaders.return_value = metadata.items()
            handler.serve_feed()
        handler.send_response.assert_called_once_with(200)
        for name, value in metadata.items():
            handler.send_header.assert_any_call(name, value)
        self.assertEqual(handler.wfile.getvalue(), f"vless://key@{ALIAS}:443#profile\n".encode())

    def test_secondary_ports_are_exact_and_hy2_is_translated(self):
        rules = nft_rules(PRIMARY, [ALIAS], "ens3", {(443, "tcp"), (8444, "tcp"), (443, "udp")}).decode()
        self.assertIn(f'ip daddr {{ {ALIAS} }} fib daddr type local udp dport {{ 443 }} dnat to {PRIMARY}', rules)
        self.assertIn(f'ip daddr {{ {ALIAS} }} fib daddr type local tcp dport {{ 443, 8444 }} dnat to {PRIMARY}', rules)
        self.assertEqual(rules.count('iifname "ens3"'), 2)
        self.assertNotIn("2096", rules)
        self.assertNotIn("2053", rules)

    def test_nginx_listens_on_alias_only_and_omits_subscription_identifier(self):
        source = f"https://{PRIMARY}:2096/{PREFIX}/{ID}"
        config = nginx_aliases([ALIAS], source).decode()
        self.assertIn(f"listen {ALIAS}:2096 ssl;", config)
        self.assertNotIn(f"listen {PRIMARY}:2096", config)
        self.assertIn(f"location ~ ^/{PREFIX}/", config)
        self.assertNotIn(ID, config)
        self.assertIn("proxy_set_header X-VPN-Alias $server_addr;", config)
        self.assertIn("access_log off;", config)


if __name__ == "__main__":
    unittest.main()
