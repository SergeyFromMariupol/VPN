import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
import uuid


SCRIPT = Path(__file__).resolve().parents[1] / 'bundle/scripts/v2raytun_routing.py'


class V2RayTunRoutingTests(unittest.TestCase):
    def test_subscription_routing_exports_exact_name_and_independent_direct_rules(self):
        name = '🇩🇪 Мой VPN / "Тест"'
        env = {**os.environ, 'TARGET_LABEL': name}
        command = [sys.executable, '-I', '-B', str(SCRIPT), '--link']
        encoded = subprocess.check_output(command, env=env).strip()
        profile = json.loads(base64.b64decode(encoded, validate=True))
        self.assertEqual(profile['name'], name)
        self.assertEqual(profile['domainStrategy'], 'IPIfNonMatch')
        self.assertEqual(profile['domainMatcher'], 'hybrid')
        domain, ip = profile['rules']
        self.assertEqual([rule['outboundTag'] for rule in profile['rules']], ['direct', 'direct'])
        self.assertEqual(set(domain['domain']), {
            'geosite:private', 'geosite:category-ru', 'domain:ru', 'domain:xn--p1ai', 'domain:su',
        })
        self.assertEqual(set(ip['ip']), {'geoip:private', 'geoip:ru'})
        self.assertNotIn('ip', domain)
        self.assertNotIn('domain', ip)
        self.assertEqual(len({uuid.UUID(item['id']) for item in (profile, domain, ip)}), 3)
        self.assertEqual(subprocess.check_output(command, env=env).strip(), encoded)


if __name__ == '__main__':
    unittest.main()
