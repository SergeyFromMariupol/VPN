"""Panel rendering must preserve asset identifiers while validating source slots."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / 'bundle/scripts/expose-panel-https.sh'
SPEC = importlib.util.spec_from_file_location('panel_template_happ', ROOT / 'bundle/scripts/happ_routing.py')
HAPP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HAPP)
TARGET = {'TARGET_IPV4': '203.0.113.10', 'TARGET_FQDN': 'vpn.example.test',
          'TARGET_PUBLIC_SCHEME': 'https', 'TARGET_LABEL': 'Panel fixture',
          'TARGET_HAPP_PROVIDER_ID': '', 'SUBSCRIPTION_PATH': 'a' * 40,
          'PANEL_BASE_PATH': 'fixture-panel-private-path'}


class SubscriptionTemplateAssets(unittest.TestCase):
    def test_original_assets_keep_their_double_underscore_globals_and_bem_classes(self):
        config = HAPP.subscription_proxy(TARGET)
        self.assertIn('window.__SUB_PAGE_DATA__', config)
        self.assertIn('vpn-app-bypass__top', config)
        for slot in ('__ANDROID_PACKAGES_JSON__', '__SERVER_IPV4__', '__SUBSCRIPTION_PATH__',
                     '__ANDROID_APPS_JS__', '__ANDROID_APPS_CSS__', '__PUBLIC_FQDN__'):
            self.assertNotIn(slot, config)
        self.assertIn('listen 203.0.113.10:2096 ssl;', config)

    def test_unknown_source_slot_is_rejected_but_unknown_injected_asset_global_is_preserved(self):
        with tempfile.TemporaryDirectory(prefix='vpn-template-assets-') as directory:
            bundle = Path(directory) / 'bundle'
            shutil.copytree(ROOT / 'bundle', bundle)
            script_dir = bundle / 'scripts'
            template = bundle / 'templates/3x-ui-subscription.nginx.conf'
            asset = bundle / 'templates/android-app-bypass.js'
            with asset.open('a', encoding='utf-8') as stream:
                stream.write('\nwindow.__OTHER_ASSET_GLOBAL__ = true;\n')
            with patch.object(HAPP, 'SCRIPT_DIR', script_dir):
                self.assertIn('window.__OTHER_ASSET_GLOBAL__', HAPP.subscription_proxy(TARGET))
                with template.open('a', encoding='ascii') as stream:
                    stream.write('\n# __UNRECOGNIZED_SUBSCRIPTION_SLOT__\n')
                with self.assertRaisesRegex(ValueError, 'Unknown subscription Nginx template placeholder'):
                    HAPP.subscription_proxy(TARGET)


@unittest.skipUnless(os.name == 'posix' and shutil.which('bash'), 'Linux Bash renderer is required')
class ActualPanelRenderer(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='vpn-panel-renderer-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundle = self.root / 'bundle'
        shutil.copytree(ROOT / 'bundle', self.bundle)
        self.stage = self.root / 'stage'; self.stage.mkdir()

    def render(self):
        # Execute the actual renderer AND its production validation section.
        # The test stops before the first install/service/firewall operation.
        source = PANEL.read_text()
        begin = source.index('render_nginx_config() {')
        end = source.index('\nrender_access() {', begin)
        validation_begin = source.rindex('render_nginx_config >"$stage/3x-ui-public.conf"')
        validation_end = source.index('\ninstall -o root -g root', validation_begin)
        driver = ('set -Eeuo pipefail\n' + source[begin:end] + '\n'
                  'die() { printf "%s\\n" "$*" >&2; exit 1; }\n'
                  'bundle_root="$FIXTURE_BUNDLE"\n'
                  'nginx_template="$FIXTURE_BUNDLE/templates/3x-ui-public.nginx.conf"\n'
                  'stage="$FIXTURE_STAGE"\n' + source[validation_begin:validation_end] + '\n')
        return subprocess.run(['bash', '-s'], input=driver, text=True, capture_output=True, timeout=30,
                              env={**os.environ, **TARGET, 'FIXTURE_BUNDLE': str(self.bundle),
                                   'FIXTURE_STAGE': str(self.stage)})

    def test_assembled_panel_and_subscription_with_real_assets_pass_production_validation(self):
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        config = (self.stage / '3x-ui-public.conf').read_text()
        self.assertIn('listen 203.0.113.10:2053 ssl;', config)
        self.assertIn('listen 203.0.113.10:2096 ssl;', config)
        self.assertIn('/fixture-panel-private-path/', config)
        self.assertIn('window.__SUB_PAGE_DATA__', config)
        self.assertIn('vpn-app-bypass__top', config)
        self.assertNotIn('__PANEL_BASE_PATH__', config)

    def test_unknown_panel_source_slot_fails_before_publication(self):
        template = self.bundle / 'templates/3x-ui-public.nginx.conf'
        with template.open('a') as stream:
            stream.write('\n# __UNRECOGNIZED_PANEL_SLOT__\n')
        result = self.render()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Unknown panel Nginx template placeholder', result.stderr)

    def test_unknown_subscription_source_slot_fails_before_publication(self):
        template = self.bundle / 'templates/3x-ui-subscription.nginx.conf'
        with template.open('a') as stream:
            stream.write('\n# __UNRECOGNIZED_SUBSCRIPTION_SLOT__\n')
        result = self.render()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Unknown subscription Nginx template placeholder', result.stderr)


if __name__ == '__main__':
    unittest.main()
