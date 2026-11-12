"""Priority ordering is a publication phase even for the basic six links."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('priority_update', ROOT / 'tools/update.py')
UPDATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UPDATE)


class PriorityOrchestration(unittest.TestCase):
    def check_completed(self, order):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / 'var/lib/vpn-installer'
            state.mkdir(parents=True)
            promotion = root / 'etc/germanyvpn-xhttp-test/promotion.json'
            promotion.parent.mkdir(parents=True)
            promotion.write_text('{"status":"committed"}')
            (state / 'portfolio-publication.json').write_text(json.dumps({
                'status': 'committed', 'target': '8.8.4.4',
                'profile_order': order or 'legacy'}))
            target = dict(TARGET_TLS_MODE='letsencrypt', TARGET_REALITY_MODE='external',
                          TARGET_EGRESS_MODE='both', TARGET_PROFILE_SET='basic',
                          TARGET_IPV4='8.8.4.4')
            if order is not None:
                target['TARGET_PROFILE_ORDER'] = order
            with (patch.object(UPDATE, 'file_state'),
                  patch.object(UPDATE, 'checkpoint') as checkpoint):
                UPDATE.completed(types.SimpleNamespace(root=root, state=state), target)
            return {call.args[0].name for call in checkpoint.call_args_list}

    def test_priority_basic_both_requires_committed_publication(self):
        names = self.check_completed('priority')
        self.assertIn('baseline-verify.done', names)
        self.assertIn('portfolio-publish.done', names)
        self.assertNotIn('portfolio-runtime.done', names)

    def test_old_basic_targets_keep_original_checkpoint_contract(self):
        for order in (None, 'legacy'):
            with self.subTest(order=order):
                names = self.check_completed(order)
                self.assertNotIn('baseline-verify.done', names)
                self.assertNotIn('portfolio-publish.done', names)

    def test_unknown_order_cannot_bypass_publication_gate(self):
        with self.assertRaisesRegex(RuntimeError, 'TARGET_PROFILE_ORDER'):
            self.check_completed('unknown')

    @unittest.skipUnless(os.name == 'posix' and shutil.which('bash'), 'Linux Bash required')
    def test_progress_lists_publication_for_each_priority_selection(self):
        for profile_set in ('basic', 'custom', 'dpi', 'all'):
            for mode in ('warp', 'direct', 'both'):
                with self.subTest(profile_set=profile_set, mode=mode):
                    env = {key: value for key, value in os.environ.items()
                           if not key.startswith('TARGET_')}
                    env.update(TARGET_PROFILE_ORDER='priority', TARGET_PROFILE_SET=profile_set,
                               TARGET_EGRESS_MODE=mode, TARGET_EXTRA_PROFILE_COUNT='0')
                    result = subprocess.run(['bash', '-c', 'source "$1"; _installer_progress_phases',
                                             'fixture', str(ROOT / 'tools/progress.sh')],
                                            env=env, capture_output=True, text=True, check=True)
                    phases = result.stdout.splitlines()
                    self.assertEqual(phases.count('portfolio-publish'), 1)
                    self.assertLess(phases.index('baseline-verify'), phases.index('portfolio-publish'))
                    self.assertLess(phases.index('portfolio-publish'), phases.index('verify'))


if __name__ == '__main__':
    unittest.main()
