"""Run the compact preset through the unchanged custom installation pipeline."""
import importlib.util
import json
from pathlib import Path
import shlex
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CATALOG = load('top10_catalog', 'bundle/portfolio/portfolio_catalog.py')
INPUTS = load('top10_input_fixtures', 'tests/test_selection_inputs.py')
PLAN = load('top10_plan_fixtures', 'tests/test_portfolio_plan.py')
PUBLICATION = load('top10_publication_fixtures', 'tests/test_portfolio_publish.py')
PUBLISH = PUBLICATION.PUBLISH
with patch.dict(sys.modules, {'grp': types.ModuleType('grp'), 'pwd': types.ModuleType('pwd')}):
    INSTALL = load('top10_installer', 'bundle/portfolio/install.py')


def selection(mode):
    rows = CATALOG.select_top10(mode, 'Personal VPN')
    values = INPUTS.inputs(TARGET_EGRESS_MODE=mode, TARGET_PROFILE_SET='custom',
                           TARGET_LABEL='Personal VPN',
                           TARGET_PROFILE_IDS=','.join(row['id'] for row in rows))
    return rows, values


class Top10Integration(unittest.TestCase):
    def test_selection_roundtrips_as_exact_custom_ids_without_a_new_enum(self):
        for mode, count in (('warp', 10), ('direct', 10), ('both', 20)):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                rows, values = selection(mode)
                INPUTS.PREFLIGHT.validate_inputs(values)
                destination = Path(directory) / 'target.env'
                INPUTS.TARGET.write_target(destination, values)
                stored = {key: shlex.split(raw)[0] for key, raw in
                          (line.split('=', 1) for line in destination.read_text().splitlines())}
                self.assertEqual(stored, values)
                reloaded = CATALOG.select_profiles(
                    stored['TARGET_PROFILE_SET'], stored['TARGET_EGRESS_MODE'],
                    stored['TARGET_LABEL'], stored['TARGET_PROFILE_IDS'])
                self.assertEqual(reloaded, rows)
                self.assertEqual(len(reloaded), count)
                self.assertEqual(CATALOG.PROFILE_SETS, ('basic', 'dpi', 'all', 'custom'))
                with self.assertRaises(ValueError):
                    INPUTS.PREFLIGHT.validate_inputs(dict(values, TARGET_PROFILE_IDS=','.join(
                        row['id'] for row in reversed(rows))))

    def test_runtime_reuses_only_baseline_xhttp_and_renders_exact_extra_roles(self):
        for mode, count, extra_count in (('warp', 10, 9), ('direct', 10, 9), ('both', 20, 18)):
            with self.subTest(mode=mode):
                rows, values = selection(mode)
                roles = {'warp', 'direct'} if mode == 'both' else {mode}
                baseline = [row for row in rows if row['baseline_reuse']]
                self.assertEqual({row['id'] for row in baseline},
                                 {'vless-reality-xhttp-packet-up-' + role for role in roles})
                extras = INSTALL.rows_for(values)
                self.assertEqual(extras, [row for row in rows if not row['baseline_reuse']])
                self.assertEqual(len(rows), count)
                self.assertEqual(len(extras), extra_count)
                config, manifest, ports = PLAN.build(values, PLAN.MAIN, extras, PLAN.shared, PLAN.profile)
                links = manifest['entries']
                self.assertEqual([entry['id'] for entry in links], [row['id'] for row in extras])
                self.assertEqual([entry['remark'] for entry in links], [row['name'] for row in extras])
                self.assertEqual(len({entry['uri'] for entry in links}), extra_count)
                self.assertFalse({row['id'] for row in baseline} & {entry['id'] for entry in links})
                self.assertEqual(ports, {30000 + row['port_offset']: row['network'] for row in extras})
                self.assertEqual(len(ports), 9)
                self.assertEqual(len(config['inbounds']), 9)
                self.assertEqual({outbound['tag'] for outbound in config['outbounds']},
                                 {'DIRECT', 'BLOCK'} if mode == 'direct' else
                                 {'DIRECT', 'BLOCK', 'WARP_CF'})
                routes = config['routing']['rules'][4:-1]
                self.assertEqual(len(routes), extra_count)
                for row, link, route in zip(extras, links, routes, strict=True):
                    expected = 'WARP_CF' if row['egress'] == 'warp' else 'DIRECT'
                    self.assertEqual(link['egress'], expected)
                    self.assertEqual(route['outboundTag'], expected)
                    self.assertEqual(route['user'], ['portfolio-' + row['egress'] + '-' + row['id']])

    def test_publication_filters_native_profiles_and_sqlite_rollback_preserves_clients(self):
        for mode, count in (('warp', 10), ('direct', 10), ('both', 20)):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                rows, values = selection(mode)
                target, data, initial = PUBLICATION.fixture(egress=mode)
                target.update(values)
                _, manifest, _ = PLAN.build(values, PLAN.MAIN, rows, PLAN.shared, PLAN.profile)
                extras = manifest['entries']
                intent = PUBLISH.plan(data, target, extras, initial)
                self.assertEqual(intent['names'], [row['name'] for row in rows])
                self.assertEqual(len(intent['names']), count)
                self.assertEqual(len(intent['insert_external']), 18 if mode == 'both' else 9)
                by_id = {client['id']: client['email'] for client in data['clients']}
                roles = {'warp', 'direct'} if mode == 'both' else {mode}
                expected_clients = {'germany-warp-xhttp' if role == 'warp' else 'germany-xhttp'
                                    for role in roles}
                self.assertEqual({by_id[join['client_id']] for join in intent['after']['joins']},
                                 expected_clients)
                self.assertEqual([entry['remark'] for entry in intent['after']['external']],
                                 [row['name'] for row in rows])
                path = Path(directory) / 'x-ui.db'
                PUBLICATION.create_db(path, data)
                applied = PUBLICATION.worker(path, 'apply', {
                    **intent, 'expected': intent['before'], 'intended': intent['after']})
                self.assertEqual(applied.returncode, 0, applied.stderr.decode())
                actual = json.loads(PUBLICATION.worker(path, 'read').stdout)
                self.assertEqual(actual['clients'], data['clients'])
                self.assertEqual(actual['joins'], intent['after']['joins'])
                self.assertEqual(actual['external'], intent['after']['external'])

                # The owner remains available for the isolated XHTTP and extra
                # links, while native gRPC/Hysteria bindings must be absent.
                runtime = Path(directory) / 'config.json'
                runtime.write_text(json.dumps({'inbounds': [
                    {'tag': tag, 'settings': {'clients': []}}
                    for tag in ('in-443-tcp', 'in-443-udp')]}))
                with patch.object(PUBLISH, 'XRAY_RUNTIME', runtime):
                    PUBLISH.verify_native_runtime(target)

                initial_by_name = dict(zip(PUBLISH.baseline_names(target), initial, strict=True))
                extra_by_id = {entry['id']: entry['uri'] for entry in extras}
                feed = [initial_by_name[row['name']] if row['baseline_reuse'] else extra_by_id[row['id']]
                        for row in rows]
                receipt = dict(intent, manifest_sha256=None)
                with (patch.object(PUBLISH, 'db_read', return_value=actual),
                      patch.object(PUBLISH, 'wait_native_runtime'),
                      patch.object(PUBLISH, 'feeds', return_value=feed)):
                    PUBLISH.verify_public(receipt, target, None)
                with (patch.object(PUBLISH, 'db_read', return_value=actual),
                      patch.object(PUBLISH, 'wait_native_runtime'),
                      patch.object(PUBLISH, 'feeds', return_value=list(reversed(feed)))):
                    with self.assertRaisesRegex(RuntimeError, 'PUBLISHED_FEED'):
                        PUBLISH.verify_public(receipt, target, None)

                restored = PUBLICATION.worker(path, 'restore', {
                    'expected': intent['after'], 'intended': intent['before'],
                    'inserted_external_ids': [row['id'] for row in intent['insert_external']],
                    'restore_joins': [row for row in data['joins']
                                      if {'client_id': row['client_id'], 'inbound_id': row['inbound_id']}
                                      in intent['delete_joins']],
                    'restore_external': [{**row, 'last_fetch_at': 0, 'last_fetch_error': ''}
                                         for row in data['external'] if row['id'] in intent['delete_external']]})
                self.assertEqual(restored.returncode, 0, restored.stderr.decode())
                self.assertEqual(json.loads(PUBLICATION.worker(path, 'read').stdout), data)


if __name__ == '__main__':
    unittest.main()
