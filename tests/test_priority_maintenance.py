"""Priority publications retain order through IP aliases and maintenance."""
import base64
from contextlib import closing
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
from urllib.parse import quote


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'bundle/base'
sys.path.insert(0, str(BASE))


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CAT = load('priority_maintenance_catalog', 'bundle/portfolio/portfolio_catalog.py')
with patch.dict(sys.modules, {key: types.ModuleType(key) for key in ('fcntl', 'grp', 'pwd')
                              if key not in sys.modules}):
    IP = load('priority_ip_reconcile', 'bundle/base/ip_reconcile.py')
NAMES = load('priority_name_fixtures', 'tests/test_manage_profile_name.py')
SNI = load('priority_sni_maintenance', 'bundle/scripts/manage-reality.py')
from ip_feed import rewrite_feed
from ip_network import uri_lines


def target(profile_set='basic', mode='both'):
    return dict(TARGET_IPV4='8.8.4.4', TARGET_LABEL='Personal VPN',
                TARGET_EGRESS_MODE=mode, TARGET_PROFILE_SET=profile_set,
                TARGET_PROFILE_ORDER='priority')


def feed(rows, address='8.8.4.4'):
    links = []
    for index, row in enumerate(rows):
        if row['protocol'] == 'vmess':
            raw = json.dumps({'add': address, 'ps': row['name'], 'id': 'credential-' + str(index),
                              'port': str(30000 + index)}).encode()
            uri = 'vmess://' + base64.b64encode(raw).decode()
        else:
            uri = (row['protocol'] + '://credential-' + str(index) + '@' + address +
                   ':' + str(30000 + index) + '?sni=example.com#' + quote(row['name'], safe=''))
        links.append(uri)
    return ('\n'.join(links) + '\n').encode()


class PriorityIPMaintenance(unittest.TestCase):
    def test_every_priority_preset_uses_exact_selected_rows_and_publication_order(self):
        for preset, count in (('basic', 3), ('dpi', 49), ('all', 73)):
            for mode in ('warp', 'direct', 'both'):
                with self.subTest(preset=preset, mode=mode):
                    values = target(preset, mode)
                    rows = IP.custom_profile_rows(values)
                    self.assertEqual(len(rows), count * (2 if mode == 'both' else 1))
                    self.assertEqual(rows, CAT.select_profiles(preset, mode, values['TARGET_LABEL'],
                                                               profile_order='priority'))
                    receipt = dict(status='committed', target=values['TARGET_IPV4'],
                                   profile_set=preset, egress=mode, profile_order='priority',
                                   names=[row['name'] for row in rows])
                    with patch.object(IP, 'managed_json', return_value=receipt):
                        IP.check_custom_publication(values, rows)
                    for changed in (dict(receipt, profile_order='legacy'),
                                    dict(receipt, names=list(reversed(receipt['names'])))):
                        with patch.object(IP, 'managed_json', return_value=changed):
                            with self.assertRaisesRegex(RuntimeError, 'IP_PUBLICATION_SELECTION'):
                                IP.check_custom_publication(values, rows)
        legacy = target()
        del legacy['TARGET_PROFILE_ORDER']
        self.assertIsNone(IP.custom_profile_rows(legacy))

    def test_custom_priority_rows_and_portfolio_receipt_match_order_policy(self):
        values = target('custom', 'direct')
        selected = CAT.select_top10('direct', values['TARGET_LABEL'])
        values['TARGET_PROFILE_IDS'] = ','.join(row['id'] for row in selected)
        rows = IP.custom_profile_rows(values)
        self.assertEqual([row['id'] for row in rows], [row['id'] for row in selected])
        extras = [row for row in rows if not row['baseline_reuse']]
        receipt = dict(phase='committed', target=values['TARGET_IPV4'], profile_set='custom',
                       egress_mode='direct', profile_order='priority',
                       profile_ids=values['TARGET_PROFILE_IDS'],
                       ports={str(30000 + row['port_offset']): row['network'] for row in extras})
        with patch.object(IP, 'managed_json', return_value=receipt):
            self.assertEqual(IP.managed_portfolio(values, rows), receipt)
        with patch.object(IP, 'managed_json', return_value=dict(receipt, profile_order='legacy')):
            with self.assertRaisesRegex(RuntimeError, 'IP_PORTFOLIO_SELECTION'):
                IP.managed_portfolio(values, rows)

    def test_aliases_keep_all_profile_orders_and_primary_readback_rejects_reordering(self):
        for preset, mode in (('basic', 'direct'), ('basic', 'both'), ('dpi', 'direct'), ('all', 'both')):
            with self.subTest(preset=preset, mode=mode):
                rows = IP.custom_profile_rows(target(preset, mode))
                names = [row['name'] for row in rows]
                original = feed(rows)
                for body in (original, base64.b64encode(original)):
                    translated = rewrite_feed(body, '8.8.4.4', '9.9.9.9')
                    self.assertEqual(len(uri_lines(translated)), len(rows))
                    def fetch(address, _path, _ua):
                        return (body if address == '8.8.4.4' else translated), {'routing': 'retained'}
                    with patch.object(IP, 'fetch_feed', side_effect=fetch):
                        self.assertEqual(IP.verify_feeds('8.8.4.4', ['9.9.9.9'], '/fixture', names),
                                         uri_lines(body))
                    reversed_body = ('\n'.join(reversed(uri_lines(body))) + '\n').encode()
                    with patch.object(IP, 'fetch_feed', return_value=(reversed_body, {})):
                        with self.assertRaisesRegex(RuntimeError, 'IP_PUBLICATION_ORDER'):
                            IP.verify_feeds('8.8.4.4', [], '/fixture', names)


class PromotedNativeMaintenance(unittest.TestCase):
    def test_rename_and_sni_edits_keep_promoted_native_order_visibility_and_credentials(self):
        M = NAMES.M
        for mode in ('direct', 'both'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                before, initial, path = NAMES.fixture(root, mode, 'basic')
                before['TARGET_PROFILE_ORDER'] = 'priority'
                rows = CAT.select_profiles('basic', mode, before['TARGET_LABEL'], profile_order='priority')
                old_by_name = {M.uri_name(uri): uri for uri in initial}
                for row in rows:
                    if row['protocol'] == 'hysteria2':
                        old_by_name[row['name']] = ('hysteria2://retained-auth@vpn.example.test:443'
                            '?sni=vpn.example.test#' + quote(row['name'], safe=''))
                initial = [old_by_name[row['name']] for row in rows]
                publication_path = root / M.tx.PUBLICATION.as_posix().lstrip('/')
                publication = json.loads(publication_path.read_bytes())
                with closing(sqlite3.connect(path)) as db, db:
                    db.execute('ALTER TABLE inbounds ADD COLUMN exclude_from_sub INTEGER DEFAULT 1')
                    for index, uri in enumerate(initial):
                        db.execute('UPDATE client_external_links SET value=?,sort_index=? WHERE remark=?',
                                   (uri, index, M.uri_name(uri)))
                    db.row_factory = sqlite3.Row
                    external = [dict(row) for row in db.execute(
                        'SELECT id,kind,value,remark,enable,sort_index FROM client_external_links ORDER BY sort_index,id')]
                publication.update(profile_order='priority', names=[row['name'] for row in rows],
                                   uri_hashes=M.tx.uri_hashes(initial),
                                   visibility_before=[{'id': 1, 'exclude_from_sub': 0}],
                                   visibility_after=[{'id': 1, 'exclude_from_sub': 1}],
                                   update_visibility=[{'id': 1, 'before': 0, 'after': 1}])
                publication['after']['external'] = external
                publication_path.write_bytes(M.x.canonical(publication))
                (root / M.tx.TARGET.as_posix().lstrip('/')).write_bytes(M.tx.serialize(before))
                after = M.request_target(before, {'label': 'New name 🚀'})
                plan = M.Plan(before, after, initial).build(root)
                renamed = json.loads(plan.files[M.tx.PUBLICATION])
                self.assertEqual([row['id'] for row in renamed['after']['external']],
                                 [row['id'] for row in external])
                for key in ('visibility_before', 'visibility_after', 'update_visibility', 'profile_order'):
                    self.assertEqual(renamed[key], publication[key])
                self.assertEqual([M.uri_identity(uri) for uri in plan.expected],
                                 [M.uri_identity(uri) for uri in initial])
                with closing(sqlite3.connect(path)) as db, db:
                    fingerprint = M.database_fingerprint(db)
                    M.tx.edit_database(db, plan.database)
                    self.assertEqual(M.database_fingerprint(db), fingerprint)
                    self.assertEqual([row[0] for row in db.execute('SELECT exclude_from_sub FROM inbounds')], [1])
                    M.tx.edit_database(db, plan.database, restore=True)
                    new_sni = SNI.request_target(before, {'mode': 'external', 'sni': 'example.net'})
                    edits = SNI.db_edits(db, before, new_sni)
                    SNI.edit_database(db, edits)
                    actual = [row[0] for row in db.execute(
                        'SELECT value FROM client_external_links ORDER BY sort_index,id')]
                    self.assertEqual(actual, [SNI.rewrite_uri(uri, before, new_sni) for uri in initial])
                    self.assertEqual([row[0] for row in db.execute('SELECT exclude_from_sub FROM inbounds')], [1])
                    self.assertEqual([M.uri_name(uri) for uri in actual], publication['names'])
                    SNI.edit_database(db, edits, restore=True)
                    self.assertEqual([row[0] for row in db.execute(
                        'SELECT value FROM client_external_links ORDER BY sort_index,id')], initial)


if __name__ == '__main__':
    unittest.main()
