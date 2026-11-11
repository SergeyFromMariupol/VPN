#!/usr/bin/env python3
"""Rename installed profiles from a bounded JSON stdin request, transactionally.

Only the prefix and its client metadata change. Credentials, transport settings,
ordering and subscription addresses are checked independently of display names.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import closing
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import signal
import sqlite3
import stat
import sys
import unicodedata
from urllib.parse import quote, unquote


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# A private module instance owns these helpers' context. No shared interpreter or
# existing REALITY module is patched, and its on-disk implementation is unchanged.
tx = load('profile_name_transaction', 'manage-reality.py')
happ = load('profile_name_metadata', 'happ_routing.py')
x = tx.x
PENDING = Path('/var/lib/vpn-installer/profile-name-management.pending')
BACKUPS = Path('/var/backups/vpn-profile-name-management')
NGINX = Path('/etc/nginx/conf.d/3x-ui-public.conf')
ALIASES = NGINX.with_name('vpn-ip-subscription.conf')
ACCESS = Path('/etc/krysyuk-standalone/access.env')
OTHER_PENDING = tuple(map(Path, ('/var/lib/vpn-installer/reality-management.pending',
                                '/var/lib/vpn-installer/update.pending')))
FIELDS = {'clients': {'comment'}, 'client_external_links': {'value', 'remark'},
          'settings': {'value'}}
TABLES = ('clients', 'client_inbounds', 'inbounds', 'hosts', 'settings', 'client_external_links')


def need(value, code):
    if not value:
        raise RuntimeError('MANAGE_PROFILE_NAME_' + code)


_command = tx.command


def command(*args, **kwargs):
    try:
        return _command(*args, **kwargs)
    except RuntimeError as error:
        value = str(error)
        if re.fullmatch(r'MANAGE_REALITY_[A-Z0-9_]+', value):
            raise RuntimeError(value.replace('MANAGE_REALITY_', 'MANAGE_PROFILE_NAME_', 1)) from None
        raise


tx.need, tx.command, tx.BACKUPS, tx.PENDING, tx.FIELDS = need, command, BACKUPS, PENDING, FIELDS
tx.WORKER = tx.WORKER.replace(
    "allowed={'inbounds':{'stream_settings'},'hosts':{'sni'},'client_external_links':{'value'}}",
    "allowed={'clients':{'comment'},'client_external_links':{'value','remark'},'settings':{'value'}}")
tx.WORKER = tx.WORKER.replace('p=json.load(sys.stdin)', 'p=json.load(sys.stdin.buffer)')
need("allowed={'clients':" in tx.WORKER, 'HELPER_CONTRACT')
_safe_failure = tx.safe_failure
tx.safe_failure = lambda error: (str(error) if re.fullmatch(
    r'MANAGE_PROFILE_NAME_[A-Z0-9_]{1,95}', str(error)) else _safe_failure(error))


def request_target(current, request):
    need(isinstance(request, dict) and set(request) == {'label'}, 'REQUEST')
    label = request['label']
    need(isinstance(label, str) and 1 <= len(label) <= 80 and bool(label.strip()) and
         not any(unicodedata.category(c) in ('Cc', 'Zl', 'Zp') for c in label), 'LABEL')
    need(current.get('TARGET_TLS_MODE', 'letsencrypt') == 'letsencrypt', 'HTTPS_REQUIRED')
    return dict(current, TARGET_LABEL=label)


def rename(value, before, after):
    prefix = before['TARGET_LABEL'] + ' · '
    need(isinstance(value, str) and value.startswith(prefix), 'NAME_BEFORE')
    return after['TARGET_LABEL'] + value[len(before['TARGET_LABEL']):]


def vmess(uri):
    raw = uri[8:]
    decoded = base64.b64decode(raw + '=' * (-len(raw) % 4), altchars=b'-_', validate=True)
    return raw, decoded.decode('utf-8'), x.strict_json(decoded)


def rewrite_uri(uri, before, after):
    if uri.startswith('vmess://'):
        encoded, raw, value = vmess(uri)
        changed = rename(value.get('ps'), before, after)
        pattern = re.compile(r'("ps"\s*:\s*)("(?:\\.|[^"\\])*")')
        matches = list(pattern.finditer(raw))
        need(len(matches) == 1 and json.loads(matches[0][2]) == value['ps'], 'VMESS_NAME')
        match = matches[0]
        # Preserve every JSON byte outside the ps string, including credentials.
        raw = raw[:match.start(2)] + json.dumps(changed, ensure_ascii=False) + raw[match.end(2):]
        encode = base64.urlsafe_b64encode if '-' in encoded or '_' in encoded else base64.b64encode
        result = encode(raw.encode('utf-8')).decode('ascii')
        return 'vmess://' + (result if encoded.endswith('=') else result.rstrip('='))
    need(uri.partition('://')[0] in ('vless', 'trojan', 'hysteria2', 'hy2'), 'URI_KIND')
    head, separator, fragment = uri.partition('#')
    need(bool(separator), 'URI_NAME')
    return head + '#' + quote(rename(unquote(fragment, errors='strict'), before, after), safe='')


def uri_identity(uri):
    if uri.startswith('vmess://'):
        value = vmess(uri)[2]
        need(isinstance(value.get('ps'), str), 'VMESS_NAME')
        del value['ps']
        return {'vmess': value}
    return {'uri': uri.partition('#')[0]}


def uri_name(uri):
    return vmess(uri)[2]['ps'] if uri.startswith('vmess://') else unquote(uri.partition('#')[2])


def client_names(target):
    protocols = ('reality', 'hysteria2', 'xhttp')
    result = {}
    if target.get('TARGET_EGRESS_MODE', 'both') != 'direct':
        result.update((f'germany-warp-{p}', target['TARGET_LABEL'] + ' · ☁️ Cloudflare · ' + p.upper())
                      for p in protocols)
    result.update((f'germany-{p}', target['TARGET_LABEL'] + ' · 🖥️ IP сервера · ' + p.upper())
                  for p in protocols)
    return result


def feed_count(target, publication):
    if publication is not None:
        need(isinstance(publication.get('names'), list) and 1 <= len(publication['names']) <= 146, 'PUBLICATION_COUNT')
        return len(publication['names'])
    need(target.get('TARGET_EGRESS_MODE', 'both') == 'both' and
         target.get('TARGET_PROFILE_SET', 'basic') == 'basic' and not target.get('TARGET_PROFILE_IDS'),
         'PUBLICATION_REQUIRED')
    return 6


def db_edits(connection, before, after):
    connection.row_factory = sqlite3.Row
    need(connection.execute('PRAGMA quick_check').fetchone()[0] == 'ok', 'DATABASE_CHECK')
    names = client_names(before)
    clients = list(connection.execute('SELECT id,email,comment FROM clients ORDER BY id'))
    need(len(clients) == len(names) and {row['email'] for row in clients} == set(names), 'MANAGED_CLIENTS')
    result = []
    for row in clients:
        need(row['comment'] == names[row['email']], 'CLIENT_NAME_BEFORE')
        result.append(['clients', row['id'], 'comment', row['comment'], rename(row['comment'], before, after)])
    for row in connection.execute('SELECT id,kind,value,remark FROM client_external_links ORDER BY id'):
        need(row['kind'] == 'link', 'EXTERNAL_KIND')
        need(uri_name(row['value']) == row['remark'], 'EXTERNAL_NAME_BEFORE')
        result.extend((['client_external_links', row['id'], 'remark', row['remark'], rename(row['remark'], before, after)],
                       ['client_external_links', row['id'], 'value', row['value'], rewrite_uri(row['value'], before, after)]))
    settings = list(connection.execute("SELECT id,value FROM settings WHERE key='subRoutingRules'"))
    need(len(settings) == 1 and settings[0]['value'] == happ.routing_link(before['TARGET_LABEL']), 'HAPP_BEFORE')
    result.append(['settings', settings[0]['id'], 'value', settings[0]['value'], happ.routing_link(after['TARGET_LABEL'])])
    return result


def database_fingerprint(connection):
    """Fingerprint all managed identities/configuration while omitting names only.

    X-UI's traffic and fetch timestamps are independent mutable observations.
    No credential, route, transport, enable flag, host, key or SNI is omitted.
    """
    connection.row_factory = sqlite3.Row
    result = {}
    for table in TABLES:
        rows = []
        for row in connection.execute(f'SELECT * FROM {table} ORDER BY rowid'):
            value = dict(row)
            for key in ('up', 'down', 'last_online', 'last_fetch_at', 'last_fetch_error'):
                value.pop(key, None)
            if table == 'clients':
                value.pop('comment', None)
                value.pop('updated_at', None)
            if table == 'inbounds':
                value.pop('last_reset', None)
            if table == 'client_external_links':
                value.pop('remark', None)
                value['value'] = uri_identity(value['value'])
            if table == 'settings' and value.get('key') == 'subRoutingRules':
                # Check the routing payload itself with only Name omitted.
                raw = value['value'].removeprefix('happ://routing/onadd/')
                routing = x.strict_json(base64.b64decode(raw, validate=True))
                routing.pop('Name')
                value['value'] = routing
            rows.append(value)
        result[table] = rows
    return x.sha(x.canonical(result))


def rewrite_nginx(raw, before, after):
    for function in (happ.routing_link, happ.v2raytun_header):
        old, new = function(before['TARGET_LABEL']).encode(), function(after['TARGET_LABEL']).encode()
        need(raw.count(old) == 1, 'NGINX_METADATA_BEFORE')
        raw = raw.replace(old, new, 1)
    return raw


def rewrite_target(raw, before, after):
    need(x.parse_env(raw) == before, 'TARGET_BEFORE')
    lines = raw.splitlines(keepends=True)
    indices = [index for index, line in enumerate(lines) if line.startswith(b'TARGET_LABEL=')]
    need(len(indices) == 1, 'TARGET_LABEL_FIELD')
    index = indices[0]
    ending = b'\r\n' if lines[index].endswith(b'\r\n') else b'\n' if lines[index].endswith(b'\n') else b''
    lines[index] = b'TARGET_LABEL=' + shlex.quote(after['TARGET_LABEL']).encode('utf-8') + ending
    return b''.join(lines)


class Plan:
    def __init__(self, before, after, initial):
        self.before, self.after, self.initial = before, after, initial
        self.expected = [rewrite_uri(uri, before, after) for uri in initial]
        need([uri_identity(uri) for uri in initial] == [uri_identity(uri) for uri in self.expected], 'URI_IDENTITY')
        self.files, self.configs, self.originals = {}, {}, {}

    def expected_before(self):
        return self.initial

    def build(self, root=Path('/')):
        def path(absolute):
            return root / absolute.as_posix().lstrip('/')

        def read(absolute):
            raw = path(absolute).read_bytes()
            self.originals[absolute] = raw
            return raw

        with closing(sqlite3.connect(path(tx.DB).as_uri() + '?mode=ro', uri=True)) as connection:
            self.database = db_edits(connection, self.before, self.after)
            self.fingerprint = database_fingerprint(connection)
        for absolute in (tx.MAIN, tx.DIRECT, tx.WARP, tx.PORTFOLIO):
            if path(absolute).exists():
                self.configs[absolute] = read(absolute)
        need(tx.MAIN in self.configs and tx.DIRECT in self.configs, 'TRANSPORT_CONFIGS')
        self.main = x.canonical(x.strict_json(self.configs[tx.MAIN]))
        for absolute in (ACCESS, tx.SERVER_ENV, ALIASES):
            if path(absolute).exists():
                read(absolute)
        self.files[NGINX] = rewrite_nginx(read(NGINX), self.before, self.after)
        need(path(tx.PROMOTION).exists(), 'PROMOTION')
        if path(tx.PROMOTION).exists():
            marker = x.strict_json(read(tx.PROMOTION))
            need(marker.get('status') == 'committed' and marker.get('target') == self.before['TARGET_IPV4'] and
                 marker.get('version') in (2, 3), 'PROMOTION')
            need(marker['direct_config_sha256'] == x.sha(self.configs[tx.DIRECT]), 'PROMOTION_HASH')
            need(marker['main_runtime_sha256'] == x.sha(self.main) or path(tx.PUBLICATION).exists(), 'PROMOTION_MAIN_HASH')
            if marker['version'] == 2:
                need(marker['warp_config_sha256'] == x.sha(self.configs[tx.WARP]), 'PROMOTION_HASH')
            else:
                raw = read(tx.BASELINE)
                need(x.sha(raw) == marker['baseline_sha256'], 'BASELINE_HASH')
                baseline = x.strict_json(raw)
                baseline['links'] = [rewrite_uri(uri, self.before, self.after) for uri in baseline['links']]
                self.files[tx.BASELINE] = x.canonical(baseline)
                marker['baseline_sha256'] = x.sha(self.files[tx.BASELINE])
                self.files[tx.PROMOTION] = x.canonical(marker)
        if path(tx.PORTFOLIO_STATE).exists():
            state = x.strict_json(read(tx.PORTFOLIO_STATE))
            raw = read(tx.LINKS)
            need(state.get('phase') == 'committed' and state.get('target') == self.before['TARGET_IPV4'] and
                 state['config_sha256'] == x.sha(self.configs[tx.PORTFOLIO]) and
                 state['links_sha256'] == x.sha(raw), 'PORTFOLIO_HASH')
            links = x.strict_json(raw)
            for entry in links['entries']:
                entry['remark'] = rename(entry['remark'], self.before, self.after)
                entry['uri'] = rewrite_uri(entry['uri'], self.before, self.after)
                need(uri_name(entry['uri']) == entry['remark'], 'PORTFOLIO_NAME')
            self.files[tx.LINKS] = x.canonical(links)
            state['links_sha256'] = x.sha(self.files[tx.LINKS])
            self.files[tx.PORTFOLIO_STATE] = x.canonical(state)
        if path(tx.PUBLICATION).exists():
            publication = x.strict_json(read(tx.PUBLICATION))
            need(publication.get('status') == 'committed' and publication.get('target') == self.before['TARGET_IPV4'] and
                 publication['names'] == [uri_name(uri) for uri in self.initial] and
                 publication['uri_hashes'] == tx.uri_hashes(self.initial), 'PUBLICATION_STATE')
            for row in publication['after']['external']:
                need(row['kind'] == 'link', 'PUBLICATION_KIND')
                row['remark'] = rename(row['remark'], self.before, self.after)
                row['value'] = rewrite_uri(row['value'], self.before, self.after)
            publication['names'] = [uri_name(uri) for uri in self.expected]
            publication['uri_hashes'] = tx.uri_hashes(self.expected)
            if publication['manifest_sha256'] is not None:
                need(tx.LINKS in self.files and publication['manifest_sha256'] == x.sha(self.originals[tx.LINKS]),
                     'PUBLICATION_MANIFEST')
                publication['manifest_sha256'] = x.sha(self.files[tx.LINKS])
            self.files[tx.PUBLICATION] = x.canonical(publication)
        else:
            feed_count(self.before, None)
        self.files[tx.TARGET] = rewrite_target(read(tx.TARGET), self.before, self.after)
        return self


def check_database(record, *, restore=False):
    with closing(sqlite3.connect(tx.DB.as_uri() + '?mode=ro', uri=True)) as connection:
        need(database_fingerprint(connection) == record['fingerprint'], 'DATABASE_IDENTITY')
        for table, row, column, old, new in record['database']:
            need(table in FIELDS and column in FIELDS[table] and isinstance(row, int), 'DATABASE_EDIT')
            value = connection.execute(f'SELECT {column} FROM {table} WHERE id=?', (row,)).fetchone()
            need(value is not None and value[0] == (old if restore else new), 'DATABASE_NAME_READBACK')


def verify_metadata():
    command(['bash', str(tx.BUNDLE / 'tests/verify-happ-routing.sh')], timeout=120, step='METADATA_VERIFY')


def verify_record(record, secret, *, restore=False):
    check_database(record, restore=restore)
    tx.verify_runtime(base64.b64decode(record['main']))
    for raw, digest in record['unchanged'].items():
        need(x.sha(Path(raw).read_bytes()) == digest, 'UNCHANGED_FILE_READBACK')
    tx.wait_published(record['before_target'] if restore else record['after_target'], secret,
                      record['before_feed'] if restore else record['after_feed'])
    verify_metadata()
    if tx.PUBLICATION.exists():
        command(['python3', '-I', '-B', str(tx.SOURCE / 'tools/portfolio_publish.py'), '--verify'],
                timeout=90, step='PUBLICATION_VERIFY')


def rollback(journal, secret):
    record = journal.record
    # A previous rollback may already have restarted timers before its final
    # metadata/readback failed. Re-pause their durably recorded owned state.
    tx.phase(journal, 'ROLLBACK_PAUSE_CERTIFICATE_TIMERS', best_effort=True)
    for timer in record['paused_timers']:
        if tx.running(timer):
            command(['systemctl', 'stop', timer])
    if record.get('runtime_touched'):
        need(tx.quiescent('certbot.service') and tx.quiescent('vpn-cert-reconcile.service'), 'CERTIFICATE_JOB_BUSY')
    tx.phase(journal, 'ROLLBACK_STOP_DATA', best_effort=True)
    if record.get('runtime_touched'):
        tx.stop(record['units'])
    if record['database_applied']:
        tx.phase(journal, 'ROLLBACK_DATABASE', best_effort=True)
        tx.database(record['database'], restore=True)
    tx.phase(journal, 'ROLLBACK_FILES', best_effort=True)
    journal.rollback()
    tx.phase(journal, 'ROLLBACK_NGINX', best_effort=True)
    command(['nginx', '-t'], step='NGINX_PREFLIGHT')
    command(['systemctl', 'reload', 'nginx.service'], step='NGINX_RELOAD')
    if record.get('runtime_touched'):
        tx.start(record['units'])
    tx.start(record['paused_timers'])
    tx.phase(journal, 'ROLLBACK_READBACK', best_effort=True)
    verify_record(record, secret, restore=True)
    record['status'] = 'rolled_back'
    need(tx.phase(journal, 'ROLLBACK_COMPLETE', best_effort=True), 'ROLLBACK_METADATA_PENDING')
    PENDING.unlink(missing_ok=True)


def apply(plan, secret):
    need(tx.running('x-ui.service') and tx.running('nginx.service'), 'BASELINE_SERVICE')
    journal = tx.snapshot(plan, ['x-ui.service'])
    journal.record.update(kind='profile-name', fingerprint=plan.fingerprint,
                          main=base64.b64encode(plan.main).decode(),
                          unchanged={str(path): x.sha(raw) for path, raw in plan.originals.items()
                                     if path not in plan.files and path != tx.MAIN})
    journal.save()
    tx.validate_candidates(plan, journal.directory)
    tx.atomic(PENDING, str(journal.directory).encode())
    durable_commit = False
    commit_attempted = False
    try:
        tx.phase(journal, 'PAUSE_CERTIFICATE_TIMERS')
        for timer in ('certbot.timer', 'vpn-cert-reconcile.timer'):
            if tx.running(timer):
                journal.record['paused_timers'].append(timer)
                journal.save()
                command(['systemctl', 'stop', timer])
        need(tx.quiescent('certbot.service') and tx.quiescent('vpn-cert-reconcile.service'), 'CERTIFICATE_JOB_BUSY')
        journal.record['runtime_touched'] = True
        tx.phase(journal, 'STOP_DATA')
        tx.stop(journal.record['units'])
        check_database(journal.record, restore=True)
        for path, raw in plan.originals.items():
            need(path.read_bytes() == raw, 'FILE_CONCURRENT_WRITE')
        journal.record['database_applied'] = 'intent'
        tx.phase(journal, 'DATABASE_APPLY')
        tx.database(plan.database)
        journal.record['database_applied'] = True
        tx.phase(journal, 'FILE_PUBLISH')
        for path, raw in plan.files.items():
            journal.change(path, raw)
        tx.phase(journal, 'NGINX_RELOAD')
        command(['nginx', '-t'], step='NGINX_PREFLIGHT')
        command(['systemctl', 'reload', 'nginx.service'], step='NGINX_RELOAD')
        tx.phase(journal, 'START_DATA')
        tx.start(journal.record['units'])
        tx.phase(journal, 'PUBLIC_READBACK')
        verify_record(journal.record, secret)
        for path, raw in plan.files.items():
            need(path.read_bytes() == raw, 'FILE_READBACK')
        tx.start(journal.record['paused_timers'])
        with x.defer_interruptions():
            commit_attempted = True
            journal.record['status'] = 'committed'
            tx.phase(journal, 'COMMITTED')
            durable_commit = True
        PENDING.unlink()
    except BaseException as original:
        if durable_commit:
            # The new state passed every check and its commit is durable. A
            # cleanup failure must never undo it under a committed journal.
            raise RuntimeError('MANAGE_PROFILE_NAME_COMMITTED_RECOVERY_REQUIRED') from None
        journal.record['status'] = 'prepared'
        if commit_attempted:
            # An atomic save can fail after replacing the journal. Require a
            # durable undo intent before restoring anything in this ambiguous
            # commit window; otherwise retain the verified state for recovery.
            need(tx.phase(journal, 'ROLLBACK_INTENT', best_effort=True), 'COMMIT_METADATA_PENDING')
        tx.remember_failure(journal, 'primary_failure', original)
        try:
            rollback(journal, secret)
        except BaseException as failure:
            tx.remember_failure(journal, 'rollback_failure', failure)
            raise RuntimeError('MANAGE_PROFILE_NAME_ROLLBACK_REQUIRED') from None
        raise
    print('PROFILE_NAME_MANAGEMENT_COMMITTED=1')


def recover():
    directory = Path(tx.private(PENDING).decode())
    need(directory.parent == BACKUPS and re.fullmatch(r'change-[a-zA-Z0-9_-]+', directory.name), 'RECOVERY_DIRECTORY')
    info = directory.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700, 'RECOVERY_DIRECTORY')
    manifest = x.strict_json(tx.private(directory / 'manifest.json'))
    need(set(manifest) == {'x-ui.db', 'managed-before.tar', 'nft-before.txt', 'ufw-before.txt'} and
         all(x.sha(tx.private(directory / name)) == digest for name, digest in manifest.items()), 'RECOVERY_SNAPSHOT')
    record = x.strict_json(tx.private(directory / 'journal.json'))
    need(record.get('kind') == 'profile-name' and record.get('version') == 1 and
         record.get('status') in ('prepared', 'committed', 'rolled_back'), 'RECOVERY_RECORD')
    secret = x.parse_env(tx.private(tx.SERVER_ENV))
    if record['status'] == 'committed':
        for path, before, after in record['files']:
            need(tx.file_state(Path(path)) == after, 'RECOVERY_FOREIGN_FILE')
        verify_record(record, secret)
        PENDING.unlink()
    else:
        rollback(tx.Journal(directory, record), secret)
    print('PROFILE_NAME_MANAGEMENT_RECOVERED=' + record['status'])


def main(argv=None):
    import fcntl
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    for option in ('--check-only', '--apply', '--recover'):
        modes.add_argument(option, action='store_true')
    args = parser.parse_args(argv)
    need(os.geteuid() == 0, 'ROOT_REQUIRED')
    os.umask(0o077)
    fd = os.open('/run/vpn-installer.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600 and
             info.st_nlink == 1, 'LOCK_OWNERSHIP')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        need(not any(path.exists() or path.is_symlink() for path in OTHER_PENDING), 'OTHER_PENDING_RECOVERY_REQUIRED')
        if args.recover:
            recover()
            return
        need(not PENDING.exists() and not PENDING.is_symlink(), 'PENDING_RECOVERY_REQUIRED')
        raw = sys.stdin.buffer.read(4097)
        need(len(raw) <= 4096, 'REQUEST_SIZE')
        before = x.parse_env(tx.private(tx.TARGET))
        after = request_target(before, x.strict_json(raw))
        if after['TARGET_LABEL'] == before['TARGET_LABEL']:
            print('PROFILE_NAME_MANAGEMENT_UNCHANGED=1')
            return
        secret = x.parse_env(tx.private(tx.SERVER_ENV))
        publication = x.strict_json(tx.private(tx.PUBLICATION)) if tx.PUBLICATION.exists() else None
        count = feed_count(before, publication)
        initial = x.native(before, secret, expected_count=count)
        plan = Plan(before, after, initial).build()
        verify_metadata()
        if tx.PUBLICATION.exists():
            command(['python3', '-I', '-B', str(tx.SOURCE / 'tools/portfolio_publish.py'), '--verify'], timeout=90,
                    step='BASELINE_PUBLICATION_VERIFY')
        if args.check_only:
            print('PROFILE_NAME_MANAGEMENT_PREFLIGHT=PASS')
        else:
            apply(plan, secret)
    finally:
        os.close(fd)


if __name__ == '__main__':
    try:
        def interrupted(signum, frame):
            raise InterruptedError('MANAGE_PROFILE_NAME_INTERRUPTED')
        for item in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(item, interrupted)
        main()
    except BaseException as error:
        code = str(error)
        if not re.fullmatch(r'MANAGE_PROFILE_NAME_[A-Z0-9_]+', code):
            code = 'MANAGE_PROFILE_NAME_FAILED'
        print('VPN_ERROR_CODE=' + code, file=sys.stderr)
        raise SystemExit(2 if code == 'MANAGE_PROFILE_NAME_LABEL' else 1)
