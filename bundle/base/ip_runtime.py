"""Plan the managed Xray and 3x-ui changes for an IPv4 topology update.

The caller owns locks, snapshots, file installation, service restarts and recovery.
This module reads configuration and returns candidates. Database writes are CAS
operations to be run as xui inside the caller's SQLite transaction.
"""
import base64
import binascii
from contextlib import closing
from dataclasses import dataclass, field
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sqlite3
from urllib.parse import quote_plus, unquote, unquote_plus, urlsplit


DB = Path('etc/x-ui/x-ui.db')
MAIN = Path('usr/local/x-ui/bin/config.json')
PROMOTION = Path('etc/germanyvpn-xhttp-test/promotion.json')
DIRECT = PROMOTION.with_name('config.json')
DIRECT_BASELINE = PROMOTION.with_name('baseline.json')
WARP = Path('etc/germanyvpn-xhttp-warp/config.json')
PORTFOLIO = Path('etc/germanyvpn-portfolio/config.json')
PORTFOLIO_LINKS = PORTFOLIO.with_name('links.json')
PORTFOLIO_STATE = PORTFOLIO.with_name('state.json')
PORTFOLIO_HOOK = Path('etc/letsencrypt/renewal-hooks/deploy/80-germanyvpn-portfolio')
PUBLICATION = Path('var/lib/vpn-installer/portfolio-publication.json')
WARP_ENV = Path('etc/krysyuk-warp-egress/warp-egress.env')
WARP_COMMON = Path('usr/local/libexec/krysyuk-warp-egress/common.sh')
WARP_TEMPLATE = WARP_ENV.with_name('xray-warp-egress.template.json')
WARP_RUNTIME = Path('run/krysyuk-warp-egress/xray.json')
WARP_PLACEHOLDER = '__PHYSICAL_IPV4__/32'
URI_SCHEMES = frozenset(('vless', 'trojan', 'hysteria2', 'hy2'))
EDITABLE = {
    'settings': frozenset(('value',)),
    'inbounds': frozenset(('listen', 'share_addr', 'stream_settings')),
    'hosts': frozenset(('address', 'sni', 'host_header', 'verify_peer_cert_by_name')),
    'client_external_links': frozenset(('value',)),
}


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':')).encode('utf-8')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def need(condition, error):
    if not condition:
        raise ValueError(error)


def host(value, old, new):
    if value == old:
        return new
    if isinstance(value, str) and re.fullmatch(re.escape(old) + r':[0-9]{1,5}', value):
        return new + value[len(old):]
    return value


def transport(value, old, new):
    """Change only fields that represent an address or HTTP authority."""
    if isinstance(value, list):
        return [transport(item, old, new) for item in value]
    if not isinstance(value, dict):
        return value
    updated = {}
    for key, item in value.items():
        if key in ('host', 'Host', 'serverName', 'verifyPeerCertByName', 'address'):
            if isinstance(item, list):
                updated[key] = [host(address, old, new) for address in item]
            else:
                updated[key] = host(item, old, new)
        else:
            updated[key] = transport(item, old, new)
    return updated


def vmess(uri):
    payload = uri.removeprefix('vmess://')
    try:
        value = json.loads(base64.b64decode(payload + '=' * (-len(payload) % 4),
                                            altchars=b'-_', validate=True))
        need(isinstance(value, dict), 'IP_VMESS_SHAPE')
        return value
    except (ValueError, UnicodeError, binascii.Error):
        raise ValueError('IP_VMESS_SHAPE') from None


def rewrite_uri(uri: str, old: str, new: str, *, endpoint_only: bool = False) -> str:
    """Change a managed profile endpoint without changing its opaque credentials."""
    if old == new:
        return uri
    if uri.startswith('vmess://'):
        data = vmess(uri)
        if data.get('add') != old:
            return uri
        data['add'] = new
        if not endpoint_only:
            for key in ('host', 'sni'):
                if key in data:
                    data[key] = host(data[key], old, new)
        return 'vmess://' + base64.b64encode(canonical(data)).decode('ascii')
    parsed = urlsplit(uri)
    need(parsed.scheme in URI_SCHEMES, 'IP_URI_SCHEME')
    if parsed.hostname != old:
        return uri
    user, separator, address = parsed.netloc.rpartition('@')
    need(separator and user and parsed.port is not None and
         address.startswith(old + ':'), 'IP_URI_AUTHORITY')
    query = parsed.query
    if not endpoint_only:
        parts = []
        for part in query.split('&'):
            key, equals, encoded = part.partition('=')
            value = unquote_plus(encoded)
            updated = value
            if key in ('sni', 'host', 'serverName', 'peer', 'verifyPeerCertByName'):
                updated = host(value, old, new)
            elif key == 'extra' and equals:
                try:
                    extra = json.loads(value)
                except (TypeError, ValueError):
                    raise ValueError('IP_URI_EXTRA') from None
                candidate = transport(extra, old, new)
                if candidate != extra:
                    updated = canonical(candidate).decode('utf-8')
            parts.append(part if value == updated else key + equals + quote_plus(updated))
        query = '&'.join(parts)
    return parsed._replace(netloc=user + separator + new + address[len(old):],
                           query=query).geturl()


def signature(uri):
    """Match the installed portfolio publisher's exact URI receipt."""
    if uri.startswith('vmess://'):
        return {'kind': 'vmess', 'value': vmess(uri)}
    parsed = urlsplit(uri)
    need(parsed.scheme in URI_SCHEMES, 'IP_URI_SCHEME')
    return {'kind': parsed.scheme, 'head': parsed._replace(fragment='').geturl(),
            'name': unquote(parsed.fragment)}


def replace_block_targets(values, old_targets, targets):
    kept = [value for value in values if value not in old_targets]
    return list(dict.fromkeys(kept + list(targets)))


def rewrite_xray(config, old, new, previous_addresses, addresses, *, warp_template=False):
    """Stage Xray listener, transport and self-destination guards."""
    old_cidrs = {ip + '/32' for ip in previous_addresses}
    cidrs = [ip + '/32' for ip in addresses]
    if warp_template:
        old_cidrs.add(WARP_PLACEHOLDER)
        cidrs = [WARP_PLACEHOLDER, *(ip + '/32' for ip in addresses if ip != new)]
    for inbound in config.get('inbounds', []):
        if inbound.get('listen') == old:
            inbound['listen'] = new
        if 'streamSettings' in inbound:
            inbound['streamSettings'] = transport(inbound['streamSettings'], old, new)
    guards = []
    for rule in config['routing']['rules']:
        if rule.get('outboundTag') != 'BLOCK':
            continue
        ips = rule.get('ip', [])
        if 'geoip:private' in ips:
            rule['ip'] = replace_block_targets(ips, old_cidrs, cidrs)
            guards.append(rule)
        domains = rule.get('domain', [])
        old_domains = {'full:' + address for address in previous_addresses}
        if old_domains.intersection(domains):
            rule['domain'] = replace_block_targets(domains, old_domains, ['full:' + new])
    need(len(guards) == 1, 'IP_XRAY_SELF_GUARD')
    for outbound in config.get('outbounds', []):
        if outbound.get('tag') != 'DIRECT' or outbound.get('protocol') != 'freedom':
            continue
        for rule in outbound['settings']['finalRules']:
            if rule.get('action') == 'block' and 'geoip:private' in rule.get('ip', []):
                rule['ip'] = replace_block_targets(rule['ip'], old_cidrs, cidrs)
    return config


@dataclass(frozen=True, repr=False)
class CellEdit:
    table: str
    row_id: int
    column: str
    before: str
    after: str


def edit_rows(connection, edits, *, restore=False):
    need(connection.in_transaction, 'IP_DB_TRANSACTION_REQUIRED')
    for item in reversed(edits) if restore else edits:
        need(item.column in EDITABLE.get(item.table, ()), 'IP_DB_EDIT_COLUMN')
        before, after = (item.after, item.before) if restore else (item.before, item.after)
        result = connection.execute(
            f'UPDATE {item.table} SET {item.column}=? WHERE id=? AND {item.column} IS ?',
            (after, item.row_id, before))
        if restore and result.rowcount == 0:
            current = connection.execute(
                f'SELECT {item.column} FROM {item.table} WHERE id=?',
                (item.row_id,)).fetchone()
            need(current == (after,), 'IP_DB_CAS')
        else:
            need(result.rowcount == 1, 'IP_DB_CAS')


def database_edits(connection, old, new, previous_addresses, addresses):
    changes = []

    def add(table, row_id, column, before, after):
        if before != after:
            changes.append(CellEdit(table, row_id, column, before, after))

    settings = connection.execute(
        "SELECT id, key, value FROM settings WHERE key IN "
        "('subListen','subDomain','subURI','xrayTemplateConfig')").fetchall()
    need(len(settings) == 4 and len({row[1] for row in settings}) == 4,
         'IP_DB_SETTINGS')
    for row_id, key, raw in settings:
        if key == 'xrayTemplateConfig':
            config = rewrite_xray(json.loads(raw), old, new, previous_addresses, addresses)
            updated = canonical(config).decode('utf-8')
        elif key == 'subURI':
            url = urlsplit(raw)
            need(url.scheme == 'https' and url.netloc == old + ':2096', 'IP_DB_SUB_URI')
            updated = url._replace(netloc=new + ':2096').geturl()
        else:
            need(raw == old, 'IP_DB_SUB_BIND')
            updated = new
        add('settings', row_id, 'value', raw, updated)

    inbounds = connection.execute(
        'SELECT id, listen, share_addr, stream_settings, node_id, port FROM inbounds').fetchall()
    need(len(inbounds) == 3 and sorted(row[-1] for row in inbounds) == [443, 443, 8443],
         'IP_DB_INBOUNDS')
    for row_id, listen, address, raw, node, _ in inbounds:
        need(node is None and address == listen == old, 'IP_DB_INBOUND_BIND')
        add('inbounds', row_id, 'listen', listen, new)
        add('inbounds', row_id, 'share_addr', address, new)
        stream = json.loads(raw)
        updated = transport(stream, old, new)
        if stream != updated:
            add('inbounds', row_id, 'stream_settings', raw, canonical(updated).decode('utf-8'))

    hosts = connection.execute(
        'SELECT id, inbound_id, address, sni, host_header, verify_peer_cert_by_name '
        'FROM hosts').fetchall()
    need(len(hosts) == 3 and {row[1] for row in hosts} == {row[0] for row in inbounds},
         'IP_DB_HOSTS')
    for row_id, _, address, sni, header, verify_name in hosts:
        need(address == old, 'IP_DB_HOST_ADDRESS')
        for column, raw in zip(('address', 'sni', 'host_header', 'verify_peer_cert_by_name'),
                               (address, sni, header, verify_name)):
            add('hosts', row_id, column, raw, host(raw, old, new))

    for row_id, kind, raw in connection.execute(
            'SELECT id, kind, value FROM client_external_links'):
        # Some operators add remote feeds to 3x-ui. These are outside the IP move.
        if kind != 'link' or not raw.startswith(tuple(s + '://' for s in URI_SCHEMES | {'vmess'})):
            continue
        add('client_external_links', row_id, 'value', raw, rewrite_uri(raw, old, new))
    return changes


@dataclass(repr=False)
class RuntimePlan:
    old: str
    new: str
    main_config: bytes
    database: list[CellEdit]
    files: dict[Path, bytes] = field(default_factory=dict)
    xray_configs: dict[Path, bytes] = field(default_factory=dict)
    promotion: tuple[Path, dict] | None = None
    publication: tuple[Path, dict] | None = None

    def apply_database(self, connection):
        edit_rows(connection, self.database)

    def restore_database(self, connection):
        edit_rows(connection, self.database, restore=True)

    def final_files(self, actual_main: bytes, published_uris: list[str]):
        """Verify X-UI's regenerated config and finish the owned receipts."""
        current = canonical(json.loads(actual_main))
        need(current == self.main_config, 'IP_MAIN_RUNTIME_READBACK')
        output = {}
        if self.promotion:
            path, receipt = self.promotion
            output[path] = canonical(receipt)
        if self.publication:
            path, receipt = self.publication
            old_hashes = [sha(canonical(signature(rewrite_uri(uri, self.new, self.old))))
                          for uri in published_uris]
            need(old_hashes == receipt['uri_hashes'], 'IP_PUBLICATION_URI_DRIFT')
            updated = dict(receipt, uri_hashes=[sha(canonical(signature(uri)))
                                               for uri in published_uris])
            output[path] = canonical(updated)
        return output


def read_file(path):
    need(path.is_file() and not path.is_symlink(), 'IP_RUNTIME_FILE')
    return path.read_bytes()


def rewrite_line(raw, prefix, previous, candidate):
    needle = prefix + previous
    lines = raw.splitlines(keepends=True)
    matches = [index for index, line in enumerate(lines) if line.rstrip(b'\r\n') == needle]
    need(len(matches) == 1, 'IP_RUNTIME_LINE')
    index = matches[0]
    lines[index] = prefix + candidate + lines[index][len(needle):]
    return b''.join(lines)


def plan_runtime(root: Path, old: str, new: str, addresses: list[str],
                 old_interface: str, new_interface: str, *,
                 previous_addresses: list[str] | None = None,
                 lineage: str | None = None,
                 database_path: Path | None = None) -> RuntimePlan:
    need(old_interface == new_interface, 'IP_INTERFACE_CHANGED')
    previous_addresses = [old] if previous_addresses is None else previous_addresses
    need(old in previous_addresses and new in addresses and
         len(set(previous_addresses)) == len(previous_addresses) and
         len(set(addresses)) == len(addresses), 'IP_RUNTIME_ADDRESS_SET')
    for value in [*previous_addresses, *addresses]:
        address = ipaddress.IPv4Address(value)
        need(str(address) == value and address.is_global and
             not address.is_multicast and not address.is_reserved, 'IP_RUNTIME_PUBLIC_IPV4')
    addresses = [new, *(ip for ip in addresses if ip != new)]
    source_db = database_path if database_path is not None else root / DB
    need(source_db.is_file() and not source_db.is_symlink(), 'IP_RUNTIME_FILE')
    with closing(sqlite3.connect(source_db.as_uri() + '?mode=ro', uri=True)) as connection:
        connection.execute('BEGIN')
        need(connection.execute('PRAGMA quick_check').fetchone() == ('ok',), 'IP_DB_CHECK')
        edits = database_edits(connection, old, new, previous_addresses, addresses)

    def candidate(path, **kwargs):
        raw = read_file(root / path)
        updated = canonical(rewrite_xray(json.loads(raw), old, new,
                                         previous_addresses, addresses, **kwargs))
        return raw, updated

    main_before, main_after = candidate(MAIN)
    plan = RuntimePlan(old, new, main_after, edits)
    plan.xray_configs[root / MAIN] = main_after
    promotion = json.loads(read_file(root / PROMOTION))
    need(promotion.get('target') == old and promotion.get('status') == 'committed' and
         promotion.get('version') in (2, 3), 'IP_PROMOTION_STATE')
    was_direct = promotion['version'] == 3
    publication_path = root / PUBLICATION
    publication = json.loads(read_file(publication_path)) if publication_path.exists() else None
    actual_main_before = sha(canonical(json.loads(main_before)))
    need(publication is not None or promotion['main_runtime_sha256'] == actual_main_before,
         'IP_PROMOTION_MAIN_HASH')
    promotion['target'] = new
    # Pruned installations retain a historical baseline hash. Their normal
    # verifier skips the promotion's baseline-only main-runtime comparison.
    if promotion['main_runtime_sha256'] == actual_main_before:
        promotion['main_runtime_sha256'] = sha(main_after)
    plan.promotion = (root / PROMOTION, promotion)

    for path, field_name in ((DIRECT, 'direct_config_sha256'), (WARP, 'warp_config_sha256')):
        if path == WARP and was_direct:
            continue
        before, after = candidate(path)
        need(promotion[field_name] == sha(before), 'IP_PROMOTION_CONFIG_HASH')
        promotion[field_name] = sha(after)
        plan.files[root / path] = after
        plan.xray_configs[root / path] = after

    if was_direct:
        before = read_file(root / DIRECT_BASELINE)
        need(promotion['baseline_sha256'] == sha(before), 'IP_DIRECT_BASELINE_HASH')
        baseline = json.loads(before)
        baseline['links'] = [rewrite_uri(uri, old, new) for uri in baseline['links']]
        after = canonical(baseline)
        plan.files[root / DIRECT_BASELINE] = after
        promotion['baseline_sha256'] = sha(after)
    else:
        plan_warp(plan, root, candidate, old, new)

    portfolio_state_path = root / PORTFOLIO_STATE
    portfolio_links_sha = None
    if portfolio_state_path.exists():
        portfolio_links_sha = plan_portfolio(plan, root, candidate, old, new, lineage)

    if publication is not None:
        need(publication['target'] == old and publication['status'] == 'committed',
             'IP_PUBLICATION_STATE')
        publication['target'] = new
        need((publication['manifest_sha256'] is None) == (portfolio_links_sha is None),
             'IP_PUBLICATION_MANIFEST')
        if portfolio_links_sha:
            before_sha, after_sha = portfolio_links_sha
            need(publication['manifest_sha256'] == before_sha, 'IP_PUBLICATION_MANIFEST')
            publication['manifest_sha256'] = after_sha
        for row in (publication['before']['external'] + publication['after']['external'] +
                    publication['insert_external']):
            if row['kind'] == 'link':
                row['value'] = rewrite_uri(row['value'], old, new)
        plan.publication = (publication_path, publication)
    return plan


def plan_warp(plan, root, candidate, old, new):
    env_path = root / WARP_ENV
    common_path = root / WARP_COMMON
    env = read_file(env_path)
    if old != new:
        plan.files[env_path] = rewrite_line(env, b'NL_PUBLIC_IPV4=',
                                            old.encode(), new.encode())
        marker = b'  [[ "$NL_PUBLIC_IPV4" == '
        suffix = b" ]] || die 'standalone public IPv4 is fixed for this bundle'"
        plan.files[common_path] = rewrite_line(
            read_file(common_path), marker, old.encode() + suffix, new.encode() + suffix)
    _, template = candidate(WARP_TEMPLATE, warp_template=True)
    plan.files[root / WARP_TEMPLATE] = template
    # ExecStartPre generates the real file. Stage independently so the timer
    # can recover an IP change after reboot when /run has no previous config.
    config = json.loads(template)
    clients = []
    for inbound, role in zip(config['inbounds'], ('NL', 'BRIDGE'), strict=True):
        matches = re.findall(rb'(?m)^WARP_EGRESS_' + role.encode() +
                             rb'_CLIENT_ID=([0-9a-f-]{36})$', env)
        need(len(matches) == 1 and
             re.fullmatch(rb'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}', matches[0]),
             'IP_WARP_IDENTITY')
        clients.append(matches[0].decode('ascii'))
        need(inbound['tag'] == 'WARP_EGRESS_' + role + '_IN' and
             inbound['listen'] == '__WARP_EGRESS_NETNS_LISTEN__',
             'IP_WARP_TEMPLATE')
        inbound['listen'] = '169.254.254.2'
        inbound['settings']['clients'][0]['id'] = clients[-1]
    need(len(set(clients)) == 2, 'IP_WARP_IDENTITY')
    for rule in config['routing']['rules']:
        if WARP_PLACEHOLDER in rule.get('ip', []):
            rule['ip'] = [new + '/32' if item == WARP_PLACEHOLDER else item
                          for item in rule['ip']]
    plan.xray_configs[root / WARP_RUNTIME] = canonical(config)


def plan_portfolio(plan, root, candidate, old, new, lineage):
    state_path = root / PORTFOLIO_STATE
    state = json.loads(read_file(state_path))
    need(state['target'] == old and state['phase'] == 'committed', 'IP_PORTFOLIO_STATE')
    state['target'] = new
    config_before, config = candidate(PORTFOLIO)
    links_before = read_file(root / PORTFOLIO_LINKS)
    hook_before = read_file(root / PORTFOLIO_HOOK)
    for name, raw in (('config', config_before), ('links', links_before), ('hook', hook_before)):
        need(state[name + '_sha256'] == sha(raw), 'IP_PORTFOLIO_HASH')
    links = json.loads(links_before)
    need(links['target'] == old, 'IP_PORTFOLIO_LINKS')
    links['target'] = new
    for entry in links['entries']:
        entry['uri'] = rewrite_uri(entry['uri'], old, new)
    links_after = canonical(links)
    hook = hook_before
    if lineage is not None:
        need(re.fullmatch(r'/etc/letsencrypt/live/[A-Za-z0-9.-]{1,253}', lineage),
             'IP_PORTFOLIO_LINEAGE')
        lines = re.findall(rb'(?m)^lineage=(/etc/letsencrypt/live/[A-Za-z0-9.-]{1,253})$',
                           hook_before)
        need(len(lines) == 1, 'IP_PORTFOLIO_LINEAGE')
        hook = rewrite_line(hook_before, b'lineage=', lines[0], lineage.encode('ascii'))
    for name, path, raw in (('config', PORTFOLIO, config), ('links', PORTFOLIO_LINKS, links_after),
                            ('hook', PORTFOLIO_HOOK, hook)):
        plan.files[root / path] = raw
        state[name + '_sha256'] = sha(raw)
    plan.files[state_path] = canonical(state)
    plan.xray_configs[root / PORTFOLIO] = config
    return sha(links_before), sha(links_after)
