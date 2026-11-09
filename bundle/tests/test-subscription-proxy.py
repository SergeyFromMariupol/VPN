"""Exercise the public TLS proxy with a loopback subscription fixture."""
from base64 import b64encode
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPSConnection, parse_headers
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
import json
import os
from pathlib import Path
import queue
import runpy
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time


BUNDLE = Path(__file__).resolve().parents[1]
METADATA = runpy.run_path(str(BUNDLE / 'scripts/happ_routing.py'))
IP_NETWORK = runpy.run_path(str(BUNDLE / 'base/ip_network.py'))
PUBLIC = '127.0.0.2'
ALIAS = '127.0.0.3'
PATH_PREFIX = 'a' * 40
SUBSCRIPTION_PATH = f'/{PATH_PREFIX}/fixture'
LABEL = 'Тест 🇩🇪 «Профиль»'
INCY_AGENT = 'INCY/3.9.9/android Dalvik/2.1.0'
COPY_URL = 'https://raw.githubusercontent.com/SergeyFromMariupol/VPN/main/bundle/scripts/android-app-bypass.txt'
PAGE_MARKER = b'<div id="app"></div>'
HTML = b'<!doctype html><html><body>' + PAGE_MARKER + b'</body></html>'
INFO = json.dumps({'marker': PAGE_MARKER.decode()}).encode()
OWNER_METADATA = {
    'Profile-Web-Page-Url': 'https://fixture.example/home',
    'Announce': 'Owner notice',
    'Announce-Url': 'https://fixture.example/notice',
}


def body_for(address):
    return b64encode(f'vless://fixture@{address}:443#fixture\n'.encode('ascii'))


class Subscription(BaseHTTPRequestHandler):
    def do_GET(self):
        assert self.headers['Host'] == 'fixture.example:2096'
        assert self.headers['X-Forwarded-Proto'] == 'https'
        if self.path == SUBSCRIPTION_PATH + '?format=info':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(INFO)
            return
        if self.path in (SUBSCRIPTION_PATH + '?html=1', SUBSCRIPTION_PATH + '?view=html') or (
                self.path == SUBSCRIPTION_PATH and self.headers.get('Accept') == 'text/html'):
            assert self.headers.get('Accept-Encoding') is None
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(HTML)
            return
        assert self.path == SUBSCRIPTION_PATH
        if self.server.hold_requests and self.headers['User-Agent'] == INCY_AGENT:
            self.server.arrivals.put(None)
            assert self.server.release_requests.wait(15)
        self.send_response(200)
        # 3X-UI 3.11 suppresses native Happ routing headers for INCY.
        if not self.headers.get('User-Agent', '').lower().startswith('incy/'):
            self.send_header('Routing', METADATA['routing_link'](LABEL))
            self.send_header('Routing-Enable', 'true')
        if self.server.owner_metadata:
            for key, value in OWNER_METADATA.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body_for(PUBLIC))

    def log_message(self, *_args):
        pass


def request(address, agent, tls, source=None, *, path=SUBSCRIPTION_PATH, extra_headers=None):
    conn = HTTPSConnection(address, 2096, timeout=12, context=tls, source_address=source)
    try:
        conn.request('GET', path, headers={'User-Agent': agent, **(extra_headers or {})})
        with conn.getresponse() as response:
            fields = ''.join(f'{name}: {value}\r\n' for name, value in response.getheaders())
            raw = f'HTTP/1.1 {response.status} {response.reason}\r\n{fields}\r\n'.encode('ascii')
            return raw, response.read()
    finally:
        conn.close()


def check_requests(address, provider_id, tls):
    agents = (('happ', 'Happ/4.10.1/Android/37'), ('happ', 'Happ/4.10.1/AndroidTV/37'),
              ('ios', 'Happ/4.10.1/iOS/26.0'), ('desktop', 'Happ/4.4.6/Windows'),
              ('incy', INCY_AGENT),
              ('incy', 'INCY/3.9.9/Android'), ('v2raytun', 'v2raytun/android'),
              ('karing', 'Karing'), ('desktop', 'INCY/1.0/windows'))
    for client, agent in agents:
        headers, body = request(address, agent, tls)
        assert METADATA['check_headers'](headers, LABEL, client, provider_id), (address, agent)
        if client == 'happ' and not provider_id:
            assert b'\r\nper-app-proxy-mode: bypass\r\n' in headers.lower(), (address, agent)
            assert b'\r\nproviderid:' not in headers.lower(), (address, agent)
        metadata = parse_headers(BytesIO(headers.split(b'\r\n', 1)[1]))
        website = [COPY_URL] if agent.lower().startswith(('happ/', 'incy/')) else None
        assert metadata.get_all('Profile-Web-Page-Url') == website, (address, agent)
        announce_url = [COPY_URL] if client == 'v2raytun' else None
        assert metadata.get_all('Announce-Url') == announce_url, (address, agent)
        if announce_url:
            assert metadata.get('Announce', '').startswith('base64:'), (address, agent)
        else:
            assert metadata.get('Announce') is None, (address, agent)
        assert body == body_for(address), (address, agent)


def check_browser_copy_panel(tls):
    asset_path = '/android-app-bypass.js'
    script_tag = b'<script src="/android-app-bypass.js" defer referrerpolicy="no-referrer"></script>'
    for query, extra in (('', {'Accept': 'text/html'}), ('?html=1', {}), ('?view=html', {})):
        raw, body = request(PUBLIC, 'Mozilla/5.0', tls, path=SUBSCRIPTION_PATH + query,
                            extra_headers={'Accept-Encoding': 'gzip', **extra})
        assert raw.startswith(b'HTTP/1.1 200'), query
        assert body == HTML.replace(PAGE_MARKER, PAGE_MARKER + script_tag), query
    raw, script = request(PUBLIC, 'Mozilla/5.0', tls, path=asset_path)
    assert raw.startswith(b'HTTP/1.1 200')
    assert b'content-type: application/javascript; charset=utf-8\r\n' in raw.lower()
    packages = (BUNDLE / 'scripts/android-app-bypass.txt').read_text(encoding='ascii')
    assert b'const packages = ' + json.dumps(packages).encode() + b';' in script
    assert b'navigator.clipboard.writeText(packages)' in script
    _, info = request(PUBLIC, 'Mozilla/5.0', tls, path=SUBSCRIPTION_PATH + '?format=info')
    assert info == INFO


def check_owner_metadata(upstream, tls):
    upstream.owner_metadata = True
    try:
        for address in (PUBLIC, ALIAS):
            for agent in ('Happ/4.10.1/Android/37', INCY_AGENT, 'v2raytun/android'):
                raw, _ = request(address, agent, tls)
                headers = parse_headers(BytesIO(raw.split(b'\r\n', 1)[1]))
                for key, value in OWNER_METADATA.items():
                    assert headers.get_all(key) == [value], (address, agent, key)
    finally:
        upstream.owner_metadata = False


def check_concurrent_alias_requests(upstream, tls):
    with ThreadPoolExecutor(max_workers=21) as workers:
        upstream.hold_requests = True
        requests = []
        try:
            for index in range(21):
                # Real clients have distinct IPs at the alias ingress, while the
                # relay makes all its upstream requests from the server itself.
                source = (f'127.0.0.{10 + index}', 0)
                requests.append(workers.submit(request, ALIAS, INCY_AGENT, tls, source))
                try:
                    upstream.arrivals.get(timeout=4)
                except queue.Empty as exc:
                    raise AssertionError(f'Alias request {index + 1} did not reach upstream') from exc
        finally:
            upstream.release_requests.set()
            upstream.hold_requests = False
        for pending in requests:
            headers, body = pending.result(timeout=8)
            assert METADATA['check_headers'](headers, LABEL, 'incy')
            assert body == body_for(ALIAS)


def wait_for_nginx(process):
    for attempt in range(40):
        try:
            with socket.create_connection((PUBLIC, 2096), timeout=2):
                return
        except ConnectionRefusedError:
            if process.poll() is not None or attempt == 39:
                raise
            time.sleep(0.1)


with tempfile.TemporaryDirectory(prefix='vpn-subscription-proxy-') as directory:
    root = Path(directory)
    cert, key = root / 'cert.pem', root / 'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-subj', '/CN=fixture.example', '-addext', f'subjectAltName=IP:{PUBLIC},IP:{ALIAS}',
                    '-out', str(cert), '-keyout', str(key)], capture_output=True, check=True)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    client_tls = ssl.create_default_context(cafile=str(cert))
    with ThreadingHTTPServer(('127.0.0.1', 2096), Subscription) as upstream:
        upstream.hold_requests = False
        upstream.owner_metadata = False
        upstream.arrivals = queue.Queue()
        upstream.release_requests = threading.Event()
        upstream.socket = tls.wrap_socket(upstream.socket, server_side=True)
        worker = threading.Thread(target=upstream.serve_forever, daemon=True)
        worker.start()
        relay_socket = root / 'feed.sock'
        settings = root / 'proxy.json'
        settings.write_text(json.dumps({'primary': PUBLIC, 'addresses': [PUBLIC, ALIAS]}), encoding='ascii')
        alias_proxy = IP_NETWORK['nginx_aliases']([ALIAS], f'https://{PUBLIC}:2096{SUBSCRIPTION_PATH}')
        alias_proxy = alias_proxy.decode('ascii').replace(IP_NETWORK['SOCKET'], str(relay_socket))
        relay = subprocess.Popen([sys.executable, str(BUNDLE / 'base/ip_feed.py'),
                                  str(relay_socket), str(settings)],
                                 env={**os.environ, 'SSL_CERT_FILE': str(cert)})
        try:
            for attempt in range(40):
                if relay_socket.exists():
                    break
                if relay.poll() is not None or attempt == 39:
                    raise RuntimeError('Subscription relay did not start')
                time.sleep(0.1)
            for provider_id in ('', 'Ab123Cd4'):
                proxy = METADATA['subscription_proxy']({
                    'TARGET_LABEL': LABEL, 'TARGET_IPV4': PUBLIC, 'TARGET_FQDN': 'fixture.example',
                    'TARGET_PUBLIC_SCHEME': 'https', 'TARGET_HAPP_PROVIDER_ID': provider_id,
                    'SUBSCRIPTION_PATH': PATH_PREFIX,
                }) + alias_proxy
                proxy = proxy.replace('/etc/krysyuk-standalone/tls/fullchain.pem', str(cert)).replace(
                    '/etc/krysyuk-standalone/tls/privkey.pem', str(key))
                paths = ('client_body', 'proxy', 'fastcgi', 'uwsgi', 'scgi')
                temp_paths = ''.join(f'{kind}_temp_path {root / kind};\n' for kind in paths)
                config = root / 'nginx.conf'
                config.write_text(f'pid {root / "nginx.pid"};\nerror_log stderr;\n'
                                  'daemon off;\nmaster_process off;\nevents {}\nhttp {\n'
                                  'access_log off;\n'
                                  'limit_conn_zone $binary_remote_addr zone=krysyuk_panel_connections:1m;\n'
                                  + temp_paths + proxy + '}\n', encoding='utf-8')
                command = ['nginx', '-e', 'stderr', '-p', directory, '-c', str(config)]
                subprocess.run([*command, '-t'], check=True)
                with subprocess.Popen(command, stderr=subprocess.PIPE) as nginx:
                    try:
                        wait_for_nginx(nginx)
                        for address in (PUBLIC, ALIAS):
                            check_requests(address, provider_id, client_tls)
                        if provider_id:
                            check_browser_copy_panel(client_tls)
                            check_owner_metadata(upstream, client_tls)
                            check_concurrent_alias_requests(upstream, client_tls)
                    finally:
                        if nginx.poll() is None:
                            nginx.terminate()
                        _, errors = nginx.communicate(timeout=10)
                        if errors:
                            print(errors.decode(errors='replace'), end='')
        finally:
            if relay.poll() is None:
                relay.terminate()
            relay.wait(timeout=5)
            upstream.shutdown()
            worker.join()

print('SUBSCRIPTION_PROXY=PASS')
