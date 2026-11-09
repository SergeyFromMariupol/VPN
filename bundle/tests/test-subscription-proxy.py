"""Exercise the public TLS proxy with a loopback subscription fixture."""
from base64 import b64encode
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPSConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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


def body_for(address):
    return b64encode(f'vless://fixture@{address}:443#fixture\n'.encode('ascii'))


class Subscription(BaseHTTPRequestHandler):
    def do_GET(self):
        assert self.headers['Host'] == 'fixture.example:2096'
        assert self.headers['X-Forwarded-Proto'] == 'https'
        assert self.path == SUBSCRIPTION_PATH
        if self.server.hold_requests and self.headers['User-Agent'] == INCY_AGENT:
            self.server.arrivals.put(None)
            assert self.server.release_requests.wait(15)
        self.send_response(200)
        # 3X-UI 3.11 suppresses native Happ routing headers for INCY.
        if not self.headers.get('User-Agent', '').lower().startswith('incy/'):
            self.send_header('Routing', METADATA['routing_link'](LABEL))
            self.send_header('Routing-Enable', 'true')
        self.end_headers()
        self.wfile.write(body_for(PUBLIC))

    def log_message(self, *_args):
        pass


def request(address, agent, tls, source=None):
    conn = HTTPSConnection(address, 2096, timeout=12, context=tls, source_address=source)
    try:
        conn.request('GET', SUBSCRIPTION_PATH, headers={'User-Agent': agent})
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
        assert body == body_for(address), (address, agent)


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
                                  + temp_paths + proxy + '}\n', encoding='ascii')
                command = ['nginx', '-e', 'stderr', '-p', directory, '-c', str(config)]
                subprocess.run([*command, '-t'], check=True)
                with subprocess.Popen(command, stderr=subprocess.PIPE) as nginx:
                    try:
                        wait_for_nginx(nginx)
                        for address in (PUBLIC, ALIAS):
                            check_requests(address, provider_id, client_tls)
                        if provider_id:
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
