"""Exercise the public TLS proxy with a loopback subscription fixture."""
from http.client import HTTPSConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import runpy
import socket
import ssl
import subprocess
import tempfile
import threading
import time


BUNDLE = Path(__file__).resolve().parents[1]
METADATA = runpy.run_path(str(BUNDLE / 'scripts/happ_routing.py'))
PUBLIC = '127.0.0.2'
PATH_PREFIX = 'a' * 40
BODY = b'vless://fixture@127.0.0.2:443#fixture\n'
LABEL = 'Тест 🇩🇪 «Профиль»'


class Subscription(BaseHTTPRequestHandler):
    def do_GET(self):
        assert self.headers['Host'] == 'fixture.example:2096'
        assert self.headers['X-Forwarded-Proto'] == 'https'
        assert self.path == f'/{PATH_PREFIX}/fixture'
        self.send_response(200)
        self.send_header('Routing', METADATA['routing_link'](LABEL))
        self.send_header('Routing-Enable', 'true')
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *_args):
        pass


with tempfile.TemporaryDirectory(prefix='vpn-subscription-proxy-') as directory:
    root = Path(directory)
    cert, key = root / 'cert.pem', root / 'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-subj', '/CN=fixture.example', '-addext', f'subjectAltName=IP:{PUBLIC}',
                    '-out', str(cert), '-keyout', str(key)], capture_output=True, check=True)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    client_tls = ssl.create_default_context(cafile=str(cert))
    with ThreadingHTTPServer(('127.0.0.1', 2096), Subscription) as upstream:
        upstream.socket = tls.wrap_socket(upstream.socket, server_side=True)
        worker = threading.Thread(target=upstream.serve_forever, daemon=True)
        worker.start()
        try:
            for provider_id in ('', 'Ab123Cd4'):
                proxy = METADATA['subscription_proxy']({
                    'TARGET_LABEL': LABEL, 'TARGET_IPV4': PUBLIC, 'TARGET_FQDN': 'fixture.example',
                    'TARGET_PUBLIC_SCHEME': 'https', 'TARGET_HAPP_PROVIDER_ID': provider_id,
                    'SUBSCRIPTION_PATH': PATH_PREFIX,
                }).replace('/etc/krysyuk-standalone/tls/fullchain.pem', str(cert)).replace(
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
                        for attempt in range(40):
                            try:
                                with socket.create_connection((PUBLIC, 2096), timeout=2):
                                    pass
                                break
                            except ConnectionRefusedError:
                                if nginx.poll() is not None or attempt == 39:
                                    raise
                                time.sleep(0.1)
                        agents = {'happ': 'Happ/4.10.1/android', 'incy': 'INCY/1.0/Android',
                                  'v2raytun': 'v2raytun/android', 'karing': 'Karing',
                                  'desktop': 'INCY/1.0/windows'}
                        for client, agent in agents.items():
                            conn = HTTPSConnection(PUBLIC, 2096, timeout=3, context=client_tls)
                            try:
                                conn.request('GET', f'/{PATH_PREFIX}/fixture', headers={'User-Agent': agent})
                                with conn.getresponse() as response:
                                    assert response.status == 200 and response.read() == BODY
                                    fields = ''.join(f'{name}: {value}\r\n' for name, value in response.getheaders())
                                    raw = f'HTTP/1.1 200 OK\r\n{fields}\r\n'.encode('ascii')
                                    assert METADATA['check_headers'](raw, LABEL, client, provider_id), client
                            finally:
                                conn.close()
                    finally:
                        if nginx.poll() is None:
                            nginx.terminate()
                        _, errors = nginx.communicate(timeout=10)
                        if errors:
                            print(errors.decode(errors='replace'), end='')
        finally:
            upstream.shutdown()
            worker.join()

print('SUBSCRIPTION_PROXY=PASS')
