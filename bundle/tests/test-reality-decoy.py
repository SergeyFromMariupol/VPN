"""Loopback-only integration: scanners see our site; authenticated gRPC works.

Uses the production Nginx renderer and the installer's digest-pinned Xray.
The disposable CA, keys and client configurations never leave the fixture.
"""
from contextlib import closing
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import uuid


ROOT = (Path(os.environ['VPN_TEST_SOURCE_ROOT']) if 'VPN_TEST_SOURCE_ROOT' in os.environ
        else Path(__file__).resolve().parents[2])
SPEC = importlib.util.spec_from_file_location('decoy_renderer', ROOT / 'bundle/base/reality-decoy.py')
DECOY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DECOY)
XRAY_DIGEST = 'a27e3f95ab6ce270956d0cecd32eda4686a811afc71c64a6a734a3dede14883e'


def port():
    with closing(socket.socket()) as stream:
        stream.bind(('127.0.0.1', 0))
        return stream.getsockname()[1]


def run(*args):
    return subprocess.check_output(args, stderr=subprocess.DEVNULL, timeout=30)


def wait_listener(number, process):
    for _ in range(100):
        if process.poll() is not None:
            raise AssertionError('Fixture process stopped')
        try:
            with socket.create_connection(('127.0.0.1', number), timeout=.2):
                return
        except OSError:
            time.sleep(.05)
    raise AssertionError('Fixture listener did not start')


def read_exact(stream, size):
    result = bytearray()
    while len(result) < size:
        part = stream.recv(size - len(result))
        if not part:
            raise AssertionError('Unexpected fixture EOF')
        result.extend(part)
    return bytes(result)


class Origin(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        body = b'authenticated-reality-grpc-payload\n'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def scanner(number, hostname, certificate, expected, path='/', expect_page=True):
    context = ssl.create_default_context(cafile=str(certificate))
    context.check_hostname = False
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(['http/1.1'])
    with socket.create_connection(('127.0.0.1', number), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=hostname) as stream:
            assert stream.getpeercert(binary_form=True) == expected, 'Scanner received an unexpected certificate'
            assert stream.version() == 'TLSv1.3'
            stream.sendall(('GET ' + path + ' HTTP/1.1\r\nHost: any.invalid\r\nConnection: close\r\n\r\n').encode('ascii'))
            result = bytearray()
            while len(result) < 1024 * 1024:
                data = stream.recv(min(4096, 1024 * 1024 - len(result)))
                if not data:
                    break
                result.extend(data)
            if expect_page:
                assert result.startswith(b'HTTP/1.1 200 ')
                _, separator, body = bytes(result).partition(b'\r\n\r\n')
                assert separator and body == DECOY.BODY.encode('utf-8'), 'Scanner did not receive the bundled default site'
            else:
                assert result.startswith(b'HTTP/1.1 404 ')
                assert b'PRIVATE_PHP_SOURCE' not in result


def payload(socks_port, origin_port):
    with socket.create_connection(('127.0.0.1', socks_port), timeout=10) as stream:
        stream.sendall(b'\x05\x01\x00')
        assert read_exact(stream, 2) == b'\x05\x00'
        stream.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01' + origin_port.to_bytes(2, 'big'))
        header = read_exact(stream, 4)
        assert header[:2] == b'\x05\x00', 'SOCKS tunnel rejected'
        size = {1: 4, 4: 16}.get(header[3])
        if header[3] == 3:
            size = read_exact(stream, 1)[0]
        assert size is not None
        read_exact(stream, size + 2)
        stream.sendall(b'GET / HTTP/1.1\r\nHost: fixture.invalid\r\nConnection: close\r\n\r\n')
        response = bytearray()
        while True:
            data = stream.recv(4096)
            if not data:
                break
            response.extend(data)
            if b'authenticated-reality-grpc-payload\n' in response:
                break
        assert response.startswith(b'HTTP/1.0 200 ') or response.startswith(b'HTTP/1.1 200 ')
        assert b'authenticated-reality-grpc-payload\n' in response


def main():
    binary = Path(os.environ['VPN_TEST_XRAY_BIN']).resolve()
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == XRAY_DIGEST
    assert b'26.10.21' in run(str(binary), 'version')
    with tempfile.TemporaryDirectory(prefix='vpn-reality-decoy.') as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        processes = []
        logs = []
        origin = ThreadingHTTPServer(('127.0.0.1', 0), Origin)
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        try:
            certroot = root / 'live'
            lineage = certroot / 'own.example.invalid'
            lineage.mkdir(parents=True)
            # Disposable locally trusted certificate, including an IP SAN.
            run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
                '-subj', '/CN=own.example.invalid', '-addext',
                'subjectAltName=DNS:own.example.invalid,IP:127.0.0.1',
                '-keyout', str(lineage / 'privkey.pem'), '-out', str(lineage / 'fullchain.pem'))
            certificate = lineage / 'fullchain.pem'
            expected = ssl.PEM_cert_to_DER_cert(certificate.read_text())
            target_port = port()
            document_root = root / 'site'
            document_root.mkdir()
            (document_root / 'index.html').write_text(DECOY.BODY, encoding='utf-8')
            (document_root / 'secret.php').write_text('<?php echo "PRIVATE_PHP_SOURCE";')
            env = dict(TARGET_REALITY_MODE='decoy', TARGET_TLS_MODE='letsencrypt',
                       TARGET_ADDRESS_MODE='domain', TARGET_FQDN='own.example.invalid',
                       TARGET_REALITY_SNI='max.ru', TARGET_IPV4='127.0.0.1')
            target = DECOY.render(env, certificate_root=certroot, port=target_port,
                                  document_root=document_root)
            nginx = root / 'nginx.conf'
            fixture_user = 'user root;\n' if os.geteuid() == 0 else ''
            nginx.write_text(fixture_user + f'pid {root}/nginx.pid;\nerror_log {root}/nginx.log;\nevents {{}}\n'
                             f'http {{ access_log off; client_body_temp_path {root}/body;\n'
                             f'proxy_temp_path {root}/proxy; fastcgi_temp_path {root}/fastcgi;\n'
                             f'uwsgi_temp_path {root}/uwsgi; scgi_temp_path {root}/scgi;\n{target}\n}}\n')

            def start(command, number):
                log = open(root / f'process-{len(processes)}.log', 'wb')
                logs.append(log)
                child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
                processes.append(child)
                wait_listener(number, child)
                return child

            run('nginx', '-t', '-p', str(root), '-c', str(nginx))
            start(['nginx', '-p', str(root), '-c', str(nginx), '-g', 'daemon off;'], target_port)
            pair = run(str(binary), 'x25519').decode()
            private = re.search(r'PrivateKey:\s*(\S+)', pair)[1]
            public = re.search(r'^(?:Public(?:\s+key|Key)|Password(?: \(PublicKey\))?):\s*([A-Za-z0-9_-]{43})\s*$', pair, re.M)[1]
            identity = str(uuid.uuid4())
            short_id = os.urandom(8).hex()
            # Test both ordinary self-steal and the intentionally different SNI.
            for client_sni in ('own.example.invalid', 'max.ru'):
                public_port, socks_port = port(), port()
                server = {'log': {'loglevel': 'error'}, 'inbounds': [{
                    'listen': '127.0.0.1', 'port': public_port, 'protocol': 'vless',
                    'settings': {'clients': [{'id': identity}], 'decryption': 'none'},
                    'streamSettings': {'network': 'grpc', 'security': 'reality',
                        'grpcSettings': {'serviceName': 'fixture-grpc'}, 'realitySettings': {
                            'target': f'127.0.0.1:{target_port}', 'serverNames': [client_sni],
                            'privateKey': private, 'shortIds': [short_id], 'xver': 0}}}],
                    # The pinned Freedom outbound blocks private targets by
                    # default. Allow only this disposable loopback HTTP origin;
                    # keep every other destination blocked in the fixture.
                    'outbounds': [{'protocol': 'freedom', 'settings': {'finalRules': [
                        {'action': 'allow', 'network': 'tcp', 'ip': ['127.0.0.1/32'],
                         'port': origin.server_port},
                        {'action': 'block'}]}}]}
                client = {'log': {'loglevel': 'error'}, 'inbounds': [{
                    'listen': '127.0.0.1', 'port': socks_port, 'protocol': 'socks',
                    'settings': {'auth': 'noauth'}}], 'outbounds': [{
                    'protocol': 'vless', 'settings': {'vnext': [{'address': '127.0.0.1',
                        'port': public_port, 'users': [{'id': identity, 'encryption': 'none'}]}]},
                    'streamSettings': {'network': 'grpc', 'security': 'reality',
                        'grpcSettings': {'serviceName': 'fixture-grpc'}, 'realitySettings': {
                            'serverName': client_sni, 'fingerprint': 'chrome',
                            'publicKey': public, 'shortId': short_id}}}]}
                server_path, client_path = root / 'server.json', root / 'client.json'
                server_path.write_text(json.dumps(server))
                client_path.write_text(json.dumps(client))
                for path in (server_path, client_path):
                    run(str(binary), 'run', '-test', '-config', str(path))
                server_process = start([str(binary), 'run', '-config', str(server_path)], public_port)
                for name in (None, 'own.example.invalid', 'max.ru', 'unknown.example.invalid'):
                    scanner(public_port, name, certificate, expected)
                scanner(public_port, client_sni, certificate, expected,
                        '/secret.php', expect_page=False)
                client_process = start([str(binary), 'run', '-config', str(client_path)], socks_port)
                payload(socks_port, origin.server_port)
                print('REALITY_AUTH_SNI=' + client_sni + ' GRPC_PAYLOAD=PASS SCANNER_OWN_CERT=PASS', flush=True)
                client_process.terminate()
                client_process.wait(timeout=10)
                server_process.terminate()
                server_process.wait(timeout=10)
            print('REALITY_DECOY_GRPC=PASS SCANNER_OWN_CERT=PASS NO_SNI=PASS')
        finally:
            for child in reversed(processes):
                if child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=5)
            origin.shutdown()
            origin.server_close()
            for log in logs:
                log.close()


if __name__ == '__main__':
    main()
