"""Execute the embedded downloader with real urllib redirect handling.

HTTPS/HTTP transports are in-memory handlers, with no sockets, APT, or system
paths. Only private temporary output files are written. The README bootstrap
also executes against these transports with its final write intercepted.
"""
from contextlib import ExitStack
from email.message import Message
import io
from pathlib import Path
import re
import shlex
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request
import urllib.response

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = 'https://github.com/fixture/archive.tar.gz'
CDN = 'https://codeload.example.invalid/fixture/archive.tar.gz'
HTTP_HOP = 'http://plaintext.example.invalid/archive.tar.gz'
REAL_BUILD_OPENER = urllib.request.build_opener


def embedded_python():
    source = (ROOT / 'install.sh').read_text(encoding='utf-8')
    marker = '"https://github.com/$repository/archive/refs/tags/$release.tar.gz" "$task_stage/source.tar.gz" <<\'PY\'\n'
    begin = source.index(marker) + len(marker)
    return source[begin:source.index('\nPY\n', begin)]


def readme_python():
    readme = (ROOT / 'README.md').read_text(encoding='utf-8')
    command = next(block.strip() for block in re.findall(r'```bash\n(.*?)\n```', readme, re.S)
                   if '/root/vpn-install.sh' in block)
    arguments = shlex.split(command.split(' && ', 1)[0])
    return command, arguments[arguments.index('-c') + 1]


class Clock:
    def __init__(self):
        self.now = 0

    def monotonic(self):
        return self.now


class Body(io.BytesIO):
    def __init__(self, raw, clock, eof_delay=0, total=None):
        super().__init__(raw)
        self.clock, self.eof_delay, self.total = clock, eof_delay, total
        self.reads = 0

    def read1(self, size=-1):
        self.reads += 1
        if self.total is not None:
            count = self.total if size < 0 else min(size, self.total)
            self.total -= count
            result = b'x' * count
        else:
            result = super().read(size)
        if not result:
            self.clock.now += self.eof_delay
        return result


class Transport:
    def __init__(self, routes, clock):
        self.routes, self.clock = routes, clock
        self.calls, self.proxies, self.bodies = [], [], []

    def response(self, request):
        url = request.full_url
        self.calls.append(url)
        if url not in self.routes:
            raise AssertionError('Unexpected mock URL: ' + url)
        route = self.routes[url]
        self.clock.now += route.get('open_delay', 0)
        headers = Message()
        code = route.get('code', 200)
        if 'location' in route:
            headers['Location'] = route['location']
        body = Body(route.get('raw', b''), self.clock, route.get('eof_delay', 0), route.get('total'))
        self.bodies.append(body)
        response = urllib.response.addinfourl(body, headers, url, code)
        response.msg = 'OK' if code == 200 else 'Found'
        return response

    def build_opener(self, *handlers):
        transport = self
        self.proxies.extend(handler.proxies for handler in handlers
                            if isinstance(handler, urllib.request.ProxyHandler))
        class HTTPS(urllib.request.HTTPSHandler):
            def https_open(self, request):
                return transport.response(request)
        class HTTP(urllib.request.HTTPHandler):
            def http_open(self, request):
                return transport.response(request)
        return REAL_BUILD_OPENER(*handlers, HTTPS(), HTTP())


class SourceDownloadFallback(unittest.TestCase):
    def run_embedded(self, routes, expected_error=None):
        clock = Clock()
        transport = Transport(routes, clock)
        with tempfile.TemporaryDirectory(prefix='vpn-source-download-') as temp, ExitStack() as stack:
            output = Path(temp) / 'source.tar.gz'
            stack.enter_context(patch.object(urllib.request, 'build_opener', transport.build_opener))
            stack.enter_context(patch.object(time, 'monotonic', clock.monotonic))
            stack.enter_context(patch.object(sys, 'argv', ['embedded-download', ORIGIN, str(output)]))
            if expected_error:
                with self.assertRaises(expected_error):
                    exec(compile(embedded_python(), 'install.sh:source-download', 'exec'), {})
            else:
                exec(compile(embedded_python(), 'install.sh:source-download', 'exec'), {})
            raw = output.read_bytes() if output.exists() else b''
        return transport, raw

    def test_successful_https_redirect_and_proxy_isolation(self):
        transport, raw = self.run_embedded({ORIGIN: {'code': 302, 'location': CDN},
                                            CDN: {'raw': b'reviewed archive bytes'}})
        self.assertEqual(raw, b'reviewed archive bytes')
        self.assertEqual(transport.calls, [ORIGIN, CDN])
        self.assertIn({}, transport.proxies)

    def test_plaintext_redirect_hop_is_rejected_before_any_http_request(self):
        transport, _ = self.run_embedded({ORIGIN: {'code': 302, 'location': HTTP_HOP},
                                          HTTP_HOP: {'code': 302, 'location': CDN},
                                          CDN: {'raw': b'HTTPS after insecure hop'}},
                                         (ValueError, urllib.error.HTTPError))
        self.assertEqual(transport.calls, [ORIGIN])

    def test_archive_size_limit_is_enforced_before_oversized_write(self):
        transport, raw = self.run_embedded({ORIGIN: {'total': 32 * 1024 * 1024 + 1}}, ValueError)
        self.assertLessEqual(len(raw), 32 * 1024 * 1024)
        self.assertEqual(transport.calls, [ORIGIN])

    def test_expired_deadline_after_open_never_reads_payload(self):
        transport, raw = self.run_embedded({ORIGIN: {'open_delay': 301, 'raw': b'late'}}, TimeoutError)
        self.assertEqual(transport.bodies[0].reads, 0)
        self.assertEqual(raw, b'')

    def test_eof_crossing_deadline_is_not_accepted_as_success(self):
        transport, raw = self.run_embedded({ORIGIN: {'open_delay': 299, 'eof_delay': 2}}, TimeoutError)
        self.assertEqual(transport.bodies[0].reads, 1)
        self.assertEqual(raw, b'')

    def test_readme_bootstrap_has_no_package_installation_before_questionnaire(self):
        command, program = readme_python()
        self.assertTrue(command.startswith('python3 '))
        self.assertNotRegex(command, r'\b(?:apt|apt-get|sudo)\b')
        self.assertIn('urllib.request', program)
        self.assertIn('&& bash /root/vpn-install.sh', command)
        compile(program, 'README.md:bootstrap', 'exec')

    def test_readme_raw_bootstrap_rejects_redirect_without_http_request(self):
        _, program = readme_python()
        raw_url = re.search(r'https://raw[.]githubusercontent[.]com/[^\"\x27]+', program).group()
        clock = Clock()
        transport = Transport({raw_url: {'code': 302, 'location': HTTP_HOP},
                               HTTP_HOP: {'raw': b'must not be written'}}, clock)
        with patch.object(urllib.request, '_opener', None), \
             patch.object(urllib.request, 'build_opener', transport.build_opener), \
             patch.object(urllib.request.HTTPRedirectHandler, 'max_redirections',
                          urllib.request.HTTPRedirectHandler.max_redirections), \
             patch.object(urllib.request.HTTPRedirectHandler, 'redirect_request',
                          urllib.request.HTTPRedirectHandler.redirect_request), \
             patch.object(Path, 'write_bytes') as write:
            with self.assertRaises((ValueError, urllib.error.HTTPError)):
                exec(compile(program, 'README.md:bootstrap', 'exec'), {})
            write.assert_not_called()
        self.assertEqual(transport.calls, [raw_url])

    def test_readme_raw_bootstrap_200_writes_exact_bytes_to_expected_mock_path(self):
        _, program = readme_python()
        raw_url = re.search(r'https://raw[.]githubusercontent[.]com/[^\"\x27]+', program).group()
        payload = b'#!/usr/bin/env bash\nprintf "reviewed installer"\n'
        transport = Transport({raw_url: {'raw': payload}}, Clock())
        with patch.object(urllib.request, '_opener', None), \
             patch.object(urllib.request, 'build_opener', transport.build_opener), \
             patch.object(urllib.request.HTTPRedirectHandler, 'max_redirections',
                          urllib.request.HTTPRedirectHandler.max_redirections), \
             patch.object(urllib.request.HTTPRedirectHandler, 'redirect_request',
                          urllib.request.HTTPRedirectHandler.redirect_request), \
             patch.object(Path, 'write_bytes', autospec=True) as write:
            exec(compile(program, 'README.md:bootstrap', 'exec'), {})
            write.assert_called_once()
            destination, written = write.call_args.args
            self.assertEqual(destination.as_posix(), '/root/vpn-install.sh')
            self.assertEqual(written, payload)
        self.assertEqual(transport.calls, [raw_url])


if __name__ == '__main__':
    unittest.main()
