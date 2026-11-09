"""Serve the managed native subscription for a secondary IPv4."""
import argparse
import base64
import binascii
import http.client
import http.server
import ipaddress
import json
from pathlib import Path
import re
import socketserver
import ssl
from urllib.parse import urlsplit, urlunsplit

from ip_runtime import rewrite_uri


MAX_FEED = 1024 * 1024
SUB_PATH = re.compile(r"/[0-9a-f]{32,128}/[A-Za-z0-9_-]{1,128}")
ROUTING_HEADERS = frozenset({"routing-enable", "routing", "providerid", "per-app-proxy-enable",
                             "per-app-proxy-mode", "per-app-proxy-list"})
HEADERS = frozenset({"subscription-userinfo", "profile-update-interval", "profile-title",
                     "support-url", "profile-web-page-url", "announce", "announce-url", "hide-settings"}) | ROUTING_HEADERS
CLIENT_HEADERS = ("User-Agent", "X-Hwid", "X-Device-Os", "X-Ver-Os", "X-Device-Model")
URI_SCHEMES = {"vless", "vmess", "trojan", "hysteria2", "hy2"}


def rewrite_feed(body, primary, alias):
    if not body or len(body) > MAX_FEED:
        raise ValueError("invalid subscription length")
    encoded = b"://" not in body
    raw = base64.b64decode(body.strip(), validate=True) if encoded else body
    lines = raw.decode("utf-8").splitlines()
    if not lines or len(lines) > 146:
        raise ValueError("invalid subscription count")
    result = []
    for line in lines:
        scheme = urlsplit(line).scheme
        if scheme not in URI_SCHEMES:
            raise ValueError("unsupported managed profile")
        rewritten = rewrite_uri(line, primary, alias, endpoint_only=True)
        if rewritten == line:
            raise ValueError("unexpected managed profile endpoint")
        result.append(rewritten)
    rewritten = ("\n".join(result) + "\n").encode("utf-8")
    return base64.b64encode(rewritten) if encoded else rewritten


def rewrite_header(key, value, primary, alias):
    if key.lower() == "profile-web-page-url":
        parsed = urlsplit(value)
        if parsed.scheme == "https" and parsed.hostname == primary and parsed.port == 2096:
            return urlunsplit(parsed._replace(netloc=f"{alias}:2096"))
    return value


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        # The subscription ID is a credential. Never log the request target.
        pass

    def do_GET(self):
        self.serve_feed()

    def do_HEAD(self):
        self.serve_feed()

    def serve_feed(self):
        if not SUB_PATH.fullmatch(self.path):
            self.send_error(404)
            return
        alias = self.headers.get("X-VPN-Alias", "")
        try:
            settings = json.loads(self.server.settings.read_bytes())
            primary = str(ipaddress.IPv4Address(settings["primary"]))
            if alias == primary or alias not in settings["addresses"]:
                self.send_error(404)
                return
            headers = {key: self.headers[key] for key in CLIENT_HEADERS if key in self.headers}
            connection = http.client.HTTPSConnection(primary, 2096, timeout=10,
                                                      context=ssl.create_default_context())
            try:
                # Use the native URI output and keep client identification for 3x-ui.
                connection.request("GET", self.path, headers=headers)
                with connection.getresponse() as response:
                    if response.status != 200:
                        self.send_error(response.status if response.status in (403, 404, 429) else 502)
                        return
                    body = rewrite_feed(response.read(MAX_FEED + 1), primary, alias)
                    metadata = [(key, rewrite_header(key, value, primary, alias))
                                for key, value in response.getheaders() if key.lower() in HEADERS]
            finally:
                connection.close()
        except (OSError, ValueError, binascii.Error, KeyError, http.client.HTTPException):
            self.send_error(502)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in metadata:
            self.send_header(key, value)
        self.end_headers()
        if self.command == "GET":
            self.wfile.write(body)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("socket")
    parser.add_argument("settings", type=Path)
    args = parser.parse_args()
    Path(args.socket).unlink(missing_ok=True)
    with socketserver.ThreadingUnixStreamServer(args.socket, Handler) as server:
        server.daemon_threads = True
        server.settings = args.settings
        server.serve_forever()


if __name__ == "__main__":
    main()
