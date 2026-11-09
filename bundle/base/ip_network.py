"""Render exact secondary-IP ingress and fetch the published URI feed."""
import base64
import http.client
import json
import re
import ssl
from urllib.parse import urlsplit, urlunsplit


TABLE = "vpn_ip_aliases"
SOCKET = "/run/vpn-ip-feed/feed.sock"


def rebind_url(value, old, new, port):
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or parsed.netloc != f"{old}:{port}" or
            parsed.query or parsed.fragment or not parsed.path.startswith("/")):
        raise ValueError("IP_ACCESS_URL")
    return urlunsplit(parsed._replace(netloc=f"{new}:{port}"))


def nginx_aliases(aliases, sub_url):
    path = urlsplit(sub_url).path
    prefix, _, identifier = path.rpartition("/")
    if (not re.fullmatch(r"/[0-9a-f]{32,128}", prefix) or
            not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", identifier)):
        raise ValueError("IP_SUBSCRIPTION_PATH")
    if not aliases:
        return b"# No secondary subscription addresses.\n"
    listeners = "\n".join(f"    listen {ip}:2096 ssl;" for ip in aliases)
    names = " ".join(aliases)
    return f"""server {{
{listeners}
    server_name {names};
    ssl_certificate /etc/krysyuk-standalone/tls/fullchain.pem;
    ssl_certificate_key /etc/krysyuk-standalone/tls/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    access_log off;
    error_log /dev/null crit;
    server_tokens off;
    location ~ ^{prefix}/[A-Za-z0-9_-]+$ {{
        limit_conn krysyuk_panel_connections 20;
        limit_except GET {{ deny all; }}
        proxy_pass http://unix:{SOCKET};
        proxy_set_header X-VPN-Alias $server_addr;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_connect_timeout 3s;
        proxy_read_timeout 15s;
    }}
    location / {{ return 404; }}
}}
""".encode("ascii")


def nft_rules(primary, aliases, interface, ports):
    rules = []
    if aliases:
        hosts = ", ".join(aliases)
        for protocol in ("tcp", "udp"):
            selected = ", ".join(str(port) for port, proto in sorted(ports) if proto == protocol)
            if selected:
                rules.append(f"ip daddr {{ {hosts} }} fib daddr type local "
                             f"{protocol} dport {{ {selected} }} dnat to {primary}")
    inbound = "\n".join(f"        iifname {json.dumps(interface)} {rule}" for rule in rules)
    local = "\n".join(f"        {rule}" for rule in rules)
    # Destroy and replace only the dedicated table in one netlink transaction.
    return f"""destroy table ip {TABLE}
table ip {TABLE} {{
    chain incoming {{
        type nat hook prerouting priority dstnat - 1; policy accept;
{inbound}
    }}
    chain local {{
        type nat hook output priority dstnat - 1; policy accept;
{local}
    }}
}}
""".encode("ascii")


def fetch_feed(address, path, agent):
    connection = http.client.HTTPSConnection(address, 2096, timeout=10,
                                              context=ssl.create_default_context())
    try:
        connection.request("GET", path, headers={"User-Agent": agent})
        with connection.getresponse() as response:
            body = response.read(1024 * 1024 + 1)
            if response.status != 200 or not 0 < len(body) <= 1024 * 1024:
                raise ValueError("IP_SUBSCRIPTION_FETCH")
            return body, {key.lower(): value for key, value in response.getheaders()}
    finally:
        connection.close()


def uri_lines(body):
    raw = body if b"://" in body else base64.b64decode(body.strip(), validate=True)
    return raw.decode("utf-8").splitlines()
