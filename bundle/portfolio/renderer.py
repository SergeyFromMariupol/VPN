"""Render a selected, secret-free portfolio recipe into an Xray inbound and URI.

The caller supplies credentials freshly generated on the target.  This module
never writes or logs the rendered result.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import re
from urllib.parse import quote, urlencode


PLACEHOLDER = re.compile(r"<([a-z_]+)>")


def _fill(value, mapping):
    if isinstance(value, str):
        def replace(match):
            key = match.group(1)
            if key not in mapping:
                raise ValueError("MISSING_PORTFOLIO_CREDENTIAL")
            return mapping[key]
        return PLACEHOLDER.sub(replace, value)
    if isinstance(value, list):
        return [_fill(item, mapping) for item in value]
    if isinstance(value, dict):
        return {key: _fill(item, mapping) for key, item in value.items()}
    return value


def render(entry: dict, target: dict, port: int, credentials: dict):
    """Return ``(inbound, share_uri)`` for one accepted nonbaseline row."""
    if entry.get("baseline_reuse") is not False or not isinstance(port, int):
        raise ValueError("PORTFOLIO_RECIPE")
    if not 1024 <= port <= 65535:
        raise ValueError("PORTFOLIO_PORT")
    listen = str(ipaddress.IPv4Address(target["TARGET_IPV4"]))
    endpoint = target["TARGET_FQDN"]
    if target.get("TARGET_ADDRESS_MODE", "domain") == "ip" and endpoint != listen:
        raise ValueError("PORTFOLIO_ENDPOINT")
    if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", endpoint):
        raise ValueError("PORTFOLIO_ENDPOINT")
    sni = target["TARGET_REALITY_SNI"]
    if not re.fullmatch(r"[a-z0-9.-]{1,253}", sni) or "cloudflare" in sni:
        raise ValueError("PORTFOLIO_SNI")
    name = entry["name"]
    if not isinstance(name, str) or not 1 <= len(name) <= 160 or "\n" in name:
        raise ValueError("PORTFOLIO_NAME")
    mapping = {
        "ip": endpoint,
        "sni": sni,
        "port": str(port),
        "remark": name,
        "id": entry["id"],
    }
    for key, value in credentials.items():
        if not re.fullmatch(r"[a-z_]+", key) or not isinstance(value, str) or not value:
            raise ValueError("PORTFOLIO_CREDENTIAL")
        mapping[key] = value
    path = mapping.get("path")
    if path is not None and (not path.startswith("/") or
                             any(char in path for char in "?#\r\n")):
        raise ValueError("PORTFOLIO_PATH")
    service_name = mapping.get("service_name")
    if service_name is not None and not re.fullmatch(r"[A-Za-z0-9._/-]{1,128}", service_name):
        raise ValueError("PORTFOLIO_GRPC")
    settings = _fill(entry["inbound_settings_template"], mapping)
    stream = _fill(entry["stream_settings_template"], mapping)
    params = _fill(entry["uri_params_template"], mapping)
    protocol = entry["protocol"]
    inbound = {
        "listen": listen,
        "port": port,
        "tag": f"PORTFOLIO_{port}",
        "protocol": "hysteria" if protocol == "hysteria2" else protocol,
        "settings": settings,
        "streamSettings": stream,
        "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"],
                     "routeOnly": True},
    }
    if protocol == "vmess":
        raw = json.dumps(params, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
        uri = "vmess://" + base64.b64encode(raw).decode("ascii")
    elif protocol in ("vless", "trojan", "hysteria2"):
        principal = mapping["uuid"] if protocol == "vless" else mapping["password"]
        uri = (entry["uri_scheme"] + "://" + quote(principal, safe="") + "@" +
               endpoint + ":" + str(port) + "?" + urlencode(params) + "#" +
               quote(name, safe=""))
    else:
        raise ValueError("PORTFOLIO_PROTOCOL")
    return inbound, uri
