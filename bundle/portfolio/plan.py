"""Build the selected extra portfolio plane without mutating the host.

The first six (or a selected subset of them) are managed by 3X-UI.  This plan
contains only the accepted extra profiles and one route per profile.
"""

from __future__ import annotations

import copy

from renderer import render


PORT_BASE = 30000
MAX_PORT_OFFSET = 126


def _require(condition, code):
    if not condition:
        raise ValueError(code)


def build(target: dict, main: dict, rows: list[dict], shared_factory,
          profile_factory):
    """Return ``(xray_config, link_manifest, port_networks)``.

    Factories supply fresh target secrets and are intentionally injectable so
    the complete routing shape can be verified offline without real secrets.
    """
    extras = [entry for entry in rows if entry.get("baseline_reuse") is False]
    _require(0 < len(extras) <= 140, "PORTFOLIO_SELECTION")
    _require(len({entry["id"] for entry in extras}) == len(extras),
             "PORTFOLIO_DUPLICATE_ID")
    _require(all(entry["egress"] in ("warp", "direct") and
                 entry["route_selector"] == "user" and
                 isinstance(entry["port_offset"], int) and
                 0 <= entry["port_offset"] <= MAX_PORT_OFFSET
                 for entry in extras), "PORTFOLIO_RECIPE_SHAPE")
    expected = {item["tag"]: item for item in main["outbounds"]}
    _require({"DIRECT", "BLOCK", "WARP_CF"} <= set(expected),
             "PORTFOLIO_BASE_OUTBOUNDS")
    direct = copy.deepcopy(expected["DIRECT"])
    direct_rules = direct.get("settings", {}).get("finalRules", [])
    _require(direct.get("protocol") == "freedom" and
             len(direct_rules) == 2 and
             direct_rules[0].get("action") == "block" and
             {"geoip:private", "::/0"} <= set(direct_rules[0].get("ip", [])) and
             direct_rules[1] == {"action": "allow"} and
             expected["BLOCK"].get("protocol") == "blackhole",
             "PORTFOLIO_DIRECT_GUARD")
    _require(expected["WARP_CF"].get("protocol") == "vless" and
             expected["WARP_CF"].get("settings", {}).get("vnext", [{}])[0].get("address") == "127.0.0.1" and
             expected["WARP_CF"]["settings"]["vnext"][0].get("port") == 24443,
             "PORTFOLIO_WARP_CONNECTOR")
    address = target["TARGET_IPV4"]
    blocked = direct["settings"]["finalRules"][0].setdefault("ip", [])
    if address + "/32" not in blocked:
        blocked.append(address + "/32")
    outbounds = [direct, copy.deepcopy(expected["BLOCK"]),
                 copy.deepcopy(expected["WARP_CF"])]
    groups: dict[int, list[dict]] = {}
    for entry in extras:
        groups.setdefault(entry["port_offset"], []).append(entry)
    _require(len(groups) <= 70, "PORTFOLIO_PORT_COUNT")
    inbounds, links, routes, networks = [], [], [], {}
    emails = set()
    for offset, members in sorted(groups.items()):
        _require(1 <= len(members) <= 2 and
                 len({entry["egress"] for entry in members}) == len(members),
                 "PORTFOLIO_PORT_GROUP")
        port = PORT_BASE + offset
        shared = shared_factory(members[0], offset)
        rendered = [render(entry, target, port,
                           profile_factory(entry, shared)) for entry in members]
        inbound = copy.deepcopy(rendered[0][0])
        key = "clients" if members[0]["protocol"] in ("vless", "hysteria2") else "users"
        for entry, (single, _) in zip(members[1:], rendered[1:]):
            _require(single["protocol"] == inbound["protocol"] and
                     single["streamSettings"] == inbound["streamSettings"] and
                     single["port"] == port and
                     key in inbound["settings"] and
                     {name: value for name, value in single["settings"].items()
                      if name != key} ==
                     {name: value for name, value in inbound["settings"].items()
                      if name != key} and
                     len(single["settings"][key]) == 1,
                     "PORTFOLIO_MERGE")
            inbound["settings"][key].extend(single["settings"][key])
        _require(len(inbound["settings"][key]) == len(members),
                 "PORTFOLIO_CLIENTS")
        inbounds.append(inbound)
        network_set = {entry["network"] for entry in members}
        _require(len(network_set) == 1 and network_set <= {"tcp", "udp"},
                 "PORTFOLIO_NETWORK")
        networks[port] = network_set.pop()
        for entry, (_, uri) in zip(members, rendered):
            user = [user for user in inbound["settings"][key]
                    if user.get("email") ==
                    "portfolio-" + entry["egress"] + "-" + entry["id"]]
            _require(len(user) == 1 and user[0]["email"] not in emails,
                     "PORTFOLIO_USER_ROUTE")
            email = user[0]["email"]
            emails.add(email)
            role = "WARP_CF" if entry["egress"] == "warp" else "DIRECT"
            routes.append({"type": "field", "user": [email],
                           "network": "tcp,udp", "outboundTag": role})
            links.append({"id": entry["id"], "remark": entry["name"],
                          "uri": uri, "port": port, "egress": role})
    _require(len(inbounds) == len(networks) and len(links) == len(extras) and
             len(routes) == len(extras), "PORTFOLIO_PLAN_COUNT")
    dns = copy.deepcopy(main["dns"])
    dns_tags = [server["tag"] for server in dns["servers"] if "tag" in server]
    _require(set(dns_tags) == {"dns_cf", "dns_q9"}, "PORTFOLIO_DNS")
    endpoint = target["TARGET_FQDN"]
    blocked_domains = list(dict.fromkeys(("full:" + address, "full:" + endpoint)))
    rules = [
        {"type": "field", "protocol": ["bittorrent"], "outboundTag": "BLOCK"},
        {"type": "field", "inboundTag": dns_tags, "outboundTag": "DIRECT"},
        {"type": "field", "ip": ["geoip:private", "::/0", address + "/32"],
         "outboundTag": "BLOCK"},
        {"type": "field", "domain": blocked_domains, "outboundTag": "BLOCK"},
        *routes,
        {"type": "field", "network": "tcp,udp", "outboundTag": "BLOCK"},
    ]
    config = {"log": {"loglevel": "none"}, "dns": dns,
              "inbounds": inbounds, "outbounds": outbounds,
              "routing": {"domainStrategy": "AsIs", "rules": rules}}
    manifest = {"version": 1, "target": address, "entries": links}
    return config, manifest, networks
