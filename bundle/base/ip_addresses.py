#!/usr/bin/env python3
"""Discover the local IPv4 endpoints for an IP-mode VPN installation."""

import argparse
import ipaddress
import json
import re
import subprocess
import sys


def public_ipv4(value):
    if not isinstance(value, str):
        raise ValueError("invalid IPv4 address")
    address = ipaddress.IPv4Address(value)
    if not address.is_global or address.is_multicast or address.is_reserved:
        raise ValueError("address is not public unicast IPv4")
    return str(address)


def assigned_addresses(records):
    addresses = {}
    for interface in records:
        flags = interface.get("flags", [])
        if ("UP" not in flags or "LOOPBACK" in flags or
                interface.get("operstate") in {"DOWN", "LOWERLAYERDOWN", "NOTPRESENT", "DORMANT"}):
            continue
        name = interface["ifname"]
        if not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,15}", name):
            raise ValueError("unsupported interface name")
        for entry in interface.get("addr_info", []):
            if entry.get("family") != "inet" or entry.get("scope") != "global":
                continue
            if any(entry.get(flag) for flag in ("tentative", "dadfailed", "deprecated")):
                continue
            if entry.get("valid_life_time") == 0 or entry.get("preferred_life_time") == 0:
                continue
            try:
                address = public_ipv4(entry.get("local"))
            except ValueError:
                continue
            if addresses.setdefault(address, name) != name:
                raise ValueError("public IPv4 is assigned on multiple interfaces")
    return addresses


def plan(addresses, previous_primary, routes):
    if not addresses:
        raise ValueError("no active local public IPv4")
    primary = previous_primary
    if primary not in addresses:
        if len(routes) != 1:
            raise ValueError("no unambiguous public IPv4 route source")
        route = routes[0]
        primary = route.get("prefsrc", route.get("src"))
        if (primary not in addresses or addresses[primary] != route.get("dev")
                or route.get("type", "unicast") != "unicast"):
            raise ValueError("route does not use a local public IPv4 source")
    return {
        "primary": primary,
        "interface": addresses[primary],
        "addresses": sorted(addresses, key=ipaddress.IPv4Address),
        "interfaces": addresses,
    }


def ip_json(*args):
    return json.loads(subprocess.check_output(
        ["ip", "-j", "-4", *args], timeout=10, stderr=subprocess.DEVNULL,
    ))


def discover(previous=None):
    previous = public_ipv4(previous) if previous is not None else None
    addresses = assigned_addresses(ip_json("address", "show"))
    routes = ip_json("route", "get", "1.1.1.1") if previous not in addresses else []
    return plan(addresses, previous, routes)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--primary", help="Keep this IPv4 primary while it is assigned")
    args = parser.parse_args()
    try:
        print(json.dumps(discover(args.primary), sort_keys=True))
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError):
        print("VPN_ERROR_CODE=IP_ADDRESS_DISCOVERY", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
