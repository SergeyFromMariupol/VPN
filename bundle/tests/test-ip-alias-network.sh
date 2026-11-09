#!/usr/bin/env bash
# Exercise the generated TCP and UDP DNAT in an isolated network namespace.
set -Eeuo pipefail
[[ $EUID == 0 ]] || exit 1
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
parent=$(readlink /proc/self/ns/net)
unshare --net bash -Eeuo pipefail -s -- "$root" "$parent" <<'ISOLATED'
[[ $(readlink /proc/self/ns/net) != "$2" ]] || exit 1
ip link set lo up
ip addr add 192.0.2.10/32 dev lo
ip addr add 192.0.2.11/32 dev lo
python3 -B - "$1/base" <<'PY'
from concurrent.futures import ThreadPoolExecutor
import socket
import subprocess
import sys

sys.path.insert(0, sys.argv[1])
from ip_network import nft_rules

primary = "192.0.2.10"
alias = "192.0.2.11"
port = 18443
config = nft_rules(primary, [alias], "lo", {(port, "tcp"), (port, "udp")})
subprocess.run(["nft", "-c", "-f", "-"], input=config, check=True)
subprocess.run(["nft", "-f", "-"], input=config, check=True)
subprocess.run(["nft", "-f", "-"], input=config, check=True)


def tcp_echo(listener):
    connection, _ = listener.accept()
    with connection:
        connection.settimeout(3)
        connection.sendall(connection.recv(32))


def udp_echo(listener):
    data, address = listener.recvfrom(32)
    listener.sendto(data, address)


with (socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp,
      socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp,
      ThreadPoolExecutor(2) as pool):
    for listener in (tcp, udp):
        listener.settimeout(3)
        listener.bind((primary, port))
    tcp.listen()
    tcp_worker = pool.submit(tcp_echo, tcp)
    udp_worker = pool.submit(udp_echo, udp)
    with socket.create_connection((alias, port), timeout=3) as client:
        client.sendall(b"tcp-alias")
        assert client.recv(32) == b"tcp-alias"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(3)
        client.connect((alias, port))
        client.send(b"udp-alias")
        assert client.recvfrom(32) == (b"udp-alias", (alias, port))
    tcp_worker.result()
    udp_worker.result()

print("IP_ALIAS_TCP_UDP_DNAT=PASS")
PY
ISOLATED
