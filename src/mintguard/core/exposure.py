"""Listening-socket inspection using `ss` (read only, on demand)."""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
from dataclasses import dataclass

from mintguard.core.commands import run_command

SS_TIMEOUT_SECONDS = 15

RISKY_PORTS = {
    21: "FTP",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    111: "RPCbind",
    139: "NetBIOS",
    445: "SMB",
    2049: "NFS",
    3306: "MySQL/MariaDB",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    27017: "MongoDB",
}

ANY_ADDRESSES = {"0.0.0.0", "::", "*", ""}

# `ss -p` process field: users:(("sshd",pid=900,fd=3))
_USERS_RE = re.compile(r'users:\(\("([^"]*)",pid=(\d+)')


@dataclass
class ListeningSocket:
    protocol: str  # "tcp" | "udp"
    address: str
    port: int
    scope: str  # "todas" | "local" | "interfaz"
    process: str | None
    pid: int | None = None  # from ss -p; lets us verify the real binary


def classify_address(address: str) -> str:
    """Classify a listening address as "todas" (any), "local" or "interfaz".

    - The whole 127.0.0.0/8 loopback range counts as local, not just
      127.0.0.1: services like systemd-resolved listen on 127.0.0.53 and
      must never be reported as network-exposed.
    - A `%zone` suffix means the socket is bound to that device. A
      wildcard bound to one device (`0.0.0.0%virbr0`, e.g. dnsmasq for
      libvirt) only serves that interface: it is NOT "todas".
    """
    base, separator, _zone = address.partition("%")
    if separator and base in ANY_ADDRESSES:
        return "interfaz"
    if base in ANY_ADDRESSES:
        return "todas"
    if base == "::1" or base.startswith("127.") or base.startswith("::ffff:127."):
        # "::ffff:127.x" is the v4-mapped loopback some dual-stack
        # sockets bind: same localhost, not an exposed interface.
        return "local"
    return "interfaz"


def parse_ss_line(line: str) -> ListeningSocket | None:
    """Parse one `ss -tulnH` line (no header) into a ListeningSocket.

    Modern iproute2 emits: Netid State Recv-Q Send-Q Local:Port Peer:Port
    [Process], so the local address is at index 4. Old versions omitted
    the State column (Local at index 3); both formats are handled and
    covered by tests.
    """
    parts = line.split()
    if len(parts) < 4:
        return None
    if parts[1] in ("LISTEN", "UNCONN", "ESTAB"):
        local_index = 4
    else:
        local_index = 3
    if local_index >= len(parts):
        return None
    local = parts[local_index]
    if ":" not in local:
        return None
    address_text, _, port_text = local.rpartition(":")
    try:
        port = int(port_text)
    except ValueError:
        return None
    address = address_text.strip("[]")
    if address_text.startswith("[") and "]" in address_text:
        # IPv6 with optional zone: `[fd7a::1%tailscale0]` -> `fd7a::1%tailscale0`
        host, _, zone = address_text[1:].partition("]")
        address = f"{host}{zone}"
    process = None
    pid = None
    # The process field is read from the joined tail: a comm may contain
    # spaces ("my prog"), which would split it into two fields.
    match = _USERS_RE.search(" ".join(parts[local_index + 2:]))
    if match:
        process = match.group(1)
        pid = int(match.group(2))
    return ListeningSocket(
        protocol=parts[0],
        address=address,
        port=port,
        scope=classify_address(address),
        process=process,
        pid=pid,
    )


def listening_sockets() -> tuple[list[ListeningSocket], str | None]:
    """Return (sockets, error). The error message is in Spanish when `ss` fails."""
    ss_path = shutil.which("ss")
    if ss_path is None:
        return [], "El comando `ss` no está disponible en este sistema."
    # Absolute path: when MintGuard runs under sudo, PATH lookup would
    # resolve `ss` in the inherited (user) PATH — a hostile binary in
    # ~/.local/bin would execute as root.
    command = [ss_path, "-tulnpH"] if os.geteuid() == 0 else [ss_path, "-tulnH"]
    result = run_command(command, SS_TIMEOUT_SECONDS)
    if result is None:
        return [], "No se pudo inspeccionar los puertos en este sistema."
    if result.returncode != 0 and not result.stdout.strip():
        # rc != 0 with no data means the inspection failed: reporting
        # "no ports listening" here would be a silent false negative.
        return [], "No se pudo inspeccionar los puertos (ss terminó con error)."
    sockets = [parsed for line in result.stdout.splitlines() if (parsed := parse_ss_line(line))]
    return sockets, None


def service_name(port: int, protocol: str) -> str:
    well_known = RISKY_PORTS.get(port, "")
    if well_known:
        return well_known
    proto = "udp" if protocol.lower().startswith("u") else "tcp"
    try:
        return socket.getservbyport(port, proto).upper()
    except OSError:
        return ""


# --- nature of the interface a socket is bound to (paso 5) -------------------

VIRTUAL_ZONE_PREFIXES = ("virbr", "docker", "br-")

# "Worst" = most exposed, for a group that mixes binds. unknown outranks
# public on purpose: a wildcard (0.0.0.0/::) exposes via every interface,
# including any public one, so it must never be softened by a mixed group.
_NATURE_RANK = {
    "unknown": 5,
    "public": 4,
    "lan": 3,
    "cgnat": 2,
    "link-local": 1,
    "virtual": 0,
}


def interface_nature(zone: str, ip: str) -> str:
    """public | lan | cgnat | loopback | link-local | virtual | unknown.

    From a bind we only have its device (zone) and/or a concrete IP:
    - a virtual bridge zone (virbr*/docker*/br-*) is "virtual" even with
      a wildcard IP: it serves VMs/containers, not the real LAN;
    - 100.64.0.0/10 is "cgnat" (mesh/overlay, e.g. Tailscale), checked
      BEFORE the RFC1918/ULA "lan" bucket;
    - a plain wildcard has neither zone nor concrete IP: "unknown" —
      judging it needs the machine's other addresses (v1.1).
    """
    zone = (zone or "").lower()
    if zone.startswith(VIRTUAL_ZONE_PREFIXES):
        return "virtual"
    ip = (ip or "").strip("[]")
    if not ip or ip in ANY_ADDRESSES:
        return "unknown"
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if addr.version == 6 and addr.ipv4_mapped is not None:
        # ::ffff:127.0.0.1 is loopback; ::ffff:8.8.8.8 is public. Python's
        # is_loopback is False for the mapped form and is_private lumps it
        # with the ULA range, so the real v4 address decides.
        addr = addr.ipv4_mapped
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if addr.version == 4 and addr in ipaddress.ip_network("100.64.0.0/10"):
        return "cgnat"
    if addr.is_private:  # RFC1918 + IPv6 ULA (fc00::/7)
        return "lan"
    return "public"


def socket_nature(address: str) -> str:
    """interface_nature for one parsed ss address (`ip` and optional `%zone`)."""
    base, _, zone = address.partition("%")
    return interface_nature(zone, base)


def worst_nature(natures: list[str]) -> str:
    """The most exposed nature of a group (conservative on mixing)."""
    return max(natures, key=lambda n: _NATURE_RANK.get(n, 5))
