"""Listening-socket inspection using `ss` (read only, on demand)."""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
from dataclasses import dataclass

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


@dataclass
class ListeningSocket:
    protocol: str  # "tcp" | "udp"
    address: str
    port: int
    scope: str  # "todas" | "local" | "interfaz"
    process: str | None


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
    if base == "::1" or base.startswith("127."):
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
    for part in parts[local_index + 2:]:
        if part.startswith("users:"):
            name = part.split('"')
            process = name[1] if len(name) > 1 else None
            break
    return ListeningSocket(
        protocol=parts[0],
        address=address,
        port=port,
        scope=classify_address(address),
        process=process,
    )


def listening_sockets() -> tuple[list[ListeningSocket], str | None]:
    """Return (sockets, error). The error message is in Spanish when `ss` fails."""
    if not shutil.which("ss"):
        return [], "El comando `ss` no está disponible en este sistema."
    command = ["ss", "-tulnpH"] if os.geteuid() == 0 else ["ss", "-tulnH"]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=SS_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [], f"No se pudo inspeccionar los puertos ({type(exc).__name__})."
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
