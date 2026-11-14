"""Listeners that are expected in their context, not new exposure.

"Exposición real" is more than the bind address: tailscale's own ports,
libvirt's virtual bridge and avahi's ephemeral sockets are how those
systems are designed to work. classify() tags them so the network check
can downgrade (INFO) or fold them (avahi → mDNS finding) instead of
crying ALTA at normal operation — otherwise the user learns that ALTA
means "normal things on my system" and ignores a real ALTA later.

Rules were set by the usage review (2026-11-14), in impact order:

- tailscaled on its own interface/overlay (`%tailscale*`, 100.64.0.0/10)
  → INFO: mesh traffic, not LAN/internet exposure.
- UDP 41641 on any address → INFO: Tailscale's DISCO (handshake) port,
  it must listen on 0.0.0.0 for NAT traversal, by design.
- dnsmasq on 192.168.122.0/24 or a virtual bridge (`%virbr*`, `%docker*`)
  → INFO: DHCP/DNS for VMs/containers; unreachable from the real LAN.
- avahi-daemon on an ephemeral UDP port (≥32768) → folded into the
  mDNS/LLMNR finding: same service announcing itself, no new exposure.

Adding a context (snap, KVM, podman…) is one more if in classify(), not
a refactor of the network check. Severity for tagged groups is decided
in checks/network.py; this module only recognizes contexts.
"""

from __future__ import annotations

import ipaddress

TAILSCALE_NETWORK = ipaddress.ip_network("100.64.0.0/10")
LIBVIRT_NETWORK = ipaddress.ip_network("192.168.122.0/24")
TAILSCALE_DISCO_PORT = 41641
# Linux default ephemeral range floor (net.ipv4.ip_local_port_range):
# avahi answers mDNS from random high UDP ports, which show up in ss.
EPHEMERAL_PORT_MIN = 32768

_TAILSCALE_ZONE_PREFIX = "tailscale"
_VIRTUAL_ZONE_PREFIXES = ("virbr", "docker", "br-")


def _ip_in(address: str, network: ipaddress.IPv4Network) -> bool:
    try:
        return ipaddress.ip_address(address) in network
    except ValueError:
        return False


def classify(
    process_name: str | None, address: str, port: int, protocol: str
) -> str | None:
    """Context tag for a listener that is expected where it listens.

    Returns "tailscale", "libvirt" or "avahi"; None means the socket is
    not recognized as expected and keeps the normal exposure severity.
    `address` is the bind address as parsed from ss, zone included
    ("100.99.183.4%tailscale0", "0.0.0.0%virbr0", "192.168.122.1").
    """
    process = (process_name or "").lower()
    protocol = protocol.lower()
    if protocol.startswith("u"):
        protocol = "udp"
    elif protocol.startswith("t"):
        protocol = "tcp"
    base, _, zone = address.partition("%")

    # Tailscale: its own daemon on its interface/overlay. The process
    # name is the signal — another service bound to tailscale0 (e.g.
    # sshd) keeps its normal severity, on purpose.
    if process == "tailscaled" and (
        zone.startswith(_TAILSCALE_ZONE_PREFIX) or _ip_in(base, TAILSCALE_NETWORK)
    ):
        return "tailscale"
    # The DISCO port is expected on ANY address (even 0.0.0.0): NAT
    # traversal requires it. Port-keyed so it also covers a custom
    # tailscaled port is NOT handled — the process rule does that.
    if protocol == "udp" and port == TAILSCALE_DISCO_PORT:
        return "tailscale"
    # libvirt's dnsmasq serves only the virtual bridge.
    if process == "dnsmasq" and (
        zone.startswith(_VIRTUAL_ZONE_PREFIXES) or _ip_in(base, LIBVIRT_NETWORK)
    ):
        return "libvirt"
    # avahi's ephemeral sockets: the mDNS service itself, not a new one.
    if process == "avahi-daemon" and protocol == "udp" and port >= EPHEMERAL_PORT_MIN:
        return "avahi"
    return None
