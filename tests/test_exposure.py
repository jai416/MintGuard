"""Regression tests for the `ss` parser and exposure classification.

These exist because the original parser read the wrong column on modern
iproute2 (which includes the State column) and reported "no listening
ports" on a machine that actually had several: a silent false negative
in a security tool.
"""

import unittest

from mintguard.core.exposure import (
    parse_ss_line,
    classify_address,
    service_name,
)

# Modern iproute2 (State column present, local address at index 4).
MODERN_TCP = (
    'tcp   LISTEN 0      4096        0.0.0.0:22            0.0.0.0:*'
    '         users:(("sshd",pid=900,fd=3))'
)
MODERN_UDP_LOCAL = (
    'udp   UNCONN 0      0        127.0.0.53%lo:53        0.0.0.0:*'
    '         users:(("systemd-resolve",pid=800,fd=17))'
)
MODERN_UDP_ZONE_BOUND = (
    'udp   UNCONN 0      0          0.0.0.0%virbr0:67      0.0.0.0:*'
    '         users:(("dnsmasq",pid=700,fd=5))'
)

# Old iproute2 (no State column, local address at index 3).
LEGACY_TCP = "tcp   0      0      0.0.0.0:445      0.0.0.0:*"


class ParseSsTests(unittest.TestCase):
    def test_modern_tcp_with_state_column(self):
        sock = parse_ss_line(MODERN_TCP)
        self.assertIsNotNone(sock)
        self.assertEqual((sock.protocol, sock.address, sock.port), ("tcp", "0.0.0.0", 22))
        self.assertEqual(sock.scope, "todas")
        self.assertEqual(sock.process, "sshd")

    def test_modern_udp_loopback_is_local_not_interfaz(self):
        sock = parse_ss_line(MODERN_UDP_LOCAL)
        self.assertIsNotNone(sock)
        self.assertEqual(sock.port, 53)
        self.assertEqual(sock.scope, "local")

    def test_modern_udp_zone_bound_is_interfaz(self):
        # 0.0.0.0%virbr0 is a wildcard bound to ONE device (dnsmasq for
        # libvirt): exposed only on that interface, not on every one.
        sock = parse_ss_line(MODERN_UDP_ZONE_BOUND)
        self.assertIsNotNone(sock)
        self.assertEqual(sock.port, 67)
        self.assertEqual(sock.scope, "interfaz")
        self.assertEqual(sock.process, "dnsmasq")

    def test_modern_ipv6_with_zone_keeps_zone_without_bracket(self):
        # Real Tailscale line shape: the `]` must not leak into the address.
        line = (
            'tcp   LISTEN 0      128      [fd7a:115c:a1e0::1]%tailscale0:443   [::]:*'
            '         users:(("tailscaled",pid=500,fd=9))'
        )
        sock = parse_ss_line(line)
        self.assertIsNotNone(sock)
        self.assertEqual(sock.address, "fd7a:115c:a1e0::1%tailscale0")
        self.assertEqual(sock.port, 443)
        self.assertEqual(sock.scope, "interfaz")
        self.assertEqual(sock.process, "tailscaled")

    def test_legacy_format_without_state_column(self):
        sock = parse_ss_line(LEGACY_TCP)
        self.assertIsNotNone(sock)
        self.assertEqual((sock.address, sock.port), ("0.0.0.0", 445))
        self.assertEqual(sock.scope, "todas")
        self.assertIsNone(sock.process)

    def test_garbage_lines_return_none(self):
        self.assertIsNone(parse_ss_line(""))
        self.assertIsNone(parse_ss_line("one two"))
        self.assertIsNone(parse_ss_line("tcp LISTEN 0 0 not-an-address:*"))


class ClassifyTests(unittest.TestCase):
    def test_loopback_subnet_counts_as_local(self):
        self.assertEqual(classify_address("127.0.0.53"), "local")
        self.assertEqual(classify_address("127.0.0.54"), "local")
        self.assertEqual(classify_address("::1"), "local")

    def test_zone_suffixes(self):
        self.assertEqual(classify_address("0.0.0.0%virbr0"), "interfaz")
        self.assertEqual(classify_address("127.0.0.1%lo"), "local")

    def test_other_addresses_are_interfaz(self):
        self.assertEqual(classify_address("192.168.122.1"), "interfaz")
        self.assertEqual(classify_address("fe80::1"), "interfaz")


class ServiceNameTests(unittest.TestCase):
    def test_known_risky_ports(self):
        self.assertEqual(service_name(23, "tcp"), "Telnet")
        self.assertEqual(service_name(445, "tcp"), "SMB")

    def test_etc_services_fallback(self):
        self.assertEqual(service_name(22, "tcp"), "SSH")

    def test_unknown_port_is_empty(self):
        self.assertEqual(service_name(59999, "tcp"), "")


if __name__ == "__main__":
    unittest.main()
