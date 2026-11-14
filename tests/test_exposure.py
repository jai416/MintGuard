"""Regression tests for the `ss` parser and exposure classification.

These exist because the original parser read the wrong column on modern
iproute2 (which includes the State column) and reported "no listening
ports" on a machine that actually had several: a silent false negative
in a security tool.
"""

import unittest
from unittest import mock

from mintguard.core.exposure import (
    listening_sockets,
    parse_ss_line,
    classify_address,
    interface_nature,
    socket_nature,
    worst_nature,
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
LEGACY_TCP6 = "tcp6  0      0      :::22            :::*"
LEGACY_UDP = "udp   0      0      0.0.0.0:68       0.0.0.0:*"


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

    def test_legacy_tcp6_and_legacy_udp(self):
        sock6 = parse_ss_line(LEGACY_TCP6)
        self.assertIsNotNone(sock6)
        self.assertEqual((sock6.protocol, sock6.address, sock6.port), ("tcp6", "::", 22))

        udp = parse_ss_line(LEGACY_UDP)
        self.assertIsNotNone(udp)
        self.assertEqual((udp.protocol, udp.address, udp.port), ("udp", "0.0.0.0", 68))

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


class InterfaceNatureTests(unittest.TestCase):
    """interface_nature: one test per nature (paso 5, fourth dimension)."""

    def test_virtual_bridge_zones(self):
        self.assertEqual(interface_nature("virbr0", "0.0.0.0"), "virtual")
        self.assertEqual(interface_nature("docker0", "172.17.0.1"), "virtual")
        self.assertEqual(interface_nature("br-c0ffee", "0.0.0.0"), "virtual")

    def test_plain_wildcards_are_unknown(self):
        # No zone, no concrete IP: judging needs the machine's addresses.
        self.assertEqual(interface_nature("", "0.0.0.0"), "unknown")
        self.assertEqual(interface_nature("", "::"), "unknown")
        self.assertEqual(interface_nature("", "*"), "unknown")
        self.assertEqual(interface_nature("eth0", ""), "unknown")

    def test_loopback(self):
        self.assertEqual(interface_nature("", "127.0.0.1"), "loopback")
        self.assertEqual(interface_nature("lo", "::1"), "loopback")

    def test_link_local(self):
        self.assertEqual(interface_nature("", "169.254.3.4"), "link-local")
        self.assertEqual(interface_nature("", "fe80::1"), "link-local")

    def test_cgnat_checked_before_lan(self):
        # 100.64.0.0/10 is is_private too: the cgnat bucket must win.
        self.assertEqual(interface_nature("tailscale0", "100.99.183.44"), "cgnat")
        self.assertEqual(interface_nature("", "100.64.7.7"), "cgnat")

    def test_lan(self):
        self.assertEqual(interface_nature("", "192.168.1.5"), "lan")
        self.assertEqual(interface_nature("", "10.0.0.3"), "lan")
        self.assertEqual(interface_nature("", "172.16.4.4"), "lan")
        self.assertEqual(interface_nature("", "fd00::5"), "lan")

    def test_public(self):
        # TEST-NET ranges (203.0.113.0/24) are non-global in ipaddress:
        # use real-world global addresses here.
        self.assertEqual(interface_nature("", "8.8.8.8"), "public")
        self.assertEqual(interface_nature("", "2606:4700::1111"), "public")

    def test_garbage_ip_is_unknown(self):
        self.assertEqual(interface_nature("", "notanip"), "unknown")

    def test_socket_nature_splits_zone(self):
        self.assertEqual(socket_nature("100.99.183.44%tailscale0"), "cgnat")
        self.assertEqual(socket_nature("0.0.0.0%virbr0"), "virtual")
        self.assertEqual(socket_nature("0.0.0.0"), "unknown")

    def test_worst_nature_is_conservative(self):
        # unknown outranks public: a wildcard exposes via every interface.
        self.assertEqual(worst_nature(["lan", "public"]), "public")
        self.assertEqual(worst_nature(["lan", "virtual"]), "lan")
        self.assertEqual(worst_nature(["cgnat", "link-local"]), "cgnat")
        self.assertEqual(worst_nature(["public", "unknown"]), "unknown")


class ListeningSocketsTests(unittest.TestCase):
    """End-to-end behaviour of the runner (A1/A2 from the security audit)."""

    def test_failed_ss_never_means_no_ports(self):
        # rc != 0 with no data used to fall through to "no ports" (INFO):
        # a failed inspection must be an explicit error instead.
        failed = mock.Mock(returncode=1, stdout="", stderr="error")
        with (
            mock.patch("mintguard.core.exposure.shutil.which", return_value="/usr/bin/ss"),
            mock.patch("mintguard.core.exposure.subprocess.run", return_value=failed),
        ):
            sockets, error = listening_sockets()
        self.assertEqual(sockets, [])
        self.assertIn("No se pudo inspeccionar", error)

    def test_output_with_rc_not_zero_still_parses(self):
        # Data present despite a weird rc: keep it (ss may exit nonzero
        # while printing valid lines on odd setups).
        result = mock.Mock(returncode=1, stdout=MODERN_TCP, stderr="")
        with (
            mock.patch("mintguard.core.exposure.shutil.which", return_value="/usr/bin/ss"),
            mock.patch("mintguard.core.exposure.subprocess.run", return_value=result) as run,
        ):
            sockets, error = listening_sockets()
        self.assertIsNone(error)
        self.assertEqual(len(sockets), 1)

    def test_uses_absolute_path_from_which(self):
        # Under sudo, PATH lookup would resolve `ss` in the inherited user
        # PATH; the resolved absolute path must be the executed binary.
        result = mock.Mock(returncode=0, stdout=MODERN_TCP, stderr="")
        with (
            mock.patch("mintguard.core.exposure.shutil.which", return_value="/usr/bin/ss"),
            mock.patch("mintguard.core.exposure.subprocess.run", return_value=result) as run,
        ):
            listening_sockets()
        command = run.call_args[0][0]
        self.assertEqual(command[0], "/usr/bin/ss")

    def test_missing_ss_is_error(self):
        with mock.patch("mintguard.core.exposure.shutil.which", return_value=None):
            sockets, error = listening_sockets()
        self.assertEqual(sockets, [])
        self.assertIn("no está disponible", error)


if __name__ == "__main__":
    unittest.main()
