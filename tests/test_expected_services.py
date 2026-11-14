"""Tests for expected-services classification (the "context" dimension).

Fixtures use real ss bind addresses (tailscale overlay, libvirt bridge,
avahi ephemeral ports) captured from the usage review of 2026-11-14.
"""

import unittest
from unittest import mock

from mintguard.core.expected_services import classify, context_is_authentic


class TailscaleTests(unittest.TestCase):
    def test_daemon_on_tailscale_addresses_is_tailscale(self):
        # Real binds of tailscaled Serve/MagicDNS on the tailscale0 zone.
        self.assertEqual(classify("tailscaled", "100.99.183.44%tailscale0", 443, "tcp"), "tailscale")
        self.assertEqual(
            classify("tailscaled", "fd7a:5c:d114:6a4a::1%tailscale0", 443, "tcp"), "tailscale"
        )
        # The CGNAT overlay IP, even without a zone suffix.
        self.assertEqual(classify("tailscaled", "100.100.100.100", 53, "udp"), "tailscale")

    def test_disco_port_is_tailscale_on_any_address(self):
        # NAT traversal requires listening on 0.0.0.0, by design.
        self.assertEqual(classify("tailscaled", "0.0.0.0", 41641, "udp"), "tailscale")
        self.assertEqual(classify("nginx", "0.0.0.0", 41641, "udp"), "tailscale")

    def test_disco_port_is_udp_only(self):
        self.assertIsNone(classify("nginx", "0.0.0.0", 41641, "tcp"))

    def test_daemon_on_wildcard_stays_visible(self):
        # tailscaled on 0.0.0.0:443 (not its interface) is NOT tagged on
        # purpose: ambiguous exposure must keep its normal severity.
        self.assertIsNone(classify("tailscaled", "0.0.0.0", 443, "tcp"))

    def test_other_services_on_tailscale0_keep_severity(self):
        # sshd bound to the tailscale IP is a deliberate service, not
        # tailscale's own: the process name is the signal, not the zone.
        self.assertIsNone(classify("sshd", "100.99.183.44%tailscale0", 22, "tcp"))

    def test_protocol_suffix_normalized(self):
        # Old ss emits udp6/tcp6 for the same real service.
        self.assertEqual(classify("tailscaled", "0.0.0.0", 41641, "udp6"), "tailscale")


class LibvirtTests(unittest.TestCase):
    def test_dnsmasq_on_libvirt_network_is_libvirt(self):
        self.assertEqual(classify("dnsmasq", "192.168.122.1", 53, "udp"), "libvirt")
        self.assertEqual(classify("dnsmasq", "192.168.122.1", 53, "tcp"), "libvirt")

    def test_dnsmasq_on_virtual_bridge_is_libvirt(self):
        # Real bind: DHCP for VMs, wildcard on the bridge device.
        self.assertEqual(classify("dnsmasq", "0.0.0.0%virbr0", 67, "udp"), "libvirt")
        self.assertEqual(classify("dnsmasq", "0.0.0.0%docker0", 53, "udp"), "libvirt")

    def test_dnsmasq_on_the_real_lan_stays_visible(self):
        self.assertIsNone(classify("dnsmasq", "192.168.1.1", 53, "udp"))

    def test_other_processes_on_virbr_not_tagged_here(self):
        # Generalizing virtual interfaces is the interface-nature rule
        # (paso 5); classify only tags the libvirt dnsmasq service.
        self.assertIsNone(classify("nginx", "0.0.0.0%virbr0", 80, "tcp"))


class AvahiTests(unittest.TestCase):
    def test_ephemeral_udp_ports_are_avahi(self):
        # Real binds seen in ss: avahi answering mDNS from random ports.
        self.assertEqual(classify("avahi-daemon", "0.0.0.0", 36476, "udp"), "avahi")
        self.assertEqual(classify("avahi-daemon", "::", 54452, "udp"), "avahi")

    def test_well_known_and_tcp_not_tagged(self):
        # 5353 is diverted earlier (discovery); below the ephemeral
        # floor or TCP it is not avahi's response socket.
        self.assertIsNone(classify("avahi-daemon", "0.0.0.0", 5353, "udp"))
        self.assertIsNone(classify("avahi-daemon", "0.0.0.0", 5353, "tcp"))
        self.assertIsNone(classify("avahi-daemon", "0.0.0.0", 8080, "tcp"))


class UnrelatedServicesTests(unittest.TestCase):
    """The rules must NOT hide real exposure."""

    def test_common_servers_stay_untagged(self):
        self.assertIsNone(classify("lighttpd", "0.0.0.0", 80, "tcp"))
        self.assertIsNone(classify("sshd", "0.0.0.0", 22, "tcp"))
        self.assertIsNone(classify("smbd", "0.0.0.0", 445, "tcp"))
        self.assertIsNone(classify(None, "0.0.0.0", 3306, "tcp"))  # sin proceso (sin root)

    def test_unknown_process_and_port(self):
        self.assertIsNone(classify(None, "0.0.0.0", 9999, "udp"))


class ContextAuthenticityTests(unittest.TestCase):
    """The tag must be backed by the real binary, not by a process name.

    Any user can rename their own process with prctl(PR_SET_NAME): the
    name `ss` prints is not proof. Only /proc/<pid>/exe is.
    """

    def test_no_process_visible_keeps_the_port_rule(self):
        # Without root `ss` runs without -p: nothing contradicts the
        # DISCO port rule (41641 is Tailscale's by design).
        self.assertTrue(context_is_authentic(None, None, "tailscale"))

    def test_no_context_needs_no_proof(self):
        self.assertTrue(context_is_authentic("sshd", 123, None))

    def test_name_without_pid_is_dropped(self):
        # A name with no pid cannot be proved: fail closed.
        self.assertFalse(context_is_authentic("dnsmasq", None, "libvirt"))

    def test_matching_exe_keeps_the_tag(self):
        with mock.patch("os.readlink", return_value="/usr/sbin/tailscaled"):
            self.assertTrue(context_is_authentic("tailscaled", 123, "tailscale"))

    def test_spoofed_name_is_dropped(self):
        # The process calls itself "tailscaled" but runs another binary.
        with mock.patch("os.readlink", return_value="/home/user/backdoor"):
            self.assertFalse(context_is_authentic("tailscaled", 123, "tailscale"))

    def test_deleted_binary_suffix_is_tolerated(self):
        # A daemon replaced by an update shows "/usr/sbin/x (deleted)".
        with mock.patch("os.readlink", return_value="/usr/sbin/avahi-daemon (deleted)"):
            self.assertTrue(context_is_authentic("avahi-daemon", 9, "avahi"))

    def test_vanished_process_is_dropped(self):
        with mock.patch("os.readlink", side_effect=OSError):
            self.assertFalse(context_is_authentic("dnsmasq", 123, "libvirt"))

    def test_port_rule_drops_a_foreign_process(self):
        # A backdoor on udp/41641 is not Tailscale's DISCO port.
        with mock.patch("os.readlink", return_value="/usr/sbin/nginx"):
            self.assertFalse(context_is_authentic("nginx", 123, "tailscale"))


if __name__ == "__main__":
    unittest.main()
