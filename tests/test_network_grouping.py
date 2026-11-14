"""Tests for grouping listening sockets into one finding per real service."""

import unittest
from unittest import mock

from mintguard.checks.network import (
    comprobar_red,
    group_endpoints,
    severity_by_exposure,
    severity_with_firewall,
)
from mintguard.core.distro import DistroInfo, PackageManager
from mintguard.core.exposure import ListeningSocket
from mintguard.core.prioritizer import Severidad


def _sock(protocol, address, port, scope="todas", process=None) -> ListeningSocket:
    return ListeningSocket(
        protocol=protocol, address=address, port=port, scope=scope, process=process
    )


def _distro_for_mixed() -> DistroInfo:
    return DistroInfo(
        distro_id="linuxmint",
        name="Linux Mint",
        version="22",
        package_manager=PackageManager("apt", "/usr/bin/apt"),
        has_systemd=True,
        mac_module=None,
        firewall_tool=None,
    )


class GroupEndpointsTests(unittest.TestCase):
    def test_same_service_on_two_families_is_one_group(self):
        groups = group_endpoints(
            [_sock("tcp", "0.0.0.0", 22), _sock("tcp", "[::]", 22)]
        )
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[("tcp", 22)]["addresses"], ["0.0.0.0", "[::]"])

    def test_protocols_stay_separate(self):
        groups = group_endpoints(
            [_sock("tcp", "0.0.0.0", 41641), _sock("udp", "0.0.0.0", 41641)]
        )
        self.assertEqual(sorted(groups), [("tcp", 41641), ("udp", 41641)])

    def test_processes_deduplicated(self):
        groups = group_endpoints(
            [
                _sock("tcp", "0.0.0.0", 22, process="sshd"),
                _sock("tcp", "[::]", 22, process="sshd"),
            ]
        )
        self.assertEqual(groups[("tcp", 22)]["processes"], ["sshd"])

    def test_worst_scope_wins(self):
        groups = group_endpoints(
            [
                _sock("tcp", "192.168.1.5", 80, scope="interfaz"),
                _sock("tcp", "0.0.0.0", 80, scope="todas"),
            ]
        )
        self.assertEqual(groups[("tcp", 80)]["scope"], "todas")

    def test_empty(self):
        self.assertEqual(group_endpoints([]), {})

    def test_legacy_tcp6_merges_with_tcp(self):
        # Old ss emits `tcp` and `tcp6` for the same service: one finding.
        groups = group_endpoints(
            [
                _sock("tcp", "0.0.0.0", 22),
                _sock("tcp6", "::", 22),
            ]
        )
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[("tcp", 22)]["addresses"], ["0.0.0.0", "::"])


class SeverityByExposureTests(unittest.TestCase):
    def test_legacy_insecure_services_are_critica_anywhere(self):
        for port in (21, 23):
            for scope in ("todas", "interfaz"):
                with self.subTest(port=port, scope=scope):
                    self.assertEqual(
                        severity_by_exposure(port, True, scope), Severidad.CRITICA
                    )

    def test_known_service_weighted_by_scope(self):
        self.assertEqual(severity_by_exposure(22, True, "todas"), Severidad.ALTA)
        self.assertEqual(severity_by_exposure(22, True, "interfaz"), Severidad.MEDIA)

    def test_unknown_port_lowered_by_scope(self):
        self.assertEqual(severity_by_exposure(9999, False, "todas"), Severidad.MEDIA)
        self.assertEqual(severity_by_exposure(9999, False, "interfaz"), Severidad.BAJA)


class SeverityWithFirewallTests(unittest.TestCase):
    """Matrix: CRITICA never lowers; active lowers (floor BAJA); inactive raises (ceiling ALTA)."""

    def test_active_lowers_one_level_with_baja_floor(self):
        self.assertEqual(severity_with_firewall(Severidad.ALTA, "active"), Severidad.MEDIA)
        self.assertEqual(severity_with_firewall(Severidad.MEDIA, "active"), Severidad.BAJA)
        self.assertEqual(severity_with_firewall(Severidad.BAJA, "active"), Severidad.BAJA)

    def test_inactive_raises_one_level_with_alta_ceiling(self):
        self.assertEqual(severity_with_firewall(Severidad.BAJA, "inactive"), Severidad.MEDIA)
        self.assertEqual(severity_with_firewall(Severidad.MEDIA, "inactive"), Severidad.ALTA)
        self.assertEqual(severity_with_firewall(Severidad.ALTA, "inactive"), Severidad.ALTA)

    def test_critica_never_changes(self):
        # FTP/Telnet stays CRITICA with or without a firewall (contract).
        self.assertEqual(severity_with_firewall(Severidad.CRITICA, "active"), Severidad.CRITICA)
        self.assertEqual(severity_with_firewall(Severidad.CRITICA, "inactive"), Severidad.CRITICA)

    def test_unknown_state_changes_nothing(self):
        for severity in Severidad:
            self.assertIs(severity_with_firewall(severity, "desconocido"), severity)


class ExpectedServicesIntegrationTests(unittest.TestCase):
    """The usage-review machine (Tailscale + libvirt + avahi): 11 ALTA → 2.

    The remaining ALTA findings must be actionable ones (real servers on
    all interfaces); the expected-in-context listeners become INFO, and
    avahi's ephemeral sockets fold into the BAJA discovery finding.
    """

    def _distro(self) -> DistroInfo:
        return DistroInfo(
            distro_id="linuxmint",
            name="Linux Mint",
            version="22",
            package_manager=PackageManager("apt", "/usr/bin/apt"),
            has_systemd=True,
            mac_module=None,
            firewall_tool="UFW",
        )

    def _sockets(self) -> list[ListeningSocket]:
        # Real shape of the reviewed machine (firewall installed, inactive).
        return [
            ListeningSocket("tcp", "0.0.0.0", 80, "todas", "lighttpd"),
            ListeningSocket("tcp", "0.0.0.0", 22, "todas", "systemd"),  # socket activation
            ListeningSocket("udp", "0.0.0.0", 41641, "todas", "tailscaled"),
            ListeningSocket("tcp", "100.99.183.44%tailscale0", 443, "interfaz", "tailscaled"),
            ListeningSocket("tcp", "fd7a:5c:d114:6a4a::1%tailscale0", 443, "interfaz", "tailscaled"),
            ListeningSocket("udp", "0.0.0.0", 36476, "todas", "avahi-daemon"),
            ListeningSocket("udp", "::", 54452, "todas", "avahi-daemon"),
            ListeningSocket("udp", "0.0.0.0", 5353, "todas", "avahi-daemon"),
            ListeningSocket("udp", "192.168.122.1", 53, "interfaz", "dnsmasq"),
            ListeningSocket("tcp", "192.168.122.1", 53, "interfaz", "dnsmasq"),
            ListeningSocket("udp", "0.0.0.0%virbr0", 67, "interfaz", "dnsmasq"),
        ]

    def _run(self):
        with (
            mock.patch(
                "mintguard.checks.network.listening_sockets",
                return_value=(self._sockets(), None),
            ),
            mock.patch(
                "mintguard.checks.network.firewall_state", return_value="inactive"
            ),
        ):
            return comprobar_red(self._distro())

    def test_only_actionable_altas_remain(self):
        findings = self._run()
        altas = [f for f in findings if f.severity == Severidad.ALTA]
        titles = sorted(f.title for f in altas)
        # lighttpd + sshd (weighted up by the inactive firewall) + the
        # firewall finding itself. The tailscale/libvirt/avahi noise is gone.
        self.assertEqual(
            titles,
            [
                "Firewall instalado pero no activo (UFW)",
                "Servicio HTTP expuesto en la red",
                "Servicio SSH expuesto en la red",
            ],
        )

    def test_tailscale_listeners_are_info(self):
        findings = self._run()
        tailscale = [f for f in findings if "Tailscale" in f.title]
        self.assertEqual(len(tailscale), 2)  # DISCO port + Serve port group
        for finding in tailscale:
            self.assertEqual(finding.severity, Severidad.INFO)
            self.assertIn("Tailscale funciona así", finding.detail)
        serve = next(f for f in tailscale if "443" in f.detail)
        # Both families are evidence of the same expected service.
        self.assertEqual(len(serve.evidence), 2)

    def test_libvirt_dns_dhcp_are_info(self):
        findings = self._run()
        libvirt = [f for f in findings if "libvirt" in f.title]
        self.assertEqual(len(libvirt), 3)  # 53/udp + 53/tcp + 67/udp
        for finding in libvirt:
            self.assertEqual(finding.severity, Severidad.INFO)
            self.assertIn("bridge virtual", finding.detail)

    def test_avahi_ephemeral_folds_into_discovery_finding(self):
        findings = self._run()
        discovery = next(f for f in findings if "descubrimiento" in f.title)
        self.assertEqual(discovery.severity, Severidad.BAJA)
        self.assertIn("UDP 0.0.0.0:36476", discovery.evidence[0])
        self.assertIn("UDP :::54452", discovery.evidence[1])
        self.assertIn("avahi-daemon responde mDNS", discovery.detail)
        self.assertNotIn("36476", " ".join(f.detail for f in findings if f is not discovery))
        # No separate finding for the ephemeral ports.
        self.assertFalse(any("36476" in f.title or "54452" in f.title for f in findings))

    def test_socket_activation_is_annotated(self):
        findings = self._run()
        sshd = next(f for f in findings if "SSH" in f.title)
        self.assertIn("socket-activado; probablemente ssh", sshd.detail)


class MixedGroupStaysVisibleTests(unittest.TestCase):
    """A group mixing expected and unexpected members keeps its severity."""

    def test_mixed_443_group_stays_alta_with_all_addresses(self):
        sockets = [
            ListeningSocket("tcp", "0.0.0.0", 443, "todas", "nginx"),
            ListeningSocket("tcp", "100.99.183.44%tailscale0", 443, "interfaz", "tailscaled"),
        ]
        with (
            mock.patch(
                "mintguard.checks.network.listening_sockets",
                return_value=(sockets, None),
            ),
            mock.patch("mintguard.checks.network.firewall_state", return_value="desconocido"),
        ):
            findings = comprobar_red(_distro_for_mixed())
        exposed = next(f for f in findings if "expuesto" in f.title)
        self.assertEqual(exposed.severity, Severidad.ALTA)
        self.assertIn("0.0.0.0:443", exposed.evidence[0])
        self.assertIn("100.99.183.44%tailscale0:443", exposed.evidence[1])
        self.assertFalse(any("Tailscale" in f.title for f in findings))


class ComprobarRedFirewallIntegrationTests(unittest.TestCase):
    """comprobar_red weights exposed endpoints with the firewall state it already computed."""

    def _distro(self) -> DistroInfo:
        return DistroInfo(
            distro_id="linuxmint",
            name="Linux Mint",
            version="22",
            package_manager=PackageManager("apt", "/usr/bin/apt"),
            has_systemd=True,
            mac_module=None,
            firewall_tool="UFW",
        )

    def _run_check(self, state: str, port: int = 22, service_known: bool = True):
        sockets = [
            ListeningSocket(
                protocol="tcp", address="0.0.0.0", port=port, scope="todas", process="sshd"
            )
        ]
        with (
            mock.patch(
                "mintguard.checks.network.listening_sockets",
                return_value=(sockets, None),
            ),
            mock.patch(
                "mintguard.checks.network.firewall_state", side_effect=lambda d: state
            ) as state_call,
        ):
            findings = comprobar_red(self._distro())
        return findings, state_call

    def _exposed_finding(self, findings):
        return next(f for f in findings if "expuesto" in f.title or "Puerto abierto" in f.title)

    def test_inactive_raises_and_explains(self):
        # Unknown port on all interfaces: MEDIA by exposure -> ALTA without
        # an active firewall. A known service already at ALTA would stay.
        findings, state_call = self._run_check("inactive", port=9999, service_known=False)
        exposed = self._exposed_finding(findings)
        self.assertEqual(exposed.severity, Severidad.ALTA)
        self.assertIn("Sin firewall activo: la exposición es directa.", exposed.detail)
        # One consultation total: the firewall finding reuses the same state.
        self.assertEqual(state_call.call_count, 1)
        firewall = next(f for f in findings if "Firewall" in f.title)
        self.assertIn("no activo", firewall.title)

    def test_active_lowers_and_explains(self):
        findings, _ = self._run_check("active")
        exposed = self._exposed_finding(findings)
        self.assertEqual(exposed.severity, Severidad.MEDIA)  # ALTA -> MEDIA
        self.assertIn("El firewall activo reduce el riesgo.", exposed.detail)

    def test_desconocido_adds_no_note(self):
        findings, _ = self._run_check("desconocido")
        exposed = self._exposed_finding(findings)
        self.assertEqual(exposed.severity, Severidad.ALTA)
        self.assertNotIn("firewall", exposed.detail)

    def test_firewall_state_computed_once_even_with_several_endpoints(self):
        findings, state_call = self._run_check("inactive")
        del findings
        self.assertEqual(state_call.call_count, 1)


if __name__ == "__main__":
    unittest.main()
