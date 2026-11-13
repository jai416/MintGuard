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
