"""Tests for grouping listening sockets into one finding per real service."""

import unittest

from mintguard.checks.network import group_endpoints, severity_by_exposure
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


if __name__ == "__main__":
    unittest.main()
