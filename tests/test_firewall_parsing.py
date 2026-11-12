"""Tests for the firewall active-state parsers and decision matrix."""

import unittest

from mintguard.checks.firewall import (
    firewall_finding,
    parse_firewall_cmd_state,
    parse_systemctl_is_active,
    parse_ufw_status,
)


class UfwStatusTests(unittest.TestCase):
    def test_active_and_inactive(self):
        self.assertEqual(parse_ufw_status("Status: active\n"), "active")
        self.assertEqual(parse_ufw_status("Status: inactive\n"), "inactive")

    def test_verbose_output(self):
        text = "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing)\n"
        self.assertEqual(parse_ufw_status(text), "active")

    def test_localized_variants(self):
        self.assertEqual(parse_ufw_status("Estado: activa\n"), "active")
        self.assertEqual(parse_ufw_status("Estado: inactivo\n"), "inactive")

    def test_error_output_is_none(self):
        self.assertIsNone(
            parse_ufw_status("ERROR: Debe ser root (administrador) para ejecutar este guión\n")
        )
        self.assertIsNone(parse_ufw_status(""))


class FirewallCmdStateTests(unittest.TestCase):
    def test_running_variants(self):
        self.assertEqual(parse_firewall_cmd_state("running\n"), "active")
        self.assertEqual(parse_firewall_cmd_state("not running\n"), "inactive")

    def test_errors_are_none(self):
        self.assertIsNone(parse_firewall_cmd_state("FAILED: unauthorized request\n"))
        self.assertIsNone(parse_firewall_cmd_state(""))


class SystemctlIsActiveTests(unittest.TestCase):
    def test_states(self):
        self.assertEqual(parse_systemctl_is_active("active\n"), "active")
        self.assertEqual(parse_systemctl_is_active("inactive\n"), "inactive")
        self.assertEqual(parse_systemctl_is_active("failed\n"), "inactive")

    def test_unknown_or_empty_is_none(self):
        self.assertIsNone(parse_systemctl_is_active("unknown\n"))
        self.assertIsNone(parse_systemctl_is_active(""))


class FirewallFindingTests(unittest.TestCase):
    def test_no_tool_detected_is_media(self):
        finding = firewall_finding(None, "desconocido")
        self.assertEqual(finding.severity.name, "MEDIA")
        self.assertIn("No se detectó", finding.title)

    def test_active_is_info(self):
        self.assertEqual(firewall_finding("UFW", "active").severity.name, "INFO")

    def test_inactive_is_alta_with_tool_suggestion(self):
        finding = firewall_finding("UFW", "inactive")
        self.assertEqual(finding.severity.name, "ALTA")
        self.assertIn("sudo ufw enable", finding.suggestion)
        self.assertIn("UFW", finding.title)

    def test_unknown_state_is_baja(self):
        finding = firewall_finding("nftables", "desconocido")
        self.assertEqual(finding.severity.name, "BAJA")


if __name__ == "__main__":
    unittest.main()
