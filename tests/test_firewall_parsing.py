"""Tests for the firewall active-state parsers and decision matrix."""

import unittest
from unittest import mock

from mintguard.checks.firewall import (
    _state_from_systemctl,
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
    """Real exit codes verified on systemd 252: 0 active, 3 inactive, 4 no unit."""

    def test_states(self):
        self.assertEqual(parse_systemctl_is_active("active\n", 0), "active")
        self.assertEqual(parse_systemctl_is_active("inactive\n", 3), "inactive")
        self.assertEqual(parse_systemctl_is_active("failed\n", 3), "inactive")

    def test_nonexistent_unit_prints_inactive_but_rc_is_4(self):
        # Verified: `systemctl is-active no-such-unit` prints "inactive"
        # with exit 4. Treating that as "inactive" reported a false ALTA
        # "installed but not active" firewall.
        self.assertIsNone(parse_systemctl_is_active("inactive\n", 4))

    def test_rc_and_text_must_agree(self):
        self.assertIsNone(parse_systemctl_is_active("inactive\n", 0))
        self.assertIsNone(parse_systemctl_is_active("active\n", 3))

    def test_unknown_or_empty_is_none(self):
        self.assertIsNone(parse_systemctl_is_active("unknown\n", 0))
        self.assertIsNone(parse_systemctl_is_active("", 0))


class StateFromSystemctlTests(unittest.TestCase):
    """Candidate loop: nonexistent units (rc 4) are skipped, not 'inactive'."""

    def _result(self, returncode, stdout):
        return mock.Mock(returncode=returncode, stdout=stdout, stderr="")

    def test_all_units_nonexistent_is_none(self):
        # Debian base: iptables binary present but no netfilter-persistent
        # unit. Previously reported false ALTA "installed but not active".
        results = self._result(4, "inactive\n")
        with mock.patch("mintguard.checks.firewall._run", return_value=results):
            self.assertIsNone(
                _state_from_systemctl("/usr/bin/systemctl", ("netfilter-persistent", "iptables"))
            )

    def test_inactive_unit_found(self):
        result = self._result(3, "inactive\n")
        with mock.patch("mintguard.checks.firewall._run", return_value=result):
            self.assertEqual(
                _state_from_systemctl("/usr/bin/systemctl", ("ufw",)), "inactive"
            )

    def test_active_unit_found(self):
        result = self._result(0, "active\n")
        with mock.patch("mintguard.checks.firewall._run", return_value=result):
            self.assertEqual(
                _state_from_systemctl("/usr/bin/systemctl", ("ufw",)), "active"
            )


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
