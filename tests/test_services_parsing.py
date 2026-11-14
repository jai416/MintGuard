"""Parsing tests for systemctl list-unit-files output."""

import unittest
from unittest import mock

from mintguard.checks.services import (
    comprobar_servicios,
    enabled_service_names,
    risky_service_names,
)

SYSTEMCTL_OUT = """accounts-daemon.service    enabled      enabled
apparmor.service           enabled      enabled
cups.service               enabled      enabled

systemd-journald.service   enabled      enabled
"""


class EnabledServiceNamesTests(unittest.TestCase):
    def test_names_and_skips_blank_lines(self):
        names = enabled_service_names(SYSTEMCTL_OUT)
        self.assertEqual(
            names,
            [
                "accounts-daemon.service",
                "apparmor.service",
                "cups.service",
                "systemd-journald.service",
            ],
        )

    def test_empty(self):
        self.assertEqual(enabled_service_names(""), [])
        self.assertEqual(enabled_service_names("\n\n"), [])


class RiskyServiceNamesTests(unittest.TestCase):
    def test_legacy_daemons_matched(self):
        self.assertEqual(
            risky_service_names(["telnetd.service", "tftpd.service", "rshd.service"]),
            ["telnetd.service", "tftpd.service", "rshd.service"],
        )

    def test_plain_names_matched(self):
        self.assertEqual(
            risky_service_names(["telnet.service", "finger.service"]),
            ["telnet.service", "finger.service"],
        )

    def test_rshim_is_not_rsh(self):
        # Substring matching used to raise a false ALTA for rshim.service.
        self.assertEqual(risky_service_names(["rshim.service"]), [])

    def test_templated_units(self):
        self.assertEqual(risky_service_names(["tftp@.service"]), ["tftp@.service"])

    def test_normal_services_ignored(self):
        self.assertEqual(risky_service_names(["sshd.service", "cups.service"]), [])


class ComprobarServiciosRunnerTests(unittest.TestCase):
    """Runner behaviour (A1/A3 from the security audit)."""

    def _distro(self, has_systemd=True):
        return mock.Mock(has_systemd=has_systemd)

    def test_failed_query_never_means_zero_services(self):
        # rc != 0 with no data used to be reported as "0 servicios
        # habilitados" (INFO): a failed query must be BAJA instead.
        failed = mock.Mock(returncode=1, stdout="", stderr="Failed to connect to bus")
        with (
            mock.patch("mintguard.checks.services.resolve_binary", return_value="/usr/bin/systemctl"),
            mock.patch("mintguard.checks.services._run", return_value=failed),
        ):
            findings = comprobar_servicios(self._distro())
        self.assertEqual(findings[0].severity.name, "BAJA")
        self.assertIn("No se pudo consultar", findings[0].title)

    def test_timeout_is_baja(self):
        with (
            mock.patch("mintguard.checks.services.resolve_binary", return_value="/usr/bin/systemctl"),
            mock.patch("mintguard.checks.services._run", return_value=None),
        ):
            findings = comprobar_servicios(self._distro())
        self.assertEqual(findings[0].severity.name, "BAJA")

    def test_uses_the_resolved_absolute_path(self):
        ok = mock.Mock(returncode=0, stdout=SYSTEMCTL_OUT, stderr="")
        with (
            mock.patch("mintguard.checks.services.resolve_binary", return_value="/usr/bin/systemctl"),
            mock.patch("mintguard.checks.services._run", return_value=ok) as run,
        ):
            comprobar_servicios(self._distro())
        self.assertEqual(run.call_args[0][0][0], "/usr/bin/systemctl")

    def test_no_systemctl_is_baja(self):
        with mock.patch("mintguard.checks.services.resolve_binary", return_value=None):
            findings = comprobar_servicios(self._distro())
        self.assertEqual(findings[0].severity.name, "BAJA")


if __name__ == "__main__":
    unittest.main()
