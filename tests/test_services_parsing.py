"""Parsing tests for systemctl list-unit-files output (and other inits)."""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mintguard.checks.services import (
    comprobar_servicios,
    enabled_service_names,
    parse_rc_update_show,
    risky_service_names,
    runit_service_names,
    sysvinit_enabled_names,
)
from mintguard.core.distro import DistroInfo

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
        return mock.Mock(has_systemd=has_systemd, init_system="desconocido")

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


def _distro_init(init: str, systemd: bool = False) -> DistroInfo:
    return DistroInfo(
        distro_id="x",
        name="X",
        version="",
        package_manager=None,
        has_systemd=systemd,
        mac_module=None,
        firewall_tool=None,
        init_system=init,
    )


class ParseRcUpdateShowTests(unittest.TestCase):
    OUT = """ * alsasound | boot default
 * sshd | default
 * cron | boot
netmount | default
junk line without pipe
"""

    def test_only_default_services(self):
        self.assertEqual(parse_rc_update_show(self.OUT), ["alsasound", "sshd", "netmount"])

    def test_empty(self):
        self.assertEqual(parse_rc_update_show(""), [])
        self.assertEqual(parse_rc_update_show("\n\n"), [])


class InitScanTests(unittest.TestCase):
    def test_runit_counts_every_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "sshd").mkdir()
            (base / "cron").symlink_to("/etc/sv/cron")
            names = runit_service_names((base,))
        self.assertEqual(names, ["cron", "sshd"])

    def test_runit_missing_directory_is_empty(self):
        self.assertEqual(runit_service_names((Path("/no/existe"),)), [])

    def test_sysvinit_strips_the_s_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "S01ssh").symlink_to("/etc/init.d/ssh")
            (base / "S99").symlink_to("/etc/init.d/edge")
            (base / "K99stop").symlink_to("/etc/init.d/stop")
            (base / "README").write_text("x", encoding="utf-8")
            names = sysvinit_enabled_names((base,))
        self.assertEqual(names, ["S99", "ssh"])  # "S99" sin nombre útil se queda

    def test_sysvinit_missing_directory_is_empty(self):
        self.assertEqual(sysvinit_enabled_names((Path("/no/existe"),)), [])


class InitBranchTests(unittest.TestCase):
    """Ramas openrc/runit/sysvinit y el fallback honesto (feedback init)."""

    def test_openrc_lists_only_default_services(self):
        out = mock.Mock(returncode=0, stdout=" * sshd | default\n * cron | boot\n", stderr="")
        with (
            mock.patch("mintguard.checks.services.resolve_binary", return_value="/sbin/rc-update"),
            mock.patch("mintguard.checks.services._run", return_value=out) as run,
        ):
            findings = comprobar_servicios(_distro_init("openrc"))
        self.assertEqual(run.call_args[0][0], ["/sbin/rc-update", "show", "default"])
        self.assertEqual(findings[0].title, "1 servicios habilitados al arranque")
        self.assertEqual(findings[0].evidence, ["sshd"])

    def test_openrc_failure_is_no_verificable_not_zero(self):
        failed = mock.Mock(returncode=1, stdout="", stderr="boom")
        with (
            mock.patch("mintguard.checks.services.resolve_binary", return_value="/sbin/rc-update"),
            mock.patch("mintguard.checks.services._run", return_value=failed),
        ):
            findings = comprobar_servicios(_distro_init("openrc"))
        self.assertEqual(findings[0].severity.name, "INFO")
        self.assertIn("no verificable", findings[0].title)

    def test_openrc_without_binary_is_no_verificable(self):
        with mock.patch("mintguard.checks.services.resolve_binary", return_value=None):
            findings = comprobar_servicios(_distro_init("openrc"))
        self.assertIn("no verificable", findings[0].title)

    def test_runit_flags_risky_with_runit_hint(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "telnetd").mkdir()
            with mock.patch("mintguard.checks.services.RUNIT_SERVICE_DIRS", (base,)):
                findings = comprobar_servicios(_distro_init("runit"))
        alta = next(f for f in findings if f.severity.name == "ALTA")
        self.assertIn("quita el enlace", alta.suggestion)

    def test_runit_without_dirs_is_no_verificable(self):
        with mock.patch("mintguard.checks.services.RUNIT_SERVICE_DIRS", (Path("/no/existe"),)):
            findings = comprobar_servicios(_distro_init("runit"))
        self.assertIn("no verificable", findings[0].title)

    def test_sysvinit_flags_risky_with_sysvinit_hint(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "S01telnet").symlink_to("/etc/init.d/telnet")
            (base / "S02ssh").symlink_to("/etc/init.d/ssh")
            with mock.patch("mintguard.checks.services.SYSVINIT_RC_DIRS", (base,)):
                findings = comprobar_servicios(_distro_init("sysvinit"))
        alta = next(f for f in findings if f.severity.name == "ALTA")
        self.assertIn("update-rc.d telnet remove", alta.suggestion)
        conteo = next(f for f in findings if "habilitados" in f.title)
        self.assertEqual(conteo.evidence, ["ssh", "telnet"])

    def test_sysvinit_without_dirs_is_no_verificable(self):
        with mock.patch("mintguard.checks.services.SYSVINIT_RC_DIRS", (Path("/no/existe"),)):
            findings = comprobar_servicios(_distro_init("sysvinit"))
        self.assertIn("no verificable", findings[0].title)

    def test_unknown_init_is_info_not_baja(self):
        # Un Devuan sano no debe sonar a alarma: es "no verificable".
        findings = comprobar_servicios(_distro_init("desconocido", systemd=False))
        self.assertEqual(findings[0].severity.name, "INFO")
        self.assertIn("no reconocido", findings[0].title)


if __name__ == "__main__":
    unittest.main()
