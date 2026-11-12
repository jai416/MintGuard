"""Parsing tests for systemctl list-unit-files output."""

import unittest

from mintguard.checks.services import enabled_service_names, risky_service_names

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


if __name__ == "__main__":
    unittest.main()
