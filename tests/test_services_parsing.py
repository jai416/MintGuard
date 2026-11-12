"""Parsing tests for systemctl list-unit-files output."""

import unittest

from mintguard.checks.services import enabled_service_names

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


if __name__ == "__main__":
    unittest.main()
