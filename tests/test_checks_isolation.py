"""`ejecutar_todos` must isolate failures: one crash keeps the other results."""

import unittest
from unittest import mock

from mintguard.checks import CHECKS, ejecutar_todos
from mintguard.core.distro import DistroInfo, PackageManager


def _fake_check(name):
    def check(distro):
        from mintguard.core.prioritizer import Finding, Severidad

        return [Finding(title=f"ok {name}", severity=Severidad.INFO, source=name)]

    return check


class IsolationTests(unittest.TestCase):
    def _patched(self, crashing):
        checks = {name: _fake_check(name) for name in CHECKS}
        checks[crashing] = mock.Mock(side_effect=RuntimeError("kaboom"))
        return checks

    def test_crashing_check_is_isolated(self):
        with mock.patch.dict(CHECKS, self._patched("services")):
            results = ejecutar_todos(DistroInfo(
                distro_id="x", name="Fake", version="1",
                package_manager=PackageManager(name="apt", path="/nonexistent/apt"),
                has_systemd=True, mac_module=None, firewall_tool=None,
            ))
        self.assertEqual(set(results), set(CHECKS))
        for name in CHECKS:
            if name == "services":
                (finding,) = results[name]
                self.assertEqual(finding.severity.name, "BAJA")
                self.assertIn("kaboom", finding.detail)
            else:
                (finding,) = results[name]
                self.assertEqual(finding.severity.name, "INFO")


if __name__ == "__main__":
    unittest.main()
