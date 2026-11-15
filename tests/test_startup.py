"""El arranque no puede romperse: se ejecuta en cada inicio de la app.

`collect_system_info()` y `detect_distro()` se llaman al construir la
aplicación: si una de las dos falla, MintGuard ni arranca. Aquí se les
da entrada basura (ficheros ilegibles, /etc/os-release vacío o con
basura) y se exige que devuelvan valores utilizables.
"""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mintguard.core import distro as distro_module
from mintguard.core.distro import DistroInfo, PackageManager, detect_distro
from mintguard.core.system import collect_system_info
from mintguard.reporting.reporter import _anonymized_distro_label, _anonymized_ram

DISTRO = DistroInfo(
    distro_id="linuxmint",
    name="Linux Mint",
    version="22",
    package_manager=PackageManager("apt", "/usr/bin/apt"),
    has_systemd=True,
    mac_module="AppArmor",
    firewall_tool="UFW",
)


class SystemInfoTests(unittest.TestCase):
    def test_collect_system_info_never_raises(self):
        info = collect_system_info()
        self.assertIsInstance(info.hostname, str)
        self.assertIsInstance(info.kernel, str)
        self.assertIsInstance(info.arch, str)
        self.assertIsInstance(info.cpu_model, str)
        self.assertIsInstance(info.uptime_text, str)
        self.assertGreaterEqual(info.cpu_count, 0)
        self.assertGreaterEqual(info.ram_total_mb, 0)

    def test_unreadable_proc_files_do_not_break_it(self):
        # /proc puede estar montado de otra forma (contenedores, chroot).
        with mock.patch("builtins.open", side_effect=OSError("boom")):
            info = collect_system_info()
        self.assertEqual(info.cpu_model, "")
        self.assertEqual(info.ram_total_mb, 0)
        self.assertEqual(info.uptime_text, "")

    def test_garbage_proc_content_does_not_break_it(self):
        handle = mock.mock_open(read_data="???\n")
        handle.return_value.__enter__.return_value = handle.return_value
        with mock.patch("builtins.open", handle):
            info = collect_system_info()
        self.assertEqual(info.ram_total_mb, 0)


class DistroDetectionTests(unittest.TestCase):
    def _with_os_release(self, content: str | None):
        if content is None:
            path = Path("/no/existe/os-release")
        else:
            tmp = tempfile.NamedTemporaryFile("w", suffix=".os-release", delete=False)
            tmp.write(content)
            tmp.close()
            path = Path(tmp.name)
        with mock.patch.object(distro_module, "OS_RELEASE_PATH", path):
            return detect_distro()

    def test_normal_detection_returns_usable_values(self):
        info = detect_distro()
        self.assertTrue(info.name)
        self.assertIsInstance(info.has_systemd, bool)
        self.assertIsInstance(info.mac_module, (str, type(None)))
        self.assertIsInstance(info.firewall_tool, (str, type(None)))

    def test_garbage_os_release_gives_sane_values(self):
        info = self._with_os_release("???\n\x00binario\nID=\nVERSION_ID=\n")
        self.assertTrue(info.name)
        self.assertIsInstance(info.version, str)

    def test_missing_os_release_gives_sane_values(self):
        info = self._with_os_release(None)
        self.assertTrue(info.name)
        self.assertEqual(info.version, "")

    def test_empty_os_release_gives_sane_values(self):
        info = self._with_os_release("")
        self.assertTrue(info.name)

    def test_name_without_pretty_name_falls_back(self):
        info = self._with_os_release('ID=linuxmint\nNAME="Linux Mint"\n')
        self.assertIn("Linux Mint", info.name)


class AnonymizedEdgeTests(unittest.TestCase):
    """Los bordes del modo anonimizado: nada de "None" ni de espacios raros."""

    def test_ram_buckets_handle_extreme_values(self):
        self.assertEqual(_anonymized_ram(0), "<2 GB")
        self.assertEqual(_anonymized_ram(-1), "<2 GB")
        self.assertEqual(_anonymized_ram(1024), "<2 GB")
        self.assertEqual(_anonymized_ram(10**9), "16 GB o más")

    def _distro(self, name: str, version: str) -> DistroInfo:
        return DistroInfo(
            distro_id="x",
            name=name,
            version=version,
            package_manager=PackageManager("apt", "/usr/bin/apt"),
            has_systemd=True,
            mac_module=None,
            firewall_tool=None,
        )

    def test_distro_label_handles_empty_and_odd_names(self):
        self.assertEqual(_anonymized_distro_label(self._distro("", "")), "")
        self.assertEqual(_anonymized_distro_label(self._distro("Mint", "")), "Mint")
        self.assertEqual(_anonymized_distro_label(self._distro("Mint", "22.3")), "Mint 22")
        # Sin espacios dobles ni codenames.
        label = _anonymized_distro_label(self._distro("Linux Mint 21.3 Una", "21.3"))
        self.assertEqual(label, "Linux Mint 21")


class DegradedSystemTests(unittest.TestCase):
    """Un sistema sin /proc, sin /etc legible y sin binarios no rompe la app.

    Cada chequeo tiene que degradar a "no verificable" (INFO), nunca a
    una excepción: una excepción en un chequeo convertiría el resto de
    resultados en un error genérico.
    """

    def test_every_check_degrades_gracefully(self):
        from mintguard.checks import ejecutar_todos
        from mintguard.core.prioritizer import Severidad
        from mintguard.reporting.reporter import generar_reporte

        real_read = Path.read_text

        def fake_read(self, *args, **kwargs):
            if str(self).startswith(("/proc", "/sys", "/etc")):
                raise PermissionError("simulado: sin permisos")
            return real_read(self, *args, **kwargs)

        with mock.patch.object(Path, "read_text", fake_read):
            with (
                mock.patch("mintguard.checks.updates.run_command", return_value=None),
                mock.patch("mintguard.checks.services.run_command", return_value=None),
                mock.patch("mintguard.checks.firewall.run_command", return_value=None),
            ):
                results = ejecutar_todos(DISTRO)

        self.assertTrue(results)
        for source, findings in results.items():
            with self.subTest(source=source):
                self.assertIsInstance(findings, list)
                for finding in findings:
                    self.assertIsInstance(finding.title, str)
                    self.assertTrue(finding.title)
                    self.assertIn(finding.severity, tuple(Severidad))

    def test_the_report_is_generated_even_with_degraded_checks(self):
        from mintguard.checks import ejecutar_todos
        from mintguard.reporting.reporter import generar_reporte

        real_read = Path.read_text

        def fake_read(self, *args, **kwargs):
            if str(self).startswith(("/proc", "/sys", "/etc")):
                raise PermissionError("simulado")
            return real_read(self, *args, **kwargs)

        with mock.patch.object(Path, "read_text", fake_read):
            with (
                mock.patch("mintguard.checks.updates.run_command", return_value=None),
                mock.patch("mintguard.checks.services.run_command", return_value=None),
                mock.patch("mintguard.checks.firewall.run_command", return_value=None),
            ):
                results = ejecutar_todos(DISTRO)

        findings = [f for items in results.values() for f in items]
        text = generar_reporte(DISTRO, collect_system_info(), findings)
        self.assertIn("Reporte de seguridad", text)


if __name__ == "__main__":
    unittest.main()
