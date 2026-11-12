"""Tests for the report generator, especially its privacy guarantees."""

import tempfile
import unittest
from pathlib import Path

from mintguard.core.distro import DistroInfo, PackageManager
from mintguard.core.prioritizer import Finding, Severidad
from mintguard.core.system import SystemInfo
from mintguard.reporting.reporter import generar_reporte, guardar_reporte


def _sample():
    distro = DistroInfo(
        distro_id="linuxmint",
        name="Linux Mint 22.3",
        version="22.3",
        package_manager=PackageManager(name="apt", path="/usr/bin/apt"),
        has_systemd=True,
        mac_module="AppArmor",
        firewall_tool="UFW",
    )
    system = SystemInfo(
        hostname="host-secreto",
        kernel="6.8.0-40-generic",
        arch="x86_64",
        cpu_model="CPU Test",
        cpu_count=2,
        ram_total_mb=8000,
        uptime_text="0d 1h",
    )
    findings = [
        Finding(
            title="41 actualización(es) disponibles (apt)",
            severity=Severidad.MEDIA,
            detail="41 paquete(s) con actualizaciones disponibles.",
            evidence=["paquete-1", "paquete-2"],
            source="updates",
        ),
        Finding(title="Servicio SSH expuesto en la red", severity=Severidad.ALTA, source="network"),
    ]
    return distro, system, findings


class GenerarReporteTests(unittest.TestCase):
    def test_structure(self):
        distro, system, findings = _sample()
        text = generar_reporte(distro, system, findings)
        self.assertIn("Reporte de seguridad", text)
        self.assertIn("## Sistema", text)
        self.assertIn("## Resumen", text)
        self.assertIn("## Hallazgos", text)
        self.assertIn("[ALTA]", text)
        self.assertIn("[MEDIA]", text)

    def test_no_hostname_in_report(self):
        distro, system, findings = _sample()
        text = generar_reporte(distro, system, findings)
        self.assertNotIn("host-secreto", text)

    def test_distro_version_not_duplicated(self):
        distro, system, findings = _sample()
        text = generar_reporte(distro, system, findings)
        self.assertIn("- Distribución: Linux Mint 22.3\n", text)
        self.assertNotIn("Linux Mint 22.3 22.3", text)

    def test_empty_findings(self):
        distro, system, findings = _sample()
        text = generar_reporte(distro, system, [])
        self.assertIn("Sin hallazgos", text)


class GuardarReporteTests(unittest.TestCase):
    def test_writes_utf8_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = guardar_reporte("contenido ñ", Path(tmp) / "r.txt")
            self.assertEqual(path.read_text(encoding="utf-8"), "contenido ñ\n")


if __name__ == "__main__":
    unittest.main()
