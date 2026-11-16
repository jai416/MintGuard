"""Tests del sistema de confianza: señales a favor / en contra.

La confianza NO es una segunda opinión sobre la severidad: sale de las
mismas entradas que la severidad ya usó. Estos tests comprueban que:

1. las señales se derivan bien (a favor / en contra / mixtas);
2. un hallazgo sin señales NO inventa una confianza;
3. la confianza y la severidad no se contradicen (un hallazgo con señales
   mixtas no se esconde: sigue en la tabla y en el reporte).
"""

import unittest

from mintguard.checks.hardening import check_iommu
from mintguard.core.confidence import (
    Confidence,
    Signal,
    SignalDirection,
    evaluar_confianza,
    resumen_confianza,
)
from mintguard.core.prioritizer import Finding, Severidad
from mintguard.reporting.reporter import generar_reporte


class ConfidenceTests(unittest.TestCase):
    def test_only_for_signals_is_high(self):
        signals = [Signal.for_("Escucha en todas las interfaces")]
        self.assertEqual(evaluar_confianza(signals), Confidence.ALTA)

    def test_only_against_signals_is_low(self):
        signals = [Signal.against("Puede ser normal en este equipo")]
        self.assertEqual(evaluar_confianza(signals), Confidence.BAJA)

    def test_mixed_signals_are_medium(self):
        signals = [Signal.for_("El kernel expone IOMMU"), Signal.against("Es normal aquí")]
        self.assertEqual(evaluar_confianza(signals), Confidence.MEDIA)

    def test_without_signals_there_is_no_confidence(self):
        # Antes de inventar un dato: sin señales, no hay confianza.
        self.assertIsNone(evaluar_confianza([]))

    def test_summary_counts_both_directions(self):
        signals = [
            Signal.for_("a"),
            Signal.for_("b"),
            Signal.against("c"),
        ]
        self.assertEqual(resumen_confianza(signals), "2 a favor, 1 en contra")
        self.assertEqual(resumen_confianza([]), "")

    def test_signal_helpers_set_the_direction(self):
        self.assertIs(Signal.for_("x").direction, SignalDirection.FOR)
        self.assertIs(Signal.against("x").direction, SignalDirection.AGAINST)


class FindingConfidenceTests(unittest.TestCase):
    def test_finding_derives_its_confidence(self):
        finding = Finding(
            title="x",
            severity=Severidad.MEDIA,
            signals=[Signal.for_("a"), Signal.against("b")],
        )
        self.assertEqual(finding.confidence, Confidence.MEDIA)

    def test_finding_without_signals_has_none(self):
        self.assertIsNone(Finding(title="x", severity=Severidad.ALTA).confidence)

    def test_confidence_never_hides_the_finding(self):
        # Una confianza baja NO esconde el hallazgo: sigue en la lista.
        finding = Finding(
            title="Posible falso positivo",
            severity=Severidad.BAJA,
            signals=[Signal.against("Puede que sea normal")],
        )
        self.assertEqual(finding.confidence, Confidence.BAJA)
        self.assertEqual(finding.severity, Severidad.BAJA)


class ReportSignalsTests(unittest.TestCase):
    def _finding(self) -> Finding:
        return Finding(
            title="IOMMU presente pero sin dominios activos",
            severity=Severidad.MEDIA,
            detail="El kernel expone IOMMU.",
            suggestion="Activa VT-d.",
            signals=[
                Signal.for_("El kernel expone IOMMU."),
                Signal.against("Puede ser normal en equipos de consumo."),
            ],
            source="sistema",
        )

    def test_report_shows_confidence_and_signals(self):
        from mintguard.core.distro import DistroInfo, PackageManager
        from mintguard.core.system import SystemInfo

        distro = DistroInfo(
            distro_id="x",
            name="Linux Mint",
            version="22",
            package_manager=PackageManager("apt", "/usr/bin/apt"),
            has_systemd=True,
            mac_module="AppArmor",
            firewall_tool="UFW",
        )
        system = SystemInfo(
            hostname="host",
            kernel="6.8",
            arch="x86_64",
            cpu_model="CPU",
            cpu_count=2,
            ram_total_mb=4000,
            uptime_text="1d 2h",
        )
        text = generar_reporte(distro, system, [self._finding()])
        self.assertIn("Confianza: Media", text)
        self.assertIn("+ El kernel expone IOMMU.", text)
        self.assertIn("- Puede ser normal en equipos de consumo.", text)

    def test_signals_survive_the_anonymized_mode(self):
        # Son texto genérico: no llevan cuentas ni rutas, y son el "por qué".
        from mintguard.core.distro import DistroInfo, PackageManager
        from mintguard.core.system import SystemInfo

        distro = DistroInfo(
            distro_id="x",
            name="Linux Mint",
            version="22",
            package_manager=PackageManager("apt", "/usr/bin/apt"),
            has_systemd=True,
            mac_module="AppArmor",
            firewall_tool="UFW",
        )
        system = SystemInfo(
            hostname="host",
            kernel="6.8",
            arch="x86_64",
            cpu_model="CPU",
            cpu_count=2,
            ram_total_mb=4000,
            uptime_text="1d 2h",
        )
        text = generar_reporte(distro, system, [self._finding()], anonimizado=True)
        self.assertIn("+ El kernel expone IOMMU.", text)
        self.assertIn("Confianza: Media", text)


class HardeningSignalsTests(unittest.TestCase):
    def test_iommu_finding_has_mixed_signals(self):
        import tempfile
        from pathlib import Path
        from unittest import mock

        # Con el directorio vacío: IOMMU presente pero sin dominios.
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch("mintguard.checks.hardening.IOMMU_DIR", Path(tmp)):
                findings = check_iommu()
        self.assertEqual(findings[0].severity, Severidad.MEDIA)
        self.assertEqual(findings[0].confidence, Confidence.MEDIA)
        a_favor = [s for s in findings[0].signals if s.direction is SignalDirection.FOR]
        en_contra = [s for s in findings[0].signals if s.direction is SignalDirection.AGAINST]
        self.assertTrue(a_favor)
        self.assertTrue(en_contra)


if __name__ == "__main__":
    unittest.main()
