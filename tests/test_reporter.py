"""Tests for the report generator, especially its privacy guarantees."""

import os
import tempfile
import unittest
from pathlib import Path

from mintguard.core.distro import DistroInfo, PackageManager
from mintguard.core.prioritizer import Finding, Severidad
from mintguard.core.system import SystemInfo
from mintguard.reporting.reporter import _anonymized_ram, generar_reporte, guardar_reporte


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


class MaskingTests(unittest.TestCase):
    """Concrete IPs are masked ALWAYS (normal and anonymized mode)."""

    def _finding_with_evidence(self):
        return Finding(
            title="Servicio expuesto",
            severity=Severidad.ALTA,
            detail="Escucha en 192.168.1.5:80 y 0.0.0.0:8080.",
            evidence=[
                "TCP 192.168.1.5:80",
                "TCP 0.0.0.0:8080",
                "TCP fd7a:5c:d114:6a4a::1%tailscale0:22",
                "TCP fe80::250:56ff:fec0:1%virbr0:53",
            ],
            source="network",
        )

    def _report(self, findings, anonimizado=False):
        distro, system, _ = _sample()
        return generar_reporte(distro, system, findings, anonimizado=anonimizado)

    def test_ipv4_masked_and_wildcard_kept(self):
        for text in (self._report([self._finding_with_evidence()]),):
            self.assertIn("TCP <ip>:80", text)
            self.assertNotIn("192.168.1.5", text)
            self.assertIn("TCP 0.0.0.0:8080", text)
            self.assertIn("Escucha en <ip>:80 y 0.0.0.0:8080.", text)

    def test_ipv6_with_zone_masked_but_zone_kept(self):
        text = self._report([self._finding_with_evidence()])
        self.assertIn("<ip>%tailscale0:22", text)
        self.assertIn("<ip>%virbr0:53", text)
        self.assertNotIn("fd7a:5c", text)
        self.assertNotIn("fe80::250", text)

    def test_masking_applies_in_both_modes(self):
        distro, system, _ = _sample()
        finding = self._finding_with_evidence()
        for anonimizado in (False, True):
            with self.subTest(anonimizado=anonimizado):
                text = generar_reporte(distro, system, [finding], anonimizado=anonimizado)
                self.assertNotIn("192.168.1.5", text)


class AnonimizadoTests(unittest.TestCase):
    def _report(self, findings, distro=None, system=None):
        base_distro, base_system, _ = _sample()
        return generar_reporte(
            distro or base_distro, system or base_system, findings, anonimizado=True
        )

    def test_marker_in_date_line(self):
        self.assertIn("modo anonimizado", self._report([]))

    def test_kernel_reduced_to_major_minor(self):
        text = self._report([])
        self.assertIn("Kernel: 6.8 (x86_64)", text)
        self.assertNotIn("6.8.0-40-generic", text)

    def test_cpu_model_hidden(self):
        text = self._report([])
        self.assertIn("CPU (2 núcleos)", text)
        self.assertNotIn("CPU Test", text)

    def test_distro_reduced_to_major_version(self):
        text = self._report([])
        self.assertIn("- Distribución: Linux Mint 22\n", text)
        self.assertNotIn("22.3", text)

    def test_hidden_sources_omit_evidence(self):
        finding = Finding(
            title="Sudo configurado",
            severity=Severidad.INFO,
            evidence=["usuario-1", "usuario-2"],
            source="permissions",
        )
        text = self._report([finding])
        self.assertNotIn("usuario-1", text)
        self.assertIn("(lista de detalles omitida en modo anonimizado)", text)

    def test_visible_sources_keep_evidence_but_masked(self):
        finding = Finding(
            title="Servicio expuesto",
            severity=Severidad.ALTA,
            evidence=["TCP 10.0.0.2:22"],
            source="network",
        )
        text = self._report([finding])
        self.assertIn("TCP <ip>:22", text)


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

    def test_findings_sorted_by_severity(self):
        # CRITICA must come before ALTA/INFO regardless of input order.
        distro, system, _ = _sample()
        critica = Finding(
            title="critico", severity=Severidad.CRITICA, detail="d", source="network"
        )
        info = Finding(title="info", severity=Severidad.INFO, detail="d", source="network")
        text = generar_reporte(distro, system, [info, critica])
        self.assertLess(text.index("[CRITICA]"), text.index("[INFO]"))

    def test_evidence_truncated_after_ten(self):
        distro, system, _ = _sample()
        finding = Finding(
            title="con evidencia",
            severity=Severidad.MEDIA,
            detail="d",
            evidence=[f"item {i}" for i in range(13)],
            source="network",
        )
        text = generar_reporte(distro, system, [finding])
        self.assertIn("- item 9", text)
        self.assertNotIn("- item 10", text)
        self.assertIn("… y 3 más", text)

    def test_resumen_counts_line(self):
        distro, system, _ = _sample()
        findings = [
            Finding(title="a", severity=Severidad.MEDIA, detail="d", source="network"),
            Finding(title="b", severity=Severidad.MEDIA, detail="d", source="network"),
            Finding(title="c", severity=Severidad.BAJA, detail="d", source="updates"),
        ]
        text = generar_reporte(distro, system, findings)
        self.assertIn("- Hallazgos: BAJA: 1, MEDIA: 2", text)

    def test_suggestion_rendered(self):
        distro, system, _ = _sample()
        finding = Finding(
            title="con sugerencia",
            severity=Severidad.ALTA,
            detail="d",
            suggestion="Haz esto: `algo`",
            source="updates",
        )
        text = generar_reporte(distro, system, [finding])
        self.assertIn("Sugerencia: Haz esto: `algo`", text)

    def test_nat_caveat_always_declared(self):
        # The exposure story must say out loud what MintGuard cannot see
        # from the machine itself: a perimeter NAT in front.
        distro, system, findings = _sample()
        text = generar_reporte(distro, system, findings)
        self.assertIn("NAT perimetral", text)
        self.assertIn("no puede verlo", text)

    def test_anonymized_ram_is_bucketed(self):
        distro, system, findings = _sample()
        text = generar_reporte(distro, system, findings, anonimizado=True)
        self.assertIn("- RAM: 4–8 GB", text)  # sample is 8000 MB
        self.assertNotIn("8000 MB", text)

    def test_anonymized_ram_buckets(self):
        self.assertEqual(_anonymized_ram(1024), "<2 GB")
        self.assertEqual(_anonymized_ram(2049), "2–4 GB")
        self.assertEqual(_anonymized_ram(6144), "4–8 GB")
        self.assertEqual(_anonymized_ram(12288), "8–16 GB")
        self.assertEqual(_anonymized_ram(32768), "16 GB o más")

    def test_loopback_with_zone_masked(self):
        # B1: the old {6,} minimum let `::1%lo` through in the clear.
        finding = Finding(
            title="Servicio local",
            severity=Severidad.INFO,
            detail="Escucha en ::1%lo y ::2%ens3.",
            evidence=["TCP ::1%lo:631", "TCP ::2%ens3:9100"],
            source="network",
        )
        distro, system, _ = _sample()
        text = generar_reporte(distro, system, [finding])
        self.assertIn("<ip>%lo", text)
        self.assertIn("<ip>%ens3", text)
        self.assertNotIn("::1%lo", text)
        self.assertNotIn("::2%ens3", text)


class GuardarReporteTests(unittest.TestCase):
    def test_writes_utf8_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = guardar_reporte("contenido ñ", Path(tmp) / "r.txt")
            self.assertEqual(path.read_text(encoding="utf-8"), "contenido ñ\n")

    def test_owner_only_mode_enforced(self):
        # umask cannot leave the report group/world readable (A5).
        with tempfile.TemporaryDirectory() as tmp:
            path = guardar_reporte("x", Path(tmp) / "r.txt")
            mode = os.stat(path).st_mode & 0o777
            self.assertEqual(mode, 0o600)

    def test_collision_regenerates_name_instead_of_overwriting(self):
        # Two saves in the same second used to silently replace the first.
        with tempfile.TemporaryDirectory() as tmp:
            first = guardar_reporte("primero", Path(tmp) / "r.txt")
            second = guardar_reporte("segundo", first.with_name(first.name))
            self.assertNotEqual(first, second)
            self.assertEqual(first.read_text(encoding="utf-8"), "primero\n")
            self.assertEqual(second.read_text(encoding="utf-8"), "segundo\n")

    def test_never_follows_a_symlink(self):
        # A planted symlink at the target name must not redirect the write.
        with tempfile.TemporaryDirectory() as tmp:
            victim = Path(tmp) / "victima.txt"
            victim.write_text("importante")
            link = Path(tmp) / "r.txt"
            link.symlink_to(victim)
            path = guardar_reporte("nuevo", link)
            self.assertNotEqual(path, link)
            self.assertEqual(victim.read_text(encoding="utf-8"), "importante")
            self.assertEqual(path.read_text(encoding="utf-8"), "nuevo\n")


if __name__ == "__main__":
    unittest.main()
