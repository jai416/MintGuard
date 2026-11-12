"""Clean plain-text report generation (no sensitive data)."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from mintguard.core.distro import DistroInfo
from mintguard.core.prioritizer import Finding, priorizar, resumen, riesgo_global
from mintguard.core.system import SystemInfo

_EVIDENCE_LIMIT = 10


def generar_reporte(distro: DistroInfo, system: SystemInfo, findings: list[Finding]) -> str:
    findings_sorted = priorizar(findings)
    counts = resumen(findings_sorted)
    manager = distro.package_manager.name if distro.package_manager else "no detectado"

    lines = [
        "Reporte de seguridad — MintGuard",
        f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "",
        "## Sistema",
        f"- Distribución: {distro.name}"
        + (f" {distro.version}" if distro.version and distro.version not in distro.name else ""),
        f"- Gestor de paquetes: {manager}",
        f"- Kernel: {system.kernel} ({system.arch})",
        f"- CPU: {system.cpu_model or 'n/d'} ({system.cpu_count} núcleos)",
        f"- RAM: {system.ram_total_mb} MB",
        f"- systemd: {'sí' if distro.has_systemd else 'no'}"
        f" | MAC: {distro.mac_module or 'ninguno'}"
        f" | Firewall: {distro.firewall_tool or 'no detectado'}",
        "",
        "## Resumen",
        f"- Riesgo global: {riesgo_global(findings_sorted)}",
    ]
    active_counts = [f"{label}: {count}" for label, count in counts.items() if count]
    lines.append(f"- Hallazgos: {', '.join(active_counts) if active_counts else 'ninguno'}")
    lines += ["", "## Hallazgos"]

    if not findings_sorted:
        lines.append("Sin hallazgos: todavía no se ha ejecutado ningún chequeo.")
        lines += ["", "Generado por MintGuard (chequeos ejecutados bajo demanda)."]
        return "\n".join(lines)

    for finding in findings_sorted:
        lines.append(f"### [{finding.severity.name}] {finding.title}")
        if finding.detail:
            lines.append(finding.detail)
        for item in finding.evidence[:_EVIDENCE_LIMIT]:
            lines.append(f"- {item}")
        if len(finding.evidence) > _EVIDENCE_LIMIT:
            lines.append(f"- … y {len(finding.evidence) - _EVIDENCE_LIMIT} más")
        if finding.suggestion:
            lines.append(f"Sugerencia: {finding.suggestion}")
        lines.append("")
    lines.append("Generado por MintGuard (chequeos ejecutados bajo demanda).")
    return "\n".join(lines)


def guardar_reporte(texto: str, ruta: Path) -> Path:
    ruta.write_text(texto + "\n", encoding="utf-8")
    return ruta
