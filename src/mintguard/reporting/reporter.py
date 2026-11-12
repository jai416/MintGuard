"""Clean plain-text report generation (no sensitive data)."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from mintguard.core.distro import DistroInfo
from mintguard.core.prioritizer import Finding, priorizar, resumen, riesgo_global
from mintguard.core.system import SystemInfo

_EVIDENCE_LIMIT = 10

# Wildcard addresses are structural, not identifying; concrete ones get masked.
_WILDCARD_ADDRESSES = {"0.0.0.0", "::", "*"}
_IPV4_MASK = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# IPv6 only when it carries a zone, or with 3+ colon groups: plain
# time/date strings ("02:50:03") and wildcards (":::41641") stay intact.
_IPV6_ZONE_MASK = re.compile(r"\b[0-9A-Fa-f:]{6,}%([A-Za-z0-9._-]+)")
_IPV6_MASK = re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){3,6}[0-9A-Fa-f]{1,4}\b")

# In anonymized mode, usernames and full service lists stay out of the report.
_HIDDEN_SOURCES = ("permissions", "services")

_KERNEL_RE = re.compile(r"^\d+\.\d+")


def _mask_concrete_ips(text: str) -> str:
    """Mask identifying addresses; keep wildcards, zones and ports."""
    text = _IPV6_ZONE_MASK.sub(lambda m: f"<ip>%{m.group(1)}", text)
    text = _IPV6_MASK.sub("<ip>", text)
    return _IPV4_MASK.sub(
        lambda m: m.group(0) if m.group(0) in _WILDCARD_ADDRESSES else "<ip>", text
    )


def _anonymized_distro_label(distro: DistroInfo) -> str:
    """Distro name with only the major version ('Linux Mint 22')."""
    name = distro.name
    version = (distro.version or "").split(".", 1)[0]
    if distro.version and distro.version in name:
        name = name.replace(distro.version, "").strip()
    if version and version not in name:
        name = f"{name} {version}".strip()
    return name


def generar_reporte(
    distro: DistroInfo,
    system: SystemInfo,
    findings: list[Finding],
    anonimizado: bool = False,
) -> str:
    findings_sorted = priorizar(findings)
    counts = resumen(findings_sorted)
    manager = distro.package_manager.name if distro.package_manager else "no detectado"

    if anonimizado:
        kernel_match = _KERNEL_RE.match(system.kernel or "")
        kernel = kernel_match.group(0) if kernel_match else "oculto"
        cpu = f"CPU ({system.cpu_count} núcleos)"
        distro_label = _anonymized_distro_label(distro)
    else:
        kernel = system.kernel
        cpu = f"{system.cpu_model or 'n/d'} ({system.cpu_count} núcleos)"
        distro_label = distro.name
        if distro.version and distro.version not in distro.name:
            distro_label = f"{distro.name} {distro.version}"

    lines = [
        "Reporte de seguridad — MintGuard",
        f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        + (" (modo anonimizado)" if anonimizado else ""),
        "",
        "## Sistema",
        f"- Distribución: {distro_label}",
        f"- Gestor de paquetes: {manager}",
        f"- Kernel: {kernel} ({system.arch})",
        f"- CPU: {cpu}",
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
        lines.append(f"### [{finding.severity.name}] {_mask_concrete_ips(finding.title)}")
        if finding.detail:
            lines.append(_mask_concrete_ips(finding.detail))
        if anonimizado and finding.source in _HIDDEN_SOURCES:
            lines.append("- (lista de detalles omitida en modo anonimizado)")
        else:
            for item in finding.evidence[:_EVIDENCE_LIMIT]:
                lines.append(f"- {_mask_concrete_ips(item)}")
            if len(finding.evidence) > _EVIDENCE_LIMIT:
                lines.append(f"- … y {len(finding.evidence) - _EVIDENCE_LIMIT} más")
        if finding.suggestion:
            lines.append(f"Sugerencia: {_mask_concrete_ips(finding.suggestion)}")
        lines.append("")
    lines.append("Generado por MintGuard (chequeos ejecutados bajo demanda).")
    return "\n".join(lines)


def guardar_reporte(texto: str, ruta: Path) -> Path:
    ruta.write_text(texto + "\n", encoding="utf-8")
    return ruta
