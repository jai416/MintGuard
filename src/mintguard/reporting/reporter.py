"""Clean plain-text report generation (no sensitive data)."""

from __future__ import annotations

import errno
import os
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
# No \b anchor here: addresses starting with ":" ("::1%lo") have no
# word boundary before them. The pattern only applies when a `%zone`
# exists, so plain times ("02:50:03") can never match.
_IPV6_ZONE_MASK = re.compile(r"[0-9A-Fa-f:]{2,}%([A-Za-z0-9._-]+)")
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


def _anonymized_ram(ram_total_mb: int) -> str:
    """Bucket RAM in anonymized mode: the exact size is a fingerprint vector."""
    gib = ram_total_mb / 1024
    if gib < 2:
        return "<2 GB"
    if gib < 4:
        return "2–4 GB"
    if gib < 8:
        return "4–8 GB"
    if gib < 16:
        return "8–16 GB"
    return "16 GB o más"


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
        ram_label = _anonymized_ram(system.ram_total_mb)
    else:
        kernel = system.kernel
        cpu = f"{system.cpu_model or 'n/d'} ({system.cpu_count} núcleos)"
        distro_label = distro.name
        if distro.version and distro.version not in distro.name:
            distro_label = f"{distro.name} {distro.version}"
        ram_label = f"{system.ram_total_mb} MB"

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
        f"- RAM: {ram_label}",
        f"- systemd: {'sí' if distro.has_systemd else 'no'}"
        f" | MAC: {distro.mac_module or 'ninguno'}"
        f" | Firewall: {distro.firewall_tool or 'no detectado'}",
        "",
        "## Resumen",
        f"- Riesgo global: {riesgo_global(findings_sorted)}",
        (
            "- Nota: la exposición se evalúa desde la propia máquina; un NAT perimetral "
            "delante (router, VPS) puede reducirla y MintGuard no puede verlo."
        ),
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
    """Write the report safely and return the path actually written.

    - Never follows a symlink in the target name (O_NOFOLLOW): a planted
      `reporte-....txt` link cannot redirect the write to another file.
    - Never overwrites (O_EXCL): a same-second collision regenerates the
      name with a counter instead of silently replacing a previous report.
    - Owner-only permissions (0600), enforced after open: umask cannot
      leave it group/world readable, and under sudo it does not end up
      root-owned 0664 in the user's directory.
    """
    target = ruta
    counter = 1
    for _ in range(8):
        try:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except OSError as error:
            if error.errno not in (errno.EEXIST, errno.ELOOP):
                raise
            counter += 1
            target = ruta.with_name(f"{ruta.stem}-{counter}{ruta.suffix}")
            continue
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(texto + "\n")
        return target
    raise OSError("No se encontró un nombre libre para guardar el reporte.")
