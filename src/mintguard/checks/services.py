"""Enabled services check via systemd (on demand)."""

from __future__ import annotations

import subprocess

from mintguard.core.commands import resolve_binary, run_command
from mintguard.core.distro import DistroInfo
from mintguard.core.prioritizer import Finding, Severidad

RISKY_SERVICE_KEYWORDS = ("telnet", "tftp", "rsh", "rlogin", "rexec", "finger")


def risky_service_names(services: list[str]) -> list[str]:
    """Service names running legacy remote access, matched by exact stem.

    Matches telnet/telnetd, tftp/tftpd... without substring false
    positives such as `rshim.service`, which merely contains "rsh".
    Templated units (`tftp@.service`) are reduced to their stem too.
    """
    risky: list[str] = []
    for service in services:
        stem = service.split("@", 1)[0].split(".", 1)[0].lower()
        base = stem[:-1] if stem.endswith("d") else stem
        if stem in RISKY_SERVICE_KEYWORDS or base in RISKY_SERVICE_KEYWORDS:
            risky.append(service)
    return risky


def enabled_service_names(text: str) -> list[str]:
    """Unit names from `systemctl list-unit-files --no-legend` output."""
    return [line.split()[0] for line in text.splitlines() if line.strip()]


def _run(cmd: list[str], timeout: int = 60) -> subprocess.CompletedProcess | None:
    return run_command(cmd, timeout)


def comprobar_servicios(distro: DistroInfo) -> list[Finding]:
    if not distro.has_systemd:
        return [
            Finding(
                title="systemd no detectado",
                severity=Severidad.BAJA,
                detail="Sin systemd no se pueden listar servicios habilitados de forma estándar.",
                suggestion="Revisa los scripts de arranque de tu distribución manualmente.",
                source="services",
            )
        ]
    systemctl_path = resolve_binary("systemctl")
    if systemctl_path is None:
        return [
            Finding(
                title="No se pudo consultar systemctl",
                severity=Severidad.BAJA,
                detail="El comando no está disponible en este sistema.",
                source="services",
            )
        ]
    # Absolute path from a standard system directory: under sudo, a PATH
    # lookup would resolve `systemctl` in the inherited user PATH (same
    # rationale as `ss`).
    result = _run(
        [
            systemctl_path,
            "list-unit-files",
            "--type=service",
            "--state=enabled",
            "--no-legend",
            "--no-pager",
        ]
    )
    if result is None:
        return [
            Finding(
                title="No se pudo consultar systemctl",
                severity=Severidad.BAJA,
                detail="El comando no respondió dentro del tiempo límite.",
                source="services",
            )
        ]
    if result.returncode != 0 and not result.stdout.strip():
        # A failed query must never be reported as "0 services enabled".
        return [
            Finding(
                title="No se pudo consultar systemctl",
                severity=Severidad.BAJA,
                detail=f"El comando terminó con error (código {result.returncode}) y sin datos.",
                source="services",
            )
        ]
    services = enabled_service_names(result.stdout)

    findings: list[Finding] = []
    for service in risky_service_names(services):
        findings.append(
            Finding(
                title=f"Servicio inseguro habilitado: {service}",
                severity=Severidad.ALTA,
                detail="Servicio de acceso remoto antiguo habilitado al arranque.",
                suggestion=f"Desactívalo si no lo necesitas: `sudo systemctl disable --now {service}`.",
                evidence=[service],
                source="services",
            )
        )
    findings.append(
        Finding(
            title=f"{len(services)} servicios habilitados al arranque",
            severity=Severidad.INFO,
            detail="Cada servicio habilitado aumenta la superficie de ataque y el tiempo de arranque.",
            suggestion="Desactiva los que no uses: `sudo systemctl disable --now <servicio>`.",
            evidence=services[:50],
            source="services",
        )
    )
    return findings
