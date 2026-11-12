"""Enabled services check via systemd (on demand)."""

from __future__ import annotations

import subprocess

from mintguard.core.distro import DistroInfo
from mintguard.core.prioritizer import Finding, Severidad

RISKY_SERVICE_KEYWORDS = ("telnet", "tftp", "rsh", "rlogin", "rexec", "finger")


def enabled_service_names(text: str) -> list[str]:
    """Unit names from `systemctl list-unit-files --no-legend` output."""
    return [line.split()[0] for line in text.splitlines() if line.strip()]


def _run(cmd: list[str], timeout: int = 60) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None


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
    result = _run(
        ["systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-legend", "--no-pager"]
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
    services = enabled_service_names(result.stdout)

    findings: list[Finding] = []
    for service in services:
        lowered = service.lower()
        if any(keyword in lowered for keyword in RISKY_SERVICE_KEYWORDS):
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
