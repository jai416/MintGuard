"""Public API of the checks package."""

from __future__ import annotations

from mintguard.core.distro import DistroInfo
from mintguard.core.prioritizer import Finding
from mintguard.checks.network import comprobar_red
from mintguard.checks.permissions import comprobar_permisos
from mintguard.checks.services import comprobar_servicios
from mintguard.checks.updates import comprobar_actualizaciones

CHECKS: dict[str, callable] = {
    "updates": comprobar_actualizaciones,
    "network": comprobar_red,
    "permissions": comprobar_permisos,
    "services": comprobar_servicios,
}


def ejecutar_todos(distro: DistroInfo) -> dict[str, list[Finding]]:
    """Run every check on demand and group findings by module."""
    return {source: list(check(distro)) for source, check in CHECKS.items()}
