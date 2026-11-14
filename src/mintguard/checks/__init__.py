"""Public API of the checks package."""

from __future__ import annotations

from collections.abc import Callable

from mintguard.core.distro import DistroInfo
from mintguard.core.prioritizer import Finding, Severidad
from mintguard.checks.hardening import comprobar_sistema
from mintguard.checks.network import comprobar_red
from mintguard.checks.permissions import comprobar_permisos
from mintguard.checks.services import comprobar_servicios
from mintguard.checks.updates import comprobar_actualizaciones

CheckFn = Callable[[DistroInfo], list[Finding]]

CHECKS: dict[str, CheckFn] = {
    "updates": comprobar_actualizaciones,
    "network": comprobar_red,
    "permissions": comprobar_permisos,
    "services": comprobar_servicios,
    "sistema": comprobar_sistema,
}


def ejecutar_todos(distro: DistroInfo) -> dict[str, list[Finding]]:
    """Run every check on demand, isolating failures per check.

    One crashing check must not discard the results of the others:
    each runs in its own try/except and a failure becomes a BAJA
    finding under its own source.
    """
    results: dict[str, list[Finding]] = {}
    for source, check in CHECKS.items():
        try:
            results[source] = list(check(distro))
        except Exception as exc:  # noqa: BLE001 - defensive by design
            results[source] = [
                Finding(
                    title=f"Error en el chequeo {source}",
                    severity=Severidad.BAJA,
                    detail=str(exc),
                    source=source,
                )
            ]
    return results
