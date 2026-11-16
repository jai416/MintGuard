"""Finding model and risk prioritization."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

from mintguard.core.confidence import Confidence, Signal, evaluar_confianza


class Severidad(IntEnum):
    INFO = 0
    BAJA = 1
    MEDIA = 2
    ALTA = 3
    CRITICA = 4


@dataclass
class Finding:
    title: str
    severity: Severidad
    detail: str = ""
    suggestion: str = ""
    evidence: list[str] = field(default_factory=list)
    source: str = ""
    # Señales a favor y en contra: la confianza sale de aquí (nunca de
    # una cuenta aparte que pueda contradecir la severidad).
    signals: list[Signal] = field(default_factory=list)

    @property
    def confidence(self) -> Confidence | None:
        """Confianza en el hallazgo según sus señales (None si no tiene)."""
        return evaluar_confianza(self.signals)


def priorizar(findings: list[Finding]) -> list[Finding]:
    """Sort findings from most to least severe (title as tiebreaker)."""
    return sorted(findings, key=lambda f: (-int(f.severity), f.title))


def resumen(findings: list[Finding]) -> dict[str, int]:
    """Count findings per severity label."""
    counts = {severidad.name: 0 for severidad in Severidad}
    for finding in findings:
        counts[finding.severity.name] += 1
    return counts


def riesgo_global(findings: list[Finding]) -> str:
    if not findings:
        return "SIN DATOS"
    return max(findings, key=lambda f: f.severity).severity.name
