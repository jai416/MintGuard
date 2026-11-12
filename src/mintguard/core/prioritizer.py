"""Finding model and risk prioritization."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


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
