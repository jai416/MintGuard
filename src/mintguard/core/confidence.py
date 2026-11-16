"""Señales y confianza de un hallazgo (todo local, sin modelos).

Un hallazgo no es solo una severidad: es una severidad **apoyada** en
señales concretas. Este módulo guarda esas señales y de ahí sale la
confianza:

- **Alta**: solo señales a favor → el hallazgo se sostiene entero.
- **Media**: señales a favor y en contra → la severidad es defendible,
  pero hay matiz, y hay que decirlo.
- **Baja**: solo señales en contra → el hallazgo se apoya en poco y
  puede ser un falso positivo.

La confianza **no** es una segunda opinión sobre la severidad: sale de
las mismas entradas que la severidad ya usó (la naturaleza de la
interfaz, el contexto esperado, el estado del firewall, el binario
verificado en `/proc`), así que las dos cosas no pueden contradecirse:
la confianza explica la severidad, no la vuelve a calcular.

Y si un hallazgo no tiene señales, no se inventa una confianza: se
muestra tal cual. Mejor sin dato que con un dato inventado.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class SignalDirection(str, Enum):
    """Sentido de una señal: apoya el hallazgo o lo contradice."""

    FOR = "a favor"
    AGAINST = "en contra"


@dataclass(frozen=True)
class Signal:
    """Una razón comprobable a favor o en contra de un hallazgo."""

    text: str
    direction: SignalDirection

    @classmethod
    def for_(cls, text: str) -> "Signal":
        """Señal que apoya el hallazgo."""
        return cls(text=text, direction=SignalDirection.FOR)

    @classmethod
    def against(cls, text: str) -> "Signal":
        """Señal que contradice el hallazgo (puede ser un falso positivo)."""
        return cls(text=text, direction=SignalDirection.AGAINST)


class Confidence(str, Enum):
    """Confianza en un hallazgo, según sus señales."""

    ALTA = "Alta"
    MEDIA = "Media"
    BAJA = "Baja"

    @property
    def label(self) -> str:
        return self.value


def evaluar_confianza(signals: list[Signal]) -> Confidence | None:
    """Confianza según las señales; None si el hallazgo no aporta señales."""
    a_favor = any(signal.direction is SignalDirection.FOR for signal in signals)
    en_contra = any(signal.direction is SignalDirection.AGAINST for signal in signals)
    if a_favor and not en_contra:
        return Confidence.ALTA
    if a_favor and en_contra:
        return Confidence.MEDIA
    if en_contra:
        return Confidence.BAJA
    return None


def resumen_confianza(signals: list[Signal]) -> str:
    """Frase corta para la interfaz: cuántas señales hay a favor y en contra."""
    a_favor = sum(1 for signal in signals if signal.direction is SignalDirection.FOR)
    en_contra = sum(1 for signal in signals if signal.direction is SignalDirection.AGAINST)
    if not a_favor and not en_contra:
        return ""
    if a_favor and en_contra:
        return f"{a_favor} a favor, {en_contra} en contra"
    if a_favor:
        return f"{a_favor} a favor"
    return f"{en_contra} en contra"
