"""Network exposure check screen."""

from __future__ import annotations

from mintguard.checks.network import comprobar_red
from mintguard.core.distro import DistroInfo
from mintguard.core.prioritizer import Finding
from mintguard.ui.screens.base import BaseCheckScreen


class NetworkScreen(BaseCheckScreen):
    title = "Red"
    check_title = "Exposición de red"
    check_source = "network"
    check_hint = (
        "Lista los puertos en escucha con `ss` y evalúa su exposición real:\n"
        "la severidad pondera el estado del firewall detectado. Asume posible\n"
        "NAT perimetral (un router delante no es visible desde la máquina).\n"
        "Pulsa Enter o el botón para ejecutar el chequeo."
    )

    def _check(self, distro: DistroInfo) -> list[Finding]:
        return comprobar_red(distro)
