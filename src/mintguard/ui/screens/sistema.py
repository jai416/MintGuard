"""Hardening audit screen (read-only: the machine is never modified)."""

from __future__ import annotations

from mintguard.checks.hardening import comprobar_sistema
from mintguard.core.distro import DistroInfo
from mintguard.core.prioritizer import Finding
from mintguard.ui.screens.base import BaseCheckScreen


class SystemScreen(BaseCheckScreen):
    TITLE = "Sistema"
    check_title = "Endurecimiento del sistema"
    check_source = "sistema"
    check_hint = (
        "Audita el kernel, el hardware, las reglas de sudo, AppArmor y la\n"
        "persistencia. Solo lectura: nada se cambia, solo se informa.\n"
        "Pulsa Enter o el botón para ejecutar el chequeo."
    )

    def _check(self, distro: DistroInfo) -> list[Finding]:
        return comprobar_sistema(distro)
