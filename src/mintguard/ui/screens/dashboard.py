"""Dashboard screen: light system summary (no heavy work)."""

from __future__ import annotations

from rich.text import Text
from textual import events
from textual.app import ComposeResult
from textual.containers import Grid, Horizontal
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Static

from mintguard.core.prioritizer import priorizar
from mintguard.core.system import collect_system_info
from mintguard.ui.widgets.nav import MouseButton, NavButtons
from mintguard.ui.widgets.severity import (
    GOOD,
    MUTED,
    SOFT,
    TEXT,
    accent_color,
    apply_severity_class,
    chip,
    count_line,
    label,
    risk_gauge,
    worst_severity_name,
)

_CHECK_CARDS = (
    ("updates", "Actualizaciones", "Paquetes y parches de seguridad pendientes"),
    ("network", "Red", "Puertos, firewall y exposición real"),
    ("permissions", "Permisos", "UID 0, sudo, SSH y archivos críticos"),
    ("services", "Servicios", "Servicios systemd habilitados al arranque"),
    ("sistema", "Sistema", "Kernel, hardware, sudoers y persistencia"),
)


def _all_findings(app) -> list:  # noqa: ANN001 - avoids a circular import
    return [finding for items in app.findings.values() for finding in items]


def build_hero_text(app) -> Text:  # noqa: ANN001 - avoids a circular import
    distro = app.distro
    system = app.system
    if distro is None or system is None:
        return Text("Recopilando información del sistema…", style=f"italic {MUTED}")
    manager = distro.package_manager.name if distro.package_manager else "no detectado"
    distro_label = distro.name
    if distro.version and distro.version not in distro.name:
        distro_label = f"{distro.name} {distro.version}"
    text = Text()
    text.append(distro_label, style=f"bold {TEXT}")
    text.append(f"  ·  {manager} · kernel {system.kernel} ({system.arch})", style=SOFT)
    text.append(
        f"\n{system.cpu_model or 'CPU n/d'} · {system.cpu_count} núcleos"
        f" · {system.ram_total_mb} MB · encendido {system.uptime_text or 'n/d'}",
        style=SOFT,
    )
    mac = distro.mac_module or "ninguno"
    firewall = distro.firewall_tool or "no detectado"
    text.append(
        f"\nsystemd {'sí' if distro.has_systemd else 'no'} · MAC {mac} · firewall {firewall}",
        style=SOFT,
    )
    # Compact on purpose: at 80x24 every saved row keeps the cards visible.
    findings = _all_findings(app)
    text.append("\nRiesgo global  ", style=f"bold {SOFT}")
    text.append_text(risk_gauge(findings))
    text.append(" · Hallazgos ", style=f"bold {SOFT}")
    text.append_text(count_line(findings))
    return text


def build_card_text(app, source: str, description: str) -> Text:  # noqa: ANN001
    findings = app.findings.get(source)
    text = Text()
    if findings is None:
        text.append("◌ sin ejecutar", style=f"italic {MUTED}")
        text.append(f"\n{description}", style=MUTED)
        return text
    if not findings:
        text.append("✔ sin hallazgos", style=f"bold {GOOD}")
    else:
        text.append(f"{len(findings)} hallazgo(s)  ", style=f"bold {TEXT}")
        worst = worst_severity_name(findings)
        if worst:
            text.append(label(worst), style=f"bold {accent_color(worst)}")
    text.append(f"\n{description}", style=MUTED)
    return text


_PRIORITIES_LIMIT = 3
_SUGGESTION_LIMIT = 44


def _shorten(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def build_priorities_text(app) -> Text:  # noqa: ANN001 - avoids a circular import
    """The action plan: what MintGuard found and what to do first.

    Three states: nothing run yet (tells the user how to start), the
    run-all in flight (says what is happening and how long apt takes),
    and findings (top prioritized, each with its recommendation).
    """
    if app.run_all_running:
        text = Text()
        text.append("⏳ Ejecutando los chequeos…", style=f"bold {TEXT}")
        text.append(
            " con apt la simulación puede tardar ~30 s; pulsa x para cancelar.",
            style=MUTED,
        )
        return text
    findings = _all_findings(app)
    if not findings:
        text = Text()
        text.append("Sin ejecutar todavía.", style=f"bold {TEXT}")
        text.append(
            " Pulsa «▶ Ejecutar todos los chequeos» (o la tecla t) y aquí verás "
            "qué encontró MintGuard y qué hacer primero, ordenado por prioridad.",
            style=MUTED,
        )
        return text
    ordered = priorizar(findings)
    text = Text()
    for finding in ordered[:_PRIORITIES_LIMIT]:
        text.append_text(chip(finding.severity.name))
        text.append(" ")
        text.append(finding.title, style=f"bold {TEXT}")
        if finding.suggestion:
            text.append(" — ", style=MUTED)
            text.append(_shorten(finding.suggestion, _SUGGESTION_LIMIT), style=SOFT)
        text.append("\n")
    tail: list[str] = []
    remaining = len(ordered) - _PRIORITIES_LIMIT
    if remaining > 0:
        tail.append(f"…y {remaining} hallazgo(s) más")
    tail.append("informe completo con todas las sugerencias: tecla r (Reporte)")
    text.append(" · ".join(tail), style=MUTED)
    return text


class DashboardScreen(Screen):
    TITLE = "Inicio"

    BINDINGS = [("f5", "refresh_info", "Refrescar datos")]

    def compose(self) -> ComposeResult:
        yield Header()
        yield NavButtons()
        yield Static(id="hero")
        with Horizontal(id="actions"):
            yield MouseButton("▶ Ejecutar todos los chequeos", id="run-all", variant="primary")
            yield MouseButton("⟳ Actualizar datos", id="refresh")
        yield Static(id="priorities")
        with Grid(id="cards"):
            for source, _, description in _CHECK_CARDS:
                yield Static(id=f"card-{source}", classes="card")
        yield Static(
            "Chequeos solo bajo demanda · todo se puede usar con el mouse · ctrl+p paleta de comandos · x cancela",
            id="hint",
        )
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "run-all":
            self.app.action_run_all_checks()
        elif event.button.id == "refresh":
            self.app.action_refresh_data()

    def on_mount(self) -> None:
        self._refresh_summary()

    def on_screen_resume(self, event: events.ScreenResume) -> None:
        """Refresh the summary every time the dashboard becomes current."""
        self.query_one(NavButtons).mark_current("inicio")
        self._refresh_summary()

    def on_click(self, event: events.Click) -> None:
        """Cards are clickable: jump to that check's screen."""
        widget_id = getattr(event.widget, "id", None)
        if widget_id and widget_id.startswith("card-"):
            self.app.action_show(widget_id.removeprefix("card-"))

    def action_refresh_info(self) -> None:
        self.app.action_refresh_data()

    def _refresh_summary(self) -> None:
        try:
            hero = self.query_one("#hero", Static)
            hero.border_title = "Sistema"
            hero.update(build_hero_text(self.app))
            priorities = self.query_one("#priorities", Static)
            priorities.border_title = "Prioridades — qué hacer primero"
            priorities.update(build_priorities_text(self.app))
            apply_severity_class(priorities, worst_severity_name(_all_findings(self.app)))
            for source, name, description in _CHECK_CARDS:
                card = self.query_one(f"#card-{source}", Static)
                card.border_title = name
                card.update(build_card_text(self.app, source, description))
                findings = self.app.findings.get(source)
                worst = worst_severity_name(findings) if findings is not None else None
                apply_severity_class(card, worst)
            # While "run all" is in flight the button is the running state.
            self.query_one("#run-all", MouseButton).disabled = self.app.run_all_running
        except Exception as exc:  # defensive: never break the screen render
            self.query_one("#hero", Static).update(Text(f"No se pudo mostrar el resumen: {exc!r}"))
