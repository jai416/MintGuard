"""Report screen: generate, copy and save a clean text report."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Markdown, Static

from mintguard.reporting.reporter import generar_reporte, guardar_reporte
from mintguard.ui.widgets.severity import MUTED

_PRIVACY_NOTE = (
    "Las IPs concretas se enmascaran; el reporte sí incluye versiones y "
    "servicios que pueden identificar la máquina: revísalo antes de pegarlo "
    "en sitios públicos."
)

_PRIVACY_NOTE_ANON = (
    "Modo anonimizado: IPs enmascaradas, versiones reducidas, CPU oculta y sin "
    "listas de usuarios ni servicios. Revísalo igualmente antes de pegarlo en "
    "sitios públicos."
)


class ReportScreen(Screen):
    title = "Reporte"

    BINDINGS = [
        ("enter", "generar", "Generar"),
        ("a", "alternar_anonimizado", "Anonimizado"),
        ("c", "copiar", "Copiar"),
        ("g", "guardar", "Guardar"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="bar"):
            yield Button("▶ Generar reporte", id="gen", variant="primary")
            yield Static("", id="status")
        yield Markdown(id="report")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "gen":
            self.action_generar()

    def action_generar(self) -> None:
        self._generar(notificar=True)

    def action_alternar_anonimizado(self) -> None:
        self._report_anonimizado = not getattr(self, "_report_anonimizado", False)
        estado = "activado" if self._report_anonimizado else "desactivado"
        if getattr(self, "_report_text", ""):
            self._generar(notificar=False)
            self.app.notify(f"Modo anonimizado {estado}; reporte regenerado.", title="Reporte")
        else:
            self.app.notify(f"Modo anonimizado {estado}.", title="Reporte")

    def _generar(self, notificar: bool) -> None:
        app = self.app
        findings = [finding for findings_list in app.findings.values() for finding in findings_list]
        if not findings:
            app.notify("Primero ejecuta algún chequeo (u, n, p, s o t).", severity="warning", title="Reporte")
            return
        anonimizado = getattr(self, "_report_anonimizado", False)
        report = generar_reporte(app.distro, app.system, findings, anonimizado=anonimizado)
        self._report_text = report
        self.query_one("#report", Markdown).update(report)
        nota = _PRIVACY_NOTE_ANON if anonimizado else _PRIVACY_NOTE
        self.query_one("#status", Static).update(Text(nota, style=f"italic {MUTED}"))
        if notificar:
            app.notify("Reporte generado. Pulsa c para copiarlo o g para guardarlo.", title="Reporte")

    def action_copiar(self) -> None:
        report = getattr(self, "_report_text", "")
        if not report:
            self.app.notify("Genera primero el reporte (Enter).", severity="warning", title="Reporte")
            return
        copy_to_clipboard = getattr(self.app, "copy_to_clipboard", None)
        if copy_to_clipboard is None:
            self.app.notify("El portapapeles no está disponible aquí; usa g para guardarlo.", severity="warning", title="Reporte")
            return
        copy_to_clipboard(report)
        self.app.notify("Reporte copiado al portapapeles.", title="Reporte")

    def action_guardar(self) -> None:
        report = getattr(self, "_report_text", "")
        if not report:
            self.app.notify("Genera primero el reporte (Enter).", severity="warning", title="Reporte")
            return
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = Path.cwd() / f"reporte-mintguard-{stamp}.txt"
        try:
            path = guardar_reporte(report, path)
        except OSError as error:
            self.app.notify(f"No se pudo guardar el reporte: {error}", severity="error", title="Reporte")
            return
        self.app.notify(f"Reporte guardado en {path}", title="Reporte")
