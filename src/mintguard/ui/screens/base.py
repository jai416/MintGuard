"""Base screen shared by all on-demand check screens: table + detail panel."""

from __future__ import annotations

from rich.text import Text
from textual import events, work
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import Button, DataTable, Footer, Header, LoadingIndicator, Static

from mintguard.core.distro import DistroInfo
from mintguard.core.prioritizer import Finding, Severidad, resumen
from mintguard.ui.widgets.severity import (
    GOOD,
    MUTED,
    SOFT,
    TEXT,
    accent_color,
    chip,
    css_class,
    label,
    worst_severity_name,
)

_EVIDENCE_LIMIT = 10


class BaseCheckScreen(Screen):
    """Pantalla con un chequeo que solo se ejecuta cuando el usuario lo pide."""

    check_title: str = "Chequeo"
    check_hint: str = "El chequeo no se ejecuta al abrir la pantalla: pulsa Enter o el botón."
    check_running_note: str = ""
    check_source: str = ""

    def _check(self, distro: DistroInfo) -> list[Finding]:
        raise NotImplementedError

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="bar"):
            yield Button("▶ Ejecutar", id="run", variant="primary")
            yield LoadingIndicator(id="loading")
            yield Static("", id="status")
        yield DataTable(id="table")
        yield Static("", id="detail")
        yield Footer()

    def on_mount(self) -> None:
        # Prefix all private state with `check_`: MessagePump owns `_running`
        # (it backs is_running); assigning it from on_mount broke the screen
        # with a cryptic SignalError from Screen._on_mount.
        self._check_findings: list[Finding] = []
        self._check_worker = None
        self._check_running = False
        self._check_cancel_requested = False
        table = self.query_one("#table", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_columns("Severidad", "Hallazgo")
        cached = self.app.findings.get(self.check_source)
        if cached is not None:
            self._populate(cached)
        else:
            self._set_status(Text(self.check_hint, style=f"italic {MUTED}"))

    def on_screen_resume(self, event: events.ScreenResume) -> None:
        """Screens registered by name are reused, not re-mounted: refresh the
        table from the app cache every time this screen becomes current."""
        if self._check_running:
            return
        cached = self.app.findings.get(self.check_source)
        if cached is not None:
            self._populate(cached)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "run":
            self.action_run_check()

    BINDINGS = [
        ("enter", "run_check", "Ejecutar"),
        ("x", "cancel_check", "Cancelar"),
    ]

    def action_run_check(self) -> None:
        if self._check_running:
            return
        button = self.query_one("#run", Button)
        loading = self.query_one("#loading", LoadingIndicator)
        self._check_running = True
        self._check_cancel_requested = False
        self._check_worker = self._ejecutar(button, loading)

    def action_cancel_check(self) -> None:
        """Cancel without blocking: the worker thread is marked, results discarded.

        The underlying command (e.g. the apt simulation) may keep running until
        it finishes; the UI is responsive again immediately.
        """
        if not self._check_running:
            return
        self._check_cancel_requested = True
        self._check_running = False
        if self._check_worker is not None:
            try:
                self._check_worker.cancel()
            except Exception:  # defensive: cancel must never break the UI
                pass
        self.query_one("#loading", LoadingIndicator).display = False
        self.query_one("#run", Button).disabled = False
        self._set_status(
            Text(
                "Chequeo cancelado. El comando en curso puede tardar un poco en terminar; su resultado se descarta.",
                style=f"italic {MUTED}",
            )
        )

    @work(thread=True, exclusive=True, group="check")
    def _ejecutar(self, button: Button, loading: LoadingIndicator) -> None:
        def start() -> None:
            button.disabled = True
            loading.display = True
            message = "Ejecutando chequeo…"
            if self.check_running_note:
                message = f"Ejecutando chequeo… {self.check_running_note}"
            self._set_status(Text(message, style=f"italic {MUTED}"))

        self.call_from_thread(start)
        try:
            results = self._check(self.app.distro)
        except Exception as exc:  # defensive: keep the UI alive
            results = [
                Finding(
                    title="Error durante el chequeo",
                    severity=Severidad.BAJA,
                    detail=str(exc),
                    source=self.check_source,
                )
            ]
        if self._check_cancel_requested:
            return  # results discarded; the cancel action already restored the UI

        def finish() -> None:
            if self._check_cancel_requested:
                return
            self._check_running = False
            loading.display = False
            button.disabled = False
            self.app.findings[self.check_source] = results
            self._populate(results)
            counts = resumen(results)
            active = ", ".join(f"{label(k)} {v}" for k, v in counts.items() if v)
            self.app.notify(
                f"Chequeo completado — {active if active else 'sin hallazgos'}",
                title=self.check_title,
            )

        self.call_from_thread(finish)

    # --- rendering helpers (UI thread only) ---------------------------------

    def _populate(self, findings: list[Finding]) -> None:
        self._check_findings = list(findings)
        table = self.query_one("#table", DataTable)
        table.clear()
        for finding in self._check_findings:
            table.add_row(chip(finding.severity.name), Text(finding.title))
        self._refresh_status()
        self._apply_severity_class(worst_severity_name(self._check_findings))
        detail = self.query_one("#detail", Static)
        if self._check_findings:
            table.focus()
            table.move_cursor(row=0)
            self._show_detail(self._check_findings[0])
        else:
            detail.update(Text("Sin hallazgos: todo bien por aquí.", style=f"bold {GOOD}"))

    def _refresh_status(self) -> None:
        counts = resumen(self._check_findings)
        active = ", ".join(f"{label(k)} {v}" for k, v in counts.items() if v)
        status = Text()
        if not self._check_findings:
            status.append("Sin hallazgos", style=f"bold {GOOD}")
        else:
            status.append(f"{len(self._check_findings)} hallazgo(s)  ", style=f"bold {TEXT}")
            worst = worst_severity_name(self._check_findings)
            if worst:
                status.append(label(worst), style=f"bold {accent_color(worst)}")
        if active:
            status.append(f"   ({active})", style=MUTED)
        self._set_status(status)

    def _show_detail(self, finding: Finding) -> None:
        detail = Text()
        detail.append_text(chip(finding.severity.name))
        detail.append("  ")
        detail.append(finding.title, style=f"bold {TEXT}")
        if finding.detail:
            detail.append(f"\n{finding.detail}")
        for item in finding.evidence[:_EVIDENCE_LIMIT]:
            detail.append(f"\n  • {item}", style=SOFT)
        if len(finding.evidence) > _EVIDENCE_LIMIT:
            detail.append(f"\n  … y {len(finding.evidence) - _EVIDENCE_LIMIT} más", style=MUTED)
        if finding.suggestion:
            detail.append("\nSugerencia: ", style=f"bold #7aa2f7")
            detail.append(finding.suggestion)
        self.query_one("#detail", Static).update(detail)

    def _apply_severity_class(self, worst: str | None) -> None:
        detail = self.query_one("#detail", Static)
        for cls in ("sev-none", "sev-info", "sev-baja", "sev-media", "sev-alta", "sev-critica"):
            detail.remove_class(cls)
        detail.add_class("sev-none" if worst is None else css_class(worst))

    def _set_status(self, text: Text) -> None:
        self.query_one("#status", Static).update(text)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        index = event.cursor_row
        if 0 <= index < len(self._check_findings):
            self._show_detail(self._check_findings[index])
