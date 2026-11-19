"""MintGuard Textual application and navigation."""

from __future__ import annotations

from typing import Callable

from textual import work
from textual.app import App, get_system_commands_provider
from textual.binding import Binding
from textual.command import DiscoveryHit, Hit, Hits, Provider

from mintguard.checks import ejecutar_todos
from mintguard.core.checkrun import CheckRun
from mintguard.core.distro import DistroInfo, detect_distro
from mintguard.core.prioritizer import Finding
from mintguard.core.system import SystemInfo, collect_system_info
from mintguard.ui.screens.dashboard import DashboardScreen
from mintguard.ui.screens.help import HelpScreen, ayuda_texto
from mintguard.ui.screens.network import NetworkScreen
from mintguard.ui.screens.permissions import PermissionsScreen
from mintguard.ui.screens.report import ReportScreen
from mintguard.ui.screens.services import ServicesScreen
from mintguard.ui.screens.sistema import SystemScreen
from mintguard.ui.screens.updates import UpdatesScreen

SCREENS_BY_NAME: dict[str, type] = {
    "inicio": DashboardScreen,
    "updates": UpdatesScreen,
    "network": NetworkScreen,
    "permissions": PermissionsScreen,
    "services": ServicesScreen,
    "sistema": SystemScreen,
    "report": ReportScreen,
}

_SCREEN_TITLES: dict[str, str] = {
    "inicio": "Inicio",
    "updates": "Actualizaciones",
    "network": "Red",
    "permissions": "Permisos",
    "services": "Servicios",
    "sistema": "Sistema",
    "report": "Reporte",
}


def _navigate_command(app: "MintGuardApp", screen_name: str) -> Callable[[], None]:
    def command() -> None:
        app.action_show(screen_name)

    return command


class MintGuardCommands(Provider):
    """MintGuard commands for the built-in palette (ctrl+p)."""

    async def discover(self) -> Hits:
        for label_text, command, help_text in self._items():
            yield DiscoveryHit(label_text, command, help=help_text)

    async def search(self, query: str) -> Hits:
        matcher = self.matcher(query)
        for label_text, command, help_text in self._items():
            score = matcher.match(label_text)
            if score > 0:
                yield Hit(score, matcher.highlight(label_text), command, help=help_text)

    def _items(self) -> list[tuple[str, Callable[[], None], str]]:
        app = self.app
        items: list[tuple[str, Callable[[], None], str]] = []
        for screen_name, title in _SCREEN_TITLES.items():
            items.append(
                (
                    f"Ir a: {title}",
                    _navigate_command(app, screen_name),
                    f"Pantalla {title}",
                )
            )
        items.append(
            (
                "Ejecutar todos los chequeos",
                lambda: app.action_run_all_checks(),
                "Actualizaciones + red + permisos + servicios",
            )
        )
        items.append(
            (
                "Actualizar datos del sistema",
                lambda: app.action_refresh_data(),
                "Relee la información ligera del sistema",
            )
        )
        return items


class MintGuardApp(App):
    TITLE = "MintGuard"
    SUB_TITLE = "Seguridad ligera, 100% en español"

    CSS = """
    Screen {
        layout: vertical;
    }
    #hero {
        margin: 0 1;
        padding: 1 2;
        border: round #414868;
        background: #16161e;
    }
    #cards {
        /* 4 columns x 2 rows: 5 check cards (the 5th goes on the second
           row). With "4 1" the extra card landed outside the grid and was
           rendered with size 0 (invisible). */
        grid-size: 4 2;
        grid-rows: auto;
        grid-columns: 1fr 1fr 1fr 1fr;
        grid-gutter: 0 1;
        /* auto: cards keep their natural height instead of being squeezed
           to zero at 80x24 (the audit measured height=1 for the grid). */
        height: auto;
        margin: 0 1;
    }
    .card {
        padding: 1;
        border: round #414868;
        background: #16161e;
    }
    #priorities {
        height: auto;
        margin: 0 1;
        padding: 0 1;
        border: round #414868;
        background: #16161e;
    }
    #hint {
        height: 1;
        margin: 0 2 1 2;
        color: #565f89;
    }
    #bar {
        height: 3;
        margin: 0 1;
    }
    #actions {
        height: 3;
        margin: 0 1;
    }
    #actions Button {
        width: auto;
        margin-right: 1;
    }
    #run, #gen, #save {
        width: auto;
    }
    #loading {
        display: none;
        width: auto;
        height: 1;
        margin-top: 1;
        margin-left: 1;
    }
    #status {
        width: 1fr;
        height: 3;
        padding: 0 1;
        content-align: center middle;
        color: #a9b1d6;
    }
    #table {
        height: 2fr;
        margin: 1;
        border: round #414868;
        background: #16161e;
    }
    #detail {
        height: 1fr;
        margin: 0 1 1 1;
        padding: 0 1;
        border: round #414868;
        background: #16161e;
        # On short terminals (80x24) the wrapped detail text overflows the
        # panel: without scrolling, the continuation lines of a finding —
        # e.g. "(conteo estimado; con sudo es exacto)" — were clipped out.
        overflow-y: auto;
    }
    #report {
        margin: 1;
        padding: 1 2;
        border: round #414868;
        background: #16161e;
    }
    .card.sev-info, #detail.sev-info, #priorities.sev-info { border: round #565f89; }
    .card.sev-baja, #detail.sev-baja, #priorities.sev-baja { border: round #7aa2f7; }
    .card.sev-media, #detail.sev-media, #priorities.sev-media { border: round #e0af68; }
    .card.sev-alta, #detail.sev-alta, #priorities.sev-alta { border: round #ff9e64; }
    .card.sev-critica, #detail.sev-critica, #priorities.sev-critica { border: round #f7768e; }
    """

    BINDINGS = [
        # show=False: at 80 columns the footer would truncate to uselessness
        # (it was 159 virtual chars). Navigation has its own NavButtons bar
        # on every screen; the keys keep working as shortcuts.
        Binding("d", "show('inicio')", "Inicio", show=False),
        Binding("u", "show('updates')", "Actualizaciones", show=False),
        Binding("n", "show('network')", "Red", show=False),
        Binding("p", "show('permissions')", "Permisos", show=False),
        Binding("s", "show('services')", "Servicios", show=False),
        Binding("k", "show('sistema')", "Sistema", show=False),
        Binding("r", "show('report')", "Reporte", show=False),
        ("t", "run_all_checks", "Ejecutar todos"),
        ("x", "cancel_run_all", "Cancelar"),
        ("q", "quit", "Salir"),
        ("?", "mostrar_ayuda", "Ayuda"),
    ]

    SCREENS = SCREENS_BY_NAME  # registered names for switch_screen()

    # Keep the system commands (quit, theme, keys...) plus ours; replacing
    # App.COMMANDS without get_system_commands_provider drops system commands.
    COMMANDS = {get_system_commands_provider, MintGuardCommands}

    def __init__(self) -> None:
        super().__init__()
        self.theme = "tokyo-night"
        # Detection is cheap: filesystem reads and PATH lookups only.
        self.distro: DistroInfo = detect_distro()
        self.system: SystemInfo = collect_system_info()
        self.findings: dict[str, list[Finding]] = {}
        # Run lifecycle for "run all": a cancelled or restarted run must
        # not publish stale results (same CheckRun pattern as the screens).
        self._run_all_check: CheckRun = CheckRun("all")
        self._run_all_worker = None

    def on_mount(self) -> None:
        # The framework's default screen has no result callbacks, so it must
        # never be popped: push the dashboard on top and navigate by switching.
        self.push_screen("inicio")

    def action_show(self, screen_name: str) -> None:
        target = SCREENS_BY_NAME.get(screen_name)
        if target is None or type(self.screen) is target:
            return
        self.switch_screen(screen_name)

    def action_mostrar_ayuda(self) -> None:
        """'?' abre el overlay de atajos (feedback de Michael y Pedro)."""
        self.push_screen(HelpScreen(ayuda_texto(self)))

    @property
    def run_all_running(self) -> bool:
        """True while the "run all" worker is in flight (dashboard state)."""
        return self._run_all_check.is_running

    def action_run_all_checks(self) -> None:
        token = self._run_all_check.start()
        self._run_all_worker = self._run_all(token)
        # The dashboard must show the "ejecutando…" state right away.
        if isinstance(self.screen, DashboardScreen):
            self.screen._refresh_summary()

    def action_cancel_run_all(self) -> None:
        """Cancel 'run all' without blocking (key x outside check screens)."""
        worker = self._run_all_worker
        if worker is None or not worker.is_running:
            self.notify("No hay chequeo conjunto en curso.", title="MintGuard")
            return
        self._run_all_check.cancel()  # stale threads discard their results
        worker.cancel()
        if isinstance(self.screen, DashboardScreen):
            self.screen._refresh_summary()
        self.notify(
            "Chequeos cancelados: el comando en curso puede tardar un poco; su resultado se descarta.",
            title="MintGuard",
        )

    def action_refresh_data(self) -> None:
        """Re-read the light system info and refresh the dashboard if visible."""
        self.system = collect_system_info()
        if isinstance(self.screen, DashboardScreen):
            self.screen._refresh_summary()
        self.notify("Datos del sistema actualizados.", title="MintGuard")

    @work(thread=True, exclusive=True, group="check-all")
    def _run_all(self, token: object) -> None:
        self.call_from_thread(self.notify, "Ejecutando todos los chequeos… puede tardar un poco.", title="MintGuard")
        try:
            results = ejecutar_todos(self.distro)
        except Exception as exc:  # defensive: keep the UI alive

            def notify_error() -> None:
                # Never leave the run marked as RUNNING: the dashboard
                # would show "ejecutando…" forever and "x" would report
                # nothing in course.
                self._run_all_check.cancel()
                if isinstance(self.screen, DashboardScreen):
                    self.screen._refresh_summary()
                self.notify(f"Error ejecutando los chequeos: {exc}", severity="error", title="MintGuard")

            self.call_from_thread(notify_error)
            return
        if not self._run_all_check.can_publish(token):
            return  # cancelled or restarted while running: discard stale results

        def store_results() -> None:
            # Re-check on the UI thread: a cancel may have landed between
            # the check above and this callback running.
            if not self._run_all_check.publish(token, results):
                return
            self.findings.update(results)
            if isinstance(self.screen, DashboardScreen):
                self.screen._refresh_summary()
            total = sum(len(items) for items in results.values())
            self.notify(f"Chequeos completados: {total} hallazgo(s).", title="MintGuard")

        # Mutate app state on the UI thread, never from the worker thread.
        self.call_from_thread(store_results)
