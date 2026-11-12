"""Mouse-first navigation bar: clickable buttons to open each screen."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Button

_NAV_ITEMS = (
    ("inicio", "Inicio"),
    ("updates", "Actualizaciones"),
    ("network", "Red"),
    ("permissions", "Permisos"),
    ("services", "Servicios"),
    ("report", "Reporte"),
)


class MouseButton(Button):
    """Mouse-only button: can_focus=False so Enter never lands on it.

    Textual gives focus to the first focusable widget on a screen; a
    focusable nav button would swallow the Enter key of screens that
    promise Enter = main action (and on the dashboard it would trigger
    "run all" by accident). Clicks keep working (Button._on_click).
    """

    can_focus = False


class NavButtons(Horizontal):
    """Row of buttons to move between screens with the mouse.

    Keyboard bindings keep working; this bar just makes every destination
    reachable without touching the keyboard.
    """

    DEFAULT_CSS = """
    NavButtons {
        height: 3;
        margin: 1 1 0 1;
    }
    NavButtons Button {
        height: 3;
        min-width: 6;
        margin-right: 1;
    }
    """

    def compose(self) -> ComposeResult:
        for name, label_text in _NAV_ITEMS:
            yield MouseButton(label_text, id=f"nav-{name}")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id or ""
        if button_id.startswith("nav-"):
            self.app.action_show(button_id.removeprefix("nav-"))

    def mark_current(self, name: str) -> None:
        """Dim the button of the screen the user is already in."""
        for button in self.query(Button):
            button.disabled = button.id == f"nav-{name}"
