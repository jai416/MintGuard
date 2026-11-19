"""Help overlay: every shortcut on screen on one panel (`?`).

Feedback de Michael y Pedro: los atajos solo estaban en el pie y en la
paleta, y se perdían. El overlay se arma desde las BINDINGS REALES de la
app y de la pantalla actual (así nunca se desincroniza de los cambios) y
cierra con Esc o '?'.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.text import Text
from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Button, Static
from textual.containers import VerticalScroll

from mintguard.ui.widgets.severity import TEXT

if TYPE_CHECKING:
    from mintguard.ui.app import MintGuardApp

_CLAVE_ANCHO = 13

# Teclas que no son Bindings de la app (viven en la paleta del sistema).
_CURADOS = (("ctrl+p", "Paleta de comandos (temas, salir…)"),)


def _datos(binding: object) -> tuple[str, str, str]:
    """(tecla, descripción, acción) de un Binding o de una tupla antigua."""
    if isinstance(binding, tuple):
        clave = str(binding[0])
        accion = str(binding[1])
        descripcion = str(binding[2]) if len(binding) > 2 else ""
        return clave, descripcion, accion
    return str(binding.key), str(binding.description or ""), str(binding.action)


def ayuda_texto(app: MintGuardApp) -> Text:
    """Atajos reales: navegación (app), generales (app) y los de la pantalla."""
    navegacion: list[tuple[str, str]] = []
    generales: list[tuple[str, str]] = []
    for binding in app.BINDINGS:
        clave, descripcion, accion = _datos(binding)
        if accion.startswith("show("):
            navegacion.append((clave, descripcion))
        else:
            generales.append((clave, descripcion))

    pantalla = app.screen
    de_pantalla = [
        _datos(binding)[:2] for binding in getattr(type(pantalla), "BINDINGS", ())
    ]

    texto = Text()
    texto.append("Ayuda de atajos\n\n", style="bold")
    if navegacion:
        texto.append("Navegación\n", style="bold #7aa2f7")
        for clave, descripcion in navegacion:
            texto.append(f"  {clave:<{_CLAVE_ANCHO}}", style=TEXT)
            texto.append(f"{descripcion}\n")
        texto.append("\n")
    if generales or _CURADOS:
        texto.append("General\n", style="bold #7aa2f7")
        for clave, descripcion in generales:
            texto.append(f"  {clave:<{_CLAVE_ANCHO}}", style=TEXT)
            texto.append(f"{descripcion}\n")
        for clave, descripcion in _CURADOS:
            texto.append(f"  {clave:<{_CLAVE_ANCHO}}", style=TEXT)
            texto.append(f"{descripcion}\n")
        texto.append("\n")
    if de_pantalla:
        titulo = getattr(pantalla, "TITLE", None) or type(pantalla).__name__
        texto.append(f"Pantalla: {titulo}\n", style="bold #7aa2f7")
        for clave, descripcion in de_pantalla:
            texto.append(f"  {clave:<{_CLAVE_ANCHO}}", style=TEXT)
            texto.append(f"{descripcion}\n")
        texto.append("\n")
    texto.append("También hay botones para todo: barra superior y tarjetas del inicio.\n", style="italic")
    texto.append("Esc o ? para cerrar.", style="italic")
    return texto


class HelpScreen(ModalScreen[None]):
    """Overlay de ayuda (tecla '?' en cualquier pantalla)."""

    CSS = """
    HelpScreen {
        align: center middle;
        background: $background 70%;
    }
    #ayuda-caja {
        width: 76;
        max-width: 90%;
        height: auto;
        max-height: 90%;
        border: round $accent;
        background: $surface;
        padding: 1 2;
    }
    """

    BINDINGS = [
        ("escape", "cerrar", "Cerrar"),
        ("?", "cerrar", "Cerrar"),
    ]

    def __init__(self, contenido: Text) -> None:
        super().__init__()
        self._contenido = contenido

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="ayuda-caja"):
            yield Static(self._contenido, id="ayuda-texto")
            yield Button("Cerrar", id="ayuda-cerrar", variant="primary")

    def action_cerrar(self) -> None:
        self.dismiss()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "ayuda-cerrar":
            self.dismiss()
