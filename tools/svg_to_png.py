"""Convierte el SVG de Textual en un PNG (para compartir en redes).

ImageMagick no sabe renderizar el SVG que genera Textual: se come el
cuerpo (los grupos con clip-path y las clases CSS). Este script aplana
el SVG: coordenadas absolutas, colores en línea y una fuente que exista
en el sistema; luego ImageMagick solo tiene que pintar texto.

    .venv/bin/python tools/svg_to_png.py docs/img/inicio-con-hallazgos.svg salida.png
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

SVG_NS = "{http://www.w3.org/2000/svg}"
FONT = "DejaVu Sans Mono"


def _css_fills(svg_text: str) -> dict[str, str]:
    """Color de relleno por clase, del bloque <style>."""
    fills: dict[str, str] = {}
    bloque = re.search(r"<style>(.*?)</style>", svg_text, re.S)
    if not bloque:
        return fills
    for clase, cuerpo in re.findall(r"\.([\w-]+)\s*\{([^}]*)\}", bloque.group(1)):
        color = re.search(r"fill:\s*(#[0-9a-fA-F]{3,8})", cuerpo)
        if color:
            fills[clase] = color.group(1)
    return fills


def _css_sizes(svg_text: str) -> dict[str, str]:
    sizes: dict[str, str] = {}
    bloque = re.search(r"<style>(.*?)</style>", svg_text, re.S)
    if not bloque:
        return sizes
    for clase, cuerpo in re.findall(r"\.([\w-]+)\s*\{([^}]*)\}", bloque.group(1)):
        size = re.search(r"font-size:\s*([\d.]+)px", cuerpo)
        if size:
            sizes[clase] = size.group(1)
    return sizes


def aplanar(svg_path: Path, alto_extra: int = 40) -> str:
    """SVG con texto en coordenadas absolutas, sin clip-path y con estilos en línea."""
    texto = svg_path.read_text(encoding="utf-8")
    fills = _css_fills(texto)
    sizes = _css_sizes(texto)
    root = ET.fromstring(texto)

    # El pie de la app queda justo en el borde: se añade un margen para
    # que la última línea no salga cortada.
    viewbox = root.get("viewBox", "").split()
    if len(viewbox) == 4:
        alto = float(viewbox[3]) + alto_extra
        root.set("viewBox", f"{viewbox[0]} {viewbox[1]} {viewbox[2]} {alto}")
        for hijo in root.iter():
            if hijo.tag.replace(SVG_NS, "") == "rect" and (
                float(hijo.get("width", 0)) > 1000 and float(hijo.get("height", 0)) > 100
            ):
                hijo.set("height", str(alto))

    def recorrer(nodo, dx: float, dy: float) -> None:
        for hijo in list(nodo):
            etiqueta = hijo.tag.replace(SVG_NS, "")
            if etiqueta == "g":
                # ImageMagick no aplica bien el clip-path de un grupo:
                # el grupo entero desaparece. El recorte no hace falta
                # para una captura (el texto ya viene recortado).
                hijo.attrib.pop("clip-path", None)
                transform = hijo.get("transform", "")
                move = re.match(r"translate\(([-\d.]+)[ ,]+([-\d.]+)\)", transform)
                nx = dx + (float(move.group(1)) if move else 0)
                ny = dy + (float(move.group(2)) if move else 0)
                recorrer(hijo, nx, ny)
            elif etiqueta == "text":
                clase = hijo.get("class", "")
                x = hijo.get("x")
                y = hijo.get("y")
                if x is not None:
                    hijo.set("x", str(round(float(x) + dx, 2)))
                if y is not None:
                    hijo.set("y", str(round(float(y) + dy, 2)))
                hijo.attrib.pop("clip-path", None)
                hijo.attrib.pop("textLength", None)
                if "fill" not in hijo.attrib and clase in fills:
                    hijo.set("fill", fills[clase])
                hijo.set("font-family", FONT)
                hijo.set("font-size", sizes.get(clase, "20"))
                hijo.set("xml:space", "preserve")
            elif etiqueta == "rect":
                # Los fondos de fila llevan el color en su clase y, como
                # los textos, viven dentro de los grupos desplazados: sin
                # sumarle el desplazamiento quedan desalineados una fila.
                clase = hijo.get("class", "")
                if "fill" not in hijo.attrib and clase in fills:
                    hijo.set("fill", fills[clase])
                if hijo.get("x") is not None:
                    hijo.set("x", str(round(float(hijo.get("x")) + dx, 2)))
                if hijo.get("y") is not None:
                    hijo.set("y", str(round(float(hijo.get("y")) + dy, 2)))
            elif etiqueta in ("defs", "style"):
                continue
            else:
                recorrer(hijo, dx, dy)

    recorrer(root, 0, 0)

    ET.register_namespace("", "http://www.w3.org/2000/svg")
    return ET.tostring(root, encoding="unicode")


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("uso: svg_to_png.py entrada.svg salida.png", file=sys.stderr)
        return 2
    origen, destino = Path(argv[1]), Path(argv[2])
    if not origen.exists():
        print(f"No existe: {origen}", file=sys.stderr)
        return 2
    if not shutil.which("convert"):
        print("Falta ImageMagick (convert)", file=sys.stderr)
        return 2

    with tempfile.NamedTemporaryFile("w", suffix=".svg", delete=False, encoding="utf-8") as tmp:
        tmp.write(aplanar(origen))
        plano = tmp.name
    try:
        subprocess.run(
            [
                "convert",
                "-background",
                "#16161e",
                plano,
                "-resize",
                "1400x",
                str(destino),
            ],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as exc:
        print(exc.stderr.decode("utf-8", "replace")[:500], file=sys.stderr)
        return 1
    finally:
        Path(plano).unlink(missing_ok=True)
    print(f"{destino} ({destino.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
