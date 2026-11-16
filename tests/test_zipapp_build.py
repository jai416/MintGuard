"""Tests del constructor del ejecutable único (Reto C).

No construye el `.pyz` (eso lo corre quien lo vaya a usar); comprueba la
lógica que decide qué dependencias van dentro y qué versión se incrusta.
Un parser roto aquí produce un ejecutable que no arranca, así que se
comprueba el parsing de nombres, el extra de linkify y que cada
dependencia calculada exista de verdad en el entorno.
"""

import importlib.metadata as md
import importlib.util
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent

_especificacion = importlib.util.spec_from_file_location(
    "build_zipapp", RAIZ / "tools" / "build_zipapp.py"
)
build_zipapp = importlib.util.module_from_spec(_especificacion)
_especificacion.loader.exec_module(build_zipapp)


class NombreDeRequisitoTests(unittest.TestCase):
    def test_ignora_comparadores_y_modificadores(self):
        # mdurl~=0.1.0 partió por separadores y dejó pegado el `~`.
        parsear = build_zipapp._nombre_de_requisito
        self.assertEqual(parsear("mdurl~=0.1.0"), "mdurl")
        self.assertEqual(parsear("rich (>=14.2.0)"), "rich")
        self.assertEqual(parsear("Pygments (>=2.19.2,<3.0.0)"), "Pygments")
        self.assertEqual(parsear("typing_extensions>=4.0"), "typing_extensions")

    def test_no_come_el_extra_ni_los_espacios(self):
        parsear = build_zipapp._nombre_de_requisito
        self.assertEqual(parsear("markdown-it-py[linkify] (>=2.1.0)"), "markdown-it-py")
        self.assertEqual(parsear("tree-sitter (>=0.25.0)"), "tree-sitter")

    def test_vacio_cuando_no_hay_nombre(self):
        self.assertEqual(build_zipapp._nombre_de_requisito("(>=1.0)"), "")


class DependenciasTests(unittest.TestCase):
    def test_textual_y_su_arbol_estan(self):
        dependencias = build_zipapp.dependencias()
        for nombre in ("textual", "rich", "pygments", "markdown-it-py", "mdurl"):
            with self.subTest(nombre=nombre):
                self.assertIn(nombre, dependencias)

    def test_el_extra_linkify_no_se_pierde(self):
        # linkify-it-py lo pide el EXTRA de markdown-it-py, no textual: si el
        # constructor no lo resuelve, el ejecutable muere al importar.
        self.assertIn("linkify-it-py", build_zipapp.dependencias())

    def test_los_extras_syntax_no_entran(self):
        dependencias = build_zipapp.dependencias()
        self.assertFalse([n for n in dependencias if n.startswith("tree-sitter")])

    def test_cada_dependencia_esta_instalada(self):
        for nombre in build_zipapp.dependencias():
            with self.subTest(nombre=nombre):
                md.distribution(nombre)  # si falta, PackageNotFoundError

    def test_no_hay_nombres_repetidos(self):
        self.assertEqual(len(build_zipapp.dependencias()), len(set(build_zipapp.dependencias())))


class VersionTests(unittest.TestCase):
    def test_version_de_pyproject_con_formato_semver(self):
        self.assertRegex(build_zipapp._version_de_pyproject(), r"^\d+\.\d+\.\d+$")

    def test_la_version_del_paquete_no_difiere(self):
        # Un número a pelo en __init__.py se quedó viejo una vez (0.2.0 vs 0.3.0).
        import mintguard

        self.assertEqual(mintguard.__version__, build_zipapp._version_de_pyproject())


if __name__ == "__main__":
    unittest.main()
