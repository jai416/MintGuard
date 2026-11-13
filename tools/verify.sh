#!/usr/bin/env bash
# Puerta de calidad completa de MintGuard (local, sin contenedores):
# suite unittest + smoke UI (incluye las 3 pruebas pilot) + medición de
# arranque. Sale con código !=0 si algo falla.
#
# Uso:  tools/verify.sh
#
# La verificación en otras distros es aparte (requiere podman):
#       .venv/bin/python tools/verify_distro.py
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "== 1/3 Suite unittest =="
.venv/bin/python -m unittest discover -s tests

echo
echo "== 2/3 Smoke UI (chequeos reales + pruebas pilot) =="
.venv/bin/python tools/smoke_ui.py

echo
echo "== 3/3 Medición de arranque =="
.venv/bin/python tools/boot_time.py

echo
echo "VERIFY OK"
echo "Pendiente antes de publicar: pasada manual en un terminal real (mouse +"
echo "tecla) y, para las familias no apt, .venv/bin/python tools/verify_distro.py"
