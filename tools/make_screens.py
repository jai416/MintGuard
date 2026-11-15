"""Regenerate the SVG screenshots in docs/img/ for the README (~35 s).

    .venv/bin/python tools/make_screens.py
"""

import asyncio
import os
import sys
from pathlib import Path

from mintguard.ui.app import MintGuardApp

SIZE = (120, 38)
OUT = Path(__file__).resolve().parent.parent / "docs" / "img"


async def main() -> int:
    os.makedirs(OUT, exist_ok=True)
    app = MintGuardApp()
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        app.save_screenshot("inicio.svg", path=str(OUT))

        await pilot.press("t")
        expected = {"updates", "network", "permissions", "services"}
        for _ in range(700):
            if set(app.findings) >= expected:
                break
            await asyncio.sleep(0.5)
        else:
            print("checks never finished", file=sys.stderr)
            return 1

        # Back to the dashboard WITH findings: the priorities panel
        # (what it found and what to do first) is the README's money shot.
        await pilot.press("d")
        await pilot.pause()
        app.save_screenshot("inicio-con-hallazgos.svg", path=str(OUT))

        await pilot.press("u")
        await pilot.pause()
        app.save_screenshot("actualizaciones.svg", path=str(OUT))

        await pilot.press("n")
        await pilot.pause()
        app.save_screenshot("red.svg", path=str(OUT))

        # La pantalla nueva: auditoría de endurecimiento (Sistema).
        await pilot.press("k")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        for _ in range(120):
            if app.findings.get("sistema"):
                break
            await asyncio.sleep(0.25)
        await pilot.pause()
        app.save_screenshot("sistema.svg", path=str(OUT))

        await pilot.press("r")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        app.save_screenshot("reporte.svg", path=str(OUT))

    print("saved:", sorted(p.name for p in OUT.glob("*.svg")))
    return 0


sys.exit(asyncio.run(main()))
