"""Headless UI smoke test (integration, ~50 s: runs the real checks and
the pilot regression tests).

Run manually — NOT picked up by `unittest discover` (deliberately, to keep
the unit suite fast):

    .venv/bin/python tools/smoke_ui.py
"""

import asyncio
import sys

from textual.widgets import DataTable

from mintguard.ui.app import SCREENS_BY_NAME, MintGuardApp


async def main() -> int:
    app = MintGuardApp()
    async with app.run_test(size=(100, 34)) as pilot:
        await pilot.pause()
        assert type(app.screen) is SCREENS_BY_NAME["inicio"], type(app.screen)

        # Visit every screen and come back.
        for key in ("u", "n", "p", "s", "r", "d"):
            await pilot.press(key)
            await pilot.pause()
        assert type(app.screen) is SCREENS_BY_NAME["inicio"], type(app.screen)

        # Run every check through the app-level "t" binding.
        expected = {"updates", "network", "permissions", "services"}
        await pilot.press("t")
        for _ in range(700):  # the apt simulation takes ~25 s on slow hardware
            if set(app.findings) >= expected:
                break
            await asyncio.sleep(0.5)
        assert set(app.findings) == expected, app.findings.keys()

        # Updates screen: the table must show the cached findings.
        await pilot.press("u")
        await pilot.pause()
        table = app.screen.query_one("#table", DataTable)
        assert table.row_count == len(app.findings["updates"]), (table.row_count, len(app.findings["updates"]))

        # Report: generated from stored findings, and must never leak the hostname.
        await pilot.press("r")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        report = getattr(app.screen, "_report_text", "")
        assert "Reporte de seguridad" in report
        assert app.system.hostname not in report, app.system.hostname

    # Pilot regression tests (per-screen check path + cancel/rerun race):
    # in their own PROCESS — IsolatedAsyncioTestCase cannot run inside
    # this already-running event loop.
    import subprocess
    from pathlib import Path

    result = subprocess.run(
        [sys.executable, str(Path(__file__).with_name("ui_pilot_tests.py"))]
    )
    if result.returncode != 0:
        print("PILOT TESTS FAILED")
        return result.returncode

    print("SMOKE OK — findings:", {k: len(v) for k, v in app.findings.items()})
    return 0


sys.exit(asyncio.run(main()))
