"""UI regression tests with the Textual pilot (~15 s headless).

Run standalone or via tools/smoke_ui.py (which calls them at the end):

    .venv/bin/python tools/ui_pilot_tests.py
    .venv/bin/python -m unittest tools/ui_pilot_tests.py  # also works

They live in tools/ (NOT tests/) on purpose: every run_test boots the
whole headless app and this hardware needs ~7 s per test, which would
slow the fast unit suite down. Coverage note: the smoke only exercised
the App-level "run all" route — that blind spot is where the
"Screen has no call_from_thread" crash lived (running a check from its
own screen killed the whole app).
"""

import asyncio
import threading
import unittest
from unittest import mock

from textual.widgets import Button

from mintguard.core.prioritizer import Finding, Severidad
from mintguard.ui.app import MintGuardApp
from mintguard.ui.screens.updates import UpdatesScreen

STALE = [Finding(title="resultado viejo de A", severity=Severidad.ALTA, source="updates")]
FRESH = [Finding(title="resultado nuevo de B", severity=Severidad.BAJA, source="updates")]


async def _wait_until(predicate, timeout_s: float = 2.0) -> bool:
    """Pump the event loop until predicate() is true (poll, never block)."""
    for _ in range(int(timeout_s / 0.05)):
        if predicate():
            return True
        await asyncio.sleep(0.05)
    return predicate()


async def _wait_event(event: threading.Event, timeout_s: float = 2.0) -> bool:
    """Pump the loop until a threading.Event is set (keeps the UI alive)."""
    for _ in range(int(timeout_s / 0.02)):
        if event.is_set():
            return True
        await asyncio.sleep(0.02)
    return event.is_set()


class PerScreenCheckTests(unittest.IsolatedAsyncioTestCase):
    async def test_check_run_from_its_screen_publishes_findings(self):
        # Regression for the CRITICAL: `self.call_from_thread` does not
        # exist on Screen (only on App); running a check used to kill the
        # app with AttributeError.
        app = MintGuardApp()
        published_evt = threading.Event()
        fake = [Finding(title="hallazgo de prueba", severity=Severidad.MEDIA, source="updates")]

        def fake_check(self, distro):
            published_evt.set()
            return fake

        with mock.patch.object(UpdatesScreen, "_check", fake_check):
            async with app.run_test(size=(100, 34)) as pilot:
                await pilot.pause()
                app.action_show("updates")
                await pilot.pause()
                screen = app.screen
                screen.action_run_check()
                ok = await _wait_until(
                    lambda: app.findings.get("updates") is fake
                )
                self.assertTrue(ok, "el chequeo por pantalla nunca publicó resultados")
                self.assertTrue(published_evt.is_set())
                self.assertFalse(screen._check_running)
                self.assertFalse(screen.query_one("#run", Button).disabled)

    async def test_cancelled_worker_thread_cannot_clobber_a_newer_run(self):
        # HIGH race: Worker.cancel() does not kill the thread. Sequence:
        # A runs (blocked) -> cancel -> B runs (immediate) -> A unblocks.
        # A's late results must be discarded, not published over B's.
        app = MintGuardApp()
        gate_a = threading.Event()  # A waits inside the gate
        reached_a = threading.Event()  # A reached the gate
        done_a = threading.Event()  # A's thread finished its attempt
        calls: list[int] = []

        def fake_check(_self, _distro):
            calls.append(1)
            if len(calls) == 1:
                reached_a.set()
                gate_a.wait(5)
                done_a.set()
                return STALE
            return FRESH

        with mock.patch.object(UpdatesScreen, "_check", fake_check):
            async with app.run_test(size=(100, 34)) as pilot:
                await pilot.pause()
                app.action_show("updates")
                await pilot.pause()
                screen = app.screen
                screen.action_run_check()  # A: blocks in the gate
                self.assertTrue(await _wait_event(reached_a), "A nunca llegó a su chequeo")
                screen.action_cancel_check()
                screen.action_run_check()  # B: returns immediately
                published = await _wait_until(lambda: app.findings.get("updates") == FRESH)
                self.assertTrue(published, "B nunca publicó sus resultados")
                gate_a.set()  # A unblocks NOW and tries to publish stale data
                self.assertTrue(await _wait_event(done_a), "A nunca terminó")
                self.assertEqual(
                    app.findings.get("updates"),
                    FRESH,
                    "el worker cancelado A publicó resultados obsoletos sobre B",
                )


class ReportScreenTests(unittest.IsolatedAsyncioTestCase):
    async def test_generate_and_anonymize_from_screen(self):
        # The report actions are async (Markdown.update returns
        # AwaitComplete) and keep their state in __init__: both the
        # generate path and the anonymize toggle must work from the UI.
        app = MintGuardApp()
        fake = [Finding(title="hallazgo secreto", severity=Severidad.ALTA, source="updates")]
        async with app.run_test(size=(100, 34)) as pilot:
            await pilot.pause()
            app.findings["updates"] = fake
            app.action_show("report")
            await pilot.pause()
            screen = app.screen
            await screen.action_generar()
            await pilot.pause()
            self.assertIn("hallazgo secreto", screen._report_text)
            self.assertIn("NAT perimetral", screen._report_text)
            await screen.action_alternar_anonimizado()
            await pilot.pause()
            self.assertTrue(screen._report_anonimizado)
            # Anonymized report must not leak the concrete finding title? It does
            # keep titles (they are findings, not system data); the system
            # section is what gets reduced — assert the mode flag flipped and
            # the text was regenerated.
            self.assertIn("(modo anonimizado)", screen._report_text)


if __name__ == "__main__":
    unittest.main()
