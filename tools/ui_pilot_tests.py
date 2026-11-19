"""UI regression tests with the Textual pilot (~45 s headless).

Run standalone or via tools/smoke_ui.py / tools/verify.sh (which run
them at the end):

    .venv/bin/python tools/ui_pilot_tests.py

They live in tools/ (NOT tests/) on purpose: every run_test boots the
whole headless app and this hardware needs ~7-12 s per test, which would
slow the fast unit suite down. Coverage: the per-screen check path (the
smoke only exercised the app-level "run all" route — that blind spot is
where the "Screen has no call_from_thread" crash lived), the
cancel→rerun race, the report screen and the dashboard priorities panel.
"""

import asyncio
import threading
import unittest
from unittest import mock

from textual.widgets import Button

from mintguard.core.prioritizer import Finding, Severidad
from mintguard.ui.app import MintGuardApp
from mintguard.ui.screens.report import _ruta_reporte
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
                self.assertFalse(screen._check_run.is_running)
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
        fake = [
            Finding(
                title="hallazgo secreto",
                severity=Severidad.ALTA,
                evidence=[f"elemento {i}" for i in range(40)],
                source="updates",
            )
        ]
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

            # Scroll con teclado (feedback de Michael): con 40 elementos de
            # evidencia el informe desborda, así que ↑/↓ y PgUp/PgDn tienen
            # que moverlo de verdad.
            scroll = screen.query_one("#report-scroll")
            scroll.scroll_to(y=0, animate=False)
            await pilot.pause()
            await pilot.press("down")
            await pilot.pause()
            self.assertGreater(scroll.scroll_offset.y, 0, "las flechas no mueven el reporte")
            await pilot.press("pageup")
            await pilot.pause()
            self.assertEqual(scroll.scroll_offset.y, 0, "PgUp no vuelve al tope")

            # Formato del reporte (feedback de Michael): texto plano por
            # defecto (sin ##), 'f' alterna a Markdown (.md).
            self.assertNotIn("## ", screen._report_text)
            await screen.action_alternar_formato()
            await pilot.pause()
            self.assertEqual(screen._report_formato, "markdown")
            self.assertIn("## Hallazgos", screen._report_text)
            self.assertTrue(str(_ruta_reporte("texto")).endswith(".txt"))
            self.assertTrue(str(_ruta_reporte("markdown")).endswith(".md"))


class DashboardPrioritiesTests(unittest.IsolatedAsyncioTestCase):
    async def test_onboarding_findings_and_running_states(self):
        # The dashboard must answer three questions: how do I start (no
        # findings), what did it find and what do I do first (findings),
        # and what is happening right now (run-all in flight).
        app = MintGuardApp()
        async with app.run_test(size=(100, 34)) as pilot:
            await pilot.pause()
            dashboard = app.screen
            priorities = dashboard.query_one("#priorities")

            def text() -> str:
                content = priorities.content
                return getattr(content, "plain", str(content))

            self.assertIn("Sin ejecutar todavía", text())
            self.assertIn("Ejecutar todos los chequeos", text())

            # Finished checks: top finding + its recommendation shown.
            app.findings["network"] = [
                Finding(
                    title="Firewall instalado pero no activo",
                    severity=Severidad.ALTA,
                    detail="d",
                    suggestion="Actívalo: `sudo ufw enable`",
                    source="network",
                )
            ]
            app.findings["updates"] = [
                Finding(
                    title="3 actualización(es) disponibles (apt)",
                    severity=Severidad.BAJA,
                    detail="d",
                    suggestion="Aplica con `sudo apt upgrade`",
                    source="updates",
                )
            ]
            dashboard._refresh_summary()
            await pilot.pause()
            summary = text()
            self.assertIn("Firewall instalado pero no activo", summary)
            self.assertIn("sudo ufw enable", summary)  # the recommendation
            self.assertIn("tecla r", summary)  # pointer to the full report
            self.assertTrue(priorities.has_class("sev-alta"))
            # The ALTA priority must render before the BAJA one.
            self.assertLess(
                summary.index("Firewall instalado"),
                summary.index("3 actualización(es)"),
            )

            # Run-all in flight: says so and the button reflects it.
            app._run_all_check.start()
            dashboard._refresh_summary()
            await pilot.pause()
            self.assertIn("Ejecutando los chequeos", text())
            self.assertTrue(dashboard.query_one("#run-all").disabled)
            app._run_all_check.cancel()


if __name__ == "__main__":
    unittest.main()
