"""Unit tests for the check-run state machine (the stale-result guard).

The UI pilot tests cover the wiring; these cover the race rules
themselves: a cancelled or superseded worker's late results must never
be published over a newer run.
"""

import unittest

from mintguard.core.checkrun import CheckRun, RunStatus
from mintguard.core.prioritizer import Finding, Severidad


def _finding(title: str = "h") -> Finding:
    return Finding(title=title, severity=Severidad.MEDIA, source="updates")


class CheckRunTests(unittest.TestCase):
    def test_starts_idle(self):
        run = CheckRun("updates")
        self.assertIs(run.status, RunStatus.IDLE)
        self.assertFalse(run.is_running)
        self.assertIsNone(run.results)

    def test_start_returns_unique_tokens_and_marks_running(self):
        run = CheckRun("updates")
        first = run.start()
        self.assertTrue(run.is_running)
        second = run.start()
        self.assertIsNot(first, second)
        self.assertTrue(run.is_running)

    def test_publish_with_live_token(self):
        run = CheckRun("updates")
        token = run.start()
        findings = [_finding()]
        self.assertTrue(run.publish(token, findings))
        self.assertIs(run.status, RunStatus.DONE)
        self.assertEqual(run.results, findings)
        self.assertFalse(run.is_running)
        self.assertIsNone(run.token)

    def test_stale_token_after_new_start_is_rejected(self):
        # The cancel→rerun race: A is superseded by B; A's late results
        # must be discarded and must not stop B from publishing later.
        run = CheckRun("updates")
        old = run.start()
        new = run.start()
        self.assertFalse(run.can_publish(old))
        self.assertFalse(run.publish(old, [_finding("viejo")]))
        self.assertTrue(run.is_running)
        self.assertTrue(run.publish(new, [_finding("nuevo")]))

    def test_cancel_discards_late_results(self):
        run = CheckRun("updates")
        token = run.start()
        run.cancel()
        self.assertIs(run.status, RunStatus.CANCELLED)
        self.assertFalse(run.can_publish(token))
        self.assertFalse(run.publish(token, [_finding()]))
        self.assertIsNone(run.results)

    def test_stale_publish_does_not_overwrite_results(self):
        run = CheckRun("updates")
        old = run.start()
        new = run.start()
        self.assertTrue(run.publish(new, [_finding("nuevo")]))
        self.assertFalse(run.publish(old, [_finding("viejo")]))
        self.assertEqual(run.results[0].title, "nuevo")

    def test_cancel_when_idle_or_done_is_noop(self):
        run = CheckRun("updates")
        run.cancel()
        self.assertIs(run.status, RunStatus.IDLE)
        token = run.start()
        run.publish(token, [])
        run.cancel()
        self.assertIs(run.status, RunStatus.DONE)

    def test_can_start_again_after_cancel_or_done(self):
        run = CheckRun("updates")
        run.start()
        run.cancel()
        self.assertTrue(run.is_running is False)
        run.start()
        self.assertTrue(run.is_running)
        run.publish(run.token, [])
        run.start()
        self.assertTrue(run.is_running)

    def test_generic_results_type_is_kept(self):
        # App._run_all publishes a dict of findings per source.
        run = CheckRun("all")
        token = run.start()
        self.assertTrue(run.publish(token, {"updates": [_finding()]}))
        self.assertEqual(run.results, {"updates": [_finding()]})


if __name__ == "__main__":
    unittest.main()
