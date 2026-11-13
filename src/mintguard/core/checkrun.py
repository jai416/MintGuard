"""One check execution as a small state machine (stale-result guard).

`Worker.cancel()` does not kill the worker thread: a cancelled or
superseded run may still finish later, and its results must never be
published over a newer run. Both `BaseCheckScreen` and `App._run_all`
need exactly this rule; keeping it here makes it unit-testable without
booting the UI (the pilot tests cover the wiring, these tests cover the
race rules themselves).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Generic, TypeVar

ResultsT = TypeVar("ResultsT")


class RunStatus(Enum):
    IDLE = auto()
    RUNNING = auto()
    CANCELLED = auto()
    DONE = auto()


@dataclass
class CheckRun(Generic[ResultsT]):
    """Lifecycle of a single on-demand execution.

    The token is the identity of one run: the worker captures it when
    started and must present it again to publish. `cancel()` and a new
    `start()` invalidate the old token, so late threads discard their
    results instead of clobbering the newer run.
    """

    source: str
    status: RunStatus = RunStatus.IDLE
    token: object | None = None
    results: ResultsT | None = None

    @property
    def is_running(self) -> bool:
        return self.status is RunStatus.RUNNING

    def start(self) -> object:
        """Begin a run; returns the token its worker must carry along."""
        self.token = object()
        self.status = RunStatus.RUNNING
        self.results = None
        return self.token

    def cancel(self) -> None:
        """Mark the current run cancelled; late results become stale.

        No-op when nothing is running (idle or already finished): the
        caller's UI state is authoritative in those cases.
        """
        if self.status is RunStatus.RUNNING:
            self.status = RunStatus.CANCELLED
            self.token = None

    def can_publish(self, token: object) -> bool:
        """True when `token` still belongs to the live run."""
        return self.status is RunStatus.RUNNING and token is self.token

    def publish(self, token: object, results: ResultsT) -> bool:
        """Publish results iff they belong to the live run.

        Returns False for stale tokens (cancelled or superseded runs):
        the caller must discard the results and leave the UI alone.
        """
        if not self.can_publish(token):
            return False
        self.results = results
        self.status = RunStatus.DONE
        self.token = None
        return True
