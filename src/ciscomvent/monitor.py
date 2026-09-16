# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Netlink event source.

``ip monitor`` is the trigger rather than a device unit, because Secure Client
reinstalls its routes on **every network change**, not only at connect. Binding
to cscotun0 appearing would fire once and miss every subsequent reinstall.

Events are debounced: a single VPN connect produces a burst of dozens of route
messages, and reconciling once per message would be wasteful and racy.
"""

from __future__ import annotations

import subprocess
import threading
import time
from collections.abc import Callable, Iterator

from .iproute import ip_binary

DEBOUNCE_SECONDS = 1.5
"""Quiet period after the last event before reconciling. Long enough to let a
connect burst settle, short enough that recovery still feels immediate."""

MAX_DEBOUNCE_SECONDS = 10.0
"""Cap on how long a sustained event stream can defer reconciliation."""


def watch(objects: str = "route link") -> Iterator[str]:
    """Yield raw netlink event lines. Blocks; runs unprivileged."""
    argv = [ip_binary(), "-4", "monitor", *objects.split()]
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1,
    )
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.strip()
            if line:
                yield line
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


class Debouncer:
    """Collapse a burst of events into one callback.

    Fires ``DEBOUNCE_SECONDS`` after the last event, or ``MAX_DEBOUNCE_SECONDS``
    after the first if events keep arriving -- so a client that churns
    continuously cannot starve reconciliation entirely.
    """

    def __init__(
        self,
        callback: Callable[[int], None],
        quiet: float = DEBOUNCE_SECONDS,
        maximum: float = MAX_DEBOUNCE_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.callback = callback
        self.quiet = quiet
        self.maximum = maximum
        self.clock = clock
        self._first: float | None = None
        self._last: float | None = None
        self._count = 0
        self._lock = threading.Lock()

    def record(self) -> None:
        with self._lock:
            now = self.clock()
            if self._first is None:
                self._first = now
            self._last = now
            self._count += 1

    def due(self) -> bool:
        with self._lock:
            if self._first is None or self._last is None:
                return False
            now = self.clock()
            return (
                now - self._last >= self.quiet
                or now - self._first >= self.maximum
            )

    def take(self) -> int:
        """Consume the pending burst, returning how many events it held."""
        with self._lock:
            count = self._count
            self._first = self._last = None
            self._count = 0
            return count

    def fire_if_due(self) -> bool:
        if not self.due():
            return False
        self.callback(self.take())
        return True

    @property
    def pending(self) -> int:
        with self._lock:
            return self._count
