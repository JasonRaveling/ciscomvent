# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Debouncing and session-grant lifetime."""

from __future__ import annotations

from ciscomvent.config import Automation, Config
from ciscomvent.daemon import SessionGrants
from ciscomvent.model import VpnState
from ciscomvent.monitor import Debouncer


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def make(quiet=1.5, maximum=10.0):
    clock = FakeClock()
    fired = []
    debouncer = Debouncer(
        callback=fired.append, quiet=quiet, maximum=maximum, clock=clock
    )
    return debouncer, clock, fired


def test_nothing_fires_without_events():
    debouncer, clock, fired = make()
    clock.advance(100)
    assert debouncer.fire_if_due() is False
    assert fired == []


def test_does_not_fire_during_the_quiet_period():
    debouncer, clock, _ = make()
    debouncer.record()
    clock.advance(1.0)
    assert debouncer.fire_if_due() is False


def test_fires_once_the_burst_settles():
    debouncer, clock, fired = make()
    debouncer.record()
    clock.advance(2.0)
    assert debouncer.fire_if_due() is True
    assert fired == [1]


def test_a_burst_collapses_into_one_callback():
    """A VPN connect produces dozens of route messages; reconciling per message
    would be wasteful and would race with the client still installing routes."""
    debouncer, clock, fired = make()
    for _ in range(40):
        debouncer.record()
        clock.advance(0.1)
    clock.advance(2.0)
    debouncer.fire_if_due()
    assert fired == [40]


def test_sustained_churn_cannot_starve_reconciliation():
    """Without the maximum, a client churning faster than the quiet period
    would defer reconciliation forever."""
    debouncer, clock, fired = make(quiet=1.5, maximum=5.0)
    for _ in range(100):
        debouncer.record()
        clock.advance(0.2)
        if debouncer.fire_if_due():
            break
    assert fired, "should have fired via the maximum"


def test_taking_a_burst_resets_the_window():
    debouncer, clock, fired = make()
    debouncer.record()
    clock.advance(2.0)
    debouncer.fire_if_due()
    assert debouncer.pending == 0
    assert debouncer.fire_if_due() is False


def test_grants_clear_when_the_tunnel_drops():
    """Approval is per VPN session. Disconnecting must not carry an approval
    into the next connection."""
    grants = SessionGrants()
    up = VpnState(devices=("cscotun0",), addresses=("192.168.224.199",))

    grants.sync(up)
    grants.grant("docker:ciscomvent-test-net")
    assert grants.allows("docker:ciscomvent-test-net", Config())

    grants.sync(VpnState())
    assert not grants.allows("docker:ciscomvent-test-net", Config())


def test_grants_clear_when_the_tunnel_address_changes():
    """A reconnect gets a new client address, which is a new session."""
    grants = SessionGrants()
    grants.sync(VpnState(devices=("cscotun0",), addresses=("192.168.224.199",)))
    grants.grant("docker:ciscomvent-test-net")

    grants.sync(VpnState(devices=("cscotun0",), addresses=("192.168.224.7",)))
    assert not grants.allows("docker:ciscomvent-test-net", Config())


def test_grants_survive_events_within_one_session():
    """Cisco reinstalls routes repeatedly while connected; re-prompting on each
    would make confirm mode unusable."""
    grants = SessionGrants()
    up = VpnState(devices=("cscotun0",), addresses=("192.168.224.199",))
    grants.sync(up)
    grants.grant("docker:ciscomvent-test-net")

    for _ in range(10):
        grants.sync(up)
    assert grants.allows("docker:ciscomvent-test-net", Config())


def test_auto_mode_allows_without_any_grant():
    grants = SessionGrants()
    assert grants.allows("docker:anything", Config(automation=Automation.AUTO))
