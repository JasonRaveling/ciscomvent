# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Control-socket request policy: who may run a command, and with what.

The README promises two tiers -- group membership for anything scoped to the
current VPN session, root for anything that persists to /etc. The socket mode
enforces the first and cannot express the second, so dispatch enforces it
against the uid the kernel reports for the peer.

These tests exercise the gate directly. They do not go over a socket, because
the point is the decision rather than the transport, and a test process cannot
choose to be uid 0.
"""

from __future__ import annotations

import pytest

from ciscomvent.config import Config
from ciscomvent.model import VpnState
from ciscomvent.daemon import (
    MAX_SESSION_GRANTS,
    ROOT_ONLY,
    Daemon,
    SessionGrants,
    checked_scope,
)

NOBODY = 1000
"""Some unprivileged caller who is nonetheless in the socket group."""


@pytest.fixture
def daemon():
    return Daemon(config=Config(), dry_run=True)


# -- the root tier -----------------------------------------------------------


@pytest.mark.parametrize("command", sorted(ROOT_ONLY))
def test_persisting_commands_are_refused_to_an_unprivileged_caller(daemon, command):
    """Group membership used to be enough for these. Both write
    /etc/ciscomvent/config.json through the root daemon, so they survived a
    reboot and handed over standing control of routing and firewall policy."""
    with pytest.raises(PermissionError, match="needs root"):
        daemon.dispatch(command, {"scope": "lan:wlp0s20f3", "enabled": True}, NOBODY)


def test_standing_approval_is_refused_to_an_unprivileged_caller(daemon):
    with pytest.raises(PermissionError, match="needs root"):
        daemon.dispatch("approve", {"scope": "docker:x", "always": True}, NOBODY)


@pytest.mark.parametrize("command", sorted(ROOT_ONLY))
def test_persisting_commands_are_allowed_to_root(daemon, command):
    daemon._authorize(command, {}, 0)  # does not raise


def test_standing_approval_is_allowed_to_root(daemon):
    daemon._authorize("approve", {"scope": "docker:x", "always": True}, 0)


# -- the group tier ----------------------------------------------------------


@pytest.mark.parametrize("command", ["status", "reconcile", "restart"])
def test_session_commands_stay_open_to_the_socket_group(daemon, command):
    """Reaching the socket already proved group membership; none of these
    grants anything that outlives the VPN session, so nothing more is asked."""
    daemon._authorize(command, {}, NOBODY)


def test_session_approval_stays_open_to_the_socket_group(daemon):
    """The tray applet's main job, and it must keep working without sudo."""
    daemon._authorize("approve", {"scope": "docker:x", "always": False}, NOBODY)
    daemon._authorize("approve", {"scope": "docker:x"}, NOBODY)


# -- failing closed ----------------------------------------------------------


def test_an_unknown_uid_is_not_root(daemon):
    """peer_uid returns None when the kernel would not vouch for the peer.
    Reading that as permission would make an unreadable credential better than
    a readable one."""
    with pytest.raises(PermissionError, match="needs root"):
        daemon.dispatch("set-automation", {"automation": "auto"}, None)


def test_a_caller_that_supplies_no_uid_at_all_is_refused(daemon):
    """The parameter defaults to None precisely so that a future caller which
    forgets to pass it fails closed instead of silently gaining root."""
    with pytest.raises(PermissionError, match="needs root"):
        daemon.dispatch("set-scope", {"scope": "lan:x", "enabled": True})


def test_the_request_body_cannot_grant_itself_root(daemon):
    """uid is an argument, never a field read out of the message."""
    with pytest.raises(PermissionError, match="needs root"):
        daemon.dispatch(
            "set-automation", {"automation": "auto", "uid": 0, "root": True}, NOBODY
        )


# -- what the client is told -------------------------------------------------


def test_status_reports_the_callers_tier(daemon, monkeypatch):
    """So the GUI can grey out what it may not do instead of offering a button
    that fails. Advisory only -- the gate above is what enforces it."""
    seen = []
    monkeypatch.setattr(
        Daemon, "snapshot", lambda self, uid=None: seen.append(uid) or {"caller_is_root": uid == 0}
    )

    assert daemon.dispatch("status", {}, 0) == {"caller_is_root": True}
    assert daemon.dispatch("status", {}, NOBODY) == {"caller_is_root": False}
    assert seen == [0, NOBODY]


# -- scope names -------------------------------------------------------------
#
# Caller-supplied strings used to be accepted verbatim and kept -- in memory
# for a session grant, in /etc/ciscomvent/config.json for a standing one.
# Nothing reaches a shell, so this is not injection defence: it stops arbitrary
# junk accumulating in a root daemon and on the root filesystem.


@pytest.mark.parametrize(
    "name",
    [
        "docker:ciscomvent-test-net",
        "docker:my_network.1",
        "lan:wlp0s20f3",
        "libvirt:virbr0",
    ],
)
def test_real_scope_names_are_accepted(name):
    assert checked_scope(name) == name


@pytest.mark.parametrize(
    "name",
    [
        "",
        None,
        42,
        ["docker:x"],
        "docker:",
        "nosuchkind:x",
        "docker",
        "no-colon-at-all",
        "docker:-leading-dash",
        "docker:x y",
        "docker:x\n" + "A" * 100,
        "docker:" + "x" * 200,
    ],
)
def test_junk_is_refused(name):
    with pytest.raises(ValueError):
        checked_scope(name)


def test_a_bad_scope_never_reaches_the_grant_set(daemon):
    with pytest.raises(ValueError):
        daemon.dispatch("approve", {"scope": "x" * 500}, NOBODY)
    assert daemon.grants.granted == set()


def test_session_grants_are_capped(daemon):
    """Validation bounds the shape of a name, not how many a caller invents.
    This set is the one thing on the session tier that grows."""
    grants = SessionGrants()
    for i in range(MAX_SESSION_GRANTS):
        grants.grant(f"docker:net{i}")

    with pytest.raises(ValueError, match="too many session grants"):
        grants.grant("docker:one-too-many")

    # Re-approving something already granted is not growth, so it still works.
    grants.grant("docker:net0")
    assert len(grants.granted) == MAX_SESSION_GRANTS


# -- putting a decision off ---------------------------------------------------

VPN_UP = VpnState(
    devices=("cscotun0",),
    addresses=("192.168.224.199",),
    captured_prefixes=(),
    has_default_route=True,
)
VPN_DOWN = VpnState(
    devices=(), addresses=(), captured_prefixes=(), has_default_route=False
)


def test_dismissal_stays_open_to_the_socket_group(daemon):
    """Weaker than the session approval beside it: it withholds a claim and
    cannot install one, so the worst a group member does with it is silence a
    prompt they could have answered outright."""
    daemon.dispatch("dismiss", {"scope": "docker:net"}, NOBODY)
    assert daemon.grants.dismissed == {"docker:net"}


def test_dismissing_never_claims_anything():
    """The whole argument for leaving this on the group tier. A dismissed scope
    has to stay exactly as blocked as it was."""
    grants = SessionGrants()
    grants.dismiss("docker:net")

    assert not grants.allows("docker:net", Config())


def test_approving_a_dismissed_scope_clears_the_dismissal():
    """Otherwise a scope could be granted and still counted as put off."""
    grants = SessionGrants()
    grants.dismiss("docker:net")
    grants.grant("docker:net")

    assert grants.granted == {"docker:net"}
    assert grants.dismissed == set()


def test_dismissals_last_only_the_session():
    """"Not now" means this session; the next connect has to ask again."""
    grants = SessionGrants()
    grants.sync(VPN_UP)
    grants.dismiss("docker:net")

    grants.sync(VPN_DOWN)
    assert grants.dismissed == set()


def test_dismissals_are_capped_like_grants():
    """A second unbounded session set would reopen exactly what capping the
    first one closed."""
    grants = SessionGrants()
    for i in range(MAX_SESSION_GRANTS):
        grants.dismiss(f"docker:net{i}")

    with pytest.raises(ValueError, match="too many session dismissals"):
        grants.dismiss("docker:one-too-many")

    grants.dismiss("docker:net0")  # already dismissed, so not growth


def test_a_bad_scope_never_reaches_the_dismissed_set(daemon):
    with pytest.raises(ValueError):
        daemon.dispatch("dismiss", {"scope": "x" * 500}, NOBODY)
    assert daemon.grants.dismissed == set()
