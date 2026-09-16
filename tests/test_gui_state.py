# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""GUI state reduction. No Qt, so it runs without a display."""

from __future__ import annotations

from ciscomvent.gui.state import Health, summarize, tooltip


def snap(**over) -> dict:
    base = {
        "vpn": {"connected": True, "devices": ["cscotun0"], "tunnel_all": True},
        "config": {"automation": "auto"},
        "scopes": [
            {"name": "docker:ciscomvent-test-net", "enabled_by_default": True},
            {"name": "lan:wlp0s20f3", "enabled_by_default": False},
        ],
        "diagnoses": [
            {
                "scope": "docker:ciscomvent-test-net",
                "device": "br-0123456789ab",
                "state": "healthy",
                "needs_fix": False,
                "note": "all probes route via br-0123456789ab",
            }
        ],
        "pending_approval": [],
        "owned_routes": ["172.18.0.0/16 dev br-0123456789ab"],
        "owned_rules": ["-A OUTPUT -o br-0123456789ab -j ACCEPT"],
    }
    base.update(over)
    return base


def test_no_snapshot_means_daemon_unreachable():
    summary = summarize(None)
    assert summary.health is Health.UNKNOWN
    assert "not reachable" in summary.headline
    assert "ciscomvent.service" in summary.detail


def test_tunnel_down_is_not_a_problem():
    """Nothing to claim while disconnected, so this must not read as an error."""
    summary = summarize(snap(vpn={"connected": False}))
    assert summary.health is Health.OFFLINE
    assert not summary.needs_attention


def test_everything_claimed_is_healthy():
    summary = summarize(snap())
    assert summary.health is Health.HEALTHY
    assert not summary.needs_attention
    assert "1 route(s)" in summary.detail


def test_pending_approval_beats_captured():
    """A scope awaiting approval is also captured. Saying "waiting for you" is
    more useful than saying "captured", which the user cannot act on directly."""
    summary = summarize(
        snap(
            pending_approval=["docker:ciscomvent-test-net"],
            diagnoses=[
                {
                    "scope": "docker:ciscomvent-test-net",
                    "state": "captured",
                    "needs_fix": True,
                    "note": "routes via cscotun0",
                }
            ],
        )
    )
    assert summary.health is Health.PENDING
    assert "docker:ciscomvent-test-net" in summary.detail


def test_captured_but_not_yet_claimed():
    summary = summarize(
        snap(
            owned_routes=[],
            owned_rules=[],
            diagnoses=[
                {
                    "scope": "docker:ciscomvent-test-net",
                    "state": "captured",
                    "needs_fix": True,
                    "note": "routes via cscotun0",
                }
            ],
        )
    )
    assert summary.health is Health.CAPTURED


def test_claimed_but_still_failing_is_distinct_from_captured():
    """These need different reactions: one waits for the daemon, the other
    means the fix is in place and did not work."""
    summary = summarize(
        snap(
            diagnoses=[
                {
                    "scope": "docker:ciscomvent-test-net",
                    "state": "misrouted",
                    "needs_fix": True,
                    "note": "unreachable",
                }
            ]
        )
    )
    assert summary.health is Health.FAILING
    assert summary.needs_attention


def test_disabled_scopes_do_not_drive_health():
    """LAN is off by default; its state must not turn the tray red."""
    summary = summarize(
        snap(
            diagnoses=[
                {
                    "scope": "docker:ciscomvent-test-net",
                    "state": "healthy",
                    "needs_fix": False,
                    "note": "",
                },
                {
                    "scope": "lan:wlp0s20f3",
                    "state": "captured",
                    "needs_fix": True,
                    "note": "captured",
                },
            ]
        )
    )
    assert summary.health is Health.HEALTHY


def test_rows_carry_enabled_flag_from_scopes():
    rows = {r.name: r for r in summarize(snap()).scopes}
    assert rows["docker:ciscomvent-test-net"].enabled is True
    assert rows["docker:ciscomvent-test-net"].marker == "ok"


def test_every_health_has_a_colour_and_headline():
    for health in Health:
        summary = summarize(None)
        object.__setattr__(summary, "health", health)
        assert summary.colour.startswith("#")
        from ciscomvent.gui.state import HEADLINES

        assert HEADLINES[health]


def test_tooltip_mentions_the_tool_and_the_state():
    text = tooltip(summarize(snap()))
    assert "ciscomvent" in text
    assert "reachable" in text


def test_down_bridges_do_not_colour_the_tray():
    """Regression: two empty Docker networks sit DOWN with nothing to reach,
    and reported as captured, which drove the tray to FAILING on a healthy
    system. `verify` had the same bug."""
    summary = summarize(
        snap(
            scopes=[
                {"name": "docker:ciscomvent-test-net", "enabled_by_default": True, "device_up": True},
                {"name": "docker:bridge", "enabled_by_default": True, "device_up": False},
            ],
            diagnoses=[
                {"scope": "docker:ciscomvent-test-net", "state": "healthy", "needs_fix": False, "note": ""},
                {"scope": "docker:bridge", "state": "captured", "needs_fix": True, "note": ""},
            ],
        )
    )
    assert summary.health is Health.HEALTHY
    assert not summary.needs_attention


def test_down_bridge_row_is_marked_idle_not_bad():
    summary = summarize(
        snap(
            scopes=[{"name": "docker:bridge", "enabled_by_default": True, "device_up": False}],
            diagnoses=[
                {"scope": "docker:bridge", "state": "captured", "needs_fix": True, "note": ""}
            ],
        )
    )
    assert summary.scopes[0].marker == "idle"


def test_gui_refuses_to_run_as_root(monkeypatch):
    """Under sudo the applet loses XDG_RUNTIME_DIR and the session bus, so KDE
    cannot show a tray icon at all -- and the control socket exists precisely so
    the GUI never needs privilege."""
    import os

    import ciscomvent.gui.app as app

    monkeypatch.setattr(os, "geteuid", lambda: 0)
    message = app.refuse_root()
    assert message is not None
    assert "sudo" in message
    assert "ciscomvent gui" in message

    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert app.refuse_root() is None


def test_effective_enabled_beats_the_discovery_default():
    """Regression: the toggle wrote config and the row kept reading
    enabled_by_default, a constant, so the button looked completely inert while
    actually working every time it was clicked."""
    summary = summarize(
        snap(
            scopes=[
                {
                    "name": "docker:ciscomvent-test-net",
                    "enabled_by_default": True,
                    "enabled": False,  # turned off via config
                    "device_up": True,
                }
            ],
            diagnoses=[
                {"scope": "docker:ciscomvent-test-net", "state": "captured",
                 "needs_fix": True, "note": ""}
            ],
        )
    )
    assert summary.scopes[0].enabled is False
    assert summary.scopes[0].marker == "off"
    # A disabled scope must not drag health down either.
    assert summary.health is Health.HEALTHY


def test_display_state_explains_an_idle_bridge():
    row = summarize(
        snap(
            scopes=[{"name": "docker:bridge", "enabled": True, "device_up": False}],
            diagnoses=[
                {"scope": "docker:bridge", "state": "captured",
                 "needs_fix": True, "note": ""}
            ],
        )
    ).scopes[0]
    assert "idle" in row.display_state
    assert "captured" not in row.display_state


def test_display_state_marks_disabled_scopes():
    row = summarize(
        snap(
            scopes=[{"name": "lan:wlp0s20f3", "enabled": False, "device_up": True}],
            diagnoses=[
                {"scope": "lan:wlp0s20f3", "state": "captured",
                 "needs_fix": True, "note": ""}
            ],
        )
    ).scopes[0]
    assert "disabled" in row.display_state


def test_healthy_detail_names_the_scopes_it_means():
    """"Containers reachable" alone does not say which containers."""
    detail = summarize(snap()).detail
    assert "docker:ciscomvent-test-net" in detail
    assert "firewall rule" in detail


# -- privilege tier ----------------------------------------------------------


def test_caller_tier_is_carried_into_the_summary():
    """The GUI greys out the controls the daemon would refuse, rather than
    offering them and reporting a failure after the click."""
    assert summarize(snap(caller_is_root=True)).caller_is_root is True
    assert summarize(snap(caller_is_root=False)).caller_is_root is False


def test_a_snapshot_without_the_field_leaves_the_controls_alone():
    """An older daemon does not send it. Defaulting to False would disable
    buttons that daemon still honours; the daemon is the gate either way."""
    base = snap()
    base.pop("caller_is_root", None)
    assert summarize(base).caller_is_root is True


# -- what an approval actually claims ----------------------------------------
#
# Approving installs a priority-100 rule for a subnet chosen by whoever created
# the network, and that rule outranks the tunnel. The scope name does not say
# which subnet, so it is not enough to decide on.


def test_pending_approval_carries_the_cidr_into_the_ui():
    summary = summarize(
        snap(
            pending_approval=["docker:x"],
            pending_claims=[
                {
                    "scope": "docker:x",
                    "device": "br-x",
                    "networks": ["10.0.0.0/16"],
                    "shadowed_by": ["10.0.0.0/8"],
                }
            ],
        )
    )

    assert summary.health is Health.PENDING
    claim = summary.pending_claims[0]
    assert claim.label == "docker:x — 10.0.0.0/16"
    assert "10.0.0.0/16" in summary.detail
    assert "10.0.0.0/8" in claim.tooltip
    # Names stay available for everything keyed on them.
    assert summary.pending == ("docker:x",)


def test_an_older_daemon_still_gets_approval_controls():
    """It sends names only. Dropping the controls because the CIDRs are missing
    would break approval outright, and the daemon is the gate either way."""
    summary = summarize(snap(pending_approval=["docker:x"]))

    assert summary.pending == ("docker:x",)
    assert summary.pending_claims[0].label == "docker:x"
    assert summary.health is Health.PENDING


def test_refused_claims_are_reported_even_when_nothing_is_wrong():
    """A subnet missing because it was refused looks exactly like one that was
    never discovered. Say which it is."""
    summary = summarize(
        snap(
            refused_claims=[
                {
                    "network": "10.0.0.0/8",
                    "scope": "docker:wide",
                    "reason": "/8 is wider than the /16 ceiling",
                }
            ]
        )
    )

    assert summary.health is Health.HEALTHY
    assert "1 claim(s) refused" in summary.detail
    assert "10.0.0.0/8" in summary.refused[0]


def test_a_dismissed_scope_stops_driving_health():
    """"Not now" has to quiet the tray, or the button changes nothing a user
    can see and the scope may as well have stayed pending."""
    pending = snap(
        pending_approval=["docker:ciscomvent-test-net"],
        diagnoses=[
            {
                "scope": "docker:ciscomvent-test-net",
                "state": "captured",
                "needs_fix": True,
                "note": "routes via cscotun0",
            }
        ],
    )
    assert summarize(pending).health is Health.PENDING

    summary = summarize(dict(pending, dismissed=["docker:ciscomvent-test-net"]))
    assert summary.health is not Health.PENDING


def test_a_dismissed_scope_does_not_mask_a_failing_one():
    """The reason dismissal exists. PENDING is tested before FAILING, so one
    scope the user has declined otherwise hides a scope that was claimed and
    is still unreachable -- the state they most need to see."""
    both = snap(
        pending_approval=["lan:wlp0s20f3"],
        diagnoses=[
            {
                "scope": "docker:ciscomvent-test-net",
                "state": "misrouted",
                "needs_fix": True,
                "note": "unreachable",
            }
        ],
    )
    assert summarize(both).health is Health.PENDING  # the masking

    summary = summarize(dict(both, dismissed=["lan:wlp0s20f3"]))
    assert summary.health is Health.FAILING


def test_a_dismissed_claim_is_still_listed_and_still_approvable():
    """Dismissing drops it from what is asking, not from what exists: the CIDR
    has to survive, or the approval confirmation has nothing to name."""
    summary = summarize(
        snap(pending_approval=["lan:wlp0s20f3"], dismissed=["lan:wlp0s20f3"])
    )

    assert summary.pending == ("lan:wlp0s20f3",)
    assert summary.awaiting == ()
