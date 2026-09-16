# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""What the daemon says about a claim before making it.

A claim installs `ip rule to <network> priority 100`, ahead of `main` at 32766
and therefore ahead of the tunnel. The subnet comes from whoever created the
network and creating a Docker network needs no root, so two things have to be
true of the daemon: it refuses the subnets that are never a repair, and what it
does ask about is described by CIDR rather than by scope name alone.
"""

from __future__ import annotations

import ipaddress
import logging

from ciscomvent.config import Config
from ciscomvent.daemon import Daemon
from ciscomvent.discovery import DiscoveryResult
from ciscomvent.model import Scope, ScopeKind, Subnet, VpnState
from ciscomvent.reconcile import Refusal

net = ipaddress.ip_network

BRIDGE = "br-0123456789ab"
WIDE_BRIDGE = "br-ffffffffffff"
UP = {BRIDGE: "UP", WIDE_BRIDGE: "UP"}

NORMAL = Scope(
    name="docker:app",
    kind=ScopeKind.DOCKER,
    device=BRIDGE,
    subnets=(Subnet(network=net("172.18.0.0/16")),),
    enabled_by_default=True,
)
WIDE = Scope(
    name="docker:untrusted",
    kind=ScopeKind.DOCKER,
    device=WIDE_BRIDGE,
    subnets=(Subnet(network=net("10.0.0.0/8")),),
    enabled_by_default=True,
)

VPN_UP = VpnState(
    devices=("cscotun0",),
    addresses=("192.168.224.199",),
    captured_prefixes=(net("10.0.0.0/8"), net("172.18.0.0/16")),
    has_default_route=True,
)


def _daemon(monkeypatch, *scopes):
    """A daemon reconciling against fixed discovery, touching no kernel."""
    import ciscomvent.daemon as dmn
    import ciscomvent.reconcile as rec

    config = Config()  # confirm mode: nothing is applied without approval
    monkeypatch.setattr(dmn, "load_config", lambda: config)
    monkeypatch.setattr(dmn, "vpn_state", lambda: VPN_UP)
    monkeypatch.setattr(
        dmn, "discover_scopes", lambda _config: DiscoveryResult(scopes=tuple(scopes))
    )
    monkeypatch.setattr(dmn, "installed_firewall_scopes", lambda: set())
    monkeypatch.setattr(rec, "actual_claims", lambda: (set(), set()))
    monkeypatch.setattr(rec, "link_states", lambda: UP)
    monkeypatch.setattr(rec, "installed_firewall_scopes", lambda: set())
    return Daemon(config=config, dry_run=True)


def test_the_approval_prompt_names_the_cidr(monkeypatch):
    """"docker:app" is not a decision. The same name can come back tomorrow
    around a different subnet, and the subnet is what gets diverted."""
    daemon = _daemon(monkeypatch, NORMAL)
    daemon.reconcile_once()

    assert daemon.pending_approval == ["docker:app"]
    claim = daemon.pending_claims[0]
    assert claim["networks"] == ["172.18.0.0/16"]
    assert claim["device"] == BRIDGE
    # The prefix the tunnel currently carries, so the prompt can say what this
    # is being taken away from.
    assert claim["shadowed_by"] == ["172.18.0.0/16"]


def test_a_refused_subnet_is_never_offered_for_approval(monkeypatch):
    """The guard runs ahead of the prompt on purpose. Offering 10.0.0.0/8 as a
    tray menu entry reading "docker:untrusted" is how it would get approved."""
    daemon = _daemon(monkeypatch, NORMAL, WIDE)
    plan = daemon.reconcile_once()

    assert daemon.pending_approval == ["docker:app"]
    assert [str(r.network) for r in plan.refused] == ["10.0.0.0/8"]
    assert "docker:untrusted" not in [c["scope"] for c in daemon.pending_claims]


def test_a_refusal_is_announced_once_not_every_tick(monkeypatch, caplog):
    """It is stable for as long as the offending network exists, and the
    reconciler runs every 60s. Repeating it buries it in itself."""
    daemon = _daemon(monkeypatch, WIDE)
    refused = (Refusal(net("10.0.0.0/8"), "docker:untrusted", "too wide"),)

    with caplog.at_level(logging.WARNING, logger="ciscomvent"):
        daemon._log_refusals(refused)
        daemon._log_refusals(refused)
    assert len(caplog.records) == 1
    assert "allow_wide_claims" in caplog.records[0].getMessage()

    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="ciscomvent"):
        daemon._log_refusals(
            (Refusal(net("10.0.0.0/8"), "docker:untrusted", "a different reason"),)
        )
    assert len(caplog.records) == 1


LEASE_WARNING = (
    "lan:wlp0s20f3: not offering 10.0.0.0/8 as a scope, /8 is wider than the "
    "/16 ceiling, and a claim outranks the tunnel. To offer it, add its exact "
    "CIDR to allow_wide_claims."
)


def test_a_discovery_warning_is_announced_once_not_every_tick(monkeypatch, caplog):
    """A prefix refused for its width never reaches a plan, so the journal is
    the only place it can surface. On the same once-only terms as a refusal:
    discovery runs every 60s and the lease is stable for as long as you stay
    attached to the network that issued it."""
    daemon = _daemon(monkeypatch)

    with caplog.at_level(logging.WARNING, logger="ciscomvent"):
        daemon._log_discovery((LEASE_WARNING,))
        daemon._log_discovery((LEASE_WARNING,))
    assert len(caplog.records) == 1
    assert "10.0.0.0/8" in caplog.records[0].getMessage()


def test_an_unrelated_warning_does_not_re_announce_the_others(monkeypatch, caplog):
    """`docker unavailable` is permanent on a host without Docker. Repeating it
    whenever anything else changes is how a journal stops being read."""
    daemon = _daemon(monkeypatch)

    with caplog.at_level(logging.WARNING, logger="ciscomvent"):
        daemon._log_discovery((LEASE_WARNING,))
    caplog.clear()

    with caplog.at_level(logging.WARNING, logger="ciscomvent"):
        daemon._log_discovery((LEASE_WARNING, "docker unavailable"))
    assert len(caplog.records) == 1
    assert "docker unavailable" in caplog.records[0].getMessage()


def test_a_warning_that_goes_away_is_announced_again_if_it_returns(monkeypatch, caplog):
    """Reattaching to the hostile network is a new event, not a duplicate."""
    daemon = _daemon(monkeypatch)

    with caplog.at_level(logging.WARNING, logger="ciscomvent"):
        daemon._log_discovery((LEASE_WARNING,))
        daemon._log_discovery(())
        daemon._log_discovery((LEASE_WARNING,))
    assert len(caplog.records) == 2

