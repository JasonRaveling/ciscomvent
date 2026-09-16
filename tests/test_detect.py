# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Detection logic.

Classification is pure, so the VPN-up condition is tested here from captured
state rather than requiring a live tunnel. The route observations below were
taken from a live capture.
"""

from __future__ import annotations

import ipaddress

from ciscomvent.detect import classify
from ciscomvent.model import (
    RouteObservation,
    Scope,
    ScopeKind,
    ScopeState,
    Subnet,
    VpnState,
)

net = ipaddress.ip_network
addr = ipaddress.ip_address

BRIDGE = "br-0123456789ab"


def make_scope(**kw) -> Scope:
    defaults = dict(
        name="docker:ciscomvent-test-net",
        kind=ScopeKind.DOCKER,
        device=BRIDGE,
        subnets=(Subnet(network=net("172.18.0.0/16"), gateway=addr("172.18.0.1")),),
        probes=(addr("172.18.0.5"),),
        enabled_by_default=True,
    )
    defaults.update(kw)
    return Scope(**defaults)


VPN_UP = VpnState(
    devices=("cscotun0",),
    addresses=("192.168.224.128",),
    captured_prefixes=(net("172.18.0.0/16"), net("192.168.1.0/24")),
    has_default_route=True,
)
VPN_DOWN = VpnState()


def test_healthy_when_routing_via_the_bridge():
    obs = (RouteObservation("172.18.0.5", dev=BRIDGE, prefsrc="172.18.0.1"),)
    state, note = classify(make_scope(), VPN_DOWN, obs)
    assert state is ScopeState.HEALTHY
    assert BRIDGE in note


def test_captured_when_routing_via_the_tunnel():
    """The exact condition from the triage: VPN up, container address resolves
    to cscotun0 with the tunnel source address."""
    obs = (
        RouteObservation("172.18.0.5", dev="cscotun0", prefsrc="192.168.224.128"),
    )
    state, note = classify(make_scope(), VPN_UP, obs)
    assert state is ScopeState.CAPTURED
    assert "cscotun0" in note


def test_captured_wins_even_if_only_one_probe_is_affected():
    obs = (
        RouteObservation("172.18.0.5", dev=BRIDGE),
        RouteObservation("172.18.0.9", dev="cscotun0"),
    )
    state, _ = classify(make_scope(), VPN_UP, obs)
    assert state is ScopeState.CAPTURED


def test_misrouted_when_device_is_neither_bridge_nor_tunnel():
    obs = (RouteObservation("172.18.0.5", dev="wlp0s20f3"),)
    state, note = classify(make_scope(), VPN_UP, obs)
    assert state is ScopeState.MISROUTED
    assert "wlp0s20f3" in note


def test_host_owned_probe_reports_no_probe_not_healthy():
    """A bridge gateway always resolves `local dev lo` because the kernel local
    table outranks the tunnel. Treating that as healthy would mask a real
    capture -- the single most dangerous false negative in this tool."""
    obs = (
        RouteObservation(
            "172.18.0.1", dev="lo", prefsrc="172.18.0.1", rtype="local"
        ),
    )
    state, note = classify(make_scope(probes=(addr("172.18.0.1"),)), VPN_UP, obs)
    assert state is not ScopeState.HEALTHY
    assert state is ScopeState.NO_PROBE
    assert "host-owned" in note


def test_local_probes_do_not_mask_a_captured_one():
    obs = (
        RouteObservation("172.18.0.1", dev="lo", rtype="local"),
        RouteObservation("172.18.0.5", dev="cscotun0"),
    )
    state, _ = classify(make_scope(), VPN_UP, obs)
    assert state is ScopeState.CAPTURED


def test_no_probes_is_no_probe():
    state, _ = classify(make_scope(probes=()), VPN_UP, ())
    assert state is ScopeState.NO_PROBE


def test_all_errors_is_error():
    obs = (RouteObservation("172.18.0.5", error="network is unreachable"),)
    state, note = classify(make_scope(), VPN_UP, obs)
    assert state is ScopeState.ERROR
    assert "unreachable" in note


def test_vpn_state_detects_tunnel_all():
    assert VPN_UP.tunnel_all is True
    assert VpnState(devices=("cscotun0",), has_default_route=False).tunnel_all is False
    assert VPN_DOWN.tunnel_all is False


def test_vpn_state_reports_which_prefix_shadows_a_subnet():
    assert VPN_UP.shadows(net("172.18.0.0/16")) == net("172.18.0.0/16")
    assert VPN_UP.shadows(net("172.19.0.0/16")) is None


def test_needs_fix_only_for_captured_and_misrouted():
    from ciscomvent.model import ScopeDiagnosis

    def diag(state):
        return ScopeDiagnosis(scope=make_scope(), state=state, observations=())

    assert diag(ScopeState.CAPTURED).needs_fix
    assert diag(ScopeState.MISROUTED).needs_fix
    assert not diag(ScopeState.HEALTHY).needs_fix
    assert not diag(ScopeState.NO_PROBE).needs_fix
    assert not diag(ScopeState.ERROR).needs_fix
