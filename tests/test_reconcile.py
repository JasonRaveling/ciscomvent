# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reconciliation: desired-vs-actual, and the traps in computing "desired"."""

from __future__ import annotations

import ipaddress
import json

from ciscomvent.config import Automation, Config
from ciscomvent.model import Scope, ScopeKind, Subnet, VpnState
from ciscomvent.reconcile import Claim, ReconcilePlan, desired_claims

net = ipaddress.ip_network
addr = ipaddress.ip_address

BRIDGE = "br-0123456789ab"
UP = {BRIDGE: "UP", "docker0": "DOWN", "wlp0s20f3": "UP"}

DOCKER = Scope(
    name="docker:ciscomvent-test-net",
    kind=ScopeKind.DOCKER,
    device=BRIDGE,
    subnets=(Subnet(network=net("172.18.0.0/16"), gateway=addr("172.18.0.1")),),
    enabled_by_default=True,
)
DOWN_SCOPE = Scope(
    name="docker:bridge",
    kind=ScopeKind.DOCKER,
    device="docker0",
    subnets=(Subnet(network=net("172.17.0.0/16")),),
    enabled_by_default=True,
)
LAN = Scope(
    name="lan:wlp0s20f3",
    kind=ScopeKind.LAN,
    device="wlp0s20f3",
    subnets=(Subnet(network=net("192.168.1.0/24")),),
    enabled_by_default=False,
)

VPN_UP = VpnState(
    devices=("cscotun0",),
    addresses=("192.168.224.199",),
    captured_prefixes=(net("172.18.0.0/16"),),
    has_default_route=True,
)
VPN_DOWN = VpnState()


def test_nothing_desired_while_the_tunnel_is_down():
    """This is what drives cleanup on disconnect -- no special case, just an
    empty desired set flowing through the same delta machinery."""
    assert desired_claims((DOCKER,), VPN_DOWN, Config(), UP).claims == {}


def test_desired_is_not_gated_on_being_captured():
    """The trap: applying the fix makes a captured scope look healthy. If
    desired depended on the diagnosis, the daemon would tear down its own
    routes, see the scope captured again, reinstall, and flap forever."""
    healthy_vpn = VpnState(
        devices=("cscotun0",),
        addresses=("192.168.224.199",),
        captured_prefixes=(),  # nothing captured any more -- we already fixed it
        has_default_route=True,
    )
    desired = desired_claims((DOCKER,), healthy_vpn, Config(), UP).claims
    assert net("172.18.0.0/16") in desired


def test_docker_scopes_are_desired_by_default():
    desired = desired_claims((DOCKER,), VPN_UP, Config(), UP).claims
    assert desired == {net("172.18.0.0/16"): DOCKER}


def test_lan_is_not_desired_until_explicitly_enabled():
    assert desired_claims((LAN,), VPN_UP, Config(), UP).claims == {}

    config = Config(enabled_scopes=["lan:wlp0s20f3"])
    assert net("192.168.1.0/24") in desired_claims((LAN,), VPN_UP, config, UP).claims


def test_docker_can_be_explicitly_disabled():
    config = Config(disabled_scopes=["docker:ciscomvent-test-net"])
    assert desired_claims((DOCKER,), VPN_UP, config, UP).claims == {}


def test_down_devices_are_never_desired():
    """Scope-link routes do not persist on a down device, so claiming one
    produces a route that silently vanishes."""
    assert desired_claims((DOWN_SCOPE,), VPN_UP, Config(), UP).claims == {}


def test_plan_is_noop_when_everything_matches():
    plan = ReconcilePlan(unchanged=(Claim(net("172.18.0.0/16"), BRIDGE),))
    assert plan.is_noop
    assert "in sync" in plan.summary()


def test_plan_reports_both_directions():
    plan = ReconcilePlan(
        to_add=(DOCKER,), to_remove=(Claim(net("172.20.0.0/16"), "br-x"),)
    )
    assert not plan.is_noop
    assert "+1" in plan.summary()
    assert "-1" in plan.summary()


def test_config_round_trips(tmp_path):
    from ciscomvent import config as config_mod

    original = Config(
        automation=Automation.AUTO,
        enabled_scopes=["lan:wlp0s20f3"],
        always_allow=["docker:ciscomvent-test-net"],
    )
    path = tmp_path / "config.json"
    config_mod.save(original, path)
    loaded = config_mod.load(path)

    assert loaded.automation is Automation.AUTO
    assert loaded.enabled_scopes == ["lan:wlp0s20f3"]
    assert loaded.always_allow == ["docker:ciscomvent-test-net"]


def test_missing_or_broken_config_falls_back_to_defaults(tmp_path):
    """A malformed config must not stop the daemon from starting."""
    from ciscomvent import config as config_mod

    assert config_mod.load(tmp_path / "absent.json").automation is Automation.CONFIRM

    broken = tmp_path / "broken.json"
    broken.write_text("{not json")
    assert config_mod.load(broken).automation is Automation.CONFIRM


def test_the_claim_ceiling_round_trips_and_fails_closed(tmp_path):
    """A typo in the ceiling must not read as "no ceiling". Falling back to 0
    would turn a bad edit into an open guard."""
    from ciscomvent import config as config_mod
    from ciscomvent.config import DEFAULT_MIN_CLAIM_PREFIXLEN

    path = tmp_path / "config.json"
    config_mod.save(
        Config(min_claim_prefixlen=20, allow_wide_claims=["10.0.0.0/8"]), path
    )
    loaded = config_mod.load(path)
    assert loaded.min_claim_prefixlen == 20
    assert loaded.allow_wide_claims == ["10.0.0.0/8"]

    for bad in ("wide", -1, 33, None):
        path.write_text(json.dumps({"min_claim_prefixlen": bad}))
        assert config_mod.load(path).min_claim_prefixlen == DEFAULT_MIN_CLAIM_PREFIXLEN


def test_confirm_mode_needs_approval_unless_always_allowed():
    config = Config(automation=Automation.CONFIRM, always_allow=["docker:x"])
    assert config.needs_approval("docker:other") is True
    assert config.needs_approval("docker:x") is False


def test_auto_mode_never_needs_approval():
    assert Config(automation=Automation.AUTO).needs_approval("anything") is False


def test_missing_firewall_rules_make_a_scope_need_reapplying(monkeypatch):
    """Cisco rebuilds its chains on connect, taking our accepts with them.
    Routing can be perfectly in sync while the rules that make it usable are
    gone, so the rules have to be part of desired state -- otherwise the
    reconciler reports "in sync" over a stack that does not work."""
    import ciscomvent.reconcile as rec

    claim = Claim(net("172.18.0.0/16"), BRIDGE)
    monkeypatch.setattr(rec, "actual_claims", lambda: ({claim}, {claim.network}))
    monkeypatch.setattr(rec, "link_states", lambda: UP)
    monkeypatch.setattr(rec, "installed_firewall_scopes", lambda: set())

    plan = rec.reconcile((DOCKER,), VPN_UP, Config())
    assert [s.name for s in plan.to_add] == ["docker:ciscomvent-test-net"]
    assert not plan.is_noop


def test_routing_and_rules_both_present_is_in_sync(monkeypatch):
    import ciscomvent.reconcile as rec

    claim = Claim(net("172.18.0.0/16"), BRIDGE)
    monkeypatch.setattr(rec, "actual_claims", lambda: ({claim}, {claim.network}))
    monkeypatch.setattr(rec, "link_states", lambda: UP)
    monkeypatch.setattr(
        rec, "installed_firewall_scopes", lambda: {"docker:ciscomvent-test-net"}
    )

    assert rec.reconcile((DOCKER,), VPN_UP, Config()).is_noop


def test_unreadable_firewall_does_not_trigger_reinstall(monkeypatch):
    """Reading iptables needs root. An unprivileged caller must not conclude the
    rules are missing and plan to reinstall them."""
    import ciscomvent.reconcile as rec

    claim = Claim(net("172.18.0.0/16"), BRIDGE)
    monkeypatch.setattr(rec, "actual_claims", lambda: ({claim}, {claim.network}))
    monkeypatch.setattr(rec, "link_states", lambda: UP)
    monkeypatch.setattr(rec, "installed_firewall_scopes", lambda: None)

    assert rec.reconcile((DOCKER,), VPN_UP, Config()).is_noop


def test_desired_scopes_are_reported_for_rule_pruning(monkeypatch):
    import ciscomvent.reconcile as rec

    monkeypatch.setattr(rec, "actual_claims", lambda: (set(), set()))
    monkeypatch.setattr(rec, "link_states", lambda: UP)
    monkeypatch.setattr(rec, "installed_firewall_scopes", lambda: set())

    plan = rec.reconcile((DOCKER,), VPN_UP, Config())
    assert plan.desired_scopes == ("docker:ciscomvent-test-net",)

    down = rec.reconcile((DOCKER,), VPN_DOWN, Config())
    assert down.desired_scopes == ()


def test_parse_rule_comment_identifies_our_rules():
    from ciscomvent.apply import parse_rule_comment

    ours = '-A OUTPUT -o br0 -m comment --comment "ciscomvent:docker:x" -j ACCEPT'
    assert parse_rule_comment(ours) == "docker:x"

    theirs = '-A OUTPUT -o br0 -m comment --comment "somethingelse" -j ACCEPT'
    assert parse_rule_comment(theirs) is None
    assert parse_rule_comment("-A OUTPUT -j ACCEPT") is None


# -- the claim guard ---------------------------------------------------------
#
# A claim is `ip rule to <network> priority 100`, consulted ahead of main at
# 32766. That is the whole design, and it means a claim outranks the tunnel
# too. The subnet comes from whoever created the network, and creating a Docker
# network needs no root.

WIDE = Scope(
    name="docker:wide",
    kind=ScopeKind.DOCKER,
    device=BRIDGE,
    subnets=(Subnet(network=net("10.0.0.0/8")),),
    enabled_by_default=True,
)


def test_a_claim_wider_than_the_ceiling_is_refused():
    """`docker network create --subnet 10.0.0.0/8` from an untrusted compose
    file would otherwise pull every corporate destination in 10/8 off the
    tunnel and onto a bridge, where a container can answer for those
    addresses."""
    result = desired_claims((WIDE,), VPN_UP, Config(), UP)

    assert result.claims == {}
    assert [r.network for r in result.refused] == [net("10.0.0.0/8")]
    assert "/16 ceiling" in result.refused[0].reason


def test_overlapping_a_captured_prefix_is_not_the_test():
    """Overlap is the normal case and the reason this tool exists. VPN_UP
    captures exactly the bridge's own subnet -- the ordinary conflict -- and
    refusing that would refuse the entire product."""
    result = desired_claims((DOCKER,), VPN_UP, Config(), UP)

    assert result.claims == {net("172.18.0.0/16"): DOCKER}
    assert result.refused == ()


def test_a_bridge_inside_a_captured_prefix_is_still_claimed():
    inside = Scope(
        name="docker:inside",
        kind=ScopeKind.DOCKER,
        device=BRIDGE,
        subnets=(Subnet(network=net("10.1.2.0/24")),),
        enabled_by_default=True,
    )
    vpn = VpnState(
        devices=("cscotun0",),
        addresses=("192.168.224.199",),
        captured_prefixes=(net("10.0.0.0/8"),),
        has_default_route=True,
    )
    result = desired_claims((inside,), vpn, Config(), UP)

    assert net("10.1.2.0/24") in result.claims
    assert result.refused == ()


def test_a_claim_that_swallows_a_tunnel_prefix_is_refused():
    """The other shape that is never a repair: the bridge's subnet strictly
    contains a prefix the headend pushed, so claiming it diverts that whole
    prefix rather than carving the bridge out of it."""
    swallower = Scope(
        name="docker:swallower",
        kind=ScopeKind.DOCKER,
        device=BRIDGE,
        subnets=(Subnet(network=net("192.168.0.0/16")),),
        enabled_by_default=True,
    )
    vpn = VpnState(
        devices=("cscotun0",),
        addresses=("192.168.224.199",),
        captured_prefixes=(net("192.168.5.0/24"),),
        has_default_route=True,
    )
    result = desired_claims((swallower,), vpn, Config(), UP)

    assert result.claims == {}
    assert "192.168.5.0/24" in result.refused[0].reason


def test_an_explicit_cidr_opt_in_is_honoured():
    """The escape hatch is keyed on the network, not the scope name: the name
    is stable while the subnet is not, so approving `docker:app` once must not
    carry over to the same name recreated around a wider subnet."""
    config = Config(allow_wide_claims=["10.0.0.0/8"])
    result = desired_claims((WIDE,), VPN_UP, config, UP)

    assert net("10.0.0.0/8") in result.claims
    assert result.refused == ()


def test_a_refused_subnet_is_removed_from_the_scope_itself():
    """policy_actions and firewall_actions both iterate scope.subnets, so a
    scope that reached them intact would install the route for a subnet refused
    here. Filtering the desired dict alone is not enough."""
    mixed = Scope(
        name="docker:mixed",
        kind=ScopeKind.DOCKER,
        device=BRIDGE,
        subnets=(
            Subnet(network=net("172.20.0.0/16")),
            Subnet(network=net("10.0.0.0/8")),
        ),
        enabled_by_default=True,
    )
    result = desired_claims((mixed,), VPN_UP, Config(), UP)

    claimed = result.claims[net("172.20.0.0/16")]
    assert claimed.networks == (net("172.20.0.0/16"),)
    assert net("10.0.0.0/8") not in result.claims
    assert [r.network for r in result.refused] == [net("10.0.0.0/8")]


def test_the_ceiling_is_configurable():
    config = Config(min_claim_prefixlen=8)
    assert net("10.0.0.0/8") in desired_claims((WIDE,), VPN_UP, config, UP).claims


def test_refusals_are_visible_in_the_plan_summary():
    """A plan reading "in sync" while a subnet is being refused would be the
    same silence the guard exists to break."""
    from ciscomvent.reconcile import Refusal

    plan = ReconcilePlan(
        unchanged=(Claim(net("172.18.0.0/16"), BRIDGE),),
        refused=(Refusal(net("10.0.0.0/8"), "docker:wide", "too wide"),),
    )
    assert plan.is_noop  # nothing to do about a refusal
    assert "in sync" in plan.summary()
    assert "1 refused" in plan.summary()
    assert plan.as_dict()["refused"][0]["network"] == "10.0.0.0/8"
