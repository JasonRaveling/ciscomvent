# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Mutation primitives: ownership tagging, idempotency, and exact undo."""

from __future__ import annotations

import ipaddress

from ciscomvent import RULE_COMMENT_PREFIX
from ciscomvent.apply import (
    LAYER_FIREWALL,
    LAYER_ROUTE,
    ROUTE_PROTO_NUM,
    ROUTE_TABLE,
    RULE_PRIORITY,
    delete_argv_for_rule,
    firewall_actions,
    policy_actions,
    route_actions,
)
from ciscomvent.model import Scope, ScopeKind, Subnet
from ciscomvent.prefixes import plan_reclaim

net = ipaddress.ip_network
addr = ipaddress.ip_address

# A device that does not exist on any host, so source_address() finds nothing
# and these tests stay independent of the machine they run on.
FAKE_DEV = "br-testonly0"

SCOPE = Scope(
    name="docker:ciscomvent-test-net",
    kind=ScopeKind.DOCKER,
    device=FAKE_DEV,
    subnets=(Subnet(network=net("172.18.0.0/16"), gateway=addr("172.18.0.1")),),
)


def test_route_actions_are_tagged_with_our_proto():
    """Ownership tagging is what makes teardown exact. Without it we would have
    to guess which routes were ours."""
    actions = route_actions(SCOPE, plan_reclaim(net("172.18.0.0/16")))
    assert len(actions) == 2
    for action in actions:
        assert "proto" in action.apply_argv
        assert str(ROUTE_PROTO_NUM) in action.apply_argv
        assert action.layer == LAYER_ROUTE


def test_route_actions_use_add_not_replace():
    """`replace` would silently overwrite a route someone else owns for the same
    prefix -- including a mirrored Cisco route. `add` fails loudly instead."""
    actions = route_actions(SCOPE, plan_reclaim(net("172.18.0.0/16")))
    for action in actions:
        assert "add" in action.apply_argv
        assert "replace" not in action.apply_argv


def test_route_undo_matches_what_was_applied():
    actions = route_actions(SCOPE, plan_reclaim(net("172.18.0.0/16")))
    for action in actions:
        assert "del" in action.undo_argv
        assert FAKE_DEV in action.undo_argv
        # The undo is proto-scoped, so it cannot remove a route we did not add.
        assert str(ROUTE_PROTO_NUM) in action.undo_argv


def test_route_actions_cover_both_halves_of_the_subnet():
    actions = route_actions(SCOPE, plan_reclaim(net("172.18.0.0/16")))
    prefixes = {a.apply_argv[3] for a in actions}
    assert prefixes == {"172.18.0.0/17", "172.18.128.0/17"}


def test_policy_actions_use_a_dedicated_table_and_rule():
    """The mechanism that survives prefix mirroring. Cisco writes to main; a
    rule at priority 100 is consulted before main at 32766, so prefix length
    stops deciding the outcome."""
    actions = policy_actions(SCOPE)
    assert len(actions) == 2

    route, rule = actions
    assert "table" in route.apply_argv
    assert str(ROUTE_TABLE) in route.apply_argv
    assert route.apply_argv[3] == "172.18.0.0/16"

    assert rule.apply_argv[1] == "rule"
    assert "lookup" in rule.apply_argv
    assert str(RULE_PRIORITY) in rule.apply_argv


def test_policy_claims_the_whole_subnet_without_splitting():
    """No /17s to mirror. Specificity stops being the contest."""
    prefixes = [
        a.apply_argv[3] for a in policy_actions(SCOPE) if a.apply_argv[1] == "route"
    ]
    assert prefixes == ["172.18.0.0/16"]


def test_policy_rule_priority_sits_between_local_and_main():
    """Above local (0) so host-owned addresses keep resolving via the local
    table; below main (32766) so we are consulted before Cisco's routes."""
    assert 0 < RULE_PRIORITY < 32766


def test_policy_rule_clears_itself_before_adding():
    """`ip rule add` has no idempotent form and stacks duplicates silently."""
    rule = policy_actions(SCOPE)[1]
    assert rule.pre_argv
    assert "del" in rule.pre_argv


def test_policy_undo_removes_both_route_and_rule():
    for action in policy_actions(SCOPE):
        assert action.undo_argv
        assert "del" in action.undo_argv


def test_policy_route_replace_is_safe_because_the_table_is_ours():
    """`replace` would be wrong in main -- it could overwrite a foreign route --
    but table 150 is written by nothing else, so it is the idempotent choice."""
    route = policy_actions(SCOPE)[0]
    assert "replace" in route.apply_argv
    assert str(ROUTE_TABLE) in route.undo_argv


def test_policy_never_touches_the_main_table():
    for action in policy_actions(SCOPE):
        joined = " ".join(action.apply_argv)
        assert "main" not in joined
        assert "unspec" not in joined


def test_firewall_actions_are_comment_tagged():
    actions = firewall_actions(SCOPE)
    assert len(actions) == 2
    for action in actions:
        assert action.layer == LAYER_FIREWALL
        joined = " ".join(action.apply_argv)
        assert f"{RULE_COMMENT_PREFIX}docker:ciscomvent-test-net" in joined
        assert "--comment" in action.apply_argv


def test_firewall_covers_output_and_input():
    chains = set()
    for action in firewall_actions(SCOPE):
        chains.add(action.apply_argv[2])
    assert chains == {"OUTPUT", "INPUT"}


def test_firewall_output_matches_egress_input_matches_ingress():
    by_chain = {a.apply_argv[2]: a.apply_argv for a in firewall_actions(SCOPE)}
    assert "-o" in by_chain["OUTPUT"]
    assert "-i" in by_chain["INPUT"]


def test_firewall_never_accepts_a_whole_interface():
    """Regression, and the reason layer 2 is safe to have on by default.

    These rules are inserted at position 1 of INPUT and OUTPUT, ahead of every
    rule ufw or firewalld installed. A bare `-i <dev> -j ACCEPT` there is not a
    repair, it is turning the host firewall off for that interface: on a Docker
    bridge it hands every container every port the host listens on, and for a
    LAN or libvirt scope the device is a physical NIC.
    """
    for action in firewall_actions(SCOPE):
        argv = action.apply_argv
        # Whichever direction it is, it names an address selector, so the rule
        # cannot match traffic outside the subnet we claimed.
        assert ("-s" in argv) or ("-d" in argv)
        assert "172.18.0.0/16" in argv


def test_firewall_egress_is_limited_to_the_claimed_subnet():
    by_chain = {a.apply_argv[2]: a.apply_argv for a in firewall_actions(SCOPE)}
    argv = by_chain["OUTPUT"]
    assert argv[argv.index("-o") + 1] == FAKE_DEV
    assert argv[argv.index("-d") + 1] == "172.18.0.0/16"


def test_firewall_ingress_admits_the_return_path_only():
    """Host-to-container is what breaks, so the reply is all INPUT has to let
    in. A container opening a new connection to a host service is left to the
    local firewall policy rather than force-accepted ahead of it."""
    by_chain = {a.apply_argv[2]: a.apply_argv for a in firewall_actions(SCOPE)}
    argv = by_chain["INPUT"]
    assert argv[argv.index("-i") + 1] == FAKE_DEV
    assert argv[argv.index("-s") + 1] == "172.18.0.0/16"
    assert argv[argv.index("--ctstate") + 1] == "ESTABLISHED,RELATED"


def test_firewall_ingress_targets_the_host_address_the_route_replies_from(
    monkeypatch,
):
    """`-d` has to be the same address the route sets as `src`, or the accept
    would not match the packets the repair actually produces."""
    from ciscomvent import apply as apply_mod
    from ciscomvent.iproute import InterfaceAddress

    monkeypatch.setattr(
        apply_mod,
        "addresses",
        lambda: [
            InterfaceAddress(
                ifname=FAKE_DEV,
                address=addr("172.18.0.1"),
                prefixlen=16,
                scope="global",
            )
        ],
    )

    by_chain = {a.apply_argv[2]: a.apply_argv for a in firewall_actions(SCOPE)}
    assert by_chain["INPUT"][by_chain["INPUT"].index("-d") + 1] == "172.18.0.1"
    # And the route it pairs with uses that same address as its preferred src.
    route = policy_actions(SCOPE)[0].apply_argv
    assert route[route.index("src") + 1] == "172.18.0.1"


def test_firewall_covers_every_subnet_of_a_multi_subnet_scope():
    scope = Scope(
        name="docker:two-subnets",
        kind=ScopeKind.DOCKER,
        device=FAKE_DEV,
        subnets=(
            Subnet(network=net("172.18.0.0/16"), gateway=addr("172.18.0.1")),
            Subnet(network=net("10.42.0.0/24"), gateway=addr("10.42.0.1")),
        ),
    )
    actions = firewall_actions(scope)
    assert len(actions) == 4
    for network in ("172.18.0.0/16", "10.42.0.0/24"):
        chains = {a.apply_argv[2] for a in actions if network in a.apply_argv}
        assert chains == {"OUTPUT", "INPUT"}


def test_firewall_actions_have_a_check_so_they_are_idempotent():
    for action in firewall_actions(SCOPE):
        assert action.check_argv is not None
        assert "-C" in action.check_argv


def test_firewall_undo_deletes_the_same_rule():
    for action in firewall_actions(SCOPE):
        assert "-D" in action.undo_argv
        assert " ".join(action.undo_argv).endswith("-j ACCEPT")


def test_rule_deletion_strips_the_quotes_iptables_adds():
    """Regression: `iptables -S` quotes the comment value. Splitting on
    whitespace carried the literal quote characters into the delete, so
    iptables looked for a rule whose comment really contained quotes, found
    none, and every removal failed with "Bad rule". Observed live: all eight
    firewall rules survived a revert that reported them as removed."""
    spec = (
        '-A OUTPUT -o br-0123456789ab -m comment '
        '--comment "ciscomvent:docker:ciscomvent-test-net" -j ACCEPT'
    )
    argv = delete_argv_for_rule(spec, "/usr/sbin/iptables")

    assert "ciscomvent:docker:ciscomvent-test-net" in argv
    assert '"ciscomvent:docker:ciscomvent-test-net"' not in argv
    assert not any('"' in token for token in argv)


def test_rule_deletion_targets_the_right_chain_and_verb():
    spec = '-A INPUT -i docker0 -m comment --comment "ciscomvent:x" -j ACCEPT'
    argv = delete_argv_for_rule(spec, "/usr/sbin/iptables")
    assert argv[1] == "-D"
    assert argv[2] == "INPUT"
    assert "-A" not in argv


def test_rule_deletion_preserves_multiword_comments():
    spec = '-A OUTPUT -o br0 -m comment --comment "ciscomvent:a b" -j ACCEPT'
    argv = delete_argv_for_rule(spec, "/usr/sbin/iptables")
    assert "ciscomvent:a b" in argv


def test_nothing_targets_cisco_chains():
    """Hard constraint: the ciscovpn chains are rebuilt by the client, so
    touching them loses the change and may destabilise it."""
    actions = firewall_actions(SCOPE) + route_actions(
        SCOPE, plan_reclaim(net("172.18.0.0/16"))
    )
    for action in actions:
        joined = " ".join(action.apply_argv) + " ".join(action.undo_argv)
        assert "ciscovpn" not in joined
        # And we never delete a Cisco route -- we win on specificity.
        assert "unspec" not in joined


def test_host_strategy_emits_one_route_per_container():
    from ciscomvent.prefixes import PrefixStrategy

    hosts = (addr("172.18.0.5"), addr("172.18.0.9"))
    plan = plan_reclaim(
        net("172.18.0.0/16"), hosts=hosts, strategy=PrefixStrategy.HOST
    )
    actions = route_actions(SCOPE, plan)
    assert {a.apply_argv[3] for a in actions} == {"172.18.0.5/32", "172.18.0.9/32"}


def test_skipped_counts_as_success():
    """Regression: removing a route the kernel already dropped -- which it does
    itself when a bridge disappears -- was logged as a failure, so a clean
    teardown produced WARNING lines in the journal. Observed live when the test
    stack was torn down: "remove failed: ip route del ... No such process"."""
    from ciscomvent.apply import Action, ActionResult, ActionStatus

    action = Action(
        layer=LAYER_ROUTE, scope="x", description="", apply_argv=(), undo_argv=()
    )
    assert ActionResult(action, ActionStatus.SKIPPED).ok
    assert ActionResult(action, ActionStatus.ALREADY_PRESENT).ok
    assert ActionResult(action, ActionStatus.APPLIED).ok
    assert not ActionResult(action, ActionStatus.FAILED).ok
