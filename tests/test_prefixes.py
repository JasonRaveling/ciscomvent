# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Prefix math -- the core of the fix, and pure, so fully testable off-VPN."""

from __future__ import annotations

import ipaddress

import pytest

from ciscomvent.prefixes import (
    PrefixStrategy,
    host_prefixes,
    outranks,
    plan_reclaim,
    split_once,
)

net = ipaddress.ip_network


def test_split_16_yields_two_17s():
    assert split_once(net("172.18.0.0/16")) == [
        net("172.18.0.0/17"),
        net("172.18.128.0/17"),
    ]


def test_split_covers_subnet_exactly():
    subnet = net("172.18.0.0/16")
    parts = split_once(subnet)
    assert sum(p.num_addresses for p in parts) == subnet.num_addresses
    assert all(p.subnet_of(subnet) for p in parts)


def test_host_route_cannot_split():
    assert split_once(net("10.0.0.1/32")) == [net("10.0.0.1/32")]


def test_default_plan_beats_cisco_16():
    plan = plan_reclaim(net("172.18.0.0/16"), competing_prefixlen=16)
    assert plan.strategy is PrefixStrategy.SPLIT
    assert len(plan.prefixes) == 2
    assert all(p.prefixlen == 17 for p in plan.prefixes)


def test_plan_covers_the_whole_subnet_not_just_a_24():
    """A /24 was the triage's first instinct; it leaves most of the /16 uncovered.

    Docker allocates across the entire /16, so coverage has to be total.
    """
    subnet = net("172.18.0.0/16")
    plan = plan_reclaim(subnet)
    covered = sum(p.num_addresses for p in plan.prefixes)
    assert covered == subnet.num_addresses

    # A container high in the range must be covered by some reclaim prefix,
    # which a single /24 would have missed entirely.
    high = ipaddress.ip_address("172.18.200.42")
    assert any(high in p for p in plan.prefixes)
    assert high not in net("172.18.0.0/24")


def test_plan_goes_deeper_when_cisco_mirrors_our_prefix():
    """The mirroring race: if Cisco copies our /17, a /17 no longer wins."""
    plan = plan_reclaim(net("172.18.0.0/16"), competing_prefixlen=17)
    assert all(p.prefixlen == 18 for p in plan.prefixes)
    assert len(plan.prefixes) == 4


def test_deep_competition_falls_back_to_host_routes():
    """Beating a /24 inside a /16 would need 512 routes; use /32s instead."""
    hosts = (
        ipaddress.ip_address("172.18.0.5"),
        ipaddress.ip_address("172.18.9.9"),
    )
    plan = plan_reclaim(
        net("172.18.0.0/16"), hosts=hosts, competing_prefixlen=24
    )
    assert plan.strategy is PrefixStrategy.HOST
    assert plan.prefixes == (net("172.18.0.5/32"), net("172.18.9.9/32"))
    assert "512" in plan.note


def test_host_strategy_uses_live_addresses():
    hosts = tuple(
        ipaddress.ip_address(a) for a in ("172.18.0.5", "172.18.0.2", "172.18.0.5")
    )
    plan = plan_reclaim(
        net("172.18.0.0/16"), hosts=hosts, strategy=PrefixStrategy.HOST
    )
    assert plan.prefixes == (net("172.18.0.2/32"), net("172.18.0.5/32"))


def test_host_prefixes_ignores_addresses_outside_the_subnet():
    hosts = tuple(
        ipaddress.ip_address(a) for a in ("172.18.0.5", "10.1.2.3")
    )
    assert host_prefixes(net("172.18.0.0/16"), hosts) == [net("172.18.0.5/32")]


def test_host_strategy_with_no_containers_is_empty():
    plan = plan_reclaim(net("172.18.0.0/16"), strategy=PrefixStrategy.HOST)
    assert plan.is_empty
    assert "nothing to reclaim" in plan.note


@pytest.mark.parametrize(
    "candidate,competitor,expected",
    [
        ("172.18.0.0/17", "172.18.0.0/16", True),
        ("172.18.0.0/16", "172.18.0.0/16", False),  # a tie is not a win
        ("172.18.0.0/16", "172.18.0.0/17", False),
        ("10.0.0.0/24", "172.18.0.0/16", False),  # unrelated prefixes
    ],
)
def test_outranks(candidate, competitor, expected):
    assert outranks(net(candidate), net(competitor)) is expected


def test_equal_prefix_is_explicitly_not_a_win():
    """This is the fragile tie the mirroring race would create: same length,
    same metric, resolution falls to insertion order."""
    assert not outranks(net("172.18.0.0/16"), net("172.18.0.0/16"))
