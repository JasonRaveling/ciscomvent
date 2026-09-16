# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Model invariants, including the next-hop seam.

External split routing is deliberately unimplemented.
These tests pin the seam so adding it later stays an extension rather than a
rewrite of every call site.
"""

from __future__ import annotations

import ipaddress

from ciscomvent.model import NextHop, Scope, ScopeKind, Subnet

net = ipaddress.ip_network
addr = ipaddress.ip_address


def test_local_nexthop_renders_dev_only():
    assert NextHop(device="br-0123456789ab").render() == "dev br-0123456789ab"


def test_local_nexthop_is_local():
    assert NextHop(device="docker0").is_local is True


def test_gateway_nexthop_renders_via():
    """The form external split routing would need. Not produced by discovery
    today, but the route builder must not be able to lose it."""
    hop = NextHop(device="wlp0s20f3", gateway=addr("192.168.1.1"))
    assert hop.render() == "via 192.168.1.1 dev wlp0s20f3"
    assert hop.is_local is False


def test_route_args_are_argv_ready():
    """Rendering goes through a list so the daemon can exec without a shell."""
    assert NextHop(device="docker0").route_args() == ["dev", "docker0"]
    assert NextHop(device="eth0", gateway=addr("10.0.0.1")).route_args() == [
        "via",
        "10.0.0.1",
        "dev",
        "eth0",
    ]


def test_every_discovered_scope_is_locally_attached():
    """Discovery can only produce locally-attached scopes: the reclaim route
    points at a device that already owns the subnet. This is why the current
    design is structurally incapable of general split tunneling."""
    scope = Scope(
        name="docker:ciscomvent-test-net",
        kind=ScopeKind.DOCKER,
        device="br-0123456789ab",
        subnets=(Subnet(network=net("172.18.0.0/16"), gateway=addr("172.18.0.1")),),
    )
    assert scope.nexthop.is_local
    assert scope.nexthop.render() == "dev br-0123456789ab"


def test_scope_covers_addresses_in_its_subnets():
    scope = Scope(
        name="docker:ciscomvent-test-net",
        kind=ScopeKind.DOCKER,
        device="br-0123456789ab",
        subnets=(Subnet(network=net("172.18.0.0/16")),),
    )
    assert scope.covers(addr("172.18.200.42"))
    assert not scope.covers(addr("172.19.0.1"))
