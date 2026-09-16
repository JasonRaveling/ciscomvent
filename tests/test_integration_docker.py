# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Integration tests against the ciscomvent-test stack.

Everything else in this suite runs on fixtures, which keeps it portable but
means nothing exercises real discovery -- the code that reads Docker, resolves a
bridge and picks probe addresses. These do, against a stack that is neutral and
reproducible rather than whatever project happens to be on the machine.

Bring it up first:

    tests/docker/testenv.sh up

Skipped entirely when it is not running, so a normal `./run-tests.sh` is
unaffected.
"""

from __future__ import annotations

import ipaddress

import pytest

from ciscomvent.detect import vpn_state
from ciscomvent.discovery import discover_scopes
from ciscomvent.dockerdisc import docker_available, list_bridge_networks
from ciscomvent.iproute import link_is_up, link_states
from ciscomvent.verify import container_ports, probe_scope
from ciscomvent.verify import routing_ok

NETWORK = "ciscomvent-test-net"
SCOPE = f"docker:{NETWORK}"
WEB = "ciscomvent-test-web"
API = "ciscomvent-test-api"

pytestmark = pytest.mark.skipif(
    not docker_available(),
    reason="docker unavailable",
)


@pytest.fixture(scope="module")
def network():
    for net in list_bridge_networks():
        if net.name == NETWORK:
            return net
    pytest.skip(f"{NETWORK} not running — start it with tests/docker/testenv.sh up")


@pytest.fixture(scope="module")
def scope():
    for candidate in discover_scopes().scopes:
        if candidate.name == SCOPE:
            return candidate
    pytest.skip(f"{SCOPE} not discovered — start tests/docker/testenv.sh up")


def test_the_network_is_discovered(network):
    assert network.subnets, "no IPAM config found"
    assert network.resolved, f"bridge unresolved: {network.bridge_source}"


def test_bridge_is_derived_from_the_id_and_actually_exists(network):
    """The derivation Docker uses, checked against the real interface rather
    than assumed -- discovery confirms it holds the gateway address."""
    assert network.bridge == "br-" + network.id[:12]
    assert len(network.bridge) <= 15  # Linux caps interface names
    assert network.bridge in link_states()


def test_the_subnet_was_not_pinned_and_is_still_found(network):
    """The compose file deliberately does not pin a subnet, which is the
    condition the tool exists for: it has to discover whatever Docker chose."""
    subnet = network.subnets[0]
    assert subnet.network.is_private
    assert subnet.gateway in subnet.network


def test_both_containers_are_present(network):
    names = {name for name, _ in network.containers}
    assert {WEB, API} <= names


def test_probes_are_live_addresses_excluding_the_gateway(scope, network):
    """A live stack must not fall back to synthetic probes, and the gateway is
    host-owned so probing it would always resolve `local dev lo`."""
    gateway = network.subnets[0].gateway
    assert scope.probes_synthetic is False
    assert scope.probes
    assert gateway not in scope.probes
    for probe in scope.probes:
        assert probe in network.subnets[0].network


def test_port_discovery_reads_both_docker_ps_forms(network):
    """web is published (127.0.0.1:18099->8080/tcp), api is only exposed
    (9090/tcp). parse_ports has to take the container-side port from each.

    Takes the `network` fixture purely so it skips with the rest when the stack
    is down; without it this was the one test that failed instead of skipping.
    """
    ports = container_ports()
    assert ports.get(WEB) == (8080,)
    assert ports.get(API) == (9090,)


def test_reachability_follows_routing(scope):
    """The property that matters, and the one H1 turned on: if the kernel routes
    to the bridge, traffic must actually complete. Correct routing with dead
    traffic is the exact signature that proved the firewall accepts necessary.
    """
    if not link_is_up(scope.device):
        pytest.skip(f"{scope.device} is down")

    routed, notes = routing_ok(scope)
    probes = probe_scope(scope)
    assert probes, "no probeable endpoint found"

    reachable = any(p.result.reachable for p in probes)
    vpn = vpn_state()

    if routed:
        assert reachable, (
            "routing resolves to the bridge but nothing answers.\n"
            f"  vpn: {'up' if vpn.connected else 'down'}\n"
            f"  routing: {notes}\n"
            f"  probes: {[(p.address, p.port, p.result.value) for p in probes]}\n"
            "This is the H1 signature: correct routing, dropped traffic."
        )
    elif not vpn.connected:
        pytest.fail(f"routing is wrong with the VPN down: {notes}")
    else:
        # Captured and not yet reclaimed. A legitimate state to observe -- the
        # daemon may not have reconciled yet, or may be waiting for approval --
        # so there is nothing to assert beyond having got this far.
        pytest.skip(f"scope is captured and not yet reclaimed: {notes}")
