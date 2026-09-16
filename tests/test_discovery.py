# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Discovery: bridge resolution, probe selection, and scope policy."""

from __future__ import annotations

import ipaddress

from ciscomvent.dockerdisc import (
    DockerNetwork,
    _parse_container_ips,
    _parse_subnets,
    resolve_bridge,
)
from ciscomvent.config import Config
from ciscomvent.discovery import (
    _host_scopes,
    _probes_for_docker,
    _synthetic_probe,
    _synthetic_probes,
    docker_scopes,
)
from ciscomvent.iproute import InterfaceAddress
from ciscomvent.model import ScopeKind, Subnet, VpnState
from ciscomvent.reconcile import claim_refusal

net = ipaddress.ip_network
addr = ipaddress.ip_address

NET_ID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
BRIDGE = "br-0123456789ab"
SUBNETS = (Subnet(network=net("172.18.0.0/16"), gateway=addr("172.18.0.1")),)


def test_bridge_derived_from_id_and_confirmed_by_gateway():
    name, source = resolve_bridge(
        NET_ID, {}, SUBNETS, {BRIDGE}, {addr("172.18.0.1"): BRIDGE}
    )
    assert name == BRIDGE
    assert source == "derived"


def test_bridge_from_explicit_option():
    """The default `bridge` network carries an explicit name rather than a
    derived one."""
    name, source = resolve_bridge(
        "78e28cd8e304aaaa",
        {"com.docker.network.bridge.name": "docker0"},
        (Subnet(network=net("172.17.0.0/16"), gateway=addr("172.17.0.1")),),
        {"docker0"},
        {addr("172.17.0.1"): "docker0"},
    )
    assert name == "docker0"
    assert source == "option"


def test_gateway_match_wins_when_derived_name_is_wrong():
    """Evidence beats convention: if the derived name exists but does not hold
    the gateway, trust whichever interface actually does."""
    name, source = resolve_bridge(
        NET_ID, {}, SUBNETS, {BRIDGE, "br-other"}, {addr("172.18.0.1"): "br-other"}
    )
    assert name == "br-other"
    assert source == "gateway-match"


def test_unverified_when_no_gateway_to_check_against():
    name, source = resolve_bridge(
        NET_ID, {}, (Subnet(network=net("172.18.0.0/16")),), {BRIDGE}, {}
    )
    assert name == BRIDGE
    assert source == "derived-unverified"


def test_unresolved_when_interface_is_absent():
    name, source = resolve_bridge(NET_ID, {}, SUBNETS, set(), {})
    assert name is None
    assert source == "unresolved"


def test_bridge_name_uses_twelve_id_chars():
    """Linux caps interface names at 15 chars, so Docker truncates to br- + 12."""
    name, _ = resolve_bridge(
        NET_ID, {}, SUBNETS, {BRIDGE}, {addr("172.18.0.1"): BRIDGE}
    )
    assert name == "br-" + NET_ID[:12]
    assert len(name) <= 15


def test_parse_container_ips_strips_cidr_suffix():
    inspected = {
        "Containers": {
            "abc": {"Name": "ciscomvent-test-web", "IPv4Address": "172.18.0.5/16"},
            "def": {"Name": "db", "IPv4Address": "172.18.0.8/16"},
            "ghi": {"Name": "v6only", "IPv4Address": ""},
        }
    }
    assert _parse_container_ips(inspected) == (addr("172.18.0.5"), addr("172.18.0.8"))


def test_parse_subnets_reads_ipam_config():
    inspected = {
        "IPAM": {"Config": [{"Subnet": "172.18.0.0/16", "Gateway": "172.18.0.1"}]}
    }
    assert _parse_subnets(inspected) == SUBNETS


def test_synthetic_probes_do_not_all_sit_at_the_bottom_of_the_subnet():
    """Regression: Secure Client installs a host route for the LAN gateway
    pointing at the physical NIC, because it needs that address to reach the
    headend. On a typical LAN the gateway is the lowest usable address, so a
    single low probe reported 192.168.1.0/24 healthy while .50, .128 and .200
    were all captured. Observed live 2026-08-13."""
    probes = _synthetic_probes(net("192.168.1.0/24"), set())
    assert addr("192.168.1.1") in probes
    assert len(probes) > 1
    # At least one probe must be past the range where carve-outs live.
    assert any(int(p.packed[-1]) > 16 for p in probes)


def test_synthetic_probes_include_the_midpoint():
    probes = _synthetic_probes(net("192.168.1.0/24"), set())
    assert addr("192.168.1.128") in probes


def test_synthetic_probes_on_a_16_span_the_range():
    probes = _synthetic_probes(net("172.18.0.0/16"), {addr("172.18.0.1")})
    assert addr("172.18.0.2") in probes
    assert addr("172.18.128.0") in probes


def test_synthetic_probes_never_return_the_broadcast_address():
    for cidr in ("192.168.1.0/24", "10.0.0.0/30", "172.16.0.0/28"):
        network = net(cidr)
        probes = _synthetic_probes(network, set())
        assert network.broadcast_address not in probes
        assert network.network_address not in probes


def test_synthetic_probes_handle_tiny_subnets():
    assert _synthetic_probes(net("10.0.0.0/31"), set())
    assert len(_synthetic_probes(net("10.0.0.5/32"), set())) <= 1


def test_synthetic_probes_respect_exclusions():
    probes = _synthetic_probes(
        net("192.168.122.0/24"), {addr("192.168.122.1"), addr("192.168.122.128")}
    )
    assert addr("192.168.122.1") not in probes
    assert addr("192.168.122.128") not in probes
    assert probes


def test_synthetic_probe_skips_host_owned_addresses():
    """Probing the gateway would always resolve `local dev lo` and mask capture."""
    probe = _synthetic_probe(net("172.18.0.0/16"), {addr("172.18.0.1")})
    assert probe == addr("172.18.0.2")


def test_synthetic_probe_skips_several_owned_addresses():
    owned = {addr("192.168.122.1"), addr("192.168.122.2")}
    assert _synthetic_probe(net("192.168.122.0/24"), owned) == addr("192.168.122.3")


def test_live_probes_exclude_the_gateway():
    network = DockerNetwork(
        id=NET_ID,
        name="ciscomvent-test-net",
        bridge=BRIDGE,
        subnets=SUBNETS,
        container_ips=(addr("172.18.0.1"), addr("172.18.0.5")),
    )
    probes, synthetic = _probes_for_docker(network, set())
    assert probes == (addr("172.18.0.5"),)
    assert synthetic is False


def test_probes_fall_back_to_synthetic_when_no_containers():
    network = DockerNetwork(
        id=NET_ID, name="ciscomvent-test-net", bridge=BRIDGE, subnets=SUBNETS
    )
    probes, synthetic = _probes_for_docker(network, set())
    assert synthetic is True
    # Spread across the range, not just the low end -- see
    # test_synthetic_probes_do_not_all_sit_at_the_bottom_of_the_subnet.
    assert probes == (addr("172.18.0.2"), addr("172.18.128.0"))


def test_live_probes_are_capped():
    ips = tuple(addr(f"172.18.0.{i}") for i in range(2, 40))
    network = DockerNetwork(
        id=NET_ID,
        name="ciscomvent-test-net",
        bridge=BRIDGE,
        subnets=SUBNETS,
        container_ips=ips,
    )
    probes, _ = _probes_for_docker(network, set())
    assert len(probes) == 4


def test_docker_scopes_are_enabled_and_carry_full_host_list():
    ips = tuple(addr(f"172.18.0.{i}") for i in range(2, 20))
    network = DockerNetwork(
        id=NET_ID,
        name="ciscomvent-test-net",
        bridge=BRIDGE,
        subnets=SUBNETS,
        container_ips=ips,
        bridge_source="derived",
    )
    scopes, warnings = docker_scopes([network], set())
    assert not warnings
    assert len(scopes) == 1
    scope = scopes[0]
    assert scope.kind is ScopeKind.DOCKER
    assert scope.enabled_by_default is True
    assert scope.device == BRIDGE
    # probes are a capped sample; hosts is the full set used for /32 fallback
    assert len(scope.probes) == 4
    assert len(scope.hosts) == len(ips)


def test_unresolved_network_is_warned_not_silently_dropped():
    network = DockerNetwork(
        id=NET_ID, name="broken", bridge=None, subnets=SUBNETS
    )
    scopes, warnings = docker_scopes([network], set())
    assert scopes == []
    assert len(warnings) == 1
    assert "broken" in warnings[0]


def _iface(ifname: str, address: str, prefixlen: int) -> InterfaceAddress:
    return InterfaceAddress(
        ifname=ifname, address=addr(address), prefixlen=prefixlen, scope="global"
    )


def test_a_normal_lease_is_offered_as_a_lan_scope():
    scopes, warnings = _host_scopes(
        [_iface("wlp0s20f3", "192.168.1.50", 24)],
        ScopeKind.LAN,
        set(),
        "note",
        Config(),
    )
    assert warnings == []
    assert [s.name for s in scopes] == ["lan:wlp0s20f3"]
    assert scopes[0].networks == (net("192.168.1.0/24"),)
    assert scopes[0].enabled_by_default is False


def test_a_hostile_lease_is_not_offered_as_a_scope_at_all():
    """The LAN prefix is whatever the lease says, so a hostile network can make
    the scope 10.0.0.0/8. The claim guard would refuse to install a rule that
    wide, but listing it anyway presents a number supplied by the wire as a
    property of this host, one config edit from a priority-100 claim."""
    scopes, warnings = _host_scopes(
        [_iface("wlp0s20f3", "10.1.2.3", 8)], ScopeKind.LAN, set(), "note", Config()
    )
    assert scopes == []
    assert len(warnings) == 1
    assert "lan:wlp0s20f3" in warnings[0]
    assert "10.0.0.0/8" in warnings[0]
    assert "allow_wide_claims" in warnings[0]


def test_an_oversized_prefix_is_warned_not_silently_dropped():
    """Silence here is indistinguishable from an interface that was never
    discovered, which is the same silence the guard exists to break."""
    _, warnings = _host_scopes(
        [_iface("virbr9", "10.1.2.3", 8)], ScopeKind.LIBVIRT, set(), "note", Config()
    )
    assert len(warnings) == 1
    assert "libvirt:virbr9" in warnings[0]


def test_only_the_oversized_address_is_dropped_from_an_interface():
    """Refusing per address, not per interface: a second address of a sane size
    on the same NIC is still a legitimate scope, and dropping it alongside the
    oversized one would refuse a repair for nothing."""
    scopes, warnings = _host_scopes(
        [_iface("eth0", "10.1.2.3", 8), _iface("eth0", "192.168.4.5", 24)],
        ScopeKind.LAN,
        set(),
        "note",
        Config(),
    )
    assert len(scopes) == 1
    assert scopes[0].networks == (net("192.168.4.0/24"),)
    assert all(p in net("192.168.4.0/24") for p in scopes[0].probes)
    assert len(warnings) == 1
    assert "10.0.0.0/8" in warnings[0]


def test_the_explicit_cidr_opt_in_reaches_discovery_too():
    """allow_wide_claims is how a wide network is claimed on purpose. Honoured
    by the guard but not by discovery, the scope would never be offered and the
    opt-in would silently do nothing."""
    config = Config(allow_wide_claims=["10.0.0.0/8"])
    scopes, warnings = _host_scopes(
        [_iface("wlp0s20f3", "10.1.2.3", 8)], ScopeKind.LAN, set(), "note", config
    )
    assert warnings == []
    assert scopes[0].networks == (net("10.0.0.0/8"),)


def test_discovery_refuses_exactly_the_widths_the_claim_guard_refuses():
    """One ceiling, asserted from both ends. Enforced twice in two spellings it
    would eventually disagree with itself, and the disagreement that matters is
    discovery hiding a scope the guard was willing to claim."""
    config = Config()
    vpn = VpnState()  # no captured prefixes, so claim_refusal is width alone
    for prefixlen in (8, 12, 15, 16, 20, 24):
        network = net(f"10.0.0.0/{prefixlen}")
        _, warnings = _host_scopes(
            [_iface("eth0", "10.0.0.1", prefixlen)],
            ScopeKind.LAN,
            set(),
            "note",
            config,
        )
        assert bool(warnings) is bool(claim_refusal(network, vpn, config)), network
