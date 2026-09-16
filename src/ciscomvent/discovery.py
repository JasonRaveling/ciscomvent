# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Assemble routable scopes from live host state.

Docker bridges are enabled by default. LAN and libvirt are discovered and
reported but disabled: restoring a local dev stack is a workstation concern,
whereas blanket LAN restoration under a tunnel-all policy is not.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass

from .config import Config
from .dockerdisc import DockerNetwork, docker_available, list_bridge_networks
from .errors import CommandError
from .iproute import InterfaceAddress, addresses
from .model import IPv4Address, IPv4Network, Scope, ScopeKind, Subnet

# Probing every container is wasteful and slows `status` on a large stack; a
# handful is enough to establish which device the kernel picks.
MAX_LIVE_PROBES = 4

# How far into a subnet to search for a usable synthetic probe address.
SYNTHETIC_PROBE_SEARCH = 16

LIBVIRT_PREFIXES = ("virbr",)
VPN_DEVICE_PREFIXES = ("cscotun",)

# Interfaces that are never a scope of their own.
_NEVER_SCOPE = ("lo",)

LAN_DISABLED_NOTE = (
    "disabled by default: restoring LAN reach under an explicit tunnel-all "
    "policy is a campus IT conversation, not a workstation default"
)
LIBVIRT_DISABLED_NOTE = "disabled by default; enable if you need VM reachability"


@dataclass(frozen=True)
class DiscoveryResult:
    scopes: tuple[Scope, ...]
    warnings: tuple[str, ...] = ()
    docker_ok: bool = True

    def enabled(self) -> tuple[Scope, ...]:
        return tuple(s for s in self.scopes if s.enabled_by_default)

    def as_dict(self) -> dict:
        return {
            "docker_available": self.docker_ok,
            "warnings": list(self.warnings),
            "scopes": [s.as_dict() for s in self.scopes],
        }


def is_vpn_device(name: str) -> bool:
    return name.startswith(VPN_DEVICE_PREFIXES)


def _synthetic_probe(
    network: IPv4Network, exclude: set[IPv4Address]
) -> IPv4Address | None:
    """First usable address in ``network`` that this host does not own.

    Probing a host-owned address is useless: the kernel ``local`` table outranks
    anything the VPN installs, so a bridge gateway always resolves ``local dev
    lo`` and would mask a capture that is really there.
    """
    for host in itertools.islice(network.hosts(), SYNTHETIC_PROBE_SEARCH):
        if host not in exclude:
            return host
    return None


def _synthetic_probes(
    network: IPv4Network, exclude: set[IPv4Address]
) -> tuple[IPv4Address, ...]:
    """Spread-out probe addresses for a subnet with nothing enumerable in it.

    Deliberately more than one, and not all at the bottom of the range. Secure
    Client installs a host route for the LAN gateway pointing at the physical
    NIC. It needs that address to reach the headend, so it carves it out of
    its own capture. On a typical LAN the gateway *is* the lowest usable
    address, so probing only there reports the whole subnet healthy while every
    other address in it is captured. Observed live on 192.168.1.0/24: .1 routed
    via wlp0s20f3 while .50, .128 and .200 all routed via cscotun0.
    """
    candidates: list[IPv4Address] = []

    low = _synthetic_probe(network, exclude)
    if low is not None:
        candidates.append(low)

    # Midpoint: past anything a client is likely to special-case, since those
    # carve-outs (gateways, DHCP servers) sit at the bottom of a subnet.
    if network.num_addresses >= 4:
        mid = network.network_address + network.num_addresses // 2
        if mid not in exclude and mid != network.broadcast_address:
            candidates.append(mid)

    seen: dict[IPv4Address, None] = {}
    for candidate in candidates:
        seen[candidate] = None
    return tuple(seen)


def _probes_for_docker(
    network: DockerNetwork, host_addrs: set[IPv4Address]
) -> tuple[tuple[IPv4Address, ...], bool]:
    """Probe addresses for a Docker network, and whether they are synthetic."""
    excluded = set(host_addrs) | {s.gateway for s in network.subnets if s.gateway}

    live = [ip for ip in network.container_ips if ip not in excluded]
    if live:
        return tuple(live[:MAX_LIVE_PROBES]), False

    # No containers running: synthetic addresses in the subnet still reveal
    # which device the kernel would choose, so detection works on an idle stack.
    synthetic: list[IPv4Address] = []
    for subnet in network.subnets:
        synthetic.extend(_synthetic_probes(subnet.network, excluded))
    return tuple(synthetic), True


def docker_scopes(
    networks: list[DockerNetwork], host_addrs: set[IPv4Address]
) -> tuple[list[Scope], list[str]]:
    scopes: list[Scope] = []
    warnings: list[str] = []

    for net in networks:
        if not net.resolved:
            warnings.append(
                f"docker network {net.name!r} ({net.id[:12]}): could not resolve "
                f"its bridge interface; skipped"
            )
            continue

        excluded = set(host_addrs) | {s.gateway for s in net.subnets if s.gateway}
        live_hosts = tuple(ip for ip in net.container_ips if ip not in excluded)

        probes, synthetic = _probes_for_docker(net, host_addrs)
        if not probes:
            warnings.append(
                f"docker network {net.name!r}: no probe address available; "
                "state cannot be determined"
            )

        subnet_list = ", ".join(str(s.network) for s in net.subnets)
        detail = f"{subnet_list} via {net.bridge}"
        if net.bridge_source.endswith("-unverified"):
            detail += " (bridge name unverified: no gateway to check against)"

        scopes.append(
            Scope(
                name=f"docker:{net.name}",
                kind=ScopeKind.DOCKER,
                device=net.bridge,
                subnets=net.subnets,
                probes=probes,
                probes_synthetic=synthetic,
                hosts=live_hosts,
                enabled_by_default=True,
                detail=detail,
                metadata={
                    "network_id": net.id,
                    "network_name": net.name,
                    "bridge_source": net.bridge_source,
                    "container_count": len(net.container_ips),
                    # JSON-safe so this survives baseline capture; verify.py
                    # joins these names against `docker ps` to find open ports.
                    "containers": [
                        {"name": name, "address": str(address)}
                        for name, address in net.containers
                        if address not in excluded
                    ],
                },
            )
        )
    return scopes, warnings


def _host_scopes(
    ifaces: list[InterfaceAddress],
    kind: ScopeKind,
    host_addrs: set[IPv4Address],
    note: str,
    config: Config,
) -> tuple[list[Scope], list[str]]:
    """Scopes for host interfaces, minus any prefix too wide to be claimable.

    An interface prefix is not a fact this host chose. On DHCP it is whatever
    the lease said, so a hostile network can answer with a /8 and make the LAN
    scope 10.0.0.0/8. The claim guard already refuses to install a rule that
    wide, but without this check discovery still lists the scope, which
    presents a number supplied by the wire as a property of this machine and
    leaves it one config edit away from a priority-100 claim out of the
    physical NIC. Nothing should offer what the guard cannot allow, so the same
    ceiling applies here, read from the same place.

    Refusing is per address rather than per interface: a second address of a
    sane size on the same NIC is still a legitimate scope, and dropping it
    along with the oversized one would refuse a repair for no reason.

    Docker scopes deliberately keep theirs and are refused later, at claim
    time. A bridge is a network created on this host rather than announced to
    it, it is enabled by default, and dropping it here would trade a refusal
    naming the CIDR for an unreachable container with no scope to explain it.
    """
    by_iface: dict[str, list[InterfaceAddress]] = {}
    for addr in ifaces:
        by_iface.setdefault(addr.ifname, []).append(addr)

    scopes: list[Scope] = []
    warnings: list[str] = []
    for ifname, addrs in sorted(by_iface.items()):
        name = f"{kind.value}:{ifname}"
        subnets: list[Subnet] = []
        for a in sorted(addrs, key=lambda a: a.address):
            refusal = config.width_refusal(a.network)
            if refusal:
                warnings.append(
                    f"{name}: not offering {a.network} as a scope, {refusal}. "
                    "To offer it, add its exact CIDR to allow_wide_claims."
                )
                continue
            subnets.append(Subnet(network=a.network, gateway=None))

        # Nothing left to offer, and the warning above already says why.
        # Keeping the scope with no subnets would give it no probes either,
        # so it would sit in `status` as NO_PROBE with nothing to explain it.
        if not subnets:
            continue

        probes: tuple[IPv4Address, ...] = ()
        for subnet in subnets:
            probes += _synthetic_probes(subnet.network, host_addrs)
        scopes.append(
            Scope(
                name=name,
                kind=kind,
                device=ifname,
                subnets=tuple(subnets),
                probes=probes,
                probes_synthetic=True,
                enabled_by_default=False,
                detail=f"{', '.join(str(s.network) for s in subnets)} via {ifname} "
                f"— {note}",
            )
        )
    return scopes, warnings


def discover_scopes(config: Config | None = None) -> DiscoveryResult:
    """Enumerate every scope on the host, with Docker enabled and the rest off.

    ``config`` supplies the ceiling that host interface prefixes are checked
    against, so a caller that has already loaded it gets the operator's value
    rather than the built-in default. Every caller in the tree passes one.
    Omitting it checks against the defaults, which cannot install anything it
    should not: the claim guard reads the real config before any rule goes in.
    """
    config = config or Config()
    warnings: list[str] = []

    all_addrs = addresses()
    host_addrs = {a.address for a in all_addrs}

    docker_ok = docker_available()
    networks: list[DockerNetwork] = []
    if docker_ok:
        try:
            networks = list_bridge_networks()
        except CommandError as exc:
            docker_ok = False
            warnings.append(f"docker discovery failed: {exc}")
    else:
        warnings.append("docker unavailable; no container scopes discovered")

    scopes, docker_warnings = docker_scopes(networks, host_addrs)
    warnings.extend(docker_warnings)

    docker_devices = {s.device for s in scopes}

    libvirt_addrs = [
        a
        for a in all_addrs
        if a.ifname.startswith(LIBVIRT_PREFIXES) and a.scope == "global"
    ]
    libvirt_scopes, libvirt_warnings = _host_scopes(
        libvirt_addrs, ScopeKind.LIBVIRT, host_addrs, LIBVIRT_DISABLED_NOTE, config
    )
    scopes.extend(libvirt_scopes)
    warnings.extend(libvirt_warnings)

    libvirt_devices = {a.ifname for a in libvirt_addrs}
    lan_addrs = [
        a
        for a in all_addrs
        if a.scope == "global"
        and a.ifname not in docker_devices
        and a.ifname not in libvirt_devices
        and not a.ifname.startswith(_NEVER_SCOPE)
        and not is_vpn_device(a.ifname)
    ]
    lan_scopes, lan_warnings = _host_scopes(
        lan_addrs, ScopeKind.LAN, host_addrs, LAN_DISABLED_NOTE, config
    )
    scopes.extend(lan_scopes)
    warnings.extend(lan_warnings)

    return DiscoveryResult(
        scopes=tuple(scopes), warnings=tuple(warnings), docker_ok=docker_ok
    )
