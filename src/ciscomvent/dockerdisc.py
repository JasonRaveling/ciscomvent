# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Docker bridge network discovery.

Uses the docker CLI rather than the SDK to keep the core dependency-free. The
user is in the ``docker`` group, so none of this needs privilege.

Nothing here may hardcode a subnet, bridge name, or container address. The
addresses observed during triage had already been reassigned to different
containers by the time the code was written.
"""

from __future__ import annotations

import ipaddress
import json
import shutil
from dataclasses import dataclass, field

from .errors import CommandError
from .iproute import interface_by_address, link_names, run
from .model import IPv4Address, Subnet

DOCKER_BRIDGE_NAME_OPTION = "com.docker.network.bridge.name"

# Linux caps interface names at 15 chars, so Docker uses br- plus 12 hex chars.
DERIVED_BRIDGE_PREFIX = "br-"
DERIVED_BRIDGE_ID_CHARS = 12


@dataclass(frozen=True)
class DockerNetwork:
    id: str
    name: str
    bridge: str | None
    subnets: tuple[Subnet, ...]
    container_ips: tuple[IPv4Address, ...] = ()
    containers: tuple[tuple[str, IPv4Address], ...] = ()
    bridge_source: str = "unresolved"
    labels: dict = field(default_factory=dict)

    @property
    def resolved(self) -> bool:
        return self.bridge is not None


def docker_binary() -> str | None:
    return shutil.which("docker")


def docker_available() -> bool:
    """True if the docker CLI exists and the daemon answers."""
    binary = docker_binary()
    if not binary:
        return False
    try:
        run([binary, "version", "--format", "{{.Server.Version}}"], timeout=10.0)
        return True
    except (CommandError, OSError):
        return False


def _bridge_network_ids(binary: str) -> list[str]:
    out = run(
        [binary, "network", "ls", "--filter", "driver=bridge", "--format", "{{.ID}}"],
        timeout=10.0,
    )
    return [line.strip() for line in out.splitlines() if line.strip()]


def _inspect(binary: str, ids: list[str]) -> list[dict]:
    if not ids:
        return []
    out = run([binary, "network", "inspect", *ids], timeout=15.0)
    try:
        data = json.loads(out)
    except json.JSONDecodeError as exc:
        raise CommandError(
            [binary, "network", "inspect"], 0, f"unparseable JSON: {exc}"
        ) from exc
    return data if isinstance(data, list) else [data]


def _parse_subnets(inspected: dict) -> tuple[Subnet, ...]:
    out: list[Subnet] = []
    ipam = inspected.get("IPAM") or {}
    for cfg in ipam.get("Config") or []:
        raw = cfg.get("Subnet")
        if not raw:
            continue
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        if network.version != 4:
            continue
        gateway = None
        if cfg.get("Gateway"):
            try:
                gateway = ipaddress.ip_address(cfg["Gateway"])
            except ValueError:
                gateway = None
        out.append(Subnet(network=network, gateway=gateway))
    return tuple(out)


def _parse_containers(inspected: dict) -> tuple[tuple[str, IPv4Address], ...]:
    """(name, address) pairs. Addresses arrive as CIDR like '172.18.0.5/16'."""
    out: list[tuple[str, IPv4Address]] = []
    for entry in (inspected.get("Containers") or {}).values():
        raw = entry.get("IPv4Address") or ""
        if not raw:
            continue
        try:
            address = ipaddress.ip_interface(raw).ip
        except ValueError:
            continue
        out.append((entry.get("Name") or "", address))
    return tuple(sorted(out, key=lambda pair: pair[1]))


def _parse_container_ips(inspected: dict) -> tuple[IPv4Address, ...]:
    """Container addresses only, deduplicated and ordered."""
    seen: dict[IPv4Address, None] = {}
    for _, address in _parse_containers(inspected):
        seen[address] = None
    return tuple(seen)


def resolve_bridge(
    network_id: str,
    options: dict,
    subnets: tuple[Subnet, ...],
    existing_links: set[str],
    addr_owner: dict[IPv4Address, str],
) -> tuple[str | None, str]:
    """Determine the host interface backing a Docker network.

    Returns ``(name, source)``. Resolution order deliberately prefers evidence
    over convention: a candidate name is only accepted outright once the
    interface is confirmed to hold the network's gateway address. Otherwise we
    search for whichever interface actually owns that address, and only fall
    back to an unverified name when there is nothing to check against.
    """
    gateways = {s.gateway for s in subnets if s.gateway}

    explicit = (options or {}).get(DOCKER_BRIDGE_NAME_OPTION)
    derived = DERIVED_BRIDGE_PREFIX + network_id[:DERIVED_BRIDGE_ID_CHARS]

    for candidate, source in ((explicit, "option"), (derived, "derived")):
        if not candidate or candidate not in existing_links:
            continue
        if any(addr_owner.get(gw) == candidate for gw in gateways):
            return candidate, source

    for gw in gateways:
        owner = addr_owner.get(gw)
        if owner:
            return owner, "gateway-match"

    # No gateway to verify against (an internal network, or one with no
    # containers yet). Accept the name if the interface exists at all.
    for candidate, source in ((explicit, "option"), (derived, "derived")):
        if candidate and candidate in existing_links:
            return candidate, f"{source}-unverified"

    return None, "unresolved"


def list_bridge_networks() -> list[DockerNetwork]:
    """All local bridge networks, with their subnets, bridge, and containers."""
    binary = docker_binary()
    if not binary:
        return []

    ids = _bridge_network_ids(binary)
    inspected = _inspect(binary, ids)

    existing_links = link_names()
    addr_owner = interface_by_address()

    out: list[DockerNetwork] = []
    for entry in inspected:
        network_id = entry.get("Id") or ""
        subnets = _parse_subnets(entry)
        if not subnets:
            continue
        bridge, source = resolve_bridge(
            network_id,
            entry.get("Options") or {},
            subnets,
            existing_links,
            addr_owner,
        )
        out.append(
            DockerNetwork(
                id=network_id,
                name=entry.get("Name") or network_id[:12],
                bridge=bridge,
                subnets=subnets,
                container_ips=_parse_container_ips(entry),
                containers=_parse_containers(entry),
                bridge_source=source,
                labels=entry.get("Labels") or {},
            )
        )
    return sorted(out, key=lambda n: n.name)
