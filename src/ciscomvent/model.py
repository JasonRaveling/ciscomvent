# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Core data model: scopes, subnets, and diagnosis results."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum

IPv4Network = ipaddress.IPv4Network
IPv4Address = ipaddress.IPv4Address


class ScopeKind(str, Enum):
    DOCKER = "docker"
    LAN = "lan"
    LIBVIRT = "libvirt"


MAX_SCOPE_NAME = 128

_SCOPE_NAME = re.compile(
    r"^(?:" + "|".join(k.value for k in ScopeKind) + r"):[A-Za-z0-9][A-Za-z0-9_.-]*$"
)
"""Shape of a real scope name: ``kind:device`` (see ``discovery``).

Derived from ScopeKind so a new kind cannot silently fail validation. Nothing
here reaches a shell, so this is not injection defence -- it stops arbitrary
strings accumulating in the daemon's memory and, for a root caller, in
/etc/ciscomvent/config.json, and it keeps a name that argparse would read as an
option out of an argv handed to pkexec.
"""


def checked_scope(value) -> str:
    """The scope name in ``value``, or raise ValueError.

    Lives here rather than in ``daemon`` because both ends of every privileged
    path need it: the daemon before it acts on a request, and the GUI before it
    puts a name in an argv that will be executed as root.
    """
    if not isinstance(value, str) or not value:
        raise ValueError("that command needs a scope")
    if len(value) > MAX_SCOPE_NAME:
        raise ValueError(f"scope name too long (limit {MAX_SCOPE_NAME} characters)")
    if not _SCOPE_NAME.match(value):
        kinds = ", ".join(k.value for k in ScopeKind)
        raise ValueError(f"not a scope name: {value!r} (expected one of {kinds} + ':')")
    return value


class ScopeState(str, Enum):
    """Result of comparing observed routing against the expected device."""

    HEALTHY = "healthy"
    """Traffic routes via the scope's own device. Nothing to do."""

    CAPTURED = "captured"
    """Traffic routes via the VPN tunnel. This is the condition we fix."""

    MISROUTED = "misrouted"
    """Traffic routes somewhere that is neither the device nor the tunnel."""

    NO_PROBE = "no_probe"
    """No address could be probed, so no claim is made."""

    ERROR = "error"
    """Route lookup failed outright."""


@dataclass(frozen=True)
class NextHop:
    """How to reach a reclaimed prefix.

    Locally-attached scopes -- every scope this tool currently supports -- route
    straight out a device, because a local interface already owns the subnet.

    External split routing would instead route *via* a gateway on that device
    (send this external prefix out the physical NIC rather than the tunnel).
    That is deliberately not implemented: it is a genuine policy circumvention
    rather than a repair, and it needs source-address handling and probably DNS
    interception to be useful. Modeling both forms here keeps the route builder
    from hardcoding the local case, so adding it later is an extension rather
    than a rewrite.
    """

    device: str
    gateway: IPv4Address | None = None

    @property
    def is_local(self) -> bool:
        """True when a local interface owns the subnet, so no gateway is needed."""
        return self.gateway is None

    def route_args(self) -> list[str]:
        """The `ip route` arguments selecting this next hop."""
        if self.gateway is None:
            return ["dev", self.device]
        return ["via", str(self.gateway), "dev", self.device]

    def render(self) -> str:
        return " ".join(self.route_args())

    def as_dict(self) -> dict:
        return {
            "device": self.device,
            "gateway": str(self.gateway) if self.gateway else None,
            "is_local": self.is_local,
        }


@dataclass(frozen=True)
class Subnet:
    network: IPv4Network
    gateway: IPv4Address | None = None

    def as_dict(self) -> dict:
        return {
            "network": str(self.network),
            "gateway": str(self.gateway) if self.gateway else None,
        }


@dataclass(frozen=True)
class Scope:
    """A set of subnets reachable through one device.

    ``enabled_by_default`` is the policy split:
    Docker bridges are on, LAN and libvirt are discovered but off until the user
    deliberately enables them.
    """

    name: str
    kind: ScopeKind
    device: str
    subnets: tuple[Subnet, ...]
    probes: tuple[IPv4Address, ...] = ()
    probes_synthetic: bool = False
    enabled_by_default: bool = False
    detail: str = ""
    metadata: dict = field(default_factory=dict)

    hosts: tuple[IPv4Address, ...] = ()
    """Every live address in this scope. ``probes`` is a capped sample of these
    used for detection; ``hosts`` is the full set, needed when falling back to
    per-host reclaim routes."""

    @property
    def networks(self) -> tuple[IPv4Network, ...]:
        return tuple(s.network for s in self.subnets)

    @property
    def nexthop(self) -> NextHop:
        """Every scope discovered today is locally attached, so no gateway."""
        return NextHop(device=self.device)

    def covers(self, addr: IPv4Address) -> bool:
        return any(addr in s.network for s in self.subnets)

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "kind": self.kind.value,
            "device": self.device,
            "subnets": [s.as_dict() for s in self.subnets],
            "probes": [str(p) for p in self.probes],
            "probes_synthetic": self.probes_synthetic,
            "hosts": [str(h) for h in self.hosts],
            "enabled_by_default": self.enabled_by_default,
            "detail": self.detail,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class RouteObservation:
    """One ``ip route get`` result."""

    target: str
    dev: str | None = None
    prefsrc: str | None = None
    rtype: str | None = None
    gateway: str | None = None
    error: str | None = None

    @property
    def is_local(self) -> bool:
        """Host-owned address. The kernel ``local`` table outranks anything the
        VPN client installs, which is why loopback and bridge gateways keep
        working while container addresses break."""
        return self.rtype == "local"

    def as_dict(self) -> dict:
        return {
            "target": self.target,
            "dev": self.dev,
            "prefsrc": self.prefsrc,
            "type": self.rtype,
            "gateway": self.gateway,
            "error": self.error,
        }


@dataclass(frozen=True)
class ScopeDiagnosis:
    scope: Scope
    state: ScopeState
    observations: tuple[RouteObservation, ...]
    note: str = ""

    @property
    def needs_fix(self) -> bool:
        return self.state in (ScopeState.CAPTURED, ScopeState.MISROUTED)

    def as_dict(self) -> dict:
        return {
            "scope": self.scope.name,
            "kind": self.scope.kind.value,
            "device": self.scope.device,
            "state": self.state.value,
            "needs_fix": self.needs_fix,
            "note": self.note,
            "observations": [o.as_dict() for o in self.observations],
        }


@dataclass(frozen=True)
class VpnState:
    """Presence of the Secure Client tunnel and what it currently shadows."""

    devices: tuple[str, ...] = ()
    addresses: tuple[str, ...] = ()
    captured_prefixes: tuple[IPv4Network, ...] = ()
    has_default_route: bool = False

    @property
    def connected(self) -> bool:
        return bool(self.devices)

    @property
    def tunnel_all(self) -> bool:
        """Tunnel-all is what makes this failure mode reachable; a split-include
        headend would not capture the bridges."""
        return self.connected and self.has_default_route

    def shadows(self, network: IPv4Network) -> IPv4Network | None:
        """The tunnel route covering ``network``, if any."""
        for p in self.captured_prefixes:
            if network.subnet_of(p) or p.subnet_of(network):
                return p
        return None

    def as_dict(self) -> dict:
        return {
            "connected": self.connected,
            "devices": list(self.devices),
            "addresses": list(self.addresses),
            "tunnel_all": self.tunnel_all,
            "captured_prefixes": [str(p) for p in self.captured_prefixes],
        }
