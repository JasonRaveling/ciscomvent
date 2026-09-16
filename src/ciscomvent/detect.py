# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Detect whether the VPN has captured a scope.

Detection is empirical: ask the kernel where a real container address would go
right now and compare against the device that owns it. We never infer from the
presence of the tunnel alone.
"""

from __future__ import annotations

import ipaddress

from .discovery import VPN_DEVICE_PREFIXES, is_vpn_device
from .iproute import addresses, link_names, route_get, routes
from .model import (
    IPv4Network,
    RouteObservation,
    Scope,
    ScopeDiagnosis,
    ScopeKind,
    ScopeState,
    VpnState,
)

__all__ = [
    "VPN_DEVICE_PREFIXES",
    "vpn_state",
    "diagnose_scope",
    "diagnose_all",
    "classify",
]


def vpn_devices() -> tuple[str, ...]:
    return tuple(sorted(n for n in link_names() if is_vpn_device(n)))


def vpn_state() -> VpnState:
    """Current tunnel presence, address, and the prefixes it has captured."""
    devices = vpn_devices()
    if not devices:
        return VpnState()

    devset = set(devices)
    addrs = tuple(
        str(a.address) for a in addresses() if a.ifname in devset
    )

    captured: list[IPv4Network] = []
    has_default = False
    for route in routes():
        if route.get("dev") not in devset:
            continue
        dst = route.get("dst")
        if not dst:
            continue
        if dst == "default":
            has_default = True
            continue
        try:
            captured.append(ipaddress.ip_network(dst, strict=False))
        except ValueError:
            continue

    return VpnState(
        devices=devices,
        addresses=addrs,
        captured_prefixes=tuple(captured),
        has_default_route=has_default,
    )


def classify(
    scope: Scope, vpn: VpnState, observations: tuple[RouteObservation, ...]
) -> tuple[ScopeState, str]:
    """Reduce a set of route observations to a single scope state."""
    if not observations:
        return ScopeState.NO_PROBE, "no probe address available"

    errored = [o for o in observations if o.error]
    local = [o for o in observations if not o.error and o.is_local]
    usable = [o for o in observations if not o.error and not o.is_local]

    if not usable:
        if errored and not local:
            return ScopeState.ERROR, errored[0].error or "route lookup failed"
        # Every probe resolved to a host-owned address, which the kernel `local`
        # table always wins. That says nothing about capture.
        return ScopeState.NO_PROBE, "all probes are host-owned addresses"

    devset = set(vpn.devices)
    via_vpn = [o for o in usable if o.dev in devset]
    if via_vpn:
        devs = sorted({o.dev for o in via_vpn if o.dev})
        return (
            ScopeState.CAPTURED,
            f"{len(via_vpn)}/{len(usable)} probe(s) route via {', '.join(devs)} "
            f"instead of {scope.device}",
        )

    wrong = [o for o in usable if o.dev != scope.device]
    if wrong:
        devs = sorted({o.dev or "?" for o in wrong})
        return (
            ScopeState.MISROUTED,
            f"{len(wrong)}/{len(usable)} probe(s) route via {', '.join(devs)}, "
            f"expected {scope.device}",
        )

    return ScopeState.HEALTHY, f"all probes route via {scope.device}"


def diagnose_scope(scope: Scope, vpn: VpnState) -> ScopeDiagnosis:
    observations = tuple(route_get(str(p)) for p in scope.probes)
    state, note = classify(scope, vpn, observations)
    if scope.probes_synthetic and state is not ScopeState.NO_PROBE:
        why = (
            "no running containers"
            if scope.kind is ScopeKind.DOCKER
            else "no enumerable endpoints"
        )
        note += f" (synthetic probe: {why})"
    return ScopeDiagnosis(
        scope=scope, state=state, observations=observations, note=note
    )


def diagnose_all(scopes: tuple[Scope, ...], vpn: VpnState) -> list[ScopeDiagnosis]:
    return [diagnose_scope(s, vpn) for s in scopes]
