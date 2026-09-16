# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Desired-vs-actual reconciliation.

The daemon never applies blindly; it computes what *should* be claimed, reads
what *is* claimed, and emits only the delta. That makes it idempotent by
construction and makes cleanup on disconnect fall out of the same code path
rather than needing a special case.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field, replace

from .apply import ROUTE_TABLE, RULE_PRIORITY, installed_firewall_scopes
from .config import Config
from .errors import CommandError
from .iproute import ip_binary, link_is_up, link_states, run_json
from .model import IPv4Network, Scope, VpnState


@dataclass(frozen=True)
class Claim:
    """One subnet asserted to route via one device."""

    network: IPv4Network
    device: str

    def as_dict(self) -> dict:
        return {"network": str(self.network), "device": self.device}


@dataclass(frozen=True)
class Refusal:
    """A subnet the guard would not let us claim, and why."""

    network: IPv4Network
    scope: str
    reason: str

    def as_dict(self) -> dict:
        return {
            "network": str(self.network),
            "scope": self.scope,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class DesiredClaims:
    """What should be claimed right now, plus what was refused getting there.

    Refusals are carried rather than dropped: a subnet silently absent from
    desired state is indistinguishable from one that was never discovered, and
    the whole point of the guard is that the operator finds out.
    """

    claims: dict[IPv4Network, Scope] = field(default_factory=dict)
    refused: tuple[Refusal, ...] = ()


@dataclass(frozen=True)
class ReconcilePlan:
    to_add: tuple[Scope, ...] = ()
    to_remove: tuple[Claim, ...] = ()
    unchanged: tuple[Claim, ...] = ()

    desired_scopes: tuple[str, ...] = ()
    """Every scope that should be claimed right now. Lets the caller prune
    firewall rules belonging to scopes that are no longer wanted, which the
    per-network claim deltas cannot express."""

    refused: tuple[Refusal, ...] = ()
    """Subnets the guard rejected. Not part of the delta -- there is nothing to
    do about them -- but the daemon logs them and clients show them."""

    @property
    def is_noop(self) -> bool:
        return not self.to_add and not self.to_remove

    def summary(self) -> str:
        parts = []
        if self.to_add:
            parts.append(f"+{len(self.to_add)} scope(s)")
        if self.to_remove:
            parts.append(f"-{len(self.to_remove)} stale claim(s)")
        if not parts:
            parts.append(f"in sync ({len(self.unchanged)} claim(s))")
        if self.refused:
            # A plan reading "in sync" while a subnet is being refused would be
            # the same silence the guard exists to break.
            parts.append(f"{len(self.refused)} refused")
        return ", ".join(parts)

    def as_dict(self) -> dict:
        return {
            "to_add": [s.name for s in self.to_add],
            "to_remove": [c.as_dict() for c in self.to_remove],
            "unchanged": [c.as_dict() for c in self.unchanged],
            "refused": [r.as_dict() for r in self.refused],
        }


def claim_refusal(
    network: IPv4Network, vpn: VpnState, config: Config
) -> str | None:
    """Why ``network`` must not be claimed, or None if it may be.

    A claim is `ip rule to <network> ... priority 100`, consulted ahead of
    `main` at 32766. That is the whole design, and it means a claim also
    outranks the tunnel's own routes. The subnet is supplied by whoever created
    the network, and creating a Docker network needs no root, so without a
    guard here `docker network create --subnet 10.0.0.0/8` pulls every
    corporate destination in 10/8 off the tunnel and onto a bridge -- where a
    container can answer for those addresses, which makes it an interception
    primitive rather than only a black-hole.

    Overlapping a captured prefix is deliberately **not** the test. Overlap is
    the normal case and the reason this tool exists: a bridge inside a range
    the headend captured is exactly what it repairs. The two things that are
    never a repair are a claim wider than any bridge needs, and a claim that
    swallows a tunnel prefix whole.
    """
    if config.wide_claim_allowed(network):
        return None

    # The ceiling lives on Config because discovery applies it too, refusing to
    # offer a host interface whose prefix could never be claimed.
    too_wide = config.width_refusal(network)
    if too_wide:
        return too_wide

    # Strict superset only: equality is the ordinary conflict this tool was
    # written for -- the headend captured the bridge's own subnet.
    swallowed = [
        p for p in vpn.captured_prefixes if p != network and p.subnet_of(network)
    ]
    if swallowed:
        return (
            "it contains tunnel prefix "
            + ", ".join(str(p) for p in swallowed)
            + ", which claiming it would divert off the tunnel entirely"
        )

    return None


def desired_claims(
    scopes: tuple[Scope, ...],
    vpn: VpnState,
    config: Config,
    states: dict[str, str] | None = None,
) -> DesiredClaims:
    """What we should be claiming right now.

    Deliberately **not** conditioned on whether a scope is currently captured.
    Applying the fix makes a captured scope look healthy, so gating on the
    diagnosis would make the daemon tear down its own routes and reinstall them
    forever. The stable predicate is: tunnel up, scope enabled, device live --
    plus a subnet the guard will allow.

    With the tunnel down this returns nothing, which is what drives cleanup on
    disconnect -- the same delta machinery, no special case.
    """
    if not vpn.connected:
        return DesiredClaims()

    states = link_states() if states is None else states
    claims: dict[IPv4Network, Scope] = {}
    refused: list[Refusal] = []
    for scope in scopes:
        if not config.scope_enabled(scope.name, scope.enabled_by_default):
            continue
        if not link_is_up(scope.device, states):
            continue

        keep = []
        for subnet in scope.subnets:
            reason = claim_refusal(subnet.network, vpn, config)
            if reason:
                refused.append(
                    Refusal(network=subnet.network, scope=scope.name, reason=reason)
                )
                continue
            keep.append(subnet)

        if not keep:
            continue
        # Narrow the scope itself, not just this dict. policy_actions and
        # firewall_actions both iterate scope.subnets, so a scope that reached
        # them intact would install the route for a subnet refused here.
        allowed = (
            scope if len(keep) == len(scope.subnets)
            else replace(scope, subnets=tuple(keep))
        )
        for subnet in keep:
            claims[subnet.network] = allowed

    return DesiredClaims(claims=claims, refused=tuple(refused))


def _ruled_networks() -> set[IPv4Network]:
    try:
        entries = run_json(
            [ip_binary(), "-j", "rule", "show", "priority", str(RULE_PRIORITY)]
        )
    except CommandError:
        return set()

    out: set[IPv4Network] = set()
    for entry in entries or []:
        dst, dstlen = entry.get("dst"), entry.get("dstlen")
        if not dst:
            continue
        try:
            out.add(ipaddress.ip_network(f"{dst}/{dstlen if dstlen is not None else 32}"))
        except ValueError:
            continue
    return out


def _table_routes() -> dict[IPv4Network, str]:
    try:
        entries = run_json(
            [ip_binary(), "-j", "-4", "route", "show", "table", str(ROUTE_TABLE)]
        )
    except CommandError:
        return {}

    out: dict[IPv4Network, str] = {}
    for entry in entries or []:
        dst, dev = entry.get("dst"), entry.get("dev")
        if not dst or not dev:
            continue
        try:
            out[ipaddress.ip_network(dst, strict=False)] = dev
        except ValueError:
            continue
    return out


def actual_claims() -> tuple[set[Claim], set[IPv4Network]]:
    """What is claimed right now.

    Returns complete claims plus every network mentioned by either half. A rule
    without its route (or vice versa) is not a claim, but it is still ours and
    still has to be cleaned up, so the caller needs both.
    """
    ruled = _ruled_networks()
    routed = _table_routes()

    complete = {
        Claim(network=network, device=device)
        for network, device in routed.items()
        if network in ruled
    }
    return complete, ruled | set(routed)


def reconcile(
    scopes: tuple[Scope, ...], vpn: VpnState, config: Config
) -> ReconcilePlan:
    wanted = desired_claims(scopes, vpn, config)
    desired = wanted.claims
    complete, touched = actual_claims()
    by_network = {c.network: c for c in complete}

    # Cisco rebuilds its firewall chains on connect, which takes our accepts
    # with them. Routing can therefore be perfectly in sync while the rules
    # that make it usable are gone -- so the rules are part of desired state,
    # not a one-off escalation.
    firewall = installed_firewall_scopes() if config.firewall else None

    to_add: list[Scope] = []
    unchanged: list[Claim] = []
    seen: set[str] = set()

    def want(scope: Scope) -> None:
        if scope.name not in seen:
            to_add.append(scope)
            seen.add(scope.name)

    for network, scope in desired.items():
        existing = by_network.get(network)
        routed = existing is not None and existing.device == scope.device
        ruled = firewall is None or scope.name in firewall

        if routed and ruled:
            unchanged.append(existing)
            continue
        # Missing, half-installed, pointing at the wrong device (the bridge was
        # recreated under a new name), or missing its accepts. Re-applying is
        # idempotent either way.
        want(scope)

    to_remove = tuple(
        sorted(
            (
                by_network.get(network) or Claim(network=network, device="")
                for network in touched
                if network not in desired
            ),
            key=lambda c: str(c.network),
        )
    )

    return ReconcilePlan(
        to_add=tuple(to_add),
        to_remove=to_remove,
        unchanged=tuple(unchanged),
        desired_scopes=tuple(sorted({s.name for s in desired.values()})),
        refused=wanted.refused,
    )
