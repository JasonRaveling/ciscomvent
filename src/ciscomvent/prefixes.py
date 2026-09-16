# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Prefix math for winning route lookups by longest-prefix match.

Pure functions, no I/O. This module encodes the core of the fix: Cisco installs
a scope-link route for each locally-discovered subnet pointing at the tunnel, and
we reclaim it by installing a strictly more-specific route pointing at the real
device. We never delete Cisco's route.

A /24 is insufficient in principle: Docker allocates across the whole /16, so
the default is a pair of /17s covering it entirely while staying more specific.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import Enum

IPv4Network = ipaddress.IPv4Network
IPv4Address = ipaddress.IPv4Address

# Splitting a /16 one bit deeper yields 2 routes. Splitting it to /25 to beat a
# competing /24 would yield 512 -- past this many we switch to per-host routes
# instead, which stay small no matter how deep the competition goes.
MAX_SPLIT_ROUTES = 8


class PrefixStrategy(str, Enum):
    """How to construct routes that outrank the tunnel's."""

    SPLIT = "split"
    """Cover the whole subnet with one-bit-longer prefixes. Default."""

    HOST = "host"
    """One /32 per known container address. Immune to prefix mirroring, but
    must be recomputed when containers start or stop."""


@dataclass(frozen=True)
class ReclaimPlan:
    """The prefixes to install for one subnet, and why."""

    subnet: IPv4Network
    prefixes: tuple[IPv4Network, ...]
    strategy: PrefixStrategy
    note: str

    @property
    def is_empty(self) -> bool:
        return not self.prefixes

    def as_dict(self) -> dict:
        return {
            "subnet": str(self.subnet),
            "prefixes": [str(p) for p in self.prefixes],
            "strategy": self.strategy.value,
            "note": self.note,
        }


def split_once(net: IPv4Network) -> list[IPv4Network]:
    """The one-bit-longer subnets that exactly cover ``net``.

    A /16 becomes two /17s. A host route cannot be split and is returned as-is.
    """
    if net.prefixlen >= net.max_prefixlen:
        return [net]
    return list(net.subnets(prefixlen_diff=1))


def host_prefixes(
    subnet: IPv4Network, hosts: tuple[IPv4Address, ...]
) -> list[IPv4Network]:
    """/32 routes for each host in ``subnet``, deduplicated and ordered.

    Hosts outside ``subnet`` are ignored rather than raising: the caller passes
    a whole network's container list and we only route what belongs here.
    """
    seen: dict[IPv4Address, None] = {}
    for h in hosts:
        if h in subnet:
            seen[h] = None
    return [ipaddress.ip_network(f"{h}/32") for h in sorted(seen)]


def plan_reclaim(
    subnet: IPv4Network,
    hosts: tuple[IPv4Address, ...] = (),
    competing_prefixlen: int | None = None,
    strategy: PrefixStrategy = PrefixStrategy.SPLIT,
    max_split: int = MAX_SPLIT_ROUTES,
) -> ReclaimPlan:
    """Build the set of prefixes that will outrank the tunnel's route.

    ``competing_prefixlen`` is the prefix length of the route currently shadowing
    this subnet, when known. Normally that equals ``subnet.prefixlen`` (Cisco
    mirrors the subnet as-is), but if Cisco ever mirrors our own reclaim routes
    we must go deeper still: Secure Client watches the main table and mirrors
    any new prefix onto the tunnel, so a prefix we install can be matched.

    Falls back to per-host routes when going deeper would require an unreasonable
    number of routes, or when the subnet cannot be split any further.
    """
    if strategy is PrefixStrategy.HOST:
        prefixes = host_prefixes(subnet, hosts)
        note = (
            f"{len(prefixes)} host route(s) from {len(hosts)} known address(es)"
            if prefixes
            else "no known container addresses; nothing to reclaim"
        )
        return ReclaimPlan(subnet, tuple(prefixes), PrefixStrategy.HOST, note)

    beat = subnet.prefixlen if competing_prefixlen is None else competing_prefixlen
    target = max(subnet.prefixlen, beat) + 1

    if target > subnet.max_prefixlen:
        prefixes = host_prefixes(subnet, hosts)
        return ReclaimPlan(
            subnet,
            tuple(prefixes),
            PrefixStrategy.HOST,
            f"cannot split beyond /{subnet.max_prefixlen}; fell back to host routes",
        )

    count = 1 << (target - subnet.prefixlen)
    if count > max_split:
        prefixes = host_prefixes(subnet, hosts)
        return ReclaimPlan(
            subnet,
            tuple(prefixes),
            PrefixStrategy.HOST,
            f"beating /{beat} would need {count} routes (>{max_split}); "
            "fell back to host routes",
        )

    split = list(subnet.subnets(new_prefix=target))
    return ReclaimPlan(
        subnet,
        tuple(split),
        PrefixStrategy.SPLIT,
        f"{len(split)} x /{target} covering {subnet} (beats /{beat})",
    )


def outranks(candidate: IPv4Network, competitor: IPv4Network) -> bool:
    """True if ``candidate`` wins a route lookup against ``competitor``.

    Longest-prefix match decides, and only for addresses both routes cover. An
    equal-length prefix is explicitly *not* a win: the kernel then falls through
    to metric and insertion order, which is the fragile tie the mirroring race
    would produce.
    """
    if not candidate.subnet_of(competitor) and not competitor.subnet_of(candidate):
        return False
    return candidate.prefixlen > competitor.prefixlen
