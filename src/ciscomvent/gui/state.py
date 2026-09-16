# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Turning a daemon snapshot into something to display.

Pure -- no Qt. The tray and the window both render from this, and it can be
tested without a display server, which is most of why it is a separate module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Health(str, Enum):
    """Overall state, in the order the tray colour should escalate."""

    UNKNOWN = "unknown"
    """The daemon could not be reached."""

    OFFLINE = "offline"
    """Tunnel down. Nothing to claim and nothing wrong."""

    HEALTHY = "healthy"
    """Every enabled scope is claimed and reachable."""

    PENDING = "pending"
    """Waiting on approval. Confirm mode, working as designed."""

    CAPTURED = "captured"
    """The tunnel has taken a scope we have not reclaimed."""

    FAILING = "failing"
    """Claimed, and still not reachable. Something is wrong."""


COLOURS = {
    Health.UNKNOWN: "#8a8a8a",
    Health.OFFLINE: "#8a8a8a",
    Health.HEALTHY: "#2e9e4f",
    Health.PENDING: "#d98a00",
    Health.CAPTURED: "#d98a00",
    Health.FAILING: "#c0392b",
}

HEADLINES = {
    Health.UNKNOWN: "Daemon not reachable",
    Health.OFFLINE: "VPN disconnected",
    Health.HEALTHY: "Containers reachable",
    Health.PENDING: "Waiting for approval",
    Health.CAPTURED: "VPN has captured your bridges",
    Health.FAILING: "Claimed, but still unreachable",
}


@dataclass(frozen=True)
class ScopeRow:
    name: str
    device: str
    state: str
    enabled: bool
    needs_fix: bool
    detail: str = ""
    device_up: bool = True

    @property
    def marker(self) -> str:
        if not self.enabled:
            return "off"
        if not self.device_up:
            return "idle"
        return "bad" if self.needs_fix else "ok"

    @property
    def display_state(self) -> str:
        """What to show in the State column.

        A bridge with no containers is DOWN and technically captured, but
        reporting that as a problem is noise -- there is nothing behind it to
        reach, and we deliberately do not claim it.
        """
        if not self.enabled:
            return f"{self.state} (disabled)"
        if not self.device_up:
            return "idle — no containers"
        return self.state

    @property
    def counts_toward_health(self) -> bool:
        """A disabled scope is not our business, and a scope whose bridge is
        DOWN has no containers to reach -- neither should colour the tray."""
        return self.enabled and self.device_up


@dataclass(frozen=True)
class PendingClaim:
    """A scope awaiting approval, and what approving it would claim.

    The name alone is not a decision. A claim installs a priority-100 rule,
    which outranks the tunnel's own routes, and the subnet comes from whoever
    created the network -- so the CIDR is the part that says whether this
    diverts a dev bridge or a corporate range.
    """

    name: str
    device: str = ""
    networks: tuple[str, ...] = ()
    shadowed_by: tuple[str, ...] = ()

    @property
    def label(self) -> str:
        if not self.networks:
            return self.name
        return f"{self.name} — {', '.join(self.networks)}"

    @property
    def tooltip(self) -> str:
        if not self.networks:
            return f"Claim {self.name} for this VPN session."
        lines = [
            f"Route {', '.join(self.networks)} via {self.device or self.name} "
            "ahead of the tunnel, for this VPN session."
        ]
        if self.shadowed_by:
            lines.append(
                "Currently carried by the tunnel as "
                f"{', '.join(self.shadowed_by)}."
            )
        return "\n".join(lines)


@dataclass(frozen=True)
class Summary:
    health: Health
    headline: str
    detail: str
    scopes: tuple[ScopeRow, ...] = ()

    pending_claims: tuple[PendingClaim, ...] = ()
    """Scopes awaiting approval, with the CIDRs approving them would claim.

    Synthesised from names alone against a daemon that predates the field, so
    it is always populated and there is one thing for the UI to read.
    """

    dismissed: tuple[str, ...] = ()
    """Pending scopes put off for this VPN session.

    A subset of ``pending_claims`` rather than a removal from it: a dismissed
    scope is still blocked, still listed and still approvable. This only says
    which ones have stopped asking.
    """

    refused: tuple[str, ...] = ()
    """Claims the daemon's guard rejected, already formatted for display."""
    routes: tuple[str, ...] = ()
    rules: tuple[str, ...] = ()
    automation: str = "confirm"
    connected: bool = False

    caller_is_root: bool = True
    """Whether the daemon will accept this client's persisting commands.

    Defaults True so an older daemon, whose snapshot has no such field, leaves
    the controls enabled exactly as before -- the daemon is the gate, this only
    decides whether the UI offers the button or explains why it cannot.
    """

    @property
    def pending(self) -> tuple[str, ...]:
        """Names only. Derived rather than stored beside ``pending_claims``:
        two fields could disagree, and a UI that keys off the wrong one would
        drop the approval controls with approvals outstanding."""
        return tuple(c.name for c in self.pending_claims)

    @property
    def awaiting(self) -> tuple[PendingClaim, ...]:
        """The claims still asking for a decision.

        Health keys off this rather than ``pending_claims``: one scope the user
        has declined would otherwise hold health at PENDING forever, and since
        PENDING is tested before FAILING it would mask a scope that is claimed
        and genuinely unreachable.
        """
        return tuple(c for c in self.pending_claims if c.name not in self.dismissed)

    @property
    def colour(self) -> str:
        return COLOURS[self.health]

    @property
    def needs_attention(self) -> bool:
        return self.health in (Health.PENDING, Health.CAPTURED, Health.FAILING)


def _rows(snapshot: dict) -> tuple[ScopeRow, ...]:
    by_name = {s["name"]: s for s in snapshot.get("scopes", [])}
    rows = []
    for diag in snapshot.get("diagnoses", []):
        scope = by_name.get(diag["scope"], {})
        rows.append(
            ScopeRow(
                name=diag["scope"],
                device=diag.get("device", ""),
                state=diag.get("state", "unknown"),
                # Effective state from config, falling back to the discovery
                # default only for snapshots that predate the field.
                enabled=bool(
                    scope.get("enabled", scope.get("enabled_by_default"))
                ),
                needs_fix=bool(diag.get("needs_fix")),
                detail=diag.get("note", ""),
                device_up=bool(scope.get("device_up", True)),
            )
        )
    return tuple(rows)


def _pending_claims(
    snapshot: dict, pending: tuple[str, ...]
) -> tuple[PendingClaim, ...]:
    """Rows for the approval controls, however old the daemon is.

    A daemon predating ``pending_claims`` sends names only; degrade to those
    rather than dropping the approval controls, since the daemon is the thing
    that decides and this only changes how the choice is labelled.
    """
    raw = snapshot.get("pending_claims")
    if not raw:
        return tuple(PendingClaim(name=name) for name in pending)

    return tuple(
        PendingClaim(
            name=str(entry.get("scope", "")),
            device=str(entry.get("device", "")),
            networks=tuple(str(n) for n in entry.get("networks") or ()),
            shadowed_by=tuple(str(n) for n in entry.get("shadowed_by") or ()),
        )
        for entry in raw
        if entry.get("scope")
    )


def summarize(snapshot: dict | None) -> Summary:
    """Reduce a daemon snapshot to what the UI shows."""
    if not snapshot:
        return Summary(
            health=Health.UNKNOWN,
            headline=HEADLINES[Health.UNKNOWN],
            detail="Is ciscomvent.service running?",
        )

    vpn = snapshot.get("vpn") or {}
    config = snapshot.get("config") or {}
    connected = bool(vpn.get("connected"))
    pending = tuple(snapshot.get("pending_approval") or [])
    pending_claims = _pending_claims(snapshot, pending)
    dismissed = tuple(snapshot.get("dismissed") or [])
    awaiting = tuple(c for c in pending_claims if c.name not in dismissed)
    refused = tuple(
        f"{r.get('network')} for {r.get('scope')} — {r.get('reason')}"
        for r in snapshot.get("refused_claims") or []
    )
    rows = _rows(snapshot)
    routes = tuple(snapshot.get("owned_routes") or [])
    rules = tuple(snapshot.get("owned_rules") or [])

    relevant = [r for r in rows if r.counts_toward_health]
    broken = [r for r in relevant if r.needs_fix]

    if not connected:
        health = Health.OFFLINE
        detail = "Nothing to claim while the tunnel is down."
    elif awaiting:
        # Checked before CAPTURED: a scope awaiting approval is also captured,
        # and "waiting for you" is the more useful thing to say. Dismissed
        # scopes are excluded, or one the user has declined would hold this
        # branch forever and nothing below it could ever show.
        health = Health.PENDING
        detail = (
            f"{len(awaiting)} scope(s) need approval: "
            + "; ".join(c.label for c in awaiting)
        )
    elif broken:
        # Claimed already but still failing is a different problem from simply
        # not having claimed it yet.
        claimed = bool(routes)
        health = Health.FAILING if claimed else Health.CAPTURED
        detail = ", ".join(f"{r.name} ({r.state})" for r in broken)
    else:
        health = Health.HEALTHY
        names = ", ".join(r.name for r in relevant) or "no active scopes"
        detail = (
            f"{names} — reachable via {len(routes)} route(s) "
            f"and {len(rules)} firewall rule(s)"
        )

    if refused:
        # Not a health state: there is nothing to fix and nothing was claimed.
        # But a subnet missing because it was refused looks exactly like one
        # that was never discovered, so say which it is.
        detail += f" · {len(refused)} claim(s) refused"

    return Summary(
        health=health,
        headline=HEADLINES[health],
        detail=detail,
        scopes=rows,
        pending_claims=pending_claims,
        dismissed=dismissed,
        refused=refused,
        routes=routes,
        rules=rules,
        automation=config.get("automation", "confirm"),
        connected=connected,
        caller_is_root=bool(snapshot.get("caller_is_root", True)),
    )


def tooltip(summary: Summary) -> str:
    return f"ciscomvent — {summary.headline}\n{summary.detail}"
