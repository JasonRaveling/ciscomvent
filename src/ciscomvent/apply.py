# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Mutation primitives: reclaim routes and, if needed, firewall accepts.

Every mutation is tagged with ownership so reconcile and teardown are exact:
routes carry ``proto ciscomvent`` (150) and rules carry a
``ciscomvent:<scope>`` comment. Nothing here reads, parses, or edits the
``ciscovpn*`` chains, and no Cisco route is ever deleted -- we win by putting
our routes in a dedicated table selected by a higher-priority rule instead.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from enum import Enum

from . import RULE_COMMENT_PREFIX
from .iproute import addresses, ip_binary
from .model import IPv4Network, Scope
from .prefixes import ReclaimPlan

ROUTE_PROTO_NUM = 150
"""Numeric route proto. Used in commands directly so the tool works whether or
not the name has been registered; 150 is unassigned in rt_protos."""

ROUTE_PROTO_NAME = "ciscomvent"
PROTO_FILE = "/etc/iproute2/rt_protos.d/ciscomvent.conf"

ROUTE_TABLE = 150
"""Dedicated routing table for our reclaim routes."""

RULE_PRIORITY = 100
"""Policy-rule priority. Must be below main (32766) so our table is consulted
first, and above local (0) so host-owned addresses keep working."""

LAYER_ROUTE = 1
LAYER_FIREWALL = 2


class Mechanism(str, Enum):
    """How to beat the tunnel's route.

    ``POLICY`` is the default and the only one observed to work. ``SPECIFIC``
    is kept because it is the mechanism the triage designed and because the
    prefix math remains useful, but it is **known to lose** on this client:

    Secure Client watches the main routing table and mirrors any new prefix it
    sees onto cscotun0. Installing 172.18.0.0/17 + 172.18.128.0/17 produced
    matching /17s via cscotun0 within seconds, and an equal-length tie resolves
    in Cisco's favour. Going deeper only invites deeper mirroring; a /32 is
    maximal and can still be tied.

    Policy routing sidesteps the contest entirely. Cisco writes to ``main``; a
    rule at priority 100 is consulted before main at 32766, so prefix length
    stops mattering. Verified on this host: Cisco installs no ip rules and uses
    no custom tables.
    """

    POLICY = "policy"
    SPECIFIC = "specific"


class ActionStatus(str, Enum):
    APPLIED = "applied"
    ALREADY_PRESENT = "already-present"
    SKIPPED = "skipped"
    FAILED = "failed"
    DRY_RUN = "dry-run"


@dataclass(frozen=True)
class Action:
    """One reversible mutation, with its own check and undo."""

    layer: int
    scope: str
    description: str
    apply_argv: tuple[str, ...]
    undo_argv: tuple[str, ...]
    check_argv: tuple[str, ...] | None = None

    pre_argv: tuple[str, ...] = ()
    """Run before apply, failures ignored. `ip rule add` has no idempotent form
    and happily stacks duplicates, so rule actions clear themselves first."""

    def render(self) -> str:
        return " ".join(self.apply_argv)

    def render_undo(self) -> str:
        return " ".join(self.undo_argv)


@dataclass(frozen=True)
class ActionResult:
    action: Action
    status: ActionStatus
    detail: str = ""

    @property
    def ok(self) -> bool:
        """Whether the action left the system in the state we wanted.

        SKIPPED counts. Deleting a route the kernel already removed -- which it
        does by itself when a bridge disappears -- converges on the desired
        state, and logging it as a failure makes a healthy teardown look broken
        in the journal.
        """
        return self.status in (
            ActionStatus.APPLIED,
            ActionStatus.ALREADY_PRESENT,
            ActionStatus.DRY_RUN,
            ActionStatus.SKIPPED,
        )

    def as_dict(self) -> dict:
        return {
            "layer": self.action.layer,
            "scope": self.action.scope,
            "description": self.action.description,
            "command": self.action.render(),
            "status": self.status.value,
            "detail": self.detail,
        }


def iptables_binary() -> str:
    return shutil.which("iptables") or "/usr/sbin/iptables"


def is_root() -> bool:
    return os.geteuid() == 0


def source_address(device: str, network: IPv4Network) -> str | None:
    """The host's own address on ``device`` within ``network``.

    Set as the route's preferred source so replies come from the bridge address
    rather than the tunnel address. Discovered rather than assumed -- for a
    Docker bridge this is what Docker calls the gateway, for a physical NIC it
    is the host's own address.
    """
    for addr in addresses():
        if addr.ifname == device and addr.address in network:
            return str(addr.address)
    return None


def policy_actions(scope: Scope) -> list[Action]:
    """Layer 1, default mechanism: dedicated table plus a rule selecting it.

    Two actions per subnet -- the route in table 150, and an ip rule at priority
    100 sending matching traffic there. Because the rule is consulted before
    ``main``, we no longer compete on prefix length, so the whole subnet can be
    claimed as-is with no splitting and nothing for Cisco to mirror.
    """
    ip = ip_binary()
    actions: list[Action] = []

    for subnet in scope.subnets:
        network = str(subnet.network)
        src = source_address(scope.device, subnet.network)

        tail = [*scope.nexthop.route_args(), "table", str(ROUTE_TABLE)]
        if src:
            tail += ["src", src]
        actions.append(
            Action(
                layer=LAYER_ROUTE,
                scope=scope.name,
                description=f"table {ROUTE_TABLE}: {network} via {scope.device}",
                apply_argv=(ip, "route", "replace", network, *tail),
                undo_argv=(
                    ip,
                    "route",
                    "del",
                    network,
                    *scope.nexthop.route_args(),
                    "table",
                    str(ROUTE_TABLE),
                ),
            )
        )

        rule = ("to", network, "lookup", str(ROUTE_TABLE), "priority", str(RULE_PRIORITY))
        actions.append(
            Action(
                layer=LAYER_ROUTE,
                scope=scope.name,
                description=f"rule: {network} -> table {ROUTE_TABLE}",
                apply_argv=(ip, "rule", "add", *rule),
                undo_argv=(ip, "rule", "del", *rule),
                pre_argv=(ip, "rule", "del", *rule),
            )
        )

    return actions


def removal_actions(network: str, device: str = "") -> list[Action]:
    """Drop a claim: its route in our table and its policy rule.

    Used for stale claims -- a subnet that moved, a bridge that was recreated,
    or everything at once when the tunnel drops.
    """
    ip = ip_binary()
    route_argv = [ip, "route", "del", network, "table", str(ROUTE_TABLE)]
    if device:
        route_argv[4:4] = ["dev", device]

    rule = ("to", network, "lookup", str(ROUTE_TABLE), "priority", str(RULE_PRIORITY))
    return [
        Action(
            layer=LAYER_ROUTE,
            scope="*",
            description=f"drop rule for {network}",
            apply_argv=(ip, "rule", "del", *rule),
            undo_argv=(ip, "rule", "add", *rule),
        ),
        Action(
            layer=LAYER_ROUTE,
            scope="*",
            description=f"drop table {ROUTE_TABLE} route for {network}",
            apply_argv=tuple(route_argv),
            undo_argv=(),
        ),
    ]


def route_actions(scope: Scope, plan: ReclaimPlan) -> list[Action]:
    """Layer 1: more-specific routes that outrank the tunnel's."""
    ip = ip_binary()
    src = source_address(scope.device, plan.subnet)
    actions: list[Action] = []

    for prefix in plan.prefixes:
        tail = [*scope.nexthop.route_args(), "proto", str(ROUTE_PROTO_NUM)]
        if src:
            tail += ["src", src]
        actions.append(
            Action(
                layer=LAYER_ROUTE,
                scope=scope.name,
                description=f"reclaim {prefix} via {scope.device}",
                # `add` rather than `replace`: if some other route already owns
                # this exact prefix we want to fail loudly, not silently
                # overwrite it.
                apply_argv=(ip, "route", "add", str(prefix), *tail),
                undo_argv=(
                    ip,
                    "route",
                    "del",
                    str(prefix),
                    *scope.nexthop.route_args(),
                    "proto",
                    str(ROUTE_PROTO_NUM),
                ),
            )
        )
    return actions


def firewall_actions(scope: Scope) -> list[Action]:
    """Layer 2: admit the repaired path on the scope's device.

    Applied alongside the routes, not as a fallback. Correct routing alone is
    not enough: Secure Client rebuilds its firewall chains on connect, and the
    ruleset a fresh connect produces drops host-to-container bridge traffic.
    DOCKER-USER cannot help here -- it is FORWARD-only and this is an OUTPUT
    path.

    Scoped to the subnets we actually claim, because these rules go in at the
    *top* of INPUT and OUTPUT, ahead of anything ufw or firewalld has to say. A
    blanket ``-i <dev> -j ACCEPT`` there is not a repair, it is switching the
    host firewall off for that interface: on a Docker bridge it hands every
    container every port the host listens on, and for a LAN or libvirt scope
    ``<dev>`` is a physical NIC.

    INPUT is further limited to ESTABLISHED,RELATED and to the host's own
    address on the device. What broke is the host dialing the container, so the
    return path is the only thing that has to be admitted here. A container
    opening a *new* connection to a host service keeps falling through to local
    firewall policy, which is where that decision belongs.
    """
    ipt = iptables_binary()
    tag = ("-m", "comment", "--comment", f"{RULE_COMMENT_PREFIX}{scope.name}")
    actions: list[Action] = []

    for subnet in scope.subnets:
        network = str(subnet.network)
        # The same address the route sets as `src`, so the two agree by
        # construction. None means the host holds nothing in this subnet, and
        # the rule stays subnet-scoped rather than widening back out.
        host = source_address(scope.device, subnet.network)

        egress = ("-o", scope.device, "-d", network, *tag, "-j", "ACCEPT")
        ingress = (
            "-i",
            scope.device,
            "-s",
            network,
            *(("-d", host) if host else ()),
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            *tag,
            "-j",
            "ACCEPT",
        )

        for chain, match in (("OUTPUT", egress), ("INPUT", ingress)):
            actions.append(
                Action(
                    layer=LAYER_FIREWALL,
                    scope=scope.name,
                    description=f"accept {chain} for {network} on {scope.device}",
                    apply_argv=(ipt, "-I", chain, "1", *match),
                    undo_argv=(ipt, "-D", chain, *match),
                    check_argv=(ipt, "-C", chain, *match),
                )
            )
    return actions


def firewall_removal_actions(scope: str) -> list[Action]:
    """Remove the accepts belonging to ``scope``, matched by their comment.

    Reconstructed from the live table rather than from a Scope object, so rules
    can be cleaned up for a scope that no longer exists -- a network that was
    torn down, or a bridge that has gone away.
    """
    ipt = iptables_binary()
    comment = f"{RULE_COMMENT_PREFIX}{scope}"
    actions: list[Action] = []

    for chain in ("OUTPUT", "INPUT"):
        proc = _run((ipt, "-S", chain))
        if proc.returncode != 0:
            continue
        for line in proc.stdout.splitlines():
            if parse_rule_comment(line) != scope:
                continue
            actions.append(
                Action(
                    layer=LAYER_FIREWALL,
                    scope=scope,
                    description=f"remove {chain} accept for {scope}",
                    apply_argv=delete_argv_for_rule(line, ipt),
                    undo_argv=(),
                )
            )
    return actions


def _run(argv: tuple[str, ...], timeout: float = 10.0) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(argv), capture_output=True, text=True, timeout=timeout, check=False
    )


def _already_present(action: Action) -> bool:
    if action.check_argv is None:
        return False
    return _run(action.check_argv).returncode == 0


def execute(actions: list[Action], dry_run: bool = False) -> list[ActionResult]:
    """Apply actions in order, idempotently.

    An action whose effect already exists is reported as ``already-present``
    rather than failing, so repeated runs converge instead of stacking
    duplicates.
    """
    results: list[ActionResult] = []

    for action in actions:
        if dry_run:
            results.append(ActionResult(action, ActionStatus.DRY_RUN))
            continue

        if _already_present(action):
            results.append(ActionResult(action, ActionStatus.ALREADY_PRESENT))
            continue

        if action.pre_argv:
            # Failure is expected and fine: it means there was nothing to clear.
            _run(action.pre_argv)

        proc = _run(action.apply_argv)
        if proc.returncode == 0:
            results.append(ActionResult(action, ActionStatus.APPLIED))
            continue

        stderr = proc.stderr.strip()
        # `ip route add` reports EEXIST this way; the route is already there.
        if "File exists" in stderr:
            results.append(
                ActionResult(action, ActionStatus.ALREADY_PRESENT, stderr)
            )
            continue

        # Deleting something already absent is convergence, not failure -- the
        # reconciler removes stale claims that may have been cleaned up by the
        # kernel when a bridge disappeared.
        if any(
            phrase in stderr
            for phrase in ("No such process", "does not exist", "not found", "No such file")
        ):
            results.append(ActionResult(action, ActionStatus.SKIPPED, stderr))
            continue

        results.append(ActionResult(action, ActionStatus.FAILED, stderr))

    return results


def revert(actions: list[Action], dry_run: bool = False) -> list[ActionResult]:
    """Undo actions in reverse order."""
    results: list[ActionResult] = []
    for action in reversed(actions):
        if dry_run:
            results.append(ActionResult(action, ActionStatus.DRY_RUN))
            continue
        proc = _run(action.undo_argv)
        if proc.returncode == 0:
            results.append(ActionResult(action, ActionStatus.APPLIED))
        else:
            stderr = proc.stderr.strip()
            missing = "No such process" in stderr or "does not exist" in stderr
            results.append(
                ActionResult(
                    action,
                    ActionStatus.SKIPPED if missing else ActionStatus.FAILED,
                    stderr,
                )
            )
    return results


def owned_routes() -> list[str]:
    """Routes currently tagged as ours, in both mechanisms' locations."""
    ip = ip_binary()
    out: list[str] = []

    proc = _run((ip, "-4", "route", "show", "proto", str(ROUTE_PROTO_NUM)))
    if proc.returncode == 0:
        out.extend(l.strip() for l in proc.stdout.splitlines() if l.strip())

    proc = _run((ip, "-4", "route", "show", "table", str(ROUTE_TABLE)))
    if proc.returncode == 0:
        out.extend(
            f"[table {ROUTE_TABLE}] {l.strip()}"
            for l in proc.stdout.splitlines()
            if l.strip()
        )
    return out


def owned_rules_ip() -> list[str]:
    """Policy rules at our priority."""
    proc = _run((ip_binary(), "rule", "show", "priority", str(RULE_PRIORITY)))
    if proc.returncode != 0:
        return []
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def owned_rules() -> list[str] | None:
    """iptables rules tagged as ours, or None if the table cannot be read.

    None rather than an empty list: reading iptables needs root, and reporting
    "0 rules" to an unprivileged caller states as fact something we could not
    observe -- which reads as "the accepts are missing" when they are present.
    """
    ipt = iptables_binary()
    out: list[str] = []
    for chain in ("OUTPUT", "INPUT"):
        proc = _run((ipt, "-S", chain))
        if proc.returncode != 0:
            return None
        out.extend(
            line.strip()
            for line in proc.stdout.splitlines()
            if RULE_COMMENT_PREFIX in line
        )
    return out


def parse_rule_comment(spec: str) -> str | None:
    """The scope name from an `iptables -S` line we own, if it is ours."""
    tokens = shlex.split(spec)
    for index, token in enumerate(tokens):
        if token == "--comment" and index + 1 < len(tokens):
            value = tokens[index + 1]
            if value.startswith(RULE_COMMENT_PREFIX):
                return value[len(RULE_COMMENT_PREFIX) :]
    return None


def installed_firewall_scopes() -> set[str] | None:
    """Scopes with both accepts present, or None if the table cannot be read.

    None matters: reading iptables needs root, and an unprivileged caller must
    not conclude the rules are missing and plan to reinstall them.
    """
    ipt = iptables_binary()
    chains: dict[str, set[str]] = {}
    for chain in ("OUTPUT", "INPUT"):
        proc = _run((ipt, "-S", chain))
        if proc.returncode != 0:
            return None
        for line in proc.stdout.splitlines():
            scope = parse_rule_comment(line)
            if scope:
                chains.setdefault(scope, set()).add(chain)
    return {s for s, seen in chains.items() if {"OUTPUT", "INPUT"} <= seen}


def delete_argv_for_rule(spec: str, binary: str | None = None) -> tuple[str, ...]:
    """Turn an `iptables -S` spec line into the argv that removes it.

    Uses shlex because `-S` quotes the comment value; splitting on whitespace
    would carry the quote characters into the match and every delete would fail.
    """
    ipt = binary or iptables_binary()
    tokens = shlex.split(spec)
    return (ipt, "-D", *tokens[1:])


def teardown_all(
    dry_run: bool = False, layers: tuple[int, ...] = (LAYER_ROUTE, LAYER_FIREWALL)
) -> list[ActionResult]:
    """Remove every route and rule we own, including stale ones.

    Routes go via a proto-scoped flush, which structurally cannot touch Cisco's
    (proto unspec) or the kernel's (proto kernel). Rules are removed by turning
    each of our `-A` spec lines back into a `-D`, so the match is exact.
    """
    ip = ip_binary()
    ipt = iptables_binary()
    results: list[ActionResult] = []

    flushes = [
        Action(
            layer=LAYER_ROUTE,
            scope="*",
            description="flush main-table routes we own",
            apply_argv=(ip, "-4", "route", "flush", "proto", str(ROUTE_PROTO_NUM)),
            undo_argv=(),
        ),
        Action(
            layer=LAYER_ROUTE,
            scope="*",
            description=f"flush table {ROUTE_TABLE}",
            apply_argv=(ip, "-4", "route", "flush", "table", str(ROUTE_TABLE)),
            undo_argv=(),
        ),
    ]
    if LAYER_ROUTE not in layers:
        flushes = []

    for flush in flushes:
        if dry_run:
            results.append(ActionResult(flush, ActionStatus.DRY_RUN))
            continue
        proc = _run(flush.apply_argv)
        # Flushing an empty or absent table is not a failure.
        empty = "does not exist" in proc.stderr or "Nothing to flush" in proc.stderr
        results.append(
            ActionResult(
                flush,
                ActionStatus.APPLIED
                if proc.returncode == 0
                else (ActionStatus.SKIPPED if empty else ActionStatus.FAILED),
                proc.stderr.strip(),
            )
        )

    # Rules must be deleted one at a time; loop until none remain at our
    # priority, with a bound so a persistent failure cannot spin forever.
    for _ in range(64):
        if dry_run or LAYER_ROUTE not in layers or not owned_rules_ip():
            break
        proc = _run((ip, "rule", "del", "priority", str(RULE_PRIORITY)))
        results.append(
            ActionResult(
                Action(
                    layer=LAYER_ROUTE,
                    scope="*",
                    description=f"remove policy rule at priority {RULE_PRIORITY}",
                    apply_argv=(ip, "rule", "del", "priority", str(RULE_PRIORITY)),
                    undo_argv=(),
                ),
                ActionStatus.APPLIED if proc.returncode == 0 else ActionStatus.FAILED,
                proc.stderr.strip(),
            )
        )
        if proc.returncode != 0:
            break

    for spec in owned_rules() if LAYER_FIREWALL in layers else []:
        argv = delete_argv_for_rule(spec, ipt)
        action = Action(
            layer=LAYER_FIREWALL,
            scope="*",
            description=f"remove rule: {spec}",
            apply_argv=argv,
            undo_argv=(),
        )
        if dry_run:
            results.append(ActionResult(action, ActionStatus.DRY_RUN))
            continue
        proc = _run(argv)
        results.append(
            ActionResult(
                action,
                ActionStatus.APPLIED if proc.returncode == 0 else ActionStatus.FAILED,
                proc.stderr.strip(),
            )
        )

    return results


def install_proto_name(dry_run: bool = False) -> tuple[bool, str]:
    """Register the proto name so `ip route show` reads clearly.

    Purely cosmetic -- every command uses the numeric value -- but it makes what
    we own legible to anyone inspecting the routing table.
    """
    content = f"{ROUTE_PROTO_NUM}\t{ROUTE_PROTO_NAME}\n"
    if dry_run:
        return True, f"would write {PROTO_FILE}: {content.strip()}"
    try:
        os.makedirs(os.path.dirname(PROTO_FILE), exist_ok=True)
        with open(PROTO_FILE, "w") as handle:
            handle.write(content)
        return True, f"wrote {PROTO_FILE}"
    except OSError as exc:
        return False, str(exc)
