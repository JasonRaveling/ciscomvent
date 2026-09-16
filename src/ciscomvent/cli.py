# ciscomvent — restores host-to-container reachability under a VPN tunnel-all policy
# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Command-line interface.

Read-only commands (``status``, ``scopes``, ``plan``, ``verify``, ``reconcile``)
need no privilege. ``apply``, ``revert`` and the ``install``/``daemon`` commands
mutate host state and require root. While the daemon is running it owns
reconciliation; the mutating commands are for one-off use and diagnosis.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import textwrap
from pathlib import Path

from . import (
    CONDITIONS,
    COPYRIGHT,
    LICENSE_SHORT,
    COPY_NOTICE,
    LICENSE_URL,
    WARRANTY,
    __version__,
)
from . import baseline as baseline_mod
from . import control
from .apply import (
    LAYER_FIREWALL,
    LAYER_ROUTE,
    ActionStatus,
    Mechanism,
    execute,
    firewall_actions,
    install_proto_name,
    is_root,
    owned_routes,
    owned_rules,
    owned_rules_ip,
    policy_actions,
    route_actions,
    teardown_all,
)
from .detect import diagnose_all, vpn_state
from .discovery import DiscoveryResult, discover_scopes
from .errors import CiscomventError
from .iproute import link_is_up, link_states
from .model import Scope, ScopeDiagnosis, ScopeState, VpnState
from .prefixes import PrefixStrategy, plan_reclaim
from .service import (
    deploy_source,
    install_autostart,
    install_cli,
    install_icon,
    install_launcher,
    remove_autostart,
    install_service,
    interpreter_for_root,
    service_status,
    uninstall_service,
)
from .verify import http_check, probe_scope, routing_ok

EXIT_OK = 0
EXIT_NEEDS_FIX = 1
EXIT_ERROR = 2

_MARK = {
    ScopeState.HEALTHY: "ok  ",
    ScopeState.CAPTURED: "VPN ",
    ScopeState.MISROUTED: "??  ",
    ScopeState.NO_PROBE: "--  ",
    ScopeState.ERROR: "ERR ",
}


def _vpn_line(vpn: VpnState) -> str:
    if not vpn.connected:
        return "VPN: down"
    mode = "tunnel-all" if vpn.tunnel_all else "split-tunnel"
    addr = f" [{', '.join(vpn.addresses)}]" if vpn.addresses else ""
    return (
        f"VPN: up on {', '.join(vpn.devices)}{addr} ({mode}), "
        f"{len(vpn.captured_prefixes)} captured prefix(es)"
    )


def _print_diagnoses(
    diagnoses: list[ScopeDiagnosis], vpn: VpnState, show_disabled: bool
) -> None:
    shown = [
        d for d in diagnoses if show_disabled or d.scope.enabled_by_default
    ]
    if not shown:
        print("  (no scopes)")
        return

    width = max(len(d.scope.name) for d in shown)
    for d in shown:
        flag = " " if d.scope.enabled_by_default else "."
        print(f"  {flag}{_MARK[d.state]}{d.scope.name:<{width}}  {d.note}")
        for obs in d.observations:
            if obs.error:
                detail = f"error: {obs.error}"
            else:
                detail = f"dev {obs.dev}" + (
                    f" src {obs.prefsrc}" if obs.prefsrc else ""
                )
                if obs.is_local:
                    detail += " (host-owned)"
            print(f"       {obs.target:<18} -> {detail}")

    if not show_disabled and any(
        not d.scope.enabled_by_default for d in diagnoses
    ):
        hidden = sum(1 for d in diagnoses if not d.scope.enabled_by_default)
        print(f"\n  {hidden} disabled scope(s) hidden; use --all to show them")


def _exit_code(diagnoses: list[ScopeDiagnosis]) -> int:
    relevant = [d for d in diagnoses if d.scope.enabled_by_default]
    if any(d.state is ScopeState.ERROR for d in relevant):
        return EXIT_ERROR
    if any(d.needs_fix for d in relevant):
        return EXIT_NEEDS_FIX
    return EXIT_OK


def _gather() -> tuple[VpnState, DiscoveryResult, list[ScopeDiagnosis]]:
    from .config import load as load_config

    vpn = vpn_state()
    discovery = discover_scopes(load_config())
    return vpn, discovery, diagnose_all(discovery.scopes, vpn)


def cmd_status(args: argparse.Namespace) -> int:
    vpn, discovery, diagnoses = _gather()

    if args.json:
        print(
            json.dumps(
                {
                    "vpn": vpn.as_dict(),
                    "discovery": discovery.as_dict(),
                    "diagnoses": [d.as_dict() for d in diagnoses],
                },
                indent=2,
            )
        )
        return _exit_code(diagnoses)

    print(_vpn_line(vpn))
    if vpn.connected and vpn.captured_prefixes:
        for prefix in vpn.captured_prefixes:
            print(f"     captured: {prefix}")
    print()
    _print_diagnoses(diagnoses, vpn, args.all)

    for warning in discovery.warnings:
        print(f"\n  warning: {warning}")

    code = _exit_code(diagnoses)
    if code == EXIT_NEEDS_FIX:
        print("\nOne or more scopes are captured. Run `ciscomvent plan` to preview")
        print("the routes that would reclaim them.")
    return code


def cmd_scopes(args: argparse.Namespace) -> int:
    from .config import load as load_config

    discovery = discover_scopes(load_config())
    if args.json:
        print(json.dumps(discovery.as_dict(), indent=2))
        return EXIT_OK

    for scope in discovery.scopes:
        state = "enabled" if scope.enabled_by_default else "disabled"
        print(f"{scope.name}  ({scope.kind.value}, {state})")
        print(f"  device : {scope.device}")
        print(f"  subnets: {', '.join(str(s.network) for s in scope.subnets)}")
        probe_kind = "synthetic" if scope.probes_synthetic else "live"
        probes = ", ".join(str(p) for p in scope.probes) or "none"
        print(f"  probes : {probes} ({probe_kind})")
        if scope.hosts:
            print(f"  hosts  : {len(scope.hosts)} live address(es)")
        if scope.metadata.get("bridge_source"):
            print(f"  bridge : resolved by {scope.metadata['bridge_source']}")
        print()

    for warning in discovery.warnings:
        print(f"warning: {warning}")
    return EXIT_OK


def cmd_plan(args: argparse.Namespace) -> int:
    """Preview the reclaim routes without touching anything."""
    vpn, discovery, diagnoses = _gather()
    strategy = PrefixStrategy(args.strategy)

    selected = [
        d
        for d in diagnoses
        if (args.all or d.scope.enabled_by_default)
        and (args.force or d.needs_fix)
    ]

    payload = []
    for diag in selected:
        scope: Scope = diag.scope
        for subnet in scope.subnets:
            shadow = vpn.shadows(subnet.network)
            plan = plan_reclaim(
                subnet.network,
                hosts=scope.hosts,
                competing_prefixlen=shadow.prefixlen if shadow else None,
                strategy=strategy,
            )
            payload.append(
                {
                    "scope": scope.name,
                    "device": scope.device,
                    "nexthop": scope.nexthop.as_dict(),
                    "nexthop_args": scope.nexthop.render(),
                    "shadowed_by": str(shadow) if shadow else None,
                    **plan.as_dict(),
                }
            )

    if args.json:
        print(json.dumps({"vpn": vpn.as_dict(), "plan": payload}, indent=2))
        return EXIT_OK

    if not payload:
        if not vpn.connected:
            print("VPN is down and no scope is captured; nothing to plan.")
            print("Use --force to preview routes anyway.")
        else:
            print("No captured scopes; nothing to plan.")
        return EXIT_OK

    print(_vpn_line(vpn))
    print()
    for item in payload:
        shadow = item["shadowed_by"] or "not currently shadowed"
        print(f"{item['scope']}  {item['subnet']}  (shadowed by: {shadow})")
        print(f"  strategy: {item['strategy']} — {item['note']}")
        for prefix in item["prefixes"]:
            print(
                f"  + ip route add {prefix} {item['nexthop_args']} "
                f"proto ciscomvent"
            )
        if not item["prefixes"]:
            print("  (nothing to install)")
        print()

    print("Preview only — no changes made. Run `sudo ciscomvent apply` to act,")
    print("or let the daemon maintain this automatically.")
    return EXIT_OK


def _select(
    diagnoses: list[ScopeDiagnosis], args: argparse.Namespace, probe: bool = False
) -> list[ScopeDiagnosis]:
    """Pick the scopes to act on.

    ``needs_fix`` alone is not enough. A scope whose routing is already correct
    but whose traffic still dies reports HEALTHY, yet that is precisely the
    case layer 2 exists for -- so when probing is requested, unreachable
    scopes are selected too.
    """
    states = link_states()
    chosen: list[ScopeDiagnosis] = []

    for diag in diagnoses:
        if not (args.all or diag.scope.enabled_by_default):
            continue
        if args.force or diag.needs_fix:
            chosen.append(diag)
            continue
        if probe and link_is_up(diag.scope.device, states):
            reachable, _ = _probe_summary(diag.scope)
            if not reachable:
                chosen.append(diag)

    if getattr(args, "scope", None):
        wanted = set(args.scope)
        chosen = [d for d in chosen if d.scope.name in wanted]
    return chosen


def _report(results: list) -> bool:
    ok = True
    for result in results:
        marker = {
            ActionStatus.APPLIED: "  +",
            ActionStatus.ALREADY_PRESENT: "  =",
            ActionStatus.DRY_RUN: "  ?",
            ActionStatus.SKIPPED: "  .",
            ActionStatus.FAILED: "  !",
        }[result.status]
        print(f"{marker} {result.action.render()}")
        if result.detail:
            print(f"      {result.status.value}: {result.detail}")
        if result.status is ActionStatus.FAILED:
            ok = False
    return ok


def _probe_summary(scope: Scope) -> tuple[bool, list]:
    probes = probe_scope(scope)
    reachable = any(p.result.reachable for p in probes)
    return reachable, probes


def cmd_apply(args: argparse.Namespace) -> int:
    """Apply layer 1, verify, and apply layer 2 only if still failing.

    The order is the point. It is also how the firewall layer was shown to be
    necessary: routing correct and traffic still dead is the signature.
    """
    if not args.dry_run and not is_root():
        print("error: applying needs root. Re-run with sudo.", file=sys.stderr)
        return EXIT_ERROR

    vpn, _discovery, diagnoses = _gather()
    targets = _select(diagnoses, args, probe=vpn.connected)

    if not targets:
        print("Nothing to apply." if vpn.connected else "VPN is down; nothing captured.")
        print("Use --force to apply anyway, --all to include disabled scopes.")
        return EXIT_OK

    states = link_states()
    skipped = [d for d in targets if not link_is_up(d.scope.device, states)]
    targets = [d for d in targets if link_is_up(d.scope.device, states)]

    for diag in skipped:
        print(
            f"skipping {diag.scope.name}: {diag.scope.device} is DOWN "
            "(no running containers, nothing to reach)"
        )
    if skipped:
        print()
    if not targets:
        print("No scope has a live device; nothing to do.")
        return EXIT_OK

    mechanism = Mechanism(args.mechanism)
    strategy = PrefixStrategy(args.strategy)
    actions = []
    for diag in targets:
        if mechanism is Mechanism.POLICY:
            actions.extend(policy_actions(diag.scope))
            continue
        for subnet in diag.scope.subnets:
            shadow = vpn.shadows(subnet.network)
            plan = plan_reclaim(
                subnet.network,
                hosts=diag.scope.hosts,
                competing_prefixlen=shadow.prefixlen if shadow else None,
                strategy=strategy,
            )
            actions.extend(route_actions(diag.scope, plan))

    print(f"Layer 1 — reclaim routing via {mechanism.value} ({len(actions)} action(s)):")
    ok = _report(execute(actions, dry_run=args.dry_run))

    if args.dry_run:
        print("\nDry run — nothing changed.")
        return EXIT_OK
    if not ok:
        print("\nSome routes failed to install; stopping before layer 2.")
        return EXIT_ERROR

    print("\nVerifying routing:")
    routed, misrouted = [], []
    for diag in targets:
        good, notes = routing_ok(diag.scope)
        print(f"  {'ok ' if good else 'BAD'} {diag.scope.name}")
        for note in notes:
            print(f"      {note}")
        (routed if good else misrouted).append(diag)

    if misrouted:
        print("\n" + "=" * 68)
        print("LAYER 1 DID NOT TAKE EFFECT for:")
        for diag in misrouted:
            print(f"  - {diag.scope.name}")
        print()
        print("Traffic is still entering the tunnel, so H1 cannot be tested for")
        print("these scopes: the precondition (routing fixed) is not met. Layer 2")
        print("would be applying firewall rules to a path packets never take.")
        print("=" * 68)

    if not routed:
        print("\nNo scope has correct routing; not applying layer 2.")
        return EXIT_NEEDS_FIX

    print("\nProbing reachability:")
    still_failing = []
    for diag in routed:
        reachable, probes = _probe_summary(diag.scope)
        print(f"  {'ok ' if reachable else 'BAD'} {diag.scope.name}")
        for probe in probes:
            label = f" ({probe.label})" if probe.label else ""
            print(
                f"      {probe.address}:{probe.port}{label} -> "
                f"{probe.result.value}: {probe.detail}"
            )
        if not reachable:
            still_failing.append(diag)

    if not still_failing:
        print("\n" + "=" * 68)
        print("H1 NOT NEEDED — layer 1 alone restored reachability.")
        print(f"Confirmed for: {', '.join(d.scope.name for d in routed)}")
        print("The ciscovpn chain does not drop bridge traffic.")
        print("=" * 68)
        return EXIT_OK if not misrouted else EXIT_NEEDS_FIX

    if args.layer == 1:
        print("\nStill failing, but --layer 1 was requested; stopping.")
        return EXIT_NEEDS_FIX

    print(f"\nLayer 2 — firewall accepts for {len(still_failing)} scope(s):")
    print("  (routing is fixed but traffic still fails, so packets are now")
    print("   reaching the bridge and something is dropping them)")
    fw_actions = []
    for diag in still_failing:
        fw_actions.extend(firewall_actions(diag.scope))
    ok = _report(execute(fw_actions, dry_run=False))

    print("\nRe-probing:")
    recovered = []
    for diag in still_failing:
        reachable, probes = _probe_summary(diag.scope)
        print(f"  {'ok ' if reachable else 'BAD'} {diag.scope.name}")
        for probe in probes:
            print(
                f"      {probe.address}:{probe.port} -> "
                f"{probe.result.value}: {probe.detail}"
            )
        if reachable:
            recovered.append(diag)

    print("\n" + "=" * 68)
    if recovered:
        print("H1 CONFIRMED — the iptables accepts were required.")
        print(f"Layer 2 recovered: {', '.join(d.scope.name for d in recovered)}")
    else:
        print("H1 UNRESOLVED — layer 2 did not help either.")
        print("Routing is correct but traffic still fails. Capture on the bridge")
        print("to see whether packets arrive at all:")
        for diag in still_failing:
            print(f"  sudo tcpdump -ni {diag.scope.device} -c 20")
    print("=" * 68)
    return EXIT_OK if recovered else EXIT_NEEDS_FIX


def cmd_revert(args: argparse.Namespace) -> int:
    """Remove everything we own, leaving no trace."""
    if not args.dry_run and not is_root():
        print("error: reverting needs root. Re-run with sudo.", file=sys.stderr)
        return EXIT_ERROR

    layers = (args.layer,) if args.layer else (LAYER_ROUTE, LAYER_FIREWALL)

    routes = owned_routes() if LAYER_ROUTE in layers else []
    ip_rules = owned_rules_ip() if LAYER_ROUTE in layers else []
    rules = (owned_rules() or []) if LAYER_FIREWALL in layers else []
    if not routes and not rules and not ip_rules:
        print("Nothing owned by ciscomvent is currently installed.")
        return EXIT_OK

    print(
        f"Removing {len(routes)} route(s), {len(ip_rules)} policy rule(s), "
        f"and {len(rules)} firewall rule(s):"
    )
    for item in (*routes, *ip_rules, *rules):
        print(f"  - {item}")
    print()
    ok = _report(teardown_all(dry_run=args.dry_run, layers=layers))
    if args.dry_run:
        print("\nDry run — nothing changed.")
    return EXIT_OK if ok else EXIT_ERROR


def cmd_verify(args: argparse.Namespace) -> int:
    """Routing plus reachability, without changing anything."""
    vpn, _discovery, diagnoses = _gather()
    shown = [d for d in diagnoses if args.all or d.scope.enabled_by_default]
    states = link_states()

    rules = owned_rules()
    rule_count = "unknown (needs root)" if rules is None else f"{len(rules)}"
    print(_vpn_line(vpn))
    print(
        f"\nInstalled by ciscomvent: {len(owned_routes())} route(s), "
        f"{rule_count} firewall rule(s)\n"
    )

    all_ok = True
    payload = []
    for diag in shown:
        # A bridge with no containers sits DOWN and has nothing to reach.
        # Reporting it as a failure buries the scopes that actually matter --
        # and `apply` already skips these, so counting them here contradicts it.
        if not link_is_up(diag.scope.device, states):
            print(f"  --  {diag.scope.name}  ({diag.scope.device} is DOWN, nothing to reach)")
            payload.append({"scope": diag.scope.name, "skipped": "device down"})
            continue

        good, notes = routing_ok(diag.scope)
        reachable, probes = _probe_summary(diag.scope)
        if not (good and reachable):
            all_ok = False
        print(
            f"  {'ok ' if good and reachable else 'BAD'} {diag.scope.name}  "
            f"(routing {'ok' if good else 'wrong'}, "
            f"{'reachable' if reachable else 'unreachable'})"
        )
        for probe in probes:
            label = f" ({probe.label})" if probe.label else ""
            print(
                f"      {probe.address}:{probe.port}{label} -> "
                f"{probe.result.value}: {probe.detail}"
            )
        payload.append(
            {
                "scope": diag.scope.name,
                "routing_ok": good,
                "routing": notes,
                "reachable": reachable,
                "probes": [p.as_dict() for p in probes],
            }
        )

    http = None
    if args.url:
        http = http_check(args.url, args.resolve)
        print(f"\n  {'ok ' if http.ok else 'BAD'} {args.url} -> {http.detail}")
        if not http.ok:
            all_ok = False

    if args.json:
        print(
            json.dumps(
                {
                    "vpn": vpn.as_dict(),
                    "scopes": payload,
                    "http": http.as_dict() if http else None,
                },
                indent=2,
            )
        )
    return EXIT_OK if all_ok else EXIT_NEEDS_FIX


def cmd_reconcile(args: argparse.Namespace) -> int:
    """Show, or apply, the desired-vs-actual delta once."""
    from .config import load as load_config
    from .reconcile import reconcile as compute

    vpn, discovery, _ = _gather()
    config = load_config()
    plan = compute(discovery.scopes, vpn, config)

    if args.json:
        print(json.dumps({"vpn": vpn.as_dict(), "plan": plan.as_dict()}, indent=2))
        return EXIT_OK

    print(_vpn_line(vpn))
    print(f"\nReconcile: {plan.summary()}\n")
    for scope in plan.to_add:
        nets = ", ".join(str(n) for n in scope.networks)
        print(f"  + claim   {scope.name} ({scope.device}) — {nets}")
    for claim in plan.to_remove:
        why = "tunnel is down" if not vpn.connected else "no longer desired"
        print(f"  - release {claim.network} via {claim.device or '?'} — {why}")
    for claim in plan.unchanged:
        print(f"  = holding {claim.network} via {claim.device}")

    if plan.refused:
        print("\nRefused (a claim outranks the tunnel, so these are not made):")
        for refusal in plan.refused:
            print(f"  ! {refusal.network} for {refusal.scope} — {refusal.reason}")
        print(
            "\n  To claim one anyway, add its exact CIDR to allow_wide_claims\n"
            "  in /etc/ciscomvent/config.json."
        )

    if not args.apply:
        if not plan.is_noop:
            print("\nPreview only. Add --apply to act (needs root).")
        return EXIT_OK

    if not is_root():
        print("\nerror: --apply needs root. Re-run with sudo.", file=sys.stderr)
        return EXIT_ERROR

    from .daemon import Daemon

    print()
    Daemon(config=config).reconcile_once(reason="cli")
    print("Applied.")
    return EXIT_OK


class _VersionAction(argparse.Action):
    """Print --version verbatim.

    argparse's built-in `version` action reflows the text through the help
    formatter, which collapses the licence notice into one wrapped paragraph.
    """

    def __call__(self, parser, namespace, values, option_string=None):
        # The load path matters: the CLI runs the deployed snapshot, not a
        # checkout, so "which copy is this" is a real question.
        print(f"ciscomvent {__version__} from {Path(__file__).resolve().parent}")
        print(COPYRIGHT)
        print(f"License {LICENSE_SHORT} <{LICENSE_URL}>")
        print("This is free software: you are free to change and redistribute it.")
        print("There is NO WARRANTY, to the extent permitted by law.")
        parser.exit()


def cmd_license(args: argparse.Namespace) -> int:
    """The GPL asks an interactive program to offer `show w' and `show c'.

    These are those, and `--version` carries the short notice.
    """
    if args.warranty:
        print(_wrap(WARRANTY))
    elif args.conditions:
        print(_wrap(CONDITIONS))
    else:
        print(f"ciscomvent {__version__}")
        print(COPYRIGHT)
        for notice in (CONDITIONS, WARRANTY, COPY_NOTICE):
            print()
            print(_wrap(notice))

    found = _license_file()
    if found:
        print(f"\nFull text: {found}")
    return EXIT_OK


def _wrap(text: str) -> str:
    """Wrap a notice to the terminal, or 79 columns when piped."""
    width = min(shutil.get_terminal_size(fallback=(80, 24)).columns, 100) - 1
    return textwrap.fill(text, width=max(width, 40))


def _license_file() -> Path | None:
    """The LICENSE shipped with this distribution, if it is still alongside us.

    The deployed copy under /usr/local/lib holds only the package, so this is
    absent there -- hence the URL always being printed as well.
    """
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "LICENSE"
        if candidate.is_file():
            return candidate
    return None


def cmd_gui(args: argparse.Namespace) -> int:
    """Launch the tray applet, or manage its autostart entry."""
    if args.install_autostart or args.remove_autostart:
        if not is_root():
            print("error: needs root. Re-run with sudo.", file=sys.stderr)
            return EXIT_ERROR
        ok, detail = (
            install_autostart() if args.install_autostart else remove_autostart()
        )
        print(detail)
        return EXIT_OK if ok else EXIT_ERROR

    try:
        from .gui.app import main as gui_main
    except ImportError as exc:
        print(f"error: PyQt5 is required for the GUI ({exc})", file=sys.stderr)
        print("On Debian/Ubuntu: sudo apt install python3-pyqt5", file=sys.stderr)
        return EXIT_ERROR

    if not control.is_available():
        print("warning: the daemon socket is not present; the applet will show")
        print("'Daemon not reachable' until ciscomvent.service is running.")
    return gui_main([sys.argv[0]])


def cmd_config(args: argparse.Namespace) -> int:
    """Show or change persisted settings."""
    from .config import Automation
    from .config import load as load_config
    from .config import save as save_config

    config = load_config()
    changed = False

    if args.automation:
        config.automation = Automation(args.automation)
        changed = True

    if changed:
        if not is_root():
            print("error: changing config needs root. Re-run with sudo.", file=sys.stderr)
            return EXIT_ERROR
        path = save_config(config)
        print(f"wrote {path}")

    if args.json:
        print(json.dumps(config.as_dict(), indent=2))
        return EXIT_OK

    print(f"automation      : {config.automation.value}")
    print(f"firewall layer  : {'on' if config.firewall else 'OFF'}")
    print(
        "socket group    : "
        + (config.socket_group or "(auto-detect: "
           + ", ".join(control.CANDIDATE_GROUPS) + ")")
    )
    print(f"enabled scopes  : {', '.join(config.enabled_scopes) or '(defaults only)'}")
    print(f"disabled scopes : {', '.join(config.disabled_scopes) or '(none)'}")
    print(f"always allowed  : {', '.join(config.always_allow) or '(none)'}")
    print(f"widest claim    : /{config.min_claim_prefixlen}")
    print(
        "wide claims ok  : "
        + (", ".join(config.allow_wide_claims) or "(none)")
    )
    if config.automation is Automation.CONFIRM:
        print(
            "\nIn confirm mode the daemon waits for approval before claiming a\n"
            "scope. Approve with `ciscomvent approve <scope>`, or switch to\n"
            "`ciscomvent config --automation auto` for zero-touch operation."
        )
    return EXIT_OK


def _approval_preview(names: list[str]) -> bool:
    """Print what approving ``names`` would actually claim right now.

    Approval is recorded by scope name, and the name is the stable half: the
    same `docker:app` can come back tomorrow around a different subnet. The
    CIDR is what a claim diverts, and a priority-100 rule outranks the tunnel,
    so it is the part worth reading before saying yes.

    Returns False if anything named would be refused by the claim guard, so the
    caller can say so rather than record an approval that will not be honoured.
    """
    from .config import load as load_config
    from .reconcile import claim_refusal

    config = load_config()
    try:
        discovery = discover_scopes(config)
        vpn = vpn_state()
    except CiscomventError as exc:
        print(f"warning: cannot show what this covers ({exc})")
        return True

    by_name = {s.name: s for s in discovery.scopes}
    clean = True

    for name in names:
        scope = by_name.get(name)
        if scope is None:
            print(f"  {name}: not discovered right now (approval still recorded)")
            continue
        for subnet in scope.subnets:
            reason = claim_refusal(subnet.network, vpn, config)
            shadow = vpn.shadows(subnet.network)
            if shadow == subnet.network:
                note = " (the tunnel currently carries this exact prefix)"
            elif shadow:
                note = f" (inside tunnel prefix {shadow})"
            else:
                note = ""
            if reason:
                clean = False
                print(
                    f"  {name}: {subnet.network} via {scope.device} "
                    f"— REFUSED, {reason}"
                )
            else:
                print(f"  {name}: {subnet.network} via {scope.device}{note}")

    return clean


def cmd_scope(args: argparse.Namespace) -> int:
    """Enable or disable a scope, through the daemon.

    Goes over the control socket rather than writing the config directly, so
    there is one implementation of what enabling means and the daemon
    reconciles immediately instead of on its next tick. The socket is also the
    only route that already knows how to refuse this below uid 0: `is_root()`
    here would be a second, client-side copy of a rule the daemon enforces on
    the request path anyway.

    Exists chiefly so the GUI has something safe to run under pkexec: an
    installed, root-owned entry point taking a validated scope name.
    """
    enabled = args.enable
    try:
        control.request("set-scope", scope=args.scope, enabled=enabled)
    except control.ControlError as exc:
        print(f"error: {exc}", file=sys.stderr)
        if not is_root():
            print(
                "Enabling or disabling a scope is written to "
                "/etc/ciscomvent/config.json and needs root.",
                file=sys.stderr,
            )
        return EXIT_ERROR

    print(f"{args.scope} {'enabled' if enabled else 'disabled'}")
    return EXIT_OK


def cmd_approve(args: argparse.Namespace) -> int:
    """Grant standing approval for scopes, so confirm mode stops asking.

    Writes to the config file, which the daemon reloads on every reconcile --
    so this takes effect without a restart. Per-session (rather than standing)
    approval needs the control socket and arrives with the GUI.
    """
    from .config import load as load_config
    from .config import save as save_config

    if not args.revoke:
        print("This approves claiming:")
        if not _approval_preview(args.scope):
            print(
                "\nA refused subnet is not claimed even once approved — approval\n"
                "is per scope, the guard is per subnet. See allow_wide_claims in\n"
                "/etc/ciscomvent/config.json."
            )
        print()

    if args.session:
        # Session grants live in the daemon's memory, so they can only be set
        # through the socket -- which needs group membership, not root.
        try:
            for name in args.scope:
                control.request("approve", scope=name, always=False)
        except control.ControlError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR
        print(f"approved for this VPN session: {', '.join(args.scope)}")
        print("Disconnecting clears this; use plain `approve` to make it stick.")
        return EXIT_OK

    if not is_root():
        print("error: needs root. Re-run with sudo.", file=sys.stderr)
        return EXIT_ERROR

    config = load_config()
    for name in args.scope:
        if args.revoke:
            if name in config.always_allow:
                config.always_allow.remove(name)
            if args.disable and name not in config.disabled_scopes:
                config.disabled_scopes.append(name)
        else:
            if name not in config.always_allow:
                config.always_allow.append(name)
            if name in config.disabled_scopes:
                config.disabled_scopes.remove(name)

    save_config(config)
    verb = "revoked" if args.revoke else "approved"
    print(f"{verb}: {', '.join(args.scope)}")
    print("The daemon picks this up on its next reconcile (within 60s, or")
    print("immediately on the next network change).")
    return EXIT_OK


def cmd_daemon(args: argparse.Namespace) -> int:
    """Install, remove, or report on the system service."""
    if args.daemon_cmd == "status":
        status = service_status()
        for key, value in status.items():
            print(f"  {key:<10} {value}")
        return EXIT_OK

    if not args.dry_run and not is_root():
        print("error: needs root. Re-run with sudo.", file=sys.stderr)
        return EXIT_ERROR

    if args.daemon_cmd == "install":
        ok, detail = install_service(
            dry_run=args.dry_run,
            enable=not args.no_enable,
            in_place=args.in_place,
        )
    else:
        ok, detail = uninstall_service(dry_run=args.dry_run)
    print(detail)
    return EXIT_OK if ok else EXIT_ERROR


def cmd_install(args: argparse.Namespace) -> int:
    """Deploy the package, put `ciscomvent` on PATH, and register the proto name.

    Does not touch systemd; `ciscomvent daemon install` does that.
    """
    if not args.dry_run and not is_root():
        print("error: needs root. Re-run with sudo.", file=sys.stderr)
        return EXIT_ERROR

    # Every step runs whether or not an earlier one failed, so an interpreter
    # the wrapper would refuse is caught here first: deploying and then
    # refusing would leave the launcher pointing at a wrapper never written.
    _, refusal = interpreter_for_root()
    if refusal:
        print(f"error: {refusal}", file=sys.stderr)
        return EXIT_ERROR

    steps = [
        ("deploy", deploy_source(dry_run=args.dry_run)),
        ("cli", install_cli(dry_run=args.dry_run)),
        ("icon", install_icon(dry_run=args.dry_run)),
        ("launcher", install_launcher(dry_run=args.dry_run)),
        ("route proto", install_proto_name(dry_run=args.dry_run)),
    ]
    failed = False
    for label, (ok, detail) in steps:
        print(f"  {'ok ' if ok else 'BAD'} {label}: {detail}")
        failed |= not ok

    if not failed and not args.dry_run:
        print("\n`ciscomvent` is now on PATH. Install the service with:")
        print("  sudo ciscomvent daemon install")
    return EXIT_ERROR if failed else EXIT_OK


def cmd_baseline(args: argparse.Namespace) -> int:
    if args.baseline_cmd == "capture":
        snapshot = baseline_mod.capture()
        path = baseline_mod.save(
            snapshot, Path(args.output) if args.output else None
        )
        golden = snapshot["is_golden"]
        print(f"Captured {'GOLDEN (VPN down)' if golden else 'VPN-UP'} baseline")
        print(f"  path    : {path}")
        print(f"  scopes  : {len(snapshot['discovery']['scopes'])}")
        print(f"  networks: {len(snapshot['docker_networks'])}")
        fw = snapshot.get("firewall", {})
        if fw.get("available"):
            print(f"  firewall: {len(fw['rules'])} rule line(s)")
        else:
            print(f"  firewall: not captured — {fw.get('reason')}")
        if not golden:
            print(
                "\nNote: taken with the VPN up, so this is not a golden reference.\n"
                "Capture again with the VPN disconnected for a clean baseline."
            )
        return EXIT_OK

    path = Path(args.path) if args.path else baseline_mod.latest()
    if path is None:
        print("No baseline found. Run `ciscomvent baseline capture` first.")
        return EXIT_ERROR
    snapshot = baseline_mod.load(path)
    if args.json:
        print(json.dumps(snapshot, indent=2))
        return EXIT_OK
    print(f"path      : {path}")
    print(f"captured  : {snapshot['captured_at']}")
    print(f"golden    : {snapshot['is_golden']}")
    print(f"vpn       : {'up' if snapshot['vpn']['connected'] else 'down'}")
    print(f"scopes    : {len(snapshot['discovery']['scopes'])}")
    for diag in snapshot["diagnoses"]:
        print(f"  {diag['state']:<10} {diag['scope']}")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ciscomvent",
        description=(
            "Restore host-to-container reachability under Cisco Secure Client "
            "tunnel-all, via policy routing the client cannot mirror."
        ),
    )
    parser.add_argument(
        "--json", action="store_true", help="emit machine-readable JSON"
    )
    # The wrapper runs the deployed snapshot, not a checkout, so "which copy am
    # I running" is a real question after any code change.
    parser.add_argument(
        "--version", action=_VersionAction, nargs=0, help="version and licence"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_status = sub.add_parser("status", help="VPN state and per-scope diagnosis")
    p_status.add_argument(
        "--all", action="store_true", help="include disabled scopes"
    )
    p_status.set_defaults(func=cmd_status)

    p_scopes = sub.add_parser("scopes", help="list discovered scopes")
    p_scopes.set_defaults(func=cmd_scopes)

    p_plan = sub.add_parser("plan", help="preview reclaim routes (read-only)")
    p_plan.add_argument("--all", action="store_true", help="include disabled scopes")
    p_plan.add_argument(
        "--force",
        action="store_true",
        help="plan even for scopes that are not currently captured",
    )
    p_plan.add_argument(
        "--strategy",
        choices=[s.value for s in PrefixStrategy],
        default=PrefixStrategy.SPLIT.value,
        help="prefix strategy (default: split)",
    )
    p_plan.set_defaults(func=cmd_plan)

    p_apply = sub.add_parser(
        "apply", help="install reclaim routes (root); layer 2 only if needed"
    )
    p_apply.add_argument("--all", action="store_true", help="include disabled scopes")
    p_apply.add_argument("--force", action="store_true", help="apply even if not captured")
    p_apply.add_argument("--scope", action="append", help="limit to named scope(s)")
    p_apply.add_argument("--dry-run", action="store_true", help="print, change nothing")
    p_apply.add_argument(
        "--layer",
        type=int,
        choices=(1, 2),
        default=2,
        help="stop after layer 1, or allow layer 2 (default)",
    )
    p_apply.add_argument(
        "--mechanism",
        choices=[m.value for m in Mechanism],
        default=Mechanism.POLICY.value,
        help="policy (default: dedicated table + ip rule, immune to prefix "
        "mirroring) or specific (longest-prefix in main; known to lose)",
    )
    p_apply.add_argument(
        "--strategy",
        choices=[s.value for s in PrefixStrategy],
        default=PrefixStrategy.SPLIT.value,
        help="prefix strategy, only used with --mechanism specific",
    )
    p_apply.set_defaults(func=cmd_apply)

    p_revert = sub.add_parser("revert", help="remove everything we own (root)")
    p_revert.add_argument("--dry-run", action="store_true", help="print, change nothing")
    p_revert.add_argument(
        "--layer",
        type=int,
        choices=(1, 2),
        help="remove only routing (1) or only firewall rules (2); default both",
    )
    p_revert.set_defaults(func=cmd_revert)

    p_verify = sub.add_parser("verify", help="routing + reachability, read-only")
    p_verify.add_argument("--all", action="store_true", help="include disabled scopes")
    p_verify.add_argument("--url", help="also run an end-to-end HTTP check")
    p_verify.add_argument(
        "--resolve",
        help="curl --resolve entry, e.g. test-site.local:443:127.0.0.1 "
        "(required for Host()-routed proxies)",
    )
    p_verify.set_defaults(func=cmd_verify)

    p_lic = sub.add_parser(
        "license", help="copyright, warranty and redistribution terms"
    )
    p_lic.add_argument(
        "--warranty", action="store_true", help="the warranty disclaimer (`show w')"
    )
    p_lic.add_argument(
        "--conditions",
        action="store_true",
        help="the redistribution conditions (`show c')",
    )
    p_lic.set_defaults(func=cmd_license)

    p_gui = sub.add_parser("gui", help="launch the tray applet")
    p_gui.add_argument(
        "--install-autostart", action="store_true", help="start at login (root)"
    )
    p_gui.add_argument(
        "--remove-autostart", action="store_true", help="stop starting at login (root)"
    )
    p_gui.set_defaults(func=cmd_gui)

    p_conf = sub.add_parser("config", help="show or change persisted settings")
    p_conf.add_argument(
        "--automation",
        choices=["confirm", "auto"],
        help="confirm (default, waits for approval) or auto (applies silently)",
    )
    p_conf.set_defaults(func=cmd_config)

    p_appr = sub.add_parser("approve", help="grant standing approval for scope(s)")
    p_appr.add_argument("scope", nargs="+", help="scope name(s), e.g. docker:my-network")
    p_appr.add_argument("--revoke", action="store_true", help="undo the approval")
    p_appr.add_argument(
        "--session",
        action="store_true",
        help="approve for this VPN session only, via the daemon socket "
        "(no root needed; cleared on disconnect)",
    )
    p_appr.add_argument(
        "--disable", action="store_true", help="with --revoke, also disable the scope"
    )
    p_appr.set_defaults(func=cmd_approve)

    p_scope = sub.add_parser("scope", help="enable or disable one scope (root)")
    p_scope.add_argument("scope", help="scope name, e.g. docker:my-network")
    state = p_scope.add_mutually_exclusive_group(required=True)
    state.add_argument("--enable", action="store_true", help="claim it when captured")
    state.add_argument("--disable", action="store_true", help="never claim it")
    p_scope.set_defaults(func=cmd_scope)

    p_rec = sub.add_parser("reconcile", help="show or apply the desired/actual delta")
    p_rec.add_argument("--apply", action="store_true", help="act on it (needs root)")
    p_rec.set_defaults(func=cmd_reconcile)

    p_daemon = sub.add_parser("daemon", help="manage the system service")
    daemon_sub = p_daemon.add_subparsers(dest="daemon_cmd", required=True)
    d_status = daemon_sub.add_parser("status", help="installed / enabled / active")
    d_status.set_defaults(func=cmd_daemon, dry_run=False)
    d_install = daemon_sub.add_parser("install", help="write and enable the unit (root)")
    d_install.add_argument("--dry-run", action="store_true")
    d_install.add_argument("--no-enable", action="store_true", help="write but do not enable")
    d_install.add_argument(
        "--in-place",
        action="store_true",
        help="run from this checkout instead of deploying. Development only: "
        "the root daemon then imports code your user can write, so anything "
        "running as you is root at its next start",
    )
    d_install.set_defaults(func=cmd_daemon)
    d_remove = daemon_sub.add_parser("uninstall", help="stop, disable, remove (root)")
    d_remove.add_argument("--dry-run", action="store_true")
    d_remove.set_defaults(func=cmd_daemon)

    p_install = sub.add_parser(
        "install",
        help="deploy the package, put `ciscomvent` on PATH, register the "
        "route proto name (root)",
    )
    p_install.add_argument("--dry-run", action="store_true")
    p_install.set_defaults(func=cmd_install)

    p_base = sub.add_parser("baseline", help="capture or show a state snapshot")
    base_sub = p_base.add_subparsers(dest="baseline_cmd", required=True)
    p_cap = base_sub.add_parser("capture", help="snapshot current host state")
    p_cap.add_argument("-o", "--output", help="write to this path")
    p_cap.set_defaults(func=cmd_baseline)
    p_show = base_sub.add_parser("show", help="summarize a snapshot")
    p_show.add_argument("path", nargs="?", help="defaults to the most recent")
    p_show.set_defaults(func=cmd_baseline)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "json"):
        args.json = False
    try:
        return args.func(args)
    except CiscomventError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
