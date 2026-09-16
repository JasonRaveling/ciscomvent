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
"""The reconciling daemon.

Runs as root under systemd. Watches netlink, debounces, reconciles, and applies
the delta -- subject to the automation mode and per-VPN-session grants.

Nothing else in the tool mutates kernel state while the daemon is running; the
CLI and GUI talk to it rather than acting themselves.
"""

from __future__ import annotations

import logging
import signal
import threading
import time
from dataclasses import dataclass, field

from . import __version__
from .apply import (
    execute,
    firewall_actions,
    firewall_removal_actions,
    installed_firewall_scopes,
    is_root,
    owned_routes,
    owned_rules,
    policy_actions,
    removal_actions,
)
from .config import CONFIG_PATH, Automation, Config
from .config import load as load_config
from .config import save as save_config
from .control import ControlServer
from .detect import diagnose_all, vpn_state
from .discovery import discover_scopes
from .iproute import link_is_up, link_states
from .model import VpnState, checked_scope
from .monitor import Debouncer, watch
from .reconcile import ReconcilePlan, reconcile

log = logging.getLogger("ciscomvent")

POLL_INTERVAL = 0.5
"""How often the main loop checks whether a debounced burst is due."""

RESYNC_SECONDS = 60.0
"""Periodic reconcile even with no netlink events, so a missed message or an
out-of-band change cannot leave us wrong indefinitely."""


MAX_SESSION_GRANTS = 64
"""Ceiling on per-session approvals held in memory."""


@dataclass
class SessionGrants:
    """Approvals valid for the current VPN session only.

    Confirm mode asks once per session rather than once per event: Secure Client
    reinstalls routes repeatedly while connected, so per-event prompting would
    be continuous. Disconnecting clears the grants, so the next connect asks
    again.
    """

    granted: set[str] = field(default_factory=set)
    dismissed: set[str] = field(default_factory=set)
    """Scopes the user has put off deciding on for this session.

    Deliberately not consulted by ``allows``: dismissing withholds a claim, it
    never installs one, so a dismissed scope stays blocked exactly as it was.
    All it changes is whether the UI still counts the scope as asking, which is
    what stops one permanently-declined scope pinning the tray amber and
    masking a scope that is claimed and genuinely failing.
    """

    session_key: str | None = None

    def sync(self, vpn: VpnState) -> None:
        """Reset grants when the tunnel changes identity or drops."""
        key = ",".join(vpn.addresses) if vpn.connected else None
        if key != self.session_key:
            if self.granted or self.dismissed:
                log.info(
                    "VPN session changed; clearing %d grant(s) and %d dismissal(s)",
                    len(self.granted),
                    len(self.dismissed),
                )
            self.granted.clear()
            self.dismissed.clear()
            self.session_key = key

    def allows(self, scope: str, config: Config) -> bool:
        if not config.needs_approval(scope):
            return True
        return scope in self.granted

    def _record(self, target: set[str], scope: str, what: str) -> None:
        if scope not in target and len(target) >= MAX_SESSION_GRANTS:
            # Validation bounds the shape of a name, not how many distinct ones
            # a caller can invent, and these sets are the things on the session
            # tier that grow. A host with more than a handful of scopes does
            # not exist; the cap is a backstop, not a policy.
            raise ValueError(
                f"too many session {what} (limit {MAX_SESSION_GRANTS}); "
                "disconnect the VPN to clear them"
            )
        target.add(scope)

    def grant(self, scope: str) -> None:
        self._record(self.granted, scope, "grants")
        # An approved scope is not also being put off.
        self.dismissed.discard(scope)

    def dismiss(self, scope: str) -> None:
        self._record(self.dismissed, scope, "dismissals")


ROOT_ONLY = frozenset({"set-automation", "set-scope"})
"""Commands that write the config file and so outlive the VPN session.

``approve`` is deliberately absent: session approval is a group-tier action and
``always=True`` is not, so it is decided per-request rather than per-command.
``reconcile`` and ``restart`` stay group-tier -- neither grants anything new,
they only re-run or resume work already approved.
"""


class Daemon:
    def __init__(self, config: Config | None = None, dry_run: bool = False) -> None:
        self.config = config or load_config()
        self.dry_run = dry_run
        self.grants = SessionGrants()
        self.stop_event = threading.Event()
        self.last_plan: ReconcilePlan | None = None
        self.pending_approval: list[str] = []
        self.pending_claims: list[dict] = []
        self._refusals_logged: frozenset = frozenset()
        self._discovery_logged: frozenset = frozenset()
        self._lock = threading.Lock()
        self.control: ControlServer | None = None
        self._last_connected: bool | None = None
        self._first_reconcile = True

    # -- core ---------------------------------------------------------------

    def reconcile_once(self, reason: str = "") -> ReconcilePlan:
        # Reload every pass so an operator editing the config -- notably to
        # approve a scope -- takes effect without restarting the daemon.
        self.config = load_config()

        vpn = vpn_state()
        self.grants.sync(vpn)

        if vpn.connected != self._last_connected:
            if vpn.connected:
                log.info(
                    "VPN up on %s [%s], %s, %d captured prefix(es)",
                    ", ".join(vpn.devices),
                    ", ".join(vpn.addresses) or "no address",
                    "tunnel-all" if vpn.tunnel_all else "split-tunnel",
                    len(vpn.captured_prefixes),
                )
            elif self._last_connected is not None:
                log.info("VPN down; releasing all claims")
            else:
                log.info("VPN down; nothing to claim")
            self._last_connected = vpn.connected

        discovery = discover_scopes(self.config)
        self._log_discovery(discovery.warnings)
        plan = reconcile(discovery.scopes, vpn, self.config)

        with self._lock:
            self.last_plan = plan

        # A steady-state no-op is logged quietly to keep the journal readable,
        # but the first pass is always announced: a daemon that says "starting"
        # and then nothing forever cannot be told apart from a hung one.
        noisy = self._first_reconcile or not plan.is_noop
        self._first_reconcile = False
        log.log(
            logging.INFO if noisy else logging.DEBUG,
            "reconcile (%s): %s",
            reason or "tick",
            plan.summary(),
        )
        self._log_refusals(plan.refused)

        if plan.is_noop:
            return plan

        # Removals are never gated. Cleaning up after ourselves -- on disconnect,
        # or when a bridge moves -- is not a change that needs permission.
        for claim in plan.to_remove:
            self._run(removal_actions(str(claim.network), claim.device), "remove")

        if self.config.firewall:
            # Accepts for scopes we no longer claim -- including every scope
            # once the tunnel drops -- have to go too, or they outlive the
            # routing they existed to support.
            installed = installed_firewall_scopes() or set()
            for name in sorted(installed - set(plan.desired_scopes)):
                self._run(firewall_removal_actions(name), f"unclaim {name}")

        allowed, blocked = [], []
        for scope in plan.to_add:
            (allowed if self.grants.allows(scope.name, self.config) else blocked).append(
                scope
            )

        for scope in allowed:
            actions = policy_actions(scope)
            if self.config.firewall:
                # Both layers together. H1 is confirmed: after a reconnect,
                # correct routing alone leaves traffic dropped, so the accepts
                # are part of the fix rather than a fallback.
                actions += firewall_actions(scope)
            self._run(actions, f"claim {scope.name}")

        with self._lock:
            self.pending_approval = [s.name for s in blocked]
            # The scope name alone is not a decision: it is the CIDR that says
            # whether approving this diverts a bridge or a corporate range.
            self.pending_claims = [
                {
                    "scope": s.name,
                    "device": s.device,
                    "networks": [str(n) for n in s.networks],
                    "shadowed_by": sorted(
                        {
                            str(shadow)
                            for n in s.networks
                            if (shadow := vpn.shadows(n)) is not None
                        }
                    ),
                }
                for s in blocked
            ]
        if blocked:
            log.info(
                "awaiting approval for: %s (automation=%s)",
                ", ".join(s.name for s in blocked),
                self.config.automation.value,
            )

        return plan

    # -- control ------------------------------------------------------------

    def snapshot(self, caller_uid: int | None = None) -> dict:
        """Everything a client needs to render state, in one round trip."""
        vpn = vpn_state()
        discovery = discover_scopes(self.config)
        diagnoses = diagnose_all(discovery.scopes, vpn)
        # Clients need this to avoid counting a bridge with no containers as a
        # failure: it sits DOWN and has nothing to reach.
        states = link_states()
        with self._lock:
            plan = self.last_plan
            pending = list(self.pending_approval)
            pending_claims = [dict(c) for c in self.pending_claims]

        return {
            "version": __version__,
            "vpn": vpn.as_dict(),
            "config": self.config.as_dict(),
            "scopes": [
                {
                    **s.as_dict(),
                    "device_up": link_is_up(s.device, states),
                    # The *effective* enabled state, not the discovery default.
                    # Without this a client shows a toggle that never moves,
                    # because enabled_by_default is a constant.
                    "enabled": self.config.scope_enabled(
                        s.name, s.enabled_by_default
                    ),
                }
                for s in discovery.scopes
            ],
            "diagnoses": [d.as_dict() for d in diagnoses],
            "plan": plan.as_dict() if plan else None,
            "pending_approval": pending,
            # Same set as pending_approval, with the CIDRs a caller needs to
            # judge it. Kept alongside rather than replacing it, so a client
            # built against the older snapshot still renders.
            "pending_claims": pending_claims,
            "refused_claims": [r.as_dict() for r in plan.refused] if plan else [],
            "session_grants": sorted(self.grants.granted),
            # Names only: these are still in pending_claims, still blocked, and
            # still approvable. This says which of them have been put off, so a
            # client can stop counting them as outstanding.
            "dismissed": sorted(self.grants.dismissed),
            "owned_routes": owned_routes(),
            "owned_rules": owned_rules() or [],
            "warnings": list(discovery.warnings),
            # So a client can grey out what it is not allowed to do rather than
            # offering it and failing. Advisory only -- dispatch is the gate.
            "caller_is_root": caller_uid == 0,
        }

    def _authorize(self, command: str, params: dict, uid: int | None) -> None:
        """Enforce the two tiers the README documents.

        Reaching this socket at all already proves membership of the owning
        group, because it is ``root:<group> 0660`` -- that is the lower tier and
        needs no second check. What the mode cannot express is the upper one, so
        every command that writes ``/etc/ciscomvent/config.json`` and therefore
        survives a reboot is checked here against the caller's kernel-reported
        uid.

        This has to live on the request path. The equivalent ``is_root()`` calls
        in ``cli.py`` guard a *direct* write by that same process and are real
        there, but they guard nothing on the socket route: an attacker does not
        run the CLI, they speak the protocol.

        ``uid`` of None means the kernel would not vouch for the peer, which is
        read as "not root".
        """
        persists = command in ROOT_ONLY or (
            command == "approve" and bool(params.get("always"))
        )
        if not persists or uid == 0:
            return

        what = "standing approval" if command == "approve" else command
        log.warning(
            "refused %s from uid %s: needs root", what, "unknown" if uid is None else uid
        )
        raise PermissionError(
            f"{what} persists to {CONFIG_PATH} and needs root; re-run with sudo. "
            "Session-only actions (approve without --always, reconcile, status) "
            "need group membership alone."
        )

    def dispatch(self, command: str, params: dict, uid: int | None = None) -> dict:
        """Handle one control-socket command.

        ``uid`` is the caller's, from ``SO_PEERCRED`` -- see
        ``control.peer_uid``. It defaults to None so that any caller which
        forgets to supply it fails closed rather than silently gaining root.
        """
        self._authorize(command, params, uid)

        if command == "status":
            return self.snapshot(uid)

        if command == "reconcile":
            plan = self.reconcile_once(reason="control socket")
            return {"plan": plan.as_dict(), "summary": plan.summary()}

        if command == "approve":
            scope = checked_scope(params.get("scope"))
            self.approve(scope, always=bool(params.get("always")))
            return {"approved": scope, "always": bool(params.get("always"))}

        if command == "dismiss":
            # Absent from ROOT_ONLY on purpose, and weaker than the session
            # approval beside it: this only withholds a claim, so the worst a
            # group member can do with it is silence a prompt they could
            # already have answered outright.
            scope = checked_scope(params.get("scope"))
            self.dismiss(scope)
            return {"dismissed": scope}

        if command == "set-automation":
            value = params.get("automation")
            config = load_config()
            config.automation = Automation(value)
            save_config(config)
            self.config = config
            log.info("automation set to %s", config.automation.value)
            self.reconcile_once(reason="automation change")
            return {"automation": config.automation.value}

        if command == "set-scope":
            return self._set_scope(params)

        if command == "restart":
            log.info("restart requested via the control socket")
            # Reply first, then exit. systemd (Restart=always) starts us again.
            # Claims are deliberately left in place while we are down: tearing
            # them up would break reachability for the sake of a restart.
            threading.Timer(0.3, self.shutdown).start()
            return {"restarting": True}

        raise ValueError(f"unknown command: {command!r}")

    def _set_scope(self, params: dict) -> dict:
        enabled = params.get("enabled")
        if enabled is None:
            raise ValueError("set-scope needs a scope and enabled flag")
        # Root-only since the authorization fix, but this is what lands in
        # /etc and it is worth refusing a malformed name before it is written.
        scope = checked_scope(params.get("scope"))

        config = load_config()
        for collection in (config.enabled_scopes, config.disabled_scopes):
            if scope in collection:
                collection.remove(scope)
        (config.enabled_scopes if enabled else config.disabled_scopes).append(scope)
        save_config(config)
        self.config = config

        log.info("scope %s %s", scope, "enabled" if enabled else "disabled")
        self.reconcile_once(reason=f"scope change for {scope}")
        return {"scope": scope, "enabled": bool(enabled)}

    def _log_refusals(self, refused: tuple) -> None:
        """Announce guard refusals once, not every 60s.

        A refusal is stable for as long as the offending network exists, so
        logging it on every pass would bury it in its own repetition. Keyed on
        the reason too, so a network that starts failing for a new reason is
        announced again.
        """
        seen = frozenset((r.scope, str(r.network), r.reason) for r in refused)
        if seen == self._refusals_logged:
            return

        for refusal in refused:
            log.warning(
                "refusing to claim %s for %s: %s. To claim it anyway, add it to "
                "allow_wide_claims in %s.",
                refusal.network,
                refusal.scope,
                refusal.reason,
                CONFIG_PATH,
            )
        if not refused and self._refusals_logged:
            log.info("previously refused claim(s) no longer present")
        self._refusals_logged = seen

    def _log_discovery(self, warnings: tuple[str, ...]) -> None:
        """Announce discovery warnings once, on the same terms as refusals.

        This is the only route to the journal for an interface prefix refused
        for its width: the scope is not offered at all, so it never reaches a
        plan and has no Refusal to carry. On untrusted wifi the line written
        here is the one signal that the network handed this host a prefix it
        had no business handing it.

        Only newly appeared warnings are logged. `docker unavailable` is
        permanent on a host without Docker, and re-announcing it every time an
        unrelated warning arrives is how a journal stops being read.
        """
        seen = frozenset(warnings)
        if seen == self._discovery_logged:
            return

        for warning in warnings:
            if warning not in self._discovery_logged:
                log.warning("discovery: %s", warning)
        self._discovery_logged = seen

    def _run(self, actions: list, label: str) -> None:
        results = execute(actions, dry_run=self.dry_run)
        for result in results:
            if not result.ok:
                log.warning("%s failed: %s (%s)", label, result.action.render(), result.detail)
            else:
                log.debug("%s: %s [%s]", label, result.action.render(), result.status.value)

    def approve(self, scope: str, always: bool = False) -> None:
        """Grant a blocked scope for this session, or permanently.

        Persisting has to go through the config file rather than the in-memory
        object, because reconcile_once reloads config on every pass and would
        otherwise discard the change immediately.
        """
        self.grants.grant(scope)
        if always:
            config = load_config()
            if scope not in config.always_allow:
                config.always_allow.append(scope)
                save_config(config)
        log.info("approved %s%s", scope, " (always)" if always else "")
        self.reconcile_once(reason=f"approval of {scope}")

    def dismiss(self, scope: str) -> None:
        """Stop counting a scope as asking, for this VPN session.

        No reconcile: nothing about what is claimed changes, and the scope stays
        in ``pending_claims`` so it can still be approved later and so the CIDR
        is there to confirm against when it is.
        """
        self.grants.dismiss(scope)
        log.info("dismissed %s for this session", scope)

    # -- loop ---------------------------------------------------------------

    def run(self) -> int:
        if not is_root() and not self.dry_run:
            log.error("the daemon must run as root")
            return 1

        log.info("starting: automation=%s", self.config.automation.value)

        debouncer = Debouncer(
            callback=lambda count: self.reconcile_once(reason=f"{count} netlink event(s)")
        )

        self.control = ControlServer(self.dispatch, group=self.config.socket_group)
        ok, detail = self.control.start()
        # A missing control socket costs the GUI, not the fix, so it is a
        # warning rather than a fatal error.
        log.log(logging.INFO if ok else logging.WARNING, "control: %s", detail)

        watcher = threading.Thread(
            target=self._watch_loop, args=(debouncer,), daemon=True
        )
        watcher.start()

        # Reconcile once at startup so we converge without waiting for churn.
        self.reconcile_once(reason="startup")

        last_resync = time.monotonic()
        while not self.stop_event.is_set():
            if debouncer.fire_if_due():
                last_resync = time.monotonic()
            elif time.monotonic() - last_resync >= RESYNC_SECONDS:
                self.reconcile_once(reason="periodic resync")
                last_resync = time.monotonic()
            self.stop_event.wait(POLL_INTERVAL)

        if getattr(self, "control", None):
            self.control.stop()
        log.info("stopping")
        return 0

    def _watch_loop(self, debouncer: Debouncer) -> None:
        while not self.stop_event.is_set():
            try:
                for _line in watch():
                    debouncer.record()
                    if self.stop_event.is_set():
                        return
            except Exception as exc:  # noqa: BLE001 - must never kill the daemon
                log.warning("monitor died (%s); restarting in 2s", exc)
                self.stop_event.wait(2.0)

    def shutdown(self, *_args) -> None:
        self.stop_event.set()


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="ciscomventd")
    parser.add_argument("--dry-run", action="store_true", help="log, change nothing")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument(
        "--once", action="store_true", help="reconcile once and exit"
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    daemon = Daemon(dry_run=args.dry_run)

    if args.once:
        plan = daemon.reconcile_once(reason="--once")
        log.info("result: %s", plan.summary())
        return 0

    signal.signal(signal.SIGTERM, daemon.shutdown)
    signal.signal(signal.SIGINT, daemon.shutdown)
    return daemon.run()


if __name__ == "__main__":
    raise SystemExit(main())
