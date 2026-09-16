# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Thin read-only wrappers over iproute2.

Everything here is unprivileged: ``ip route get``, ``ip addr``, ``ip link`` and
``ip monitor`` all work as a normal user. Mutation lives in the daemon,
never here.
"""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any

from .errors import CommandError
from .model import IPv4Address, RouteObservation

# The daemon runs from systemd with a minimal PATH, and /usr/sbin is not
# guaranteed to be on a user's PATH either. Resolve explicitly.
_IP_CANDIDATES = ("/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip")

DEFAULT_TIMEOUT = 5.0


def ip_binary() -> str:
    found = shutil.which("ip")
    if found:
        return found
    for candidate in _IP_CANDIDATES:
        if os.path.exists(candidate):
            return candidate
    raise CommandError(["ip"], 127, "iproute2 not found")


def run(argv: list[str], timeout: float = DEFAULT_TIMEOUT) -> str:
    proc = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        raise CommandError(argv, proc.returncode, proc.stderr)
    return proc.stdout


def run_json(argv: list[str], timeout: float = DEFAULT_TIMEOUT) -> Any:
    out = run(argv, timeout=timeout)
    if not out.strip():
        return []
    try:
        return json.loads(out)
    except json.JSONDecodeError as exc:
        raise CommandError(argv, 0, f"unparseable JSON: {exc}") from exc


def _ip(*args: str) -> list:
    return run_json([ip_binary(), "-j", *args])


@dataclass(frozen=True)
class InterfaceAddress:
    ifname: str
    address: IPv4Address
    prefixlen: int
    scope: str

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(
            f"{self.address}/{self.prefixlen}", strict=False
        )


def link_names() -> set[str]:
    return {entry["ifname"] for entry in _ip("link", "show") if "ifname" in entry}


def link_exists(name: str) -> bool:
    try:
        _ip("link", "show", name)
        return True
    except CommandError:
        return False


def link_states() -> dict[str, str]:
    """Map interface name to operstate (UP, DOWN, UNKNOWN)."""
    return {
        entry["ifname"]: entry.get("operstate", "UNKNOWN")
        for entry in _ip("link", "show")
        if "ifname" in entry
    }


def link_is_up(name: str, states: dict[str, str] | None = None) -> bool:
    """Whether a device can actually carry traffic.

    A Docker bridge with no running containers sits DOWN, and scope-link routes
    do not persist on a down device -- they are accepted and then silently
    disappear. Such a scope has nothing to reach and must not be treated as a
    target, or it produces failures that look like the bug we are fixing.
    """
    states = link_states() if states is None else states
    return states.get(name, "DOWN").upper() in ("UP", "UNKNOWN")


def addresses() -> list[InterfaceAddress]:
    """All IPv4 addresses currently configured, across all interfaces."""
    result: list[InterfaceAddress] = []
    for entry in _ip("-4", "addr", "show"):
        ifname = entry.get("ifname")
        if not ifname:
            continue
        for info in entry.get("addr_info", []):
            if info.get("family") != "inet":
                continue
            try:
                addr = ipaddress.ip_address(info["local"])
            except (KeyError, ValueError):
                continue
            result.append(
                InterfaceAddress(
                    ifname=ifname,
                    address=addr,
                    prefixlen=int(info.get("prefixlen", 32)),
                    scope=info.get("scope", ""),
                )
            )
    return result


def interface_by_address() -> dict[IPv4Address, str]:
    """Map each configured address to its interface.

    This is the authoritative cross-check for bridge-name resolution: rather
    than trusting a derived ``br-<id[:12]>`` string, confirm the interface
    actually holds the network's gateway address.
    """
    return {a.address: a.ifname for a in addresses()}


def routes(table: str = "main") -> list[dict]:
    return _ip("-4", "route", "show", "table", table)


def route_get(target: str) -> RouteObservation:
    """Resolve how the kernel would route to ``target`` right now.

    A failed lookup is returned as an observation carrying ``error`` rather than
    raised, because an unreachable probe is a diagnosis, not a crash.
    """
    try:
        entries = _ip("route", "get", str(target))
    except CommandError as exc:
        return RouteObservation(target=str(target), error=exc.stderr or str(exc))
    except subprocess.TimeoutExpired:
        return RouteObservation(target=str(target), error="timed out")

    if not entries:
        return RouteObservation(target=str(target), error="no route returned")

    entry = entries[0]
    return RouteObservation(
        target=str(target),
        dev=entry.get("dev"),
        prefsrc=entry.get("prefsrc"),
        rtype=entry.get("type"),
        gateway=entry.get("gateway"),
    )


def routes_via(devices: set[str]) -> list[dict]:
    """Main-table routes whose egress device is one of ``devices``."""
    return [r for r in routes() if r.get("dev") in devices]
