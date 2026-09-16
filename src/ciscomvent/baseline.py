# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Golden state capture.

A baseline taken with the VPN *down* is the reference for everything later: it
records what correct routing looks like, so a post-fix state can be compared
against known-good rather than against a guess.

The firewall portion needs root. Rather than prompting, it degrades and records
why: the daemon already runs as root and can fill that gap.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .config import load as load_config
from .detect import diagnose_all, vpn_state
from .discovery import discover_scopes
from .dockerdisc import list_bridge_networks
from .errors import CommandError
from .iproute import ip_binary, run_json

SCHEMA_VERSION = 1


def default_dir() -> Path:
    state = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return Path(state) / "ciscomvent" / "baselines"


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _capture_firewall() -> dict:
    """iptables-save via non-interactive sudo, or an explanation of why not."""
    binary = shutil.which("iptables-save") or "/usr/sbin/iptables-save"
    if not os.path.exists(binary):
        return {"available": False, "reason": "iptables-save not found"}

    if os.geteuid() == 0:
        argv = [binary]
    else:
        argv = ["sudo", "-n", binary]

    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=10.0, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"available": False, "reason": str(exc)}

    if proc.returncode != 0:
        return {
            "available": False,
            "reason": "needs root; passwordless sudo unavailable "
            "(the daemon will capture this)",
        }
    return {"available": True, "rules": proc.stdout.splitlines()}


def capture(include_firewall: bool = True) -> dict:
    """Snapshot routing, addressing, Docker topology, and scope diagnosis."""
    vpn = vpn_state()
    discovery = discover_scopes(load_config())
    diagnoses = diagnose_all(discovery.scopes, vpn)

    ip = ip_binary()
    kernel: dict = {}
    for key, args in (
        ("routes_all_tables", ["-j", "-4", "route", "show", "table", "all"]),
        ("addresses", ["-j", "-4", "addr", "show"]),
        ("links", ["-j", "link", "show"]),
    ):
        try:
            kernel[key] = run_json([ip, *args], timeout=10.0)
        except CommandError as exc:
            kernel[key] = {"error": str(exc)}

    networks = []
    try:
        networks = [
            {
                "id": n.id,
                "name": n.name,
                "bridge": n.bridge,
                "bridge_source": n.bridge_source,
                "subnets": [s.as_dict() for s in n.subnets],
                "container_ips": [str(ip_) for ip_ in n.container_ips],
            }
            for n in list_bridge_networks()
        ]
    except CommandError:
        pass

    snapshot = {
        "schema_version": SCHEMA_VERSION,
        "captured_at": _timestamp(),
        "hostname": os.uname().nodename,
        "vpn": vpn.as_dict(),
        "is_golden": not vpn.connected,
        "discovery": discovery.as_dict(),
        "diagnoses": [d.as_dict() for d in diagnoses],
        "docker_networks": networks,
        "kernel": kernel,
    }
    if include_firewall:
        snapshot["firewall"] = _capture_firewall()
    return snapshot


def save(snapshot: dict, path: Path | None = None) -> Path:
    if path is None:
        stamp = snapshot["captured_at"].replace(":", "").replace("-", "")
        tag = "golden" if snapshot.get("is_golden") else "vpn"
        path = default_dir() / f"{stamp}-{tag}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(snapshot, indent=2) + "\n")
    # May contain firewall rules and internal addressing.
    path.chmod(0o600)
    return path


def load(path: Path) -> dict:
    return json.loads(Path(path).read_text())


def latest(directory: Path | None = None) -> Path | None:
    directory = directory or default_dir()
    if not directory.is_dir():
        return None
    files = sorted(directory.glob("*.json"))
    return files[-1] if files else None
