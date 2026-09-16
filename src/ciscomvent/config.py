# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Persisted configuration.

Deliberately small and human-editable. The daemon runs as root, so this lives
in /etc rather than a user directory, and the file is the only thing that
decides whether the daemon may touch the kernel unprompted.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from .model import IPv4Network

CONFIG_PATH = Path("/etc/ciscomvent/config.json")

DEFAULT_MIN_CLAIM_PREFIXLEN = 16
"""Widest network claimable without an explicit opt-in.

Docker's own default pools do not go wider: 172.17-172.31 are handed out as
/16s and 192.168.0.0/16 in /20s, and libvirt's default bridge is a /24. So
this refuses nothing the usual tooling produces on its own.
"""


class Automation(str, Enum):
    """Whether the daemon may apply without being asked.

    ``CONFIRM`` is the default: the daemon always computes the plan and emits an
    event, but waits for approval before touching the kernel. Because Secure
    Client reinstalls routes repeatedly within one session, approval is granted
    **per VPN session** rather than per event -- confirm once after connect and
    the daemon maintains that scope until the tunnel drops. Otherwise the
    prompting would be continuous.

    ``AUTO`` applies silently. Only this mode meets the acceptance bar of
    surviving a reconnect with zero interaction; ``CONFIRM`` meets it with one
    approval per reconnect.
    """

    CONFIRM = "confirm"
    AUTO = "auto"


@dataclass
class Config:
    automation: Automation = Automation.CONFIRM

    socket_group: str | None = None
    """Group given ownership of the control socket, or None to auto-detect.

    Auto-detection tries a dedicated `ciscomvent` group first, then the
    platform admin group (`sudo` on Debian-family, `wheel` elsewhere). Naming a
    group that does not exist leaves the socket root-only rather than
    substituting a different one, which would widen access silently.
    """

    firewall: bool = True
    """Whether to install the layer 2 accepts alongside the routes.

    On by default because H1 is confirmed: after a VPN reconnect, correct
    routing alone is not enough and host-to-container traffic is dropped until
    the accepts are in place. This is no longer a speculative escalation."""

    enabled_scopes: list[str] = field(default_factory=list)
    """Scopes enabled beyond the defaults, by name. Docker scopes are on by
    default; LAN and libvirt must be named here to be touched at all."""

    disabled_scopes: list[str] = field(default_factory=list)
    """Scopes explicitly turned off, overriding the default-on for Docker."""

    always_allow: list[str] = field(default_factory=list)
    """Scopes promoted to standing approval, so confirm mode stops asking."""

    min_claim_prefixlen: int = DEFAULT_MIN_CLAIM_PREFIXLEN
    """Floor on the prefix length of any claim -- a ceiling on its width.

    A claim installs `ip rule to <network> priority 100`, which is consulted
    ahead of `main` at 32766. That is the whole design, and it means a claim
    also outranks the tunnel's routes. The subnet comes from whoever created
    the network and creating a Docker network needs no root, so without a floor
    `docker network create --subnet 10.0.0.0/8` diverts every corporate
    destination in 10/8 onto a bridge.
    """

    allow_wide_claims: list[str] = field(default_factory=list)
    """Exact CIDRs to claim even though the guard would refuse them.

    Keyed on the network rather than the scope name, because the name is stable
    while its subnet is not: a standing approval of `docker:app` must not carry
    over to the same name recreated around a wider subnet. No control-socket
    command writes this -- editing the file as root is the only way in.
    """

    def scope_enabled(self, name: str, default: bool) -> bool:
        if name in self.disabled_scopes:
            return False
        if name in self.enabled_scopes:
            return True
        return default

    def needs_approval(self, name: str) -> bool:
        return self.automation is Automation.CONFIRM and name not in self.always_allow

    def wide_claim_allowed(self, network: IPv4Network) -> bool:
        """Whether the operator has accepted this exact network by hand."""
        return str(network) in self.allow_wide_claims

    def width_refusal(self, network: IPv4Network) -> str | None:
        """Why ``network`` is too wide to claim, or None if its size is fine.

        The ceiling half of the claim guard, kept here because both of its
        inputs are config and because two callers need it. `reconcile` asks
        before installing a rule; `discovery` asks before offering a host
        interface as a scope at all, having no VpnState to ask the other half
        of the guard about. One implementation so the two cannot drift into
        disagreeing about what is claimable.
        """
        if self.wide_claim_allowed(network):
            return None
        if network.prefixlen < self.min_claim_prefixlen:
            return (
                f"/{network.prefixlen} is wider than the "
                f"/{self.min_claim_prefixlen} ceiling, and a claim outranks "
                "the tunnel"
            )
        return None

    def as_dict(self) -> dict:
        return {
            "automation": self.automation.value,
            "firewall": self.firewall,
            "socket_group": self.socket_group,
            "enabled_scopes": sorted(self.enabled_scopes),
            "disabled_scopes": sorted(self.disabled_scopes),
            "always_allow": sorted(self.always_allow),
            "min_claim_prefixlen": self.min_claim_prefixlen,
            "allow_wide_claims": sorted(self.allow_wide_claims),
        }


def load(path: Path | None = None) -> Config:
    """Read config, falling back to defaults. A malformed file must not stop the
    daemon from starting, so it degrades to defaults rather than raising."""
    path = path or CONFIG_PATH
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return Config()

    try:
        automation = Automation(raw.get("automation", "confirm"))
    except ValueError:
        automation = Automation.CONFIRM

    try:
        min_prefixlen = int(raw.get("min_claim_prefixlen", DEFAULT_MIN_CLAIM_PREFIXLEN))
    except (TypeError, ValueError):
        min_prefixlen = DEFAULT_MIN_CLAIM_PREFIXLEN
    if not 0 <= min_prefixlen <= 32:
        # A nonsense value falls back to the default rather than to 0, which
        # would read as "no ceiling" and turn a typo into an open guard.
        min_prefixlen = DEFAULT_MIN_CLAIM_PREFIXLEN

    return Config(
        automation=automation,
        firewall=bool(raw.get("firewall", True)),
        socket_group=raw.get("socket_group") or None,
        enabled_scopes=list(raw.get("enabled_scopes", [])),
        disabled_scopes=list(raw.get("disabled_scopes", [])),
        always_allow=list(raw.get("always_allow", [])),
        min_claim_prefixlen=min_prefixlen,
        allow_wide_claims=[str(n) for n in raw.get("allow_wide_claims", [])],
    )


def save(config: Config, path: Path | None = None) -> Path:
    path = path or CONFIG_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(config.as_dict(), indent=2) + "\n")
    os.replace(tmp, path)  # atomic, so a crash cannot leave a half-written file
    return path
