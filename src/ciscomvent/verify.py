# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reachability verification.

Distinguishes the three outcomes that tell a routing failure apart from a
firewall drop:

- **connected or refused** -- packets reached the container and something came
  back. Routing works and nothing is dropping us. A refusal is a *success* for
  our purposes: an RST means the path is intact.
- **timed out** -- the black-hole signature. Either still routed into the tunnel
  (layer 1 not effective) or reaching the bridge and being dropped (layer 2
  needed).
- **unreachable** -- no route at all, an ICMP error came back promptly.

A raw TCP connect to the container address tests exactly the hop that breaks,
without DNS, TLS, Host headers, or docker-proxy in the way.
"""

from __future__ import annotations

import re
import socket
import subprocess
from dataclasses import dataclass
from enum import Enum

from .dockerdisc import docker_binary
from .errors import CommandError
from .iproute import route_get, run
from .model import IPv4Address, Scope

DEFAULT_TIMEOUT = 3.0

# Ports as `docker ps` prints them: "80/tcp", "0.0.0.0:3309->3306/tcp",
# "127.0.0.1:18080->80/tcp". The internal port is what listens on the
# container address, so take the right-hand side of any mapping.
_PORT_RE = re.compile(r"(\d+)/(?:tcp|udp)")


class Reach(str, Enum):
    OPEN = "open"
    REFUSED = "refused"
    TIMEOUT = "timeout"
    UNREACHABLE = "unreachable"
    ERROR = "error"

    @property
    def reachable(self) -> bool:
        """Whether packets completed a round trip. A refusal counts."""
        return self in (Reach.OPEN, Reach.REFUSED)


@dataclass(frozen=True)
class Probe:
    address: str
    port: int
    result: Reach
    detail: str = ""
    label: str = ""

    def as_dict(self) -> dict:
        return {
            "address": self.address,
            "port": self.port,
            "label": self.label,
            "result": self.result.value,
            "reachable": self.result.reachable,
            "detail": self.detail,
        }


def parse_ports(spec: str) -> tuple[int, ...]:
    """Internal container ports from a `docker ps` Ports column."""
    ports: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        # For a published mapping, the internal port is after the arrow.
        target = part.split("->")[-1]
        match = _PORT_RE.search(target)
        if match:
            port = int(match.group(1))
            if port not in ports:
                ports.append(port)
    return tuple(ports)


def container_ports() -> dict[str, tuple[int, ...]]:
    """Map container name to the ports listening inside it."""
    binary = docker_binary()
    if not binary:
        return {}
    try:
        out = run([binary, "ps", "--format", "{{.Names}}\t{{.Ports}}"], timeout=10.0)
    except (CommandError, OSError):
        return {}

    mapping: dict[str, tuple[int, ...]] = {}
    for line in out.splitlines():
        if "\t" not in line:
            continue
        name, _, spec = line.partition("\t")
        ports = parse_ports(spec)
        if ports:
            mapping[name.strip()] = ports
    return mapping


def tcp_probe(
    address: str, port: int, timeout: float = DEFAULT_TIMEOUT, label: str = ""
) -> Probe:
    """One TCP connect attempt, classified."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((address, port))
        return Probe(address, port, Reach.OPEN, "connected", label)
    except socket.timeout:
        return Probe(
            address, port, Reach.TIMEOUT, f"no response in {timeout:g}s", label
        )
    except ConnectionRefusedError:
        return Probe(address, port, Reach.REFUSED, "RST — path intact", label)
    except OSError as exc:
        name = getattr(exc, "strerror", None) or str(exc)
        unreachable = exc.errno in (
            socket.errno.ENETUNREACH,
            socket.errno.EHOSTUNREACH,
        )
        return Probe(
            address,
            port,
            Reach.UNREACHABLE if unreachable else Reach.ERROR,
            name,
            label,
        )
    finally:
        sock.close()


def probe_scope(
    scope: Scope, timeout: float = DEFAULT_TIMEOUT, limit: int = 3
) -> list[Probe]:
    """Probe live endpoints in a scope, preferring containers with open ports."""
    ports = container_ports()
    targets: list[tuple[str, str, int]] = []

    for entry in scope.metadata.get("containers", ()):
        name = entry.get("name", "")
        address = entry.get("address", "")
        if not address:
            continue
        for port in ports.get(name, ()):
            targets.append((name, address, port))
            break
        if len(targets) >= limit:
            break

    if not targets:
        # No port information: fall back to the probe addresses, which at least
        # exercise routing even if nothing is listening.
        for address in scope.probes[:limit]:
            targets.append(("", str(address), 80))

    return [
        tcp_probe(address, port, timeout=timeout, label=name)
        for name, address, port in targets
    ]


def routing_ok(scope: Scope) -> tuple[bool, list[str]]:
    """Whether every probe address now resolves to the scope's own device."""
    notes: list[str] = []
    ok = True
    for address in scope.probes:
        obs = route_get(str(address))
        if obs.error:
            ok = False
            notes.append(f"{address}: {obs.error}")
        elif obs.dev != scope.device:
            ok = False
            notes.append(f"{address}: dev {obs.dev}, expected {scope.device}")
        else:
            notes.append(f"{address}: dev {obs.dev}")
    return ok, notes


@dataclass(frozen=True)
class HttpCheck:
    url: str
    resolve: str | None
    ok: bool
    detail: str

    def as_dict(self) -> dict:
        return {
            "url": self.url,
            "resolve": self.resolve,
            "ok": self.ok,
            "detail": self.detail,
        }


def http_check(
    url: str, resolve: str | None = None, timeout: float = 5.0
) -> HttpCheck:
    """The canonical end-to-end test, through the published port.

    Always pass ``resolve`` for a Host()-routed reverse proxy: a bare IP request
    matches no router and fails misleadingly.
    """
    argv = ["curl", "--ipv4", "--silent", "--show-error", "--max-time", str(timeout)]
    if resolve:
        argv += ["--resolve", resolve]
    argv += ["--output", "/dev/null", "--write-out", "%{http_code}", url]

    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout + 3, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return HttpCheck(url, resolve, False, str(exc))

    if proc.returncode == 0:
        return HttpCheck(url, resolve, True, f"HTTP {proc.stdout.strip()}")
    return HttpCheck(
        url, resolve, False, proc.stderr.strip() or f"curl exit {proc.returncode}"
    )
