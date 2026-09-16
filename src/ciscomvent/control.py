# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Control socket: how unprivileged clients talk to the root daemon.

Root never talks to the desktop and the desktop never touches the kernel. The
GUI asks this socket for state and sends approvals back; the daemon does the
mutating. That split is why the tray applet raises its own notifications rather
than the daemon reaching into a user session bus.

Protocol is newline-delimited JSON, one request and one response per line:

    {"command": "status"}
    {"ok": true, "data": {...}}
"""

from __future__ import annotations

import grp
import json
import logging
import os
import socket
import socketserver
import struct
import threading
from pathlib import Path

log = logging.getLogger("ciscomvent")

SOCKET_DIR = Path("/run/ciscomvent")
SOCKET_PATH = SOCKET_DIR / "control.sock"

CANDIDATE_GROUPS = ("ciscomvent", "sudo", "wheel")
"""Groups tried, in order, when none is configured.

Anything reachable through this socket changes routing and firewall state, so
access is restricted to an administrative group -- one whose members can already
become root, so the socket grants no privilege they did not have. Never make it
world-writable.

The order matters. A dedicated ``ciscomvent`` group comes first so an admin can
create one for finer-grained access than "everyone who can sudo". After that
come the platform admin groups: ``sudo`` on Debian-family systems, ``wheel`` on
RHEL, Fedora and Arch. Hardcoding ``sudo`` alone meant the lookup failed on half
the distributions in use and the socket silently became root-only, locking out
every unprivileged client including the GUI.
"""

CONNECT_TIMEOUT = 5.0
"""Client-side, waiting for the daemon to answer."""

REQUEST_TIMEOUT = 10.0
"""Server-side, waiting for a client to finish its request line.

Only the client used to set a timeout, so a peer that connected and then said
nothing -- or said something endless -- held a daemon thread indefinitely. This
bounds the read, not the work that follows it.
"""

MAX_REQUEST_BYTES = 65536
"""Longest request line accepted. Requests are a single JSON object naming a
command and a scope; the real ones are a couple of hundred bytes."""

MAX_CONNECTIONS = 32
"""Concurrent handler threads. ThreadingUnixStreamServer spawns one per
connection with no ceiling of its own, so a client opening sockets in a loop
could exhaust the daemon's threads."""


class ControlError(Exception):
    """The daemon could not be reached, or refused the request."""


# -- peer credentials -------------------------------------------------------


def peer_uid(conn: socket.socket) -> int | None:
    """The uid of the process at the other end, as recorded by the kernel.

    ``SO_PEERCRED`` returns a ``struct ucred`` -- pid, uid, gid -- that the
    kernel fills in at ``connect(2)`` from the peer's real credentials. The
    client never transmits it and has no way to influence it, which is the
    whole point: nothing a client *says* about itself can be trusted, and the
    socket mode is a single bit that cannot express a second tier. Taking the
    uid from the connection is what lets the daemon enforce per-command policy
    instead of leaving it to a client-side check the caller can simply skip.

    Only the uid is used. ``ucred.gid`` is the peer's primary gid, **not** its
    supplementary groups, so a user who is a supplementary member of the socket
    group reports some unrelated gid and a naive check would reject nearly
    everyone. Group membership needs no re-checking anyway: reaching a
    ``root:<group> 0660`` socket already proves it.

    Reading credentials from the socket also avoids the ``/proc/<pid>`` race --
    the snapshot is taken at connect time and pinned to the connection, so
    there is no window in which the pid is recycled or the process execs
    something setuid between the check and its use.

    ``None`` means the credentials could not be read; callers must treat that
    as "not root" rather than as permission.
    """
    option = getattr(socket, "SO_PEERCRED", None)
    if option is None:  # not Linux -- the daemon is Linux-only regardless
        return None
    try:
        raw = conn.getsockopt(socket.SOL_SOCKET, option, struct.calcsize("3i"))
    except OSError:
        return None
    _pid, uid, _gid = struct.unpack("3i", raw)
    return uid


# -- client -----------------------------------------------------------------


def is_available(path: Path | None = None) -> bool:
    return (path or SOCKET_PATH).exists()


def request(command: str, path: Path | None = None, **params) -> dict:
    """Send one command and return its ``data`` payload."""
    path = path or SOCKET_PATH
    payload = json.dumps({"command": command, **params}) + "\n"

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(CONNECT_TIMEOUT)
    try:
        sock.connect(str(path))
        sock.sendall(payload.encode())
        raw = b""
        while not raw.endswith(b"\n"):
            chunk = sock.recv(65536)
            if not chunk:
                break
            raw += chunk
    except FileNotFoundError as exc:
        raise ControlError(f"daemon socket not found at {path}") from exc
    except PermissionError as exc:
        # Naming a specific group here would be a guess: which one is in use is
        # resolved by the daemon at startup and can be configured.
        raise ControlError(
            f"permission denied on {path}. The socket is restricted to its "
            f"owning group -- run `ls -l {path}` to see which, and join it, or "
            "set socket_group in /etc/ciscomvent/config.json"
        ) from exc
    except OSError as exc:
        raise ControlError(f"cannot reach the daemon: {exc}") from exc
    finally:
        sock.close()

    if not raw.strip():
        raise ControlError("daemon closed the connection without replying")

    try:
        reply = json.loads(raw.decode())
    except json.JSONDecodeError as exc:
        raise ControlError(f"unparseable reply: {exc}") from exc

    if not reply.get("ok"):
        raise ControlError(reply.get("error") or "the daemon refused the request")
    return reply.get("data") or {}


# -- server -----------------------------------------------------------------


class _Handler(socketserver.StreamRequestHandler):
    timeout = REQUEST_TIMEOUT
    """StreamRequestHandler.setup() applies this to the connection for us."""

    def handle(self) -> None:
        # Read the caller's identity before anything they sent, so the value
        # handed to dispatch can never be derived from the request body.
        uid = peer_uid(self.connection)

        try:
            # Bounded: an unbounded readline lets a client with no newline in
            # its stream grow the root daemon's memory until it is killed.
            # One byte over the limit is enough to tell "too long" apart from
            # "client hung up mid-line".
            line = self.rfile.readline(MAX_REQUEST_BYTES + 1)
        except OSError as exc:  # includes socket.timeout
            log.debug("control read failed: %s", exc)
            return

        if not line:
            return
        if len(line) > MAX_REQUEST_BYTES:
            self._reply(
                {
                    "ok": False,
                    "error": f"request too large (limit {MAX_REQUEST_BYTES} bytes)",
                }
            )
            return

        try:
            message = json.loads(line.decode())
            command = message.pop("command", "")
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            self._reply({"ok": False, "error": f"bad request: {exc}"})
            return

        try:
            data = self.server.dispatch(command, message, uid)
            self._reply({"ok": True, "data": data})
        except Exception as exc:  # noqa: BLE001 - a bad request must not kill us
            log.warning("control command %r failed: %s", command, exc)
            self._reply({"ok": False, "error": str(exc)})

    def _reply(self, payload: dict) -> None:
        try:
            self.wfile.write((json.dumps(payload) + "\n").encode())
        except OSError as exc:
            # The client gave up while we were working. Its problem, not ours,
            # and now reachable by timeout as well as by disconnect.
            log.debug("control reply not delivered: %s", exc)


class _Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, path: str, dispatch) -> None:
        # dispatch(command, params, uid) -- uid is None when the kernel would
        # not say, which the callee must read as "not root".
        self.dispatch = dispatch
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(path, _Handler)

    def process_request(self, request, client_address) -> None:
        """Take a slot before spawning, or drop the connection.

        Acquired here, on the accept loop, and released at the end of the
        worker thread below. Dropping is the right failure: the alternative is
        an unbounded thread count in a root daemon, and a client that finds the
        socket busy can simply retry.
        """
        if not self._slots.acquire(blocking=False):
            log.warning(
                "control socket at capacity (%d connections); dropping one",
                MAX_CONNECTIONS,
            )
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()  # the thread that would have released never ran
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


class ControlServer:
    """Runs the socket alongside the daemon loop."""

    def __init__(self, dispatch, path: Path | None = None, group: str | None = None):
        """``group`` of None means auto-detect from CANDIDATE_GROUPS."""
        self.path = path or SOCKET_PATH
        self.group = group
        self.dispatch = dispatch
        self._server: _Server | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> tuple[bool, str]:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # A stale socket from an unclean shutdown would block the bind.
            if self.path.exists():
                self.path.unlink()

            # bind() creates the socket with 0777 & ~umask and _restrict only
            # tightens it afterwards, so between the two it is as open as the
            # umask allows -- 0755 at systemd's default, 0777 at umask 000.
            # Binding under 0177 means it is 0600 from the instant it exists,
            # and _restrict widens it to 0660 for the owning group. umask is
            # process-global, which is safe only because start() runs before
            # the daemon spawns any thread.
            previous = os.umask(0o177)
            try:
                self._server = _Server(str(self.path), self.dispatch)
            finally:
                os.umask(previous)
            detail = self._restrict()

            self._thread = threading.Thread(
                target=self._server.serve_forever, daemon=True
            )
            self._thread.start()
        except OSError as exc:
            return False, f"control socket unavailable: {exc}"
        return True, f"listening on {self.path} ({detail})"

    def _resolve_group(self) -> str | None:
        """The group to hand the socket to, or None for root-only.

        A configured group that does not exist fails closed rather than falling
        through to auto-detection. Substituting, say, ``sudo`` for a missing
        ``myteam`` would silently widen access beyond what was asked for.
        """
        if self.group:
            try:
                grp.getgrnam(self.group)
                return self.group
            except KeyError:
                log.warning(
                    "configured socket group %r does not exist; refusing to "
                    "substitute another group, so the socket stays root-only",
                    self.group,
                )
                return None

        for name in CANDIDATE_GROUPS:
            try:
                grp.getgrnam(name)
                return name
            except KeyError:
                continue
        return None

    def _restrict(self) -> str:
        """Owner root, group-writable, never world-accessible."""
        group = self._resolve_group()
        if group is not None:
            try:
                os.chown(self.path, 0, grp.getgrnam(group).gr_gid)
                os.chmod(self.path, 0o660)
                return f"root:{group} 0660"
            except (PermissionError, OSError) as exc:
                # The group exists, so this is a privilege problem -- most
                # likely CAP_CHOWN missing from the unit.
                log.warning("cannot give the socket to group %s: %s", group, exc)

        # Falling back to root-only is safe; falling back to world-writable is
        # not. Say so, because the symptom is every client being locked out.
        os.chmod(self.path, 0o600)
        return "root-only 0600 — no usable group, unprivileged clients cannot connect"

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        try:
            self.path.unlink()
        except OSError:
            pass
