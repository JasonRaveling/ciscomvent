# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Control socket protocol and permissions."""

from __future__ import annotations

import json
import os
import socket
import stat

import pytest

from pathlib import Path

from ciscomvent.control import ControlError, ControlServer, is_available, request


@pytest.fixture
def server(tmp_path):
    calls = []

    def dispatch(command, params, uid):
        calls.append((command, params, uid))
        if command == "boom":
            raise ValueError("deliberate failure")
        if command == "echo":
            return dict(params)
        return {"command": command}

    path = tmp_path / "control.sock"
    srv = ControlServer(dispatch, path=path, group="definitely-no-such-group")
    ok, _ = srv.start()
    assert ok
    yield srv, path, calls
    srv.stop()


def test_round_trip(server):
    _srv, path, calls = server
    assert request("status", path=path) == {"command": "status"}
    assert calls == [("status", {}, os.getuid())]


def test_parameters_are_passed_through(server):
    _srv, path, _ = server
    data = request("echo", path=path, scope="docker:x", always=True)
    assert data == {"scope": "docker:x", "always": True}


def test_dispatch_errors_come_back_as_errors_not_crashes(server):
    """A bad request must not take the daemon down with it."""
    _srv, path, _ = server
    with pytest.raises(ControlError, match="deliberate failure"):
        request("boom", path=path)
    # Still serving afterwards.
    assert request("status", path=path)["command"] == "status"


def test_malformed_json_is_rejected_cleanly(server):
    _srv, path, _ = server
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(str(path))
    sock.sendall(b"{not json\n")
    reply = json.loads(sock.recv(65536).decode())
    sock.close()

    assert reply["ok"] is False
    assert "bad request" in reply["error"]
    assert request("status", path=path)["command"] == "status"


def test_missing_socket_is_a_clear_error(tmp_path):
    with pytest.raises(ControlError, match="not found"):
        request("status", path=tmp_path / "absent.sock")


def test_is_available_reflects_reality(server, tmp_path):
    _srv, path, _ = server
    assert is_available(path)
    assert not is_available(tmp_path / "absent.sock")


def test_socket_is_never_world_accessible(server):
    """Anything reachable here changes routing and firewall state."""
    _srv, path, _ = server
    mode = os.stat(path).st_mode
    assert not mode & stat.S_IROTH
    assert not mode & stat.S_IWOTH


def test_unknown_group_falls_back_to_root_only_not_world_writable(server):
    """The fixture asks for a group that does not exist. Failing closed matters:
    failing open would hand routing control to every local account."""
    _srv, path, _ = server
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600


def test_stale_socket_does_not_block_startup(tmp_path):
    """An unclean shutdown leaves the socket file behind; binding over it must
    still work or the daemon cannot restart."""
    path = tmp_path / "control.sock"
    path.write_text("stale")

    srv = ControlServer(lambda c, p, u: {"ok": c}, path=path, group="nope")
    ok, detail = srv.start()
    try:
        assert ok, detail
        assert request("status", path=path) == {"ok": "status"}
    finally:
        srv.stop()


def test_stop_removes_the_socket(tmp_path):
    path = tmp_path / "control.sock"
    srv = ControlServer(lambda c, p, u: {}, path=path, group="nope")
    srv.start()
    assert path.exists()
    srv.stop()
    assert not path.exists()


def test_restart_is_a_supported_command(tmp_path):
    """The tray offers "Restart daemon" and the daemon restarts itself, so no
    sudo is needed from the GUI. It only works because the unit uses
    Restart=always -- a clean exit under on-failure would stay dead."""
    seen = []

    def dispatch(command, params, uid):
        seen.append(command)
        return {"restarting": True}

    path = tmp_path / "control.sock"
    srv = ControlServer(dispatch, path=path, group="nope")
    srv.start()
    try:
        assert request("restart", path=path) == {"restarting": True}
        assert seen == ["restart"]
    finally:
        srv.stop()


# -- socket group resolution -------------------------------------------------
#
# The group was hardcoded to "sudo", so on RHEL, Fedora and Arch -- where the
# admin group is "wheel" -- the lookup failed and the socket silently became
# root-only, refusing every unprivileged client including the GUI.


def _only(monkeypatch, *existing):
    """Pretend only the named groups exist on this system."""
    import grp

    def fake(name):
        if name in existing:
            return type("Group", (), {"gr_gid": 999, "gr_name": name})()
        raise KeyError(name)

    monkeypatch.setattr(grp, "getgrnam", fake)


def _make_server(group=None, tmp_path=None):
    """Not named `server` -- that is the fixture above, and a plain function of
    the same name at module level silently replaces it."""
    return ControlServer(
        lambda c, p, u: {}, path=(tmp_path or Path("/tmp")) / "s", group=group
    )


def test_autodetect_finds_the_debian_admin_group(monkeypatch, tmp_path):
    _only(monkeypatch, "sudo", "adm")
    assert _make_server(tmp_path=tmp_path)._resolve_group() == "sudo"


def test_autodetect_finds_wheel_where_there_is_no_sudo(monkeypatch, tmp_path):
    """The case that was broken: RHEL, Fedora and Arch."""
    _only(monkeypatch, "wheel", "adm")
    assert _make_server(tmp_path=tmp_path)._resolve_group() == "wheel"


def test_a_dedicated_group_is_preferred_over_the_admin_group(monkeypatch, tmp_path):
    """Lets an admin grant socket access without granting sudo."""
    _only(monkeypatch, "ciscomvent", "sudo", "wheel")
    assert _make_server(tmp_path=tmp_path)._resolve_group() == "ciscomvent"


def test_configured_group_wins_over_detection(monkeypatch, tmp_path):
    _only(monkeypatch, "ciscomvent", "sudo", "devs")
    assert _make_server(group="devs", tmp_path=tmp_path)._resolve_group() == "devs"


def test_configured_group_that_is_missing_fails_closed(monkeypatch, tmp_path):
    """Substituting sudo for a missing "myteam" would silently widen access to
    everyone who can become root, which is not what was asked for."""
    _only(monkeypatch, "sudo", "wheel")
    assert _make_server(group="myteam", tmp_path=tmp_path)._resolve_group() is None


def test_no_usable_group_at_all_fails_closed(monkeypatch, tmp_path):
    _only(monkeypatch)  # nothing exists
    assert _make_server(tmp_path=tmp_path)._resolve_group() is None


def test_candidate_order_is_deliberate():
    from ciscomvent.control import CANDIDATE_GROUPS

    assert CANDIDATE_GROUPS.index("ciscomvent") < CANDIDATE_GROUPS.index("sudo")
    assert "wheel" in CANDIDATE_GROUPS


def test_adm_is_not_a_candidate_group():
    """It was, and it is the one group in the list whose members are *not*
    root-capable on Debian and Ubuntu -- a log-reading group holding routing
    and firewall control is real privilege gain, not a convenience."""
    from ciscomvent.control import CANDIDATE_GROUPS

    assert "adm" not in CANDIDATE_GROUPS


def test_a_host_with_only_adm_gets_a_root_only_socket(monkeypatch, tmp_path):
    _only(monkeypatch, "adm")
    assert _make_server(tmp_path=tmp_path)._resolve_group() is None


def test_socket_group_round_trips_through_config(tmp_path):
    from ciscomvent import config as config_mod
    from ciscomvent.config import Config

    path = tmp_path / "config.json"
    config_mod.save(Config(socket_group="devs"), path)
    assert config_mod.load(path).socket_group == "devs"
    # Absent or blank means auto-detect, not a group literally named "".
    config_mod.save(Config(), path)
    assert config_mod.load(path).socket_group is None


# -- caller identity ---------------------------------------------------------
#
# The protocol carries no identity and anything the client asserts about itself
# is forgeable, so the daemon takes the caller's uid from the kernel instead.


def test_dispatch_is_told_the_callers_real_uid(server):
    """SO_PEERCRED, not anything in the request body."""
    _srv, path, calls = server
    request("echo", path=path)
    assert calls[-1][2] == os.getuid()


@pytest.mark.skipif(os.getuid() == 0, reason="running as root makes this vacuous")
def test_the_uid_cannot_be_spoofed_by_the_request(server):
    """A client claiming uid 0 in its JSON must not be believed. `uid` is
    popped from the wire only as an ordinary parameter; the third argument
    still comes from the kernel."""
    _srv, path, calls = server
    data = request("echo", path=path, uid=0)

    assert data == {"uid": 0}          # echoed back as the plain param it is
    assert calls[-1][2] == os.getuid()  # but the authenticated uid is unchanged
    assert calls[-1][2] != 0


def test_peer_uid_reads_the_connecting_process(tmp_path):
    import socket as socket_mod

    from ciscomvent.control import peer_uid

    path = tmp_path / "peer.sock"
    listener = socket_mod.socket(socket_mod.AF_UNIX, socket_mod.SOCK_STREAM)
    listener.bind(str(path))
    listener.listen(1)

    client = socket_mod.socket(socket_mod.AF_UNIX, socket_mod.SOCK_STREAM)
    try:
        client.connect(str(path))
        conn, _ = listener.accept()
        try:
            assert peer_uid(conn) == os.getuid()
        finally:
            conn.close()
    finally:
        client.close()
        listener.close()


@pytest.mark.skipif(os.getuid() == 0, reason="needs an unprivileged caller")
def test_end_to_end_a_group_member_cannot_persist_config(tmp_path):
    """The whole chain, not just the decision: connect, have the kernel vouch
    for the peer, reach the real dispatch, come back as a refusal.

    The socket mode is what admits the caller at all, so reaching dispatch is
    already proof of group membership -- exactly the position the finding
    describes, where that used to be enough to rewrite /etc.
    """
    from ciscomvent.config import Config
    from ciscomvent.daemon import Daemon

    daemon = Daemon(config=Config(), dry_run=True)
    path = tmp_path / "control.sock"
    srv = ControlServer(daemon.dispatch, path=path, group="nope")
    srv.start()
    try:
        with pytest.raises(ControlError, match="needs root"):
            request("set-scope", path=path, scope="lan:wlp0s20f3", enabled=True)
        with pytest.raises(ControlError, match="needs root"):
            request("set-automation", path=path, automation="auto")
        with pytest.raises(ControlError, match="needs root"):
            request("approve", path=path, scope="docker:x", always=True)
    finally:
        srv.stop()


# -- request limits ----------------------------------------------------------
#
# The daemon is root and the reads were unbounded: no size cap, no server-side
# timeout, no ceiling on concurrent handler threads.


def test_an_oversized_request_is_refused_rather_than_buffered(server):
    """readline() had no limit, so a client streaming bytes with no newline in
    them grew the root daemon's memory until the OOM killer intervened."""
    from ciscomvent.control import MAX_REQUEST_BYTES

    _srv, path, _ = server
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect(str(path))
    sock.sendall(b"x" * (MAX_REQUEST_BYTES + 4096))
    sock.shutdown(socket.SHUT_WR)
    reply = json.loads(sock.recv(65536).decode())
    sock.close()

    assert reply["ok"] is False
    assert "too large" in reply["error"]
    assert request("status", path=path)["command"] == "status"


def test_a_request_at_the_limit_still_works(server):
    """The cap must reject the pathological case without clipping real ones."""
    _srv, path, _ = server
    assert request("echo", path=path, scope="docker:" + "n" * 1000)


def test_a_silent_client_is_dropped_instead_of_holding_a_thread(monkeypatch, tmp_path):
    """Only the client set a timeout. A peer that connected and then said
    nothing held a daemon thread for as long as it cared to."""
    from ciscomvent import control as control_mod

    monkeypatch.setattr(control_mod._Handler, "timeout", 0.2)

    path = tmp_path / "quiet.sock"
    srv = ControlServer(lambda c, p, u: {}, path=path, group="nope")
    srv.start()
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(str(path))
        # Never sends a newline. The server gives up and closes.
        assert sock.recv(4096) == b""
        sock.close()
    finally:
        srv.stop()


def test_connections_beyond_the_ceiling_are_dropped(monkeypatch, tmp_path):
    """ThreadingUnixStreamServer spawns a thread per connection and caps
    nothing, so a client opening sockets in a loop exhausted the daemon."""
    import time

    from ciscomvent import control as control_mod

    monkeypatch.setattr(control_mod, "MAX_CONNECTIONS", 1)
    monkeypatch.setattr(control_mod._Handler, "timeout", 3.0)

    path = tmp_path / "busy.sock"
    srv = ControlServer(lambda c, p, u: {}, path=path, group="nope")
    srv.start()
    held = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        held.connect(str(path))
        # Wait for the accept loop to actually take the only slot, rather than
        # racing it with a sleep.
        deadline = time.monotonic() + 5
        while srv._server._slots._value != 0 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert srv._server._slots._value == 0, "server never took the slot"

        second = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        second.settimeout(10)
        second.connect(str(path))
        assert second.recv(4096) == b""  # dropped, not queued forever
        second.close()
    finally:
        held.close()
        srv.stop()


# -- creation mode -----------------------------------------------------------


def test_the_socket_is_never_world_accessible_even_for_an_instant(monkeypatch, tmp_path):
    """bind() created the socket at 0777 & ~umask and _restrict only tightened
    it afterwards. systemd's default UMask=0022 kept the window at 0755, which
    is not writable by others and so was survivable -- but incidentally, not by
    design. Under umask 000 the socket was briefly 0777: world-writable, and
    connecting needs exactly write permission."""
    from ciscomvent import control as control_mod

    seen = {}
    real_server = control_mod._Server

    class Recording(real_server):
        def __init__(self, path, dispatch):
            super().__init__(path, dispatch)  # this call is the bind
            seen["at_bind"] = stat.S_IMODE(os.stat(path).st_mode)

    monkeypatch.setattr(control_mod, "_Server", Recording)

    before = os.umask(0o000)  # worst case
    try:
        srv = ControlServer(lambda c, p, u: {}, path=tmp_path / "s.sock", group="nope")
        srv.start()
        srv.stop()
    finally:
        os.umask(before)

    assert seen["at_bind"] == 0o600
    assert not seen["at_bind"] & stat.S_IWOTH


def test_the_process_umask_is_restored_after_binding(tmp_path):
    """It is tightened around the bind and is process-global."""
    before = os.umask(0o022)
    try:
        srv = ControlServer(lambda c, p, u: {}, path=tmp_path / "u.sock", group="nope")
        srv.start()
        srv.stop()
        assert os.umask(0o022) == 0o022
    finally:
        os.umask(before)
