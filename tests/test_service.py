# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit generation, especially the capability/readability interaction."""

from __future__ import annotations

import os
import pwd
import sys
from pathlib import Path

import pytest

import ciscomvent.service as service
from ciscomvent.service import (
    DESKTOP_TEMPLATE,
    ICON_PATH,
    INSTALL_ROOT,
    LAUNCHER_PATH,
    install_cli,
    install_service,
    interpreter_for_root,
    unit_text,
    unprivileged_writer,
)

PYENV = "/home/dev/.pyenv/versions/3.12.0/bin/python3"


def test_default_unit_reads_from_the_deployed_copy_not_a_home_directory():
    """Regression: the first unit set PYTHONPATH to the checkout under /home
    and dropped all capabilities except CAP_NET_ADMIN/CAP_NET_RAW. Root ignores
    file permissions via CAP_DAC_OVERRIDE, so dropping it made a 0750 home
    directory untraversable and the daemon crash-looped 45 times with
    ModuleNotFoundError while appearing correctly configured."""
    text = unit_text(python="/usr/bin/python3")
    load_path = [
        line for line in text.splitlines() if line.startswith("Environment=PYTHONPATH")
    ]
    assert load_path == [f"Environment=PYTHONPATH={INSTALL_ROOT}"]
    # Documentation= may still reference the checkout; it is a human pointer and
    # is never loaded. What matters is that nothing is *imported* from /home.
    assert "/home/" not in load_path[0]


def test_default_unit_keeps_the_tight_capability_set():
    """Exactly the three capabilities the work needs, and no DAC bypass.

    CAP_CHOWN is not decoration: without it os.chown on the control socket
    fails, the socket silently falls back to root-only, and every unprivileged
    client is locked out -- which pushes users toward running the GUI under
    sudo, defeating the privilege split entirely.
    """
    text = unit_text(python="/usr/bin/python3")
    # Inspect the directives, not the whole file: the surrounding comment
    # mentions CAP_DAC_OVERRIDE precisely to explain why it is *not* granted.
    granted = {
        cap
        for line in text.splitlines()
        if line.startswith(("CapabilityBoundingSet=", "AmbientCapabilities="))
        for cap in line.split("=", 1)[1].split()
    }
    assert granted == {"CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_CHOWN"}


def test_in_place_unit_grants_the_dac_bypass_it_needs():
    """If the package really is read from a home directory, the daemon needs the
    capability back -- otherwise it fails the same way."""
    text = unit_text(python="/usr/bin/python3", in_place=True)
    assert "CAP_DAC_READ_SEARCH" in text


def test_in_place_unit_points_at_the_checkout():
    text = unit_text(python="/usr/bin/python3", in_place=True)
    assert str(INSTALL_ROOT) not in text.split("[Install]")[0]


def test_in_place_unit_says_it_is_development_only():
    """The install output scrolls away; `systemctl cat` does not. The unit's
    own comment has to carry why the flag is not for a standing install, and
    the default unit, which has nothing to warn about, must not carry it."""
    comments = [
        line
        for line in unit_text(python="/usr/bin/python3", in_place=True).splitlines()
        if line.startswith("#")
    ]
    assert any("Development only" in line for line in comments)
    assert "--in-place" not in unit_text(python="/usr/bin/python3")


def test_in_place_install_output_names_the_checkout_and_who_can_write_it(
    monkeypatch, tmp_path
):
    """The finding: nothing said the root daemon was about to import from a
    directory the desktop user can write. Now the install output does, by
    path and by name, in the dry run as well as the real one."""
    checkout = tmp_path / "src"
    checkout.mkdir()
    monkeypatch.setattr(sys, "executable", "/usr/bin/python3")
    monkeypatch.setattr(service, "source_root", lambda: str(checkout))

    ok, detail = install_service(dry_run=True, in_place=True)

    assert ok
    assert "WARNING" in detail
    assert str(checkout) in detail
    if os.getuid() != 0:
        assert pwd.getpwuid(os.getuid()).pw_name in detail

    # The deployed path has nothing to warn about.
    ok, detail = install_service(dry_run=True)
    assert ok
    assert "WARNING" not in detail


def test_unprivileged_writer_reports_the_owner_of_a_user_owned_path(tmp_path):
    if os.getuid() == 0:
        pytest.skip("tmp_path is root's when the tests run as root")
    me = pwd.getpwuid(os.getuid()).pw_name
    assert unprivileged_writer(tmp_path) == me
    # A path below a user-owned directory inherits the answer even if it does
    # not exist yet: renaming the parent is enough to swap it out.
    assert unprivileged_writer(tmp_path / "missing" / "src") == me


def test_unprivileged_writer_finds_nobody_under_usr():
    assert unprivileged_writer(Path("/usr/bin")) is None


def test_the_system_interpreter_is_accepted_as_typed():
    """/usr/bin/python3 must stay unversioned in the unit, or the next
    interpreter upgrade orphans it."""
    assert interpreter_for_root("/usr/bin/python3") == ("/usr/bin/python3", "")


def test_an_interpreter_outside_usr_is_refused_by_name():
    python, reason = interpreter_for_root(PYENV)
    assert python is None
    assert PYENV in reason
    assert "/usr/bin/python3" in reason


def test_a_merged_usr_bin_is_spelled_as_usr_bin(monkeypatch, tmp_path):
    """On a merged-usr system /bin is a symlink to usr/bin, so /bin/python3
    is the system interpreter however it was typed. Refusing it would be a
    false positive; writing it as /usr/bin/python3 is the point."""
    usr = tmp_path / "usr"
    (usr / "bin").mkdir(parents=True)
    (usr / "bin" / "python3").touch()
    (tmp_path / "bin").symlink_to("usr/bin")
    monkeypatch.setattr(service, "SYSTEM_PREFIX", usr)

    python, reason = interpreter_for_root(str(tmp_path / "bin" / "python3"))

    assert reason == ""
    assert python == str(usr / "bin" / "python3")


def test_a_venv_link_to_the_system_interpreter_is_refused(tmp_path):
    """A venv's bin/python3 is a symlink to /usr/bin/python3. Judged by its
    target it is the system interpreter; judged by where it sits it is a file
    in a directory its owner controls, which is the one that matters."""
    venv_bin = tmp_path / "venv" / "bin"
    venv_bin.mkdir(parents=True)
    link = venv_bin / "python3"
    link.symlink_to("/usr/bin/python3")

    python, reason = interpreter_for_root(str(link))

    assert python is None
    assert str(link) in reason


def test_a_link_under_usr_into_a_home_directory_is_refused(monkeypatch, tmp_path):
    usr = tmp_path / "usr"
    (usr / "local" / "bin").mkdir(parents=True)
    home_python = tmp_path / "home" / "dev" / "python3"
    home_python.parent.mkdir(parents=True)
    home_python.touch()
    (usr / "local" / "bin" / "python3").symlink_to(home_python)
    monkeypatch.setattr(service, "SYSTEM_PREFIX", usr)

    python, _ = interpreter_for_root(str(usr / "local" / "bin" / "python3"))

    assert python is None


def test_install_refuses_a_pyenv_interpreter_before_deploying_anything(monkeypatch):
    """The refusal has to come first: a deploy followed by a refused wrapper
    leaves the launcher pointing at a wrapper that was never written."""
    monkeypatch.setattr(sys, "executable", PYENV)

    def untouched(*_args, **_kwargs):
        raise AssertionError("deploy_source ran")

    monkeypatch.setattr(service, "deploy_source", untouched)

    ok, detail = install_service()
    assert not ok
    assert PYENV in detail

    ok, detail = install_cli(dry_run=True)
    assert not ok
    assert PYENV in detail


def test_unit_declares_the_capabilities_the_work_actually_needs():
    text = unit_text(python="/usr/bin/python3")
    # CAP_NET_ADMIN for ip route/rule, CAP_NET_RAW for iptables.
    assert "CAP_NET_ADMIN" in text
    assert "CAP_NET_RAW" in text


def test_config_directory_stays_writable_under_protectsystem():
    """ProtectSystem=full makes /etc read-only, so our config path needs an
    explicit exemption or the daemon cannot persist approvals."""
    text = unit_text(python="/usr/bin/python3")
    assert "ProtectSystem=full" in text
    assert "ReadWritePaths=/etc/ciscomvent" in text


def test_unit_restarts_after_any_exit():
    text = unit_text(python="/usr/bin/python3")
    assert "Restart=always" in text


def test_unit_starts_after_docker():
    """Docker creates the bridges we claim."""
    assert "docker.service" in unit_text(python="/usr/bin/python3")


def test_the_desktop_entry_names_the_icon_the_install_writes():
    """The entry's Icon= and the path install_icon writes are declared apart
    from each other. If they drift the launcher silently falls back to a
    generic placeholder, which looks like a theme problem rather than a bug."""
    named = [l for l in DESKTOP_TEMPLATE.splitlines() if l.startswith("Icon=")]
    assert named == [f"Icon={ICON_PATH.stem}"]


def test_the_icon_goes_somewhere_the_theme_actually_searches():
    """Anything outside hicolor's scalable/apps is never looked up by name."""
    assert ICON_PATH.parent == Path("/usr/share/icons/hicolor/scalable/apps")
    assert ICON_PATH.suffix == ".svg"


def test_the_launcher_goes_somewhere_the_compositor_actually_searches():
    """KWin resolves a Wayland window's icon by locating <app_id>.desktop in
    the XDG applications directories. The autostart directory is not one of
    them, so the autostart copy cannot stand in for this entry."""
    assert LAUNCHER_PATH.parent == Path("/usr/share/applications")
    assert LAUNCHER_PATH.suffix == ".desktop"
