# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""What the GUI is allowed to hand pkexec.

The window escalates rather than offering a control that can only fail, which
means the desktop session assembles an argv that will run as root. pkexec
replaces the environment, so the argv is the whole exposure: which program, and
which arguments.
"""

from __future__ import annotations

import pytest

from ciscomvent.gui import escalate

# No Qt here on purpose -- these are the decisions, not the process.


@pytest.fixture
def binaries(tmp_path, monkeypatch):
    """A trusted pkexec and CLI, as a stock distro would have them."""
    pkexec = tmp_path / "pkexec"
    cli = tmp_path / "ciscomvent"
    for path in (pkexec, cli):
        path.write_text("#!/bin/sh\n")
        path.chmod(0o755)

    monkeypatch.setattr(escalate, "PKEXEC_CANDIDATES", (pkexec,))
    monkeypatch.setattr(escalate, "CLI_PATH", cli)
    # Ownership cannot be faked without root, so the trust test is the thing
    # under test everywhere it matters and stubbed to pass everywhere else.
    monkeypatch.setattr(escalate, "_trusted", lambda p: True)
    return pkexec, cli


def test_the_argv_is_absolute_and_unshelled(binaries):
    pkexec, cli = binaries
    argv = escalate.set_scope_argv("docker:my-net", enabled=True)

    assert argv == [str(pkexec), str(cli), "scope", "docker:my-net", "--enable"]
    assert escalate.set_scope_argv("docker:my-net", enabled=False)[-1] == "--disable"


def test_a_name_argparse_would_read_as_an_option_is_refused(binaries):
    """Nothing reaches a shell, so quoting is not the risk. A scope called
    `--help` -- or `-K`, which curl reads as "load this config file" -- being
    parsed as an option by the thing running as root is."""
    for bad in ("--enable", "-rf", "docker:x; id", "", "docker:" + "a" * 200):
        with pytest.raises(ValueError):
            escalate.set_scope_argv(bad, enabled=True)


def test_a_cli_that_is_not_root_owned_is_refused(tmp_path, monkeypatch):
    """The whole point of resolving an absolute installed path rather than
    sys.argv[0]: running from a checkout means the entry point is under a home
    directory, and this would run it as root."""
    cli = tmp_path / "ciscomvent"
    cli.write_text("#!/bin/sh\n")
    cli.chmod(0o755)
    monkeypatch.setattr(escalate, "CLI_PATH", cli)

    # Owned by the test user, not root.
    with pytest.raises(escalate.EscalationUnavailable, match="owned by root"):
        escalate.cli_binary()


class _Stat:
    def __init__(self, uid, mode):
        self.st_uid, self.st_mode = uid, mode


@pytest.mark.parametrize(
    "uid, mode, ok",
    [
        (0, 0o100755, True),   # root:root rwxr-xr-x -- the stock layout
        (0, 0o100775, False),  # chmod g+w /usr/local/bin, one command away
        (0, 0o100777, False),
        (1000, 0o100755, False),  # a checkout under a home directory
    ],
)
def test_only_a_root_owned_unwritable_binary_is_trusted(uid, mode, ok):
    """Ownership cannot be faked without root, so the rule is tested on stat
    results rather than on files the suite would have to own."""
    assert escalate.trusted_stat(_Stat(uid, mode)) is ok


def test_a_missing_cli_is_refused_with_the_install_command(tmp_path, monkeypatch):
    monkeypatch.setattr(escalate, "CLI_PATH", tmp_path / "absent")
    with pytest.raises(escalate.EscalationUnavailable, match="not installed"):
        escalate.cli_binary()


def test_pkexec_is_not_looked_up_on_the_caller_s_path(tmp_path, monkeypatch):
    """PATH belongs to the user this is escalating away from. A writable
    directory early in it would decide which binary gets to prompt for the
    admin password."""
    monkeypatch.setenv("PATH", str(tmp_path))
    planted = tmp_path / "pkexec"
    planted.write_text("#!/bin/sh\n")
    planted.chmod(0o777)

    monkeypatch.setattr(escalate, "PKEXEC_CANDIDATES", (tmp_path / "absent",))
    with pytest.raises(escalate.EscalationUnavailable, match="not installed"):
        escalate.pkexec_binary()


def test_availability_is_false_rather_than_raising(tmp_path, monkeypatch):
    """render() calls this on every poll; it decides whether to offer the
    control, so it must answer rather than throw into the paint path."""
    monkeypatch.setattr(escalate, "CLI_PATH", tmp_path / "absent")
    assert escalate.available() is False


def test_the_hint_names_a_command_that_exists(binaries):
    hint = escalate.sudo_hint("docker:my-net", enabled=False)
    assert "scope docker:my-net --disable" in hint


def test_pkexec_exit_codes_are_translated():
    assert "Authentication" in escalate.describe_failure(126)
    assert "could not run" in escalate.describe_failure(127)
    assert "status 3" in escalate.describe_failure(3)


def test_a_stale_deploy_is_named_rather_than_left_as_a_status_code():
    """The CLI under /usr/local/lib is deployed separately from a checkout, so
    an applet newer than its install is a normal state, not a corruption."""
    detail = escalate.describe_failure(2, "ciscomvent: error: argument command: "
                                          "invalid choice: 'scope'")
    assert "sudo ciscomvent install" in detail
    assert "invalid choice" in detail  # the real message is still there


def test_child_stderr_is_bounded():
    detail = escalate.describe_failure(1, "x" * 5000)
    assert len(detail) < escalate.MAX_STDERR + 200


# -- revert ------------------------------------------------------------------
#
# The window offers this as a two-entry menu rather than one button, so the
# layer reaches the argv from a click. It is the only caller-supplied value in
# a revert command line.


def test_revert_argv_removes_both_layers_by_default(binaries):
    pkexec, cli = binaries
    argv = escalate.revert_argv()

    assert argv == [str(pkexec), str(cli), "revert"]


def test_revert_argv_carries_the_firewall_layer(binaries):
    assert escalate.revert_argv(2)[-2:] == ["--layer", "2"]
    assert escalate.revert_argv(1)[-2:] == ["--layer", "1"]


@pytest.mark.parametrize("bad", [0, 3, -1, "2", "2; rm -rf /", None.__class__, [2]])
def test_a_layer_that_is_not_one_is_refused(binaries, bad):
    """The table is the whole validator: anything not in it has no flags to
    look up, so nothing unrecognised can be formatted into a root argv."""
    with pytest.raises(ValueError):
        escalate.revert_argv(bad)


def test_the_revert_hint_names_a_command_that_exists(binaries):
    assert escalate.revert_sudo_hint().endswith(" revert")
    assert escalate.revert_sudo_hint(2).endswith(" revert --layer 2")
