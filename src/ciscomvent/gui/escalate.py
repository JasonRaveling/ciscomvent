# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Building an argv the desktop session may run as root.

The daemon enforces its root tier on the request path, so the GUI cannot
perform a persisting command however it asks. Rather than offer a control that
can only fail, the window escalates: pkexec authenticates the user and re-runs
the CLI as root, which then speaks the same socket command with uid 0.

Everything here is about what crosses that boundary. pkexec replaces the
environment with a minimal one, so the environment is not the exposure; the
argv is. Two things therefore have to be true before a QProcess is started, and
both are decided here rather than at the call site:

- the program is a **fixed absolute path** to a root-owned, non-group-writable
  file. Resolving `ciscomvent` through PATH would run whatever the user's own
  `~/.local/bin` holds -- as root, on their behalf, which is the privilege
  escalation this is supposed to be a controlled instance of.
- every argument is either a literal this module wrote or a value already
  through ``checked_scope``. Nothing reaches a shell (QProcess takes program and
  arguments separately), so quoting is not the risk; a name starting with `-`
  being read by argparse as an option is.

Pure and Qt-free so the decisions can be tested directly.
"""

from __future__ import annotations

from pathlib import Path

from ..model import checked_scope
from ..service import CLI_PATH

PKEXEC_CANDIDATES = (
    Path("/usr/bin/pkexec"),
    Path("/bin/pkexec"),
    Path("/usr/local/bin/pkexec"),
)
"""Absolute, in the order a distro is likely to have them.

Not ``shutil.which``: PATH is the caller's, and the caller is exactly who this
is escalating away from. A user-writable directory earlier in PATH would decide
which binary gets to prompt for the admin password.
"""


class EscalationUnavailable(Exception):
    """No safe way to run as root. Carries what to tell the user instead."""


def trusted_stat(st) -> bool:
    """Root-owned and writable by nobody else.

    Group-writable counts as untrusted: `chmod g+w /usr/local/bin` is one
    command, and /usr/local is where the CLI this authenticates for lives.
    Split from the filesystem lookup so the rule can be tested without a
    root-owned fixture, which a test suite cannot create.
    """
    return st.st_uid == 0 and not st.st_mode & 0o022


def _trusted(path: Path) -> bool:
    try:
        return trusted_stat(path.stat())
    except OSError:
        return False


def pkexec_binary() -> Path:
    """The pkexec to use, or raise EscalationUnavailable."""
    for candidate in PKEXEC_CANDIDATES:
        if candidate.exists():
            if not _trusted(candidate):
                raise EscalationUnavailable(
                    f"{candidate} is not owned by root, or is writable by others. "
                    "Refusing to hand it an authentication prompt."
                )
            return candidate
    raise EscalationUnavailable(
        "pkexec is not installed, so this cannot ask for authentication."
    )


def cli_binary() -> Path:
    """The installed CLI, or raise EscalationUnavailable.

    Deliberately the installed copy rather than ``sys.argv[0]``: running from a
    checkout puts the entry point under a home directory, and pkexec would run
    whatever is written there as root.
    """
    if not CLI_PATH.exists():
        raise EscalationUnavailable(
            f"{CLI_PATH} is not installed, so there is nothing safe to run as "
            "root. Install it with `sudo ciscomvent install`."
        )
    if not _trusted(CLI_PATH):
        raise EscalationUnavailable(
            f"{CLI_PATH} is not owned by root, or is writable by others. "
            "Refusing to run it as root."
        )
    return CLI_PATH


def set_scope_argv(scope: str, enabled: bool) -> list[str]:
    """Full argv for enabling or disabling one scope as root.

    Raises ValueError for a name that is not a scope name, and
    EscalationUnavailable when there is no trusted pair of binaries.
    """
    scope = checked_scope(scope)
    return [
        str(pkexec_binary()),
        str(cli_binary()),
        "scope",
        scope,
        "--enable" if enabled else "--disable",
    ]


REVERT_LAYER_FLAGS: dict[int | None, tuple[str, ...]] = {
    None: (),
    1: ("--layer", "1"),
    2: ("--layer", "2"),
}
"""The ``--layer`` arguments by layer, with None meaning both.

A lookup rather than formatting the caller's value into the argv. The rule this
module exists to keep is that every argument is a literal it wrote itself, and
a table keeps that true by construction instead of by a validator that has to
be read closely to be believed.
"""


def revert_argv(layer: int | None = None) -> list[str]:
    """Full argv for removing what we own, as root.

    ``layer`` of None removes routing and firewall rules both, 1 the routing
    only and 2 the accepts only, matching the CLI's own ``--layer``.

    Raises ValueError for anything else, and EscalationUnavailable when there
    is no trusted pair of binaries.
    """
    try:
        flags = REVERT_LAYER_FLAGS[layer]
    except (KeyError, TypeError):
        raise ValueError(f"not a revert layer: {layer!r}") from None
    return [str(pkexec_binary()), str(cli_binary()), "revert", *flags]


def available() -> bool:
    """Whether escalation could run at all, for deciding what to offer."""
    try:
        pkexec_binary()
        cli_binary()
    except EscalationUnavailable:
        return False
    return True


MAX_STDERR = 500
"""Enough for an argparse usage line or a daemon refusal, not a core dump."""


def describe_failure(exit_code: int, stderr: str = "") -> str:
    """pkexec's exit codes, which are otherwise opaque in a dialog.

    126 and 127 are pkexec's own and never reach the CLI. Anything else came
    from the CLI itself, where its stderr says far more than the number does --
    most usefully when /usr/local/lib holds an older deploy than the GUI is
    running from, which argparse reports as an invalid choice.
    """
    if exit_code == 126:
        return "Authentication failed, or the request was dismissed."
    if exit_code == 127:
        return f"pkexec could not run {CLI_PATH}."

    detail = stderr.strip()[:MAX_STDERR]
    head = f"{CLI_PATH} exited with status {exit_code}."
    if not detail:
        return head
    if "invalid choice" in detail:
        head += (
            "\n\nThe installed copy looks older than this applet. "
            "Update both with `sudo ciscomvent install`."
        )
    return f"{head}\n\n{detail}"


def sudo_hint(scope: str, enabled: bool) -> str:
    """The equivalent by hand, for when escalation is not available."""
    flag = "--enable" if enabled else "--disable"
    return f"sudo {CLI_PATH} scope {scope} {flag}"


def revert_sudo_hint(layer: int | None = None) -> str:
    """The equivalent by hand, for when escalation is not available."""
    return " ".join(("sudo", str(CLI_PATH), "revert", *REVERT_LAYER_FLAGS[layer]))
