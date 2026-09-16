# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""systemd unit generation and installation.

The unit is generated rather than shipped as a static file because the package
is not pip-installed on this host, so the interpreter path and PYTHONPATH have
to be baked in at install time.

By default the package is *deployed* to INSTALL_ROOT rather than read from the
checkout. See that constant for why -- it is a capability problem, not a
convenience.

Both baked-in paths are code the daemon runs as root, so what may be baked in
is vetted: SYSTEM_PREFIX for the interpreter, in_place_warning for the checkout.
"""

from __future__ import annotations

import os
import pwd
import shutil
import subprocess
import sys
from importlib import resources
from pathlib import Path

SERVICE_NAME = "ciscomvent.service"
SERVICE_PATH = Path("/etc/systemd/system") / SERVICE_NAME

INSTALL_ROOT = Path("/usr/local/lib/ciscomvent")
"""Where the daemon's copy of the package lives.

Running from a checkout under /home does not work with a tight capability set.
Root bypasses file permissions via CAP_DAC_OVERRIDE, and dropping that (as the
unit does, keeping only CAP_NET_ADMIN and CAP_NET_RAW) means a 0750 home
directory becomes genuinely untraversable for the service. Deploying here also
removes the daemon's dependency on /home being mounted at boot, and stops a
moved or deleted checkout from breaking it.
"""

UNIT_TEMPLATE = """\
[Unit]
Description=ciscomvent — restore host-to-container reachability under VPN
{documentation}# Docker creates the bridges we claim; starting after it avoids a pointless
# first reconcile against an empty topology.
After=network.target docker.service
Wants=network.target

[Service]
Type=simple
ExecStart={python} -m ciscomvent.daemon
Environment=PYTHONPATH={pythonpath}
Environment=PYTHONUNBUFFERED=1

# Route and rule changes need CAP_NET_ADMIN; iptables needs CAP_NET_RAW;
# CAP_CHOWN hands the control socket to its group so unprivileged clients can
# reach it. Everything else is dropped -- including CAP_DAC_OVERRIDE, which is
# what lets root ignore file permissions. That is why the package is deployed
# out of the user's home directory rather than read from a checkout.
{capabilities}NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
# /etc read-only except our own config.
ProtectSystem=full
ReadWritePaths=/etc/ciscomvent

# always, not on-failure: the control socket can ask the daemon to exit for a
# restart, and that is a clean exit which on-failure would not bring back.
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""


def source_root() -> str:
    """The directory that must be on PYTHONPATH for `-m ciscomvent.daemon`."""
    return str(Path(__file__).resolve().parent.parent)


def docs_path() -> str | None:
    """The README shipped with this distribution, if one is alongside us.

    Searched upward rather than assumed. The deployed copy under INSTALL_ROOT
    holds only the package, so there may be no README to point at -- and a
    Documentation= line naming a file that does not exist is worse than no
    line at all, which is what the previous design-document path became.
    """
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "README.md"
        if candidate.is_file():
            return str(candidate)
    return None


def package_dir() -> Path:
    return Path(__file__).resolve().parent


def deploy_source(dry_run: bool = False) -> tuple[bool, str]:
    """Copy the package to INSTALL_ROOT so the daemon does not read from /home.

    Means the running daemon is a snapshot: re-run install after changing the
    code, or use --in-place while iterating.
    """
    source = package_dir()
    target = INSTALL_ROOT / "ciscomvent"

    # Running via the installed wrapper means source *is* target. Without this
    # guard the copy deleted its own source and left INSTALL_ROOT empty,
    # breaking both the CLI and the daemon.
    if source == target:
        if dry_run:
            return True, f"already running from {target}; nothing to copy"
        return True, f"already deployed at {target} (ran from it; not copied)"

    if dry_run:
        return True, f"would copy {source} -> {target}"

    # Stage beside the target and swap, so a failure part-way through cannot
    # leave INSTALL_ROOT without a usable package.
    staging = INSTALL_ROOT / "ciscomvent.new"
    try:
        INSTALL_ROOT.mkdir(parents=True, exist_ok=True)
        if staging.exists():
            shutil.rmtree(staging)
        shutil.copytree(
            source, staging, ignore=shutil.ignore_patterns("__pycache__", "*.pyc")
        )
        # World-readable so the tight capability set can reach it.
        for path in [INSTALL_ROOT, staging, *staging.rglob("*")]:
            path.chmod(0o755 if path.is_dir() else 0o644)

        if target.exists():
            shutil.rmtree(target)
        os.rename(staging, target)
    except OSError as exc:
        shutil.rmtree(staging, ignore_errors=True)
        return False, str(exc)
    return True, f"deployed to {target}"


SYSTEM_PREFIX = Path("/usr")
"""Where an interpreter must live before anything that runs as root names it.

The unit's ExecStart= and the wrapper's exec line both take sys.executable
from whichever python ran the install. A pyenv, conda or venv interpreter
lives under the installing user's home, so baking it in hands that user a
root daemon, and a root `sudo ciscomvent`, running a binary they can replace.
Under /usr means root-owned on a stock distro. /usr/local is inside the
prefix and passes deliberately: it is root-owned as shipped, and a /usr/local
that someone has made writable is a PATH-hijacking problem of its own, wider
than an interpreter path and not something a prefix check can catch.
"""


def interpreter_for_root(python: str | None = None) -> tuple[str | None, str]:
    """The interpreter the unit and wrapper may name, or why they may not.

    Vets `python` (default sys.executable) against SYSTEM_PREFIX and returns
    (path, "") or (None, reason). The directory is resolved but the file is
    not: /usr/bin/python3 stays unversioned so an interpreter upgrade does not
    orphan the unit, a merged-usr /bin/python3 is spelled /usr/bin/python3
    rather than refused for how the installer typed it, and a venv's
    bin/python3, a symlink to the system interpreter in a directory its owner
    controls, is judged by where the link sits rather than where it points.
    The target is checked as well, so a link under /usr into a home directory
    is refused too.
    """
    python = python or sys.executable
    path = Path(python)
    if not path.is_absolute():
        return None, f"{python!r} is not an absolute path to an interpreter"
    spelled = path.parent.resolve() / path.name
    if all(p.is_relative_to(SYSTEM_PREFIX) for p in (spelled, spelled.resolve())):
        return str(spelled), ""
    return None, (
        f"{python} is outside {SYSTEM_PREFIX}, so a user may be able to replace "
        "it (a pyenv, conda or venv interpreter, most likely). The unit and the "
        "`ciscomvent` wrapper would run it as root. Re-run this install with the "
        "system interpreter, e.g. /usr/bin/python3."
    )


CLI_PATH = Path("/usr/local/bin/ciscomvent")

CLI_TEMPLATE = """\
#!/bin/sh
# Generated by `ciscomvent install`. Do not edit.
#
# Runs the deployed copy in {pythonpath}, not a checkout, so the CLI and the
# daemon are always the same code. Re-run the install to update both.
PYTHONPATH="{pythonpath}${{PYTHONPATH:+:$PYTHONPATH}}"
export PYTHONPATH
exec "{python}" -m ciscomvent "$@"
"""


def cli_text(python: str, pythonpath: str | None = None) -> str:
    """The wrapper for `python`, which the caller has vetted (interpreter_for_root)."""
    return CLI_TEMPLATE.format(
        python=python,
        pythonpath=pythonpath or str(INSTALL_ROOT),
    )


def install_cli(dry_run: bool = False) -> tuple[bool, str]:
    """Put a `ciscomvent` command on PATH.

    pyproject declares a console script, but that only materialises on a pip
    install, and this host has no venv and an externally-managed Python. A
    generated wrapper avoids touching the system Python entirely.
    """
    python, refusal = interpreter_for_root()
    if refusal:
        return False, refusal
    if dry_run:
        return True, f"would write {CLI_PATH}"
    try:
        CLI_PATH.write_text(cli_text(python))
        CLI_PATH.chmod(0o755)
    except OSError as exc:
        return False, str(exc)
    return True, f"wrote {CLI_PATH}"


def unprivileged_writer(path: Path) -> str | None:
    """Who other than root can change what `path` names, or None if nobody.

    Walks up to / because a writable ancestor is enough: rename the directory,
    put another in its place, and every path below it names something else.
    Reports the owner of the first component root does not own, or the
    component itself when root owns it but left it group- or world-writable.
    """
    for component in (path, *path.parents):
        try:
            st = component.stat()
        except OSError:
            continue
        if st.st_uid != 0:
            try:
                return pwd.getpwuid(st.st_uid).pw_name
            except KeyError:
                return f"uid {st.st_uid}"
        if st.st_mode & 0o022:
            return f"anyone (through {component})"
    return None


def in_place_warning(source: str) -> str:
    """What --in-place costs, for the install output.

    A warning rather than a refusal: the flag exists for iterating from a
    checkout, and a checkout is writable by whoever is iterating, so refusing
    a writable one would refuse every real use.
    """
    writer = unprivileged_writer(Path(source))
    which = (
        f"which {writer} can write"
        if writer
        else "a checkout rather than the deployed copy"
    )
    return (
        "WARNING: --in-place makes the root daemon import its code from\n"
        f"  {source},\n"
        f"  {which}. Whoever can write there is root on the next\n"
        "  daemon start, and `ciscomvent restart` is one socket command away.\n"
        "  Development only; reinstall without --in-place before leaving this\n"
        "  unit in place."
    )


def unit_text(
    python: str,
    pythonpath: str | None = None,
    in_place: bool = False,
) -> str:
    """The unit for `python`, which the caller has vetted (interpreter_for_root)."""
    if pythonpath is None:
        pythonpath = source_root() if in_place else str(INSTALL_ROOT)

    if in_place:
        # Reading a 0750 home directory needs the DAC bypass that dropping
        # capabilities takes away. The comment says what that costs, so that
        # `systemctl cat` shows it long after the install output is gone.
        extra = (
            "# --in-place: the package is read from a checkout, which a root\n"
            "# process cannot reach under a 0750 home directory without the DAC\n"
            "# bypass. The checkout is writable by its owner, so whatever runs as\n"
            "# them can put code in front of this root daemon. Development only;\n"
            "# reinstall without --in-place to close it.\n"
            "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_CHOWN "
            "CAP_DAC_READ_SEARCH\n"
            "AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_CHOWN "
            "CAP_DAC_READ_SEARCH\n"
        )
    else:
        extra = (
            "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_CHOWN\n"
            "AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_CHOWN\n"
        )

    readme = docs_path()
    return UNIT_TEMPLATE.format(
        python=python,
        pythonpath=pythonpath,
        documentation=f"Documentation=file://{readme}\n" if readme else "",
        capabilities=extra,
    )


def install_service(
    dry_run: bool = False, enable: bool = True, in_place: bool = False
) -> tuple[bool, str]:
    # Vetted before anything is written, so a refusal deploys nothing rather
    # than deploying and then failing at the wrapper.
    python, refusal = interpreter_for_root()
    if refusal:
        return False, refusal

    text = unit_text(python, in_place=in_place)
    warning = in_place_warning(source_root()) if in_place else ""
    if dry_run:
        preview = warning if in_place else deploy_source(dry_run=True)[1]
        return True, f"{preview}\n\nwould write {SERVICE_PATH}:\n\n{text}"

    notes = []
    if not in_place:
        ok, detail = deploy_source()
        if not ok:
            return False, detail
        notes.append(detail)

    ok, detail = install_cli()
    if not ok:
        return False, detail
    notes.append(detail)

    try:
        SERVICE_PATH.write_text(text)
        Path("/etc/ciscomvent").mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return False, str(exc)

    steps = [["systemctl", "daemon-reload"]]
    if enable:
        steps.append(["systemctl", "enable", SERVICE_NAME])

    for argv in steps:
        proc = subprocess.run(argv, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            return False, f"{' '.join(argv)}: {proc.stderr.strip()}"

    prefix = "".join(f"{n}\n" for n in notes)
    source = f"{source_root()} (in-place)" if in_place else str(INSTALL_ROOT)
    summary = (
        f"{prefix}wrote {SERVICE_PATH}\n"
        f"  enabled: {enable}\n"
        f"  source:  {source}\n"
        f"  start with:  systemctl restart {SERVICE_NAME}\n"
        f"  follow with: journalctl -fu {SERVICE_NAME}"
    )
    # Last, so it is what the eye lands on.
    return True, (f"{summary}\n\n{warning}" if warning else summary)


def uninstall_service(dry_run: bool = False) -> tuple[bool, str]:
    if dry_run:
        return True, f"would stop, disable, and remove {SERVICE_PATH}"

    for argv in (
        ["systemctl", "stop", SERVICE_NAME],
        ["systemctl", "disable", SERVICE_NAME],
    ):
        subprocess.run(argv, capture_output=True, text=True, check=False)

    try:
        os.remove(SERVICE_PATH)
    except FileNotFoundError:
        return True, "not installed"
    except OSError as exc:
        return False, str(exc)

    subprocess.run(
        ["systemctl", "daemon-reload"], capture_output=True, text=True, check=False
    )
    return True, f"removed {SERVICE_PATH}"


def service_status() -> dict:
    """Whether the unit is installed, enabled, and running."""
    def ask(argv: list[str]) -> str:
        proc = subprocess.run(argv, capture_output=True, text=True, check=False)
        return proc.stdout.strip()

    return {
        "installed": SERVICE_PATH.exists(),
        "enabled": ask(["systemctl", "is-enabled", SERVICE_NAME]) or "unknown",
        "active": ask(["systemctl", "is-active", SERVICE_NAME]) or "unknown",
    }


LAUNCHER_PATH = Path("/usr/share/applications/ciscomvent.desktop")
"""The application menu entry.

Also where a Wayland compositor gets the applet's window icon. A client cannot
set one there the way it can under X11: KWin takes the window's app_id, finds
the desktop entry of that name in the XDG applications directories, and draws
its Icon=. The applet names this file's stem as its app_id (gui/app.py,
identify), so without this entry the title bar and taskbar show the generic
Wayland placeholder however the icon is set from inside the process. The
autostart copy cannot stand in for it: the autostart directory is not one of
the directories searched.
"""

AUTOSTART_PATH = Path("/etc/xdg/autostart/ciscomvent.desktop")

# One entry serves the menu and autostart; each place ignores the keys meant
# for the other. StartupNotify is off because a launch shows a tray icon and
# no window, so the launcher's busy cursor would otherwise spin until it timed
# out.
DESKTOP_TEMPLATE = """\
[Desktop Entry]
Type=Application
Name=ciscomvent
Comment=Restore host-to-container reachability under VPN
Exec={exec_path} gui
Icon=ciscomvent
Terminal=false
StartupNotify=false
Categories=Network;System;
X-GNOME-Autostart-enabled=true
"""

ICON_PATH = Path("/usr/share/icons/hicolor/scalable/apps/ciscomvent.svg")
"""Where the desktop entry's `Icon=ciscomvent` is looked up.

The applet does not read this -- it renders the same SVG straight out of the
package. This copy is for everything outside the process: the launcher, and any
Wayland compositor, which have no window to read an icon off.
"""


def install_icon(dry_run: bool = False) -> tuple[bool, str]:
    """Put the mark where the icon theme can find it."""
    try:
        data = (
            resources.files("ciscomvent.gui")
            .joinpath("icons/ciscomvent.svg")
            .read_bytes()
        )
    except OSError as exc:
        return False, f"icon missing from the package: {exc}"

    if dry_run:
        return True, f"would write {ICON_PATH}"
    try:
        ICON_PATH.parent.mkdir(parents=True, exist_ok=True)
        ICON_PATH.write_bytes(data)
        ICON_PATH.chmod(0o644)
    except OSError as exc:
        return False, str(exc)
    return True, f"wrote {ICON_PATH}"


def _write_entry(path: Path, dry_run: bool) -> tuple[bool, str]:
    text = DESKTOP_TEMPLATE.format(exec_path=CLI_PATH)
    if dry_run:
        return True, f"would write {path}"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        path.chmod(0o644)
    except OSError as exc:
        return False, str(exc)
    return True, f"wrote {path}"


def install_launcher(dry_run: bool = False) -> tuple[bool, str]:
    """Register the applet with the application menu, and through it the icon
    a Wayland compositor draws on its window. See LAUNCHER_PATH."""
    return _write_entry(LAUNCHER_PATH, dry_run)


def install_autostart(dry_run: bool = False) -> tuple[bool, str]:
    """Start the tray applet at login, for every user on the machine.

    Opt-in rather than part of the normal install: the applet is per-session
    and system-wide autostart affects accounts other than the one running this.
    """
    # The entry names Icon=ciscomvent, and under Wayland the applet's window
    # icon resolves through the menu entry, so writing autostart alone would
    # leave both blank for anyone who enabled it without having run
    # `ciscomvent install`.
    details = []
    for step in (install_icon, install_launcher):
        ok, detail = step(dry_run=dry_run)
        if not ok:
            return False, detail
        details.append(detail)

    ok, detail = _write_entry(AUTOSTART_PATH, dry_run)
    if not ok:
        return False, detail
    return True, f"{detail} ({'; '.join(details)})"


def remove_autostart() -> tuple[bool, str]:
    try:
        os.remove(AUTOSTART_PATH)
    except FileNotFoundError:
        return True, "autostart not installed"
    except OSError as exc:
        return False, str(exc)
    return True, f"removed {AUTOSTART_PATH}"
