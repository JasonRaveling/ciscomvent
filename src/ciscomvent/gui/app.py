# ciscomvent — restores host-to-container reachability under a VPN tunnel-all policy
# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""PyQt5 tray applet and window.

Talks to the daemon over the control socket and never touches the kernel
itself. Desktop notifications are raised here, in the user's session, rather
than by the root daemon reaching into a session bus it has no business in.
"""

from __future__ import annotations

import os
import signal
import sys
from importlib import resources

from PyQt5.QtCore import (
    QBuffer,
    QByteArray,
    QIODevice,
    QProcess,
    QRectF,
    QSize,
    Qt,
    QTimer,
)
from PyQt5.QtGui import (
    QColor,
    QFont,
    QIcon,
    QImage,
    QImageReader,
    QPainter,
    QPen,
    QPixmap,
)
from PyQt5.QtWidgets import (
    QAction,
    QApplication,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSystemTrayIcon,
    QTabWidget,
    QToolButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .. import (
    CONDITIONS,
    COPYRIGHT,
    LICENSE_SHORT,
    COPY_NOTICE,
    LICENSE_URL,
    WARRANTY,
    __version__,
    control,
)
from ..apply import LAYER_FIREWALL, RULE_PRIORITY
from ..service import LAUNCHER_PATH
from . import escalate
from .state import COLOURS, Health, Summary, summarize, tooltip

ROW_COLOURS = {
    "ok": "#d6d6d6",
    "bad": "#c0392b",
    "off": "#8a8a8a",
    "idle": "#8a8a8a",
}

POLL_MS = 5000
"""How often to refresh. The daemon reacts to netlink in ~1.5s, so this is only
about how quickly the display catches up, not how quickly the fix applies."""

ICON_PX = 64
"""The size the mark's proportions are written in; every other size scales
from it."""

ICON_SIZES = (16, 22, 24, 32, 48, 64, 128)
"""Sizes a panel or tray host is likely to ask for. Handing QIcon all of them
means the badge gets drawn at the target size instead of being downsampled
from a single 64px bitmap, which smeared it at panel sizes."""

ICON_FILE = "icons/ciscomvent.svg"


def _html(text: str) -> str:
    """Escape for rich text.

    The copyright line carries an email in angle brackets, which a rich-text
    widget would otherwise swallow as an unknown tag -- taking the contact
    address the GPL asks us to include with it.
    """
    escaped = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    # The GPL's wording uses two spaces after a full stop; HTML collapses runs.
    return escaped.replace("  ", "&nbsp;&nbsp;")


def _mark() -> QByteArray | None:
    """The shipped SVG, or None if nothing can render it.

    Rendered through Qt's SVG image plugin rather than QtSvg's QSvgRenderer.
    The renderer is a Python binding of its own, python3-pyqt5.qtsvg on Debian,
    which python3-pyqt5 does not pull in, so every install that followed the
    README got the fallback circle. The plugin ships in the C++ library that
    binding needs anyway (libqt5svg5, which Qt's GUI library recommends), so
    this path works everywhere the renderer did and on plain installs besides.
    make_icon still falls back to the drawn circle when even the plugin is
    missing, so the tray is never left empty.

    Read through importlib.resources rather than off __file__ so it resolves
    the same whether the applet runs from a checkout or from the copy `install`
    deploys under INSTALL_ROOT.
    """
    if b"svg" not in QImageReader.supportedImageFormats():
        return None
    try:
        data = resources.files("ciscomvent.gui").joinpath(ICON_FILE).read_bytes()
    except OSError:
        return None
    return QByteArray(data)


def _badge_rect(px: int) -> QRectF:
    """Where the attention badge sits. Shared with the tests, so the geometry
    is stated once rather than restated by whatever checks it rendered."""
    scale = px / ICON_PX
    size = 22 * scale
    return QRectF(px - size - 4 * scale, 4 * scale, size, size)


def _draw_badge(painter: QPainter, colour: str, px: int) -> None:
    """A dot for "needs you", so the state is legible without relying on
    colour alone.

    Filled in the health colour and ringed in white, where the drawn circle
    used a bare white dot. The mark is an open shape, so the corner the badge
    sits in is part transparent -- a white dot disappeared against a light
    panel at every size, and one of the two tones now always contrasts.
    """
    ring = max(1.0, 3 * px / ICON_PX)

    pen = QPen(QColor("#ffffff"))
    pen.setWidthF(ring)
    painter.setPen(pen)
    painter.setBrush(QColor(colour))

    # Inset by half the stroke, which straddles the path either side.
    rect = _badge_rect(px)
    painter.drawEllipse(rect.adjusted(ring / 2, ring / 2, -ring / 2, -ring / 2))


def _silhouette(mark: QByteArray, px: int) -> QImage | None:
    """The mark rasterised at one size by the SVG image plugin.

    A scaled size on the reader has the plugin draw the vector at that size.
    Without it the plugin hands back the SVG's own canvas, several hundred
    pixels across, and a panel icon would show one corner of the mark.
    """
    buffer = QBuffer()
    buffer.setData(mark)
    buffer.open(QIODevice.ReadOnly)
    reader = QImageReader(buffer, b"svg")
    reader.setScaledSize(QSize(px, px))
    image = reader.read()
    return None if image.isNull() else image


def _draw(colour: str, badge: bool, px: int, mark: QByteArray | None) -> QPixmap:
    """Render the mark at one size, tinted to the health colour.

    Paints into a QImage rather than straight onto a QPixmap: the tint needs a
    composition mode, and only the raster engine guarantees those.
    """
    image = QImage(px, px, QImage.Format_ARGB32_Premultiplied)
    image.fill(Qt.transparent)

    painter = QPainter(image)
    painter.setRenderHint(QPainter.Antialiasing)

    silhouette = _silhouette(mark, px) if mark is not None else None
    if silhouette is not None:
        painter.drawImage(0, 0, silhouette)
        # The mark carries no fill of its own, so flooding the health colour
        # through its alpha is what makes the icon state-bearing.
        painter.setCompositionMode(QPainter.CompositionMode_SourceIn)
        painter.fillRect(image.rect(), QColor(colour))
        painter.setCompositionMode(QPainter.CompositionMode_SourceOver)
    else:
        inset = 6 * px / ICON_PX
        painter.setBrush(QColor(colour))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(QRectF(inset, inset, px - 2 * inset, px - 2 * inset))

    if badge:
        _draw_badge(painter, colour, px)
    painter.end()

    return QPixmap.fromImage(image)


def make_icon(colour: str, badge: bool = False) -> QIcon:
    """Build the icon at every size a panel or taskbar might ask for.

    The colour still comes straight from the health mapping -- the shipped
    mark is a bare silhouette, and tinting it is what carries state.
    """
    mark = _mark()
    icon = QIcon()
    for px in ICON_SIZES:
        icon.addPixmap(_draw(colour, badge, px, mark))
    return icon


DISMISS_TIP = (
    "Stops this scope asking until the next VPN session.\n"
    "It stays unclaimed, so containers on its network stay unreachable."
)

AUTOMATION_TIP = (
    "On: claim scopes as soon as the VPN captures them.\n"
    "Off: wait for approval each VPN session before changing anything."
)

# The daemon refuses both of these below uid 0 -- they are written to
# /etc/ciscomvent/config.json and outlive the VPN session. Saying so in place
# beats offering the control and reporting a failure after the click.
AUTOMATION_NEEDS_ROOT = (
    "Changing the automation mode is written to /etc/ciscomvent/config.json "
    "and needs root:\n"
    "    sudo ciscomvent config --automation auto"
)

TOGGLE_WILL_PROMPT = (
    "Enabling or disabling a scope is written to /etc/ciscomvent/config.json, "
    "so this asks for authentication first."
)

TOGGLE_NEEDS_ROOT = (
    "Enabling or disabling a scope is written to /etc/ciscomvent/config.json "
    "and needs root, and pkexec is not available to ask for it:\n"
    "    sudo ciscomvent scope <scope> --enable\n"
    "Approving for this VPN session works without either."
)

REVERT_TIP = (
    "Removes what ciscomvent installed, asking for authentication first.\n"
    "The daemon reinstalls whatever it still wants within a minute, so this\n"
    "is for inspecting or handing back the host, not for turning the fix off:\n"
    "disable the scopes or stop the service for that."
)

REVERT_NEEDS_ROOT = (
    "Removing routes and firewall rules needs root, and pkexec is not "
    "available to ask for it:\n"
    "    sudo ciscomvent revert"
)


class DaemonLink:
    """Thin wrapper over the control socket that never raises at the UI."""

    def __init__(self) -> None:
        self.error: str | None = None

    def snapshot(self) -> dict | None:
        try:
            data = control.request("status")
            self.error = None
            return data
        except control.ControlError as exc:
            self.error = str(exc)
            return None

    def send(self, command: str, **params) -> tuple[bool, str, dict]:
        try:
            data = control.request(command, **params)
            return True, "ok", data
        except control.ControlError as exc:
            return False, str(exc), {}


class Window(QMainWindow):
    """Scope management plus a live view of what we own."""

    def __init__(self, link: DaemonLink) -> None:
        super().__init__()
        self.link = link
        self.setWindowTitle(f"ciscomvent {__version__}")
        self.resize(760, 520)

        central = QWidget()
        layout = QVBoxLayout(central)

        self.headline = QLabel("…")
        font = QFont()
        font.setPointSize(font.pointSize() + 3)
        font.setBold(True)
        self.headline.setFont(font)
        layout.addWidget(self.headline)

        self.detail = QLabel("")
        self.detail.setWordWrap(True)
        layout.addWidget(self.detail)

        tabs = QTabWidget()

        self.scopes = QTreeWidget()
        self.scopes.setColumnCount(4)
        self.scopes.setHeaderLabels(["Scope", "Device", "State", "Detail"])
        self.scopes.setRootIsDecorated(False)
        tabs.addTab(self.scopes, "Scopes")

        self.owned = QPlainTextEdit()
        self.owned.setReadOnly(True)
        self.owned.setFont(QFont("monospace"))
        tabs.addTab(self.owned, "Routes && rules")

        layout.addWidget(tabs)

        buttons = QHBoxLayout()
        self.toggle_button = QPushButton("Enable / Disable")
        self.toggle_button.clicked.connect(self.toggle_selected)
        buttons.addWidget(self.toggle_button)

        self.approve_button = QPushButton("Approve for this session")
        self.approve_button.clicked.connect(self.approve_selected)
        buttons.addWidget(self.approve_button)

        self.dismiss_button = QPushButton("Not now")
        self.dismiss_button.clicked.connect(self.dismiss_selected)
        self.dismiss_button.setToolTip(DISMISS_TIP)
        buttons.addWidget(self.dismiss_button)

        refresh = QPushButton("Reconcile")
        refresh.clicked.connect(self.reconcile)
        buttons.addWidget(refresh)

        buttons.addStretch()

        # Past the stretch, at the far edge. Everything to its left is routine
        # and undone by clicking again; this is neither, so it does not sit in
        # the row a misclick travels along.
        self.revert_button = QToolButton()
        self.revert_button.setText("Revert")
        # InstantPopup, so there is no default action a plain click can fire.
        # Both entries remove something and they differ in how much, which is a
        # choice worth making every time rather than inheriting from last time.
        self.revert_button.setPopupMode(QToolButton.InstantPopup)
        self.revert_menu = QMenu(self.revert_button)
        self.revert_actions = [
            self._revert_action("Firewall rules", LAYER_FIREWALL),
            self._revert_action("Firewall rules && routes", None),
        ]
        self.revert_button.setMenu(self.revert_menu)
        buttons.addWidget(self.revert_button)

        layout.addLayout(buttons)

        # Actions were silent: the toggle wrote config and the display kept
        # showing the discovery default, so it looked inert. Say what happened.
        self.activity = QLabel("")
        self.activity.setWordWrap(True)
        self.activity.setStyleSheet("color: #8a8a8a;")
        layout.addWidget(self.activity)

        self.setCentralWidget(central)
        self._summary: Summary | None = None
        self._escalation: QProcess | None = None
        """The pkexec run in flight, if any. Held so it is not collected mid-run,
        and so a second click cannot stack a second password prompt."""

        self.refresh_callback = lambda: None

    def render(self, summary: Summary) -> None:
        self._summary = summary
        self.headline.setText(summary.headline)
        self.headline.setStyleSheet(f"color: {summary.colour};")
        self.detail.setText(summary.detail)
        # The taskbar entry tracks health like the tray does, so the state is
        # readable without the panel's tray area being on screen. Set on the
        # window, not the application, to leave the About box and message
        # boxes on the neutral default. Under X11 only: a Wayland compositor
        # draws the desktop entry's icon and ignores this, so there the
        # taskbar carries the plain mark and the tray alone carries state.
        self.setWindowIcon(make_icon(summary.colour, badge=summary.needs_attention))

        selected = {i.text(0) for i in self.scopes.selectedItems()}
        self.scopes.clear()
        for row in summary.scopes:
            item = QTreeWidgetItem(
                [
                    row.name,
                    row.device,
                    row.display_state,
                    row.detail,
                ]
            )
            # Colour by marker, not needs_fix: an idle bridge with no
            # containers is technically captured but is not a problem.
            item.setForeground(0, QColor(ROW_COLOURS[row.marker]))
            self.scopes.addTopLevelItem(item)
            if row.name in selected:
                item.setSelected(True)
        for column in range(3):
            self.scopes.resizeColumnToContents(column)

        lines = ["# routes"]
        lines += list(summary.routes) or ["(none)"]
        lines += ["", "# firewall rules"]
        lines += list(summary.rules) or ["(none)"]
        self.owned.setPlainText("\n".join(lines))

        self.approve_button.setEnabled(bool(summary.pending))
        # Keyed on awaiting, not pending: a scope already put off has nothing
        # left to dismiss, while approving it stays available.
        self.dismiss_button.setEnabled(bool(summary.awaiting))

        # set-scope writes /etc, which the daemon refuses below uid 0. Where
        # pkexec can authenticate we offer the control and escalate on click;
        # where it cannot, the button stays dead and the tooltip says why.
        can_act = summary.caller_is_root or escalate.available()
        self.toggle_button.setEnabled(can_act and self._escalation is None)
        self.toggle_button.setToolTip(
            ""
            if summary.caller_is_root
            else TOGGLE_WILL_PROMPT
            if can_act
            else TOGGLE_NEEDS_ROOT
        )

        # Not keyed on caller_is_root like the toggle: revert has no control
        # socket command to fall back to, so pkexec is the only route to it
        # whoever is running the applet.
        can_revert = escalate.available()
        self.revert_button.setEnabled(can_revert and self._escalation is None)
        self.revert_button.setToolTip(REVERT_TIP if can_revert else REVERT_NEEDS_ROOT)

    def dismiss_selected(self) -> None:
        """Put a pending scope off for this VPN session.

        No confirmation: unlike approving, this changes nothing about what is
        routed -- the scope was unclaimed before the click and is unclaimed
        after it. Reversible by approving it, and cleared on the next connect.
        """
        name = self._selected_scope()
        if not name:
            return

        ok, detail, _ = self.link.send("dismiss", scope=name)
        self._after(ok, detail, f"{name} left unclaimed for this session")

    def _selected_scope(self) -> str | None:
        items = self.scopes.selectedItems()
        if not items:
            QMessageBox.information(self, "ciscomvent", "Select a scope first.")
            return None
        return items[0].text(0)

    def _after(self, ok: bool, detail: str, message: str) -> None:
        """Report the outcome and refresh now rather than at the next poll."""
        if ok:
            self.activity.setText(message)
        else:
            self.activity.setText(f"failed: {detail}")
            QMessageBox.warning(self, "ciscomvent", detail)
        self.refresh_callback()

    def toggle_selected(self) -> None:
        name = self._selected_scope()
        if not name or self._summary is None:
            return
        row = next((r for r in self._summary.scopes if r.name == name), None)
        if row is None:
            return
        want = not row.enabled

        if self._summary.caller_is_root:
            ok, detail, _ = self.link.send("set-scope", scope=name, enabled=want)
            self._after(ok, detail, f"{name} {'enabled' if want else 'disabled'}")
            return

        self._escalate_set_scope(name, want)

    def _escalate_set_scope(self, name: str, enabled: bool) -> None:
        """Re-run the CLI as root, with pkexec doing the authentication.

        The daemon refuses set-scope below uid 0 and nothing here can change
        that, so the choice is between a control that can only fail and one
        that asks. Asking crosses a privilege boundary, so what crosses it is
        decided in ``escalate`` rather than assembled at this call site --
        including that the program is a fixed absolute root-owned path and the
        scope name has been through the same validator the daemon uses.
        """
        if self._escalation is not None:
            return  # a prompt is already up; a second would stack on it

        try:
            argv = escalate.set_scope_argv(name, enabled)
        except (escalate.EscalationUnavailable, ValueError) as exc:
            QMessageBox.warning(
                self,
                "ciscomvent",
                f"{exc}\n\nBy hand:\n    {escalate.sudo_hint(name, enabled)}",
            )
            return

        verb = "enable" if enabled else "disable"
        self._run_escalated(
            argv,
            f"Authenticating to {verb} {name}…",
            f"{name} {'enabled' if enabled else 'disabled'}",
        )

    def _run_escalated(self, argv: list[str], busy: str, done: str) -> None:
        """Start a pkexec run, with at most one in flight.

        ``done`` is what the activity label says on a clean exit; a failure
        reports what the CLI said instead.
        """
        self.activity.setText(busy)

        # QProcess rather than subprocess: the password prompt can sit there
        # for as long as the user takes, and blocking the event loop on it
        # would freeze the window behind the dialog.
        proc = QProcess(self)
        proc.finished.connect(
            lambda code, _status, message=done: self._escalation_done(code, message)
        )
        self._escalation = proc
        self._enable_escalating(False)
        proc.start(argv[0], argv[1:])

    def _enable_escalating(self, enabled: bool) -> None:
        """Every control that escalates.

        They share one QProcess slot, so a prompt from either has to disable
        the other -- otherwise a second click stacks a second password dialog
        on the first and only one of the two runs.
        """
        self.toggle_button.setEnabled(enabled)
        self.revert_button.setEnabled(enabled)

    def _escalation_done(self, code: int, done: str) -> None:
        # Read before clearing: the CLI's own stderr says far more than the
        # exit status does, and it is the only channel back from the root side.
        stderr = ""
        if self._escalation is not None:
            stderr = bytes(self._escalation.readAllStandardError()).decode(
                "utf-8", "replace"
            )
        self._escalation = None
        # Provisional: the render that refresh_callback triggers decides what
        # each one is actually allowed to offer.
        self._enable_escalating(True)

        if code == 0:
            self.activity.setText(done)
        else:
            detail = escalate.describe_failure(code, stderr)
            self.activity.setText(f"failed: {detail.splitlines()[0]}")
            # 126 is a dismissed or failed prompt -- the user just said no, and
            # a dialog telling them so is noise.
            if code != 126:
                QMessageBox.warning(self, "ciscomvent", detail)
        self.refresh_callback()

    def approve_selected(self) -> None:
        name = self._selected_scope()
        if not name:
            return

        pending = self._summary.pending_claims if self._summary else ()
        claim = next((c for c in pending if c.name == name), None)
        if claim is not None and claim.networks:
            # The name is stable, the subnet is not. Confirming against the
            # CIDR is the difference between approving a dev bridge and
            # approving a range that carries corporate traffic.
            answer = QMessageBox.question(
                self,
                "ciscomvent",
                f"Route {', '.join(claim.networks)} via "
                f"{claim.device or name} ahead of the VPN tunnel, for this "
                "session?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if answer != QMessageBox.Yes:
                return

        ok, detail, _ = self.link.send("approve", scope=name, always=False)
        self._after(ok, detail, f"{name} approved for this VPN session")

    def reconcile(self) -> None:
        ok, detail, data = self.link.send("reconcile")
        self._after(ok, detail, f"Reconciled: {data.get('summary', 'done')}")

    def _revert_action(self, label: str, layer: int | None) -> QAction:
        """One entry in the Revert menu.

        The returned action has to be kept referenced by the caller: entries
        held only by a local have been collected out from under a menu here
        before, which empties it after __init__ returns.
        """
        action = self.revert_menu.addAction(label)
        action.triggered.connect(
            lambda _checked=False, chosen=layer: self.revert(chosen)
        )
        return action

    def revert(self, layer: int | None = None) -> None:
        """Remove what we own, after saying what goes and what stays.

        Through pkexec even for a root caller, because there is no teardown
        command on the control socket and this is not the place to add one:
        tearing down routing for the whole machine is the most destructive
        thing the session tier could be handed, and it is a tier whose only
        credential is group membership.
        """
        if self._escalation is not None:
            return  # a prompt is already up; a second would stack on it

        if not self._confirm_revert(layer):
            return

        try:
            argv = escalate.revert_argv(layer)
        except (escalate.EscalationUnavailable, ValueError) as exc:
            QMessageBox.warning(
                self,
                "ciscomvent",
                f"{exc}\n\nBy hand:\n    {escalate.revert_sudo_hint(layer)}",
            )
            return

        self._run_escalated(argv, "Authenticating to revert…", "Reverted")

    def _confirm_revert(self, layer: int | None) -> bool:
        """Name what goes, from the last snapshot.

        The counts are shown but deliberately not used to decide whether the
        control does anything: an unreachable daemon reports neither while the
        claims it installed are still in the kernel, and that is exactly a
        moment when someone wants this. The CLI is the authority and says so
        itself when there is nothing to remove.
        """
        summary = self._summary
        routes = len(summary.routes) if summary else 0
        rules = len(summary.rules) if summary else 0

        if layer == LAYER_FIREWALL:
            going = f"Remove {rules} firewall rule(s)?"
            staying = (
                "The reclaim routes stay, so those networks keep routing "
                "correctly and their traffic keeps being dropped."
            )
        else:
            going = (
                f"Remove {routes} route(s), {rules} firewall rule(s) and the "
                f"policy rules at priority {RULE_PRIORITY}?"
            )
            staying = "Nothing ciscomvent installed is left behind."

        answer = QMessageBox.question(
            self,
            "ciscomvent",
            f"{going}\n\n{staying}\n\n"
            "The daemon reinstalls whatever it still wants within a minute. "
            "To keep it off, disable the scopes or stop the service.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        return answer == QMessageBox.Yes


class AboutDialog(QDialog):
    """Copyright, licence and warranty.

    A plain dialog rather than QMessageBox: that class lays out several labels
    of its own, so widening the text means a stylesheet that also widens the
    icon label, which pushes the text off the dialog. Here the width is set
    once, on the dialog, and word-wrapped labels fill it.
    """

    WIDTH = 520

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("About ciscomvent")
        self.setMinimumWidth(self.WIDTH)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        title = QLabel(f"<b>ciscomvent {__version__}</b>")
        font = title.font()
        font.setPointSize(font.pointSize() + 2)
        title.setFont(font)
        layout.addWidget(title)

        layout.addWidget(
            self._body(
                "Restores host-to-container reachability under a VPN "
                "tunnel-all policy."
            )
        )
        layout.addWidget(
            self._body(
                f"{_html(COPYRIGHT)}<br>"
                f"License {LICENSE_SHORT} "
                f'(<a href="{LICENSE_URL}">full text</a>)'
            )
        )
        for notice in (CONDITIONS, WARRANTY, COPY_NOTICE):
            layout.addWidget(self._body(_html(notice)))

        layout.addStretch()
        buttons = QDialogButtonBox(QDialogButtonBox.Ok)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)

    def _body(self, html: str) -> QLabel:
        label = QLabel(html)
        label.setTextFormat(Qt.RichText)
        # Wrapping is the label's job; the notices arrive as single paragraphs
        # precisely so it can wrap them to this dialog rather than to whatever
        # width they happened to be written at.
        label.setWordWrap(True)
        label.setOpenExternalLinks(True)
        label.setTextInteractionFlags(
            Qt.TextBrowserInteraction | Qt.TextSelectableByMouse
        )
        return label


class Tray(QSystemTrayIcon):
    def __init__(self, link: DaemonLink, window: Window) -> None:
        super().__init__()
        self.link = link
        self.window = window
        self._last_health: Health | None = None
        self._notified: set[str] = set()
        self.refresh_callback = lambda: None

        self.menu = QMenu()

        # Every QAction is parented to the menu. Without a parent they are
        # owned only by the local variable, so Python collects them when
        # __init__ returns and PyQt destroys the C++ object -- the entry
        # silently vanishes from the menu.
        self.status_action = self._add("Status: …", enabled=False)
        self.restart_action = self._add("Restart daemon", self.restart_daemon)
        self.menu.addSeparator()

        self.approve_menu = self.menu.addMenu("Approve")
        self.approve_menu.setEnabled(False)

        self.open_action = self._add("Open window", self.show_window)
        self.reconcile_action = self._add("Reconcile", self.reconcile)

        self.menu.addSeparator()
        self.auto_action = self._add(
            "Approve automatically", self.set_automation, checkable=True
        )
        self.auto_action.setToolTip(AUTOMATION_TIP)

        self.menu.addSeparator()
        # The GPL names an about box as the GUI equivalent of `show w'/`show c'.
        self.about_action = self._add("About ciscomvent", self.show_about)
        self.quit_action = self._add("Quit applet", QApplication.quit)
        self.quit_action.setToolTip(
            "Closes this applet only. The daemon keeps maintaining your routes."
        )

        self.setContextMenu(self.menu)

        # Left-click opens the window, in addition to the menu entry.
        self.activated.connect(self._clicked)

        # An icon must exist before show(); otherwise Qt warns "No Icon set"
        # and the tray entry is invisible until the first render.
        self.setIcon(make_icon(COLOURS[Health.UNKNOWN]))
        self.setToolTip("ciscomvent — starting…")

    def _add(self, label, slot=None, *, enabled=True, checkable=False) -> QAction:
        action = QAction(label, self.menu)  # parented, so Qt owns its lifetime
        action.setEnabled(enabled)
        action.setCheckable(checkable)
        if slot is not None:
            action.triggered.connect(slot)
        self.menu.addAction(action)
        return action

    def _clicked(self, reason) -> None:
        if reason == QSystemTrayIcon.Trigger:
            self.show_window()

    def restart_daemon(self) -> None:
        """Ask the daemon to restart itself.

        No sudo needed: the daemon is already root and exits on request, and
        systemd brings it straight back. Your routes and rules stay in place
        while it is down -- it reconciles them again on startup.
        """
        ok, detail, _ = self.link.send("restart")
        self.showMessage(
            "ciscomvent",
            "Daemon restarting…" if ok else f"failed: {detail}",
            QSystemTrayIcon.Information if ok else QSystemTrayIcon.Warning,
            4000,
        )
        # It takes a moment to come back; poll sooner than the normal interval
        # so the tray does not sit on "not reachable" longer than it must.
        QTimer.singleShot(1500, self.refresh_callback)
        QTimer.singleShot(6000, self.refresh_callback)

    def reconcile(self) -> None:
        ok, detail, data = self.link.send("reconcile")
        self.showMessage(
            "ciscomvent",
            data.get("summary", detail) if ok else f"failed: {detail}",
            QSystemTrayIcon.Information if ok else QSystemTrayIcon.Warning,
            4000,
        )
        self.refresh_callback()

    def show_about(self) -> None:
        """The about box the GPL asks a GUI program to provide."""
        AboutDialog(self.window).exec_()

    def show_window(self) -> None:
        self.window.show()
        self.window.raise_()
        self.window.activateWindow()

    def set_automation(self, checked: bool) -> None:
        self.link.send("set-automation", automation="auto" if checked else "confirm")

    def render(self, summary: Summary) -> None:
        self.setIcon(make_icon(summary.colour, badge=summary.needs_attention))
        self.setToolTip(tooltip(summary))
        self.status_action.setText(f"Status: {summary.headline}")
        self.auto_action.setChecked(summary.automation == "auto")
        # Persisted, so root-only; per-session approval below is not. Both
        # branches set the tooltip, or a demotion would leave the stale one.
        self.auto_action.setEnabled(summary.caller_is_root)
        self.auto_action.setToolTip(
            AUTOMATION_TIP if summary.caller_is_root else AUTOMATION_NEEDS_ROOT
        )

        self.approve_menu.clear()
        self.approve_menu.setEnabled(bool(summary.pending_claims))
        for claim in summary.pending_claims:
            # Labelled with the CIDR, not just the scope name: approving
            # installs a rule that outranks the tunnel for that range, and the
            # range is chosen by whoever created the network.
            action = QAction(claim.label, self.approve_menu)
            action.setToolTip(claim.tooltip)
            action.triggered.connect(
                lambda _checked, scope=claim.name: self.link.send(
                    "approve", scope=scope, always=False
                )
            )
            self.approve_menu.addAction(action)

        self._maybe_notify(summary)
        self._last_health = summary.health

    def _maybe_notify(self, summary: Summary) -> None:
        """Notify on transitions, not on every poll."""
        if summary.health == self._last_health:
            return

        if summary.health is Health.PENDING:
            self.showMessage(
                "ciscomvent — approval needed",
                summary.detail,
                QSystemTrayIcon.Warning,
                10000,
            )
        elif summary.health is Health.FAILING:
            self.showMessage(
                "ciscomvent — still unreachable",
                summary.detail,
                QSystemTrayIcon.Critical,
                10000,
            )
        elif (
            summary.health is Health.HEALTHY
            and self._last_health is not None
            and self._last_health not in (Health.OFFLINE, Health.UNKNOWN)
        ):
            self.showMessage(
                "ciscomvent — restored", summary.detail, QSystemTrayIcon.Information, 4000
            )


def refuse_root() -> str | None:
    """The applet is a desktop client and must not run as root.

    Under sudo it loses XDG_RUNTIME_DIR and the session bus, so KDE's
    StatusNotifierItem host is unreachable and the tray icon never appears --
    which is what the "SNI unavailable" warning is really saying. It is also
    contrary to the design: the unprivileged client talks to the privileged
    daemon over the control socket, and running it as root defeats the split.
    """
    if os.geteuid() != 0:
        return None
    return (
        "Run the applet as your desktop user, not with sudo.\n\n"
        "As root it has no session bus, so KDE cannot show a tray icon, and\n"
        "the whole point of the control socket is that the GUI does not need\n"
        "privilege. If connecting fails, you need membership of the socket's\n"
        f"owning group -- run `ls -l {control.SOCKET_PATH}` to see which.\n\n"
        "    ciscomvent gui"
    )


def identify(app: QApplication) -> None:
    """Tell the desktop which program this is.

    Qt identifies a process by its executable, and this one's is the
    interpreter: the tray's settings listed the applet as "__main__.py". Under
    Wayland the window's app_id fell back to the same thing, and the
    compositor resolves a window's icon by finding the desktop entry of that
    name, so the title bar and taskbar showed the generic Wayland placeholder
    whatever setWindowIcon was given. Naming the menu entry here is what fixes
    that; the entry itself is written by `ciscomvent install`.
    """
    app.setApplicationName(LAUNCHER_PATH.stem)
    app.setDesktopFileName(LAUNCHER_PATH.stem)


def main(argv: list[str] | None = None) -> int:
    message = refuse_root()
    if message:
        print(f"error: {message}", file=sys.stderr)
        return 1

    app = QApplication(argv if argv is not None else sys.argv)
    identify(app)  # before any window exists: the app_id is sent on creation
    app.setQuitOnLastWindowClosed(False)  # closing the window keeps the tray
    # Every top-level widget inherits this, so dialogs raised before the first
    # render still carry the mark rather than Qt's placeholder. Under X11: a
    # Wayland compositor draws the icon named by the desktop entry identify()
    # points it at, and ignores what the client sets.
    app.setWindowIcon(make_icon(COLOURS[Health.UNKNOWN]))

    if not QSystemTrayIcon.isSystemTrayAvailable():
        print("No system tray available on this desktop.", file=sys.stderr)
        return 1

    link = DaemonLink()
    window = Window(link)
    tray = Tray(link, window)
    tray.show()

    def refresh() -> None:
        summary = summarize(link.snapshot())
        tray.render(summary)
        window.render(summary)

    window.refresh_callback = refresh
    tray.refresh_callback = refresh

    # Render before the first timer tick, so the tray never shows the "no icon"
    # placeholder while waiting on the poll interval.
    refresh()

    timer = QTimer()
    timer.timeout.connect(refresh)
    timer.start(POLL_MS)

    # Qt's event loop blocks Python's signal handling, so without this Ctrl+C
    # does nothing and the only way out is closing the terminal.
    signal.signal(signal.SIGINT, lambda *_: app.quit())
    signal.signal(signal.SIGTERM, lambda *_: app.quit())
    wakeup = QTimer()
    wakeup.timeout.connect(lambda: None)  # give the interpreter a slice to run
    wakeup.start(200)

    return app.exec_()


if __name__ == "__main__":
    raise SystemExit(main())
