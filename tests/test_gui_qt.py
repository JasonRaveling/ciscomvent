# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Qt-level wiring tests.

Runs headless via the offscreen platform plugin. These exist because the two
worst GUI regressions so far were both invisible to the Qt-free state tests and
to code review: a menu whose entries were garbage collected, and widget setup
that got swallowed into an unreachable branch of another method.
"""

from __future__ import annotations

import gc
import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt5.QtWidgets", reason="PyQt5 not installed")

from PyQt5.QtCore import QSize  # noqa: E402
from PyQt5.QtWidgets import (  # noqa: E402
    QApplication,
    QSystemTrayIcon,
    QToolButton,
)

from ciscomvent.gui import app as app_mod  # noqa: E402
from ciscomvent.gui.app import DaemonLink, Tray, Window  # noqa: E402
from ciscomvent.gui.state import COLOURS, Health, PendingClaim  # noqa: E402
from ciscomvent.service import LAUNCHER_PATH  # noqa: E402


@pytest.fixture(scope="module")
def qt_app():
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.fixture
def tray(qt_app):
    link = DaemonLink()
    window = Window(link)
    icon = Tray(link, window)
    # The failure mode being guarded against only appears once the constructor
    # has returned and unparented objects become collectable.
    gc.collect()
    return icon, window


def test_every_menu_entry_survives_construction(tray):
    """Regression: Open window, Reconcile and Quit applet were QActions
    held only by local variables. Python collected them when __init__ returned
    and PyQt destroyed the C++ objects, so they vanished from the menu while
    the ones stored on self stayed."""
    icon, _ = tray
    labels = [a.text() for a in icon.menu.actions() if not a.isSeparator()]

    assert labels == [
        "Status: …",
        "Restart daemon",
        "Approve",
        "Open window",
        "Reconcile",
        "Approve automatically",
        "About ciscomvent",
        "Quit applet",
    ]


def test_left_click_opens_the_window(tray):
    """Regression: inserting a helper method after setContextMenu swallowed the
    activated.connect call into an unreachable branch, so left-click silently
    stopped working while the menu entry kept functioning."""
    icon, window = tray
    assert not window.isVisible()

    icon.activated.emit(QSystemTrayIcon.Trigger)
    assert window.isVisible()


def test_tray_has_an_icon_before_the_first_render(tray):
    """Regression, twice: showing a QSystemTrayIcon with no icon logs
    "No Icon set" and leaves the entry invisible until the first poll."""
    icon, _ = tray
    assert not icon.icon().isNull()
    assert icon.toolTip()


def test_automation_toggle_is_checkable(tray):
    icon, _ = tray
    assert icon.auto_action.isCheckable()
    assert icon.auto_action.toolTip()


def test_approve_submenu_starts_disabled(tray):
    """Nothing is pending at startup, so offering approval would be misleading."""
    icon, _ = tray
    assert not icon.approve_menu.isEnabled()


def test_quit_entry_explains_it_does_not_stop_the_fix(tray):
    """Quitting the applet leaves the daemon maintaining routes; a user who
    assumes otherwise would think they had disabled the tool."""
    icon, _ = tray
    assert "daemon" in icon.quit_action.toolTip().lower()


def test_about_box_is_offered(tray):
    """The GPL's "How to Apply These Terms" names an about box as the GUI
    equivalent of the `show w' / `show c' commands it asks terminal programs
    to provide."""
    icon, _ = tray
    labels = [a.text() for a in icon.menu.actions()]
    assert "About ciscomvent" in labels


def test_about_box_states_copyright_warranty_and_conditions(tray, qt_app):
    from ciscomvent import CONDITIONS, COPYRIGHT, LICENSE_URL, WARRANTY

    icon, _ = tray
    # Build the same text the dialog shows, without opening a modal box.
    assert COPYRIGHT.startswith("Copyright (C)")
    # The GPL's wording wraps as "WITHOUT ANY\nWARRANTY", so normalise before
    # asserting rather than weakening the check.
    flat = " ".join(WARRANTY.split())
    assert "WITHOUT ANY WARRANTY" in flat
    assert "redistribute" in CONDITIONS
    assert LICENSE_URL.startswith("https://")
    assert icon.about_action.isEnabled()


def test_licence_notices_carry_no_line_breaks():
    """Regression: the notices were stored hard-wrapped at ~78 columns. The
    dialog then wrapped the already-wrapped text and stranded fragments like
    "FOR A" on their own line. Whatever displays them decides the width, so
    they have to arrive as single paragraphs."""
    from ciscomvent import CONDITIONS, COPY_NOTICE, WARRANTY

    for notice in (WARRANTY, CONDITIONS, COPY_NOTICE):
        assert "\n" not in notice


def test_about_escapes_the_contact_address(qt_app):
    """The copyright line ends in an email in angle brackets. Rich text would
    treat it as an unknown tag and drop it, losing the contact information the
    GPL asks to be included."""
    from ciscomvent import COPYRIGHT
    from ciscomvent.gui.app import _html

    rendered = _html(COPYRIGHT)
    assert "&lt;" in rendered and "&gt;" in rendered
    assert "<" not in rendered.replace("&lt;", "").replace("&gt;", "")
    assert _html("x & y").startswith("x &amp;")


def test_about_dialog_fits_its_own_width(qt_app):
    """Regression: widening the notice used a `QLabel { min-width: 34em }`
    stylesheet on a QMessageBox. That applies to *every* label the box owns,
    including the icon, so the dialog became icon-width plus text-width and the
    text ran off the right edge, partly hidden."""
    from PyQt5.QtWidgets import QLabel

    from ciscomvent.gui.app import AboutDialog

    dialog = AboutDialog()
    dialog.show()
    qt_app.processEvents()
    qt_app.processEvents()
    try:
        labels = dialog.findChildren(QLabel)
        assert labels
        for label in labels:
            right = label.x() + label.width()
            assert right <= dialog.width(), (
                f"{label.text()[:40]!r} extends to {right}px "
                f"in a {dialog.width()}px dialog"
            )
    finally:
        dialog.close()


def test_about_dialog_body_labels_wrap(qt_app):
    """The notices arrive as single paragraphs, so the labels must wrap them --
    otherwise each becomes one very long line and the dialog grows to fit it."""
    from PyQt5.QtWidgets import QLabel

    from ciscomvent.gui.app import AboutDialog

    dialog = AboutDialog()
    try:
        body = [
            label
            for label in dialog.findChildren(QLabel)
            if "WARRANTY" in label.text() or "redistribute" in label.text()
        ]
        assert len(body) >= 2
        assert all(label.wordWrap() for label in body)
    finally:
        dialog.close()


# -- privilege tier ----------------------------------------------------------
#
# The daemon refuses persisting commands below uid 0. A control that can only
# fail is worse than no control, so each one either escalates (scope
# enable/disable, via pkexec) or says why it cannot.


@pytest.fixture
def no_escalation(monkeypatch):
    """A host with no pkexec, or no trusted CLI to run under it."""
    from ciscomvent.gui import escalate

    monkeypatch.setattr(escalate, "available", lambda: False)


def _summary(**over):
    from ciscomvent.gui.state import Health, Summary

    base = {"health": Health.HEALTHY, "headline": "Healthy", "detail": ""}
    base.update(over)
    return Summary(**base)


def test_the_toggle_is_offered_and_escalates_for_an_unprivileged_caller(tray):
    """set-scope still needs uid 0 -- the button no longer pretends otherwise,
    it authenticates. The tooltip promises the prompt rather than a failure."""
    icon, window = tray
    summary = _summary(caller_is_root=False)

    icon.render(summary)
    window.render(summary)

    assert window.toggle_button.isEnabled()
    assert "authentication" in window.toggle_button.toolTip()
    # Not wired to escalation, so it stays greyed and keeps saying why.
    assert not icon.auto_action.isEnabled()
    assert "needs root" in icon.auto_action.toolTip()


def test_the_toggle_falls_back_to_a_hint_with_no_way_to_escalate(
    tray, no_escalation
):
    """A host without pkexec gets the old dead button -- but the tooltip names
    the command that does work rather than leaving it a mystery."""
    _icon, window = tray
    window.render(_summary(caller_is_root=False))

    assert not window.toggle_button.isEnabled()
    assert "needs root" in window.toggle_button.toolTip()
    assert "ciscomvent scope" in window.toggle_button.toolTip()


def test_root_only_controls_are_enabled_for_root(tray):
    icon, window = tray
    summary = _summary(caller_is_root=True)

    icon.render(summary)
    window.render(summary)

    assert icon.auto_action.isEnabled()
    assert window.toggle_button.isEnabled()


def test_the_tier_hint_does_not_go_stale_across_renders(tray, no_escalation):
    """Rendering unprivileged then privileged must not leave the sudo hint on a
    control that now works."""
    icon, window = tray

    icon.render(_summary(caller_is_root=False))
    window.render(_summary(caller_is_root=False))
    icon.render(_summary(caller_is_root=True))
    window.render(_summary(caller_is_root=True))

    assert "needs root" not in icon.auto_action.toolTip()
    assert icon.auto_action.toolTip()  # the real explanation is back
    assert "needs root" not in window.toggle_button.toolTip()


def test_session_approval_stays_available_without_root(tray):
    """The applet's main job, and the one tier that never needed sudo."""
    icon, window = tray
    summary = _summary(
        caller_is_root=False,
        pending_claims=(PendingClaim(name="docker:x", networks=("172.18.0.0/16",)),),
    )

    icon.render(summary)
    window.render(summary)

    assert icon.approve_menu.isEnabled()
    assert window.approve_button.isEnabled()


def _corner_colours(icon, px=64):
    """Tally the opaque pixels in the quadrant the attention badge sits in."""
    image = icon.pixmap(px, px).toImage()
    tally = {}
    for x in range(px // 2, px):
        for y in range(px // 2):
            colour = image.pixelColor(x, y)
            if colour.alpha() > 200:
                tally[colour.name()] = tally.get(colour.name(), 0) + 1
    return tally


def test_the_mark_ships_with_the_package(qt_app):
    """Guards packaging rather than Qt. The SVG is data, not a module, so it
    only reaches an installed copy because pyproject declares it as
    package-data and deploy_source copies more than *.py. Either regressing
    silently demotes every icon to the fallback circle, which is still
    non-null and so passes every other test here."""
    assert app_mod._mark() is not None


def test_the_icon_offers_every_size_a_panel_might_ask_for(qt_app):
    """A single 64px bitmap downsampled to a 22px panel smeared the badge."""
    icon = app_mod.make_icon(COLOURS[Health.HEALTHY])
    sizes = sorted(s.width() for s in icon.availableSizes())
    assert sizes == sorted(app_mod.ICON_SIZES)


def test_health_reaches_the_icon_and_not_just_the_tooltip(qt_app):
    """The mark ships as a bare silhouette carrying no fill of its own, so the
    tint is the only thing making the icon state-bearing. If the composition
    mode stopped applying, every state would render identically -- and still
    be non-null, which is all the older icon test checked."""
    healthy = app_mod.make_icon(COLOURS[Health.HEALTHY]).pixmap(64, 64).toImage()
    failing = app_mod.make_icon(COLOURS[Health.FAILING]).pixmap(64, 64).toImage()
    assert healthy != failing


def test_the_attention_badge_does_not_rely_on_white_alone(qt_app):
    """The badge sits in a corner the open mark leaves part transparent, so the
    bare white dot the drawn circle used was invisible against a light panel at
    every size. It is filled in the health colour and ringed in white now, so
    one of the two tones contrasts whatever the panel is."""
    colour = COLOURS[Health.PENDING]
    plain = _corner_colours(app_mod.make_icon(colour, badge=False))
    badged = _corner_colours(app_mod.make_icon(colour, badge=True))

    # Nothing else in the icon is white, so the ring is what put it there.
    assert "#ffffff" not in plain
    assert badged["#ffffff"] > 0

    # The fill cannot be counted -- it is the same colour as the mark it
    # covers -- so read it where only the badge can be.
    centre = app_mod._badge_rect(64).center()
    image = app_mod.make_icon(colour, badge=True).pixmap(64, 64).toImage()
    assert image.pixelColor(int(centre.x()), int(centre.y())).name() == colour


def test_a_missing_svg_plugin_costs_the_mark_not_the_icon(qt_app, monkeypatch):
    """Qt's SVG image plugin is a separate distro package (libqt5svg5) that the
    gui extra's `PyQt5>=5.15` does not necessarily pull in. An icon has to
    exist regardless, or the tray entry is invisible -- the regression this
    file already guards against twice."""
    monkeypatch.setattr(
        app_mod.QImageReader, "supportedImageFormats", staticmethod(lambda: [])
    )
    assert app_mod._mark() is None

    icon = app_mod.make_icon(COLOURS[Health.HEALTHY], badge=True)
    assert not icon.isNull()
    sizes = sorted(s.width() for s in icon.availableSizes())
    assert sizes == sorted(app_mod.ICON_SIZES)


def test_the_window_carries_a_health_icon_for_the_taskbar(tray):
    """The window had no icon at all, so its taskbar entry showed Qt's
    placeholder -- the one icon a user sees when the window is open and the
    tray is not in view."""
    _, window = tray

    window.render(_summary(health=Health.HEALTHY))
    healthy = window.windowIcon().pixmap(64, 64).toImage()
    assert not window.windowIcon().isNull()

    window.render(_summary(health=Health.FAILING))
    assert window.windowIcon().pixmap(64, 64).toImage() != healthy


def test_the_dismiss_button_is_offered_and_says_what_it_costs(tray):
    """The label is deliberately short, so the consequence -- that the scope
    stays unclaimed -- has to live in the tooltip."""
    _, window = tray
    claim = PendingClaim(name="docker:x", networks=("172.18.0.0/16",))

    window.render(_summary(pending_claims=(claim,)))

    assert window.dismiss_button.isEnabled()
    assert "unreachable" in window.dismiss_button.toolTip()


def test_a_scope_already_put_off_stays_approvable(tray):
    """Dismissing is not disabling. Nothing is left to dismiss, but changing
    your mind has to stay one click away."""
    _, window = tray
    claim = PendingClaim(name="docker:x", networks=("172.18.0.0/16",))

    window.render(_summary(pending_claims=(claim,), dismissed=("docker:x",)))

    assert not window.dismiss_button.isEnabled()
    assert window.approve_button.isEnabled()


# -- revert ------------------------------------------------------------------
#
# A destructive control in a window whose other buttons are all undone by
# clicking them again. The tests are about what it takes to fire it by
# accident, and about it not being offered where it cannot work.


@pytest.fixture
def confirmed(monkeypatch):
    """Answer the confirmation Yes, and record the argv instead of running it."""
    from PyQt5.QtWidgets import QMessageBox

    monkeypatch.setattr(
        QMessageBox, "question", staticmethod(lambda *a, **k: QMessageBox.Yes)
    )
    started: list[list[str]] = []
    monkeypatch.setattr(app_mod.escalate, "revert_argv", lambda layer: ["x", str(layer)])
    monkeypatch.setattr(
        Window, "_run_escalated", lambda self, argv, busy, done: started.append(argv)
    )
    return started


def test_both_revert_entries_survive_construction(tray):
    """Same failure as the tray menu had: a QAction held only by a local is
    collected when __init__ returns, taking the entry with it."""
    _icon, window = tray

    assert [a.text() for a in window.revert_menu.actions()] == [
        "Firewall rules",
        "Firewall rules && routes",
    ]


def test_revert_has_no_default_action_a_single_click_can_fire(tray):
    """MenuButtonPopup would make one of the two the click target. Both remove
    something and they differ in how much, so neither is a safe default."""
    _icon, window = tray

    assert window.revert_button.popupMode() == QToolButton.InstantPopup
    assert window.revert_button.defaultAction() is None


@pytest.mark.parametrize(
    "label, layer", [("Firewall rules", "2"), ("Firewall rules && routes", "None")]
)
def test_each_entry_reverts_its_own_layer(tray, confirmed, label, layer):
    _icon, window = tray
    action = next(a for a in window.revert_menu.actions() if a.text() == label)

    action.trigger()

    assert confirmed == [["x", layer]]


def test_declining_the_confirmation_runs_nothing(tray, monkeypatch):
    from PyQt5.QtWidgets import QMessageBox

    monkeypatch.setattr(
        QMessageBox, "question", staticmethod(lambda *a, **k: QMessageBox.No)
    )
    started = []
    monkeypatch.setattr(
        Window, "_run_escalated", lambda self, *a: started.append(a)
    )
    _icon, window = tray

    window.revert(None)

    assert started == []


def test_revert_is_offered_without_root(tray):
    """Unlike the toggle it has no socket command to fall back to, so pkexec is
    the only route to it for root and non-root alike."""
    _icon, window = tray
    window.render(_summary(caller_is_root=False))

    assert window.revert_button.isEnabled()


def test_revert_falls_back_to_a_hint_with_no_way_to_escalate(tray, no_escalation):
    _icon, window = tray
    window.render(_summary(caller_is_root=True))

    assert not window.revert_button.isEnabled()
    assert "ciscomvent revert" in window.revert_button.toolTip()


def test_one_prompt_at_a_time_across_both_escalating_controls(tray):
    """They share a single QProcess slot, so a second prompt would replace the
    first rather than queue behind it."""
    _icon, window = tray
    window._escalation = object()

    window.render(_summary(caller_is_root=False))

    assert not window.revert_button.isEnabled()
    assert not window.toggle_button.isEnabled()


def test_the_mark_is_drawn_at_the_size_asked_for(qt_app):
    """The SVG is read through Qt's image plugin with a scaled size, which has
    it rasterise the vector at that size. Without the scaled size the plugin
    hands back the SVG's own canvas, several hundred pixels across, and a
    panel icon drawn from that shows one corner of the mark."""
    mark = app_mod._mark()
    assert mark is not None
    for px in (16, 128):
        image = app_mod._silhouette(mark, px)
        assert image.size() == QSize(px, px)
        drawn = any(
            image.pixelColor(x, y).alpha() > 0 for x in range(px) for y in range(px)
        )
        assert drawn


def test_the_applet_names_the_menu_entry_as_its_app_id(qt_app):
    """Under Wayland the compositor resolves a window's icon by looking up a
    desktop entry named after its app_id, and Qt's fallback for that is the
    executable. Here that is the interpreter, for which no entry exists, so
    the window showed the generic Wayland placeholder. The name has to be the
    entry install writes, or the lookup fails the same way."""
    app_mod.identify(qt_app)
    assert qt_app.desktopFileName() == LAUNCHER_PATH.stem
    # What the tray's settings page lists the applet as; it was "__main__.py".
    assert qt_app.applicationName() == "ciscomvent"
