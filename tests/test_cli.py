# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""The command-line surface itself, as distinct from what the commands do."""

from __future__ import annotations

import pytest

from ciscomvent.cli import build_parser


def test_in_place_help_says_what_it_hands_to_the_user(monkeypatch, capsys):
    """The flag's own help is the one place the risk is read *before* the
    decision; the unit comment and the install output come after it."""
    # Wide enough that argparse does not wrap the sentence being looked for.
    monkeypatch.setenv("COLUMNS", "400")
    with pytest.raises(SystemExit):
        build_parser().parse_args(["daemon", "install", "--help"])

    out = capsys.readouterr().out
    # The option's own row, not the usage line that also names the flag.
    line = next(l for l in out.splitlines() if l.lstrip().startswith("--in-place"))
    assert "Development only" in line
    assert "root" in line
