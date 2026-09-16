# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exception hierarchy."""

from __future__ import annotations


class CiscomventError(Exception):
    """Base for all errors raised by this package."""


class CommandError(CiscomventError):
    """A subprocess failed or produced unparseable output."""

    def __init__(self, argv: list[str], returncode: int, stderr: str = "") -> None:
        self.argv = argv
        self.returncode = returncode
        self.stderr = stderr.strip()
        detail = f": {self.stderr}" if self.stderr else ""
        super().__init__(f"{' '.join(argv)} exited {returncode}{detail}")


class DiscoveryError(CiscomventError):
    """A required piece of host state could not be discovered."""
