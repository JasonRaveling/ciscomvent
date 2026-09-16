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
"""Restore host-to-container reachability under Cisco Secure Client tunnel-all.

The failure this addresses is a *routing* one, not a firewall or TLS one: the
client enumerates locally-discovered subnets on connect and installs a scope-link
route for each pointing at the tunnel, shadowing the Docker bridge routes. TCP
connects to 127.0.0.1 still succeed -- docker-proxy answers -- but its upstream
hop to the container enters the tunnel and black-holes.

The fix is a dedicated routing table selected by an ip rule consulted before
the main table, plus firewall accepts on the bridge. See the README.
"""

from __future__ import annotations

__version__ = "0.1.0"

# One source of truth for the licence text, so the CLI's --version, the
# `license` command and the GUI about box cannot drift apart.
AUTHOR = "Jason Raveling <ciscomvent@webunraveling.com>"
COPYRIGHT_YEAR = "2026"
COPYRIGHT = f"Copyright (C) {COPYRIGHT_YEAR}  {AUTHOR}"

LICENSE_URL = "https://www.gnu.org/licenses/gpl-3.0.html"
LICENSE_SHORT = "GPLv3+: GNU GPL version 3 or later"

# Each notice is one logical line with no embedded newlines, so whatever
# displays it decides how to wrap: textwrap for a terminal, the widget for a
# dialog. Storing them pre-wrapped meant the consumer wrapped already-wrapped
# text and stranded fragments on their own lines.
WARRANTY = (
    "This program is distributed in the hope that it will be useful, but "
    "WITHOUT ANY WARRANTY; without even the implied warranty of "
    "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the "
    "GNU General Public License for more details."
)

CONDITIONS = (
    "This program is free software: you can redistribute it and/or modify it "
    "under the terms of the GNU General Public License as published by the "
    "Free Software Foundation, either version 3 of the License, or (at your "
    "option) any later version."
)

COPY_NOTICE = (
    "You should have received a copy of the GNU General Public License along "
    "with this program.  If not, see <https://www.gnu.org/licenses/>."
)

ROUTE_PROTO = "ciscomvent"
"""Routes we install carry this proto, so reconcile and teardown can match on
ownership exactly and can never touch Cisco's (proto unspec) or the kernel's
(proto kernel) routes."""

RULE_COMMENT_PREFIX = "ciscomvent:"
"""iptables rules we install carry this comment prefix, for the same reason."""
