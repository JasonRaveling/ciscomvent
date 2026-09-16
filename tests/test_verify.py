# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reachability classification and port discovery."""

from __future__ import annotations

from ciscomvent.verify import Reach, parse_ports


def test_refused_counts_as_reachable():
    """An RST means the packet reached the container and a reply came back.
    For diagnosing a black hole that is a success, not a failure -- treating it
    as failure would send us looking for a firewall problem that isn't there."""
    assert Reach.REFUSED.reachable is True
    assert Reach.OPEN.reachable is True


def test_timeout_and_unreachable_are_not_reachable():
    assert Reach.TIMEOUT.reachable is False
    assert Reach.UNREACHABLE.reachable is False
    assert Reach.ERROR.reachable is False


def test_parse_simple_exposed_port():
    assert parse_ports("80/tcp") == (80,)


def test_parse_published_mapping_takes_the_internal_port():
    """The container listens on the right-hand side of the arrow; the left is
    the host-side publication, which is not what we probe."""
    spec = "0.0.0.0:3309->3306/tcp, [::]:3309->3306/tcp"
    assert parse_ports(spec) == (3306,)


def test_parse_loopback_published_mapping():
    assert parse_ports("127.0.0.1:18080->80/tcp") == (80,)


def test_parse_multiple_exposed_ports():
    assert parse_ports("1025/tcp, 1110/tcp, 8025/tcp") == (1025, 1110, 8025)


def test_parse_multi_publication():
    spec = (
        "0.0.0.0:80->80/tcp, [::]:80->80/tcp, "
        "0.0.0.0:443->443/tcp, [::]:443->443/tcp, "
        "0.0.0.0:8080->8080/tcp, [::]:8080->8080/tcp"
    )
    assert parse_ports(spec) == (80, 443, 8080)


def test_parse_empty_and_garbage():
    assert parse_ports("") == ()
    assert parse_ports("   ") == ()
    assert parse_ports("not a port") == ()


def test_parse_udp():
    assert parse_ports("53/udp") == (53,)
