#!/usr/bin/env bash
#
# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent, free software under the GNU GPL v3 or later,
# with ABSOLUTELY NO WARRANTY. See LICENSE or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
# Bring the ciscomvent-test stack up or down.
#
# The unit tests do not need this -- they run entirely on fixtures. This exists
# so the tool can be exercised end to end against a neutral stack instead of
# whatever real project happens to be on the machine.
#
#   ./testenv.sh up       start it
#   ./testenv.sh down     stop and remove it, including the network
#   ./testenv.sh status    what it looks like to ciscomvent
set -euo pipefail

cd "$(dirname "$0")"

case "${1:-status}" in
up)
    docker compose up -d
    echo
    echo "Up. ciscomvent should now discover 'docker:ciscomvent-test-net'."
    ;;
down)
    # -v also removes the network, so the bridge disappears and the reconciler
    # has a stale claim to clean up -- useful to watch on purpose.
    docker compose down -v
    echo "Removed."
    ;;
status)
    echo "=== containers ==="
    docker ps --filter 'name=ciscomvent-test-' \
        --format '  {{.Names}}\t{{.Status}}\t{{.Ports}}'
    echo
    echo "=== network ==="
    if docker network inspect ciscomvent-test-net >/dev/null 2>&1; then
        docker network inspect ciscomvent-test-net --format \
            '  id      : {{.Id}}
  subnet  : {{range .IPAM.Config}}{{.Subnet}}{{end}}
  gateway : {{range .IPAM.Config}}{{.Gateway}}{{end}}'
        echo "  bridge  : br-$(docker network inspect ciscomvent-test-net \
            --format '{{.Id}}' | cut -c1-12)"
        echo
        echo "=== addresses ==="
        docker network inspect ciscomvent-test-net --format \
            '{{range .Containers}}  {{.Name}}	{{.IPv4Address}}
{{end}}'
    else
        echo "  not present — run './testenv.sh up'"
    fi
    ;;
*)
    echo "usage: $0 {up|down|status}" >&2
    exit 2
    ;;
esac
