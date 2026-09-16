#!/usr/bin/env bash
#
# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent, free software under the GNU GPL v3 or later,
# with ABSOLUTELY NO WARRANTY. See LICENSE or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
# Run the test suite.
#
# This host has no python3-venv, so pytest lives in a repo-local .devtools/
# directory installed with `pip install --target` -- nothing system-wide is
# modified. Bootstraps it on first run.
set -euo pipefail

cd "$(dirname "$0")"

if [ ! -x .devtools/bin/pytest ]; then
    echo "bootstrapping pytest into .devtools/ ..."
    python3 -m pip install --quiet --target .devtools pytest
fi

PYTHONPATH=.devtools:src exec python3 .devtools/bin/pytest "$@"
