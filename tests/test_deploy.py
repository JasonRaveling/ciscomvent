# Copyright (C) 2026  Jason Raveling <ciscomvent@webunraveling.com>
# Part of ciscomvent. This program comes with ABSOLUTELY NO WARRANTY; it is
# free software under the GNU GPL v3 or later. See the LICENSE file at the
# root of this distribution, or <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Deployment safety.

Regression cover for a bug that deleted the installed package: run through the
wrapper, the deploy source and target are the same path, and the copy removed
its own source before reading it.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import ciscomvent.service as service


def _fake_package(root: Path) -> Path:
    pkg = root / "ciscomvent"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("# marker\n")
    (pkg / "daemon.py").write_text("# daemon\n")
    cache = pkg / "__pycache__"
    cache.mkdir()
    (cache / "junk.pyc").write_text("junk")
    return pkg


def test_self_deploy_is_a_noop_and_does_not_delete_the_package(monkeypatch, tmp_path):
    """The exact failure: `sudo ciscomvent daemon install` run from the deployed
    copy wiped /usr/local/lib/ciscomvent and left the CLI and daemon unable to
    import anything."""
    install_root = tmp_path / "usr-local-lib"
    pkg = _fake_package(install_root)

    monkeypatch.setattr(service, "INSTALL_ROOT", install_root)
    monkeypatch.setattr(service, "package_dir", lambda: pkg)

    ok, detail = service.deploy_source()

    assert ok
    assert "not copied" in detail
    assert (pkg / "__init__.py").read_text() == "# marker\n"
    assert (pkg / "daemon.py").exists()


def test_normal_deploy_copies_from_a_checkout(monkeypatch, tmp_path):
    checkout = tmp_path / "checkout" / "src"
    pkg = _fake_package(checkout)
    install_root = tmp_path / "usr-local-lib"

    monkeypatch.setattr(service, "INSTALL_ROOT", install_root)
    monkeypatch.setattr(service, "package_dir", lambda: pkg)

    ok, _ = service.deploy_source()

    assert ok
    assert (install_root / "ciscomvent" / "__init__.py").read_text() == "# marker\n"
    # Source is untouched.
    assert (pkg / "__init__.py").exists()


def test_deploy_excludes_bytecode_caches(monkeypatch, tmp_path):
    checkout = tmp_path / "checkout" / "src"
    pkg = _fake_package(checkout)
    install_root = tmp_path / "usr-local-lib"

    monkeypatch.setattr(service, "INSTALL_ROOT", install_root)
    monkeypatch.setattr(service, "package_dir", lambda: pkg)
    service.deploy_source()

    assert not (install_root / "ciscomvent" / "__pycache__").exists()


def test_redeploy_replaces_the_previous_copy(monkeypatch, tmp_path):
    checkout = tmp_path / "checkout" / "src"
    pkg = _fake_package(checkout)
    install_root = tmp_path / "usr-local-lib"

    monkeypatch.setattr(service, "INSTALL_ROOT", install_root)
    monkeypatch.setattr(service, "package_dir", lambda: pkg)
    service.deploy_source()

    # A file removed from the source must not survive in the deployed copy.
    (pkg / "daemon.py").unlink()
    (pkg / "__init__.py").write_text("# updated\n")
    service.deploy_source()

    target = install_root / "ciscomvent"
    assert target.joinpath("__init__.py").read_text() == "# updated\n"
    assert not target.joinpath("daemon.py").exists()


def test_failed_deploy_leaves_the_existing_copy_intact(monkeypatch, tmp_path):
    """Staging then swapping means a mid-copy failure cannot leave the install
    root empty, which is what made the original bug unrecoverable in place."""
    checkout = tmp_path / "checkout" / "src"
    pkg = _fake_package(checkout)
    install_root = tmp_path / "usr-local-lib"

    monkeypatch.setattr(service, "INSTALL_ROOT", install_root)
    monkeypatch.setattr(service, "package_dir", lambda: pkg)
    service.deploy_source()

    def boom(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(shutil, "copytree", boom)
    ok, detail = service.deploy_source()

    assert not ok
    assert "disk full" in detail
    assert (install_root / "ciscomvent" / "__init__.py").exists()
    assert not (install_root / "ciscomvent.new").exists()
