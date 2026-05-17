# SPDX-FileCopyrightText: Gianluca
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for onepassword commands: restart-sidecar backend wiring and enforcement."""

import shutil
import subprocess

import pytest

from qutebrowser.api import cmdutils
from qutebrowser.browser.onepassword.commands import (
    onepassword_restart_sidecar,
    onepassword_status,
)


@pytest.fixture(autouse=True)
def _enable(config_stub):
    config_stub.set_obj("onepassword.enabled", True)
    config_stub.set_obj("onepassword.socket_path", "")


@pytest.fixture()
def fake_which(monkeypatch):
    monkeypatch.setattr(
        shutil,
        "which",
        lambda x: "/fake/qute-1pass-sidecar" if x == "qute-1pass-sidecar" else None,
    )


# ---------------------------------------------------------------------------
# sidecar binary not on PATH
# ---------------------------------------------------------------------------


def test_restart_sidecar_not_found_raises(qapp, config_stub, monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda x: None)
    with pytest.raises(cmdutils.CommandError, match="not found"):
        onepassword_restart_sidecar()


# ---------------------------------------------------------------------------
# experimental_bridge enforcement
# ---------------------------------------------------------------------------


def test_restart_sidecar_native_without_experimental_bridge_raises(
    qapp, config_stub, monkeypatch, fake_which
):
    config_stub.set_obj("onepassword.backend", "native")
    config_stub.set_obj("onepassword.experimental_bridge", False)
    with pytest.raises(cmdutils.CommandError, match="experimental_bridge"):
        onepassword_restart_sidecar()


def test_restart_sidecar_native_with_experimental_bridge_allowed(
    qapp, config_stub, monkeypatch, fake_which
):
    launched = []
    monkeypatch.setattr(subprocess, "Popen", lambda cmd, **kw: launched.append(cmd))
    config_stub.set_obj("onepassword.backend", "native")
    config_stub.set_obj("onepassword.experimental_bridge", True)
    onepassword_restart_sidecar()
    assert launched[0][:2] == ["/fake/qute-1pass-sidecar", "--backend"]
    assert "native" in launched[0]


# ---------------------------------------------------------------------------
# --backend argument passed to sidecar
# ---------------------------------------------------------------------------


def test_restart_sidecar_passes_backend_op_cli(
    qapp, config_stub, monkeypatch, fake_which
):
    launched = []
    monkeypatch.setattr(subprocess, "Popen", lambda cmd, **kw: launched.append(cmd))
    config_stub.set_obj("onepassword.backend", "op-cli")
    onepassword_restart_sidecar()
    assert launched[0] == ["/fake/qute-1pass-sidecar", "--backend", "op-cli"]


# ---------------------------------------------------------------------------
# --socket-path propagation
# ---------------------------------------------------------------------------


def test_restart_sidecar_passes_socket_path(qapp, config_stub, monkeypatch, fake_which):
    launched = []
    monkeypatch.setattr(subprocess, "Popen", lambda cmd, **kw: launched.append(cmd))
    config_stub.set_obj("onepassword.backend", "op-cli")
    config_stub.set_obj("onepassword.socket_path", "/custom/op.sock")
    onepassword_restart_sidecar()
    assert "--socket-path" in launched[0]
    idx = launched[0].index("--socket-path")
    assert launched[0][idx + 1] == "/custom/op.sock"


def test_restart_sidecar_no_socket_path_when_empty(
    qapp, config_stub, monkeypatch, fake_which
):
    launched = []
    monkeypatch.setattr(subprocess, "Popen", lambda cmd, **kw: launched.append(cmd))
    config_stub.set_obj("onepassword.backend", "op-cli")
    onepassword_restart_sidecar()
    assert "--socket-path" not in launched[0]
