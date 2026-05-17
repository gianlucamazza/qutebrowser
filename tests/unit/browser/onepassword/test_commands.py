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


# ---------------------------------------------------------------------------
# onepassword_status — degraded backend display
# ---------------------------------------------------------------------------


def test_status_shows_degraded_reason(qapp, monkeypatch):
    from qutebrowser.utils import message
    from qutebrowser.browser.onepassword import commands

    infos = []
    monkeypatch.setattr(message, "info", lambda s: infos.append(s))

    fake_bridge = type(
        "FakeBridge",
        (),
        {
            "is_connected": lambda self: True,
            "capabilities": set(),
            "ping": lambda self, cb: cb(
                {
                    "result": {
                        "backend": "OpCliBackend",
                        "locked": False,
                        "degraded": True,
                        "degraded_from": "native",
                        "degraded_reason": "launcher not found",
                        "capabilities": [],
                    }
                }
            ),
        },
    )()

    from qutebrowser.utils import objreg

    monkeypatch.setattr(objreg, "get", lambda key, default=None: fake_bridge)

    onepassword_status()
    assert len(infos) == 1
    assert "degraded from native" in infos[0]
    assert "launcher not found" in infos[0]


# ---------------------------------------------------------------------------
# copy commands — username / password / totp
# ---------------------------------------------------------------------------


def _make_credential_bridge(monkeypatch, item: dict, qapp):
    """Patch objreg.get to return a bridge that yields *item* via get_credentials."""
    from qutebrowser.utils import objreg

    fake_bridge = type(
        "FakeBridge",
        (),
        {
            "get_credentials": lambda self, url, cb, **kw: cb(item, None),
        },
    )()
    monkeypatch.setattr(objreg, "get", lambda key, default=None: fake_bridge)
    return fake_bridge


def test_copy_username_uses_copy_plain(qapp, config_stub, monkeypatch):
    config_stub.set_obj("onepassword.enabled", True)
    copied = []
    monkeypatch.setattr(
        "qutebrowser.browser.onepassword.clipboard_redact.copy_plain",
        lambda v, label: copied.append((v, label)),
    )
    _make_credential_bridge(
        monkeypatch, {"username": "user@x.com", "password": "pw", "totp": None}, qapp
    )

    from qutebrowser.browser.onepassword.commands import onepassword_copy_username

    tab = type(
        "T",
        (),
        {
            "url": lambda self: type(
                "U", (), {"toString": lambda self: "https://x.com"}
            )()
        },
    )()
    onepassword_copy_username(tab)
    assert copied == [("user@x.com", "username")]


def test_copy_password_uses_copy_secret(qapp, config_stub, monkeypatch):
    config_stub.set_obj("onepassword.enabled", True)
    copied = []
    monkeypatch.setattr(
        "qutebrowser.browser.onepassword.clipboard_redact.copy_secret",
        lambda v, label, **kw: copied.append((v, label)),
    )
    _make_credential_bridge(
        monkeypatch, {"username": "u", "password": "s3cr3t", "totp": None}, qapp
    )

    from qutebrowser.browser.onepassword.commands import onepassword_copy_password

    tab = type(
        "T",
        (),
        {
            "url": lambda self: type(
                "U", (), {"toString": lambda self: "https://x.com"}
            )()
        },
    )()
    onepassword_copy_password(tab)
    assert copied == [("s3cr3t", "password")]


def test_copy_totp_uses_copy_secret(qapp, config_stub, monkeypatch):
    config_stub.set_obj("onepassword.enabled", True)
    copied = []
    monkeypatch.setattr(
        "qutebrowser.browser.onepassword.clipboard_redact.copy_secret",
        lambda v, label, **kw: copied.append((v, label)),
    )
    _make_credential_bridge(
        monkeypatch, {"username": "u", "password": "pw", "totp": "123456"}, qapp
    )

    from qutebrowser.browser.onepassword.commands import onepassword_copy_totp

    tab = type(
        "T",
        (),
        {
            "url": lambda self: type(
                "U", (), {"toString": lambda self: "https://x.com"}
            )()
        },
    )()
    onepassword_copy_totp(tab)
    assert copied == [("123456", "TOTP")]


def test_copy_totp_missing_field_shows_error(qapp, config_stub, monkeypatch):
    config_stub.set_obj("onepassword.enabled", True)
    errors = []
    monkeypatch.setattr("qutebrowser.utils.message.error", lambda s: errors.append(s))
    _make_credential_bridge(
        monkeypatch, {"username": "u", "password": "pw", "totp": None}, qapp
    )

    from qutebrowser.browser.onepassword.commands import onepassword_copy_totp

    tab = type(
        "T",
        (),
        {
            "url": lambda self: type(
                "U", (), {"toString": lambda self: "https://x.com"}
            )()
        },
    )()
    onepassword_copy_totp(tab)
    assert any("no TOTP" in e for e in errors)
