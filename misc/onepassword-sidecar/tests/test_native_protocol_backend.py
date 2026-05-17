# SPDX-FileCopyrightText: Gianluca
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for NativeProtocolBackend."""

import json
import os
import pathlib
import struct
import subprocess
import sys
import textwrap
import threading
import time

import pytest

from sidecar.backends.native_protocol import (
    BackendUnavailable,
    BrowserVerificationFailed,
    NativeProtocolBackend,
    NativeProtocolError,
)

FAKE_BS = pathlib.Path(__file__).parent / "captures" / "fake_bs.py"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def nm_frame(msg: dict) -> bytes:
    payload = json.dumps(msg, separators=(",", ":")).encode()
    return struct.pack("<I", len(payload)) + payload


def make_fake_launcher(tmp_path: pathlib.Path, bs_script: pathlib.Path) -> pathlib.Path:
    """Shell script that ignores env vars and runs bs_script directly."""
    script = tmp_path / "qute-1pass-sidecar"
    script.write_text(f"#!/bin/sh\nexec {sys.executable} {bs_script}\n")
    script.chmod(0o755)
    return script


def make_fake_manifest(tmp_path: pathlib.Path) -> pathlib.Path:
    manifest = tmp_path / "com.1password.1password.json"
    manifest.write_text(
        json.dumps(
            {
                "name": "com.1password.1password",
                "description": "fake",
                "path": "/dev/null",
                "type": "stdio",
                "allowed_extensions": ["{d634138d-c276-4fc8-924b-40a0ea21d284}"],
            }
        )
    )
    return manifest


def patched_backend(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
    bs_script: pathlib.Path = FAKE_BS,
) -> NativeProtocolBackend:
    launcher = make_fake_launcher(tmp_path, bs_script)
    manifest = make_fake_manifest(tmp_path)
    bs_fake = tmp_path / "1Password-BrowserSupport"
    bs_fake.touch()

    import sidecar.backends.native_protocol as nm_mod

    monkeypatch.setattr(nm_mod, "_LAUNCHER_SEARCH", [launcher])
    monkeypatch.setattr(nm_mod, "_MANIFEST_SEARCH", [manifest])
    monkeypatch.setattr(nm_mod, "_BS_PATH", bs_fake)

    # Stub out the embedded OpCliBackend so tests don't need `op` installed.
    from unittest.mock import MagicMock

    op_stub = MagicMock()
    op_stub.find_items.return_value = [
        {"id": "abc", "title": "GitHub", "username": "user", "url_match_score": 1}
    ]
    op_stub.get_item.return_value = {
        "username": "user",
        "password": "secret",
        "totp": None,
        "fields": [],
    }
    op_stub.save_login.return_value = {"id": "new123"}

    from sidecar.backends import op_cli

    monkeypatch.setattr(op_cli, "OpCliBackend", lambda: op_stub)

    backend = NativeProtocolBackend()
    backend._op_cli = op_stub  # ensure the stub is used
    return backend


# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------


def test_handshake_capabilities(monkeypatch, tmp_path):
    b = patched_backend(monkeypatch, tmp_path)
    try:
        assert "fill" in b.capabilities()
        assert "save" in b.capabilities()
        assert "totp" in b.capabilities()
        # passkeys not yet supported
        assert "passkey_get" not in b.capabilities()
    finally:
        b.close()


def test_lock_state_unlocked(monkeypatch, tmp_path):
    b = patched_backend(monkeypatch, tmp_path)
    try:
        assert b.lock_state() == "Unlocked"
    finally:
        b.close()


def test_account_count(monkeypatch, tmp_path):
    b = patched_backend(monkeypatch, tmp_path)
    try:
        assert b.account_count() == 1
    finally:
        b.close()


def test_find_items_delegates_to_op_cli(monkeypatch, tmp_path):
    b = patched_backend(monkeypatch, tmp_path)
    try:
        items = b.find_items("https://github.com")
        assert items[0]["title"] == "GitHub"
        b._op_cli.find_items.assert_called_once_with("https://github.com")
    finally:
        b.close()


def test_get_item_delegates_to_op_cli(monkeypatch, tmp_path):
    b = patched_backend(monkeypatch, tmp_path)
    try:
        item = b.get_item("abc")
        assert item["username"] == "user"
        b._op_cli.get_item.assert_called_once_with("abc", reveal=True)
    finally:
        b.close()


def test_save_login_delegates_to_op_cli(monkeypatch, tmp_path):
    b = patched_backend(monkeypatch, tmp_path)
    try:
        result = b.save_login("https://x.com", "user", "pw")
        assert result["id"] == "new123"
    finally:
        b.close()


def test_passkey_get_raises(monkeypatch, tmp_path):
    b = patched_backend(monkeypatch, tmp_path)
    try:
        with pytest.raises(NativeProtocolError, match="passkey_get not yet supported"):
            b.passkey_get("example.com", "challenge", [])
    finally:
        b.close()


def test_passkey_create_raises(monkeypatch, tmp_path):
    b = patched_backend(monkeypatch, tmp_path)
    try:
        with pytest.raises(
            NativeProtocolError, match="passkey_create not yet supported"
        ):
            b.passkey_create("example.com", {}, "challenge", [])
    finally:
        b.close()


def test_launcher_not_found(monkeypatch, tmp_path):
    import sidecar.backends.native_protocol as nm_mod

    monkeypatch.setattr(nm_mod, "_LAUNCHER_SEARCH", [tmp_path / "no-such-binary"])
    monkeypatch.setattr(nm_mod, "_MANIFEST_SEARCH", [tmp_path / "no-manifest.json"])
    bs_fake = tmp_path / "1Password-BrowserSupport"
    bs_fake.touch()
    monkeypatch.setattr(nm_mod, "_BS_PATH", bs_fake)
    with pytest.raises(BackendUnavailable, match="launcher not found"):
        NativeProtocolBackend()


def test_bs_not_found(monkeypatch, tmp_path):
    with pytest.raises(BackendUnavailable, match="not found at"):
        NativeProtocolBackend(bs_path=tmp_path / "no-BrowserSupport")


def test_locked_bs_gives_empty_capabilities(monkeypatch, tmp_path):
    """A fake BrowserSupport that reports Locked → capabilities should be empty."""
    locked_bs = tmp_path / "locked_bs.py"
    locked_bs.write_text(
        textwrap.dedent(
            f"""\
            import json, struct, sys
            LOCKED = {{"lockState": "Locked"}}
            ONE_ACCOUNT = {{"accounts": [{{"type": "Locked", "content": {{}}}}]}}
            RESPONSES = {{"NmLockState": LOCKED, "NmRequestAccounts": ONE_ACCOUNT, "NmOfflineStatus": {{"authFailed": False}}}}
            def send(msg):
                p = json.dumps(msg, separators=(",", ":")).encode()
                sys.stdout.buffer.write(struct.pack("<I", len(p)) + p)
                sys.stdout.buffer.flush()
            def recv():
                h = sys.stdin.buffer.read(4)
                if len(h) < 4: return None
                (n,) = struct.unpack("<I", h)
                return json.loads(sys.stdin.buffer.read(n))
            while True:
                msg = recv()
                if msg is None: break
                cb, inv_type = msg["callbackId"], msg["invocation"]["type"]
                if inv_type in RESPONSES:
                    send({{"type": "Success", "content": {{"callbackId": cb, "response": {{"type": inv_type, "content": RESPONSES[inv_type]}}, "browser_state": {{"type": "Known"}}}}}})
                else:
                    send({{"type": "BrowserSupport", "content": {{"callbackId": cb, "response": "UnknownInvocation", "browser_state": {{"type": "Known"}}}}}})
            """
        )
    )

    b = patched_backend(monkeypatch, tmp_path, bs_script=locked_bs)
    try:
        assert b.capabilities() == set()
    finally:
        b.close()
