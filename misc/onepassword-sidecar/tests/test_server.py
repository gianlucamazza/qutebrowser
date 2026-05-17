# SPDX-FileCopyrightText: Gianluca Mazza <info@gianlucamazza.it>
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for SidecarServer: dispatch error handling + socket permissions."""

import json
import os
import pathlib
import socket
import sys
import threading

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from sidecar.backends.base import OnePasswordBackend
from sidecar.server import SidecarServer


class _ErrorBackend(OnePasswordBackend):
    """Backend that raises configurable exceptions for testing dispatch."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    def capabilities(self):
        return set()

    def find_items(self, url):
        raise self._exc

    def get_item(self, item_id, reveal=True):
        raise self._exc

    def save_login(self, url, username, password, title=None):
        raise self._exc

    def passkey_get(self, rp_id, challenge, allow_credentials):
        raise self._exc

    def passkey_create(self, rp_id, user, challenge, pub_key_cred_params):
        raise self._exc


def _dispatch(backend, method, params=None):
    server = SidecarServer(backend=backend)
    req = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    )
    return server._dispatch(req)


# ---------------------------------------------------------------------------
# NativeProtocolError → -32000
# ---------------------------------------------------------------------------


def test_dispatch_catches_native_protocol_error():
    from sidecar.backends.native_protocol import NativeProtocolError

    backend = _ErrorBackend(NativeProtocolError("passkey not supported"))
    resp = _dispatch(backend, "find_items", {"url": "https://example.com"})
    assert resp["error"]["code"] == -32000
    assert "passkey not supported" in resp["error"]["message"]


def test_dispatch_catches_browser_verification_failed():
    from sidecar.backends.native_protocol import BrowserVerificationFailed

    backend = _ErrorBackend(BrowserVerificationFailed("verification failed"))
    resp = _dispatch(backend, "get_item", {"id": "abc"})
    assert resp["error"]["code"] == -32000


def test_dispatch_unhandled_exception_returns_32603():
    backend = _ErrorBackend(RuntimeError("unexpected"))
    resp = _dispatch(backend, "find_items", {"url": "https://example.com"})
    assert resp["error"]["code"] == -32603
    # Must NOT expose the exception message (could contain secrets)
    assert "unexpected" not in resp["error"]["message"]


# ---------------------------------------------------------------------------
# Socket permissions race fix (chmod before listen)
# ---------------------------------------------------------------------------


def test_socket_is_0600_before_accepting_connections(tmp_path):
    sock_path = tmp_path / "qute-1pass.sock"
    server = SidecarServer(socket_path=str(sock_path))

    # Start server in background; it blocks on accept() after bind+chmod+listen
    t = threading.Thread(target=server.start, daemon=True)
    t.start()

    # Wait briefly for the socket to appear
    import time

    for _ in range(50):
        if sock_path.exists():
            break
        time.sleep(0.01)

    assert sock_path.exists(), "socket was never created"
    mode = oct(sock_path.stat().st_mode & 0o777)
    server.stop()

    assert mode == oct(0o600), f"socket has wrong mode {mode}, expected 0o600"
