# SPDX-FileCopyrightText: Gianluca
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for OnePasswordClient (JSON-RPC layer)."""

import json
import logging

import pytest

from qutebrowser.browser.onepassword.client import OnePasswordClient, _socket_path


# ---------------------------------------------------------------------------
# fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(qapp, request):
    """Create a OnePasswordClient and ensure it is deleted after the test."""
    c = OnePasswordClient()
    request.addfinalizer(c.deleteLater)
    return c


# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------


def test_call_increments_id(client):
    calls: list[dict] = []

    def _fake_write(data: bytes) -> None:
        calls.append(json.loads(data.decode().strip()))

    client._socket.write = _fake_write  # type: ignore[method-assign]

    client.call("ping", {}, lambda r: None)
    client.call("find_items", {"url": "https://x.com"}, lambda r: None)

    assert calls[0]["id"] == 1
    assert calls[1]["id"] == 2
    assert calls[0]["method"] == "ping"
    assert calls[1]["method"] == "find_items"


def test_dispatch_calls_callback(client):
    results: list[dict] = []
    client._pending[42] = results.append

    response = json.dumps({"jsonrpc": "2.0", "id": 42, "result": {"pong": True}})
    client._dispatch(response)

    assert len(results) == 1
    assert results[0]["result"]["pong"] is True
    assert 42 not in client._pending


def test_dispatch_warns_on_unknown_id(client, caplog):
    response = json.dumps({"jsonrpc": "2.0", "id": 99, "result": {}})
    with caplog.at_level(logging.WARNING, "misc"):
        client._dispatch(response)
    assert any("no pending callback" in m for m in caplog.messages)


def test_dispatch_logs_error_on_bad_json(client, caplog):
    with caplog.at_level(logging.ERROR, "misc"):
        client._dispatch("this is not json")
    assert any("bad JSON" in m for m in caplog.messages)


def test_buffer_splits_on_newlines(client):
    results: list[dict] = []
    client._pending[1] = results.append
    client._pending[2] = results.append

    r1 = json.dumps({"jsonrpc": "2.0", "id": 1, "result": "a"}).encode()
    r2 = json.dumps({"jsonrpc": "2.0", "id": 2, "result": "b"}).encode()

    client._buf += r1 + b"\n" + r2 + b"\n"
    while b"\n" in client._buf:
        line, client._buf = client._buf.split(b"\n", 1)
        client._dispatch(line.decode())

    assert len(results) == 2
    assert results[0]["result"] == "a"
    assert results[1]["result"] == "b"


# ---------------------------------------------------------------------------
# socket_path config override
# ---------------------------------------------------------------------------


def test_socket_path_uses_config(config_stub):
    config_stub.set_obj("onepassword.socket_path", "/custom/op.sock")
    assert _socket_path() == "/custom/op.sock"


def test_socket_path_default_uses_xdg_runtime_dir(config_stub, monkeypatch):
    # socket_path defaults to "" — fall back to XDG_RUNTIME_DIR
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/1000")
    assert _socket_path() == "/run/user/1000/qute-1pass.sock"
