# SPDX-FileCopyrightText: Gianluca
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for OnePasswordBridge: capabilities cache, ping guard, passkey forwarders."""

import logging

import pytest

from qutebrowser.browser.onepassword.bridge import OnePasswordBridge


@pytest.fixture()
def bridge(qapp, request, monkeypatch):
    b = OnePasswordBridge()
    request.addfinalizer(b.deleteLater)
    monkeypatch.setattr(b._client, "connect_to_sidecar", lambda: None)
    monkeypatch.setattr(b._client, "is_connected", lambda: True)
    return b


# ---------------------------------------------------------------------------
# _on_ping_result
# ---------------------------------------------------------------------------


def test_on_ping_result_populates_capabilities(qtbot, bridge):
    with qtbot.waitSignal(bridge.capabilities_changed, timeout=500):
        bridge._on_ping_result(
            {"result": {"capabilities": ["fill", "save", "passkey_get"]}}
        )
    assert bridge.capabilities == {"fill", "save", "passkey_get"}


def test_on_ping_result_populates_backend_status(bridge):
    bridge._on_ping_result(
        {
            "result": {
                "capabilities": ["fill", "save"],
                "backend": "OpCliBackend",
                "degraded": True,
                "degraded_from": "native",
                "degraded_reason": "launcher not found",
            }
        }
    )
    assert bridge.backend_status["degraded"] is True
    assert bridge.backend_status["degraded_from"] == "native"
    assert bridge.backend_status["degraded_reason"] == "launcher not found"
    assert bridge.backend_status["backend"] == "OpCliBackend"
    assert "capabilities" not in bridge.backend_status


def test_on_ping_result_error_leaves_capabilities_empty(bridge, caplog):
    with caplog.at_level(logging.WARNING, logger="misc"):
        bridge._on_ping_result({"error": {"message": "sidecar error"}})
    assert bridge.capabilities == set()


def test_on_ping_result_error_does_not_emit_signal(bridge, caplog):
    emitted = []
    bridge.capabilities_changed.connect(lambda: emitted.append(True))
    with caplog.at_level(logging.WARNING, logger="misc"):
        bridge._on_ping_result({"error": {"message": "sidecar error"}})
    assert emitted == []


# ---------------------------------------------------------------------------
# ensure_connected — ping guard
# ---------------------------------------------------------------------------


def test_ensure_connected_triggers_ping_once(bridge, monkeypatch):
    calls = []
    monkeypatch.setattr(bridge._client, "call", lambda *a: calls.append(a))
    bridge.ensure_connected()
    bridge.ensure_connected()
    pings = [c for c in calls if c[0] == "ping"]
    assert len(pings) == 1


# ---------------------------------------------------------------------------
# passkey forwarders
# ---------------------------------------------------------------------------


def test_passkey_get_forwards_to_client(bridge, monkeypatch):
    calls = []
    bridge._ping_done = True
    monkeypatch.setattr(bridge._client, "call", lambda *a: calls.append(a))
    cb = object()
    bridge.passkey_get({"rp_id": "example.com"}, cb)
    assert len(calls) == 1
    assert calls[0][0] == "passkey_get"
    assert calls[0][1] == {"rp_id": "example.com"}
    assert calls[0][2] is cb


def test_passkey_create_forwards_to_client(bridge, monkeypatch):
    calls = []
    bridge._ping_done = True
    monkeypatch.setattr(bridge._client, "call", lambda *a: calls.append(a))
    cb = object()
    params = {"rp_id": "example.com", "challenge": "abc"}
    bridge.passkey_create(params, cb)
    assert len(calls) == 1
    assert calls[0][0] == "passkey_create"
    assert calls[0][1] is params
    assert calls[0][2] is cb


# ---------------------------------------------------------------------------
# is_connected
# ---------------------------------------------------------------------------


def test_is_connected_delegates_to_client(bridge):
    assert bridge.is_connected() is True


# ---------------------------------------------------------------------------
# get_credentials
# ---------------------------------------------------------------------------


def test_get_credentials_calls_find_then_get(bridge, monkeypatch):
    """get_credentials chains find_items → get_item and delivers the item."""
    find_result = [{"id": "abc", "title": "GitHub", "url_match_score": 1}]
    get_result = {"username": "user", "password": "s3cr3t", "totp": None}
    calls = []

    def fake_call(method, params, cb):
        calls.append((method, params))
        if method == "find_items":
            cb({"result": find_result})
        elif method == "get_item":
            cb({"result": get_result})

    bridge._ping_done = True
    monkeypatch.setattr(bridge._client, "call", fake_call)

    received = []
    bridge.get_credentials(
        "https://github.com", lambda item, err: received.append((item, err))
    )

    assert len(received) == 1
    item, err = received[0]
    assert err is None
    assert item["username"] == "user"
    assert item["password"] == "s3cr3t"
    assert calls[0][0] == "find_items"
    assert calls[1][0] == "get_item"
    assert calls[1][1] == {"id": "abc"}


def test_get_credentials_no_items_returns_error(bridge, monkeypatch):
    bridge._ping_done = True
    monkeypatch.setattr(
        bridge._client,
        "call",
        lambda method, params, cb: (
            cb({"result": []}) if method == "find_items" else None
        ),
    )

    received = []
    bridge.get_credentials(
        "https://example.com", lambda item, err: received.append((item, err))
    )

    assert received[0] == (None, "no items found for https://example.com")


def test_get_credentials_find_error_propagates(bridge, monkeypatch):
    bridge._ping_done = True
    monkeypatch.setattr(
        bridge._client,
        "call",
        lambda method, params, cb: cb({"error": {"message": "vault locked"}}),
    )

    received = []
    bridge.get_credentials(
        "https://example.com", lambda item, err: received.append((item, err))
    )

    assert received[0] == (None, "vault locked")
