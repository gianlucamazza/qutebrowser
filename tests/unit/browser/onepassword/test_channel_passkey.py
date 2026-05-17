# SPDX-FileCopyrightText: Gianluca
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for OnePasswordChannel passkey slots and signals (Phase C)."""

import json

import pytest

from qutebrowser.qt.core import QObject, pyqtSignal
from qutebrowser.browser.onepassword.channel import OnePasswordChannel


class _FakeTab:
    abort_questions = None


class _PasskeyBridge(QObject):
    """Bridge stub that emits capabilities_changed and records passkey calls."""

    capabilities_changed = pyqtSignal()

    def __init__(self, caps=None):
        super().__init__()
        self.capabilities: set[str] = set(caps or [])
        self.passkey_calls: list[tuple[str, dict, object]] = []

    def passkey_get(self, params: dict, callback) -> None:
        self.passkey_calls.append(("get", params, callback))

    def passkey_create(self, params: dict, callback) -> None:
        self.passkey_calls.append(("create", params, callback))


@pytest.fixture()
def bridge_with_passkey():
    b = _PasskeyBridge(caps={"passkey_get", "passkey_create"})
    yield b
    b.deleteLater()


@pytest.fixture()
def bridge_no_passkey():
    b = _PasskeyBridge(caps=set())
    yield b
    b.deleteLater()


@pytest.fixture()
def channel_passkey(qapp, request, bridge_with_passkey):
    ch = OnePasswordChannel(_FakeTab(), bridge_with_passkey)
    request.addfinalizer(ch.deleteLater)
    return ch


@pytest.fixture()
def channel_no_passkey(qapp, request, bridge_no_passkey):
    ch = OnePasswordChannel(_FakeTab(), bridge_no_passkey)
    request.addfinalizer(ch.deleteLater)
    return ch


# ---------------------------------------------------------------------------
# capabilities() slot
# ---------------------------------------------------------------------------


def test_capabilities_empty(channel_no_passkey):
    result = channel_no_passkey.capabilities()
    assert json.loads(result) == []


def test_capabilities_sorted(channel_passkey):
    result = channel_passkey.capabilities()
    caps = json.loads(result)
    assert set(caps) == {"passkey_get", "passkey_create"}
    assert caps == sorted(caps)


# ---------------------------------------------------------------------------
# passkey_get — capability missing
# ---------------------------------------------------------------------------


def test_passkey_get_no_capability_emits_error(qtbot, channel_no_passkey):
    params = json.dumps(
        {"rp_id": "example.com", "challenge": "abc", "allow_credentials": []}
    )
    with qtbot.waitSignal(channel_no_passkey.passkey_error, timeout=500) as sig:
        channel_no_passkey.passkey_get("req-1", params)
    assert sig.args[0] == "req-1"
    assert "capability not available" in sig.args[1]


def test_passkey_get_no_capability_does_not_call_bridge(
    channel_no_passkey, bridge_no_passkey
):
    params = json.dumps(
        {"rp_id": "example.com", "challenge": "abc", "allow_credentials": []}
    )
    channel_no_passkey.passkey_get("req-2", params)
    assert bridge_no_passkey.passkey_calls == []


# ---------------------------------------------------------------------------
# passkey_get — invalid JSON
# ---------------------------------------------------------------------------


def test_passkey_get_invalid_json_emits_error(qtbot, channel_passkey):
    with qtbot.waitSignal(channel_passkey.passkey_error, timeout=500) as sig:
        channel_passkey.passkey_get("req-3", "not-json{")
    assert sig.args[0] == "req-3"
    assert "invalid params" in sig.args[1]


# ---------------------------------------------------------------------------
# passkey_get — success path
# ---------------------------------------------------------------------------


def test_passkey_get_calls_bridge(channel_passkey, bridge_with_passkey):
    params = {
        "rp_id": "example.com",
        "challenge": "abc",
        "allow_credentials": ["cred1"],
    }
    channel_passkey.passkey_get("req-4", json.dumps(params))
    assert len(bridge_with_passkey.passkey_calls) == 1
    kind, sent_params, _ = bridge_with_passkey.passkey_calls[0]
    assert kind == "get"
    assert sent_params == params


def test_passkey_get_emits_result_on_success(
    qtbot, channel_passkey, bridge_with_passkey
):
    params = {"rp_id": "example.com", "challenge": "abc", "allow_credentials": []}
    with qtbot.waitSignal(channel_passkey.passkey_result, timeout=500) as sig:
        channel_passkey.passkey_get("req-5", json.dumps(params))
        _, _, cb = bridge_with_passkey.passkey_calls[-1]
        cb({"result": {"credential_id_b64": "xyz"}})
    assert sig.args[0] == "req-5"
    assert json.loads(sig.args[1]) == {"credential_id_b64": "xyz"}


def test_passkey_get_emits_error_on_sidecar_error(
    qtbot, channel_passkey, bridge_with_passkey
):
    params = {"rp_id": "example.com", "challenge": "abc", "allow_credentials": []}
    with qtbot.waitSignal(channel_passkey.passkey_error, timeout=500) as sig:
        channel_passkey.passkey_get("req-6", json.dumps(params))
        _, _, cb = bridge_with_passkey.passkey_calls[-1]
        cb({"error": {"code": -32000, "message": "sidecar timeout"}})
    assert sig.args[0] == "req-6"
    assert "sidecar timeout" in sig.args[1]


# ---------------------------------------------------------------------------
# passkey_create — capability missing
# ---------------------------------------------------------------------------


def test_passkey_create_no_capability_emits_error(qtbot, channel_no_passkey):
    params = json.dumps(
        {
            "rp_id": "example.com",
            "user": {},
            "challenge": "abc",
            "pub_key_cred_params": [],
        }
    )
    with qtbot.waitSignal(channel_no_passkey.passkey_error, timeout=500) as sig:
        channel_no_passkey.passkey_create("req-7", params)
    assert sig.args[0] == "req-7"
    assert "capability not available" in sig.args[1]


# ---------------------------------------------------------------------------
# passkey_create — success path
# ---------------------------------------------------------------------------


def test_passkey_create_emits_result_on_success(
    qtbot, channel_passkey, bridge_with_passkey
):
    params = {
        "rp_id": "example.com",
        "user": {"id": "uid", "name": "alice", "display_name": "Alice"},
        "challenge": "abc",
        "pub_key_cred_params": [{"type": "public-key", "alg": -7}],
    }
    blob = {
        "credential_id_b64": "newcred",
        "attestation_obj_b64": "att",
        "client_data_json_b64": "cdj",
    }
    with qtbot.waitSignal(channel_passkey.passkey_result, timeout=500) as sig:
        channel_passkey.passkey_create("req-8", json.dumps(params))
        _, _, cb = bridge_with_passkey.passkey_calls[-1]
        cb({"result": blob})
    assert sig.args[0] == "req-8"
    assert json.loads(sig.args[1]) == blob


# ---------------------------------------------------------------------------
# capabilities_changed forwarding
# ---------------------------------------------------------------------------


def test_capabilities_changed_forwarded(qtbot, channel_passkey, bridge_with_passkey):
    with qtbot.waitSignal(channel_passkey.capabilities_changed, timeout=500):
        bridge_with_passkey.capabilities_changed.emit()
