# SPDX-FileCopyrightText: Gianluca Mazza <info@gianlucamazza.it>
# SPDX-License-Identifier: GPL-3.0-or-later

"""End-to-end round-trip tests: FakeSidecar → OnePasswordClient → Bridge → Channel.

These tests exercise the full qutebrowser-side stack (client, bridge, channel)
against an in-process fake sidecar, without requiring the real `op` CLI or
1Password.app.
"""

import json
import logging

import pytest

from qutebrowser.browser.onepassword.bridge import OnePasswordBridge
from qutebrowser.browser.onepassword.channel import OnePasswordChannel
from qutebrowser.qt.core import QCoreApplication


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


class _FakeTab:
    """Minimal tab double: records run_js_async calls."""

    def __init__(self) -> None:
        self.js_calls: list[str] = []
        self.abort_questions = object()

    def run_js_async(self, code: str) -> None:
        self.js_calls.append(code)


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _enable(config_stub):
    config_stub.set_obj("onepassword.enabled", True)
    config_stub.set_obj("onepassword.autosave_on_submit", True)


@pytest.fixture()
def bridge(qapp, request, fake_sidecar):
    b = OnePasswordBridge()

    def _cleanup():
        # Disconnect cleanly before fake_sidecar tears down; otherwise Qt fires
        # PeerClosedError when the server socket closes while the client is alive.
        b.disconnect()
        QCoreApplication.processEvents()
        b.deleteLater()

    request.addfinalizer(_cleanup)
    return b


# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------


def test_fill_round_trip(qtbot, bridge, fake_sidecar):
    """fill() finds an item, fetches credentials, and injects JS into the tab."""
    fake_sidecar.preset_response("ping", {"result": {"capabilities": ["fill", "save"]}})
    fake_sidecar.preset_response(
        "find_items", {"result": [{"id": "abc", "title": "Example"}]}
    )
    fake_sidecar.preset_response(
        "get_item", {"result": {"username": "alice@x.com", "password": "s3cr3t"}}
    )

    tab = _FakeTab()
    bridge.fill(tab, "https://x.com")

    qtbot.waitUntil(lambda: len(tab.js_calls) > 0, timeout=2000)

    js = tab.js_calls[0]
    assert "alice@x.com" in js
    assert "s3cr3t" in js
    assert (
        fake_sidecar.requests_for("find_items")[0]["params"]["url"] == "https://x.com"
    )
    assert fake_sidecar.requests_for("get_item")[0]["params"]["id"] == "abc"


def test_autosave_round_trip(qtbot, bridge, fake_sidecar, monkeypatch):
    """autosave_requested() asks the user, then saves credentials to the sidecar."""
    fake_sidecar.preset_response("ping", {"result": {"capabilities": ["fill", "save"]}})
    fake_sidecar.preset_response("save_login", {"result": {"id": "xyz"}})

    infos: list[str] = []
    monkeypatch.setattr(
        "qutebrowser.browser.onepassword.channel.message.ask",
        lambda **kw: True,
    )
    monkeypatch.setattr(
        "qutebrowser.browser.onepassword.bridge.message.info",
        infos.append,
    )

    tab = _FakeTab()
    channel = OnePasswordChannel(tab, bridge)
    channel.autosave_requested("https://x.com", "alice", "s3cr3t")

    qtbot.waitUntil(lambda: bool(infos), timeout=2000)

    assert "xyz" in infos[0]
    reqs = fake_sidecar.requests_for("save_login")
    assert len(reqs) == 1
    assert reqs[0]["params"]["url"] == "https://x.com"
    assert reqs[0]["params"]["username"] == "alice"
    assert reqs[0]["params"]["password"] == "s3cr3t"


def test_passkey_get_round_trip(qtbot, bridge, fake_sidecar):
    """passkey_get() is capability-gated and forwards the sidecar blob to the page."""
    blob = {"authenticator_data_b64": "AAAA", "signature_b64": "BBBB"}
    fake_sidecar.preset_response(
        "ping", {"result": {"capabilities": ["fill", "passkey_get"]}}
    )
    fake_sidecar.preset_response("passkey_get", {"result": blob})

    tab = _FakeTab()
    channel = OnePasswordChannel(tab, bridge)

    # Wait for ping to complete so capabilities are populated.
    with qtbot.waitSignal(bridge.capabilities_changed, timeout=2000):
        bridge.ensure_connected()

    assert "passkey_get" in bridge.capabilities

    params = json.dumps({"rp_id": "example.com", "challenge": "abc123"})
    with qtbot.waitSignal(channel.passkey_result, timeout=2000) as blocker:
        channel.passkey_get("req-1", params)

    req_id, payload = blocker.args
    assert req_id == "req-1"
    result = json.loads(payload)
    assert result["authenticator_data_b64"] == "AAAA"
    assert result["signature_b64"] == "BBBB"
    assert (
        fake_sidecar.requests_for("passkey_get")[0]["params"]["rp_id"] == "example.com"
    )


def test_backend_offline(qtbot, qapp, monkeypatch, config_stub, caplog):
    """When the sidecar socket does not exist, the client emits an error signal."""
    config_stub.set_obj("onepassword.enabled", True)
    monkeypatch.setattr(
        "qutebrowser.browser.onepassword.client._socket_path",
        lambda: "/tmp/qute-1pass-nonexistent-e2e.sock",
    )
    bridge = OnePasswordBridge()
    errors: list[str] = []
    bridge._client.error.connect(errors.append)
    # The connection failure is intentional; suppress the log it produces.
    # Errors fire on 'misc' (client._on_error) and 'message' (_on_client_error);
    # a WARNING fires on 'misc' (_on_ping_result with "not connected" reply).
    # caplog.at_level(ERROR) on root suppresses ERRORs; nested WARNING on 'misc'
    # suppresses the WARNING — LogFailHandler skips when record.levelno == level.
    with caplog.at_level(logging.ERROR):
        with caplog.at_level(logging.WARNING, logger="misc"):
            bridge.ensure_connected()
            qtbot.wait(50)
    assert len(errors) > 0
    bridge.deleteLater()
