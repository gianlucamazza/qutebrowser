# SPDX-FileCopyrightText: Gianluca
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for OnePasswordChannel (QWebChannel autosave bridge)."""

import pytest

from qutebrowser.browser.onepassword.channel import OnePasswordChannel


class _FakeTab:
    abort_questions = None


class _FakeBridge:
    def __init__(self):
        self.saved: list[tuple[str, str, str]] = []

    def save(self, url: str, username: str, password: str) -> None:
        self.saved.append((url, username, password))


@pytest.fixture()
def bridge():
    return _FakeBridge()


@pytest.fixture()
def channel(qapp, config_stub, request, bridge):
    """OnePasswordChannel with a fully initialised config stub."""
    ch = OnePasswordChannel(_FakeTab(), bridge)
    request.addfinalizer(ch.deleteLater)
    return ch


def test_autosave_calls_bridge_on_yes(channel, bridge, monkeypatch):
    monkeypatch.setattr(
        "qutebrowser.browser.onepassword.channel.message.ask",
        lambda **_kw: True,
    )
    channel.autosave_requested("https://example.com", "alice", "s3cret")
    assert bridge.saved == [("https://example.com", "alice", "s3cret")]


def test_autosave_skips_bridge_on_no(channel, bridge, monkeypatch):
    monkeypatch.setattr(
        "qutebrowser.browser.onepassword.channel.message.ask",
        lambda **_kw: False,
    )
    channel.autosave_requested("https://example.com", "alice", "s3cret")
    assert bridge.saved == []


def test_autosave_skips_when_disabled(channel, bridge, config_stub):
    config_stub.set_obj("onepassword.autosave_on_submit", False)
    channel.autosave_requested("https://example.com", "alice", "s3cret")
    assert bridge.saved == []


def test_autosave_passes_empty_password_to_bridge(channel, bridge, monkeypatch):
    """The shim guards against empty passwords; the channel itself does not."""
    monkeypatch.setattr(
        "qutebrowser.browser.onepassword.channel.message.ask",
        lambda **_kw: True,
    )
    channel.autosave_requested("https://example.com", "alice", "")
    assert bridge.saved == [("https://example.com", "alice", "")]
