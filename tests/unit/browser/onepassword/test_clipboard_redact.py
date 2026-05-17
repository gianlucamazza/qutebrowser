# SPDX-FileCopyrightText: Gianluca
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for clipboard_redact helpers."""

import pytest

from qutebrowser.browser.onepassword import clipboard_redact


@pytest.fixture(autouse=True)
def _reset_state():
    """Reset module-level timer/secret state between tests."""
    if clipboard_redact._clear_timer is not None:
        clipboard_redact._clear_timer.stop()
    clipboard_redact._clear_timer = None
    clipboard_redact._last_secret = None
    yield
    if clipboard_redact._clear_timer is not None:
        clipboard_redact._clear_timer.stop()
    clipboard_redact._clear_timer = None
    clipboard_redact._last_secret = None


@pytest.fixture()
def clipboard(monkeypatch):
    """Fake clipboard backed by a dict."""
    store = {"value": ""}

    monkeypatch.setattr(
        "qutebrowser.browser.onepassword.clipboard_redact.utils.set_clipboard",
        lambda v, **_: store.__setitem__("value", v),
    )
    monkeypatch.setattr(
        "qutebrowser.browser.onepassword.clipboard_redact.utils.get_clipboard",
        lambda **_: store["value"],
    )
    monkeypatch.setattr(
        "qutebrowser.browser.onepassword.clipboard_redact.message.info",
        lambda *a: None,
    )
    return store


def test_copy_secret_sets_clipboard(qapp, clipboard):
    clipboard_redact.copy_secret("s3cr3t", "password", ttl_seconds=60)
    assert clipboard["value"] == "s3cr3t"


def test_copy_secret_starts_timer(qapp, clipboard):
    clipboard_redact.copy_secret("s3cr3t", "password", ttl_seconds=60)
    assert clipboard_redact._clear_timer is not None
    assert clipboard_redact._clear_timer.isActive()


def test_maybe_clear_clears_when_unchanged(qapp, clipboard):
    clipboard["value"] = "s3cr3t"
    clipboard_redact._maybe_clear("s3cr3t")
    assert clipboard["value"] == ""


def test_maybe_clear_skips_when_changed(qapp, clipboard):
    clipboard["value"] = "something_else"
    clipboard_redact._maybe_clear("s3cr3t")
    assert clipboard["value"] == "something_else"


def test_copy_secret_cancels_previous_timer(qapp, clipboard):
    clipboard_redact.copy_secret("first", "password", ttl_seconds=60)
    first_timer = clipboard_redact._clear_timer
    clipboard_redact.copy_secret("second", "password", ttl_seconds=60)
    assert not first_timer.isActive()
    assert clipboard_redact._clear_timer is not first_timer
    assert clipboard["value"] == "second"


def test_copy_plain_sets_clipboard_no_timer(qapp, clipboard):
    clipboard_redact.copy_plain("user@example.com", "username")
    assert clipboard["value"] == "user@example.com"
    assert clipboard_redact._clear_timer is None
