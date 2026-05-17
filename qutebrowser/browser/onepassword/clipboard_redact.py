# SPDX-FileCopyrightText: Gianluca
# SPDX-License-Identifier: GPL-3.0-or-later

"""Clipboard helpers with automatic redaction for secrets."""

from typing import Optional

from qutebrowser.qt.core import QTimer
from qutebrowser.utils import log, message, utils

_clear_timer: Optional[QTimer] = None
_last_secret: Optional[str] = None


def copy_secret(value: str, label: str, ttl_seconds: int = 30) -> None:
    """Copy *value* to clipboard and schedule auto-clear after *ttl_seconds*.

    If another copy_secret call arrives before the timer fires, the previous
    timer is cancelled and a new one is started. If the user copies something
    else before the timer fires, the clear is skipped (safe guard: we only
    clear if the clipboard still contains our secret).
    """
    global _clear_timer, _last_secret

    if _clear_timer is not None and _clear_timer.isActive():
        _clear_timer.stop()

    utils.set_clipboard(value)
    _last_secret = value

    log.misc.debug(
        f"1Password: {label} copied to clipboard; clearing in {ttl_seconds}s"
    )
    message.info(f"1Password: {label} copied — clearing in {ttl_seconds}s")

    _clear_timer = QTimer()
    _clear_timer.setSingleShot(True)
    _clear_timer.timeout.connect(lambda: _maybe_clear(value))
    _clear_timer.start(ttl_seconds * 1000)


def copy_plain(value: str, label: str) -> None:
    """Copy *value* to clipboard with no auto-clear (use for non-secret data)."""
    utils.set_clipboard(value)
    message.info(f"1Password: {label} copied")


def _maybe_clear(expected: str) -> None:
    """Clear clipboard only if it still contains the expected secret."""
    global _last_secret
    try:
        current = utils.get_clipboard()
    except utils.ClipboardError:
        return
    if current == expected:
        utils.set_clipboard("")
        _last_secret = None
        message.info("1Password: clipboard cleared")
