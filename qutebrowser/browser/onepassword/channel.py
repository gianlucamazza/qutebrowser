# SPDX-FileCopyrightText: Gianluca
# SPDX-License-Identifier: GPL-3.0-or-later

"""QWebChannel-exposed QObject for the 1Password autosave bridge."""

from typing import Any, Optional

from qutebrowser.qt.core import QObject, pyqtSlot
from qutebrowser.qt.webchannel import QWebChannel
from qutebrowser.utils import log, message, usertypes


class OnePasswordChannel(QObject):
    """Receives autosave_requested() calls from page JS via QWebChannel.

    One instance per tab; holds a weak reference to the tab for prompt
    abort signalling and delegates saves to the global OnePasswordBridge.
    """

    def __init__(self, tab: Any, bridge: Any, parent: Optional[QObject] = None) -> None:
        super().__init__(parent)
        self._tab = tab
        self._bridge = bridge

    @pyqtSlot(str, str, str)
    def autosave_requested(self, url: str, username: str, password: str) -> None:
        """Called by the in-page shim when a password form is submitted."""
        from qutebrowser.config import config

        if not config.val.onepassword.autosave_on_submit:
            return

        log.misc.debug(f"1Password: autosave requested for {url!r}")

        answer = message.ask(
            title="1Password: save login?",
            text=(
                f"Save credentials for <b>{url}</b> to 1Password?"
                "<br>Username: <tt>{}</tt>".format(username or "(empty)")
            ),
            mode=usertypes.PromptMode.yesno,
            abort_on=[self._tab.abort_questions],
        )
        if answer:
            self._bridge.save(url, username, password)


def setup_for_page(page: Any, tab: Any, bridge: Any) -> QWebChannel:
    """Create a QWebChannel wired to the given page in MainWorld.

    Returns the channel so the caller can keep it alive (the page does not
    take ownership when worldId != 0).
    """
    channel = QWebChannel(parent=page)
    op_obj = OnePasswordChannel(tab, bridge, parent=channel)
    channel.registerObject("onepassword", op_obj)
    # worldId=0 exposes qt.webChannelTransport in MainWorld JS.
    page.setWebChannel(channel, 0)
    return channel
