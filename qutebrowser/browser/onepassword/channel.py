# SPDX-FileCopyrightText: Gianluca Mazza <info@gianlucamazza.it>
# SPDX-License-Identifier: GPL-3.0-or-later

"""QWebChannel-exposed QObject for the 1Password autosave bridge."""

import json
from typing import Any, Optional

from qutebrowser.qt.core import QObject, pyqtSignal, pyqtSlot
from qutebrowser.qt.webchannel import QWebChannel
from qutebrowser.utils import log, message, usertypes


class OnePasswordChannel(QObject):
    """Receives calls from page JS via QWebChannel.

    One instance per tab; delegates saves and passkey operations to
    the global OnePasswordBridge.
    """

    # Passkey async responses: (req_id, json_payload)
    passkey_result = pyqtSignal(str, str)
    passkey_error = pyqtSignal(str, str)
    # Forwarded from bridge when backend capabilities become known
    capabilities_changed = pyqtSignal()

    def __init__(self, tab: Any, bridge: Any, parent: Optional[QObject] = None) -> None:
        super().__init__(parent)
        self._tab = tab
        self._bridge = bridge
        self._bridge.capabilities_changed.connect(self.capabilities_changed)

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

    @pyqtSlot(result=str)
    def capabilities(self) -> str:
        """Return JSON array of backend capabilities (may be empty before ping)."""
        return json.dumps(sorted(self._bridge.capabilities))

    @pyqtSlot(str, str)
    def passkey_get(self, req_id: str, json_params: str) -> None:
        """Request a passkey assertion; emits passkey_result or passkey_error."""
        if "passkey_get" not in self._bridge.capabilities:
            self.passkey_error.emit(req_id, "capability not available")
            return
        try:
            params = json.loads(json_params)
        except json.JSONDecodeError as e:
            self.passkey_error.emit(req_id, f"invalid params: {e}")
            return
        self._bridge.passkey_get(params, lambda r: self._on_passkey_resp(req_id, r))

    @pyqtSlot(str, str)
    def passkey_create(self, req_id: str, json_params: str) -> None:
        """Request passkey registration; emits passkey_result or passkey_error."""
        if "passkey_create" not in self._bridge.capabilities:
            self.passkey_error.emit(req_id, "capability not available")
            return
        try:
            params = json.loads(json_params)
        except json.JSONDecodeError as e:
            self.passkey_error.emit(req_id, f"invalid params: {e}")
            return
        self._bridge.passkey_create(params, lambda r: self._on_passkey_resp(req_id, r))

    def _on_passkey_resp(self, req_id: str, resp: dict[str, Any]) -> None:
        if "error" in resp:
            self.passkey_error.emit(req_id, resp["error"]["message"])
        else:
            self.passkey_result.emit(req_id, json.dumps(resp.get("result", {})))


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
