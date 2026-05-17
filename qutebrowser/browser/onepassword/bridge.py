# SPDX-FileCopyrightText: Gianluca
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tab-side bridge: connects OnePasswordClient to tab operations."""

from typing import Any, Optional

from qutebrowser.qt.core import QObject, pyqtSignal, pyqtSlot
from qutebrowser.browser.onepassword.client import OnePasswordClient
from qutebrowser.utils import log, message, utils


class OnePasswordBridge(QObject):
    """Manages a OnePasswordClient and exposes high-level fill/save operations.

    One instance per application; individual tab actions receive the active tab.
    """

    capabilities_changed = pyqtSignal()

    def __init__(self, parent: Optional[QObject] = None) -> None:
        super().__init__(parent)
        self._client = OnePasswordClient(self)
        self._client.error.connect(self._on_client_error)
        self._client.connected.connect(self._on_connected)
        self._client.disconnected.connect(self._on_disconnected)
        self._connected = False
        self._capabilities: set[str] = set()
        self._ping_done = False

    # ------------------------------------------------------------------
    # public
    # ------------------------------------------------------------------

    @property
    def capabilities(self) -> set[str]:
        """Last known backend capabilities; empty until first ping completes."""
        return self._capabilities

    def ensure_connected(self) -> None:
        """Connect to sidecar if not already connected; trigger ping once."""
        if not self._client.is_connected():
            self._client.connect_to_sidecar()
        if not self._ping_done:
            self._ping_done = True
            self.ping(self._on_ping_result)

    def disconnect(self) -> None:
        self._client.disconnect_from_sidecar()

    def fill(self, tab: Any, url: str, otp: bool = False) -> None:
        """Find credentials for url and fill the active tab's form."""
        self.ensure_connected()
        self._client.call(
            "find_items",
            {"url": url},
            lambda resp: self._on_find_items(resp, tab, url, otp),
        )

    def save(self, url: str, username: str, password: str) -> None:
        """Save a login to 1Password."""
        self.ensure_connected()
        self._client.call(
            "save_login",
            {"url": url, "username": username, "password": password},
            self._on_save_done,
        )

    def ping(self, callback: Any) -> None:
        self.ensure_connected()
        self._client.call("ping", {}, callback)

    def passkey_get(self, params: dict[str, Any], callback: Any) -> None:
        """Forward a passkey assertion request to the sidecar."""
        self.ensure_connected()
        self._client.call("passkey_get", params, callback)

    def passkey_create(self, params: dict[str, Any], callback: Any) -> None:
        """Forward a passkey registration request to the sidecar."""
        self.ensure_connected()
        self._client.call("passkey_create", params, callback)

    # ------------------------------------------------------------------
    # callbacks
    # ------------------------------------------------------------------

    def _on_ping_result(self, resp: dict[str, Any]) -> None:
        if "error" in resp:
            log.misc.warning(f"1Password: ping failed: {resp['error']['message']}")
            return
        caps = resp.get("result", {}).get("capabilities", [])
        self._capabilities = set(caps)
        log.misc.debug(f"1Password: backend capabilities: {sorted(self._capabilities)}")
        self.capabilities_changed.emit()

    def _on_find_items(
        self, resp: dict[str, Any], tab: Any, url: str, otp: bool
    ) -> None:
        if "error" in resp:
            message.error(f"1Password: {resp['error']['message']}")
            return
        items: list[dict[str, Any]] = resp.get("result", [])
        if not items:
            message.error(f"1Password: no items found for {url}")
            return
        # Use the highest-scoring match.
        # Multi-match selection is Phase B (autosave/prompt).
        best = items[0]
        self._client.call(
            "get_item",
            {"id": best["id"]},
            lambda r: self._on_got_item(r, tab, otp),
        )

    def _on_got_item(self, resp: dict[str, Any], tab: Any, otp: bool) -> None:
        if "error" in resp:
            message.error(f"1Password: {resp['error']['message']}")
            return
        item = resp.get("result", {})
        username = item.get("username", "")
        password = item.get("password", "")
        totp: Optional[str] = item.get("totp")

        tab.run_js_async(_build_fill_js(username, password))

        if otp and totp:
            utils.set_clipboard(totp)
            message.info("1Password: TOTP copied to clipboard.")
        elif otp and not totp:
            message.info("1Password: no TOTP field found for this item.")

    def _on_save_done(self, resp: dict[str, Any]) -> None:
        if "error" in resp:
            message.error(f"1Password: save failed: {resp['error']['message']}")
            return
        item_id = resp.get("result", {}).get("id", "?")
        message.info(f"1Password: login saved (id: {item_id}).")

    # ------------------------------------------------------------------
    # signal handlers
    # ------------------------------------------------------------------

    @pyqtSlot()
    def _on_connected(self) -> None:
        self._connected = True
        log.misc.debug("1Password: bridge connected")

    @pyqtSlot()
    def _on_disconnected(self) -> None:
        self._connected = False
        log.misc.debug("1Password: bridge disconnected")

    @pyqtSlot(str)
    def _on_client_error(self, err: str) -> None:
        message.error(err)


# ---------------------------------------------------------------------------
# JS helpers
# ---------------------------------------------------------------------------


def _js_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n")


def _build_fill_js(username: str, password: str) -> str:
    u = _js_escape(username)
    p = _js_escape(password)
    return f"""
(function() {{
    function isVisible(el) {{
        var s = el.ownerDocument.defaultView.getComputedStyle(el, null);
        return s.visibility !== 'hidden' && s.display !== 'none'
            && s.opacity !== '0' && el.offsetWidth > 0 && el.offsetHeight > 0;
    }}
    function fill(el, val) {{
        el.focus();
        var nativeSetter = Object.getOwnPropertyDescriptor(
            window.HTMLInputElement.prototype, 'value').set;
        nativeSetter.call(el, val);
        el.dispatchEvent(new Event('input', {{bubbles: true}}));
        el.dispatchEvent(new Event('change', {{bubbles: true}}));
        el.blur();
    }}
    document.querySelectorAll('form').forEach(function(form) {{
        var inputs = Array.from(form.querySelectorAll('input'));
        if (!inputs.some(i => i.type === 'password')) return;
        inputs.forEach(function(inp) {{
            if (!isVisible(inp)) return;
            if (inp.type === 'text' || inp.type === 'email') fill(inp, '{u}');
            if (inp.type === 'password') fill(inp, '{p}');
        }});
    }});
}})();
"""
