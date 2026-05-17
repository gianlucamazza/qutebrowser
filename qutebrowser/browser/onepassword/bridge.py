# SPDX-FileCopyrightText: Gianluca
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tab-side bridge: connects OnePasswordClient to tab operations."""

from typing import Any, Optional

from qutebrowser.qt.core import QObject, pyqtSignal, pyqtSlot
from qutebrowser.browser.onepassword.client import OnePasswordClient
from qutebrowser.utils import log, message


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
        self._backend_status: dict[str, Any] = {}
        self._ping_done = False

    # ------------------------------------------------------------------
    # public
    # ------------------------------------------------------------------

    @property
    def capabilities(self) -> set[str]:
        """Last known backend capabilities; empty until first ping completes."""
        return self._capabilities

    @property
    def backend_status(self) -> dict[str, Any]:
        """Last known backend status fields (all ping result fields except capabilities)."""
        return self._backend_status

    def ensure_connected(self) -> None:
        """Connect to sidecar if not already connected; trigger ping once."""
        if not self._client.is_connected():
            self._client.connect_to_sidecar()
        if not self._ping_done:
            self._ping_done = True
            self.ping(self._on_ping_result)

    def is_connected(self) -> bool:
        return self._client.is_connected()

    def disconnect(self) -> None:
        self._client.disconnect_from_sidecar()

    def fill(self, tab: Any, url: str, otp: bool = False) -> None:
        """Find credentials for url and fill the active tab's form."""
        self.ensure_connected()
        self.get_credentials(
            url,
            lambda item, err: self._on_credentials_for_fill(item, err, tab, otp),
        )

    def get_credentials(
        self,
        url: str,
        callback: Any,
        *,
        hint_alternatives: bool = True,
    ) -> None:
        """find_items + get_item pipeline; callback(item_dict | None, error_msg | None).

        If *hint_alternatives* is True and more than one item matches, a
        :message.info hint is shown before proceeding with the best match.
        """
        self.ensure_connected()

        def _on_find(resp: dict[str, Any]) -> None:
            if "error" in resp:
                callback(None, resp["error"]["message"])
                return
            items: list[dict[str, Any]] = resp.get("result", [])
            if not items:
                callback(None, f"no items found for {url}")
                return
            if hint_alternatives and len(items) > 1:
                message.info(
                    f"1Password: {len(items)} items match — using "
                    f"'{items[0].get('title', items[0]['id'])}'; "
                    ":onepassword-pick to choose differently"
                )
            self._client.call("get_item", {"id": items[0]["id"]}, _on_get)

        def _on_get(resp: dict[str, Any]) -> None:
            if "error" in resp:
                callback(None, resp["error"]["message"])
                return
            callback(resp.get("result", {}), None)

        self._client.call("find_items", {"url": url}, _on_find)

    def fill_by_id(self, tab: Any, item_id: str) -> None:
        """Fetch a specific vault item by ID and fill the current page's form."""
        self.ensure_connected()

        def _on_get(resp: dict[str, Any]) -> None:
            if "error" in resp:
                message.error(f"1Password: {resp['error']['message']}")
                return
            self._on_credentials_for_fill(resp.get("result", {}), None, tab, False)

        self._client.call("get_item", {"id": item_id}, _on_get)

    def fill_field(self, tab: Any, url: str) -> None:
        """Fill only the currently focused input field.

        Inspects the focused element's type/autocomplete/name attributes to decide
        whether to inject the username or the password. Useful for multi-step login
        forms where username and password appear on separate pages.
        """
        self.ensure_connected()
        self.get_credentials(
            url,
            lambda item, err: self._on_credentials_for_fill_field(item, err, tab),
            hint_alternatives=False,
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
        result = resp.get("result", {})
        caps = result.get("capabilities", [])
        self._capabilities = set(caps)
        self._backend_status = {k: v for k, v in result.items() if k != "capabilities"}
        log.misc.debug(f"1Password: backend capabilities: {sorted(self._capabilities)}")
        self.capabilities_changed.emit()

    def _on_credentials_for_fill(
        self, item: dict[str, Any] | None, err: str | None, tab: Any, otp: bool
    ) -> None:
        if err:
            message.error(f"1Password: {err}")
            return
        assert item is not None
        username = item.get("username", "")
        password = item.get("password", "")
        totp: Optional[str] = item.get("totp")

        tab.run_js_async(_build_fill_js(username, password))

        if otp and totp:
            from qutebrowser.browser.onepassword.clipboard_redact import copy_secret

            copy_secret(totp, "TOTP")
        elif otp and not totp:
            message.info("1Password: no TOTP field found for this item.")

    def _on_credentials_for_fill_field(
        self, item: dict[str, Any] | None, err: str | None, tab: Any
    ) -> None:
        if err:
            message.error(f"1Password: {err}")
            return
        assert item is not None
        username = item.get("username", "")
        password = item.get("password", "")
        tab.run_js_async(_build_fill_field_js(username, password))

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
    return (
        s.replace("\\", "\\\\")
        .replace("'", "\\'")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace(" ", "\\u2028")
        .replace(" ", "\\u2029")
    )


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


def _build_fill_field_js(username: str, password: str) -> str:
    """Return JS that fills only document.activeElement based on its field type.

    Uses autocomplete, type, and name attributes to decide whether to inject
    the username or the password. Returns a JSON string describing what was
    done (or an error) so callers can log the outcome.
    """
    u = _js_escape(username)
    p = _js_escape(password)
    return f"""
(function() {{
    var el = document.activeElement;
    if (!el || el.tagName !== 'INPUT') {{
        return JSON.stringify({{error: 'no focused input element'}});
    }}
    var t = (el.type || '').toLowerCase();
    var ac = (el.autocomplete || '').toLowerCase();
    var name = (el.name || el.id || '').toLowerCase();
    var kind = 'unknown';
    if (t === 'password' || ac.includes('password') || /pass/.test(name)) {{
        kind = 'password';
    }} else if (
        t === 'email' || ac.includes('username') || ac.includes('email') ||
        /user|login|email|mail/.test(name)
    ) {{
        kind = 'username';
    }}
    if (kind === 'unknown') {{
        return JSON.stringify({{error: 'cannot detect field type (type=' + t + ', autocomplete=' + ac + ', name=' + name + ')'}});
    }}
    var val = kind === 'password' ? '{p}' : '{u}';
    var nativeSetter = Object.getOwnPropertyDescriptor(
        window.HTMLInputElement.prototype, 'value').set;
    nativeSetter.call(el, val);
    el.dispatchEvent(new Event('input', {{bubbles: true}}));
    el.dispatchEvent(new Event('change', {{bubbles: true}}));
    return JSON.stringify({{kind: kind}});
}})();
"""
