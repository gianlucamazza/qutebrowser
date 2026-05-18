# SPDX-FileCopyrightText: Gianluca Mazza <info@gianlucamazza.it>
# SPDX-License-Identifier: GPL-3.0-or-later

"""qutebrowser commands for 1Password integration."""

import shutil
import subprocess
from typing import TYPE_CHECKING

from qutebrowser.api import apitypes, cmdutils
from qutebrowser.completion.models import onepassword_model
from qutebrowser.utils import message, objreg, usertypes

if TYPE_CHECKING:
    from qutebrowser.browser.onepassword.bridge import OnePasswordBridge

_BRIDGE_KEY = "onepassword-bridge"
_onepassword_items_completion = onepassword_model.onepassword_items


def _bridge() -> "OnePasswordBridge":
    from qutebrowser.browser.onepassword.bridge import OnePasswordBridge

    b = objreg.get(_BRIDGE_KEY, default=None)
    if b is None:
        b = OnePasswordBridge()
        objreg.register(_BRIDGE_KEY, b)
    return b


def _check_enabled() -> bool:
    from qutebrowser.config import config

    if not config.val.onepassword.enabled:
        message.error(
            "1Password integration is disabled. "
            "Set onepassword.enabled = true to use it."
        )
        return False
    return True


@cmdutils.register()
@cmdutils.argument("tab", value=cmdutils.Value.cur_tab)
@cmdutils.argument("item_id", completion=_onepassword_items_completion)
def onepassword_pick(tab: apitypes.Tab, item_id: str) -> None:
    """Choose a 1Password item from a completion list and fill the form.

    Opens a completion popup with vault items matching the current page URL.
    Select an item with Tab/Enter to fill the form, or type part of the title
    or username to filter. Requires ``op`` CLI v2 to be on PATH and authenticated.

    Args:
        item_id: The vault item ID to use (selected via completion).
    """
    if not _check_enabled():
        return
    if not item_id:
        raise cmdutils.CommandError("No item selected.")
    _bridge().fill_by_id(tab, item_id)


@cmdutils.register()
@cmdutils.argument("tab", value=cmdutils.Value.cur_tab)
def onepassword_fill(tab: apitypes.Tab, otp: bool = False) -> None:
    """Fill the current page's login form from 1Password.

    When exactly one vault item matches the page URL, fills directly.
    When multiple items match (e.g. credentials in different vaults),
    opens the :onepassword-pick completion so the user can choose
    explicitly — no silent guessing.

    Args:
        otp: Also copy the TOTP code to the clipboard.
    """
    if not _check_enabled():
        return
    url = tab.url().toString()

    def _on_matches(matches, err):
        if err:
            message.error(f"1Password: {err}")
            return
        if not matches:
            message.info(f"1Password: no items found for {url}")
            return
        if len(matches) == 1:
            _bridge().fill_by_id(tab, matches[0]["id"], otp=otp)
            return
        message.info(f"1Password: {len(matches)} items match — opening picker")
        cmd = objreg.get("status-command", scope="window", window=tab.win_id)
        cmd.cmd_set_text(":onepassword-pick ")

    _bridge().find_matches(url, _on_matches)


@cmdutils.register()
@cmdutils.argument("tab", value=cmdutils.Value.cur_tab)
def onepassword_fill_field(tab: apitypes.Tab) -> None:
    """Fill only the currently focused input field using 1Password.

    Unlike ``onepassword-fill``, this command targets the single focused
    element and uses its ``type``, ``autocomplete``, and ``name`` attributes
    to decide whether to inject the username or the password.  Useful for
    multi-step login forms (e.g. Google, Microsoft) that show username and
    password on separate pages.

    Bind it to a key and press it while the input field is focused.
    """
    if not _check_enabled():
        return
    _bridge().fill_field(tab, tab.url().toString())


@cmdutils.register()
@cmdutils.argument("tab", value=cmdutils.Value.cur_tab)
def onepassword_save(tab: apitypes.Tab) -> None:
    """Prompt for credentials and save them to 1Password for the current URL.

    Args:
        tab: The current tab (injected automatically).
    """
    if not _check_enabled():
        return
    url = tab.url().toString()

    username = message.ask(
        title="1Password: save login",
        text=f"Username for {url}:",
        mode=usertypes.PromptMode.text,
        abort_on=[tab.abort_questions],
    )
    if username is None:
        return

    password = message.ask(
        title="1Password: save login",
        text=f"Password for {url}:",
        mode=usertypes.PromptMode.pwd,
        abort_on=[tab.abort_questions],
    )
    if password is None:
        return

    _bridge().save(url, username, password)


@cmdutils.register()
def onepassword_restart_sidecar() -> None:
    """Disconnect from and relaunch the 1Password sidecar process.

    The sidecar binary ``qute-1pass-sidecar`` must be on PATH.
    """
    if not _check_enabled():
        return
    from qutebrowser.config import config

    sidecar = shutil.which("qute-1pass-sidecar")
    if sidecar is None:
        raise cmdutils.CommandError(
            "qute-1pass-sidecar not found on PATH. "
            "See misc/onepassword-sidecar/ for installation."
        )

    backend = config.val.onepassword.backend
    if backend == "native" and not config.val.onepassword.experimental_bridge:
        raise cmdutils.CommandError(
            "native backend requires onepassword.experimental_bridge = true. "
            "Warning: this backend reverse-engineers 1Password's internal protocol "
            "and may violate 1Password's Terms of Service."
        )

    b = objreg.get(_BRIDGE_KEY, default=None)
    if b is not None:
        b.disconnect()

    cmd = [sidecar, "--backend", backend]
    socket_path = config.val.onepassword.socket_path
    if socket_path:
        cmd += ["--socket-path", socket_path]

    subprocess.Popen(cmd, start_new_session=True)
    message.info("1Password: sidecar restarted.")


@cmdutils.register()
def onepassword_status() -> None:
    """Show 1Password sidecar connection status and capabilities."""
    if not _check_enabled():
        return
    b = _bridge()
    if not b.is_connected():
        message.info("1Password: sidecar not connected")
        return

    def _show(resp: dict[str, object]) -> None:
        if "error" in resp:
            message.error(f"1Password: {resp['error']['message']}")
            return
        r = resp.get("result", {})
        backend = r.get("backend", "?")
        if r.get("degraded"):
            backend = (
                f"{backend} (degraded from {r.get('degraded_from', '?')}: "
                f"{r.get('degraded_reason', '?')})"
            )
        message.info(
            f"1Password: backend={backend}, "
            f"locked={r.get('locked', False)}, "
            f"capabilities={sorted(b.capabilities)}"
        )

    b.ping(_show)


@cmdutils.register()
@cmdutils.argument("tab", value=cmdutils.Value.cur_tab)
def onepassword_copy_username(tab: apitypes.Tab) -> None:
    """Copy the username for the current page from 1Password."""
    if not _check_enabled():
        return
    from qutebrowser.browser.onepassword.clipboard_redact import copy_plain

    def _cb(item: dict[str, object] | None, err: str | None) -> None:
        if err:
            message.error(f"1Password: {err}")
            return
        assert item is not None
        copy_plain(item.get("username", ""), "username")

    _bridge().get_credentials(tab.url().toString(), _cb)


@cmdutils.register()
@cmdutils.argument("tab", value=cmdutils.Value.cur_tab)
def onepassword_copy_password(tab: apitypes.Tab) -> None:
    """Copy the password for the current page from 1Password (auto-clears in 30s)."""
    if not _check_enabled():
        return
    from qutebrowser.browser.onepassword.clipboard_redact import copy_secret

    def _cb(item: dict[str, object] | None, err: str | None) -> None:
        if err:
            message.error(f"1Password: {err}")
            return
        assert item is not None
        copy_secret(item.get("password", ""), "password")

    _bridge().get_credentials(tab.url().toString(), _cb)


@cmdutils.register()
@cmdutils.argument("tab", value=cmdutils.Value.cur_tab)
def onepassword_copy_totp(tab: apitypes.Tab) -> None:
    """Copy the TOTP code for the current page from 1Password (auto-clears in 30s).

    Prefer this over ``onepassword-fill --otp`` when you need the code without
    filling the form (e.g. for a second-factor prompt on a different step).
    """
    if not _check_enabled():
        return
    from qutebrowser.browser.onepassword.clipboard_redact import copy_secret

    def _cb(item: dict[str, object] | None, err: str | None) -> None:
        if err:
            message.error(f"1Password: {err}")
            return
        assert item is not None
        totp = item.get("totp")
        if not totp:
            message.error("1Password: no TOTP field found for this item.")
            return
        copy_secret(totp, "TOTP")

    _bridge().get_credentials(tab.url().toString(), _cb)
