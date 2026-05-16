# SPDX-FileCopyrightText: Gianluca
# SPDX-License-Identifier: GPL-3.0-or-later

"""qutebrowser commands for 1Password integration."""

import shutil
import subprocess

from qutebrowser.api import apitypes, cmdutils
from qutebrowser.utils import message, objreg, usertypes

_BRIDGE_KEY = "onepassword-bridge"


def _bridge() -> "OnePasswordBridge":  # type: ignore[name-defined]  # noqa: F821
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
def onepassword_fill(tab: apitypes.Tab, otp: bool = False) -> None:
    """Fill the current page's login form from 1Password.

    Args:
        otp: Also copy the TOTP code to the clipboard.
    """
    if not _check_enabled():
        return
    _bridge().fill(tab, tab.url().toString(), otp=otp)


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

    sidecar = shutil.which("qute-1pass-sidecar")
    if sidecar is None:
        raise cmdutils.CommandError(
            "qute-1pass-sidecar not found on PATH. "
            "See misc/onepassword-sidecar/ for installation."
        )

    b = objreg.get(_BRIDGE_KEY, default=None)
    if b is not None:
        b.disconnect()

    subprocess.Popen([sidecar], start_new_session=True)  # noqa: S603
    message.info("1Password: sidecar restarted.")
