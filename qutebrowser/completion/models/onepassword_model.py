# SPDX-FileCopyrightText: Gianluca
# SPDX-License-Identifier: GPL-3.0-or-later

"""Completion model for 1Password vault item selection."""

import json
import shutil
import subprocess

from qutebrowser.completion.models import completionmodel, listcategory


def onepassword_items(*, info):
    """CompletionModel with 1Password items matching the current page URL.

    Calls ``op item list`` synchronously with a 3-second timeout.  Returns an
    empty model if ``op`` is not on PATH, not authenticated, or the call times
    out — the command will show an error when the user selects nothing.
    """
    model = completionmodel.CompletionModel(column_widths=(35, 55, 10))

    url = ""
    if info.cur_tab is not None:
        url = info.cur_tab.url().toString()

    entries = _fetch_items(url)
    model.add_category(listcategory.ListCategory("1Password Items", entries))
    return model


def _fetch_items(url: str) -> list[tuple[str, str, str]]:
    op = shutil.which("op")
    if not op:
        return []

    cmd = [op, "item", "list", "--categories", "Login", "--format", "json"]
    if url:
        cmd += ["--url", url]

    try:
        result = subprocess.run(  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            timeout=3,
        )
        if result.returncode != 0:
            return []
        items = json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return []

    entries = []
    for item in items:
        item_id = item.get("id", "")
        title = item.get("title", "?")
        username = ""
        for field in item.get("fields", []):
            if field.get("purpose") == "USERNAME":
                username = field.get("value", "")
                break
        entries.append((item_id, title, username))
    return entries
