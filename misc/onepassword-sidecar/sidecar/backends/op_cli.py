# SPDX-FileCopyrightText: Gianluca Mazza <info@gianlucamazza.it>
# SPDX-License-Identifier: GPL-3.0-or-later

"""1Password op CLI v2 backend."""

import json
import subprocess
import urllib.parse
from typing import Any

from publicsuffixlist import PublicSuffixList

from sidecar.backends.base import OnePasswordBackend

_PSL = PublicSuffixList()


class OpCliError(Exception):
    pass


def _hosts_match(host: str, item_host: str) -> bool:
    """Subdomain-aware host match using the Mozilla Public Suffix List.

    Matches when both hosts are equal or share the same registrable domain
    (eTLD+1) as computed via the Public Suffix List. This correctly handles:
    - locale subdomains: 'it-it.facebook.com' and 'www.facebook.com' both
      reduce to 'facebook.com' → match
    - genuine subdomains: 'api.github.com' and 'github.com' → match
    - lookalikes: 'evilgithub.com' vs 'github.com' → no match
    - ccTLDs: 'app.bar.co.uk' vs 'app.baz.co.uk' → no match ('co.uk' is a
      public suffix; their eTLD+1 are 'bar.co.uk' and 'baz.co.uk')
    - shared PaaS hosts: 'app1.herokuapp.com' vs 'app2.herokuapp.com' →
      no match ('herokuapp.com' is a public suffix)

    Hosts without a PSL suffix (localhost, raw IPs) fall back to strict
    equality via the first check.
    """
    if not host or not item_host:
        return False
    if host == item_host:
        return True
    h_etld1 = _PSL.privatesuffix(host)
    i_etld1 = _PSL.privatesuffix(item_host)
    if not h_etld1 or not i_etld1:
        return False
    return h_etld1 == i_etld1


class OpCliBackend(OnePasswordBackend):
    """Backend using the official `op` CLI v2 (biometric unlock supported)."""

    def capabilities(self) -> set[str]:
        return {"fill", "save", "totp"}

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _run(self, *args: str) -> Any:
        try:
            result = subprocess.run(
                ["op", *args, "--format=json"],
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            raise OpCliError(e.stderr.strip()) from e
        return json.loads(result.stdout)

    def _run_plain(self, *args: str) -> str:
        """Run op command that returns plain text (e.g. --otp)."""
        try:
            result = subprocess.run(
                ["op", *args],
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            raise OpCliError(e.stderr.strip()) from e
        return result.stdout.strip()

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    def find_items(self, url: str) -> list[dict[str, Any]]:
        host = urllib.parse.urlparse(url).hostname or url
        items: list[dict[str, Any]] = self._run("item", "list", "--categories=Login")
        results = []
        for item in items:
            urls = item.get("urls") or []
            matched = False
            for u in urls:
                href = u.get("href", "")
                item_host = urllib.parse.urlparse(href).hostname or ""
                if _hosts_match(host, item_host):
                    matched = True
                    break
            if not matched:
                continue
            results.append(
                {
                    "id": item["id"],
                    "title": item.get("title", ""),
                    "username": item.get("additional_information", ""),
                    "vault": item.get("vault", {}).get("name", ""),
                    "url_match_score": 1,
                }
            )
        return results

    def get_item(self, item_id: str, reveal: bool = True) -> dict[str, Any]:
        args = ["item", "get", item_id]
        if reveal:
            args.append("--reveal")
        raw = self._run(*args)
        fields = raw.get("fields", [])
        username = ""
        password = ""
        for f in fields:
            purpose = f.get("purpose", "")
            if purpose == "USERNAME":
                username = f.get("value", "")
            elif purpose == "PASSWORD":
                password = f.get("value", "")

        totp = None
        for f in fields:
            if f.get("type") == "OTP":
                try:
                    totp = self._run_plain("item", "get", item_id, "--otp")
                except OpCliError:
                    pass
                break

        return {
            "username": username,
            "password": password,
            "totp": totp,
            "fields": fields,
        }

    def save_login(
        self,
        url: str,
        username: str,
        password: str,
        title: str | None = None,
    ) -> dict[str, Any]:
        host = urllib.parse.urlparse(url).hostname or url
        item_title = title or host
        args = [
            "item",
            "create",
            "--category=Login",
            f"--title={item_title}",
            f"--url={url}",
            f"username={username}",
            f"password={password}",
        ]
        raw = self._run(*args)
        return {"id": raw["id"]}
