# SPDX-FileCopyrightText: Gianluca
# SPDX-License-Identifier: GPL-3.0-or-later

"""Abstract base class for 1Password sidecar backends."""

import abc
from typing import Any


class OnePasswordBackend(abc.ABC):
    """Abstract backend; concrete impls are OpCliBackend and NativeProtocolBackend."""

    @abc.abstractmethod
    def capabilities(self) -> set[str]:
        """Return set of supported features.

        Known tokens: 'fill', 'save', 'totp', 'passkey_get', 'passkey_create'.
        """

    @abc.abstractmethod
    def find_items(self, url: str) -> list[dict[str, Any]]:
        """Return matching login items for url.

        Each item: {id, title, username, url_match_score}.
        """

    @abc.abstractmethod
    def get_item(self, item_id: str, reveal: bool = True) -> dict[str, Any]:
        """Return item fields: {username, password, totp?, fields:[...]}."""

    @abc.abstractmethod
    def save_login(
        self,
        url: str,
        username: str,
        password: str,
        title: str | None = None,
    ) -> dict[str, Any]:
        """Create a new login item. Returns {id}."""

    def passkey_get(
        self, rp_id: str, challenge: str, allow_credentials: list[str]
    ) -> dict[str, Any]:
        """Sign a WebAuthn assertion. Default: not supported."""
        raise NotImplementedError("passkey_get not supported by this backend")

    def passkey_create(
        self,
        rp_id: str,
        user: dict[str, Any],
        challenge: str,
        pub_key_cred_params: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Create a new passkey credential. Default: not supported."""
        raise NotImplementedError("passkey_create not supported by this backend")
