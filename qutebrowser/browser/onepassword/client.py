# SPDX-FileCopyrightText: Gianluca Mazza <info@gianlucamazza.it>
# SPDX-License-Identifier: GPL-3.0-or-later

"""Async JSON-RPC 2.0 client connecting to the 1Password sidecar over a Unix socket."""

import json
import os
import pathlib
from collections.abc import Callable
from typing import Any, Optional

from qutebrowser.qt.core import QObject, QTimer, pyqtSignal, pyqtSlot
from qutebrowser.qt.network import QLocalSocket
from qutebrowser.utils import log


def _socket_path() -> str:
    from qutebrowser.config import config

    custom = config.val.onepassword.socket_path
    if custom:
        return custom
    runtime = os.environ.get("XDG_RUNTIME_DIR", "/tmp")
    return str(pathlib.Path(runtime) / "qute-1pass.sock")


class OnePasswordClient(QObject):
    """Non-blocking JSON-RPC client for the 1Password sidecar.

    Signals:
        connected: Emitted when the socket connects successfully.
        disconnected: Emitted when the socket disconnects.
        error: Emitted with a human-readable error string.
    """

    connected = pyqtSignal()
    disconnected = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, parent: Optional[QObject] = None) -> None:
        super().__init__(parent)
        self._socket = QLocalSocket(self)
        self._buf = b""
        self._pending: dict[int, Callable[[dict[str, Any]], None]] = {}
        self._next_id = 1
        self._socket.connected.connect(self._on_connected)
        self._socket.disconnected.connect(self._on_disconnected)
        self._socket.readyRead.connect(self._on_ready_read)
        self._socket.errorOccurred.connect(self._on_error)

    # ------------------------------------------------------------------
    # public
    # ------------------------------------------------------------------

    def connect_to_sidecar(self) -> None:
        """Initiate connection to the sidecar socket."""
        path = _socket_path()
        log.misc.debug(f"1Password: connecting to {path}")
        self._socket.connectToServer(path)

    def disconnect_from_sidecar(self) -> None:
        self._socket.disconnectFromServer()

    def is_connected(self) -> bool:
        return self._socket.state() == QLocalSocket.LocalSocketState.ConnectedState

    def call(
        self,
        method: str,
        params: dict[str, Any],
        callback: Callable[[dict[str, Any]], None],
    ) -> None:
        """Send a JSON-RPC request; call callback(result_or_error_dict) on reply."""
        if not self.is_connected():
            log.misc.debug(f"1Password: call {method!r} dropped, not connected")
            callback({"error": {"code": -32000, "message": "sidecar not connected"}})
            return
        req_id = self._next_id
        self._next_id += 1
        self._pending[req_id] = callback
        payload = (
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "method": method,
                    "params": params,
                }
            )
            + "\n"
        )
        self._socket.write(payload.encode())

    # ------------------------------------------------------------------
    # slots
    # ------------------------------------------------------------------

    @pyqtSlot()
    def _on_connected(self) -> None:
        log.misc.debug("1Password: sidecar connected")
        self.connected.emit()

    @pyqtSlot()
    def _on_disconnected(self) -> None:
        log.misc.debug("1Password: sidecar disconnected")
        self._buf = b""
        self.disconnected.emit()

    @pyqtSlot()
    def _on_ready_read(self) -> None:
        self._buf += bytes(self._socket.readAll())
        while b"\n" in self._buf:
            line, self._buf = self._buf.split(b"\n", 1)
            self._dispatch(line.decode())

    @pyqtSlot(QLocalSocket.LocalSocketError)
    def _on_error(self, err: QLocalSocket.LocalSocketError) -> None:
        msg = self._socket.errorString()
        log.misc.error(f"1Password: socket error {err}: {msg}")
        self.error.emit(f"1Password sidecar error: {msg}")

    # ------------------------------------------------------------------
    # internal
    # ------------------------------------------------------------------

    def _dispatch(self, raw: str) -> None:
        try:
            resp = json.loads(raw)
        except json.JSONDecodeError:
            log.misc.error(f"1Password: bad JSON from sidecar: {raw!r}")
            return
        req_id = resp.get("id")
        cb = self._pending.pop(req_id, None)
        if cb is None:
            log.misc.warning(f"1Password: no pending callback for id {req_id}")
            return
        cb(resp)
