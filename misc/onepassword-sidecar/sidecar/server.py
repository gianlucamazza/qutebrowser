# SPDX-FileCopyrightText: Gianluca
# SPDX-License-Identifier: GPL-3.0-or-later

"""JSON-RPC 2.0 server over a Unix domain socket."""

import json
import logging
import os
import pathlib
import socket
import threading
from typing import Any

from sidecar.backends.base import OnePasswordBackend
from sidecar.backends.op_cli import OpCliBackend, OpCliError

log = logging.getLogger("qute-1pass")

_METHODS = {
    "ping",
    "find_items",
    "get_item",
    "save_login",
    "passkey_get",
    "passkey_create",
}


def _socket_path() -> pathlib.Path:
    runtime = os.environ.get("XDG_RUNTIME_DIR", "/tmp")
    return pathlib.Path(runtime) / "qute-1pass.sock"


class SidecarServer:
    def __init__(self, backend: OnePasswordBackend | None = None) -> None:
        self._backend: OnePasswordBackend = backend or OpCliBackend()
        self._sock: socket.socket | None = None
        self._path = _socket_path()

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        if self._path.exists():
            self._path.unlink()
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(str(self._path))
        self._path.chmod(0o600)
        self._sock.listen(8)
        log.info(
            "Listening on %s (backend: %s)", self._path, type(self._backend).__name__
        )
        try:
            while True:
                conn, _ = self._sock.accept()
                t = threading.Thread(target=self._handle, args=(conn,), daemon=True)
                t.start()
        except OSError:
            pass  # socket closed by stop()

    def stop(self) -> None:
        if self._sock:
            self._sock.close()
        if self._path.exists():
            self._path.unlink()

    # ------------------------------------------------------------------
    # connection handler
    # ------------------------------------------------------------------

    def _handle(self, conn: socket.socket) -> None:
        buf = b""
        with conn:
            while chunk := conn.recv(4096):
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    response = self._dispatch(line.decode())
                    conn.sendall((json.dumps(response) + "\n").encode())

    def _dispatch(self, raw: str) -> dict[str, Any]:
        try:
            req = json.loads(raw)
        except json.JSONDecodeError as e:
            return _error(None, -32700, f"Parse error: {e}")

        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        if method not in _METHODS:
            return _error(req_id, -32601, f"Method not found: {method}")

        try:
            result = self._call(method, params)
            return {"jsonrpc": "2.0", "id": req_id, "result": result}
        except (OpCliError, NotImplementedError) as e:
            return _error(req_id, -32000, str(e))
        except Exception as e:  # noqa: BLE001
            log.exception("Unhandled error in %s", method)
            return _error(req_id, -32603, f"Internal error: {e}")

    def _call(self, method: str, params: dict[str, Any]) -> Any:
        b = self._backend
        if method == "ping":
            return {
                "backend": type(b).__name__,
                "capabilities": sorted(b.capabilities()),
                "locked": False,
            }
        if method == "find_items":
            return b.find_items(params["url"])
        if method == "get_item":
            return b.get_item(params["id"], params.get("reveal", True))
        if method == "save_login":
            return b.save_login(
                params["url"],
                params["username"],
                params["password"],
                params.get("title"),
            )
        if method == "passkey_get":
            return b.passkey_get(
                params["rp_id"],
                params["challenge"],
                params.get("allow_credentials", []),
            )
        if method == "passkey_create":
            return b.passkey_create(
                params["rp_id"],
                params["user"],
                params["challenge"],
                params.get("pub_key_cred_params", []),
            )
        raise NotImplementedError(method)


def _error(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": code, "message": message},
    }


def main() -> None:
    import argparse
    import signal

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )

    parser = argparse.ArgumentParser(description="qutebrowser 1Password sidecar")
    parser.add_argument("--backend", choices=["op-cli", "native"], default="op-cli")
    args = parser.parse_args()

    if args.backend == "native":
        try:
            from sidecar.backends.native_protocol import NativeProtocolBackend

            backend: OnePasswordBackend = NativeProtocolBackend()
        except ImportError:
            log.warning("native_protocol backend not available, falling back to op-cli")
            backend = OpCliBackend()
    else:
        backend = OpCliBackend()

    server = SidecarServer(backend=backend)
    signal.signal(signal.SIGTERM, lambda *_: server.stop())
    signal.signal(signal.SIGINT, lambda *_: server.stop())
    server.start()


if __name__ == "__main__":
    main()
