# SPDX-FileCopyrightText: Gianluca
# SPDX-License-Identifier: GPL-3.0-or-later

"""Shared fixtures for onepassword unit tests."""

import json
import os
import socket
import threading

import pytest


class FakeSidecar:
    """In-process Unix socket server speaking JSON-RPC 2.0 (newline-delimited).

    Preset responses per method with preset_response(); inspect received
    requests with requests_for().
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(path)
        self._sock.listen(1)
        self._responses: dict[str, dict] = {}
        self.requests: list[dict] = []
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def preset_response(self, method: str, response: dict) -> None:
        """Register a canned response for a given RPC method."""
        self._responses[method] = response

    def requests_for(self, method: str) -> list[dict]:
        """Return all received requests with the given method name."""
        return [r for r in self.requests if r.get("method") == method]

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        self._sock.settimeout(2.0)
        try:
            conn, _ = self._sock.accept()
        except (socket.timeout, OSError):
            return
        conn.settimeout(0.1)
        buf = b""
        while not self._stop.is_set():
            try:
                data = conn.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                break
            buf += data
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                try:
                    req = json.loads(line.decode())
                except json.JSONDecodeError:
                    continue
                self.requests.append(req)
                method = req.get("method", "")
                body = self._responses.get(method, {"result": {}})
                resp = {"jsonrpc": "2.0", "id": req.get("id"), **body}
                try:
                    conn.sendall((json.dumps(resp) + "\n").encode())
                except OSError:
                    break
        try:
            conn.close()
        except OSError:
            pass

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        if self._thread:
            self._thread.join(timeout=2)
        if os.path.exists(self.path):
            os.unlink(self.path)


@pytest.fixture()
def fake_sidecar(tmp_path, monkeypatch):
    """Start a FakeSidecar and redirect _socket_path to it."""
    path = str(tmp_path / "qute-1pass-test.sock")
    sidecar = FakeSidecar(path)
    monkeypatch.setattr(
        "qutebrowser.browser.onepassword.client._socket_path",
        lambda: path,
    )
    sidecar.start()
    yield sidecar
    sidecar.stop()
