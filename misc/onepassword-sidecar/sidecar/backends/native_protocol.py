# SPDX-FileCopyrightText: Gianluca
# SPDX-License-Identifier: GPL-3.0-or-later

"""1Password NativeProtocolBackend — speaks Chrome Native Messaging to BrowserSupport.

Architecture
------------
1Password-BrowserSupport acts as a proxy between the browser extension and the
main 1Password desktop app.  It speaks Chrome Native Messaging (4-byte
little-endian length prefix + UTF-8 JSON payload) over stdin/stdout.

NM message format (confirmed by reverse-engineering the official Firefox extension):
  Request:  {"callbackId": <int>, "invocation": {"type": "<TypeName>", "content": {...}}}
  Response: {"type": "Success"|"Failure"|"BrowserSupport"|"NotificationModern",
             "content": {"callbackId": <int>,
                         "response": {"type": "<TypeName>", "content": {...}},
                         "browser_state": {"type": "Known"|"Untrusted"|"Unknown"}}}

Available invocation types (from official extension background.js):
  NmLockState, NmRequestAccounts, NmOfflineStatus, NmShowUnlock,
  NmCollectedPageDetails, NmAcknowledgeFillItem, NmCreateItem,
  NmViewItem, NmEditItem, NmShouldPromptToAddAccount, NmPromptToAddAccount,
  NmRequestDelegatedSession, NmSendSecureRemoteAutofillCredentialBundle, ...

NOTE: Credentials (username/password) are decrypted locally by the extension's
WASM crypto engine and are NOT transmitted over the NM protocol.  This backend
provides status/account information via NM and delegates data operations to the
embedded OpCliBackend.

Browser Verification
--------------------
BrowserSupport verifies the calling process by reading /proc/<ppid>/exe and
checking the basename against /etc/1password/custom_allowed_browsers.  This
backend spawns the `qute-1pass-sidecar` ELF launcher which forks BrowserSupport
as a child and stays alive as bidirectional stdin/stdout proxy, so BrowserSupport
sees the launcher as its parent.

Setup (one-time, requires root):
    make -C misc/onepassword-sidecar/launcher install
    echo "qute-1pass-sidecar" | sudo tee -a /etc/1password/custom_allowed_browsers

DISCLAIMER: use likely violates 1Password ToS.
Gate: onepassword.experimental_bridge=true (default: false).
"""

import json
import logging
import os
import pathlib
import queue
import struct
import subprocess
import threading
import time
from typing import Any

from sidecar.backends.base import OnePasswordBackend
from sidecar.backends.op_cli import OpCliBackend, OpCliError

log = logging.getLogger("qute-1pass")

_LAUNCHER_SEARCH = [
    pathlib.Path("/usr/local/bin/qute-1pass-sidecar"),
    pathlib.Path.home() / ".local/bin/qute-1pass-sidecar",
]
_BS_PATH = pathlib.Path("/opt/1Password/1Password-BrowserSupport")
_MANIFEST_SEARCH = [
    pathlib.Path.home()
    / ".mozilla/native-messaging-hosts/com.1password.1password.json",
    pathlib.Path(
        "/usr/lib/mozilla/native-messaging-hosts/com.1password.1password.json"
    ),
    pathlib.Path.home()
    / ".config/chromium/NativeMessagingHosts/com.1password.1password.json",
]
_EXTENSION_ID = "{d634138d-c276-4fc8-924b-40a0ea21d284}"

# NM protocol version expected by BrowserSupport (from extension source)
_NM_ACCOUNTS_VERSION = 1


class NativeProtocolError(Exception):
    pass


class BrowserVerificationFailed(NativeProtocolError):
    pass


class BackendUnavailable(NativeProtocolError):
    pass


class NativeProtocolBackend(OnePasswordBackend):
    """Backend that validates desktop connection via NM and delegates data ops to op CLI.

    Capabilities:
      fill, save, totp — delegated to embedded OpCliBackend
      passkey_get/create — NOT yet available (passkeys are signed inside the
                           extension's WASM engine, not exposed via NM protocol)
    """

    def __init__(
        self,
        bs_path: pathlib.Path = _BS_PATH,
        extension_id: str = _EXTENSION_ID,
    ) -> None:
        self._bs_path = bs_path
        self._extension_id = extension_id
        self._proc: subprocess.Popen | None = None
        self._recv_queue: queue.Queue[dict] = queue.Queue()
        self._reader_thread: threading.Thread | None = None
        self._capabilities_set: set[str] = set()
        self._lock = threading.Lock()
        self._cb_counter = 0
        self._pending: dict[int, queue.Queue] = {}

        # Embedded op-cli backend for data operations
        self._op_cli = OpCliBackend()

        self._start()

    # ------------------------------------------------------------------
    # OnePasswordBackend interface
    # ------------------------------------------------------------------

    def capabilities(self) -> set[str]:
        return self._capabilities_set

    def find_items(self, url: str) -> list[dict[str, Any]]:
        return self._op_cli.find_items(url)

    def get_item(self, item_id: str, reveal: bool = True) -> dict[str, Any]:
        return self._op_cli.get_item(item_id, reveal=reveal)

    def save_login(
        self,
        url: str,
        username: str,
        password: str,
        title: str | None = None,
    ) -> dict[str, Any]:
        return self._op_cli.save_login(url, username, password, title)

    def passkey_get(
        self, rp_id: str, challenge: str, allow_credentials: list[str]
    ) -> dict[str, Any]:
        raise NativeProtocolError(
            "passkey_get not yet supported: passkey signing is performed inside "
            "the 1Password extension's WASM engine and is not exposed via the NM protocol."
        )

    def passkey_create(
        self,
        rp_id: str,
        user: dict[str, Any],
        challenge: str,
        pub_key_cred_params: list[dict[str, Any]],
    ) -> dict[str, Any]:
        raise NativeProtocolError("passkey_create not yet supported: see passkey_get.")

    def lock_state(self) -> str:
        """Return 'Unlocked', 'Locked', or 'Unknown'."""
        try:
            resp = self._nm_call("NmLockState")
            return resp.get("lockState", "Unknown")
        except NativeProtocolError:
            return "Unknown"

    def account_count(self) -> int:
        """Return number of unlocked accounts."""
        try:
            resp = self._nm_call(
                "NmRequestAccounts",
                {
                    "version": _NM_ACCOUNTS_VERSION,
                    "userRequested": False,
                    "supportsDelegation": True,
                },
            )
            return sum(
                1 for a in resp.get("accounts", []) if a.get("type") == "Unlocked"
            )
        except NativeProtocolError:
            return 0

    # ------------------------------------------------------------------
    # internal — lifecycle
    # ------------------------------------------------------------------

    def _find_launcher(self) -> pathlib.Path:
        for p in _LAUNCHER_SEARCH:
            if p.exists():
                return p
        raise BackendUnavailable(
            "qute-1pass-sidecar launcher not found. "
            "Run: make -C misc/onepassword-sidecar/launcher install\n"
            "Then: echo 'qute-1pass-sidecar' | sudo tee -a /etc/1password/custom_allowed_browsers"
        )

    def _find_manifest(self) -> pathlib.Path:
        for p in _MANIFEST_SEARCH:
            if p.exists():
                return p
        raise BackendUnavailable(
            "1Password native messaging manifest not found. "
            "Install the 1Password browser extension first."
        )

    def _start(self) -> None:
        if not self._bs_path.exists():
            raise BackendUnavailable(
                f"1Password-BrowserSupport not found at {self._bs_path}"
            )
        launcher = self._find_launcher()
        manifest = self._find_manifest()

        log.info("NativeProtocol: starting launcher %s", launcher)
        env = {
            **os.environ,
            "QUTE_1PASS_BS_PATH": str(self._bs_path),
            "QUTE_1PASS_MANIFEST": str(manifest),
            "QUTE_1PASS_EXT_ID": self._extension_id,
        }
        try:
            self._proc = subprocess.Popen(
                [str(launcher)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=env,
            )
        except OSError as e:
            raise BackendUnavailable(f"Failed to start launcher: {e}") from e

        self._reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
        self._reader_thread.start()

        # Give BrowserSupport time to connect to the desktop app.
        time.sleep(0.8)
        if self._proc.poll() is not None:
            rc = self._proc.returncode
            raise BrowserVerificationFailed(
                f"Launcher exited with code {rc}. "
                "Ensure '/usr/local/bin/qute-1pass-sidecar' (root-owned) is installed and "
                "'qute-1pass-sidecar' is in /etc/1password/custom_allowed_browsers."
            )

        self._handshake()

    # ------------------------------------------------------------------
    # internal — NM protocol
    # ------------------------------------------------------------------

    def _next_cb_id(self) -> int:
        with self._lock:
            self._cb_counter += 1
            return self._cb_counter

    def _nm_send(self, cb_id: int, inv_type: str, content: dict | None = None) -> None:
        assert self._proc and self._proc.stdin
        inv: dict[str, Any] = {"type": inv_type}
        if content is not None:
            inv["content"] = content
        msg = {"callbackId": cb_id, "invocation": inv}
        payload = json.dumps(msg, separators=(",", ":")).encode("utf-8")
        frame = struct.pack("<I", len(payload)) + payload
        with self._lock:
            self._proc.stdin.write(frame)
            self._proc.stdin.flush()

    def _reader_loop(self) -> None:
        assert self._proc and self._proc.stdout
        while True:
            header = self._proc.stdout.read(4)
            if len(header) < 4:
                log.debug("NativeProtocol: BrowserSupport stdout closed")
                # Wake up all pending callers
                with self._lock:
                    for q in self._pending.values():
                        q.put(None)
                break
            (length,) = struct.unpack("<I", header)
            body = self._proc.stdout.read(length)
            if len(body) < length:
                break
            try:
                msg = json.loads(body)
            except json.JSONDecodeError:
                log.warning("NativeProtocol: bad JSON: %r", body[:200])
                continue

            msg_type = msg.get("type", "")
            content = msg.get("content", {})
            cb_id = content.get("callbackId") if isinstance(content, dict) else None

            log.debug("NativeProtocol: recv type=%s cb=%s", msg_type, cb_id)

            if cb_id is not None:
                with self._lock:
                    q = self._pending.pop(cb_id, None)
                if q is not None:
                    q.put(msg)
                    continue

            # Unmatched notification — log and discard
            if msg_type in ("NotificationModern", "Notification"):
                notif = content.get("content", {}) if isinstance(content, dict) else {}
                log.debug("NativeProtocol: notification %s", notif.get("type", "?"))
            else:
                log.debug("NativeProtocol: unmatched message type=%s", msg_type)

    def _nm_call(
        self, inv_type: str, content: dict | None = None, timeout: float = 10.0
    ) -> dict:
        """Send an NM invocation and return the response content dict."""
        cb_id = self._next_cb_id()
        response_q: queue.Queue = queue.Queue()
        with self._lock:
            self._pending[cb_id] = response_q
        self._nm_send(cb_id, inv_type, content)

        try:
            msg = response_q.get(timeout=timeout)
        except queue.Empty:
            with self._lock:
                self._pending.pop(cb_id, None)
            raise NativeProtocolError(f"Timeout waiting for response to {inv_type!r}")

        if msg is None:
            raise NativeProtocolError("BrowserSupport connection closed")

        msg_type = msg.get("type", "")
        inner = msg.get("content", {})

        if msg_type == "BrowserSupport":
            response_str = inner.get("response", "")
            if response_str in (
                "BrowserVerificationFailed",
                "BrowserHelperNotRegistered",
            ):
                raise BrowserVerificationFailed(
                    f"BrowserSupport rejected us: {response_str}. "
                    "Ensure 'qute-1pass-sidecar' is in /etc/1password/custom_allowed_browsers."
                )
            raise NativeProtocolError(
                f"BrowserSupport error for {inv_type!r}: {response_str}"
            )

        if msg_type == "Failure":
            raise NativeProtocolError(
                f"Failure response for {inv_type!r}: {inner.get('response', '')}"
            )

        if msg_type != "Success":
            raise NativeProtocolError(
                f"Unexpected response type {msg_type!r} for {inv_type!r}"
            )

        # Success: response is {"type": inv_type, "content": {...}}
        response = inner.get("response", {})
        return response.get("content", response) if isinstance(response, dict) else {}

    def _handshake(self) -> None:
        """Verify desktop connection and determine capabilities."""
        # Check lock state
        lock = self._nm_call("NmLockState", timeout=10.0)
        lock_state = lock.get("lockState", "Unknown")
        log.info("NativeProtocol: lock state = %s", lock_state)

        if lock_state == "Locked":
            log.warning("NativeProtocol: vault is locked; fill operations will fail")

        # Get account list
        accts = self._nm_call(
            "NmRequestAccounts",
            {
                "version": _NM_ACCOUNTS_VERSION,
                "userRequested": False,
                "supportsDelegation": True,
            },
            timeout=10.0,
        )
        unlocked = [a for a in accts.get("accounts", []) if a.get("type") == "Unlocked"]
        log.info("NativeProtocol: %d unlocked account(s) available", len(unlocked))

        if lock_state == "Unlocked" and unlocked:
            self._capabilities_set = {"fill", "save", "totp"}
        else:
            self._capabilities_set = set()

        log.info("NativeProtocol: capabilities = %s", sorted(self._capabilities_set))

    def close(self) -> None:
        """Terminate BrowserSupport and release resources."""
        proc = self._proc
        self._proc = None
        if proc is None:
            return
        try:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=2)
        except OSError:
            pass
        finally:
            for f in (proc.stdin, proc.stdout):
                try:
                    if f is not None:
                        f.close()
                except OSError:
                    pass

    def __del__(self) -> None:
        self.close()
