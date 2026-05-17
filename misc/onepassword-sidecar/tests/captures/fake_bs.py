#!/usr/bin/env python3
"""Fake 1Password-BrowserSupport for unit tests.

Speaks the Chrome Native Messaging protocol on stdin/stdout:
  Request:  4-byte LE length + JSON {"callbackId": int, "invocation": {"type": str, "content": ...}}
  Response: 4-byte LE length + JSON {"type": "Success", "content": {"callbackId": int,
                                     "response": {"type": str, "content": {...}},
                                     "browser_state": {"type": "Known"}}}

Responds to:
  NmLockState      → lockState=Unlocked
  NmRequestAccounts → one unlocked account
  NmOfflineStatus  → authFailed=false
  anything else    → BrowserSupport/UnknownInvocation
"""

import json
import struct
import sys


def nm_send(msg: dict) -> None:
    payload = json.dumps(msg, separators=(",", ":")).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("<I", len(payload)) + payload)
    sys.stdout.buffer.flush()


def nm_recv() -> dict | None:
    header = sys.stdin.buffer.read(4)
    if len(header) < 4:
        return None
    (length,) = struct.unpack("<I", header)
    body = sys.stdin.buffer.read(length)
    if len(body) < length:
        return None
    return json.loads(body)


RESPONSES = {
    "NmLockState": {"lockState": "Unlocked"},
    "NmRequestAccounts": {
        "accounts": [
            {
                "type": "Unlocked",
                "content": {
                    "details": {
                        "accountUuid": "FAKEUUID000001",
                        "accountName": "Test Account",
                        "email": "test@example.com",
                    }
                },
            }
        ]
    },
    "NmOfflineStatus": {"authFailed": False},
}


def main() -> None:
    while True:
        msg = nm_recv()
        if msg is None:
            break
        cb_id = msg.get("callbackId", 0)
        invocation = msg.get("invocation", {})
        inv_type = invocation.get("type", "")

        if inv_type in RESPONSES:
            nm_send(
                {
                    "type": "Success",
                    "content": {
                        "callbackId": cb_id,
                        "response": {"type": inv_type, "content": RESPONSES[inv_type]},
                        "browser_state": {"type": "Known"},
                    },
                }
            )
        else:
            nm_send(
                {
                    "type": "BrowserSupport",
                    "content": {
                        "callbackId": cb_id,
                        "response": "UnknownInvocation",
                        "browser_state": {"type": "Known"},
                    },
                }
            )


if __name__ == "__main__":
    main()
