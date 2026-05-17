# 1Password BrowserSupport — Native Protocol Notes

> **DISCLAIMER**: This document describes the result of reverse engineering
> 1Password's internal BrowserSupport IPC for the purpose of implementing an
> experimental integration. Use of this protocol likely violates 1Password's
> Terms of Service. The feature is gated behind
> `onepassword.experimental_bridge = true` (default: `false`). Do not enable it
> in production environments where ToS compliance is required.

---

## Architecture Overview

```
browser extension <─── Chrome Native Messaging (stdin/stdout) ───> 1Password-BrowserSupport
                        4-byte LE length prefix + JSON body                 │
                                                                             │  UDS (internal)
                                                           /run/user/1000/1Password-BrowserSupport.sock
                                                                             │
                                                                    1Password.app (main)

1Password.app (main) <── abstract UDS @1PASSWORD_SDK_INTERGATIONS ── op CLI / libop_sdk
1Password.app (main) <── UDS /home/<user>/.1password/agent.sock ───── ssh-agent clients
```

### How the NativeProtocolBackend works

1. **Spawns** the `qute-1pass-sidecar` bridge launcher ELF (root-owned, installed
   at `/usr/local/bin/`), passing BrowserSupport path + manifest + extension ID
   via environment variables.
2. The launcher **forks** BrowserSupport as a child and stays alive as its parent
   process (so BrowserSupport sees `qute-1pass-sidecar` as its ppid via `/proc`).
3. The launcher acts as a **bidirectional stdin/stdout proxy** between our process
   and BrowserSupport, using `poll()` for non-blocking I/O.
4. We communicate via Chrome Native Messaging framing on the launcher's stdin/stdout.
5. BrowserSupport internally opens its own UDS to the 1Password desktop app.

---

## Chrome Native Messaging Protocol (framing)

Spec: <https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging>

```
┌─────────────────────────────────────────┐
│  length (4 bytes, little-endian uint32) │
├─────────────────────────────────────────┤
│  payload (UTF-8 JSON, `length` bytes)   │
└─────────────────────────────────────────┘
```

Both directions use the same framing. No separator byte between messages.

Python helpers:

```python
import json, struct

def nm_send(proc, msg):
    payload = json.dumps(msg, separators=(",", ":")).encode("utf-8")
    proc.stdin.write(struct.pack("<I", len(payload)) + payload)
    proc.stdin.flush()

def nm_recv(proc):
    header = proc.stdout.read(4)
    if len(header) < 4:
        raise EOFError
    (length,) = struct.unpack("<I", header)
    return json.loads(proc.stdout.read(length))
```

---

## BrowserSupport Invocation

From `~/.mozilla/native-messaging-hosts/com.1password.1password.json`:

```json
{
  "name": "com.1password.1password",
  "path": "/opt/1Password/1Password-BrowserSupport",
  "type": "stdio",
  "allowed_extensions": [
    "{0a75d802-9aed-41e7-8daa-24c067386e82}",
    "{25fc87fa-4d31-4fee-b5c1-c32a7844c063}",
    "{d634138d-c276-4fc8-924b-40a0ea21d284}"
  ]
}
```

Invocation: `1Password-BrowserSupport <manifest_path> <extension_id>`

Extension ID `{d634138d-c276-4fc8-924b-40a0ea21d284}` is the Firefox extension.

---

## Browser Verification

BrowserSupport verifies its caller by reading `/proc/<ppid>/exe` and checking
the basename against a whitelist that includes `/etc/1password/custom_allowed_browsers`
(root-owned, one basename per line).

**Key discovery**: Binary permission check — the caller binary must be root-owned
(in a system directory). A user-space binary at `~/.local/bin/` fails with
"binary permission verification failed".

**Solution used**: Install the launcher ELF to `/usr/local/bin/qute-1pass-sidecar`
(root:root, 0755), register it in `/etc/1password/custom_allowed_browsers`.

```bash
# Build and install (requires root)
make -C misc/onepassword-sidecar/launcher install   # installs to /usr/local/bin/
echo "qute-1pass-sidecar" | sudo tee -a /etc/1password/custom_allowed_browsers
```

**Why not LD_PRELOAD?** `/opt/1Password/1Password-BrowserSupport` is setgid
(`-rwxr-sr-x root onepassword`). The dynamic linker ignores `LD_PRELOAD` for
setgid/setuid binaries. A non-setgid shadow copy aborts with
"process detected it was running without libc's security". The
`custom_allowed_browsers` + root-owned launcher is the correct approach.

The `shim/` directory contains an abandoned LD_PRELOAD shim kept for reference.

---

## NM Message Format (CONFIRMED by live strace + extension RE)

**Source**: `strace -p <BrowserSupport_pid> -e trace=read,write -s 4096`
while the official Firefox extension is active, plus decompilation of
`/tmp/1p_ext/background/background.js` (extracted from the XPI).

### Request (browser → BrowserSupport)

```json
{
  "callbackId": <uint32>,
  "invocation": {
    "type": "<InvocationTypeName>",
    "content": { ... }
  }
}
```

For invocations with no parameters (e.g. `NmLockState`), omit `"content"`.

### Response (BrowserSupport → browser)

```json
{
  "type": "Success" | "Failure" | "BrowserSupport" | "NotificationModern" | "Notification",
  "content": {
    "callbackId": <uint32>,
    "response": {
      "type": "<InvocationTypeName>",
      "content": { ... }
    },
    "browser_state": {"type": "Known" | "Untrusted" | "Unknown"}
  }
}
```

- `"Success"`: `content.response` is the typed response object.
- `"BrowserSupport"`: `content.response` is a string (e.g. `"UnknownInvocation"`).
- `"Failure"`: similar to `"BrowserSupport"`.
- `"NotificationModern"`: unsolicited push from desktop app (no `callbackId` match).

**Important**: The `{"t": ..., "c": ...}` adjacently-tagged format found in the
binary strings is an **internal** format used between BrowserSupport and the
1Password desktop app over UDS — NOT the NM protocol we speak.

---

## Verified Invocation Types (from official extension background.js)

These are the types that BrowserSupport actually accepts:

| Type | content fields | Notes |
|------|---------------|-------|
| `NmLockState` | _(none)_ | Returns `{"lockState": "Unlocked"\|"Locked"}` |
| `NmRequestAccounts` | `version`, `userRequested`, `supportsDelegation` | Returns `{"accounts": [...]}` |
| `NmOfflineStatus` | _(none)_ | Returns `{"authFailed": bool}` |
| `NmShowUnlock` | _(none)_ | Triggers 1P unlock UI |
| `NmShowUnlockAccount` | `accountUuid` | Unlock specific account |
| `NmCollectedPageDetails` | `collectedPageDetails` | Push page analysis to desktop |
| `NmAcknowledgeFillItem` | `success` | Confirm fill complete |
| `NmCreateItem` | item fields | Create vault item |
| `NmViewItem` | `itemUuid`, `accountUuid` | Open item in 1P UI |
| `NmEditItem` | item fields | Edit existing item |
| `NmRequestDelegatedSession` | session fields | Delegated session |
| `NmShouldPromptToAddAccount` | account fields | Query add-account prompt |
| `NmPromptToAddAccount` | account fields | Show add-account prompt |
| `NmShowDesktopSettingsPage` | page fields | Open 1P settings |
| `NmSendSecureRemoteAutofillCredentialBundle` | encrypted bundle | Remote autofill |
| `NmRequestDesktopApplicationDeviceInfo` | _(none)_ | Get device info |
| `NmRequestUpgradeOffline` | _(none)_ | Offline upgrade |

**Types in binary strings but NOT in extension**: `NmRequestAuthorization`,
`NmNativeAutofillRequest`, `NmNativeAutofillResponse` — these are internal
BrowserSupport ↔ desktop app protocol, not the NM protocol.

---

## Credential Architecture (critical discovery)

**Credentials are NOT transmitted over the NM protocol.**

The 1Password browser extension maintains a local encrypted vault (synchronized
from the desktop app). Credentials are decrypted locally inside the extension's
WebAssembly crypto engine. The NM protocol is used only for:

- **Coordination**: which item to fill (desktop sends `FillItem` notification
  with `itemUuid`; extension decrypts that item from its local vault).
- **Account management**: lock state, account list, unlock triggers.
- **UI operations**: open item, show settings, show unlock dialog.

Consequence: `NativeProtocolBackend.find_items()`, `get_item()`, and `save_login()`
are **delegated to an embedded `OpCliBackend`**. The `op` CLI accesses the vault
directly (via `@1PASSWORD_SDK_INTERGATIONS` socket to the desktop app).

Passkey signing is also performed inside the extension's WASM — not exposed via
NM. `passkey_get`/`passkey_create` are currently not implemented.

---

## Live Test Results

Confirmed working (2026-05-17, 1Password 8.x on Linux):

```python
# NmLockState → {"lockState": "Unlocked"}
# NmRequestAccounts → {"accounts": [{"type": "Unlocked", "content": {...}}]}
# NmOfflineStatus → {"authFailed": False}
# All with browser_state={"type": "Known"}
```

Verification log from BrowserSupport:
```
Browser "/usr/local/bin/qute-1pass-sidecar" verified successfully
Connected to the desktop app
```

---

## Confirmed Sockets (via `ss -xlp`)

| Socket | Purpose |
|--------|---------|
| `/run/user/1000/1Password-BrowserSupport.sock` | BrowserSupport ↔ desktop (internal) |
| `/run/user/1000/s.sock` | Desktop main RPC |
| `@1PASSWORD_SDK_INTERGATIONS` | op CLI / SDK integrations |
| `~/.1password/agent.sock` | SSH agent |

We interact only with BrowserSupport via stdin/stdout (Chrome NM). The UDS
sockets above are internal and not directly useful to us.

---

## Future Work: Passkey via NM

`NmPerformUserVerification` (in binary strings) may be relevant for passkey
user-verification step. Full passkey flow requires:

1. Understanding how the extension intercepts `navigator.credentials.get()` /
   `navigator.credentials.create()` (via content script, not NM).
2. Finding whether there is a direct NM path for passkey signing requests, or
   if passkeys are always handled by the extension's WASM crypto engine locally.

The `NmNativeAutofillRequest` type (internal BrowserSupport ↔ desktop protocol)
handles passkey subtypes (`passkeyAuthenticate`, `passkeyRegister`) but is NOT
accessible from the NM layer we speak.

This remains an open research item. Until resolved, `passkey_get`/`passkey_create`
raise `NativeProtocolError` and are excluded from capabilities.
