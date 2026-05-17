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
                                                                             │  UDS
                                                           /run/user/1000/1Password-BrowserSupport.sock
                                                                             │
                                                                    1Password.app (main)

1Password.app (main) <── abstract UDS @1PASSWORD_SDK_INTERGATIONS ── op CLI / libop_sdk
1Password.app (main) <── UDS /home/<user>/.1password/agent.sock ───── ssh-agent clients
```

### What the NativeProtocolBackend actually does

1. **Spawns** `/opt/1Password/1Password-BrowserSupport` as a subprocess, passing
   the native messaging manifest path + extension ID on argv (Chrome NM convention).
2. **Communicates** via stdin/stdout using Chrome Native Messaging framing (see below).
3. **LD_PRELOAD shim** spoofs the parent-process identity check that BrowserSupport
   performs on startup (see "Browser Verification" section below).
4. BrowserSupport then opens its own UDS to the main 1Password app and proxies
   all requests through it.

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

Both directions (host→extension, extension→host) use the same framing on
stdin/stdout respectively. No separator byte between messages.

Python read/write helpers:

```python
import json, struct, subprocess

def nm_send(proc: subprocess.Popen, msg: dict) -> None:
    payload = json.dumps(msg).encode("utf-8")
    proc.stdin.write(struct.pack("<I", len(payload)) + payload)
    proc.stdin.flush()

def nm_recv(proc: subprocess.Popen) -> dict:
    header = proc.stdout.read(4)
    if len(header) < 4:
        raise EOFError("BrowserSupport exited")
    (length,) = struct.unpack("<I", header)
    return json.loads(proc.stdout.read(length))
```

---

## BrowserSupport Invocation

From `/home/<user>/.mozilla/native-messaging-hosts/com.1password.1password.json`:

```json
{
  "name": "com.1password.1password",
  "description": "1Password BrowserSupport",
  "path": "/opt/1Password/1Password-BrowserSupport",
  "type": "stdio",
  "allowed_extensions": [
    "{0a75d802-9aed-41e7-8daa-24c067386e82}",
    "{25fc87fa-4d31-4fee-b5c1-c32a7844c063}",
    "{d634138d-c276-4fc8-924b-40a0ea21d284}"
  ]
}
```

Invocation convention (from observing the live process via `pgrep -af 1Password`):

```
/opt/1Password/1Password-BrowserSupport <manifest_path> <extension_id>
```

We use extension ID `{d634138d-c276-4fc8-924b-40a0ea21d284}` (Firefox extension).
The same manifest JSON is installed for all supported browsers; the extension ID
is passed at runtime for BrowserSupport's logging only — the actual trust check
is browser-binary-based (see below), not extension-ID-based.

---

## Browser Verification

**Source path in binary** (Rust, not stripped):
`native-messaging/op-browser-support/src/browser_verification/linux.rs`

BrowserSupport walks the **process ancestry** of its caller and checks whether any
ancestor is a known trusted browser binary. Error variants found in the binary:

- `BrowserVerificationFailed` — no trusted ancestor found.
- `BrowserSignatureMaxDepthExceeded` — walked too many levels without finding one.
- `Signature mismatch: got …` — found a /proc/<pid>/exe but hash didn't match.
- `BrowserHelperNotRegistered` — extension not registered in the manifest.

**Browser state enum**: `Known | Untrusted | Unknown`

The check most likely:
1. Reads `/proc/<ppid>/exe` (or walks further ancestors).
2. Hashes the target binary and compares against a hardcoded whitelist.

### D.0.1 — Capture procedure (run to confirm before writing shim)

With the official 1Password Firefox extension active and 1Password.app running,
trigger an autofill or login prompt, then capture:

```bash
pid=$(pgrep -f "1Password-BrowserSupport.*mozilla")
strace -f -p "$pid" \
  -e trace=openat,read,readlink,readlinkat,statx,newfstatat \
  -s 256 -o /tmp/op-bs-verify.strace
# trigger: click "Fill password" in 1Password extension in Firefox
# then Ctrl-C strace
grep -E '/proc/[0-9]+/(exe|comm|cmdline|maps|status|attr)' /tmp/op-bs-verify.strace
```

Expected output: list of exact `/proc/<ppid>/...` paths BrowserSupport probes.
This is the ground truth for designing the LD_PRELOAD shim.

### Shim strategy: LD_PRELOAD

See `../shim/qute_browser_spoof.c`. Intercepts the syscalls identified above,
returning a trusted browser path (e.g. `/usr/bin/firefox`) for any `/proc/<ppid>/...`
probe where `ppid` is BrowserSupport's actual parent (our sidecar process).

The shim is loaded exclusively into the BrowserSupport subprocess via:

```python
env["LD_PRELOAD"] = str(shim_path)
proc = subprocess.Popen([bs_path, manifest, ext_id], env=env, ...)
```

No other process sees the override.

---

## NM RPC Type Catalogue

Extracted via `grep -aoE 'Nm[A-Z][A-Za-z]+' /opt/1Password/1Password-BrowserSupport | sort -u`.

### Invocations (browser → BrowserSupport)

| Type | Purpose |
|------|---------|
| `NmRequestAuthorization` | Initial auth handshake |
| `NmDropAuthorization` | Tear down session |
| `NmRequestAccounts` | List accounts |
| `NmRequestDelegatedSession` | Delegated session for CLI integration |
| `NmRequestDSecretProxy` | D-Bus Secret Service proxy |
| `NmCollectedPageDetails` | Send form page context for fill |
| `NmAcknowledgeFillItem` | Confirm item was filled |
| `NmCreateItem` | Create vault item |
| `NmEditItem` | Edit existing item |
| `NmViewItem` | Open item in 1P UI |
| `NmShowUnlock` | Show unlock dialog |
| `NmShowUnlockAccount` | Show unlock for specific account |
| `NmShowDesktopSettingsPage` | Open settings |
| `NmPromptToAddAccount` | Prompt to add 1P account |
| `NmShowWarning` | Show warning dialog |
| `NmPerformUserVerification` | Biometric / UV prompt |
| `NmAcknowledgeCheckExtensionPinStatus` | Extension PIN status ack |
| `NmAcknowledgeCheckExtensionFirstSsoFlow` | SSO first-run ack |
| `NmRequestUpgradeOffline` | Offline upgrade request |
| `NmAuthorizePartnerBrowser` | Partner browser authorization |
| `NmNativeAutofillRequest` | Autofill + passkey (see subtypes) |
| `NmRequestMacNativeAutofillStatus` | macOS native autofill status |
| `NmShouldPromptToAddAccount` | Query whether to show add-account |

### Responses (BrowserSupport → browser)

| Type | Purpose |
|------|---------|
| `NmAuthorizationResponse` | Auth handshake result |
| `NmRequestAccountsResponse` | Account list |
| `NmRequestDelegatedSessionResponse` / `Error` | Delegated session result |
| `NmRequestDSecretProxyResponse` | D-Bus proxy result |
| `NmLockStateResponse` | Lock state |
| `NmOfflineStatusResponse` | Offline status |
| `NmSendSecureRemoteAutofillCredentialBundleRequest/Response` | Secure credential bundle |
| `NmDesktopApplicationDeviceInfoResponse` | Device info |
| `NmMacNativeAutofillStatusResponse` | macOS autofill status |
| `NmShouldPromptToAddAccountResponse` | Add-account prompt result |
| `NmNativeAutofillResponse` | Autofill + passkey result |
| `NmUserVerificationRequest` | UV prompt parameters |

### Notifications (BrowserSupport → browser, unsolicited)

| Type | Purpose |
|------|---------|
| `NmNotification.AppQuit` | 1Password.app exited |
| `NmNotification.AutofillItemUpdated` | Item changed in vault |
| `NmNotification.BrowserVerificationFailed` | Browser identity check failed |
| `NmNotification.AccountRemoved` | Account removed from vault |
| `NmNotification.FillShortcutActivated` | Global fill shortcut pressed |
| `NmNotification.CollectActivePageDetails` | BrowserSupport requests page context |
| `NmNotification.BrowserHelperNotRegistered` | Extension not in manifest |
| `NmNotification.LostConnectionToApp` | Disconnected from 1Password.app |
| `NmNotification.ExtensionSupportDisabled` | Extension support turned off |
| `NmNotification.SsoMigrationStarted/Completed` | SSO migration events |

### NmNativeAutofillRequest subtypes (passkey-relevant)

From the concatenated string blob in the binary:

| Subtype | Purpose |
|---------|---------|
| `passwordOrPasskey` | Fill either password or passkey (user chooses) |
| `oneTimeCode` | Fill TOTP |
| `inlineUnlock` | Inline biometric unlock |
| `itemCredentials` | Return full item credentials |
| `getFeatureFlagStatus` | Feature flag query |
| `getResource` | Generic resource fetch |
| `passkeyRegister` | **WebAuthn `create()` — register new passkey** |
| `passkeySave` | Save passkey to existing item |
| `passkeyAuthenticate` | **WebAuthn `get()` — authenticate with passkey** |
| `generatedPassword` | Return a generated password |
| `usernameSuggestions` | Return username suggestions |

### Encrypted channel fields

Found in blob adjacent to `NmSendSecureRemoteAutofillCredentialBundleResponse`:
`psk`, `localKeypair`, `remotePubKey` — indicates a Noise-protocol or X25519 ECDH
secure channel for credential transmission. The `NmSendSecureRemoteAutofill...`
methods encrypt the credential bundle before returning it to the extension.

---

## SDK Path (not usable for passkeys)

`libop_sdk_ipc_client.so` connects to the abstract socket `@1PASSWORD_SDK_INTERGATIONS`.
This is used by `op` CLI v2. Static analysis shows **no passkey/WebAuthn symbols**
in the SDK lib — signing is not exposed via the SDK path. SDK is only useful for
fill/save (already handled by `OpCliBackend`).

---

## Passkey Schema Mapping (preliminary, to be confirmed by D.0.1 capture)

### passkey_get

JSON-RPC sidecar request → NM envelope:

```json
{
  "type": "NmNativeAutofillRequest",
  "payload": {
    "type": "passkeyAuthenticate",
    "origin": "https://<rp_id>",
    "rpId": "<rp_id>",
    "challenge": "<base64url>",
    "allowCredentials": [{"type": "public-key", "id": "<base64url>"}]
  }
}
```

Expected `NmNativeAutofillResponse` payload (field names to be confirmed):

```json
{
  "type": "passkeyAuthenticate",
  "credentialId": "<base64url>",
  "authenticatorData": "<base64url>",
  "signature": "<base64url>",
  "userHandle": "<base64url | null>"
}
```

Mapped to sidecar JSON-RPC response: `{authenticator_data_b64, signature_b64, user_handle_b64, credential_id_b64}`.

### passkey_create

```json
{
  "type": "NmNativeAutofillRequest",
  "payload": {
    "type": "passkeyRegister",
    "origin": "https://<rp_id>",
    "rpId": "<rp_id>",
    "rpName": "<rp name>",
    "userId": "<base64url>",
    "userName": "<username>",
    "challenge": "<base64url>",
    "pubKeyCredParams": [{"type": "public-key", "alg": -7}]
  }
}
```

Whether BrowserSupport accepts `passkeyRegister` from a non-blessed caller
(post-shim) is unknown until D.0.1 capture + live testing.

---

## Confirmed Sockets (via `ss -xlp` with 1Password.app running)

| Socket | Owner | Purpose |
|--------|-------|---------|
| `/run/user/1000/1Password-BrowserSupport.sock` | 1Password BrowserSupport | Internal BrowserSupport ↔ main app IPC |
| `/run/user/1000/s.sock` | 1Password main app | Main RPC socket |
| `@1PASSWORD_SDK_INTERGATIONS` (abstract) | 1Password main app | SDK / op CLI integrations |
| `/home/<user>/.1password/agent.sock` | 1Password main app | SSH agent |
| `@/tmp/1Password-<uid>/...` (abstract) | 1Password | Crash handler / IPC |

The socket that matters for the NativeProtocolBackend is **NOT** any of these
directly — BrowserSupport opens its connection to the main app internally after
it starts. We only interact with BrowserSupport via stdin/stdout.
