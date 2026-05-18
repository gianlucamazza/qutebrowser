# qute-1pass-sidecar

Sidecar daemon for qutebrowser's experimental 1Password integration.
Listens on a Unix socket, speaks JSON-RPC 2.0, and delegates to a
pluggable backend — either the official `op` CLI (default, ToS-clean) or
an experimental native-protocol backend that speaks the 1Password desktop
app IPC directly.

Companion browser-side code lives in the `validate-8642-webauthn` branch of
[gianlucamazza/qutebrowser](https://github.com/gianlucamazza/qutebrowser/tree/validate-8642-webauthn).
See [`doc/onepassword.asciidoc`](https://github.com/gianlucamazza/qutebrowser/blob/validate-8642-webauthn/doc/onepassword.asciidoc)
for the browser-side setup and command reference.

The copy in `misc/onepassword-sidecar/` of that branch mirrors this
repository and is kept in sync; either is installable via pip/pipx.

## Requirements

- Python 3.11+
- [1Password CLI v2](https://developer.1password.com/docs/cli/) (`op`)
  installed and signed in with biometric unlock enabled
- Linux (macOS support untested; Windows not supported)

## Install

```bash
# From PyPI (recommended)
pipx install qute-1pass-sidecar

# From source (for development)
pip install -e .
```

This installs the `qute-1pass-sidecar` executable.

## Native backend launcher (optional, required for `--backend native`)

The native backend communicates with 1Password by spawning
`/opt/1Password/1Password-BrowserSupport` — the same helper process used
by the official browser extension. BrowserSupport verifies its caller's
binary via `/proc/<ppid>/exe` and requires it to be root-owned and
listed in `/etc/1password/custom_allowed_browsers`.

The bundled `launcher/` directory contains a small C bridge program that
forks BrowserSupport as a child and proxies stdin/stdout via `poll()`.
Build and install it with:

```bash
# Compile
make -C launcher

# Install root-owned to /usr/local/bin (required for native backend)
make -C launcher install-system
# Then register as a trusted browser (one-time, requires root):
echo qute-1pass-sidecar | sudo tee -a /etc/1password/custom_allowed_browsers
```

`make install` (without `-system`) installs to `~/.local/bin` for
development/testing, but that path does **not** satisfy 1Password's
root-owned binary requirement, so the native backend will still degrade
to `op-cli` with a clear error message.

If the launcher is not installed at all, starting the sidecar with
`--backend native` automatically falls back to `op-cli` and reports
the reason via `ping()` (visible via `:onepassword status` in
qutebrowser).

## Run

```bash
qute-1pass-sidecar [--backend op-cli|native] [--socket-path PATH]
```

Options:

| Flag | Default | Description |
|------|---------|-------------|
| `--backend` | `op-cli` | Backend to use. `native` is experimental and requires `onepassword.experimental_bridge = true` in qutebrowser. |
| `--socket-path` | `$XDG_RUNTIME_DIR/qute-1pass.sock` | Unix socket path. Must match `onepassword.socket_path` in qutebrowser config if set. |

The easiest way to start the sidecar from qutebrowser itself is:

```
:onepassword restart-sidecar
```

This reads `onepassword.backend` and `onepassword.socket_path` from the
browser's config and spawns the sidecar with the matching arguments.

## systemd user unit

Create `~/.config/systemd/user/qute-1pass-sidecar.service`:

```ini
[Unit]
Description=qutebrowser 1Password sidecar
After=graphical-session.target

[Service]
ExecStart=%h/.local/bin/qute-1pass-sidecar --backend op-cli
Restart=on-failure
RestartSec=5

[Install]
WantedBy=graphical-session.target
```

Enable and start:

```bash
systemctl --user enable --now qute-1pass-sidecar.service
```

## Troubleshooting

**Socket file collision** — if `qute-1pass.sock` already exists from a
previous crashed run and the sidecar refuses to bind, remove the stale
file:

```bash
rm "$XDG_RUNTIME_DIR/qute-1pass.sock"
```

**`op` CLI not signed in** — the `op-cli` backend will fail with
`"locked"` if you haven't authenticated. Run:

```bash
op signin
```

and confirm biometric unlock is configured (`op account list` should show
your account).

**Checking sidecar status from qutebrowser** — use:

```
:onepassword status
```

This sends a `ping` RPC and displays the backend name, capability set,
and lock status.

**Logs** — start the sidecar with `--log-level debug` (if supported by
your install) or run it in a terminal to see JSON-RPC traffic on stderr.
