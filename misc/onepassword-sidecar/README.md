# qute-1pass-sidecar

Sidecar daemon for qutebrowser's experimental 1Password integration.
Listens on a Unix socket, speaks JSON-RPC 2.0, and delegates to a
pluggable backend — either the official `op` CLI (default, ToS-clean) or
an experimental native-protocol backend that speaks the 1Password desktop
app IPC directly.

See [`doc/onepassword.asciidoc`](../../doc/onepassword.asciidoc) in the
qutebrowser repository for the browser-side setup and command reference.

## Requirements

- Python 3.10+
- [1Password CLI v2](https://developer.1password.com/docs/cli/) (`op`)
  installed and signed in with biometric unlock enabled
- Linux (macOS support untested; Windows not supported)

## Install

```bash
# From source (recommended for development)
pip install -e .

# Or with pipx for an isolated environment
pipx install .
```

This installs the `qute-1pass-sidecar` executable.

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
