# codex-imessage-control-plane

`codex-imessage-control-plane` is a macOS-only runtime that connects Codex sessions to iMessage.

`README.md` is the canonical setup guide for both humans and coding agents.
`AGENTS.md` is intentionally lightweight and points back here.

It provides one control-plane process that can:
- forward Codex `notify` payloads to iMessage
- read inbound iMessage replies from Messages `chat.db`
- route replies back to the right Codex session (including tmux-based routing)
- drain a fallback outbound queue when AppleScript send attempts fail

## Scope and Non-Goals

This repository is focused on a local, single-user macOS runtime.

Non-goals:
- Linux/Windows support
- hosted SaaS orchestration
- guaranteed delivery or SLA-backed messaging
- enterprise-grade MDM automation policies

## Requirements

- macOS (Messages app available and signed in)
- Python 3.11+ (runtime enforces this)
- Codex CLI installed and authenticated
- Optional but recommended: tmux
- Bundled sender script at `scripts/send-imessage.applescript` (no external path required)

Privacy/Security permissions required on macOS:
- `Automation`: allow your terminal/runner (`Terminal`, `iTerm`, etc.) and `osascript` to control `Messages`
- `Full Disk Access`: grant the launchd runtime app or Python binary (shown by setup commands) so it can read `~/Library/Messages/chat.db`

## Quickstart

1. Clone and enter the repo.

```bash
cd /path/to/codex-imessage-control-plane
```

2. Resolve Python from `PATH` and enforce `3.11+`.

```bash
PYTHON_BIN="$(command -v python3 || true)"
if [ -z "$PYTHON_BIN" ]; then
  echo "python3 not found in PATH."
  exit 1
fi
"$PYTHON_BIN" --version
if ! "$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
  echo "Require Python 3.11+."
  exit 1
fi
```

3. Set minimum environment.

```bash
export CODEX_IMESSAGE_TO="+15555550123"
export CODEX_HOME="$HOME/.codex"
export CODEX_IMESSAGE_NOTIFY_MODE="route"
export PYTHON_BIN
```

4. Configure Codex `notify` hook in `~/.codex/config.toml`.

```bash
"$PYTHON_BIN" codex_imessage_control_plane.py setup-notify-hook \
  --recipient "$CODEX_IMESSAGE_TO" \
  --python-bin "$PYTHON_BIN"
```

This updater is idempotent and writes `notify` at top-level.
It is safe even if `config.toml` currently has misplaced/duplicate `notify` entries (including under `[notice.model_migrations]`).

Compatibility note:
- Current Codex releases parse `notify` as a sequence (array), not a string command.
- If an older Codex build fails with `invalid type: sequence, expected a string`, switch to legacy string form for that build.

5. Install and start launchd (recommended).

```bash
"$PYTHON_BIN" codex_imessage_control_plane.py setup-launchd \
  --recipient "$CODEX_IMESSAGE_TO" \
  --python-bin "$PYTHON_BIN"
"$PYTHON_BIN" codex_imessage_control_plane.py doctor
```

`setup-launchd` writes `~/Library/LaunchAgents/<label>.plist`, bootstraps the service, and by default runs the `chat.db` Full Disk Access check first using the same runtime binary it configures for launchd. When the selected Python install provides `Python.app`, setup also prepares a visible target at `~/Applications/Codex iMessage Python.app` (symlink-first, copy fallback) and uses that app's embedded runtime binary for launchd/FDA guidance.

During permission setup, follow the command output exactly. It prints:
- `Permission to grant: Full Disk Access (System Settings > Privacy & Security > Full Disk Access).`
- `Grant Full Disk Access to this app: ...` (when available)
- `Grant access to this Python binary: ...`

Grant Full Disk Access to one of those printed targets (prefer the app path when shown), keep the command running, and wait for:
- `Full Disk Access confirmed: chat.db is now readable.`

`setup-permissions` starts polling `chat.db` before opening System Settings, then keeps polling until readable or timeout.

6. Optional: run in foreground instead of launchd.

```bash
"$PYTHON_BIN" codex_imessage_control_plane.py run
```

7. Optional one-cycle smoke test.

```bash
"$PYTHON_BIN" codex_imessage_control_plane.py once --trace
```

## First-Run Failure Modes

`setup-notify-hook` / `setup-launchd` exits with `Require Python 3.11+`:
- On some macOS hosts, `python3` in `PATH` still points to Apple Python 3.9.
- Use an explicit 3.11+ binary, then re-run setup:
  - `PYTHON_BIN=/opt/homebrew/bin/python3.13` (or another installed 3.11+ path)
  - `"$PYTHON_BIN" codex_imessage_control_plane.py setup-notify-hook --recipient "$CODEX_IMESSAGE_TO" --python-bin "$PYTHON_BIN"`
  - `"$PYTHON_BIN" codex_imessage_control_plane.py setup-launchd --recipient "$CODEX_IMESSAGE_TO" --python-bin "$PYTHON_BIN"`

`doctor` says `notify hook is not configured...` or `unable to parse ~/.codex/config.toml`:
- Re-run:
  - `"$PYTHON_BIN" codex_imessage_control_plane.py setup-notify-hook --recipient "$CODEX_IMESSAGE_TO" --python-bin "$PYTHON_BIN"`

`setup-launchd` says shell can read `chat.db` but launchd cannot:
- Grant Full Disk Access to `permission_app` shown by `doctor` (usually `~/Applications/Codex iMessage Python.app`).
- Re-run:
  - `"$PYTHON_BIN" codex_imessage_control_plane.py setup-launchd --recipient "$CODEX_IMESSAGE_TO" --python-bin "$PYTHON_BIN" --skip-permissions`
  - `"$PYTHON_BIN" codex_imessage_control_plane.py doctor`
- If this keeps repeating after Python upgrades/reinstalls, run:
  - `"$PYTHON_BIN" codex_imessage_control_plane.py setup-launchd --recipient "$CODEX_IMESSAGE_TO" --python-bin "$PYTHON_BIN" --repair-tcc`
  - This attempts to reset stale TCC Full Disk Access approval for the runtime bundle id and re-runs permission setup.

`setup-launchd` keeps failing with shell/runtime readable but launchd still denied (even after granting FDA):
- Cause can be stale TCC code requirements for `org.python.python` after Python upgrades/reinstalls.
- Check for TCC mismatch signals:
  - `/usr/bin/log show --style syslog --last 15m --predicate 'subsystem == "com.apple.TCC" && eventMessage CONTAINS "kTCCServiceSystemPolicyAllFiles" && eventMessage CONTAINS "org.python.python"'`
  - look for: `Failed to match existing code requirement for subject org.python.python`
- Reset stale approvals, then grant again in System Settings:
  - `tccutil reset SystemPolicyAllFiles org.python.python`
  - `tccutil reset SystemPolicyAllFiles com.mitchellh.ghostty`
  - re-enable FDA for `~/Applications/Codex iMessage Python.app` (and terminal app if needed)
  - re-run `setup-launchd` and `doctor`
- Shortcut:
  - `"$PYTHON_BIN" codex_imessage_control_plane.py setup-launchd --recipient "$CODEX_IMESSAGE_TO" --python-bin "$PYTHON_BIN" --repair-tcc`

`doctor` transiently shows `control-plane lock PID not alive` immediately after restart:
- Wait 1-2 seconds and run `doctor` again.

## Public Interfaces

### CLI commands

```bash
# Unified control plane
python3 codex_imessage_control_plane.py run [--poll 0.5] [--dry-run] [--trace]
python3 codex_imessage_control_plane.py once [--dry-run] [--trace]
python3 codex_imessage_control_plane.py notify [PAYLOAD_JSON] [--dry-run]
python3 codex_imessage_control_plane.py doctor [--json]
python3 codex_imessage_control_plane.py setup-notify-hook [--recipient TO] [--python-bin PATH]
python3 codex_imessage_control_plane.py setup-permissions [--timeout 180] [--poll 1.0] [--no-open]
python3 codex_imessage_control_plane.py setup-launchd [--label LABEL] [--recipient TO] [--python-bin PATH] [--skip-permissions] [--timeout 180] [--poll 1.0] [--no-open]

# Notify helper (best-effort)
python3 codex_imessage_notify.py attention [--cwd DIR] [--need TEXT] [--to RECIPIENT] [--dry-run]
python3 codex_imessage_notify.py route [--cwd DIR] [--need TEXT] [--to RECIPIENT] [--dry-run] [PAYLOAD_JSON]
```

### Inbound iMessage command grammar

When inbound routing is enabled, reply messages support:
- `help`
- `list`
- `status @<session_ref>`
- `@<session_ref> <instruction>`
- `new <label>: <instruction>`

### Important environment variables

- `CODEX_IMESSAGE_TO`: destination phone number or Apple ID email
- `CODEX_HOME`: Codex home directory (defaults to `~/.codex`)
- `CODEX_IMESSAGE_NOTIFY_MODE`: `send`, `state_only`, or `route`
- `CODEX_IMESSAGE_CHAT_DB`: override Messages database path (default `~/Library/Messages/chat.db`)
- `CODEX_IMESSAGE_QUEUE`: fallback queue JSONL path
- `CODEX_IMESSAGE_MAX_LEN`: max outgoing message chunk size
- `CODEX_IMESSAGE_INBOUND_POLL_S`: control-plane polling interval for `run`
- `CODEX_IMESSAGE_STRICT_TMUX`: strict tmux routing mode (`1` default)
- `CODEX_IMESSAGE_REQUIRE_SESSION_REF`: require explicit `@ref` for ambiguous replies
- `CODEX_IMESSAGE_TMUX_ACK_TIMEOUT_S`: tmux dispatch acknowledgement timeout
- `CODEX_IMESSAGE_ROUTE_VIA_TMUX`: route responses through tmux (`1` default)
- `CODEX_IMESSAGE_ENABLE_NEW_SESSION`: allow creating sessions from inbound messages (`1` default)
- `CODEX_IMESSAGE_AUTO_CREATE_ON_MISSING`: auto-create when no session matches (`1` default)
- `CODEX_IMESSAGE_LAUNCHD_LABEL`: launchd service label used by `doctor`

## Launchd

Use:

```bash
python3 codex_imessage_control_plane.py setup-launchd
```

This command:
- writes `~/Library/LaunchAgents/<label>.plist`
- uses the current Python interpreter by default (`--python-bin` to override)
- attempts to provision a visible FDA target app at `~/Applications/Codex iMessage Python.app` (symlink-first, copy fallback)
- reuses an existing healthy `~/Applications/Codex iMessage Python.app` when present to preserve Full Disk Access grants
- bootstraps + kickstarts the agent via `launchctl`
- runs `setup-permissions` by default so launchd can read `chat.db`

`setup-permissions` prefers launchd runtime targets from the installed plist when available, so FDA guidance aligns with what launchd actually executes.

If `setup-launchd` reports that the shell can read `chat.db` but launchd cannot, grant Full Disk Access to the app or Python binary shown in command output, then re-run `setup-launchd`.

Tip: `python3 codex_imessage_control_plane.py doctor` now shows both `runtime_python` and `permission_app` under Launchd so you can grant FDA to the exact runtime target.

When `permission_app` is present (usually `~/Applications/Codex iMessage Python.app`), grant FDA there first; do not grant FDA to Ghostty/Terminal unless that terminal binary is the runtime target shown by `doctor`.

If you are unsure which app to grant, use `doctor` as source of truth:
- `Launchd.permission_app` (preferred target)
- `Launchd.runtime_python` (binary target when no app is shown)

A template remains available at `examples/com.codex.imessage-control-plane.plist` for manual customization.

## Cleanup / Uninstall

To remove integration from a host machine (launchd + app bundle + hook wiring + runtime state), follow:
- `docs/cleanup.md`

`docs/cleanup.md` includes both:
- one-shot reset commands, and
- a required post-reset validation checklist (launchd/tmux/process/config/state).

## Documentation

- `AGENTS.md`
- `docs/architecture.md`
- `docs/cleanup.md`
- `docs/control-plane.md`
- `docs/security.md`
- `docs/troubleshooting.md`

## Support Model

This project is maintained on a best-effort basis by contributors.

- No guaranteed response times
- No SLA
- Community PRs and well-scoped bug reports are welcome

## License

MIT. See `LICENSE`.
