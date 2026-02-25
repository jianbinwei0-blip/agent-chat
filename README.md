# agent-chat

`agent-chat` is a macOS-only runtime that connects Codex or Claude sessions to iMessage and/or Telegram.

`README.md` is the canonical setup guide for both humans and coding agents.
`AGENTS.md` is intentionally lightweight and points back here.

Canonical naming in this repository now uses `agent-chat` / `agent_chat_*`.

It provides one control-plane process that can:
- forward Codex/Claude `notify` payloads to iMessage and/or Telegram
- read inbound iMessage replies from Messages `chat.db`
- read inbound Telegram bot updates
- route replies back to the right Codex/Claude session (including tmux-based routing)
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
- Codex CLI or Claude CLI installed and authenticated
- Optional but recommended: tmux
- Bundled sender script at `scripts/send-imessage.applescript` (no external path required)

Privacy/Security permissions required on macOS:
- `Automation`: allow the launchd runtime app/Python and `osascript` to control `Messages`
- `Full Disk Access`: grant the launchd runtime app or Python binary (shown by setup commands) so it can read `~/Library/Messages/chat.db`

## Quickstart

1. Clone and enter the repo.

```bash
cd /path/to/agent-chat
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
export AGENT_IMESSAGE_TO="+15555550123"
export AGENT_CHAT_HOME="$HOME/.codex"
export AGENT_CHAT_NOTIFY_MODE="route"
export PYTHON_BIN

# Optional transport mode:
#   imessage (default), telegram, or both
# export AGENT_CHAT_TRANSPORT="telegram"
# export AGENT_TELEGRAM_BOT_TOKEN="<bot token>"
# export AGENT_TELEGRAM_CHAT_ID="<chat id>"
# export AGENT_TELEGRAM_API_BASE="https://api.telegram.org"

# Optional: switch runtime from codex (default) to claude
# export AGENT_CHAT_AGENT="claude"
# export CLAUDE_HOME="$HOME/.claude"
```

If you use Telegram transport (`AGENT_CHAT_TRANSPORT=telegram|both`), get a bot token first:

1. Open Telegram and chat with `@BotFather`.
2. Run `/newbot` to create a bot (or `/token` for an existing bot).
3. Copy the HTTP API token and set:
   - `export AGENT_TELEGRAM_BOT_TOKEN="<bot token>"`

4. Configure notify hook for your agent runtime.

```bash
"$PYTHON_BIN" agent_chat_control_plane.py setup-notify-hook \
  --agent "${AGENT_CHAT_AGENT:-codex}" \
  --recipient "${AGENT_IMESSAGE_TO:-}" \
  --python-bin "$PYTHON_BIN"
```

`--recipient` is required only when transport includes iMessage (`AGENT_CHAT_TRANSPORT=imessage|both`).
When transport includes Telegram, setup also requires `AGENT_TELEGRAM_BOT_TOKEN`; if missing, setup prints BotFather steps and exits.

This updater is idempotent:
- `--agent codex`: writes `notify` at top-level in `~/.codex/config.toml`
- `--agent claude`: writes hook commands under `hooks.Notification` and `hooks.Stop` in `~/.claude/settings.json`

Compatibility note:
- Current Codex releases parse `notify` as a sequence (array), not a string command.

5. Install and start launchd (recommended).

```bash
"$PYTHON_BIN" agent_chat_control_plane.py setup-launchd \
  --agent "${AGENT_CHAT_AGENT:-codex}" \
  --recipient "${AGENT_IMESSAGE_TO:-}" \
  --python-bin "$PYTHON_BIN"
"$PYTHON_BIN" agent_chat_control_plane.py doctor --agent "${AGENT_CHAT_AGENT:-codex}"
```

`--recipient` is required only when transport includes iMessage (`AGENT_CHAT_TRANSPORT=imessage|both`).
When transport includes Telegram, setup also requires `AGENT_TELEGRAM_BOT_TOKEN`; if missing, setup prints BotFather steps and exits.

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
"$PYTHON_BIN" agent_chat_control_plane.py run
```

7. Optional one-cycle smoke test.

```bash
"$PYTHON_BIN" agent_chat_control_plane.py once --trace
```

## First-Run Failure Modes

`setup-notify-hook` / `setup-launchd` exits with `Require Python 3.11+`:
- On some macOS hosts, `python3` in `PATH` still points to Apple Python 3.9.
- Use an explicit 3.11+ binary, then re-run setup:
  - `PYTHON_BIN=/opt/homebrew/bin/python3.13` (or another installed 3.11+ path)
  - `"$PYTHON_BIN" agent_chat_control_plane.py setup-notify-hook --recipient "$AGENT_IMESSAGE_TO" --python-bin "$PYTHON_BIN"`
  - `"$PYTHON_BIN" agent_chat_control_plane.py setup-launchd --recipient "$AGENT_IMESSAGE_TO" --python-bin "$PYTHON_BIN"`

`doctor` says `notify hook is not configured...` or `unable to parse ~/.codex/config.toml`:
- Re-run:
  - `"$PYTHON_BIN" agent_chat_control_plane.py setup-notify-hook --recipient "$AGENT_IMESSAGE_TO" --python-bin "$PYTHON_BIN"`

`setup-launchd` says shell can read `chat.db` but launchd cannot:
- Grant Full Disk Access to `permission_app` shown by `doctor` (usually `~/Applications/Codex iMessage Python.app`).
- Re-run:
  - `"$PYTHON_BIN" agent_chat_control_plane.py setup-launchd --recipient "$AGENT_IMESSAGE_TO" --python-bin "$PYTHON_BIN" --skip-permissions`
  - `"$PYTHON_BIN" agent_chat_control_plane.py doctor`
- If this keeps repeating after Python upgrades/reinstalls, run:
  - `"$PYTHON_BIN" agent_chat_control_plane.py setup-launchd --recipient "$AGENT_IMESSAGE_TO" --python-bin "$PYTHON_BIN" --repair-tcc`
  - This attempts to reset stale TCC Full Disk Access approval for the runtime bundle id and re-runs permission setup.

`setup-launchd` keeps failing with shell/runtime readable but launchd still denied (even after granting FDA):
- Cause can be stale TCC code requirements for `org.python.python` after Python upgrades/reinstalls.
- Check for TCC mismatch signals:
  - `/usr/bin/log show --style syslog --last 15m --predicate 'subsystem == "com.apple.TCC" && eventMessage CONTAINS "kTCCServiceSystemPolicyAllFiles" && eventMessage CONTAINS "org.python.python"'`
  - look for: `Failed to match existing code requirement for subject org.python.python`
- Reset stale approvals, then grant again in System Settings:
  - `tccutil reset SystemPolicyAllFiles org.python.python`
  - re-enable FDA for `~/Applications/Codex iMessage Python.app`
  - re-run `setup-launchd` and `doctor`
- Shortcut:
  - `"$PYTHON_BIN" agent_chat_control_plane.py setup-launchd --recipient "$AGENT_IMESSAGE_TO" --python-bin "$PYTHON_BIN" --repair-tcc`

`doctor` transiently shows `control-plane lock PID not alive` immediately after restart:
- Wait 1-2 seconds and run `doctor` again.

## Public Interfaces

### CLI commands

```bash
# Unified control plane
python3 agent_chat_control_plane.py run [--agent codex|claude] [--poll 0.5] [--dry-run] [--trace]
python3 agent_chat_control_plane.py once [--agent codex|claude] [--dry-run] [--trace]
python3 agent_chat_control_plane.py notify [--agent codex|claude] [PAYLOAD_JSON] [--dry-run]
python3 agent_chat_control_plane.py doctor [--agent codex|claude] [--json]
python3 agent_chat_control_plane.py setup-notify-hook [--agent codex|claude] [--recipient TO] [--python-bin PATH]
python3 agent_chat_control_plane.py setup-permissions [--agent codex|claude] [--timeout 180] [--poll 1.0] [--no-open]
python3 agent_chat_control_plane.py setup-launchd [--agent codex|claude] [--label LABEL] [--recipient TO] [--python-bin PATH] [--skip-permissions] [--timeout 180] [--poll 1.0] [--no-open]

# Notify helper (best-effort)
python3 agent_chat_notify.py attention [--cwd DIR] [--need TEXT] [--to RECIPIENT] [--dry-run]
python3 agent_chat_notify.py route [--cwd DIR] [--need TEXT] [--to RECIPIENT] [--dry-run] [PAYLOAD_JSON]

# Installed console scripts
agent-chat ...
agent-chat-notify ...
agent-chat-outbound ...
agent-chat-reply ...
```

### Inbound command grammar (iMessage / Telegram)

When inbound routing is enabled (from iMessage and/or Telegram), reply messages support:
- `help`
- `list`
- `status @<session_ref>`
- `@<session_ref> <instruction>`
- `new <label>: <instruction>`

### Important environment variables

- `AGENT_IMESSAGE_TO`: destination phone number or Apple ID email (required for `imessage` / `both`)
- `AGENT_CHAT_HOME`: runtime home directory for Codex state (defaults to `~/.codex`)
- `AGENT_CHAT_NOTIFY_MODE`: `send`, `state_only`, or `route`
- `AGENT_CHAT_TRANSPORT`: `imessage` (default), `telegram`, or `both`
- `AGENT_TELEGRAM_BOT_TOKEN`: Telegram bot token (required for `telegram` / `both`)
- `AGENT_TELEGRAM_CHAT_ID`: Telegram chat ID to send to / accept inbound from (required for `telegram` / `both`)
- `AGENT_TELEGRAM_API_BASE`: Telegram API base URL override (optional; default `https://api.telegram.org`)
- `AGENT_TELEGRAM_INBOUND_CURSOR`: Telegram inbound cursor path override
- `AGENT_IMESSAGE_CHAT_DB`: override Messages database path (default `~/Library/Messages/chat.db`)
- `AGENT_CHAT_QUEUE`: fallback queue JSONL path
- `AGENT_IMESSAGE_MAX_LEN`: max outgoing message chunk size
- `AGENT_CHAT_INBOUND_POLL_S`: control-plane polling interval for `run`
- `AGENT_CHAT_STRICT_TMUX`: strict tmux routing mode (`1` default)
- `AGENT_CHAT_REQUIRE_SESSION_REF`: require explicit `@ref` for ambiguous replies
- `AGENT_CHAT_TMUX_ACK_TIMEOUT_S`: tmux dispatch acknowledgement timeout
- `AGENT_CHAT_ROUTE_VIA_TMUX`: route responses through tmux (`1` default)
- `AGENT_CHAT_ENABLE_NEW_SESSION`: allow creating sessions from inbound messages (`1` default)
- `AGENT_CHAT_AUTO_CREATE_ON_MISSING`: auto-create when no session matches (`1` default)
- `AGENT_CHAT_LAUNCHD_LABEL`: launchd service label used by `doctor`

## Launchd

Use:

```bash
python3 agent_chat_control_plane.py setup-launchd
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

Tip: `python3 agent_chat_control_plane.py doctor` now shows both `runtime_python` and `permission_app` under Launchd so you can grant FDA to the exact runtime target.

When `permission_app` is present (usually `~/Applications/Codex iMessage Python.app`), grant FDA there first; do not grant FDA to terminal apps unless that terminal binary is the runtime target shown by `doctor`.

If you are unsure which app to grant, use `doctor` as source of truth:
- `Launchd.permission_app` (preferred target)
- `Launchd.runtime_python` (binary target when no app is shown)

Template for manual customization:
- `examples/com.agent-chat.plist`

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
