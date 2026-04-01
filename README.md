# agent-chat

`agent-chat` is a macOS-first runtime that connects Codex, Claude, or Pi sessions to iMessage, Telegram, and/or Discord.

`README.md` is the canonical setup guide for both humans and coding agents.
`AGENTS.md` is intentionally lightweight and points back here.

Canonical naming in this repository now uses `agent-chat` / `agent_chat_*`.

It provides one control-plane process that can:
- forward Codex/Claude notify payloads plus Pi session activity to iMessage, Telegram, and/or Discord
- read inbound iMessage replies from Messages `chat.db`
- read inbound Telegram bot updates
- poll configured Discord control channels, session-bound channels, and active threads for inbound bot interactions
- route replies back to the right Codex/Claude/Pi session (including tmux-based routing)
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
- Codex CLI, Claude CLI, and/or Pi coding agent installed and authenticated
- Required: Homebrew (setup auto-installs when missing)
- Required: tmux (setup auto-installs via Homebrew when missing)
- Bundled sender script at `scripts/send-imessage.applescript` (no external path required)

Privacy/Security permissions required on macOS:
- Telegram-only / Discord-only mode (`AGENT_CHAT_TRANSPORT=telegram|discord` or `AGENT_CHAT_TRANSPORTS=telegram,discord` without iMessage): no Full Disk Access required.
- iMessage mode (`imessage`, `both`, or any `AGENT_CHAT_TRANSPORTS` set that includes `imessage`): grant `Automation` (Messages control) and `Full Disk Access` (read `~/Library/Messages/chat.db`) to the runtime app/Python target printed by setup.

## Guided Setup (Recommended)

If you want the fastest path with the least terminal work, use the guided setup flow:

### Any supported transport

```bash
cd /path/to/agent-chat
bash scripts/setup-agent-chat-easy.sh
```

This interactive flow helps you choose:
- runtime: Codex, Claude, or Pi
- transport: iMessage, Telegram, or Discord
- the minimum required credentials/ids for that transport

It then writes a local env file, runs `setup-notify-hook`, `setup-launchd`, and `doctor`, and prints a first-success checklist.

### Telegram-first shortcut

If you already know you want Telegram, you can still use the Telegram-specific wrapper:

1. In Telegram (once):
   - create or open your bot in `@BotFather`
   - create your target group in Telegram (`New Group`)
   - if you want topic routing, use a supergroup with Topics enabled (`Group Info -> Edit -> Topics`)
   - run `/setprivacy` in `@BotFather` and choose `Disable` for the bot
   - add the bot to your target group
   - promote the bot to admin (`Group Info -> Administrators -> Add Admin`)
   - verify admin permissions include posting messages (and topic management when Topics are enabled)
2. Run:

```bash
cd /path/to/agent-chat
bash scripts/setup-telegram-easy.sh
```

The script will:
- ask whether you want `Codex` or `Claude`
- ask for your Telegram bot token
- save/update `.env.telegram.local`
- run `setup-notify-hook`, `setup-launchd`, and `doctor`

3. First-use check in Telegram:
   - if setup pauses, send one plain message in your target group/topic (this bootstraps chat id)
   - send `list`
   - send `bind @<session_ref>` once to bind the topic to that session (or use `@<session_ref> hello`)
   - send `where` if you want the current topic/session binding explained back to you
   - after binding, plain text in that topic routes automatically
   - if you see `group chat was upgraded to a supergroup`, set `AGENT_TELEGRAM_CHAT_ID` to the returned `migrate_to_chat_id` and rerun `setup-launchd`

## Telegram Golden Paths (Fastest First Success)

Use this section when your goal is Telegram + one runtime with minimum branching.
The full `Quickstart` below still covers iMessage and mixed transport setups.
If you want the simplest guided flow for any supported transport, run `bash scripts/setup-agent-chat-easy.sh`.
If you already know you want Telegram only, `bash scripts/setup-telegram-easy.sh` remains the shortest wrapper.

### Telegram + Codex (5-minute path)

1. Bot and group prep in Telegram (once per bot):
   - in `@BotFather`, run `/newbot` (or `/token`) and copy token
   - run `/setprivacy` for the bot and select `Disable`
   - add bot to target group/topic and promote to admin
2. Repo + env prep:

```bash
cd /path/to/agent-chat
PYTHON_BIN="$(command -v python3)"
"$PYTHON_BIN" --version

cp env.telegram.example .env.telegram.local
# edit .env.telegram.local and set AGENT_TELEGRAM_BOT_TOKEN
source .env.telegram.local

unset AGENT_IMESSAGE_TO
export AGENT_CHAT_AGENT="codex"
export AGENT_CHAT_HOME="${AGENT_CHAT_HOME:-$HOME/.codex}"
```

3. Configure and start:

```bash
"$PYTHON_BIN" agent_chat_control_plane.py setup-notify-hook --agent codex --python-bin "$PYTHON_BIN"
"$PYTHON_BIN" agent_chat_control_plane.py setup-launchd --agent codex --python-bin "$PYTHON_BIN"
"$PYTHON_BIN" agent_chat_control_plane.py doctor --agent codex --json
```

Success markers:
- `setup-notify-hook` prints `Updated notify hook in ~/.codex/config.toml`
- `setup-launchd` exits cleanly (if chat ID is unknown, it waits for one inbound Telegram message)
- `doctor --json` shows:
  - `"agent": "codex"`
  - `"transport.mode": "telegram"`
  - `"transport.telegram_token_present": true`
  - non-empty `"transport.telegram_chat_id"` (or `"transport.telegram_chat_ids"`)
  - `"launchd.loaded": true`

### Telegram + Claude (5-minute path)

1. Use the same bot/group prep as Codex path.
2. Repo + env prep:

```bash
cd /path/to/agent-chat
PYTHON_BIN="$(command -v python3)"
"$PYTHON_BIN" --version

cp env.telegram.example .env.telegram.local
# edit .env.telegram.local and set AGENT_TELEGRAM_BOT_TOKEN
source .env.telegram.local

unset AGENT_IMESSAGE_TO
export AGENT_CHAT_AGENT="claude"
export CLAUDE_HOME="${CLAUDE_HOME:-$HOME/.claude}"
```

3. Configure and start:

```bash
"$PYTHON_BIN" agent_chat_control_plane.py setup-notify-hook --agent claude --python-bin "$PYTHON_BIN"
"$PYTHON_BIN" agent_chat_control_plane.py setup-launchd --agent claude --python-bin "$PYTHON_BIN"
"$PYTHON_BIN" agent_chat_control_plane.py doctor --agent claude --json
```

Success markers:
- `setup-notify-hook` prints `Updated notify hook in ~/.claude/settings.json`
- `setup-launchd` exits cleanly (or pauses for Telegram chat bootstrap message)
- `doctor --json` shows:
  - `"agent": "claude"`
  - `"transport.mode": "telegram"`
  - `"transport.telegram_token_present": true`
  - non-empty `"transport.telegram_chat_id"` (or `"transport.telegram_chat_ids"`)
  - `"launchd.loaded": true`

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

3. Optional Homebrew/tmux preflight (`setup-notify-hook`/`setup-launchd` auto-install both when missing).

```bash
if command -v tmux >/dev/null 2>&1; then
  tmux -V
else
  echo "tmux not found. setup-notify-hook/setup-launchd will auto-install Homebrew (if needed) and run: brew install tmux"
fi
```

4. Set minimum environment.

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

# Optional: switch runtime from Codex (default) to Claude
# export AGENT_CHAT_AGENT="claude"
# export CLAUDE_HOME="$HOME/.claude"
```

If you use Telegram transport (`AGENT_CHAT_TRANSPORT=telegram|both`), get a bot token first:

1. Open Telegram and chat with `@BotFather`.
2. Run `/newbot` to create a bot (or `/token` for an existing bot).
3. Copy the HTTP API token and set:
   - `export AGENT_TELEGRAM_BOT_TOKEN="<bot token>"`

Telegram topic/supergroup setup (recommended):

1. Create a Telegram group in the client app (`New Group`) and add at least one human member.
2. If you want per-topic routing, enable Topics for that group (`Group Info -> Edit -> Topics`), which uses supergroup behavior.
3. In `@BotFather`, run `/setprivacy`, choose your bot, and select `Disable`.
4. Add the bot to that group.
5. Promote the bot to admin (`Group Info -> Administrators -> Add Admin`) and allow message posting (plus topic-management permissions when Topics are enabled).
6. Set chat routing env vars:
   - `export AGENT_CHAT_TRANSPORT="telegram"`
   - optional: `export AGENT_TELEGRAM_CHAT_ID="<group chat id>"` (example: `-1003836591224`)
   - optional: `export AGENT_TELEGRAM_CHAT_IDS="<group chat id>,<owner user id>"` for multiple allowed inbound sources.
   - for topic-enabled groups, chat ids are typically supergroup ids beginning with `-100`.
7. Start the control plane (`setup-launchd` or `run`).
   - If `AGENT_TELEGRAM_CHAT_ID`/`AGENT_TELEGRAM_CHAT_IDS` are missing, `setup-launchd` enters Telegram bootstrap mode and waits for a message from the target group/topic to auto-detect the group chat id.
   - On macOS with default setup behavior (without `--no-open`), setup may also open a Telegram deep link (`startgroup`) to speed up bot/group onboarding.
   - Telegram Bot API cannot create a group on your behalf; group creation still happens in the Telegram client.
8. In the target topic, send one explicit bind message to establish session/topic mapping:
   - `bind @<session_ref>` (or the legacy `@<session_ref> hello`)
9. Optional: send `where` to see what the current topic is bound to.
10. After binding, plain text in that topic routes to the bound session. You do not need direct-reply or `@bot` mention for every message.
11. Move an existing Codex session to a different topic:
   - In the destination topic, send `bind @<session_ref>` once.
   - Binding is canonicalized as one-topic-per-session and one-session-per-topic, so the session follows the new topic automatically.

If topic messages are not received after setup:
- remove and re-add the bot to the group after privacy changes, then promote to admin again.
- verify no other process is consuming the same bot token via `getUpdates` (look for HTTP `409 Conflict`).
- if Telegram API returns `group chat was upgraded to a supergroup`, update to `migrate_to_chat_id`, then rerun `setup-launchd` and `doctor`.

Discord setup (recommended for control channel + per-session channels):

See `docs/discord.md` for the full guide.

High-level checklist:
- create/invite the bot and enable **Message Content Intent**
- choose one Discord control channel
- optionally configure a category for auto-created session channels
- grant `View Channel`, `Send Messages`, `Read Message History`, and `Manage Channels` when using session-channel mode
- set `AGENT_DISCORD_BOT_TOKEN`, `AGENT_DISCORD_CONTROL_CHANNEL_ID`, and `AGENT_DISCORD_SESSION_CHANNELS=1` as needed

Behavior summary:
- the control channel stays unbound and handles commands like `help`, `list`, `where`, `status`, and `new ...`
- session channels are created lazily and bind one channel to one session
- plain text in a bound session channel routes back to that same session without `@<ref>`
- send `bind @<session_ref>` to move the current topic/channel/thread to another session

6. Configure notify hook for your agent runtime.

```bash
"$PYTHON_BIN" agent_chat_control_plane.py setup-notify-hook \
  --agent "${AGENT_CHAT_AGENT:-codex}" \
  --recipient "${AGENT_IMESSAGE_TO:-}" \
  --python-bin "$PYTHON_BIN"
```

`--recipient` is required only when transport includes iMessage (`AGENT_CHAT_TRANSPORT=imessage|both`).
When transport includes Telegram, setup requires `AGENT_TELEGRAM_BOT_TOKEN`; if missing, setup prints BotFather steps and exits.
When transport includes Discord, setup requires `AGENT_DISCORD_BOT_TOKEN`; if missing, setup exits with Discord token setup guidance.
`setup-notify-hook` and `setup-launchd` require Homebrew + tmux. If missing, setup first attempts automatic Homebrew install, then runs `brew install tmux`.

This updater is idempotent:
- `--agent codex`: writes `notify` at top-level in `~/.codex/config.toml`
- `--agent claude`: writes hook commands under `hooks.Notification` and `hooks.Stop` in `~/.claude/settings.json`

Compatibility note:
- Current Codex releases parse `notify` as a sequence (array), not a string command.

7. Install and start launchd (recommended).

```bash
"$PYTHON_BIN" agent_chat_control_plane.py setup-launchd \
  --agent "${AGENT_CHAT_AGENT:-codex}" \
  --recipient "${AGENT_IMESSAGE_TO:-}" \
  --python-bin "$PYTHON_BIN"
"$PYTHON_BIN" agent_chat_control_plane.py doctor --agent "${AGENT_CHAT_AGENT:-codex}"
```

`--recipient` is required only when transport includes iMessage (`AGENT_CHAT_TRANSPORT=imessage|both`).
When transport includes Telegram, setup requires `AGENT_TELEGRAM_BOT_TOKEN`; if missing, setup prints BotFather steps and exits.
When transport includes Discord, setup requires `AGENT_DISCORD_BOT_TOKEN`; if missing, setup exits with Discord token setup guidance.
If Telegram chat IDs are missing, `setup-launchd` now waits for an inbound message from the target group/topic and auto-detects `AGENT_TELEGRAM_CHAT_ID`.

`setup-launchd` writes `~/Library/LaunchAgents/<label>.plist` and bootstraps the service.
If transport includes iMessage (`imessage`/`both`), setup also runs the `chat.db` Full Disk Access check first using the same runtime binary it configures for launchd.
If transport is `telegram` or `discord` only, `chat.db` Full Disk Access setup is skipped.
When the selected Python install provides `Python.app`, setup also prepares a visible target at `~/Applications/AgentChatPython.app` (symlink-first, copy fallback) and uses that app's embedded runtime binary for launchd/FDA guidance.

During permission setup, follow the command output exactly. It prints:
- `Permission to grant: Full Disk Access (System Settings > Privacy & Security > Full Disk Access).`
- `Grant Full Disk Access to this app: ...` (when available)
- `Grant access to this Python binary: ...`
- `Detailed steps before the Settings window opens:`
- `1) In Full Disk Access, add and enable this app: ...` (or the Python binary line when no app is provided)
- `Action required now: ... enable access for app: ...`

Grant Full Disk Access to one of those printed targets (prefer the app path when shown), keep the command running, and wait for:
- `Full Disk Access confirmed: chat.db is now readable.`

`setup-permissions` now flushes and prints the detailed grant target instructions before opening System Settings. It then starts polling `chat.db` and keeps polling until readable or timeout.
`setup-permissions` is only needed when transport includes iMessage (`imessage`/`both`).

8. Optional: run in foreground instead of launchd.

```bash
"$PYTHON_BIN" agent_chat_control_plane.py run
```

9. Optional one-cycle smoke test.

```bash
"$PYTHON_BIN" agent_chat_control_plane.py once --trace
```

10. Optional Telegram diagnostics helper (Codex + Claude setups).

```bash
scripts/telegram-diagnose.sh
# deterministic upstream probe:
# scripts/telegram-diagnose.sh --pause-launchd
```

## Launchd and Permissions

Use:

```bash
python3 agent_chat_control_plane.py setup-launchd
```

This command:
- writes `~/Library/LaunchAgents/<label>.plist`
- uses the current Python interpreter by default (`--python-bin` to override)
- attempts to provision a visible FDA target app at `~/Applications/AgentChatPython.app` (symlink-first, copy fallback)
- reuses an existing healthy `~/Applications/AgentChatPython.app` when present to preserve Full Disk Access grants
- bootstraps + kickstarts the agent via `launchctl`
- runs `setup-permissions` by default so launchd can read `chat.db`

`setup-permissions` prefers launchd runtime targets from the installed plist when available, so FDA guidance aligns with what launchd actually executes.

If `setup-launchd` reports that the shell can read `chat.db` but launchd cannot, grant Full Disk Access to the app or Python binary shown in command output, then re-run `setup-launchd`.

Tip: `python3 agent_chat_control_plane.py doctor` now shows both `runtime_python` and `permission_app` under Launchd so you can grant FDA to the exact runtime target.

When `permission_app` is present (usually `~/Applications/AgentChatPython.app`), grant FDA there first; do not grant FDA to terminal apps unless that terminal binary is the runtime target shown by `doctor`.

If you are unsure which app to grant, use `doctor` as source of truth:
- `Launchd.permission_app` (preferred target)
- `Launchd.runtime_python` (binary target when no app is shown)

Template for manual customization:
- `examples/com.agent-chat.plist`

## Validate a Live Roundtrip (Telegram)

After setup succeeds, validate real routing in under a minute:

1. In the target Telegram topic/group, send `list` to inspect active session refs.
2. Send one explicit bind message: `bind @<session_ref>` (or `@<session_ref> hello`).
3. Optionally send `where` to confirm the topic/session binding in plain English.
4. Expect a routed response in the same topic; this establishes topic/session mapping.
5. Send plain text (for example `status @<session_ref>` or `continue`) in the same topic.
6. If no response arrives, run:

```bash
scripts/telegram-diagnose.sh --pause-launchd
```

If diagnostics report `HTTP 409 Conflict`, stop the competing `getUpdates` consumer and retry.

## Assisted Setup Prompts

You can ask Codex CLI or Claude CLI to run this setup end-to-end using the same idempotent commands.

### Codex prompt template

From the `agent-chat` repo root, run Codex and provide:

```text
Read README.md and set up agent-chat for Codex.
Homebrew + tmux are required; if missing, let setup auto-install both.
Use Python 3.11+ preflight checks.
Configure transport=telegram with AGENT_TELEGRAM_BOT_TOKEN from my environment.
If AGENT_TELEGRAM_CHAT_ID is missing, run setup-launchd bootstrap flow and capture it from inbound group/topic message.
Unset AGENT_IMESSAGE_TO for telegram-only mode.
Run:
- python3 agent_chat_control_plane.py setup-notify-hook --agent codex --python-bin "$(command -v python3)"
- python3 agent_chat_control_plane.py setup-launchd --agent codex --python-bin "$(command -v python3)"
- python3 agent_chat_control_plane.py doctor --agent codex --json
Then report updated files and health status.
```

### Claude prompt template

From the same repo root, run Claude and provide:

```text
Read README.md and set up agent-chat for Claude.
Homebrew + tmux are required; if missing, let setup auto-install both.
Use Python 3.11+ preflight checks.
Configure transport=telegram with AGENT_TELEGRAM_BOT_TOKEN from my environment.
If AGENT_TELEGRAM_CHAT_ID is missing, run setup-launchd bootstrap flow and capture it from inbound group/topic message.
Unset AGENT_IMESSAGE_TO for telegram-only mode.
Set CLAUDE_HOME if needed.
Run:
- python3 agent_chat_control_plane.py setup-notify-hook --agent claude --python-bin "$(command -v python3)"
- python3 agent_chat_control_plane.py setup-launchd --agent claude --python-bin "$(command -v python3)"
- python3 agent_chat_control_plane.py doctor --agent claude --json
Then report updated files and health status.
```

## Troubleshooting Shortcuts

For detailed recovery steps, see `docs/troubleshooting.md`.

Most first-run issues reduce to one of these:
- Python from `PATH` is below `3.11`
- Homebrew or tmux is missing
- notify-hook config needs to be re-written
- launchd has not been granted the right iMessage permissions target
- Telegram/Discord bot setup is incomplete

Recommended recovery loop:

```bash
python3 agent_chat_control_plane.py setup-notify-hook --agent "${AGENT_CHAT_AGENT:-codex}" --python-bin "$(command -v python3)"
python3 agent_chat_control_plane.py setup-launchd --agent "${AGENT_CHAT_AGENT:-codex}" --python-bin "$(command -v python3)"
python3 agent_chat_control_plane.py doctor --json
```

If `doctor` still shows problems, jump to:
- `docs/troubleshooting.md`
- `docs/control-plane.md`
- `docs/discord.md` for Discord-specific issues

## Reference

### CLI commands

```bash
# Unified control plane
python3 agent_chat_control_plane.py run [--agent codex|claude|pi] [--poll 0.5] [--dry-run] [--trace]
python3 agent_chat_control_plane.py once [--agent codex|claude|pi] [--dry-run] [--trace]
python3 agent_chat_control_plane.py notify [--agent codex|claude|pi] [PAYLOAD_JSON] [--dry-run]
python3 agent_chat_control_plane.py doctor [--agent codex|claude|pi] [--json]
python3 agent_chat_control_plane.py guided-setup [--agent codex|claude|pi] [--transport telegram|discord|imessage] [--env-file PATH] [transport-specific options]
python3 agent_chat_control_plane.py setup-notify-hook [--agent codex|claude|pi] [--recipient TO] [--python-bin PATH]
python3 agent_chat_control_plane.py setup-permissions [--agent codex|claude|pi] [--timeout 180] [--poll 1.0] [--no-open]
python3 agent_chat_control_plane.py setup-launchd [--agent codex|claude|pi] [--label LABEL] [--recipient TO] [--python-bin PATH] [--skip-permissions] [--timeout 180] [--poll 1.0] [--no-open]

# Notify helper (best-effort)
python3 agent_chat_notify.py attention [--cwd DIR] [--need TEXT] [--to RECIPIENT] [--dry-run]
python3 agent_chat_notify.py route [--cwd DIR] [--need TEXT] [--to RECIPIENT] [--dry-run] [PAYLOAD_JSON]

# Installed console scripts
agent-chat ...
agent-chat-notify ...
agent-chat-outbound ...
agent-chat-reply ...
```

### Inbound commands and routing

Common inbound commands:
- `help`
- `list`
- `where` / `context`
- `status @<session_ref>`
- `bind @<session_ref>`
- `@<session_ref> <instruction>`
- `new <label>: <instruction>`

On first use in a Telegram topic, Discord channel/thread, or iMessage control surface, agent-chat now appends a short quick-start hint so users can discover `list`, `where`, `bind`, and `new ...` in-context.

When no target session can be resolved, agent-chat asks which runtime to create:
- `1` / `codex`
- `2` / `claude`
- `3` / `pi`
- `cancel`

For the full routing contract, pending-choice scoping, Telegram topic behavior, and Discord session-channel behavior, see:
- `docs/control-plane.md`
- `docs/discord.md`

### Important environment variables

Most setups only need a small subset:
- `AGENT_CHAT_AGENT`
- `AGENT_CHAT_TRANSPORT` or `AGENT_CHAT_TRANSPORTS`
- `AGENT_CHAT_HOME`
- `AGENT_IMESSAGE_TO` for iMessage
- `AGENT_TELEGRAM_BOT_TOKEN` and optionally `AGENT_TELEGRAM_CHAT_ID` for Telegram
- `AGENT_DISCORD_BOT_TOKEN` and `AGENT_DISCORD_CONTROL_CHANNEL_ID` for Discord

Frequently used advanced overrides:
- `AGENT_CHAT_STRICT_TMUX`
- `AGENT_CHAT_REQUIRE_SESSION_REF`
- `AGENT_CHAT_TMUX_ACK_TIMEOUT_S`
- `AGENT_CHAT_ROUTE_VIA_TMUX`
- `AGENT_CHAT_ENABLE_NEW_SESSION`
- `AGENT_CHAT_AUTO_CREATE_ON_MISSING`
- `AGENT_CHAT_LAUNCHD_LABEL`
- `AGENT_CHAT_NOTIFICATION_LEVEL` (`quiet`, `default`, `verbose`)

`AGENT_CHAT_NOTIFICATION_LEVEL` controls autonomous session-update noise:
- `quiet`: only urgent prompts/errors; suppress automatic completion/update notifications
- `default`: automatic completion notifications, plus Discord session-channel progress updates
- `verbose`: automatic completion notifications and progress updates across enabled transports

For the full environment reference, see:
- `docs/control-plane.md`
- `docs/discord.md` for Discord-specific variables

## Cleanup / Uninstall

To remove integration from a host machine (launchd + app bundle + hook wiring + runtime state), follow:
- `docs/cleanup.md`

`docs/cleanup.md` includes both:
- one-shot reset commands, and
- a required post-reset validation checklist (launchd/tmux/process/config/state).

## Documentation

- `AGENTS.md` (table of contents for agents)
- `docs/index.md` (knowledge-system entrypoint)
- `docs/architecture.md`
- `docs/changelog.md`
- `docs/cleanup.md`
- `docs/control-plane.md`
- `docs/discord.md`
- `docs/exec-plans/README.md`
- `docs/exec-plans/tech-debt-tracker.md`
- `docs/security.md`
- `docs/troubleshooting.md`

## Support Model

This project is maintained on a best-effort basis by contributors.

- No guaranteed response times
- No SLA
- Community PRs and well-scoped bug reports are welcome

## License

MIT. See `LICENSE`.
