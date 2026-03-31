# Agent Messaging Control Plane

## Runtime Contract

- Authoritative long-lived process: launchd label defaults to `com.agent-chat`.
- Codex/Claude `notify` hooks forward payloads only; they do not spawn daemons. Pi is integrated through session polling plus direct CLI/tmux control.
- Single process handles:
  - outbound needs-input notifications plus Discord session-channel updates
  - inbound iMessage replies from `chat.db`
  - inbound Telegram bot updates
  - inbound Discord control-channel, session-channel, and thread polling for bot interactions
  - session routing (tmux + resume fallback)
  - fallback queue draining

## Data Flow

1. Codex or Claude emits notify payload to `agent_chat_control_plane.py notify`; Pi is observed through session files and direct CLI/tmux control.
2. Control plane updates session registry and sends routed messages for the active transport set.
3. During `run`, control plane tails runtime session JSONL, polls `~/Library/Messages/chat.db` only when transport includes iMessage, fetches Telegram updates when transport includes Telegram, and polls configured Discord channels/threads when transport includes Discord.
4. Replies are routed by `@ref`, reply context, or missing-session choice flow.
   - when no target session matches, control plane asks for runtime choice (`Codex`/`Claude`/`Pi`) before creating a background session.
   - for Telegram topics, canonical conversation bindings are checked first for implicit replies.
   - for Discord session channels, implicit inbound routing first checks the session record's stored `discord_channel_id`, then falls back to canonical conversation bindings.
5. When `AGENT_DISCORD_SESSION_CHANNELS=1`, the configured Discord control channel stays unbound; session traffic is routed into auto-created Discord channels bound one-per-session.
6. Failed outbound sends are queued in `~/.codex/tmp/agent_chat_queue.jsonl`; run loop drains queue on subsequent cycles.

## Key State Files

- `~/.codex/tmp/agent_chat_control_plane.lock`
- `~/.codex/tmp/agent_chat_session_registry.json`
- `~/.codex/tmp/agent_chat_message_session_index.json`
- `~/.codex/tmp/agent_chat_control_outbound_cursor.json`
- `~/.codex/tmp/imessage_inbound_cursor.json`
- `~/.codex/tmp/telegram_inbound_cursor.json`
- `~/.codex/tmp/discord_inbound_cursor.json`
- `~/.codex/tmp/agent_chat_queue.jsonl`

## Health Checks

```bash
python3 agent_chat_control_plane.py setup-notify-hook --recipient "$AGENT_IMESSAGE_TO" --python-bin "$(command -v python3)"
python3 agent_chat_control_plane.py setup-launchd
python3 agent_chat_control_plane.py setup-permissions
python3 agent_chat_control_plane.py doctor
python3 agent_chat_control_plane.py doctor --json
python3 agent_chat_control_plane.py once --trace
```

`doctor` reports launchd load state, lock PID liveness, chat.db readability, queue depth, cursor/state summary, and routing snapshot:
- strict tmux mode
- require explicit session refs
- selected tmux socket
- active agent pane count/sample
- last dispatch error (if any)
- launchd runtime permission targets (`runtime_python` and `permission_app` when available)

Use `Launchd.permission_app` and `Launchd.runtime_python` as the authoritative Full Disk Access targets. Do not grant FDA to a terminal app unless `doctor` reports that exact terminal binary as `runtime_python`.

## Routing Controls

- `AGENT_CHAT_STRICT_TMUX` (default `1`)
  - `1`: keep strict tmux errors for general pane dispatch failures.
  - exception: if a target session exists but has no usable pane mapping (`tmux_stale` no-pane class), control plane falls back to `resume` so replies still append to that session.
  - `0`: allow agent resume fallback for `tmux_failed`/`tmux_stale`.
- `AGENT_CHAT_REQUIRE_SESSION_REF` (default follows strict mode)
  - when enabled, ambiguous implicit replies require `@<ref> <instruction>`.
- `AGENT_CHAT_TMUX_ACK_TIMEOUT_S` (default `2.0`)
  - controls user-message ack wait window after tmux send.
- `AGENT_CHAT_TRACE` or `run/once --trace`
  - emits per-message routing traces to stderr logs.

## Discord Session-Channel Mode

See `docs/discord.md` for end-to-end Discord setup and operator guidance.

When `AGENT_DISCORD_SESSION_CHANNELS=1`:
- `AGENT_DISCORD_CONTROL_CHANNEL_ID` (or `AGENT_DISCORD_CHANNEL_ID`) is the control channel for `help`, `list`, `status`, and session creation.
- the control channel is intentionally not rebound to a session, so it remains usable as a command surface.
- session output is mirrored to a dedicated Discord channel per session.
- session channels are created lazily on first meaningful outbound delivery, not eagerly for every discovered session.
- each session has at most one bound Discord channel, and each bound session channel maps back to exactly one session.
- plain text in a bound session channel routes back to that session without requiring `@<ref>`.
- inbound routing resolves the target from stored session-channel metadata first, then falls back to generic conversation bindings.
- auto-created session channels can be placed under `AGENT_DISCORD_SESSION_CATEGORY_ID` when configured.
- setup requirements for this mode are: bot token, **Message Content Intent**, access to the control channel, and `Manage Channels` if automatic channel creation is enabled.

## Missing-Session Choice Flow

When an inbound reply targets a missing session (`@ref ...` or implicit resolution miss), control plane records a pending create request and sends:

- `1) Codex`
- `2) Claude`
- `3) Pi`
- `cancel`

Follow-up behavior:
- `1`/`codex`: create a Codex session in background.
- `2`/`claude`: create a Claude session in background.
- `3`/`pi`: create a Pi session in background.
- `cancel`: clear the pending request.

If tmux creation fails after runtime choice, control plane falls back to direct (non-tmux) session creation.
Pending choice scope:
- iMessage / non-threaded: one global pending request; newest unresolved request replaces older state.
- Telegram topics: one pending request per `chat_id:message_thread_id`.
- Discord channel/thread inbound: one pending request per canonical Discord conversation key.

When a runtime choice creates a session from Telegram topic input, the topic is bound to that session. Outbound session messages then include `message_thread_id` so updates stay in the same topic.
Registry migration/load/save keeps Telegram topic bindings canonical (one topic per session, one session per topic), and `telegram_thread_bindings` is treated as the source of truth when it conflicts with per-session topic fields.
To move an existing Codex session to another Telegram topic, send one explicit bind message in the destination topic: `@<session_ref> hello`. The destination topic becomes the session's canonical binding.

## Failure Modes

- `chat.db` unreadable (only relevant when transport includes iMessage):
  - Symptoms: inbound disabled warnings in stderr log.
  - Fix: run `python3 agent_chat_control_plane.py setup-launchd` (recommended) or `setup-permissions`, then grant the exact target printed by setup:
    - `Permission to grant: Full Disk Access (System Settings > Privacy & Security > Full Disk Access).`
    - `Grant Full Disk Access to this app: ...` (preferred when shown)
    - `Grant access to this Python binary: ...`
    - `Detailed steps before the Settings window opens:`
    - `1) In Full Disk Access, add and enable this app: ...` (or binary line when no app is available)
    - `Action required now: ... enable access for app: ...`
  - setup flushes this guidance before opening System Settings, then polls `chat.db` until readable or timeout.
- Apple Events automation denied (`-1743`):
  - Grant Automation permission for the launchd runtime app/Python and `osascript` to control Messages.
- Queue backlog grows:
  - Check Messages automation permissions and run `doctor`.
  - Confirm queue is being drained and launchd service is running.
- Strict tmux routing failures:
  - Symptoms: iMessage receives strict routing error with no fallback response.
  - Fix: ensure target session has a live agent tmux pane and resend with `@<ref> ...`.
  - note: if session metadata exists but pane mapping is missing/stale, control plane now resumes directly (no strict-mode error for this specific case).

## Launchd Runtime Notes

- `setup-launchd` uses the current Python interpreter by default and writes a LaunchAgent plist automatically.
- Full Disk Access/chat.db checks run only when transport includes iMessage (`imessage`/`both`).
- when possible, `setup-launchd` prepares `~/Applications/AgentChatPython.app` and uses its embedded runtime path in LaunchAgent `ProgramArguments`.
- Verify the launchd `ProgramArguments` path points to `agent_chat_control_plane.py`.
- Avoid protected-path mismatches (for example stale script paths under denied folders).
- Grant Full Disk Access to the app or exact Python binary used by launchd (check via `launchctl print ...` and `ps`).

## Logs

- `~/Library/Logs/agent-chat.launchd.out.log`
- `~/Library/Logs/agent-chat.launchd.err.log`
