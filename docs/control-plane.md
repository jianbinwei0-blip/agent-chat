# Agent Messaging Control Plane

## Runtime Contract

- Authoritative long-lived process: launchd label defaults to `com.agent-chat`.
- Codex/Claude `notify` hooks forward payloads only; they do not spawn daemons.
- Single process handles:
  - outbound needs-input notifications to iMessage and/or Telegram
  - inbound iMessage replies from `chat.db`
  - inbound Telegram bot updates
  - session routing (tmux + resume fallback)
  - fallback queue draining

## Data Flow

1. Codex or Claude emits notify payload to `agent_chat_control_plane.py notify`.
2. Control plane updates session registry and sends routed messages for active transport mode.
3. During `run`, control plane tails session JSONL, polls `~/Library/Messages/chat.db`, and fetches Telegram updates.
4. Replies are routed by `@ref`, reply context, or missing-session choice flow.
   - when no target session matches, control plane asks for runtime choice (`Codex`/`Claude`) before creating a background session.
   - for Telegram topics, thread binding (`chat_id:message_thread_id -> session_id`) is checked first for implicit replies.
5. Failed outbound sends are queued in `~/.codex/tmp/agent_chat_queue.jsonl`; run loop drains queue on subsequent cycles.

## Key State Files

- `~/.codex/tmp/agent_chat_control_plane.lock`
- `~/.codex/tmp/agent_chat_session_registry.json`
- `~/.codex/tmp/agent_chat_message_session_index.json`
- `~/.codex/tmp/agent_chat_control_outbound_cursor.json`
- `~/.codex/tmp/imessage_inbound_cursor.json`
- `~/.codex/tmp/telegram_inbound_cursor.json`
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

## Missing-Session Choice Flow

When an inbound reply targets a missing session (`@ref ...` or implicit resolution miss), control plane records a pending create request and sends:

- `1) Codex`
- `2) Claude`
- `cancel`

Follow-up behavior:
- `1`/`codex`: create Codex session in background.
- `2`/`claude`: create Claude session in background.
- `cancel`: clear the pending request.

If tmux creation fails after runtime choice, control plane falls back to direct (non-tmux) session creation.
Pending choice scope:
- iMessage / non-threaded: one global pending request; newest unresolved request replaces older state.
- Telegram topics: one pending request per `chat_id:message_thread_id`.

When a runtime choice creates a session from Telegram topic input, the topic is bound to that session. Outbound session messages then include `message_thread_id` so updates stay in the same topic.

## Failure Modes

- `chat.db` unreadable:
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
- when possible, `setup-launchd` prepares `~/Applications/AgentChatPython.app` and uses its embedded runtime path in LaunchAgent `ProgramArguments`.
- Verify the launchd `ProgramArguments` path points to `agent_chat_control_plane.py`.
- Avoid protected-path mismatches (for example stale script paths under denied folders).
- Grant Full Disk Access to the app or exact Python binary used by launchd (check via `launchctl print ...` and `ps`).

## Logs

- `~/Library/Logs/agent-chat.launchd.out.log`
- `~/Library/Logs/agent-chat.launchd.err.log`
