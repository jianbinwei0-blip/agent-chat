# Codex iMessage Control Plane

## Runtime Contract

- Authoritative long-lived process: `com.codex.imessage-control-plane` (launchd).
- Codex `notify` hook forwards payloads only; it does not spawn daemons.
- Single process handles:
  - outbound needs-input notifications
  - inbound iMessage replies from `chat.db`
  - session/tmux routing
  - fallback queue draining

## Data Flow

1. Codex emits notify payload to `codex_imessage_control_plane.py notify`.
2. Control plane updates session registry and sends routed iMessages.
3. During `run`, control plane tails session JSONL and polls `~/Library/Messages/chat.db`.
4. Replies are routed by `@ref`, reply context, or auto-create logic.
5. Failed outbound sends are queued in `~/.codex/tmp/imessage_queue.jsonl`; run loop drains queue on subsequent cycles.

## Key State Files

- `~/.codex/tmp/imessage_control_plane.lock`
- `~/.codex/tmp/imessage_session_registry.json`
- `~/.codex/tmp/imessage_message_session_index.json`
- `~/.codex/tmp/imessage_control_outbound_cursor.json`
- `~/.codex/tmp/imessage_inbound_cursor.json`
- `~/.codex/tmp/imessage_queue.jsonl`

## Health Checks

```bash
python3 codex_imessage_control_plane.py setup-notify-hook --recipient "$CODEX_IMESSAGE_TO" --python-bin "$(command -v python3)"
python3 codex_imessage_control_plane.py setup-launchd
python3 codex_imessage_control_plane.py setup-permissions
python3 codex_imessage_control_plane.py doctor
python3 codex_imessage_control_plane.py doctor --json
python3 codex_imessage_control_plane.py once --trace
```

`doctor` reports launchd load state, lock PID liveness, chat.db readability, queue depth, cursor/state summary, and routing snapshot:
- strict tmux mode
- require explicit session refs
- selected tmux socket
- active Codex pane count/sample
- last dispatch error (if any)
- launchd runtime permission targets (`runtime_python` and `permission_app` when available)

Use `Launchd.permission_app` and `Launchd.runtime_python` as the authoritative Full Disk Access targets. Do not grant FDA to a terminal app unless `doctor` reports that exact terminal binary as `runtime_python`.

## Routing Controls

- `CODEX_IMESSAGE_STRICT_TMUX` (default `1`)
  - `1`: never run non-tmux resume fallback when pane dispatch fails.
  - `0`: allow codex resume fallback for `tmux_failed`/`tmux_stale`.
- `CODEX_IMESSAGE_REQUIRE_SESSION_REF` (default follows strict mode)
  - when enabled, ambiguous implicit replies require `@<ref> <instruction>`.
- `CODEX_IMESSAGE_TMUX_ACK_TIMEOUT_S` (default `2.0`)
  - controls user-message ack wait window after tmux send.
- `CODEX_IMESSAGE_TRACE` or `run/once --trace`
  - emits per-message routing traces to stderr logs.

## Failure Modes

- `chat.db` unreadable:
  - Symptoms: inbound disabled warnings in stderr log.
  - Fix: run `python3 codex_imessage_control_plane.py setup-launchd` (recommended) or `setup-permissions`, then grant the exact target printed by setup:
    - `Permission to grant: Full Disk Access (System Settings > Privacy & Security > Full Disk Access).`
    - `Grant Full Disk Access to this app: ...` (preferred when shown)
    - `Grant access to this Python binary: ...`
  - setup starts polling `chat.db` before opening System Settings and keeps polling until readable or timeout.
- Apple Events automation denied (`-1743`):
  - Grant Automation permission for terminal/osascript to control Messages.
- Queue backlog grows:
  - Check Messages automation permissions and run `doctor`.
  - Confirm queue is being drained and launchd service is running.
- Strict tmux routing failures:
  - Symptoms: iMessage receives strict routing error with no fallback response.
  - Fix: ensure target session has a live Codex tmux pane and resend with `@<ref> ...`.

## Launchd Runtime Notes

- `setup-launchd` uses the current Python interpreter by default and writes a LaunchAgent plist automatically.
- when possible, `setup-launchd` prepares `~/Applications/Codex iMessage Python.app` and uses its embedded runtime path in LaunchAgent `ProgramArguments`.
- Verify the launchd `ProgramArguments` path points to the intended control-plane script.
- Avoid protected-path mismatches (for example stale script paths under denied folders).
- Grant Full Disk Access to the app or exact Python binary used by launchd (check via `launchctl print ...` and `ps`).

## Logs

- `~/Library/Logs/codex-imessage-control-plane.launchd.out.log`
- `~/Library/Logs/codex-imessage-control-plane.launchd.err.log`
