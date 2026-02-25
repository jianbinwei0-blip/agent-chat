# Security

## Security Model

This project runs locally on macOS and interacts with:
- `Messages` via Apple Events (`osascript`)
- local Messages database (`~/Library/Messages/chat.db`)
- Telegram Bot API (when Telegram transport is enabled)
- local agent runtime session/history files under `AGENT_CHAT_HOME`

It is not a network service and is designed for single-user local operation.

## Trust Boundaries

- macOS user account boundary: runtime inherits the invoking user's permissions.
- Apple Events boundary: automation grants control of the Messages app.
- Filesystem boundary: Full Disk Access determines whether `chat.db` is readable.

## Sensitive Data

Potentially sensitive local data:
- iMessage/Telegram message text from inbound/outbound workflows
- Codex prompts/responses from session/history files
- session identifiers and routing metadata in state JSON files

Recommendations:
- avoid committing runtime state/log files
- keep `AGENT_CHAT_HOME` under a user-owned path
- restrict machine/user account access where this runtime executes

## Permission Hardening

1. Grant `Automation` only to the exact terminal/runner binaries you use.
2. Grant `Full Disk Access` only to the app/runtime binary that executes the launchd runtime (for example `~/Applications/Codex iMessage Python.app` when provided by setup).
3. Prefer LaunchAgents (user context) over system daemons for this workflow.
4. Review launchd `ProgramArguments` and `EnvironmentVariables` for least privilege.

## Runtime Hardening Knobs

Useful controls:
- `AGENT_CHAT_STRICT_TMUX=1`
- `AGENT_CHAT_REQUIRE_SESSION_REF=1`
- `AGENT_CHAT_NOTIFY_MODE=route`
- `AGENT_CHAT_ONLY_NEEDS_INPUT=1`

These reduce accidental misrouting and unnecessary message fanout.

## Vulnerability Reporting

See the top-level `SECURITY.md` for disclosure/reporting instructions.
