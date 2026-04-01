# Changelog

## 2026-03-31 — Integration UX pass

This release packaged a focused UX improvement pass for `agent-chat`.

### Added
- `where` / `context` command to explain the current routing surface
- `bind @<session_ref>` command for explicit Telegram/Discord rebinding
- `guided-setup` CLI flow
- `scripts/setup-agent-chat-easy.sh` wrapper
- one-time in-context onboarding hints for control surfaces and session surfaces
- `AGENT_CHAT_NOTIFICATION_LEVEL` with `quiet`, `default`, and `verbose`

### Improved
- `list` now shows recency, waiting/active state, and binding summary
- `status @<session_ref>` now shows bindings, last activity, and next steps
- missing-session prompts are more conversational and actionable
- strict tmux routing failures now explain what happened and what to do next
- Telegram and Discord setup guidance now points users toward `bind` and `where`
- guided setup now writes a local env file, runs setup commands, and prints a first-success checklist

### Behavior notes
- `quiet` suppresses autonomous completion/progress notifications from session activity
- `default` preserves current behavior
- `verbose` emits autonomous progress updates across enabled transports
- first-use hints are shown once per surface and persisted in registry state

### Docs
- updated: `README.md`
- updated: `docs/control-plane.md`
- updated: `docs/discord.md`
- updated: `docs/troubleshooting.md`
- added planning/summary artifacts under `docs/exec-plans/completed/`

### Validation
- `python3 -m unittest discover -s tests -p 'test_*.py'`
- result: `Ran 291 tests ... OK`
