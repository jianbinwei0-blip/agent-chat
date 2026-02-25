# AGENTS.md

This file is intentionally short.

## Canonical Setup Instructions

Use `README.md` as the single source of truth for setup and recovery:
- `Quickstart`
- `Codex / Claude Assisted Setup`
- `First-Run Failure Modes`
- `Launchd`
- `Cleanup / Uninstall`

If `AGENTS.md` and `README.md` diverge, `README.md` is authoritative. Keep this file as a pointer and update `README.md` first.

Canonical runtime entrypoint is `agent_chat_control_plane.py`.

## Agent Execution Contract

- Prefer the built-in idempotent setup commands over ad-hoc file edits:
  - `setup-notify-hook`
  - `setup-launchd`
  - `doctor`
- Require Homebrew + `tmux` in setup flows; auto-install both when missing (otherwise fail with actionable guidance).
- Do not default to `/usr/bin/python3`; resolve Python from `PATH` and require `3.11+`.
- Do not point messaging send paths to external files outside this repo.
- Do not remove launchd setup/doctor flows.
- Keep setup instructions idempotent and safe for repeated execution.

## One-Shot (Reference)

Run from repo root:

```bash
PYTHON_BIN="$(command -v python3 || true)"
if [ -z "$PYTHON_BIN" ]; then
  echo "python3 not found in PATH."
  exit 1
fi
if ! "$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
  echo "Require Python 3.11+."
  exit 1
fi

if ! command -v brew >/dev/null 2>&1; then
  NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

if ! command -v tmux >/dev/null 2>&1; then
  brew install tmux
fi

export AGENT_CHAT_AGENT="${AGENT_CHAT_AGENT:-codex}"
export AGENT_CHAT_HOME="$HOME/.codex"
export AGENT_CHAT_NOTIFY_MODE="route"
# export AGENT_CHAT_TRANSPORT="telegram"   # imessage|telegram|both
# export AGENT_TELEGRAM_BOT_TOKEN="<bot token>"
# export AGENT_TELEGRAM_CHAT_ID="<chat id>"
# export AGENT_IMESSAGE_TO="+15555550123"  # required for imessage|both

"$PYTHON_BIN" agent_chat_control_plane.py setup-notify-hook \
  --agent "$AGENT_CHAT_AGENT" \
  --recipient "${AGENT_IMESSAGE_TO:-}" \
  --python-bin "$PYTHON_BIN"

"$PYTHON_BIN" agent_chat_control_plane.py setup-launchd \
  --agent "$AGENT_CHAT_AGENT" \
  --recipient "${AGENT_IMESSAGE_TO:-}" \
  --python-bin "$PYTHON_BIN"

"$PYTHON_BIN" agent_chat_control_plane.py doctor --agent "$AGENT_CHAT_AGENT"
```
