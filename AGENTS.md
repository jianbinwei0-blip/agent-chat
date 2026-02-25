# AGENTS.md

This file is intentionally short.

## Canonical Setup Instructions

Use `README.md` as the single source of truth for setup and recovery:
- `Quickstart`
- `First-Run Failure Modes`
- `Launchd`
- `Cleanup / Uninstall`

If `AGENTS.md` and `README.md` diverge, `README.md` is authoritative. Keep this file as a pointer and update `README.md` first.

## Agent Execution Contract

- Prefer the built-in idempotent setup commands over ad-hoc file edits:
  - `setup-notify-hook`
  - `setup-launchd`
  - `doctor`
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

export CODEX_IMESSAGE_TO="+15555550123"   # replace
export CODEX_HOME="$HOME/.codex"
export CODEX_IMESSAGE_NOTIFY_MODE="route"

"$PYTHON_BIN" agent_imessage_control_plane.py setup-notify-hook \
  --recipient "$CODEX_IMESSAGE_TO" \
  --python-bin "$PYTHON_BIN"

"$PYTHON_BIN" agent_imessage_control_plane.py setup-launchd \
  --recipient "$CODEX_IMESSAGE_TO" \
  --python-bin "$PYTHON_BIN"

"$PYTHON_BIN" agent_imessage_control_plane.py doctor
```
