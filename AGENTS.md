# AGENTS.md

This file is intentionally short.
Treat it as a map, not the manual.

## System Of Record

Repository knowledge is the source of truth.

- Setup and operations: `README.md`
- Knowledge map and doc routing: `docs/index.md`
- Runtime entrypoint: `agent_chat_control_plane.py`

If this file conflicts with docs, docs are authoritative.

## Progressive Disclosure

1. Start with `README.md` for setup and runtime contracts.
2. Use `docs/index.md` to locate the right domain docs.
3. Open only the linked docs needed for the current task.
4. When behavior changes, update the relevant docs in the same PR.

## Doc Routing

- Runtime architecture and flow: `docs/architecture.md`, `docs/control-plane.md`
- Setup and recovery: `README.md`, `docs/troubleshooting.md`, `docs/cleanup.md`
- Security and privacy: `SECURITY.md`, `docs/security.md`
- Execution history and debt: `docs/exec-plans/`

## Execution Constraints

- Prefer idempotent control-plane commands over ad-hoc edits:
  - `setup-notify-hook`
  - `setup-launchd`
  - `doctor`
- Require Python `3.11+` resolved from `PATH`; do not hardcode `/usr/bin/python3`.
- Keep setup flows idempotent and safe for repeated runs.
- Keep message sender paths in-repo (`scripts/send-imessage.applescript`).
