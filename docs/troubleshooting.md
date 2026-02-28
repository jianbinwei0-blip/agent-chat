# Troubleshooting

## Quick Diagnostics

Run:

```bash
python3 agent_chat_control_plane.py setup-notify-hook --recipient "$AGENT_IMESSAGE_TO" --python-bin "$(command -v python3)"
python3 agent_chat_control_plane.py setup-launchd
python3 agent_chat_control_plane.py setup-permissions
python3 agent_chat_control_plane.py doctor
python3 agent_chat_control_plane.py doctor --json
python3 agent_chat_control_plane.py once --trace
```

## Common Issues

### Setup fails with `Require Python 3.11+`

Symptoms:
- setup commands stop immediately with `Require Python 3.11+`.

Cause:
- `python3` from `PATH` may resolve to `/usr/bin/python3` (3.9) on macOS.

Fix:
- resolve and pin a 3.11+ interpreter explicitly:
  - `PYTHON_BIN=/opt/homebrew/bin/python3.13` (or another installed 3.11+ path)
  - `"$PYTHON_BIN" --version`
  - `"$PYTHON_BIN" agent_chat_control_plane.py setup-notify-hook --recipient "$AGENT_IMESSAGE_TO" --python-bin "$PYTHON_BIN"`
  - `"$PYTHON_BIN" agent_chat_control_plane.py setup-launchd --recipient "$AGENT_IMESSAGE_TO" --python-bin "$PYTHON_BIN"`

### No iMessage sent

Symptoms:
- no outbound message arrives
- queue file grows (`agent_chat_queue.jsonl`)

Checks:
- verify `AGENT_IMESSAGE_TO` is set and normalized correctly
- ensure Messages is signed in
- confirm Automation permission for terminal/runner + `osascript`

### Telegram transport does not send or receive

Symptoms:
- no Telegram messages arrive
- inbound Telegram replies are not routed back

Checks:
- verify `AGENT_CHAT_TRANSPORT` is `telegram` or `both`
- verify `AGENT_TELEGRAM_BOT_TOKEN` is set and valid
- verify `AGENT_TELEGRAM_CHAT_ID` is set to the expected chat
- verify network access to `https://api.telegram.org` (or your `AGENT_TELEGRAM_API_BASE`)
- create/refresh token with `@BotFather` and re-run `setup-notify-hook` / `setup-launchd`

### Inbound replies are ignored

Symptoms:
- `doctor` or stderr indicates inbound disabled
- replies never resume sessions

Checks:
- run `python3 agent_chat_control_plane.py setup-launchd` (or `setup-permissions`) and keep it running while granting access
- when setup starts, grant exactly this permission:
  - `Permission to grant: Full Disk Access (System Settings > Privacy & Security > Full Disk Access).`
- setup prints the exact FDA targets to add:
  - `Grant Full Disk Access to this app: ...` (preferred when present)
  - `Grant access to this Python binary: ...`
- setup also prints step-by-step guidance before opening System Settings:
  - `Detailed steps before the Settings window opens:`
  - `1) In Full Disk Access, add and enable this app: ...` (or Python binary line when no app is available)
  - `Action required now: ... enable access for app: ...`
- do not guess the target app from terminal name; use the printed path
- setup flushes this guidance before opening System Settings, then keeps polling `chat.db` until access is detected
- wait for `Full Disk Access confirmed: chat.db is now readable.` before leaving setup
- run `python3 agent_chat_control_plane.py doctor` and use `Launchd.runtime_python` / `Launchd.permission_app` as the authoritative FDA targets
- prefer granting Full Disk Access to the shown app (usually `~/Applications/AgentChatPython.app`), or to the shown runtime Python binary if no app is shown
- do not grant Full Disk Access to terminal apps unless `doctor` explicitly shows that terminal binary as `runtime_python`
- `setup-permissions` now prefers launchd runtime targets from the installed plist, so its guidance should match `doctor`
- if output says "shell can read chat.db, but launchd cannot", grant Full Disk Access to the shown app/binary itself (not only Terminal), then rerun `setup-launchd`
- verify `AGENT_IMESSAGE_CHAT_DB` (if overridden) points to a readable DB
- ensure `chat.db` exists at `~/Library/Messages/chat.db` when not overridden
- if recurring failures happen after Python upgrades, use:
  - `python3 agent_chat_control_plane.py setup-launchd --recipient "$AGENT_IMESSAGE_TO" --repair-tcc`
  - this resets stale Full Disk Access approvals for the runtime bundle id and reruns permission setup

If launchd still cannot read `chat.db` after FDA was granted:
- inspect recent TCC logs for stale code requirement mismatches:
  - `/usr/bin/log show --style syslog --last 15m --predicate 'subsystem == "com.apple.TCC" && eventMessage CONTAINS "kTCCServiceSystemPolicyAllFiles" && eventMessage CONTAINS "org.python.python"'`
  - look for: `Failed to match existing code requirement for subject org.python.python`
- reset stale TCC approvals and re-grant:
  - `tccutil reset SystemPolicyAllFiles org.python.python`
  - re-enable Full Disk Access for `~/Applications/AgentChatPython.app`
- rerun:
  - `python3 agent_chat_control_plane.py setup-launchd --recipient "$AGENT_IMESSAGE_TO"`
  - `python3 agent_chat_control_plane.py doctor`
- shortcut:
  - `python3 agent_chat_control_plane.py setup-launchd --recipient "$AGENT_IMESSAGE_TO" --repair-tcc`

### `doctor` reports notify hook missing/mis-scoped or config parse errors

Symptoms:
- `notify hook is not configured at top-level in ~/.codex/config.toml`
- `notify hook appears under [notice.model_migrations]`
- `unable to parse ~/.codex/config.toml for notify hook`

Fix:
- run:
  - `python3 agent_chat_control_plane.py setup-notify-hook --recipient "$AGENT_IMESSAGE_TO" --python-bin "$(command -v python3)"`
- then re-run:
  - `python3 agent_chat_control_plane.py doctor`

### Need to re-run setup automatically after permission changes

Run:

```bash
python3 agent_chat_control_plane.py setup-launchd --recipient "$AGENT_IMESSAGE_TO"
python3 agent_chat_control_plane.py doctor
```

Notes:
- macOS privacy grants still require user interaction in System Settings; CLI cannot bypass this.
- after granting, rerun the commands above to refresh launchd and confirm `doctor` reports `OK`.

### "Python cannot be opened because of a problem"

Symptoms:
- macOS shows a dialog for `Python` when running setup/launchd

Checks and fixes:
- update to the latest repo version (friendly app provisioning is symlink-first to avoid broken copied bundles)
- rerun `python3 agent_chat_control_plane.py setup-launchd`
- if a stale app remains, remove and recreate:
  - `rm -rf ~/Applications/Codex\\ iMessage\\ Python.app`
  - rerun `setup-launchd`

### Burst of old iMessages gets sent (historical replay)

Symptoms:
- control plane suddenly emits many `help/error/status` messages
- this often happens right after reinstall/cleanup/startup

Cause:
- stale inbound cursor state (especially `last_rowid: 0`) can replay old `chat.db` rows.
- fixed in current `main`: startup now auto-reseeds the inbound cursor safely and stores recipient/handle metadata.

Checks:
- inspect cursor: `cat ~/.codex/tmp/imessage_inbound_cursor.json`
- run one dry cycle: `python3 agent_chat_control_plane.py once --dry-run --trace`

Recovery:
- stop running control-plane processes
- delete cursor and run one dry cycle to reseed:
  - `rm -f ~/.codex/tmp/imessage_inbound_cursor.json`
  - `python3 agent_chat_control_plane.py once --dry-run --trace`
- then start normal runtime (`setup-launchd` or `run`)

### Launchd appears loaded but routing looks broken

Checks:
- run `python3 agent_chat_control_plane.py setup-launchd` to regenerate + reload plist from current environment
- verify `ProgramArguments` paths in plist are absolute and current
- set `AGENT_CHAT_LAUNCHD_LABEL` to match your LaunchAgent label
- inspect launchd stdout/stderr logs configured in the plist

### Tmux routing fails

Symptoms:
- strict-routing errors or no dispatch confirmation

Checks:
- verify target pane/session is still live
- set/verify `AGENT_CHAT_TMUX_SOCKET` if non-default socket is used
- test with explicit routing message: `@<session_ref> <instruction>`
- temporarily relax strict mode for debugging: `AGENT_CHAT_STRICT_TMUX=0`
- if the target session exists but pane mapping is stale/missing, control plane now auto-falls back to `resume` for that case; strict-mode errors should now indicate non-no-pane failures.

### Missing session when replying (`@ref` or implicit)

Symptoms:
- `@<session_ref> ...` with an unknown target returns a runtime choice prompt instead of immediate session creation.
- an implicit reply with no resolvable target session (for example, no session currently awaiting input) returns the same runtime choice prompt.

Expected behavior:
- reply `1`/`codex` or `2`/`claude` to pick runtime for new background session.
- reply `cancel` to abort.
- if tmux launch fails after runtime choice, control plane falls back to non-tmux session creation.
- only one pending runtime-choice request is retained at a time (newest unresolved request wins).
- strict mode still requires explicit `@<session_ref>` for ambiguous implicit routing contexts.

### Ambiguous replies or wrong target session

Checks:
- use explicit `@<session_ref>` addressing
- set `AGENT_CHAT_REQUIRE_SESSION_REF=1`
- inspect registry/index files in `$AGENT_CHAT_HOME/tmp`

## Useful Environment Overrides

- `AGENT_CHAT_TRACE=1`
- `AGENT_CHAT_INBOUND_POLL_S`
- `AGENT_CHAT_INBOUND_RETRY_S`
- `AGENT_CHAT_QUEUE_DRAIN_LIMIT`
- `AGENT_IMESSAGE_MAX_LEN`

## If You Still Cannot Resolve It

Open an issue with:
- command used
- relevant env vars (redacted)
- `doctor --json` output
- minimal repro steps

## Full Removal

If you want to disable/remove the integration entirely from the machine, follow:
- `docs/cleanup.md`
