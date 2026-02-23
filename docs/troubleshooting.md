# Troubleshooting

## Quick Diagnostics

Run:

```bash
python3 codex_imessage_control_plane.py setup-notify-hook --recipient "$CODEX_IMESSAGE_TO" --python-bin "$(command -v python3)"
python3 codex_imessage_control_plane.py setup-launchd
python3 codex_imessage_control_plane.py setup-permissions
python3 codex_imessage_control_plane.py doctor
python3 codex_imessage_control_plane.py doctor --json
python3 codex_imessage_control_plane.py once --trace
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
  - `"$PYTHON_BIN" codex_imessage_control_plane.py setup-notify-hook --recipient "$CODEX_IMESSAGE_TO" --python-bin "$PYTHON_BIN"`
  - `"$PYTHON_BIN" codex_imessage_control_plane.py setup-launchd --recipient "$CODEX_IMESSAGE_TO" --python-bin "$PYTHON_BIN"`

### No iMessage sent

Symptoms:
- no outbound message arrives
- queue file grows (`imessage_queue.jsonl`)

Checks:
- verify `CODEX_IMESSAGE_TO` is set and normalized correctly
- ensure Messages is signed in
- confirm Automation permission for terminal/runner + `osascript`

### Inbound replies are ignored

Symptoms:
- `doctor` or stderr indicates inbound disabled
- replies never resume sessions

Checks:
- run `python3 codex_imessage_control_plane.py setup-launchd` (or `setup-permissions`) and keep it running while granting access
- when setup starts, grant exactly this permission:
  - `Permission to grant: Full Disk Access (System Settings > Privacy & Security > Full Disk Access).`
- setup prints the exact FDA targets to add:
  - `Grant Full Disk Access to this app: ...` (preferred when present)
  - `Grant access to this Python binary: ...`
- do not guess the target app from terminal name; use the printed path
- setup starts polling `chat.db` before opening System Settings, then keeps polling until access is detected
- wait for `Full Disk Access confirmed: chat.db is now readable.` before leaving setup
- run `python3 codex_imessage_control_plane.py doctor` and use `Launchd.runtime_python` / `Launchd.permission_app` as the authoritative FDA targets
- prefer granting Full Disk Access to the shown app (usually `~/Applications/Codex iMessage Python.app`), or to the shown runtime Python binary if no app is shown
- do not grant Full Disk Access to Ghostty/Terminal unless `doctor` explicitly shows that terminal binary as `runtime_python`
- `setup-permissions` now prefers launchd runtime targets from the installed plist, so its guidance should match `doctor`
- if output says "shell can read chat.db, but launchd cannot", grant Full Disk Access to the shown app/binary itself (not only Terminal), then rerun `setup-launchd`
- verify `CODEX_IMESSAGE_CHAT_DB` (if overridden) points to a readable DB
- ensure `chat.db` exists at `~/Library/Messages/chat.db` when not overridden
- if recurring failures happen after Python upgrades, use:
  - `python3 codex_imessage_control_plane.py setup-launchd --recipient "$CODEX_IMESSAGE_TO" --repair-tcc`
  - this resets stale Full Disk Access approvals for the runtime bundle id and reruns permission setup

If launchd still cannot read `chat.db` after FDA was granted:
- inspect recent TCC logs for stale code requirement mismatches:
  - `/usr/bin/log show --style syslog --last 15m --predicate 'subsystem == "com.apple.TCC" && eventMessage CONTAINS "kTCCServiceSystemPolicyAllFiles" && eventMessage CONTAINS "org.python.python"'`
  - look for: `Failed to match existing code requirement for subject org.python.python`
- reset stale TCC approvals and re-grant:
  - `tccutil reset SystemPolicyAllFiles org.python.python`
  - `tccutil reset SystemPolicyAllFiles com.mitchellh.ghostty`
  - re-enable Full Disk Access for `~/Applications/Codex iMessage Python.app` (and terminal app if needed)
- rerun:
  - `python3 codex_imessage_control_plane.py setup-launchd --recipient "$CODEX_IMESSAGE_TO"`
  - `python3 codex_imessage_control_plane.py doctor`
- shortcut:
  - `python3 codex_imessage_control_plane.py setup-launchd --recipient "$CODEX_IMESSAGE_TO" --repair-tcc`

### `doctor` reports notify hook missing/mis-scoped or config parse errors

Symptoms:
- `notify hook is not configured at top-level in ~/.codex/config.toml`
- `notify hook appears under [notice.model_migrations]`
- `unable to parse ~/.codex/config.toml for notify hook`

Fix:
- run:
  - `python3 codex_imessage_control_plane.py setup-notify-hook --recipient "$CODEX_IMESSAGE_TO" --python-bin "$(command -v python3)"`
- then re-run:
  - `python3 codex_imessage_control_plane.py doctor`

### Need to re-run setup automatically after permission changes

Run:

```bash
python3 codex_imessage_control_plane.py setup-launchd --recipient "$CODEX_IMESSAGE_TO"
python3 codex_imessage_control_plane.py doctor
```

Notes:
- macOS privacy grants still require user interaction in System Settings; CLI cannot bypass this.
- after granting, rerun the commands above to refresh launchd and confirm `doctor` reports `OK`.

### "Python cannot be opened because of a problem"

Symptoms:
- macOS shows a dialog for `Python` when running setup/launchd

Checks and fixes:
- update to the latest repo version (friendly app provisioning is symlink-first to avoid broken copied bundles)
- rerun `python3 codex_imessage_control_plane.py setup-launchd`
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
- run one dry cycle: `python3 codex_imessage_control_plane.py once --dry-run --trace`

Recovery:
- stop running control-plane processes
- delete cursor and run one dry cycle to reseed:
  - `rm -f ~/.codex/tmp/imessage_inbound_cursor.json`
  - `python3 codex_imessage_control_plane.py once --dry-run --trace`
- then start normal runtime (`setup-launchd` or `run`)

### Launchd appears loaded but routing looks broken

Checks:
- run `python3 codex_imessage_control_plane.py setup-launchd` to regenerate + reload plist from current environment
- verify `ProgramArguments` paths in plist are absolute and current
- set `CODEX_IMESSAGE_LAUNCHD_LABEL` to match your LaunchAgent label
- inspect launchd stdout/stderr logs configured in the plist

### Tmux routing fails

Symptoms:
- strict-routing errors or no dispatch confirmation

Checks:
- verify target pane/session is still live
- set/verify `CODEX_IMESSAGE_TMUX_SOCKET` if non-default socket is used
- test with explicit routing message: `@<session_ref> <instruction>`
- temporarily relax strict mode for debugging: `CODEX_IMESSAGE_STRICT_TMUX=0`

### Ambiguous replies or wrong target session

Checks:
- use explicit `@<session_ref>` addressing
- set `CODEX_IMESSAGE_REQUIRE_SESSION_REF=1`
- inspect registry/index files in `$CODEX_HOME/tmp`

## Useful Environment Overrides

- `CODEX_IMESSAGE_TRACE=1`
- `CODEX_IMESSAGE_INBOUND_POLL_S`
- `CODEX_IMESSAGE_INBOUND_RETRY_S`
- `CODEX_IMESSAGE_QUEUE_DRAIN_LIMIT`
- `CODEX_IMESSAGE_MAX_LEN`

## If You Still Cannot Resolve It

Open an issue with:
- command used
- relevant env vars (redacted)
- `doctor --json` output
- minimal repro steps

## Full Removal

If you want to disable/remove the integration entirely from the machine, follow:
- `docs/cleanup.md`
