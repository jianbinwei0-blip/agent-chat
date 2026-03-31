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

For a guided Telegram-first setup with prompts, run:

```bash
bash scripts/setup-telegram-easy.sh
```

## 60-Second Decision Tree

1. Setup command fails immediately:
   - check Python first (`python3 --version`)
   - if below 3.11, pin `PYTHON_BIN` to a 3.11+ install and rerun setup
2. Setup succeeds but Telegram send/receive is missing:
   - run `scripts/telegram-diagnose.sh`
   - confirm token, transport mode, chat ID bootstrap, and no `HTTP 409 Conflict`
3. Telegram receives message but routing does nothing:
   - in topic, send `@<session_ref> hello` once to bind topic/session
   - rerun `scripts/telegram-diagnose.sh --pause-launchd` for deterministic upstream probe
4. Inbound remains disabled after setup:
   - rerun `setup-launchd`/`setup-permissions`
   - grant Full Disk Access to exact `doctor` targets (`permission_app` / `runtime_python`)

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
- run `scripts/telegram-diagnose.sh` first for a single-pass config/cursor/log/getUpdates check
- verify `AGENT_CHAT_TRANSPORT` is `telegram` or `both`
- verify `AGENT_TELEGRAM_BOT_TOKEN` is set and valid
- verify `AGENT_TELEGRAM_CHAT_ID` is set to the expected chat, or bootstrap it via:
  - `python3 agent_chat_control_plane.py setup-launchd`
  - then send one plain-text message in the target topic/group while setup is waiting
- verify bot privacy is disabled in `@BotFather` (`/setprivacy -> Disable`)
- verify the bot is still in the target group and has admin role (especially after privacy changes)
- verify network access to `https://api.telegram.org` (or your `AGENT_TELEGRAM_API_BASE`)
- create/refresh token with `@BotFather` and re-run `setup-notify-hook` / `setup-launchd`
- if using long polling, verify no competing consumer is polling the same token (`HTTP 409 Conflict` from `getUpdates`)
- if topic messages still do not arrive, remove/re-add the bot in the group and promote to admin again
- Telegram Bot API cannot auto-create groups; group creation must be done in Telegram client UI.

### Telegram group upgraded to supergroup (topic messages missing)

Symptoms:
- topic messages are visible in Telegram but not routed by agent-chat
- direct send/checks return `Bad Request: group chat was upgraded to a supergroup`

Cause:
- `AGENT_TELEGRAM_CHAT_ID` points to an old basic-group id after Telegram migration.
- topic routing happens in the migrated supergroup id (typically begins with `-100`).

Fix:
- capture `migrate_to_chat_id` from the Telegram API error response
- update `AGENT_TELEGRAM_CHAT_ID` to that migrated id
- rerun:
  - `python3 agent_chat_control_plane.py setup-launchd`
  - `python3 agent_chat_control_plane.py doctor --json`
- verify `doctor --json` now shows the migrated supergroup id under `transport.telegram_chat_id`

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
- reply `1`/`codex`, `2`/`claude`, or `3`/`pi` to pick runtime for a new background session.
- reply `cancel` to abort.
- if tmux launch fails after runtime choice, control plane falls back to non-tmux session creation.
- iMessage/non-threaded inbound keeps one global pending runtime-choice request (newest unresolved request wins).
- Telegram topic inbound keeps pending runtime choice per `chat_id:message_thread_id`.
- Discord channel/thread inbound keeps pending runtime choice per canonical Discord conversation key.
- strict mode still requires explicit `@<session_ref>` for ambiguous implicit routing contexts.

Telegram topic specifics:
- once a topic is bound to a session, implicit replies in that topic target the bound session first.
- if a reply comes from a bound topic but outbound messages are not staying in-thread, inspect `~/.codex/tmp/agent_chat_session_registry.json`; `telegram_thread_bindings` is authoritative and per-session `telegram_message_thread_id` fields are migration metadata only.

### Telegram topic plain text does nothing

Symptoms:
- `hello` in topic appears in Telegram, but there is no bot response.
- `~/.codex/tmp/telegram_inbound_cursor.json` does not advance.

Checks:
- run `scripts/telegram-diagnose.sh --pause-launchd` for deterministic upstream polling checks
- if `AGENT_TELEGRAM_CHAT_ID` is empty, run `setup-launchd` and complete bootstrap by sending plain text from the target topic/group
- ensure the topic is bound at least once: send `@<session_ref> ping` in that topic, then retry plain text.
- enable trace and inspect logs:
  - `AGENT_CHAT_TRACE=1`
  - `rg -n "telegram getUpdates|inbound rowid=" ~/Library/Logs/agent-chat.launchd.err.log | tail -n 80`
- if no new `inbound rowid` appears after sending a topic message, test upstream delivery directly:
  - stop poller temporarily (`launchctl bootout gui/$(id -u)/com.agent-chat`)
  - call `getUpdates` with offset after current cursor
  - restart poller (`launchctl bootstrap ... && launchctl kickstart ...`)
- if upstream `getUpdates` returns zero updates for your new message:
  - re-check `/setprivacy` is disabled for the bot
  - remove and re-add bot to the group
  - promote bot to admin again
- if logs show `telegram getUpdates failed: HTTP Error 409: Conflict`:
  - another process/webhook is consuming this bot token; stop the other consumer or clear webhook (`deleteWebhook`)
- for setup diagnostics only, you can temporarily set `AGENT_TELEGRAM_ACCEPT_ALL_CHATS=1` to bypass chat-id filtering.

### Discord channel or thread messages do nothing

Symptoms:
- message appears in Discord, but there is no bot response
- `doctor --json` shows Discord transport enabled, but no new Discord cursor progress appears

Checks:
- verify `AGENT_DISCORD_BOT_TOKEN` is valid and the bot has access to the target control channel/thread
- enable **Message Content Intent** for the bot; without it, Discord messages may be visible to the gateway/API but arrive with empty `content`
- set `AGENT_DISCORD_CHANNEL_ID` or `AGENT_DISCORD_CHANNEL_IDS` to the control-channel allowlist you expect the poller to watch
- if `AGENT_DISCORD_SESSION_CHANNELS=1`, also verify the bot has permission to create channels (`Manage Channels`) and, when used, access to `AGENT_DISCORD_SESSION_CATEGORY_ID`
- if you are using threads, send one explicit bind message first (`@<session_ref> hello`) so the control plane stores a canonical conversation binding
- enable trace and inspect launchd stderr for Discord polling failures
- run `doctor --json` and verify `transport.discord_enabled`, `transport.discord_token_present`, and `transport.discord_channel_ids`

### Discord session-channel reply creates a new session instead of resuming the existing one

Symptoms:
- plain text posted in an existing Discord session channel triggers the missing-session runtime-choice flow
- a brand new session/channel is created instead of routing back to the existing session

Checks:
- confirm you replied in the bound session channel, not the control channel
- inspect `~/.codex/tmp/agent_chat_session_registry.json` and verify the target session record has `discord_channel_id` set to that channel id
- verify `AGENT_DISCORD_CONTROL_CHANNEL_ID` points only at the control channel; do not reuse the control channel id as a session channel id
- if session-channel mode is enabled, remember that the control channel intentionally stays unbound and plain text there is treated as control-surface input, not session input
- after recent fixes, inbound Discord routing resolves existing session channels from session metadata first and only then falls back to generic conversation bindings; if behavior still regresses, capture `doctor --json` plus the relevant session record and stderr trace lines

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
