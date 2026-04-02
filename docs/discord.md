# Discord Setup and Routing

Use this page when `agent-chat` is running with Discord transport enabled.
It covers bot setup, required permissions, control-channel vs session-channel behavior, and how session-to-channel mapping works.

## What Discord Mode Does

With Discord transport enabled, the control plane can:
- send outbound session updates to Discord
- poll Discord for inbound plain-text messages
- route replies back to Codex, Claude, or Pi sessions
- surface Discord-origin Pi prompts on the desktop and report lifecycle milestones back to Discord
- optionally create one dedicated Discord channel per session

Discord can be used by itself or alongside iMessage and/or Telegram.

## Minimum Setup

### 1. Create or open a Discord bot

In the Discord Developer Portal:
- create or select your application
- create or select the bot user
- copy the bot token for `AGENT_DISCORD_BOT_TOKEN`
- enable **Message Content Intent**

`Message Content Intent` is required for the current inbound model. Without it, the bot may see messages with empty `content`, so plain-text routing will not work.

### 2. Invite the bot to your server

Give it access to:
- one control channel
- optionally, one category for auto-created session channels

Enable Developer Mode in Discord so you can copy IDs.

### 3. Grant required permissions

Required for normal control-channel operation:
- `View Channel`
- `Send Messages`
- `Read Message History`

Required for session-channel mode (`AGENT_DISCORD_SESSION_CHANNELS=1`):
- `Manage Channels`
- access to the configured category when `AGENT_DISCORD_SESSION_CATEGORY_ID` is set

## Recommended Environment

### Control-channel-only mode

```bash
export AGENT_CHAT_TRANSPORT="discord"
export AGENT_DISCORD_BOT_TOKEN="<discord bot token>"
export AGENT_DISCORD_CHANNEL_ID="<control channel id>"
# optional:
# export AGENT_DISCORD_CHANNEL_IDS="<control channel id>,<extra allowed thread or channel id>"
```

### Control channel + session channels

```bash
export AGENT_CHAT_TRANSPORT="discord"
export AGENT_DISCORD_BOT_TOKEN="<discord bot token>"
export AGENT_DISCORD_CONTROL_CHANNEL_ID="<control channel id>"
export AGENT_DISCORD_CHANNEL_ID="$AGENT_DISCORD_CONTROL_CHANNEL_ID"
export AGENT_DISCORD_SESSION_CHANNELS=1
# optional:
# export AGENT_DISCORD_SESSION_CATEGORY_ID="<category id>"
# export AGENT_DISCORD_SESSION_CHANNEL_PREFIX="pi-agent-chat"
# export AGENT_DISCORD_CHANNEL_IDS="$AGENT_DISCORD_CONTROL_CHANNEL_ID"
```

Notes:
- `AGENT_DISCORD_CHANNEL_ID` remains the default channel identifier.
- In session-channel mode, it should point at the control channel, not a per-session channel.
- `AGENT_DISCORD_CHANNEL_IDS` is usually just the control-channel allowlist; bound session channels are discovered from registry state.

## Control Channel vs Session Channels

When `AGENT_DISCORD_SESSION_CHANNELS=1`, Discord has two roles.

### Control channel

The control channel:
- stays intentionally unbound to any one session
- is used for `help`, `list`, `status`, `new ...`, and missing-session runtime-choice prompts
- is the only Discord channel you must configure manually

Plain text in the control channel is treated as control-plane input, not as a reply to a specific existing session.

### Session channels

A session channel:
- is bound one-to-one with exactly one session
- receives outbound session updates, needs-input prompts, and follow-up replies
- accepts plain-text inbound replies that route back to that same session
- can hand off Discord file attachments to an existing bound Pi session in the first-pass attachment workflow

Session channels are created lazily on the first meaningful outbound delivery for a session. `agent-chat` does not eagerly create channels for every discovered session.

## Session <-> Channel Mapping Behavior

`agent-chat` persists Discord session-channel mappings in the registry.

Behavioral rules:
- one session has at most one bound Discord session channel
- one bound Discord session channel maps back to exactly one session
- the control channel is never rebound as a session channel in session-channel mode
- you do **not** manually configure per-session channel IDs

Inbound routing for a bound session channel works like this:
1. resolve the channel id from the inbound Discord message
2. check whether an existing session record already stores that `discord_channel_id`
3. if not found, fall back to generic conversation bindings
4. route the plain-text message to the resolved session

That metadata-first lookup keeps an existing session channel sticky across restarts and registry normalization.

## Typical User Flow

### From the control channel

Use commands like:
- `help`
- `list`
- `where` / `context`
- `status @abcd1234`
- `new bugfix: investigate failing test`

If no target session can be resolved, the control plane asks which runtime to start:
- `1` / `codex` for Codex
- `2` / `claude` for Claude
- `3` / `pi` for Pi
- `cancel`

### From a bound session channel

Just send plain text, for example:
- `continue`
- `summarize current state`
- `fix the failing test`

You do not need `@<ref>` in a bound session channel.
If you need to move the current channel/thread to another session, send `bind @<session_ref>`.
If you want the current channel/thread explained back to you, send `where` or `context`.
On first use, agent-chat also appends a one-time quick-start hint so users can learn the control/session channel model in-context.

When Pi is blocked waiting on you, Discord now uses a clearer waiting-state message shape:
- the message explicitly says Pi is waiting for your input on `@<session_ref>`
- the active question/request is repeated in a cleaner plain-text block
- the message ends with obvious next-step suggestions such as `continue`, `summarize`, `yes`, `no`, or numeric choices when Pi provided options
- in a bound session channel, the message reminds you that plain text in that same channel continues the same session

### Desktop visibility and origin-aware progress

When a Pi session becomes Discord-bound, agent-chat now treats Discord visibility as a per-session policy instead of one global always-mirror behavior.

Default behavior:
- newly Discord-bound Pi sessions default to `origin_scoped`
- existing explicit session mode is preserved when a session is rebound or reused
- `origin_scoped` is the safe default for normal day-to-day use because it keeps Discord collaborators informed about Discord-origin work without mirroring unrelated local desktop exploration

Per-session progress modes:
- `origin_scoped` (default): send lifecycle updates only for prompts that came from Discord
- `shared_status`: send milestone lifecycle updates for both Discord-origin and local desktop-origin prompts
- `full_mirror`: send the broadest set of lifecycle updates for both origins; useful for demos or highly collaborative sessions
- `local_only`: suppress automatic Discord lifecycle updates for every prompt origin

What this means in practice:
- a prompt sent from Discord is accepted into the target Pi session and surfaced on the desktop immediately
- if the Pi surface is already foreground/visible, Discord says the prompt is visible on the desktop now
- if the Pi surface is backgrounded or hidden, Discord says the prompt was queued and marked for desktop attention
- in `origin_scoped`, later lifecycle milestones such as `working`, `needs_input`, `completed`, `failed`, and `cancelled` continue to post back to Discord only for that Discord-origin prompt
- local desktop-only work is **not** mirrored back to Discord by default in `origin_scoped`

Desktop attention states tracked for Discord-origin prompts:
- `inline_visible`: the prompt is already visible in the active Pi desktop surface
- `notification_visible`: the prompt was surfaced through desktop notification/attention handling because the session was not frontmost
- `attention_badged`: the session still has unread remote attention to clear
- `waiting_for_user`: Pi is blocked and waiting for a reply
- `resolved`: the active prompt lifecycle finished

This lifecycle metadata is persisted per session so progress gating stays stable across restarts and channel/session rebinding.

### Discord attachment handoff (first pass)

For existing Discord-bound Pi sessions, you can now attach files directly in Discord.

Current first-pass behavior:
- works best in a bound Discord session channel or thread that already resolves to an existing session
- downloads supported Discord attachments into local control-plane storage before routing the message to Pi
- appends a prompt block telling Pi which local files were attached and where they were saved
- if you also include text, that text is routed alongside the attachment handoff
- if the attachment message has no text, agent-chat treats it like a follow-up request to inspect the attached files and continue

Storage:
- default local storage root: `~/.codex/tmp/discord_attachments/`
- session/message-specific subdirectories are created under that root
- optional overrides:
  - `AGENT_CHAT_DISCORD_ATTACHMENT_DIR`
  - `AGENT_CHAT_DISCORD_ATTACHMENT_MAX_BYTES`

Current limitations:
- first pass is intended for existing bound sessions, not attachment-only new-session creation from the control channel
- downloads that exceed the configured size limit are skipped and reported back in Discord
- only Discord file attachments are handled; embeds and external link previews are not treated as files

## Launchd Notes

Use the normal setup flow:

```bash
python3 agent_chat_control_plane.py setup-notify-hook --agent "${AGENT_CHAT_AGENT:-codex}" --python-bin "$(command -v python3)"
python3 agent_chat_control_plane.py setup-launchd --agent "${AGENT_CHAT_AGENT:-codex}" --python-bin "$(command -v python3)"
python3 agent_chat_control_plane.py doctor --json
```

Discord-only mode does not require Messages `chat.db` access or Full Disk Access.

## Troubleshooting

### Discord messages appear but agent-chat does nothing

Check:
- `AGENT_DISCORD_BOT_TOKEN` is valid
- **Message Content Intent** is enabled
- the bot can see the control channel
- `doctor --json` shows `transport.discord_enabled: true`
- `doctor --json` shows the expected `transport.discord_channel_ids`

### Session channel reply creates a new session instead of using the existing one

Check:
- you replied in the bound session channel, not the control channel
- the session record in `~/.codex/tmp/agent_chat_session_registry.json` has the expected `discord_channel_id`
- `AGENT_DISCORD_CONTROL_CHANNEL_ID` points only at the control channel
- the control channel was not reused as a session channel

### Session channels are not created

Check:
- `AGENT_DISCORD_SESSION_CHANNELS=1`
- the bot has `Manage Channels`
- the bot can access the configured `AGENT_DISCORD_SESSION_CATEGORY_ID`
- the control channel lookup succeeds and belongs to the expected guild

## Related Docs

- `README.md`
- `docs/control-plane.md`
- `docs/architecture.md`
- `docs/troubleshooting.md`
