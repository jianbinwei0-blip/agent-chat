# Discord Session/Channel Mapping

## Objective and Scope

Add a Discord-first session/channel workflow to `agent-chat` so Discord can act like a real remote workspace instead of only a lightweight command bridge.

In scope:
- one configured Discord control channel used for `help`, `list`, `status`, and session creation
- automatic Discord text-channel creation for sessions when session-channel mode is enabled
- canonical session-to-channel bindings stored in the existing generic `conversation_bindings` registry map
- outbound delivery of meaningful session output to the bound session channel
- inbound routing of plain-text messages from a bound session channel back to that session
- backward-compatible behavior when session-channel mode is disabled
- tests and docs for the new workflow

Out of scope:
- slash commands / buttons / Discord interaction API
- multi-user authorization
- archival / deletion of session channels
- thread-per-session mode as the default UX

## Acceptance Criteria

- Discord session-channel mode can be enabled without breaking existing control-channel-only behavior.
- The configured Discord control channel remains unbound and usable for `help`, `list`, `status`, and missing-session runtime choice.
- When a session first emits outbound content and has no bound Discord conversation, the control plane can create a Discord channel, bind it to that session, and send the session output there.
- Follow-up outbound session updates resolve to the bound Discord session channel automatically.
- Plain-text messages sent in a bound session channel route back to the bound session without requiring `@<ref>`.
- Session creation from the control channel binds the new session to its created session channel rather than hijacking the control channel binding.
- Existing Discord direct-channel binding behavior remains functional when session-channel mode is disabled.
- Tests cover channel auto-creation, outbound routing, control-channel protection, and inbound bound-channel routing.

## Current Status

- Planning + implementation in progress.

## Decision Log

- 2026-03-31: Use **session ↔ conversation** as the underlying model, but implement **channel-per-session** as the initial Discord UX. This reuses the generic `conversation_bindings` registry and avoids inventing a Discord-only mapping store.
- 2026-03-31: Keep one manually configured Discord control channel via existing `AGENT_DISCORD_CHANNEL_ID` / `AGENT_DISCORD_CHANNEL_IDS`; do not require users to configure per-session channel IDs manually.
- 2026-03-31: Gate the new behavior behind explicit env configuration so existing Discord installs are not silently converted from control-channel mode to channel-per-session mode.
- 2026-03-31: Mirror meaningful assistant output to the bound session channel using a new `update` delivery kind, while preserving existing `needs_input` / `responded` notifications.
- 2026-03-31: Create session channels lazily on first needed outbound delivery, which avoids creating empty channels for sessions that never emit anything meaningful.

## Implementation Plan

1. **Config and Discord helper layer**
   - Add env parsing helpers for:
     - `AGENT_DISCORD_SESSION_CHANNELS`
     - `AGENT_DISCORD_CONTROL_CHANNEL_ID`
     - `AGENT_DISCORD_SESSION_CATEGORY_ID`
     - `AGENT_DISCORD_SESSION_CHANNEL_PREFIX`
   - Treat existing `AGENT_DISCORD_CHANNEL_ID` as the default control channel when `AGENT_DISCORD_CONTROL_CHANNEL_ID` is unset.
   - Add Discord API helpers for:
     - fetching channel metadata
     - creating guild text channels
     - resolving / sanitizing session channel names

2. **Session binding and channel creation**
   - Add helpers to:
     - detect whether an inbound Discord message came from the configured control channel
     - create or reuse a session channel for a session
     - bind that channel to the session using `conversation_bindings`
   - Store minimal session-channel metadata on the session record for diagnostics (`discord_channel_id`, optional `discord_channel_name`).

3. **Outbound behavior**
   - Extend `_send_structured()` to lazily provision/bind a Discord session channel when session-channel mode is enabled and the target message belongs to a session.
   - Add a new outbound `update` path for assistant messages so active sessions emit meaningful output to their bound Discord channel even when they are not waiting for input.

4. **Inbound behavior**
   - Keep the control channel unbound.
   - Inbound plain text from a bound Discord session channel should continue to use the existing generic conversation-binding lookup.
   - When a missing-session flow is initiated from the control channel, runtime choice and created-session confirmation remain in the control channel, but the created session binds to its own session channel.

5. **Validation**
   - Add unit tests for channel helper functions and outbound auto-binding.
   - Add inbound tests for session-channel routing and control-channel protection.
   - Run targeted tests and the full test suite.

## Validation Notes

- Pending implementation.
