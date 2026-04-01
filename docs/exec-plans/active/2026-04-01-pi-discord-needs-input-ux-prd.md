# Pi Discord Needs-Input UX PRD

## Objective

Make Pi's "waiting for user input" moments in Discord obvious, actionable, and low-friction.

The desired outcome is that when Pi pauses in a Discord-bound session, the user can immediately answer the right question without having to infer session state, remember command syntax, or guess whether plain text will route correctly.

## Scope

### In
- Discord user-facing copy for Pi sessions that are waiting on human input
- standardized waiting-state message shape for Discord session channels and bindable Discord contexts
- explicit next-step suggestions appended to Pi needs-input messages
- better session/status wording for Discord when a Pi session is blocked on the user
- tests and docs for the new message UX

### Out
- Discord slash commands, buttons, or modals
- hosted analytics or usage telemetry
- attachment/file upload support
- session archive/rename/close lifecycle controls
- non-Discord transport-specific waiting UX changes beyond copy consistency where shared helpers are reused

## User Problems

### UP-1: "Pi is waiting" is not clear enough
Users can miss the difference between:
- Pi sending a normal progress update
- Pi finishing work
- Pi explicitly waiting for a reply before proceeding

### UP-2: The next reply is not obvious
Even when the user understands that Pi is blocked, they may not know whether to:
- answer a direct question
- send `continue`
- ask for a summary
- approve a plan
- choose between options

### UP-3: Routing confidence is too low
In Discord, users need reassurance that replying in the current bound channel will continue the same Pi session.
Without that reassurance, they may overuse `@<session_ref>` or avoid replying at all.

### UP-4: Pi questions can arrive in raw, hard-to-scan form
Pi often produces thoughtful but dense text.
Discord users need a shorter front-loaded summary and clearer reply instructions.

### UP-5: Waiting sessions are hard to spot later
If a user comes back later, `list` and `status` should make it clear that a Pi session is blocked on user input, not simply idle.

## Goals

- Make waiting-state messages visually and semantically distinct from normal updates.
- Tell the user exactly what Pi needs next.
- Preserve plain-text reply simplicity in bound Discord session channels.
- Reuse existing control-plane patterns (`where`, `bind`, `list`, `status`) instead of inventing a new command model.

## Non-Goals

- Rich Discord interaction UI in this milestone
- General transport redesign across Telegram/iMessage
- Replacing Pi's native wording with aggressive summarization or lossy rewriting
- Solving all Discord workflow gaps in one change set

## Proposed Features

## P0 — Ship next

### F-1: Standardize Pi waiting-state header in Discord
Every Pi needs-input delivery in Discord should begin with a consistent header that signals:
- Pi is waiting for input
- which session is affected
- that this is a reply checkpoint, not just a status update

Acceptance:
- Discord waiting messages for Pi use a consistent header format
- the header includes `@<session_ref>`
- the message clearly says Pi is waiting on the user

Example message UX:

```text
Pi is waiting for your input on @abcd1234.

It found two ways to proceed with the failing test and needs your choice before it edits code.
```

### F-2: Append explicit next-step suggestions
Every Discord waiting-state message should end with 2-4 obvious reply suggestions.
The goal is not to constrain the user, but to reduce blank-screen friction.

Acceptance:
- suggested replies appear on Pi waiting messages in Discord
- suggestions are short and plain-text friendly
- suggestions adapt to common cases when possible; otherwise use safe defaults

Safe default suggestions:
- `continue`
- `summarize`
- `yes`
- `no`

Example message UX:

```text
Reply here with plain text to continue this session.
Try: `continue`, `summarize`, `yes`, or `no`.
```

### F-3: Improve choice/approval formatting
When Pi's waiting text appears to contain a choice, approval checkpoint, or missing detail request, the Discord-facing message should make that shape clearer.

Acceptance:
- choice-style prompts are rendered as short bullet points or numbered options when possible
- approval-style prompts say Pi is ready for approval
- missing-detail prompts say which detail is needed

Example message UX:

```text
Pi is waiting for your input on @abcd1234.

It can:
1) patch the mock
2) update the assertion

Reply with `1`, `2`, `summarize`, or your own instructions.
```

### F-4: Reinforce routing confidence in bound session channels
When Pi is waiting in a bound Discord session channel, the message should reassure the user that a normal reply in the same channel continues the same session.

Acceptance:
- waiting messages in bound session channels explicitly say that plain text here continues the same session
- control-channel messages continue to steer users toward `@<session_ref>` or `bind` as appropriate

Example message UX:

```text
Reply in this channel with plain text to continue @abcd1234.
```

### F-5: Surface "waiting on you" in `list` / `status`
The control plane should expose a clearer waiting state for Pi sessions when users inspect them from Discord.

Acceptance:
- `list` differentiates user-blocked waiting from generic active/idle state
- `status @<session_ref>` explains Pi is waiting for user input when applicable
- next-step guidance is included

Example message UX:

```text
Status for @abcd1234:
- Runtime: Pi
- State: waiting on you
- Last active: 6m ago
- Reply here: yes (bound Discord session channel)
- Next: answer Pi's question, or send `summarize`
```

## P1 — Follow-on

### F-6: Smarter canned suggestions by checkpoint type
- detect approval checkpoints vs clarification checkpoints vs choice checkpoints
- tailor suggestions accordingly (`approve`, `revise`, `pick 1`, `continue with defaults`)

### F-7: Waiting-state recap command
- `status @<session_ref>` or `where` can show the last unresolved Pi question more explicitly

## P2 — Longer-term roadmap

### F-8: Rich Discord interaction UI
- buttons/select menus/slash commands for common Pi reply actions
- richer embeds for waiting state and session summaries

## Milestone Acceptance Criteria

- Pi waiting-state messages in Discord use a consistent, more actionable format
- bound Discord session channels explicitly tell users that plain text continues the session
- `list` / `status` better expose "waiting on you" for Pi sessions
- docs describe the new waiting-state behavior
- regression tests cover the new copy/formatting paths

## Current Status

- Planning only
- No code changes yet

## Decisions

- 2026-04-01: Start with plain-text UX improvements before investing in slash commands or buttons.
- 2026-04-01: Keep the first milestone Discord-focused; only shared helper copy should affect other transports.
- 2026-04-01: Suggested replies are hints, not a constrained command menu; free-form user replies must continue to work.
- 2026-04-01: Reuse existing session/channel binding semantics instead of introducing a Pi-specific Discord control model.

## Validation Notes

- Planned validation:
  - targeted unit tests in `tests/test_agent_chat_control_plane.py`
  - full suite: `python3 -m unittest discover -s tests -p 'test_*.py'`
- Result:
  - Pending implementation
