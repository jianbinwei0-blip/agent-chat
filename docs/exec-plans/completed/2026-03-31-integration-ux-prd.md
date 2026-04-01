# Integration UX Improvement PRD

## Objective

Make the `agent-chat` integration easier to understand and recover when routing across iMessage, Telegram, and Discord.

This PRD defines a concrete milestone that is complete when all P0 items ship in-repo and the P1/P2 roadmap is documented for follow-up.

## Scope

### In
- Inbound command UX in `agent_chat_control_plane.py`
- User-facing routing, bind, and recovery messages
- Session list/status legibility improvements
- Documentation updates for new commands and behavior
- Regression coverage in `tests/test_agent_chat_control_plane.py`

### Out
- Full setup wizard / GUI onboarding
- Notification preference center
- Analytics pipeline or hosted telemetry
- Session archive/close lifecycle UI

## User Problems

### UP-1: Routing state is invisible
Users do not know:
- what the current chat/topic/channel is bound to
- whether plain text will continue an existing session
- whether they are in a control surface or a session surface

### UP-2: Binding requires magic syntax
Users currently have to discover that `@<session_ref> hello` is the binding move for Telegram/Discord contexts.
That is functional but not obvious.

### UP-3: Recovery copy is too operator-oriented
When session resolution fails, users get technical feedback but not always the clearest next step.
They should be told exactly what to do next inside the same chat surface.

### UP-4: Session discovery is hard on mobile
`list` and `status` need to be more glanceable and useful on a phone.
Users care about:
- which session is waiting
- what transport context it is bound to
- how recently it was active

### UP-5: New sessions should feel anchored to the current surface
When a user creates a new session from a Telegram topic or Discord session surface, they expect that surface to keep following that session.

## Proposed Features

## P0 — Ship in this milestone

### F-1: Add `where` / `context` command
Provide an explicit command that explains the current routing surface.

Acceptance:
- `where` and `context` return the current surface and bound session when available
- Telegram topic, Discord channel/thread, and iMessage control-surface behaviors are explained in plain English

Example message UX:

```text
Context:
- Surface: Telegram topic 123456:99
- Bound session: @abcd1234 (bugfix, Claude)
- Follow-up: reply here with plain text. Plain-text replies in this topic will continue the same session.
- Rebind: send `bind @<session_ref>` if this surface should move to another session.
```

### F-2: Add explicit `bind @<session_ref>` command
Reduce syntax burden by giving users a direct command for binding the current Telegram topic or Discord channel/thread.

Acceptance:
- `bind @<session_ref>` works in Telegram topics and Discord channels/threads
- the confirmation message explains what happens next
- unsupported surfaces return a clear next step

Example message UX:

```text
Bound this Telegram topic to @abcd1234 (bugfix, Claude).
Future plain-text replies here will continue that session.
```

### F-3: Improve `list` and `status`
Make session discovery glanceable.

Acceptance:
- `list` includes waiting/active state, recency, and binding summary
- `status @<session_ref>` includes last active, bindings, and next-step guidance

Example message UX:

```text
Sessions:
- [Claude] @abcd1234 (bugfix) — waiting — 5m ago — Telegram topic 123456:99
- [Codex] @ef567890 — active — 18m ago — unbound
```

### F-4: Make missing-session and dispatch failures conversational
Replace terse operator copy with clear, action-oriented guidance.

Acceptance:
- unresolved routing prompt explains the current surface and next choices
- strict tmux failures say what happened and what to do next
- messages mention `list`, `where`, and `bind` where appropriate

Example message UX:

```text
I couldn't match that message to an existing session.
Surface: Discord channel 123456 [control]
Choose a runtime for a new background session:
1) Codex
2) Claude
3) Pi
Reply with 1, 2, or 3 (or codex/claude/pi). Reply 'cancel' to abort.
Need an existing ref instead? Send `list`. If this is the right topic/channel, send `bind @<session_ref>`.
```

### F-5: Auto-bind new sessions to the current Telegram/Discord surface when safe
If a user starts a new session from a routed conversational surface, keep that surface attached to the new session.

Acceptance:
- new sessions created from Telegram topics bind back to that topic
- new sessions created from bindable Discord contexts bind back to that context
- success messages explain that plain text there will keep routing to the same session

Example message UX:

```text
Created session @abcd1234 (bugfix).
Plain-text replies in this topic will continue the same session.
```

## P1 — Next milestone

### F-6: Guided onboarding flow
- one guided setup entry point
- transport/runtime selection
- live end-to-end test at the end

### F-7: Smarter notification controls
- verbosity modes by transport
- needs-input defaulting
- digest mode for lower-priority updates

### F-8: Stronger control-surface onboarding
- teach control vs session surfaces explicitly during first use
- show one-time examples after setup or first bind

## P2 — Longer-term roadmap

### F-9: Session lifecycle management
- rename session
- archive / close session
- stale-session cleanup suggestions

### F-10: UX instrumentation
- time to first successful roundtrip
- common recovery paths
- bind success rate
- setup failure breakdown by transport

## Milestone Acceptance Criteria

- P0 features are implemented in code
- user-facing docs mention the new commands and binding behavior
- regression tests cover the new command and binding flows
- repository tests pass

## Decision Log

- 2026-03-31: Scope narrowed to a complete P0 milestone that can ship entirely within this repository.
- 2026-03-31: `where/context` and `bind` were chosen over adding more hidden implicit behavior.
- 2026-03-31: New-session auto-binding is limited to contexts where the system already has stable routing semantics.
- 2026-03-31: P1/P2 remain documented roadmap items, not partial implementations.

## Validation Notes

- Target command:
  - `python3 -m unittest discover -s tests -p 'test_*.py' -v`
- Result:
  - `Ran 285 tests ... OK`
