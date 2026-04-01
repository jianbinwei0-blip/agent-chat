# Pi <-> Discord Integration: Next Implementation Plan

## Objective

Define the next execution sequence for Pi <-> Discord integration after the recent routing, onboarding, and notification improvements.

This plan treats **Pi needs-input UX in Discord** as the immediate next milestone, then sequences the next highest-value Discord improvements so work can continue without re-deciding priorities each time.

## Scope

### In
- immediate next milestone for Pi waiting-state UX in Discord
- sequencing for the next Discord-focused milestones after that
- expected code/doc/test touchpoints
- rollout and validation guidance

### Out
- implementation of the milestones themselves
- non-Discord product roadmap beyond dependencies worth noting
- hosted analytics, SaaS orchestration, or multi-tenant policy work

## Acceptance Criteria

- the repository has a concrete next-step plan for Pi <-> Discord work
- the immediate milestone is specific enough to implement without further PRD work
- follow-on milestones are prioritized and justified
- likely affected files and validation steps are captured

## Current Status

- Planning only
- Discord control-channel and session-channel workflows already exist
- guided onboarding, notification controls, `where`, and `bind` have already shipped

## Why This Order

The current Discord integration is already usable for session routing, but the next bottleneck is **human handoff quality**.
Users can create/bind sessions and receive updates, but when Pi pauses for clarification, approval, or a choice, Discord still puts too much burden on the user to infer what to do next.

Therefore the immediate next milestone should improve the quality of the Pi ↔ human checkpoint.
After that, the next biggest practical unlock is attachment handoff, followed by channel lifecycle sustainability.

## Milestone Sequence

## M1 — Pi needs-input UX in Discord (next)

Goal:
- make Pi waiting-state messages explicit, actionable, and easy to answer in Discord

Deliverables:
- standardized Pi waiting-state header for Discord
- appended suggested replies (`continue`, `summarize`, `yes`, `no`, etc.)
- clearer formatting for choices/approvals/missing-detail checkpoints
- `list` / `status` wording that distinguishes "waiting on you"
- docs and tests

Likely files:
- `agent_chat_control_plane.py`
- `docs/discord.md`
- `docs/control-plane.md`
- `README.md` (if behavior is user-visible enough for top-level mention)
- `tests/test_agent_chat_control_plane.py`

Implementation notes:
- prefer helper-level changes instead of scattering Discord copy logic through the main loop
- keep first pass plain-text only
- preserve free-form replies in bound session channels
- ensure control-channel wording still nudges users toward `@<session_ref>` where needed

Acceptance criteria:
- every Pi waiting message in Discord clearly says Pi is waiting for the user
- each message ends with explicit next-step guidance
- bound channel messages state that plain text there continues the same session
- tests cover the new formatting branches

## M2 — Discord attachment handoff to Pi

Goal:
- let users attach logs, screenshots, or small files in Discord and have those attachments routed into the correct Pi session context

Deliverables:
- download/safe-store Discord attachments for bound session messages
- append attachment metadata into the routed Pi prompt
- emit a Discord confirmation message describing what was attached
- document supported file types/limits/operator expectations

Likely files:
- `agent_chat_control_plane.py`
- Discord polling / normalization helpers in the control plane
- temp-file/session-path helper code
- `docs/discord.md`
- `docs/troubleshooting.md`
- tests for attachment parsing and routing

Implementation notes:
- start with file attachments only; defer embeds and external link unfurling
- save files under a session-scoped temp directory
- protect against duplicate processing on restart/re-poll
- define a conservative size limit for first pass

Acceptance criteria:
- a bound Discord session message with attachments routes both the text and the attachments to Pi
- operators can tell where attachments are stored and how they are referenced
- attachment errors are user-visible and recoverable

## M3 — Session lifecycle controls for Discord

Goal:
- make long-running Discord session-channel usage sustainable

Deliverables:
- explicit commands for at least a minimal lifecycle set, likely:
  - `close @<session_ref>`
  - `rename @<session_ref> <label>`
  - `unbind @<session_ref>` or equivalent
- clear behavior for bound session channels after close/archive
- docs/tests for channel lifecycle semantics

Likely files:
- `agent_chat_control_plane.py`
- `docs/discord.md`
- `docs/control-plane.md`
- tests for command parsing and registry updates

Implementation notes:
- start with metadata/state changes before automating Discord archival/deletion
- do not silently destroy channels in the first pass
- keep control-channel and bound-channel semantics explicit

Acceptance criteria:
- operators can retire or rename Discord-bound sessions without hand-editing registry state
- lifecycle actions produce clear next-step messages

## M4 — Thread-per-session mode (optional alternate Discord UX)

Goal:
- provide a lower-clutter Discord deployment model than channel-per-session

Deliverables:
- optional thread-per-session mode from the control channel
- routing and binding semantics parallel to existing session-channel mode
- docs describing tradeoffs between channel and thread modes

Why after M3:
- thread mode expands UX options but does not solve a more urgent user pain than needs-input, attachments, or lifecycle management

## M5 — Discord-specific observability and permission diagnostics

Goal:
- make Discord misconfiguration faster to diagnose

Deliverables:
- richer `doctor` reporting for Discord token/channel/permission/session-channel state
- rate-limit / last-poll / last-send diagnostics where practical
- clearer troubleshooting guidance

Likely files:
- `agent_chat_control_plane.py`
- `docs/discord.md`
- `docs/troubleshooting.md`
- tests for doctor output and config handling

## M6 — Multi-user control guardrails

Goal:
- make shared Discord servers safer for Pi session control

Possible scope:
- allowed user IDs
- allowed role IDs
- session-controller ownership semantics
- read-only observers vs active controllers

## M7 — Discord-native interaction model

Goal:
- move beyond plain-text parsing when the control-plane foundations are stable

Possible scope:
- slash commands
- buttons/select menus
- richer embeds for waiting state and status
- lower-latency event handling if architecture changes warrant it

## Dependency Notes

- M1 builds on existing Discord binding/session-channel behavior and should not require schema changes.
- M2 may require new attachment metadata on session records or new cursor/idempotency tracking for Discord messages.
- M3 should review how existing registry state models completed/stale sessions before adding new commands.
- M4 should build on the same generic conversation-binding model already used for Telegram/Discord contexts.
- M5 can partially ship incrementally alongside earlier milestones if useful.

## Recommended Execution Strategy

1. Ship **M1** as a focused UX-only change set.
2. Reassess message shapes after real use, then implement **M2**.
3. Add **M3** before Discord channel clutter becomes operational pain.
4. Treat **M4-M7** as follow-on roadmap items unless user demand or operator pain changes the order.

## Validation Notes

For each milestone:
- add focused unit tests first
- update `README.md` and `docs/discord.md` whenever user-visible behavior changes
- run full validation before merge:

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

## Decisions

- 2026-04-01: Prioritize the Pi ↔ human checkpoint before adding richer Discord transport features.
- 2026-04-01: Keep the next milestone plain-text first; richer Discord-native interactions remain a later investment.
- 2026-04-01: Attachment handoff is the next major utility unlock after waiting-state UX.
- 2026-04-01: Lifecycle controls should precede broader Discord UX expansion to avoid channel sprawl.
