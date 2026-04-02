# Pi Discord Desktop Visibility: Implementation Plan

## Objective

Implement the next milestone from `docs/exec-plans/active/2026-04-01-pi-discord-desktop-visibility-and-origin-aware-progress.md`:

1. Discord-origin prompts to Pi sessions become visibly present on the desktop immediately.
2. Discord receives milestone progress for Discord-origin prompts by default.
3. Desktop-origin prompts remain private by default.
4. Per-session sharing modes exist in the data model and progress policy.

This plan deliberately avoids changing Pi's native `resume` behavior.

## Scope

### In
- registry/session metadata for per-session Discord progress mode and active prompt lifecycle
- origin capture for inbound Discord prompts routed to Pi sessions
- desktop visibility helper path for Discord-origin prompts
- standardized Discord progress formatting for accepted / working / needs-input / completed / failed / cancelled
- origin-aware lifecycle emission policy in outbound session processing
- tests/docs required for the new behavior

### Out
- changing Pi's internal TUI or attach/resume semantics
- slash commands, buttons, or Discord-native interactive UI
- token/tool-level live streaming to Discord
- general transport redesign for Telegram/iMessage
- full collaborative watch/subscription model

## Acceptance Criteria

### Milestone-level
- Discord-origin prompts targeting Pi sessions trigger a local desktop visibility action immediately.
- Newly Discord-bound Pi sessions default to `origin_scoped`.
- Discord-origin prompts emit milestone lifecycle updates to Discord in `origin_scoped` mode.
- Desktop-origin prompts do not emit Discord lifecycle updates in `origin_scoped` mode.
- Standardized Discord copy is used for the milestone lifecycle states.
- Tests cover origin-aware gating, default mode selection, and desktop attention branching where practical.

### Phase-level guardrails
- P0 must ship with a stable default path for `origin_scoped`.
- `shared_status`, `full_mirror`, and `local_only` should be introduced as normalized modes in code/docs even if desktop-origin prompt inference ships in a later phase.

## Current Status

- Planning only
- PRD approved
- No code changes yet

## Implementation Strategy

Deliver in two layers:

1. **P0 functional milestone**
   - fully implement Discord-origin desktop visibility
   - fully implement origin-aware Discord lifecycle posting for Discord-origin prompts
   - fully suppress desktop-origin Discord lifecycle updates in `origin_scoped`
   - introduce normalized per-session mode helpers and defaults

2. **P1 strengthening work**
   - improve desktop-origin prompt inference so `shared_status` / `full_mirror` can mirror local work more accurately
   - improve desktop attention affordances beyond the initial notification/banner path

The key implementation move is to make **prompt origin** and **session progress mode** explicit control-plane concepts.

## Proposed Data Model Changes

## Session record additions

Add the following fields to session records in the registry:

- `discord_progress_mode`
  - one of: `origin_scoped`, `shared_status`, `full_mirror`, `local_only`
- `active_prompt_id`
  - opaque id for the most recent tracked prompt lifecycle
- `active_prompt_origin`
  - `discord` or `desktop`
- `active_prompt_transport`
  - initially `discord` when the active prompt originated there
- `active_prompt_context`
  - canonical conversation key or channel/thread id summary
- `active_prompt_status`
  - `accepted`, `working`, `needs_input`, `completed`, `failed`, `cancelled`
- `desktop_attention_state`
  - `inline_visible`, `notification_visible`, `attention_badged`, `waiting_for_user`, `resolved`, or `none`
- `last_desktop_attention_ts`
  - timestamp of last desktop attention event
- `last_discord_prompt_ts`
  - timestamp of last Discord-origin prompt accepted for the session

Notes:
- P0 only requires robust lifecycle handling for `active_prompt_origin=discord`.
- `desktop` origin tracking can begin as best-effort and be strengthened in P1.

## Registry normalization requirements

- missing/invalid `discord_progress_mode` -> normalize to `origin_scoped` for Discord-bound sessions
- non-Discord-bound sessions may omit the field until first needed, but helpers should still normalize to `origin_scoped`
- invalid `desktop_attention_state` -> normalize to `none`

## Step-by-Step Plan

## T1: Add normalized session-mode and lifecycle helpers

Goal:
Create one helper layer that owns progress-mode normalization, lifecycle-state normalization, and policy decisions.

Implementation:
- Add helper functions in `agent_chat_control_plane.py` for:
  - `_normalize_discord_progress_mode(...)`
  - `_session_discord_progress_mode(session_rec=...)`
  - `_set_default_discord_progress_mode_for_session(...)`
  - `_normalize_desktop_attention_state(...)`
  - `_should_emit_discord_lifecycle_event(...)`
  - `_is_discord_origin_prompt(...)`
- Keep all mode semantics centralized so inbound/outbound code does not hardcode `origin_scoped` rules inline.

Likely code touchpoints:
- `agent_chat_control_plane.py`
- registry load/save/upsert helpers in the same file

Tests:
- mode normalization returns `origin_scoped` on invalid/missing values
- `local_only` suppresses all automatic Discord lifecycle events
- `origin_scoped` posts only for Discord-origin prompts
- `shared_status` / `full_mirror` policy helpers return true for both origins

## T2: Extend session upsert/defaulting for Discord-bound Pi sessions

Goal:
Ensure newly Discord-bound sessions default to `origin_scoped` and persist lifecycle metadata safely.

Implementation:
- Update the session upsert/bind path so that when a Pi session becomes Discord-bound, it gets:
  - `discord_progress_mode = origin_scoped` if absent
- Ensure rebinding/reuse paths preserve an explicit mode rather than overwriting it.
- Keep the defaulting behavior narrow: only set defaults when the field is absent/invalid.

Likely code touchpoints:
- Discord bind helpers in `agent_chat_control_plane.py`
- any session creation or bind-confirmation path already setting `discord_channel_id`

Tests:
- new Discord-bound session gets `origin_scoped`
- rebinding an existing session preserves explicit `shared_status`/`local_only`

## T3: Capture prompt origin when processing inbound Discord prompts

Goal:
When a Discord message is routed to a Pi session, persist enough metadata to drive later lifecycle decisions.

Implementation:
- In Discord inbound routing paths, after target session resolution but before/after dispatch:
  - generate `active_prompt_id`
  - set `active_prompt_origin = discord`
  - set `active_prompt_transport = discord`
  - set `active_prompt_context` from canonical Discord conversation key
  - set `active_prompt_status = accepted`
  - set `last_discord_prompt_ts`
- Persist this metadata even if the dispatch path uses tmux or resume fallback.
- Make `accepted` a real prompt-lifecycle state rather than only an immediate Discord send side effect.

Likely code touchpoints:
- `_process_inbound_replies(...)`
- Discord inbound normalization helpers
- dispatch call sites around `_dispatch_prompt_to_session(...)`

Tests:
- Discord-bound Pi session inbound reply records active prompt metadata
- non-Discord inbound paths do not mark prompts as Discord-origin
- accepted message and lifecycle metadata stay aligned on the same session

## T4: Add desktop visibility helper for Discord-origin prompts

Goal:
Make Discord-origin prompts visibly present on the desktop immediately.

Implementation:
- Add a helper such as `_emit_desktop_visibility_for_discord_prompt(...)` that:
  1. determines whether the target Pi session appears foreground-attached, background-attached, or hidden/unattached
  2. chooses the first viable visibility path
  3. records `desktop_attention_state` and `last_desktop_attention_ts`
- Suggested visibility path order for P0:
  - **foreground-attached tmux pane**: show a tmux-visible banner/message for the attached desktop client if discoverable
  - otherwise: macOS desktop notification via `osascript` / standard notification path
  - always: persist session attention metadata in the registry
- If foreground detection is ambiguous, prefer a safe fallback to notification rather than doing nothing.

Implementation notes:
- P0 does not need a perfect presence model; it needs a reliable visible signal.
- Reuse existing tmux discovery/session metadata where possible.
- If tmux client targeting is complex, shipping a notification-first fallback is acceptable so long as the desktop user sees something.

Likely code touchpoints:
- `agent_chat_control_plane.py`
- possibly a small new helper for macOS notification shelling
- Pi/tmux session discovery helpers

Tests:
- foreground-like path -> helper records `inline_visible`
- background/hidden path -> helper records `notification_visible` and `attention_badged`
- notification send failure still leaves registry attention state updated best-effort

## T5: Standardize Discord lifecycle copy and send path

Goal:
Move lifecycle copy into a small set of helpers so accepted/working/needs-input/completed/failed/cancelled states are consistent.

Implementation:
- Add formatter helpers, for example:
  - `_format_discord_progress_text(...)`
  - `_format_discord_progress_accepted(...)`
  - `_format_discord_progress_working(...)`
  - `_format_discord_progress_needs_input(...)`
  - `_format_discord_progress_completed(...)`
  - `_format_discord_progress_failed(...)`
- Ensure accepted copy differs based on desktop visibility result:
  - visible inline now
  - or marked for desktop attention
- Keep existing Pi needs-input helper logic where useful, but route through the new lifecycle formatter contract.

Likely code touchpoints:
- `_send_structured(...)`
- Pi-specific needs-input formatting helpers
- Discord-specific message rendering branches

Tests:
- accepted copy mentions `@ref` and desktop visibility/attention correctly
- needs-input copy says Pi is waiting and gives reply guidance
- completion/failure copy uses stable action-oriented wording

## T6: Gate outbound Discord lifecycle emission by origin + mode

Goal:
Make outbound lifecycle sends origin-aware instead of transport-only.

Implementation:
- Update outbound session processing (`_process_session_file(...)` and related helpers) to consult:
  - session mode
  - active prompt origin
  - active prompt status
  - event kind (`update`, `needs_input`, `responded`, etc.)
- Policy for P0:
  - if active prompt origin is `discord` and mode is `origin_scoped`, emit Discord lifecycle milestones
  - if activity occurs with no active Discord-origin prompt and mode is `origin_scoped`, suppress Discord lifecycle output
  - if mode is `local_only`, suppress all automatic Discord lifecycle output
  - if mode is `shared_status` / `full_mirror`, allow lifecycle output for both origins
- When a terminal event occurs, mark:
  - `active_prompt_status = completed|failed|cancelled`
  - `desktop_attention_state = resolved`

Likely code touchpoints:
- `_process_session_file(...)`
- `_send_structured(...)`
- any helpers deciding whether to emit completion/progress notifications

Tests:
- Discord-origin prompt -> `working`/`needs_input`/`completed` post in `origin_scoped`
- desktop-origin activity -> no post in `origin_scoped`
- `shared_status` and `full_mirror` policy helpers allow lifecycle sends for both origins
- `local_only` suppresses automatic posts even for Discord-origin prompts

## T7: Add minimal working-state transition for Discord-origin prompts

Goal:
Represent the gap between `accepted` and `completed/needs_input` with one stable `working` transition.

Implementation:
- On first meaningful outbound assistant activity after a Discord-origin prompt is accepted, emit `working` once if not already emitted.
- Persist `active_prompt_status = working`.
- Avoid repeated `working` messages for the same prompt.

Notes:
- This should be lightweight; do not over-model internal Pi phases in P0.

Tests:
- first outbound assistant activity after accepted -> one `working` message
- later progress updates do not repeat `working` unless a new prompt id is created

## T8: Document desktop visibility and mode semantics

Goal:
Keep user-facing docs aligned with the shipped behavior.

Implementation:
- Update:
  - `docs/discord.md`
  - `docs/control-plane.md`
  - `README.md` if the top-level behavior change is material enough
- Document:
  - desktop visibility behavior for Discord-origin Pi prompts
  - default `origin_scoped` mode
  - concise definitions for `shared_status`, `full_mirror`, `local_only`
  - that local desktop work is not mirrored by default

Tests/validation:
- docs review against implemented copy and mode names

## T9: Add regression tests before broad refactors

Goal:
Lock behavior down with targeted tests before iterating on internals.

Test clusters to add:
- session-mode normalization and defaults
- Discord inbound prompt origin metadata capture
- desktop visibility helper state branching
- accepted copy formatting
- origin-aware suppression of desktop-origin lifecycle messages in `origin_scoped`
- needs-input/completed lifecycle behavior for Discord-origin prompts
- preservation of explicit mode across rebind/update flows

Primary file:
- `tests/test_agent_chat_control_plane.py`

## T10: P1 follow-up — infer desktop-origin prompt lifecycles more accurately

Goal:
Make `shared_status` / `full_mirror` reflect actual local desktop prompts rather than only remote ones.

Why this is follow-on:
- P0 can fully satisfy the main user need with Discord-origin visibility + progress.
- Accurate desktop-origin mirroring requires stronger local prompt detection than the current outbound assistant-only tailing provides.

Implementation options:
- extend session tailing to detect new local user-message events and create `active_prompt_origin = desktop`
- if exact user-message detection is not stable across runtimes, use a best-effort heuristic tied to session activity windows

Acceptance for follow-on:
- local desktop prompts in `shared_status` / `full_mirror` generate coherent lifecycle updates to Discord
- `origin_scoped` remains unchanged

## Rollout Order

### Phase A — internal plumbing
- T1
- T2
- T3

### Phase B — user-visible P0 behavior
- T4
- T5
- T6
- T7

### Phase C — docs + hardening
- T8
- T9

### Phase D — follow-on strengthening
- T10

## Risks and Mitigations

### Risk: foreground/background detection is imperfect
Mitigation:
- prefer a reliable desktop notification fallback
- record state best-effort in registry even when exact foreground classification is uncertain

### Risk: local desktop-origin prompt inference is weak
Mitigation:
- keep P0 centered on Discord-origin prompts
- treat `shared_status` / `full_mirror` local-origin mirroring as a P1 strengthening item if needed

### Risk: lifecycle copy fragments across code paths
Mitigation:
- centralize formatting helpers before editing many send branches

### Risk: existing notification-level behavior conflicts with lifecycle policy
Mitigation:
- make origin/mode policy a separate helper layer and keep notification verbosity as a second-level filter rather than the primary decision source

## Validation Notes

Planned validation sequence:

1. targeted tests for new helpers and Discord inbound/outbound branches:
```bash
python3 -m unittest \
  tests.test_agent_chat_control_plane.TestAgentChatControlPlane
```

2. full suite:
```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

3. manual smoke test after implementation:
- create or bind a Discord session channel to a Pi session
- send a Discord-origin prompt
- verify desktop visibility appears immediately
- verify Discord receives accepted -> working -> needs_input/completed progression as appropriate
- type a local desktop prompt in the same session
- verify no Discord lifecycle post appears in `origin_scoped`

## Decision Log

- 2026-04-01: Implement `origin_scoped` as the default and fully-supported P0 behavior.
- 2026-04-01: Treat desktop visibility as satisfied by a reliable visible desktop signal, not necessarily by Pi-native inline rendering in the first pass.
- 2026-04-01: Introduce session modes now, but allow desktop-origin lifecycle inference to harden in a follow-on phase.
- 2026-04-01: Keep lifecycle updates milestone-based and centralized in helper formatting/policy code.
