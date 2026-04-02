# Pi Discord Desktop Visibility and Origin-Aware Progress PRD

## Objective

Make Discord-origin prompts to Pi sessions visible on the desktop immediately, while keeping Discord informed of meaningful progress without turning Discord into a noisy mirror of all local desktop work.

This milestone should improve the Pi <-> Discord collaboration loop without attempting to change Pi's native `resume` semantics.

## Scope

### In
- desktop visibility rules for Discord-origin prompts targeting Pi sessions
- per-session progress-sharing modes that distinguish Discord-origin work from desktop-origin work
- standardized Discord copy for accepted / working / needs-input / completed / failed states
- explicit state model for foreground/background/hidden desktop visibility
- regression coverage for origin-aware Discord progress policy and user-facing copy
- docs updates for the new behavior and mode semantics

### Out
- changing Pi's native `resume` behavior
- redesigning Pi's internal TUI
- Discord slash commands, buttons, or modal workflows
- token-level or tool-call-level live streaming into Discord
- non-Discord transport redesign beyond shared helper wording where reused
- analytics/telemetry pipeline work

## User Problems

### UP-1: Discord-origin prompts are not visible enough on the desktop
When a Discord message is routed into a Pi session, the desktop user may not see that message without manually re-attaching or re-opening the session.

### UP-2: Remote requesters need progress closure
If a user asks Pi to do something from Discord, they expect Discord to reflect whether Pi accepted the request, is working, is blocked, or finished.

### UP-3: Mirroring all local desktop work back into Discord would create noise
Not every local follow-up or exploratory prompt belongs in the Discord thread. The integration needs a scoped default that respects origin and user intent.

### UP-4: Session sharing policy is implicit today
There is no explicit per-session model for whether Discord should see progress for Discord-origin prompts only, all prompts, or no automatic progress at all.

### UP-5: Desktop attention state is underspecified
The integration needs a clear product contract for what happens when a Discord-origin prompt targets a foreground, background, or hidden Pi session.

## Goals

- Make Discord-origin prompts visible locally without requiring the user to manually reopen a session just to confirm delivery.
- Mirror meaningful progress back to Discord for Discord-origin prompts.
- Keep desktop-origin prompts private by default.
- Support explicit per-session sharing modes when a session is intentionally collaborative.
- Keep progress updates milestone-based and low-noise.

## Non-Goals

- Solving Pi session attach/resume UX in this milestone
- Replacing Pi's own transcript rendering model
- Shipping a general-purpose presence system across all transports
- Building a full notification preference center

## Proposed Features

## P0 — Ship in this milestone

### F-1: Desktop visibility for Discord-origin prompts
When a Discord-origin prompt is routed to a Pi session, it must become visible on the desktop immediately according to the session's desktop visibility state.

Acceptance:
- foreground Pi session -> Discord-origin prompt is visibly present in the active desktop surface without a manual reopen
- background Pi session -> the desktop receives a visible attention signal and the session is marked unread/attention-needed
- hidden/unattached Pi session -> the desktop receives a visible attention signal and the session is marked unread/attention-needed

### F-2: Origin-aware Discord progress policy
The control plane should treat prompt origin as a first-class input to Discord progress behavior.

Acceptance:
- Discord-origin prompts receive Discord milestone updates by default
- desktop-origin prompts do not receive Discord milestone updates by default
- routing metadata preserves enough origin context to keep the lifecycle coherent

### F-3: Per-session progress-sharing modes
Add explicit per-session modes that define when Discord should receive automatic progress updates.

Acceptance:
- mode definitions exist in code/docs for `origin_scoped`, `shared_status`, `full_mirror`, and `local_only`
- newly Discord-bound sessions default to `origin_scoped`
- progress delivery behavior follows the selected mode consistently

### F-4: Standardized Discord progress copy
Discord progress messages should use concise, stable lifecycle wording.

Acceptance:
- accepted / working / needs-input / completed / failed / cancelled states use standardized copy
- Discord-origin accepted copy confirms delivery to the target session
- needs-input copy explicitly says Pi is waiting and tells the user how to continue
- completion/failure copy is compact and action-oriented

### F-5: Milestone-based update cadence
Discord should receive milestone updates rather than a raw stream of internal activity.

Acceptance:
- `accepted` is sent immediately
- `working` is sent once when Pi starts acting on the prompt
- `needs_input`, `completed`, `failed`, and `cancelled` are sent immediately on state transition
- intermediate progress in `origin_scoped` and `shared_status` is limited to major phase changes and long-running periodic summaries

## P1 — Follow-on

### F-6: Session mode switching UX
- explicit command surface to inspect/change a session's sharing mode
- clear confirmation copy when a mode changes

### F-7: Prompt-correlated Discord progress trail
- edit-in-place or grouped follow-up messages where transport constraints allow
- one coherent lifecycle trail per prompt

### F-8: Stronger desktop attention affordances
- richer unread/attention indicators in session lists or companion UI
- clearer escalation when Pi reaches needs-input for a Discord-origin prompt

## P2 — Longer-term roadmap

### F-9: Richer collaborative controls
- subscribe/watch semantics for remote observers
- per-thread visibility policies
- optional richer progress details for explicitly shared sessions

### F-10: UX instrumentation
- frequency of Discord-origin prompts
- how often desktop attention states fire
- how often shared modes are enabled
- signal/noise feedback on Discord progress cadence

## Behavior Contract

## Per-session modes

### `origin_scoped` (default)
Use for normal Discord-bound sessions.

Rules:
- Discord-origin prompts:
  - visible on desktop immediately
  - progress posted to Discord
- desktop-origin prompts:
  - visible locally
  - no automatic Discord progress
- desktop-origin needs-input/completion:
  - stay local only

### `shared_status`
Use for intentionally collaborative sessions where milestone sharing is desired.

Rules:
- Discord-origin prompts:
  - visible on desktop immediately
  - progress posted to Discord
- desktop-origin prompts:
  - visible locally
  - milestone progress posted to Discord
- cadence remains milestone-based, not verbose streaming

### `full_mirror`
Use for demos, debugging, or highly collaborative sessions.

Rules:
- all prompts:
  - visible locally
  - progress posted to Discord
- updates may be more frequent than `shared_status`
- still avoid token-level/tool-level spam in this milestone

### `local_only`
Use for privacy-sensitive or desktop-only work.

Rules:
- no automatic progress posts to Discord for any prompt origin
- desktop visibility rules still apply locally

## Desktop visibility states

### `inline_visible`
Meaning:
- the prompt is visibly present in the active desktop Pi surface

Applies when:
- the target Pi session is foreground

### `notification_visible`
Meaning:
- the prompt is visible through a desktop notification/banner/overlay even when the Pi session is not frontmost

Applies when:
- the target Pi session is background or hidden/unattached

### `attention_badged`
Meaning:
- the session is marked as having unread remote attention

Applies when:
- a Discord-origin prompt has arrived and the user has not yet viewed/cleared the session attention state

### `waiting_for_user`
Meaning:
- Pi is blocked on the active prompt and needs user input

Applies when:
- Pi emits a needs-input event for that prompt

### `resolved`
Meaning:
- the active prompt lifecycle has ended (completed, failed, or cancelled)

Applies when:
- the active prompt reaches a terminal milestone

## Event rules

### Discord-origin prompt -> Pi session
1. Create a prompt event with origin=`discord`, session id, origin surface, and prompt correlation id.
2. Make the prompt visible on the desktop immediately:
   - foreground -> `inline_visible`
   - background -> `notification_visible` + `attention_badged`
   - hidden/unattached -> `notification_visible` + `attention_badged`
3. Post Discord lifecycle updates according to the session mode.

### Desktop-origin prompt -> Pi session
1. The prompt is visible locally by definition.
2. Discord lifecycle updates depend on the session mode:
   - `origin_scoped` -> do not post
   - `shared_status` -> post milestone updates
   - `full_mirror` -> post milestone updates with richer cadence
   - `local_only` -> do not post

### Progress event matrix

| Event | Discord-origin prompt | Desktop-origin prompt |
| --- | --- | --- |
| accepted | post in `origin_scoped` / `shared_status` / `full_mirror` | post only in `shared_status` / `full_mirror` |
| working | post in `origin_scoped` / `shared_status` / `full_mirror` | post only in `shared_status` / `full_mirror` |
| needs_input | post in `origin_scoped` / `shared_status` / `full_mirror` | post only in `shared_status` / `full_mirror` |
| completed | post in `origin_scoped` / `shared_status` / `full_mirror` | post only in `shared_status` / `full_mirror` |
| failed | post in `origin_scoped` / `shared_status` / `full_mirror` | post only in `shared_status` / `full_mirror` |
| cancelled | post in `origin_scoped` / `shared_status` / `full_mirror` | post only in `shared_status` / `full_mirror` |
| any automatic lifecycle event | suppress in `local_only` | suppress in `local_only` |

### Cadence rules
- `accepted`: send immediately
- `working`: send once when Pi begins acting on the prompt
- `needs_input`: send immediately and prominently
- `completed` / `failed` / `cancelled`: send immediately on transition
- `origin_scoped` and `shared_status`: only send additional progress on major phase change or periodic long-running summary
- `full_mirror`: may send more frequent summaries, but still should not emit every internal tool or token event

## Standard Discord Copy

### Accepted (Discord-origin)
```text
Got it — sent to `@ref`. It's now visible on the desktop.
```

Fallback when desktop surface is background/hidden:
```text
Got it — sent to `@ref`. It's queued in the session and marked for desktop attention.
```

### Working (Discord-origin)
```text
Pi is working on your request in `@ref`.
```

### Needs input (Discord-origin)
```text
Pi is waiting for your input on `@ref`.
{question}
Reply here to continue.
```

If structured choices are present:
```text
Pi is waiting for your input on `@ref`.
{question}
Reply here with `1`, `2`, `yes`, `no`, or your own instructions.
```

### Completed (Discord-origin)
```text
Done in `@ref`.
{summary}
```

### Failed (Discord-origin)
```text
Pi hit a problem in `@ref`.
{summary}
Reply here if you want Pi to try a different approach.
```

### Cancelled (Discord-origin)
```text
Cancelled in `@ref`.
```

### Desktop-origin progress in `shared_status`
Accepted:
```text
Pi started local work in `@ref`.
```

Working:
```text
Pi is working locally in `@ref`.
```

Needs input:
```text
Pi needs input in `@ref`.
{question}
```

Completed:
```text
Pi completed local work in `@ref`.
{summary}
```

## Milestone Acceptance Criteria

- Discord-origin prompts targeting Pi sessions are visible on the desktop according to the documented desktop visibility state rules.
- newly Discord-bound sessions default to `origin_scoped`
- Discord-origin prompts post milestone lifecycle updates to Discord in `origin_scoped`
- desktop-origin prompts do not post automatic lifecycle updates to Discord in `origin_scoped`
- `shared_status`, `full_mirror`, and `local_only` semantics are documented and enforced in tests/helpers where implemented
- standardized Discord progress copy is documented and used for the new lifecycle states
- docs describe both the desktop visibility behavior and the per-session mode model
- regression tests cover origin-aware lifecycle posting and desktop attention-state branching where practical

## Likely Files

- `agent_chat_control_plane.py`
- `docs/discord.md`
- `docs/control-plane.md`
- `README.md` (if top-level user behavior changes merit mention)
- `tests/test_agent_chat_control_plane.py`

## Current Status

- Planning only
- No code changes yet

## Decisions

- 2026-04-01: Do not attempt to change Pi's native `resume` semantics in this milestone.
- 2026-04-01: Default Discord-bound Pi sessions to `origin_scoped` so Discord sees progress for Discord-origin work but not local desktop experimentation.
- 2026-04-01: Desktop visibility for Discord-origin prompts is required even when Discord progress cadence remains conservative.
- 2026-04-01: Progress should remain milestone-based; token/tool spam is explicitly out of scope.
- 2026-04-01: Shared-session behavior should be opt-in via per-session modes rather than inferred from channel binding alone.

## Validation Notes

- Planned validation:
  - targeted unit tests in `tests/test_agent_chat_control_plane.py`
  - docs review for `README.md`, `docs/control-plane.md`, and `docs/discord.md`
  - full suite: `python3 -m unittest discover -s tests -p 'test_*.py'`
- Result:
  - Pending implementation
