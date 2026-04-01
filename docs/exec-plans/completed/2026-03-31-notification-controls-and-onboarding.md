# Notification Controls and Control-Surface Onboarding

## Objective

Implement the next two roadmap items after guided onboarding:

1. smarter notification controls
2. stronger control-surface onboarding

## Scope

- Add a notification-level control for autonomous session activity
- Preserve current default behavior while enabling quieter or more verbose modes
- Add one-time quick-start hints on first use of control surfaces and bound session surfaces
- Persist onboarding state in the control-plane registry
- Update docs and tests

## Acceptance Criteria

- `AGENT_CHAT_NOTIFICATION_LEVEL` supports `quiet`, `default`, and `verbose`
- `quiet` suppresses automatic completion/progress notifications from session activity
- `default` preserves current behavior
- `verbose` emits progress updates across enabled transports, not just Discord session channels
- first-use control surfaces get one-time quick-start guidance in-context
- first-use bound session surfaces get one-time continuation guidance in-context
- tests pass

## Decisions

- Notification controls affect autonomous session activity, not direct replies to explicit user commands.
- Control-surface onboarding is appended once per surface and persisted in registry state.
- Session-surface onboarding is appended once per bound surface and teaches `where` and `bind` explicitly.

## Validation Notes

- Target command:
  - `python3 -m unittest discover -s tests -p 'test_*.py'`
- Result:
  - `Ran 291 tests ... OK`
