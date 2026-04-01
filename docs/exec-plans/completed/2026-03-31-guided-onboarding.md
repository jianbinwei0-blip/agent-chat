# Guided Onboarding Flow

## Objective

Implement the next highest-value roadmap item from the integration UX PRD: a guided onboarding flow that helps users configure one runtime and one transport with minimal manual assembly.

## Scope

- Add a `guided-setup` command to `agent_chat_control_plane.py`
- Add a generic wrapper script at `scripts/setup-agent-chat-easy.sh`
- Keep `scripts/setup-telegram-easy.sh` as a Telegram-specific wrapper
- Persist chosen settings to a local env file
- Run the existing idempotent setup commands (`setup-notify-hook`, `setup-launchd`, `doctor`)
- Print transport-specific first-success guidance
- Add unit coverage and docs updates

## Acceptance Criteria

- Users can run one guided command and select runtime + transport
- The flow prompts only for transport-specific secrets/ids
- A local env file is created/updated
- Existing setup commands are reused instead of duplicated
- README and troubleshooting docs mention the new flow
- Tests pass

## Decisions

- Guided setup supports one transport at a time (`telegram`, `discord`, or `imessage`) to keep onboarding legible.
- The flow writes `.env.telegram.local` by default for Telegram and `.env.agent-chat.local` for other transports.
- Telegram-specific onboarding remains available as a thin wrapper for backwards compatibility and speed.
- The guided flow stays in the Python control-plane CLI so it is testable and reuses existing setup internals directly.

## Validation Notes

- Target command:
  - `python3 -m unittest discover -s tests -p 'test_*.py'`
- Result:
  - `Ran 288 tests ... OK`
