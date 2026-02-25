# Architecture

## Overview

`agent-chat-control-plane` is a local macOS runtime that synchronizes:
- outbound Codex/Claude notifications -> iMessage and/or Telegram
- inbound iMessage and Telegram replies -> Codex/Claude sessions

The primary daemon is `agent_chat_control_plane.py`, which consolidates behavior that historically lived in separate outbound/reply bridges.

## Components

- `agent_chat_control_plane.py`
  - Long-lived run loop (`run`) and one-shot cycle (`once`)
  - Notify payload ingestion (`notify`)
  - Health diagnostics (`doctor`)
  - Session registry, routing, queue draining, inbound polling
- `agent_chat_notify.py`
  - Best-effort notify formatter/sender
  - Supports `attention` and `route` modes
  - Can update attention state/index without sending (`state_only` mode)
- `agent_chat_outbound_lib.py`
  - Session JSONL tailing and outbound message extraction
  - Request-user-input detection and mirroring controls
- `agent_chat_reply_lib.py`
  - iMessage `chat.db` inbound polling
  - Reply/session correlation and resume/tmux dispatch helpers
- `agent_chat_dedupe.py`
  - Shared dedupe key store + TTL

## Data and State

By default, state lives under `$CODEX_HOME/tmp` (usually `~/.codex/tmp`).

Key files include:
- `imessage_control_plane.lock`
- `imessage_session_registry.json`
- `imessage_message_session_index.json`
- `imessage_control_outbound_cursor.json`
- `imessage_inbound_cursor.json`
- `telegram_inbound_cursor.json`
- `imessage_queue.jsonl`
- `imessage_dedupe_index.json`

Inbound reads default to:
- `~/Library/Messages/chat.db` (override with `CODEX_IMESSAGE_CHAT_DB`)

## Control Flow

1. Codex or Claude emits a notify payload.
2. Runtime ingests payload via `notify` path and updates attention/session metadata.
3. Outbound messages are sent through iMessage and/or Telegram depending on transport mode.
4. Inbound replies are polled from iMessage `chat.db` and Telegram updates.
5. Routing selects a target session using explicit `@ref`, reply linkage, and registry context.
6. Dispatch proceeds via tmux + agent resume paths according to routing flags.

## Routing Semantics

Supported inbound command grammar:
- `help`
- `list`
- `status @<session_ref>`
- `@<session_ref> <instruction>`
- `new <label>: <instruction>`
- otherwise: implicit routing (subject to strict/reference settings)

Key controls:
- `CODEX_IMESSAGE_STRICT_TMUX`
- `CODEX_IMESSAGE_REQUIRE_SESSION_REF`
- `CODEX_IMESSAGE_TMUX_ACK_TIMEOUT_S`
- `CODEX_IMESSAGE_ROUTE_VIA_TMUX`
- `CODEX_IMESSAGE_ENABLE_NEW_SESSION`
- `CODEX_IMESSAGE_AUTO_CREATE_ON_MISSING`

## Operational Model

- Single-instance lock prevents duplicate control-plane daemons.
- Fail-open philosophy for non-critical paths: best-effort send/notify behavior should not crash callers.
- Queue drain and retry loops reduce transient Apple Events/GUI failures.
- `doctor` provides machine-readable and human-readable health summaries for launchd, chat DB access, queue depth, and routing status.
