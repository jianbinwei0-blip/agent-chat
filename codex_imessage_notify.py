#!/usr/bin/env python3
"""Codex → iMessage notifier (macOS).

This is best-effort and must never fail the calling process.

Usage:
  codex_imessage_notify.py attention [--cwd DIRNAME] [--need TEXT] [--to RECIPIENT] [--dry-run]
  codex_imessage_notify.py route [--cwd DIRNAME] [--need TEXT] [--to RECIPIENT] [--dry-run] [PAYLOAD_JSON]

Config:
  - CODEX_IMESSAGE_TO: recipient phone number (e.g. +13135551234) or Apple ID email
  - CODEX_IMESSAGE_NOTIFY_MODE: send (default), state_only, or route
    - state_only: update attention state/index for reply routing without sending iMessages
    - route: only send input-needed prompts and final completion status
  - CODEX_IMESSAGE_NOTIFY_FALLBACK_INPUT: when route mode is enabled, allow generic
    input-needed fallback iMessage when exact question text is unavailable (default: 1)
  - CODEX_IMESSAGE_FINAL_STATUS_ENABLED: when route mode is enabled, send final
    completion status notifications (default: 1)
  - CODEX_IMESSAGE_DEDUPE_INDEX: shared dedupe index path (JSON)
  - CODEX_IMESSAGE_DEDUPE_TTL_S: dedupe TTL seconds (default: 86400)
  - CODEX_IMESSAGE_QUEUE: fallback queue path (JSONL); defaults to $CODEX_HOME/tmp/imessage_queue.jsonl
  - CODEX_IMESSAGE_ATTENTION_INDEX: path to per-session attention index JSON
  - CODEX_HOME: defaults to ~/.codex
  - CODEX_HISTORY_PATH: override history.jsonl path (defaults to $CODEX_HOME/history.jsonl)
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import platform
import re
import subprocess
import sys
import time
from pathlib import Path

import codex_imessage_dedupe


_ATTENTION_INDEX_MAX_ENTRIES = 100
_ATTENTION_INDEX_MAX_AGE_S = 7 * 24 * 60 * 60
_FINAL_STATUS_DEDUPE_TTL_SECONDS = 120


def _find_newest_session_file(*, codex_home: Path) -> Path | None:
    try:
        sessions_dir = codex_home / "sessions"
        if not sessions_dir.exists():
            return None

        newest: Path | None = None
        newest_mtime = -1.0

        for path in sessions_dir.rglob("*.jsonl"):
            try:
                mtime = path.stat().st_mtime
            except Exception:
                continue
            if mtime > newest_mtime:
                newest_mtime = mtime
                newest = path

        return newest
    except Exception:
        return None


def _normalize_recipient(raw: str) -> str:
    recipient = raw.strip()
    if recipient.startswith("+"):
        return recipient

    compact = re.sub(r"[\s\-\(\)\.]", "", recipient)
    if compact.isdigit():
        # Common US case: 10-digit number → +1...
        if len(compact) == 10:
            return f"+1{compact}"
        # 11-digit starting with 1 → +1...
        if len(compact) == 11 and compact.startswith("1"):
            return f"+{compact}"

    return recipient


def _tmux_socket_from_env() -> str | None:
    raw = os.environ.get("TMUX")
    if not (isinstance(raw, str) and raw.strip()):
        return None
    token = raw.split(",", 1)[0].strip()
    if token:
        return token
    return None


def _read_last_user_text(history_path: Path) -> str | None:
    try:
        if not history_path.exists():
            return None
        last_line: str | None = None
        with history_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    last_line = line
        if not last_line:
            return None

        event = json.loads(last_line)
        if isinstance(event, dict):
            text = event.get("text")
            if isinstance(text, str) and text.strip():
                return text.strip()
        return None
    except Exception:
        return None


def _read_session_meta_from_session(session_path: Path) -> dict[str, object] | None:
    try:
        if not session_path.exists():
            return None

        with session_path.open("r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line:
                    continue

                try:
                    event = json.loads(line)
                except Exception:
                    continue

                if not isinstance(event, dict):
                    continue
                if event.get("type") != "session_meta":
                    continue

                payload = event.get("payload")
                if isinstance(payload, dict):
                    return payload
                return None

        return None
    except Exception:
        return None


def _read_latest_session_meta(*, codex_home: Path) -> dict[str, object] | None:
    try:
        session_path_env = os.environ.get("CODEX_SESSION_PATH") or os.environ.get("CODEX_SESSION_FILE")
        if session_path_env:
            session_path = Path(session_path_env)
            meta = _read_session_meta_from_session(session_path)
            if meta:
                return meta

        newest = _find_newest_session_file(codex_home=codex_home)
        if not newest:
            return None

        return _read_session_meta_from_session(newest)
    except Exception:
        return None


def _read_last_assistant_text_from_session(session_path: Path) -> str | None:
    """Return the last assistant message from a Codex session JSONL, if present."""
    try:
        if not session_path.exists():
            return None

        last_text: str | None = None
        with session_path.open("r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line:
                    continue

                try:
                    event = json.loads(line)
                except Exception:
                    continue

                if not isinstance(event, dict):
                    continue

                if event.get("type") == "response_item":
                    payload = event.get("payload")
                    if not isinstance(payload, dict):
                        continue

                    if payload.get("type") != "message" or payload.get("role") != "assistant":
                        continue

                    content = payload.get("content")
                    if not isinstance(content, list):
                        continue

                    chunks: list[str] = []
                    for item in content:
                        if not isinstance(item, dict):
                            continue
                        if item.get("type") != "output_text":
                            continue
                        text = item.get("text")
                        if isinstance(text, str) and text:
                            chunks.append(text)
                    if chunks:
                        last_text = "".join(chunks).strip()
                    continue

                if event.get("type") == "event_msg":
                    payload = event.get("payload")
                    if not isinstance(payload, dict):
                        continue

                    if payload.get("type") not in {"agent_message", "assistant_message"}:
                        continue

                    message = payload.get("message")
                    if isinstance(message, str) and message.strip():
                        last_text = message.strip()
                    continue

        return last_text.strip() if isinstance(last_text, str) and last_text.strip() else None
    except Exception:
        return None


def _read_last_request_user_input_from_session(session_path: Path) -> dict[str, object] | None:
    """Return request_user_input payload arguments for iMessage rendering.

    Prefer the latest unanswered prompt. If everything was already answered
    by the time we read the file (race with quick UI responses), fall back to
    the most recent prompt so the user still sees what was asked.
    """
    try:
        if not session_path.exists():
            return None

        pending_args_by_call_id: dict[str, dict[str, object]] = {}
        pending_order: list[str] = []
        latest_seen_args: dict[str, object] | None = None
        with session_path.open("r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line:
                    continue

                try:
                    event = json.loads(line)
                except Exception:
                    continue

                if not isinstance(event, dict):
                    continue

                if event.get("type") != "response_item":
                    continue

                payload = event.get("payload")
                if not isinstance(payload, dict):
                    continue

                payload_type = payload.get("type")

                if payload_type == "function_call" and payload.get("name") == "request_user_input":
                    call_id_raw = payload.get("call_id")
                    call_id = call_id_raw.strip() if isinstance(call_id_raw, str) and call_id_raw.strip() else None
                    # Ignore calls without call_id; we cannot safely correlate completion.
                    if not call_id:
                        continue

                    raw_args = payload.get("arguments")
                    parsed: dict[str, object] | None = None
                    if isinstance(raw_args, dict):
                        parsed = raw_args
                    elif isinstance(raw_args, str) and raw_args.strip():
                        try:
                            candidate = json.loads(raw_args)
                            parsed = candidate if isinstance(candidate, dict) else None
                        except Exception:
                            parsed = None

                    if not parsed:
                        continue

                    pending_args_by_call_id[call_id] = parsed
                    latest_seen_args = parsed
                    if call_id in pending_order:
                        pending_order.remove(call_id)
                    pending_order.append(call_id)
                    continue

                if payload_type == "function_call_output":
                    call_id_raw = payload.get("call_id")
                    call_id = call_id_raw.strip() if isinstance(call_id_raw, str) and call_id_raw.strip() else None
                    if not call_id:
                        continue

                    pending_args_by_call_id.pop(call_id, None)
                    if call_id in pending_order:
                        pending_order.remove(call_id)
                    continue

        if not pending_order:
            return latest_seen_args
        latest_pending = pending_order[-1]
        return pending_args_by_call_id.get(latest_pending)
    except Exception:
        return None


def _format_request_user_input_for_imessage(payload: dict[str, object]) -> str | None:
    try:
        questions = payload.get("questions")
        if not isinstance(questions, list) or not questions:
            return None

        lines: list[str] = []
        for idx, q in enumerate(questions, start=1):
            if not isinstance(q, dict):
                continue
            header = q.get("header")
            header_text = header.strip() if isinstance(header, str) and header.strip() else None
            question = q.get("question")
            question_text = question.strip() if isinstance(question, str) and question.strip() else None
            title = f"{idx}) {header_text}: {question_text}" if header_text else f"{idx}) {question_text}"
            if question_text:
                lines.append(title)

            options = q.get("options")
            if not isinstance(options, list) or not options:
                continue
            opt_idx = 0
            for opt in options:
                if not isinstance(opt, dict):
                    continue
                label = opt.get("label")
                label_text = label.strip() if isinstance(label, str) and label.strip() else None
                if not label_text:
                    continue
                opt_idx += 1
                desc = opt.get("description")
                desc_text = desc.strip() if isinstance(desc, str) and desc.strip() else None
                if desc_text:
                    lines.append(f"   {opt_idx}. {label_text} — {desc_text}")
                else:
                    lines.append(f"   {opt_idx}. {label_text}")

        rendered = "\n".join(lines).strip()
        return rendered or None
    except Exception:
        return None


def _read_last_assistant_text(*, codex_home: Path) -> str | None:
    """Best-effort: find the most recently modified session file and extract last assistant text."""
    try:
        session_path_env = os.environ.get("CODEX_SESSION_PATH") or os.environ.get("CODEX_SESSION_FILE")
        if session_path_env:
            session_path = Path(session_path_env)
            if session_path.exists():
                direct = _read_last_assistant_text_from_session(session_path)
                if direct:
                    return direct

        newest = _find_newest_session_file(codex_home=codex_home)
        if not newest:
            return None

        return _read_last_assistant_text_from_session(newest)
    except Exception:
        return None


def _format_attention_message(
    *,
    cwd: str | None,
    need: str,
    session_id: str | None,
    request: str | None,
    questions: str | None = None,
) -> str:
    now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    host = platform.node() or "host"

    parts: list[str] = ["Codex needs your attention", f"Host: {host}", f"Time: {now}"]
    parts.append(f"Need: {need}")
    if session_id:
        parts.append(f"Session: {session_id}")

    if request:
        parts.append("")
        parts.append("Request:")
        parts.append(request)

    if questions:
        parts.append("")
        parts.append("Questions:")
        parts.append(questions)

    parts.append("")
    parts.append("Reply to this iMessage; Codex can apply your reply to the session.")

    return "\n".join(parts).strip()


def _chunk_text(text: str, max_len: int) -> list[str]:
    if max_len <= 0:
        return [text]
    if not text:
        return [""]

    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = min(start + max_len, len(text))
        if end >= len(text):
            chunks.append(text[start:end])
            break

        newline_index = text.rfind("\n", start, end)
        split_at = newline_index + 1 if newline_index != -1 else end
        if split_at <= start:
            split_at = end

        chunks.append(text[start:split_at])
        start = split_at

    return chunks


def _split_message(header: str, body: str, max_message_chars: int) -> list[str]:
    base = f"{header}\n{body}"
    if max_message_chars <= 0 or len(base) <= max_message_chars:
        return [base]

    part_line_reserved = "\nPart 000000/000000\n"
    if max_message_chars <= len(header) + len(part_line_reserved):
        raise ValueError("max_message_chars too small to fit header + part counter")

    max_body_chunk = max_message_chars - len(header) - len(part_line_reserved)
    chunks = _chunk_text(body, max_body_chunk)
    if not chunks:
        return [base]

    n = len(chunks)
    messages = [f"{header}\nPart {i}/{n}\n{chunk}" for i, chunk in enumerate(chunks, start=1)]

    for message in messages:
        if len(message) > max_message_chars:
            raise RuntimeError("Internal error: split message exceeds max_message_chars")

    return messages


def _split_for_imessage(message: str, *, max_message_chars: int) -> list[str]:
    if max_message_chars <= 0 or len(message) <= max_message_chars:
        return [message]

    first_nl = message.find("\n")
    if first_nl == -1:
        # No good header; just chunk the whole message.
        return _chunk_text(message, max_message_chars)

    header = message[:first_nl]
    body = message[first_nl + 1 :]
    return _split_message(header, body, max_message_chars)


def _send_imessage(*, recipient: str, message: str) -> bool:
    script_path = Path(__file__).resolve().parent / "scripts" / "send-imessage.applescript"
    if not script_path.exists():
        return False

    try:
        proc = subprocess.run(
            ["osascript", str(script_path), recipient, message],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return proc.returncode == 0
    except Exception:
        return False


def _enqueue_fallback(*, queue_path: Path, recipient: str, message: str) -> None:
    try:
        queue_path.parent.mkdir(parents=True, exist_ok=True)
        record = {"ts": int(time.time()), "to": recipient, "text": message}
        with queue_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False))
            f.write("\n")
    except Exception:
        # Best-effort only.
        return


def _read_json_dict(path: Path) -> dict[str, object] | None:
    try:
        if not path.exists():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _write_json_atomic(path: Path, data: dict[str, object]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_suffix(path.suffix + ".tmp")
        tmp_path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        tmp_path.replace(path)
    except Exception:
        return


def _attention_index_path(*, codex_home: Path) -> Path:
    return Path(
        os.environ.get(
            "CODEX_IMESSAGE_ATTENTION_INDEX",
            str(codex_home / "tmp" / "imessage_attention_index.json"),
        )
    )


def _prune_attention_index(index: dict[str, object], *, now_ts: int) -> dict[str, object]:
    pruned: dict[str, object] = {}
    cutoff = now_ts - _ATTENTION_INDEX_MAX_AGE_S

    for sid, record in index.items():
        if not isinstance(record, dict):
            continue
        ts = record.get("ts")
        if not (isinstance(ts, int) and ts > 0):
            continue
        if ts < cutoff:
            continue
        pruned[sid] = record

    if len(pruned) <= _ATTENTION_INDEX_MAX_ENTRIES:
        return pruned

    # Keep newest N by ts.
    def _ts(item: tuple[str, object]) -> int:
        _, rec = item
        if isinstance(rec, dict):
            ts = rec.get("ts")
            return int(ts) if isinstance(ts, int) else 0
        return 0

    items = sorted(pruned.items(), key=_ts, reverse=True)[:_ATTENTION_INDEX_MAX_ENTRIES]
    return dict(items)


def _upsert_attention_index(
    *,
    codex_home: Path,
    session_id: str | None,
    record: dict[str, object],
) -> None:
    if not (isinstance(session_id, str) and session_id.strip()):
        return

    path = _attention_index_path(codex_home=codex_home)
    index = _read_json_dict(path) or {}
    index[session_id.strip()] = record
    index = _prune_attention_index(index, now_ts=int(record.get("ts") or time.time()))
    _write_json_atomic(path, index)


def _write_last_attention_state(
    *,
    codex_home: Path,
    recipient: str,
    session_id: str | None,
    cwd: str | None,
    session_path: str | None,
    tmux_pane: str | None,
    tmux_socket: str | None,
) -> None:
    try:
        state_path = Path(
            os.environ.get(
                "CODEX_IMESSAGE_LAST_ATTENTION",
                str(codex_home / "tmp" / "imessage_last_attention.json"),
            )
        )
        state_path.parent.mkdir(parents=True, exist_ok=True)

        record = {
            "ts": int(time.time()),
            "to": recipient,
            "session_id": session_id,
            "cwd": cwd,
            "session_path": session_path,
            "tmux_pane": tmux_pane,
            "tmux_socket": tmux_socket,
        }

        tmp_path = state_path.with_suffix(state_path.suffix + ".tmp")
        tmp_path.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
        tmp_path.replace(state_path)

        # Also keep a per-session index so replies can be routed to the correct tmux pane.
        _upsert_attention_index(codex_home=codex_home, session_id=session_id, record=record)
    except Exception:
        # Best-effort only.
        return


def _is_state_only_notify_mode() -> bool:
    mode = os.environ.get("CODEX_IMESSAGE_NOTIFY_MODE", "send").strip().lower()
    return mode in {"state_only", "state-only", "metadata_only", "metadata-only", "meta"}


def _is_route_notify_mode() -> bool:
    return os.environ.get("CODEX_IMESSAGE_NOTIFY_MODE", "send").strip().lower() == "route"


def _env_bool(name: str, *, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip() not in {"0", "false", "False", "off", "OFF", ""}


def _max_message_chars() -> int:
    value = os.environ.get("CODEX_IMESSAGE_MAX_LEN", "").strip()
    if not value:
        return 1800
    try:
        parsed = int(value)
        return parsed if parsed > 0 else 1800
    except Exception:
        return 1800


def _extract_notify_payload(unknown: list[str]) -> dict[str, object] | None:
    for extra in unknown:
        if not isinstance(extra, str):
            continue
        candidate = extra.strip()
        if not (candidate.startswith("{") and candidate.endswith("}")):
            continue
        try:
            parsed = json.loads(candidate)
        except Exception:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _payload_blob(payload: dict[str, object] | None) -> str:
    if not isinstance(payload, dict):
        return ""
    try:
        return json.dumps(payload, ensure_ascii=False, sort_keys=True)
    except Exception:
        return ""


def _payload_event_type(payload: dict[str, object] | None) -> str | None:
    if not isinstance(payload, dict):
        return None
    for key in (
        "type",
        "event",
        "kind",
        "event_type",
        "event-type",
        "name",
        "method",
        "hook_event_name",
        "hook-event-name",
        "hookEventName",
    ):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    nested = payload.get("params")
    if isinstance(nested, dict):
        for key in (
            "type",
            "event",
            "kind",
            "event_type",
            "event-type",
            "name",
            "method",
            "hook_event_name",
            "hook-event-name",
            "hookEventName",
        ):
            value = nested.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip().lower()
    return None


def _is_completion_event(payload: dict[str, object] | None) -> bool:
    event_type = _payload_event_type(payload)
    if event_type in {
        "agent-turn-complete",
        "agent_turn_complete",
        "turn.completed",
        "turn/completed",
        "turn-complete",
        "turn_complete",
        "task-complete",
        "task_complete",
        "stop",
    }:
        return True
    blob = _payload_blob(payload).lower()
    if not blob:
        return False
    return "agent-turn-complete" in blob or "turn.completed" in blob or "turn/completed" in blob


def _is_input_event(payload: dict[str, object] | None) -> bool:
    if payload is None:
        return False

    event_type = _payload_event_type(payload)
    if event_type in {
        "needs_input",
        "needs-input",
        "need_input",
        "need-input",
        "request_user_input",
        "request-user-input",
        "exec_approval_request",
        "exec-approval-request",
        "apply_patch_approval_request",
        "apply-patch-approval-request",
        "elicitation_request",
        "elicitation-request",
        "approval_required",
        "approval-required",
    }:
        return True

    blob = _payload_blob(payload).lower()
    if not blob:
        return False
    hints = (
        "request_user_input",
        "needs_input",
        "needs-input",
        "exec_approval_request",
        "apply_patch_approval_request",
        "approval",
        "question",
        "ask_for_approval",
        "implement this plan?",
    )
    return any(hint in blob for hint in hints)


def _extract_call_id(payload: dict[str, object] | None) -> str | None:
    if not isinstance(payload, dict):
        return None
    for key in ("call_id", "call-id", "callId"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    for nested_key in ("payload", "params"):
        nested = payload.get(nested_key)
        if isinstance(nested, dict):
            for key in ("call_id", "call-id", "callId"):
                value = nested.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
    return None


def _send_structured(
    *,
    recipient: str,
    session_id: str | None,
    kind: str,
    text: str,
    max_message_chars: int,
    dry_run: bool,
    queue_path: Path,
) -> None:
    sid = session_id or "unknown"
    header = f"[Codex] {sid} — {kind} — {_dt.datetime.now().astimezone().replace(microsecond=0).isoformat()}"
    body = text.rstrip() + "\n"
    try:
        messages = _split_message(header, body, max_message_chars=max_message_chars)
    except Exception:
        messages = [f"{header}\n{body}"]

    for message in messages:
        if dry_run:
            sys.stdout.write(message)
            sys.stdout.write("\n---\n")
            continue
        ok = _send_imessage(recipient=recipient, message=message)
        if not ok:
            _enqueue_fallback(queue_path=queue_path, recipient=recipient, message=message)


def _send_routed_needs_input(
    *,
    codex_home: Path,
    recipient: str,
    session_id: str | None,
    scope: str,
    call_id: str | None,
    prompt_text: str,
    dedupe_text: str,
    max_message_chars: int,
    dry_run: bool,
    queue_path: Path,
) -> None:
    if call_id:
        call_key = codex_imessage_dedupe.build_dedupe_key(
            category="needs_input_call_id",
            scope=scope,
            text=call_id,
        )
        if not codex_imessage_dedupe.mark_once(codex_home=codex_home, key=call_key):
            return

    semantic_key = codex_imessage_dedupe.build_dedupe_key(
        category="needs_input",
        scope=scope,
        text=dedupe_text,
    )
    if not codex_imessage_dedupe.mark_once(codex_home=codex_home, key=semantic_key):
        return

    _send_structured(
        recipient=recipient,
        session_id=session_id,
        kind="needs_input",
        text=prompt_text,
        max_message_chars=max_message_chars,
        dry_run=dry_run,
        queue_path=queue_path,
    )


def _send_routed_final_status(
    *,
    codex_home: Path,
    recipient: str,
    session_id: str | None,
    scope: str,
    payload: dict[str, object] | None,
    response_text: str | None,
    cwd: str | None,
    max_message_chars: int,
    dry_run: bool,
    queue_path: Path,
) -> None:
    payload_fingerprint = _payload_blob(payload) or "completion"
    final_key = codex_imessage_dedupe.build_dedupe_key(
        category="final_status",
        scope=scope,
        text=payload_fingerprint,
    )
    if not codex_imessage_dedupe.mark_once(
        codex_home=codex_home,
        key=final_key,
        ttl_seconds=_FINAL_STATUS_DEDUPE_TTL_SECONDS,
    ):
        return

    text = response_text.strip() if isinstance(response_text, str) and response_text.strip() else "Turn completed."

    _send_structured(
        recipient=recipient,
        session_id=session_id,
        kind="responded",
        text=text,
        max_message_chars=max_message_chars,
        dry_run=dry_run,
        queue_path=queue_path,
    )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(add_help=True)
    sub = parser.add_subparsers(dest="kind", required=True)

    attention = sub.add_parser("attention", help="Send a 'needs attention' iMessage")
    attention.add_argument("--cwd", default=None)
    attention.add_argument("--need", default="Waiting on approval / question / input.")
    attention.add_argument("--to", default=None)
    attention.add_argument("--dry-run", action="store_true")

    route = sub.add_parser("route", help="Route notify payload into input/final iMessage behavior")
    route.add_argument("--cwd", default=None)
    route.add_argument("--need", default="Waiting on approval / question / input.")
    route.add_argument("--to", default=None)
    route.add_argument("--dry-run", action="store_true")

    args, unknown = parser.parse_known_args(argv)
    notify_payload = _extract_notify_payload(unknown)

    if args.kind not in {"attention", "route"}:
        return 0

    recipient_raw = args.to or os.environ.get("CODEX_IMESSAGE_TO")
    if not recipient_raw:
        return 0
    recipient = _normalize_recipient(recipient_raw)

    codex_home = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex")))
    history_path = Path(os.environ.get("CODEX_HISTORY_PATH", str(codex_home / "history.jsonl")))
    assistant_response = _read_last_assistant_text(codex_home=codex_home)
    request = assistant_response
    if not request:
        request = _read_last_user_text(history_path)

    meta = _read_latest_session_meta(codex_home=codex_home)
    session_id: str | None = None
    cwd_full: str | None = None
    if isinstance(notify_payload, dict):
        thread_id = notify_payload.get("thread-id") or notify_payload.get("thread_id") or notify_payload.get("threadId")
        if isinstance(thread_id, str) and thread_id.strip():
            session_id = thread_id.strip()
        notify_cwd = notify_payload.get("cwd")
        if isinstance(notify_cwd, str) and notify_cwd.strip():
            cwd_full = notify_cwd.strip()
        params = notify_payload.get("params")
        if isinstance(params, dict):
            if not session_id:
                nested_thread_id = params.get("thread-id") or params.get("thread_id") or params.get("threadId")
                if isinstance(nested_thread_id, str) and nested_thread_id.strip():
                    session_id = nested_thread_id.strip()
            if not cwd_full:
                nested_cwd = params.get("cwd")
                if isinstance(nested_cwd, str) and nested_cwd.strip():
                    cwd_full = nested_cwd.strip()
    if isinstance(meta, dict):
        if not session_id:
            meta_id = meta.get("id")
            if isinstance(meta_id, str) and meta_id.strip():
                session_id = meta_id.strip()
        if not cwd_full:
            meta_cwd = meta.get("cwd")
            if isinstance(meta_cwd, str) and meta_cwd.strip():
                cwd_full = meta_cwd.strip()
    if not cwd_full:
        try:
            cwd_full = str(Path.cwd())
        except Exception:
            cwd_full = None

    # Best-effort session path: used by the control plane to correlate inbound replies
    # to the active session state and latest prompt context.
    session_path: str | None = None
    session_path_env = os.environ.get("CODEX_SESSION_PATH") or os.environ.get("CODEX_SESSION_FILE")
    if session_path_env:
        try:
            candidate = Path(session_path_env)
            if candidate.exists():
                session_path = str(candidate)
        except Exception:
            session_path = None
    if not session_path:
        newest = _find_newest_session_file(codex_home=codex_home)
        if newest:
            session_path = str(newest)

    tmux_pane = os.environ.get("TMUX_PANE")
    tmux_socket = _tmux_socket_from_env()

    _write_last_attention_state(
        codex_home=codex_home,
        recipient=recipient,
        session_id=session_id,
        cwd=cwd_full,
        session_path=session_path,
        tmux_pane=tmux_pane,
        tmux_socket=tmux_socket,
    )

    if _is_state_only_notify_mode():
        return 0

    max_len = _max_message_chars()
    queue_path = Path(
        os.environ.get(
            "CODEX_IMESSAGE_QUEUE",
            str(codex_home / "tmp" / "imessage_queue.jsonl"),
        )
    )

    is_route = args.kind == "route" or _is_route_notify_mode()
    if is_route:
        scope = session_id or cwd_full or "unknown"
        call_id = _extract_call_id(notify_payload)

        if _env_bool("CODEX_IMESSAGE_FINAL_STATUS_ENABLED", default=True) and _is_completion_event(notify_payload):
            _send_routed_final_status(
                codex_home=codex_home,
                recipient=recipient,
                session_id=session_id,
                scope=scope,
                payload=notify_payload,
                response_text=assistant_response,
                cwd=args.cwd or cwd_full,
                max_message_chars=max_len,
                dry_run=args.dry_run,
                queue_path=queue_path,
            )
            return 0

        if not _is_input_event(notify_payload):
            return 0

        questions_text: str | None = None
        if session_path:
            parsed_questions = _read_last_request_user_input_from_session(Path(session_path))
            if parsed_questions:
                questions_text = _format_request_user_input_for_imessage(parsed_questions)

        if not questions_text and not _env_bool("CODEX_IMESSAGE_NOTIFY_FALLBACK_INPUT", default=True):
            return 0

        prompt_text = questions_text or args.need
        dedupe_text = prompt_text if questions_text else f"{args.need}\n{_payload_blob(notify_payload) or 'fallback'}"
        _send_routed_needs_input(
            codex_home=codex_home,
            recipient=recipient,
            session_id=session_id,
            scope=scope,
            call_id=call_id,
            prompt_text=prompt_text,
            dedupe_text=dedupe_text,
            max_message_chars=max_len,
            dry_run=args.dry_run,
            queue_path=queue_path,
        )
        return 0

    # Legacy attention mode.
    questions_text: str | None = None
    if session_path:
        parsed_questions = _read_last_request_user_input_from_session(Path(session_path))
        if parsed_questions:
            questions_text = _format_request_user_input_for_imessage(parsed_questions)

    message = _format_attention_message(
        cwd=args.cwd,
        need=args.need,
        session_id=session_id,
        request=request,
        questions=questions_text,
    )

    parts = _split_for_imessage(message, max_message_chars=max_len)

    if args.dry_run:
        sys.stdout.write(f"TO: {recipient}\n\n")
        for idx, part in enumerate(parts):
            if idx:
                sys.stdout.write("\n---\n")
            sys.stdout.write(part)
            sys.stdout.write("\n")
        return 0

    for part in parts:
        ok = _send_imessage(recipient=recipient, message=part)
        if not ok:
            _enqueue_fallback(queue_path=queue_path, recipient=recipient, message=part)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except SystemExit:
        raise
    except Exception:
        # Never fail the caller.
        raise SystemExit(0)
