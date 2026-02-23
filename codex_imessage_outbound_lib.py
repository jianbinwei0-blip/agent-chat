#!/usr/bin/env python3
"""Codex session → iMessage outbound mirror (macOS).

Tails the active Codex session JSONL and sends iMessages for:
  - user messages
  - assistant messages
  - Plan Mode questions (request_user_input)

This is best-effort and must never fail the calling process.

Usage:
  python3 codex_imessage_outbound_lib.py run [--poll 0.5] [--dry-run] [--session-path PATH]
  python3 codex_imessage_outbound_lib.py once [--dry-run] [--session-path PATH]

Config:
  - CODEX_IMESSAGE_TO: recipient phone/email
  - CODEX_HOME: defaults to ~/.codex
  - CODEX_SESSION_PATH / CODEX_SESSION_FILE: optional explicit session file
  - CODEX_IMESSAGE_MIRROR_ROLES: comma-separated roles to mirror; default user,assistant
    (example: assistant)
  - CODEX_IMESSAGE_ONLY_NEEDS_INPUT: when set (default: 1), notify only when Codex
    requests user input/approval via request_user_input. Set to 0 to restore full mirroring.
  - CODEX_IMESSAGE_QUEUE: fallback queue path (JSONL); defaults to $CODEX_HOME/tmp/imessage_queue.jsonl
  - CODEX_IMESSAGE_OUTBOUND_CURSOR: cursor JSON path; defaults to $CODEX_HOME/tmp/imessage_outbound_cursor.json
  - CODEX_IMESSAGE_OUTBOUND_BRIDGE_LOCK: lock path; defaults to $CODEX_HOME/tmp/imessage_outbound_bridge.lock
  - CODEX_IMESSAGE_DEDUPE_INDEX: shared dedupe index path (JSON)
  - CODEX_IMESSAGE_DEDUPE_TTL_S: dedupe TTL seconds (default: 86400)
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import errno
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

import codex_imessage_dedupe


_MAX_MESSAGE_CHARS_DEFAULT = 1800
_SESSION_SCAN_INTERVAL_S = 2.0
_VALID_MESSAGE_ROLES = frozenset({"user", "assistant"})
_MAX_SEEN_NEEDS_INPUT_CALL_IDS = 512
_SEEN_NEEDS_INPUT_MAX_AGE_S = 7 * 24 * 60 * 60
_ATTENTION_INDEX_MAX_ENTRIES = 100
_ATTENTION_INDEX_MAX_AGE_S = 7 * 24 * 60 * 60


def _now_local_iso() -> str:
    return dt.datetime.now().astimezone().replace(microsecond=0).isoformat()


def _normalize_recipient(recipient: str) -> str:
    candidate = recipient.strip()
    if "@" in candidate:
        return candidate

    digits = "".join(ch for ch in candidate if ch.isdigit())
    if not digits:
        return candidate

    if candidate.startswith("+"):
        return f"+{digits}"

    if len(digits) == 10:
        return f"+1{digits}"

    if len(digits) == 11 and digits.startswith("1"):
        return f"+{digits}"

    return candidate


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


def _load_json(path: Path) -> dict[str, object] | None:
    try:
        if not path.exists():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _write_json(path: Path, data: dict[str, object]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_suffix(path.suffix + ".tmp")
        tmp_path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        tmp_path.replace(path)
    except Exception:
        return


def _acquire_single_instance_lock(*, codex_home: Path) -> object | None:
    lock_path = Path(
        os.environ.get(
            "CODEX_IMESSAGE_OUTBOUND_BRIDGE_LOCK",
            str(codex_home / "tmp" / "imessage_outbound_bridge.lock"),
        )
    )
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        f = lock_path.open("a", encoding="utf-8")
    except Exception:
        return object()

    try:
        import fcntl  # macOS/Unix only
    except Exception:
        try:
            f.close()
        except Exception:
            pass
        return object()

    try:
        try:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            if e.errno in {errno.EACCES, errno.EAGAIN}:
                f.close()
                return None
            raise

        try:
            f.seek(0)
            f.truncate()
            f.write(str(os.getpid()))
            f.flush()
        except Exception:
            pass

        return f
    except Exception:
        try:
            f.close()
        except Exception:
            pass
        return object()


def _read_session_id(*, session_path: Path) -> str | None:
    try:
        if not session_path.exists():
            return None
        with session_path.open("r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
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
                if not isinstance(payload, dict):
                    return None
                sid = payload.get("id")
                return sid.strip() if isinstance(sid, str) and sid.strip() else None
        return None
    except Exception:
        return None


def _read_session_cwd(*, session_path: Path) -> str | None:
    try:
        if not session_path.exists():
            return None
        with session_path.open("r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
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
                if not isinstance(payload, dict):
                    return None
                cwd = payload.get("cwd")
                return cwd.strip() if isinstance(cwd, str) and cwd.strip() else None
        return None
    except Exception:
        return None


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

    def _ts(item: tuple[str, object]) -> int:
        _, rec = item
        if not isinstance(rec, dict):
            return 0
        ts = rec.get("ts")
        return int(ts) if isinstance(ts, int) else 0

    newest = sorted(pruned.items(), key=_ts, reverse=True)[:_ATTENTION_INDEX_MAX_ENTRIES]
    return dict(newest)


def _upsert_attention_index(
    *,
    codex_home: Path,
    session_id: str | None,
    record: dict[str, object],
) -> None:
    if not (isinstance(session_id, str) and session_id.strip()):
        return
    path = _attention_index_path(codex_home=codex_home)
    index = _load_json(path) or {}
    index[session_id.strip()] = record
    index = _prune_attention_index(index, now_ts=int(record.get("ts") or time.time()))
    _write_json(path, index)


def _write_last_attention_state(
    *,
    codex_home: Path,
    recipient: str,
    session_id: str | None,
    cwd: str | None,
    session_path: str | None,
    tmux_pane: str | None,
) -> None:
    try:
        state_path = Path(
            os.environ.get(
                "CODEX_IMESSAGE_LAST_ATTENTION",
                str(codex_home / "tmp" / "imessage_last_attention.json"),
            )
        )
        record = {
            "ts": int(time.time()),
            "to": recipient,
            "session_id": session_id,
            "cwd": cwd,
            "session_path": session_path,
            "tmux_pane": tmux_pane,
        }
        _write_json(state_path, record)
        _upsert_attention_index(codex_home=codex_home, session_id=session_id, record=record)
    except Exception:
        return


def _parse_mirror_roles(raw: str | None) -> set[str]:
    if raw is None:
        return set(_VALID_MESSAGE_ROLES)

    value = raw.strip()
    if not value:
        return set(_VALID_MESSAGE_ROLES)

    tokens = [tok.strip().lower() for tok in re.split(r"[\s,]+", value) if tok.strip()]
    if not tokens:
        return set(_VALID_MESSAGE_ROLES)

    if "all" in tokens or "*" in tokens:
        return set(_VALID_MESSAGE_ROLES)
    if "none" in tokens:
        return set()

    roles = {tok for tok in tokens if tok in _VALID_MESSAGE_ROLES}
    if roles:
        return roles

    return set(_VALID_MESSAGE_ROLES)


def _extract_message_text_from_payload(payload: dict[str, object]) -> tuple[str, str] | None:
    if payload.get("type") != "message":
        return None

    role = payload.get("role")
    if not isinstance(role, str) or role not in {"user", "assistant"}:
        return None

    content = payload.get("content")
    if not isinstance(content, list):
        return None

    chunks: list[str] = []
    wanted_type = "input_text" if role == "user" else "output_text"
    for item in content:
        if not isinstance(item, dict):
            continue
        if item.get("type") != wanted_type:
            continue
        text = item.get("text")
        if isinstance(text, str) and text:
            chunks.append(text)

    if not chunks:
        return None
    return role, "".join(chunks)


def _parse_request_user_input_arguments(raw_args: object) -> dict[str, object] | None:
    if isinstance(raw_args, dict):
        return raw_args
    if isinstance(raw_args, str) and raw_args.strip():
        try:
            parsed = json.loads(raw_args)
        except Exception:
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def _normalize_request_user_input_questions(args: dict[str, object]) -> list[dict[str, object]]:
    raw_questions = args.get("questions")
    if not isinstance(raw_questions, list):
        return []

    normalized: list[dict[str, object]] = []
    for q in raw_questions:
        if not isinstance(q, dict):
            continue

        question = q.get("question")
        question_text = question.strip() if isinstance(question, str) and question.strip() else None
        if not question_text:
            continue

        rec: dict[str, object] = {"question": question_text}

        qid = q.get("id")
        if isinstance(qid, str) and qid.strip():
            rec["id"] = qid.strip()

        header = q.get("header")
        if isinstance(header, str) and header.strip():
            rec["header"] = header.strip()

        raw_options = q.get("options")
        options_out: list[dict[str, object]] = []
        if isinstance(raw_options, list):
            for opt in raw_options:
                if not isinstance(opt, dict):
                    continue
                label = opt.get("label")
                label_text = label.strip() if isinstance(label, str) and label.strip() else None
                if not label_text:
                    continue

                option_rec: dict[str, object] = {"label": label_text}
                desc = opt.get("description")
                if isinstance(desc, str) and desc.strip():
                    option_rec["description"] = desc.strip()
                options_out.append(option_rec)

        if options_out:
            rec["options"] = options_out

        normalized.append(rec)

    return normalized


def _render_request_user_input_questions(questions: list[dict[str, object]]) -> str | None:
    lines: list[str] = []
    for idx, q in enumerate(questions, start=1):
        if not isinstance(q, dict):
            continue

        question = q.get("question")
        question_text = question.strip() if isinstance(question, str) and question.strip() else None
        if not question_text:
            continue

        header = q.get("header")
        header_text = header.strip() if isinstance(header, str) and header.strip() else None
        if header_text:
            lines.append(f"{idx}) {header_text}: {question_text}")
        else:
            lines.append(f"{idx}) {question_text}")

        raw_options = q.get("options")
        if not isinstance(raw_options, list) or not raw_options:
            continue

        opt_idx = 0
        for opt in raw_options:
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


def _extract_request_user_input_payload(payload: dict[str, object]) -> dict[str, object] | None:
    if payload.get("type") != "function_call" or payload.get("name") != "request_user_input":
        return None

    args = _parse_request_user_input_arguments(payload.get("arguments"))
    if not args:
        return None

    questions = _normalize_request_user_input_questions(args)
    if not questions:
        return None
    return {"questions": questions}


def _extract_request_user_input_text(payload: dict[str, object]) -> str | None:
    parsed = _extract_request_user_input_payload(payload)
    if not isinstance(parsed, dict):
        return None
    questions = parsed.get("questions")
    if not isinstance(questions, list) or not questions:
        return None
    return _render_request_user_input_questions(questions)


def _parse_json_maybe(value: object) -> object | None:
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str) and value.strip():
        try:
            return json.loads(value)
        except Exception:
            return None
    return None


def _format_tool_call_args(args: object | None) -> str | None:
    if args is None:
        return None
    if isinstance(args, str) and args.strip():
        return args.strip()
    if isinstance(args, (dict, list)):
        try:
            return json.dumps(args, ensure_ascii=False, indent=2, sort_keys=True)
        except Exception:
            return str(args)
    try:
        return str(args)
    except Exception:
        return None


def _extract_tool_call(payload: dict[str, object]) -> tuple[str, str] | None:
    if payload.get("type") != "function_call":
        return None

    name = payload.get("name")
    if not isinstance(name, str) or not name.strip():
        return None

    if name == "request_user_input":
        question_text = _extract_request_user_input_text(payload)
        if not question_text:
            return None
        return "needs_input", question_text

    args_raw = payload.get("arguments")
    parsed = _parse_json_maybe(args_raw)
    rendered = _format_tool_call_args(parsed if parsed is not None else args_raw)

    if rendered:
        return f"tool_call:{name.strip()}", f"ToolCall: {name.strip()}\n{rendered}"
    return f"tool_call:{name.strip()}", f"ToolCall: {name.strip()}"


def _extract_tool_result(
    payload: dict[str, object],
    *,
    call_id_to_name: dict[str, str],
) -> tuple[str, str] | None:
    if payload.get("type") != "function_call_output":
        return None

    output = payload.get("output")
    if not isinstance(output, str) or not output.strip():
        return None

    call_id = payload.get("call_id")
    tool_name: str | None = None
    if isinstance(call_id, str) and call_id.strip():
        tool_name = call_id_to_name.get(call_id.strip())

    if tool_name:
        header = f"ToolResult: {tool_name}"
        kind = f"tool_result:{tool_name}"
    else:
        header = "ToolResult"
        kind = "tool_result"

    if isinstance(call_id, str) and call_id.strip():
        body = f"call_id: {call_id.strip()}\n{output.strip()}"
    else:
        body = output.strip()

    return kind, f"{header}\n{body}"


_REDACTIONS = [
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), "sk-<REDACTED>"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "<AWS_ACCESS_KEY_ID_REDACTED>"),
    (re.compile(r"\bASIA[0-9A-Z]{16}\b"), "<AWS_ACCESS_KEY_ID_REDACTED>"),
    (re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"), "ghp_<REDACTED>"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "github_pat_<REDACTED>"),
    (re.compile(r"\bntn_[A-Za-z0-9]{10,}\b"), "ntn_<REDACTED>"),
    (re.compile(r"\bgd_[A-Za-z0-9_-]{10,}\b"), "gd_<REDACTED>"),
]

_JWT_CANDIDATE_RE = re.compile(r"\b[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b")


def _is_jwt_like(token: str) -> bool:
    parts = token.split(".")
    if len(parts) != 3:
        return False

    header_b64 = parts[0]
    pad_len = (-len(header_b64)) % 4
    try:
        decoded = base64.urlsafe_b64decode(header_b64 + ("=" * pad_len))
    except Exception:
        return False

    try:
        header = json.loads(decoded.decode("utf-8"))
    except Exception:
        return False

    if not isinstance(header, dict):
        return False

    # JWT headers usually include alg and often typ.
    alg = header.get("alg")
    if not isinstance(alg, str) or not alg.strip():
        return False

    typ = header.get("typ")
    if typ is None:
        return True
    return isinstance(typ, str) and typ.strip().lower() == "jwt"


def _redact(text: str) -> str:
    if os.environ.get("CODEX_IMESSAGE_REDACT", "1").strip() in {"0", "false", "False"}:
        return text

    out = text
    for pattern, replacement in _REDACTIONS:
        out = pattern.sub(replacement, out)
    out = _JWT_CANDIDATE_RE.sub(lambda m: "<JWT_REDACTED>" if _is_jwt_like(m.group(0)) else m.group(0), out)
    return out


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
        return


def _cursor_path(*, codex_home: Path) -> Path:
    return Path(
        os.environ.get(
            "CODEX_IMESSAGE_OUTBOUND_CURSOR",
            str(codex_home / "tmp" / "imessage_outbound_cursor.json"),
        )
    )


def _prune_seen_needs_input_call_ids(raw: object, *, now_ts: int | None = None) -> dict[str, int]:
    now = now_ts if isinstance(now_ts, int) and now_ts > 0 else int(time.time())
    cutoff = now - _SEEN_NEEDS_INPUT_MAX_AGE_S
    pruned: dict[str, int] = {}

    if isinstance(raw, dict):
        items = raw.items()
    elif isinstance(raw, list):
        # Backward-compat for any previous list shape.
        items = ((v, now) for v in raw)
    else:
        items = ()

    for key, value in items:
        if not isinstance(key, str):
            continue
        key_text = key.strip()
        if not key_text:
            continue
        ts = int(value) if isinstance(value, int) else now
        if ts < cutoff:
            continue
        pruned[key_text] = ts

    if len(pruned) <= _MAX_SEEN_NEEDS_INPUT_CALL_IDS:
        return pruned

    # Keep newest ids by timestamp.
    newest = sorted(pruned.items(), key=lambda item: item[1], reverse=True)[:_MAX_SEEN_NEEDS_INPUT_CALL_IDS]
    return dict(newest)


def _load_cursor(*, cursor_path: Path) -> tuple[str | None, int, dict[str, int]]:
    data = _load_json(cursor_path) or {}
    session_path = data.get("session_path")
    offset = data.get("offset")
    seen_raw = data.get("seen_needs_input_call_ids")
    session_path_str = session_path if isinstance(session_path, str) and session_path else None
    offset_int = int(offset) if isinstance(offset, int) else 0
    seen_needs_input_call_ids = _prune_seen_needs_input_call_ids(seen_raw, now_ts=int(time.time()))
    return session_path_str, offset_int, seen_needs_input_call_ids


def _save_cursor(
    *,
    cursor_path: Path,
    session_path: Path,
    offset: int,
    seen_needs_input_call_ids: dict[str, int],
) -> None:
    seen_pruned = _prune_seen_needs_input_call_ids(seen_needs_input_call_ids, now_ts=int(time.time()))
    _write_json(
        cursor_path,
        {
            "session_path": str(session_path),
            "offset": int(offset),
            "seen_needs_input_call_ids": seen_pruned,
            "ts": int(time.time()),
        },
    )


def _resolve_session_path(*, codex_home: Path, explicit: str | None) -> Path | None:
    if explicit:
        candidate = Path(explicit)
        return candidate if candidate.exists() else None

    env_path = os.environ.get("CODEX_SESSION_PATH") or os.environ.get("CODEX_SESSION_FILE")
    if env_path:
        candidate = Path(env_path)
        return candidate if candidate.exists() else None

    return _find_newest_session_file(codex_home=codex_home)


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
    header = f"[Codex] {sid} — {kind} — {_now_local_iso()}"
    body = _redact(text.rstrip()) + "\n"
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


def _process_session_path(
    *,
    codex_home: Path,
    session_path: Path,
    offset: int,
    recipient: str,
    mirror_roles: set[str],
    max_message_chars: int,
    dry_run: bool,
    queue_path: Path,
    session_id_cache: dict[str, str | None],
    call_id_to_name: dict[str, str],
    seen_needs_input_call_ids: dict[str, int],
) -> int:
    try:
        size = session_path.stat().st_size
    except Exception:
        return offset

    if offset < 0 or offset > size:
        offset = size

    # Ensure we have a session id cached for this path.
    cache_key = str(session_path)
    if cache_key not in session_id_cache:
        session_id_cache[cache_key] = _read_session_id(session_path=session_path)

    session_id = session_id_cache.get(cache_key)
    session_cwd = _read_session_cwd(session_path=session_path)

    needs_input_only = os.environ.get("CODEX_IMESSAGE_ONLY_NEEDS_INPUT", "1").strip() not in {
        "0",
        "false",
        "False",
    }

    mirror_tools = os.environ.get("CODEX_IMESSAGE_MIRROR_TOOLS", "1").strip() not in {"0", "false", "False"}

    try:
        with session_path.open("r", encoding="utf-8") as f:
            f.seek(offset)
            while True:
                raw = f.readline()
                if not raw:
                    break
                offset = f.tell()
                line = raw.strip()
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

                extracted = _extract_message_text_from_payload(payload)
                if extracted:
                    role, text = extracted
                    if needs_input_only:
                        continue
                    if role not in mirror_roles:
                        continue
                    _send_structured(
                        recipient=recipient,
                        session_id=session_id,
                        kind=role,
                        text=text,
                        max_message_chars=max_message_chars,
                        dry_run=dry_run,
                        queue_path=queue_path,
                    )
                    continue

                tool_call = _extract_tool_call(payload)
                if tool_call:
                    kind, text = tool_call

                    if kind != "needs_input":
                        if needs_input_only or not mirror_tools:
                            continue
                        call_id = payload.get("call_id")
                        name = payload.get("name")
                        if isinstance(call_id, str) and isinstance(name, str) and call_id.strip() and name.strip():
                            call_id_to_name[call_id.strip()] = name.strip()
                    else:
                        call_id_raw = payload.get("call_id")
                        call_id = call_id_raw.strip() if isinstance(call_id_raw, str) and call_id_raw.strip() else None
                        session_scope = (
                            session_id.strip()
                            if isinstance(session_id, str) and session_id.strip()
                            else cache_key
                        )
                        if call_id:
                            dedupe_key = f"{cache_key}:{call_id}"
                            if dedupe_key in seen_needs_input_call_ids:
                                continue
                            call_key = codex_imessage_dedupe.build_dedupe_key(
                                category="needs_input_call_id",
                                scope=session_scope,
                                text=call_id,
                            )
                            if not codex_imessage_dedupe.mark_once(codex_home=codex_home, key=call_key):
                                continue
                        semantic_key = codex_imessage_dedupe.build_dedupe_key(
                            category="needs_input",
                            scope=session_scope,
                            text=text,
                        )
                        if not codex_imessage_dedupe.mark_once(codex_home=codex_home, key=semantic_key):
                            continue

                    _send_structured(
                        recipient=recipient,
                        session_id=session_id,
                        kind=kind,
                        text=text,
                        max_message_chars=max_message_chars,
                        dry_run=dry_run,
                        queue_path=queue_path,
                    )
                    if kind == "needs_input":
                        _write_last_attention_state(
                            codex_home=codex_home,
                            recipient=recipient,
                            session_id=session_id,
                            cwd=session_cwd,
                            session_path=str(session_path),
                            tmux_pane=os.environ.get("TMUX_PANE"),
                        )
                        call_id_raw = payload.get("call_id")
                        call_id = call_id_raw.strip() if isinstance(call_id_raw, str) and call_id_raw.strip() else None
                        if call_id:
                            seen_needs_input_call_ids[f"{cache_key}:{call_id}"] = int(time.time())
                            if len(seen_needs_input_call_ids) > (_MAX_SEEN_NEEDS_INPUT_CALL_IDS * 2):
                                pruned = _prune_seen_needs_input_call_ids(
                                    seen_needs_input_call_ids,
                                    now_ts=int(time.time()),
                                )
                                seen_needs_input_call_ids.clear()
                                seen_needs_input_call_ids.update(pruned)
                    continue

                if mirror_tools and not needs_input_only:
                    tool_result = _extract_tool_result(payload, call_id_to_name=call_id_to_name)
                    if tool_result:
                        kind, text = tool_result
                        _send_structured(
                            recipient=recipient,
                            session_id=session_id,
                            kind=kind,
                            text=text,
                            max_message_chars=max_message_chars,
                            dry_run=dry_run,
                            queue_path=queue_path,
                        )
                        continue

        return offset
    except Exception:
        return offset


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(add_help=True)
    sub = parser.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="Run forever and mirror new messages")
    run.add_argument("--poll", type=float, default=0.5)
    run.add_argument("--dry-run", action="store_true")
    run.add_argument("--session-path", default=None)

    once = sub.add_parser("once", help="Process messages once and exit")
    once.add_argument("--dry-run", action="store_true")
    once.add_argument("--session-path", default=None)

    args = parser.parse_args(argv)

    recipient_raw = os.environ.get("CODEX_IMESSAGE_TO")
    if not recipient_raw:
        return 0
    recipient = _normalize_recipient(recipient_raw)

    codex_home = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex")))
    lock_handle = _acquire_single_instance_lock(codex_home=codex_home)
    if lock_handle is None:
        return 0

    cursor = _cursor_path(codex_home=codex_home)
    cursor_session_path, offset, seen_needs_input_call_ids = _load_cursor(cursor_path=cursor)

    max_message_chars = _MAX_MESSAGE_CHARS_DEFAULT
    env_max = os.environ.get("CODEX_IMESSAGE_MAX_LEN", "").strip()
    if env_max:
        try:
            max_message_chars = int(env_max)
        except Exception:
            max_message_chars = _MAX_MESSAGE_CHARS_DEFAULT

    queue_path = Path(
        os.environ.get(
            "CODEX_IMESSAGE_QUEUE",
            str(codex_home / "tmp" / "imessage_queue.jsonl"),
        )
    )
    mirror_roles = _parse_mirror_roles(os.environ.get("CODEX_IMESSAGE_MIRROR_ROLES"))

    session_id_cache: dict[str, str | None] = {}
    call_id_to_name: dict[str, str] = {}

    def resolve_current() -> Path | None:
        resolved = _resolve_session_path(codex_home=codex_home, explicit=args.session_path)
        if not resolved:
            return None
        return resolved

    # Starting behavior: if we have no cursor yet, do not replay the full history.
    current = resolve_current()
    if not current:
        return 0

    if not cursor.exists() or cursor_session_path != str(current):
        try:
            offset = current.stat().st_size
        except Exception:
            offset = 0
        _save_cursor(
            cursor_path=cursor,
            session_path=current,
            offset=offset,
            seen_needs_input_call_ids=seen_needs_input_call_ids,
        )

    if args.cmd == "once":
        offset = _process_session_path(
            codex_home=codex_home,
            session_path=current,
            offset=offset,
            recipient=recipient,
            mirror_roles=mirror_roles,
            max_message_chars=max_message_chars,
            dry_run=args.dry_run,
            queue_path=queue_path,
            session_id_cache=session_id_cache,
            call_id_to_name=call_id_to_name,
            seen_needs_input_call_ids=seen_needs_input_call_ids,
        )
        _save_cursor(
            cursor_path=cursor,
            session_path=current,
            offset=offset,
            seen_needs_input_call_ids=seen_needs_input_call_ids,
        )
        return 0

    last_scan = 0.0
    while True:
        try:
            now = time.monotonic()
            if now - last_scan >= _SESSION_SCAN_INTERVAL_S:
                newest = resolve_current()
                if newest and str(newest) != str(current):
                    current = newest
                    session_id_cache.pop(str(current), None)
                    call_id_to_name.clear()
                    try:
                        offset = current.stat().st_size
                    except Exception:
                        offset = 0
                last_scan = now

            offset = _process_session_path(
                codex_home=codex_home,
                session_path=current,
                offset=offset,
                recipient=recipient,
                mirror_roles=mirror_roles,
                max_message_chars=max_message_chars,
                dry_run=args.dry_run,
                queue_path=queue_path,
                session_id_cache=session_id_cache,
                call_id_to_name=call_id_to_name,
                seen_needs_input_call_ids=seen_needs_input_call_ids,
            )
            _save_cursor(
                cursor_path=cursor,
                session_path=current,
                offset=offset,
                seen_needs_input_call_ids=seen_needs_input_call_ids,
            )
        except KeyboardInterrupt:
            return 0
        except Exception:
            # Best-effort: keep running.
            pass
        time.sleep(float(args.poll))


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except SystemExit:
        raise
    except Exception:
        raise SystemExit(0)
