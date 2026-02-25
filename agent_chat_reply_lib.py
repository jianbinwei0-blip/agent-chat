#!/usr/bin/env python3
"""Codex/Claude ← iMessage reply bridge (macOS).

Reads new inbound iMessage replies from Messages' local SQLite DB and resumes the
most recently-notified Codex/Claude session with the reply text.

Usage:
  python3 agent_chat_reply_lib.py run
  python3 agent_chat_reply_lib.py run --poll 2
  python3 agent_chat_reply_lib.py once

Config:
  - CODEX_IMESSAGE_TO: recipient phone number (e.g. +13135551234) or Apple ID email
  - CODEX_IMESSAGE_SEND_REPLY: set to 1/true to send CODEX_REPLY iMessages back (default: disabled)
  - CODEX_HOME: defaults to ~/.codex
  - CODEX_IMESSAGE_LAST_ATTENTION: path to last attention state JSON
      (defaults to $CODEX_HOME/tmp/imessage_last_attention.json)
  - CODEX_IMESSAGE_ATTENTION_INDEX: path to per-session attention index JSON
      (defaults to $CODEX_HOME/tmp/imessage_attention_index.json)
  - CODEX_IMESSAGE_REPLY_CURSOR: path to reply cursor JSON
      (defaults to $CODEX_HOME/tmp/imessage_reply_cursor.json)
  - CODEX_IMESSAGE_CHAT_DB: path to chat.db (defaults to ~/Library/Messages/chat.db)

Notes:
  - Accessing ~/Library/Messages/chat.db may require granting Full Disk Access to
    your terminal/Python (System Settings → Privacy & Security → Full Disk Access).
  - This script is best-effort and must never fail the calling process.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path


_UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_APPLE_EPOCH_UNIX = 978307200  # 2001-01-01T00:00:00Z in Unix epoch seconds
_NSEC_PER_SEC = 1_000_000_000
_ATTN_HEAD = "Codex needs your attention"
_ATTN_TAIL = "Reply to this iMessage; Codex can apply your reply to the session."
_BOT_PREFIX = "CODEX_REPLY:"
_DEFAULT_CODEX_TIMEOUT_S: float | None = None
_DEFAULT_TMUX_REPLY_POLL_S = 0.5
_DEFAULT_TMUX_USER_ACK_TIMEOUT_S = 2.0
_DEFAULT_TMUX_SUBMIT_DELAY_S = 0.18
_TMUX_BIN_CANDIDATES = (
    "/opt/homebrew/bin/tmux",
    "/usr/local/bin/tmux",
    "/usr/bin/tmux",
)
_CLAUDE_BIN_CANDIDATES = (
    "/opt/homebrew/bin/claude",
    "/usr/local/bin/claude",
    "/usr/bin/claude",
)
_SUPPORTED_AGENTS = frozenset({"codex", "claude"})


def _normalize_tmux_socket(*, tmux_socket: str | None) -> str | None:
    if not isinstance(tmux_socket, str):
        return None
    value = tmux_socket.strip()
    return value if value else None


def _tmux_socket_from_env() -> str | None:
    raw = os.environ.get("TMUX")
    if not isinstance(raw, str) or not raw.strip():
        return None
    socket_path = raw.strip().split(",", 1)[0].strip()
    return socket_path if socket_path else None


def _resolve_tmux_bin() -> str:
    override = os.environ.get("CODEX_IMESSAGE_TMUX_BIN")
    if isinstance(override, str) and override.strip():
        return override.strip()

    discovered = shutil.which("tmux")
    if isinstance(discovered, str) and discovered.strip():
        return discovered.strip()

    for candidate in _TMUX_BIN_CANDIDATES:
        try:
            if Path(candidate).exists() and os.access(candidate, os.X_OK):
                return candidate
        except Exception:
            continue
    return "tmux"


def _normalize_agent(*, agent: str | None) -> str:
    candidate = agent.strip().lower() if isinstance(agent, str) else ""
    return candidate if candidate in _SUPPORTED_AGENTS else "codex"


def _resolve_claude_bin() -> str:
    override = os.environ.get("CODEX_IMESSAGE_CLAUDE_BIN")
    if isinstance(override, str) and override.strip():
        return override.strip()

    discovered = shutil.which("claude")
    if isinstance(discovered, str) and discovered.strip():
        return discovered.strip()

    for candidate in _CLAUDE_BIN_CANDIDATES:
        try:
            if Path(candidate).exists() and os.access(candidate, os.X_OK):
                return candidate
        except Exception:
            continue
    return "claude"


def _tmux_cmd(*parts: str, tmux_socket: str | None = None) -> list[str]:
    cmd = [_resolve_tmux_bin()]
    socket_value = _normalize_tmux_socket(tmux_socket=tmux_socket) or _tmux_socket_from_env()
    if socket_value:
        cmd.extend(["-S", socket_value])
    cmd.extend(list(parts))
    return cmd


def _acquire_single_instance_lock(*, codex_home: Path) -> object | None:
    """Prevent multiple reply-bridge instances from running concurrently.

    Codex's notify hook may run in environments where process listing is restricted
    (so `pgrep`/`ps` checks fail). Use a lockfile instead.
    """
    lock_path = Path(
        os.environ.get(
            "CODEX_IMESSAGE_REPLY_BRIDGE_LOCK",
            str(codex_home / "tmp" / "imessage_reply_bridge.lock"),
        )
    )
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        f = lock_path.open("a", encoding="utf-8")
    except Exception:
        # Can't lock; proceed anyway (best-effort bridge).
        return object()

    try:
        import fcntl  # macOS/Unix only
    except Exception:
        # Can't lock; proceed anyway.
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
            # Best-effort only.
            pass

        return f  # keep handle open for lock lifetime
    except Exception:
        try:
            f.close()
        except Exception:
            pass
        # Can't lock; proceed anyway.
        return object()


def _is_attention_message(text: str) -> bool:
    # We must not "resume" a session from our own attention notification.
    # Some macOS DB rows truncate the tail marker, so match on the stable header.
    return _ATTN_HEAD in text


def _is_bot_message(text: str) -> bool:
    candidate = text.strip()
    # Some rows include a leading "#" marker in the decoded body (observed in chat.db).
    # Treat that as non-semantic so we don't loop on our own outbound replies.
    while candidate.startswith("#"):
        candidate = candidate[1:].lstrip()
    return candidate.startswith(_BOT_PREFIX)


def _read_varint(data: bytes, pos: int) -> tuple[int | None, int]:
    value = 0
    shift = 0
    start = pos

    # Protobuf-style varint (7-bit groups with high-bit continuation).
    while pos < len(data) and shift <= 63:
        byte = data[pos]
        value |= (byte & 0x7F) << shift
        pos += 1

        if (byte & 0x80) == 0:
            return value, pos
        shift += 7

    return None, start


def _extract_text_from_attributed_body(raw: bytes) -> str | None:
    """Best-effort extraction of message text from Messages' attributedBody blob."""
    if not raw:
        return None

    # On modern macOS, message text is often stored in `attributedBody` even when
    # `message.text` is NULL. This blob typically contains an ASCII '+' followed
    # by a varint string length and then UTF-8 text.
    start_search = 0
    marker = raw.find(b"NSString")
    if marker == -1:
        marker = raw.find(b"NSMutableString")
    if marker != -1:
        start_search = marker

    plus = raw.find(b"+", start_search)
    if plus == -1:
        plus = raw.find(b"+")
    if plus == -1:
        return None

    length, pos = _read_varint(raw, plus + 1)
    if length is None or length <= 0:
        return None

    start = pos
    # Some blobs include a small tag byte (e.g. 0x07) before the UTF-8 string.
    if start < len(raw) and raw[start] < 0x20 and start + 1 < len(raw):
        nxt = raw[start + 1]
        if nxt in (9, 10, 13) or 32 <= nxt <= 126:
            start += 1

    end = min(len(raw), start + int(length))
    text_bytes = raw[start:end]
    try:
        text = text_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return None

    # Drop control chars except whitespace/newlines.
    text = "".join(ch for ch in text if ch in "\n\r\t" or ord(ch) >= 32).strip()
    return text or None


def _format_bot_reply(*, response: str, session_id: str | None) -> str:
    header_lines = [_BOT_PREFIX]
    if session_id and session_id.strip():
        header_lines.append(f"Session: {session_id.strip()}")
    header = "\n".join(header_lines)
    return f"{header}\n{response}".strip()


def _format_bot_replies(*, response: str, session_id: str | None) -> list[str]:
    max_len = 1800
    body = response.strip()
    if not body:
        return [_BOT_PREFIX]

    # Single-message fast path.
    single = _format_bot_reply(response=body, session_id=session_id)
    if len(single) <= max_len:
        return [single]

    # Multi-part replies: keep every part recognizable to prevent self-looping.
    chunks: list[str] = []
    # Leave space for "CODEX_REPLY: (i/n)\nSession: ...\n" header.
    # We'll do a first pass chunking, then render with final n.
    provisional_header = f"{_BOT_PREFIX} (999/999)\n"
    if session_id and session_id.strip():
        provisional_header += f"Session: {session_id.strip()}\n"
    chunk_len = max(1, max_len - len(provisional_header))
    for i in range(0, len(body), chunk_len):
        chunks.append(body[i : i + chunk_len])

    total = len(chunks)
    out: list[str] = []
    for idx, chunk in enumerate(chunks, start=1):
        header_lines = [f"{_BOT_PREFIX} ({idx}/{total})"]
        if session_id and session_id.strip():
            header_lines.append(f"Session: {session_id.strip()}")
        header = "\n".join(header_lines)
        msg = f"{header}\n{chunk}".strip()
        if len(msg) > max_len:
            msg = msg[: max_len - 1] + "…"
        out.append(msg)
    return out


def _get_message_text_by_guid(*, conn: sqlite3.Connection, guid: str) -> str | None:
    if not guid:
        return None

    try:
        cur = conn.execute(
            "SELECT m.text, m.attributedBody FROM message AS m WHERE m.guid = ? LIMIT 1",
            [guid],
        )
        row = cur.fetchone()
        if not row:
            return None
        text, attributed_body = row

        extracted: str | None = None
        if isinstance(text, str) and text.strip():
            extracted = text.strip()
        else:
            blob: bytes | None = None
            if isinstance(attributed_body, memoryview):
                blob = attributed_body.tobytes()
            elif isinstance(attributed_body, (bytes, bytearray)):
                blob = bytes(attributed_body)
            if blob:
                extracted = _extract_text_from_attributed_body(blob)

        return extracted.strip() if isinstance(extracted, str) and extracted.strip() else None
    except Exception:
        return None


def _resolve_session_id(
    *,
    conn: sqlite3.Connection,
    reply_text: str,
    reply_to_guid: str | None,
    fallback_session_id: str | None,
) -> str | None:
    direct = _extract_session_id(reply_text)
    if direct:
        return direct

    if isinstance(reply_to_guid, str) and reply_to_guid.strip():
        replied_text = _get_message_text_by_guid(conn=conn, guid=reply_to_guid.strip())
        if replied_text:
            sid = _extract_session_id(replied_text)
            if sid:
                return sid

    if isinstance(fallback_session_id, str) and fallback_session_id.strip():
        return fallback_session_id.strip()
    return None


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


def _run_codex_resume(
    *,
    session_id: str,
    cwd: str | None,
    prompt: str,
    codex_home: Path,
    timeout_s: float | None,
) -> str | None:
    out_dir = codex_home / "tmp"
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        # Best-effort only; if this fails we'll still try to run Codex.
        pass

    out_path = out_dir / f"imessage_last_response_{int(time.time())}_{os.getpid()}.txt"

    cmd: list[str] = ["codex", "-a", "never", "-s", "workspace-write"]
    if cwd:
        cmd.extend(["-C", cwd])
    cmd.extend(
        [
            "exec",
            "--skip-git-repo-check",
            "--output-last-message",
            str(out_path),
            "resume",
            session_id,
            "-",
        ]
    )

    try:
        timeout: float | None = None

        # Explicit CLI/config param takes precedence.
        if timeout_s is not None:
            timeout = None if float(timeout_s) <= 0 else float(timeout_s)
        else:
            # Back-compat: allow env var to override when present.
            timeout_raw = os.environ.get("CODEX_IMESSAGE_CODEX_TIMEOUT_SECS")
            if timeout_raw is not None:
                try:
                    timeout = None if float(timeout_raw) <= 0 else float(timeout_raw)
                except Exception:
                    timeout = _DEFAULT_CODEX_TIMEOUT_S

        proc = subprocess.run(
            cmd,
            input=prompt,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            env={**os.environ, "CODEX_IMESSAGE_REPLY": "1"},
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return "(codex exec resume timed out)"
    except Exception:
        return None

    if proc.returncode != 0:
        return None

    try:
        content = out_path.read_text(encoding="utf-8").strip()
        return content if content else None
    except Exception:
        return None


def _run_agent_resume(
    *,
    agent: str,
    session_id: str,
    cwd: str | None,
    prompt: str,
    codex_home: Path,
    timeout_s: float | None,
) -> str | None:
    normalized = _normalize_agent(agent=agent)
    if normalized != "claude":
        return _run_codex_resume(
            session_id=session_id,
            cwd=cwd,
            prompt=prompt,
            codex_home=codex_home,
            timeout_s=timeout_s,
        )

    cmd: list[str] = [_resolve_claude_bin(), "-p", "--resume", session_id, prompt]
    try:
        timeout = None if timeout_s is None else (None if float(timeout_s) <= 0 else float(timeout_s))
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            text=True,
            cwd=cwd if isinstance(cwd, str) and cwd.strip() else None,
            timeout=timeout,
            env={**os.environ, "CLAUDE_IMESSAGE_REPLY": "1"},
        )
    except subprocess.TimeoutExpired:
        return "(claude --resume timed out)"
    except Exception:
        return None

    if proc.returncode != 0:
        return None

    return proc.stdout.strip() if isinstance(proc.stdout, str) and proc.stdout.strip() else None


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


def _read_last_user_text_from_session(session_path: Path) -> str | None:
    """Return the last user message from a Codex session JSONL, if present."""
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
                    if payload.get("type") != "message" or payload.get("role") != "user":
                        continue

                    content = payload.get("content")
                    if not isinstance(content, list):
                        continue

                    chunks: list[str] = []
                    for item in content:
                        if not isinstance(item, dict):
                            continue
                        if item.get("type") != "input_text":
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
                    if payload.get("type") != "user_message":
                        continue
                    message = payload.get("message")
                    if isinstance(message, str) and message.strip():
                        last_text = message.strip()
                    continue

        return last_text.strip() if isinstance(last_text, str) and last_text.strip() else None
    except Exception:
        return None


def _wait_for_new_user_text(*, session_path: Path, before: str | None, timeout_s: float) -> str | None:
    deadline = time.monotonic() + max(0.0, float(timeout_s))
    while time.monotonic() < deadline:
        current = _read_last_user_text_from_session(session_path)
        if current and current != before:
            return current
        time.sleep(_DEFAULT_TMUX_REPLY_POLL_S)
    return None


def _wait_for_new_assistant_text(*, session_path: Path, before: str | None, timeout_s: float | None) -> str | None:
    if timeout_s is None:
        return None

    deadline = time.monotonic() + max(0.0, float(timeout_s))
    while time.monotonic() < deadline:
        current = _read_last_assistant_text_from_session(session_path)
        if current and current != before:
            return current
        time.sleep(_DEFAULT_TMUX_REPLY_POLL_S)
    return None


def _tmux_send_prompt(*, pane: str, prompt: str, tmux_socket: str | None = None) -> bool:
    text = " ".join(prompt.splitlines()).strip()
    if not text:
        return False
    try:
        first = subprocess.run(
            _tmux_cmd("send-keys", "-t", pane, "-l", text, tmux_socket=tmux_socket),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if first.returncode != 0:
            return False

        # Codex treats very fast text streams as paste bursts; Enter during that window
        # inserts a newline instead of submitting. Wait briefly before submit keys.
        delay_s = _DEFAULT_TMUX_SUBMIT_DELAY_S
        raw_delay = os.environ.get("CODEX_IMESSAGE_TMUX_SUBMIT_DELAY_S", "").strip()
        if raw_delay:
            try:
                delay_s = max(0.0, float(raw_delay))
            except Exception:
                delay_s = _DEFAULT_TMUX_SUBMIT_DELAY_S
        if delay_s > 0:
            time.sleep(delay_s)

        # Prefer carriage-return style submission first for terminal/TUI apps.
        # "Return" can be rendered literally in some tmux setups; avoid it.
        for key in ("C-m", "Enter"):
            second = subprocess.run(
                _tmux_cmd("send-keys", "-t", pane, key, tmux_socket=tmux_socket),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if second.returncode == 0:
                return True
        return False
    except Exception:
        return False


def _session_path_matches_session_id(*, session_path: str | None, session_id: str) -> bool:
    if not (isinstance(session_path, str) and session_path.strip()):
        return False
    sp = session_path.strip()
    sid = session_id.strip()
    return bool(sid) and sid in sp


def _handle_prompt(
    *,
    recipient: str,
    session_id: str,
    cwd: str | None,
    prompt: str,
    codex_home: Path,
    dry_run: bool,
    echo: bool = False,
    rowid: int | None = None,
    timeout_s: float | None = _DEFAULT_CODEX_TIMEOUT_S,
    use_tmux: bool = False,
    tmux_pane: str | None = None,
    tmux_socket: str | None = None,
    session_path: str | None = None,
) -> None:
    tmux_allowed = bool(use_tmux and tmux_pane and _session_path_matches_session_id(session_path=session_path, session_id=session_id))
    if tmux_allowed and tmux_pane:
        if dry_run:
            tmux_bin = _resolve_tmux_bin()
            socket_flag = ""
            socket_value = _normalize_tmux_socket(tmux_socket=tmux_socket) or _tmux_socket_from_env()
            if socket_value:
                socket_flag = f" -S {socket_value}"
            sys.stdout.write(
                f"{tmux_bin}{socket_flag} send-keys -t {tmux_pane} -l <prompt>; "
                f"{tmux_bin}{socket_flag} send-keys -t {tmux_pane} Enter\n"
            )
            return
        if echo:
            if rowid is not None:
                sys.stdout.write(f"rowid={rowid}\n")
            sys.stdout.write(f"tmux_pane={tmux_pane}\n")

        response: str | None = None
        before_text: str | None = None
        before_user_text: str | None = None
        session_path_obj: Path | None = None
        if session_path:
            session_path_obj = Path(session_path)
            before_user_text = _read_last_user_text_from_session(session_path_obj)
            before_text = _read_last_assistant_text_from_session(session_path_obj)

        ok = _tmux_send_prompt(pane=tmux_pane, prompt=prompt, tmux_socket=tmux_socket)
        tmux_ack = False
        if ok and session_path_obj is not None:
            tmux_ack = _wait_for_new_user_text(
                session_path=session_path_obj,
                before=before_user_text,
                timeout_s=_DEFAULT_TMUX_USER_ACK_TIMEOUT_S,
            ) is not None
            if not tmux_ack:
                # Retry submit keys before giving up. Some interactive TUIs
                # occasionally miss the first submit key from a background hook.
                for submit_key in ("C-m", "Enter"):
                    try:
                        submit = subprocess.run(
                            _tmux_cmd("send-keys", "-t", tmux_pane, submit_key, tmux_socket=tmux_socket),
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            check=False,
                        )
                    except Exception:
                        continue
                    if submit.returncode != 0:
                        continue
                    tmux_ack = _wait_for_new_user_text(
                        session_path=session_path_obj,
                        before=before_user_text,
                        timeout_s=_DEFAULT_TMUX_USER_ACK_TIMEOUT_S,
                    ) is not None
                    if tmux_ack:
                        break

        if ok and tmux_ack:
            if session_path_obj:
                response = _wait_for_new_assistant_text(
                    session_path=session_path_obj,
                    before=before_text,
                    timeout_s=timeout_s,
                )
            if not response:
                response = "(sent to tmux; no new assistant message observed yet)"
        else:
            if echo:
                reason = "tmux send failed"
                if ok and not tmux_ack:
                    reason = "tmux did not update target session quickly"
                sys.stdout.write(
                    f"tmux dispatch not confirmed ({reason}); "
                    "no codex resume fallback (pane mapping exists)\n"
                )
            response = (
                "(sent to tmux pane but could not confirm execution; "
                "no background fallback run)"
            )
    else:
        active_agent = _normalize_agent(agent=os.environ.get("CODEX_IMESSAGE_AGENT") or os.environ.get("IMESSAGE_AGENT"))
        if use_tmux and tmux_pane and echo:
            sys.stdout.write("tmux context mismatch; using CLI resume fallback\n")
        if active_agent == "claude":
            display_cmd = [_resolve_claude_bin(), "-p", "--resume", session_id, prompt]
        else:
            display_cmd = ["codex", "-a", "never", "-s", "workspace-write"]
            if cwd:
                display_cmd.extend(["-C", cwd])
            display_cmd.extend(["exec", "--skip-git-repo-check", "resume", session_id, "-"])

        if dry_run:
            sys.stdout.write(" ".join(display_cmd) + "\n")
            return
        if echo:
            if rowid is not None:
                sys.stdout.write(f"rowid={rowid}\n")
            sys.stdout.write(" ".join(display_cmd) + "\n")

        response = _run_agent_resume(
            agent=active_agent,
            session_id=session_id,
            cwd=cwd,
            prompt=prompt,
            codex_home=codex_home,
            timeout_s=timeout_s,
        )
    if not response:
        response = "(no response from CLI resume; check logs / timeout)"

    if echo:
        max_chars_raw = os.environ.get("CODEX_IMESSAGE_ECHO_MAX_CHARS", "4000")
        try:
            max_chars = max(0, int(max_chars_raw))
        except Exception:
            max_chars = 4000

        shown = response
        if max_chars and len(shown) > max_chars:
            shown = shown[: max_chars - 1] + "…"
        sys.stdout.write("----- assistant reply -----\n")
        sys.stdout.write(shown.rstrip() + "\n")
        sys.stdout.write("----- end reply -----\n")

    send_reply_raw = os.environ.get("CODEX_IMESSAGE_SEND_REPLY", "").strip().lower()
    send_reply = send_reply_raw in {"1", "true", "yes", "y", "on"}
    if not send_reply:
        if echo:
            sys.stdout.write("skipped iMessage reply (set CODEX_IMESSAGE_SEND_REPLY=1 to enable)\n")
        return

    parts = _format_bot_replies(response=response, session_id=session_id)
    sent = 0
    for msg in parts:
        if _send_imessage(recipient=recipient, message=msg):
            sent += 1
    if echo:
        sys.stdout.write(f"sent {sent}/{len(parts)} iMessage part(s)\n")


def _normalize_recipient(raw: str) -> str:
    recipient = raw.strip()
    if recipient.startswith("+"):
        return recipient

    compact = re.sub(r"[\s\-\(\)\.]", "", recipient)
    if compact.isdigit():
        if len(compact) == 10:
            return f"+1{compact}"
        if len(compact) == 11 and compact.startswith("1"):
            return f"+{compact}"

    return recipient


def _candidate_handle_ids(recipient: str) -> list[str]:
    ids: set[str] = set()
    if recipient:
        ids.add(recipient)
        if recipient.startswith("+"):
            ids.add(recipient[1:])

    digits = re.sub(r"\D", "", recipient)
    if digits:
        ids.add(digits)
        if len(digits) == 11 and digits.startswith("1"):
            ids.add(digits[1:])
        if len(digits) == 10:
            ids.add(digits)
            ids.add(f"+1{digits}")

    # Keep stable ordering for sqlite placeholders.
    return sorted(i for i in ids if i)


def _read_json(path: Path) -> dict[str, object] | None:
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
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)
    except Exception:
        return


def _open_chat_db(path: Path) -> sqlite3.Connection | None:
    try:
        if not path.exists():
            return None
        # Open read-only (uri mode); keeps us from mutating the DB.
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        # Best-effort hardening: avoid accidental writes and tolerate transient DB locks.
        try:
            conn.execute("PRAGMA query_only = 1")
        except Exception:
            pass
        try:
            conn.execute("PRAGMA busy_timeout = 1000")
        except Exception:
            pass
        return conn
    except Exception:
        return None


def _unix_ts_to_apple_date_ns(unix_ts: int) -> int:
    # Messages' `message.date` is typically nanoseconds since Apple epoch (2001-01-01).
    # If the input ts is older than Apple epoch, clamp to 0.
    delta = unix_ts - _APPLE_EPOCH_UNIX
    return max(0, int(delta) * _NSEC_PER_SEC)


def _max_rowid(conn: sqlite3.Connection) -> int:
    try:
        cur = conn.execute("SELECT COALESCE(MAX(ROWID), 0) FROM message")
        row = cur.fetchone()
        if row and isinstance(row[0], int):
            return row[0]
    except Exception:
        return 0
    return 0


def _max_rowid_at_or_before_unix_ts(conn: sqlite3.Connection, unix_ts: int) -> int:
    """Best-effort: return the max ROWID at or before the given Unix timestamp."""
    try:
        cutoff = _unix_ts_to_apple_date_ns(unix_ts)
        cur = conn.execute("SELECT COALESCE(MAX(ROWID), 0) FROM message WHERE date <= ?", [cutoff])
        row = cur.fetchone()
        if row and isinstance(row[0], int):
            return row[0]
    except Exception:
        return 0
    return 0


def _fetch_new_replies(
    *,
    conn: sqlite3.Connection,
    after_rowid: int,
    handle_ids: list[str],
) -> list[tuple[int, str, str | None]]:
    if not handle_ids:
        return []

    placeholders = ",".join("?" for _ in handle_ids)
    # Prefer only inbound messages (avoid looping on our own outbound "attention" or "CODEX_REPLY" messages).
    # Messages DB schema is not perfectly stable across macOS releases, so we treat this as best-effort.
    try:
        cols_raw = conn.execute("PRAGMA table_info(message)").fetchall()
        cols = {str(row[1]) for row in cols_raw if isinstance(row, (tuple, list)) and len(row) > 1}
    except Exception:
        cols = set()

    has_is_from_me = "is_from_me" in cols
    has_thread_originator = "thread_originator_guid" in cols
    has_associated_guid = "associated_message_guid" in cols

    select_cols = ["m.ROWID", "m.text", "m.attributedBody", "m.reply_to_guid"]
    if has_thread_originator:
        select_cols.append("m.thread_originator_guid")
    if has_associated_guid:
        select_cols.append("m.associated_message_guid")

    inbound_filter = "AND COALESCE(m.is_from_me, 0) = 0" if has_is_from_me else ""
    sql = f"""
      SELECT {", ".join(select_cols)}
      FROM message AS m
      JOIN handle AS h ON m.handle_id = h.ROWID
      WHERE m.ROWID > ?
        AND (m.text IS NOT NULL OR m.attributedBody IS NOT NULL)
        {inbound_filter}
        AND h.id IN ({placeholders})
      ORDER BY m.ROWID ASC
    """

    try:
        rows = conn.execute(sql, [after_rowid, *handle_ids]).fetchall()
    except Exception:
        return []

    out: list[tuple[int, str, str | None]] = []
    for row in rows:
        if not isinstance(row, (tuple, list)) or len(row) < 4:
            continue

        rowid = row[0]
        text = row[1]
        attributed_body = row[2]
        reply_to_guid = row[3]
        idx = 4
        thread_originator_guid = None
        if has_thread_originator and len(row) > idx:
            thread_originator_guid = row[idx]
            idx += 1
        associated_guid = None
        if has_associated_guid and len(row) > idx:
            associated_guid = row[idx]

        if not isinstance(rowid, int):
            continue

        extracted: str | None = None
        if isinstance(text, str) and text.strip():
            extracted = text.strip()
        else:
            blob: bytes | None = None
            if isinstance(attributed_body, memoryview):
                blob = attributed_body.tobytes()
            elif isinstance(attributed_body, (bytes, bytearray)):
                blob = bytes(attributed_body)
            if blob:
                extracted = _extract_text_from_attributed_body(blob)

        if extracted:
            # Prefer thread origin for threaded replies: this tracks the intended
            # thread root and is more stable than immediate reply linkage.
            ref_guid: str | None = None
            for candidate in (thread_originator_guid, reply_to_guid, associated_guid):
                if isinstance(candidate, str) and candidate.strip():
                    ref_guid = candidate.strip()
                    break
            out.append((rowid, extracted, ref_guid))
    return out


def _extract_session_id(text: str) -> str | None:
    match = _UUID_RE.search(text)
    if match:
        return match.group(0)
    return None


def _resume_session(*, session_id: str, cwd: str | None, prompt: str, dry_run: bool) -> None:
    cmd: list[str] = ["codex"]
    if cwd:
        cmd.extend(["-C", cwd])
    cmd.extend(["exec", "--skip-git-repo-check", "resume", session_id, prompt])

    if dry_run:
        sys.stdout.write(" ".join(cmd) + "\n")
        return

    try:
        subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={**os.environ, "CODEX_IMESSAGE_REPLY": "1"},
        )
    except Exception:
        return


def _load_last_attention_state(codex_home: Path) -> dict[str, object] | None:
    state_path = Path(
        os.environ.get(
            "CODEX_IMESSAGE_LAST_ATTENTION",
            str(codex_home / "tmp" / "imessage_last_attention.json"),
        )
    )
    return _read_json(state_path)


def _attention_index_path(*, codex_home: Path) -> Path:
    return Path(
        os.environ.get(
            "CODEX_IMESSAGE_ATTENTION_INDEX",
            str(codex_home / "tmp" / "imessage_attention_index.json"),
        )
    )


def _load_attention_index(codex_home: Path) -> dict[str, object] | None:
    return _read_json(_attention_index_path(codex_home=codex_home))


def _session_registry_path(*, codex_home: Path) -> Path:
    return Path(
        os.environ.get(
            "CODEX_IMESSAGE_SESSION_REGISTRY",
            str(codex_home / "tmp" / "imessage_session_registry.json"),
        )
    )


def _load_session_registry(codex_home: Path) -> dict[str, object] | None:
    return _read_json(_session_registry_path(codex_home=codex_home))


def _coerce_nonempty_str(value: object) -> str | None:
    if isinstance(value, str):
        s = value.strip()
        return s if s else None
    return None


def _select_attention_context(
    *,
    session_id: str,
    attention_index: dict[str, object] | None,
    last_attention_state: dict[str, object] | None,
    session_registry: dict[str, object] | None = None,
) -> dict[str, str]:
    """Return best-effort context for a session.

    Prefer a per-session attention index record, but merge missing fields from
    the most recent attention state. Fall back to control-plane session registry
    when index/state are missing.
    """
    out: dict[str, str] = {}

    primary: dict[str, object] | None = None
    if isinstance(attention_index, dict):
        candidate = attention_index.get(session_id)
        if isinstance(candidate, dict):
            primary = candidate

    if isinstance(primary, dict):
        for key in ("cwd", "tmux_pane", "tmux_socket", "session_path"):
            value = _coerce_nonempty_str(primary.get(key))
            if value:
                out[key] = value

    state_matches_session = False
    if isinstance(last_attention_state, dict):
        state_session_id = _coerce_nonempty_str(last_attention_state.get("session_id"))
        # Older attention-state records may not include session_id; in that case,
        # keep old fallback behavior. Otherwise, only merge when the session matches.
        state_matches_session = state_session_id is None or state_session_id == session_id

    if state_matches_session and isinstance(last_attention_state, dict):
        for key in ("cwd", "tmux_pane", "tmux_socket", "session_path"):
            if key in out:
                continue
            value = _coerce_nonempty_str(last_attention_state.get(key))
            if value:
                out[key] = value

    sessions = session_registry.get("sessions") if isinstance(session_registry, dict) else None
    rec = sessions.get(session_id) if isinstance(sessions, dict) else None
    if isinstance(rec, dict):
        for key in ("cwd", "tmux_pane", "tmux_socket", "session_path"):
            if key in out:
                continue
            value = _coerce_nonempty_str(rec.get(key))
            if value:
                out[key] = value

    return out


def _load_cursor(*, cursor_path: Path) -> int:
    data = _read_json(cursor_path)
    if not data:
        return 0
    rowid = data.get("last_rowid")
    return int(rowid) if isinstance(rowid, int) else 0


def _save_cursor(*, cursor_path: Path, rowid: int) -> None:
    _write_json(cursor_path, {"last_rowid": rowid, "ts": int(time.time())})


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(add_help=True)
    sub = parser.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="Run forever and process replies")
    run.add_argument("--poll", type=float, default=2.0)
    run.add_argument("--dry-run", action="store_true")
    run.add_argument("--echo", action="store_true")
    run.add_argument("--timeout", type=float, default=_DEFAULT_CODEX_TIMEOUT_S)
    run.add_argument("--tmux", action="store_true", help="Inject reply into tmux pane from attention state/index")

    once = sub.add_parser("once", help="Process replies once and exit")
    once.add_argument("--dry-run", action="store_true")
    once.add_argument("--echo", action="store_true")
    once.add_argument("--timeout", type=float, default=_DEFAULT_CODEX_TIMEOUT_S)
    once.add_argument("--tmux", action="store_true", help="Inject reply into tmux pane from attention state/index")

    args = parser.parse_args(argv)

    recipient_raw = os.environ.get("CODEX_IMESSAGE_TO")
    if not recipient_raw:
        return 0
    recipient = _normalize_recipient(recipient_raw)
    handle_ids = _candidate_handle_ids(recipient)

    codex_home = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex")))
    # Prevent multiple concurrent bridge instances (notify hooks may try to start this repeatedly).
    _lock_handle = _acquire_single_instance_lock(codex_home=codex_home)
    if _lock_handle is None:
        return 0
    cursor_path = Path(
        os.environ.get(
            "CODEX_IMESSAGE_REPLY_CURSOR",
            str(codex_home / "tmp" / "imessage_reply_cursor.json"),
        )
    )

    chat_db = Path(
        os.environ.get(
            "CODEX_IMESSAGE_CHAT_DB",
            str(Path.home() / "Library" / "Messages" / "chat.db"),
        )
    )

    conn = _open_chat_db(chat_db)
    if conn is None:
        return 0

    # Important: if the cursor file doesn't exist yet, starting from ROWID=0 could replay
    # the user's entire inbound message history into Codex. When this bridge is auto-started
    # by a "needs attention" notification, we want to begin at (roughly) the time of that
    # notification.
    last_rowid = _load_cursor(cursor_path=cursor_path)
    if not cursor_path.exists():
        state = _load_last_attention_state(codex_home)
        state_ts = state.get("ts") if isinstance(state, dict) else None
        if isinstance(state_ts, int) and state_ts > 0:
            last_rowid = _max_rowid_at_or_before_unix_ts(conn, state_ts)
        else:
            last_rowid = _max_rowid(conn)
        _save_cursor(cursor_path=cursor_path, rowid=last_rowid)

    while True:
        replies = _fetch_new_replies(conn=conn, after_rowid=last_rowid, handle_ids=handle_ids)
        for rowid, text, reply_to_guid in replies:
            last_rowid = rowid
            _save_cursor(cursor_path=cursor_path, rowid=last_rowid)

            if _is_attention_message(text):
                continue
            if _is_bot_message(text):
                continue

            state = _load_last_attention_state(codex_home)
            fallback_session_id: str | None = None
            if isinstance(state, dict):
                state_session = state.get("session_id")
                if isinstance(state_session, str) and state_session.strip():
                    fallback_session_id = state_session.strip()

            session_id = _resolve_session_id(
                conn=conn,
                reply_text=text,
                reply_to_guid=reply_to_guid,
                fallback_session_id=fallback_session_id,
            )

            if not session_id:
                continue

            attention_index = _load_attention_index(codex_home)
            session_registry = _load_session_registry(codex_home)
            ctx = _select_attention_context(
                session_id=session_id,
                attention_index=attention_index,
                last_attention_state=(state if isinstance(state, dict) else None),
                session_registry=session_registry,
            )
            cwd = ctx.get("cwd")
            tmux_pane = ctx.get("tmux_pane")
            tmux_socket = ctx.get("tmux_socket")
            session_path = ctx.get("session_path")

            _handle_prompt(
                recipient=recipient,
                session_id=session_id,
                cwd=cwd,
                prompt=text,
                codex_home=codex_home,
                dry_run=bool(args.dry_run),
                echo=bool(args.echo),
                rowid=rowid,
                timeout_s=(float(args.timeout) if args.timeout is not None else None),
                use_tmux=bool(args.tmux),
                tmux_pane=tmux_pane,
                tmux_socket=tmux_socket,
                session_path=session_path,
            )

        if args.cmd == "once":
            break
        time.sleep(float(args.poll))

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except SystemExit:
        raise
    except Exception:
        raise SystemExit(0)
