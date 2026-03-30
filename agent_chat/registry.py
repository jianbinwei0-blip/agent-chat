from __future__ import annotations

from typing import Any


_RUNTIME_BINDING_KEYS = {"tmux_pane", "tmux_socket", "agent"}


def conversation_key(*, transport: str | None, channel_id: str | None, thread_id: int | str | None = None) -> str | None:
    transport_text = transport.strip().lower() if isinstance(transport, str) else ""
    channel_text = channel_id.strip() if isinstance(channel_id, str) else ""
    if not transport_text or not channel_text:
        return None
    normalized_thread = normalize_thread_id(thread_id)
    return f"{transport_text}:{channel_text}:{normalized_thread if normalized_thread is not None else 0}"


def normalize_thread_id(value: object) -> int | str | None:
    if value is None:
        return 0
    if isinstance(value, int):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return 0
        try:
            return int(text)
        except Exception:
            return text
    return 0


def normalize_conversation_bindings(*, raw: object, sessions: dict[str, Any]) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    out: dict[str, str] = {}
    for key, value in raw.items():
        key_text = key.strip() if isinstance(key, str) else ""
        sid = value.strip() if isinstance(value, str) else ""
        if not key_text or not sid or sid not in sessions:
            continue
        out[key_text] = sid
    return out


def normalize_runtime_bindings(raw: object) -> dict[str, dict[str, str]]:
    if not isinstance(raw, dict):
        return {}
    out: dict[str, dict[str, str]] = {}
    for key, value in raw.items():
        key_text = key.strip() if isinstance(key, str) else ""
        if not key_text or not isinstance(value, dict):
            continue
        record: dict[str, str] = {}
        for field in _RUNTIME_BINDING_KEYS:
            item = value.get(field)
            if isinstance(item, str) and item.strip():
                record[field] = item.strip()
        if "tmux_pane" not in record:
            continue
        out[key_text] = record
    return out
