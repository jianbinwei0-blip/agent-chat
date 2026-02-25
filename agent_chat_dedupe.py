#!/usr/bin/env python3
"""Shared iMessage deduplication helpers.

This module provides best-effort, cross-process dedupe primitives for iMessage
notifications. It uses a JSON index file guarded by a file lock.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import time
from pathlib import Path


_DEFAULT_TTL_SECONDS = 24 * 60 * 60
_MAX_ENTRIES = 4096


def _normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def build_dedupe_key(*, category: str, scope: str, text: str) -> str:
    category_text = category.strip() or "default"
    scope_text = scope.strip() or "global"
    normalized = _normalize_text(text)
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:24]
    return f"{category_text}:{scope_text}:{digest}"


def _index_path(*, codex_home: Path) -> Path:
    return Path(
        os.environ.get(
            "AGENT_CHAT_DEDUPE_INDEX",
            str(codex_home / "tmp" / "agent_chat_dedupe_index.json"),
        )
    )


def _lock_path(*, codex_home: Path, index_path: Path) -> Path:
    raw = os.environ.get("AGENT_CHAT_DEDUPE_LOCK")
    if raw and raw.strip():
        return Path(raw.strip())
    return Path(str(index_path) + ".lock")


def _dedupe_ttl_seconds(*, override: int | None = None) -> int:
    if isinstance(override, int) and override > 0:
        return override
    raw = os.environ.get("AGENT_CHAT_DEDUPE_TTL_S", "").strip()
    if raw:
        try:
            parsed = int(raw)
            if parsed > 0:
                return parsed
        except Exception:
            pass
    return _DEFAULT_TTL_SECONDS


def _read_json_dict(path: Path) -> dict[str, int]:
    try:
        if not path.exists():
            return {}
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {}
        out: dict[str, int] = {}
        for key, value in data.items():
            if not isinstance(key, str):
                continue
            if isinstance(value, int):
                out[key] = value
        return out
    except Exception:
        return {}


def _write_json_atomic(path: Path, data: dict[str, int]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    tmp_path.replace(path)


def _prune(index: dict[str, int], *, now_ts: int, ttl_seconds: int) -> dict[str, int]:
    cutoff = now_ts - ttl_seconds
    pruned = {key: ts for key, ts in index.items() if isinstance(ts, int) and ts >= cutoff}
    if len(pruned) <= _MAX_ENTRIES:
        return pruned
    newest = sorted(pruned.items(), key=lambda item: item[1], reverse=True)[:_MAX_ENTRIES]
    return dict(newest)


def _with_lock(lock_path: Path):
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("a", encoding="utf-8")
    try:
        import fcntl
    except Exception:
        return handle
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    except OSError as exc:
        if exc.errno in {errno.EACCES, errno.EAGAIN}:
            return handle
        raise
    return handle


def mark_once(
    *,
    codex_home: Path,
    key: str,
    now_ts: int | None = None,
    ttl_seconds: int | None = None,
) -> bool:
    """Return True if key is new (and record it), False if recently seen."""
    key_text = key.strip() if isinstance(key, str) else ""
    if not key_text:
        return True

    now = now_ts if isinstance(now_ts, int) and now_ts > 0 else int(time.time())
    ttl = _dedupe_ttl_seconds(override=ttl_seconds)
    index_path = _index_path(codex_home=codex_home)
    lock_path = _lock_path(codex_home=codex_home, index_path=index_path)

    try:
        lock = _with_lock(lock_path)
    except Exception:
        # Fail open: do not block notifications on lock failures.
        return True

    try:
        index = _read_json_dict(index_path)
        index = _prune(index, now_ts=now, ttl_seconds=ttl)
        existing_ts = index.get(key_text)
        if isinstance(existing_ts, int) and existing_ts >= (now - ttl):
            return False
        index[key_text] = now
        index = _prune(index, now_ts=now, ttl_seconds=ttl)
        _write_json_atomic(index_path, index)
        return True
    except Exception:
        # Fail open: never block required notifications due to storage issues.
        return True
    finally:
        try:
            lock.close()
        except Exception:
            pass
