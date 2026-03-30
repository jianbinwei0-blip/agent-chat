from __future__ import annotations

from typing import Iterable


_SUPPORTED_TRANSPORTS = ("imessage", "telegram", "discord")


def _normalize_transport_token(token: object) -> str | None:
    if not isinstance(token, str):
        return None
    value = token.strip().lower()
    if not value:
        return None
    if value == "both":
        return "both"
    if value in _SUPPORTED_TRANSPORTS:
        return value
    return None


def parse_transport_list(raw_multi: str | None, raw_legacy: str | None = None) -> list[str]:
    selected: list[str] = []
    seen: set[str] = set()

    def _add(value: str) -> None:
        if value in seen:
            return
        seen.add(value)
        selected.append(value)

    if isinstance(raw_multi, str) and raw_multi.strip():
        for part in raw_multi.split(","):
            token = _normalize_transport_token(part)
            if token is None:
                continue
            if token == "both":
                _add("imessage")
                _add("telegram")
            else:
                _add(token)
    else:
        token = _normalize_transport_token(raw_legacy or "imessage")
        if token == "both":
            _add("imessage")
            _add("telegram")
        elif token is not None:
            _add(token)

    if not selected:
        return ["imessage"]
    return selected


def transport_mode_summary(transports: Iterable[str]) -> str:
    ordered = [item for item in _SUPPORTED_TRANSPORTS if item in set(transports)]
    if ordered == ["imessage", "telegram"]:
        return "both"
    if len(ordered) == 1:
        return ordered[0]
    return ",".join(ordered) if ordered else "imessage"
