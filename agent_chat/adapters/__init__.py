from __future__ import annotations

from .codex import ADAPTER as CODEX_ADAPTER
from .claude import ADAPTER as CLAUDE_ADAPTER
from .pi import ADAPTER as PI_ADAPTER
from .imessage import ADAPTER as IMESSAGE_ADAPTER
from .telegram import ADAPTER as TELEGRAM_ADAPTER
from .discord import ADAPTER as DISCORD_ADAPTER

AGENT_ADAPTERS = {
    CODEX_ADAPTER.id: CODEX_ADAPTER,
    CLAUDE_ADAPTER.id: CLAUDE_ADAPTER,
    PI_ADAPTER.id: PI_ADAPTER,
}

TRANSPORT_ADAPTERS = {
    IMESSAGE_ADAPTER.id: IMESSAGE_ADAPTER,
    TELEGRAM_ADAPTER.id: TELEGRAM_ADAPTER,
    DISCORD_ADAPTER.id: DISCORD_ADAPTER,
}


def get_agent_adapter(agent: str):
    return AGENT_ADAPTERS.get((agent or "").strip().lower(), CODEX_ADAPTER)


def get_transport_adapter(transport: str):
    return TRANSPORT_ADAPTERS.get((transport or "").strip().lower())


__all__ = [
    "AGENT_ADAPTERS",
    "TRANSPORT_ADAPTERS",
    "get_agent_adapter",
    "get_transport_adapter",
]
