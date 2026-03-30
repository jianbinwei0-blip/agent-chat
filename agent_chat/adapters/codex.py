from __future__ import annotations

from pathlib import Path

from agent_chat.types import AgentAdapter


ADAPTER = AgentAdapter(
    id="codex",
    label="Codex",
    default_home_env="AGENT_CHAT_HOME",
    default_home_factory=lambda: Path.home() / ".codex",
    session_root_resolver=lambda home: home / "sessions",
    session_env_keys=("CODEX_SESSION_PATH", "CODEX_SESSION_FILE"),
    bin_env_key="AGENT_CHAT_CODEX_BIN",
    default_bin="codex",
)
