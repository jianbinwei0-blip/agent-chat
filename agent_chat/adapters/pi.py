from __future__ import annotations

from pathlib import Path

from agent_chat.types import AgentAdapter


ADAPTER = AgentAdapter(
    id="pi",
    label="Pi",
    default_home_env="AGENT_CHAT_PI_HOME",
    default_home_factory=lambda: Path.home() / ".pi" / "agent",
    session_root_resolver=lambda home: home / "sessions",
    session_env_keys=("PI_SESSION_PATH", "PI_CODING_AGENT_SESSION", "PI_SESSION_FILE"),
    bin_env_key="AGENT_CHAT_PI_BIN",
    default_bin="pi",
)
