from __future__ import annotations

from pathlib import Path

from agent_chat.types import AgentAdapter


ADAPTER = AgentAdapter(
    id="claude",
    label="Claude",
    default_home_env="CLAUDE_HOME",
    default_home_factory=lambda: Path.home() / ".claude",
    session_root_resolver=lambda home: Path((home / "projects")),
    session_env_keys=("CLAUDE_SESSION_PATH", "CLAUDE_TRANSCRIPT_PATH", "CODEX_SESSION_PATH", "CODEX_SESSION_FILE"),
    bin_env_key="AGENT_CHAT_CLAUDE_BIN",
    default_bin="claude",
)
