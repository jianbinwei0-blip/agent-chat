from __future__ import annotations

from dataclasses import dataclass
from typing import Callable
from pathlib import Path


@dataclass(frozen=True)
class AgentAdapter:
    id: str
    label: str
    default_home_env: str
    default_home_factory: Callable[[], Path]
    session_root_resolver: Callable[[Path], Path]
    session_env_keys: tuple[str, ...]
    bin_env_key: str | None = None
    default_bin: str | None = None


@dataclass(frozen=True)
class TransportAdapter:
    id: str
    label: str
