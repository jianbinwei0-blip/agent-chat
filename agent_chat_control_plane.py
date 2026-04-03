#!/usr/bin/env python3
"""Unified Codex/Claude messaging control plane (macOS).

This daemon combines:
- outbound needs-input notifications across all active Codex/Claude sessions
- inbound iMessage/Telegram command-reply intake and session routing
- optional notify-hook completion forwarding
- fallback outbound queue draining

Design goals:
- single canonical process + lock
- deterministic routing with explicit @ref and reply-thread correlation
- minimal outbound noise by default (needs_input + responded)
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import plistlib
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import time
import traceback
import urllib.parse as urllib_parse
import urllib.request as urllib_request
from pathlib import Path
from typing import Any, Callable

import agent_chat_dedupe
import agent_chat_notify as notify
import agent_chat_outbound_lib as outbound
import agent_chat_reply_lib as reply
from agent_chat.adapters import AGENT_ADAPTERS
from agent_chat.config import parse_transport_list, transport_mode_summary
from agent_chat.registry import (
    conversation_key as registry_conversation_key,
    normalize_conversation_bindings,
    normalize_runtime_bindings,
)

_MIN_PYTHON_VERSION = (3, 11)
_SESSION_UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_SESSION_STATUS_LINE_UUID_RE = re.compile(
    r"·\s*([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\s*·"
)

_DISCORD_PROGRESS_MODES = {"origin_scoped", "shared_status", "full_mirror", "local_only"}
_DESKTOP_ATTENTION_STATES = {
    "inline_visible",
    "notification_visible",
    "attention_badged",
    "waiting_for_user",
    "resolved",
    "none",
}
_ACTIVE_PROMPT_STATUSES = {"accepted", "working", "needs_input", "completed", "failed", "cancelled"}
_ACTIVE_PROMPT_ORIGINS = {"discord", "desktop"}


def _is_supported_python_version(version: tuple[int, int, int]) -> bool:
    return (int(version[0]), int(version[1])) >= _MIN_PYTHON_VERSION


def _build_python_upgrade_message(*, executable: str, version: tuple[int, int, int]) -> str:
    min_major, min_minor = _MIN_PYTHON_VERSION
    major, minor, micro = (int(version[0]), int(version[1]), int(version[2]))
    detected = f"{major}.{minor}.{micro}"
    return (
        f"agent_chat_control_plane.py requires Python {min_major}.{min_minor}+.\n"
        f"Detected: Python {detected} ({executable})\n"
        "Please upgrade Python and rerun this command.\n"
    )


def _ensure_supported_python_runtime() -> None:
    version = (
        int(getattr(sys.version_info, "major", 0)),
        int(getattr(sys.version_info, "minor", 0)),
        int(getattr(sys.version_info, "micro", 0)),
    )
    if not _is_supported_python_version(version):
        sys.stderr.write(
            _build_python_upgrade_message(
                executable=sys.executable,
                version=version,
            )
        )
        raise SystemExit(2)


_ensure_supported_python_runtime()
import tomllib


_SESSION_SCAN_INTERVAL_S = 2.0
_MAX_REGISTRY_ENTRIES = 256
_MAX_MESSAGE_INDEX_ENTRIES = 1024
_DEFAULT_REF_LEN = 8
_DEFAULT_MIN_PREFIX = 6
_DEFAULT_MAX_MESSAGE_CHARS = 1800
_DEFAULT_RESUME_TIMEOUT_S = 120.0
_DEFAULT_QUEUE_DRAIN_LIMIT = 25
_DEFAULT_INPUT_NEEDED_TEXT = "Waiting on approval / question / input."
_DEFAULT_TMUX_ACK_TIMEOUT_S = 2.0
_CHAT_DB_WARN_INTERVAL_S = 300.0
_DEFAULT_TELEGRAM_SEND_TIMEOUT_S = 10.0
_DEFAULT_TELEGRAM_SETUP_BOOTSTRAP_TIMEOUT_S = 90.0
_DEFAULT_TELEGRAM_API_BASE = "https://api.telegram.org"
_DEFAULT_DISCORD_API_BASE = "https://discord.com/api/v10"
_DEFAULT_DISCORD_ATTACHMENT_MAX_BYTES = 10 * 1024 * 1024
_DEFAULT_TMUX_NEW_SESSION_NAME = "agent"
_DEFAULT_TMUX_WINDOW_PREFIX = "agent"
_DEFAULT_SETUP_PERMISSIONS_TIMEOUT_S = 180.0
_DEFAULT_SETUP_PERMISSIONS_POLL_S = 1.0
_LAUNCHD_POST_START_VERIFY_DELAY_S = 0.8
_FULL_DISK_ACCESS_SETTINGS_URL = "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
_DEFAULT_FRIENDLY_PYTHON_APP_NAME = "AgentChatPython.app"
_HOMEBREW_INSTALL_URL = "https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh"
_TMUX_BIN_CANDIDATES = (
    "/opt/homebrew/bin/tmux",
    "/usr/local/bin/tmux",
    "/usr/bin/tmux",
)
_BREW_BIN_CANDIDATES = (
    "/opt/homebrew/bin/brew",
    "/usr/local/bin/brew",
)
_CODEX_BIN_CANDIDATES = (
    "/opt/homebrew/bin/codex",
    "/usr/local/bin/codex",
    "/usr/bin/codex",
)
_CLAUDE_BIN_CANDIDATES = (
    "/opt/homebrew/bin/claude",
    "/usr/local/bin/claude",
    "/usr/bin/claude",
)
_PI_BIN_CANDIDATES = (
    "/opt/homebrew/bin/pi",
    "/usr/local/bin/pi",
    "/usr/bin/pi",
)
_DEFAULT_LAUNCHD_LABEL = "com.agent-chat"
_INBOUND_DISABLED_LOG_MARKER = "[agent-chat] inbound disabled:"
_INBOUND_RESTORED_LOG_MARKER = "[agent-chat] inbound chat.db access restored."
_TCC_FDA_SERVICE = "SystemPolicyAllFiles"
_TCC_MISMATCH_SUBSTRING = "Failed to match existing code requirement for subject"
_MAX_DOCTOR_PANE_SAMPLE = 8
_HELP_TEXT = (
    "Commands:\n"
    "- list — recent sessions\n"
    "- where / context — explain this surface\n"
    "- status @<session_ref> — inspect one session\n"
    "- bind @<session_ref> — bind this Telegram topic or Discord channel/thread\n"
    "- @<session_ref> <instruction> — send work to a session\n"
    "- new <label>: <instruction> — start a new session\n"
    "- help"
)

_SUPPORTED_AGENTS = frozenset(AGENT_ADAPTERS.keys())

_chat_db_last_warning_text: str | None = None
_chat_db_last_warning_ts: float = 0.0
_chat_db_last_status: str | None = None


def _warn_stderr(message: str) -> None:
    ts = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    try:
        text = message.rstrip("\n")
        if not text:
            text = ""
        for line in text.splitlines() or [""]:
            if ts:
                sys.stderr.write(f"[{ts}] {line}\n")
            else:
                sys.stderr.write(line + "\n")
        sys.stderr.flush()
    except Exception:
        return


def _warn_chat_db_once(*, detail: str) -> None:
    global _chat_db_last_warning_text, _chat_db_last_warning_ts, _chat_db_last_status

    text = detail.strip()
    if not text:
        return
    _chat_db_last_status = "error"

    now = time.time()
    should_emit = (
        _chat_db_last_warning_text != text
        or (now - _chat_db_last_warning_ts) >= _CHAT_DB_WARN_INTERVAL_S
    )
    if not should_emit:
        return

    _chat_db_last_warning_text = text
    _chat_db_last_warning_ts = now
    _warn_stderr(
        (
            "[agent-chat] inbound disabled: "
            f"{text}. Grant Full Disk Access for the launchd runtime app or Python binary "
            "or run control plane from a Terminal/tmux session."
        )
    )


def _clear_chat_db_warning() -> None:
    global _chat_db_last_warning_text, _chat_db_last_status

    if _chat_db_last_status == "ok":
        return
    _chat_db_last_warning_text = None
    _chat_db_last_status = "ok"
    _warn_stderr(_INBOUND_RESTORED_LOG_MARKER)


def _resolve_resume_timeout_s() -> float | None:
    raw = os.environ.get("AGENT_CHAT_RESUME_TIMEOUT_S", "").strip()
    if not raw:
        return _DEFAULT_RESUME_TIMEOUT_S
    try:
        value = float(raw)
    except Exception:
        return _DEFAULT_RESUME_TIMEOUT_S
    return None if value <= 0 else value


def _normalize_agent(*, agent: str | None) -> str:
    candidate = agent.strip().lower() if isinstance(agent, str) else ""
    return candidate if candidate in _SUPPORTED_AGENTS else "codex"


def _current_agent() -> str:
    return _normalize_agent(agent=os.environ.get("AGENT_CHAT_AGENT"))


def _agent_display_name(*, agent: str | None = None) -> str:
    normalized = _normalize_agent(agent=agent if agent is not None else _current_agent())
    adapter = AGENT_ADAPTERS.get(normalized)
    return adapter.label if adapter is not None else "Codex"


def _agent_from_message_header(*, text: str | None) -> str | None:
    if not isinstance(text, str):
        return None
    pattern = "|".join(sorted(re.escape(item) for item in _SUPPORTED_AGENTS))
    m = re.match(rf"^\s*\[({pattern})\]\b", text, flags=re.IGNORECASE)
    if not m:
        return None
    return _normalize_agent(agent=m.group(1))


def _agent_command_keyword(*, agent: str | None = None) -> str:
    normalized = _normalize_agent(agent=agent if agent is not None else _current_agent())
    return normalized


def _agent_home_path(*, agent: str | None = None) -> Path:
    normalized = _normalize_agent(agent=agent if agent is not None else _current_agent())
    adapter = AGENT_ADAPTERS.get(normalized)
    if adapter is None:
        return Path.home() / ".codex"

    env_candidates: list[str] = []
    if normalized == "codex":
        env_candidates.extend(["AGENT_CHAT_CODEX_HOME", "AGENT_CHAT_HOME"])
    elif normalized == "claude":
        env_candidates.extend(["AGENT_CHAT_CLAUDE_HOME", "CLAUDE_HOME"])
    elif normalized == "pi":
        env_candidates.extend(["AGENT_CHAT_PI_HOME", "PI_CODING_AGENT_DIR"])
    env_candidates.append(adapter.default_home_env)

    for env_name in env_candidates:
        value = os.environ.get(env_name, "").strip()
        if value:
            return Path(value)
    return adapter.default_home_factory()


def _normalize_fs_path(*, path: Path | str) -> str:
    return os.path.normcase(os.path.abspath(os.path.expanduser(str(path))))


def _lookup_agent_home_path(*, agent: str, current_home: Path) -> Path:
    normalized = _normalize_agent(agent=agent)
    if normalized == "claude":
        override = os.environ.get("AGENT_CHAT_CLAUDE_HOME", "").strip()
        if override:
            return Path(override)
        return _agent_home_path(agent="claude")
    if normalized == "pi":
        override = os.environ.get("AGENT_CHAT_PI_HOME", "").strip() or os.environ.get("PI_CODING_AGENT_DIR", "").strip()
        if override:
            return Path(override)
        return _agent_home_path(agent="pi")

    override = os.environ.get("AGENT_CHAT_CODEX_HOME", "").strip()
    if override:
        return Path(override)

    codex_home_env = os.environ.get("AGENT_CHAT_HOME", "").strip()
    if not codex_home_env:
        return Path.home() / ".codex"

    codex_home = Path(codex_home_env)
    if _current_agent() == "codex":
        return codex_home

    claude_home_env = os.environ.get("CLAUDE_HOME", "").strip()
    pi_home_env = os.environ.get("AGENT_CHAT_PI_HOME", "").strip() or os.environ.get("PI_CODING_AGENT_DIR", "").strip()
    current_norm = _normalize_fs_path(path=current_home)
    codex_norm = _normalize_fs_path(path=codex_home)
    claude_norm = _normalize_fs_path(path=claude_home_env) if claude_home_env else ""
    pi_norm = _normalize_fs_path(path=pi_home_env) if pi_home_env else ""
    if codex_norm == current_norm or (claude_norm and codex_norm == claude_norm) or (pi_norm and codex_norm == pi_norm):
        return Path.home() / ".codex"

    return codex_home


def _agent_session_root(*, codex_home: Path, agent: str | None = None) -> Path:
    normalized = _normalize_agent(agent=agent if agent is not None else _current_agent())
    if normalized == "claude":
        projects_path = os.environ.get("CLAUDE_PROJECTS_PATH", "").strip()
        if projects_path:
            return Path(projects_path)
    if normalized == "pi":
        session_dir = os.environ.get("PI_SESSION_DIR", "").strip() or os.environ.get("AGENT_CHAT_PI_SESSION_DIR", "").strip()
        if session_dir:
            return Path(session_dir)
    adapter = AGENT_ADAPTERS.get(normalized)
    if adapter is None:
        return codex_home / "sessions"
    return adapter.session_root_resolver(codex_home)


def _session_path_env_keys(*, agent: str | None = None) -> tuple[str, ...]:
    normalized = _normalize_agent(agent=agent if agent is not None else _current_agent())
    adapter = AGENT_ADAPTERS.get(normalized)
    if adapter is None:
        return ("CODEX_SESSION_PATH", "CODEX_SESSION_FILE")
    return adapter.session_env_keys


def _shared_control_state_home(*, codex_home: Path) -> Path:
    override = os.environ.get("AGENT_CHAT_STATE_HOME", "").strip()
    if override:
        return Path(override)

    codex_home_env = os.environ.get("AGENT_CHAT_HOME", "").strip()
    if not codex_home_env:
        if _current_agent() != "codex":
            try:
                return _lookup_agent_home_path(agent="codex", current_home=codex_home)
            except Exception:
                return codex_home
        return codex_home

    try:
        return _lookup_agent_home_path(agent="codex", current_home=codex_home)
    except Exception:
        return codex_home


def _control_lock_path(*, codex_home: Path) -> Path:
    shared_home = _shared_control_state_home(codex_home=codex_home)
    return Path(
        os.environ.get(
            "AGENT_CHAT_CONTROL_LOCK",
            str(shared_home / "tmp" / "agent_chat_control_plane.lock"),
        )
    )


def _chat_db_path(*, codex_home: Path) -> Path:
    _ = codex_home
    env_path = os.environ.get("AGENT_IMESSAGE_CHAT_DB", "").strip()
    if env_path:
        return Path(env_path)

    primary = Path.home() / "Library" / "Messages" / "chat.db"
    if primary.exists():
        return primary

    backup_root = Path.home() / "Library" / "Messages" / "db-backups"
    latest: Path | None = None
    latest_mtime = -1.0
    try:
        for candidate in backup_root.glob("*/chat.db"):
            try:
                mtime = candidate.stat().st_mtime
            except Exception:
                continue
            if mtime > latest_mtime:
                latest = candidate
                latest_mtime = mtime
    except Exception:
        latest = None

    return latest if latest is not None else primary


def _codex_config_path(*, codex_home: Path) -> Path:
    env_path = os.environ.get("CODEX_CONFIG_PATH", "").strip()
    if env_path:
        return Path(env_path)
    return codex_home / "config.toml"


def _claude_settings_path(*, codex_home: Path) -> Path:
    env_path = os.environ.get("CLAUDE_SETTINGS_PATH", "").strip() or os.environ.get("CLAUDE_CONFIG_PATH", "").strip()
    if env_path:
        return Path(env_path)
    return codex_home / "settings.json"


def _is_control_plane_notify_command(command: str) -> bool:
    cmd = command.lower()
    if "notify" not in cmd:
        return False
    return "agent_chat_control_plane.py" in cmd


def _notify_hook_value_present(value: object) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        if not value:
            return False
        if not all(isinstance(part, str) for part in value):
            return False
        return any(part.strip() for part in value)
    return False


def _claude_hook_event_has_notify(*, hooks: dict[str, Any], event_name: str) -> bool:
    event_rules = hooks.get(event_name)
    if not isinstance(event_rules, list):
        return False
    for rule in event_rules:
        if not isinstance(rule, dict):
            continue
        commands = rule.get("hooks")
        if not isinstance(commands, list):
            continue
        for item in commands:
            if not isinstance(item, dict):
                continue
            if item.get("type") != "command":
                continue
            command = item.get("command")
            if isinstance(command, str) and command.strip():
                if _is_control_plane_notify_command(command):
                    return True
    return False


def _notify_hook_status_claude(*, codex_home: Path) -> dict[str, Any]:
    path = _claude_settings_path(codex_home=codex_home)
    status: dict[str, Any] = {
        "path": str(path),
        "exists": path.exists(),
        "top_level_present": False,
        "mis_scoped_present": False,
        "error": None,
    }
    if not path.exists():
        return status

    try:
        raw = path.read_text(encoding="utf-8")
    except Exception as exc:
        status["error"] = f"{type(exc).__name__}: {exc}"
        return status

    try:
        parsed = json.loads(raw) if raw.strip() else {}
    except Exception as exc:
        status["error"] = f"{type(exc).__name__}: {exc}"
        return status

    if not isinstance(parsed, dict):
        return status

    hooks = parsed.get("hooks")
    if not isinstance(hooks, dict):
        return status

    status["top_level_present"] = _claude_hook_event_has_notify(hooks=hooks, event_name="Notification") and (
        _claude_hook_event_has_notify(hooks=hooks, event_name="Stop")
    )
    return status


def _notify_hook_status(*, codex_home: Path) -> dict[str, Any]:
    current = _current_agent()
    if current == "claude":
        return _notify_hook_status_claude(codex_home=codex_home)
    if current == "pi":
        return {
            "path": None,
            "exists": True,
            "top_level_present": True,
            "mis_scoped_present": False,
            "error": None,
            "not_required": True,
        }

    path = _codex_config_path(codex_home=codex_home)
    status: dict[str, Any] = {
        "path": str(path),
        "exists": path.exists(),
        "top_level_present": False,
        "mis_scoped_present": False,
        "error": None,
    }
    if not path.exists():
        return status

    try:
        raw = path.read_text(encoding="utf-8")
    except Exception as exc:
        status["error"] = f"{type(exc).__name__}: {exc}"
        return status

    try:
        parsed = tomllib.loads(raw)
    except Exception as exc:
        status["error"] = f"{type(exc).__name__}: {exc}"
        return status

    if not isinstance(parsed, dict):
        return status

    top_level = parsed.get("notify")
    if _notify_hook_value_present(top_level):
        status["top_level_present"] = True

    notice = parsed.get("notice")
    if isinstance(notice, dict):
        model_migrations = notice.get("model_migrations")
        if isinstance(model_migrations, dict):
            misplaced = model_migrations.get("notify")
            if _notify_hook_value_present(misplaced):
                status["mis_scoped_present"] = True

    return status


def _resolve_python_bin_for_notify_hook(*, python_bin: str) -> str:
    python_text = python_bin.strip() if isinstance(python_bin, str) else ""
    if not python_text:
        return str(Path(sys.executable).resolve())
    if Path(python_text).is_absolute():
        return str(Path(python_text).resolve())
    resolved = shutil.which(python_text)
    if resolved:
        return str(Path(resolved).resolve())
    return str((Path.cwd() / python_text).resolve())


def _notify_hook_env_prefix(*, recipient: str, agent: str) -> str:
    recipient_text = recipient.strip()
    agent_text = _normalize_agent(agent=agent)
    items: list[str] = []

    if recipient_text:
        items.append(f"AGENT_IMESSAGE_TO={shlex.quote(recipient_text)}")
    items.append(f"AGENT_CHAT_AGENT={shlex.quote(agent_text)}")

    transport_mode = _transport_mode()
    transport_list = _transport_list(mode=transport_mode)
    if transport_mode != "imessage":
        items.append(f"AGENT_CHAT_TRANSPORT={shlex.quote(transport_mode)}")
    if transport_list != ["imessage"]:
        items.append(f"AGENT_CHAT_TRANSPORTS={shlex.quote(','.join(transport_list))}")

    if _transport_telegram_enabled(mode=transport_mode):
        token = _telegram_bot_token()
        chat_id = _telegram_chat_id()
        chat_ids_raw = os.environ.get("AGENT_TELEGRAM_CHAT_IDS", "")
        chat_ids = chat_ids_raw.strip() if isinstance(chat_ids_raw, str) else ""
        if token:
            items.append(f"AGENT_TELEGRAM_BOT_TOKEN={shlex.quote(token)}")
        if chat_id:
            items.append(f"AGENT_TELEGRAM_CHAT_ID={shlex.quote(chat_id)}")
        if chat_ids:
            items.append(f"AGENT_TELEGRAM_CHAT_IDS={shlex.quote(chat_ids)}")
        api_base_raw = os.environ.get("AGENT_TELEGRAM_API_BASE", "")
        api_base = api_base_raw.strip() if isinstance(api_base_raw, str) else ""
        if api_base:
            items.append(f"AGENT_TELEGRAM_API_BASE={shlex.quote(api_base)}")

    if _transport_discord_enabled(mode=transport_mode):
        token = _discord_bot_token()
        channel_id = _discord_channel_id()
        channel_ids_raw = os.environ.get("AGENT_DISCORD_CHANNEL_IDS", "")
        owner_ids_raw = os.environ.get("AGENT_DISCORD_OWNER_USER_IDS", "")
        if token:
            items.append(f"AGENT_DISCORD_BOT_TOKEN={shlex.quote(token)}")
        if channel_id:
            items.append(f"AGENT_DISCORD_CHANNEL_ID={shlex.quote(channel_id)}")
        control_channel_raw = os.environ.get("AGENT_DISCORD_CONTROL_CHANNEL_ID", "")
        session_category_raw = os.environ.get("AGENT_DISCORD_SESSION_CATEGORY_ID", "")
        session_prefix_raw = os.environ.get("AGENT_DISCORD_SESSION_CHANNEL_PREFIX", "")
        if isinstance(channel_ids_raw, str) and channel_ids_raw.strip():
            items.append(f"AGENT_DISCORD_CHANNEL_IDS={shlex.quote(channel_ids_raw.strip())}")
        if isinstance(owner_ids_raw, str) and owner_ids_raw.strip():
            items.append(f"AGENT_DISCORD_OWNER_USER_IDS={shlex.quote(owner_ids_raw.strip())}")
        if _discord_session_channels_enabled():
            items.append("AGENT_DISCORD_SESSION_CHANNELS=1")
        if isinstance(control_channel_raw, str) and control_channel_raw.strip():
            items.append(f"AGENT_DISCORD_CONTROL_CHANNEL_ID={shlex.quote(control_channel_raw.strip())}")
        if isinstance(session_category_raw, str) and session_category_raw.strip():
            items.append(f"AGENT_DISCORD_SESSION_CATEGORY_ID={shlex.quote(session_category_raw.strip())}")
        if isinstance(session_prefix_raw, str) and session_prefix_raw.strip():
            items.append(f"AGENT_DISCORD_SESSION_CHANNEL_PREFIX={shlex.quote(session_prefix_raw.strip())}")

    return " ".join(items)


def _build_notify_hook_command(*, recipient: str, python_bin: str, script_path: Path, agent: str) -> list[str]:
    recipient_text = recipient.strip()
    python_text = python_bin.strip()
    script_text = str(script_path)
    agent_text = _normalize_agent(agent=agent)
    env_prefix = _notify_hook_env_prefix(recipient=recipient_text, agent=agent_text)
    notify_cmd = (
        'payload="${1:-}"; if [ -z "$payload" ]; then payload="${CODEX_NOTIFY_PAYLOAD:-}"; fi; '
        'if [ -z "$payload" ]; then payload="$(cat)"; fi; '
        f'if [ -n "$payload" ]; then {env_prefix} '
        f'{shlex.quote(python_text)} {shlex.quote(script_text)} '
        'notify "$payload" >/dev/null 2>&1 || true; fi'
    )
    return ["bash", "-lc", notify_cmd, "--"]


def _build_notify_hook_shell_command(*, recipient: str, python_bin: str, script_path: Path, agent: str) -> str:
    return shlex.join(
        _build_notify_hook_command(
            recipient=recipient,
            python_bin=python_bin,
            script_path=script_path,
            agent=agent,
        )
    )


def _toml_table_name_from_header(line: str) -> str | None:
    stripped = line.strip()
    m_array = re.match(r"^\[\[\s*([^\[\]]+?)\s*\]\]\s*(?:#.*)?$", stripped)
    if m_array:
        return m_array.group(1).strip()
    m_table = re.match(r"^\[\s*([^\[\]]+?)\s*\]\s*(?:#.*)?$", stripped)
    if m_table:
        return m_table.group(1).strip()
    return None


def _upsert_notify_hook_text(*, raw: str, notify_line: str) -> str:
    lines = raw.splitlines()
    table_name: str | None = None
    kept: list[str] = []

    for line in lines:
        header_table = _toml_table_name_from_header(line)
        if header_table is not None:
            table_name = header_table
            kept.append(line)
            continue

        if re.match(r"^\s*notify\s*=", line):
            # Ensure notify lives at top-level and clean up misscoped entries.
            if table_name is None or table_name == "notice.model_migrations":
                continue
        kept.append(line)

    insert_at = len(kept)
    for idx, line in enumerate(kept):
        if _toml_table_name_from_header(line) is not None:
            insert_at = idx
            break
    kept.insert(insert_at, notify_line)

    return "\n".join(kept).rstrip("\n") + "\n"


def _upsert_claude_notify_hook_text(*, raw: str, hook_command: str) -> str:
    parsed: dict[str, Any]
    if raw.strip():
        loaded = json.loads(raw)
        if not isinstance(loaded, dict):
            raise ValueError("Expected object at top-level in Claude settings.")
        parsed = loaded
    else:
        parsed = {}

    hooks = parsed.get("hooks")
    if not isinstance(hooks, dict):
        hooks = {}

    for event_name in ("Notification", "Stop"):
        event_rules = hooks.get(event_name)
        if not isinstance(event_rules, list):
            event_rules = []

        target_rule: dict[str, Any] | None = None
        for rule in event_rules:
            if not isinstance(rule, dict):
                continue
            matcher = rule.get("matcher")
            if matcher is None or (isinstance(matcher, str) and not matcher.strip()):
                target_rule = rule
                break

        if target_rule is None:
            target_rule = {"matcher": "", "hooks": []}
            event_rules.append(target_rule)
        else:
            target_rule["matcher"] = ""

        command_hooks = target_rule.get("hooks")
        if not isinstance(command_hooks, list):
            command_hooks = []

        cleaned_hooks: list[object] = []
        exists = False
        for item in command_hooks:
            if not isinstance(item, dict):
                cleaned_hooks.append(item)
                continue
            if item.get("type") != "command":
                cleaned_hooks.append(item)
                continue
            command = item.get("command")
            if isinstance(command, str):
                if _is_control_plane_notify_command(command):
                    if command.strip() == hook_command:
                        exists = True
                    continue
                if command.strip() == hook_command:
                    exists = True
            cleaned_hooks.append(item)
        if not exists:
            cleaned_hooks.append({"type": "command", "command": hook_command})

        target_rule["hooks"] = cleaned_hooks
        hooks[event_name] = event_rules

    parsed["hooks"] = hooks
    return json.dumps(parsed, ensure_ascii=False, indent=2).rstrip("\n") + "\n"


def _run_setup_notify_hook(
    *,
    codex_home: Path,
    recipient: str,
    python_bin: str,
    script_path: Path,
) -> int:
    agent = _current_agent()
    transport_mode = _transport_mode()
    for setup_err in (
        _validate_telegram_setup_requirements(transport_mode=transport_mode),
        _validate_discord_setup_requirements(transport_mode=transport_mode),
    ):
        if isinstance(setup_err, str):
            sys.stdout.write(setup_err)
            return 1

    recipient_text = _normalize_recipient(recipient) if recipient.strip() else ""
    if _transport_imessage_enabled(mode=transport_mode) and not recipient_text:
        sys.stdout.write("AGENT_IMESSAGE_TO is required. Provide --recipient or set AGENT_IMESSAGE_TO.\n")
        return 1

    python_text = _resolve_python_bin_for_notify_hook(python_bin=python_bin)
    script_abs = script_path.expanduser().resolve()
    if not script_abs.exists():
        sys.stdout.write(f"Control-plane script not found: {script_abs}\n")
        return 1

    if agent == "pi":
        sys.stdout.write(
            "Pi integration does not install a notify hook; session polling and routing are sufficient.\n"
        )
        sys.stdout.write(f"Python binary: {python_text}\n")
        sys.stdout.write(f"Script: {script_abs}\n")
        return 0

    config_path = _claude_settings_path(codex_home=codex_home) if agent == "claude" else _codex_config_path(
        codex_home=codex_home
    )
    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        sys.stdout.write(f"Failed creating config directory: {type(exc).__name__}: {exc}\n")
        return 1

    try:
        raw = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
    except Exception as exc:
        sys.stdout.write(f"Failed reading config: {type(exc).__name__}: {exc}\n")
        return 1

    notify_line = "notify = " + json.dumps(
        _build_notify_hook_command(
            recipient=recipient_text,
            python_bin=python_text,
            script_path=script_abs,
            agent=agent,
        ),
        ensure_ascii=False,
    )
    if agent == "claude":
        hook_command = _build_notify_hook_shell_command(
            recipient=recipient_text,
            python_bin=python_text,
            script_path=script_abs,
            agent=agent,
        )
        try:
            updated = _upsert_claude_notify_hook_text(raw=raw, hook_command=hook_command)
        except Exception as exc:
            sys.stdout.write(f"Failed updating Claude settings: {type(exc).__name__}: {exc}\n")
            return 1
    else:
        updated = _upsert_notify_hook_text(raw=raw, notify_line=notify_line)
    try:
        config_path.write_text(updated, encoding="utf-8")
    except Exception as exc:
        sys.stdout.write(f"Failed writing config: {type(exc).__name__}: {exc}\n")
        return 1

    sys.stdout.write(f"Updated notify hook in {config_path}\n")
    sys.stdout.write(f"Recipient: {recipient_text or '(none)'}\n")
    sys.stdout.write(f"Python binary: {python_text}\n")
    sys.stdout.write(f"Script: {script_abs}\n")
    sys.stdout.write(f"Restart {_agent_display_name(agent=agent)} to apply notify hook changes.\n")
    return 0


def _acquire_single_instance_lock(*, codex_home: Path) -> object | None:
    lock_path = _control_lock_path(codex_home=codex_home)
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        f = lock_path.open("a", encoding="utf-8")
    except Exception:
        return object()

    try:
        import fcntl
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


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        if not path.exists():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _write_json(path: Path, data: dict[str, Any]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)
    except Exception:
        return


def _registry_path(*, codex_home: Path) -> Path:
    return Path(
        os.environ.get(
            "AGENT_CHAT_SESSION_REGISTRY",
            str(codex_home / "tmp" / "agent_chat_session_registry.json"),
        )
    )


def _message_index_path(*, codex_home: Path) -> Path:
    return Path(
        os.environ.get(
            "AGENT_CHAT_MESSAGE_SESSION_INDEX",
            str(codex_home / "tmp" / "agent_chat_message_session_index.json"),
        )
    )


def _outbound_cursor_path(*, codex_home: Path) -> Path:
    return Path(
        os.environ.get(
            "AGENT_CHAT_CONTROL_OUTBOUND_CURSOR",
            str(codex_home / "tmp" / "agent_chat_control_outbound_cursor.json"),
        )
    )


def _inbound_cursor_path(*, codex_home: Path) -> Path:
    shared_home = _shared_control_state_home(codex_home=codex_home)
    return Path(
        os.environ.get(
            "AGENT_IMESSAGE_INBOUND_CURSOR",
            str(shared_home / "tmp" / "imessage_inbound_cursor.json"),
        )
    )


def _queue_path(*, codex_home: Path) -> Path:
    return Path(
        os.environ.get(
            "AGENT_CHAT_QUEUE",
            str(codex_home / "tmp" / "agent_chat_queue.jsonl"),
        )
    )


def _transport_list(*, mode: str | None = None) -> list[str]:
    if isinstance(mode, str) and mode.strip():
        return parse_transport_list(mode, None)
    return parse_transport_list(
        os.environ.get("AGENT_CHAT_TRANSPORTS"),
        os.environ.get("AGENT_CHAT_TRANSPORT", "imessage"),
    )


def _transport_mode() -> str:
    return transport_mode_summary(_transport_list())


def _transport_imessage_enabled(*, mode: str | None = None) -> bool:
    return "imessage" in _transport_list(mode=mode)


def _transport_telegram_enabled(*, mode: str | None = None) -> bool:
    return "telegram" in _transport_list(mode=mode)


def _transport_discord_enabled(*, mode: str | None = None) -> bool:
    return "discord" in _transport_list(mode=mode)


def _telegram_bot_token() -> str | None:
    raw = os.environ.get("AGENT_TELEGRAM_BOT_TOKEN", "")
    token = raw.strip() if isinstance(raw, str) else ""
    return token or None


def _telegram_chat_id() -> str | None:
    raw = os.environ.get("AGENT_TELEGRAM_CHAT_ID", "")
    chat_id = raw.strip() if isinstance(raw, str) else ""
    return chat_id or None


def _telegram_chat_ids() -> list[str]:
    out: list[str] = []
    seen: set[str] = set()

    raw_multi = os.environ.get("AGENT_TELEGRAM_CHAT_IDS", "")
    if isinstance(raw_multi, str) and raw_multi.strip():
        for part in re.split(r"[\s,]+", raw_multi.strip()):
            chat_id = part.strip()
            if not chat_id or chat_id in seen:
                continue
            seen.add(chat_id)
            out.append(chat_id)

    primary = _telegram_chat_id()
    if isinstance(primary, str):
        chat_id = primary.strip()
        if chat_id and chat_id not in seen:
            seen.add(chat_id)
            out.append(chat_id)

    return out


def _telegram_owner_user_ids() -> set[str]:
    out: set[str] = set()

    raw_multi = os.environ.get("AGENT_TELEGRAM_OWNER_USER_IDS", "")
    if isinstance(raw_multi, str) and raw_multi.strip():
        for part in re.split(r"[\s,]+", raw_multi.strip()):
            candidate = part.strip()
            if candidate:
                out.add(candidate)

    if out:
        return out

    # Backward-compatible fallback: infer a likely owner id from configured
    # private chat ids (positive numeric ids) when explicit owner ids are unset.
    for chat_id in _telegram_chat_ids():
        trimmed = chat_id.strip()
        if not trimmed:
            continue
        if trimmed.startswith("-"):
            continue
        out.add(trimmed)
    return out


def _telegram_sender_is_owner(*, sender_user_id: str | None) -> bool:
    candidate = sender_user_id.strip() if isinstance(sender_user_id, str) else ""
    if not candidate:
        return False
    owners = _telegram_owner_user_ids()
    return candidate in owners


def _telegram_accept_all_chats() -> bool:
    return _env_enabled("AGENT_TELEGRAM_ACCEPT_ALL_CHATS", default=False)


def _telegram_general_topic_thread_id() -> int | None:
    raw = os.environ.get("AGENT_TELEGRAM_GENERAL_TOPIC_THREAD_ID")
    if isinstance(raw, str):
        trimmed = raw.strip()
        if trimmed:
            return _normalize_telegram_thread_id(trimmed)
    # Telegram forum supergroups use topic id 1 for #general.
    return 1


def _normalize_telegram_thread_id(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None
        try:
            parsed = int(raw)
        except Exception:
            return None
        return parsed if parsed > 0 else None
    return None


def _telegram_thread_key(*, chat_id: str | None, thread_id: int | None) -> str | None:
    chat = chat_id.strip() if isinstance(chat_id, str) else ""
    normalized_thread_id = _normalize_telegram_thread_id(thread_id)
    if not chat or normalized_thread_id is None:
        return None
    return f"{chat}:{normalized_thread_id}"


def _telegram_thread_chat_id_from_key(*, thread_key: str | None) -> str | None:
    key = thread_key.strip() if isinstance(thread_key, str) else ""
    if ":" not in key:
        return None
    chat_raw = key.rsplit(":", 1)[0]
    chat = chat_raw.strip()
    if not chat:
        return None
    thread_raw = key.rsplit(":", 1)[-1]
    if _normalize_telegram_thread_id(thread_raw) is None:
        return None
    return chat


def _normalize_telegram_thread_key(*, thread_key: str | None) -> str | None:
    key = thread_key.strip() if isinstance(thread_key, str) else ""
    if ":" not in key:
        return None
    chat = key.rsplit(":", 1)[0].strip()
    thread_raw = key.rsplit(":", 1)[-1]
    thread_id = _normalize_telegram_thread_id(thread_raw)
    if not chat or thread_id is None:
        return None
    return _telegram_thread_key(chat_id=chat, thread_id=thread_id)


def _telegram_thread_id_from_key(*, thread_key: str | None) -> int | None:
    key = thread_key.strip() if isinstance(thread_key, str) else ""
    normalized_key = _normalize_telegram_thread_key(thread_key=key)
    if normalized_key is None:
        return None
    thread_raw = normalized_key.rsplit(":", 1)[-1]
    return _normalize_telegram_thread_id(thread_raw)


def _telegram_bot_token_setup_instructions() -> str:
    return (
        "AGENT_TELEGRAM_BOT_TOKEN is required when AGENT_CHAT_TRANSPORT includes Telegram.\n"
        "How to get a bot token:\n"
        "  1. Open Telegram and chat with @BotFather.\n"
        "  2. Run /newbot to create a bot (or /token for an existing bot).\n"
        "  3. Copy the HTTP API token and export:\n"
        "     AGENT_TELEGRAM_BOT_TOKEN=\"<bot token>\"\n"
    )


def _validate_telegram_setup_requirements(*, transport_mode: str) -> str | None:
    if not _transport_telegram_enabled(mode=transport_mode):
        return None
    if _telegram_bot_token():
        return None
    return _telegram_bot_token_setup_instructions()


def _discord_bot_token_setup_instructions() -> str:
    return (
        "AGENT_DISCORD_BOT_TOKEN is required when AGENT_CHAT_TRANSPORT includes Discord.\n"
        "Create a bot in the Discord developer portal, add it to your server, and export:\n"
        "  AGENT_DISCORD_BOT_TOKEN=\"<bot token>\"\n"
        "Also set AGENT_DISCORD_CHANNEL_ID or AGENT_DISCORD_CHANNEL_IDS to the channel/thread allowlist.\n"
    )


def _validate_discord_setup_requirements(*, transport_mode: str) -> str | None:
    if not _transport_discord_enabled(mode=transport_mode):
        return None
    if _discord_bot_token():
        return None
    return _discord_bot_token_setup_instructions()


def _bootstrap_telegram_group_chat_id(
    *,
    codex_home: Path,
    timeout_s: float,
    open_link: bool,
) -> tuple[str | None, str | None]:
    token = _telegram_bot_token()
    if not isinstance(token, str) or not token.strip():
        return None, _telegram_bot_token_setup_instructions().strip()
    token_text = token.strip()

    timeout_window_s = float(timeout_s) if timeout_s > 0 else _DEFAULT_TELEGRAM_SETUP_BOOTSTRAP_TIMEOUT_S
    timeout_window_s = max(1.0, timeout_window_s)
    after_update_id = _load_telegram_inbound_cursor(codex_home=codex_home)

    bot_username: str | None = None
    get_me_url = f"{_telegram_api_base()}/bot{token_text}/getMe"
    try:
        with urllib_request.urlopen(urllib_request.Request(get_me_url), timeout=_DEFAULT_TELEGRAM_SEND_TIMEOUT_S) as response:
            raw = response.read()
        parsed = json.loads(raw.decode("utf-8", errors="replace"))
        result = parsed.get("result") if isinstance(parsed, dict) else None
        username_raw = result.get("username") if isinstance(result, dict) else None
        if isinstance(username_raw, str):
            candidate = username_raw.strip()
            if candidate:
                bot_username = candidate
    except Exception:
        bot_username = None

    if open_link and isinstance(bot_username, str):
        deep_link = f"https://t.me/{bot_username}?startgroup=true"
        try:
            subprocess.run(
                ["open", deep_link],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass

    sys.stdout.write(
        "Telegram setup: detecting target group/supergroup chat id from new inbound messages.\n"
    )
    if isinstance(bot_username, str):
        sys.stdout.write(
            f"Action required: add @{bot_username} to the target topic/group and send any plain-text message.\n"
        )
    else:
        sys.stdout.write(
            "Action required: add the bot to the target topic/group and send any plain-text message.\n"
        )
    sys.stdout.flush()

    deadline = time.monotonic() + timeout_window_s
    while time.monotonic() < deadline:
        updates = _fetch_telegram_updates(
            token=token_text,
            chat_ids=None,
            after_update_id=after_update_id,
        )
        if updates:
            max_update_id = max(row[0] for row in updates)
            if max_update_id > after_update_id:
                after_update_id = max_update_id
                _save_telegram_inbound_cursor(
                    codex_home=codex_home,
                    last_update_id=after_update_id,
                )
            for _, _, _, _, incoming_chat_id, _ in updates:
                chat_id_text = incoming_chat_id.strip() if isinstance(incoming_chat_id, str) else ""
                if not chat_id_text:
                    continue
                # Telegram groups/supergroups use negative chat ids.
                if not chat_id_text.startswith("-"):
                    continue
                return chat_id_text, None
        time.sleep(1.0)

    return (
        None,
        (
            "timed out waiting for a Telegram group message. "
            "Send a plain-text message in the target topic/group and rerun setup-launchd."
        ),
    )


def _telegram_api_base() -> str:
    raw = os.environ.get("AGENT_TELEGRAM_API_BASE", _DEFAULT_TELEGRAM_API_BASE)
    base = raw.strip() if isinstance(raw, str) else _DEFAULT_TELEGRAM_API_BASE
    if not base:
        base = _DEFAULT_TELEGRAM_API_BASE
    return base.rstrip("/")


def _telegram_inbound_cursor_path(*, codex_home: Path) -> Path:
    shared_home = _shared_control_state_home(codex_home=codex_home)
    return Path(
        os.environ.get(
            "AGENT_TELEGRAM_INBOUND_CURSOR",
            str(shared_home / "tmp" / "telegram_inbound_cursor.json"),
        )
    )


def _load_telegram_inbound_cursor(*, codex_home: Path) -> int:
    raw = _read_json(_telegram_inbound_cursor_path(codex_home=codex_home))
    if not isinstance(raw, dict):
        return 0
    last_update_id = raw.get("last_update_id")
    return int(last_update_id) if isinstance(last_update_id, int) else 0


def _save_telegram_inbound_cursor(*, codex_home: Path, last_update_id: int) -> None:
    payload: dict[str, Any] = {
        "last_update_id": int(last_update_id),
        "ts": int(time.time()),
    }
    _write_json(_telegram_inbound_cursor_path(codex_home=codex_home), payload)


def _send_telegram_message(
    *,
    token: str,
    chat_id: str,
    message: str,
    message_thread_id: int | None = None,
    timeout_s: float = _DEFAULT_TELEGRAM_SEND_TIMEOUT_S,
) -> bool:
    token_text = token.strip()
    chat_id_text = chat_id.strip()
    if not token_text or not chat_id_text:
        return False

    url = f"{_telegram_api_base()}/bot{token_text}/sendMessage"
    payload_fields: dict[str, str] = {"chat_id": chat_id_text, "text": message}
    normalized_thread_id = _normalize_telegram_thread_id(message_thread_id)
    if normalized_thread_id is not None:
        payload_fields["message_thread_id"] = str(normalized_thread_id)
    payload = urllib_parse.urlencode(payload_fields).encode("utf-8")
    request = urllib_request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib_request.urlopen(request, timeout=float(timeout_s)) as response:
            raw = response.read()
    except Exception:
        return False

    try:
        parsed = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return False
    return isinstance(parsed, dict) and bool(parsed.get("ok"))


def _fetch_telegram_updates(
    *,
    token: str,
    chat_ids: list[str] | None,
    after_update_id: int,
) -> list[tuple[int, str, str | None, int | None, str, str | None]]:
    token_text = token.strip()
    if not token_text:
        return []

    params: dict[str, str] = {
        "timeout": "0",
        "allowed_updates": json.dumps(["message", "edited_message", "channel_post", "edited_channel_post"]),
    }
    if int(after_update_id) > 0:
        params["offset"] = str(int(after_update_id) + 1)

    trace_enabled = _env_enabled("AGENT_CHAT_TRACE", default=False)

    url = f"{_telegram_api_base()}/bot{token_text}/getUpdates?{urllib_parse.urlencode(params)}"
    request = urllib_request.Request(url)
    try:
        with urllib_request.urlopen(request, timeout=_DEFAULT_TELEGRAM_SEND_TIMEOUT_S) as response:
            raw = response.read()
    except Exception as exc:
        if trace_enabled:
            _warn_stderr(f"[agent-chat][trace] telegram getUpdates failed: {type(exc).__name__}: {exc}")
        return []

    try:
        parsed = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception as exc:
        if trace_enabled:
            _warn_stderr(f"[agent-chat][trace] telegram getUpdates decode failed: {type(exc).__name__}: {exc}")
        return []

    if not isinstance(parsed, dict) or not bool(parsed.get("ok")):
        if trace_enabled:
            description = parsed.get("description") if isinstance(parsed, dict) else None
            _warn_stderr(
                f"[agent-chat][trace] telegram getUpdates non-ok response: {description if isinstance(description, str) else parsed!r}"
            )
        return []
    result = parsed.get("result")
    if not isinstance(result, list):
        if trace_enabled:
            _warn_stderr("[agent-chat][trace] telegram getUpdates response missing list result")
        return []
    if trace_enabled and result:
        _warn_stderr(
            f"[agent-chat][trace] telegram getUpdates fetched={len(result)} after_update_id={after_update_id}"
        )

    allowed_chat_ids: set[str] = set()
    for candidate in chat_ids or []:
        if not isinstance(candidate, str):
            continue
        normalized = candidate.strip()
        if normalized:
            allowed_chat_ids.add(normalized)

    out: list[tuple[int, str, str | None, int | None, str, str | None]] = []
    for update in result:
        if not isinstance(update, dict):
            continue
        update_id = update.get("update_id")
        if not isinstance(update_id, int):
            continue
        message_like: dict[str, Any] | None = None
        for key in ("message", "edited_message", "channel_post", "edited_channel_post"):
            candidate = update.get(key)
            if isinstance(candidate, dict):
                message_like = candidate
                break
        if not isinstance(message_like, dict):
            out.append((update_id, "", None, None, "", None))
            continue
        chat = message_like.get("chat")
        if not isinstance(chat, dict):
            out.append((update_id, "", None, None, "", None))
            continue
        incoming_chat_id = chat.get("id")
        incoming_chat_text = str(incoming_chat_id).strip() if incoming_chat_id is not None else ""
        if not incoming_chat_text:
            out.append((update_id, "", None, None, "", None))
            continue
        if allowed_chat_ids and incoming_chat_text not in allowed_chat_ids:
            out.append((update_id, "", None, None, incoming_chat_text, None))
            continue
        sender_user_id: str | None = None
        sender_raw = message_like.get("from")
        if isinstance(sender_raw, dict):
            sender_id_raw = sender_raw.get("id")
            sender_id_text = str(sender_id_raw).strip() if sender_id_raw is not None else ""
            if sender_id_text:
                sender_user_id = sender_id_text
        text_raw = message_like.get("text")
        if isinstance(text_raw, str):
            normalized_text = text_raw.strip()
        else:
            caption_raw = message_like.get("caption")
            normalized_text = caption_raw.strip() if isinstance(caption_raw, str) else ""
        message_thread_id = _normalize_telegram_thread_id(message_like.get("message_thread_id"))
        reply_reference_text: str | None = None
        reply_to_message = message_like.get("reply_to_message")
        if isinstance(reply_to_message, dict):
            reply_text = reply_to_message.get("text")
            if isinstance(reply_text, str):
                trimmed_reply_text = reply_text.strip()
                if trimmed_reply_text:
                    reply_reference_text = trimmed_reply_text

        out.append((update_id, normalized_text, reply_reference_text, message_thread_id, incoming_chat_text, sender_user_id))
    return out


def _discord_bot_token() -> str | None:
    raw = os.environ.get("AGENT_DISCORD_BOT_TOKEN", "")
    token = raw.strip() if isinstance(raw, str) else ""
    return token or None


def _discord_channel_id() -> str | None:
    raw = os.environ.get("AGENT_DISCORD_CHANNEL_ID", "")
    channel_id = raw.strip() if isinstance(raw, str) else ""
    return channel_id or None


def _discord_channel_ids() -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    primary = _discord_channel_id()
    if isinstance(primary, str) and primary.strip():
        seen.add(primary.strip())
        values.append(primary.strip())
    raw_multi = os.environ.get("AGENT_DISCORD_CHANNEL_IDS", "")
    if isinstance(raw_multi, str) and raw_multi.strip():
        for part in raw_multi.split(","):
            text = part.strip()
            if text and text not in seen:
                seen.add(text)
                values.append(text)
    return values


def _discord_session_channels_enabled() -> bool:
    return _env_enabled("AGENT_DISCORD_SESSION_CHANNELS", default=False)


def _discord_control_channel_id() -> str | None:
    raw = os.environ.get("AGENT_DISCORD_CONTROL_CHANNEL_ID", "")
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    return _discord_channel_id()


def _discord_control_channel_ids() -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    primary = _discord_control_channel_id()
    if isinstance(primary, str) and primary.strip():
        seen.add(primary.strip())
        values.append(primary.strip())
    for channel_id in _discord_channel_ids():
        if channel_id not in seen:
            seen.add(channel_id)
            values.append(channel_id)
    return values


def _discord_session_category_id() -> str | None:
    raw = os.environ.get("AGENT_DISCORD_SESSION_CATEGORY_ID", "")
    return raw.strip() if isinstance(raw, str) and raw.strip() else None


def _discord_session_channel_prefix() -> str | None:
    raw = os.environ.get("AGENT_DISCORD_SESSION_CHANNEL_PREFIX", "")
    return raw.strip().lower() if isinstance(raw, str) and raw.strip() else None


def _discord_owner_user_ids() -> set[str]:
    owners: set[str] = set()
    raw_multi = os.environ.get("AGENT_DISCORD_OWNER_USER_IDS", "")
    if isinstance(raw_multi, str) and raw_multi.strip():
        for part in raw_multi.split(","):
            text = part.strip()
            if text:
                owners.add(text)
    return owners


def _discord_sender_is_owner(*, sender_user_id: str | None) -> bool:
    sender = sender_user_id.strip() if isinstance(sender_user_id, str) else ""
    return bool(sender) and sender in _discord_owner_user_ids()


def _discord_accept_all_channels() -> bool:
    return _env_enabled("AGENT_DISCORD_ACCEPT_ALL_CHANNELS", default=False)


def _discord_api_base() -> str:
    raw = os.environ.get("AGENT_DISCORD_API_BASE", _DEFAULT_DISCORD_API_BASE)
    base = raw.strip() if isinstance(raw, str) else _DEFAULT_DISCORD_API_BASE
    return (base or _DEFAULT_DISCORD_API_BASE).rstrip("/")


def _discord_inbound_cursor_path(*, codex_home: Path) -> Path:
    shared_home = _shared_control_state_home(codex_home=codex_home)
    return Path(
        os.environ.get(
            "AGENT_DISCORD_INBOUND_CURSOR",
            str(shared_home / "tmp" / "discord_inbound_cursor.json"),
        )
    )


def _load_discord_inbound_cursor(*, codex_home: Path) -> dict[str, Any]:
    raw = _read_json(_discord_inbound_cursor_path(codex_home=codex_home))
    return raw if isinstance(raw, dict) else {"channels": {}, "bot_user_id": None}


def _save_discord_inbound_cursor(*, codex_home: Path, state: dict[str, Any]) -> None:
    payload = {
        "channels": state.get("channels") if isinstance(state.get("channels"), dict) else {},
        "bot_user_id": state.get("bot_user_id") if isinstance(state.get("bot_user_id"), str) else None,
        "ts": int(time.time()),
    }
    _write_json(_discord_inbound_cursor_path(codex_home=codex_home), payload)


def _discord_request(*, token: str, path: str, method: str = "GET", data: dict[str, Any] | None = None) -> dict[str, Any] | list[Any] | None:
    token_text = token.strip()
    if not token_text:
        return None
    url = f"{_discord_api_base()}/{path.lstrip('/')}"
    body: bytes | None = None
    headers = {
        "Authorization": f"Bot {token_text}",
        "User-Agent": "agent-chat/0.1",
    }
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib_request.Request(url, data=body, headers=headers, method=method.upper())
    try:
        with urllib_request.urlopen(request, timeout=_DEFAULT_TELEGRAM_SEND_TIMEOUT_S) as response:
            raw = response.read()
    except Exception:
        return None
    try:
        return json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return None


def _discord_attachment_max_bytes() -> int:
    raw = os.environ.get("AGENT_CHAT_DISCORD_ATTACHMENT_MAX_BYTES", "").strip()
    if not raw:
        return _DEFAULT_DISCORD_ATTACHMENT_MAX_BYTES
    try:
        return max(1024, int(raw))
    except Exception:
        return _DEFAULT_DISCORD_ATTACHMENT_MAX_BYTES



def _discord_attachment_root(*, codex_home: Path) -> Path:
    shared_home = _shared_control_state_home(codex_home=codex_home)
    override = os.environ.get("AGENT_CHAT_DISCORD_ATTACHMENT_DIR", "").strip()
    if override:
        return Path(override)
    return shared_home / "tmp" / "discord_attachments"



def _sanitize_discord_attachment_filename(filename: str | None) -> str:
    raw = filename.strip() if isinstance(filename, str) else ""
    candidate = Path(raw).name if raw else "attachment.bin"
    candidate = re.sub(r"[^A-Za-z0-9._-]+", "_", candidate).strip("._") or "attachment.bin"
    return candidate[:160]



def _normalize_discord_attachment_payloads(raw: object) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for idx, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            continue
        attachment_id = item.get("id") if isinstance(item.get("id"), str) and item.get("id").strip() else f"attachment-{idx}"
        attachment_id = str(attachment_id).strip()
        if attachment_id in seen_ids:
            continue
        url = item.get("url") if isinstance(item.get("url"), str) and item.get("url").strip() else None
        proxy_url = item.get("proxy_url") if isinstance(item.get("proxy_url"), str) and item.get("proxy_url").strip() else None
        download_url = proxy_url or url
        if not isinstance(download_url, str) or not download_url.strip():
            continue
        filename = _sanitize_discord_attachment_filename(
            item.get("filename") if isinstance(item.get("filename"), str) else None
        )
        size = item.get("size") if isinstance(item.get("size"), int) and int(item.get("size")) >= 0 else None
        content_type = item.get("content_type") if isinstance(item.get("content_type"), str) and item.get("content_type").strip() else None
        out.append(
            {
                "id": attachment_id,
                "filename": filename,
                "url": download_url.strip(),
                "size": size,
                "content_type": content_type.strip() if isinstance(content_type, str) else None,
            }
        )
        seen_ids.add(attachment_id)
    return out



def _download_discord_attachment(*, url: str, destination: Path, max_bytes: int) -> tuple[int | None, str | None]:
    request = urllib_request.Request(url.strip(), headers={"User-Agent": "agent-chat/0.1"})
    destination.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = destination.with_suffix(destination.suffix + ".tmp")
    try:
        with urllib_request.urlopen(request, timeout=_DEFAULT_TELEGRAM_SEND_TIMEOUT_S) as response:
            content_length_raw = response.headers.get("Content-Length")
            if isinstance(content_length_raw, str) and content_length_raw.strip():
                try:
                    if int(content_length_raw.strip()) > int(max_bytes):
                        return None, f"exceeds max size {int(max_bytes)} bytes"
                except Exception:
                    pass
            total = 0
            with tmp_path.open("wb") as handle:
                while True:
                    chunk = response.read(64 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > int(max_bytes):
                        handle.close()
                        try:
                            tmp_path.unlink()
                        except Exception:
                            pass
                        return None, f"exceeds max size {int(max_bytes)} bytes"
                    handle.write(chunk)
        tmp_path.replace(destination)
        return total, None
    except Exception as exc:
        try:
            tmp_path.unlink()
        except Exception:
            pass
        return None, f"{type(exc).__name__}: {exc}"



def _store_discord_attachments_for_session(
    *,
    codex_home: Path,
    session_id: str,
    message_id: int,
    attachments: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    sid = session_id.strip()
    if not sid or not attachments:
        return [], []

    root = _discord_attachment_root(codex_home=codex_home) / sid / str(int(message_id))
    max_bytes = _discord_attachment_max_bytes()
    saved: list[dict[str, Any]] = []
    errors: list[str] = []

    for idx, attachment in enumerate(attachments, start=1):
        filename = _sanitize_discord_attachment_filename(
            attachment.get("filename") if isinstance(attachment.get("filename"), str) else None
        )
        size = attachment.get("size") if isinstance(attachment.get("size"), int) else None
        if isinstance(size, int) and size > int(max_bytes):
            errors.append(f"{filename}: exceeds max size {int(max_bytes)} bytes")
            continue
        download_url = attachment.get("url") if isinstance(attachment.get("url"), str) else None
        if not isinstance(download_url, str) or not download_url.strip():
            errors.append(f"{filename}: missing download url")
            continue
        dest = root / f"{idx:02d}-{filename}"
        downloaded_size, err = _download_discord_attachment(
            url=download_url,
            destination=dest,
            max_bytes=max_bytes,
        )
        if err:
            errors.append(f"{filename}: {err}")
            continue
        saved.append(
            {
                "filename": filename,
                "path": str(dest),
                "size": downloaded_size if isinstance(downloaded_size, int) else size,
                "content_type": attachment.get("content_type") if isinstance(attachment.get("content_type"), str) else None,
            }
        )
    return saved, errors



def _augment_prompt_with_discord_attachments(
    *,
    prompt: str,
    saved_attachments: list[dict[str, Any]],
    attachment_errors: list[str],
) -> str:
    if not saved_attachments and not attachment_errors:
        return prompt.strip()

    lines = ["Discord attachment handoff:"]
    if saved_attachments:
        lines.append("The user attached file(s) in Discord. Inspect them before continuing:")
        for attachment in saved_attachments:
            filename = attachment.get("filename") if isinstance(attachment.get("filename"), str) else "attachment"
            path = attachment.get("path") if isinstance(attachment.get("path"), str) else "-"
            size = attachment.get("size") if isinstance(attachment.get("size"), int) else None
            content_type = attachment.get("content_type") if isinstance(attachment.get("content_type"), str) else None
            details: list[str] = []
            if isinstance(size, int):
                details.append(f"{size} bytes")
            if isinstance(content_type, str) and content_type.strip():
                details.append(content_type.strip())
            suffix = f" ({', '.join(details)})" if details else ""
            lines.append(f"- {filename}{suffix}: {path}")
    if attachment_errors:
        lines.append("Attachment download issues:")
        for err in attachment_errors[:5]:
            lines.append(f"- {err}")

    user_prompt = prompt.strip()
    lines.append("")
    if user_prompt:
        lines.append("User message:")
        lines.append(user_prompt)
    else:
        lines.append("User message: Please inspect the attached files and continue.")
    return "\n".join(lines).strip()



def _discord_attachment_notice_text(*, saved_attachments: list[dict[str, Any]], attachment_errors: list[str]) -> str:
    if not saved_attachments and not attachment_errors:
        return ""
    parts: list[str] = []
    if saved_attachments:
        count = len(saved_attachments)
        noun = "file" if count == 1 else "files"
        parts.append(f"Attached {count} {noun}.")
    if attachment_errors:
        count = len(attachment_errors)
        noun = "attachment" if count == 1 else "attachments"
        parts.append(f"{count} {noun} could not be downloaded.")
    return " ".join(parts)



def _discord_bot_user_id(*, token: str, codex_home: Path) -> str | None:
    state = _load_discord_inbound_cursor(codex_home=codex_home)
    cached = state.get("bot_user_id") if isinstance(state.get("bot_user_id"), str) else None
    if isinstance(cached, str) and cached.strip():
        return cached.strip()
    parsed = _discord_request(token=token, path="users/@me")
    if not isinstance(parsed, dict):
        return None
    user_id = parsed.get("id")
    if not isinstance(user_id, str) or not user_id.strip():
        return None
    state["bot_user_id"] = user_id.strip()
    _save_discord_inbound_cursor(codex_home=codex_home, state=state)
    return user_id.strip()


def _discord_get_channel(*, token: str, channel_id: str) -> dict[str, Any] | None:
    channel_text = channel_id.strip() if isinstance(channel_id, str) else ""
    if not channel_text:
        return None
    parsed = _discord_request(token=token, path=f"channels/{channel_text}")
    return parsed if isinstance(parsed, dict) else None


def _discord_sanitize_channel_name(*, value: str) -> str:
    raw = value.strip().lower() if isinstance(value, str) else ""
    raw = re.sub(r"[^a-z0-9-]+", "-", raw)
    raw = re.sub(r"-+", "-", raw).strip("-")
    if not raw:
        raw = "session"
    return raw[:90].rstrip("-") or "session"


def _discord_session_channel_name(*, registry: dict[str, Any], session_id: str) -> str:
    sid = session_id.strip()
    sessions = registry.get("sessions") if isinstance(registry.get("sessions"), dict) else {}
    rec = sessions.get(sid) if isinstance(sessions, dict) else None
    alias = rec.get("alias") if isinstance(rec, dict) and isinstance(rec.get("alias"), str) else None
    cwd = rec.get("cwd") if isinstance(rec, dict) and isinstance(rec.get("cwd"), str) else None
    agent = _normalize_agent(agent=rec.get("agent") if isinstance(rec, dict) and isinstance(rec.get("agent"), str) else None)

    label = alias.strip() if isinstance(alias, str) and alias.strip() else ""
    if not label and isinstance(cwd, str) and cwd.strip():
        label = Path(cwd.strip()).name or "session"
    if not label:
        label = "session"

    pieces: list[str] = []
    prefix = _discord_session_channel_prefix()
    if isinstance(prefix, str) and prefix.strip():
        pieces.append(prefix.strip())
    pieces.extend([agent, label, _session_ref(sid)])
    return _discord_sanitize_channel_name(value="-".join(piece for piece in pieces if piece))


def _discord_create_text_channel(
    *,
    token: str,
    guild_id: str,
    name: str,
    parent_id: str | None = None,
) -> tuple[str | None, str | None]:
    guild_text = guild_id.strip() if isinstance(guild_id, str) else ""
    channel_name = _discord_sanitize_channel_name(value=name)
    if not guild_text or not channel_name:
        return None, None
    payload: dict[str, Any] = {"name": channel_name, "type": 0}
    if isinstance(parent_id, str) and parent_id.strip():
        payload["parent_id"] = parent_id.strip()
    parsed = _discord_request(
        token=token,
        path=f"guilds/{guild_text}/channels",
        method="POST",
        data=payload,
    )
    if not isinstance(parsed, dict):
        _warn_stderr(
            "[agent-chat] Discord session channel create failed. "
            "Check bot permissions (Manage Channels) and category access."
        )
        return None, None
    channel_id = parsed.get("id") if isinstance(parsed.get("id"), str) else None
    created_name = parsed.get("name") if isinstance(parsed.get("name"), str) else channel_name
    if not isinstance(channel_id, str) or not channel_id.strip():
        _warn_stderr(
            "[agent-chat] Discord session channel create returned no channel id. "
            "Check bot permissions (Manage Channels) and category access."
        )
        return None, None
    return channel_id.strip(), created_name


def _discord_store_session_channel_metadata(
    *,
    registry: dict[str, Any],
    session_id: str,
    channel_id: str,
    channel_name: str | None,
    parent_id: str | None = None,
    guild_id: str | None = None,
) -> None:
    fields: dict[str, Any] = {"discord_channel_id": channel_id.strip()}
    if isinstance(channel_name, str) and channel_name.strip():
        fields["discord_channel_name"] = channel_name.strip()
    if isinstance(parent_id, str) and parent_id.strip():
        fields["discord_channel_parent_id"] = parent_id.strip()
    if isinstance(guild_id, str) and guild_id.strip():
        fields["discord_guild_id"] = guild_id.strip()
    _upsert_session(registry=registry, session_id=session_id, fields=fields)
    _set_default_discord_progress_mode_for_session(registry=registry, session_id=session_id)


def _discord_session_channel_for_session(*, registry: dict[str, Any], session_id: str | None) -> str | None:
    sid = session_id.strip() if isinstance(session_id, str) else ""
    if not sid:
        return None
    sessions = registry.get("sessions")
    rec = sessions.get(sid) if isinstance(sessions, dict) else None
    if not isinstance(rec, dict):
        return None
    channel_id = rec.get("discord_channel_id")
    if isinstance(channel_id, str) and channel_id.strip():
        return channel_id.strip()
    return None


def _lookup_session_by_discord_channel_id(*, registry: dict[str, Any], channel_id: str | None) -> str | None:
    channel_text = channel_id.strip() if isinstance(channel_id, str) else ""
    if not channel_text or _discord_is_control_channel(channel_id=channel_text):
        return None
    sessions = registry.get("sessions")
    if isinstance(sessions, dict):
        for sid, rec in sessions.items():
            if not isinstance(sid, str) or not isinstance(rec, dict):
                continue
            bound_channel_id = rec.get("discord_channel_id")
            if isinstance(bound_channel_id, str) and bound_channel_id.strip() == channel_text:
                return sid
    return _lookup_session_by_conversation(
        registry=registry,
        transport="discord",
        channel_id=channel_text,
        thread_id=0,
    )


def _discord_is_control_channel(*, channel_id: str | None) -> bool:
    channel_text = channel_id.strip() if isinstance(channel_id, str) else ""
    if not channel_text:
        return False
    return channel_text in set(_discord_control_channel_ids())


def _should_bind_discord_context(*, channel_id: str | None, thread_id: str | None) -> bool:
    if isinstance(thread_id, str) and thread_id.strip():
        return True
    if _discord_session_channels_enabled() and _discord_is_control_channel(channel_id=channel_id):
        return False
    return True


def _discord_ensure_session_channel(
    *,
    codex_home: Path,
    registry: dict[str, Any],
    session_id: str,
) -> tuple[str | None, str | None]:
    sid = session_id.strip()
    if not sid:
        return None, None
    existing = _discord_session_channel_for_session(registry=registry, session_id=sid)
    if isinstance(existing, str) and existing.strip() and not _discord_is_control_channel(channel_id=existing):
        return existing.strip(), None

    token = _discord_bot_token()
    control_channel_id = _discord_control_channel_id()
    if not isinstance(token, str) or not token.strip() or not isinstance(control_channel_id, str) or not control_channel_id.strip():
        return None, None

    control_channel = _discord_get_channel(token=token.strip(), channel_id=control_channel_id.strip())
    if not isinstance(control_channel, dict):
        _warn_stderr("[agent-chat] Discord control channel lookup failed; cannot create session channel.")
        return None, None
    guild_id = control_channel.get("guild_id") if isinstance(control_channel.get("guild_id"), str) else None
    if not isinstance(guild_id, str) or not guild_id.strip():
        return None, None

    parent_id = _discord_session_category_id()
    if not isinstance(parent_id, str) or not parent_id.strip():
        parent_id = control_channel.get("parent_id") if isinstance(control_channel.get("parent_id"), str) else None

    channel_name = _discord_session_channel_name(registry=registry, session_id=sid)
    created_channel_id, created_name = _discord_create_text_channel(
        token=token.strip(),
        guild_id=guild_id.strip(),
        name=channel_name,
        parent_id=parent_id,
    )
    if not isinstance(created_channel_id, str) or not created_channel_id.strip():
        return None, None

    _bind_conversation_to_session(
        registry=registry,
        transport="discord",
        channel_id=created_channel_id.strip(),
        thread_id=None,
        session_id=sid,
    )
    _discord_store_session_channel_metadata(
        registry=registry,
        session_id=sid,
        channel_id=created_channel_id.strip(),
        channel_name=created_name,
        parent_id=parent_id,
        guild_id=guild_id,
    )
    _save_registry(codex_home=codex_home, registry=registry)
    return created_channel_id.strip(), created_name


def _send_discord_message(*, token: str, channel_id: str, message: str) -> bool:
    channel_text = channel_id.strip() if isinstance(channel_id, str) else ""
    if not channel_text:
        return False
    parsed = _discord_request(
        token=token,
        path=f"channels/{channel_text}/messages",
        method="POST",
        data={"content": message},
    )
    return isinstance(parsed, dict) and bool(parsed.get("id"))


def _fetch_discord_active_thread_ids(*, token: str, channel_id: str) -> list[str]:
    channel_text = channel_id.strip() if isinstance(channel_id, str) else ""
    if not channel_text:
        return []
    parsed = _discord_request(token=token, path=f"channels/{channel_text}/threads/active")
    if not isinstance(parsed, dict):
        return []
    threads = parsed.get("threads")
    if not isinstance(threads, list):
        return []
    out: list[str] = []
    for item in threads:
        if not isinstance(item, dict):
            continue
        thread_id = item.get("id")
        if isinstance(thread_id, str) and thread_id.strip():
            out.append(thread_id.strip())
    return out


def _discord_poll_channel_ids(*, registry: dict[str, Any]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for channel_id in _discord_control_channel_ids():
        if channel_id not in seen:
            seen.add(channel_id)
            out.append(channel_id)
    bindings = registry.get("conversation_bindings")
    if isinstance(bindings, dict):
        for key in bindings.keys():
            if not isinstance(key, str) or not key.startswith("discord:"):
                continue
            _, channel_id, thread_raw = key.split(":", 2)
            for candidate in (channel_id.strip(), thread_raw.strip() if thread_raw.strip() not in {"", "0"} else ""):
                if candidate and candidate not in seen:
                    seen.add(candidate)
                    out.append(candidate)
    return out


def _fetch_discord_updates(
    *,
    token: str,
    registry: dict[str, Any],
    codex_home: Path,
) -> tuple[list[tuple[int, str, str | None, str | None, str, str | None, str | None, list[dict[str, Any]]]], dict[str, Any]]:
    state = _load_discord_inbound_cursor(codex_home=codex_home)
    channels_state = state.get("channels") if isinstance(state.get("channels"), dict) else {}
    bot_user_id = _discord_bot_user_id(token=token, codex_home=codex_home)
    poll_ids: list[str] = []
    seen_poll: set[str] = set()
    for channel_id in _discord_poll_channel_ids(registry=registry):
        if channel_id not in seen_poll:
            seen_poll.add(channel_id)
            poll_ids.append(channel_id)
        for thread_id in _fetch_discord_active_thread_ids(token=token, channel_id=channel_id):
            if thread_id not in seen_poll:
                seen_poll.add(thread_id)
                poll_ids.append(thread_id)

    out: list[tuple[int, str, str | None, str | None, str, str | None, str | None, list[dict[str, Any]]]] = []
    for poll_id in poll_ids:
        after_id = channels_state.get(poll_id)
        params = "limit=50"
        if isinstance(after_id, str) and after_id.strip():
            params += f"&after={urllib_parse.quote(after_id.strip())}"
        parsed = _discord_request(token=token, path=f"channels/{poll_id}/messages?{params}")
        if not isinstance(parsed, list):
            continue
        for item in reversed(parsed):
            if not isinstance(item, dict):
                continue
            message_id = item.get("id")
            if not isinstance(message_id, str) or not message_id.strip():
                continue
            channels_state[poll_id] = message_id.strip()
            author = item.get("author") if isinstance(item.get("author"), dict) else {}
            author_id = author.get("id") if isinstance(author.get("id"), str) else None
            if bot_user_id and author_id == bot_user_id:
                continue
            content = item.get("content") if isinstance(item.get("content"), str) else ""
            attachments = _normalize_discord_attachment_payloads(item.get("attachments"))
            if not content.strip() and not attachments:
                continue
            referenced = item.get("referenced_message") if isinstance(item.get("referenced_message"), dict) else None
            referenced_text = referenced.get("content") if isinstance(referenced, dict) and isinstance(referenced.get("content"), str) else None
            parent_id = item.get("channel_id") if isinstance(item.get("channel_id"), str) else poll_id
            out.append((
                int(message_id),
                content.strip(),
                referenced_text.strip() if isinstance(referenced_text, str) and referenced_text.strip() else None,
                parent_id,
                poll_id,
                author_id.strip() if isinstance(author_id, str) and author_id.strip() else None,
                item.get("guild_id") if isinstance(item.get("guild_id"), str) else None,
                attachments,
            ))
    state["channels"] = channels_state
    if isinstance(bot_user_id, str) and bot_user_id.strip():
        state["bot_user_id"] = bot_user_id.strip()
    return out, state


def _process_inbound_discord_replies(
    *,
    codex_home: Path,
    recipient: str,
    after_message_id: int,
    max_message_chars: int,
    min_prefix: int,
    dry_run: bool,
    resume_timeout_s: float | None,
    trace: bool,
) -> int:
    token = _discord_bot_token()
    if not isinstance(token, str) or not token.strip():
        return after_message_id

    registry = _load_registry(codex_home=codex_home)
    updates, state = _fetch_discord_updates(token=token.strip(), registry=registry, codex_home=codex_home)
    if not updates:
        _save_discord_inbound_cursor(codex_home=codex_home, state=state)
        return after_message_id

    update_context_map: dict[int, dict[str, Any]] = {}
    update_reply_text_map: dict[int, str] = {}
    max_seen = after_message_id
    for message_id, text, reply_text, parent_id, channel_id, sender_user_id, guild_id, attachments in updates:
        if message_id <= after_message_id:
            continue
        max_seen = max(max_seen, message_id)
        update_context_map[message_id] = {
            "transport": "discord",
            "discord_parent_channel_id": parent_id,
            "discord_channel_id": channel_id,
            "discord_sender_user_id": sender_user_id,
            "discord_guild_id": guild_id,
            "discord_attachments": attachments,
        }
        if isinstance(reply_text, str) and reply_text.strip():
            update_reply_text_map[message_id] = reply_text.strip()

    def _fetch_virtual_replies(*, conn: sqlite3.Connection, after_rowid: int, handle_ids: list[str]) -> list[tuple[int, str, str | None]]:
        del conn, handle_ids
        rows: list[tuple[int, str, str | None]] = []
        for message_id, text, _, _, _, _, _, attachments in updates:
            if message_id <= after_rowid:
                continue
            effective_text = text if isinstance(text, str) else ""
            if not effective_text.strip() and isinstance(attachments, list) and attachments:
                effective_text = "continue"
            rows.append((message_id, effective_text, None))
        rows.sort(key=lambda item: item[0])
        return rows

    def _virtual_reference_guids(*, conn: sqlite3.Connection, rowid: int, fallback_guid: str | None) -> list[str]:
        del conn, rowid, fallback_guid
        return []

    def _virtual_reference_texts(*, conn: sqlite3.Connection, rowid: int, fallback_guid: str | None) -> list[str] | None:
        del conn, fallback_guid
        reply_text = update_reply_text_map.get(int(rowid))
        if isinstance(reply_text, str) and reply_text.strip():
            return [reply_text.strip()]
        return []

    def _virtual_row_contexts(*, conn: sqlite3.Connection, after_rowid: int, handle_ids: list[str]) -> dict[int, dict[str, Any]]:
        del conn, handle_ids
        return {
            int(message_id): context
            for message_id, context in update_context_map.items()
            if int(message_id) > int(after_rowid)
        }

    temp_conn = sqlite3.connect(":memory:")
    try:
        rowid = _process_inbound_replies(
            codex_home=codex_home,
            conn=temp_conn,
            recipient=recipient,
            handle_ids=[],
            after_rowid=after_message_id,
            max_message_chars=max_message_chars,
            min_prefix=min_prefix,
            dry_run=dry_run,
            resume_timeout_s=resume_timeout_s,
            trace=trace,
            fetch_replies_fn=_fetch_virtual_replies,
            reference_guids_fn=_virtual_reference_guids,
            reference_texts_fn=_virtual_reference_texts,
            row_contexts_fn=_virtual_row_contexts,
        )
    finally:
        try:
            temp_conn.close()
        except Exception:
            pass

    _save_discord_inbound_cursor(codex_home=codex_home, state=state)
    return max(max_seen, rowid)


def _attention_index_path(*, codex_home: Path) -> Path:
    return Path(
        os.environ.get(
            "AGENT_CHAT_ATTENTION_INDEX",
            str(codex_home / "tmp" / "agent_chat_attention_index.json"),
        )
    )


def _last_attention_state_path(*, codex_home: Path) -> Path:
    return Path(
        os.environ.get(
            "AGENT_CHAT_LAST_ATTENTION",
            str(codex_home / "tmp" / "agent_chat_last_attention.json"),
        )
    )


def _load_attention_index(*, codex_home: Path) -> dict[str, Any] | None:
    return _read_json(_attention_index_path(codex_home=codex_home))


def _load_last_attention_state(*, codex_home: Path) -> dict[str, Any] | None:
    return _read_json(_last_attention_state_path(codex_home=codex_home))


def _coerce_nonempty_str(value: object) -> str | None:
    if isinstance(value, str):
        trimmed = value.strip()
        if trimmed:
            return trimmed
    return None


def _coerce_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _persist_attention_state(
    *,
    codex_home: Path,
    registry: dict[str, Any],
    session_id: str,
    session_rec: dict[str, Any] | None,
    state: str,
    tmux_pane: str | None = None,
    tmux_socket: str | None = None,
    extra_fields: dict[str, Any] | None = None,
) -> None:
    sid = session_id.strip() if isinstance(session_id, str) else ""
    if not sid:
        return

    normalized_state = _normalize_desktop_attention_state(state=state)
    ts = int(time.time())
    normalized_pane = tmux_pane.strip() if isinstance(tmux_pane, str) and tmux_pane.strip() else None
    normalized_socket = _normalize_tmux_socket(tmux_socket=tmux_socket)

    session_fields: dict[str, Any] = {
        "desktop_attention_state": normalized_state,
        "last_desktop_attention_ts": ts,
        "last_attention_ts": ts,
    }
    if normalized_pane:
        session_fields["tmux_pane"] = normalized_pane
    if normalized_socket:
        session_fields["tmux_socket"] = normalized_socket
    if isinstance(extra_fields, dict):
        session_fields.update(extra_fields)

    if isinstance(session_rec, dict):
        session_rec.update(session_fields)
    _upsert_session(registry=registry, session_id=sid, fields=session_fields)

    sessions = registry.get("sessions")
    active_rec = sessions.get(sid) if isinstance(sessions, dict) else None
    if not isinstance(active_rec, dict):
        active_rec = session_rec if isinstance(session_rec, dict) else {}

    record: dict[str, Any] = {
        "ts": ts,
        "session_id": sid,
        "desktop_attention_state": normalized_state,
    }
    for key in ("agent", "cwd", "session_path"):
        value = _coerce_nonempty_str(active_rec.get(key) if isinstance(active_rec, dict) else None)
        if value:
            record[key] = value
    if normalized_pane:
        record["tmux_pane"] = normalized_pane
    if normalized_socket:
        record["tmux_socket"] = normalized_socket

    _write_json(_last_attention_state_path(codex_home=codex_home), record)
    attention_index = _read_json(_attention_index_path(codex_home=codex_home)) or {}
    attention_index[sid] = record
    try:
        attention_index = notify._prune_attention_index(attention_index, now_ts=ts)
    except Exception:
        pass
    _write_json(_attention_index_path(codex_home=codex_home), attention_index)


def _select_attention_context(
    *,
    session_id: str,
    attention_index: dict[str, Any] | None,
    last_attention_state: dict[str, Any] | None,
) -> dict[str, str]:
    keys = (
        "agent",
        "cwd",
        "tmux_pane",
        "tmux_socket",
        "session_path",
    )
    out: dict[str, str] = {}

    primary = attention_index.get(session_id) if isinstance(attention_index, dict) else None
    if isinstance(primary, dict):
        for key in keys:
            value = _coerce_nonempty_str(primary.get(key))
            if value:
                out[key] = value

    state_matches_session = False
    if isinstance(last_attention_state, dict):
        state_session_id = _coerce_nonempty_str(last_attention_state.get("session_id"))
        state_matches_session = state_session_id is None or state_session_id == session_id

    if state_matches_session and isinstance(last_attention_state, dict):
        for key in keys:
            if key in out:
                continue
            value = _coerce_nonempty_str(last_attention_state.get(key))
            if value:
                out[key] = value

    return out


def _apply_attention_context_to_session(
    *,
    session_id: str,
    session_rec: dict[str, Any] | None,
    attention_index: dict[str, Any] | None,
    last_attention_state: dict[str, Any] | None,
) -> None:
    if not isinstance(session_rec, dict):
        return
    merged = _select_attention_context(
        session_id=session_id,
        attention_index=attention_index,
        last_attention_state=last_attention_state,
    )
    for key, value in merged.items():
        existing = session_rec.get(key)
        if isinstance(existing, str) and existing.strip():
            continue
        session_rec[key] = value


def _read_lock_pid(lock_path: Path) -> int | None:
    try:
        raw = lock_path.read_text(encoding="utf-8").strip()
    except Exception:
        return None
    if not raw:
        return None
    try:
        pid = int(raw)
    except Exception:
        return None
    return pid if pid > 0 else None


def _is_pid_alive(pid: int | None) -> bool:
    if not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except Exception:
        return False
    return True


def _queue_stats(queue_path: Path) -> dict[str, Any]:
    stats: dict[str, Any] = {
        "path": str(queue_path),
        "exists": queue_path.exists(),
        "size_bytes": 0,
        "lines": 0,
        "latest_ts": None,
    }
    if not queue_path.exists():
        return stats

    try:
        stats["size_bytes"] = int(queue_path.stat().st_size)
    except Exception:
        stats["size_bytes"] = 0

    try:
        lines = 0
        latest_ts: int | None = None
        with queue_path.open("r", encoding="utf-8", errors="replace") as f:
            for raw in f:
                if not raw.strip():
                    continue
                lines += 1
                try:
                    event = json.loads(raw)
                except Exception:
                    continue
                if not isinstance(event, dict):
                    continue
                ts = event.get("ts")
                if isinstance(ts, int):
                    latest_ts = ts if latest_ts is None else max(latest_ts, ts)
        stats["lines"] = lines
        stats["latest_ts"] = latest_ts
    except Exception:
        return stats

    return stats


def _enqueue_fallback_event(
    *,
    queue_path: Path,
    transport: str,
    recipient: str,
    message: str,
    telegram_message_thread_id: int | None = None,
) -> None:
    queue_path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "ts": int(time.time()),
        "transport": transport,
        "to": recipient,
        "text": message,
    }
    normalized_thread_id = _normalize_telegram_thread_id(telegram_message_thread_id)
    if normalized_thread_id is not None:
        record["telegram_message_thread_id"] = normalized_thread_id
    with queue_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False))
        f.write("\n")


def _send_message_with_transport(
    *,
    transport: str,
    recipient: str,
    message: str,
    telegram_message_thread_id: int | None = None,
    discord_channel_id: str | None = None,
) -> bool:
    if transport == "imessage":
        recipient_text = recipient.strip()
        if not recipient_text:
            return False
        return bool(outbound._send_imessage(recipient=recipient_text, message=message))
    if transport == "telegram":
        token = _telegram_bot_token()
        if not token:
            return False
        chat_id = recipient.strip()
        if not chat_id:
            return False
        return _send_telegram_message(
            token=token,
            chat_id=chat_id,
            message=message,
            message_thread_id=telegram_message_thread_id,
        )
    if transport == "discord":
        token = _discord_bot_token()
        channel_id = discord_channel_id.strip() if isinstance(discord_channel_id, str) and discord_channel_id.strip() else recipient.strip()
        if not token or not channel_id:
            return False
        return _send_discord_message(token=token, channel_id=channel_id, message=message)
    return False


def _deliver_message_across_transports(
    *,
    codex_home: Path,
    imessage_recipient: str,
    message: str,
    telegram_chat_id: str | None = None,
    telegram_message_thread_id: int | None = None,
    discord_channel_id: str | None = None,
    deliver_to_imessage: bool = True,
    deliver_to_telegram: bool = True,
    deliver_to_discord: bool = True,
) -> bool:
    queue_path = _queue_path(codex_home=codex_home)
    mode = _transport_mode()
    sent_any = False
    attempted = False

    if deliver_to_imessage and _transport_imessage_enabled(mode=mode):
        recipient_text = imessage_recipient.strip()
        if recipient_text:
            attempted = True
            if _send_message_with_transport(transport="imessage", recipient=recipient_text, message=message):
                sent_any = True
            else:
                _enqueue_fallback_event(
                    queue_path=queue_path,
                    transport="imessage",
                    recipient=recipient_text,
                    message=message,
                )

    if deliver_to_telegram and _transport_telegram_enabled(mode=mode):
        chat_id = telegram_chat_id if isinstance(telegram_chat_id, str) and telegram_chat_id.strip() else _telegram_chat_id()
        if isinstance(chat_id, str) and chat_id.strip():
            attempted = True
            chat_id_text = chat_id.strip()
            if _send_message_with_transport(
                transport="telegram",
                recipient=chat_id_text,
                message=message,
                telegram_message_thread_id=telegram_message_thread_id,
            ):
                sent_any = True
            else:
                _enqueue_fallback_event(
                    queue_path=queue_path,
                    transport="telegram",
                    recipient=chat_id_text,
                    message=message,
                    telegram_message_thread_id=telegram_message_thread_id,
                )

    if deliver_to_discord and _transport_discord_enabled(mode=mode):
        channel_id = discord_channel_id if isinstance(discord_channel_id, str) and discord_channel_id.strip() else _discord_channel_id()
        if isinstance(channel_id, str) and channel_id.strip():
            attempted = True
            channel_id_text = channel_id.strip()
            if _send_message_with_transport(
                transport="discord",
                recipient=channel_id_text,
                message=message,
                discord_channel_id=channel_id_text,
            ):
                sent_any = True
            else:
                _enqueue_fallback_event(
                    queue_path=queue_path,
                    transport="discord",
                    recipient=channel_id_text,
                    message=message,
                )

    return sent_any if attempted else False


def _drain_fallback_queue(
    *,
    codex_home: Path,
    dry_run: bool,
    max_items: int,
) -> dict[str, Any]:
    queue_path = _queue_path(codex_home=codex_home)
    stats: dict[str, Any] = {
        "attempted": 0,
        "sent": 0,
        "retained": 0,
        "parse_errors": 0,
        "disabled": max_items <= 0,
        "path": str(queue_path),
    }
    if max_items <= 0:
        return stats
    if not queue_path.exists():
        return stats

    staging_path = queue_path.with_name(f"{queue_path.name}.drain.{os.getpid()}")
    try:
        os.replace(queue_path, staging_path)
    except FileNotFoundError:
        return stats
    except Exception as exc:
        stats["error"] = f"rename_failed:{type(exc).__name__}"
        return stats

    retained_lines: list[str] = []
    try:
        with staging_path.open("r", encoding="utf-8", errors="replace") as f:
            for raw in f:
                line = raw.rstrip("\n")
                if not line.strip():
                    continue

                if stats["attempted"] >= max_items:
                    retained_lines.append(line)
                    stats["retained"] = int(stats["retained"]) + 1
                    continue

                stats["attempted"] = int(stats["attempted"]) + 1
                try:
                    event = json.loads(line)
                except Exception:
                    retained_lines.append(line)
                    stats["retained"] = int(stats["retained"]) + 1
                    stats["parse_errors"] = int(stats["parse_errors"]) + 1
                    continue

                if not isinstance(event, dict):
                    retained_lines.append(line)
                    stats["retained"] = int(stats["retained"]) + 1
                    stats["parse_errors"] = int(stats["parse_errors"]) + 1
                    continue

                transport = event.get("transport")
                transport_text = transport.strip().lower() if isinstance(transport, str) else "imessage"
                recipient = event.get("to")
                message = event.get("text")
                if not isinstance(recipient, str) or not isinstance(message, str):
                    retained_lines.append(line)
                    stats["retained"] = int(stats["retained"]) + 1
                    stats["parse_errors"] = int(stats["parse_errors"]) + 1
                    continue

                telegram_message_thread_id = _normalize_telegram_thread_id(event.get("telegram_message_thread_id"))

                if dry_run:
                    retained_lines.append(line)
                    stats["retained"] = int(stats["retained"]) + 1
                    continue

                ok = _send_message_with_transport(
                    transport=transport_text,
                    recipient=recipient,
                    message=message,
                    telegram_message_thread_id=telegram_message_thread_id,
                )
                if ok:
                    stats["sent"] = int(stats["sent"]) + 1
                else:
                    retained_lines.append(line)
                    stats["retained"] = int(stats["retained"]) + 1
    finally:
        try:
            staging_path.unlink()
        except Exception:
            pass

    if retained_lines:
        try:
            queue_path.parent.mkdir(parents=True, exist_ok=True)
            with queue_path.open("a", encoding="utf-8") as f:
                for line in retained_lines:
                    f.write(line)
                    f.write("\n")
        except Exception as exc:
            stats["error"] = f"requeue_failed:{type(exc).__name__}"
            _warn_stderr(
                "[agent-chat] fallback queue requeue failed: "
                f"{type(exc).__name__}: {exc}"
            )

    return stats


def _launchd_service_loaded(*, label: str) -> tuple[bool, str]:
    uid = os.getuid()
    try:
        proc = subprocess.run(
            ["launchctl", "print", f"gui/{uid}/{label}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"

    if proc.returncode == 0:
        return True, "loaded"

    err = (proc.stderr or "").strip()
    if err:
        return False, err.splitlines()[-1]
    return False, f"launchctl exit {proc.returncode}"


def _launchd_err_log_path() -> Path:
    return Path(
        os.environ.get(
            "AGENT_CHAT_LAUNCHD_ERR_LOG",
            str(Path.home() / "Library" / "Logs" / "agent-chat.launchd.err.log"),
        )
    )


def _recipient_from_launchagent_plist(*, label: str) -> str | None:
    plist_path = Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"
    if not plist_path.exists():
        return None
    try:
        with plist_path.open("rb") as f:
            data = plistlib.load(f)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    env = data.get("EnvironmentVariables")
    if not isinstance(env, dict):
        return None
    raw = env.get("AGENT_IMESSAGE_TO")
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    return text if text else None


def _permission_app_from_runtime_python(*, runtime_python: str) -> str | None:
    text = runtime_python.strip() if isinstance(runtime_python, str) else ""
    if not text:
        return None
    path = Path(text)
    for candidate in [path] + list(path.parents):
        if candidate.name.endswith(".app"):
            return str(candidate)
    return None


def _launchd_runtime_targets_from_plist(*, label: str) -> tuple[str | None, str | None]:
    plist_path = Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"
    if not plist_path.exists():
        return None, None
    try:
        with plist_path.open("rb") as f:
            data = plistlib.load(f)
    except Exception:
        return None, None
    if not isinstance(data, dict):
        return None, None
    program_args = data.get("ProgramArguments")
    if not isinstance(program_args, list) or not program_args:
        return None, None
    runtime = program_args[0]
    if not isinstance(runtime, str):
        return None, None
    runtime_text = runtime.strip()
    if not runtime_text:
        return None, None
    return runtime_text, _permission_app_from_runtime_python(runtime_python=runtime_text)

def _tail_text(
    *,
    path: Path,
    max_bytes: int = 32768,
    max_age_s: float | None = None,
) -> str:
    if max_bytes <= 0:
        return ""
    try:
        if not path.exists():
            return ""
        if isinstance(max_age_s, (int, float)) and max_age_s > 0:
            try:
                age_s = time.time() - float(path.stat().st_mtime)
                if age_s > float(max_age_s):
                    return ""
            except Exception:
                return ""
        with path.open("rb") as f:
            try:
                f.seek(0, os.SEEK_END)
                size = f.tell()
            except Exception:
                size = 0
            if size > max_bytes:
                f.seek(size - max_bytes)
            else:
                f.seek(0)
            data = f.read()
        if not data:
            return ""
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _launchd_inbound_warning_active(
    *,
    path: Path,
    max_bytes: int = 32768,
    max_age_s: float | None = None,
) -> bool:
    text = _tail_text(path=path, max_bytes=max_bytes, max_age_s=max_age_s)
    if not text:
        return False
    disabled_pos = text.rfind(_INBOUND_DISABLED_LOG_MARKER)
    if disabled_pos < 0:
        return False
    restored_pos = text.rfind(_INBOUND_RESTORED_LOG_MARKER)
    return restored_pos < disabled_pos


def _launchd_inbound_restored_active(
    *,
    path: Path,
    max_bytes: int = 32768,
    max_age_s: float | None = None,
) -> bool:
    text = _tail_text(path=path, max_bytes=max_bytes, max_age_s=max_age_s)
    if not text:
        return False
    restored_pos = text.rfind(_INBOUND_RESTORED_LOG_MARKER)
    if restored_pos < 0:
        return False
    disabled_pos = text.rfind(_INBOUND_DISABLED_LOG_MARKER)
    return disabled_pos < restored_pos


def _app_bundle_identifier(*, app_path: Path) -> str | None:
    info_path = app_path / "Contents" / "Info.plist"
    try:
        with info_path.open("rb") as f:
            payload = plistlib.load(f)
    except Exception:
        return None
    value = payload.get("CFBundleIdentifier") if isinstance(payload, dict) else None
    if not isinstance(value, str):
        return None
    bundle_id = value.strip()
    return bundle_id or None


def _tcc_log_has_code_requirement_mismatch(*, bundle_id: str, lookback_m: int = 20) -> bool:
    token = bundle_id.strip()
    if not token:
        return False
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", token):
        return False
    lookback = max(1, int(lookback_m))
    predicate = (
        'subsystem == "com.apple.TCC" '
        '&& eventMessage CONTAINS "kTCCServiceSystemPolicyAllFiles" '
        f'&& eventMessage CONTAINS "{token}"'
    )
    try:
        proc = subprocess.run(
            [
                "/usr/bin/log",
                "show",
                "--style",
                "syslog",
                "--last",
                f"{lookback}m",
                "--predicate",
                predicate,
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except Exception:
        return False
    if proc.returncode != 0:
        return False
    text_raw = proc.stdout
    text = text_raw if isinstance(text_raw, str) else ""
    return f"{_TCC_MISMATCH_SUBSTRING} {token}" in text


def _reset_tcc_full_disk_access(*, bundle_id: str) -> tuple[bool, str | None]:
    token = bundle_id.strip()
    if not token:
        return False, "missing bundle identifier"
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", token):
        return False, f"invalid bundle identifier: {token}"
    try:
        proc = subprocess.run(
            ["tccutil", "reset", _TCC_FDA_SERVICE, token],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
    if proc.returncode == 0:
        return True, None
    detail = (proc.stderr or proc.stdout or f"exit {proc.returncode}").strip()
    if not detail:
        detail = f"exit {proc.returncode}"
    return False, detail


def _chat_db_access_status(*, codex_home: Path) -> tuple[Path, bool, str | None]:
    chat_db = _chat_db_path(codex_home=codex_home)
    if not chat_db.exists():
        return chat_db, False, "chat.db not found"

    try:
        conn = sqlite3.connect(f"file:{chat_db}?mode=ro", uri=True)
        conn.close()
    except Exception as exc:
        return chat_db, False, f"{type(exc).__name__}: {exc}"

    return chat_db, True, None


def _chat_db_access_status_for_runtime(
    *,
    codex_home: Path,
    runtime_python_bin: str,
) -> tuple[Path, bool, str | None]:
    runtime_text = runtime_python_bin.strip() if isinstance(runtime_python_bin, str) else ""
    if not runtime_text:
        runtime_text = str(Path(sys.executable).resolve())
    elif not Path(runtime_text).is_absolute():
        resolved = shutil.which(runtime_text)
        if resolved:
            runtime_text = resolved
        else:
            runtime_text = str((Path.cwd() / runtime_text).resolve())

    this_python = str(Path(sys.executable).resolve())
    try:
        if Path(runtime_text).resolve() == Path(this_python):
            return _chat_db_access_status(codex_home=codex_home)
    except Exception:
        pass

    chat_db = _chat_db_path(codex_home=codex_home)
    if not chat_db.exists():
        return chat_db, False, "chat.db not found"

    probe_code = (
        "import sqlite3,sys\n"
        "db=sys.argv[1]\n"
        "conn=sqlite3.connect(f'file:{db}?mode=ro', uri=True)\n"
        "conn.close()\n"
    )
    try:
        proc = subprocess.run(
            [runtime_text, "-c", probe_code, str(chat_db)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError:
        return chat_db, False, f"runtime python not found: {runtime_text}"
    except Exception as exc:
        return chat_db, False, f"{type(exc).__name__}: {exc}"

    if proc.returncode == 0:
        return chat_db, True, None
    detail = (proc.stderr or proc.stdout or f"exit {proc.returncode}").strip()
    if not detail:
        detail = f"exit {proc.returncode}"
    return chat_db, False, detail


def _open_full_disk_access_settings() -> bool:
    try:
        proc = subprocess.run(
            ["open", _FULL_DISK_ACCESS_SETTINGS_URL],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return False
    return proc.returncode == 0


def _launchagent_plist_path(*, label: str) -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"


def _launchd_log_paths() -> tuple[Path, Path]:
    logs_dir = Path.home() / "Library" / "Logs"
    return (
        logs_dir / "agent-chat.launchd.out.log",
        logs_dir / "agent-chat.launchd.err.log",
    )


def _build_launchagent_plist(
    *,
    label: str,
    python_bin: str,
    script_path: Path,
    codex_home: Path,
    recipient: str,
) -> dict[str, Any]:
    out_log, err_log = _launchd_log_paths()
    notify_mode = os.environ.get("AGENT_CHAT_NOTIFY_MODE", "route").strip() or "route"
    agent = _current_agent()
    recipient_text = recipient.strip()

    env_vars: dict[str, str] = {
        "AGENT_CHAT_HOME": str(codex_home),
        "AGENT_CHAT_AGENT": agent,
        "AGENT_CHAT_NOTIFY_MODE": notify_mode,
        "AGENT_CHAT_LAUNCHD_LABEL": label,
        "AGENT_CHAT_TRANSPORT": _transport_mode(),
        "AGENT_CHAT_TRANSPORTS": ",".join(_transport_list()),
        "PATH": os.environ.get("PATH", "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"),
    }
    if recipient_text:
        env_vars["AGENT_IMESSAGE_TO"] = recipient_text

    if agent == "claude":
        env_vars["CLAUDE_HOME"] = str(codex_home)
    elif agent == "pi":
        env_vars["AGENT_CHAT_PI_HOME"] = str(codex_home)
        env_vars["PI_CODING_AGENT_DIR"] = str(codex_home)

    passthrough = (
        "CLAUDE_HOME",
        "CLAUDE_SETTINGS_PATH",
        "CLAUDE_CONFIG_PATH",
        "CLAUDE_PROJECTS_PATH",
        "AGENT_IMESSAGE_CHAT_DB",
        "AGENT_CHAT_INBOUND_POLL_S",
        "AGENT_CHAT_INBOUND_RETRY_S",
        "AGENT_IMESSAGE_MAX_LEN",
        "AGENT_CHAT_QUEUE_DRAIN_LIMIT",
        "AGENT_CHAT_RESUME_TIMEOUT_S",
        "AGENT_CHAT_TMUX_SOCKET",
        "AGENT_CHAT_STRICT_TMUX",
        "AGENT_CHAT_REQUIRE_SESSION_REF",
        "AGENT_CHAT_TMUX_NEW_SESSION_NAME",
        "AGENT_CHAT_TMUX_WINDOW_PREFIX",
        "AGENT_CHAT_CLAUDE_BIN",
        "AGENT_CHAT_CODEX_BIN",
        "AGENT_CHAT_PI_BIN",
        "AGENT_CHAT_PI_HOME",
        "PI_CODING_AGENT_DIR",
        "AGENT_IMESSAGE_SETUP_PERMISSIONS_TIMEOUT_S",
        "AGENT_IMESSAGE_SETUP_PERMISSIONS_POLL_S",
        "AGENT_CHAT_TRANSPORT",
        "AGENT_CHAT_TRANSPORTS",
        "AGENT_TELEGRAM_BOT_TOKEN",
        "AGENT_TELEGRAM_CHAT_ID",
        "AGENT_TELEGRAM_CHAT_IDS",
        "AGENT_TELEGRAM_API_BASE",
        "AGENT_TELEGRAM_INBOUND_CURSOR",
        "AGENT_DISCORD_BOT_TOKEN",
        "AGENT_DISCORD_CHANNEL_ID",
        "AGENT_DISCORD_CHANNEL_IDS",
        "AGENT_DISCORD_OWNER_USER_IDS",
        "AGENT_DISCORD_INBOUND_CURSOR",
        "AGENT_DISCORD_CONTROL_CHANNEL_ID",
        "AGENT_DISCORD_SESSION_CHANNELS",
        "AGENT_DISCORD_SESSION_CATEGORY_ID",
        "AGENT_DISCORD_SESSION_CHANNEL_PREFIX",
    )
    for key in passthrough:
        raw = os.environ.get(key)
        if isinstance(raw, str):
            value = raw.strip()
            if value:
                env_vars[key] = value

    return {
        "Label": label,
        "ProgramArguments": [python_bin, str(script_path), "run"],
        "EnvironmentVariables": env_vars,
        "RunAtLoad": True,
        "KeepAlive": True,
        "StandardOutPath": str(out_log),
        "StandardErrorPath": str(err_log),
    }


def _python_runtime_healthy(*, python_exec: Path) -> bool:
    if not python_exec.exists():
        return False
    try:
        proc = subprocess.run(
            [str(python_exec), "-c", "import sqlite3; import sys; sys.exit(0)"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return False
    return proc.returncode == 0


def _python_app_bundle_for_binary(*, python_bin: str) -> Path | None:
    raw = python_bin.strip() if isinstance(python_bin, str) else ""
    if not raw:
        return None

    if Path(raw).is_absolute():
        python_path = Path(raw)
    else:
        resolved = shutil.which(raw)
        if resolved:
            python_path = Path(resolved)
        else:
            python_path = (Path.cwd() / raw).resolve()

    try:
        python_path = python_path.resolve()
    except Exception:
        python_path = python_path.expanduser()

    for parent in [python_path] + list(python_path.parents):
        if parent.name == "Python.app" and parent.is_dir():
            return parent
    for base in [python_path.parent] + list(python_path.parents):
        candidate = base / "Resources" / "Python.app"
        if candidate.is_dir():
            return candidate
    return None


def _prepare_friendly_python_app(*, source_app: Path) -> tuple[Path | None, str | None]:
    target_app = Path.home() / "Applications" / _DEFAULT_FRIENDLY_PYTHON_APP_NAME
    source_path = source_app.expanduser()
    try:
        source_path = source_path.resolve()
    except Exception:
        pass

    source_exec = source_path / "Contents" / "MacOS" / "Python"
    if not source_exec.exists():
        return None, f"source Python app executable missing at {source_exec}"

    try:
        target_app.parent.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        return None, f"failed creating {target_app.parent}: {type(exc).__name__}: {exc}"

    target_exec = target_app / "Contents" / "MacOS" / "Python"

    # Preserve a working friendly runtime to avoid churn in Full Disk Access grants.
    if (target_app.exists() or target_app.is_symlink()) and _python_runtime_healthy(
        python_exec=target_exec
    ):
        return target_app, "reused existing friendly Python app to preserve Full Disk Access grants"

    if target_app.is_symlink():
        try:
            target_resolved = target_app.resolve()
            if target_resolved == source_path and target_exec.exists():
                return target_app, None
        except Exception:
            pass
        try:
            target_app.unlink()
        except Exception as exc:
            return None, f"failed replacing {target_app}: {type(exc).__name__}: {exc}"

    if target_app.exists():
        try:
            target_resolved = target_app.resolve()
            if target_resolved == source_path and target_exec.exists():
                return target_app, None
        except Exception:
            pass

        try:
            if target_app.is_file():
                target_app.unlink()
            else:
                shutil.rmtree(target_app)
        except Exception as exc:
            return None, f"failed replacing {target_app}: {type(exc).__name__}: {exc}"

    link_detail: str | None = None
    try:
        target_app.symlink_to(source_path, target_is_directory=True)
    except Exception as exc:
        try:
            shutil.copytree(source_path, target_app, symlinks=True)
        except Exception as copy_exc:
            return (
                None,
                "failed linking "
                f"{source_path} -> {target_app}: {type(exc).__name__}: {exc}; "
                f"fallback copy failed: {type(copy_exc).__name__}: {copy_exc}",
            )
        link_detail = (
            "failed symlinking "
            f"{source_path} -> {target_app}: {type(exc).__name__}: {exc}; copied app bundle instead"
        )

    if target_exec.exists():
        return target_app, link_detail

    if link_detail is None:
        link_detail = f"friendly Python app executable missing at {target_exec}"
    return None, link_detail


def _resolve_launchd_runtime_python(*, python_bin: str) -> tuple[str, Path | None, str | None]:
    python_text = python_bin.strip() if isinstance(python_bin, str) else ""
    if not python_text:
        python_text = str(Path(sys.executable).resolve())
    elif not Path(python_text).is_absolute():
        resolved = shutil.which(python_text)
        if resolved:
            python_text = resolved
        else:
            python_text = str((Path.cwd() / python_text).resolve())

    source_app = _python_app_bundle_for_binary(python_bin=python_text)
    if source_app is None:
        return python_text, None, None

    friendly_app, detail = _prepare_friendly_python_app(source_app=source_app)
    permission_app = friendly_app or source_app
    app_exec = permission_app / "Contents" / "MacOS" / "Python"
    if app_exec.exists():
        return str(app_exec), permission_app, detail
    if detail is None:
        detail = f"friendly Python app executable missing at {app_exec}"
    return python_text, permission_app, detail


def _run_setup_launchd(
    *,
    codex_home: Path,
    recipient: str,
    label: str,
    python_bin: str,
    script_path: Path,
    setup_permissions: bool,
    timeout_s: float,
    poll_s: float,
    open_settings: bool,
    repair_tcc: bool = False,
) -> int:
    transport_mode = _transport_mode()
    imessage_enabled = _transport_imessage_enabled(mode=transport_mode)
    for setup_err in (
        _validate_telegram_setup_requirements(transport_mode=transport_mode),
        _validate_discord_setup_requirements(transport_mode=transport_mode),
    ):
        if isinstance(setup_err, str):
            sys.stdout.write(setup_err)
            return 1

    recipient_text = _normalize_recipient(recipient) if recipient.strip() else ""
    if _transport_imessage_enabled(mode=transport_mode) and not recipient_text:
        sys.stdout.write("AGENT_IMESSAGE_TO is required. Provide --recipient or set AGENT_IMESSAGE_TO.\n")
        return 1
    if _transport_telegram_enabled(mode=transport_mode):
        telegram_chat_ids = _telegram_chat_ids()
        if not telegram_chat_ids:
            bootstrap_chat_id, bootstrap_err = _bootstrap_telegram_group_chat_id(
                codex_home=codex_home,
                timeout_s=float(_DEFAULT_TELEGRAM_SETUP_BOOTSTRAP_TIMEOUT_S),
                open_link=bool(open_settings),
            )
            if isinstance(bootstrap_chat_id, str) and bootstrap_chat_id.strip():
                os.environ["AGENT_TELEGRAM_CHAT_ID"] = bootstrap_chat_id.strip()
                telegram_chat_ids = _telegram_chat_ids()
            if not telegram_chat_ids:
                sys.stdout.write(
                    "AGENT_TELEGRAM_CHAT_ID is required when AGENT_CHAT_TRANSPORT includes Telegram.\n"
                )
                if isinstance(bootstrap_err, str) and bootstrap_err.strip():
                    sys.stdout.write(bootstrap_err.strip() + "\n")
                else:
                    sys.stdout.write(
                        "Set AGENT_TELEGRAM_CHAT_ID (or AGENT_TELEGRAM_CHAT_IDS) and rerun setup-launchd.\n"
                    )
                return 1

    label_text = label.strip() or _DEFAULT_LAUNCHD_LABEL
    python_text = python_bin.strip() if isinstance(python_bin, str) else ""
    if not python_text:
        python_text = str(Path(sys.executable).resolve())

    script_abs = script_path.expanduser().resolve()
    if not script_abs.exists():
        sys.stdout.write(f"Control-plane script not found: {script_abs}\n")
        return 1

    launchd_python, permission_app_path, app_note = _resolve_launchd_runtime_python(
        python_bin=python_text
    )

    if setup_permissions and imessage_enabled:
        perm_rc = _run_setup_permissions(
            codex_home=codex_home,
            timeout_s=timeout_s,
            poll_s=poll_s,
            open_settings=open_settings,
            probe_python_bin=launchd_python,
            permission_app_path=permission_app_path,
        )
        if perm_rc != 0:
            sys.stdout.write("Launchd setup aborted because chat.db permissions are still missing.\n")
            return perm_rc

    plist_path = _launchagent_plist_path(label=label_text)
    out_log, err_log = _launchd_log_paths()
    try:
        plist_path.parent.mkdir(parents=True, exist_ok=True)
        out_log.parent.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        sys.stdout.write(f"Failed creating launchd directories: {type(exc).__name__}: {exc}\n")
        return 1

    payload = _build_launchagent_plist(
        label=label_text,
        python_bin=launchd_python,
        script_path=script_abs,
        codex_home=codex_home,
        recipient=recipient_text,
    )
    try:
        with plist_path.open("wb") as f:
            plistlib.dump(payload, f, sort_keys=False)
    except Exception as exc:
        sys.stdout.write(f"Failed writing LaunchAgent plist: {type(exc).__name__}: {exc}\n")
        return 1

    uid = os.getuid()
    domain = f"gui/{uid}"
    service = f"{domain}/{label_text}"

    # Best effort: unload previous service instance first.
    try:
        subprocess.run(
            ["launchctl", "bootout", service],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass

    # Service can remain explicitly disabled in launchd overrides; enable first
    # to avoid bootstrap EIO failures for disabled labels.
    try:
        subprocess.run(
            ["launchctl", "enable", service],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass

    try:
        bootstrap = subprocess.run(
            ["launchctl", "bootstrap", domain, str(plist_path)],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
    except Exception as exc:
        sys.stdout.write(f"launchctl bootstrap failed: {type(exc).__name__}: {exc}\n")
        return 1
    if bootstrap.returncode != 0:
        detail = (bootstrap.stderr or "").strip() or f"exit {bootstrap.returncode}"
        sys.stdout.write(f"launchctl bootstrap failed: {detail}\n")
        return 1

    try:
        subprocess.run(
            ["launchctl", "kickstart", "-k", service],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass

    loaded, detail = _launchd_service_loaded(label=label_text)
    if not loaded:
        sys.stdout.write(
            "LaunchAgent was written, but launchd did not report it as loaded: "
            f"{detail}\n"
        )
        return 1

    try:
        time.sleep(_LAUNCHD_POST_START_VERIFY_DELAY_S)
    except Exception:
        pass
    launchd_warning = _launchd_inbound_warning_active(path=err_log, max_age_s=120.0)
    if imessage_enabled and launchd_warning:
        chat_db, chat_db_readable, chat_db_error = _chat_db_access_status(codex_home=codex_home)
        permission_bundle_id = _app_bundle_identifier(app_path=permission_app_path) if permission_app_path is not None else None
        sys.stdout.write(
            "LaunchAgent started, but launchd runtime still cannot read chat.db.\n"
        )
        sys.stdout.write(f"Python binary: {launchd_python}\n")
        if permission_app_path is not None:
            sys.stdout.write(f"Full Disk Access app: {permission_app_path}\n")
        sys.stdout.write(f"chat.db path: {chat_db}\n")
        if isinstance(chat_db_error, str) and chat_db_error.strip():
            sys.stdout.write(f"Current shell probe detail: {chat_db_error.strip()}\n")
        permission_help = (
            "In System Settings > Privacy & Security > Full Disk Access, "
            "add the Full Disk Access app above (preferred) or the Python binary above, "
            "then rerun setup-launchd.\n"
        )
        if chat_db_readable:
            sys.stdout.write(
                "Current shell can read chat.db, but launchd cannot. "
                + permission_help
            )
            if isinstance(permission_bundle_id, str) and permission_bundle_id and _tcc_log_has_code_requirement_mismatch(
                bundle_id=permission_bundle_id
            ):
                sys.stdout.write(
                    "Detected probable stale TCC code-requirement mismatch for "
                    f"{permission_bundle_id}.\n"
                )
                sys.stdout.write(
                    f"Recommended repair: `tccutil reset {_TCC_FDA_SERVICE} {permission_bundle_id}` "
                    "then re-enable Full Disk Access for the app and rerun setup-launchd.\n"
                )
        else:
            sys.stdout.write(permission_help)
        if repair_tcc:
            if isinstance(permission_bundle_id, str) and permission_bundle_id:
                sys.stdout.write(
                    "Attempting automatic TCC repair for launchd runtime bundle id: "
                    f"{permission_bundle_id}\n"
                )
                reset_ok, reset_detail = _reset_tcc_full_disk_access(bundle_id=permission_bundle_id)
                if reset_ok:
                    sys.stdout.write(
                        f"Reset {_TCC_FDA_SERVICE} approval for {permission_bundle_id}. "
                        "Re-enable Full Disk Access when prompted.\n"
                    )
                else:
                    sys.stdout.write(
                        "Automatic TCC reset failed: "
                        f"{reset_detail or 'unknown error'}\n"
                    )
            else:
                sys.stdout.write(
                    "Automatic TCC repair unavailable: could not determine runtime app bundle id.\n"
                )

            perm_rc = _run_setup_permissions(
                codex_home=codex_home,
                timeout_s=timeout_s,
                poll_s=poll_s,
                open_settings=open_settings,
                probe_python_bin=launchd_python,
                permission_app_path=permission_app_path,
            )
            if perm_rc == 0:
                try:
                    subprocess.run(
                        ["launchctl", "kickstart", "-k", service],
                        check=False,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                except Exception:
                    pass
                try:
                    time.sleep(_LAUNCHD_POST_START_VERIFY_DELAY_S)
                except Exception:
                    pass
                launchd_warning = _launchd_inbound_warning_active(path=err_log, max_age_s=120.0)
                if not launchd_warning:
                    sys.stdout.write("Launchd inbound access verified after TCC repair.\n")
                else:
                    sys.stdout.write(
                        "Launchd still reports inbound disabled after TCC repair. "
                        "Confirm Full Disk Access is enabled for the runtime app and retry setup-launchd.\n"
                    )
            else:
                sys.stdout.write(
                    "Automatic TCC repair could not complete permission verification.\n"
                )
        if launchd_warning:
            return 1

    sys.stdout.write(f"LaunchAgent installed and started: {label_text}\n")
    sys.stdout.write(f"Plist: {plist_path}\n")
    sys.stdout.write(f"Python binary: {launchd_python}\n")
    if permission_app_path is not None:
        sys.stdout.write(f"Full Disk Access app: {permission_app_path}\n")
    if isinstance(app_note, str) and app_note.strip():
        sys.stdout.write(f"Python app setup note: {app_note.strip()}\n")
    sys.stdout.write(f"Script: {script_abs}\n")
    if imessage_enabled and setup_permissions:
        sys.stdout.write("chat.db permission check: passed for this Python binary.\n")
    elif imessage_enabled:
        sys.stdout.write(
            "chat.db permission check: skipped. "
            "If inbound replies stay disabled, run `setup-permissions` for this Python binary.\n"
        )
    else:
        sys.stdout.write(
            "chat.db permission check: not required when iMessage transport is disabled.\n"
        )
    return 0


def _run_setup_permissions(
    *,
    codex_home: Path,
    timeout_s: float,
    poll_s: float,
    open_settings: bool,
    probe_python_bin: str | None = None,
    permission_app_path: Path | None = None,
) -> int:
    python_bin = (
        probe_python_bin.strip()
        if isinstance(probe_python_bin, str) and probe_python_bin.strip()
        else str(Path(sys.executable).resolve())
    )
    chat_db, chat_db_readable, chat_db_error = _chat_db_access_status_for_runtime(
        codex_home=codex_home,
        runtime_python_bin=python_bin,
    )
    if chat_db_readable:
        sys.stdout.write("Full Disk Access check: already granted for inbound chat.db reads.\n")
        sys.stdout.write(f"Python binary: {python_bin}\n")
        if permission_app_path is not None:
            sys.stdout.write(f"Full Disk Access app: {permission_app_path}\n")
        sys.stdout.write(f"chat.db: readable ({chat_db})\n")
        sys.stdout.flush()
        return 0

    sys.stdout.write("Full Disk Access setup is required for inbound iMessage replies.\n")
    sys.stdout.write(
        "Permission to grant: Full Disk Access "
        "(System Settings > Privacy & Security > Full Disk Access).\n"
    )
    sys.stdout.write("Add one of these targets:\n")
    if permission_app_path is not None:
        sys.stdout.write(f"Grant Full Disk Access to this app: {permission_app_path}\n")
    sys.stdout.write(f"Grant access to this Python binary: {python_bin}\n")
    if permission_app_path is not None:
        wait_target = f"app: {permission_app_path}"
        sys.stdout.write("Detailed steps before the Settings window opens:\n")
        sys.stdout.write(f"1) In Full Disk Access, add and enable this app: {permission_app_path}\n")
        sys.stdout.write(
            f"2) If the app is unavailable, add and enable this Python binary: {python_bin}\n"
        )
    else:
        wait_target = f"Python binary: {python_bin}"
        sys.stdout.write("Detailed steps before the Settings window opens:\n")
        sys.stdout.write(f"1) In Full Disk Access, add and enable this Python binary: {python_bin}\n")
    sys.stdout.write("3) Keep this command running until it confirms chat.db is readable.\n")
    sys.stdout.write(
        "Action required now: in System Settings > Privacy & Security > Full Disk Access, "
        f"enable access for {wait_target}.\n"
    )
    sys.stdout.write(f"chat.db path: {chat_db}\n")
    if isinstance(chat_db_error, str) and chat_db_error.strip():
        sys.stdout.write(f"Current chat.db error: {chat_db_error.strip()}\n")
    sys.stdout.write(
        f"Waiting for Full Disk Access grant for {wait_target}; polling chat.db until readable.\n"
    )
    sys.stdout.flush()

    timeout_s = max(0.0, float(timeout_s))
    poll_s = max(0.1, float(poll_s))
    if timeout_s <= 0:
        return 1

    deadline = time.monotonic() + timeout_s
    settings_opened = False
    while time.monotonic() < deadline:
        _, chat_db_readable, chat_db_error = _chat_db_access_status_for_runtime(
            codex_home=codex_home,
            runtime_python_bin=python_bin,
        )
        if chat_db_readable:
            sys.stdout.write("Full Disk Access confirmed: chat.db is now readable.\n")
            sys.stdout.flush()
            return 0
        if open_settings and not settings_opened:
            if _open_full_disk_access_settings():
                sys.stdout.write("Opened System Settings to Full Disk Access.\n")
            else:
                sys.stdout.write(
                    "Could not auto-open System Settings; open Privacy > Full Disk Access manually.\n"
                )
            sys.stdout.flush()
            settings_opened = True
        time.sleep(poll_s)

    if isinstance(chat_db_error, str) and chat_db_error.strip():
        sys.stdout.write(f"Timed out waiting for chat.db access: {chat_db_error.strip()}\n")
    else:
        sys.stdout.write("Timed out waiting for chat.db access.\n")
    sys.stdout.flush()
    return 1

def _guided_setup_default_env_file(*, transport: str) -> Path:
    normalized = transport.strip().lower()
    if normalized == "telegram":
        return Path(".env.telegram.local")
    return Path(".env.agent-chat.local")


_GUIDED_SETUP_TRANSPORTS = ("telegram", "discord", "imessage")
_GUIDED_SETUP_RUNTIME_CHOICES = tuple(sorted(_SUPPORTED_AGENTS))



def _prompt_choice(
    *,
    prompt: str,
    choices: tuple[str, ...],
    default: str,
    input_fn: Callable[[str], str] = input,
) -> str:
    allowed = {item.strip().lower() for item in choices if item.strip()}
    default_norm = default.strip().lower()
    while True:
        raw = input_fn(prompt).strip().lower()
        if not raw:
            raw = default_norm
        if raw in allowed:
            return raw
        sys.stdout.write(f"Invalid choice '{raw}'. Choose one of: {', '.join(choices)}.\n")
        sys.stdout.flush()



def _prompt_text(
    *,
    prompt: str,
    default: str | None = None,
    allow_empty: bool = False,
    secret: bool = False,
    input_fn: Callable[[str], str] = input,
    secret_input_fn: Callable[[str], str] | None = None,
) -> str:
    while True:
        raw: str
        if secret:
            reader = secret_input_fn
            if reader is None:
                try:
                    import getpass

                    reader = getpass.getpass
                except Exception:
                    reader = input_fn
            try:
                raw = reader(prompt)
            except Exception:
                raw = input_fn(prompt)
        else:
            raw = input_fn(prompt)
        value = raw.strip()
        if not value and isinstance(default, str):
            value = default.strip()
        if value or allow_empty:
            return value
        sys.stdout.write("A value is required.\n")
        sys.stdout.flush()



def _prompt_bool(
    *,
    prompt: str,
    default: bool,
    input_fn: Callable[[str], str] = input,
) -> bool:
    while True:
        raw = input_fn(prompt).strip().lower()
        if not raw:
            return bool(default)
        if raw in {"y", "yes", "true", "1"}:
            return True
        if raw in {"n", "no", "false", "0"}:
            return False
        sys.stdout.write("Please answer yes or no.\n")
        sys.stdout.flush()



def _guided_setup_file_lines(path: Path) -> list[str]:
    try:
        if path.exists():
            return path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []
    return []



def _guided_setup_write_shell_var(*, path: Path, key: str, value: str | None, unset: bool = False) -> None:
    lines = _guided_setup_file_lines(path)
    export_prefix = f"export {key}="
    unset_line = f"unset {key}"
    if unset:
        new_line = unset_line
    else:
        safe = (value or "").replace("\\", "\\\\").replace('"', '\\"')
        new_line = f'export {key}="{safe}"'

    out: list[str] = []
    updated = False
    for line in lines:
        stripped = line.strip()
        if line.startswith(export_prefix) or stripped == unset_line:
            if not updated:
                out.append(new_line)
                updated = True
            continue
        out.append(line)
    if not updated:
        if out and out[-1].strip():
            out.append("")
        out.append(new_line)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(out).rstrip() + "\n", encoding="utf-8")



def _guided_setup_runtime_home_value(*, agent: str) -> str | None:
    normalized = _normalize_agent(agent=agent)
    if normalized == "claude":
        return os.environ.get("CLAUDE_HOME", "").strip() or str(Path.home() / ".claude")
    if normalized == "pi":
        return (
            os.environ.get("AGENT_CHAT_PI_HOME", "").strip()
            or os.environ.get("PI_CODING_AGENT_DIR", "").strip()
            or str(Path.home() / ".pi" / "agent")
        )
    return os.environ.get("AGENT_CHAT_HOME", "").strip() or str(Path.home() / ".codex")



def _guided_setup_write_env_file(
    *,
    path: Path,
    agent: str,
    transport: str,
    recipient: str | None,
    telegram_token: str | None,
    telegram_chat_id: str | None,
    discord_token: str | None,
    discord_control_channel_id: str | None,
    discord_session_channels: bool,
    discord_session_category_id: str | None,
) -> None:
    normalized_agent = _normalize_agent(agent=agent)
    normalized_transport = transport.strip().lower()

    _guided_setup_write_shell_var(path=path, key="AGENT_CHAT_AGENT", value=normalized_agent)
    _guided_setup_write_shell_var(path=path, key="AGENT_CHAT_TRANSPORT", value=normalized_transport)
    _guided_setup_write_shell_var(path=path, key="AGENT_CHAT_NOTIFY_MODE", value="route")
    _guided_setup_write_shell_var(
        path=path,
        key="AGENT_CHAT_HOME",
        value=os.environ.get("AGENT_CHAT_HOME", "").strip() or str(Path.home() / ".codex"),
    )
    _guided_setup_write_shell_var(
        path=path,
        key="CLAUDE_HOME",
        value=os.environ.get("CLAUDE_HOME", "").strip() or str(Path.home() / ".claude"),
    )
    _guided_setup_write_shell_var(
        path=path,
        key="AGENT_CHAT_PI_HOME",
        value=(
            os.environ.get("AGENT_CHAT_PI_HOME", "").strip()
            or os.environ.get("PI_CODING_AGENT_DIR", "").strip()
            or str(Path.home() / ".pi" / "agent")
        ),
    )

    if normalized_transport == "imessage":
        _guided_setup_write_shell_var(path=path, key="AGENT_IMESSAGE_TO", value=recipient or "")
    else:
        _guided_setup_write_shell_var(path=path, key="AGENT_IMESSAGE_TO", value=None, unset=True)

    if normalized_transport == "telegram":
        _guided_setup_write_shell_var(path=path, key="AGENT_TELEGRAM_BOT_TOKEN", value=telegram_token or "")
        _guided_setup_write_shell_var(path=path, key="AGENT_TELEGRAM_CHAT_ID", value=telegram_chat_id or "")
        _guided_setup_write_shell_var(path=path, key="AGENT_TELEGRAM_GENERAL_TOPIC_THREAD_ID", value="1")
    else:
        _guided_setup_write_shell_var(path=path, key="AGENT_TELEGRAM_BOT_TOKEN", value=None, unset=True)
        _guided_setup_write_shell_var(path=path, key="AGENT_TELEGRAM_CHAT_ID", value=None, unset=True)

    if normalized_transport == "discord":
        control_channel_id = (discord_control_channel_id or "").strip()
        _guided_setup_write_shell_var(path=path, key="AGENT_DISCORD_BOT_TOKEN", value=discord_token or "")
        _guided_setup_write_shell_var(path=path, key="AGENT_DISCORD_CONTROL_CHANNEL_ID", value=control_channel_id)
        _guided_setup_write_shell_var(path=path, key="AGENT_DISCORD_CHANNEL_ID", value=control_channel_id)
        _guided_setup_write_shell_var(
            path=path,
            key="AGENT_DISCORD_SESSION_CHANNELS",
            value="1" if discord_session_channels else "0",
        )
        if isinstance(discord_session_category_id, str) and discord_session_category_id.strip():
            _guided_setup_write_shell_var(
                path=path,
                key="AGENT_DISCORD_SESSION_CATEGORY_ID",
                value=discord_session_category_id.strip(),
            )
        else:
            _guided_setup_write_shell_var(path=path, key="AGENT_DISCORD_SESSION_CATEGORY_ID", value=None, unset=True)
    else:
        _guided_setup_write_shell_var(path=path, key="AGENT_DISCORD_BOT_TOKEN", value=None, unset=True)
        _guided_setup_write_shell_var(path=path, key="AGENT_DISCORD_CONTROL_CHANNEL_ID", value=None, unset=True)
        _guided_setup_write_shell_var(path=path, key="AGENT_DISCORD_CHANNEL_ID", value=None, unset=True)
        _guided_setup_write_shell_var(path=path, key="AGENT_DISCORD_SESSION_CHANNELS", value=None, unset=True)
        _guided_setup_write_shell_var(path=path, key="AGENT_DISCORD_SESSION_CATEGORY_ID", value=None, unset=True)



def _guided_setup_apply_env(
    *,
    agent: str,
    transport: str,
    recipient: str | None,
    telegram_token: str | None,
    telegram_chat_id: str | None,
    discord_token: str | None,
    discord_control_channel_id: str | None,
    discord_session_channels: bool,
    discord_session_category_id: str | None,
) -> None:
    normalized_agent = _normalize_agent(agent=agent)
    normalized_transport = transport.strip().lower()
    os.environ["AGENT_CHAT_AGENT"] = normalized_agent
    os.environ["AGENT_CHAT_TRANSPORT"] = normalized_transport
    os.environ["AGENT_CHAT_NOTIFY_MODE"] = "route"
    os.environ.setdefault("AGENT_CHAT_HOME", str(Path.home() / ".codex"))
    os.environ.setdefault("CLAUDE_HOME", str(Path.home() / ".claude"))
    os.environ.setdefault("AGENT_CHAT_PI_HOME", str(Path.home() / ".pi" / "agent"))

    if normalized_transport == "imessage":
        os.environ["AGENT_IMESSAGE_TO"] = recipient or ""
    else:
        os.environ.pop("AGENT_IMESSAGE_TO", None)

    if normalized_transport == "telegram":
        os.environ["AGENT_TELEGRAM_BOT_TOKEN"] = telegram_token or ""
        if isinstance(telegram_chat_id, str):
            os.environ["AGENT_TELEGRAM_CHAT_ID"] = telegram_chat_id
        os.environ.setdefault("AGENT_TELEGRAM_GENERAL_TOPIC_THREAD_ID", "1")
    else:
        os.environ.pop("AGENT_TELEGRAM_BOT_TOKEN", None)
        os.environ.pop("AGENT_TELEGRAM_CHAT_ID", None)

    if normalized_transport == "discord":
        control_channel_id = (discord_control_channel_id or "").strip()
        os.environ["AGENT_DISCORD_BOT_TOKEN"] = discord_token or ""
        os.environ["AGENT_DISCORD_CONTROL_CHANNEL_ID"] = control_channel_id
        os.environ["AGENT_DISCORD_CHANNEL_ID"] = control_channel_id
        os.environ["AGENT_DISCORD_SESSION_CHANNELS"] = "1" if discord_session_channels else "0"
        if isinstance(discord_session_category_id, str) and discord_session_category_id.strip():
            os.environ["AGENT_DISCORD_SESSION_CATEGORY_ID"] = discord_session_category_id.strip()
        else:
            os.environ.pop("AGENT_DISCORD_SESSION_CATEGORY_ID", None)
    else:
        os.environ.pop("AGENT_DISCORD_BOT_TOKEN", None)
        os.environ.pop("AGENT_DISCORD_CONTROL_CHANNEL_ID", None)
        os.environ.pop("AGENT_DISCORD_CHANNEL_ID", None)
        os.environ.pop("AGENT_DISCORD_SESSION_CHANNELS", None)
        os.environ.pop("AGENT_DISCORD_SESSION_CATEGORY_ID", None)



def _render_guided_setup_preflight(
    *,
    transport: str,
    discord_session_channels: bool,
    telegram_chat_id: str | None,
) -> str:
    normalized_transport = transport.strip().lower()
    lines = ["Before setup:"]
    if normalized_transport == "telegram":
        lines.extend(
            [
                "1) Create or pick your Telegram group/topic.",
                "2) In @BotFather, disable bot privacy with /setprivacy.",
                "3) Add the bot to the group and promote it to admin.",
            ]
        )
        if not (isinstance(telegram_chat_id, str) and telegram_chat_id.strip()):
            lines.append("4) If setup-launchd pauses, send one plain message there to bootstrap chat id.")
    elif normalized_transport == "discord":
        lines.extend(
            [
                "1) Enable Message Content Intent for the Discord bot.",
                "2) Invite the bot and confirm it can view/send/read the control channel.",
            ]
        )
        if discord_session_channels:
            lines.append("3) Grant Manage Channels if you want auto-created session channels.")
    else:
        lines.extend(
            [
                "1) Make sure Messages is signed in on this Mac.",
                "2) Keep setup running while you grant Automation and Full Disk Access.",
            ]
        )
    return "\n".join(lines) + "\n"



def _render_guided_setup_success(
    *,
    transport: str,
    discord_session_channels: bool,
) -> str:
    normalized_transport = transport.strip().lower()
    lines = ["Setup complete. First check:"]
    if normalized_transport == "telegram":
        lines.extend(
            [
                "1) In the target topic/group, send `list`.",
                "2) Bind once with `bind @<session_ref>`.",
                "3) Optionally send `where`.",
                "4) Then send plain text in that topic.",
            ]
        )
    elif normalized_transport == "discord":
        lines.extend(
            [
                "1) In the control channel, send `list`.",
                "2) Create or target a session with `new bugfix: investigate failing test`.",
                "3) If needed, inspect routing with `where`.",
            ]
        )
        if discord_session_channels:
            lines.append("4) In a bound session channel, plain text continues the same session.")
        else:
            lines.append("4) In the control channel, route explicitly with `@<session_ref> <instruction>`.")
    else:
        lines.extend(
            [
                "1) Let the permission prompts settle, then run `doctor`.",
                "2) Send yourself `list`.",
                "3) Continue a session with `@<session_ref> <instruction>`.",
            ]
        )
    return "\n".join(lines) + "\n"



def _run_guided_setup(
    *,
    agent: str | None,
    transport: str | None,
    recipient: str | None,
    telegram_token: str | None,
    telegram_chat_id: str | None,
    discord_token: str | None,
    discord_control_channel_id: str | None,
    discord_session_channels: bool | None,
    discord_session_category_id: str | None,
    env_file: str | None,
    python_bin: str,
    open_settings: bool,
    input_fn: Callable[[str], str] = input,
    secret_input_fn: Callable[[str], str] | None = None,
) -> int:
    selected_agent = _normalize_agent(agent=agent) if isinstance(agent, str) and agent.strip() else _prompt_choice(
        prompt=(
            "Choose runtime [codex/claude/pi] "
            f"(default: {_normalize_agent(agent=os.environ.get('AGENT_CHAT_AGENT'))}): "
        ),
        choices=_GUIDED_SETUP_RUNTIME_CHOICES,
        default=_normalize_agent(agent=os.environ.get("AGENT_CHAT_AGENT")),
        input_fn=input_fn,
    )

    transport_default = transport.strip().lower() if isinstance(transport, str) and transport.strip() else "telegram"
    if transport_default not in _GUIDED_SETUP_TRANSPORTS:
        transport_default = "telegram"
    selected_transport = transport_default if isinstance(transport, str) and transport.strip() else _prompt_choice(
        prompt=f"Choose transport [telegram/discord/imessage] (default: {transport_default}): ",
        choices=_GUIDED_SETUP_TRANSPORTS,
        default=transport_default,
        input_fn=input_fn,
    )

    normalized_recipient = _normalize_recipient(recipient) if isinstance(recipient, str) and recipient.strip() else ""
    if selected_transport == "imessage" and not normalized_recipient:
        normalized_recipient = _normalize_recipient(
            _prompt_text(
                prompt="Enter your iMessage destination (+15555550123 or email): ",
                input_fn=input_fn,
            )
        )

    selected_telegram_token = telegram_token.strip() if isinstance(telegram_token, str) else ""
    selected_telegram_chat_id = telegram_chat_id.strip() if isinstance(telegram_chat_id, str) else ""
    if selected_transport == "telegram":
        if not selected_telegram_token:
            selected_telegram_token = _prompt_text(
                prompt="Paste your Telegram bot token (from @BotFather): ",
                secret=True,
                input_fn=input_fn,
                secret_input_fn=secret_input_fn,
            )
        if not selected_telegram_chat_id:
            selected_telegram_chat_id = _prompt_text(
                prompt="Optional Telegram group/topic chat id (leave blank to bootstrap during setup-launchd): ",
                allow_empty=True,
                input_fn=input_fn,
            )

    selected_discord_token = discord_token.strip() if isinstance(discord_token, str) else ""
    selected_discord_control_channel_id = discord_control_channel_id.strip() if isinstance(discord_control_channel_id, str) else ""
    selected_discord_session_channels = bool(discord_session_channels) if discord_session_channels is not None else True
    selected_discord_session_category_id = discord_session_category_id.strip() if isinstance(discord_session_category_id, str) else ""
    if selected_transport == "discord":
        if not selected_discord_token:
            selected_discord_token = _prompt_text(
                prompt="Paste your Discord bot token: ",
                secret=True,
                input_fn=input_fn,
                secret_input_fn=secret_input_fn,
            )
        if not selected_discord_control_channel_id:
            selected_discord_control_channel_id = _prompt_text(
                prompt="Enter the Discord control channel id: ",
                input_fn=input_fn,
            )
        if discord_session_channels is None:
            selected_discord_session_channels = _prompt_bool(
                prompt="Create per-session Discord channels automatically? [Y/n]: ",
                default=True,
                input_fn=input_fn,
            )
        if selected_discord_session_channels and not selected_discord_session_category_id:
            selected_discord_session_category_id = _prompt_text(
                prompt="Optional Discord category id for session channels (leave blank to skip): ",
                allow_empty=True,
                input_fn=input_fn,
            )

    env_path = Path(env_file).expanduser() if isinstance(env_file, str) and env_file.strip() else _guided_setup_default_env_file(
        transport=selected_transport
    )
    env_path = env_path.resolve()

    _guided_setup_write_env_file(
        path=env_path,
        agent=selected_agent,
        transport=selected_transport,
        recipient=normalized_recipient,
        telegram_token=selected_telegram_token,
        telegram_chat_id=selected_telegram_chat_id,
        discord_token=selected_discord_token,
        discord_control_channel_id=selected_discord_control_channel_id,
        discord_session_channels=selected_discord_session_channels,
        discord_session_category_id=selected_discord_session_category_id,
    )
    _guided_setup_apply_env(
        agent=selected_agent,
        transport=selected_transport,
        recipient=normalized_recipient,
        telegram_token=selected_telegram_token,
        telegram_chat_id=selected_telegram_chat_id,
        discord_token=selected_discord_token,
        discord_control_channel_id=selected_discord_control_channel_id,
        discord_session_channels=selected_discord_session_channels,
        discord_session_category_id=selected_discord_session_category_id,
    )

    sys.stdout.write("agent-chat guided setup\n\n")
    sys.stdout.write(f"Runtime: {_agent_display_name(agent=selected_agent)}\n")
    sys.stdout.write(f"Transport: {selected_transport}\n")
    sys.stdout.write(f"Env file: {env_path}\n")
    if selected_transport == "telegram":
        sys.stdout.write(
            "Telegram chat id: "
            f"{selected_telegram_chat_id or '(bootstrap from first inbound message during setup-launchd)'}\n"
        )
    elif selected_transport == "discord":
        sys.stdout.write(f"Discord control channel: {selected_discord_control_channel_id}\n")
        sys.stdout.write(
            f"Discord session channels: {'enabled' if selected_discord_session_channels else 'disabled'}\n"
        )
    else:
        sys.stdout.write(f"iMessage recipient: {normalized_recipient}\n")
    sys.stdout.write("\n")
    sys.stdout.write(
        _render_guided_setup_preflight(
            transport=selected_transport,
            discord_session_channels=selected_discord_session_channels,
            telegram_chat_id=selected_telegram_chat_id,
        )
    )
    sys.stdout.write("\nRunning setup commands...\n")
    sys.stdout.flush()

    tmux_bin, tmux_setup_err = _ensure_tmux_available_for_setup()
    if isinstance(tmux_setup_err, str):
        sys.stdout.write(tmux_setup_err)
        return 1
    if isinstance(tmux_bin, str) and tmux_bin.strip():
        os.environ["AGENT_CHAT_TMUX_BIN"] = tmux_bin.strip()

    codex_home = _agent_home_path(agent=selected_agent)
    python_text = _resolve_python_bin_for_notify_hook(python_bin=python_bin)
    script_path = Path(__file__).resolve()

    notify_rc = _run_setup_notify_hook(
        codex_home=codex_home,
        recipient=normalized_recipient,
        python_bin=python_text,
        script_path=script_path,
    )
    if notify_rc != 0:
        return int(notify_rc)

    if selected_transport == "telegram" and not selected_telegram_chat_id:
        sys.stdout.write(
            "\nIf setup-launchd pauses waiting for Telegram bootstrap, send one plain message in the target group/topic now.\n"
        )
        sys.stdout.flush()

    launchd_rc = _run_setup_launchd(
        codex_home=codex_home,
        recipient=normalized_recipient,
        label=os.environ.get("AGENT_CHAT_LAUNCHD_LABEL", _DEFAULT_LAUNCHD_LABEL),
        python_bin=python_text,
        script_path=script_path,
        setup_permissions=True,
        timeout_s=float(_DEFAULT_SETUP_PERMISSIONS_TIMEOUT_S),
        poll_s=float(_DEFAULT_SETUP_PERMISSIONS_POLL_S),
        open_settings=open_settings,
        repair_tcc=False,
    )
    if launchd_rc != 0:
        return int(launchd_rc)

    doctor_rc = _run_doctor(codex_home=codex_home, recipient=normalized_recipient or None, as_json=False)
    sys.stdout.write("\n")
    sys.stdout.write(
        _render_guided_setup_success(
            transport=selected_transport,
            discord_session_channels=selected_discord_session_channels,
        )
    )
    if env_path.name == ".env.telegram.local":
        sys.stdout.write(f"Source this config in future shells if needed: source {env_path}\n")
    else:
        sys.stdout.write(f"Source this config in future shells if needed: source {env_path}\n")
    return int(doctor_rc)



def _doctor_report(*, codex_home: Path, recipient: str | None) -> dict[str, Any]:
    now_ts = int(time.time())
    agent = _current_agent()
    transport_mode = _transport_mode()
    imessage_enabled = _transport_imessage_enabled(mode=transport_mode)
    telegram_enabled = _transport_telegram_enabled(mode=transport_mode)
    discord_enabled = _transport_discord_enabled(mode=transport_mode)
    telegram_chat_id = _telegram_chat_id()
    telegram_chat_ids = _telegram_chat_ids()
    telegram_token_present = bool(_telegram_bot_token())
    discord_channel_id = _discord_channel_id()
    discord_channel_ids = _discord_channel_ids()
    discord_control_channel_id = _discord_control_channel_id()
    discord_session_channels = _discord_session_channels_enabled()
    discord_session_category_id = _discord_session_category_id()
    discord_token_present = bool(_discord_bot_token())
    launchd_label = os.environ.get("AGENT_CHAT_LAUNCHD_LABEL", _DEFAULT_LAUNCHD_LABEL).strip() or _DEFAULT_LAUNCHD_LABEL
    launchd_loaded, launchd_detail = _launchd_service_loaded(label=launchd_label)
    launchd_err_log = _launchd_err_log_path()
    launchd_inbound_warning = _launchd_inbound_warning_active(path=launchd_err_log)
    launchd_inbound_restored = _launchd_inbound_restored_active(path=launchd_err_log)
    launchd_runtime_python, launchd_permission_app = _launchd_runtime_targets_from_plist(
        label=launchd_label
    )

    lock_path = _control_lock_path(codex_home=codex_home)
    lock_pid = _read_lock_pid(lock_path)
    lock_alive = _is_pid_alive(lock_pid)

    chat_db = _chat_db_path(codex_home=codex_home)
    shell_chat_db_readable: bool | None = None
    shell_chat_db_error: str | None = None
    chat_db_readable: bool | None = None
    chat_db_error: str | None = None
    chat_db_source = "not_required"
    runtime_chat_db_readable: bool | None = None
    runtime_chat_db_error: str | None = None
    if imessage_enabled:
        chat_db, shell_chat_db_readable, shell_chat_db_error = _chat_db_access_status(codex_home=codex_home)
        chat_db_readable = shell_chat_db_readable
        chat_db_error = shell_chat_db_error
        chat_db_source = "shell"
        runtime_python = (
            launchd_runtime_python.strip()
            if isinstance(launchd_runtime_python, str) and launchd_runtime_python.strip()
            else ""
        )
        if runtime_python:
            chat_db, runtime_chat_db_readable, runtime_chat_db_error = _chat_db_access_status_for_runtime(
                codex_home=codex_home,
                runtime_python_bin=runtime_python,
            )
            chat_db_readable = runtime_chat_db_readable
            chat_db_error = runtime_chat_db_error
            chat_db_source = "runtime_probe"

        # launchd runtime status is authoritative for long-lived inbound health once restored.
        if launchd_loaded and lock_alive and launchd_inbound_restored and not launchd_inbound_warning:
            chat_db_readable = True
            chat_db_error = None
            chat_db_source = "launchd_log"
    chat_db_exists = chat_db.exists()

    registry = _load_registry(codex_home=codex_home)
    sessions = registry.get("sessions")
    aliases = registry.get("aliases")
    strict_tmux = _strict_tmux_enabled()
    require_session_ref = _require_session_ref_enabled(strict_tmux=strict_tmux)
    preferred_tmux_socket = _normalize_tmux_socket(
        tmux_socket=os.environ.get("AGENT_CHAT_TMUX_SOCKET")
    ) or _choose_registry_tmux_socket(registry=registry)
    active_codex_panes = _tmux_active_codex_panes(tmux_socket=preferred_tmux_socket)
    last_dispatch_error = registry.get("last_dispatch_error")
    if not isinstance(last_dispatch_error, dict):
        last_dispatch_error = None

    outbound_cursor_raw = _read_json(_outbound_cursor_path(codex_home=codex_home)) or {}
    inbound_cursor = _load_inbound_cursor(codex_home=codex_home)
    telegram_inbound_cursor = _load_telegram_inbound_cursor(codex_home=codex_home)
    discord_inbound_cursor = _load_discord_inbound_cursor(codex_home=codex_home)
    reply_cursor_raw = _read_json(
        Path(
            os.environ.get(
                "AGENT_IMESSAGE_REPLY_CURSOR",
                str(codex_home / "tmp" / "agent_chat_reply_cursor.json"),
            )
        )
    ) or {}

    queue = _queue_stats(_queue_path(codex_home=codex_home))
    notify_hook = _notify_hook_status(codex_home=codex_home)
    notify_top_level = bool(notify_hook.get("top_level_present"))
    notify_misscoped = bool(notify_hook.get("mis_scoped_present"))
    notify_error = notify_hook.get("error")

    recipient_text = recipient.strip() if isinstance(recipient, str) else ""
    if not recipient_text:
        fallback_recipient = _recipient_from_launchagent_plist(label=launchd_label)
        if isinstance(fallback_recipient, str):
            recipient_text = fallback_recipient
    health: list[str] = []
    if imessage_enabled and not recipient_text:
        health.append("missing recipient (AGENT_IMESSAGE_TO)")
    if telegram_enabled and not telegram_token_present:
        health.append("missing Telegram bot token (AGENT_TELEGRAM_BOT_TOKEN)")
    if telegram_enabled and not telegram_chat_ids:
        health.append("missing Telegram chat id (set AGENT_TELEGRAM_CHAT_ID or AGENT_TELEGRAM_CHAT_IDS)")
    if discord_enabled and not discord_token_present:
        health.append("missing Discord bot token (AGENT_DISCORD_BOT_TOKEN)")
    if discord_enabled and not discord_channel_ids:
        health.append("missing Discord channel id (set AGENT_DISCORD_CHANNEL_ID or AGENT_DISCORD_CHANNEL_IDS)")
    if not launchd_loaded:
        health.append("launchd service not loaded")
    if imessage_enabled and launchd_inbound_warning:
        health.append("launchd reports inbound disabled (check chat.db permissions)")
    if imessage_enabled and not chat_db_readable:
        health.append("chat.db unreadable for inbound replies")
    queue_lines = queue.get("lines")
    if isinstance(queue_lines, int) and queue_lines > 0:
        health.append("fallback queue has pending messages")
    if not lock_alive:
        health.append("control-plane lock PID not alive")
    if not notify_top_level:
        if agent == "claude":
            health.append("notify hook is not configured in ~/.claude/settings.json")
        else:
            health.append("notify hook is not configured at top-level in ~/.codex/config.toml")
    if notify_misscoped:
        health.append("notify hook appears under [notice.model_migrations]; move it to top-level `notify`")
    if isinstance(notify_error, str) and notify_error.strip():
        if agent == "claude":
            health.append("unable to parse ~/.claude/settings.json for notify hook")
        else:
            health.append("unable to parse ~/.codex/config.toml for notify hook")

    return {
        "ok": len(health) == 0,
        "ts": now_ts,
        "agent": agent,
        "codex_home": str(codex_home),
        "recipient": recipient_text or None,
        "transport": {
            "mode": transport_mode,
            "transports": _transport_list(mode=transport_mode),
            "imessage_enabled": imessage_enabled,
            "telegram_enabled": telegram_enabled,
            "discord_enabled": discord_enabled,
            "telegram_chat_id": telegram_chat_id,
            "telegram_chat_ids": telegram_chat_ids,
            "telegram_token_present": telegram_token_present,
            "discord_channel_id": discord_channel_id,
            "discord_channel_ids": discord_channel_ids,
            "discord_control_channel_id": discord_control_channel_id,
            "discord_session_channels": discord_session_channels,
            "discord_session_category_id": discord_session_category_id,
            "discord_token_present": discord_token_present,
        },
        "launchd": {
            "label": launchd_label,
            "loaded": launchd_loaded,
            "detail": launchd_detail,
            "err_log_path": str(launchd_err_log),
            "inbound_warning": launchd_inbound_warning,
            "inbound_restored": launchd_inbound_restored,
            "runtime_python": launchd_runtime_python,
            "permission_app": launchd_permission_app,
        },
        "lock": {
            "path": str(lock_path),
            "pid": lock_pid,
            "pid_alive": lock_alive,
        },
        "chat_db": {
            "path": str(chat_db),
            "exists": chat_db_exists,
            "readable": chat_db_readable,
            "error": chat_db_error,
            "source": chat_db_source,
            "shell_readable": shell_chat_db_readable,
            "shell_error": shell_chat_db_error,
            "runtime_readable": runtime_chat_db_readable,
            "runtime_error": runtime_chat_db_error,
        },
        "state": {
            "session_count": len(sessions) if isinstance(sessions, dict) else 0,
            "alias_count": len(aliases) if isinstance(aliases, dict) else 0,
            "inbound_cursor_rowid": inbound_cursor,
            "telegram_inbound_cursor_update_id": telegram_inbound_cursor,
            "discord_inbound_cursor": discord_inbound_cursor,
            "outbound_cursor_ts": outbound_cursor_raw.get("ts") if isinstance(outbound_cursor_raw, dict) else None,
            "reply_cursor_rowid": reply_cursor_raw.get("last_rowid") if isinstance(reply_cursor_raw, dict) else None,
            "last_dispatch_error": last_dispatch_error,
        },
        "routing": {
            "strict_tmux": strict_tmux,
            "require_session_ref": require_session_ref,
            "tmux_socket": preferred_tmux_socket,
            "active_codex_panes": active_codex_panes,
        },
        "queue": queue,
        "notify_hook": notify_hook,
        "issues": health,
    }


def _run_doctor(*, codex_home: Path, recipient: str | None, as_json: bool) -> int:
    report = _doctor_report(codex_home=codex_home, recipient=recipient)
    if as_json:
        sys.stdout.write(json.dumps(report, ensure_ascii=False, indent=2))
        sys.stdout.write("\n")
        return 0

    status = "OK" if bool(report.get("ok")) else "DEGRADED"
    sys.stdout.write(f"Agent iMessage doctor: {status}\n")
    sys.stdout.write(f"Agent: {report.get('agent') or _current_agent()}\n")
    sys.stdout.write(f"Home: {report.get('codex_home')}\n")
    sys.stdout.write(f"Recipient: {report.get('recipient') or '(missing)'}\n")
    transport = _coerce_dict(report.get("transport"))
    sys.stdout.write(
        "Transport: "
        f"mode={transport.get('mode') or _transport_mode()} "
        f"imessage={bool(transport.get('imessage_enabled'))} "
        f"telegram={bool(transport.get('telegram_enabled'))} "
        f"discord={bool(transport.get('discord_enabled'))}\n"
    )
    if bool(transport.get("telegram_enabled")):
        telegram_chat_id = transport.get("telegram_chat_id")
        sys.stdout.write(f"Telegram chat: {telegram_chat_id or '(missing)'}\n")
        telegram_chat_ids = transport.get("telegram_chat_ids")
        if isinstance(telegram_chat_ids, list) and telegram_chat_ids:
            rendered_chat_ids = ", ".join(str(item).strip() for item in telegram_chat_ids if str(item).strip())
            if rendered_chat_ids:
                sys.stdout.write(f"Telegram inbound chats: {rendered_chat_ids}\n")
        sys.stdout.write(
            f"Telegram token: {'configured' if bool(transport.get('telegram_token_present')) else 'missing'}\n"
        )
    if bool(transport.get("discord_enabled")):
        discord_channel_id = transport.get("discord_channel_id")
        sys.stdout.write(f"Discord channel: {discord_channel_id or '(missing)'}\n")
        discord_channel_ids = transport.get("discord_channel_ids")
        if isinstance(discord_channel_ids, list) and discord_channel_ids:
            rendered_channel_ids = ", ".join(str(item).strip() for item in discord_channel_ids if str(item).strip())
            if rendered_channel_ids:
                sys.stdout.write(f"Discord inbound channels: {rendered_channel_ids}\n")
        discord_control_channel_id = transport.get("discord_control_channel_id")
        if isinstance(discord_control_channel_id, str) and discord_control_channel_id.strip():
            sys.stdout.write(f"Discord control channel: {discord_control_channel_id.strip()}\n")
        if bool(transport.get("discord_session_channels")):
            sys.stdout.write("Discord session channels: enabled\n")
            discord_session_category_id = transport.get("discord_session_category_id")
            if isinstance(discord_session_category_id, str) and discord_session_category_id.strip():
                sys.stdout.write(f"Discord session category: {discord_session_category_id.strip()}\n")
        sys.stdout.write(
            f"Discord token: {'configured' if bool(transport.get('discord_token_present')) else 'missing'}\n"
        )

    launchd = _coerce_dict(report.get("launchd"))
    sys.stdout.write(
        "Launchd: "
        f"{'loaded' if launchd.get('loaded') else 'not loaded'}"
        f" ({launchd.get('label')})\n"
    )
    detail = launchd.get("detail")
    if isinstance(detail, str) and detail.strip():
        sys.stdout.write(f"  detail: {detail.strip()}\n")
    runtime_python = launchd.get("runtime_python")
    if isinstance(runtime_python, str) and runtime_python.strip():
        sys.stdout.write(f"  runtime_python: {runtime_python.strip()}\n")
    permission_app = launchd.get("permission_app")
    if isinstance(permission_app, str) and permission_app.strip():
        sys.stdout.write(f"  permission_app: {permission_app.strip()}\n")
    if bool(launchd.get("inbound_warning")):
        sys.stdout.write(f"  warning: inbound-disabled seen in {launchd.get('err_log_path')}\n")

    lock = _coerce_dict(report.get("lock"))
    sys.stdout.write(
        "Lock: "
        f"pid={lock.get('pid') or '-'}"
        f" alive={bool(lock.get('pid_alive'))}"
        f" path={lock.get('path')}\n"
    )

    chat_db = _coerce_dict(report.get("chat_db"))
    sys.stdout.write(
        "Inbound chat.db: "
        f"{'readable' if chat_db.get('readable') else 'unreadable'}"
        f" path={chat_db.get('path')}\n"
    )
    chat_err = chat_db.get("error")
    if isinstance(chat_err, str) and chat_err.strip():
        sys.stdout.write(f"  detail: {chat_err.strip()}\n")

    queue = _coerce_dict(report.get("queue"))
    sys.stdout.write(
        "Fallback queue: "
        f"lines={queue.get('lines', 0)}"
        f" size={queue.get('size_bytes', 0)}"
        f" path={queue.get('path')}\n"
    )

    notify_hook = _coerce_dict(report.get("notify_hook"))
    sys.stdout.write(
        "Notify hook: "
        f"{'configured' if notify_hook.get('top_level_present') else 'missing'}"
        f" path={notify_hook.get('path')}\n"
    )
    if bool(notify_hook.get("mis_scoped_present")):
        sys.stdout.write("  warning: found notify under [notice.model_migrations]\n")
    notify_err = notify_hook.get("error")
    if isinstance(notify_err, str) and notify_err.strip():
        sys.stdout.write(f"  detail: {notify_err.strip()}\n")

    routing = _coerce_dict(report.get("routing"))
    active = _coerce_dict(routing.get("active_codex_panes"))
    sys.stdout.write(
        "Routing: "
        f"strict_tmux={bool(routing.get('strict_tmux'))} "
        f"require_session_ref={bool(routing.get('require_session_ref'))} "
        f"tmux_socket={routing.get('tmux_socket') or '-'} "
        f"active_codex_panes={active.get('count', 0)}\n"
    )

    issues = report.get("issues")
    if isinstance(issues, list) and issues:
        sys.stdout.write("Issues:\n")
        for issue in issues:
            if isinstance(issue, str) and issue.strip():
                sys.stdout.write(f"- {issue.strip()}\n")
    return 0


def _default_registry() -> dict[str, Any]:
    return {
        "schema_version": 2,
        "sessions": {},
        "aliases": {},
        "last_dispatch_error": None,
        "pending_new_session_choice": None,
        "pending_new_session_choice_by_context": {},
        "conversation_bindings": {},
        "conversation_runtime_bindings": {},
        "pending_new_session_choice_by_thread": {},
        "telegram_thread_bindings": {},
        "telegram_thread_tmux_bindings": {},
        "surface_onboarding_control": {},
        "surface_onboarding_session": {},
        "ts": int(time.time()),
    }



def _normalize_surface_onboarding_state(*, raw: object) -> dict[str, int]:
    if not isinstance(raw, dict):
        return {}
    out: dict[str, int] = {}
    for key, value in raw.items():
        surface_key = key.strip() if isinstance(key, str) else ""
        ts = int(value) if isinstance(value, int) else None
        if not surface_key or not isinstance(ts, int) or ts <= 0:
            continue
        out[surface_key] = ts
    return out



def _surface_key_for_context(
    *,
    transport: str | None,
    recipient: str | None = None,
    telegram_chat_id: str | None = None,
    telegram_message_thread_id: int | None = None,
    discord_channel_id: str | None = None,
    discord_parent_channel_id: str | None = None,
) -> str | None:
    normalized_transport = transport.strip().lower() if isinstance(transport, str) and transport.strip() else "imessage"
    if normalized_transport == "telegram":
        conv_key = _conversation_key(
            transport="telegram",
            channel_id=telegram_chat_id,
            thread_id=telegram_message_thread_id,
        )
        if conv_key:
            return conv_key
        chat_id = telegram_chat_id.strip() if isinstance(telegram_chat_id, str) and telegram_chat_id.strip() else ""
        return f"telegram:{chat_id}:0" if chat_id else None
    if normalized_transport == "discord":
        context_channel_id = discord_parent_channel_id or discord_channel_id
        context_thread_id: int | str | None = 0
        if (
            isinstance(discord_parent_channel_id, str)
            and discord_parent_channel_id.strip()
            and isinstance(discord_channel_id, str)
            and discord_channel_id.strip()
            and discord_parent_channel_id.strip() != discord_channel_id.strip()
        ):
            context_thread_id = discord_channel_id.strip()
        return _conversation_key(
            transport="discord",
            channel_id=context_channel_id,
            thread_id=context_thread_id,
        )
    recipient_text = recipient.strip() if isinstance(recipient, str) and recipient.strip() else "global"
    return f"imessage:{recipient_text}:0"



def _surface_onboarding_bucket(*, registry: dict[str, Any], bucket: str) -> dict[str, int]:
    key = "surface_onboarding_session" if bucket == "session" else "surface_onboarding_control"
    raw = registry.get(key)
    normalized = _normalize_surface_onboarding_state(raw=raw)
    registry[key] = normalized
    return normalized



def _surface_onboarding_seen(*, registry: dict[str, Any], bucket: str, surface_key: str | None) -> bool:
    key = surface_key.strip() if isinstance(surface_key, str) else ""
    if not key:
        return False
    state = _surface_onboarding_bucket(registry=registry, bucket=bucket)
    return key in state



def _mark_surface_onboarding_seen(*, registry: dict[str, Any], bucket: str, surface_key: str | None) -> None:
    key = surface_key.strip() if isinstance(surface_key, str) else ""
    if not key:
        return
    state = _surface_onboarding_bucket(registry=registry, bucket=bucket)
    state[key] = int(time.time())



def _control_surface_onboarding_hint(*, transport: str | None) -> str:
    normalized_transport = transport.strip().lower() if isinstance(transport, str) and transport.strip() else "imessage"
    if normalized_transport == "telegram":
        return (
            "\n\nQuick start:\n"
            "- `list` shows sessions\n"
            "- `where` explains this topic\n"
            "- `bind @<session_ref>` binds this topic\n"
            "- `new <label>: <instruction>` starts a session"
        )
    if normalized_transport == "discord":
        return (
            "\n\nQuick start:\n"
            "- `list` shows sessions\n"
            "- `where` explains this channel or thread\n"
            "- `bind @<session_ref>` rebinds this surface\n"
            "- `new <label>: <instruction>` starts a session"
        )
    return (
        "\n\nQuick start:\n"
        "- `list` shows sessions\n"
        "- `where` explains this routing surface\n"
        "- `@<session_ref> <instruction>` targets one session\n"
        "- `new <label>: <instruction>` starts a session"
    )



def _session_surface_onboarding_hint(*, transport: str | None) -> str:
    normalized_transport = transport.strip().lower() if isinstance(transport, str) and transport.strip() else "imessage"
    if normalized_transport == "discord":
        return (
            "\n\nThis surface is now session-bound:\n"
            "- plain text continues the same session\n"
            "- `where` explains the binding\n"
            "- `bind @<session_ref>` moves it to another session"
        )
    if normalized_transport == "telegram":
        return (
            "\n\nThis topic is now session-bound:\n"
            "- plain text continues the same session\n"
            "- `where` explains the binding\n"
            "- `bind @<session_ref>` moves it to another session"
        )
    return (
        "\n\nThis session is active here:\n"
        "- plain text continues it\n"
        "- `where` explains the routing context\n"
        "- `list` shows other sessions"
    )



def _append_surface_onboarding_hint(
    *,
    registry: dict[str, Any] | None,
    text: str,
    bucket: str,
    transport: str | None,
    recipient: str | None = None,
    telegram_chat_id: str | None = None,
    telegram_message_thread_id: int | None = None,
    discord_channel_id: str | None = None,
    discord_parent_channel_id: str | None = None,
) -> str:
    active_registry = registry if isinstance(registry, dict) else None
    if active_registry is None:
        return text
    surface_key = _surface_key_for_context(
        transport=transport,
        recipient=recipient,
        telegram_chat_id=telegram_chat_id,
        telegram_message_thread_id=telegram_message_thread_id,
        discord_channel_id=discord_channel_id,
        discord_parent_channel_id=discord_parent_channel_id,
    )
    if _surface_onboarding_seen(registry=active_registry, bucket=bucket, surface_key=surface_key):
        return text
    _mark_surface_onboarding_seen(registry=active_registry, bucket=bucket, surface_key=surface_key)
    hint = _session_surface_onboarding_hint(transport=transport) if bucket == "session" else _control_surface_onboarding_hint(transport=transport)
    return text.rstrip() + hint


def _normalize_pending_new_session_choice_payload(*, raw: object) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None

    prompt = raw.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        return None

    action_raw = raw.get("action")
    action = action_raw.strip().lower() if isinstance(action_raw, str) else "implicit"
    if action not in {"resume", "implicit"}:
        action = "implicit"

    source_text = raw.get("source_text") if isinstance(raw.get("source_text"), str) else ""
    source_ref = raw.get("source_ref") if isinstance(raw.get("source_ref"), str) else None
    label = raw.get("label") if isinstance(raw.get("label"), str) else None
    cwd = raw.get("cwd") if isinstance(raw.get("cwd"), str) else None
    created_ts = raw.get("created_ts") if isinstance(raw.get("created_ts"), int) else int(time.time())

    return {
        "prompt": prompt.strip(),
        "action": action,
        "source_text": source_text.strip() if isinstance(source_text, str) else "",
        "source_ref": source_ref.strip() if isinstance(source_ref, str) and source_ref.strip() else None,
        "label": label.strip() if isinstance(label, str) and label.strip() else None,
        "cwd": cwd.strip() if isinstance(cwd, str) and cwd.strip() else None,
        "created_ts": created_ts,
    }


def _normalize_pending_new_session_choice_by_thread(*, raw: object) -> dict[str, dict[str, Any]]:
    if not isinstance(raw, dict):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for key, value in raw.items():
        thread_key = key.strip() if isinstance(key, str) else ""
        if not thread_key:
            continue
        payload = _normalize_pending_new_session_choice_payload(raw=value)
        if isinstance(payload, dict):
            out[thread_key] = payload
    return out


def _normalize_pending_new_session_choice_by_context(*, raw: object) -> dict[str, dict[str, Any]]:
    if not isinstance(raw, dict):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for key, value in raw.items():
        context_key = key.strip() if isinstance(key, str) else ""
        if not context_key:
            continue
        payload = _normalize_pending_new_session_choice_payload(raw=value)
        if isinstance(payload, dict):
            out[context_key] = payload
    return out


def _conversation_key(*, transport: str | None, channel_id: str | None, thread_id: int | str | None = None) -> str | None:
    return registry_conversation_key(transport=transport, channel_id=channel_id, thread_id=thread_id)


def _conversation_key_from_telegram_thread_key(*, thread_key: str | None) -> str | None:
    normalized = _normalize_telegram_thread_key(thread_key=thread_key)
    if not normalized:
        return None
    chat_id = _telegram_thread_chat_id_from_key(thread_key=normalized)
    thread_id = _telegram_thread_id_from_key(thread_key=normalized)
    return _conversation_key(transport="telegram", channel_id=chat_id, thread_id=thread_id)


def _normalize_telegram_thread_bindings(*, raw: object, sessions: dict[str, Any]) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    out: dict[str, str] = {}
    for key, value in raw.items():
        thread_key = _normalize_telegram_thread_key(thread_key=key if isinstance(key, str) else None)
        sid = value.strip() if isinstance(value, str) else ""
        if not thread_key or not sid:
            continue
        if sid not in sessions:
            continue
        out[thread_key] = sid
    return out


def _normalize_conversation_bindings_for_registry(
    *,
    raw: object,
    legacy_telegram_raw: object,
    sessions: dict[str, Any],
) -> dict[str, str]:
    out = normalize_conversation_bindings(raw=raw, sessions=sessions)
    legacy = _normalize_telegram_thread_bindings(raw=legacy_telegram_raw, sessions=sessions)
    for thread_key, sid in legacy.items():
        conv_key = _conversation_key_from_telegram_thread_key(thread_key=thread_key)
        if conv_key and sid not in {""}:
            out.setdefault(conv_key, sid)
    return out


def _normalize_telegram_thread_tmux_bindings(*, raw: object) -> dict[str, dict[str, str]]:
    if not isinstance(raw, dict):
        return {}

    out: dict[str, dict[str, str]] = {}
    for key, value in raw.items():
        thread_key = _normalize_telegram_thread_key(thread_key=key if isinstance(key, str) else None)
        if not thread_key:
            continue

        pane: str = ""
        socket: str | None = None
        agent: str | None = None

        if isinstance(value, str):
            pane = value.strip()
        elif isinstance(value, dict):
            pane_raw = value.get("tmux_pane")
            pane = pane_raw.strip() if isinstance(pane_raw, str) else ""
            socket_raw = value.get("tmux_socket")
            if isinstance(socket_raw, str):
                socket = _normalize_tmux_socket(tmux_socket=socket_raw)
            agent_raw = value.get("agent")
            if isinstance(agent_raw, str) and agent_raw.strip():
                agent = _normalize_agent(agent=agent_raw)
        if not pane:
            continue

        record: dict[str, str] = {"tmux_pane": pane}
        if isinstance(socket, str) and socket.strip():
            record["tmux_socket"] = socket.strip()
        if isinstance(agent, str) and agent.strip():
            record["agent"] = agent.strip()
        out[thread_key] = record
    return out


def _normalize_conversation_runtime_bindings_for_registry(*, raw: object, legacy_telegram_raw: object) -> dict[str, dict[str, str]]:
    out = normalize_runtime_bindings(raw)
    legacy = _normalize_telegram_thread_tmux_bindings(raw=legacy_telegram_raw)
    for thread_key, record in legacy.items():
        conv_key = _conversation_key_from_telegram_thread_key(thread_key=thread_key)
        if conv_key:
            out.setdefault(conv_key, record)
    return out


def _canonicalize_telegram_thread_state(*, sessions: dict[str, Any], raw_bindings: object) -> dict[str, str]:
    explicit = _normalize_telegram_thread_bindings(raw=raw_bindings, sessions=sessions)
    explicit_thread_keys = set(explicit.keys())
    canonical: dict[str, str] = {}
    session_to_thread: dict[str, str] = {}

    # Explicit bindings from registry state are authoritative. When duplicates
    # exist for a session, last entry wins by insertion order.
    for thread_key, sid in explicit.items():
        previous_thread = session_to_thread.get(sid)
        if isinstance(previous_thread, str) and previous_thread != thread_key:
            canonical.pop(previous_thread, None)

        previous_sid = canonical.get(thread_key)
        if isinstance(previous_sid, str) and previous_sid != sid:
            session_to_thread.pop(previous_sid, None)

        canonical[thread_key] = sid
        session_to_thread[sid] = thread_key

    # Backfill from session metadata only when no explicit binding exists.
    for sid, rec in sessions.items():
        if not isinstance(sid, str) or not sid:
            continue
        if not isinstance(rec, dict):
            continue
        if sid in session_to_thread:
            continue
        thread_key = _telegram_thread_key(
            chat_id=rec.get("telegram_chat_id") if isinstance(rec.get("telegram_chat_id"), str) else None,
            thread_id=_normalize_telegram_thread_id(rec.get("telegram_message_thread_id")),
        )
        if not thread_key or thread_key in canonical or thread_key in explicit_thread_keys:
            continue
        canonical[thread_key] = sid
        session_to_thread[sid] = thread_key

    # Sync session metadata to canonical mapping; clear stale topic metadata.
    for sid, rec in sessions.items():
        if not isinstance(sid, str) or not sid or not isinstance(rec, dict):
            continue
        assigned_key = session_to_thread.get(sid)
        if isinstance(assigned_key, str):
            rec["telegram_chat_id"] = _telegram_thread_chat_id_from_key(thread_key=assigned_key)
            rec["telegram_message_thread_id"] = _telegram_thread_id_from_key(thread_key=assigned_key)
        else:
            if "telegram_chat_id" in rec:
                rec["telegram_chat_id"] = None
            if "telegram_message_thread_id" in rec:
                rec["telegram_message_thread_id"] = None

    return canonical


def _load_registry(*, codex_home: Path) -> dict[str, Any]:
    raw = _read_json(_registry_path(codex_home=codex_home))
    if not isinstance(raw, dict):
        return _default_registry()

    sessions = raw.get("sessions")
    aliases = raw.get("aliases")
    last_dispatch_error = raw.get("last_dispatch_error")
    sessions_map = sessions if isinstance(sessions, dict) else {}
    pending_new_session_choice = _normalize_pending_new_session_choice_payload(
        raw=raw.get("pending_new_session_choice")
    )
    pending_new_session_choice_by_thread = _normalize_pending_new_session_choice_by_thread(
        raw=raw.get("pending_new_session_choice_by_thread")
    )
    pending_new_session_choice_by_context = _normalize_pending_new_session_choice_by_context(
        raw=raw.get("pending_new_session_choice_by_context")
    )
    surface_onboarding_control = _normalize_surface_onboarding_state(raw=raw.get("surface_onboarding_control"))
    surface_onboarding_session = _normalize_surface_onboarding_state(raw=raw.get("surface_onboarding_session"))
    telegram_thread_bindings = _canonicalize_telegram_thread_state(
        sessions=sessions_map,
        raw_bindings=raw.get("telegram_thread_bindings"),
    )
    telegram_thread_tmux_bindings = _normalize_telegram_thread_tmux_bindings(
        raw=raw.get("telegram_thread_tmux_bindings")
    )
    conversation_bindings = _normalize_conversation_bindings_for_registry(
        raw=raw.get("conversation_bindings"),
        legacy_telegram_raw=telegram_thread_bindings,
        sessions=sessions_map,
    )
    conversation_runtime_bindings = _normalize_conversation_runtime_bindings_for_registry(
        raw=raw.get("conversation_runtime_bindings"),
        legacy_telegram_raw=telegram_thread_tmux_bindings,
    )
    for thread_key, payload in pending_new_session_choice_by_thread.items():
        conv_key = _conversation_key_from_telegram_thread_key(thread_key=thread_key)
        if conv_key:
            pending_new_session_choice_by_context.setdefault(conv_key, payload)
    if not isinstance(last_dispatch_error, dict):
        last_dispatch_error = None
    out: dict[str, Any] = {
        "schema_version": int(raw.get("schema_version")) if isinstance(raw.get("schema_version"), int) else 2,
        "sessions": sessions_map,
        "aliases": aliases if isinstance(aliases, dict) else {},
        "last_dispatch_error": last_dispatch_error,
        "pending_new_session_choice": pending_new_session_choice,
        "pending_new_session_choice_by_context": pending_new_session_choice_by_context,
        "conversation_bindings": conversation_bindings,
        "conversation_runtime_bindings": conversation_runtime_bindings,
        "pending_new_session_choice_by_thread": pending_new_session_choice_by_thread,
        "telegram_thread_bindings": telegram_thread_bindings,
        "telegram_thread_tmux_bindings": telegram_thread_tmux_bindings,
        "surface_onboarding_control": surface_onboarding_control,
        "surface_onboarding_session": surface_onboarding_session,
        "ts": int(time.time()),
    }
    _normalize_session_records_in_registry(registry=out)
    return out


def _save_registry(*, codex_home: Path, registry: dict[str, Any]) -> None:
    _normalize_session_records_in_registry(registry=registry)
    sessions = registry.get("sessions")
    if not isinstance(sessions, dict):
        sessions = {}
    aliases = registry.get("aliases")
    if not isinstance(aliases, dict):
        aliases = {}
    last_dispatch_error = registry.get("last_dispatch_error")
    if not isinstance(last_dispatch_error, dict):
        last_dispatch_error = None
    pending_new_session_choice = _normalize_pending_new_session_choice_payload(
        raw=registry.get("pending_new_session_choice")
    )
    pending_new_session_choice_by_context = _normalize_pending_new_session_choice_by_context(
        raw=registry.get("pending_new_session_choice_by_context")
    )
    surface_onboarding_control = _normalize_surface_onboarding_state(raw=registry.get("surface_onboarding_control"))
    surface_onboarding_session = _normalize_surface_onboarding_state(raw=registry.get("surface_onboarding_session"))
    conversation_bindings = _normalize_conversation_bindings_for_registry(
        raw=registry.get("conversation_bindings"),
        legacy_telegram_raw=registry.get("telegram_thread_bindings"),
        sessions=sessions,
    )
    conversation_runtime_bindings = _normalize_conversation_runtime_bindings_for_registry(
        raw=registry.get("conversation_runtime_bindings"),
        legacy_telegram_raw=registry.get("telegram_thread_tmux_bindings"),
    )

    telegram_thread_bindings = _canonicalize_telegram_thread_state(
        sessions=sessions,
        raw_bindings=registry.get("telegram_thread_bindings"),
    )
    for conv_key, sid in conversation_bindings.items():
        if not isinstance(conv_key, str) or not conv_key.startswith("telegram:"):
            continue
        _, chat_id, thread_raw = conv_key.split(":", 2)
        thread_key = _telegram_thread_key(chat_id=chat_id, thread_id=_normalize_telegram_thread_id(thread_raw))
        if thread_key:
            telegram_thread_bindings[thread_key] = sid
    telegram_thread_bindings = _canonicalize_telegram_thread_state(
        sessions=sessions,
        raw_bindings=telegram_thread_bindings,
    )

    telegram_thread_tmux_bindings = _normalize_telegram_thread_tmux_bindings(
        raw=registry.get("telegram_thread_tmux_bindings")
    )
    for conv_key, record in conversation_runtime_bindings.items():
        if not isinstance(conv_key, str) or not conv_key.startswith("telegram:"):
            continue
        _, chat_id, thread_raw = conv_key.split(":", 2)
        thread_key = _telegram_thread_key(chat_id=chat_id, thread_id=_normalize_telegram_thread_id(thread_raw))
        if thread_key:
            telegram_thread_tmux_bindings[thread_key] = record

    pending_new_session_choice_by_thread = _normalize_pending_new_session_choice_by_thread(
        raw=registry.get("pending_new_session_choice_by_thread")
    )
    for conv_key, payload in pending_new_session_choice_by_context.items():
        if not isinstance(conv_key, str) or not conv_key.startswith("telegram:"):
            continue
        _, chat_id, thread_raw = conv_key.split(":", 2)
        thread_key = _telegram_thread_key(chat_id=chat_id, thread_id=_normalize_telegram_thread_id(thread_raw))
        if thread_key:
            pending_new_session_choice_by_thread[thread_key] = payload

    # Keep only newest sessions by recency keys.
    if len(sessions) > _MAX_REGISTRY_ENTRIES:
        sortable: list[tuple[str, int]] = []
        for sid, rec in sessions.items():
            if not isinstance(sid, str) or not isinstance(rec, dict):
                continue
            ts = rec.get("last_attention_ts")
            if not isinstance(ts, int):
                ts = rec.get("last_update_ts")
            if not isinstance(ts, int):
                ts = 0
            sortable.append((sid, ts))
        keep = {sid for sid, _ in sorted(sortable, key=lambda item: item[1], reverse=True)[:_MAX_REGISTRY_ENTRIES]}
        sessions = {sid: rec for sid, rec in sessions.items() if sid in keep}
        aliases = {
            alias: sid
            for alias, sid in aliases.items()
            if isinstance(alias, str) and isinstance(sid, str) and sid in sessions
        }
        telegram_thread_bindings = {
            thread_key: sid
            for thread_key, sid in telegram_thread_bindings.items()
            if isinstance(thread_key, str) and isinstance(sid, str) and sid in sessions
        }
        conversation_bindings = {
            key: sid
            for key, sid in conversation_bindings.items()
            if isinstance(key, str) and isinstance(sid, str) and sid in sessions
        }

    _write_json(
        _registry_path(codex_home=codex_home),
        {
            "schema_version": 2,
            "sessions": sessions,
            "aliases": aliases,
            "last_dispatch_error": last_dispatch_error,
            "pending_new_session_choice": pending_new_session_choice,
            "pending_new_session_choice_by_context": pending_new_session_choice_by_context,
            "conversation_bindings": conversation_bindings,
            "conversation_runtime_bindings": conversation_runtime_bindings,
            "pending_new_session_choice_by_thread": pending_new_session_choice_by_thread,
            "telegram_thread_bindings": telegram_thread_bindings,
            "telegram_thread_tmux_bindings": telegram_thread_tmux_bindings,
            "surface_onboarding_control": surface_onboarding_control,
            "surface_onboarding_session": surface_onboarding_session,
            "ts": int(time.time()),
        },
    )


def _session_ref(session_id: str, ref_len: int = _DEFAULT_REF_LEN) -> str:
    sid = session_id.strip()
    if not sid:
        return ""
    n = max(4, int(ref_len))
    return sid[:n]


def _upsert_session(
    *,
    registry: dict[str, Any],
    session_id: str,
    fields: dict[str, Any],
) -> None:
    sid = session_id.strip()
    if not sid:
        return

    sessions = registry.setdefault("sessions", {})
    if not isinstance(sessions, dict):
        sessions = {}
        registry["sessions"] = sessions

    existing = sessions.get(sid)
    if not isinstance(existing, dict):
        existing = {}

    merged = {**existing, **fields}
    merged["session_id"] = sid
    merged["ref"] = _session_ref(sid)
    merged["last_update_ts"] = int(time.time())
    sessions[sid] = merged

    alias = merged.get("alias")
    if isinstance(alias, str) and alias.strip():
        alias_norm = alias.strip().lower()
        aliases = registry.setdefault("aliases", {})
        if not isinstance(aliases, dict):
            aliases = {}
            registry["aliases"] = aliases
        aliases[alias_norm] = sid



def _normalize_session_record_for_registry(*, session_rec: dict[str, Any]) -> None:
    if not isinstance(session_rec, dict):
        return

    if "discord_progress_mode" in session_rec or (
        isinstance(session_rec.get("discord_channel_id"), str) and session_rec.get("discord_channel_id").strip()
    ):
        session_rec["discord_progress_mode"] = _session_discord_progress_mode(session_rec=session_rec)

    if "desktop_attention_state" in session_rec:
        session_rec["desktop_attention_state"] = _normalize_desktop_attention_state(
            session_rec.get("desktop_attention_state")
        )

    prompt_status = _normalize_active_prompt_status(session_rec.get("active_prompt_status"))
    if prompt_status is None:
        session_rec.pop("active_prompt_status", None)
    else:
        session_rec["active_prompt_status"] = prompt_status

    prompt_origin = _normalize_active_prompt_origin(session_rec.get("active_prompt_origin"))
    if prompt_origin is None:
        session_rec.pop("active_prompt_origin", None)
    else:
        session_rec["active_prompt_origin"] = prompt_origin
        if prompt_origin == "discord":
            session_rec["active_prompt_transport"] = "discord"

    prompt_transport = session_rec.get("active_prompt_transport")
    if isinstance(prompt_transport, str):
        prompt_transport = prompt_transport.strip().lower()
        if prompt_transport:
            session_rec["active_prompt_transport"] = prompt_transport
        else:
            session_rec.pop("active_prompt_transport", None)
    else:
        session_rec.pop("active_prompt_transport", None)



def _normalize_session_records_in_registry(*, registry: dict[str, Any]) -> None:
    sessions = registry.get("sessions")
    if not isinstance(sessions, dict):
        return
    for rec in sessions.values():
        if isinstance(rec, dict):
            _normalize_session_record_for_registry(session_rec=rec)



def _set_default_discord_progress_mode_for_session(
    *,
    registry: dict[str, Any],
    session_id: str,
) -> str:
    sid = session_id.strip()
    if not sid:
        return "origin_scoped"
    sessions = registry.setdefault("sessions", {})
    if not isinstance(sessions, dict):
        sessions = {}
        registry["sessions"] = sessions
    rec = sessions.get(sid)
    if not isinstance(rec, dict):
        rec = {"session_id": sid, "ref": _session_ref(sid)}
        sessions[sid] = rec
    normalized = _session_discord_progress_mode(session_rec=rec)
    rec["discord_progress_mode"] = normalized
    return normalized



def _build_prompt_lifecycle_id(*, session_id: str, context_key: str | None) -> str:
    seed = f"{session_id.strip()}:{context_key or ''}:{time.time_ns()}"
    digest = hashlib.sha1(seed.encode("utf-8", errors="ignore")).hexdigest()[:12]
    return f"prompt-{digest}"



def _record_discord_prompt_acceptance(
    *,
    registry: dict[str, Any],
    session_id: str,
    context_key: str | None,
) -> str:
    sid = session_id.strip()
    if not sid:
        return ""
    prompt_id = _build_prompt_lifecycle_id(session_id=sid, context_key=context_key)
    _upsert_session(
        registry=registry,
        session_id=sid,
        fields={
            "active_prompt_id": prompt_id,
            "active_prompt_origin": "discord",
            "active_prompt_transport": "discord",
            "active_prompt_context": context_key.strip() if isinstance(context_key, str) and context_key.strip() else None,
            "active_prompt_status": "accepted",
            "last_discord_prompt_ts": int(time.time()),
        },
    )
    _set_default_discord_progress_mode_for_session(registry=registry, session_id=sid)
    return prompt_id


def _requires_tmux_backed_new_session_for_context(*, transport: str | None, agent: str | None) -> bool:
    return (transport or "").strip().lower() == "discord" and _normalize_agent(agent=agent) == "pi"



def _update_active_prompt_lifecycle(
    *,
    registry: dict[str, Any],
    session_id: str,
    status: str | None = None,
    desktop_attention_state: str | None = None,
) -> None:
    sid = session_id.strip()
    if not sid:
        return

    fields: dict[str, Any] = {}
    normalized_status = _normalize_active_prompt_status(status)
    if normalized_status is not None:
        fields["active_prompt_status"] = normalized_status
        if normalized_status == "needs_input" and desktop_attention_state is None:
            desktop_attention_state = "waiting_for_user"
        elif normalized_status in {"completed", "failed", "cancelled"} and desktop_attention_state is None:
            desktop_attention_state = "resolved"

    if desktop_attention_state is not None:
        normalized_attention = _normalize_desktop_attention_state(desktop_attention_state)
        fields["desktop_attention_state"] = normalized_attention
        fields["last_desktop_attention_ts"] = int(time.time())

    if fields:
        _upsert_session(registry=registry, session_id=sid, fields=fields)


_NOTIFY_TERMINAL_CANCELLED_VALUES = {
    "cancel",
    "cancelled",
    "canceled",
    "abort",
    "aborted",
    "interrupted",
    "user_cancelled",
    "user_canceled",
}


_NOTIFY_TERMINAL_FAILED_VALUES = {
    "error",
    "errored",
    "failed",
    "failure",
    "exception",
    "crash",
    "crashed",
    "timed_out",
    "timeout",
}


def _infer_notify_terminal_status(*, payload: dict[str, Any] | None) -> str:
    if not isinstance(payload, dict):
        return "completed"

    def _string_candidates(source: dict[str, Any] | None) -> list[str]:
        if not isinstance(source, dict):
            return []
        out: list[str] = []
        for key in (
            "status",
            "state",
            "result",
            "outcome",
            "reason",
            "stop_reason",
            "finish_reason",
            "hook_event_name",
            "hook-event-name",
            "hookEventName",
        ):
            value = source.get(key)
            if isinstance(value, str) and value.strip():
                out.append(value.strip().lower())
        return out

    candidates = _string_candidates(payload)
    params = payload.get("params") if isinstance(payload.get("params"), dict) else None
    candidates.extend(_string_candidates(params))

    if any(value in _NOTIFY_TERMINAL_CANCELLED_VALUES for value in candidates):
        return "cancelled"
    if any(value in _NOTIFY_TERMINAL_FAILED_VALUES for value in candidates):
        return "failed"

    for source in (payload, params):
        if not isinstance(source, dict):
            continue
        for key in ("success", "ok"):
            value = source.get(key)
            if value is False:
                return "failed"
        for key in ("error", "errors", "exception"):
            value = source.get(key)
            if isinstance(value, str) and value.strip():
                return "failed"
            if isinstance(value, (dict, list)) and value:
                return "failed"

    return "completed"


def _set_alias(*, registry: dict[str, Any], session_id: str, label: str) -> None:
    sid = session_id.strip()
    alias = label.strip().lower()
    if not sid or not alias:
        return

    sessions = registry.setdefault("sessions", {})
    if not isinstance(sessions, dict):
        sessions = {}
        registry["sessions"] = sessions

    rec = sessions.get(sid)
    if not isinstance(rec, dict):
        rec = {}
    rec["alias"] = alias
    sessions[sid] = rec

    aliases = registry.setdefault("aliases", {})
    if not isinstance(aliases, dict):
        aliases = {}
        registry["aliases"] = aliases
    aliases[alias] = sid


def _get_pending_new_session_choice(*, registry: dict[str, Any]) -> dict[str, Any] | None:
    return _normalize_pending_new_session_choice_payload(raw=registry.get("pending_new_session_choice"))


def _set_pending_new_session_choice(
    *,
    registry: dict[str, Any],
    prompt: str,
    action: str,
    source_text: str,
    source_ref: str | None = None,
    label: str | None = None,
    cwd: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "prompt": prompt.strip(),
        "action": action.strip().lower() if isinstance(action, str) else "implicit",
        "source_text": source_text.strip() if isinstance(source_text, str) else "",
        "source_ref": source_ref.strip() if isinstance(source_ref, str) and source_ref.strip() else None,
        "label": label.strip() if isinstance(label, str) and label.strip() else None,
        "cwd": cwd.strip() if isinstance(cwd, str) and cwd.strip() else None,
        "created_ts": int(time.time()),
    }
    registry["pending_new_session_choice"] = payload
    return payload


def _clear_pending_new_session_choice(*, registry: dict[str, Any]) -> None:
    if registry.get("pending_new_session_choice") is None:
        return
    registry["pending_new_session_choice"] = None


def _get_pending_new_session_choice_by_thread(
    *,
    registry: dict[str, Any],
    thread_key: str | None,
) -> dict[str, Any] | None:
    key = thread_key.strip() if isinstance(thread_key, str) else ""
    if not key:
        return None
    conv_key = _conversation_key_from_telegram_thread_key(thread_key=key)
    from_context = _get_pending_new_session_choice_by_context(registry=registry, context_key=conv_key)
    if isinstance(from_context, dict):
        return from_context
    mapping = registry.get("pending_new_session_choice_by_thread")
    if not isinstance(mapping, dict):
        return None
    return _normalize_pending_new_session_choice_payload(raw=mapping.get(key))


def _set_pending_new_session_choice_by_thread(
    *,
    registry: dict[str, Any],
    thread_key: str,
    prompt: str,
    action: str,
    source_text: str,
    source_ref: str | None = None,
    label: str | None = None,
    cwd: str | None = None,
) -> dict[str, Any]:
    key = thread_key.strip()
    payload = _set_pending_new_session_choice(
        registry={"pending_new_session_choice": None},
        prompt=prompt,
        action=action,
        source_text=source_text,
        source_ref=source_ref,
        label=label,
        cwd=cwd,
    )
    mapping = registry.setdefault("pending_new_session_choice_by_thread", {})
    if not isinstance(mapping, dict):
        mapping = {}
        registry["pending_new_session_choice_by_thread"] = mapping
    mapping[key] = payload
    conv_key = _conversation_key_from_telegram_thread_key(thread_key=key)
    if conv_key:
        _set_pending_new_session_choice_by_context(
            registry=registry,
            context_key=conv_key,
            prompt=payload["prompt"],
            action=payload["action"],
            source_text=payload["source_text"],
            source_ref=payload.get("source_ref"),
            label=payload.get("label"),
            cwd=payload.get("cwd"),
        )
    return payload


def _clear_pending_new_session_choice_by_thread(*, registry: dict[str, Any], thread_key: str | None) -> None:
    key = thread_key.strip() if isinstance(thread_key, str) else ""
    if not key:
        return
    mapping = registry.get("pending_new_session_choice_by_thread")
    if not isinstance(mapping, dict):
        return
    mapping.pop(key, None)
    conv_key = _conversation_key_from_telegram_thread_key(thread_key=key)
    if conv_key:
        _clear_pending_new_session_choice_by_context(registry=registry, context_key=conv_key)


def _get_pending_new_session_choice_by_context(
    *,
    registry: dict[str, Any],
    context_key: str | None,
) -> dict[str, Any] | None:
    key = context_key.strip() if isinstance(context_key, str) else ""
    if not key:
        return None
    mapping = registry.get("pending_new_session_choice_by_context")
    if not isinstance(mapping, dict):
        return None
    return _normalize_pending_new_session_choice_payload(raw=mapping.get(key))


def _set_pending_new_session_choice_by_context(
    *,
    registry: dict[str, Any],
    context_key: str,
    prompt: str,
    action: str,
    source_text: str,
    source_ref: str | None = None,
    label: str | None = None,
    cwd: str | None = None,
) -> dict[str, Any]:
    key = context_key.strip()
    payload = _set_pending_new_session_choice(
        registry={"pending_new_session_choice": None},
        prompt=prompt,
        action=action,
        source_text=source_text,
        source_ref=source_ref,
        label=label,
        cwd=cwd,
    )
    mapping = registry.setdefault("pending_new_session_choice_by_context", {})
    if not isinstance(mapping, dict):
        mapping = {}
        registry["pending_new_session_choice_by_context"] = mapping
    mapping[key] = payload
    return payload


def _clear_pending_new_session_choice_by_context(*, registry: dict[str, Any], context_key: str | None) -> None:
    key = context_key.strip() if isinstance(context_key, str) else ""
    if not key:
        return
    mapping = registry.get("pending_new_session_choice_by_context")
    if not isinstance(mapping, dict):
        return
    mapping.pop(key, None)


def _bind_conversation_to_session(
    *,
    registry: dict[str, Any],
    transport: str,
    channel_id: str | None,
    thread_id: int | str | None,
    session_id: str,
) -> None:
    key = _conversation_key(transport=transport, channel_id=channel_id, thread_id=thread_id)
    sid = session_id.strip() if isinstance(session_id, str) else ""
    if not key or not sid:
        return
    _upsert_session(registry=registry, session_id=sid, fields={})
    bindings = registry.setdefault("conversation_bindings", {})
    if not isinstance(bindings, dict):
        bindings = {}
        registry["conversation_bindings"] = bindings
    for existing_key, existing_sid in list(bindings.items()):
        if existing_key == key:
            continue
        if existing_sid == sid:
            bindings.pop(existing_key, None)
    bindings[key] = sid



def _bind_discord_context_to_session(
    *,
    registry: dict[str, Any],
    session_id: str,
    discord_channel_id: str | None,
    discord_parent_channel_id: str | None = None,
) -> None:
    sid = session_id.strip() if isinstance(session_id, str) else ""
    current_channel = discord_channel_id.strip() if isinstance(discord_channel_id, str) else ""
    parent_channel = discord_parent_channel_id.strip() if isinstance(discord_parent_channel_id, str) else ""
    if not sid:
        return

    if parent_channel and current_channel and parent_channel != current_channel:
        _bind_conversation_to_session(
            registry=registry,
            transport="discord",
            channel_id=parent_channel,
            thread_id=current_channel,
            session_id=sid,
        )
        _discord_store_session_channel_metadata(
            registry=registry,
            session_id=sid,
            channel_id=current_channel,
            channel_name=None,
            parent_id=parent_channel,
        )
        return

    target_channel = current_channel or parent_channel
    if not target_channel:
        return
    _bind_conversation_to_session(
        registry=registry,
        transport="discord",
        channel_id=target_channel,
        thread_id=0,
        session_id=sid,
    )
    _discord_store_session_channel_metadata(
        registry=registry,
        session_id=sid,
        channel_id=target_channel,
        channel_name=None,
    )


def _lookup_session_by_conversation(
    *,
    registry: dict[str, Any],
    transport: str,
    channel_id: str | None,
    thread_id: int | str | None,
) -> str | None:
    key = _conversation_key(transport=transport, channel_id=channel_id, thread_id=thread_id)
    if not key:
        return None
    bindings = registry.get("conversation_bindings")
    if not isinstance(bindings, dict):
        return None
    sid = bindings.get(key)
    if not isinstance(sid, str) or not sid.strip():
        return None
    sessions = registry.get("sessions")
    if isinstance(sessions, dict) and sid in sessions:
        return sid
    return None


def _set_conversation_runtime_binding(
    *,
    registry: dict[str, Any],
    transport: str,
    channel_id: str | None,
    thread_id: int | str | None,
    tmux_pane: str,
    tmux_socket: str | None = None,
    agent: str | None = None,
) -> None:
    key = _conversation_key(transport=transport, channel_id=channel_id, thread_id=thread_id)
    pane = tmux_pane.strip() if isinstance(tmux_pane, str) else ""
    if not key or not pane:
        return
    bindings = registry.setdefault("conversation_runtime_bindings", {})
    if not isinstance(bindings, dict):
        bindings = {}
        registry["conversation_runtime_bindings"] = bindings
    record: dict[str, str] = {"tmux_pane": pane}
    socket_norm = _normalize_tmux_socket(tmux_socket=tmux_socket)
    if isinstance(socket_norm, str) and socket_norm.strip():
        record["tmux_socket"] = socket_norm.strip()
    if isinstance(agent, str) and agent.strip():
        record["agent"] = _normalize_agent(agent=agent)
    bindings[key] = record


def _lookup_conversation_runtime_binding(
    *,
    registry: dict[str, Any],
    transport: str,
    channel_id: str | None,
    thread_id: int | str | None,
) -> dict[str, str] | None:
    key = _conversation_key(transport=transport, channel_id=channel_id, thread_id=thread_id)
    if not key:
        return None
    bindings = registry.get("conversation_runtime_bindings")
    if not isinstance(bindings, dict):
        return None
    record = bindings.get(key)
    return record if isinstance(record, dict) else None


def _set_telegram_thread_tmux_binding(
    *,
    registry: dict[str, Any],
    thread_key: str,
    tmux_pane: str,
    tmux_socket: str | None = None,
    agent: str | None = None,
) -> None:
    key = _normalize_telegram_thread_key(thread_key=thread_key)
    pane = tmux_pane.strip() if isinstance(tmux_pane, str) else ""
    if not key or not pane:
        return

    bindings = registry.get("telegram_thread_tmux_bindings")
    if not isinstance(bindings, dict):
        bindings = {}
        registry["telegram_thread_tmux_bindings"] = bindings

    record: dict[str, str] = {"tmux_pane": pane}
    socket_norm = _normalize_tmux_socket(tmux_socket=tmux_socket if isinstance(tmux_socket, str) else None)
    if isinstance(socket_norm, str) and socket_norm.strip():
        record["tmux_socket"] = socket_norm.strip()
    if isinstance(agent, str) and agent.strip():
        record["agent"] = _normalize_agent(agent=agent)
    bindings[key] = record
    _set_conversation_runtime_binding(
        registry=registry,
        transport="telegram",
        channel_id=_telegram_thread_chat_id_from_key(thread_key=key),
        thread_id=_telegram_thread_id_from_key(thread_key=key),
        tmux_pane=pane,
        tmux_socket=socket_norm,
        agent=agent,
    )


def _lookup_telegram_thread_tmux_binding(
    *,
    registry: dict[str, Any],
    thread_key: str | None,
    fallback_session_id: str | None = None,
) -> dict[str, str] | None:
    key = _normalize_telegram_thread_key(thread_key=thread_key)
    if not key:
        return None

    generic_record = _lookup_conversation_runtime_binding(
        registry=registry,
        transport="telegram",
        channel_id=_telegram_thread_chat_id_from_key(thread_key=key),
        thread_id=_telegram_thread_id_from_key(thread_key=key),
    )
    if isinstance(generic_record, dict):
        pane = generic_record.get("tmux_pane")
        if isinstance(pane, str) and pane.strip():
            return generic_record

    bindings = _normalize_telegram_thread_tmux_bindings(raw=registry.get("telegram_thread_tmux_bindings"))
    registry["telegram_thread_tmux_bindings"] = bindings
    record = bindings.get(key)
    if isinstance(record, dict):
        pane = record.get("tmux_pane")
        if isinstance(pane, str) and pane.strip():
            return record

    sid = fallback_session_id.strip() if isinstance(fallback_session_id, str) else ""
    sessions = registry.get("sessions")
    rec = sessions.get(sid) if isinstance(sessions, dict) and sid else None
    if not isinstance(rec, dict):
        return None
    pane = rec.get("tmux_pane")
    pane_norm = pane.strip() if isinstance(pane, str) else ""
    if not pane_norm:
        return None
    socket_norm = _normalize_tmux_socket(
        tmux_socket=rec.get("tmux_socket") if isinstance(rec.get("tmux_socket"), str) else None
    )
    agent_norm = _normalize_agent(agent=rec.get("agent") if isinstance(rec.get("agent"), str) else _current_agent())
    _set_telegram_thread_tmux_binding(
        registry=registry,
        thread_key=key,
        tmux_pane=pane_norm,
        tmux_socket=socket_norm,
        agent=agent_norm,
    )
    refreshed = _normalize_telegram_thread_tmux_bindings(raw=registry.get("telegram_thread_tmux_bindings"))
    registry["telegram_thread_tmux_bindings"] = refreshed
    resolved = refreshed.get(key)
    return resolved if isinstance(resolved, dict) else None


def _resolve_session_from_telegram_thread_tmux_binding(
    *,
    codex_home: Path,
    registry: dict[str, Any],
    chat_id: str | None,
    message_thread_id: int | None,
    fallback_session_id: str | None = None,
    agent: str | None = None,
) -> str | None:
    thread_key = _telegram_thread_key(chat_id=chat_id, thread_id=message_thread_id)
    if not thread_key:
        return None

    binding = _lookup_telegram_thread_tmux_binding(
        registry=registry,
        thread_key=thread_key,
        fallback_session_id=fallback_session_id,
    )
    if not isinstance(binding, dict):
        return None

    pane = binding.get("tmux_pane")
    pane_norm = pane.strip() if isinstance(pane, str) else ""
    if not pane_norm:
        return None

    socket_norm = _normalize_tmux_socket(
        tmux_socket=binding.get("tmux_socket") if isinstance(binding.get("tmux_socket"), str) else None
    )
    if not _tmux_pane_exists(pane=pane_norm, tmux_socket=socket_norm):
        return None

    latest_sid = _tmux_latest_session_id_from_pane(pane=pane_norm, tmux_socket=socket_norm)
    latest_sid_norm = latest_sid.strip() if isinstance(latest_sid, str) else ""
    if not latest_sid_norm:
        return None

    recovered = _recover_session_record_from_disk(
        codex_home=codex_home,
        session_id=latest_sid_norm,
        registry=registry,
    )
    fields: dict[str, Any] = recovered if isinstance(recovered, dict) and recovered else {}
    fields["tmux_pane"] = pane_norm
    if isinstance(socket_norm, str) and socket_norm.strip():
        fields["tmux_socket"] = socket_norm.strip()

    fallback_agent: str | None = None
    binding_agent = binding.get("agent")
    if isinstance(binding_agent, str) and binding_agent.strip():
        fallback_agent = _normalize_agent(agent=binding_agent)
    elif isinstance(agent, str) and agent.strip():
        fallback_agent = _normalize_agent(agent=agent)
    elif isinstance(fallback_session_id, str) and fallback_session_id.strip():
        sessions = registry.get("sessions")
        old_rec = sessions.get(fallback_session_id.strip()) if isinstance(sessions, dict) else None
        if isinstance(old_rec, dict):
            old_agent = old_rec.get("agent")
            if isinstance(old_agent, str) and old_agent.strip():
                fallback_agent = _normalize_agent(agent=old_agent)
    if not isinstance(fields.get("agent"), str) or not str(fields.get("agent")).strip():
        fields["agent"] = fallback_agent if isinstance(fallback_agent, str) else _current_agent()

    _upsert_session(registry=registry, session_id=latest_sid_norm, fields=fields)
    _bind_telegram_thread_to_session(
        registry=registry,
        chat_id=chat_id,
        message_thread_id=message_thread_id,
        session_id=latest_sid_norm,
    )
    return latest_sid_norm


def _bind_telegram_thread_to_session(
    *,
    registry: dict[str, Any],
    chat_id: str | None,
    message_thread_id: int | None,
    session_id: str,
) -> None:
    thread_key = _telegram_thread_key(chat_id=chat_id, thread_id=message_thread_id)
    sid = session_id.strip() if isinstance(session_id, str) else ""
    if not thread_key or not sid:
        return
    _upsert_session(
        registry=registry,
        session_id=sid,
        fields={},
    )
    _bind_conversation_to_session(
        registry=registry,
        transport="telegram",
        channel_id=chat_id,
        thread_id=message_thread_id,
        session_id=sid,
    )
    sessions = registry.get("sessions")
    if not isinstance(sessions, dict):
        sessions = {}
        registry["sessions"] = sessions
    bindings = _canonicalize_telegram_thread_state(
        sessions=sessions,
        raw_bindings=registry.get("telegram_thread_bindings"),
    )
    bindings[thread_key] = sid
    ordered_bindings = {
        existing_key: existing_sid
        for existing_key, existing_sid in bindings.items()
        if existing_key != thread_key
    }
    ordered_bindings[thread_key] = sid
    registry["telegram_thread_bindings"] = _canonicalize_telegram_thread_state(
        sessions=sessions,
        raw_bindings=ordered_bindings,
    )

    rec = sessions.get(sid) if isinstance(sessions, dict) else None
    if isinstance(rec, dict):
        pane = rec.get("tmux_pane")
        pane_norm = pane.strip() if isinstance(pane, str) else ""
        if pane_norm:
            socket_norm = _normalize_tmux_socket(
                tmux_socket=rec.get("tmux_socket") if isinstance(rec.get("tmux_socket"), str) else None
            )
            rec_agent = rec.get("agent") if isinstance(rec.get("agent"), str) else None
            _set_telegram_thread_tmux_binding(
                registry=registry,
                thread_key=thread_key,
                tmux_pane=pane_norm,
                tmux_socket=socket_norm,
                agent=rec_agent,
            )


def _lookup_session_by_telegram_thread(
    *,
    registry: dict[str, Any],
    chat_id: str | None,
    message_thread_id: int | None,
) -> str | None:
    thread_key = _telegram_thread_key(chat_id=chat_id, thread_id=message_thread_id)
    if not thread_key:
        return None
    via_generic = _lookup_session_by_conversation(
        registry=registry,
        transport="telegram",
        channel_id=chat_id,
        thread_id=message_thread_id,
    )
    if isinstance(via_generic, str) and via_generic.strip():
        return via_generic.strip()
    bindings = registry.get("telegram_thread_bindings")
    if not isinstance(bindings, dict):
        return None
    sid = bindings.get(thread_key)
    if not isinstance(sid, str) or not sid.strip():
        return None
    sessions = registry.get("sessions")
    if isinstance(sessions, dict) and sid in sessions:
        return sid
    return None


def _lookup_single_telegram_thread_for_chat(
    *,
    registry: dict[str, Any],
    chat_id: str | None,
) -> int | None:
    normalized_chat_id = chat_id.strip() if isinstance(chat_id, str) else ""
    if not normalized_chat_id:
        return None
    bindings = registry.get("telegram_thread_bindings")
    if not isinstance(bindings, dict):
        return None
    prefix = f"{normalized_chat_id}:"
    thread_ids: set[int] = set()
    for thread_key, sid in bindings.items():
        if not isinstance(thread_key, str) or not thread_key.startswith(prefix):
            continue
        if not isinstance(sid, str) or not sid.strip():
            continue
        thread_id = _telegram_thread_id_from_key(thread_key=thread_key)
        if thread_id is None:
            continue
        thread_ids.add(int(thread_id))
    if len(thread_ids) != 1:
        return None
    return next(iter(thread_ids))


def _lookup_single_session_by_telegram_chat(
    *,
    registry: dict[str, Any],
    chat_id: str | None,
) -> str | None:
    normalized_chat_id = chat_id.strip() if isinstance(chat_id, str) else ""
    if not normalized_chat_id:
        return None

    candidate_sids: set[str] = set()

    bindings = registry.get("telegram_thread_bindings")
    if isinstance(bindings, dict):
        prefix = f"{normalized_chat_id}:"
        for thread_key, sid in bindings.items():
            if not isinstance(thread_key, str) or not thread_key.startswith(prefix):
                continue
            if isinstance(sid, str) and sid.strip():
                candidate_sids.add(sid.strip())

    sessions = registry.get("sessions")
    if isinstance(sessions, dict):
        for sid, rec in sessions.items():
            if not isinstance(sid, str) or not sid.strip():
                continue
            if not isinstance(rec, dict):
                continue
            rec_chat_raw = rec.get("telegram_chat_id")
            rec_chat_id = rec_chat_raw.strip() if isinstance(rec_chat_raw, str) else ""
            if rec_chat_id and rec_chat_id == normalized_chat_id:
                candidate_sids.add(sid.strip())

    if len(candidate_sids) != 1:
        return None
    sid = next(iter(candidate_sids))
    if not isinstance(sessions, dict) or sid not in sessions:
        return None
    return sid


def _infer_single_telegram_chat_id_from_registry(*, registry: dict[str, Any]) -> str | None:
    candidate_chat_ids: set[str] = set()

    bindings = registry.get("telegram_thread_bindings")
    if isinstance(bindings, dict):
        for thread_key, sid in bindings.items():
            if not isinstance(sid, str) or not sid.strip():
                continue
            chat_id = _telegram_thread_chat_id_from_key(thread_key=thread_key if isinstance(thread_key, str) else None)
            if isinstance(chat_id, str) and chat_id.strip():
                candidate_chat_ids.add(chat_id.strip())

    tmux_bindings = registry.get("telegram_thread_tmux_bindings")
    if isinstance(tmux_bindings, dict):
        for thread_key, binding in tmux_bindings.items():
            if not isinstance(binding, dict):
                continue
            pane = binding.get("tmux_pane")
            if not isinstance(pane, str) or not pane.strip():
                continue
            chat_id = _telegram_thread_chat_id_from_key(thread_key=thread_key if isinstance(thread_key, str) else None)
            if isinstance(chat_id, str) and chat_id.strip():
                candidate_chat_ids.add(chat_id.strip())

    sessions = registry.get("sessions")
    if isinstance(sessions, dict):
        for rec in sessions.values():
            if not isinstance(rec, dict):
                continue
            rec_chat_raw = rec.get("telegram_chat_id")
            rec_chat_id = rec_chat_raw.strip() if isinstance(rec_chat_raw, str) else ""
            if rec_chat_id:
                candidate_chat_ids.add(rec_chat_id)

    if len(candidate_chat_ids) != 1:
        return None
    return next(iter(candidate_chat_ids))


def _telegram_thread_id_for_session(*, registry: dict[str, Any], session_id: str | None) -> int | None:
    sid = session_id.strip() if isinstance(session_id, str) else ""
    if not sid:
        return None

    # Primary source of truth is canonical thread bindings.
    bindings = registry.get("telegram_thread_bindings")
    if isinstance(bindings, dict):
        for thread_key, bound_sid in bindings.items():
            if isinstance(bound_sid, str) and bound_sid == sid:
                from_key = _telegram_thread_id_from_key(thread_key=thread_key if isinstance(thread_key, str) else None)
                if from_key is not None:
                    return from_key

    # Backward-compatible fallback: use session metadata when no canonical
    # mapping exists yet (for legacy records that predate bindings map).
    sessions = registry.get("sessions")
    rec = sessions.get(sid) if isinstance(sessions, dict) else None
    if not isinstance(rec, dict):
        return None

    fallback_thread_id = _normalize_telegram_thread_id(rec.get("telegram_message_thread_id"))

    configured_chat = _telegram_chat_id()
    configured_chat_id = configured_chat.strip() if isinstance(configured_chat, str) else ""
    if not configured_chat_id:
        inferred_chat = _infer_single_telegram_chat_id_from_registry(registry=registry)
        configured_chat_id = inferred_chat.strip() if isinstance(inferred_chat, str) else ""
    rec_chat_raw = rec.get("telegram_chat_id")
    rec_chat_id = rec_chat_raw.strip() if isinstance(rec_chat_raw, str) else ""

    # Avoid cross-chat routing when both IDs are known and disagree.
    if configured_chat_id and rec_chat_id and rec_chat_id != configured_chat_id:
        return None

    if fallback_thread_id is not None:
        return fallback_thread_id

    # For sessions that are not bound to a topic, route to #general so the
    # session remains discoverable and can later be rebound via @<session_id>.
    if configured_chat_id:
        return _telegram_general_topic_thread_id()
    return None


def _telegram_chat_id_for_session(*, registry: dict[str, Any], session_id: str | None) -> str | None:
    sid = session_id.strip() if isinstance(session_id, str) else ""
    if not sid:
        return None

    bindings = registry.get("telegram_thread_bindings")
    if isinstance(bindings, dict):
        for thread_key, bound_sid in bindings.items():
            if isinstance(bound_sid, str) and bound_sid == sid:
                from_key = _telegram_thread_chat_id_from_key(thread_key=thread_key if isinstance(thread_key, str) else None)
                if isinstance(from_key, str) and from_key.strip():
                    return from_key.strip()

    sessions = registry.get("sessions")
    rec = sessions.get(sid) if isinstance(sessions, dict) else None
    if not isinstance(rec, dict):
        return None
    rec_chat_raw = rec.get("telegram_chat_id")
    rec_chat_id = rec_chat_raw.strip() if isinstance(rec_chat_raw, str) else ""
    if rec_chat_id:
        return rec_chat_id
    return None


def _discord_target_channel_id_for_session(*, registry: dict[str, Any], session_id: str | None) -> str | None:
    sid = session_id.strip() if isinstance(session_id, str) else ""
    if not sid:
        return None

    direct = _discord_session_channel_for_session(registry=registry, session_id=sid)
    if isinstance(direct, str) and direct.strip() and not _discord_is_control_channel(channel_id=direct):
        return direct.strip()

    bindings = registry.get("conversation_bindings")
    if isinstance(bindings, dict):
        for conv_key, bound_sid in bindings.items():
            if not isinstance(conv_key, str) or not conv_key.startswith("discord:"):
                continue
            if not isinstance(bound_sid, str) or bound_sid != sid:
                continue
            _, channel_id, thread_raw = conv_key.split(":", 2)
            thread_text = thread_raw.strip()
            if thread_text and thread_text != "0":
                return thread_text
            if channel_id.strip() and not _discord_is_control_channel(channel_id=channel_id.strip()):
                return channel_id.strip()

    sessions = registry.get("sessions")
    rec = sessions.get(sid) if isinstance(sessions, dict) else None
    if not isinstance(rec, dict):
        return None
    channel_id = rec.get("discord_channel_id")
    if isinstance(channel_id, str) and channel_id.strip() and not _discord_is_control_channel(channel_id=channel_id.strip()):
        return channel_id.strip()
    bindings_rec = rec.get("bindings") if isinstance(rec.get("bindings"), dict) else None
    discord_binding = bindings_rec.get("discord") if isinstance(bindings_rec, dict) and isinstance(bindings_rec.get("discord"), dict) else None
    if isinstance(discord_binding, dict):
        thread_id = discord_binding.get("thread_id")
        if isinstance(thread_id, str) and thread_id.strip():
            return thread_id.strip()
        channel_id = discord_binding.get("channel_id")
        if isinstance(channel_id, str) and channel_id.strip():
            return channel_id.strip()
    return None


def _strip_leading_telegram_mention_for_command(*, text: str) -> str:
    raw = text.strip()
    if not raw.startswith("@"):
        return raw
    match = re.match(r"^@[A-Za-z0-9_]+\s+(.+)$", raw, flags=re.DOTALL)
    if not match:
        return raw
    remainder = match.group(1).strip()
    if not remainder:
        return raw
    first_token = remainder.split(None, 1)[0]
    first_lower = first_token.lower()
    if first_token.startswith("@") or first_lower in {"help", "list", "where", "context", "status", "bind", "new"}:
        return remainder
    return raw


def _normalize_telegram_slash_command(*, text: str) -> str:
    raw = text.strip()
    if not raw.startswith("/"):
        return raw

    match = re.match(r"^/([A-Za-z0-9_]+)(?:@[A-Za-z0-9_]+)?(?:\s+(.+))?$", raw, flags=re.DOTALL)
    if not match:
        return raw

    command = match.group(1).strip().lower()
    remainder = (match.group(2) or "").strip()

    if command == "help":
        return "help"
    if command == "list":
        return "list"
    if command in {"where", "context"}:
        return "context"
    if command == "status":
        return f"status {remainder}".strip()
    if command == "bind":
        return f"bind {remainder}".strip()
    if command == "new":
        return f"new {remainder}".strip()
    if command in {"resume", "r", "reply"}:
        if not remainder:
            return raw
        m_resume = re.match(r"^@?([^\s:]+)\s+(.+)$", remainder, flags=re.DOTALL)
        if not m_resume:
            return remainder
        session_ref = m_resume.group(1).strip()
        prompt = m_resume.group(2).strip()
        if not session_ref or not prompt:
            return remainder
        return f"@{session_ref} {prompt}"

    return raw


def _parse_inbound_command(text: str) -> dict[str, str]:
    raw = _strip_leading_telegram_mention_for_command(text=text)
    raw = _normalize_telegram_slash_command(text=raw)
    if not raw:
        return {"action": "noop"}

    lowered = raw.lower()
    if lowered == "help":
        return {"action": "help"}
    if lowered == "list":
        return {"action": "list"}
    if lowered in {"where", "context"}:
        return {"action": "context"}

    m_status = re.match(r"^status\s+@?(\S+)\s*$", raw, flags=re.IGNORECASE)
    if m_status:
        return {"action": "status", "session_ref": m_status.group(1).strip()}

    m_bind = re.match(r"^bind\s+@?(\S+)\s*$", raw, flags=re.IGNORECASE)
    if m_bind:
        return {"action": "bind", "session_ref": m_bind.group(1).strip()}

    m_new = re.match(r"^new\s+([A-Za-z0-9._-]+)\s*:\s*(.+)$", raw, flags=re.IGNORECASE | re.DOTALL)
    if m_new:
        return {
            "action": "new",
            "label": m_new.group(1).strip().lower(),
            "prompt": m_new.group(2).strip(),
        }

    m_resume = re.match(r"^@([^\s:]+)\s+(.+)$", raw, flags=re.DOTALL)
    if m_resume:
        return {
            "action": "resume",
            "session_ref": m_resume.group(1).strip(),
            "prompt": m_resume.group(2).strip(),
        }

    return {"action": "implicit", "prompt": raw}


def _parse_agent_choice_response(*, text: str) -> str | None:
    raw = text.strip().lower()
    if not raw:
        return None
    if raw in {"cancel", "abort", "stop", "none"}:
        return "cancel"
    if raw in {"1", "codex", "codex code", "use codex", "codexcode"}:
        return "codex"
    if raw in {"2", "claude", "claude code", "use claude", "claudecode"}:
        return "claude"
    if raw in {"3", "pi", "pi coding agent", "use pi", "pi-agent", "piagent"}:
        return "pi"
    return None


def _rewrite_numeric_choice_prompt(
    *,
    prompt: str,
    session_rec: dict[str, Any] | None,
) -> tuple[str | None, str | None]:
    raw = prompt.strip()
    if not raw:
        return prompt, None
    if not isinstance(session_rec, dict):
        return prompt, None

    pending = session_rec.get("pending_request_user_input")
    if not isinstance(pending, dict):
        return prompt, None

    raw_questions = pending.get("questions")
    if not isinstance(raw_questions, list) or not raw_questions:
        return prompt, None

    questions = [q for q in raw_questions if isinstance(q, dict)]
    if not questions:
        return prompt, None

    m_pair = re.match(r"^\s*(\d+)\s*[.:/\-]\s*(\d+)\s*$", raw)
    if m_pair:
        question_idx = int(m_pair.group(1))
        option_idx = int(m_pair.group(2))
    else:
        m_single = re.match(r"^\s*(\d+)\s*[.)]?\s*$", raw)
        if not m_single:
            return prompt, None
        if len(questions) != 1:
            return (
                None,
                (
                    f"Numeric reply '{raw}' is ambiguous across {len(questions)} questions. "
                    'Reply with "<question>.<option>" such as "1.2".'
                ),
            )
        question_idx = 1
        option_idx = int(m_single.group(1))

    if question_idx < 1 or question_idx > len(questions):
        return (
            None,
            f"Question index {question_idx} is out of range. Valid questions: 1-{len(questions)}.",
        )

    question = questions[question_idx - 1]
    raw_options = question.get("options")
    if not isinstance(raw_options, list) or not raw_options:
        return prompt, None

    option_labels: list[str] = []
    for opt in raw_options:
        if not isinstance(opt, dict):
            continue
        label = opt.get("label")
        if isinstance(label, str) and label.strip():
            option_labels.append(label.strip())

    if not option_labels:
        return prompt, None

    if option_idx < 1 or option_idx > len(option_labels):
        return (
            None,
            (
                f"Option index {option_idx} is out of range for question {question_idx}. "
                f"Valid options: 1-{len(option_labels)}."
            ),
        )

    question_id = question.get("id")
    question_id_text = question_id.strip() if isinstance(question_id, str) and question_id.strip() else None
    question_text = question.get("question")
    question_text_value = question_text.strip() if isinstance(question_text, str) and question_text.strip() else None
    option_label = option_labels[option_idx - 1]

    if question_id_text and question_text_value:
        subject = f'id "{question_id_text}" ("{question_text_value}")'
    elif question_id_text:
        subject = f'id "{question_id_text}"'
    elif question_text_value:
        subject = f'"{question_text_value}"'
    else:
        subject = f"#{question_idx}"

    rewritten = f'Answer for question {subject}: selected option {option_idx} "{option_label}".'
    return rewritten, None


def _resolve_session_ref(
    *,
    registry: dict[str, Any],
    session_ref: str,
    min_prefix: int = _DEFAULT_MIN_PREFIX,
) -> tuple[str | None, str | None]:
    ref = session_ref.strip()
    if not ref:
        return None, "No session reference provided."

    sessions = registry.get("sessions")
    if not isinstance(sessions, dict):
        return None, f"No session found for ref '{ref}'."

    # Exact SID match.
    if ref in sessions:
        return ref, None

    # Alias map match.
    aliases = registry.get("aliases")
    if isinstance(aliases, dict):
        alias_sid = aliases.get(ref.lower())
        if isinstance(alias_sid, str) and alias_sid in sessions:
            return alias_sid, None

    # Alias in record fallback.
    alias_matches: list[str] = []
    for sid, rec in sessions.items():
        if not isinstance(sid, str) or not isinstance(rec, dict):
            continue
        alias = rec.get("alias")
        if isinstance(alias, str) and alias.strip().lower() == ref.lower():
            alias_matches.append(sid)

    if len(alias_matches) == 1:
        return alias_matches[0], None
    if len(alias_matches) > 1:
        return None, f"Ambiguous alias '{ref}'. Send `list` and use a longer `@<ref>` command."

    # Prefix match.
    prefix_matches: list[str] = []
    if len(ref) >= max(1, int(min_prefix)):
        for sid in sessions.keys():
            if isinstance(sid, str) and sid.startswith(ref):
                prefix_matches.append(sid)

    if len(prefix_matches) == 1:
        return prefix_matches[0], None
    if len(prefix_matches) > 1:
        return None, f"Ambiguous session ref '{ref}'. Send `list` and use a longer `@<ref>` command."

    return None, f"No session found for ref '{ref}'. Send `list` to view active refs, or `new <label>: <instruction>` to start one."


def _choose_implicit_session(*, registry: dict[str, Any]) -> tuple[str | None, str | None]:
    sessions = registry.get("sessions")
    if not isinstance(sessions, dict) or not sessions:
        return None, "No tracked sessions yet. Send `new <label>: <instruction>` to start one, or `list` to inspect active refs."

    waiting: list[tuple[str, int]] = []
    for sid, rec in sessions.items():
        if not isinstance(sid, str) or not isinstance(rec, dict):
            continue
        if rec.get("awaiting_input") is True:
            ts = rec.get("last_attention_ts")
            waiting.append((sid, int(ts) if isinstance(ts, int) else 0))

    if len(waiting) == 1:
        return waiting[0][0], None
    if len(waiting) > 1:
        waiting_sorted = sorted(waiting, key=lambda item: item[1], reverse=True)
        refs = [f"@{_session_ref(sid)}" for sid, _ in waiting_sorted[:6]]
        return None, "Ambiguous target session. Use an explicit ref: " + ", ".join(refs)

    return None, "No session here is currently awaiting input. Send `where`, `list`, `bind @<session_ref>`, or `@<session_ref> <instruction>`."


def _session_is_waiting_for_input(*, session_rec: dict[str, Any] | None) -> bool:
    if not isinstance(session_rec, dict):
        return False
    if session_rec.get("awaiting_input") is True:
        return True
    pending = session_rec.get("pending_request_user_input")
    return isinstance(pending, dict) and bool(pending)


def _normalize_message_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def _message_hash(text: str) -> str:
    return hashlib.sha256(_normalize_message_text(text).encode("utf-8")).hexdigest()[:24]


def _load_message_index(*, codex_home: Path) -> dict[str, Any]:
    raw = _read_json(_message_index_path(codex_home=codex_home))
    if not isinstance(raw, dict):
        return {"messages": [], "ts": int(time.time())}
    messages = raw.get("messages")
    if not isinstance(messages, list):
        messages = []
    return {"messages": messages, "ts": int(time.time())}


def _save_message_index(*, codex_home: Path, index: dict[str, Any]) -> None:
    messages = index.get("messages")
    if not isinstance(messages, list):
        messages = []
    if len(messages) > _MAX_MESSAGE_INDEX_ENTRIES:
        messages = messages[-_MAX_MESSAGE_INDEX_ENTRIES:]
    _write_json(
        _message_index_path(codex_home=codex_home),
        {"messages": messages, "ts": int(time.time())},
    )


def _record_outbound_message(
    *,
    index: dict[str, Any],
    session_id: str | None,
    kind: str,
    text: str,
    agent: str | None,
) -> None:
    messages = index.setdefault("messages", [])
    if not isinstance(messages, list):
        messages = []
        index["messages"] = messages

    messages.append(
        {
            "ts": int(time.time()),
            "session_id": session_id,
            "kind": kind,
            "hash": _message_hash(text),
            "agent": _normalize_agent(agent=agent),
        }
    )


def _lookup_agent_by_session_id(
    *,
    index: dict[str, Any],
    session_id: str,
) -> str | None:
    sid = session_id.strip()
    if not sid:
        return None
    messages = index.get("messages")
    if not isinstance(messages, list):
        return None

    for rec in reversed(messages):
        if not isinstance(rec, dict):
            continue
        if rec.get("session_id") != sid:
            continue
        agent = rec.get("agent")
        if isinstance(agent, str) and agent.strip():
            return _normalize_agent(agent=agent)
    return None


def _lookup_session_by_message_hash(
    *,
    index: dict[str, Any],
    replied_text: str,
) -> str | None:
    h = _message_hash(replied_text)
    messages = index.get("messages")
    if not isinstance(messages, list):
        return None

    for rec in reversed(messages):
        if not isinstance(rec, dict):
            continue
        if rec.get("hash") != h:
            continue
        sid = rec.get("session_id")
        if isinstance(sid, str) and sid.strip():
            return sid.strip()
    return None


def _session_refs_from_text(text: str) -> list[str]:
    if not isinstance(text, str) or not text.strip():
        return []
    out: list[str] = []
    for match in re.finditer(r"@([0-9a-fA-F]{6,32})\b", text):
        ref = match.group(1).strip().lower()
        if ref and ref not in out:
            out.append(ref)
    return out


def _lookup_session_by_text_ref(
    *,
    registry: dict[str, Any],
    replied_text: str,
) -> str | None:
    refs = _session_refs_from_text(replied_text)
    for ref in refs:
        sid, _ = _resolve_session_ref(
            registry=registry,
            session_ref=ref,
            min_prefix=_DEFAULT_MIN_PREFIX,
        )
        if isinstance(sid, str) and sid.strip():
            return sid.strip()
    return None


def _load_outbound_cursor(*, codex_home: Path) -> tuple[dict[str, int], dict[str, int]]:
    raw = _read_json(_outbound_cursor_path(codex_home=codex_home))
    if not isinstance(raw, dict):
        return {}, {}

    files_raw = raw.get("files")
    seen_raw = raw.get("seen_needs_input_call_ids")

    files: dict[str, int] = {}
    if isinstance(files_raw, dict):
        for key, value in files_raw.items():
            if isinstance(key, str) and isinstance(value, int):
                files[key] = value

    seen = outbound._prune_seen_needs_input_call_ids(seen_raw, now_ts=int(time.time()))
    return files, seen


def _save_outbound_cursor(
    *,
    codex_home: Path,
    files: dict[str, int],
    seen_needs_input_call_ids: dict[str, int],
) -> None:
    seen = outbound._prune_seen_needs_input_call_ids(seen_needs_input_call_ids, now_ts=int(time.time()))
    _write_json(
        _outbound_cursor_path(codex_home=codex_home),
        {
            "files": files,
            "seen_needs_input_call_ids": seen,
            "ts": int(time.time()),
        },
    )


def _normalize_handle_ids(handle_ids: list[str] | None) -> list[str]:
    if not isinstance(handle_ids, list):
        return []
    normalized = {
        handle.strip()
        for handle in handle_ids
        if isinstance(handle, str) and handle.strip()
    }
    return sorted(normalized)


def _load_inbound_cursor_state(*, codex_home: Path) -> dict[str, Any] | None:
    raw = _read_json(_inbound_cursor_path(codex_home=codex_home))
    if not isinstance(raw, dict):
        return None
    return raw


def _load_inbound_cursor(*, codex_home: Path) -> int:
    raw = _load_inbound_cursor_state(codex_home=codex_home)
    if not isinstance(raw, dict):
        return 0
    rowid = raw.get("last_rowid")
    return int(rowid) if isinstance(rowid, int) else 0


def _save_inbound_cursor(
    *,
    codex_home: Path,
    rowid: int,
    recipient: str | None = None,
    handle_ids: list[str] | None = None,
) -> None:
    payload: dict[str, Any] = {"last_rowid": int(rowid), "ts": int(time.time())}
    recipient_text = recipient.strip() if isinstance(recipient, str) else ""
    if recipient_text:
        payload["recipient"] = recipient_text
    handles = _normalize_handle_ids(handle_ids)
    if handles:
        payload["handle_ids"] = handles
    _write_json(_inbound_cursor_path(codex_home=codex_home), payload)


def _notification_level() -> str:
    raw = os.environ.get("AGENT_CHAT_NOTIFICATION_LEVEL", "default")
    level = raw.strip().lower() if isinstance(raw, str) else "default"
    if level in {"quiet", "default", "verbose"}:
        return level
    return "default"



def _should_emit_session_completion_notification() -> bool:
    return _notification_level() != "quiet"



def _should_emit_session_progress_update() -> bool:
    level = _notification_level()
    if level == "verbose":
        return True
    if level == "quiet":
        return False
    return _transport_discord_enabled() and _discord_session_channels_enabled()



def _normalize_discord_progress_mode(mode: object) -> str:
    normalized = mode.strip().lower() if isinstance(mode, str) else ""
    if normalized in _DISCORD_PROGRESS_MODES:
        return normalized
    return "origin_scoped"



def _session_discord_progress_mode(*, session_rec: dict[str, Any] | None) -> str:
    if not isinstance(session_rec, dict):
        return "origin_scoped"
    return _normalize_discord_progress_mode(session_rec.get("discord_progress_mode"))



def _normalize_desktop_attention_state(state: object) -> str:
    normalized = state.strip().lower() if isinstance(state, str) else ""
    if normalized in _DESKTOP_ATTENTION_STATES:
        return normalized
    return "none"



def _normalize_active_prompt_status(status: object) -> str | None:
    normalized = status.strip().lower() if isinstance(status, str) else ""
    if normalized in _ACTIVE_PROMPT_STATUSES:
        return normalized
    return None



def _normalize_active_prompt_origin(origin: object) -> str | None:
    normalized = origin.strip().lower() if isinstance(origin, str) else ""
    if normalized in _ACTIVE_PROMPT_ORIGINS:
        return normalized
    return None



def _is_discord_origin_prompt(*, session_rec: dict[str, Any] | None) -> bool:
    if not isinstance(session_rec, dict):
        return False
    return _normalize_active_prompt_origin(session_rec.get("active_prompt_origin")) == "discord"



def _should_emit_discord_lifecycle_event(
    *,
    session_rec: dict[str, Any] | None,
    event_kind: str | None = None,
) -> bool:
    del event_kind
    if not isinstance(session_rec, dict):
        return False
    mode = _session_discord_progress_mode(session_rec=session_rec)
    if mode == "local_only":
        return False
    if mode == "origin_scoped":
        return _is_discord_origin_prompt(session_rec=session_rec)
    return True



def _discord_lifecycle_kind_for_structured_kind(*, kind: str) -> str | None:
    normalized = kind.strip().lower()
    if normalized in {"accepted", "working", "needs_input", "failed", "cancelled", "completed"}:
        return normalized
    if normalized == "responded":
        return "completed"
    return None



def _format_discord_progress_accepted(*, ref: str, origin: str | None, desktop_attention_state: str | None) -> str:
    if origin == "desktop":
        return f"Pi started local work in `@{ref}`."
    normalized_attention = _normalize_desktop_attention_state(desktop_attention_state)
    if normalized_attention == "inline_visible":
        return f"Got it — sent to `@{ref}`. It's now visible on the desktop."
    if normalized_attention in {"notification_visible", "attention_badged", "waiting_for_user"}:
        return f"Got it — sent to `@{ref}`. It's queued in the session and marked for desktop attention."
    return f"Got it — sent to `@{ref}`."



def _render_discord_lifecycle_text(
    *,
    session_id: str | None,
    kind: str,
    text: str,
    session_rec: dict[str, Any] | None,
) -> str | None:
    lifecycle_kind = _discord_lifecycle_kind_for_structured_kind(kind=kind)
    if lifecycle_kind is None:
        return None

    sid = session_id.strip() if isinstance(session_id, str) else ""
    ref = (
        session_rec.get("ref")
        if isinstance(session_rec, dict) and isinstance(session_rec.get("ref"), str) and session_rec.get("ref").strip()
        else _session_ref(sid)
    )
    origin = _normalize_active_prompt_origin(session_rec.get("active_prompt_origin") if isinstance(session_rec, dict) else None)
    desktop_attention_state = (
        session_rec.get("desktop_attention_state") if isinstance(session_rec, dict) else None
    )
    prompt_text = text.strip()

    if lifecycle_kind == "accepted":
        return _format_discord_progress_accepted(
            ref=ref,
            origin=origin,
            desktop_attention_state=desktop_attention_state,
        )

    if lifecycle_kind == "working":
        if origin == "desktop":
            return f"Pi is working locally in `@{ref}`."
        return f"Pi is working on your request in `@{ref}`."

    if lifecycle_kind == "needs_input":
        questions = _pi_pending_questions(session_rec=session_rec)
        rendered_questions = outbound._render_request_user_input_questions(questions) if questions else None
        prompt_body = rendered_questions.strip() if isinstance(rendered_questions, str) and rendered_questions.strip() else prompt_text
        if not prompt_body:
            prompt_body = "Pi needs more information before it can continue."
        lead = f"Pi needs input in `@{ref}`." if origin == "desktop" else f"Pi is waiting for your input on `@{ref}`."
        suggestion = _pi_needs_input_suggestion_text(session_rec=session_rec, text=prompt_body)
        lines = [lead, "", prompt_body, "", "Reply here to continue.", suggestion]
        return "\n".join(lines).strip()

    if lifecycle_kind == "completed":
        lead = f"Pi completed local work in `@{ref}`." if origin == "desktop" else f"Done in `@{ref}`."
        return f"{lead}\n{prompt_text}".strip() if prompt_text else lead

    if lifecycle_kind == "failed":
        lines = [f"Pi hit a problem in `@{ref}`."]
        if prompt_text:
            lines.extend(["", prompt_text])
        lines.extend(["", "Reply here if you want Pi to try a different approach."])
        return "\n".join(lines).strip()

    if lifecycle_kind == "cancelled":
        return f"Cancelled in `@{ref}`."

    return prompt_text or None



def _send_structured(
    *,
    codex_home: Path,
    recipient: str,
    session_id: str | None,
    kind: str,
    text: str,
    max_message_chars: int,
    dry_run: bool,
    message_index: dict[str, Any],
    agent: str | None = None,
    telegram_chat_id: str | None = None,
    telegram_message_thread_id: int | None = None,
    discord_channel_id: str | None = None,
    registry: dict[str, Any] | None = None,
    deliver_to_imessage: bool = True,
    deliver_to_telegram: bool = True,
    deliver_to_discord: bool = True,
    discord_lifecycle_event: bool = False,
) -> None:
    resolved_thread_id = _normalize_telegram_thread_id(telegram_message_thread_id)
    resolved_chat_id = telegram_chat_id.strip() if isinstance(telegram_chat_id, str) and telegram_chat_id.strip() else None
    resolved_discord_channel_id = discord_channel_id.strip() if isinstance(discord_channel_id, str) and discord_channel_id.strip() else None
    active_registry = registry if isinstance(registry, dict) else None
    if isinstance(session_id, str) and session_id.strip() and (
        active_registry is None
        or resolved_thread_id is None
        or resolved_chat_id is None
        or resolved_discord_channel_id is None
    ):
        if active_registry is None:
            active_registry = _load_registry(codex_home=codex_home)
        if active_registry is None:
            active_registry = {}
        if resolved_thread_id is None:
            resolved_thread_id = _telegram_thread_id_for_session(registry=active_registry, session_id=session_id)
        if resolved_chat_id is None:
            resolved_chat_id = _telegram_chat_id_for_session(registry=active_registry, session_id=session_id)
        if resolved_chat_id is None:
            resolved_chat_id = _infer_single_telegram_chat_id_from_registry(registry=active_registry)
        if resolved_discord_channel_id is None:
            resolved_discord_channel_id = _discord_target_channel_id_for_session(registry=active_registry, session_id=session_id)
        if resolved_discord_channel_id is None and _discord_session_channels_enabled():
            created_channel_id, _ = _discord_ensure_session_channel(
                codex_home=codex_home,
                registry=active_registry,
                session_id=session_id,
            )
            if isinstance(created_channel_id, str) and created_channel_id.strip():
                resolved_discord_channel_id = created_channel_id.strip()

    session_rec: dict[str, Any] | None = None
    if isinstance(session_id, str) and session_id.strip() and isinstance(active_registry, dict):
        sessions = active_registry.get("sessions")
        candidate = sessions.get(session_id) if isinstance(sessions, dict) else None
        session_rec = candidate if isinstance(candidate, dict) else None

    inferred_agent = None
    if isinstance(session_rec, dict):
        rec_agent = session_rec.get("agent")
        if isinstance(rec_agent, str) and rec_agent.strip():
            inferred_agent = rec_agent.strip()
    normalized_agent = _normalize_agent(agent=agent if agent is not None else inferred_agent or _current_agent())
    sid = session_id or "unknown"
    header = f"[{_agent_display_name(agent=normalized_agent)}] {sid} — {kind} — {outbound._now_local_iso()}"
    rendered_text = text.rstrip()
    if kind == "needs_input" and normalized_agent == "pi" and isinstance(session_id, str) and session_id.strip():
        rendered_text = _format_pi_needs_input_text(
            session_id=session_id,
            registry=active_registry if isinstance(active_registry, dict) else {},
            session_rec=session_rec,
            text=rendered_text,
            discord_channel_id=resolved_discord_channel_id,
        )
    body = outbound._redact(rendered_text) + "\n"

    try:
        messages = outbound._split_message(header, body, max_message_chars=max_message_chars)
    except Exception:
        messages = [f"{header}\n{body}"]

    discord_message: str | None = None
    if discord_lifecycle_event:
        discord_message = _render_discord_lifecycle_text(
            session_id=session_id,
            kind=kind,
            text=text,
            session_rec=session_rec,
        )
        if isinstance(discord_message, str):
            discord_message = outbound._redact(discord_message.rstrip())

    sent_discord_lifecycle = False
    for msg in messages:
        _record_outbound_message(
            index=message_index,
            session_id=session_id,
            kind=kind,
            text=msg,
            agent=normalized_agent,
        )
        if dry_run:
            sys.stdout.write(msg)
            sys.stdout.write("\n---\n")
            continue

        _deliver_message_across_transports(
            codex_home=codex_home,
            imessage_recipient=recipient,
            message=msg,
            telegram_chat_id=resolved_chat_id,
            telegram_message_thread_id=resolved_thread_id,
            discord_channel_id=resolved_discord_channel_id,
            deliver_to_imessage=deliver_to_imessage,
            deliver_to_telegram=deliver_to_telegram,
            deliver_to_discord=deliver_to_discord and discord_message is None,
        )

        if deliver_to_discord and discord_message is not None and not sent_discord_lifecycle:
            _deliver_message_across_transports(
                codex_home=codex_home,
                imessage_recipient=recipient,
                message=discord_message,
                telegram_chat_id=resolved_chat_id,
                telegram_message_thread_id=resolved_thread_id,
                discord_channel_id=resolved_discord_channel_id,
                deliver_to_imessage=False,
                deliver_to_telegram=False,
                deliver_to_discord=True,
            )
            sent_discord_lifecycle = True

    if dry_run and discord_message and deliver_to_discord and discord_message not in messages:
        sys.stdout.write("discord> ")
        sys.stdout.write(discord_message)
        sys.stdout.write("\n---\n")


def _find_all_session_files(*, codex_home: Path, agent: str | None = None) -> list[Path]:
    sessions_dir = _agent_session_root(codex_home=codex_home, agent=agent)
    if not sessions_dir.exists():
        return []

    out: list[Path] = []
    for path in sessions_dir.rglob("*.jsonl"):
        out.append(path)
    return out


def _agent_for_session_path(*, session_path: Path, current_home: Path) -> str:
    session_resolved = _normalize_fs_path(path=session_path)
    for agent_name in sorted(_SUPPORTED_AGENTS):
        try:
            root = _agent_session_root(codex_home=_lookup_agent_home_path(agent=agent_name, current_home=current_home), agent=agent_name)
        except Exception:
            continue
        root_norm = _normalize_fs_path(path=root)
        if session_resolved.startswith(root_norm.rstrip(os.sep) + os.sep) or session_resolved == root_norm:
            return agent_name
    return _current_agent()


def _process_session_file(
    *,
    codex_home: Path,
    session_path: Path,
    offset: int,
    recipient: str,
    max_message_chars: int,
    dry_run: bool,
    registry: dict[str, Any],
    message_index: dict[str, Any],
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

    cache_key = str(session_path)
    if cache_key not in session_id_cache:
        session_id_cache[cache_key] = outbound._read_session_id(session_path=session_path)

    session_id = session_id_cache.get(cache_key)
    session_cwd = outbound._read_session_cwd(session_path=session_path)
    session_agent = _agent_for_session_path(session_path=session_path, current_home=codex_home)

    if isinstance(session_id, str) and session_id.strip():
        fields: dict[str, Any] = {"session_path": str(session_path), "agent": session_agent}
        if isinstance(session_cwd, str) and session_cwd.strip():
            fields["cwd"] = session_cwd.strip()
        _upsert_session(registry=registry, session_id=session_id.strip(), fields=fields)

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

                sid = session_id.strip() if isinstance(session_id, str) and session_id.strip() else None
                if not sid:
                    continue

                text: str | None = None
                event_type = event.get("type")

                if event_type == "response_item":
                    payload = event.get("payload")
                    if not isinstance(payload, dict):
                        continue

                    tool_call = outbound._extract_tool_call(payload)
                    if tool_call:
                        kind, text = tool_call
                        if kind != "needs_input":
                            call_id = payload.get("call_id")
                            name = payload.get("name")
                            if isinstance(call_id, str) and isinstance(name, str) and call_id.strip() and name.strip():
                                call_id_to_name[call_id.strip()] = name.strip()
                            continue

                        call_id_raw = payload.get("call_id")
                        call_id = call_id_raw.strip() if isinstance(call_id_raw, str) and call_id_raw.strip() else None
                        session_scope = sid

                        if call_id:
                            dedupe_key = f"{cache_key}:{call_id}"
                            if dedupe_key in seen_needs_input_call_ids:
                                continue
                            call_key = agent_chat_dedupe.build_dedupe_key(
                                category="needs_input_call_id",
                                scope=session_scope,
                                text=call_id,
                            )
                            if not agent_chat_dedupe.mark_once(codex_home=codex_home, key=call_key):
                                continue

                        semantic_key = agent_chat_dedupe.build_dedupe_key(
                            category="needs_input",
                            scope=session_scope,
                            text=text,
                        )
                        if not agent_chat_dedupe.mark_once(codex_home=codex_home, key=semantic_key):
                            continue

                        sessions = registry.get("sessions")
                        rec = sessions.get(sid) if isinstance(sessions, dict) else None
                        deliver_to_discord = _should_emit_discord_lifecycle_event(
                            session_rec=rec if isinstance(rec, dict) else None,
                            event_kind="needs_input",
                        )
                        active_prompt_status = _normalize_active_prompt_status(
                            rec.get("active_prompt_status") if isinstance(rec, dict) else None
                        )
                        if active_prompt_status == "accepted" and deliver_to_discord:
                            _send_structured(
                                codex_home=codex_home,
                                recipient=recipient,
                                session_id=sid,
                                kind="working",
                                text="",
                                max_message_chars=max_message_chars,
                                dry_run=dry_run,
                                message_index=message_index,
                                agent=session_agent,
                                registry=registry,
                                deliver_to_imessage=False,
                                deliver_to_telegram=False,
                                deliver_to_discord=True,
                                discord_lifecycle_event=True,
                            )
                            _update_active_prompt_lifecycle(
                                registry=registry,
                                session_id=sid,
                                status="working",
                            )
                        _send_structured(
                            codex_home=codex_home,
                            recipient=recipient,
                            session_id=sid,
                            kind="needs_input",
                            text=text,
                            max_message_chars=max_message_chars,
                            dry_run=dry_run,
                            message_index=message_index,
                            registry=registry,
                            deliver_to_discord=deliver_to_discord,
                            discord_lifecycle_event=deliver_to_discord,
                        )

                        session_fields: dict[str, Any] = {
                            "agent": session_agent,
                            "cwd": session_cwd,
                            "session_path": str(session_path),
                            "awaiting_input": True,
                            "pending_completion": True,
                            "last_attention_ts": int(time.time()),
                            "last_needs_input": text,
                            "active_prompt_status": "needs_input",
                            "desktop_attention_state": "waiting_for_user",
                            "last_desktop_attention_ts": int(time.time()),
                        }
                        pending_request_user_input = outbound._extract_request_user_input_payload(payload)
                        if isinstance(pending_request_user_input, dict):
                            session_fields["pending_request_user_input"] = pending_request_user_input
                        tmux_pane = os.environ.get("TMUX_PANE")
                        if isinstance(tmux_pane, str) and tmux_pane.strip():
                            session_fields["tmux_pane"] = tmux_pane.strip()
                        tmux_socket = _tmux_socket_from_env()
                        if isinstance(tmux_socket, str) and tmux_socket.strip():
                            session_fields["tmux_socket"] = tmux_socket.strip()

                        _upsert_session(
                            registry=registry,
                            session_id=sid,
                            fields=session_fields,
                        )

                        if call_id:
                            seen_needs_input_call_ids[f"{cache_key}:{call_id}"] = int(time.time())
                            if len(seen_needs_input_call_ids) > 1024:
                                pruned = outbound._prune_seen_needs_input_call_ids(
                                    seen_needs_input_call_ids,
                                    now_ts=int(time.time()),
                                )
                                seen_needs_input_call_ids.clear()
                                seen_needs_input_call_ids.update(pruned)
                        continue

                    extracted = outbound._extract_message_text_from_payload(payload)
                    if not extracted:
                        continue
                    role, text = extracted
                    if role != "assistant":
                        continue
                elif event_type == "message" and session_agent == "pi":
                    message = event.get("message")
                    if not isinstance(message, dict):
                        continue
                    if message.get("role") != "assistant":
                        continue
                    parts: list[str] = []
                    content = message.get("content")
                    if isinstance(content, str) and content.strip():
                        parts.append(content.strip())
                    elif isinstance(content, list):
                        for item in content:
                            if not isinstance(item, dict):
                                continue
                            if item.get("type") != "text":
                                continue
                            text_value = item.get("text")
                            if isinstance(text_value, str) and text_value.strip():
                                parts.append(text_value.strip())
                    text = "\n".join(parts).strip() or None
                    if not text:
                        continue
                else:
                    continue

                sessions = registry.get("sessions")
                rec = sessions.get(sid) if isinstance(sessions, dict) else None
                pending_completion = isinstance(rec, dict) and rec.get("pending_completion") is True
                should_emit_update = _should_emit_session_progress_update()
                deliver_to_discord = _should_emit_discord_lifecycle_event(
                    session_rec=rec if isinstance(rec, dict) else None,
                    event_kind="update",
                )
                active_prompt_status = _normalize_active_prompt_status(
                    rec.get("active_prompt_status") if isinstance(rec, dict) else None
                )

                if pending_completion and active_prompt_status == "accepted" and deliver_to_discord:
                    _send_structured(
                        codex_home=codex_home,
                        recipient=recipient,
                        session_id=sid,
                        kind="working",
                        text="",
                        max_message_chars=max_message_chars,
                        dry_run=dry_run,
                        message_index=message_index,
                        agent=session_agent,
                        registry=registry,
                        deliver_to_imessage=False,
                        deliver_to_telegram=False,
                        deliver_to_discord=True,
                        discord_lifecycle_event=True,
                    )
                    _update_active_prompt_lifecycle(
                        registry=registry,
                        session_id=sid,
                        status="working",
                    )
                    active_prompt_status = "working"

                if pending_completion:
                    if _should_emit_session_completion_notification():
                        _send_structured(
                            codex_home=codex_home,
                            recipient=recipient,
                            session_id=sid,
                            kind="responded",
                            text=text,
                            max_message_chars=max_message_chars,
                            dry_run=dry_run,
                            message_index=message_index,
                            agent=session_agent,
                            registry=registry,
                            deliver_to_discord=deliver_to_discord,
                            discord_lifecycle_event=deliver_to_discord,
                        )

                    _update_active_prompt_lifecycle(
                        registry=registry,
                        session_id=sid,
                        status="completed",
                    )
                    _upsert_session(
                        registry=registry,
                        session_id=sid,
                        fields={
                            "awaiting_input": False,
                            "pending_completion": False,
                            "last_response_ts": int(time.time()),
                            "pending_request_user_input": None,
                            "active_prompt_status": "completed",
                            "desktop_attention_state": "resolved",
                            "last_desktop_attention_ts": int(time.time()),
                        },
                    )
                elif should_emit_update:
                    _send_structured(
                        codex_home=codex_home,
                        recipient=recipient,
                        session_id=sid,
                        kind="update",
                        text=text,
                        max_message_chars=max_message_chars,
                        dry_run=dry_run,
                        message_index=message_index,
                        agent=session_agent,
                        registry=registry,
                        deliver_to_discord=False,
                    )
                    _upsert_session(
                        registry=registry,
                        session_id=sid,
                        fields={
                            "last_response_ts": int(time.time()),
                        },
                    )

        return offset
    except Exception:
        return offset


def _session_last_active_ts(*, session_rec: dict[str, Any] | None) -> int | None:
    if not isinstance(session_rec, dict):
        return None
    candidates: list[int] = []
    for key in ("last_attention_ts", "last_response_ts", "last_resume_ts", "last_update_ts", "created_ts"):
        value = session_rec.get(key)
        if isinstance(value, int) and value > 0:
            candidates.append(int(value))
    if not candidates:
        return None
    return max(candidates)



def _format_relative_age(*, ts: int | None, now_ts: int | None = None) -> str:
    if not isinstance(ts, int) or ts <= 0:
        return "-"
    current = int(now_ts) if isinstance(now_ts, int) else int(time.time())
    delta = max(0, current - int(ts))
    if delta < 15:
        return "just now"
    if delta < 60:
        return f"{delta}s ago"
    minutes = max(1, delta // 60)
    if minutes < 60:
        return f"{minutes}m ago"
    hours = max(1, delta // 3600)
    if hours < 24:
        return f"{hours}h ago"
    days = max(1, delta // 86400)
    return f"{days}d ago"



def _session_binding_descriptions(*, registry: dict[str, Any], session_id: str) -> list[str]:
    sid = session_id.strip() if isinstance(session_id, str) else ""
    if not sid:
        return []

    out: list[str] = []
    seen: set[str] = set()

    def _push(label: str) -> None:
        text = label.strip()
        if not text or text in seen:
            return
        seen.add(text)
        out.append(text)

    telegram_bindings = registry.get("telegram_thread_bindings")
    if isinstance(telegram_bindings, dict):
        for thread_key, bound_sid in telegram_bindings.items():
            if not isinstance(bound_sid, str) or bound_sid != sid:
                continue
            chat_id = _telegram_thread_chat_id_from_key(thread_key=thread_key if isinstance(thread_key, str) else None)
            thread_id = _telegram_thread_id_from_key(thread_key=thread_key if isinstance(thread_key, str) else None)
            if isinstance(chat_id, str) and chat_id.strip() and thread_id is not None:
                _push(f"Telegram topic {chat_id.strip()}:{thread_id}")

    conversation_bindings = registry.get("conversation_bindings")
    if isinstance(conversation_bindings, dict):
        for conv_key, bound_sid in conversation_bindings.items():
            if not isinstance(bound_sid, str) or bound_sid != sid:
                continue
            if not isinstance(conv_key, str):
                continue
            parts = conv_key.split(":", 2)
            if len(parts) != 3:
                continue
            transport, channel_id_raw, thread_raw = parts
            channel_id = channel_id_raw.strip()
            thread_text = thread_raw.strip()
            if transport == "telegram" and channel_id:
                thread_id = _normalize_telegram_thread_id(thread_text)
                if thread_id is not None:
                    _push(f"Telegram topic {channel_id}:{thread_id}")
                else:
                    _push(f"Telegram chat {channel_id}")
            elif transport == "discord" and channel_id:
                if thread_text and thread_text != "0":
                    _push(f"Discord thread {thread_text} (channel {channel_id})")
                elif not _discord_is_control_channel(channel_id=channel_id):
                    _push(f"Discord channel {channel_id}")

    sessions = registry.get("sessions")
    rec = sessions.get(sid) if isinstance(sessions, dict) else None
    if isinstance(rec, dict):
        direct_discord_channel_id = rec.get("discord_channel_id")
        if isinstance(direct_discord_channel_id, str) and direct_discord_channel_id.strip():
            channel_id = direct_discord_channel_id.strip()
            if not _discord_is_control_channel(channel_id=channel_id):
                _push(f"Discord channel {channel_id}")

    return out



def _session_state_label(*, session_rec: dict[str, Any] | None) -> str:
    if not isinstance(session_rec, dict):
        return "active"
    if _session_is_waiting_for_input(session_rec=session_rec):
        agent = _normalize_agent(
            agent=session_rec.get("agent") if isinstance(session_rec.get("agent"), str) else None
        )
        if agent == "pi":
            return "waiting on you"
        return "waiting"
    return "active"



def _brief_text(*, text: str | None, max_chars: int = 140) -> str | None:
    if not isinstance(text, str):
        return None
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return None
    first = lines[0]
    if len(first) <= max(16, int(max_chars)):
        return first
    return first[: max(16, int(max_chars)) - 1].rstrip() + "…"



def _pi_pending_questions(*, session_rec: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(session_rec, dict):
        return []
    pending = session_rec.get("pending_request_user_input")
    if not isinstance(pending, dict):
        return []
    raw_questions = pending.get("questions")
    if not isinstance(raw_questions, list):
        return []
    return [q for q in raw_questions if isinstance(q, dict)]



def _pi_needs_input_suggestion_text(*, session_rec: dict[str, Any] | None, text: str) -> str:
    questions = _pi_pending_questions(session_rec=session_rec)
    if len(questions) == 1:
        raw_options = questions[0].get("options")
        option_count = len([opt for opt in raw_options if isinstance(opt, dict)]) if isinstance(raw_options, list) else 0
        if option_count >= 2:
            return "Try: `1`, `2`, `summarize`, or your own instructions."
        if option_count == 1:
            return "Try: `1`, `summarize`, or your own instructions."
    if len(questions) > 1:
        has_options = any(
            isinstance(q.get("options"), list) and any(isinstance(opt, dict) for opt in q.get("options", []))
            for q in questions
        )
        if has_options:
            return "Use `<question>.<option>` such as `1.2`, or send `summarize`."

    lowered = text.strip().lower()
    if any(token in lowered for token in ("approve", "approval", "ready to apply", "apply changes", "ready to edit")):
        return "Try: `approve`, `revise`, `summarize`, or your own instructions."
    if any(token in lowered for token in ("yes or no", "yes/no", "should i", "should we", "do you want", "confirm")):
        return "Try: `yes`, `no`, `summarize`, or your own instructions."
    return "Try: `continue`, `summarize`, `yes`, or `no`."



def _format_pi_needs_input_text(
    *,
    session_id: str,
    registry: dict[str, Any],
    session_rec: dict[str, Any] | None,
    text: str,
    discord_channel_id: str | None = None,
) -> str:
    rec = session_rec if isinstance(session_rec, dict) else None
    ref = rec.get("ref") if isinstance(rec, dict) and isinstance(rec.get("ref"), str) else _session_ref(session_id)
    prompt_text = text.strip()
    questions = _pi_pending_questions(session_rec=rec)
    rendered_questions = outbound._render_request_user_input_questions(questions) if questions else None
    prompt_body = rendered_questions.strip() if isinstance(rendered_questions, str) and rendered_questions.strip() else prompt_text
    if not prompt_body:
        prompt_body = "Pi needs more information before it can continue."

    has_bound_surface = bool(_session_binding_descriptions(registry=registry, session_id=session_id))
    if not has_bound_surface and isinstance(discord_channel_id, str) and discord_channel_id.strip():
        has_bound_surface = True

    lines = [f"Pi is waiting for your input on @{ref}.", "", prompt_body, ""]
    if has_bound_surface:
        lines.append(f"Reply here with plain text to continue @{ref}.")
    else:
        lines.append(f"Reply with `@{ref} <instruction>` to continue this session.")
    lines.append(_pi_needs_input_suggestion_text(session_rec=rec, text=prompt_body))
    return "\n".join(lines).strip()



def _render_session_identity(*, registry: dict[str, Any], session_id: str) -> str:
    sessions = registry.get("sessions")
    rec = sessions.get(session_id) if isinstance(sessions, dict) else None
    alias = rec.get("alias") if isinstance(rec, dict) and isinstance(rec.get("alias"), str) else ""
    agent = _normalize_agent(agent=rec.get("agent") if isinstance(rec, dict) and isinstance(rec.get("agent"), str) else None)
    ref = rec.get("ref") if isinstance(rec, dict) and isinstance(rec.get("ref"), str) else _session_ref(session_id)
    if alias:
        return f"@{ref} ({alias}, {_agent_display_name(agent=agent)})"
    return f"@{ref} ({_agent_display_name(agent=agent)})"



def _render_session_list(*, registry: dict[str, Any]) -> str:
    sessions = registry.get("sessions")
    if not isinstance(sessions, dict) or not sessions:
        return "No tracked sessions yet. Send `new <label>: <instruction>` to start one."

    rows: list[tuple[int, str, dict[str, Any]]] = []
    for sid, rec in sessions.items():
        if not isinstance(sid, str) or not isinstance(rec, dict):
            continue
        ts = _session_last_active_ts(session_rec=rec)
        rows.append((int(ts) if isinstance(ts, int) else 0, sid, rec))

    rows.sort(key=lambda item: item[0], reverse=True)

    lines = ["Sessions:"]
    for _, sid, rec in rows[:12]:
        ref = rec.get("ref") if isinstance(rec.get("ref"), str) else _session_ref(sid)
        alias = rec.get("alias") if isinstance(rec.get("alias"), str) else ""
        agent = _normalize_agent(agent=rec.get("agent") if isinstance(rec.get("agent"), str) else None)
        state = _session_state_label(session_rec=rec)
        last_active = _format_relative_age(ts=_session_last_active_ts(session_rec=rec))
        bindings = _session_binding_descriptions(registry=registry, session_id=sid)
        binding_summary = bindings[0] if bindings else "unbound"
        if alias:
            lines.append(
                f"- [{_agent_display_name(agent=agent)}] @{ref} ({alias}) — {state} — {last_active} — {binding_summary}"
            )
        else:
            lines.append(f"- [{_agent_display_name(agent=agent)}] @{ref} — {state} — {last_active} — {binding_summary}")

    return "\n".join(lines)



def _render_session_status(*, session_id: str, registry: dict[str, Any]) -> str:
    sessions = registry.get("sessions")
    if not isinstance(sessions, dict):
        return f"Session {session_id} not found."
    rec = sessions.get(session_id)
    if not isinstance(rec, dict):
        return f"Session {session_id} not found."

    ref = rec.get("ref") if isinstance(rec.get("ref"), str) else _session_ref(session_id)
    alias = rec.get("alias") if isinstance(rec.get("alias"), str) else ""
    waiting = "yes" if _session_is_waiting_for_input(session_rec=rec) else "no"
    state = _session_state_label(session_rec=rec)
    agent = _normalize_agent(agent=rec.get("agent") if isinstance(rec.get("agent"), str) else None)
    cwd = rec.get("cwd") if isinstance(rec.get("cwd"), str) else ""
    path = rec.get("session_path") if isinstance(rec.get("session_path"), str) else ""
    pane = rec.get("tmux_pane") if isinstance(rec.get("tmux_pane"), str) else ""
    socket_value = rec.get("tmux_socket") if isinstance(rec.get("tmux_socket"), str) else ""
    bindings = _session_binding_descriptions(registry=registry, session_id=session_id)
    last_active = _format_relative_age(ts=_session_last_active_ts(session_rec=rec))

    next_text = f"reply in a bound topic/channel, or send `@{ref} <instruction>` from any control surface."
    if agent == "pi" and _session_is_waiting_for_input(session_rec=rec):
        if bindings:
            next_text = "reply in the bound topic/channel, or send `summarize`."
        else:
            next_text = f"send `@{ref} <instruction>` or `summarize`."

    lines = [
        f"Session: {session_id}",
        f"Ref: @{ref}",
        f"Alias: {alias or '-'}",
        f"Agent: {_agent_display_name(agent=agent)}",
        f"State: {state}",
        f"Awaiting input: {waiting}",
        f"Last active: {last_active}",
        f"Bindings: {', '.join(bindings) if bindings else '-'}",
        f"CWD: {cwd or '-'}",
        f"Session path: {path or '-'}",
        f"Tmux pane: {pane or '-'}",
        f"Tmux socket: {socket_value or '-'}",
    ]
    if agent == "pi" and _session_is_waiting_for_input(session_rec=rec):
        last_request = _brief_text(text=rec.get("last_needs_input") if isinstance(rec.get("last_needs_input"), str) else None)
        if isinstance(last_request, str) and last_request:
            lines.append(f"Last Pi request: {last_request}")
    lines.append(f"Next: {next_text}")
    return "\n".join(lines)


def _first_nonempty_from_sources(
    *,
    sources: tuple[dict[str, Any] | None, ...],
    keys: tuple[str, ...],
) -> str | None:
    for source in sources:
        if not isinstance(source, dict):
            continue
        for key in keys:
            value = source.get(key)
            if isinstance(value, str):
                trimmed = value.strip()
                if trimmed:
                    return trimmed
    return None


def _extract_session_id_from_notify_payload(payload: dict[str, Any]) -> tuple[str | None, dict[str, Any] | None]:
    params_raw = payload.get("params")
    params = params_raw if isinstance(params_raw, dict) else None
    sources = (payload, params)

    session_id = _first_nonempty_from_sources(
        sources=sources,
        keys=(
            "thread-id",
            "thread_id",
            "threadId",
            "session_id",
            "session-id",
            "sessionId",
            "session",
        ),
    )
    if session_id:
        return session_id, params

    session_path = _first_nonempty_from_sources(
        sources=sources,
        keys=(
            "session_path",
            "session-path",
            "sessionPath",
            "session_file",
            "session-file",
            "transcript_path",
            "transcript-path",
            "transcriptPath",
        ),
    )
    if isinstance(session_path, str) and session_path:
        resolved = outbound._read_session_id(session_path=Path(session_path))
        if isinstance(resolved, str) and resolved.strip():
            session_id = resolved.strip()

    return session_id, params


def _extract_notify_context_fields(
    *,
    payload: dict[str, Any],
    params: dict[str, Any] | None,
) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    sources = (payload, params)

    payload_agent = _first_nonempty_from_sources(
        sources=sources,
        keys=("agent", "source_agent", "runtime_agent"),
    )
    normalized_payload_agent = payload_agent.strip().lower() if isinstance(payload_agent, str) else ""
    if normalized_payload_agent in _SUPPORTED_AGENTS:
        fields["agent"] = normalized_payload_agent
    else:
        fields["agent"] = _current_agent()

    tmux_pane = os.environ.get("TMUX_PANE")
    if isinstance(tmux_pane, str) and tmux_pane.strip():
        fields["tmux_pane"] = tmux_pane.strip()
    tmux_socket = _tmux_socket_from_env()
    if isinstance(tmux_socket, str) and tmux_socket.strip():
        fields["tmux_socket"] = tmux_socket.strip()

    cwd = _first_nonempty_from_sources(sources=sources, keys=("cwd",))

    if cwd is None:
        pwd = os.environ.get("PWD")
        if isinstance(pwd, str) and pwd.strip():
            cwd = pwd.strip()

    if isinstance(cwd, str) and cwd.strip():
        fields["cwd"] = cwd.strip()

    session_path = _first_nonempty_from_sources(
        sources=sources,
        keys=(
            "session_path",
            "session-path",
            "sessionPath",
            "session_file",
            "session-file",
            "transcript_path",
            "transcript-path",
            "transcriptPath",
        ),
    )
    if not session_path:
        for env_key in _session_path_env_keys():
            env_session_path = os.environ.get(env_key)
            if isinstance(env_session_path, str) and env_session_path.strip():
                session_path = env_session_path.strip()
                break
    if isinstance(session_path, str) and session_path.strip():
        fields["session_path"] = session_path.strip()

    return fields


def _env_enabled(name: str, *, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return bool(default)
    return raw.strip().lower() not in {"0", "false", "no", "off"}


def _strict_tmux_enabled() -> bool:
    return _env_enabled("AGENT_CHAT_STRICT_TMUX", default=True)


def _require_session_ref_enabled(*, strict_tmux: bool) -> bool:
    return _env_enabled("AGENT_CHAT_REQUIRE_SESSION_REF", default=strict_tmux)


def _tmux_ack_timeout_s() -> float:
    fallback = getattr(reply, "_DEFAULT_TMUX_USER_ACK_TIMEOUT_S", _DEFAULT_TMUX_ACK_TIMEOUT_S)
    raw = os.environ.get("AGENT_CHAT_TMUX_ACK_TIMEOUT_S", "").strip()
    if not raw:
        return float(fallback)
    try:
        return max(0.1, float(raw))
    except Exception:
        return float(fallback)


def _set_last_dispatch_error(
    *,
    registry: dict[str, Any],
    session_id: str | None,
    mode: str,
    reason: str | None = None,
) -> None:
    payload: dict[str, Any] = {"ts": int(time.time()), "mode": mode}
    if isinstance(session_id, str) and session_id.strip():
        payload["session_id"] = session_id.strip()
    if isinstance(reason, str) and reason.strip():
        payload["reason"] = reason.strip()
    registry["last_dispatch_error"] = payload


def _clear_last_dispatch_error(*, registry: dict[str, Any]) -> None:
    if registry.get("last_dispatch_error") is None:
        return
    registry["last_dispatch_error"] = None



def _bound_session_for_inbound_context(
    *,
    registry: dict[str, Any],
    transport: str | None,
    telegram_chat_id: str | None = None,
    telegram_message_thread_id: int | None = None,
    discord_channel_id: str | None = None,
    discord_parent_channel_id: str | None = None,
) -> str | None:
    normalized_transport = transport.strip().lower() if isinstance(transport, str) and transport.strip() else "imessage"
    if normalized_transport == "telegram":
        sid = _lookup_session_by_telegram_thread(
            registry=registry,
            chat_id=telegram_chat_id,
            message_thread_id=telegram_message_thread_id,
        )
        if sid:
            return sid
        return _lookup_single_session_by_telegram_chat(registry=registry, chat_id=telegram_chat_id)

    if normalized_transport == "discord":
        sid = _lookup_session_by_discord_channel_id(registry=registry, channel_id=discord_channel_id)
        if sid:
            return sid
        context_channel_id = discord_parent_channel_id or discord_channel_id
        context_thread_id: int | str | None = 0
        if (
            isinstance(discord_parent_channel_id, str)
            and discord_parent_channel_id.strip()
            and isinstance(discord_channel_id, str)
            and discord_channel_id.strip()
            and discord_parent_channel_id.strip() != discord_channel_id.strip()
        ):
            context_thread_id = discord_channel_id.strip()
        return _lookup_session_by_conversation(
            registry=registry,
            transport="discord",
            channel_id=context_channel_id,
            thread_id=context_thread_id,
        )

    return None



def _context_surface_label(
    *,
    transport: str | None,
    recipient: str | None = None,
    telegram_chat_id: str | None = None,
    telegram_message_thread_id: int | None = None,
    discord_channel_id: str | None = None,
    discord_parent_channel_id: str | None = None,
) -> str:
    normalized_transport = transport.strip().lower() if isinstance(transport, str) and transport.strip() else "imessage"
    if normalized_transport == "telegram":
        if isinstance(telegram_chat_id, str) and telegram_chat_id.strip() and telegram_message_thread_id is not None:
            return f"Telegram topic {telegram_chat_id.strip()}:{telegram_message_thread_id}"
        if isinstance(telegram_chat_id, str) and telegram_chat_id.strip():
            return f"Telegram chat {telegram_chat_id.strip()}"
        return "Telegram conversation"
    if normalized_transport == "discord":
        if (
            isinstance(discord_parent_channel_id, str)
            and discord_parent_channel_id.strip()
            and isinstance(discord_channel_id, str)
            and discord_channel_id.strip()
            and discord_parent_channel_id.strip() != discord_channel_id.strip()
        ):
            return f"Discord thread {discord_channel_id.strip()} (channel {discord_parent_channel_id.strip()})"
        channel_id = discord_parent_channel_id or discord_channel_id
        if isinstance(channel_id, str) and channel_id.strip():
            label = f"Discord channel {channel_id.strip()}"
            if _discord_is_control_channel(channel_id=channel_id.strip()):
                label += " [control]"
            return label
        return "Discord conversation"
    recipient_text = recipient.strip() if isinstance(recipient, str) else ""
    if recipient_text:
        return f"iMessage conversation with {recipient_text}"
    return "iMessage conversation"



def _context_followup_hint(
    *,
    transport: str | None,
    telegram_message_thread_id: int | None = None,
    discord_channel_id: str | None = None,
    discord_parent_channel_id: str | None = None,
) -> str:
    normalized_transport = transport.strip().lower() if isinstance(transport, str) and transport.strip() else "imessage"
    if normalized_transport == "telegram" and telegram_message_thread_id is not None:
        return " Plain-text replies in this topic will continue the same session."
    if normalized_transport == "discord":
        if (
            isinstance(discord_parent_channel_id, str)
            and discord_parent_channel_id.strip()
            and isinstance(discord_channel_id, str)
            and discord_channel_id.strip()
            and discord_parent_channel_id.strip() != discord_channel_id.strip()
        ):
            return " Plain-text replies in this thread will continue the same session."
        channel_id = discord_parent_channel_id or discord_channel_id
        if isinstance(channel_id, str) and channel_id.strip():
            if _discord_is_control_channel(channel_id=channel_id.strip()):
                return " This is a control surface, so targeted follow-ups should use a session channel or `@<ref> ...`."
            return " Plain-text replies here will continue the same session."
    return ""



def _render_bind_confirmation(
    *,
    registry: dict[str, Any],
    session_id: str,
    transport: str | None,
    telegram_chat_id: str | None = None,
    telegram_message_thread_id: int | None = None,
    discord_channel_id: str | None = None,
    discord_parent_channel_id: str | None = None,
) -> str:
    session_label = _render_session_identity(registry=registry, session_id=session_id)
    normalized_transport = transport.strip().lower() if isinstance(transport, str) and transport.strip() else "imessage"
    if normalized_transport == "telegram":
        if telegram_message_thread_id is not None:
            return f"Bound this Telegram topic to {session_label}. Future plain-text replies here will continue that session."
        return f"Bound this Telegram chat to {session_label}."
    if normalized_transport == "discord":
        if (
            isinstance(discord_parent_channel_id, str)
            and discord_parent_channel_id.strip()
            and isinstance(discord_channel_id, str)
            and discord_channel_id.strip()
            and discord_parent_channel_id.strip() != discord_channel_id.strip()
        ):
            return f"Bound this Discord thread to {session_label}. Future plain-text replies here will continue that session."
        return f"Bound this Discord channel to {session_label}. Future plain-text replies here will continue that session."
    return f"Bound this conversation to {session_label}."



def _render_context_status(
    *,
    registry: dict[str, Any],
    transport: str | None,
    recipient: str | None,
    telegram_chat_id: str | None = None,
    telegram_message_thread_id: int | None = None,
    discord_channel_id: str | None = None,
    discord_parent_channel_id: str | None = None,
) -> str:
    normalized_transport = transport.strip().lower() if isinstance(transport, str) and transport.strip() else "imessage"
    surface = _context_surface_label(
        transport=normalized_transport,
        recipient=recipient,
        telegram_chat_id=telegram_chat_id,
        telegram_message_thread_id=telegram_message_thread_id,
        discord_channel_id=discord_channel_id,
        discord_parent_channel_id=discord_parent_channel_id,
    )
    bound_sid = _bound_session_for_inbound_context(
        registry=registry,
        transport=normalized_transport,
        telegram_chat_id=telegram_chat_id,
        telegram_message_thread_id=telegram_message_thread_id,
        discord_channel_id=discord_channel_id,
        discord_parent_channel_id=discord_parent_channel_id,
    )

    lines = ["Context:", f"- Surface: {surface}"]

    if isinstance(bound_sid, str) and bound_sid.strip():
        lines.append(f"- Bound session: {_render_session_identity(registry=registry, session_id=bound_sid.strip())}")
        followup_text = "reply here with plain text"
        followup_hint = _context_followup_hint(
            transport=normalized_transport,
            telegram_message_thread_id=telegram_message_thread_id,
            discord_channel_id=discord_channel_id,
            discord_parent_channel_id=discord_parent_channel_id,
        ).strip()
        if followup_hint:
            followup_text += f". {followup_hint}"
        lines.append(f"- Follow-up: {followup_text}")
        lines.append("- Rebind: send `bind @<session_ref>` to move this surface.")
        return "\n".join(lines)

    if normalized_transport == "telegram":
        lines.append("- Bound session: none")
        lines.append("- Next: send `bind @<session_ref>` to connect this topic, or `@<session_ref> <instruction>` once.")
    elif normalized_transport == "discord":
        channel_id = discord_parent_channel_id or discord_channel_id
        if isinstance(channel_id, str) and channel_id.strip() and _discord_is_control_channel(channel_id=channel_id.strip()):
            lines.append("- Role: control surface for `help`, `list`, `where`, `status`, and `new ...`.")
            lines.append("- Next: send `new <label>: <instruction>`, `list`, or route explicitly with `@<session_ref> ...`.")
        else:
            lines.append("- Bound session: none")
            lines.append("- Next: send `bind @<session_ref>` to attach this channel/thread, or `new <label>: <instruction>`.")
    else:
        lines.append("- Role: global control surface")
        lines.append("- Next: send `list`, `status @<session_ref>`, or `@<session_ref> <instruction>`.")

    return "\n".join(lines)



def _render_missing_session_prompt(
    *,
    transport: str | None,
    recipient: str | None,
    registry: dict[str, Any],
    telegram_chat_id: str | None = None,
    telegram_message_thread_id: int | None = None,
    discord_channel_id: str | None = None,
    discord_parent_channel_id: str | None = None,
) -> str:
    surface = _context_surface_label(
        transport=transport,
        recipient=recipient,
        telegram_chat_id=telegram_chat_id,
        telegram_message_thread_id=telegram_message_thread_id,
        discord_channel_id=discord_channel_id,
        discord_parent_channel_id=discord_parent_channel_id,
    )
    lines = [
        "I couldn't match that message to a session.",
        f"Surface: {surface}",
        "Choose a runtime for a new background session:",
        "1) Codex",
        "2) Claude",
        "3) Pi",
        "Reply with 1, 2, or 3 (or codex/claude/pi). Reply 'cancel' to abort.",
        "Need an existing ref instead? Send `list`. If this is the right surface, send `bind @<session_ref>`.",
    ]
    return "\n".join(lines)



def _dispatch_failure_text(*, session_id: str, mode: str, reason: str | None) -> str:
    ref = _session_ref(session_id) or session_id[:8]
    reason_key = reason.strip().lower() if isinstance(reason, str) and reason.strip() else ""
    reason_details = {
        "pane_missing": "no pane mapping was available",
        "pane_stale": "the stored pane mapping is stale",
        "pane_discovery_ambiguous": "multiple tmux panes matched and routing is ambiguous",
        "session_path_missing": "session path metadata is missing for tmux correlation",
        "session_path_mismatch": "the tmux pane did not match the target session",
        "send_failed": "tmux send-keys failed",
        "ack_timeout": "tmux did not acknowledge the prompt in time",
        "session_record_missing": "session metadata is missing",
    }
    detail = reason_details.get(reason_key) or (
        "tmux routing failed" if mode == "tmux_failed" else "tmux pane routing is unavailable"
    )
    return (
        f"I couldn't deliver that to @{ref} because {detail}. "
        "Strict tmux routing is enabled, so I did not fall back to resume. "
        "Next: bring the target tmux pane online, then resend `@<ref> <instruction>`. "
        "If you are unsure which session is bound here, send `where` or `list`."
    )


def _should_resume_fallback_for_tmux_dispatch(*, mode: str, reason: str | None) -> bool:
    if mode != "tmux_stale":
        return False
    reason_key = reason.strip().lower() if isinstance(reason, str) and reason.strip() else ""
    return reason_key in {
        "pane_missing",
        "pane_stale",
        "pane_discovery_ambiguous",
        "session_path_missing",
        "session_path_mismatch",
    }


def _render_notify_input_text(*, session_path: str | None) -> tuple[str, dict[str, Any] | None]:
    if not (isinstance(session_path, str) and session_path.strip()):
        return _DEFAULT_INPUT_NEEDED_TEXT, None
    parsed = notify._read_last_request_user_input_from_session(Path(session_path.strip()))
    if not isinstance(parsed, dict):
        return _DEFAULT_INPUT_NEEDED_TEXT, None
    rendered = notify._format_request_user_input_for_imessage(parsed)
    if isinstance(rendered, str) and rendered.strip():
        return rendered.strip(), parsed
    return _DEFAULT_INPUT_NEEDED_TEXT, parsed


def _default_new_session_cwd() -> str | None:
    pwd = os.environ.get("PWD")
    if isinstance(pwd, str) and pwd.strip():
        return pwd.strip()
    try:
        return str(Path.cwd())
    except Exception:
        return None


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
    discovered = _discover_tmux_bin()
    if discovered:
        return discovered
    return "tmux"


def _resolve_brew_bin() -> str | None:
    discovered = shutil.which("brew")
    if isinstance(discovered, str) and discovered.strip():
        return discovered.strip()

    for candidate in _BREW_BIN_CANDIDATES:
        try:
            if Path(candidate).exists() and os.access(candidate, os.X_OK):
                return candidate
        except Exception:
            continue
    return None


def _discover_tmux_bin() -> str | None:
    override = os.environ.get("AGENT_CHAT_TMUX_BIN")
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
    return None


def _ensure_tmux_available_for_setup() -> tuple[str | None, str | None]:
    tmux_bin = _discover_tmux_bin()
    if isinstance(tmux_bin, str) and tmux_bin.strip():
        return tmux_bin.strip(), None

    brew_bin = _resolve_brew_bin()
    if not brew_bin:
        brew_bin, brew_setup_err = _install_homebrew_for_setup()
        if isinstance(brew_setup_err, str):
            return None, brew_setup_err
        if not isinstance(brew_bin, str) or not brew_bin.strip():
            return (
                None,
                "tmux is required for setup commands, but Homebrew could not be resolved after install.\n"
                "Install Homebrew (https://brew.sh/) and rerun setup.\n",
            )
        brew_bin = brew_bin.strip()

    sys.stdout.write("tmux not found. Attempting automatic install via Homebrew...\n")
    sys.stdout.write(f"Running: {shlex.join([brew_bin, 'install', 'tmux'])}\n")
    sys.stdout.flush()
    try:
        proc = subprocess.run(
            [brew_bin, "install", "tmux"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except Exception as exc:
        return (
            None,
            "Failed to run Homebrew while installing tmux: "
            f"{type(exc).__name__}: {exc}\n"
            "Run `brew install tmux` manually, then rerun setup.\n",
        )

    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        if detail:
            detail = detail.splitlines()[-1]
        else:
            detail = f"exit {proc.returncode}"
        return (
            None,
            "Automatic tmux install failed via Homebrew: "
            f"{detail}\n"
            "Run `brew install tmux` manually, then rerun setup.\n",
        )

    tmux_bin = _discover_tmux_bin()
    if isinstance(tmux_bin, str) and tmux_bin.strip():
        sys.stdout.write(f"tmux installed: {tmux_bin.strip()}\n")
        sys.stdout.flush()
        return tmux_bin.strip(), None
    return (
        None,
        "Homebrew reported success, but tmux is still not available in PATH.\n"
        "Open a new shell (or set AGENT_CHAT_TMUX_BIN) and rerun setup.\n",
    )


def _install_homebrew_for_setup() -> tuple[str | None, str | None]:
    sys.stdout.write("Homebrew not found. Attempting automatic Homebrew install...\n")
    sys.stdout.write(f"Source: {_HOMEBREW_INSTALL_URL}\n")
    sys.stdout.flush()

    env = dict(os.environ)
    env["NONINTERACTIVE"] = "1"
    env.setdefault("HOMEBREW_NO_ANALYTICS", "1")
    try:
        proc = subprocess.run(
            ["/bin/bash", "-c", f"$(curl -fsSL {_HOMEBREW_INSTALL_URL})"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
    except Exception as exc:
        return (
            None,
            "Failed to run automatic Homebrew install: "
            f"{type(exc).__name__}: {exc}\n"
            "Install Homebrew manually from https://brew.sh/, then rerun setup.\n",
        )

    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        if detail:
            detail = detail.splitlines()[-1]
        else:
            detail = f"exit {proc.returncode}"
        return (
            None,
            "Automatic Homebrew install failed: "
            f"{detail}\n"
            "Install Homebrew manually from https://brew.sh/, then rerun setup.\n",
        )

    brew_bin = _resolve_brew_bin()
    if isinstance(brew_bin, str) and brew_bin.strip():
        sys.stdout.write(f"Homebrew installed: {brew_bin.strip()}\n")
        sys.stdout.flush()
        return brew_bin.strip(), None
    return (
        None,
        "Homebrew install completed, but `brew` is still not available in PATH.\n"
        "Open a new shell (or run brew shellenv), then rerun setup.\n",
    )


def _resolve_codex_bin() -> str:
    override = os.environ.get("AGENT_CHAT_CODEX_BIN")
    if isinstance(override, str) and override.strip():
        return override.strip()

    discovered = shutil.which("codex")
    if isinstance(discovered, str) and discovered.strip():
        return discovered.strip()

    for candidate in _CODEX_BIN_CANDIDATES:
        try:
            if Path(candidate).exists() and os.access(candidate, os.X_OK):
                return candidate
        except Exception:
            continue

    return "codex"


def _resolve_claude_bin() -> str:
    override = os.environ.get("AGENT_CHAT_CLAUDE_BIN")
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


def _resolve_pi_bin() -> str:
    override = os.environ.get("AGENT_CHAT_PI_BIN")
    if isinstance(override, str) and override.strip():
        return override.strip()

    discovered = shutil.which("pi")
    if isinstance(discovered, str) and discovered.strip():
        return discovered.strip()

    for candidate in _PI_BIN_CANDIDATES:
        try:
            if Path(candidate).exists() and os.access(candidate, os.X_OK):
                return candidate
        except Exception:
            continue

    return "pi"


def _resolve_agent_bin(*, agent: str | None = None) -> str:
    normalized = _normalize_agent(agent=agent if agent is not None else _current_agent())
    if normalized == "claude":
        return _resolve_claude_bin()
    if normalized == "pi":
        return _resolve_pi_bin()
    return _resolve_codex_bin()


def _is_agent_command(command: str, *, agent: str | None = None) -> bool:
    if not isinstance(command, str):
        return False
    return _agent_command_keyword(agent=agent if agent is not None else _current_agent()) in command.lower()


def _tmux_cmd(*parts: str, tmux_socket: str | None = None) -> list[str]:
    cmd = [_resolve_tmux_bin()]
    socket_value = _normalize_tmux_socket(tmux_socket=tmux_socket)
    if socket_value:
        cmd.extend(["-S", socket_value])
    cmd.extend(list(parts))
    return cmd


def _choose_registry_tmux_socket(*, registry: dict[str, Any]) -> str | None:
    sessions = registry.get("sessions")
    if not isinstance(sessions, dict):
        return None

    best_socket: str | None = None
    best_ts = -1
    for rec in sessions.values():
        if not isinstance(rec, dict):
            continue
        socket_value = _normalize_tmux_socket(
            tmux_socket=rec.get("tmux_socket") if isinstance(rec.get("tmux_socket"), str) else None
        )
        if not socket_value:
            continue
        ts_candidates = [
            rec.get("last_resume_ts"),
            rec.get("last_attention_ts"),
            rec.get("last_update_ts"),
            rec.get("last_response_ts"),
        ]
        max_ts = 0
        for ts in ts_candidates:
            if isinstance(ts, int) and ts > max_ts:
                max_ts = ts
        if max_ts >= best_ts:
            best_ts = max_ts
            best_socket = socket_value

    return best_socket


def _tmux_active_codex_panes(*, tmux_socket: str | None) -> dict[str, Any]:
    socket_value = _normalize_tmux_socket(tmux_socket=tmux_socket)
    try:
        proc = subprocess.run(
            _tmux_cmd(
                "list-panes",
                "-a",
                "-F",
                "#{pane_id}\t#{pane_current_command}\t#{pane_current_path}",
                tmux_socket=socket_value,
            ),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
        )
    except Exception as exc:
        return {
            "socket": socket_value,
            "count": 0,
            "sample": [],
            "error": f"{type(exc).__name__}: {exc}",
        }

    if proc.returncode != 0:
        err = (proc.stderr or "").strip()
        return {
            "socket": socket_value,
            "count": 0,
            "sample": [],
            "error": err or f"tmux exit {proc.returncode}",
        }

    panes: list[dict[str, str]] = []
    for raw in proc.stdout.splitlines():
        parts = raw.split("\t")
        if len(parts) < 3:
            continue
        pane_id = parts[0].strip()
        command = parts[1].strip()
        pane_path = parts[2].strip()
        if not pane_id:
            continue
        if not _is_agent_command(command):
            continue
        panes.append({"pane_id": pane_id, "command": command, "path": pane_path})

    return {
        "socket": socket_value,
        "count": len(panes),
        "sample": panes[:_MAX_DOCTOR_PANE_SAMPLE],
    }


def _tmux_session_exists(*, session_name: str, tmux_socket: str | None = None) -> bool:
    if not isinstance(session_name, str) or not session_name.strip():
        return False
    try:
        proc = subprocess.run(
            _tmux_cmd("has-session", "-t", session_name.strip(), tmux_socket=tmux_socket),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except Exception:
        return False
    return proc.returncode == 0


def _tmux_ensure_active_session(*, cwd: str | None, tmux_socket: str | None = None) -> tuple[str | None, str | None]:
    raw_base = os.environ.get("AGENT_CHAT_TMUX_NEW_SESSION_NAME", _DEFAULT_TMUX_NEW_SESSION_NAME)
    base = raw_base.strip() if isinstance(raw_base, str) and raw_base.strip() else _DEFAULT_TMUX_NEW_SESSION_NAME

    # Keep all iMessage-driven tmux work in one canonical session.
    if _tmux_session_exists(session_name=base, tmux_socket=tmux_socket):
        return base, None

    cmd = _tmux_cmd("new-session", "-d", "-s", base, tmux_socket=tmux_socket)
    if isinstance(cwd, str) and cwd.strip():
        cmd.extend(["-c", cwd.strip()])
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except Exception:
        return None, f"Failed to start tmux session '{base}'."

    if proc.returncode == 0:
        return base, None
    if _tmux_session_exists(session_name=base, tmux_socket=tmux_socket):
        return base, None
    return None, f"Failed to start tmux session '{base}'."


def _sanitize_tmux_window_label(*, label: str | None) -> str:
    if not isinstance(label, str):
        return "session"
    candidate = label.strip().lower()
    if not candidate:
        return "session"
    candidate = re.sub(r"[^a-z0-9._-]+", "-", candidate)
    candidate = re.sub(r"-{2,}", "-", candidate).strip("-.")
    if not candidate:
        return "session"
    return candidate[:32]


def _tmux_start_codex_window(
    *,
    session_name: str,
    cwd: str | None,
    label: str | None = None,
    agent: str | None = None,
    tmux_socket: str | None = None,
) -> tuple[str | None, str | None, str | None]:
    if not isinstance(session_name, str) or not session_name.strip():
        return None, None, "Invalid tmux session name."

    raw_prefix = os.environ.get("AGENT_CHAT_TMUX_WINDOW_PREFIX", _DEFAULT_TMUX_WINDOW_PREFIX)
    prefix = raw_prefix.strip() if isinstance(raw_prefix, str) and raw_prefix.strip() else _DEFAULT_TMUX_WINDOW_PREFIX
    label_token = _sanitize_tmux_window_label(label=label)
    ts = time.strftime("%H%M%S")
    base_window_name = f"{prefix}-{label_token}-{ts}"
    normalized_agent = _normalize_agent(agent=agent if agent is not None else _current_agent())
    agent_bin = _resolve_agent_bin(agent=normalized_agent)
    if normalized_agent == "claude":
        launch_cmd = f"CLAUDE_CHAT_REPLY=1 {shlex.quote(agent_bin)}"
    elif normalized_agent == "pi":
        pi_home = _agent_home_path(agent="pi")
        launch_cmd = (
            f"AGENT_CHAT_REPLY=1 PI_CODING_AGENT_DIR={shlex.quote(str(pi_home))} "
            f"{shlex.quote(agent_bin)}"
        )
    else:
        launch_cmd = f"AGENT_CHAT_REPLY=1 {shlex.quote(agent_bin)} -a never -s danger-full-access"

    for i in range(0, 64):
        window_name = base_window_name if i == 0 else f"{base_window_name}-{i}"
        cmd = _tmux_cmd(
            "new-window",
            "-P",
            "-F",
            "#{pane_id}",
            "-t",
            session_name.strip(),
            "-n",
            window_name,
            tmux_socket=tmux_socket,
        )
        if isinstance(cwd, str) and cwd.strip():
            cmd.extend(["-c", cwd.strip()])
        cmd.append(launch_cmd)

        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
                text=True,
            )
        except Exception:
            return None, None, "Failed to create tmux window."

        if proc.returncode != 0:
            continue

        pane = proc.stdout.strip()
        if not pane:
            return None, None, "tmux created a window but did not return pane ID."
        return pane, window_name, None

    return None, None, f"Failed to create tmux window for {_agent_display_name(agent=normalized_agent)}."


def _tmux_wait_for_pane_command(*, pane: str, expected: str, timeout_s: float, tmux_socket: str | None = None) -> bool:
    target = expected.strip().lower()
    if not target:
        return False

    deadline = time.monotonic() + max(0.0, float(timeout_s))
    while time.monotonic() < deadline:
        try:
            proc = subprocess.run(
                _tmux_cmd("display-message", "-p", "-t", pane, "#{pane_current_command}", tmux_socket=tmux_socket),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
                text=True,
            )
        except Exception:
            return False

        if proc.returncode == 0:
            current = proc.stdout.strip().lower()
            if current == target:
                return True

        time.sleep(0.25)

    return False


def _tmux_pane_exists(*, pane: str, tmux_socket: str | None = None) -> bool:
    target = pane.strip()
    if not target:
        return False

    try:
        proc = subprocess.run(
            _tmux_cmd("list-panes", "-a", "-F", "#{pane_id}", tmux_socket=tmux_socket),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            text=True,
        )
    except Exception:
        return False

    if proc.returncode != 0:
        return False

    for raw in proc.stdout.splitlines():
        if raw.strip() == target:
            return True
    return False


def _tmux_desktop_presence_for_pane(*, pane: str, tmux_socket: str | None = None) -> str:
    target = pane.strip()
    if not target:
        return "hidden"

    try:
        proc = subprocess.run(
            _tmux_cmd(
                "display-message",
                "-p",
                "-t",
                target,
                "#{session_attached}\t#{window_active}\t#{pane_active}",
                tmux_socket=tmux_socket,
            ),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            text=True,
        )
    except Exception:
        return "hidden"

    if proc.returncode != 0:
        return "hidden"

    parts = proc.stdout.strip().split("\t")
    session_attached = parts[0].strip() if len(parts) > 0 else "0"
    window_active = parts[1].strip() if len(parts) > 1 else "0"
    pane_active = parts[2].strip() if len(parts) > 2 else "0"
    if session_attached not in {"", "0"} and window_active == "1" and pane_active == "1":
        return "foreground_attached"
    if session_attached not in {"", "0"}:
        return "background_attached"
    return "hidden"


def _tmux_show_desktop_visibility_banner(*, pane: str, message: str, tmux_socket: str | None = None) -> bool:
    target = pane.strip()
    text = message.strip()
    if not target or not text:
        return False

    try:
        proc = subprocess.run(
            _tmux_cmd(
                "display-message",
                "-d",
                "5000",
                "-t",
                target,
                text,
                tmux_socket=tmux_socket,
            ),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except Exception:
        return False

    return proc.returncode == 0


def _applescript_quote(*, text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _show_macos_desktop_notification(*, title: str, message: str, subtitle: str | None = None) -> bool:
    title_text = title.strip()
    message_text = message.strip()
    subtitle_text = subtitle.strip() if isinstance(subtitle, str) and subtitle.strip() else None
    if not title_text or not message_text:
        return False

    script = f"display notification {_applescript_quote(text=message_text)} with title {_applescript_quote(text=title_text)}"
    if subtitle_text:
        script += f" subtitle {_applescript_quote(text=subtitle_text)}"

    try:
        proc = subprocess.run(
            ["osascript", "-e", script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except Exception:
        return False

    return proc.returncode == 0


def _desktop_visibility_prompt_excerpt(*, prompt: str, max_chars: int = 160) -> str:
    collapsed = re.sub(r"\s+", " ", prompt or "").strip()
    if not collapsed:
        return "New Discord message routed to the session."
    if len(collapsed) <= max_chars:
        return collapsed
    return collapsed[: max_chars - 1].rstrip() + "…"


def _emit_desktop_visibility_for_discord_prompt(
    *,
    codex_home: Path,
    registry: dict[str, Any],
    session_id: str,
    session_rec: dict[str, Any] | None,
    prompt: str,
    agent: str | None = None,
) -> str:
    sid = session_id.strip() if isinstance(session_id, str) else ""
    normalized_agent = _normalize_agent(
        agent=agent if agent is not None else (session_rec.get("agent") if isinstance(session_rec, dict) else None)
    )
    if not sid or normalized_agent != "pi":
        return "none"

    tmux_pane = session_rec.get("tmux_pane") if isinstance(session_rec, dict) and isinstance(session_rec.get("tmux_pane"), str) else None
    tmux_socket = _normalize_tmux_socket(
        tmux_socket=session_rec.get("tmux_socket") if isinstance(session_rec, dict) and isinstance(session_rec.get("tmux_socket"), str) else None
    )
    if tmux_socket is None:
        tmux_socket = _choose_registry_tmux_socket(registry=registry)

    pane_norm = tmux_pane.strip() if isinstance(tmux_pane, str) and tmux_pane.strip() else ""
    socket_norm = tmux_socket.strip() if isinstance(tmux_socket, str) and tmux_socket.strip() else None
    pane_valid = False
    if pane_norm:
        pane_valid = _tmux_pane_exists(pane=pane_norm, tmux_socket=socket_norm)
        if pane_valid:
            pane_valid = _tmux_pane_matches_session(
                pane=pane_norm,
                session_rec=session_rec if isinstance(session_rec, dict) else {},
                session_id=sid,
                tmux_socket=socket_norm,
                agent=normalized_agent,
            )
    if not pane_valid:
        discovered_pane, discovered_socket = _tmux_discover_codex_pane_for_session(
            session_rec=session_rec if isinstance(session_rec, dict) else {},
            session_id=sid,
            tmux_socket=socket_norm,
            agent=normalized_agent,
        )
        if isinstance(discovered_pane, str) and discovered_pane.strip():
            pane_norm = discovered_pane.strip()
            pane_valid = True
            if isinstance(discovered_socket, str) and discovered_socket.strip():
                socket_norm = discovered_socket.strip()
            if isinstance(session_rec, dict):
                session_rec["tmux_pane"] = pane_norm
                if socket_norm:
                    session_rec["tmux_socket"] = socket_norm

    prompt_excerpt = _desktop_visibility_prompt_excerpt(prompt=prompt)
    session_ref = _session_ref(sid)
    banner_text = f"Discord → Pi @{session_ref}: {prompt_excerpt}"
    notification_title = f"Discord → Pi @{session_ref}"
    notification_subtitle = "agent-chat desktop visibility"

    state = "attention_badged"
    presence = _tmux_desktop_presence_for_pane(pane=pane_norm, tmux_socket=socket_norm) if pane_valid and pane_norm else "hidden"
    if presence == "foreground_attached" and pane_norm:
        if _tmux_show_desktop_visibility_banner(pane=pane_norm, message=banner_text, tmux_socket=socket_norm):
            state = "inline_visible"
        elif _show_macos_desktop_notification(
            title=notification_title,
            subtitle=notification_subtitle,
            message=prompt_excerpt,
        ):
            state = "notification_visible"
    elif _show_macos_desktop_notification(
        title=notification_title,
        subtitle=notification_subtitle,
        message=prompt_excerpt,
    ):
        state = "notification_visible"

    _persist_attention_state(
        codex_home=codex_home,
        registry=registry,
        session_id=sid,
        session_rec=session_rec,
        state=state,
        tmux_pane=pane_norm or None,
        tmux_socket=socket_norm,
        extra_fields={"agent": normalized_agent},
    )
    return state


def _normalize_path_for_match(path_value: str | None) -> str | None:
    if not isinstance(path_value, str):
        return None
    raw = path_value.strip()
    if not raw:
        return None
    try:
        return str(Path(raw).resolve())
    except Exception:
        return raw


def _tmux_read_pane_context(
    *,
    pane: str,
    tmux_socket: str | None = None,
) -> tuple[str | None, str | None]:
    target = pane.strip()
    if not target:
        return None, None

    try:
        proc = subprocess.run(
            _tmux_cmd(
                "display-message",
                "-p",
                "-t",
                target,
                "#{pane_current_command}\t#{pane_current_path}",
                tmux_socket=tmux_socket,
            ),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            text=True,
        )
    except Exception:
        return None, None

    if proc.returncode != 0:
        return None, None

    raw = proc.stdout.strip()
    if not raw:
        return None, None

    parts = raw.split("\t", 1)
    command = parts[0].strip() if parts else ""
    pane_path = parts[1].strip() if len(parts) > 1 else ""
    return (command or None), (pane_path or None)


def _tmux_codex_panes_for_cwd(*, cwd: str, tmux_socket: str | None = None, agent: str | None = None) -> list[str]:
    target_cwd = _normalize_path_for_match(cwd)
    if not target_cwd:
        return []

    try:
        proc = subprocess.run(
            _tmux_cmd(
                "list-panes",
                "-a",
                "-F",
                "#{pane_id}\t#{pane_current_command}\t#{pane_current_path}",
                tmux_socket=tmux_socket,
            ),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            text=True,
        )
    except Exception:
        return []

    if proc.returncode != 0:
        return []

    matches: list[str] = []
    for raw in proc.stdout.splitlines():
        parts = raw.split("\t")
        if len(parts) < 3:
            continue
        pane_id = parts[0].strip()
        current_cmd = parts[1].strip().lower()
        current_path = _normalize_path_for_match(parts[2].strip())
        if not pane_id:
            continue
        if not _is_agent_command(current_cmd, agent=agent):
            continue
        if current_path != target_cwd:
            continue
        matches.append(pane_id)
    return matches


def _tmux_pane_matches_session(
    *,
    pane: str,
    session_rec: dict[str, Any],
    session_id: str | None = None,
    tmux_socket: str | None = None,
    agent: str | None = None,
) -> bool:
    command, pane_path = _tmux_read_pane_context(pane=pane, tmux_socket=tmux_socket)
    normalized_agent = _normalize_agent(agent=agent if agent is not None else None)
    sid = session_id.strip() if isinstance(session_id, str) else ""
    pane_mentions_sid = False
    pane_status_sid_matches = False
    if sid:
        pane_mentions_sid = _tmux_pane_mentions_session_id(
            pane=pane,
            session_id=sid,
            tmux_socket=tmux_socket,
        )
        pane_status_sid = _tmux_status_line_session_id_from_pane(
            pane=pane,
            tmux_socket=tmux_socket,
        )
        pane_status_sid_matches = isinstance(pane_status_sid, str) and pane_status_sid.strip().lower() == sid.lower()

    if not (isinstance(command, str) and _is_agent_command(command, agent=normalized_agent)):
        if normalized_agent == "pi" and pane_status_sid_matches:
            return True
        if normalized_agent == "pi" and isinstance(command, str) and command.strip().lower() in {"node", "pi"} and _tmux_pane_looks_like_pi(pane=pane, tmux_socket=tmux_socket):
            return True
        return False

    if normalized_agent == "pi" and (pane_status_sid_matches or _tmux_pane_looks_like_pi(pane=pane, tmux_socket=tmux_socket)):
        return True

    rec_cwd = session_rec.get("cwd") if isinstance(session_rec.get("cwd"), str) else None
    target_cwd = _normalize_path_for_match(rec_cwd)
    if not target_cwd:
        if sid:
            return pane_mentions_sid
        return True

    pane_path_norm = _normalize_path_for_match(pane_path)
    if not pane_path_norm:
        return False
    if pane_path_norm != target_cwd:
        return False

    peers = _tmux_codex_panes_for_cwd(cwd=target_cwd, tmux_socket=tmux_socket, agent=agent)
    if len(peers) <= 1:
        return True

    pane_id = pane.strip()
    if pane_id not in peers:
        return False

    sid = session_id.strip() if isinstance(session_id, str) else ""
    if not sid:
        return False
    return _tmux_pane_mentions_session_id(
        pane=pane_id,
        session_id=sid,
        tmux_socket=tmux_socket,
    )


def _tmux_status_line_session_id_from_pane(
    *,
    pane: str,
    tmux_socket: str | None = None,
) -> str | None:
    target = pane.strip()
    if not target:
        return None

    try:
        proc = subprocess.run(
            _tmux_cmd(
                "capture-pane",
                "-p",
                "-t",
                target,
                "-S",
                "-200",
                tmux_socket=tmux_socket,
            ),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            text=True,
        )
    except Exception:
        return None

    if proc.returncode != 0:
        return None

    haystack = proc.stdout or ""
    if not haystack:
        return None

    latest_status_sid: str | None = None
    for line in haystack.splitlines():
        status_match = _SESSION_STATUS_LINE_UUID_RE.search(line)
        if status_match:
            latest_status_sid = status_match.group(1)
    return latest_status_sid


def _tmux_pane_mentions_session_id(
    *,
    pane: str,
    session_id: str,
    tmux_socket: str | None = None,
) -> bool:
    target = pane.strip()
    sid = session_id.strip()
    if not target or not sid:
        return False

    latest_sid = _tmux_latest_session_id_from_pane(pane=target, tmux_socket=tmux_socket)
    if isinstance(latest_sid, str) and latest_sid.strip():
        return latest_sid.strip().lower() == sid.lower()

    try:
        proc = subprocess.run(
            _tmux_cmd(
                "capture-pane",
                "-p",
                "-t",
                target,
                "-S",
                "-200",
                tmux_socket=tmux_socket,
            ),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            text=True,
        )
    except Exception:
        return None

    if proc.returncode != 0:
        return False
    haystack = proc.stdout or ""
    if not haystack:
        return False
    return sid in haystack


def _tmux_pane_looks_like_pi(
    *,
    pane: str,
    tmux_socket: str | None = None,
) -> bool:
    target = pane.strip()
    if not target:
        return False
    try:
        proc = subprocess.run(
            _tmux_cmd(
                "capture-pane",
                "-p",
                "-t",
                target,
                "-S",
                "-80",
                tmux_socket=tmux_socket,
            ),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            text=True,
        )
    except Exception:
        return False
    if proc.returncode != 0:
        return False
    haystack = (proc.stdout or "").lower()
    if not haystack:
        return False
    return (
        "pi v" in haystack
        or "pi can explain its own features" in haystack
        or "[skills]" in haystack and "[extensions]" in haystack
    )


def _tmux_latest_session_id_from_pane(
    *,
    pane: str,
    tmux_socket: str | None = None,
) -> str | None:
    target = pane.strip()
    if not target:
        return None

    try:
        proc = subprocess.run(
            _tmux_cmd(
                "capture-pane",
                "-p",
                "-t",
                target,
                "-S",
                "-200",
                tmux_socket=tmux_socket,
            ),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            text=True,
        )
    except Exception:
        return False

    if proc.returncode != 0:
        return None

    haystack = proc.stdout or ""
    if not haystack:
        return None

    latest_status_sid: str | None = None
    latest_generic_sid: str | None = None
    for line in haystack.splitlines():
        status_match = _SESSION_STATUS_LINE_UUID_RE.search(line)
        if status_match:
            latest_status_sid = status_match.group(1)
        for generic_match in _SESSION_UUID_RE.finditer(line):
            latest_generic_sid = generic_match.group(0)

    if latest_status_sid:
        return latest_status_sid
    if latest_generic_sid:
        return latest_generic_sid
    return None


def _tmux_filter_panes_by_session_id(
    *,
    pane_ids: list[str],
    session_id: str | None,
    tmux_socket: str | None = None,
) -> list[str]:
    sid = session_id.strip() if isinstance(session_id, str) else ""
    if not sid:
        return []

    matched: list[str] = []
    for pane_id in pane_ids:
        if not isinstance(pane_id, str) or not pane_id.strip():
            continue
        if _tmux_pane_mentions_session_id(
            pane=pane_id.strip(),
            session_id=sid,
            tmux_socket=tmux_socket,
        ):
            matched.append(pane_id.strip())
    return matched


def _tmux_discover_codex_pane_for_session(
    *,
    session_rec: dict[str, Any],
    session_id: str | None = None,
    tmux_socket: str | None = None,
    agent: str | None = None,
) -> tuple[str | None, str | None]:
    try:
        proc = subprocess.run(
            _tmux_cmd(
                "list-panes",
                "-a",
                "-F",
                "#{pane_id}\t#{pane_current_command}\t#{pane_current_path}",
                tmux_socket=tmux_socket,
            ),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            text=True,
        )
    except Exception:
        return None, None

    if proc.returncode != 0:
        return None, None

    normalized_agent = _normalize_agent(agent=agent if agent is not None else None)
    all_panes: list[tuple[str, str, str]] = []
    candidates: list[tuple[str, str]] = []
    for raw in proc.stdout.splitlines():
        parts = raw.split("\t")
        if len(parts) < 3:
            continue
        pane_id = parts[0].strip()
        current_cmd = parts[1].strip().lower()
        current_path = parts[2].strip()
        if not pane_id:
            continue
        all_panes.append((pane_id, current_cmd, current_path))
        if not _is_agent_command(current_cmd, agent=agent):
            continue
        candidates.append((pane_id, current_path))

    sid = session_id.strip() if isinstance(session_id, str) else ""
    if normalized_agent == "pi":
        if sid:
            sid_matches = [
                pane_id
                for pane_id, _, _ in all_panes
                if (
                    (_tmux_status_line_session_id_from_pane(pane=pane_id, tmux_socket=tmux_socket) or "").strip().lower()
                    == sid.lower()
                )
            ]
            if len(sid_matches) == 1:
                return sid_matches[0], _normalize_tmux_socket(tmux_socket=tmux_socket)
        pi_panes = [
            pane_id
            for pane_id, current_cmd, _ in all_panes
            if current_cmd in {"node", "pi"} and _tmux_pane_looks_like_pi(pane=pane_id, tmux_socket=tmux_socket)
        ]
        if len(pi_panes) == 1:
            return pi_panes[0], _normalize_tmux_socket(tmux_socket=tmux_socket)

    if not candidates:
        return None, None

    rec_cwd = session_rec.get("cwd") if isinstance(session_rec.get("cwd"), str) else None
    target_cwd = _normalize_path_for_match(rec_cwd)
    if target_cwd:
        cwd_matches = [
            pane_id
            for pane_id, pane_path in candidates
            if _normalize_path_for_match(pane_path) == target_cwd
        ]
        if len(cwd_matches) == 1:
            return cwd_matches[0], _normalize_tmux_socket(tmux_socket=tmux_socket)
        if len(cwd_matches) > 1:
            sid_matches = _tmux_filter_panes_by_session_id(
                pane_ids=cwd_matches,
                session_id=session_id,
                tmux_socket=tmux_socket,
            )
            if len(sid_matches) == 1:
                return sid_matches[0], _normalize_tmux_socket(tmux_socket=tmux_socket)
            return None, None

    if len(candidates) == 1:
        return candidates[0][0], _normalize_tmux_socket(tmux_socket=tmux_socket)

    sid_matches = _tmux_filter_panes_by_session_id(
        pane_ids=[pane_id for pane_id, _ in candidates],
        session_id=session_id,
        tmux_socket=tmux_socket,
    )
    if len(sid_matches) == 1:
        return sid_matches[0], _normalize_tmux_socket(tmux_socket=tmux_socket)
    return None, None


def _tmux_routing_enabled() -> bool:
    raw = os.environ.get("AGENT_CHAT_ROUTE_VIA_TMUX", "1").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def _dispatch_resume_to_session(
    *,
    target_sid: str,
    prompt: str,
    session_rec: dict[str, Any] | None,
    codex_home: Path,
    resume_timeout_s: float | None = None,
    agent: str | None = None,
) -> tuple[str, str | None]:
    rec_agent: str | None = None
    if isinstance(session_rec, dict):
        raw_agent = session_rec.get("agent")
        if isinstance(raw_agent, str) and raw_agent.strip():
            rec_agent = raw_agent
    effective_agent = _normalize_agent(agent=agent if agent is not None else rec_agent)
    cwd = session_rec.get("cwd") if isinstance(session_rec, dict) and isinstance(session_rec.get("cwd"), str) else None
    session_path = session_rec.get("session_path") if isinstance(session_rec, dict) and isinstance(session_rec.get("session_path"), str) else None
    session_path_obj = Path(session_path.strip()) if isinstance(session_path, str) and session_path.strip() else None

    before_user_text: str | None = None
    before_assistant_text: str | None = None
    if effective_agent == "pi" and isinstance(session_path_obj, Path):
        before_user_text = reply._read_last_user_text_from_session(session_path_obj)
        before_assistant_text = reply._read_last_assistant_text_from_session(session_path_obj)

    resume_home = codex_home if effective_agent == _current_agent() else _lookup_agent_home_path(
        agent=effective_agent,
        current_home=codex_home,
    )
    response = reply._run_agent_resume(
        agent=effective_agent,
        session_id=target_sid,
        cwd=cwd,
        prompt=prompt,
        codex_home=resume_home,
        timeout_s=resume_timeout_s,
    )
    if response:
        return "resume", response

    if effective_agent != "pi" or not isinstance(session_path_obj, Path):
        return "resume", response

    ack_timeout = float(_tmux_ack_timeout_s())
    observed_user = reply._wait_for_new_user_text(
        session_path=session_path_obj,
        before=before_user_text,
        timeout_s=ack_timeout,
    )

    assistant_wait_s = 1.0
    if resume_timeout_s is not None:
        try:
            assistant_wait_s = max(0.0, min(float(resume_timeout_s), 1.0))
        except Exception:
            assistant_wait_s = 1.0
    observed_assistant = reply._wait_for_new_assistant_text(
        session_path=session_path_obj,
        before=before_assistant_text,
        timeout_s=assistant_wait_s,
    )
    if observed_assistant:
        return "resume", observed_assistant
    if observed_user is not None:
        return "resume_unconfirmed", None
    return "resume", response


def _dispatch_prompt_to_session(
    *,
    target_sid: str,
    prompt: str,
    session_rec: dict[str, Any] | None,
    codex_home: Path,
    resume_timeout_s: float | None = None,
    agent: str | None = None,
) -> tuple[str, str | None]:
    rec_agent: str | None = None
    if isinstance(session_rec, dict):
        raw_agent = session_rec.get("agent")
        if isinstance(raw_agent, str) and raw_agent.strip():
            rec_agent = raw_agent
    effective_agent = _normalize_agent(agent=agent if agent is not None else rec_agent)
    if isinstance(session_rec, dict):
        session_rec["agent"] = effective_agent

    cwd = session_rec.get("cwd") if isinstance(session_rec, dict) and isinstance(session_rec.get("cwd"), str) else None
    strict_tmux = _strict_tmux_enabled()
    tmux_enabled = _tmux_routing_enabled()
    tmux_identity_present = False
    if isinstance(session_rec, dict):
        pane_hint = session_rec.get("tmux_pane")
        socket_hint = session_rec.get("tmux_socket")
        tmux_identity_present = (
            (isinstance(pane_hint, str) and bool(pane_hint.strip()))
            or (isinstance(socket_hint, str) and bool(socket_hint.strip()))
        )

    if isinstance(session_rec, dict):
        session_rec["last_dispatch_reason"] = None

    if tmux_enabled and isinstance(session_rec, dict):
        pane = session_rec.get("tmux_pane")
        tmux_socket = session_rec.get("tmux_socket")
        tmux_socket_norm = _normalize_tmux_socket(tmux_socket=tmux_socket if isinstance(tmux_socket, str) else None)
        session_path = session_rec.get("session_path")
        pane_norm = pane.strip() if isinstance(pane, str) else ""
        if not pane_norm:
            discovered_pane, discovered_socket = _tmux_discover_codex_pane_for_session(
                session_rec=session_rec,
                session_id=target_sid,
                tmux_socket=tmux_socket_norm,
                agent=effective_agent,
            )
            if isinstance(discovered_pane, str) and discovered_pane.strip():
                pane_norm = discovered_pane.strip()
                session_rec["tmux_pane"] = pane_norm
                if isinstance(discovered_socket, str) and discovered_socket.strip():
                    tmux_socket_norm = discovered_socket.strip()
                    session_rec["tmux_socket"] = tmux_socket_norm
            elif strict_tmux and tmux_identity_present:
                session_rec["last_dispatch_reason"] = "pane_missing"
                return "tmux_stale", None

        if pane_norm and not (isinstance(session_path, str) and session_path.strip()):
            pane_is_valid = _tmux_pane_exists(pane=pane_norm, tmux_socket=tmux_socket_norm)
            if pane_is_valid:
                pane_is_valid = _tmux_pane_matches_session(
                    pane=pane_norm,
                    session_rec=session_rec,
                    session_id=target_sid,
                    tmux_socket=tmux_socket_norm,
                    agent=effective_agent,
                )
            if not pane_is_valid:
                discovered_pane, discovered_socket = _tmux_discover_codex_pane_for_session(
                    session_rec=session_rec,
                    session_id=target_sid,
                    tmux_socket=tmux_socket_norm,
                    agent=effective_agent,
                )
                if isinstance(discovered_pane, str) and discovered_pane.strip():
                    pane_norm = discovered_pane.strip()
                    session_rec["tmux_pane"] = pane_norm
                    if isinstance(discovered_socket, str) and discovered_socket.strip():
                        tmux_socket_norm = discovered_socket.strip()
                        session_rec["tmux_socket"] = tmux_socket_norm
                    refreshed_valid = _tmux_pane_exists(pane=pane_norm, tmux_socket=tmux_socket_norm)
                    if refreshed_valid:
                        refreshed_valid = _tmux_pane_matches_session(
                            pane=pane_norm,
                            session_rec=session_rec,
                            session_id=target_sid,
                            tmux_socket=tmux_socket_norm,
                            agent=effective_agent,
                        )
                    if not refreshed_valid:
                        session_rec["last_dispatch_reason"] = "pane_stale"
                        return "tmux_stale", None
                else:
                    session_rec["last_dispatch_reason"] = "pane_stale"
                    return "tmux_stale", None

            send_kwargs: dict[str, Any] = {"pane": pane_norm, "prompt": prompt}
            if tmux_socket_norm:
                send_kwargs["tmux_socket"] = tmux_socket_norm
            if not reply._tmux_send_prompt(**send_kwargs):
                session_rec["last_dispatch_reason"] = "send_failed"
                return "tmux_failed", None
            session_rec["last_dispatch_reason"] = None
            return "tmux", None

        if pane_norm and isinstance(session_path, str) and session_path.strip():
            session_path_norm = session_path.strip()
            if reply._session_path_matches_session_id(session_path=session_path_norm, session_id=target_sid):
                pane_is_valid = _tmux_pane_exists(pane=pane_norm, tmux_socket=tmux_socket_norm)
                if pane_is_valid:
                    pane_is_valid = _tmux_pane_matches_session(
                        pane=pane_norm,
                        session_rec=session_rec,
                        session_id=target_sid,
                        tmux_socket=tmux_socket_norm,
                        agent=effective_agent,
                    )
                if not pane_is_valid:
                    discovered_pane, discovered_socket = _tmux_discover_codex_pane_for_session(
                        session_rec=session_rec,
                        session_id=target_sid,
                        tmux_socket=tmux_socket_norm,
                        agent=effective_agent,
                    )
                    if isinstance(discovered_pane, str) and discovered_pane.strip():
                        pane_norm = discovered_pane.strip()
                        session_rec["tmux_pane"] = pane_norm
                        if isinstance(discovered_socket, str) and discovered_socket.strip():
                            tmux_socket_norm = discovered_socket.strip()
                            session_rec["tmux_socket"] = tmux_socket_norm
                        refreshed_valid = _tmux_pane_exists(pane=pane_norm, tmux_socket=tmux_socket_norm)
                        if refreshed_valid:
                            refreshed_valid = _tmux_pane_matches_session(
                                pane=pane_norm,
                                session_rec=session_rec,
                                session_id=target_sid,
                                tmux_socket=tmux_socket_norm,
                            )
                        if not refreshed_valid:
                            session_rec["last_dispatch_reason"] = "pane_stale"
                            return "tmux_stale", None
                    else:
                        session_rec["last_dispatch_reason"] = "pane_stale"
                        return "tmux_stale", None
                session_path_obj = Path(session_path_norm)
                before_user_text = reply._read_last_user_text_from_session(session_path_obj)
                send_kwargs: dict[str, Any] = {"pane": pane_norm, "prompt": prompt}
                if tmux_socket_norm:
                    send_kwargs["tmux_socket"] = tmux_socket_norm
                if not reply._tmux_send_prompt(**send_kwargs):
                    session_rec["last_dispatch_reason"] = "send_failed"
                    return "tmux_failed", None

                ack_timeout = _tmux_ack_timeout_s()
                observed = reply._wait_for_new_user_text(
                    session_path=session_path_obj,
                    before=before_user_text,
                    timeout_s=float(ack_timeout),
                )
                if observed is not None:
                    session_rec["last_dispatch_reason"] = None
                    return "tmux", None

                # Some terminal/keymap combinations accept only specific submit keys.
                # "Return" can be rendered literally in some tmux setups; avoid it.
                for submit_key in ("C-m", "Enter"):
                    try:
                        submit = subprocess.run(
                            _tmux_cmd("send-keys", "-t", pane_norm, submit_key, tmux_socket=tmux_socket_norm),
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            check=False,
                        )
                    except Exception:
                        continue
                    if submit.returncode != 0:
                        continue

                    observed = reply._wait_for_new_user_text(
                        session_path=session_path_obj,
                        before=before_user_text,
                        timeout_s=0.75,
                    )
                    if observed is not None:
                        session_rec["last_dispatch_reason"] = None
                        return "tmux", None
                session_rec["last_dispatch_reason"] = "ack_timeout"
                return "tmux_unconfirmed", None
            if strict_tmux and tmux_identity_present:
                session_rec["last_dispatch_reason"] = "session_path_mismatch"
                return "tmux_stale", None

        if strict_tmux and tmux_identity_present:
            session_rec["last_dispatch_reason"] = "session_path_missing" if not (
                isinstance(session_path, str) and session_path.strip()
            ) else "pane_missing"
            return "tmux_stale", None

    if strict_tmux and tmux_enabled and tmux_identity_present:
        return "tmux_stale", None

    return _dispatch_resume_to_session(
        target_sid=target_sid,
        prompt=prompt,
        session_rec=session_rec,
        codex_home=codex_home,
        resume_timeout_s=resume_timeout_s,
        agent=effective_agent,
    )


def _resolve_session_from_reply_context(
    *,
    conn: sqlite3.Connection,
    reply_text: str,
    reply_to_guid: str | None,
    reply_reference_guids: list[str] | None = None,
    reply_reference_texts: list[str] | None = None,
    registry: dict[str, Any],
    message_index: dict[str, Any],
    require_explicit_ref: bool = False,
) -> tuple[str | None, str | None]:
    direct = reply._extract_session_id(reply_text)
    if direct:
        return direct, None

    guid_candidates: list[str] = []
    if isinstance(reply_reference_guids, list):
        for value in reply_reference_guids:
            if isinstance(value, str) and value.strip():
                normalized = value.strip()
                if normalized not in guid_candidates:
                    guid_candidates.append(normalized)
    if isinstance(reply_to_guid, str) and reply_to_guid.strip():
        normalized_reply_to = reply_to_guid.strip()
        if normalized_reply_to not in guid_candidates:
            guid_candidates.append(normalized_reply_to)

    resolved_sids: list[str] = []

    def _resolve_from_replied_text(*, replied_text: str) -> None:
        sid = reply._extract_session_id(replied_text)
        if sid:
            if sid not in resolved_sids:
                resolved_sids.append(sid)
            return

        refs = _session_refs_from_text(replied_text)
        by_ref: str | None = None
        if refs:
            by_ref = _lookup_session_by_text_ref(registry=registry, replied_text=replied_text)
            # If explicit refs are present but unresolved, do not fall back to hash;
            # hash matches can collide across repeated message text.
            if by_ref and by_ref not in resolved_sids:
                resolved_sids.append(by_ref)
            return

        by_ref = _lookup_session_by_text_ref(registry=registry, replied_text=replied_text)
        if by_ref and by_ref not in resolved_sids:
            resolved_sids.append(by_ref)
            return

        by_hash = _lookup_session_by_message_hash(index=message_index, replied_text=replied_text)
        if by_hash and by_hash not in resolved_sids:
            sessions = registry.get("sessions")
            rec = sessions.get(by_hash) if isinstance(sessions, dict) else None
            if _session_is_waiting_for_input(session_rec=rec if isinstance(rec, dict) else None):
                resolved_sids.append(by_hash)

    if isinstance(reply_reference_texts, list):
        for value in reply_reference_texts:
            if isinstance(value, str) and value.strip():
                _resolve_from_replied_text(replied_text=value.strip())

    for guid in guid_candidates:
        replied_text = reply._get_message_text_by_guid(conn=conn, guid=guid)
        if not replied_text:
            continue
        _resolve_from_replied_text(replied_text=replied_text)

    if resolved_sids:
        return resolved_sids[0], None

    sid, err = _choose_implicit_session(registry=registry)
    if sid:
        return sid, None
    if require_explicit_ref:
        if err:
            return None, f"{err} Strict tmux routing requires explicit @<ref> when context is ambiguous."
        return None, "Strict tmux routing requires explicit @<ref> when context is ambiguous."
    return None, err


def _reply_reference_guids_for_row(
    *,
    conn: sqlite3.Connection,
    rowid: int,
    fallback_guid: str | None,
) -> list[str]:
    candidates: list[str] = []

    def _add(value: object) -> None:
        if isinstance(value, str):
            v = value.strip()
            if v and v not in candidates:
                candidates.append(v)

    _add(fallback_guid)
    try:
        row = conn.execute(
            "SELECT thread_originator_guid, reply_to_guid, associated_message_guid FROM message WHERE ROWID = ?",
            [rowid],
        ).fetchone()
    except Exception:
        row = None

    if isinstance(row, (tuple, list)):
        # Prefer direct reply linkage. thread_originator_guid can point to
        # older messages in the conversation and cause wrong session routing.
        reply_to = row[1] if len(row) > 1 else None
        associated = row[2] if len(row) > 2 else None
        _add(reply_to)
        _add(associated)

    return candidates


def _recover_session_record_from_disk(
    *,
    codex_home: Path,
    session_id: str,
    registry: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    def _candidate_agent_homes(*, current_home: Path) -> list[tuple[str, Path]]:
        out: list[tuple[str, Path]] = []
        seen: set[tuple[str, str]] = set()

        def _add(agent_name: str, home: Path) -> None:
            key = (agent_name, str(home))
            if key in seen:
                return
            seen.add(key)
            out.append((agent_name, home))

        _add(_current_agent(), current_home)
        for agent_name in sorted(_SUPPORTED_AGENTS):
            _add(agent_name, _lookup_agent_home_path(agent=agent_name, current_home=current_home))
        return out

    sid = session_id.strip()
    if not sid:
        return None

    newest: Path | None = None
    newest_mtime = -1.0
    newest_agent: str | None = None
    for agent_name, home in _candidate_agent_homes(current_home=codex_home):
        for path in _find_all_session_files(codex_home=home, agent=agent_name):
            path_str = str(path)
            if sid not in path_str:
                continue
            try:
                mtime = path.stat().st_mtime
            except Exception:
                continue
            if mtime > newest_mtime:
                newest = path
                newest_mtime = mtime
                newest_agent = agent_name

    if newest is None:
        return None

    fields: dict[str, Any] = {
        "session_path": str(newest),
        "agent": _normalize_agent(agent=newest_agent if newest_agent is not None else _current_agent()),
    }
    cwd = outbound._read_session_cwd(session_path=newest)
    if isinstance(cwd, str) and cwd.strip():
        fields["cwd"] = cwd.strip()

    preferred_socket = _normalize_tmux_socket(tmux_socket=os.environ.get("AGENT_CHAT_TMUX_SOCKET"))
    if preferred_socket is None and isinstance(registry, dict):
        preferred_socket = _choose_registry_tmux_socket(registry=registry)
    if isinstance(preferred_socket, str) and preferred_socket.strip():
        fields["tmux_socket"] = preferred_socket.strip()

    return fields


def _recover_session_record_from_tmux(
    *,
    codex_home: Path,
    session_id: str,
    registry: dict[str, Any] | None = None,
    agent: str | None = None,
) -> dict[str, Any] | None:
    sid = session_id.strip()
    if not sid:
        return None

    preferred_socket = _normalize_tmux_socket(tmux_socket=os.environ.get("AGENT_CHAT_TMUX_SOCKET"))
    if preferred_socket is None and isinstance(registry, dict):
        preferred_socket = _choose_registry_tmux_socket(registry=registry)

    candidates: list[str] = []
    for raw in (agent, _current_agent(), "codex", "claude"):
        normalized = _normalize_agent(agent=raw)
        if normalized not in candidates:
            candidates.append(normalized)

    for candidate_agent in candidates:
        probe_rec: dict[str, Any] = {"agent": candidate_agent}
        pane, discovered_socket = _tmux_discover_codex_pane_for_session(
            session_rec=probe_rec,
            session_id=sid,
            tmux_socket=preferred_socket,
            agent=candidate_agent,
        )
        if not isinstance(pane, str) or not pane.strip():
            continue

        pane_norm = pane.strip()
        socket_norm = _normalize_tmux_socket(
            tmux_socket=discovered_socket if isinstance(discovered_socket, str) else preferred_socket
        )
        fields: dict[str, Any] = {
            "agent": candidate_agent,
            "tmux_pane": pane_norm,
        }
        if isinstance(socket_norm, str) and socket_norm.strip():
            fields["tmux_socket"] = socket_norm.strip()

        _command, pane_path = _tmux_read_pane_context(pane=pane_norm, tmux_socket=socket_norm)
        if isinstance(pane_path, str) and pane_path.strip():
            fields["cwd"] = pane_path.strip()
        return fields

    return None


def _session_agent_from_record(*, session_rec: dict[str, Any] | None) -> str | None:
    if not isinstance(session_rec, dict):
        return None
    raw = session_rec.get("agent")
    if not isinstance(raw, str) or not raw.strip():
        return None
    return _normalize_agent(agent=raw)


def _session_registry_path_for_home(*, home: Path) -> Path:
    return home / "tmp" / "agent_chat_session_registry.json"


def _message_index_path_for_home(*, home: Path) -> Path:
    return home / "tmp" / "agent_chat_message_session_index.json"


def _lookup_agent_by_session_id_across_homes(
    *,
    session_id: str,
    codex_home: Path,
    current_registry: dict[str, Any] | None,
    current_message_index: dict[str, Any],
) -> str | None:
    sid = session_id.strip()
    if not sid:
        return None

    current_home = str(codex_home)
    homes: list[tuple[str, Path]] = []
    seen: set[tuple[str, str]] = set()

    def _add(agent_name: str, home: Path) -> None:
        key = (agent_name, str(home))
        if key in seen:
            return
        seen.add(key)
        homes.append((agent_name, home))

    _add(_current_agent(), codex_home)
    for agent_name in sorted(_SUPPORTED_AGENTS):
        _add(agent_name, _lookup_agent_home_path(agent=agent_name, current_home=codex_home))

    ordered_homes = [entry for entry in homes if str(entry[1]) != current_home]
    ordered_homes.extend(entry for entry in homes if str(entry[1]) == current_home)

    # Registry entries are authoritative when present.
    for agent_name, home in ordered_homes:
        if str(home) == current_home and isinstance(current_registry, dict):
            registry_data = current_registry
        else:
            registry_data = _read_json(_session_registry_path_for_home(home=home))

        sessions = registry_data.get("sessions") if isinstance(registry_data, dict) else None
        rec = sessions.get(sid) if isinstance(sessions, dict) else None
        if not isinstance(rec, dict):
            continue

        from_record = _session_agent_from_record(session_rec=rec)
        if isinstance(from_record, str):
            return from_record

        # If the record only exists in another home, infer the owning agent from that home.
        if str(home) != current_home:
            return _normalize_agent(agent=agent_name)

    # Fall back to message indexes (prefer other homes first).
    for _, home in ordered_homes:
        if str(home) == current_home:
            index_data: dict[str, Any] | None = current_message_index
        else:
            loaded = _read_json(_message_index_path_for_home(home=home))
            index_data = loaded if isinstance(loaded, dict) else None

        if not isinstance(index_data, dict):
            continue

        from_index = _lookup_agent_by_session_id(index=index_data, session_id=sid)
        if isinstance(from_index, str):
            return from_index

    return None


def _agent_from_reply_reference_guids(
    *,
    conn: sqlite3.Connection,
    reply_reference_guids: list[str] | None,
) -> str | None:
    if not isinstance(reply_reference_guids, list):
        return None
    for guid in reply_reference_guids:
        if not isinstance(guid, str) or not guid.strip():
            continue
        text = reply._get_message_text_by_guid(conn=conn, guid=guid.strip())
        candidate = _agent_from_message_header(text=text)
        if isinstance(candidate, str):
            return candidate
    return None


def _resolve_session_agent(
    *,
    conn: sqlite3.Connection,
    codex_home: Path,
    registry: dict[str, Any],
    session_id: str | None,
    session_rec: dict[str, Any] | None,
    reply_reference_guids: list[str] | None,
    message_index: dict[str, Any],
) -> str:
    from_record = _session_agent_from_record(session_rec=session_rec)
    if isinstance(from_record, str):
        return from_record

    from_reply = _agent_from_reply_reference_guids(conn=conn, reply_reference_guids=reply_reference_guids)
    if isinstance(from_reply, str):
        return from_reply

    if isinstance(session_id, str) and session_id.strip():
        from_homes = _lookup_agent_by_session_id_across_homes(
            session_id=session_id,
            codex_home=codex_home,
            current_registry=registry,
            current_message_index=message_index,
        )
        if isinstance(from_homes, str):
            return from_homes

    return _current_agent()


def _find_new_session_since(*, codex_home: Path, before: set[str], agent: str | None = None) -> Path | None:
    newest: Path | None = None
    newest_mtime = -1.0
    for path in _find_all_session_files(codex_home=codex_home, agent=agent):
        p = str(path)
        if p in before:
            continue
        try:
            mtime = path.stat().st_mtime
        except Exception:
            continue
        if mtime > newest_mtime:
            newest = path
            newest_mtime = mtime
    return newest


def _wait_for_new_session_file(
    *,
    codex_home: Path,
    before: set[str],
    timeout_s: float,
    agent: str | None = None,
) -> Path | None:
    deadline = time.monotonic() + max(0.0, float(timeout_s))
    while time.monotonic() < deadline:
        created = _find_new_session_since(codex_home=codex_home, before=before, agent=agent)
        if created:
            return created
        time.sleep(0.25)
    return None


def _create_new_session_in_tmux(
    *,
    codex_home: Path,
    prompt: str,
    cwd: str | None,
    label: str | None = None,
    agent: str | None = None,
    tmux_socket: str | None = None,
) -> tuple[str | None, str | None, str | None, str | None]:
    normalized_agent = _normalize_agent(agent=agent if agent is not None else _current_agent())
    current_agent = _current_agent()
    if normalized_agent == current_agent:
        agent_home = codex_home
    else:
        agent_home = _lookup_agent_home_path(agent=normalized_agent, current_home=codex_home)
    agent_name = _agent_display_name(agent=normalized_agent)
    text = " ".join(prompt.splitlines()).strip()
    if not text:
        return None, None, None, "No instruction text was provided."

    before = {
        str(path)
        for path in _find_all_session_files(
            codex_home=agent_home,
            agent=normalized_agent,
        )
    }

    tmux_socket_norm = _normalize_tmux_socket(tmux_socket=tmux_socket)
    ensure_kwargs: dict[str, Any] = {"cwd": cwd}
    if tmux_socket_norm:
        ensure_kwargs["tmux_socket"] = tmux_socket_norm
    tmux_session, tmux_err = _tmux_ensure_active_session(**ensure_kwargs)
    if not tmux_session:
        return None, None, None, tmux_err or "Could not resolve tmux session."

    window_kwargs: dict[str, Any] = {
        "session_name": tmux_session,
        "cwd": cwd,
        "label": label,
        "agent": normalized_agent,
    }
    if tmux_socket_norm:
        window_kwargs["tmux_socket"] = tmux_socket_norm
    pane, window_name, window_err = _tmux_start_codex_window(**window_kwargs)
    if not pane:
        return None, None, None, window_err or "Could not create tmux window."

    # Best-effort warmup only. Do not fail solely on command-name mismatch because
    # packaged/wrapped Codex binaries may appear as different pane commands.
    wait_kwargs: dict[str, Any] = {
        "pane": pane,
        "expected": _agent_command_keyword(agent=normalized_agent),
        "timeout_s": 8.0,
    }
    if tmux_socket_norm:
        wait_kwargs["tmux_socket"] = tmux_socket_norm
    _tmux_wait_for_pane_command(**wait_kwargs)

    send_kwargs: dict[str, Any] = {"pane": pane, "prompt": text}
    if tmux_socket_norm:
        send_kwargs["tmux_socket"] = tmux_socket_norm
    if not reply._tmux_send_prompt(**send_kwargs):
        return None, None, pane, f"Started {agent_name} in tmux but failed to submit initial prompt."

    created = _wait_for_new_session_file(
        codex_home=agent_home,
        before=before,
        timeout_s=12.0,
        agent=normalized_agent,
    )
    if not created:
        newest = _find_all_session_files(codex_home=agent_home, agent=normalized_agent)
        if newest:
            newest.sort(key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)
            created = newest[0]

    if not created:
        return None, None, pane, f"Started {agent_name} in tmux but could not locate session file."

    session_id = outbound._read_session_id(session_path=created)
    if not isinstance(session_id, str) or not session_id.strip():
        return None, str(created), pane, "Session file was found but session ID was not available."

    return session_id.strip(), str(created), pane, None


def _create_new_session(
    *,
    codex_home: Path,
    label: str,
    prompt: str,
    agent: str | None = None,
    cwd: str | None = None,
) -> tuple[str | None, str | None, str | None]:
    del label
    normalized_agent = _normalize_agent(agent=agent if agent is not None else _current_agent())
    current_agent = _current_agent()
    if normalized_agent == current_agent:
        agent_home = codex_home
    else:
        agent_home = _lookup_agent_home_path(agent=normalized_agent, current_home=codex_home)
    before = {
        str(path)
        for path in _find_all_session_files(
            codex_home=agent_home,
            agent=normalized_agent,
        )
    }

    out_dir = agent_home / "tmp"
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    out_path = out_dir / f"agent_chat_new_session_{int(time.time())}_{os.getpid()}.txt"

    if normalized_agent == "claude":
        cmd = [_resolve_agent_bin(agent=normalized_agent), "-p", prompt]
    elif normalized_agent == "pi":
        cmd = [_resolve_agent_bin(agent=normalized_agent), "-p", prompt]
    else:
        cmd = [
            _resolve_agent_bin(agent=normalized_agent),
            "-a",
            "never",
            "-s",
            "danger-full-access",
        ]
        if isinstance(cwd, str) and cwd.strip():
            cmd.extend(["-C", cwd.strip()])
        cmd.extend(
            [
                "exec",
                "--skip-git-repo-check",
                "--output-last-message",
                str(out_path),
                prompt,
            ]
        )

    try:
        env = {**os.environ, "AGENT_CHAT_REPLY": "1", "CLAUDE_CHAT_REPLY": "1"}
        if normalized_agent == "pi":
            env.setdefault("PI_CODING_AGENT_DIR", str(agent_home))
            env.setdefault("AGENT_CHAT_PI_HOME", str(agent_home))
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            text=True,
            env=env,
            cwd=cwd.strip() if isinstance(cwd, str) and cwd.strip() else None,
        )
    except Exception:
        return None, None, "Failed to start new session."

    if proc.returncode != 0:
        return None, None, "New session command failed."

    created = _find_new_session_since(
        codex_home=agent_home,
        before=before,
        agent=normalized_agent,
    )
    if not created:
        # Best-effort fallback: newest file.
        newest = _find_all_session_files(codex_home=agent_home, agent=normalized_agent)
        if newest:
            newest.sort(key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)
            created = newest[0]

    if not created:
        return None, None, "Session created but could not locate session file."

    session_id = outbound._read_session_id(session_path=created)
    if not session_id:
        return None, None, "Session created but session ID was not found."

    response: str | None = None
    if normalized_agent in {"claude", "pi"}:
        response = proc.stdout.strip() if isinstance(proc.stdout, str) and proc.stdout.strip() else None
    else:
        try:
            response = out_path.read_text(encoding="utf-8").strip() or None
        except Exception:
            response = None

    return session_id, str(created), response


def _handle_notify_payload(
    *,
    codex_home: Path,
    recipient: str,
    payload_text: str,
    dry_run: bool,
) -> None:
    try:
        payload = json.loads(payload_text)
    except Exception:
        return

    if not isinstance(payload, dict):
        return

    session_id, params = _extract_session_id_from_notify_payload(payload)
    if not session_id:
        return

    registry = _load_registry(codex_home=codex_home)
    notify_fields = _extract_notify_context_fields(payload=payload, params=params)
    if notify_fields:
        _upsert_session(registry=registry, session_id=session_id, fields=notify_fields)
    sessions = registry.get("sessions")
    rec = sessions.get(session_id) if isinstance(sessions, dict) else None

    is_input_event = notify._is_input_event(payload)
    is_completion_event = notify._is_completion_event(payload)

    if is_input_event:
        session_path: str | None = None
        notify_session_path = notify_fields.get("session_path")
        if isinstance(notify_session_path, str) and notify_session_path.strip():
            session_path = notify_session_path.strip()
        elif isinstance(rec, dict):
            rec_path = rec.get("session_path")
            if isinstance(rec_path, str) and rec_path.strip():
                session_path = rec_path.strip()

        prompt_text, pending_request_user_input = _render_notify_input_text(session_path=session_path)
        call_id = notify._extract_call_id(payload)

        if isinstance(call_id, str) and call_id.strip():
            call_key = agent_chat_dedupe.build_dedupe_key(
                category="needs_input_call_id",
                scope=session_id,
                text=call_id.strip(),
            )
            if not agent_chat_dedupe.mark_once(codex_home=codex_home, key=call_key):
                if not is_completion_event:
                    _save_registry(codex_home=codex_home, registry=registry)
                return

        dedupe_text = prompt_text
        if dedupe_text == _DEFAULT_INPUT_NEEDED_TEXT:
            dedupe_text = f"{dedupe_text}\n{notify._payload_blob(payload) or 'fallback'}"
        semantic_key = agent_chat_dedupe.build_dedupe_key(
            category="needs_input",
            scope=session_id,
            text=dedupe_text,
        )
        if agent_chat_dedupe.mark_once(codex_home=codex_home, key=semantic_key):
            message_index = _load_message_index(codex_home=codex_home)
            deliver_to_discord = _should_emit_discord_lifecycle_event(
                session_rec=rec if isinstance(rec, dict) else None,
                event_kind="needs_input",
            )
            _send_structured(
                codex_home=codex_home,
                recipient=recipient,
                session_id=session_id,
                kind="needs_input",
                text=prompt_text,
                max_message_chars=_DEFAULT_MAX_MESSAGE_CHARS,
                dry_run=dry_run,
                message_index=message_index,
                deliver_to_discord=deliver_to_discord,
                discord_lifecycle_event=deliver_to_discord,
            )
            _save_message_index(codex_home=codex_home, index=message_index)

            update_fields: dict[str, Any] = {
                "awaiting_input": True,
                "pending_completion": True,
                "last_attention_ts": int(time.time()),
                "last_needs_input": prompt_text,
            }
            if isinstance(pending_request_user_input, dict):
                update_fields["pending_request_user_input"] = pending_request_user_input
            if isinstance(session_path, str) and session_path.strip():
                update_fields["session_path"] = session_path.strip()
            _update_active_prompt_lifecycle(
                registry=registry,
                session_id=session_id,
                status="needs_input",
            )
            _upsert_session(registry=registry, session_id=session_id, fields=update_fields)

    if not is_completion_event:
        _save_registry(codex_home=codex_home, registry=registry)
        return

    scope = session_id
    payload_fingerprint = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    final_key = agent_chat_dedupe.build_dedupe_key(
        category="final_status",
        scope=scope,
        text=payload_fingerprint,
    )
    if not agent_chat_dedupe.mark_once(codex_home=codex_home, key=final_key, ttl_seconds=120):
        return

    response_text: str | None = None
    for key in ("last-assistant-message", "last_assistant_message"):
        val = payload.get(key)
        if isinstance(val, str) and val.strip():
            response_text = val.strip()
            break

    if not response_text and isinstance(params, dict):
        for key in ("last-assistant-message", "last_assistant_message"):
            val = params.get(key)
            if isinstance(val, str) and val.strip():
                response_text = val.strip()
                break

    if not response_text and isinstance(rec, dict):
        sp = rec.get("session_path")
        if isinstance(sp, str) and sp.strip():
            response_text = reply._read_last_assistant_text_from_session(Path(sp.strip()))

    terminal_status = _infer_notify_terminal_status(payload=payload)

    if not response_text:
        if terminal_status == "failed":
            response_text = "Turn failed."
        elif terminal_status == "cancelled":
            response_text = "Turn cancelled."
        else:
            response_text = "Turn completed."

    structured_kind = "responded" if terminal_status == "completed" else terminal_status

    if _should_emit_session_completion_notification():
        message_index = _load_message_index(codex_home=codex_home)
        deliver_to_discord = _should_emit_discord_lifecycle_event(
            session_rec=rec if isinstance(rec, dict) else None,
            event_kind=terminal_status,
        )
        _send_structured(
            codex_home=codex_home,
            recipient=recipient,
            session_id=session_id,
            kind=structured_kind,
            text=response_text,
            max_message_chars=_DEFAULT_MAX_MESSAGE_CHARS,
            dry_run=dry_run,
            message_index=message_index,
            deliver_to_discord=deliver_to_discord,
            discord_lifecycle_event=deliver_to_discord,
        )
        _save_message_index(codex_home=codex_home, index=message_index)

    _update_active_prompt_lifecycle(
        registry=registry,
        session_id=session_id,
        status=terminal_status,
    )
    _upsert_session(
        registry=registry,
        session_id=session_id,
        fields={
            "awaiting_input": False,
            "pending_completion": False,
            "last_response_ts": int(time.time()),
            "pending_request_user_input": None,
        },
    )
    _save_registry(codex_home=codex_home, registry=registry)


def _process_inbound_replies(
    *,
    codex_home: Path,
    conn: sqlite3.Connection,
    recipient: str,
    handle_ids: list[str],
    after_rowid: int,
    max_message_chars: int,
    min_prefix: int,
    dry_run: bool,
    resume_timeout_s: float | None = None,
    trace: bool = False,
    fetch_replies_fn: Callable[..., list[tuple[int, str, str | None]]] | None = None,
    reference_guids_fn: Callable[..., list[str]] | None = None,
    reference_texts_fn: Callable[..., list[str] | None] | None = None,
    row_contexts_fn: Callable[..., dict[int, dict[str, Any]]] | None = None,
) -> int:
    if fetch_replies_fn is not None:
        replies = fetch_replies_fn(conn=conn, after_rowid=after_rowid, handle_ids=handle_ids)
    else:
        replies = reply._fetch_new_replies(conn=conn, after_rowid=after_rowid, handle_ids=handle_ids)
    if not replies:
        return after_rowid
    row_contexts = (
        row_contexts_fn(conn=conn, after_rowid=after_rowid, handle_ids=handle_ids)
        if row_contexts_fn is not None
        else {}
    )
    if not isinstance(row_contexts, dict):
        row_contexts = {}

    registry = _load_registry(codex_home=codex_home)
    message_index = _load_message_index(codex_home=codex_home)
    attention_index = _load_attention_index(codex_home=codex_home)
    last_attention_state = _load_last_attention_state(codex_home=codex_home)
    auto_create_on_missing = _env_enabled("AGENT_CHAT_AUTO_CREATE_ON_MISSING", default=True)
    strict_tmux = _strict_tmux_enabled()
    require_session_ref = _require_session_ref_enabled(strict_tmux=strict_tmux)

    def _trace(message: str) -> None:
        if not trace:
            return
        _warn_stderr(f"[agent-chat][trace] {message}")

    last_rowid = after_rowid

    for rowid, text, reply_to_guid in replies:
        last_rowid = rowid
        row_context_raw = row_contexts.get(int(rowid))
        row_context = row_context_raw if isinstance(row_context_raw, dict) else {}
        row_transport_raw = row_context.get("transport")
        row_transport = row_transport_raw.strip().lower() if isinstance(row_transport_raw, str) else ""
        row_telegram_chat_id = (
            row_context.get("telegram_chat_id") if isinstance(row_context.get("telegram_chat_id"), str) else None
        )
        row_telegram_thread_id = _normalize_telegram_thread_id(row_context.get("telegram_message_thread_id"))
        if row_transport == "telegram" and row_telegram_thread_id is None:
            inferred_thread_id = _lookup_single_telegram_thread_for_chat(
                registry=registry,
                chat_id=row_telegram_chat_id,
            )
            if inferred_thread_id is not None:
                row_telegram_thread_id = inferred_thread_id
        row_telegram_sender_user_id = (
            row_context.get("telegram_sender_user_id")
            if isinstance(row_context.get("telegram_sender_user_id"), str)
            else None
        )
        row_thread_key = _telegram_thread_key(chat_id=row_telegram_chat_id, thread_id=row_telegram_thread_id)
        row_discord_parent_channel_id = (
            row_context.get("discord_parent_channel_id")
            if isinstance(row_context.get("discord_parent_channel_id"), str)
            else None
        )
        row_discord_channel_id = (
            row_context.get("discord_channel_id") if isinstance(row_context.get("discord_channel_id"), str) else None
        )
        row_discord_sender_user_id = (
            row_context.get("discord_sender_user_id")
            if isinstance(row_context.get("discord_sender_user_id"), str)
            else None
        )
        row_discord_attachments = _normalize_discord_attachment_payloads(row_context.get("discord_attachments"))
        discord_attachments_only = bool(row_transport == "discord" and row_discord_attachments and not text.strip())
        if discord_attachments_only:
            text = "continue"
        row_context_key: str | None = None
        row_context_channel_id: str | None = None
        row_context_thread_id: int | str | None = None
        if row_transport == "telegram":
            row_context_channel_id = row_telegram_chat_id
            row_context_thread_id = row_telegram_thread_id
            row_context_key = _conversation_key(
                transport="telegram",
                channel_id=row_context_channel_id,
                thread_id=row_context_thread_id,
            )
        elif row_transport == "discord":
            row_context_channel_id = row_discord_parent_channel_id or row_discord_channel_id
            row_context_thread_id = (
                row_discord_channel_id
                if row_discord_parent_channel_id and row_discord_channel_id and row_discord_parent_channel_id != row_discord_channel_id
                else 0
            )
            row_context_key = _conversation_key(
                transport="discord",
                channel_id=row_context_channel_id,
                thread_id=row_context_thread_id,
            )
        row_reply_discord_channel_id = row_discord_channel_id if row_transport == "discord" else None
        _trace(f"inbound rowid={rowid} text={text.strip()[:120]!r}")
        if reference_guids_fn is not None:
            reference_guids = reference_guids_fn(conn=conn, rowid=rowid, fallback_guid=reply_to_guid)
        else:
            reference_guids = _reply_reference_guids_for_row(
                conn=conn,
                rowid=rowid,
                fallback_guid=reply_to_guid,
            )
        if reference_texts_fn is not None:
            reference_texts = reference_texts_fn(conn=conn, rowid=rowid, fallback_guid=reply_to_guid)
        else:
            reference_texts = None

        if reply._is_attention_message(text):
            continue
        if reply._is_bot_message(text):
            continue

        pending_choice_scope = "global"
        pending_choice = _get_pending_new_session_choice(registry=registry)
        if row_transport == "telegram" and row_thread_key:
            pending_choice_for_thread = _get_pending_new_session_choice_by_thread(
                registry=registry,
                thread_key=row_thread_key,
            )
            if isinstance(pending_choice_for_thread, dict):
                pending_choice = pending_choice_for_thread
                pending_choice_scope = "thread"
        elif row_context_key:
            pending_choice_for_context = _get_pending_new_session_choice_by_context(
                registry=registry,
                context_key=row_context_key,
            )
            if isinstance(pending_choice_for_context, dict):
                pending_choice = pending_choice_for_context
                pending_choice_scope = "context"
        if isinstance(pending_choice, dict):
            choice = _parse_agent_choice_response(text=text)
            if choice == "cancel":
                if pending_choice_scope == "context":
                    _clear_pending_new_session_choice_by_context(registry=registry, context_key=row_context_key)
                elif pending_choice_scope == "thread":
                    _clear_pending_new_session_choice_by_thread(registry=registry, thread_key=row_thread_key)
                else:
                    _clear_pending_new_session_choice(registry=registry)
                _send_structured(
                    codex_home=codex_home,
                    recipient=recipient,
                    session_id=None,
                    kind="status",
                    text="Canceled pending new-session creation request.",
                    max_message_chars=max_message_chars,
                    dry_run=dry_run,
                    message_index=message_index,
                    telegram_message_thread_id=row_telegram_thread_id,
                    telegram_chat_id=row_telegram_chat_id,
                    discord_channel_id=row_reply_discord_channel_id,
                )
                continue
            if choice in _SUPPORTED_AGENTS:
                requested_prompt = pending_choice.get("prompt")
                if not isinstance(requested_prompt, str) or not requested_prompt.strip():
                    if pending_choice_scope == "context":
                        _clear_pending_new_session_choice_by_context(registry=registry, context_key=row_context_key)
                    elif pending_choice_scope == "thread":
                        _clear_pending_new_session_choice_by_thread(registry=registry, thread_key=row_thread_key)
                    else:
                        _clear_pending_new_session_choice(registry=registry)
                    _send_structured(
                        codex_home=codex_home,
                        recipient=recipient,
                        session_id=None,
                        kind="error",
                        text="Pending new-session request was invalid and has been cleared.",
                        max_message_chars=max_message_chars,
                        dry_run=dry_run,
                        message_index=message_index,
                        telegram_message_thread_id=row_telegram_thread_id,
                        telegram_chat_id=row_telegram_chat_id,
                        discord_channel_id=row_reply_discord_channel_id,
                    )
                    continue

                pending_label = pending_choice.get("label")
                selected_label = pending_label if isinstance(pending_label, str) else None
                pending_cwd = pending_choice.get("cwd")
                selected_cwd = pending_cwd if isinstance(pending_cwd, str) else None

                preferred_tmux_socket = _normalize_tmux_socket(
                    tmux_socket=os.environ.get("AGENT_CHAT_TMUX_SOCKET")
                ) or _choose_registry_tmux_socket(registry=registry)

                sid, session_path, pane, create_err = _create_new_session_in_tmux(
                    codex_home=codex_home,
                    prompt=requested_prompt.strip(),
                    cwd=selected_cwd,
                    label=selected_label,
                    agent=choice,
                    tmux_socket=preferred_tmux_socket,
                )
                created_via_tmux = bool(sid)
                create_response: str | None = None
                fallback_err: str | None = None
                require_tmux_backed_session = _requires_tmux_backed_new_session_for_context(
                    transport=row_transport,
                    agent=choice,
                )
                if not sid and not require_tmux_backed_session:
                    sid, session_path, create_response = _create_new_session(
                        codex_home=codex_home,
                        label=selected_label or "session",
                        prompt=requested_prompt.strip(),
                        agent=choice,
                        cwd=selected_cwd,
                    )
                    if not sid:
                        fallback_err = create_response
                elif not sid:
                    fallback_err = "skipped (Discord-origin Pi sessions require tmux-backed creation)"

                if not sid:
                    if require_tmux_backed_session:
                        err_text = (
                            "Couldn't start a tmux-backed Pi session for this Discord request. "
                            "Foreground desktop visibility requires a tmux-backed Pi session. "
                            f"tmux: {create_err or 'unknown'}. Reply `3` to retry after fixing tmux, or `cancel` to abort."
                        )
                    else:
                        err_text = (
                            "Failed to create new session after agent selection."
                            f" tmux: {create_err or 'unknown'}; fallback: {fallback_err or 'unknown'}"
                        )
                    _send_structured(
                        codex_home=codex_home,
                        recipient=recipient,
                        session_id=None,
                        kind="error",
                        text=err_text,
                        max_message_chars=max_message_chars,
                        dry_run=dry_run,
                        message_index=message_index,
                        agent=choice,
                        telegram_message_thread_id=row_telegram_thread_id,
                telegram_chat_id=row_telegram_chat_id,
                discord_channel_id=row_reply_discord_channel_id,
                    )
                    continue

                session_cwd = selected_cwd
                if session_path:
                    extracted_cwd = outbound._read_session_cwd(session_path=Path(session_path))
                    if isinstance(extracted_cwd, str) and extracted_cwd.strip():
                        session_cwd = extracted_cwd.strip()

                fields: dict[str, Any] = {
                    "agent": choice,
                    "awaiting_input": False,
                    "pending_request_user_input": None,
                }
                if session_path:
                    fields["session_path"] = session_path
                if isinstance(session_cwd, str) and session_cwd.strip():
                    fields["cwd"] = session_cwd.strip()

                if created_via_tmux:
                    fields["pending_completion"] = True
                    fields["last_resume_ts"] = int(time.time())
                    if isinstance(pane, str) and pane.strip():
                        fields["tmux_pane"] = pane.strip()
                    if isinstance(preferred_tmux_socket, str) and preferred_tmux_socket.strip():
                        fields["tmux_socket"] = preferred_tmux_socket.strip()
                else:
                    fields["pending_completion"] = False
                    fields["last_response_ts"] = int(time.time())

                _upsert_session(registry=registry, session_id=sid, fields=fields)
                if isinstance(selected_label, str):
                    alias = selected_label.strip().lower()
                    if re.match(r"^[A-Za-z0-9._-]+$", alias):
                        _set_alias(registry=registry, session_id=sid, label=alias)

                session_channel_id: str | None = None
                if row_transport == "discord" and _discord_session_channels_enabled():
                    session_channel_id, _ = _discord_ensure_session_channel(
                        codex_home=codex_home,
                        registry=registry,
                        session_id=sid,
                    )

                if row_thread_key and row_transport == "telegram":
                    _bind_telegram_thread_to_session(
                        registry=registry,
                        chat_id=row_telegram_chat_id,
                        message_thread_id=row_telegram_thread_id,
                        session_id=sid,
                    )
                elif row_transport == "discord" and row_context_channel_id and _should_bind_discord_context(
                    channel_id=row_context_channel_id,
                    thread_id=row_context_thread_id,
                ):
                    _bind_conversation_to_session(
                        registry=registry,
                        transport="discord",
                        channel_id=row_context_channel_id,
                        thread_id=row_context_thread_id,
                        session_id=sid,
                    )
                if pending_choice_scope == "context":
                    _clear_pending_new_session_choice_by_context(registry=registry, context_key=row_context_key)
                elif pending_choice_scope == "thread":
                    _clear_pending_new_session_choice_by_thread(registry=registry, thread_key=row_thread_key)
                else:
                    _clear_pending_new_session_choice(registry=registry)

                if created_via_tmux:
                    text_out = (
                        f"Started {_agent_display_name(agent=choice)} session @{_session_ref(sid)} "
                        f"in tmux pane {pane or '-'}."
                    )
                else:
                    text_out = (
                        f"Started {_agent_display_name(agent=choice)} session @{_session_ref(sid)} "
                        "without tmux."
                    )
                if isinstance(session_channel_id, str) and session_channel_id.strip() and not _discord_is_control_channel(channel_id=session_channel_id):
                    text_out += f" Session channel: <#{session_channel_id.strip()}>."
                text_out += _context_followup_hint(
                    transport=row_transport or "imessage",
                    telegram_message_thread_id=row_telegram_thread_id,
                    discord_channel_id=row_discord_channel_id,
                    discord_parent_channel_id=row_discord_parent_channel_id,
                )
                text_out = _append_surface_onboarding_hint(
                    registry=registry,
                    text=text_out,
                    bucket="session",
                    transport=row_transport or "imessage",
                    recipient=recipient,
                    telegram_chat_id=row_telegram_chat_id,
                    telegram_message_thread_id=row_telegram_thread_id,
                    discord_channel_id=row_discord_channel_id,
                    discord_parent_channel_id=row_discord_parent_channel_id,
                )
                _send_structured(
                    codex_home=codex_home,
                    recipient=recipient,
                    session_id=sid,
                    kind="accepted",
                    text=text_out,
                    max_message_chars=max_message_chars,
                    dry_run=dry_run,
                    message_index=message_index,
                    agent=choice,
                    telegram_message_thread_id=row_telegram_thread_id,
                    telegram_chat_id=row_telegram_chat_id,
                    discord_channel_id=row_reply_discord_channel_id,
                )
                continue

        cmd = _parse_inbound_command(text)
        action = cmd.get("action")
        if action == "noop":
            continue
        _trace(f"parsed action={action} reply_to_guid={bool(reply_to_guid)}")

        if action == "help":
            help_text = _append_surface_onboarding_hint(
                registry=registry,
                text=_HELP_TEXT,
                bucket="control",
                transport=row_transport or "imessage",
                recipient=recipient,
                telegram_chat_id=row_telegram_chat_id,
                telegram_message_thread_id=row_telegram_thread_id,
                discord_channel_id=row_discord_channel_id,
                discord_parent_channel_id=row_discord_parent_channel_id,
            )
            _send_structured(
                codex_home=codex_home,
                recipient=recipient,
                session_id=None,
                kind="help",
                text=help_text,
                max_message_chars=max_message_chars,
                dry_run=dry_run,
                message_index=message_index,
                telegram_message_thread_id=row_telegram_thread_id,
                telegram_chat_id=row_telegram_chat_id,
                discord_channel_id=row_reply_discord_channel_id,
            )
            continue

        if action == "list":
            list_text = _append_surface_onboarding_hint(
                registry=registry,
                text=_render_session_list(registry=registry),
                bucket="control",
                transport=row_transport or "imessage",
                recipient=recipient,
                telegram_chat_id=row_telegram_chat_id,
                telegram_message_thread_id=row_telegram_thread_id,
                discord_channel_id=row_discord_channel_id,
                discord_parent_channel_id=row_discord_parent_channel_id,
            )
            _send_structured(
                codex_home=codex_home,
                recipient=recipient,
                session_id=None,
                kind="status",
                text=list_text,
                max_message_chars=max_message_chars,
                dry_run=dry_run,
                message_index=message_index,
                telegram_message_thread_id=row_telegram_thread_id,
                telegram_chat_id=row_telegram_chat_id,
                discord_channel_id=row_reply_discord_channel_id,
            )
            continue

        if action == "context":
            context_bucket = "session" if _bound_session_for_inbound_context(
                registry=registry,
                transport=row_transport or "imessage",
                telegram_chat_id=row_telegram_chat_id,
                telegram_message_thread_id=row_telegram_thread_id,
                discord_channel_id=row_discord_channel_id,
                discord_parent_channel_id=row_discord_parent_channel_id,
            ) else "control"
            context_text = _append_surface_onboarding_hint(
                registry=registry,
                text=_render_context_status(
                    registry=registry,
                    transport=row_transport or "imessage",
                    recipient=recipient,
                    telegram_chat_id=row_telegram_chat_id,
                    telegram_message_thread_id=row_telegram_thread_id,
                    discord_channel_id=row_discord_channel_id,
                    discord_parent_channel_id=row_discord_parent_channel_id,
                ),
                bucket=context_bucket,
                transport=row_transport or "imessage",
                recipient=recipient,
                telegram_chat_id=row_telegram_chat_id,
                telegram_message_thread_id=row_telegram_thread_id,
                discord_channel_id=row_discord_channel_id,
                discord_parent_channel_id=row_discord_parent_channel_id,
            )
            _send_structured(
                codex_home=codex_home,
                recipient=recipient,
                session_id=None,
                kind="status",
                text=context_text,
                max_message_chars=max_message_chars,
                dry_run=dry_run,
                message_index=message_index,
                telegram_message_thread_id=row_telegram_thread_id,
                telegram_chat_id=row_telegram_chat_id,
                discord_channel_id=row_reply_discord_channel_id,
            )
            continue

        if action == "bind":
            session_ref = cmd.get("session_ref", "")
            sid, err = _resolve_session_ref(registry=registry, session_ref=session_ref, min_prefix=min_prefix)
            if not sid:
                _send_structured(
                    codex_home=codex_home,
                    recipient=recipient,
                    session_id=None,
                    kind="error",
                    text=err or "Session not found.",
                    max_message_chars=max_message_chars,
                    dry_run=dry_run,
                    message_index=message_index,
                    telegram_message_thread_id=row_telegram_thread_id,
                    telegram_chat_id=row_telegram_chat_id,
                    discord_channel_id=row_reply_discord_channel_id,
                )
                continue

            bound = False
            if row_transport == "telegram" and row_thread_key:
                _bind_telegram_thread_to_session(
                    registry=registry,
                    chat_id=row_telegram_chat_id,
                    message_thread_id=row_telegram_thread_id,
                    session_id=sid,
                )
                bound = True
            elif row_transport == "discord" and row_context_channel_id and _should_bind_discord_context(
                channel_id=row_context_channel_id,
                thread_id=row_context_thread_id,
            ):
                _bind_discord_context_to_session(
                    registry=registry,
                    session_id=sid,
                    discord_channel_id=row_discord_channel_id,
                    discord_parent_channel_id=row_discord_parent_channel_id,
                )
                bound = True

            if not bound:
                _send_structured(
                    codex_home=codex_home,
                    recipient=recipient,
                    session_id=None,
                    kind="error",
                    text="`bind` works in Telegram topics and Discord channels/threads. In iMessage, send `@<session_ref> <instruction>` instead.",
                    max_message_chars=max_message_chars,
                    dry_run=dry_run,
                    message_index=message_index,
                    telegram_message_thread_id=row_telegram_thread_id,
                    telegram_chat_id=row_telegram_chat_id,
                    discord_channel_id=row_reply_discord_channel_id,
                )
                continue

            bind_text = _append_surface_onboarding_hint(
                registry=registry,
                text=_render_bind_confirmation(
                    registry=registry,
                    session_id=sid,
                    transport=row_transport or "imessage",
                    telegram_chat_id=row_telegram_chat_id,
                    telegram_message_thread_id=row_telegram_thread_id,
                    discord_channel_id=row_discord_channel_id,
                    discord_parent_channel_id=row_discord_parent_channel_id,
                ),
                bucket="session",
                transport=row_transport or "imessage",
                recipient=recipient,
                telegram_chat_id=row_telegram_chat_id,
                telegram_message_thread_id=row_telegram_thread_id,
                discord_channel_id=row_discord_channel_id,
                discord_parent_channel_id=row_discord_parent_channel_id,
            )
            _send_structured(
                codex_home=codex_home,
                recipient=recipient,
                session_id=sid,
                kind="accepted",
                text=bind_text,
                max_message_chars=max_message_chars,
                dry_run=dry_run,
                message_index=message_index,
                telegram_message_thread_id=row_telegram_thread_id,
                telegram_chat_id=row_telegram_chat_id,
                discord_channel_id=row_reply_discord_channel_id,
            )
            continue

        if action == "status":
            session_ref = cmd.get("session_ref", "")
            sid, err = _resolve_session_ref(registry=registry, session_ref=session_ref, min_prefix=min_prefix)
            if not sid:
                _send_structured(
                    codex_home=codex_home,
                    recipient=recipient,
                    session_id=None,
                    kind="error",
                    text=err or "Session not found.",
                    max_message_chars=max_message_chars,
                    dry_run=dry_run,
                    message_index=message_index,
                    telegram_message_thread_id=row_telegram_thread_id,
                    telegram_chat_id=row_telegram_chat_id,
                    discord_channel_id=row_reply_discord_channel_id,
                )
                continue

            _send_structured(
                codex_home=codex_home,
                recipient=recipient,
                session_id=sid,
                kind="status",
                text=_render_session_status(session_id=sid, registry=registry),
                max_message_chars=max_message_chars,
                dry_run=dry_run,
                message_index=message_index,
                telegram_message_thread_id=row_telegram_thread_id,
                telegram_chat_id=row_telegram_chat_id,
                discord_channel_id=row_reply_discord_channel_id,
            )
            continue

        if action == "new":
            allow_new = os.environ.get("AGENT_CHAT_ENABLE_NEW_SESSION", "1").strip() not in {
                "0",
                "false",
                "False",
            }
            if not allow_new:
                _send_structured(
                    codex_home=codex_home,
                    recipient=recipient,
                    session_id=None,
                    kind="error",
                    text="Creating new sessions from inbound messages is disabled.",
                    max_message_chars=max_message_chars,
                    dry_run=dry_run,
                    message_index=message_index,
                    telegram_message_thread_id=row_telegram_thread_id,
                    telegram_chat_id=row_telegram_chat_id,
                    discord_channel_id=row_reply_discord_channel_id,
                )
                continue

            label = cmd.get("label", "")
            prompt = cmd.get("prompt", "")
            sid, session_path, err = _create_new_session(codex_home=codex_home, label=label, prompt=prompt)
            if not sid:
                _send_structured(
                    codex_home=codex_home,
                    recipient=recipient,
                    session_id=None,
                    kind="error",
                    text=err or "Failed to create new session.",
                    max_message_chars=max_message_chars,
                    dry_run=dry_run,
                    message_index=message_index,
                    telegram_message_thread_id=row_telegram_thread_id,
                    telegram_chat_id=row_telegram_chat_id,
                    discord_channel_id=row_reply_discord_channel_id,
                )
                continue

            _upsert_session(
                registry=registry,
                session_id=sid,
                fields={
                    "agent": _current_agent(),
                    "session_path": session_path,
                    "awaiting_input": False,
                    "pending_completion": False,
                    "pending_request_user_input": None,
                },
            )
            if label:
                _set_alias(registry=registry, session_id=sid, label=label)

            session_channel_id: str | None = None
            if row_transport == "discord" and _discord_session_channels_enabled():
                session_channel_id, _ = _discord_ensure_session_channel(
                    codex_home=codex_home,
                    registry=registry,
                    session_id=sid,
                )

            if row_thread_key and row_transport == "telegram":
                _bind_telegram_thread_to_session(
                    registry=registry,
                    chat_id=row_telegram_chat_id,
                    message_thread_id=row_telegram_thread_id,
                    session_id=sid,
                )
            elif row_transport == "discord" and row_context_channel_id and _should_bind_discord_context(
                channel_id=row_context_channel_id,
                thread_id=row_context_thread_id,
            ):
                _bind_discord_context_to_session(
                    registry=registry,
                    session_id=sid,
                    discord_channel_id=row_discord_channel_id,
                    discord_parent_channel_id=row_discord_parent_channel_id,
                )

            created_label = f" ({label})" if label else ""
            created_text = f"Created @{_session_ref(sid)}{created_label}."
            if isinstance(session_channel_id, str) and session_channel_id.strip() and not _discord_is_control_channel(channel_id=session_channel_id):
                created_text += f" Session channel: <#{session_channel_id.strip()}>."
            created_text += _context_followup_hint(
                transport=row_transport or "imessage",
                telegram_message_thread_id=row_telegram_thread_id,
                discord_channel_id=row_discord_channel_id,
                discord_parent_channel_id=row_discord_parent_channel_id,
            )
            created_text = _append_surface_onboarding_hint(
                registry=registry,
                text=created_text,
                bucket="session",
                transport=row_transport or "imessage",
                recipient=recipient,
                telegram_chat_id=row_telegram_chat_id,
                telegram_message_thread_id=row_telegram_thread_id,
                discord_channel_id=row_discord_channel_id,
                discord_parent_channel_id=row_discord_parent_channel_id,
            )

            _send_structured(
                codex_home=codex_home,
                recipient=recipient,
                session_id=sid,
                kind="accepted",
                text=created_text,
                max_message_chars=max_message_chars,
                dry_run=dry_run,
                message_index=message_index,
                telegram_message_thread_id=row_telegram_thread_id,
                telegram_chat_id=row_telegram_chat_id,
                discord_channel_id=row_reply_discord_channel_id,
            )
            continue

        target_sid: str | None = None
        err: str | None = None
        prompt = cmd.get("prompt", "").strip()
        if discord_attachments_only and action == "implicit":
            prompt = ""
        if not prompt and not row_discord_attachments:
            _send_structured(
                codex_home=codex_home,
                recipient=recipient,
                session_id=None,
                kind="error",
                text="No instruction text was provided.",
                max_message_chars=max_message_chars,
                dry_run=dry_run,
                message_index=message_index,
                telegram_message_thread_id=row_telegram_thread_id,
                telegram_chat_id=row_telegram_chat_id,
                discord_channel_id=row_reply_discord_channel_id,
            )
            continue

        if action == "resume":
            target_sid, err = _resolve_session_ref(
                registry=registry,
                session_ref=cmd.get("session_ref", ""),
                min_prefix=min_prefix,
            )
            if not target_sid:
                raw_ref = cmd.get("session_ref", "")
                requested_sid = raw_ref.strip() if isinstance(raw_ref, str) else ""
                if requested_sid and _SESSION_UUID_RE.fullmatch(requested_sid):
                    recovered = _recover_session_record_from_disk(
                        codex_home=codex_home,
                        session_id=requested_sid,
                        registry=registry,
                    )
                    if not (isinstance(recovered, dict) and recovered):
                        recovered = _recover_session_record_from_tmux(
                            codex_home=codex_home,
                            session_id=requested_sid,
                            registry=registry,
                            agent=_current_agent(),
                        )
                    if isinstance(recovered, dict) and recovered:
                        _upsert_session(registry=registry, session_id=requested_sid, fields=recovered)
                        target_sid = requested_sid
                        err = None
            if not target_sid and row_transport == "telegram":
                bound_sid = _lookup_session_by_telegram_thread(
                    registry=registry,
                    chat_id=row_telegram_chat_id,
                    message_thread_id=row_telegram_thread_id,
                )
                rebound_sid = _resolve_session_from_telegram_thread_tmux_binding(
                    codex_home=codex_home,
                    registry=registry,
                    chat_id=row_telegram_chat_id,
                    message_thread_id=row_telegram_thread_id,
                    fallback_session_id=bound_sid,
                    agent=_current_agent(),
                )
                if isinstance(rebound_sid, str) and rebound_sid.strip():
                    target_sid = rebound_sid.strip()
                    err = None
            if not target_sid and row_transport == "discord":
                bound_sid = _lookup_session_by_discord_channel_id(
                    registry=registry,
                    channel_id=row_discord_channel_id,
                )
                if not bound_sid and row_context_channel_id:
                    bound_sid = _lookup_session_by_conversation(
                        registry=registry,
                        transport="discord",
                        channel_id=row_context_channel_id,
                        thread_id=row_context_thread_id,
                    )
                if isinstance(bound_sid, str) and bound_sid.strip():
                    target_sid = bound_sid.strip()
                    err = None
        else:
            if action == "implicit" and row_transport == "telegram":
                bound_sid = _lookup_session_by_telegram_thread(
                    registry=registry,
                    chat_id=row_telegram_chat_id,
                    message_thread_id=row_telegram_thread_id,
                )
                rebound_sid = _resolve_session_from_telegram_thread_tmux_binding(
                    codex_home=codex_home,
                    registry=registry,
                    chat_id=row_telegram_chat_id,
                    message_thread_id=row_telegram_thread_id,
                    fallback_session_id=bound_sid,
                    agent=_current_agent(),
                )
                target_sid = rebound_sid if isinstance(rebound_sid, str) and rebound_sid.strip() else bound_sid
                if not target_sid and row_thread_key and _telegram_sender_is_owner(
                    sender_user_id=row_telegram_sender_user_id
                ):
                    target_sid = _lookup_single_session_by_telegram_chat(
                        registry=registry,
                        chat_id=row_telegram_chat_id,
                    )
            elif action == "implicit" and row_transport == "discord":
                target_sid = _lookup_session_by_discord_channel_id(
                    registry=registry,
                    channel_id=row_discord_channel_id,
                )
                if not target_sid and row_context_channel_id:
                    target_sid = _lookup_session_by_conversation(
                        registry=registry,
                        transport="discord",
                        channel_id=row_context_channel_id,
                        thread_id=row_context_thread_id,
                    )
                if not target_sid and row_context_channel_id and _discord_sender_is_owner(sender_user_id=row_discord_sender_user_id):
                    target_sid = _lookup_session_by_conversation(
                        registry=registry,
                        transport="discord",
                        channel_id=row_context_channel_id,
                        thread_id=0,
                    )
            if not target_sid:
                target_sid, err = _resolve_session_from_reply_context(
                    conn=conn,
                    reply_text=text,
                    reply_to_guid=reply_to_guid,
                    reply_reference_guids=reference_guids,
                    reply_reference_texts=reference_texts,
                    registry=registry,
                    message_index=message_index,
                    require_explicit_ref=(action == "implicit" and require_session_ref),
                )
        _trace(f"resolved target_sid={target_sid or '-'} err={err or '-'}")

        if not target_sid:
            if row_transport == "discord" and row_discord_attachments:
                _send_structured(
                    codex_home=codex_home,
                    recipient=recipient,
                    session_id=None,
                    kind="error",
                    text=(
                        "Discord attachment handoff currently needs an existing target session. "
                        "Bind this channel first, or send `@<session_ref> <instruction>` with the attachment."
                    ),
                    max_message_chars=max_message_chars,
                    dry_run=dry_run,
                    message_index=message_index,
                    telegram_message_thread_id=row_telegram_thread_id,
                    telegram_chat_id=row_telegram_chat_id,
                    discord_channel_id=row_reply_discord_channel_id,
                )
                continue
            # Keep strict mode for ambiguous implicit routing, but still allow the
            # runtime-choice flow when there is no active implicit target at all.
            implicit_missing_without_ambiguity = (
                action == "implicit"
                and strict_tmux
                and isinstance(err, str)
                and err.startswith(
                    (
                        "No session here is currently awaiting input.",
                        "No session is currently awaiting input.",
                        "No tracked sessions yet.",
                        "No tracked sessions.",
                    )
                )
            )
            allow_auto_create = auto_create_on_missing and (
                not (strict_tmux and action == "implicit") or implicit_missing_without_ambiguity
            )
            if allow_auto_create:
                fallback_cwd = _default_new_session_cwd()
                auto_create_label: str | None = None
                if action == "resume":
                    raw_ref = cmd.get("session_ref", "")
                    if isinstance(raw_ref, str) and raw_ref.strip():
                        auto_create_label = raw_ref.strip()
                source_ref = cmd.get("session_ref", "") if action == "resume" else None
                if row_thread_key and row_transport == "telegram":
                    _set_pending_new_session_choice_by_thread(
                        registry=registry,
                        thread_key=row_thread_key,
                        prompt=prompt,
                        action=action,
                        source_text=text,
                        source_ref=source_ref if isinstance(source_ref, str) and source_ref.strip() else None,
                        label=auto_create_label,
                        cwd=fallback_cwd,
                    )
                elif row_context_key:
                    _set_pending_new_session_choice_by_context(
                        registry=registry,
                        context_key=row_context_key,
                        prompt=prompt,
                        action=action,
                        source_text=text,
                        source_ref=source_ref if isinstance(source_ref, str) and source_ref.strip() else None,
                        label=auto_create_label,
                        cwd=fallback_cwd,
                    )
                else:
                    _set_pending_new_session_choice(
                        registry=registry,
                        prompt=prompt,
                        action=action,
                        source_text=text,
                        source_ref=source_ref if isinstance(source_ref, str) and source_ref.strip() else None,
                        label=auto_create_label,
                        cwd=fallback_cwd,
                    )
                pending_prompt = _append_surface_onboarding_hint(
                    registry=registry,
                    text=_render_missing_session_prompt(
                        transport=row_transport or "imessage",
                        recipient=recipient,
                        registry=registry,
                        telegram_chat_id=row_telegram_chat_id,
                        telegram_message_thread_id=row_telegram_thread_id,
                        discord_channel_id=row_discord_channel_id,
                        discord_parent_channel_id=row_discord_parent_channel_id,
                    ),
                    bucket="control",
                    transport=row_transport or "imessage",
                    recipient=recipient,
                    telegram_chat_id=row_telegram_chat_id,
                    telegram_message_thread_id=row_telegram_thread_id,
                    discord_channel_id=row_discord_channel_id,
                    discord_parent_channel_id=row_discord_parent_channel_id,
                )
                _send_structured(
                    codex_home=codex_home,
                    recipient=recipient,
                    session_id=None,
                    kind="needs_input",
                    text=pending_prompt,
                    max_message_chars=max_message_chars,
                    dry_run=dry_run,
                    message_index=message_index,
                    telegram_message_thread_id=row_telegram_thread_id,
                    telegram_chat_id=row_telegram_chat_id,
                    discord_channel_id=row_reply_discord_channel_id,
                )
                continue

            _send_structured(
                codex_home=codex_home,
                recipient=recipient,
                session_id=None,
                kind="error",
                text=err or "Could not resolve target session.",
                max_message_chars=max_message_chars,
                dry_run=dry_run,
                message_index=message_index,
                telegram_message_thread_id=row_telegram_thread_id,
                telegram_chat_id=row_telegram_chat_id,
                discord_channel_id=row_reply_discord_channel_id,
            )
            continue

        if row_thread_key and row_transport == "telegram":
            _bind_telegram_thread_to_session(
                registry=registry,
                chat_id=row_telegram_chat_id,
                message_thread_id=row_telegram_thread_id,
                session_id=target_sid,
            )
        elif row_transport == "discord" and row_context_channel_id and _should_bind_discord_context(
            channel_id=row_context_channel_id,
            thread_id=row_context_thread_id,
        ):
            _bind_discord_context_to_session(
                registry=registry,
                session_id=target_sid,
                discord_channel_id=row_discord_channel_id,
                discord_parent_channel_id=row_discord_parent_channel_id,
            )

        sessions = registry.get("sessions")
        rec = sessions.get(target_sid) if isinstance(sessions, dict) else None
        if not isinstance(rec, dict):
            recovered = _recover_session_record_from_disk(
                codex_home=codex_home,
                session_id=target_sid,
                registry=registry,
            )
            if isinstance(recovered, dict) and recovered:
                _upsert_session(registry=registry, session_id=target_sid, fields=recovered)
                sessions = registry.get("sessions")
                rec = sessions.get(target_sid) if isinstance(sessions, dict) else None
        if not isinstance(rec, dict):
            from_attention = _select_attention_context(
                session_id=target_sid,
                attention_index=attention_index,
                last_attention_state=last_attention_state,
            )
            if from_attention:
                _upsert_session(registry=registry, session_id=target_sid, fields=from_attention)
                sessions = registry.get("sessions")
                rec = sessions.get(target_sid) if isinstance(sessions, dict) else None
        _apply_attention_context_to_session(
            session_id=target_sid,
            session_rec=rec if isinstance(rec, dict) else None,
            attention_index=attention_index,
            last_attention_state=last_attention_state,
        )
        session_agent = _resolve_session_agent(
            conn=conn,
            codex_home=codex_home,
            registry=registry,
            session_id=target_sid,
            session_rec=rec if isinstance(rec, dict) else None,
            reply_reference_guids=reference_guids,
            message_index=message_index,
        )
        if isinstance(rec, dict):
            rec["agent"] = session_agent

        prompt_for_dispatch, prompt_err = _rewrite_numeric_choice_prompt(
            prompt=prompt,
            session_rec=rec if isinstance(rec, dict) else None,
        )
        if prompt_err:
            _send_structured(
                codex_home=codex_home,
                recipient=recipient,
                session_id=target_sid,
                kind="error",
                text=prompt_err,
                max_message_chars=max_message_chars,
                dry_run=dry_run,
                message_index=message_index,
                agent=session_agent,
                telegram_message_thread_id=row_telegram_thread_id,
                telegram_chat_id=row_telegram_chat_id,
                discord_channel_id=row_reply_discord_channel_id,
            )
            continue
        if not prompt_for_dispatch and not row_discord_attachments:
            _send_structured(
                codex_home=codex_home,
                recipient=recipient,
                session_id=target_sid,
                kind="error",
                text="No instruction text was provided.",
                max_message_chars=max_message_chars,
                dry_run=dry_run,
                message_index=message_index,
                agent=session_agent,
                telegram_message_thread_id=row_telegram_thread_id,
                telegram_chat_id=row_telegram_chat_id,
                discord_channel_id=row_reply_discord_channel_id,
            )
            continue

        attachment_notice_text = ""
        if row_transport == "discord" and row_discord_attachments and session_agent == "pi":
            saved_attachments, attachment_errors = _store_discord_attachments_for_session(
                codex_home=codex_home,
                session_id=target_sid,
                message_id=int(rowid),
                attachments=row_discord_attachments,
            )
            attachment_notice_text = _discord_attachment_notice_text(
                saved_attachments=saved_attachments,
                attachment_errors=attachment_errors,
            )
            if saved_attachments:
                prompt_for_dispatch = _augment_prompt_with_discord_attachments(
                    prompt=prompt_for_dispatch or "",
                    saved_attachments=saved_attachments,
                    attachment_errors=attachment_errors,
                )
                if isinstance(rec, dict):
                    first_saved = saved_attachments[0].get("path") if isinstance(saved_attachments[0], dict) else None
                    if isinstance(first_saved, str) and first_saved.strip():
                        rec["last_discord_attachment_dir"] = str(Path(first_saved).parent)
            elif attachment_errors and not (isinstance(prompt_for_dispatch, str) and prompt_for_dispatch.strip()):
                _send_structured(
                    codex_home=codex_home,
                    recipient=recipient,
                    session_id=target_sid,
                    kind="error",
                    text=(
                        "I couldn't use the Discord attachment(s). "
                        + "; ".join(attachment_errors[:3])
                    ),
                    max_message_chars=max_message_chars,
                    dry_run=dry_run,
                    message_index=message_index,
                    agent=session_agent,
                    telegram_message_thread_id=row_telegram_thread_id,
                    telegram_chat_id=row_telegram_chat_id,
                    discord_channel_id=row_reply_discord_channel_id,
                )
                continue

        if not prompt_for_dispatch:
            _send_structured(
                codex_home=codex_home,
                recipient=recipient,
                session_id=target_sid,
                kind="error",
                text="No instruction text was provided.",
                max_message_chars=max_message_chars,
                dry_run=dry_run,
                message_index=message_index,
                agent=session_agent,
                telegram_message_thread_id=row_telegram_thread_id,
                telegram_chat_id=row_telegram_chat_id,
                discord_channel_id=row_reply_discord_channel_id,
            )
            continue

        dispatch_mode, response = _dispatch_prompt_to_session(
            target_sid=target_sid,
            prompt=prompt_for_dispatch,
            session_rec=rec if isinstance(rec, dict) else None,
            codex_home=codex_home,
            resume_timeout_s=resume_timeout_s,
            agent=session_agent,
        )
        dispatch_reason = rec.get("last_dispatch_reason") if isinstance(rec, dict) and isinstance(rec.get("last_dispatch_reason"), str) else None
        _trace(
            f"dispatch mode={dispatch_mode} sid={target_sid} "
            f"reason={dispatch_reason or '-'} strict_tmux={strict_tmux}"
        )
        context_followup_text = _context_followup_hint(
            transport=row_transport or "imessage",
            telegram_message_thread_id=row_telegram_thread_id,
            discord_channel_id=row_discord_channel_id,
            discord_parent_channel_id=row_discord_parent_channel_id,
        )
        attachment_notice_prefix = f"{attachment_notice_text} " if attachment_notice_text else ""

        def _session_surface_text(base_text: str) -> str:
            return _append_surface_onboarding_hint(
                registry=registry,
                text=base_text,
                bucket="session",
                transport=row_transport or "imessage",
                recipient=recipient,
                telegram_chat_id=row_telegram_chat_id,
                telegram_message_thread_id=row_telegram_thread_id,
                discord_channel_id=row_discord_channel_id,
                discord_parent_channel_id=row_discord_parent_channel_id,
            )

        def _accepted_dispatch_text(mode: str) -> str:
            if row_transport == "discord" and session_agent == "pi":
                desktop_attention_state = _emit_desktop_visibility_for_discord_prompt(
                    codex_home=codex_home,
                    registry=registry,
                    session_id=target_sid,
                    session_rec=rec if isinstance(rec, dict) else None,
                    prompt=prompt_for_dispatch,
                    agent=session_agent,
                )
                if desktop_attention_state == "inline_visible":
                    return _session_surface_text(
                        f"{attachment_notice_prefix}Got it — sent to @{_session_ref(target_sid)}. "
                        f"It's now visible on the desktop.{context_followup_text}"
                    )
                if desktop_attention_state in {"notification_visible", "attention_badged", "waiting_for_user"}:
                    return _session_surface_text(
                        f"{attachment_notice_prefix}Got it — sent to @{_session_ref(target_sid)}. "
                        f"It's queued in the session and marked for desktop attention.{context_followup_text}"
                    )
            if mode == "tmux":
                return _session_surface_text(
                    f"{attachment_notice_prefix}Sent to tmux pane for @{_session_ref(target_sid)}. "
                    f"Check progress on your Mac.{context_followup_text}"
                )
            if mode == "tmux_unconfirmed":
                return _session_surface_text(
                    f"{attachment_notice_prefix}Sent to tmux pane for @{_session_ref(target_sid)}. "
                    f"Execution may be delayed; check the pane on your Mac.{context_followup_text}"
                )
            return _session_surface_text(
                f"{attachment_notice_prefix}Sent to {_agent_display_name(agent=session_agent)} session @{_session_ref(target_sid)}. "
                f"Waiting for output.{context_followup_text}"
            )

        discord_prompt_lifecycle = row_transport == "discord" and session_agent == "pi"

        def _record_discord_prompt_if_needed() -> None:
            if discord_prompt_lifecycle:
                _record_discord_prompt_acceptance(
                    registry=registry,
                    session_id=target_sid,
                    context_key=row_context_key,
                )

        def _send_discord_failed_lifecycle(error_text: str) -> None:
            if not discord_prompt_lifecycle:
                return
            if not _should_emit_discord_lifecycle_event(
                session_rec=rec if isinstance(rec, dict) else None,
                event_kind="failed",
            ):
                return
            _send_structured(
                codex_home=codex_home,
                recipient=recipient,
                session_id=target_sid,
                kind="failed",
                text=error_text,
                max_message_chars=max_message_chars,
                dry_run=dry_run,
                message_index=message_index,
                agent=session_agent,
                telegram_message_thread_id=row_telegram_thread_id,
                telegram_chat_id=row_telegram_chat_id,
                discord_channel_id=row_reply_discord_channel_id,
                deliver_to_imessage=False,
                deliver_to_telegram=False,
                deliver_to_discord=True,
                discord_lifecycle_event=True,
            )

        if dispatch_mode == "tmux":
            _clear_last_dispatch_error(registry=registry)
            _record_discord_prompt_if_needed()
            _send_structured(
                codex_home=codex_home,
                recipient=recipient,
                session_id=target_sid,
                kind="accepted",
                text=_accepted_dispatch_text("tmux"),
                max_message_chars=max_message_chars,
                dry_run=dry_run,
                message_index=message_index,
                agent=session_agent,
                telegram_message_thread_id=row_telegram_thread_id,
                telegram_chat_id=row_telegram_chat_id,
                discord_channel_id=row_reply_discord_channel_id,
                discord_lifecycle_event=discord_prompt_lifecycle,
            )
            _upsert_session(
                registry=registry,
                session_id=target_sid,
                fields={
                    "agent": session_agent,
                    "awaiting_input": False,
                    "pending_completion": True,
                    "last_resume_ts": int(time.time()),
                    "pending_request_user_input": None,
                    "last_dispatch_reason": None,
                },
            )
            continue

        if dispatch_mode == "tmux_unconfirmed":
            _clear_last_dispatch_error(registry=registry)
            _record_discord_prompt_if_needed()
            _send_structured(
                codex_home=codex_home,
                recipient=recipient,
                session_id=target_sid,
                kind="accepted",
                text=_accepted_dispatch_text("tmux_unconfirmed"),
                max_message_chars=max_message_chars,
                dry_run=dry_run,
                message_index=message_index,
                agent=session_agent,
                telegram_message_thread_id=row_telegram_thread_id,
                telegram_chat_id=row_telegram_chat_id,
                discord_channel_id=row_reply_discord_channel_id,
                discord_lifecycle_event=discord_prompt_lifecycle,
            )
            _upsert_session(
                registry=registry,
                session_id=target_sid,
                fields={
                    "agent": session_agent,
                    "awaiting_input": False,
                    "pending_completion": True,
                    "last_resume_ts": int(time.time()),
                    "pending_request_user_input": None,
                    "last_dispatch_reason": dispatch_reason,
                },
            )
            continue

        if dispatch_mode in {"tmux_failed", "tmux_stale"}:
            _set_last_dispatch_error(
                registry=registry,
                session_id=target_sid,
                mode=dispatch_mode,
                reason=dispatch_reason,
            )
            allow_resume_override = _should_resume_fallback_for_tmux_dispatch(
                mode=dispatch_mode,
                reason=dispatch_reason,
            )
            if strict_tmux and not allow_resume_override:
                preserved_pane = ""
                if isinstance(rec, dict):
                    rec_pane = rec.get("tmux_pane")
                    if isinstance(rec_pane, str):
                        preserved_pane = rec_pane
                if dispatch_mode == "tmux_stale":
                    preserved_pane = ""
                failure_text = _dispatch_failure_text(
                    session_id=target_sid,
                    mode=dispatch_mode,
                    reason=dispatch_reason,
                )
                _send_structured(
                    codex_home=codex_home,
                    recipient=recipient,
                    session_id=target_sid,
                    kind="error",
                    text=failure_text,
                    max_message_chars=max_message_chars,
                    dry_run=dry_run,
                    message_index=message_index,
                    agent=session_agent,
                    telegram_message_thread_id=row_telegram_thread_id,
                    telegram_chat_id=row_telegram_chat_id,
                    discord_channel_id=row_reply_discord_channel_id,
                    deliver_to_discord=not discord_prompt_lifecycle,
                )
                _send_discord_failed_lifecycle(failure_text)
                _update_active_prompt_lifecycle(
                    registry=registry,
                    session_id=target_sid,
                    status="failed",
                )
                _upsert_session(
                    registry=registry,
                    session_id=target_sid,
                    fields={
                        "agent": session_agent,
                        "tmux_pane": preserved_pane,
                        "awaiting_input": True,
                        "pending_completion": True,
                        "pending_request_user_input": rec.get("pending_request_user_input") if isinstance(rec, dict) else None,
                        "last_dispatch_reason": dispatch_reason,
                    },
                )
                continue

            fallback_cwd = rec.get("cwd") if isinstance(rec, dict) and isinstance(rec.get("cwd"), str) else None
            preserved_pane = ""
            if dispatch_mode != "tmux_stale" and isinstance(rec, dict):
                rec_pane = rec.get("tmux_pane")
                if isinstance(rec_pane, str):
                    preserved_pane = rec_pane
            resume_mode, response = _dispatch_resume_to_session(
                target_sid=target_sid,
                prompt=prompt_for_dispatch,
                session_rec=rec if isinstance(rec, dict) else None,
                codex_home=codex_home,
                resume_timeout_s=resume_timeout_s,
                agent=session_agent,
            )
            if resume_mode == "resume_unconfirmed":
                _clear_last_dispatch_error(registry=registry)
                _record_discord_prompt_if_needed()
                _send_structured(
                    codex_home=codex_home,
                    recipient=recipient,
                    session_id=target_sid,
                    kind="accepted",
                    text=_accepted_dispatch_text("resume_unconfirmed"),
                    max_message_chars=max_message_chars,
                    dry_run=dry_run,
                    message_index=message_index,
                    agent=session_agent,
                    telegram_message_thread_id=row_telegram_thread_id,
                    telegram_chat_id=row_telegram_chat_id,
                    discord_channel_id=row_reply_discord_channel_id,
                    discord_lifecycle_event=discord_prompt_lifecycle,
                )
                _upsert_session(
                    registry=registry,
                    session_id=target_sid,
                    fields={
                        "agent": session_agent,
                        "tmux_pane": preserved_pane,
                        "awaiting_input": False,
                        "pending_completion": True,
                        "last_resume_ts": int(time.time()),
                        "pending_request_user_input": None,
                        "last_dispatch_reason": dispatch_reason,
                    },
                )
                continue
            if not response:
                failure_text = f"No response from {_agent_display_name(agent=session_agent).lower()} resume. Check session logs."
                _send_structured(
                    codex_home=codex_home,
                    recipient=recipient,
                    session_id=target_sid,
                    kind="error",
                    text=failure_text,
                    max_message_chars=max_message_chars,
                    dry_run=dry_run,
                    message_index=message_index,
                    agent=session_agent,
                    telegram_message_thread_id=row_telegram_thread_id,
                    telegram_chat_id=row_telegram_chat_id,
                    discord_channel_id=row_reply_discord_channel_id,
                    deliver_to_discord=not discord_prompt_lifecycle,
                )
                _send_discord_failed_lifecycle(failure_text)
                _update_active_prompt_lifecycle(
                    registry=registry,
                    session_id=target_sid,
                    status="failed",
                )
                _upsert_session(
                    registry=registry,
                    session_id=target_sid,
                    fields={
                        "agent": session_agent,
                        "tmux_pane": preserved_pane,
                        "awaiting_input": False,
                        "pending_completion": False,
                        "pending_request_user_input": None,
                        "last_dispatch_reason": dispatch_reason,
                    },
                )
                continue

            _record_discord_prompt_if_needed()
            _send_structured(
                codex_home=codex_home,
                recipient=recipient,
                session_id=target_sid,
                kind="responded",
                text=response,
                max_message_chars=max_message_chars,
                dry_run=dry_run,
                message_index=message_index,
                agent=session_agent,
                telegram_message_thread_id=row_telegram_thread_id,
                telegram_chat_id=row_telegram_chat_id,
                discord_channel_id=row_reply_discord_channel_id,
                discord_lifecycle_event=discord_prompt_lifecycle,
            )
            _update_active_prompt_lifecycle(
                registry=registry,
                session_id=target_sid,
                status="completed",
            )
            _upsert_session(
                registry=registry,
                session_id=target_sid,
                fields={
                    "agent": session_agent,
                    "tmux_pane": preserved_pane,
                    "awaiting_input": False,
                    "pending_completion": False,
                    "last_response_ts": int(time.time()),
                    "pending_request_user_input": None,
                    "last_dispatch_reason": dispatch_reason,
                },
            )
            continue

        _clear_last_dispatch_error(registry=registry)
        if dispatch_mode == "resume_unconfirmed":
            _record_discord_prompt_if_needed()
            _send_structured(
                codex_home=codex_home,
                recipient=recipient,
                session_id=target_sid,
                kind="accepted",
                text=_accepted_dispatch_text("resume_unconfirmed"),
                max_message_chars=max_message_chars,
                dry_run=dry_run,
                message_index=message_index,
                agent=session_agent,
                telegram_message_thread_id=row_telegram_thread_id,
                telegram_chat_id=row_telegram_chat_id,
                discord_channel_id=row_reply_discord_channel_id,
                discord_lifecycle_event=discord_prompt_lifecycle,
            )
            _upsert_session(
                registry=registry,
                session_id=target_sid,
                fields={
                    "agent": session_agent,
                    "awaiting_input": False,
                    "pending_completion": True,
                    "last_resume_ts": int(time.time()),
                    "pending_request_user_input": None,
                    "last_dispatch_reason": None,
                },
            )
            continue
        if not response:
            failure_text = f"No response from {_agent_display_name(agent=session_agent).lower()} resume. Check session logs."
            _send_structured(
                codex_home=codex_home,
                recipient=recipient,
                session_id=target_sid,
                kind="error",
                text=failure_text,
                max_message_chars=max_message_chars,
                dry_run=dry_run,
                message_index=message_index,
                agent=session_agent,
                telegram_message_thread_id=row_telegram_thread_id,
                telegram_chat_id=row_telegram_chat_id,
                discord_channel_id=row_reply_discord_channel_id,
                deliver_to_discord=not discord_prompt_lifecycle,
            )
            _send_discord_failed_lifecycle(failure_text)
            _update_active_prompt_lifecycle(
                registry=registry,
                session_id=target_sid,
                status="failed",
            )
            continue

        _record_discord_prompt_if_needed()
        _send_structured(
            codex_home=codex_home,
            recipient=recipient,
            session_id=target_sid,
            kind="responded",
            text=response,
            max_message_chars=max_message_chars,
            dry_run=dry_run,
            message_index=message_index,
            agent=session_agent,
            telegram_message_thread_id=row_telegram_thread_id,
                telegram_chat_id=row_telegram_chat_id,
                discord_channel_id=row_reply_discord_channel_id,
                discord_lifecycle_event=discord_prompt_lifecycle,
        )

        _update_active_prompt_lifecycle(
            registry=registry,
            session_id=target_sid,
            status="completed",
        )
        _upsert_session(
            registry=registry,
            session_id=target_sid,
            fields={
                "agent": session_agent,
                "awaiting_input": False,
                "pending_completion": False,
                "last_response_ts": int(time.time()),
                "pending_request_user_input": None,
                "last_dispatch_reason": None,
            },
        )

    _save_registry(codex_home=codex_home, registry=registry)
    _save_message_index(codex_home=codex_home, index=message_index)
    return last_rowid

def _process_inbound_telegram_replies(
    *,
    codex_home: Path,
    recipient: str,
    after_update_id: int,
    max_message_chars: int,
    min_prefix: int,
    dry_run: bool,
    resume_timeout_s: float | None = None,
    trace: bool = False,
) -> int:
    token = _telegram_bot_token()
    accept_all_chats = _telegram_accept_all_chats()
    chat_ids = _telegram_chat_ids()
    if not isinstance(token, str) or not token.strip():
        return after_update_id
    if not chat_ids and not accept_all_chats:
        return after_update_id

    updates = _fetch_telegram_updates(
        token=token.strip(),
        chat_ids=None if accept_all_chats else chat_ids,
        after_update_id=after_update_id,
    )
    if not updates:
        return after_update_id
    update_reply_text_map = {
        int(update_id): reply_text for update_id, _text, reply_text, _thread_id, _chat_id, _sender_user_id in updates
    }
    update_context_map: dict[int, dict[str, Any]] = {
        int(update_id): {
            "transport": "telegram",
            "telegram_chat_id": source_chat_id,
            "telegram_message_thread_id": _normalize_telegram_thread_id(thread_id),
            "telegram_sender_user_id": sender_user_id,
        }
        for update_id, _text, _reply_text, thread_id, source_chat_id, sender_user_id in updates
    }

    def _fetch_virtual_replies(*, conn: sqlite3.Connection, after_rowid: int, handle_ids: list[str]) -> list[tuple[int, str, str | None]]:
        del conn, handle_ids
        return [
            (update_id, text, None)
            for update_id, text, _reply_text, _thread_id, _chat_id, _sender_user_id in updates
            if int(update_id) > int(after_rowid)
        ]

    def _empty_reference_guids(*, conn: sqlite3.Connection, rowid: int, fallback_guid: str | None) -> list[str]:
        del conn, rowid, fallback_guid
        return []

    def _virtual_reference_texts(*, conn: sqlite3.Connection, rowid: int, fallback_guid: str | None) -> list[str]:
        del conn, fallback_guid
        reply_text = update_reply_text_map.get(int(rowid))
        if isinstance(reply_text, str) and reply_text.strip():
            return [reply_text.strip()]
        return []

    def _virtual_row_contexts(*, conn: sqlite3.Connection, after_rowid: int, handle_ids: list[str]) -> dict[int, dict[str, Any]]:
        del conn, handle_ids
        return {
            int(update_id): context
            for update_id, context in update_context_map.items()
            if int(update_id) > int(after_rowid)
        }

    temp_conn = sqlite3.connect(":memory:")
    try:
        return _process_inbound_replies(
            codex_home=codex_home,
            conn=temp_conn,
            recipient=recipient,
            handle_ids=[],
            after_rowid=after_update_id,
            max_message_chars=max_message_chars,
            min_prefix=min_prefix,
            dry_run=dry_run,
            resume_timeout_s=resume_timeout_s,
            trace=trace,
            fetch_replies_fn=_fetch_virtual_replies,
            reference_guids_fn=_empty_reference_guids,
            reference_texts_fn=_virtual_reference_texts,
            row_contexts_fn=_virtual_row_contexts,
        )
    finally:
        try:
            temp_conn.close()
        except Exception:
            pass


def _process_outbound(
    *,
    codex_home: Path,
    recipient: str,
    max_message_chars: int,
    dry_run: bool,
    files_cursor: dict[str, int],
    seen_needs_input_call_ids: dict[str, int],
) -> tuple[dict[str, int], dict[str, int]]:
    registry = _load_registry(codex_home=codex_home)
    message_index = _load_message_index(codex_home=codex_home)

    session_paths: list[Path] = []
    seen_session_paths: set[str] = set()
    for agent_name in sorted(_SUPPORTED_AGENTS):
        agent_home = _lookup_agent_home_path(agent=agent_name, current_home=codex_home)
        for path in _find_all_session_files(codex_home=agent_home, agent=agent_name):
            path_key = str(path)
            if path_key in seen_session_paths:
                continue
            seen_session_paths.add(path_key)
            session_paths.append(path)
    session_paths.sort(key=lambda p: p.stat().st_mtime if p.exists() else 0)

    session_id_cache: dict[str, str | None] = {}
    call_id_to_name: dict[str, str] = {}

    active_keys = {str(path) for path in session_paths}
    for stale in list(files_cursor.keys()):
        if stale not in active_keys:
            files_cursor.pop(stale, None)

    for session_path in session_paths:
        key = str(session_path)
        offset = files_cursor.get(key, 0)

        # On first sight, tail from end by default to avoid replaying old history.
        # If this session is already awaiting input/pending completion in registry,
        # rewind to start so we can recover missed notifications after restarts.
        if key not in files_cursor:
            start_from_head = False
            sid = session_id_cache.get(key)
            if sid is None:
                session_id_cache[key] = outbound._read_session_id(session_path=session_path)
                sid = session_id_cache.get(key)
            if isinstance(sid, str) and sid.strip():
                sessions = registry.get("sessions")
                rec = sessions.get(sid.strip()) if isinstance(sessions, dict) else None
                if isinstance(rec, dict) and (
                    rec.get("awaiting_input") is True or rec.get("pending_completion") is True
                ):
                    start_from_head = True

            if not start_from_head:
                try:
                    offset = session_path.stat().st_size
                except Exception:
                    offset = 0

        new_offset = _process_session_file(
            codex_home=codex_home,
            session_path=session_path,
            offset=offset,
            recipient=recipient,
            max_message_chars=max_message_chars,
            dry_run=dry_run,
            registry=registry,
            message_index=message_index,
            session_id_cache=session_id_cache,
            call_id_to_name=call_id_to_name,
            seen_needs_input_call_ids=seen_needs_input_call_ids,
        )
        files_cursor[key] = new_offset

    _save_registry(codex_home=codex_home, registry=registry)
    _save_message_index(codex_home=codex_home, index=message_index)

    return files_cursor, seen_needs_input_call_ids


def _normalize_recipient(raw: str) -> str:
    return outbound._normalize_recipient(raw)


def _open_chat_db(codex_home: Path) -> sqlite3.Connection | None:
    chat_db = _chat_db_path(codex_home=codex_home)
    if not chat_db.exists():
        _warn_chat_db_once(detail=f"chat DB not found at {chat_db}")
        return None

    try:
        conn = sqlite3.connect(f"file:{chat_db}?mode=ro", uri=True)
        try:
            conn.execute("PRAGMA query_only = 1")
        except Exception:
            pass
        try:
            conn.execute("PRAGMA busy_timeout = 1000")
        except Exception:
            pass
        _clear_chat_db_warning()
        return conn
    except Exception as exc:
        _warn_chat_db_once(detail=f"cannot open {chat_db}: {type(exc).__name__}: {exc}")
        return None


def _ensure_inbound_cursor_seed(
    *,
    codex_home: Path,
    conn: sqlite3.Connection,
    recipient: str | None,
    handle_ids: list[str],
) -> int:
    cursor_path = _inbound_cursor_path(codex_home=codex_home)
    cursor_state = _load_inbound_cursor_state(codex_home=codex_home)
    last_rowid = _load_inbound_cursor(codex_home=codex_home)
    recipient_norm = _normalize_recipient(recipient) if isinstance(recipient, str) else ""
    handle_ids_norm = _normalize_handle_ids(handle_ids)

    # Guard against replay floods: cursor rowid 0 with existing history replays old texts.
    # Also reseed if the cursor was recorded for a different recipient/handle scope.
    should_seed = False
    if not cursor_path.exists() or not isinstance(cursor_state, dict):
        should_seed = True
    elif last_rowid <= 0:
        should_seed = True
    else:
        saved_recipient = cursor_state.get("recipient")
        if (
            isinstance(saved_recipient, str)
            and saved_recipient.strip()
            and recipient_norm
            and saved_recipient.strip() != recipient_norm
        ):
            should_seed = True
        saved_handles = cursor_state.get("handle_ids")
        saved_handles_norm = _normalize_handle_ids(saved_handles if isinstance(saved_handles, list) else None)
        if saved_handles_norm and handle_ids_norm and saved_handles_norm != handle_ids_norm:
            should_seed = True

    if not should_seed:
        return last_rowid

    last_rowid = reply._max_rowid(conn)
    _save_inbound_cursor(
        codex_home=codex_home,
        rowid=last_rowid,
        recipient=recipient_norm,
        handle_ids=handle_ids_norm,
    )
    return last_rowid


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(add_help=True)
    sub = parser.add_subparsers(dest="cmd", required=True)
    default_agent = _normalize_agent(agent=os.environ.get("AGENT_CHAT_AGENT"))

    def _add_agent_arg(cmd_parser: argparse.ArgumentParser) -> None:
        cmd_parser.add_argument(
            "--agent",
            default=default_agent,
            choices=sorted(_SUPPORTED_AGENTS),
            help="Agent runtime to integrate (codex, claude, or pi)",
        )

    run = sub.add_parser("run", help="Run control plane forever")
    _add_agent_arg(run)
    run.add_argument("--poll", type=float, default=float(os.environ.get("AGENT_CHAT_INBOUND_POLL_S", "0.5")))
    run.add_argument("--dry-run", action="store_true")
    run.add_argument("--trace", action="store_true", help="Emit per-message routing trace logs")

    once = sub.add_parser("once", help="Run one control-plane cycle")
    _add_agent_arg(once)
    once.add_argument("--dry-run", action="store_true")
    once.add_argument("--trace", action="store_true", help="Emit per-message routing trace logs")

    notify_cmd = sub.add_parser("notify", help="Process a single notify payload JSON")
    _add_agent_arg(notify_cmd)
    notify_cmd.add_argument("payload", nargs="?", default="")
    notify_cmd.add_argument("--dry-run", action="store_true")

    doctor_cmd = sub.add_parser("doctor", help="Show control-plane health diagnostics")
    _add_agent_arg(doctor_cmd)
    doctor_cmd.add_argument("--json", action="store_true", help="Emit JSON diagnostics")
    setup_notify = sub.add_parser(
        "setup-notify-hook",
        help="Install/update notify hook for Codex, Claude, or Pi",
    )
    _add_agent_arg(setup_notify)
    setup_notify.add_argument(
        "--recipient",
        default="",
        help="Destination phone/email; falls back to AGENT_IMESSAGE_TO",
    )
    setup_notify.add_argument(
        "--python-bin",
        default=str(Path(sys.executable).resolve()),
        help="Python binary to invoke from notify hook (defaults to current interpreter)",
    )
    setup_cmd = sub.add_parser(
        "setup-permissions",
        help="Open Full Disk Access settings and wait for chat.db readability",
    )
    _add_agent_arg(setup_cmd)
    setup_cmd.add_argument(
        "--timeout",
        type=float,
        default=float(_DEFAULT_SETUP_PERMISSIONS_TIMEOUT_S),
        help=f"Max seconds to wait for chat.db readability (default {_DEFAULT_SETUP_PERMISSIONS_TIMEOUT_S})",
    )
    setup_cmd.add_argument(
        "--poll",
        type=float,
        default=float(_DEFAULT_SETUP_PERMISSIONS_POLL_S),
        help=f"Polling interval seconds while waiting (default {_DEFAULT_SETUP_PERMISSIONS_POLL_S})",
    )
    setup_cmd.add_argument(
        "--no-open",
        action="store_true",
        help="Do not auto-open System Settings",
    )
    setup_launchd = sub.add_parser(
        "setup-launchd",
        help="Install and start a launchd LaunchAgent for automatic startup",
    )
    _add_agent_arg(setup_launchd)
    setup_launchd.add_argument(
        "--label",
        default=os.environ.get("AGENT_CHAT_LAUNCHD_LABEL", _DEFAULT_LAUNCHD_LABEL),
        help=f"Launchd label (default {_DEFAULT_LAUNCHD_LABEL})",
    )
    setup_launchd.add_argument(
        "--recipient",
        default="",
        help="Destination phone/email; falls back to AGENT_IMESSAGE_TO",
    )
    setup_launchd.add_argument(
        "--python-bin",
        default=str(Path(sys.executable).resolve()),
        help="Python binary for launchd ProgramArguments[0] (defaults to current interpreter)",
    )
    setup_launchd.add_argument(
        "--skip-permissions",
        action="store_true",
        help="Skip upfront chat.db permission setup check",
    )
    setup_launchd.add_argument(
        "--timeout",
        type=float,
        default=float(_DEFAULT_SETUP_PERMISSIONS_TIMEOUT_S),
        help=f"Max seconds to wait for chat.db readability (default {_DEFAULT_SETUP_PERMISSIONS_TIMEOUT_S})",
    )
    setup_launchd.add_argument(
        "--poll",
        type=float,
        default=float(_DEFAULT_SETUP_PERMISSIONS_POLL_S),
        help=f"Polling interval seconds while waiting (default {_DEFAULT_SETUP_PERMISSIONS_POLL_S})",
    )
    setup_launchd.add_argument(
        "--no-open",
        action="store_true",
        help="Do not auto-open System Settings",
    )
    setup_launchd.add_argument(
        "--repair-tcc",
        action="store_true",
        help=(
            "When launchd remains denied, reset Full Disk Access approval for the runtime "
            "bundle id and rerun permission setup automatically"
        ),
    )
    guided_setup = sub.add_parser(
        "guided-setup",
        help="Run an interactive onboarding flow for one runtime + one transport",
    )
    guided_setup.add_argument("--agent", default=None, choices=sorted(_SUPPORTED_AGENTS), help="Runtime to configure")
    guided_setup.add_argument(
        "--transport",
        default=None,
        choices=list(_GUIDED_SETUP_TRANSPORTS),
        help="Transport to configure (guided setup supports one transport at a time)",
    )
    guided_setup.add_argument("--recipient", default="", help="iMessage destination for imessage transport")
    guided_setup.add_argument("--telegram-token", default="", help="Telegram bot token")
    guided_setup.add_argument("--telegram-chat-id", default="", help="Telegram group/topic chat id")
    guided_setup.add_argument("--discord-token", default="", help="Discord bot token")
    guided_setup.add_argument("--discord-control-channel-id", default="", help="Discord control channel id")
    discord_session_mode = guided_setup.add_mutually_exclusive_group()
    discord_session_mode.add_argument(
        "--discord-session-channels",
        dest="discord_session_channels",
        action="store_true",
        help="Enable auto-created per-session Discord channels",
    )
    discord_session_mode.add_argument(
        "--no-discord-session-channels",
        dest="discord_session_channels",
        action="store_false",
        help="Disable auto-created per-session Discord channels",
    )
    guided_setup.set_defaults(discord_session_channels=None)
    guided_setup.add_argument(
        "--discord-session-category-id",
        default="",
        help="Optional Discord category id for per-session channels",
    )
    guided_setup.add_argument(
        "--env-file",
        default="",
        help="Shell env file to create/update (defaults to .env.telegram.local for Telegram, else .env.agent-chat.local)",
    )
    guided_setup.add_argument(
        "--python-bin",
        default=str(Path(sys.executable).resolve()),
        help="Python binary to use for setup commands (defaults to current interpreter)",
    )
    guided_setup.add_argument(
        "--no-open",
        action="store_true",
        help="Do not auto-open System Settings during iMessage permission setup",
    )

    args = parser.parse_args(argv)

    agent = _normalize_agent(agent=getattr(args, "agent", None))
    os.environ["AGENT_CHAT_AGENT"] = agent

    if args.cmd in {"setup-notify-hook", "setup-launchd"}:
        tmux_bin, tmux_setup_err = _ensure_tmux_available_for_setup()
        if isinstance(tmux_setup_err, str):
            sys.stdout.write(tmux_setup_err)
            return 1
        if isinstance(tmux_bin, str) and tmux_bin.strip():
            os.environ["AGENT_CHAT_TMUX_BIN"] = tmux_bin.strip()

    recipient_raw = os.environ.get("AGENT_IMESSAGE_TO")
    codex_home = _agent_home_path(agent=agent)
    recipient = _normalize_recipient(recipient_raw) if isinstance(recipient_raw, str) and recipient_raw.strip() else ""
    transport_mode = _transport_mode()
    trace_enabled = bool(getattr(args, "trace", False)) or _env_enabled("AGENT_CHAT_TRACE", default=False)

    if args.cmd == "doctor":
        doctor_recipient: str | None = recipient if recipient else recipient_raw
        return _run_doctor(codex_home=codex_home, recipient=doctor_recipient, as_json=bool(args.json))
    if args.cmd == "guided-setup":
        return _run_guided_setup(
            agent=str(args.agent) if isinstance(args.agent, str) else None,
            transport=str(args.transport) if isinstance(args.transport, str) else None,
            recipient=str(args.recipient) if isinstance(args.recipient, str) else None,
            telegram_token=str(args.telegram_token) if isinstance(args.telegram_token, str) else None,
            telegram_chat_id=str(args.telegram_chat_id) if isinstance(args.telegram_chat_id, str) else None,
            discord_token=str(args.discord_token) if isinstance(args.discord_token, str) else None,
            discord_control_channel_id=(
                str(args.discord_control_channel_id) if isinstance(args.discord_control_channel_id, str) else None
            ),
            discord_session_channels=args.discord_session_channels,
            discord_session_category_id=(
                str(args.discord_session_category_id) if isinstance(args.discord_session_category_id, str) else None
            ),
            env_file=str(args.env_file) if isinstance(args.env_file, str) else None,
            python_bin=str(args.python_bin),
            open_settings=not bool(args.no_open),
        )
    if args.cmd == "setup-notify-hook":
        notify_recipient_raw = args.recipient.strip() if isinstance(args.recipient, str) else ""
        if not notify_recipient_raw:
            notify_recipient_raw = recipient_raw.strip() if isinstance(recipient_raw, str) else ""
        notify_recipient = _normalize_recipient(notify_recipient_raw) if notify_recipient_raw else ""
        return _run_setup_notify_hook(
            codex_home=codex_home,
            recipient=notify_recipient,
            python_bin=str(args.python_bin),
            script_path=Path(__file__).resolve(),
        )
    if args.cmd == "setup-permissions":
        if not _transport_imessage_enabled(mode=transport_mode):
            sys.stdout.write(
                "Full Disk Access setup is only required when AGENT_CHAT_TRANSPORT includes iMessage "
                "(imessage or both).\n"
            )
            return 0
        launchd_label = (
            os.environ.get("AGENT_CHAT_LAUNCHD_LABEL", _DEFAULT_LAUNCHD_LABEL).strip()
            or _DEFAULT_LAUNCHD_LABEL
        )
        launchd_runtime_python, launchd_permission_app = _launchd_runtime_targets_from_plist(
            label=launchd_label
        )
        setup_kwargs: dict[str, Any] = {}
        if isinstance(launchd_runtime_python, str) and launchd_runtime_python.strip():
            setup_kwargs["probe_python_bin"] = launchd_runtime_python.strip()
        if isinstance(launchd_permission_app, str) and launchd_permission_app.strip():
            setup_kwargs["permission_app_path"] = Path(launchd_permission_app.strip())
        return _run_setup_permissions(
            codex_home=codex_home,
            timeout_s=float(args.timeout),
            poll_s=float(args.poll),
            open_settings=not bool(args.no_open),
            **setup_kwargs,
        )
    if args.cmd == "setup-launchd":
        launchd_recipient_raw = args.recipient.strip() if isinstance(args.recipient, str) else ""
        if not launchd_recipient_raw:
            launchd_recipient_raw = recipient_raw.strip() if isinstance(recipient_raw, str) else ""
        launchd_recipient = _normalize_recipient(launchd_recipient_raw) if launchd_recipient_raw else ""
        return _run_setup_launchd(
            codex_home=codex_home,
            recipient=launchd_recipient,
            label=str(args.label),
            python_bin=str(args.python_bin),
            script_path=Path(__file__).resolve(),
            setup_permissions=not bool(args.skip_permissions),
            timeout_s=float(args.timeout),
            poll_s=float(args.poll),
            open_settings=not bool(args.no_open),
            repair_tcc=bool(args.repair_tcc),
        )

    if args.cmd == "notify":
        payload = args.payload.strip()
        if not payload:
            return 0
        _handle_notify_payload(
            codex_home=codex_home,
            recipient=recipient,
            payload_text=payload,
            dry_run=bool(args.dry_run),
        )
        return 0

    if (
        not recipient
        and not _transport_telegram_enabled(mode=transport_mode)
        and not _transport_discord_enabled(mode=transport_mode)
    ):
        return 0

    lock_handle = _acquire_single_instance_lock(codex_home=codex_home)
    if lock_handle is None:
        return 0

    if args.cmd in {"run", "once"}:
        _warn_stderr(
            "[agent-chat] startup "
            f"script={Path(__file__).resolve()} "
            f"python={sys.executable} "
            f"agent={agent} "
            f"strict_tmux={_strict_tmux_enabled()} "
            f"trace={trace_enabled} "
            f"chat_db={_chat_db_path(codex_home=codex_home)}"
        )

    max_message_chars = _DEFAULT_MAX_MESSAGE_CHARS
    env_max = os.environ.get("AGENT_IMESSAGE_MAX_LEN", "").strip()
    if env_max:
        try:
            max_message_chars = int(env_max)
        except Exception:
            max_message_chars = _DEFAULT_MAX_MESSAGE_CHARS

    min_prefix = _DEFAULT_MIN_PREFIX
    env_min_prefix = os.environ.get("AGENT_CHAT_SESSION_REF_MIN", "").strip()
    if env_min_prefix:
        try:
            min_prefix = max(1, int(env_min_prefix))
        except Exception:
            min_prefix = _DEFAULT_MIN_PREFIX

    resume_timeout_s = _resolve_resume_timeout_s()
    queue_drain_limit = _DEFAULT_QUEUE_DRAIN_LIMIT
    env_queue_limit = os.environ.get("AGENT_CHAT_QUEUE_DRAIN_LIMIT", "").strip()
    if env_queue_limit:
        try:
            queue_drain_limit = max(0, int(env_queue_limit))
        except Exception:
            queue_drain_limit = _DEFAULT_QUEUE_DRAIN_LIMIT

    files_cursor, seen_needs_input_call_ids = _load_outbound_cursor(codex_home=codex_home)

    imessage_enabled = _transport_imessage_enabled(mode=transport_mode)
    conn = _open_chat_db(codex_home) if imessage_enabled else None
    handle_ids = reply._candidate_handle_ids(recipient) if imessage_enabled else []
    inbound_rowid = 0
    if conn is not None:
        inbound_rowid = _ensure_inbound_cursor_seed(
            codex_home=codex_home,
            conn=conn,
            recipient=recipient,
            handle_ids=handle_ids,
        )
    telegram_update_id = _load_telegram_inbound_cursor(codex_home=codex_home)
    discord_cursor_state = _load_discord_inbound_cursor(codex_home=codex_home)
    discord_inbound_rowid = 0
    discord_channels = discord_cursor_state.get("channels") if isinstance(discord_cursor_state, dict) else {}
    if isinstance(discord_channels, dict):
        for value in discord_channels.values():
            try:
                discord_inbound_rowid = max(discord_inbound_rowid, int(str(value).strip()))
            except Exception:
                continue

    inbound_retry_s = 30.0
    env_retry = os.environ.get("AGENT_CHAT_INBOUND_RETRY_S", "").strip()
    if env_retry:
        try:
            inbound_retry_s = max(0.0, float(env_retry))
        except Exception:
            inbound_retry_s = 30.0

    next_inbound_retry_monotonic = 0.0

    def _ensure_inbound_ready(*, now_monotonic: float | None = None) -> bool:
        nonlocal conn, inbound_rowid, next_inbound_retry_monotonic

        if not imessage_enabled:
            return False
        if conn is not None:
            return True

        now = now_monotonic if isinstance(now_monotonic, float) else time.monotonic()
        if now < next_inbound_retry_monotonic:
            return False

        next_inbound_retry_monotonic = now + inbound_retry_s
        conn = _open_chat_db(codex_home)
        if conn is None:
            return False

        inbound_rowid = _ensure_inbound_cursor_seed(
            codex_home=codex_home,
            conn=conn,
            recipient=recipient,
            handle_ids=handle_ids,
        )
        return True

    if imessage_enabled:
        _ensure_inbound_ready(now_monotonic=0.0)

    def cycle() -> None:
        nonlocal files_cursor, seen_needs_input_call_ids, inbound_rowid, telegram_update_id, discord_inbound_rowid

        _drain_fallback_queue(
            codex_home=codex_home,
            dry_run=bool(args.dry_run),
            max_items=queue_drain_limit,
        )

        files_cursor, seen_needs_input_call_ids = _process_outbound(
            codex_home=codex_home,
            recipient=recipient,
            max_message_chars=max_message_chars,
            dry_run=bool(args.dry_run),
            files_cursor=files_cursor,
            seen_needs_input_call_ids=seen_needs_input_call_ids,
        )
        _save_outbound_cursor(
            codex_home=codex_home,
            files=files_cursor,
            seen_needs_input_call_ids=seen_needs_input_call_ids,
        )

        if imessage_enabled and _ensure_inbound_ready():
            conn_ready = conn
            if conn_ready is None:
                return
            inbound_rowid = _process_inbound_replies(
                codex_home=codex_home,
                conn=conn_ready,
                recipient=recipient,
                handle_ids=handle_ids,
                after_rowid=inbound_rowid,
                max_message_chars=max_message_chars,
                min_prefix=min_prefix,
                dry_run=bool(args.dry_run),
                resume_timeout_s=resume_timeout_s,
                trace=trace_enabled,
            )
            _save_inbound_cursor(
                codex_home=codex_home,
                rowid=inbound_rowid,
                recipient=recipient,
                handle_ids=handle_ids,
            )

        if _transport_telegram_enabled(mode=transport_mode):
            next_telegram_update_id = _process_inbound_telegram_replies(
                codex_home=codex_home,
                recipient=recipient,
                after_update_id=telegram_update_id,
                max_message_chars=max_message_chars,
                min_prefix=min_prefix,
                dry_run=bool(args.dry_run),
                resume_timeout_s=resume_timeout_s,
                trace=trace_enabled,
            )
            if next_telegram_update_id != telegram_update_id:
                _save_telegram_inbound_cursor(
                    codex_home=codex_home,
                    last_update_id=next_telegram_update_id,
                )
                telegram_update_id = next_telegram_update_id

        if _transport_discord_enabled(mode=transport_mode):
            discord_inbound_rowid = _process_inbound_discord_replies(
                codex_home=codex_home,
                recipient=recipient,
                after_message_id=discord_inbound_rowid,
                max_message_chars=max_message_chars,
                min_prefix=min_prefix,
                dry_run=bool(args.dry_run),
                resume_timeout_s=resume_timeout_s,
                trace=trace_enabled,
            )

    if args.cmd == "once":
        cycle()
        return 0

    last_scan = 0.0
    while True:
        try:
            now = time.monotonic()
            if now - last_scan >= _SESSION_SCAN_INTERVAL_S:
                last_scan = now

            cycle()
            time.sleep(float(args.poll))
        except KeyboardInterrupt:
            return 0
        except Exception as exc:
            _warn_stderr(
                "[agent-chat] cycle error: "
                f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}"
            )
            time.sleep(float(args.poll))


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except SystemExit:
        raise
    except Exception:
        raise SystemExit(0)
