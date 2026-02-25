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

_MIN_PYTHON_VERSION = (3, 11)
_SESSION_UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_SESSION_STATUS_LINE_UUID_RE = re.compile(
    r"·\s*([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\s*·"
)


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
_DEFAULT_TELEGRAM_API_BASE = "https://api.telegram.org"
_DEFAULT_TMUX_NEW_SESSION_NAME = "agent"
_DEFAULT_TMUX_WINDOW_PREFIX = "agent"
_DEFAULT_SETUP_PERMISSIONS_TIMEOUT_S = 180.0
_DEFAULT_SETUP_PERMISSIONS_POLL_S = 1.0
_LAUNCHD_POST_START_VERIFY_DELAY_S = 0.8
_FULL_DISK_ACCESS_SETTINGS_URL = "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
_DEFAULT_FRIENDLY_PYTHON_APP_NAME = "Codex iMessage Python.app"
_TMUX_BIN_CANDIDATES = (
    "/opt/homebrew/bin/tmux",
    "/usr/local/bin/tmux",
    "/usr/bin/tmux",
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
_DEFAULT_LAUNCHD_LABEL = "com.agent-chat-control-plane"
_INBOUND_DISABLED_LOG_MARKER = "[imessage-control-plane] inbound disabled:"
_INBOUND_RESTORED_LOG_MARKER = "[imessage-control-plane] inbound chat.db access restored."
_TCC_FDA_SERVICE = "SystemPolicyAllFiles"
_TCC_MISMATCH_SUBSTRING = "Failed to match existing code requirement for subject"
_MAX_DOCTOR_PANE_SAMPLE = 8
_HELP_TEXT = (
    "Commands:\n"
    "- list\n"
    "- status @<session_ref>\n"
    "- @<session_ref> <instruction>\n"
    "- new <label>: <instruction>\n"
    "- help"
)

_SUPPORTED_AGENTS = frozenset({"codex", "claude"})

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
            "[imessage-control-plane] inbound disabled: "
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
    raw = os.environ.get("CODEX_IMESSAGE_RESUME_TIMEOUT_S", "").strip()
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
    return _normalize_agent(agent=os.environ.get("CODEX_IMESSAGE_AGENT") or os.environ.get("IMESSAGE_AGENT"))


def _agent_display_name(*, agent: str | None = None) -> str:
    normalized = _normalize_agent(agent=agent if agent is not None else _current_agent())
    return "Claude" if normalized == "claude" else "Codex"


def _agent_from_message_header(*, text: str | None) -> str | None:
    if not isinstance(text, str):
        return None
    m = re.match(r"^\s*\[(codex|claude)\]\b", text, flags=re.IGNORECASE)
    if not m:
        return None
    return _normalize_agent(agent=m.group(1))


def _agent_command_keyword(*, agent: str | None = None) -> str:
    normalized = _normalize_agent(agent=agent if agent is not None else _current_agent())
    return "claude" if normalized == "claude" else "codex"


def _agent_home_path(*, agent: str | None = None) -> Path:
    normalized = _normalize_agent(agent=agent if agent is not None else _current_agent())
    if normalized == "claude":
        return Path(os.environ.get("CLAUDE_HOME", str(Path.home() / ".claude")))
    return Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex")))


def _normalize_fs_path(*, path: Path | str) -> str:
    return os.path.normcase(os.path.abspath(os.path.expanduser(str(path))))


def _lookup_agent_home_path(*, agent: str, current_home: Path) -> Path:
    normalized = _normalize_agent(agent=agent)
    if normalized == "claude":
        override = os.environ.get("CODEX_IMESSAGE_CLAUDE_HOME", "").strip()
        if override:
            return Path(override)
        return _agent_home_path(agent="claude")

    override = os.environ.get("CODEX_IMESSAGE_CODEX_HOME", "").strip()
    if override:
        return Path(override)

    codex_home_env = os.environ.get("CODEX_HOME", "").strip()
    if not codex_home_env:
        return Path.home() / ".codex"

    codex_home = Path(codex_home_env)
    if _current_agent() == "codex":
        return codex_home

    claude_home_env = os.environ.get("CLAUDE_HOME", "").strip()
    current_norm = _normalize_fs_path(path=current_home)
    codex_norm = _normalize_fs_path(path=codex_home)
    claude_norm = _normalize_fs_path(path=claude_home_env) if claude_home_env else ""
    if codex_norm == current_norm or (claude_norm and codex_norm == claude_norm):
        return Path.home() / ".codex"

    return codex_home


def _agent_session_root(*, codex_home: Path, agent: str | None = None) -> Path:
    normalized = _normalize_agent(agent=agent if agent is not None else _current_agent())
    if normalized == "claude":
        projects_path = os.environ.get("CLAUDE_PROJECTS_PATH", "").strip()
        if projects_path:
            return Path(projects_path)
        return codex_home / "projects"
    return codex_home / "sessions"


def _session_path_env_keys(*, agent: str | None = None) -> tuple[str, ...]:
    normalized = _normalize_agent(agent=agent if agent is not None else _current_agent())
    if normalized == "claude":
        return ("CLAUDE_SESSION_PATH", "CLAUDE_TRANSCRIPT_PATH", "CODEX_SESSION_PATH", "CODEX_SESSION_FILE")
    return ("CODEX_SESSION_PATH", "CODEX_SESSION_FILE")


def _shared_control_state_home(*, codex_home: Path) -> Path:
    override = os.environ.get("CODEX_IMESSAGE_STATE_HOME", "").strip()
    if override:
        return Path(override)

    codex_home_env = os.environ.get("CODEX_HOME", "").strip()
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
            "CODEX_IMESSAGE_CONTROL_LOCK",
            str(shared_home / "tmp" / "imessage_control_plane.lock"),
        )
    )


def _chat_db_path(*, codex_home: Path) -> Path:
    _ = codex_home
    env_path = os.environ.get("CODEX_IMESSAGE_CHAT_DB", "").strip()
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
    if _current_agent() == "claude":
        return _notify_hook_status_claude(codex_home=codex_home)

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
        items.append(f"CODEX_IMESSAGE_TO={shlex.quote(recipient_text)}")
    items.append(f"CODEX_IMESSAGE_AGENT={shlex.quote(agent_text)}")

    transport_mode = _transport_mode()
    if transport_mode != "imessage":
        items.append(f"CODEX_IMESSAGE_TRANSPORT={shlex.quote(transport_mode)}")

    if _transport_telegram_enabled(mode=transport_mode):
        token = _telegram_bot_token()
        chat_id = _telegram_chat_id()
        if token:
            items.append(f"CODEX_TELEGRAM_BOT_TOKEN={shlex.quote(token)}")
        if chat_id:
            items.append(f"CODEX_TELEGRAM_CHAT_ID={shlex.quote(chat_id)}")
        api_base_raw = os.environ.get("CODEX_TELEGRAM_API_BASE", "")
        api_base = api_base_raw.strip() if isinstance(api_base_raw, str) else ""
        if api_base:
            items.append(f"CODEX_TELEGRAM_API_BASE={shlex.quote(api_base)}")

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
    telegram_setup_err = _validate_telegram_setup_requirements(transport_mode=transport_mode)
    if isinstance(telegram_setup_err, str):
        sys.stdout.write(telegram_setup_err)
        return 1

    recipient_text = _normalize_recipient(recipient) if recipient.strip() else ""
    if _transport_imessage_enabled(mode=transport_mode) and not recipient_text:
        sys.stdout.write("CODEX_IMESSAGE_TO is required. Provide --recipient or set CODEX_IMESSAGE_TO.\n")
        return 1

    python_text = _resolve_python_bin_for_notify_hook(python_bin=python_bin)
    script_abs = script_path.expanduser().resolve()
    if not script_abs.exists():
        sys.stdout.write(f"Control-plane script not found: {script_abs}\n")
        return 1

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
            "CODEX_IMESSAGE_SESSION_REGISTRY",
            str(codex_home / "tmp" / "imessage_session_registry.json"),
        )
    )


def _message_index_path(*, codex_home: Path) -> Path:
    return Path(
        os.environ.get(
            "CODEX_IMESSAGE_MESSAGE_SESSION_INDEX",
            str(codex_home / "tmp" / "imessage_message_session_index.json"),
        )
    )


def _outbound_cursor_path(*, codex_home: Path) -> Path:
    return Path(
        os.environ.get(
            "CODEX_IMESSAGE_CONTROL_OUTBOUND_CURSOR",
            str(codex_home / "tmp" / "imessage_control_outbound_cursor.json"),
        )
    )


def _inbound_cursor_path(*, codex_home: Path) -> Path:
    shared_home = _shared_control_state_home(codex_home=codex_home)
    return Path(
        os.environ.get(
            "CODEX_IMESSAGE_INBOUND_CURSOR",
            str(shared_home / "tmp" / "imessage_inbound_cursor.json"),
        )
    )


def _queue_path(*, codex_home: Path) -> Path:
    return Path(
        os.environ.get(
            "CODEX_IMESSAGE_QUEUE",
            str(codex_home / "tmp" / "imessage_queue.jsonl"),
        )
    )


def _transport_mode() -> str:
    raw = os.environ.get("CODEX_IMESSAGE_TRANSPORT", "imessage")
    mode = raw.strip().lower() if isinstance(raw, str) else "imessage"
    if mode in {"imessage", "telegram", "both"}:
        return mode
    return "imessage"


def _transport_imessage_enabled(*, mode: str | None = None) -> bool:
    selected = mode if isinstance(mode, str) else _transport_mode()
    return selected in {"imessage", "both"}


def _transport_telegram_enabled(*, mode: str | None = None) -> bool:
    selected = mode if isinstance(mode, str) else _transport_mode()
    return selected in {"telegram", "both"}


def _telegram_bot_token() -> str | None:
    raw = os.environ.get("CODEX_TELEGRAM_BOT_TOKEN", "")
    token = raw.strip() if isinstance(raw, str) else ""
    return token or None


def _telegram_chat_id() -> str | None:
    raw = os.environ.get("CODEX_TELEGRAM_CHAT_ID", "")
    chat_id = raw.strip() if isinstance(raw, str) else ""
    return chat_id or None


def _telegram_bot_token_setup_instructions() -> str:
    return (
        "CODEX_TELEGRAM_BOT_TOKEN is required when CODEX_IMESSAGE_TRANSPORT includes Telegram.\n"
        "How to get a bot token:\n"
        "  1. Open Telegram and chat with @BotFather.\n"
        "  2. Run /newbot to create a bot (or /token for an existing bot).\n"
        "  3. Copy the HTTP API token and export:\n"
        "     CODEX_TELEGRAM_BOT_TOKEN=\"<bot token>\"\n"
    )


def _validate_telegram_setup_requirements(*, transport_mode: str) -> str | None:
    if not _transport_telegram_enabled(mode=transport_mode):
        return None
    if _telegram_bot_token():
        return None
    return _telegram_bot_token_setup_instructions()


def _telegram_api_base() -> str:
    raw = os.environ.get("CODEX_TELEGRAM_API_BASE", _DEFAULT_TELEGRAM_API_BASE)
    base = raw.strip() if isinstance(raw, str) else _DEFAULT_TELEGRAM_API_BASE
    if not base:
        base = _DEFAULT_TELEGRAM_API_BASE
    return base.rstrip("/")


def _telegram_inbound_cursor_path(*, codex_home: Path) -> Path:
    shared_home = _shared_control_state_home(codex_home=codex_home)
    return Path(
        os.environ.get(
            "CODEX_TELEGRAM_INBOUND_CURSOR",
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


def _send_telegram_message(*, token: str, chat_id: str, message: str, timeout_s: float = _DEFAULT_TELEGRAM_SEND_TIMEOUT_S) -> bool:
    token_text = token.strip()
    chat_id_text = chat_id.strip()
    if not token_text or not chat_id_text:
        return False

    url = f"{_telegram_api_base()}/bot{token_text}/sendMessage"
    payload = urllib_parse.urlencode({"chat_id": chat_id_text, "text": message}).encode("utf-8")
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


def _fetch_telegram_updates(*, token: str, chat_id: str | None, after_update_id: int) -> list[tuple[int, str, str | None]]:
    token_text = token.strip()
    if not token_text:
        return []

    params: dict[str, str] = {"timeout": "0", "allowed_updates": json.dumps(["message"])}
    if int(after_update_id) > 0:
        params["offset"] = str(int(after_update_id) + 1)

    url = f"{_telegram_api_base()}/bot{token_text}/getUpdates?{urllib_parse.urlencode(params)}"
    request = urllib_request.Request(url)
    try:
        with urllib_request.urlopen(request, timeout=_DEFAULT_TELEGRAM_SEND_TIMEOUT_S) as response:
            raw = response.read()
    except Exception:
        return []

    try:
        parsed = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return []

    if not isinstance(parsed, dict) or not bool(parsed.get("ok")):
        return []
    result = parsed.get("result")
    if not isinstance(result, list):
        return []

    target_chat_id = chat_id.strip() if isinstance(chat_id, str) else ""
    out: list[tuple[int, str, str | None]] = []
    for update in result:
        if not isinstance(update, dict):
            continue
        update_id = update.get("update_id")
        if not isinstance(update_id, int):
            continue
        message = update.get("message")
        if not isinstance(message, dict):
            continue
        chat = message.get("chat")
        if not isinstance(chat, dict):
            continue
        incoming_chat_id = chat.get("id")
        incoming_chat_text = str(incoming_chat_id).strip() if incoming_chat_id is not None else ""
        if target_chat_id and incoming_chat_text != target_chat_id:
            continue
        text = message.get("text")
        if not isinstance(text, str) or not text.strip():
            continue
        reply_reference_text: str | None = None
        reply_to_message = message.get("reply_to_message")
        if isinstance(reply_to_message, dict):
            reply_text = reply_to_message.get("text")
            if isinstance(reply_text, str):
                trimmed_reply_text = reply_text.strip()
                if trimmed_reply_text:
                    reply_reference_text = trimmed_reply_text

        out.append((update_id, text.strip(), reply_reference_text))
    return out


def _attention_index_path(*, codex_home: Path) -> Path:
    return Path(
        os.environ.get(
            "CODEX_IMESSAGE_ATTENTION_INDEX",
            str(codex_home / "tmp" / "imessage_attention_index.json"),
        )
    )


def _last_attention_state_path(*, codex_home: Path) -> Path:
    return Path(
        os.environ.get(
            "CODEX_IMESSAGE_LAST_ATTENTION",
            str(codex_home / "tmp" / "imessage_last_attention.json"),
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
) -> None:
    queue_path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "ts": int(time.time()),
        "transport": transport,
        "to": recipient,
        "text": message,
    }
    with queue_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False))
        f.write("\n")


def _send_message_with_transport(*, transport: str, recipient: str, message: str) -> bool:
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
        return _send_telegram_message(token=token, chat_id=chat_id, message=message)
    return False


def _deliver_message_across_transports(
    *,
    codex_home: Path,
    imessage_recipient: str,
    message: str,
) -> bool:
    queue_path = _queue_path(codex_home=codex_home)
    mode = _transport_mode()
    sent_any = False
    attempted = False

    if _transport_imessage_enabled(mode=mode):
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

    if _transport_telegram_enabled(mode=mode):
        chat_id = _telegram_chat_id()
        if isinstance(chat_id, str) and chat_id.strip():
            attempted = True
            chat_id_text = chat_id.strip()
            if _send_message_with_transport(transport="telegram", recipient=chat_id_text, message=message):
                sent_any = True
            else:
                _enqueue_fallback_event(
                    queue_path=queue_path,
                    transport="telegram",
                    recipient=chat_id_text,
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

                if dry_run:
                    retained_lines.append(line)
                    stats["retained"] = int(stats["retained"]) + 1
                    continue

                ok = _send_message_with_transport(
                    transport=transport_text,
                    recipient=recipient,
                    message=message,
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
                "[imessage-control-plane] fallback queue requeue failed: "
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
            "CODEX_IMESSAGE_LAUNCHD_ERR_LOG",
            str(Path.home() / "Library" / "Logs" / "agent-chat-control-plane.launchd.err.log"),
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
    raw = env.get("CODEX_IMESSAGE_TO")
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
    commands: tuple[list[str], ...] = (
        ["open", _FULL_DISK_ACCESS_SETTINGS_URL],
        ["open", "-b", "com.apple.systempreferences"],
    )
    for cmd in commands:
        try:
            proc = subprocess.run(
                cmd,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            continue
        if proc.returncode == 0:
            return True
    return False


def _launchagent_plist_path(*, label: str) -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"


def _launchd_log_paths() -> tuple[Path, Path]:
    logs_dir = Path.home() / "Library" / "Logs"
    return (
        logs_dir / "agent-chat-control-plane.launchd.out.log",
        logs_dir / "agent-chat-control-plane.launchd.err.log",
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
    notify_mode = os.environ.get("CODEX_IMESSAGE_NOTIFY_MODE", "route").strip() or "route"
    agent = _current_agent()
    recipient_text = recipient.strip()

    env_vars: dict[str, str] = {
        "CODEX_HOME": str(codex_home),
        "CODEX_IMESSAGE_AGENT": agent,
        "CODEX_IMESSAGE_NOTIFY_MODE": notify_mode,
        "CODEX_IMESSAGE_LAUNCHD_LABEL": label,
        "PATH": os.environ.get("PATH", "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"),
    }
    if recipient_text:
        env_vars["CODEX_IMESSAGE_TO"] = recipient_text

    if agent == "claude":
        env_vars["CLAUDE_HOME"] = str(codex_home)

    passthrough = (
        "CLAUDE_HOME",
        "CLAUDE_SETTINGS_PATH",
        "CLAUDE_CONFIG_PATH",
        "CLAUDE_PROJECTS_PATH",
        "CODEX_IMESSAGE_CHAT_DB",
        "CODEX_IMESSAGE_INBOUND_POLL_S",
        "CODEX_IMESSAGE_INBOUND_RETRY_S",
        "CODEX_IMESSAGE_MAX_LEN",
        "CODEX_IMESSAGE_QUEUE_DRAIN_LIMIT",
        "CODEX_IMESSAGE_RESUME_TIMEOUT_S",
        "CODEX_IMESSAGE_TMUX_SOCKET",
        "CODEX_IMESSAGE_STRICT_TMUX",
        "CODEX_IMESSAGE_REQUIRE_SESSION_REF",
        "CODEX_IMESSAGE_TMUX_NEW_SESSION_NAME",
        "CODEX_IMESSAGE_TMUX_WINDOW_PREFIX",
        "CODEX_IMESSAGE_CLAUDE_BIN",
        "CODEX_IMESSAGE_CODEX_BIN",
        "CODEX_IMESSAGE_SETUP_PERMISSIONS_TIMEOUT_S",
        "CODEX_IMESSAGE_SETUP_PERMISSIONS_POLL_S",
        "CODEX_IMESSAGE_TRANSPORT",
        "CODEX_TELEGRAM_BOT_TOKEN",
        "CODEX_TELEGRAM_CHAT_ID",
        "CODEX_TELEGRAM_API_BASE",
        "CODEX_TELEGRAM_INBOUND_CURSOR",
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
    telegram_setup_err = _validate_telegram_setup_requirements(transport_mode=transport_mode)
    if isinstance(telegram_setup_err, str):
        sys.stdout.write(telegram_setup_err)
        return 1

    recipient_text = _normalize_recipient(recipient) if recipient.strip() else ""
    if _transport_imessage_enabled(mode=transport_mode) and not recipient_text:
        sys.stdout.write("CODEX_IMESSAGE_TO is required. Provide --recipient or set CODEX_IMESSAGE_TO.\n")
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

    if setup_permissions:
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
    if launchd_warning:
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
    if setup_permissions:
        sys.stdout.write("chat.db permission check: passed for this Python binary.\n")
    else:
        sys.stdout.write(
            "chat.db permission check: skipped. "
            "If inbound replies stay disabled, run `setup-permissions` for this Python binary.\n"
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
    sys.stdout.write(f"chat.db path: {chat_db}\n")
    if isinstance(chat_db_error, str) and chat_db_error.strip():
        sys.stdout.write(f"Current chat.db error: {chat_db_error.strip()}\n")
    sys.stdout.write("Waiting for permission grant: polling chat.db until readable.\n")

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
            return 0
        if open_settings and not settings_opened:
            if _open_full_disk_access_settings():
                sys.stdout.write("Opened System Settings to Full Disk Access.\n")
            else:
                sys.stdout.write(
                    "Could not auto-open System Settings; open Privacy > Full Disk Access manually.\n"
                )
            settings_opened = True
        time.sleep(poll_s)

    if isinstance(chat_db_error, str) and chat_db_error.strip():
        sys.stdout.write(f"Timed out waiting for chat.db access: {chat_db_error.strip()}\n")
    else:
        sys.stdout.write("Timed out waiting for chat.db access.\n")
    return 1

def _doctor_report(*, codex_home: Path, recipient: str | None) -> dict[str, Any]:
    now_ts = int(time.time())
    agent = _current_agent()
    transport_mode = _transport_mode()
    imessage_enabled = _transport_imessage_enabled(mode=transport_mode)
    telegram_enabled = _transport_telegram_enabled(mode=transport_mode)
    telegram_chat_id = _telegram_chat_id()
    telegram_token_present = bool(_telegram_bot_token())
    launchd_label = os.environ.get("CODEX_IMESSAGE_LAUNCHD_LABEL", _DEFAULT_LAUNCHD_LABEL).strip() or _DEFAULT_LAUNCHD_LABEL
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

    chat_db, shell_chat_db_readable, shell_chat_db_error = _chat_db_access_status(codex_home=codex_home)
    chat_db_readable = shell_chat_db_readable
    chat_db_error = shell_chat_db_error
    chat_db_source = "shell"
    runtime_chat_db_readable: bool | None = None
    runtime_chat_db_error: str | None = None
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
        tmux_socket=os.environ.get("CODEX_IMESSAGE_TMUX_SOCKET")
    ) or _choose_registry_tmux_socket(registry=registry)
    active_codex_panes = _tmux_active_codex_panes(tmux_socket=preferred_tmux_socket)
    last_dispatch_error = registry.get("last_dispatch_error")
    if not isinstance(last_dispatch_error, dict):
        last_dispatch_error = None

    outbound_cursor_raw = _read_json(_outbound_cursor_path(codex_home=codex_home)) or {}
    inbound_cursor = _load_inbound_cursor(codex_home=codex_home)
    telegram_inbound_cursor = _load_telegram_inbound_cursor(codex_home=codex_home)
    reply_cursor_raw = _read_json(
        Path(
            os.environ.get(
                "CODEX_IMESSAGE_REPLY_CURSOR",
                str(codex_home / "tmp" / "imessage_reply_cursor.json"),
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
        health.append("missing recipient (CODEX_IMESSAGE_TO)")
    if telegram_enabled and not telegram_token_present:
        health.append("missing Telegram bot token (CODEX_TELEGRAM_BOT_TOKEN)")
    if telegram_enabled and not (isinstance(telegram_chat_id, str) and telegram_chat_id.strip()):
        health.append("missing Telegram chat id (CODEX_TELEGRAM_CHAT_ID)")
    if not launchd_loaded:
        health.append("launchd service not loaded")
    if launchd_inbound_warning:
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
            "imessage_enabled": imessage_enabled,
            "telegram_enabled": telegram_enabled,
            "telegram_chat_id": telegram_chat_id,
            "telegram_token_present": telegram_token_present,
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
        f"telegram={bool(transport.get('telegram_enabled'))}\n"
    )
    if bool(transport.get("telegram_enabled")):
        telegram_chat_id = transport.get("telegram_chat_id")
        sys.stdout.write(f"Telegram chat: {telegram_chat_id or '(missing)'}\n")
        sys.stdout.write(
            f"Telegram token: {'configured' if bool(transport.get('telegram_token_present')) else 'missing'}\n"
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
        "sessions": {},
        "aliases": {},
        "last_dispatch_error": None,
        "ts": int(time.time()),
    }


def _load_registry(*, codex_home: Path) -> dict[str, Any]:
    raw = _read_json(_registry_path(codex_home=codex_home))
    if not isinstance(raw, dict):
        return _default_registry()

    sessions = raw.get("sessions")
    aliases = raw.get("aliases")
    last_dispatch_error = raw.get("last_dispatch_error")
    if not isinstance(last_dispatch_error, dict):
        last_dispatch_error = None
    out: dict[str, Any] = {
        "sessions": sessions if isinstance(sessions, dict) else {},
        "aliases": aliases if isinstance(aliases, dict) else {},
        "last_dispatch_error": last_dispatch_error,
        "ts": int(time.time()),
    }
    return out


def _save_registry(*, codex_home: Path, registry: dict[str, Any]) -> None:
    sessions = registry.get("sessions")
    if not isinstance(sessions, dict):
        sessions = {}
    aliases = registry.get("aliases")
    if not isinstance(aliases, dict):
        aliases = {}
    last_dispatch_error = registry.get("last_dispatch_error")
    if not isinstance(last_dispatch_error, dict):
        last_dispatch_error = None

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

        # Prune aliases to kept sids.
        aliases = {
            alias: sid
            for alias, sid in aliases.items()
            if isinstance(alias, str) and isinstance(sid, str) and sid in sessions
        }

    _write_json(
        _registry_path(codex_home=codex_home),
        {
            "sessions": sessions,
            "aliases": aliases,
            "last_dispatch_error": last_dispatch_error,
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


def _parse_inbound_command(text: str) -> dict[str, str]:
    raw = text.strip()
    if not raw:
        return {"action": "noop"}

    lowered = raw.lower()
    if lowered == "help":
        return {"action": "help"}
    if lowered == "list":
        return {"action": "list"}

    m_status = re.match(r"^status\s+@?(\S+)\s*$", raw, flags=re.IGNORECASE)
    if m_status:
        return {"action": "status", "session_ref": m_status.group(1).strip()}

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
        return None, f"Ambiguous alias '{ref}'. Send list and use @<ref>."

    # Prefix match.
    prefix_matches: list[str] = []
    if len(ref) >= max(1, int(min_prefix)):
        for sid in sessions.keys():
            if isinstance(sid, str) and sid.startswith(ref):
                prefix_matches.append(sid)

    if len(prefix_matches) == 1:
        return prefix_matches[0], None
    if len(prefix_matches) > 1:
        return None, f"Ambiguous session ref '{ref}'. Send list and use a longer @<ref>."

    return None, f"No session found for ref '{ref}'. Send list to view active refs."


def _choose_implicit_session(*, registry: dict[str, Any]) -> tuple[str | None, str | None]:
    sessions = registry.get("sessions")
    if not isinstance(sessions, dict) or not sessions:
        return None, "No tracked sessions. Send list, @<ref> ..., or new <label>: ..."

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
        return None, "Ambiguous target session. Use explicit ref: " + ", ".join(refs)

    return None, "No session is currently awaiting input. Use @<ref> ... or new <label>: ..."


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
) -> None:
    normalized_agent = _normalize_agent(agent=agent if agent is not None else _current_agent())
    sid = session_id or "unknown"
    header = f"[{_agent_display_name(agent=normalized_agent)}] {sid} — {kind} — {outbound._now_local_iso()}"
    body = outbound._redact(text.rstrip()) + "\n"

    try:
        messages = outbound._split_message(header, body, max_message_chars=max_message_chars)
    except Exception:
        messages = [f"{header}\n{body}"]

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
        )


def _find_all_session_files(*, codex_home: Path, agent: str | None = None) -> list[Path]:
    sessions_dir = _agent_session_root(codex_home=codex_home, agent=agent)
    if not sessions_dir.exists():
        return []

    out: list[Path] = []
    for path in sessions_dir.rglob("*.jsonl"):
        out.append(path)
    return out


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

    if isinstance(session_id, str) and session_id.strip():
        fields: dict[str, Any] = {"session_path": str(session_path), "agent": _current_agent()}
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

                if event.get("type") != "response_item":
                    continue

                payload = event.get("payload")
                if not isinstance(payload, dict):
                    continue

                sid = session_id.strip() if isinstance(session_id, str) and session_id.strip() else None
                if not sid:
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

                    _send_structured(
                        codex_home=codex_home,
                        recipient=recipient,
                        session_id=sid,
                        kind="needs_input",
                        text=text,
                        max_message_chars=max_message_chars,
                        dry_run=dry_run,
                        message_index=message_index,
                    )

                    session_fields: dict[str, Any] = {
                        "agent": _current_agent(),
                        "cwd": session_cwd,
                        "session_path": str(session_path),
                        "awaiting_input": True,
                        "pending_completion": True,
                        "last_attention_ts": int(time.time()),
                        "last_needs_input": text,
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

                sessions = registry.get("sessions")
                if not isinstance(sessions, dict):
                    continue
                rec = sessions.get(sid)
                if not isinstance(rec, dict):
                    continue
                if rec.get("pending_completion") is not True:
                    continue

                _send_structured(
                    codex_home=codex_home,
                    recipient=recipient,
                    session_id=sid,
                    kind="responded",
                    text=text,
                    max_message_chars=max_message_chars,
                    dry_run=dry_run,
                    message_index=message_index,
                )

                _upsert_session(
                    registry=registry,
                    session_id=sid,
                    fields={
                        "awaiting_input": False,
                        "pending_completion": False,
                        "last_response_ts": int(time.time()),
                        "pending_request_user_input": None,
                    },
                )

        return offset
    except Exception:
        return offset


def _render_session_list(*, registry: dict[str, Any]) -> str:
    sessions = registry.get("sessions")
    if not isinstance(sessions, dict) or not sessions:
        return "No tracked sessions yet."

    rows: list[tuple[int, str, dict[str, Any]]] = []
    for sid, rec in sessions.items():
        if not isinstance(sid, str) or not isinstance(rec, dict):
            continue
        ts = rec.get("last_attention_ts")
        if not isinstance(ts, int):
            ts = rec.get("last_update_ts")
        rows.append((int(ts) if isinstance(ts, int) else 0, sid, rec))

    rows.sort(key=lambda item: item[0], reverse=True)

    lines = ["Sessions:"]
    for _, sid, rec in rows[:12]:
        ref = rec.get("ref") if isinstance(rec.get("ref"), str) else _session_ref(sid)
        alias = rec.get("alias") if isinstance(rec.get("alias"), str) else ""
        waiting = "waiting" if rec.get("awaiting_input") is True else "idle"
        cwd = rec.get("cwd") if isinstance(rec.get("cwd"), str) else ""
        if alias:
            lines.append(f"- @{ref} ({alias}) — {waiting} — {cwd}")
        else:
            lines.append(f"- @{ref} — {waiting} — {cwd}")

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
    waiting = "yes" if rec.get("awaiting_input") is True else "no"
    cwd = rec.get("cwd") if isinstance(rec.get("cwd"), str) else ""
    path = rec.get("session_path") if isinstance(rec.get("session_path"), str) else ""
    pane = rec.get("tmux_pane") if isinstance(rec.get("tmux_pane"), str) else ""
    socket_value = rec.get("tmux_socket") if isinstance(rec.get("tmux_socket"), str) else ""

    lines = [
        f"Session: {session_id}",
        f"Ref: @{ref}",
        f"Alias: {alias or '-'}",
        f"Awaiting input: {waiting}",
        f"CWD: {cwd or '-'}",
        f"Session path: {path or '-'}",
        f"Tmux pane: {pane or '-'}",
        f"Tmux socket: {socket_value or '-'}",
    ]
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
    return _env_enabled("CODEX_IMESSAGE_STRICT_TMUX", default=True)


def _require_session_ref_enabled(*, strict_tmux: bool) -> bool:
    return _env_enabled("CODEX_IMESSAGE_REQUIRE_SESSION_REF", default=strict_tmux)


def _tmux_ack_timeout_s() -> float:
    fallback = getattr(reply, "_DEFAULT_TMUX_USER_ACK_TIMEOUT_S", _DEFAULT_TMUX_ACK_TIMEOUT_S)
    raw = os.environ.get("CODEX_IMESSAGE_TMUX_ACK_TIMEOUT_S", "").strip()
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


def _dispatch_failure_text(*, session_id: str, mode: str, reason: str | None) -> str:
    ref = _session_ref(session_id) or session_id[:8]
    reason_key = reason.strip().lower() if isinstance(reason, str) and reason.strip() else ""
    reason_details = {
        "pane_missing": "no pane mapping was available",
        "pane_stale": "stored pane mapping is stale",
        "pane_discovery_ambiguous": "multiple Codex panes matched and routing is ambiguous",
        "session_path_missing": "session path is missing for tmux correlation",
        "session_path_mismatch": "session path did not match the target session",
        "send_failed": "tmux send-keys failed",
        "ack_timeout": "tmux did not acknowledge the prompt in time",
        "session_record_missing": "session metadata is missing",
    }
    detail = reason_details.get(reason_key) or (
        "tmux routing failed" if mode == "tmux_failed" else "tmux pane routing is unavailable"
    )
    return (
        f"Strict tmux routing for @{ref}: {detail}. "
        "No fallback resume was run. Bring the target tmux Codex pane online and resend with "
        "@<ref> <instruction>."
    )


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


def _resolve_codex_bin() -> str:
    override = os.environ.get("CODEX_IMESSAGE_CODEX_BIN")
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


def _resolve_agent_bin(*, agent: str | None = None) -> str:
    normalized = _normalize_agent(agent=agent if agent is not None else _current_agent())
    if normalized == "claude":
        return _resolve_claude_bin()
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
    raw_base = os.environ.get("CODEX_IMESSAGE_TMUX_NEW_SESSION_NAME", _DEFAULT_TMUX_NEW_SESSION_NAME)
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
    tmux_socket: str | None = None,
) -> tuple[str | None, str | None, str | None]:
    if not isinstance(session_name, str) or not session_name.strip():
        return None, None, "Invalid tmux session name."

    raw_prefix = os.environ.get("CODEX_IMESSAGE_TMUX_WINDOW_PREFIX", _DEFAULT_TMUX_WINDOW_PREFIX)
    prefix = raw_prefix.strip() if isinstance(raw_prefix, str) and raw_prefix.strip() else _DEFAULT_TMUX_WINDOW_PREFIX
    label_token = _sanitize_tmux_window_label(label=label)
    ts = time.strftime("%H%M%S")
    base_window_name = f"{prefix}-{label_token}-{ts}"
    agent = _current_agent()
    agent_bin = _resolve_agent_bin(agent=agent)
    if agent == "claude":
        launch_cmd = f"CLAUDE_IMESSAGE_REPLY=1 {shlex.quote(agent_bin)}"
    else:
        launch_cmd = f"CODEX_IMESSAGE_REPLY=1 {shlex.quote(agent_bin)} -a never -s danger-full-access"

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

    return None, None, f"Failed to create tmux window for {_agent_display_name(agent=agent)}."


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
    if not (isinstance(command, str) and _is_agent_command(command, agent=agent)):
        return False

    rec_cwd = session_rec.get("cwd") if isinstance(session_rec.get("cwd"), str) else None
    target_cwd = _normalize_path_for_match(rec_cwd)
    if not target_cwd:
        sid = session_id.strip() if isinstance(session_id, str) else ""
        if sid:
            return _tmux_pane_mentions_session_id(
                pane=pane,
                session_id=sid,
                tmux_socket=tmux_socket,
            )
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
        return False

    haystack = proc.stdout or ""
    if not haystack:
        return False

    latest_status_sid: str | None = None
    latest_generic_sid: str | None = None
    for line in haystack.splitlines():
        status_match = _SESSION_STATUS_LINE_UUID_RE.search(line)
        if status_match:
            latest_status_sid = status_match.group(1)
        for generic_match in _SESSION_UUID_RE.finditer(line):
            latest_generic_sid = generic_match.group(0)

    if latest_status_sid:
        return latest_status_sid.lower() == sid.lower()
    if latest_generic_sid:
        return latest_generic_sid.lower() == sid.lower()
    return sid in haystack


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
        if not _is_agent_command(current_cmd, agent=agent):
            continue
        candidates.append((pane_id, current_path))

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
    raw = os.environ.get("CODEX_IMESSAGE_ROUTE_VIA_TMUX", "1").strip().lower()
    return raw not in {"0", "false", "no", "off"}


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
        if (not pane_norm) and isinstance(session_path, str) and session_path.strip():
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

    response = reply._run_agent_resume(
        agent=effective_agent,
        session_id=target_sid,
        cwd=cwd,
        prompt=prompt,
        codex_home=codex_home,
        timeout_s=resume_timeout_s,
    )
    return "resume", response


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
        _add("codex", _lookup_agent_home_path(agent="codex", current_home=current_home))
        _add("claude", _lookup_agent_home_path(agent="claude", current_home=current_home))
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

    preferred_socket = _normalize_tmux_socket(tmux_socket=os.environ.get("CODEX_IMESSAGE_TMUX_SOCKET"))
    if preferred_socket is None and isinstance(registry, dict):
        preferred_socket = _choose_registry_tmux_socket(registry=registry)
    if isinstance(preferred_socket, str) and preferred_socket.strip():
        fields["tmux_socket"] = preferred_socket.strip()

    return fields


def _session_agent_from_record(*, session_rec: dict[str, Any] | None) -> str | None:
    if not isinstance(session_rec, dict):
        return None
    raw = session_rec.get("agent")
    if not isinstance(raw, str) or not raw.strip():
        return None
    return _normalize_agent(agent=raw)


def _session_registry_path_for_home(*, home: Path) -> Path:
    return home / "tmp" / "imessage_session_registry.json"


def _message_index_path_for_home(*, home: Path) -> Path:
    return home / "tmp" / "imessage_message_session_index.json"


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
    _add("codex", _lookup_agent_home_path(agent="codex", current_home=codex_home))
    _add("claude", _lookup_agent_home_path(agent="claude", current_home=codex_home))

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


def _find_new_session_since(*, codex_home: Path, before: set[str]) -> Path | None:
    newest: Path | None = None
    newest_mtime = -1.0
    for path in _find_all_session_files(codex_home=codex_home):
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


def _wait_for_new_session_file(*, codex_home: Path, before: set[str], timeout_s: float) -> Path | None:
    deadline = time.monotonic() + max(0.0, float(timeout_s))
    while time.monotonic() < deadline:
        created = _find_new_session_since(codex_home=codex_home, before=before)
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
    tmux_socket: str | None = None,
) -> tuple[str | None, str | None, str | None, str | None]:
    agent = _current_agent()
    agent_name = _agent_display_name(agent=agent)
    text = " ".join(prompt.splitlines()).strip()
    if not text:
        return None, None, None, "No instruction text was provided."

    before = {str(path) for path in _find_all_session_files(codex_home=codex_home)}

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
    }
    if tmux_socket_norm:
        window_kwargs["tmux_socket"] = tmux_socket_norm
    pane, window_name, window_err = _tmux_start_codex_window(**window_kwargs)
    if not pane:
        return None, None, None, window_err or "Could not create tmux window."

    # Best-effort warmup only. Do not fail solely on command-name mismatch because
    # packaged/wrapped Codex binaries may appear as different pane commands.
    wait_kwargs: dict[str, Any] = {"pane": pane, "expected": _agent_command_keyword(agent=agent), "timeout_s": 8.0}
    if tmux_socket_norm:
        wait_kwargs["tmux_socket"] = tmux_socket_norm
    _tmux_wait_for_pane_command(**wait_kwargs)

    send_kwargs: dict[str, Any] = {"pane": pane, "prompt": text}
    if tmux_socket_norm:
        send_kwargs["tmux_socket"] = tmux_socket_norm
    if not reply._tmux_send_prompt(**send_kwargs):
        return None, None, pane, f"Started {agent_name} in tmux but failed to submit initial prompt."

    created = _wait_for_new_session_file(codex_home=codex_home, before=before, timeout_s=12.0)
    if not created:
        newest = _find_all_session_files(codex_home=codex_home)
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
) -> tuple[str | None, str | None, str | None]:
    agent = _current_agent()
    before = {str(path) for path in _find_all_session_files(codex_home=codex_home)}

    out_dir = codex_home / "tmp"
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    out_path = out_dir / f"imessage_new_session_{int(time.time())}_{os.getpid()}.txt"

    if agent == "claude":
        cmd = [_resolve_agent_bin(agent=agent), "-p", prompt]
    else:
        cmd = [
            _resolve_agent_bin(agent=agent),
            "-a",
            "never",
            "-s",
            "danger-full-access",
            "exec",
            "--skip-git-repo-check",
            "--output-last-message",
            str(out_path),
            prompt,
        ]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            text=True,
            env={**os.environ, "CODEX_IMESSAGE_REPLY": "1", "CLAUDE_IMESSAGE_REPLY": "1"},
        )
    except Exception:
        return None, None, "Failed to start new session."

    if proc.returncode != 0:
        return None, None, "New session command failed."

    created = _find_new_session_since(codex_home=codex_home, before=before)
    if not created:
        # Best-effort fallback: newest file.
        newest = _find_all_session_files(codex_home=codex_home)
        if newest:
            newest.sort(key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)
            created = newest[0]

    if not created:
        return None, None, "Session created but could not locate session file."

    session_id = outbound._read_session_id(session_path=created)
    if not session_id:
        return None, None, "Session created but session ID was not found."

    response: str | None = None
    if agent == "claude":
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
            _send_structured(
                codex_home=codex_home,
                recipient=recipient,
                session_id=session_id,
                kind="needs_input",
                text=prompt_text,
                max_message_chars=_DEFAULT_MAX_MESSAGE_CHARS,
                dry_run=dry_run,
                message_index=message_index,
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

    if not response_text:
        response_text = "Turn completed."

    message_index = _load_message_index(codex_home=codex_home)
    _send_structured(
        codex_home=codex_home,
        recipient=recipient,
        session_id=session_id,
        kind="responded",
        text=response_text,
        max_message_chars=_DEFAULT_MAX_MESSAGE_CHARS,
        dry_run=dry_run,
        message_index=message_index,
    )
    _save_message_index(codex_home=codex_home, index=message_index)

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
) -> int:
    if fetch_replies_fn is not None:
        replies = fetch_replies_fn(conn=conn, after_rowid=after_rowid, handle_ids=handle_ids)
    else:
        replies = reply._fetch_new_replies(conn=conn, after_rowid=after_rowid, handle_ids=handle_ids)
    if not replies:
        return after_rowid

    registry = _load_registry(codex_home=codex_home)
    message_index = _load_message_index(codex_home=codex_home)
    attention_index = _load_attention_index(codex_home=codex_home)
    last_attention_state = _load_last_attention_state(codex_home=codex_home)
    auto_create_on_missing = _env_enabled("CODEX_IMESSAGE_AUTO_CREATE_ON_MISSING", default=True)
    strict_tmux = _strict_tmux_enabled()
    require_session_ref = _require_session_ref_enabled(strict_tmux=strict_tmux)

    def _trace(message: str) -> None:
        if not trace:
            return
        _warn_stderr(f"[imessage-control-plane][trace] {message}")

    last_rowid = after_rowid

    for rowid, text, reply_to_guid in replies:
        last_rowid = rowid
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

        cmd = _parse_inbound_command(text)
        action = cmd.get("action")
        if action == "noop":
            continue
        _trace(f"parsed action={action} reply_to_guid={bool(reply_to_guid)}")

        if action == "help":
            _send_structured(
                codex_home=codex_home,
                recipient=recipient,
                session_id=None,
                kind="help",
                text=_HELP_TEXT,
                max_message_chars=max_message_chars,
                dry_run=dry_run,
                message_index=message_index,
            )
            continue

        if action == "list":
            _send_structured(
                codex_home=codex_home,
                recipient=recipient,
                session_id=None,
                kind="status",
                text=_render_session_list(registry=registry),
                max_message_chars=max_message_chars,
                dry_run=dry_run,
                message_index=message_index,
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
            )
            continue

        if action == "new":
            allow_new = os.environ.get("CODEX_IMESSAGE_ENABLE_NEW_SESSION", "1").strip() not in {
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
                    text="Creating new sessions from iMessage is disabled.",
                    max_message_chars=max_message_chars,
                    dry_run=dry_run,
                    message_index=message_index,
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

            _send_structured(
                codex_home=codex_home,
                recipient=recipient,
                session_id=sid,
                kind="accepted",
                text=f"Created session @{_session_ref(sid)} ({label}).",
                max_message_chars=max_message_chars,
                dry_run=dry_run,
                message_index=message_index,
            )
            continue

        target_sid: str | None = None
        err: str | None = None
        prompt = cmd.get("prompt", "").strip()
        if not prompt:
            _send_structured(
                codex_home=codex_home,
                recipient=recipient,
                session_id=None,
                kind="error",
                text="No instruction text was provided.",
                max_message_chars=max_message_chars,
                dry_run=dry_run,
                message_index=message_index,
            )
            continue

        if action == "resume":
            target_sid, err = _resolve_session_ref(
                registry=registry,
                session_ref=cmd.get("session_ref", ""),
                min_prefix=min_prefix,
            )
        else:
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
            allow_auto_create = auto_create_on_missing and not (strict_tmux and action == "implicit")
            if allow_auto_create:
                fallback_cwd = _default_new_session_cwd()
                auto_create_label: str | None = None
                preferred_tmux_socket = _normalize_tmux_socket(
                    tmux_socket=os.environ.get("CODEX_IMESSAGE_TMUX_SOCKET")
                ) or _choose_registry_tmux_socket(registry=registry)
                if action == "resume":
                    raw_ref = cmd.get("session_ref", "")
                    if isinstance(raw_ref, str) and raw_ref.strip():
                        auto_create_label = raw_ref.strip()

                sid, session_path, pane, create_err = _create_new_session_in_tmux(
                    codex_home=codex_home,
                    prompt=prompt,
                    cwd=fallback_cwd,
                    label=auto_create_label,
                    tmux_socket=preferred_tmux_socket,
                )
                if sid:
                    session_cwd = fallback_cwd
                    if session_path:
                        extracted_cwd = outbound._read_session_cwd(session_path=Path(session_path))
                        if isinstance(extracted_cwd, str) and extracted_cwd.strip():
                            session_cwd = extracted_cwd.strip()

                    fields: dict[str, Any] = {
                        "agent": _current_agent(),
                        "awaiting_input": False,
                        "pending_completion": True,
                        "last_resume_ts": int(time.time()),
                        "pending_request_user_input": None,
                    }
                    if session_path:
                        fields["session_path"] = session_path
                    if isinstance(session_cwd, str) and session_cwd.strip():
                        fields["cwd"] = session_cwd.strip()
                    if isinstance(pane, str) and pane.strip():
                        fields["tmux_pane"] = pane.strip()
                    if isinstance(preferred_tmux_socket, str) and preferred_tmux_socket.strip():
                        fields["tmux_socket"] = preferred_tmux_socket.strip()

                    _upsert_session(registry=registry, session_id=sid, fields=fields)

                    if action == "resume":
                        raw_ref = cmd.get("session_ref", "")
                        if isinstance(raw_ref, str):
                            alias = raw_ref.strip().lower()
                            if re.match(r"^[A-Za-z0-9._-]+$", alias):
                                _set_alias(registry=registry, session_id=sid, label=alias)

                    _send_structured(
                        codex_home=codex_home,
                        recipient=recipient,
                        session_id=sid,
                        kind="accepted",
                        text=(
                            f"No matching session found; started new session @{_session_ref(sid)} "
                            f"in tmux pane {pane or '-'}."
                        ),
                        max_message_chars=max_message_chars,
                        dry_run=dry_run,
                        message_index=message_index,
                    )
                    continue

                _send_structured(
                    codex_home=codex_home,
                    recipient=recipient,
                    session_id=None,
                    kind="error",
                    text=create_err or err or "Could not resolve target session.",
                    max_message_chars=max_message_chars,
                    dry_run=dry_run,
                    message_index=message_index,
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
            )
            continue

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

        if dispatch_mode == "tmux":
            _clear_last_dispatch_error(registry=registry)
            _send_structured(
                codex_home=codex_home,
                recipient=recipient,
                session_id=target_sid,
                kind="accepted",
                text=f"Sent to tmux pane for @{_session_ref(target_sid)}. Follow execution on your Mac.",
                max_message_chars=max_message_chars,
                dry_run=dry_run,
                message_index=message_index,
                agent=session_agent,
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
            _send_structured(
                codex_home=codex_home,
                recipient=recipient,
                session_id=target_sid,
                kind="accepted",
                text=(
                    f"Sent to tmux pane for @{_session_ref(target_sid)}. "
                    "Execution may be delayed; check the pane on your Mac."
                ),
                max_message_chars=max_message_chars,
                dry_run=dry_run,
                message_index=message_index,
                agent=session_agent,
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
            if strict_tmux:
                preserved_pane = ""
                if isinstance(rec, dict):
                    rec_pane = rec.get("tmux_pane")
                    if isinstance(rec_pane, str):
                        preserved_pane = rec_pane
                if dispatch_mode == "tmux_stale":
                    preserved_pane = ""
                _send_structured(
                    codex_home=codex_home,
                    recipient=recipient,
                    session_id=target_sid,
                    kind="error",
                    text=_dispatch_failure_text(
                        session_id=target_sid,
                        mode=dispatch_mode,
                        reason=dispatch_reason,
                    ),
                    max_message_chars=max_message_chars,
                    dry_run=dry_run,
                    message_index=message_index,
                    agent=session_agent,
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
            response = reply._run_agent_resume(
                agent=session_agent,
                session_id=target_sid,
                cwd=fallback_cwd,
                prompt=prompt_for_dispatch,
                codex_home=codex_home,
                timeout_s=resume_timeout_s,
            )
            if not response:
                _send_structured(
                    codex_home=codex_home,
                    recipient=recipient,
                    session_id=target_sid,
                    kind="error",
                    text=f"No response from {_agent_display_name(agent=session_agent).lower()} resume. Check session logs.",
                    max_message_chars=max_message_chars,
                    dry_run=dry_run,
                    message_index=message_index,
                    agent=session_agent,
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
        if not response:
            _send_structured(
                codex_home=codex_home,
                recipient=recipient,
                session_id=target_sid,
                kind="error",
                text=f"No response from {_agent_display_name(agent=session_agent).lower()} resume. Check session logs.",
                max_message_chars=max_message_chars,
                dry_run=dry_run,
                message_index=message_index,
                agent=session_agent,
            )
            continue

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
    chat_id = _telegram_chat_id()
    if not isinstance(token, str) or not token.strip():
        return after_update_id
    if not isinstance(chat_id, str) or not chat_id.strip():
        return after_update_id

    updates = _fetch_telegram_updates(
        token=token.strip(),
        chat_id=chat_id.strip(),
        after_update_id=after_update_id,
    )
    if not updates:
        return after_update_id
    update_reply_text_map = {int(update_id): reply_text for update_id, _text, reply_text in updates}

    def _fetch_virtual_replies(*, conn: sqlite3.Connection, after_rowid: int, handle_ids: list[str]) -> list[tuple[int, str, str | None]]:
        del conn, handle_ids
        return [(update_id, text, None) for update_id, text, _reply_text in updates if int(update_id) > int(after_rowid)]

    def _empty_reference_guids(*, conn: sqlite3.Connection, rowid: int, fallback_guid: str | None) -> list[str]:
        del conn, rowid, fallback_guid
        return []

    def _virtual_reference_texts(*, conn: sqlite3.Connection, rowid: int, fallback_guid: str | None) -> list[str]:
        del conn, fallback_guid
        reply_text = update_reply_text_map.get(int(rowid))
        if isinstance(reply_text, str) and reply_text.strip():
            return [reply_text.strip()]
        return []

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

    session_paths = _find_all_session_files(codex_home=codex_home)
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
    default_agent = _normalize_agent(agent=os.environ.get("CODEX_IMESSAGE_AGENT") or os.environ.get("IMESSAGE_AGENT"))

    def _add_agent_arg(cmd_parser: argparse.ArgumentParser) -> None:
        cmd_parser.add_argument(
            "--agent",
            default=default_agent,
            choices=sorted(_SUPPORTED_AGENTS),
            help="Agent runtime to integrate (codex or claude)",
        )

    run = sub.add_parser("run", help="Run control plane forever")
    _add_agent_arg(run)
    run.add_argument("--poll", type=float, default=float(os.environ.get("CODEX_IMESSAGE_INBOUND_POLL_S", "0.5")))
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
        help="Install/update notify hook for Codex or Claude",
    )
    _add_agent_arg(setup_notify)
    setup_notify.add_argument(
        "--recipient",
        default="",
        help="Destination phone/email; falls back to CODEX_IMESSAGE_TO",
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
        default=os.environ.get("CODEX_IMESSAGE_LAUNCHD_LABEL", _DEFAULT_LAUNCHD_LABEL),
        help=f"Launchd label (default {_DEFAULT_LAUNCHD_LABEL})",
    )
    setup_launchd.add_argument(
        "--recipient",
        default="",
        help="Destination phone/email; falls back to CODEX_IMESSAGE_TO",
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

    args = parser.parse_args(argv)

    agent = _normalize_agent(agent=getattr(args, "agent", None))
    os.environ["CODEX_IMESSAGE_AGENT"] = agent

    recipient_raw = os.environ.get("CODEX_IMESSAGE_TO")
    codex_home = _agent_home_path(agent=agent)
    recipient = _normalize_recipient(recipient_raw) if isinstance(recipient_raw, str) and recipient_raw.strip() else ""
    transport_mode = _transport_mode()
    trace_enabled = bool(getattr(args, "trace", False)) or _env_enabled("CODEX_IMESSAGE_TRACE", default=False)

    if args.cmd == "doctor":
        doctor_recipient: str | None = recipient if recipient else recipient_raw
        return _run_doctor(codex_home=codex_home, recipient=doctor_recipient, as_json=bool(args.json))
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
        launchd_label = (
            os.environ.get("CODEX_IMESSAGE_LAUNCHD_LABEL", _DEFAULT_LAUNCHD_LABEL).strip()
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

    if not recipient and not _transport_telegram_enabled(mode=transport_mode):
        return 0

    lock_handle = _acquire_single_instance_lock(codex_home=codex_home)
    if lock_handle is None:
        return 0

    if args.cmd in {"run", "once"}:
        _warn_stderr(
            "[imessage-control-plane] startup "
            f"script={Path(__file__).resolve()} "
            f"python={sys.executable} "
            f"agent={agent} "
            f"strict_tmux={_strict_tmux_enabled()} "
            f"trace={trace_enabled} "
            f"chat_db={_chat_db_path(codex_home=codex_home)}"
        )

    max_message_chars = _DEFAULT_MAX_MESSAGE_CHARS
    env_max = os.environ.get("CODEX_IMESSAGE_MAX_LEN", "").strip()
    if env_max:
        try:
            max_message_chars = int(env_max)
        except Exception:
            max_message_chars = _DEFAULT_MAX_MESSAGE_CHARS

    min_prefix = _DEFAULT_MIN_PREFIX
    env_min_prefix = os.environ.get("CODEX_IMESSAGE_SESSION_REF_MIN", "").strip()
    if env_min_prefix:
        try:
            min_prefix = max(1, int(env_min_prefix))
        except Exception:
            min_prefix = _DEFAULT_MIN_PREFIX

    resume_timeout_s = _resolve_resume_timeout_s()
    queue_drain_limit = _DEFAULT_QUEUE_DRAIN_LIMIT
    env_queue_limit = os.environ.get("CODEX_IMESSAGE_QUEUE_DRAIN_LIMIT", "").strip()
    if env_queue_limit:
        try:
            queue_drain_limit = max(0, int(env_queue_limit))
        except Exception:
            queue_drain_limit = _DEFAULT_QUEUE_DRAIN_LIMIT

    files_cursor, seen_needs_input_call_ids = _load_outbound_cursor(codex_home=codex_home)

    conn = _open_chat_db(codex_home)
    handle_ids = reply._candidate_handle_ids(recipient)
    inbound_rowid = 0
    if conn is not None:
        inbound_rowid = _ensure_inbound_cursor_seed(
            codex_home=codex_home,
            conn=conn,
            recipient=recipient,
            handle_ids=handle_ids,
        )
    telegram_update_id = _load_telegram_inbound_cursor(codex_home=codex_home)

    inbound_retry_s = 30.0
    env_retry = os.environ.get("CODEX_IMESSAGE_INBOUND_RETRY_S", "").strip()
    if env_retry:
        try:
            inbound_retry_s = max(0.0, float(env_retry))
        except Exception:
            inbound_retry_s = 30.0

    next_inbound_retry_monotonic = 0.0

    def _ensure_inbound_ready(*, now_monotonic: float | None = None) -> bool:
        nonlocal conn, inbound_rowid, next_inbound_retry_monotonic

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

    _ensure_inbound_ready(now_monotonic=0.0)

    def cycle() -> None:
        nonlocal files_cursor, seen_needs_input_call_ids, inbound_rowid, telegram_update_id

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

        if _ensure_inbound_ready():
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
                "[imessage-control-plane] cycle error: "
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
