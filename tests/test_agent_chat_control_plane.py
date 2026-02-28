import io
import json
import plistlib
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import agent_chat_control_plane as cp


class TestAgentChatControlPlane(unittest.TestCase):
    def test_is_supported_python_version_rejects_3_10(self) -> None:
        self.assertFalse(cp._is_supported_python_version((3, 10, 14)))  # type: ignore[attr-defined]
        self.assertTrue(cp._is_supported_python_version((3, 11, 0)))  # type: ignore[attr-defined]

    def test_build_python_upgrade_message_mentions_upgrade(self) -> None:
        text = cp._build_python_upgrade_message(  # type: ignore[attr-defined]
            executable="/usr/bin/python3",
            version=(3, 9, 6),
        )
        self.assertIn("requires Python 3.11+", text)
        self.assertIn("Detected: Python 3.9.6", text)
        self.assertIn("Please upgrade Python", text)

    def test_warn_stderr_prefixes_timestamp_per_line(self) -> None:
        with (
            mock.patch.object(cp.time, "strftime", return_value="2026-02-16T12:34:56-0800"),
            mock.patch("sys.stderr", new_callable=io.StringIO) as err,
        ):
            cp._warn_stderr("line1\nline2\n")  # type: ignore[attr-defined]

        self.assertEqual(
            err.getvalue(),
            "[2026-02-16T12:34:56-0800] line1\n"
            "[2026-02-16T12:34:56-0800] line2\n",
        )

    def test_warn_chat_db_once_mentions_app_or_python_binary(self) -> None:
        with (
            mock.patch.object(cp, "_warn_stderr") as warn_mock,
            mock.patch.object(cp.time, "time", return_value=100.0),
        ):
            cp._chat_db_last_warning_text = None  # type: ignore[attr-defined]
            cp._chat_db_last_warning_ts = 0.0  # type: ignore[attr-defined]
            cp._chat_db_last_status = None  # type: ignore[attr-defined]
            cp._warn_chat_db_once(detail="cannot open chat.db")  # type: ignore[attr-defined]

        warn_mock.assert_called_once()
        text = warn_mock.call_args.args[0]
        self.assertIn("app or Python binary", text)

    def test_parse_inbound_command_help(self) -> None:
        cmd = cp._parse_inbound_command("help")  # type: ignore[attr-defined]
        self.assertEqual(cmd.get("action"), "help")

    def test_parse_inbound_command_list(self) -> None:
        cmd = cp._parse_inbound_command("list")  # type: ignore[attr-defined]
        self.assertEqual(cmd.get("action"), "list")

    def test_parse_inbound_command_status_with_ref(self) -> None:
        cmd = cp._parse_inbound_command("status @019c33b4")  # type: ignore[attr-defined]
        self.assertEqual(cmd.get("action"), "status")
        self.assertEqual(cmd.get("session_ref"), "019c33b4")

    def test_parse_inbound_command_new_session(self) -> None:
        cmd = cp._parse_inbound_command("new bugfix: inspect failing tests")  # type: ignore[attr-defined]
        self.assertEqual(cmd.get("action"), "new")
        self.assertEqual(cmd.get("label"), "bugfix")
        self.assertEqual(cmd.get("prompt"), "inspect failing tests")

    def test_parse_inbound_command_resume_with_explicit_ref(self) -> None:
        cmd = cp._parse_inbound_command("@019c33b4 apply patch")  # type: ignore[attr-defined]
        self.assertEqual(cmd.get("action"), "resume")
        self.assertEqual(cmd.get("session_ref"), "019c33b4")
        self.assertEqual(cmd.get("prompt"), "apply patch")

    def test_parse_inbound_command_implicit(self) -> None:
        cmd = cp._parse_inbound_command("please continue")  # type: ignore[attr-defined]
        self.assertEqual(cmd.get("action"), "implicit")
        self.assertEqual(cmd.get("prompt"), "please continue")

    def test_lookup_agent_home_path_uses_default_codex_when_runtime_points_codex_home_to_claude(self) -> None:
        with mock.patch.dict(
            cp.os.environ,  # type: ignore[attr-defined]
            {
                "AGENT_CHAT_AGENT": "claude",
                "AGENT_CHAT_HOME": "/tmp/claude-home",
                "CLAUDE_HOME": "/tmp/claude-home",
            },
            clear=False,
        ):
            home = cp._lookup_agent_home_path(  # type: ignore[attr-defined]
                agent="codex",
                current_home=Path("/tmp/claude-home"),
            )
        self.assertEqual(home, Path.home() / ".codex")

    def test_lookup_agent_home_path_respects_explicit_codex_override(self) -> None:
        with mock.patch.dict(
            cp.os.environ,  # type: ignore[attr-defined]
            {
                "AGENT_CHAT_AGENT": "claude",
                "AGENT_CHAT_HOME": "/tmp/claude-home",
                "CLAUDE_HOME": "/tmp/claude-home",
                "AGENT_CHAT_CODEX_HOME": "/tmp/real-codex-home",
            },
            clear=False,
        ):
            home = cp._lookup_agent_home_path(  # type: ignore[attr-defined]
                agent="codex",
                current_home=Path("/tmp/claude-home"),
            )
        self.assertEqual(home, Path("/tmp/real-codex-home"))

    def test_control_lock_path_defaults_to_shared_codex_home_in_claude_runtime(self) -> None:
        with mock.patch.dict(
            cp.os.environ,  # type: ignore[attr-defined]
            {
                "AGENT_CHAT_AGENT": "claude",
                "AGENT_CHAT_HOME": "/tmp/claude-home",
                "CLAUDE_HOME": "/tmp/claude-home",
            },
            clear=False,
        ):
            lock_path = cp._control_lock_path(codex_home=Path("/tmp/claude-home"))  # type: ignore[attr-defined]

        self.assertEqual(lock_path, Path.home() / ".codex" / "tmp" / "agent_chat_control_plane.lock")

    def test_inbound_cursor_path_defaults_to_shared_codex_home_in_claude_runtime(self) -> None:
        with mock.patch.dict(
            cp.os.environ,  # type: ignore[attr-defined]
            {
                "AGENT_CHAT_AGENT": "claude",
                "AGENT_CHAT_HOME": "/tmp/claude-home",
                "CLAUDE_HOME": "/tmp/claude-home",
            },
            clear=False,
        ):
            cursor_path = cp._inbound_cursor_path(codex_home=Path("/tmp/claude-home"))  # type: ignore[attr-defined]

        self.assertEqual(cursor_path, Path.home() / ".codex" / "tmp" / "imessage_inbound_cursor.json")

    def test_telegram_inbound_cursor_path_defaults_to_shared_codex_home_in_claude_runtime(self) -> None:
        with mock.patch.dict(
            cp.os.environ,  # type: ignore[attr-defined]
            {
                "AGENT_CHAT_AGENT": "claude",
                "AGENT_CHAT_HOME": "/tmp/claude-home",
                "CLAUDE_HOME": "/tmp/claude-home",
            },
            clear=False,
        ):
            cursor_path = cp._telegram_inbound_cursor_path(codex_home=Path("/tmp/claude-home"))  # type: ignore[attr-defined]

        self.assertEqual(cursor_path, Path.home() / ".codex" / "tmp" / "telegram_inbound_cursor.json")

    def test_ensure_inbound_cursor_seed_reseeds_when_existing_cursor_is_zero(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            codex_home = Path(td)
            cursor_path = codex_home / "tmp" / "imessage_inbound_cursor.json"
            cursor_path.parent.mkdir(parents=True, exist_ok=True)
            cursor_path.write_text(json.dumps({"last_rowid": 0, "ts": 1}), encoding="utf-8")

            with mock.patch.object(cp.reply, "_max_rowid", return_value=1234):
                rowid = cp._ensure_inbound_cursor_seed(  # type: ignore[attr-defined]
                    codex_home=codex_home,
                    conn=mock.Mock(spec=sqlite3.Connection),
                    recipient="+15551234567",
                    handle_ids=["+15551234567"],
                )

            self.assertEqual(rowid, 1234)
            saved = json.loads(cursor_path.read_text(encoding="utf-8"))
            self.assertEqual(saved.get("last_rowid"), 1234)
            self.assertEqual(saved.get("recipient"), "+15551234567")
            self.assertEqual(saved.get("handle_ids"), ["+15551234567"])

    def test_ensure_inbound_cursor_seed_reseeds_when_recipient_changes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            codex_home = Path(td)
            cursor_path = codex_home / "tmp" / "imessage_inbound_cursor.json"
            cursor_path.parent.mkdir(parents=True, exist_ok=True)
            cursor_path.write_text(
                json.dumps(
                    {
                        "last_rowid": 500,
                        "ts": 1,
                        "recipient": "+15550000000",
                        "handle_ids": ["+15550000000"],
                    }
                ),
                encoding="utf-8",
            )

            with mock.patch.object(cp.reply, "_max_rowid", return_value=1234):
                rowid = cp._ensure_inbound_cursor_seed(  # type: ignore[attr-defined]
                    codex_home=codex_home,
                    conn=mock.Mock(spec=sqlite3.Connection),
                    recipient="+15551234567",
                    handle_ids=["+15551234567"],
                )

            self.assertEqual(rowid, 1234)
            saved = json.loads(cursor_path.read_text(encoding="utf-8"))
            self.assertEqual(saved.get("last_rowid"), 1234)
            self.assertEqual(saved.get("recipient"), "+15551234567")
            self.assertEqual(saved.get("handle_ids"), ["+15551234567"])

    def test_ensure_inbound_cursor_seed_keeps_existing_when_metadata_matches(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            codex_home = Path(td)
            cursor_path = codex_home / "tmp" / "imessage_inbound_cursor.json"
            cursor_path.parent.mkdir(parents=True, exist_ok=True)
            cursor_path.write_text(
                json.dumps(
                    {
                        "last_rowid": 500,
                        "ts": 1,
                        "recipient": "+15551234567",
                        "handle_ids": ["+15551234567"],
                    }
                ),
                encoding="utf-8",
            )

            with mock.patch.object(cp.reply, "_max_rowid") as max_rowid_mock:
                rowid = cp._ensure_inbound_cursor_seed(  # type: ignore[attr-defined]
                    codex_home=codex_home,
                    conn=mock.Mock(spec=sqlite3.Connection),
                    recipient="+15551234567",
                    handle_ids=["+15551234567"],
                )

            self.assertEqual(rowid, 500)
            max_rowid_mock.assert_not_called()

    def test_extract_notify_context_fields_captures_tmux_socket(self) -> None:
        with mock.patch.dict(
            cp.os.environ,  # type: ignore[attr-defined]
            {
                "TMUX_PANE": "%9",
                "TMUX": "/tmp/tmux-501/default,12345,0",
                "PWD": "/tmp/project",
            },
            clear=True,
        ):
            fields = cp._extract_notify_context_fields(  # type: ignore[attr-defined]
                payload={},
                params=None,
            )

        self.assertEqual(fields.get("tmux_pane"), "%9")
        self.assertEqual(fields.get("tmux_socket"), "/tmp/tmux-501/default")
        self.assertEqual(fields.get("cwd"), "/tmp/project")

    def test_extract_notify_context_fields_ignores_terminal_context(self) -> None:
        with mock.patch.dict(
            cp.os.environ,  # type: ignore[attr-defined]
            {
                "TERM_PROGRAM": "ExampleTerminal.app",
                "ITERM_SESSION_ID": "w0t1p2:ABCDEF",
                "TTY": "/dev/ttys014",
                "PWD": "/tmp/project",
            },
            clear=True,
        ):
            fields = cp._extract_notify_context_fields(  # type: ignore[attr-defined]
                payload={},
                params=None,
            )

        self.assertNotIn("terminal_app", fields)
        self.assertNotIn("terminal_session_id", fields)
        self.assertNotIn("terminal_tty", fields)
        self.assertEqual(fields.get("cwd"), "/tmp/project")

    def test_extract_notify_context_fields_maps_transcript_path(self) -> None:
        fields = cp._extract_notify_context_fields(  # type: ignore[attr-defined]
            payload={"transcript_path": "/tmp/claude-session.jsonl"},
            params=None,
        )
        self.assertEqual(fields.get("session_path"), "/tmp/claude-session.jsonl")

    def test_extract_notify_context_fields_prefers_payload_agent_over_runtime(self) -> None:
        with mock.patch.dict(
            cp.os.environ,  # type: ignore[attr-defined]
            {"AGENT_CHAT_AGENT": "claude"},
            clear=False,
        ):
            fields = cp._extract_notify_context_fields(  # type: ignore[attr-defined]
                payload={"agent": "codex"},
                params=None,
            )
        self.assertEqual(fields.get("agent"), "codex")

    def test_handle_notify_payload_routes_input_event(self) -> None:
        payload = {
            "type": "needs-input",
            "thread-id": "sid-123",
            "cwd": "/tmp/project",
            "call_id": "call-1",
        }
        registry: dict[str, object] = {"sessions": {}}
        message_index: dict[str, object] = {}
        sent: list[dict[str, object]] = []

        def _capture_send(**kwargs: object) -> None:
            sent.append(dict(kwargs))

        with tempfile.TemporaryDirectory() as td:
            codex_home = Path(td)
            with (
                mock.patch.object(cp, "_load_registry", return_value=registry),
                mock.patch.object(cp, "_load_message_index", return_value=message_index),
                mock.patch.object(cp, "_save_registry"),
                mock.patch.object(cp, "_save_message_index"),
                mock.patch.object(cp, "_send_structured", side_effect=_capture_send),
                mock.patch.object(cp.agent_chat_dedupe, "mark_once", return_value=True),
                mock.patch("subprocess.Popen") as popen_mock,
            ):
                cp._handle_notify_payload(  # type: ignore[attr-defined]
                    codex_home=codex_home,
                    recipient="+15551234567",
                    payload_text=json.dumps(payload),
                    dry_run=False,
                )

        self.assertTrue(any(msg.get("kind") == "needs_input" for msg in sent))
        self.assertEqual(registry["sessions"]["sid-123"]["awaiting_input"], True)  # type: ignore[index]
        self.assertEqual(registry["sessions"]["sid-123"]["pending_completion"], True)  # type: ignore[index]
        popen_mock.assert_not_called()

    def test_handle_notify_payload_completion_accepts_session_id_key(self) -> None:
        payload = {
            "type": "agent-turn-complete",
            "session_id": "sid-123",
            "last-assistant-message": "done",
        }
        sent: list[dict[str, object]] = []

        def _capture_send(**kwargs: object) -> None:
            sent.append(dict(kwargs))

        with tempfile.TemporaryDirectory() as td:
            codex_home = Path(td)
            with (
                mock.patch.object(cp, "_send_structured", side_effect=_capture_send),
                mock.patch.object(cp.agent_chat_dedupe, "mark_once", return_value=True),
            ):
                cp._handle_notify_payload(  # type: ignore[attr-defined]
                    codex_home=codex_home,
                    recipient="+15551234567",
                    payload_text=json.dumps(payload),
                    dry_run=False,
                )

        self.assertTrue(any(msg.get("kind") == "responded" for msg in sent))
        self.assertTrue(any(msg.get("session_id") == "sid-123" for msg in sent))

    def test_handle_notify_payload_completion_from_hook_event_name(self) -> None:
        payload = {
            "hook_event_name": "Stop",
            "session_id": "sid-123",
            "last_assistant_message": "done",
        }
        sent: list[dict[str, object]] = []

        def _capture_send(**kwargs: object) -> None:
            sent.append(dict(kwargs))

        with tempfile.TemporaryDirectory() as td:
            codex_home = Path(td)
            with (
                mock.patch.object(cp, "_send_structured", side_effect=_capture_send),
                mock.patch.object(cp.agent_chat_dedupe, "mark_once", return_value=True),
            ):
                cp._handle_notify_payload(  # type: ignore[attr-defined]
                    codex_home=codex_home,
                    recipient="+15551234567",
                    payload_text=json.dumps(payload),
                    dry_run=False,
                )

        self.assertTrue(any(msg.get("kind") == "responded" for msg in sent))
        self.assertTrue(any(msg.get("session_id") == "sid-123" for msg in sent))

    def test_resolve_session_ref_exact_match(self) -> None:
        registry = {
            "sessions": {
                "019c33b4-e0ed-7021-940a-02b1e8147a82": {"alias": "alpha"},
            }
        }
        sid, err = cp._resolve_session_ref(registry=registry, session_ref="019c33b4-e0ed-7021-940a-02b1e8147a82")  # type: ignore[attr-defined]
        self.assertEqual(sid, "019c33b4-e0ed-7021-940a-02b1e8147a82")
        self.assertIsNone(err)

    def test_resolve_session_ref_alias(self) -> None:
        registry = {
            "sessions": {
                "019c33b4-e0ed-7021-940a-02b1e8147a82": {"alias": "alpha"},
            }
        }
        sid, err = cp._resolve_session_ref(registry=registry, session_ref="alpha")  # type: ignore[attr-defined]
        self.assertEqual(sid, "019c33b4-e0ed-7021-940a-02b1e8147a82")
        self.assertIsNone(err)

    def test_resolve_session_ref_unique_prefix(self) -> None:
        registry = {
            "sessions": {
                "019c33b4-e0ed-7021-940a-02b1e8147a82": {"alias": "alpha"},
                "019c55aa-e0ed-7021-940a-02b1e8147a81": {"alias": "beta"},
            }
        }
        sid, err = cp._resolve_session_ref(registry=registry, session_ref="019c33b4", min_prefix=6)  # type: ignore[attr-defined]
        self.assertEqual(sid, "019c33b4-e0ed-7021-940a-02b1e8147a82")
        self.assertIsNone(err)

    def test_resolve_session_ref_ambiguous_prefix(self) -> None:
        registry = {
            "sessions": {
                "019c33b4-e0ed-7021-940a-02b1e8147a82": {"alias": "alpha"},
                "019c33b4-1234-7021-940a-02b1e8147a81": {"alias": "beta"},
            }
        }
        sid, err = cp._resolve_session_ref(registry=registry, session_ref="019c33b4", min_prefix=6)  # type: ignore[attr-defined]
        self.assertIsNone(sid)
        self.assertIsInstance(err, str)
        if not isinstance(err, str):
            self.fail("expected ambiguous prefix error text")
        self.assertIn("Ambiguous", err)

    def test_choose_implicit_session_unique_waiting(self) -> None:
        registry = {
            "sessions": {
                "sid1": {"awaiting_input": False, "last_attention_ts": 1},
                "sid2": {"awaiting_input": True, "last_attention_ts": 2},
            }
        }
        sid, err = cp._choose_implicit_session(registry=registry)  # type: ignore[attr-defined]
        self.assertEqual(sid, "sid2")
        self.assertIsNone(err)

    def test_choose_implicit_session_ambiguous(self) -> None:
        registry = {
            "sessions": {
                "sid1": {"awaiting_input": True, "last_attention_ts": 1},
                "sid2": {"awaiting_input": True, "last_attention_ts": 2},
            }
        }
        sid, err = cp._choose_implicit_session(registry=registry)  # type: ignore[attr-defined]
        self.assertIsNone(sid)
        self.assertIsInstance(err, str)
        if not isinstance(err, str):
            self.fail("expected ambiguous implicit session error text")
        self.assertIn("Ambiguous", err)

    def test_resolve_session_from_reply_context_conflicting_guids_prefers_first_resolved_guid(self) -> None:
        conn = sqlite3.connect(":memory:")
        sid_a = "019c891f-bb63-71d2-ab92-40a574111e9f"
        sid_b = "019c891f-cfa2-7e43-a60e-df1d683e6fe5"
        guid_a = "GUID-A"
        guid_b = "GUID-B"

        with mock.patch.object(
            cp.reply,
            "_get_message_text_by_guid",
            side_effect=[
                f"[Codex] {sid_a} — responded — t",
                f"[Codex] {sid_b} — responded — t",
            ],
        ):
            sid, err = cp._resolve_session_from_reply_context(  # type: ignore[attr-defined]
                conn=conn,
                reply_text="Only one session?",
                reply_to_guid=guid_a,
                reply_reference_guids=[guid_a, guid_b],
                registry={"sessions": {sid_a: {}, sid_b: {}}},
                message_index={"messages": []},
                require_explicit_ref=True,
            )

        self.assertEqual(sid, sid_a)
        self.assertIsNone(err)

    def test_resolve_session_from_reply_context_uses_ref_from_replied_text_when_uuid_missing(self) -> None:
        conn = sqlite3.connect(":memory:")
        sid = "019c902c-40c0-7253-9580-e7f7ae35eb3d"
        sid_ref = sid[:8]

        with mock.patch.object(
            cp.reply,
            "_get_message_text_by_guid",
            return_value=f"[Codex] @{sid_ref} — accepted — 2026-02-24T07:54:32-08:00",
        ):
            resolved, err = cp._resolve_session_from_reply_context(  # type: ignore[attr-defined]
                conn=conn,
                reply_text="continue",
                reply_to_guid="GUID-REF-ONLY",
                reply_reference_guids=["GUID-REF-ONLY"],
                registry={"sessions": {sid: {}}},
                message_index={"messages": []},
                require_explicit_ref=True,
            )

        self.assertEqual(resolved, sid)
        self.assertIsNone(err)

    def test_resolve_session_from_reply_context_prefers_ref_over_hash(self) -> None:
        conn = sqlite3.connect(":memory:")
        sid_ref_target = "019c902c-40c0-7253-9580-e7f7ae35eb3d"
        sid_hash_other = "019c8e4f-392c-7650-84e4-1cbb73ae8037"
        replied_text = f"[Codex] @{sid_ref_target[:8]} — accepted — follow execution on your Mac."

        with mock.patch.object(cp.reply, "_get_message_text_by_guid", return_value=replied_text):
            resolved, err = cp._resolve_session_from_reply_context(  # type: ignore[attr-defined]
                conn=conn,
                reply_text="continue",
                reply_to_guid="GUID-REF-HASH",
                reply_reference_guids=["GUID-REF-HASH"],
                registry={"sessions": {sid_ref_target: {}, sid_hash_other: {}}},
                message_index={
                    "messages": [
                        {
                            "ts": 1,
                            "session_id": sid_hash_other,
                            "kind": "accepted",
                            "hash": cp._message_hash(replied_text),  # type: ignore[attr-defined]
                        }
                    ]
                },
                require_explicit_ref=True,
            )

        self.assertEqual(resolved, sid_ref_target)
        self.assertIsNone(err)

    def test_resolve_session_from_reply_context_does_not_use_hash_when_ref_is_ambiguous(self) -> None:
        conn = sqlite3.connect(":memory:")
        sid_a = "019c1234-1111-7111-8111-111111111111"
        sid_b = "019c1234-2222-7222-8222-222222222222"
        sid_hash_other = "019c8e4f-392c-7650-84e4-1cbb73ae8037"
        replied_text = "[Codex] @019c1234 — accepted — follow execution on your Mac."

        with mock.patch.object(cp.reply, "_get_message_text_by_guid", return_value=replied_text):
            resolved, err = cp._resolve_session_from_reply_context(  # type: ignore[attr-defined]
                conn=conn,
                reply_text="continue",
                reply_to_guid="GUID-AMBIG",
                reply_reference_guids=["GUID-AMBIG"],
                registry={"sessions": {sid_a: {}, sid_b: {}, sid_hash_other: {}}},
                message_index={
                    "messages": [
                        {
                            "ts": 1,
                            "session_id": sid_hash_other,
                            "kind": "accepted",
                            "hash": cp._message_hash(replied_text),  # type: ignore[attr-defined]
                        }
                    ]
                },
                require_explicit_ref=True,
            )

        self.assertIsNone(resolved)
        self.assertIsInstance(err, str)
        if not isinstance(err, str):
            self.fail("expected strict tmux routing error text")
        self.assertIn("Strict tmux routing", err)

    def test_resolve_session_from_reply_context_uses_hash_only_when_session_waiting(self) -> None:
        conn = sqlite3.connect(":memory:")
        sid = "019c8e4f-392c-7650-84e4-1cbb73ae8037"
        replied_text = "[Codex] acknowledged."

        with mock.patch.object(cp.reply, "_get_message_text_by_guid", return_value=replied_text):
            resolved, err = cp._resolve_session_from_reply_context(  # type: ignore[attr-defined]
                conn=conn,
                reply_text="continue",
                reply_to_guid="GUID-HASH-WAITING",
                reply_reference_guids=["GUID-HASH-WAITING"],
                registry={"sessions": {sid: {"awaiting_input": True}}},
                message_index={
                    "messages": [
                        {
                            "ts": 1,
                            "session_id": sid,
                            "kind": "responded",
                            "hash": cp._message_hash(replied_text),  # type: ignore[attr-defined]
                        }
                    ]
                },
                require_explicit_ref=True,
            )

        self.assertEqual(resolved, sid)
        self.assertIsNone(err)

    def test_resolve_session_from_reply_context_uses_reply_reference_texts_without_guids(self) -> None:
        conn = sqlite3.connect(":memory:")
        sid = "019c902c-40c0-7253-9580-e7f7ae35eb3d"
        sid_ref = sid[:8]

        resolved, err = cp._resolve_session_from_reply_context(  # type: ignore[attr-defined]
            conn=conn,
            reply_text="continue",
            reply_to_guid=None,
            reply_reference_guids=[],
            reply_reference_texts=[f"[Codex] @{sid_ref} — accepted — follow execution on your Mac."],
            registry={"sessions": {sid: {}}},
            message_index={"messages": []},
            require_explicit_ref=True,
        )

        self.assertEqual(resolved, sid)
        self.assertIsNone(err)

    def test_resolve_session_from_reply_context_does_not_use_hash_when_session_not_waiting(self) -> None:
        conn = sqlite3.connect(":memory:")
        sid = "019c8e4f-392c-7650-84e4-1cbb73ae8037"
        replied_text = "[Codex] acknowledged."

        with mock.patch.object(cp.reply, "_get_message_text_by_guid", return_value=replied_text):
            resolved, err = cp._resolve_session_from_reply_context(  # type: ignore[attr-defined]
                conn=conn,
                reply_text="continue",
                reply_to_guid="GUID-HASH-NOT-WAITING",
                reply_reference_guids=["GUID-HASH-NOT-WAITING"],
                registry={"sessions": {sid: {"awaiting_input": False}}},
                message_index={
                    "messages": [
                        {
                            "ts": 1,
                            "session_id": sid,
                            "kind": "responded",
                            "hash": cp._message_hash(replied_text),  # type: ignore[attr-defined]
                        }
                    ]
                },
                require_explicit_ref=True,
            )

        self.assertIsNone(resolved)
        self.assertIsInstance(err, str)
        if not isinstance(err, str):
            self.fail("expected strict tmux routing error text")
        self.assertIn("Strict tmux routing", err)

    def test_reply_reference_guids_for_row_collects_and_orders_candidates(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.execute(
            """
            CREATE TABLE message (
              ROWID INTEGER PRIMARY KEY,
              reply_to_guid TEXT,
              thread_originator_guid TEXT,
              associated_message_guid TEXT
            )
            """
        )
        conn.execute(
            """
            INSERT INTO message (ROWID, reply_to_guid, thread_originator_guid, associated_message_guid)
            VALUES (10, 'REPLY', 'THREAD', 'ASSOC')
            """
        )

        guids = cp._reply_reference_guids_for_row(  # type: ignore[attr-defined]
            conn=conn,
            rowid=10,
            fallback_guid="THREAD",
        )

        self.assertEqual(guids, ["THREAD", "REPLY", "ASSOC"])

    def test_reply_reference_guids_for_row_excludes_thread_originator_when_fallback_missing(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.execute(
            """
            CREATE TABLE message (
              ROWID INTEGER PRIMARY KEY,
              reply_to_guid TEXT,
              thread_originator_guid TEXT,
              associated_message_guid TEXT
            )
            """
        )
        conn.execute(
            """
            INSERT INTO message (ROWID, reply_to_guid, thread_originator_guid, associated_message_guid)
            VALUES (10, 'REPLY', 'THREAD', 'ASSOC')
            """
        )

        guids = cp._reply_reference_guids_for_row(  # type: ignore[attr-defined]
            conn=conn,
            rowid=10,
            fallback_guid=None,
        )

        self.assertEqual(guids, ["REPLY", "ASSOC"])

    def test_dispatch_prompt_prefers_tmux(self) -> None:
        sid = "019c33b4-e0ed-7021-940a-02b1e8147a82"
        rec = {
            "cwd": "/tmp/project",
            "tmux_pane": "%9",
            "session_path": f"/tmp/sessions/{sid}.jsonl",
        }

        with (
            mock.patch.object(cp.reply, "_session_path_matches_session_id", return_value=True),
            mock.patch.object(cp, "_tmux_pane_exists", return_value=True),
            mock.patch.object(cp, "_tmux_pane_matches_session", return_value=True, create=True),
            mock.patch.object(cp.reply, "_read_last_user_text_from_session", return_value="before"),
            mock.patch.object(cp.reply, "_wait_for_new_user_text", return_value="after"),
            mock.patch.object(cp.reply, "_tmux_send_prompt", return_value=True) as tmux_send_mock,
            mock.patch.object(cp.reply, "_run_codex_resume", return_value="fallback") as resume_mock,
        ):
            mode, response = cp._dispatch_prompt_to_session(  # type: ignore[attr-defined]
                target_sid=sid,
                prompt="continue",
                session_rec=rec,
                codex_home=Path("/tmp/codex-home"),
            )

        self.assertEqual(mode, "tmux")
        self.assertIsNone(response)
        tmux_send_mock.assert_called_once_with(pane="%9", prompt="continue")
        resume_mock.assert_not_called()

    def test_tmux_discover_codex_pane_for_session_unique_cwd(self) -> None:
        rec = {"cwd": "/tmp/project"}
        pane_listing = "\n".join(
            [
                "%2\tzsh\t/tmp/project",
                "%3\tcodex-aarch64-a\t/tmp/other",
                "%9\tcodex\t/tmp/project",
            ]
        )

        with mock.patch(
            "subprocess.run",
            return_value=mock.Mock(returncode=0, stdout=pane_listing),
        ):
            pane, socket = cp._tmux_discover_codex_pane_for_session(  # type: ignore[attr-defined]
                session_rec=rec,
                tmux_socket="/tmp/tmux-501/default",
            )

        self.assertEqual(pane, "%9")
        self.assertEqual(socket, "/tmp/tmux-501/default")

    def test_tmux_discover_codex_pane_for_session_uses_session_id_when_cwd_ambiguous(self) -> None:
        sid = "019c652e-11a2-7a90-9d30-da780acb95c8"
        rec = {"cwd": "/Users/testuser"}
        pane_listing = "\n".join(
            [
                "%0\tcodex-aarch64-a\t/Users/testuser",
                "%2\tcodex-aarch64-a\t/Users/testuser",
            ]
        )

        with mock.patch(
            "subprocess.run",
            side_effect=[
                mock.Mock(returncode=0, stdout=pane_listing),
                mock.Mock(returncode=0, stdout=f"... {sid} ..."),
                mock.Mock(returncode=0, stdout="... some other session ..."),
            ],
        ):
            pane, socket = cp._tmux_discover_codex_pane_for_session(  # type: ignore[attr-defined]
                session_rec=rec,
                session_id=sid,
                tmux_socket="/tmp/tmux-501/default",
            )

        self.assertEqual(pane, "%0")
        self.assertEqual(socket, "/tmp/tmux-501/default")

    def test_tmux_pane_matches_session_requires_session_id_hint_when_cwd_ambiguous(self) -> None:
        sid = "019c652e-11a2-7a90-9d30-da780acb95c8"
        rec = {"cwd": "/Users/testuser"}
        with (
            mock.patch.object(
                cp,
                "_tmux_read_pane_context",
                return_value=("codex-aarch64-a", "/Users/testuser"),
            ),
            mock.patch.object(
                cp,
                "_tmux_codex_panes_for_cwd",
                return_value=["%0", "%1"],
                create=True,
            ),
            mock.patch.object(cp, "_tmux_pane_mentions_session_id", return_value=False),
        ):
            matches = cp._tmux_pane_matches_session(  # type: ignore[attr-defined]
                pane="%0",
                session_rec=rec,
                session_id=sid,
            )

        self.assertFalse(matches)

    def test_tmux_pane_matches_session_accepts_session_id_hint_when_cwd_ambiguous(self) -> None:
        sid = "019c652e-11a2-7a90-9d30-da780acb95c8"
        rec = {"cwd": "/Users/testuser"}
        with (
            mock.patch.object(
                cp,
                "_tmux_read_pane_context",
                return_value=("codex-aarch64-a", "/Users/testuser"),
            ),
            mock.patch.object(
                cp,
                "_tmux_codex_panes_for_cwd",
                return_value=["%0", "%1"],
                create=True,
            ),
            mock.patch.object(cp, "_tmux_pane_mentions_session_id", return_value=True),
        ):
            matches = cp._tmux_pane_matches_session(  # type: ignore[attr-defined]
                pane="%0",
                session_rec=rec,
                session_id=sid,
            )

        self.assertTrue(matches)

    def test_tmux_pane_matches_session_keeps_cwd_match_when_unambiguous(self) -> None:
        sid = "019c652e-11a2-7a90-9d30-da780acb95c8"
        rec = {"cwd": "/Users/testuser"}
        with (
            mock.patch.object(
                cp,
                "_tmux_read_pane_context",
                return_value=("codex-aarch64-a", "/Users/testuser"),
            ),
            mock.patch.object(
                cp,
                "_tmux_codex_panes_for_cwd",
                return_value=["%0"],
                create=True,
            ),
            mock.patch.object(cp, "_tmux_pane_mentions_session_id", return_value=False),
        ):
            matches = cp._tmux_pane_matches_session(  # type: ignore[attr-defined]
                pane="%0",
                session_rec=rec,
                session_id=sid,
            )

        self.assertTrue(matches)

    def test_tmux_pane_matches_session_uses_explicit_agent_not_runtime(self) -> None:
        sid = "019c652e-11a2-7a90-9d30-da780acb95c8"
        rec = {"cwd": "/Users/testuser"}
        with (
            mock.patch.object(
                cp,
                "_tmux_read_pane_context",
                return_value=("codex-aarch64-a", "/Users/testuser"),
            ),
            mock.patch.object(
                cp,
                "_tmux_codex_panes_for_cwd",
                return_value=["%0"],
                create=True,
            ),
            mock.patch.dict(cp.os.environ, {"AGENT_CHAT_AGENT": "claude"}, clear=False),
        ):
            matches = cp._tmux_pane_matches_session(  # type: ignore[attr-defined]
                pane="%0",
                session_rec=rec,
                session_id=sid,
                agent="codex",
            )

        self.assertTrue(matches)

    def test_tmux_discover_codex_pane_for_session_uses_explicit_agent_not_runtime(self) -> None:
        rec = {"cwd": "/Users/testuser"}
        pane_listing = "\n".join(
            [
                "%0\tcodex-aarch64-a\t/Users/testuser",
                "%23\tclaude\t/Users/testuser",
            ]
        )

        with (
            mock.patch("subprocess.run", return_value=mock.Mock(returncode=0, stdout=pane_listing)),
            mock.patch.dict(cp.os.environ, {"AGENT_CHAT_AGENT": "claude"}, clear=False),
        ):
            pane, socket = cp._tmux_discover_codex_pane_for_session(  # type: ignore[attr-defined]
                session_rec=rec,
                session_id=None,
                tmux_socket="/tmp/tmux-501/default",
                agent="codex",
            )

        self.assertEqual(pane, "%0")
        self.assertEqual(socket, "/tmp/tmux-501/default")

    def test_dispatch_prompt_discovery_uses_session_agent_over_runtime(self) -> None:
        sid = "019c33b4-e0ed-7021-940a-02b1e8147a82"
        rec = {
            "agent": "codex",
            "cwd": "/tmp/project",
            "session_path": f"/tmp/sessions/{sid}.jsonl",
        }

        discover_mock = mock.Mock(return_value=("%12", "/tmp/tmux-501/default"))
        pane_match_mock = mock.Mock(return_value=True)
        with (
            mock.patch.object(cp.reply, "_session_path_matches_session_id", return_value=True),
            mock.patch.object(cp, "_tmux_discover_codex_pane_for_session", discover_mock),
            mock.patch.object(cp, "_tmux_pane_exists", return_value=True),
            mock.patch.object(cp, "_tmux_pane_matches_session", pane_match_mock, create=True),
            mock.patch.object(cp.reply, "_read_last_user_text_from_session", return_value="before"),
            mock.patch.object(cp.reply, "_wait_for_new_user_text", return_value="after"),
            mock.patch.object(cp.reply, "_tmux_send_prompt", return_value=True) as tmux_send_mock,
            mock.patch.object(cp.reply, "_run_agent_resume", return_value="fallback") as resume_mock,
            mock.patch.dict(cp.os.environ, {"AGENT_CHAT_AGENT": "claude"}, clear=False),
        ):
            mode, response = cp._dispatch_prompt_to_session(  # type: ignore[attr-defined]
                target_sid=sid,
                prompt="continue",
                session_rec=rec,
                codex_home=Path("/tmp/codex-home"),
                agent="codex",
            )

        self.assertEqual(mode, "tmux")
        self.assertIsNone(response)
        discover_mock.assert_called_once_with(
            session_rec=rec,
            session_id=sid,
            tmux_socket=None,
            agent="codex",
        )
        pane_match_mock.assert_called_once_with(
            pane="%12",
            session_rec=rec,
            session_id=sid,
            tmux_socket="/tmp/tmux-501/default",
            agent="codex",
        )
        tmux_send_mock.assert_called_once_with(
            pane="%12",
            prompt="continue",
            tmux_socket="/tmp/tmux-501/default",
        )
        resume_mock.assert_not_called()

    def test_tmux_pane_mentions_session_id_uses_latest_session_id_in_capture(self) -> None:
        old_sid = "019c891f-cfa2-7e43-a60e-df1d683e6fe5"
        new_sid = "019c891f-bb63-71d2-ab92-40a574111e9f"
        pane_capture = (
            f"[Codex] {old_sid} — responded — 2026-02-23T13:45:12-08:00\\n"
            "Some output\\n"
            f"~ · {new_sid} · 6.74M used · gpt-5.3-codex xhigh\\n"
        )

        with mock.patch(
            "subprocess.run",
            return_value=mock.Mock(returncode=0, stdout=pane_capture),
        ):
            old_matches = cp._tmux_pane_mentions_session_id(  # type: ignore[attr-defined]
                pane="%0",
                session_id=old_sid,
            )
            new_matches = cp._tmux_pane_mentions_session_id(  # type: ignore[attr-defined]
                pane="%0",
                session_id=new_sid,
            )

        self.assertFalse(old_matches)
        self.assertTrue(new_matches)

    def test_dispatch_prompt_discovers_tmux_pane_when_missing(self) -> None:
        sid = "019c33b4-e0ed-7021-940a-02b1e8147a82"
        rec = {
            "cwd": "/tmp/project",
            "session_path": f"/tmp/sessions/{sid}.jsonl",
        }

        discover_mock = mock.Mock(return_value=("%12", "/tmp/tmux-501/default"))
        with (
            mock.patch.object(cp.reply, "_session_path_matches_session_id", return_value=True),
            mock.patch.object(cp, "_tmux_discover_codex_pane_for_session", discover_mock),
            mock.patch.object(cp, "_tmux_pane_exists", return_value=True),
            mock.patch.object(cp, "_tmux_pane_matches_session", return_value=True, create=True),
            mock.patch.object(cp.reply, "_read_last_user_text_from_session", return_value="before"),
            mock.patch.object(cp.reply, "_wait_for_new_user_text", return_value="after"),
            mock.patch.object(cp.reply, "_tmux_send_prompt", return_value=True) as tmux_send_mock,
            mock.patch.object(cp.reply, "_run_codex_resume", return_value="fallback") as resume_mock,
        ):
            mode, response = cp._dispatch_prompt_to_session(  # type: ignore[attr-defined]
                target_sid=sid,
                prompt="continue",
                session_rec=rec,
                codex_home=Path("/tmp/codex-home"),
            )

        self.assertEqual(mode, "tmux")
        self.assertIsNone(response)
        self.assertEqual(rec.get("tmux_pane"), "%12")
        self.assertEqual(rec.get("tmux_socket"), "/tmp/tmux-501/default")
        discover_mock.assert_called_once_with(
            session_rec=rec,
            session_id=sid,
            tmux_socket=None,
            agent="codex",
        )
        tmux_send_mock.assert_called_once_with(
            pane="%12",
            prompt="continue",
            tmux_socket="/tmp/tmux-501/default",
        )
        resume_mock.assert_not_called()

    def test_dispatch_prompt_tmux_stale_pane_discovers_replacement(self) -> None:
        sid = "019c33b4-e0ed-7021-940a-02b1e8147a82"
        rec = {
            "cwd": "/tmp/project",
            "tmux_pane": "%4",
            "session_path": f"/tmp/sessions/{sid}.jsonl",
        }

        with (
            mock.patch.object(cp.reply, "_session_path_matches_session_id", return_value=True),
            mock.patch.object(cp, "_tmux_discover_codex_pane_for_session", return_value=("%12", None)),
            mock.patch.object(cp, "_tmux_pane_exists", side_effect=[False, True]),
            mock.patch.object(cp, "_tmux_pane_matches_session", return_value=True, create=True),
            mock.patch.object(cp.reply, "_read_last_user_text_from_session", return_value="before"),
            mock.patch.object(cp.reply, "_wait_for_new_user_text", return_value="after"),
            mock.patch.object(cp.reply, "_tmux_send_prompt", return_value=True) as tmux_send_mock,
            mock.patch.object(cp.reply, "_run_codex_resume", return_value="fallback") as resume_mock,
        ):
            mode, response = cp._dispatch_prompt_to_session(  # type: ignore[attr-defined]
                target_sid=sid,
                prompt="continue",
                session_rec=rec,
                codex_home=Path("/tmp/codex-home"),
            )

        self.assertEqual(mode, "tmux")
        self.assertIsNone(response)
        self.assertEqual(rec.get("tmux_pane"), "%12")
        tmux_send_mock.assert_called_once_with(pane="%12", prompt="continue")
        resume_mock.assert_not_called()

    def test_dispatch_prompt_treats_mismatched_pane_context_as_stale(self) -> None:
        sid = "019c33b4-e0ed-7021-940a-02b1e8147a82"
        rec = {
            "cwd": "/tmp/project",
            "tmux_pane": "%9",
            "session_path": f"/tmp/sessions/{sid}.jsonl",
        }

        with (
            mock.patch.object(cp.reply, "_session_path_matches_session_id", return_value=True),
            mock.patch.object(cp, "_tmux_pane_exists", return_value=True),
            mock.patch.object(cp, "_tmux_pane_matches_session", return_value=False, create=True),
            mock.patch.object(cp, "_tmux_discover_codex_pane_for_session", return_value=(None, None)),
            mock.patch.object(cp.reply, "_tmux_send_prompt", return_value=True) as tmux_send_mock,
            mock.patch.object(cp.reply, "_run_codex_resume", return_value="fallback") as resume_mock,
        ):
            mode, response = cp._dispatch_prompt_to_session(  # type: ignore[attr-defined]
                target_sid=sid,
                prompt="continue",
                session_rec=rec,
                codex_home=Path("/tmp/codex-home"),
            )

        self.assertEqual(mode, "tmux_stale")
        self.assertIsNone(response)
        tmux_send_mock.assert_not_called()
        resume_mock.assert_not_called()

    def test_dispatch_prompt_prefers_tmux_with_socket(self) -> None:
        sid = "019c33b4-e0ed-7021-940a-02b1e8147a82"
        rec = {
            "cwd": "/tmp/project",
            "tmux_pane": "%9",
            "tmux_socket": "/tmp/tmux-501/default",
            "session_path": f"/tmp/sessions/{sid}.jsonl",
        }

        with (
            mock.patch.object(cp.reply, "_session_path_matches_session_id", return_value=True),
            mock.patch.object(cp, "_tmux_pane_exists", return_value=True),
            mock.patch.object(cp, "_tmux_pane_matches_session", return_value=True, create=True),
            mock.patch.object(cp.reply, "_read_last_user_text_from_session", return_value="before"),
            mock.patch.object(cp.reply, "_wait_for_new_user_text", return_value="after"),
            mock.patch.object(cp.reply, "_tmux_send_prompt", return_value=True) as tmux_send_mock,
            mock.patch.object(cp.reply, "_run_codex_resume", return_value="fallback") as resume_mock,
        ):
            mode, response = cp._dispatch_prompt_to_session(  # type: ignore[attr-defined]
                target_sid=sid,
                prompt="continue",
                session_rec=rec,
                codex_home=Path("/tmp/codex-home"),
            )

        self.assertEqual(mode, "tmux")
        self.assertIsNone(response)
        tmux_send_mock.assert_called_once_with(
            pane="%9",
            prompt="continue",
            tmux_socket="/tmp/tmux-501/default",
        )
        resume_mock.assert_not_called()

    def test_dispatch_prompt_falls_back_to_resume(self) -> None:
        sid = "019c33b4-e0ed-7021-940a-02b1e8147a82"
        rec = {
            "cwd": "/tmp/project",
            "tmux_pane": "%9",
            "session_path": f"/tmp/sessions/{sid}.jsonl",
        }

        with (
            mock.patch.object(cp.reply, "_session_path_matches_session_id", return_value=False),
            mock.patch.object(cp.reply, "_tmux_send_prompt", return_value=True),
            mock.patch.object(cp.reply, "_run_codex_resume", return_value="ok") as resume_mock,
            mock.patch.dict(cp.os.environ, {"AGENT_CHAT_STRICT_TMUX": "0"}, clear=False),
        ):
            mode, response = cp._dispatch_prompt_to_session(  # type: ignore[attr-defined]
                target_sid=sid,
                prompt="continue",
                session_rec=rec,
                codex_home=Path("/tmp/codex-home"),
            )

        self.assertEqual(mode, "resume")
        self.assertEqual(response, "ok")
        resume_mock.assert_called_once()

    def test_dispatch_prompt_falls_back_to_resume_uses_session_agent_over_runtime(self) -> None:
        sid = "019c33b4-e0ed-7021-940a-02b1e8147a82"
        rec = {
            "agent": "codex",
            "cwd": "/tmp/project",
            "tmux_pane": "%9",
            "session_path": f"/tmp/sessions/{sid}.jsonl",
        }

        with (
            mock.patch.object(cp.reply, "_session_path_matches_session_id", return_value=False),
            mock.patch.object(cp.reply, "_tmux_send_prompt", return_value=True),
            mock.patch.object(cp.reply, "_run_agent_resume", return_value="ok") as resume_mock,
            mock.patch.dict(
                cp.os.environ,  # type: ignore[attr-defined]
                {"AGENT_CHAT_STRICT_TMUX": "0", "AGENT_CHAT_AGENT": "claude"},
                clear=False,
            ),
        ):
            mode, response = cp._dispatch_prompt_to_session(  # type: ignore[attr-defined]
                target_sid=sid,
                prompt="continue",
                session_rec=rec,
                codex_home=Path("/tmp/codex-home"),
            )

        self.assertEqual(mode, "resume")
        self.assertEqual(response, "ok")
        resume_mock.assert_called_once()
        self.assertEqual(resume_mock.call_args.kwargs.get("agent"), "codex")

    def test_dispatch_prompt_with_terminal_context_falls_back_to_resume(self) -> None:
        sid = "019c33b4-e0ed-7021-940a-02b1e8147a82"
        rec = {
            "cwd": "/tmp/project",
            "session_path": f"/tmp/sessions/{sid}.jsonl",
            "terminal_app": "ExampleTerminal",
            "terminal_tty": "/dev/ttys014",
        }

        with (
            mock.patch.object(cp.reply, "_session_path_matches_session_id", return_value=True),
            mock.patch.object(
                cp,
                "_terminal_send_prompt",
                side_effect=AssertionError("terminal routing should be disabled"),
                create=True,
            ),
            mock.patch.object(cp.reply, "_run_codex_resume", return_value="ok") as resume_mock,
            mock.patch.dict(cp.os.environ, {"AGENT_CHAT_STRICT_TMUX": "0"}, clear=False),
        ):
            mode, response = cp._dispatch_prompt_to_session(  # type: ignore[attr-defined]
                target_sid=sid,
                prompt="continue",
                session_rec=rec,
                codex_home=Path("/tmp/codex-home"),
            )

        self.assertEqual(mode, "resume")
        self.assertEqual(response, "ok")
        resume_mock.assert_called_once()

    def test_dispatch_prompt_tmux_send_failure_does_not_fallback(self) -> None:
        sid = "019c33b4-e0ed-7021-940a-02b1e8147a82"
        rec = {
            "cwd": "/tmp/project",
            "tmux_pane": "%9",
            "session_path": f"/tmp/sessions/{sid}.jsonl",
        }

        with (
            mock.patch.object(cp.reply, "_session_path_matches_session_id", return_value=True),
            mock.patch.object(cp, "_tmux_pane_exists", return_value=True),
            mock.patch.object(cp, "_tmux_pane_matches_session", return_value=True, create=True),
            mock.patch.object(cp.reply, "_tmux_send_prompt", return_value=False) as tmux_send_mock,
            mock.patch.object(cp.reply, "_run_codex_resume", return_value="ok") as resume_mock,
        ):
            mode, response = cp._dispatch_prompt_to_session(  # type: ignore[attr-defined]
                target_sid=sid,
                prompt="continue",
                session_rec=rec,
                codex_home=Path("/tmp/codex-home"),
            )

        self.assertEqual(mode, "tmux_failed")
        self.assertIsNone(response)
        tmux_send_mock.assert_called_once_with(pane="%9", prompt="continue")
        resume_mock.assert_not_called()

    def test_dispatch_prompt_tmux_no_ack_is_unconfirmed_but_not_fallback(self) -> None:
        sid = "019c33b4-e0ed-7021-940a-02b1e8147a82"
        rec = {
            "cwd": "/tmp/project",
            "tmux_pane": "%9",
            "session_path": f"/tmp/sessions/{sid}.jsonl",
        }
        submit_keys: list[str] = []

        def _capture_submit(cmd: list[str], **kwargs: object) -> mock.Mock:
            if "send-keys" in cmd and "-l" not in cmd:
                submit_keys.append(str(cmd[-1]))
            return mock.Mock(returncode=1)

        with (
            mock.patch.object(cp.reply, "_session_path_matches_session_id", return_value=True),
            mock.patch.object(cp, "_tmux_pane_exists", return_value=True),
            mock.patch.object(cp, "_tmux_pane_matches_session", return_value=True, create=True),
            mock.patch.object(cp.reply, "_read_last_user_text_from_session", return_value="before"),
            mock.patch.object(cp.reply, "_wait_for_new_user_text", return_value=None),
            mock.patch("subprocess.run", side_effect=_capture_submit),
            mock.patch.object(cp.reply, "_tmux_send_prompt", return_value=True) as tmux_send_mock,
            mock.patch.object(cp.reply, "_run_codex_resume", return_value="ok") as resume_mock,
        ):
            mode, response = cp._dispatch_prompt_to_session(  # type: ignore[attr-defined]
                target_sid=sid,
                prompt="continue",
                session_rec=rec,
                codex_home=Path("/tmp/codex-home"),
            )

        self.assertEqual(mode, "tmux_unconfirmed")
        self.assertIsNone(response)
        tmux_send_mock.assert_called_once_with(pane="%9", prompt="continue")
        resume_mock.assert_not_called()
        self.assertEqual(submit_keys, ["C-m", "Enter"])

    def test_dispatch_prompt_tmux_stale_pane_returns_tmux_stale(self) -> None:
        sid = "019c33b4-e0ed-7021-940a-02b1e8147a82"
        rec = {
            "cwd": "/tmp/project",
            "tmux_pane": "%4",
            "session_path": f"/tmp/sessions/{sid}.jsonl",
        }

        with (
            mock.patch.object(cp.reply, "_session_path_matches_session_id", return_value=True),
            mock.patch.object(cp.reply, "_read_last_user_text_from_session", return_value="before"),
            mock.patch.object(cp.reply, "_wait_for_new_user_text", return_value="after"),
            mock.patch.object(cp, "_tmux_pane_exists", return_value=False, create=True),
            mock.patch.object(cp, "_tmux_discover_codex_pane_for_session", return_value=(None, None)),
            mock.patch.object(cp.reply, "_tmux_send_prompt", return_value=True) as tmux_send_mock,
            mock.patch.object(cp.reply, "_run_codex_resume", return_value="ok") as resume_mock,
        ):
            mode, response = cp._dispatch_prompt_to_session(  # type: ignore[attr-defined]
                target_sid=sid,
                prompt="continue",
                session_rec=rec,
                codex_home=Path("/tmp/codex-home"),
            )

        self.assertEqual(mode, "tmux_stale")
        self.assertIsNone(response)
        tmux_send_mock.assert_not_called()
        resume_mock.assert_not_called()

    def test_dispatch_prompt_strict_tmux_without_tmux_identity_falls_back_to_resume(self) -> None:
        sid = "019c33b4-e0ed-7021-940a-02b1e8147a82"
        rec = {
            "cwd": "/tmp/project",
            "session_path": f"/tmp/sessions/{sid}.jsonl",
        }

        with (
            mock.patch.object(cp.reply, "_session_path_matches_session_id", return_value=True),
            mock.patch.object(cp, "_tmux_discover_codex_pane_for_session", return_value=(None, None)),
            mock.patch.object(cp.reply, "_run_codex_resume", return_value="ok") as resume_mock,
            mock.patch.dict(
                cp.os.environ,  # type: ignore[attr-defined]
                {"AGENT_CHAT_STRICT_TMUX": "1"},
                clear=False,
            ),
        ):
            mode, response = cp._dispatch_prompt_to_session(  # type: ignore[attr-defined]
                target_sid=sid,
                prompt="continue",
                session_rec=rec,
                codex_home=Path("/tmp/codex-home"),
            )

        self.assertEqual(mode, "resume")
        self.assertEqual(response, "ok")
        resume_mock.assert_called_once()

    def test_apply_attention_context_to_session_ignores_terminal_fields(self) -> None:
        sid = "11111111-1111-1111-1111-111111111111"
        rec: dict[str, object] = {"cwd": "/tmp/project"}
        attention_index = {
            sid: {
                "cwd": "/tmp/project",
                "terminal_app": "ExampleTerminal",
                "terminal_session_id": "w0t1:abc",
                "terminal_tty": "/dev/ttys014",
            }
        }

        cp._apply_attention_context_to_session(  # type: ignore[attr-defined]
            session_id=sid,
            session_rec=rec,
            attention_index=attention_index,
            last_attention_state=None,
        )

        self.assertNotIn("terminal_app", rec)
        self.assertNotIn("terminal_session_id", rec)
        self.assertNotIn("terminal_tty", rec)

    def test_process_inbound_replies_tmux_stale_falls_back_and_clears_mapping_when_strict_disabled(self) -> None:
        sid = "019c33b4-e0ed-7021-940a-02b1e8147a82"
        registry = {
            "sessions": {
                sid: {
                    "cwd": "/tmp/project",
                    "tmux_pane": "%4",
                    "session_path": f"/tmp/sessions/{sid}.jsonl",
                }
            }
        }
        message_index: dict[str, object] = {}
        sent: list[dict[str, object]] = []

        def _capture_send(**kwargs: object) -> None:
            sent.append(dict(kwargs))

        with (
            sqlite3.connect(":memory:") as conn,
            mock.patch.object(cp.reply, "_fetch_new_replies", return_value=[(101, "continue", None)]),
            mock.patch.object(cp.reply, "_is_attention_message", return_value=False),
            mock.patch.object(cp.reply, "_is_bot_message", return_value=False),
            mock.patch.object(cp, "_load_registry", return_value=registry),
            mock.patch.object(cp, "_load_message_index", return_value=message_index),
            mock.patch.object(cp, "_resolve_session_from_reply_context", return_value=(sid, None)),
            mock.patch.object(cp, "_rewrite_numeric_choice_prompt", return_value=("continue", None)),
            mock.patch.object(cp, "_dispatch_prompt_to_session", return_value=("tmux_stale", None)),
            mock.patch.object(cp.reply, "_run_codex_resume", return_value="fallback response") as resume_mock,
            mock.patch.dict(cp.os.environ, {"AGENT_CHAT_STRICT_TMUX": "0"}, clear=False),
            mock.patch.object(cp, "_send_structured", side_effect=_capture_send),
            mock.patch.object(cp, "_save_registry"),
            mock.patch.object(cp, "_save_message_index"),
        ):
            rowid = cp._process_inbound_replies(  # type: ignore[attr-defined]
                conn=conn,
                after_rowid=0,
                handle_ids=["+15551234567"],
                codex_home=Path("/tmp/codex-home"),
                recipient="+15551234567",
                max_message_chars=1800,
                min_prefix=6,
                dry_run=False,
            )

        self.assertEqual(rowid, 101)
        self.assertEqual(registry["sessions"][sid].get("tmux_pane"), "")
        self.assertTrue(any(m.get("kind") == "responded" and m.get("text") == "fallback response" for m in sent))
        resume_mock.assert_called_once_with(
            session_id=sid,
            cwd="/tmp/project",
            prompt="continue",
            codex_home=Path("/tmp/codex-home"),
            timeout_s=None,
        )

    def test_process_inbound_replies_recovers_missing_session_record_before_dispatch(self) -> None:
        sid = "019c33b4-e0ed-7021-940a-02b1e8147a82"
        session_path = f"/tmp/sessions/{sid}.jsonl"
        registry = {"sessions": {}}
        message_index: dict[str, object] = {}
        sent: list[dict[str, object]] = []

        def _capture_send(**kwargs: object) -> None:
            sent.append(dict(kwargs))

        def _dispatch_with_recovery(**kwargs: object):
            rec = kwargs.get("session_rec")
            if isinstance(rec, dict) and rec.get("session_path") == session_path:
                return "tmux", None
            return "tmux_stale", None

        with (
            sqlite3.connect(":memory:") as conn,
            mock.patch.object(cp.reply, "_fetch_new_replies", return_value=[(101, "continue", None)]),
            mock.patch.object(cp.reply, "_is_attention_message", return_value=False),
            mock.patch.object(cp.reply, "_is_bot_message", return_value=False),
            mock.patch.object(cp, "_load_registry", return_value=registry),
            mock.patch.object(cp, "_load_message_index", return_value=message_index),
            mock.patch.object(cp, "_resolve_session_from_reply_context", return_value=(sid, None)),
            mock.patch.object(cp, "_rewrite_numeric_choice_prompt", return_value=("continue", None)),
            mock.patch.object(
                cp,
                "_recover_session_record_from_disk",
                return_value={"session_path": session_path, "cwd": "/tmp/project"},
                create=True,
            ),
            mock.patch.object(cp, "_dispatch_prompt_to_session", side_effect=_dispatch_with_recovery),
            mock.patch.object(cp, "_send_structured", side_effect=_capture_send),
            mock.patch.object(cp, "_save_registry"),
            mock.patch.object(cp, "_save_message_index"),
        ):
            rowid = cp._process_inbound_replies(  # type: ignore[attr-defined]
                conn=conn,
                after_rowid=0,
                handle_ids=["+15551234567"],
                codex_home=Path("/tmp/codex-home"),
                recipient="+15551234567",
                max_message_chars=1800,
                min_prefix=6,
                dry_run=False,
            )

        self.assertEqual(rowid, 101)
        self.assertTrue(any(m.get("kind") == "accepted" for m in sent))

    def test_recover_session_record_from_disk_finds_other_agent_home_session(self) -> None:
        sid = "019c92e8-a03c-71f3-858f-c0e2a14153e3"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            codex_home = root / "codex-home"
            claude_home = root / "claude-home"
            session_path = codex_home / "sessions" / "2026" / "02" / "24" / f"rollout-{sid}.jsonl"
            session_path.parent.mkdir(parents=True, exist_ok=True)
            session_path.write_text("", encoding="utf-8")

            with mock.patch.dict(
                cp.os.environ,  # type: ignore[attr-defined]
                {
                    "AGENT_CHAT_AGENT": "claude",
                    "AGENT_CHAT_HOME": str(codex_home),
                    "CLAUDE_HOME": str(claude_home),
                },
                clear=False,
            ):
                rec = cp._recover_session_record_from_disk(  # type: ignore[attr-defined]
                    codex_home=claude_home,
                    session_id=sid,
                    registry=None,
                )

        self.assertIsInstance(rec, dict)
        self.assertIsNotNone(rec)
        if not isinstance(rec, dict):
            self.fail("expected recovered session record")
        self.assertEqual(rec.get("agent"), "codex")
        self.assertEqual(rec.get("session_path"), str(session_path))

    def test_process_inbound_replies_tmux_failed_fallback_prefers_other_home_registry_agent(self) -> None:
        sid = "019c92e8-a03c-71f3-858f-c0e2a14153e3"
        sent: list[dict[str, object]] = []

        def _capture_send(**kwargs: object) -> None:
            sent.append(dict(kwargs))

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            codex_home = root / "codex-home"
            claude_home = root / "claude-home"
            (codex_home / "tmp").mkdir(parents=True, exist_ok=True)
            (claude_home / "tmp").mkdir(parents=True, exist_ok=True)
            (codex_home / "tmp" / "agent_chat_session_registry.json").write_text(
                json.dumps(
                    {
                        "sessions": {
                            sid: {
                                "session_id": sid,
                                "agent": "codex",
                                "cwd": "/tmp/project",
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )

            registry = {"sessions": {}}
            message_index: dict[str, object] = {
                "messages": [
                    {
                        "session_id": sid,
                        "kind": "error",
                        "hash": "deadbeef",
                        "agent": "claude",
                    }
                ]
            }

            with (
                sqlite3.connect(":memory:") as conn,
                mock.patch.object(cp.reply, "_fetch_new_replies", return_value=[(101, "continue", None)]),
                mock.patch.object(cp.reply, "_is_attention_message", return_value=False),
                mock.patch.object(cp.reply, "_is_bot_message", return_value=False),
                mock.patch.object(cp, "_load_registry", return_value=registry),
                mock.patch.object(cp, "_load_message_index", return_value=message_index),
                mock.patch.object(cp, "_resolve_session_from_reply_context", return_value=(sid, None)),
                mock.patch.object(cp, "_rewrite_numeric_choice_prompt", return_value=("continue", None)),
                mock.patch.object(cp, "_dispatch_prompt_to_session", return_value=("tmux_failed", None)),
                mock.patch.object(cp.reply, "_run_agent_resume", return_value=None) as resume_mock,
                mock.patch.dict(
                    cp.os.environ,  # type: ignore[attr-defined]
                    {
                        "AGENT_CHAT_STRICT_TMUX": "0",
                        "AGENT_CHAT_AGENT": "claude",
                        "AGENT_CHAT_HOME": str(codex_home),
                        "CLAUDE_HOME": str(claude_home),
                    },
                    clear=False,
                ),
                mock.patch.object(cp, "_send_structured", side_effect=_capture_send),
                mock.patch.object(cp, "_save_registry"),
                mock.patch.object(cp, "_save_message_index"),
            ):
                rowid = cp._process_inbound_replies(  # type: ignore[attr-defined]
                    conn=conn,
                    after_rowid=0,
                    handle_ids=["+15551234567"],
                    codex_home=claude_home,
                    recipient="+15551234567",
                    max_message_chars=1800,
                    min_prefix=6,
                    dry_run=False,
                )

        self.assertEqual(rowid, 101)
        resume_mock.assert_called_once()
        self.assertEqual(resume_mock.call_args.kwargs.get("agent"), "codex")
        self.assertTrue(any("no response from codex resume" in str(m.get("text", "")).lower() for m in sent))

    def test_process_inbound_replies_tmux_failed_falls_back_when_strict_disabled(self) -> None:
        sid = "019c33b4-e0ed-7021-940a-02b1e8147a82"
        registry = {
            "sessions": {
                sid: {
                    "cwd": "/tmp/project",
                    "tmux_pane": "%4",
                    "session_path": f"/tmp/sessions/{sid}.jsonl",
                }
            }
        }
        message_index: dict[str, object] = {}
        sent: list[dict[str, object]] = []

        def _capture_send(**kwargs: object) -> None:
            sent.append(dict(kwargs))

        with (
            sqlite3.connect(":memory:") as conn,
            mock.patch.object(cp.reply, "_fetch_new_replies", return_value=[(101, "continue", None)]),
            mock.patch.object(cp.reply, "_is_attention_message", return_value=False),
            mock.patch.object(cp.reply, "_is_bot_message", return_value=False),
            mock.patch.object(cp, "_load_registry", return_value=registry),
            mock.patch.object(cp, "_load_message_index", return_value=message_index),
            mock.patch.object(cp, "_resolve_session_from_reply_context", return_value=(sid, None)),
            mock.patch.object(cp, "_rewrite_numeric_choice_prompt", return_value=("continue", None)),
            mock.patch.object(cp, "_dispatch_prompt_to_session", return_value=("tmux_failed", None)),
            mock.patch.object(cp.reply, "_run_codex_resume", return_value="fallback response") as resume_mock,
            mock.patch.dict(cp.os.environ, {"AGENT_CHAT_STRICT_TMUX": "0"}, clear=False),
            mock.patch.object(cp, "_send_structured", side_effect=_capture_send),
            mock.patch.object(cp, "_save_registry"),
            mock.patch.object(cp, "_save_message_index"),
        ):
            rowid = cp._process_inbound_replies(  # type: ignore[attr-defined]
                conn=conn,
                after_rowid=0,
                handle_ids=["+15551234567"],
                codex_home=Path("/tmp/codex-home"),
                recipient="+15551234567",
                max_message_chars=1800,
                min_prefix=6,
                dry_run=False,
            )

        self.assertEqual(rowid, 101)
        self.assertTrue(any(m.get("kind") == "responded" and m.get("text") == "fallback response" for m in sent))
        resume_mock.assert_called_once_with(
            session_id=sid,
            cwd="/tmp/project",
            prompt="continue",
            codex_home=Path("/tmp/codex-home"),
            timeout_s=None,
        )

    def test_process_inbound_replies_tmux_failed_fallback_uses_session_agent_over_runtime(self) -> None:
        sid = "019c33b4-e0ed-7021-940a-02b1e8147a82"
        registry = {
            "sessions": {
                sid: {
                    "agent": "codex",
                    "cwd": "/tmp/project",
                    "tmux_pane": "%4",
                    "session_path": f"/tmp/sessions/{sid}.jsonl",
                }
            }
        }
        message_index: dict[str, object] = {}
        sent: list[dict[str, object]] = []

        def _capture_send(**kwargs: object) -> None:
            sent.append(dict(kwargs))

        with (
            sqlite3.connect(":memory:") as conn,
            mock.patch.object(cp.reply, "_fetch_new_replies", return_value=[(101, "continue", None)]),
            mock.patch.object(cp.reply, "_is_attention_message", return_value=False),
            mock.patch.object(cp.reply, "_is_bot_message", return_value=False),
            mock.patch.object(cp, "_load_registry", return_value=registry),
            mock.patch.object(cp, "_load_message_index", return_value=message_index),
            mock.patch.object(cp, "_resolve_session_from_reply_context", return_value=(sid, None)),
            mock.patch.object(cp, "_rewrite_numeric_choice_prompt", return_value=("continue", None)),
            mock.patch.object(cp, "_dispatch_prompt_to_session", return_value=("tmux_failed", None)),
            mock.patch.object(cp.reply, "_run_agent_resume", return_value=None) as resume_mock,
            mock.patch.dict(
                cp.os.environ,  # type: ignore[attr-defined]
                {"AGENT_CHAT_STRICT_TMUX": "0", "AGENT_CHAT_AGENT": "claude"},
                clear=False,
            ),
            mock.patch.object(cp, "_send_structured", side_effect=_capture_send),
            mock.patch.object(cp, "_save_registry"),
            mock.patch.object(cp, "_save_message_index"),
        ):
            rowid = cp._process_inbound_replies(  # type: ignore[attr-defined]
                conn=conn,
                after_rowid=0,
                handle_ids=["+15551234567"],
                codex_home=Path("/tmp/codex-home"),
                recipient="+15551234567",
                max_message_chars=1800,
                min_prefix=6,
                dry_run=False,
            )

        self.assertEqual(rowid, 101)
        resume_mock.assert_called_once()
        self.assertEqual(resume_mock.call_args.kwargs.get("agent"), "codex")
        self.assertTrue(any("no response from codex resume" in str(m.get("text", "")).lower() for m in sent))

    def test_process_inbound_replies_tmux_stale_strict_reports_error_without_fallback(self) -> None:
        sid = "019c33b4-e0ed-7021-940a-02b1e8147a82"
        registry = {
            "sessions": {
                sid: {
                    "cwd": "/tmp/project",
                    "tmux_pane": "%4",
                    "session_path": f"/tmp/sessions/{sid}.jsonl",
                }
            }
        }
        message_index: dict[str, object] = {}
        sent: list[dict[str, object]] = []

        def _capture_send(**kwargs: object) -> None:
            sent.append(dict(kwargs))

        with (
            sqlite3.connect(":memory:") as conn,
            mock.patch.object(cp.reply, "_fetch_new_replies", return_value=[(101, "continue", None)]),
            mock.patch.object(cp.reply, "_is_attention_message", return_value=False),
            mock.patch.object(cp.reply, "_is_bot_message", return_value=False),
            mock.patch.object(cp, "_load_registry", return_value=registry),
            mock.patch.object(cp, "_load_message_index", return_value=message_index),
            mock.patch.object(cp, "_resolve_session_from_reply_context", return_value=(sid, None)),
            mock.patch.object(cp, "_rewrite_numeric_choice_prompt", return_value=("continue", None)),
            mock.patch.object(cp, "_dispatch_prompt_to_session", return_value=("tmux_stale", None)),
            mock.patch.object(cp.reply, "_run_codex_resume", return_value="fallback response") as resume_mock,
            mock.patch.object(cp, "_send_structured", side_effect=_capture_send),
            mock.patch.object(cp, "_save_registry"),
            mock.patch.object(cp, "_save_message_index"),
        ):
            rowid = cp._process_inbound_replies(  # type: ignore[attr-defined]
                conn=conn,
                after_rowid=0,
                handle_ids=["+15551234567"],
                codex_home=Path("/tmp/codex-home"),
                recipient="+15551234567",
                max_message_chars=1800,
                min_prefix=6,
                dry_run=False,
            )

        self.assertEqual(rowid, 101)
        self.assertEqual(registry["sessions"][sid].get("tmux_pane"), "")
        self.assertTrue(any(m.get("kind") == "error" and "strict tmux routing" in str(m.get("text", "")).lower() for m in sent))
        self.assertFalse(any(m.get("kind") == "responded" for m in sent))
        resume_mock.assert_not_called()

    def test_process_inbound_replies_tmux_stale_no_pane_strict_falls_back_to_resume(self) -> None:
        sid = "019c33b4-e0ed-7021-940a-02b1e8147a82"
        registry = {
            "sessions": {
                sid: {
                    "cwd": "/tmp/project",
                    "session_path": f"/tmp/sessions/{sid}.jsonl",
                }
            }
        }
        message_index: dict[str, object] = {}
        sent: list[dict[str, object]] = []

        def _capture_send(**kwargs: object) -> None:
            sent.append(dict(kwargs))

        def _dispatch_no_pane(**kwargs: object):
            rec = kwargs.get("session_rec")
            if isinstance(rec, dict):
                rec["last_dispatch_reason"] = "pane_missing"
            return "tmux_stale", None

        with (
            sqlite3.connect(":memory:") as conn,
            mock.patch.object(cp.reply, "_fetch_new_replies", return_value=[(101, "continue", None)]),
            mock.patch.object(cp.reply, "_is_attention_message", return_value=False),
            mock.patch.object(cp.reply, "_is_bot_message", return_value=False),
            mock.patch.object(cp, "_load_registry", return_value=registry),
            mock.patch.object(cp, "_load_message_index", return_value=message_index),
            mock.patch.object(cp, "_resolve_session_from_reply_context", return_value=(sid, None)),
            mock.patch.object(cp, "_rewrite_numeric_choice_prompt", return_value=("continue", None)),
            mock.patch.object(cp, "_dispatch_prompt_to_session", side_effect=_dispatch_no_pane),
            mock.patch.object(cp.reply, "_run_codex_resume", return_value="fallback response") as resume_mock,
            mock.patch.object(cp, "_send_structured", side_effect=_capture_send),
            mock.patch.object(cp, "_save_registry"),
            mock.patch.object(cp, "_save_message_index"),
        ):
            rowid = cp._process_inbound_replies(  # type: ignore[attr-defined]
                conn=conn,
                after_rowid=0,
                handle_ids=["+15551234567"],
                codex_home=Path("/tmp/codex-home"),
                recipient="+15551234567",
                max_message_chars=1800,
                min_prefix=6,
                dry_run=False,
            )

        self.assertEqual(rowid, 101)
        self.assertTrue(any(m.get("kind") == "responded" and m.get("text") == "fallback response" for m in sent))
        self.assertFalse(any(m.get("kind") == "error" and "strict tmux routing" in str(m.get("text", "")).lower() for m in sent))
        resume_mock.assert_called_once_with(
            session_id=sid,
            cwd="/tmp/project",
            prompt="continue",
            codex_home=Path("/tmp/codex-home"),
            timeout_s=None,
        )

    def test_process_inbound_replies_tmux_failed_strict_reports_error_without_fallback(self) -> None:
        sid = "019c33b4-e0ed-7021-940a-02b1e8147a82"
        registry = {
            "sessions": {
                sid: {
                    "cwd": "/tmp/project",
                    "tmux_pane": "%4",
                    "session_path": f"/tmp/sessions/{sid}.jsonl",
                }
            }
        }
        message_index: dict[str, object] = {}
        sent: list[dict[str, object]] = []

        def _capture_send(**kwargs: object) -> None:
            sent.append(dict(kwargs))

        with (
            sqlite3.connect(":memory:") as conn,
            mock.patch.object(cp.reply, "_fetch_new_replies", return_value=[(101, "continue", None)]),
            mock.patch.object(cp.reply, "_is_attention_message", return_value=False),
            mock.patch.object(cp.reply, "_is_bot_message", return_value=False),
            mock.patch.object(cp, "_load_registry", return_value=registry),
            mock.patch.object(cp, "_load_message_index", return_value=message_index),
            mock.patch.object(cp, "_resolve_session_from_reply_context", return_value=(sid, None)),
            mock.patch.object(cp, "_rewrite_numeric_choice_prompt", return_value=("continue", None)),
            mock.patch.object(cp, "_dispatch_prompt_to_session", return_value=("tmux_failed", None)),
            mock.patch.object(cp.reply, "_run_codex_resume", return_value="fallback response") as resume_mock,
            mock.patch.object(cp, "_send_structured", side_effect=_capture_send),
            mock.patch.object(cp, "_save_registry"),
            mock.patch.object(cp, "_save_message_index"),
        ):
            rowid = cp._process_inbound_replies(  # type: ignore[attr-defined]
                conn=conn,
                after_rowid=0,
                handle_ids=["+15551234567"],
                codex_home=Path("/tmp/codex-home"),
                recipient="+15551234567",
                max_message_chars=1800,
                min_prefix=6,
                dry_run=False,
            )

        self.assertEqual(rowid, 101)
        self.assertTrue(any(m.get("kind") == "error" and "strict tmux routing" in str(m.get("text", "")).lower() for m in sent))
        self.assertFalse(any(m.get("kind") == "responded" for m in sent))
        resume_mock.assert_not_called()

    def test_create_new_session_in_tmux_uses_session_file_when_command_name_differs(self) -> None:
        created = Path("/tmp/codex/sessions/rollout-1.jsonl")

        with (
            mock.patch.object(cp, "_find_all_session_files", return_value=[]),
            mock.patch.object(cp, "_tmux_ensure_active_session", return_value=("agent", None)),
            mock.patch.object(cp, "_tmux_start_codex_window", return_value=("%4", "agent-session-000001", None)),
            mock.patch.object(cp, "_tmux_wait_for_pane_command", return_value=False),
            mock.patch.object(cp.reply, "_tmux_send_prompt", return_value=True) as send_prompt_mock,
            mock.patch.object(cp, "_wait_for_new_session_file", return_value=created),
            mock.patch.object(cp.outbound, "_read_session_id", return_value="sid-123"),
        ):
            sid, session_path, pane, err = cp._create_new_session_in_tmux(  # type: ignore[attr-defined]
                codex_home=Path("/tmp/codex-home"),
                prompt="continue",
                cwd="/tmp/project",
            )

        self.assertEqual(sid, "sid-123")
        self.assertEqual(session_path, str(created))
        self.assertEqual(pane, "%4")
        self.assertIsNone(err)
        send_prompt_mock.assert_called_once_with(pane="%4", prompt="continue")

    def test_create_new_session_in_tmux_reports_session_file_failure_not_command_failure(self) -> None:
        with (
            mock.patch.object(cp, "_find_all_session_files", side_effect=[[], []]),
            mock.patch.object(cp, "_tmux_ensure_active_session", return_value=("agent", None)),
            mock.patch.object(cp, "_tmux_start_codex_window", return_value=("%4", "agent-session-000001", None)),
            mock.patch.object(cp, "_tmux_wait_for_pane_command", return_value=False),
            mock.patch.object(cp.reply, "_tmux_send_prompt", return_value=True),
            mock.patch.object(cp, "_wait_for_new_session_file", return_value=None),
        ):
            sid, session_path, pane, err = cp._create_new_session_in_tmux(  # type: ignore[attr-defined]
                codex_home=Path("/tmp/codex-home"),
                prompt="continue",
                cwd="/tmp/project",
            )

        self.assertIsNone(sid)
        self.assertIsNone(session_path)
        self.assertEqual(pane, "%4")
        self.assertIsInstance(err, str)
        self.assertIn("could not locate session file", err or "")

    def test_create_new_session_in_tmux_passes_label_to_window_creation(self) -> None:
        created = Path("/tmp/codex/sessions/rollout-1.jsonl")

        with (
            mock.patch.object(cp, "_find_all_session_files", return_value=[]),
            mock.patch.object(cp, "_tmux_ensure_active_session", return_value=("agent", None)),
            mock.patch.object(cp, "_tmux_start_codex_window", return_value=("%4", "agent-bugfix-120102", None)) as window_mock,
            mock.patch.object(cp, "_tmux_wait_for_pane_command", return_value=False),
            mock.patch.object(cp.reply, "_tmux_send_prompt", return_value=True),
            mock.patch.object(cp, "_wait_for_new_session_file", return_value=created),
            mock.patch.object(cp.outbound, "_read_session_id", return_value="sid-123"),
        ):
            sid, session_path, pane, err = cp._create_new_session_in_tmux(  # type: ignore[attr-defined]
                codex_home=Path("/tmp/codex-home"),
                prompt="continue",
                cwd="/tmp/project",
                label="bugfix",
            )

        self.assertEqual(sid, "sid-123")
        self.assertEqual(session_path, str(created))
        self.assertEqual(pane, "%4")
        self.assertIsNone(err)
        window_mock.assert_called_once_with(
            session_name="agent",
            cwd="/tmp/project",
            label="bugfix",
            agent="codex",
        )

    def test_process_inbound_replies_missing_session_requests_agent_choice(self) -> None:
        registry: dict[str, object] = {"sessions": {}, "pending_new_session_choice": None}
        message_index: dict[str, object] = {}
        sent: list[dict[str, object]] = []

        def _capture_send(**kwargs: object) -> None:
            sent.append(dict(kwargs))

        with (
            sqlite3.connect(":memory:") as conn,
            mock.patch.object(cp.reply, "_fetch_new_replies", return_value=[(101, "@bugfix continue", None)]),
            mock.patch.object(cp.reply, "_is_attention_message", return_value=False),
            mock.patch.object(cp.reply, "_is_bot_message", return_value=False),
            mock.patch.object(cp, "_load_registry", return_value=registry),
            mock.patch.object(cp, "_load_message_index", return_value=message_index),
            mock.patch.object(cp, "_resolve_session_ref", return_value=(None, "Session not found.")),
            mock.patch.object(cp, "_default_new_session_cwd", return_value="/tmp/project"),
            mock.patch.object(cp, "_send_structured", side_effect=_capture_send),
            mock.patch.object(cp, "_save_registry"),
            mock.patch.object(cp, "_save_message_index"),
        ):
            rowid = cp._process_inbound_replies(  # type: ignore[attr-defined]
                conn=conn,
                after_rowid=0,
                handle_ids=["+15551234567"],
                codex_home=Path("/tmp/codex-home"),
                recipient="+15551234567",
                max_message_chars=1800,
                min_prefix=6,
                dry_run=False,
            )

        self.assertEqual(rowid, 101)
        pending = registry.get("pending_new_session_choice")
        self.assertIsInstance(pending, dict)
        if not isinstance(pending, dict):
            self.fail("expected pending choice payload")
        self.assertEqual(pending.get("label"), "bugfix")
        self.assertEqual(pending.get("cwd"), "/tmp/project")
        self.assertEqual(pending.get("prompt"), "continue")
        self.assertTrue(any(msg.get("kind") == "needs_input" for msg in sent))

    def test_process_inbound_replies_implicit_no_waiting_strict_requests_agent_choice(self) -> None:
        registry: dict[str, object] = {"sessions": {}, "pending_new_session_choice": None}
        message_index: dict[str, object] = {}
        sent: list[dict[str, object]] = []

        def _capture_send(**kwargs: object) -> None:
            sent.append(dict(kwargs))

        with (
            sqlite3.connect(":memory:") as conn,
            mock.patch.object(cp.reply, "_fetch_new_replies", return_value=[(101, "continue", None)]),
            mock.patch.object(cp.reply, "_is_attention_message", return_value=False),
            mock.patch.object(cp.reply, "_is_bot_message", return_value=False),
            mock.patch.object(cp, "_load_registry", return_value=registry),
            mock.patch.object(cp, "_load_message_index", return_value=message_index),
            mock.patch.object(
                cp,
                "_resolve_session_from_reply_context",
                return_value=(
                    None,
                    "No session is currently awaiting input. Use @<ref> ... or new <label>: ... "
                    "Strict tmux routing requires explicit @<ref> when context is ambiguous.",
                ),
            ),
            mock.patch.object(cp, "_default_new_session_cwd", return_value="/tmp/project"),
            mock.patch.dict(cp.os.environ, {"AGENT_CHAT_STRICT_TMUX": "1"}, clear=False),
            mock.patch.object(cp, "_send_structured", side_effect=_capture_send),
            mock.patch.object(cp, "_save_registry"),
            mock.patch.object(cp, "_save_message_index"),
        ):
            rowid = cp._process_inbound_replies(  # type: ignore[attr-defined]
                conn=conn,
                after_rowid=0,
                handle_ids=["+15551234567"],
                codex_home=Path("/tmp/codex-home"),
                recipient="+15551234567",
                max_message_chars=1800,
                min_prefix=6,
                dry_run=False,
            )

        self.assertEqual(rowid, 101)
        pending = registry.get("pending_new_session_choice")
        self.assertIsInstance(pending, dict)
        if not isinstance(pending, dict):
            self.fail("expected pending choice payload")
        self.assertEqual(pending.get("action"), "implicit")
        self.assertEqual(pending.get("cwd"), "/tmp/project")
        self.assertEqual(pending.get("prompt"), "continue")
        self.assertTrue(any(msg.get("kind") == "needs_input" for msg in sent))
        self.assertFalse(any(msg.get("kind") == "error" for msg in sent))

    def test_process_inbound_replies_pending_choice_creates_selected_agent_session(self) -> None:
        registry: dict[str, object] = {
            "sessions": {},
            "pending_new_session_choice": {
                "prompt": "continue",
                "action": "resume",
                "label": "bugfix",
                "cwd": "/tmp/project",
                "created_ts": 1,
                "source_text": "@bugfix continue",
                "source_ref": "bugfix",
            },
        }
        message_index: dict[str, object] = {}
        sent: list[dict[str, object]] = []
        captured: dict[str, object] = {}

        def _capture_send(**kwargs: object) -> None:
            sent.append(dict(kwargs))

        def _fake_create_new_session_in_tmux(**kwargs: object):
            captured.update(kwargs)
            return "sid-123", "/tmp/sessions/sid-123.jsonl", "%9", None

        with (
            sqlite3.connect(":memory:") as conn,
            mock.patch.object(cp.reply, "_fetch_new_replies", return_value=[(102, "2", None)]),
            mock.patch.object(cp.reply, "_is_attention_message", return_value=False),
            mock.patch.object(cp.reply, "_is_bot_message", return_value=False),
            mock.patch.object(cp, "_load_registry", return_value=registry),
            mock.patch.object(cp, "_load_message_index", return_value=message_index),
            mock.patch.object(cp, "_create_new_session_in_tmux", side_effect=_fake_create_new_session_in_tmux),
            mock.patch.object(cp.outbound, "_read_session_cwd", return_value="/tmp/project"),
            mock.patch.object(cp, "_send_structured", side_effect=_capture_send),
            mock.patch.object(cp, "_save_registry"),
            mock.patch.object(cp, "_save_message_index"),
        ):
            rowid = cp._process_inbound_replies(  # type: ignore[attr-defined]
                conn=conn,
                after_rowid=0,
                handle_ids=["+15551234567"],
                codex_home=Path("/tmp/codex-home"),
                recipient="+15551234567",
                max_message_chars=1800,
                min_prefix=6,
                dry_run=False,
            )

        self.assertEqual(rowid, 102)
        self.assertEqual(captured.get("agent"), "claude")
        self.assertEqual(captured.get("label"), "bugfix")
        self.assertEqual(captured.get("cwd"), "/tmp/project")
        self.assertIsNone(registry.get("pending_new_session_choice"))
        sessions = registry.get("sessions")
        self.assertIsInstance(sessions, dict)
        if not isinstance(sessions, dict):
            self.fail("expected sessions map")
        session_rec = sessions.get("sid-123")
        self.assertIsInstance(session_rec, dict)
        if not isinstance(session_rec, dict):
            self.fail("expected session record")
        self.assertEqual(session_rec.get("agent"), "claude")
        self.assertTrue(any(m.get("kind") == "accepted" for m in sent))

    def test_process_inbound_replies_pending_choice_tmux_failure_falls_back_to_non_tmux_create(self) -> None:
        registry: dict[str, object] = {
            "sessions": {},
            "pending_new_session_choice": {
                "prompt": "continue",
                "action": "implicit",
                "label": None,
                "cwd": "/tmp/project",
                "created_ts": 1,
                "source_text": "continue",
                "source_ref": None,
            },
        }
        message_index: dict[str, object] = {}
        sent: list[dict[str, object]] = []

        def _capture_send(**kwargs: object) -> None:
            sent.append(dict(kwargs))

        with (
            sqlite3.connect(":memory:") as conn,
            mock.patch.object(cp.reply, "_fetch_new_replies", return_value=[(103, "codex", None)]),
            mock.patch.object(cp.reply, "_is_attention_message", return_value=False),
            mock.patch.object(cp.reply, "_is_bot_message", return_value=False),
            mock.patch.object(cp, "_load_registry", return_value=registry),
            mock.patch.object(cp, "_load_message_index", return_value=message_index),
            mock.patch.object(cp, "_create_new_session_in_tmux", return_value=(None, None, None, "tmux failed")),
            mock.patch.object(
                cp,
                "_create_new_session",
                return_value=("sid-456", "/tmp/sessions/sid-456.jsonl", "ok"),
            ) as fallback_mock,
            mock.patch.object(cp.outbound, "_read_session_cwd", return_value="/tmp/project"),
            mock.patch.object(cp, "_send_structured", side_effect=_capture_send),
            mock.patch.object(cp, "_save_registry"),
            mock.patch.object(cp, "_save_message_index"),
        ):
            rowid = cp._process_inbound_replies(  # type: ignore[attr-defined]
                conn=conn,
                after_rowid=0,
                handle_ids=["+15551234567"],
                codex_home=Path("/tmp/codex-home"),
                recipient="+15551234567",
                max_message_chars=1800,
                min_prefix=6,
                dry_run=False,
            )

        self.assertEqual(rowid, 103)
        fallback_mock.assert_called_once()
        self.assertEqual(fallback_mock.call_args.kwargs.get("agent"), "codex")
        self.assertIsNone(registry.get("pending_new_session_choice"))
        sessions = registry.get("sessions")
        self.assertIsInstance(sessions, dict)
        if not isinstance(sessions, dict):
            self.fail("expected sessions map")
        rec = sessions.get("sid-456")
        self.assertIsInstance(rec, dict)
        if not isinstance(rec, dict):
            self.fail("expected session record")
        self.assertEqual(rec.get("agent"), "codex")
        self.assertTrue(any("without tmux" in str(m.get("text", "")).lower() for m in sent))

    def test_rewrite_numeric_choice_prompt_single_question(self) -> None:
        rec = {
            "pending_request_user_input": {
                "questions": [
                    {
                        "id": "ui_scope",
                        "question": "Which UI should this optimization plan target as the primary scope?",
                        "options": [
                            {"label": "CaptureSetup sticky pane (Recommended)"},
                            {"label": "IntentForm preview section"},
                            {"label": "Both surfaces"},
                            {"label": "None of the above"},
                        ],
                    }
                ]
            }
        }

        rewritten, err = cp._rewrite_numeric_choice_prompt(  # type: ignore[attr-defined]
            prompt="1",
            session_rec=rec,
        )

        self.assertIsNone(err)
        self.assertIsInstance(rewritten, str)
        self.assertIn('id "ui_scope"', rewritten or "")
        self.assertIn('option 1 "CaptureSetup sticky pane (Recommended)"', rewritten or "")

    def test_rewrite_numeric_choice_prompt_rejects_out_of_range(self) -> None:
        rec = {
            "pending_request_user_input": {
                "questions": [
                    {
                        "id": "ui_scope",
                        "question": "Which UI should this optimization plan target as the primary scope?",
                        "options": [
                            {"label": "CaptureSetup sticky pane (Recommended)"},
                            {"label": "IntentForm preview section"},
                        ],
                    }
                ]
            }
        }

        rewritten, err = cp._rewrite_numeric_choice_prompt(  # type: ignore[attr-defined]
            prompt="9",
            session_rec=rec,
        )

        self.assertIsNone(rewritten)
        self.assertIsInstance(err, str)
        self.assertIn("Valid options: 1-2", err or "")

    def test_main_run_continues_without_chat_db(self) -> None:
        with (
            mock.patch.dict(
                cp.os.environ,
                {"AGENT_IMESSAGE_TO": "+15551234567", "AGENT_CHAT_HOME": "/tmp/codex-home"},
                clear=False,
            ),
            mock.patch.object(cp, "_acquire_single_instance_lock", return_value=object()),
            mock.patch.object(cp, "_load_outbound_cursor", return_value=({}, {})),
            mock.patch.object(cp, "_open_chat_db", return_value=None) as open_db_mock,
            mock.patch.object(cp, "_process_outbound", return_value=({}, {})) as process_outbound_mock,
            mock.patch.object(cp, "_save_outbound_cursor"),
            mock.patch.object(cp, "_process_inbound_replies") as inbound_mock,
            mock.patch.object(cp, "_save_inbound_cursor") as save_inbound_mock,
            mock.patch("time.sleep", side_effect=KeyboardInterrupt),
        ):
            rc = cp.main(["run", "--poll", "0.01"])

        self.assertEqual(rc, 0)
        self.assertGreaterEqual(open_db_mock.call_count, 1)
        process_outbound_mock.assert_called_once()
        inbound_mock.assert_not_called()
        save_inbound_mock.assert_not_called()

    def test_main_run_retries_chat_db_attach(self) -> None:
        fake_conn = mock.Mock(spec=sqlite3.Connection)

        with (
            mock.patch.dict(
                cp.os.environ,
                {
                    "AGENT_IMESSAGE_TO": "+15551234567",
                    "AGENT_CHAT_HOME": "/tmp/codex-home",
                    "AGENT_CHAT_INBOUND_RETRY_S": "0",
                },
                clear=False,
            ),
            mock.patch.object(cp, "_acquire_single_instance_lock", return_value=object()),
            mock.patch.object(cp, "_load_outbound_cursor", return_value=({}, {})),
            mock.patch.object(cp, "_open_chat_db", side_effect=[None, fake_conn]) as open_db_mock,
            mock.patch.object(cp, "_ensure_inbound_cursor_seed", return_value=11) as seed_mock,
            mock.patch.object(cp, "_process_outbound", return_value=({}, {})),
            mock.patch.object(cp, "_save_outbound_cursor"),
            mock.patch.object(cp, "_process_inbound_replies", return_value=12) as inbound_mock,
            mock.patch.object(cp, "_save_inbound_cursor") as save_inbound_mock,
            mock.patch("time.sleep", side_effect=[None, KeyboardInterrupt]),
        ):
            rc = cp.main(["run", "--poll", "0.01"])

        self.assertEqual(rc, 0)
        self.assertGreaterEqual(open_db_mock.call_count, 2)
        seed_mock.assert_called_once()
        self.assertGreaterEqual(inbound_mock.call_count, 1)
        self.assertGreaterEqual(save_inbound_mock.call_count, 1)

    def test_main_run_seeds_inbound_cursor_when_chat_db_is_ready_at_startup(self) -> None:
        fake_conn = mock.Mock(spec=sqlite3.Connection)

        with (
            mock.patch.dict(
                cp.os.environ,
                {
                    "AGENT_IMESSAGE_TO": "+15551234567",
                    "AGENT_CHAT_HOME": "/tmp/codex-home",
                },
                clear=False,
            ),
            mock.patch.object(cp, "_acquire_single_instance_lock", return_value=object()),
            mock.patch.object(cp, "_load_outbound_cursor", return_value=({}, {})),
            mock.patch.object(cp, "_open_chat_db", return_value=fake_conn),
            mock.patch.object(cp, "_ensure_inbound_cursor_seed", return_value=42) as seed_mock,
            mock.patch.object(cp, "_process_outbound", return_value=({}, {})),
            mock.patch.object(cp, "_save_outbound_cursor"),
            mock.patch.object(cp, "_process_inbound_replies", return_value=43) as inbound_mock,
            mock.patch.object(cp, "_save_inbound_cursor"),
            mock.patch("time.sleep", side_effect=KeyboardInterrupt),
        ):
            rc = cp.main(["run", "--poll", "0.01"])

        self.assertEqual(rc, 0)
        seed_mock.assert_called_once()
        self.assertGreaterEqual(inbound_mock.call_count, 1)
        self.assertEqual(inbound_mock.call_args.kwargs.get("after_rowid"), 42)

    def test_ensure_tmux_available_for_setup_returns_existing_tmux(self) -> None:
        with (
            mock.patch.object(cp, "_discover_tmux_bin", return_value="/opt/homebrew/bin/tmux"),
            mock.patch.object(cp, "_resolve_brew_bin") as brew_mock,
            mock.patch.object(cp.subprocess, "run") as run_mock,
        ):
            tmux_bin, err = cp._ensure_tmux_available_for_setup()  # type: ignore[attr-defined]

        self.assertEqual(tmux_bin, "/opt/homebrew/bin/tmux")
        self.assertIsNone(err)
        brew_mock.assert_not_called()
        run_mock.assert_not_called()

    def test_ensure_tmux_available_for_setup_installs_via_homebrew_when_missing(self) -> None:
        with (
            mock.patch.object(cp, "_discover_tmux_bin", side_effect=[None, "/opt/homebrew/bin/tmux"]),
            mock.patch.object(cp, "_resolve_brew_bin", return_value="/opt/homebrew/bin/brew"),
            mock.patch.object(cp.subprocess, "run", return_value=mock.Mock(returncode=0, stdout="", stderr="")) as run_mock,
            mock.patch("sys.stdout", new_callable=io.StringIO) as out,
        ):
            tmux_bin, err = cp._ensure_tmux_available_for_setup()  # type: ignore[attr-defined]

        self.assertEqual(tmux_bin, "/opt/homebrew/bin/tmux")
        self.assertIsNone(err)
        run_mock.assert_called_once_with(
            ["/opt/homebrew/bin/brew", "install", "tmux"],
            check=False,
            stdout=cp.subprocess.PIPE,  # type: ignore[attr-defined]
            stderr=cp.subprocess.PIPE,  # type: ignore[attr-defined]
            text=True,
        )
        text = out.getvalue()
        self.assertIn("Attempting automatic install via Homebrew", text)
        self.assertIn("tmux installed: /opt/homebrew/bin/tmux", text)

    def test_ensure_tmux_available_for_setup_installs_homebrew_when_missing(self) -> None:
        with (
            mock.patch.object(cp, "_discover_tmux_bin", side_effect=[None, "/opt/homebrew/bin/tmux"]),
            mock.patch.object(cp, "_resolve_brew_bin", return_value=None),
            mock.patch.object(cp, "_install_homebrew_for_setup", return_value=("/opt/homebrew/bin/brew", None)) as install_brew_mock,
            mock.patch.object(cp.subprocess, "run", return_value=mock.Mock(returncode=0, stdout="", stderr="")),
        ):
            tmux_bin, err = cp._ensure_tmux_available_for_setup()  # type: ignore[attr-defined]

        self.assertEqual(tmux_bin, "/opt/homebrew/bin/tmux")
        self.assertIsNone(err)
        install_brew_mock.assert_called_once()

    def test_ensure_tmux_available_for_setup_fails_when_homebrew_auto_install_fails(self) -> None:
        with (
            mock.patch.object(cp, "_discover_tmux_bin", return_value=None),
            mock.patch.object(cp, "_resolve_brew_bin", return_value=None),
            mock.patch.object(
                cp,
                "_install_homebrew_for_setup",
                return_value=(None, "Automatic Homebrew install failed: blocked\n"),
            ),
        ):
            tmux_bin, err = cp._ensure_tmux_available_for_setup()  # type: ignore[attr-defined]

        self.assertIsNone(tmux_bin)
        self.assertIsInstance(err, str)
        self.assertIn("Automatic Homebrew install failed", err or "")

    def test_ensure_tmux_available_for_setup_surfaces_homebrew_failure(self) -> None:
        with (
            mock.patch.object(cp, "_discover_tmux_bin", return_value=None),
            mock.patch.object(cp, "_resolve_brew_bin", return_value="/opt/homebrew/bin/brew"),
            mock.patch.object(
                cp.subprocess,
                "run",
                return_value=mock.Mock(returncode=1, stdout="", stderr="Error: network unavailable"),
            ),
        ):
            tmux_bin, err = cp._ensure_tmux_available_for_setup()  # type: ignore[attr-defined]

        self.assertIsNone(tmux_bin)
        self.assertIsInstance(err, str)
        self.assertIn("Automatic tmux install failed", err or "")
        self.assertIn("network unavailable", err or "")

    def test_install_homebrew_for_setup_runs_noninteractive_installer(self) -> None:
        with (
            mock.patch.object(
                cp.subprocess,
                "run",
                return_value=mock.Mock(returncode=0, stdout="", stderr=""),
            ) as run_mock,
            mock.patch.object(cp, "_resolve_brew_bin", return_value="/opt/homebrew/bin/brew"),
            mock.patch("sys.stdout", new_callable=io.StringIO) as out,
        ):
            brew_bin, err = cp._install_homebrew_for_setup()  # type: ignore[attr-defined]

        self.assertEqual(brew_bin, "/opt/homebrew/bin/brew")
        self.assertIsNone(err)
        run_mock.assert_called_once()
        cmd = run_mock.call_args.args[0]
        self.assertEqual(cmd[:2], ["/bin/bash", "-c"])
        self.assertIn(cp._HOMEBREW_INSTALL_URL, cmd[2])  # type: ignore[attr-defined]
        kwargs = run_mock.call_args.kwargs
        self.assertEqual(kwargs.get("check"), False)
        env = kwargs.get("env")
        self.assertIsInstance(env, dict)
        env_dict = env if isinstance(env, dict) else {}
        self.assertEqual(env_dict.get("NONINTERACTIVE"), "1")
        self.assertEqual(env_dict.get("HOMEBREW_NO_ANALYTICS"), "1")
        text = out.getvalue()
        self.assertIn("Attempting automatic Homebrew install", text)
        self.assertIn("Homebrew installed: /opt/homebrew/bin/brew", text)

    def test_install_homebrew_for_setup_surfaces_install_failure(self) -> None:
        with mock.patch.object(
            cp.subprocess,
            "run",
            return_value=mock.Mock(returncode=1, stdout="", stderr="Error: install blocked"),
        ):
            brew_bin, err = cp._install_homebrew_for_setup()  # type: ignore[attr-defined]

        self.assertIsNone(brew_bin)
        self.assertIsInstance(err, str)
        self.assertIn("Automatic Homebrew install failed", err or "")
        self.assertIn("https://brew.sh/", err or "")

    def test_tmux_ensure_active_session_reuses_agent_when_present(self) -> None:
        calls: list[list[str]] = []

        def _run(cmd: list[str], **kwargs: object) -> mock.Mock:
            calls.append(cmd)
            if cmd[:3] == ["tmux", "has-session", "-t"]:
                return mock.Mock(returncode=0)
            raise AssertionError(f"unexpected command: {cmd}")

        with (
            mock.patch.object(cp, "_resolve_tmux_bin", return_value="tmux"),
            mock.patch("subprocess.run", side_effect=_run),
        ):
            session_name, err = cp._tmux_ensure_active_session(cwd="/tmp/project")  # type: ignore[attr-defined]

        self.assertEqual(session_name, "agent")
        self.assertIsNone(err)
        self.assertEqual(calls, [["tmux", "has-session", "-t", "agent"]])

    def test_tmux_ensure_active_session_creates_agent_once_when_missing(self) -> None:
        calls: list[list[str]] = []

        def _run(cmd: list[str], **kwargs: object) -> mock.Mock:
            calls.append(cmd)
            if cmd[:3] == ["tmux", "has-session", "-t"]:
                return mock.Mock(returncode=1)
            if cmd[:2] == ["tmux", "new-session"]:
                return mock.Mock(returncode=0)
            raise AssertionError(f"unexpected command: {cmd}")

        with (
            mock.patch.object(cp, "_resolve_tmux_bin", return_value="tmux"),
            mock.patch("subprocess.run", side_effect=_run),
        ):
            session_name, err = cp._tmux_ensure_active_session(cwd="/tmp/project")  # type: ignore[attr-defined]

        self.assertEqual(session_name, "agent")
        self.assertIsNone(err)
        self.assertEqual(calls, [["tmux", "has-session", "-t", "agent"], ["tmux", "new-session", "-d", "-s", "agent", "-c", "/tmp/project"]])

    def test_tmux_start_codex_window_uses_label_in_window_name(self) -> None:
        captured: dict[str, object] = {}

        def _run(cmd: list[str], **kwargs: object) -> mock.Mock:
            captured["cmd"] = cmd
            return mock.Mock(returncode=0, stdout="%4\n")

        with (
            mock.patch("subprocess.run", side_effect=_run),
            mock.patch("time.strftime", return_value="120102"),
        ):
            pane, window_name, err = cp._tmux_start_codex_window(  # type: ignore[attr-defined]
                session_name="agent",
                cwd="/tmp/project",
                label="Bug Fix",
            )

        self.assertIsNone(err)
        self.assertEqual(pane, "%4")
        self.assertEqual(window_name, "agent-bug-fix-120102")
        cmd = captured.get("cmd")
        self.assertIsInstance(cmd, list)
        cmd_list = cmd if isinstance(cmd, list) else []
        self.assertIn("-n", cmd_list)
        idx = cmd_list.index("-n")
        self.assertEqual(cmd_list[idx + 1], "agent-bug-fix-120102")

    def test_tmux_start_codex_window_uses_session_fallback_when_label_missing(self) -> None:
        with (
            mock.patch("subprocess.run", return_value=mock.Mock(returncode=0, stdout="%4\n")),
            mock.patch("time.strftime", return_value="120102"),
        ):
            pane, window_name, err = cp._tmux_start_codex_window(  # type: ignore[attr-defined]
                session_name="agent",
                cwd="/tmp/project",
                label=None,
            )

        self.assertIsNone(err)
        self.assertEqual(pane, "%4")
        self.assertEqual(window_name, "agent-session-120102")

    def test_tmux_start_codex_window_uses_configured_codex_bin(self) -> None:
        captured: dict[str, object] = {}

        def _run(cmd: list[str], **kwargs: object) -> mock.Mock:
            captured["cmd"] = cmd
            return mock.Mock(returncode=0, stdout="%4\n")

        with (
            mock.patch.dict(
                cp.os.environ,
                {"AGENT_CHAT_CODEX_BIN": "/custom/bin/codex"},
                clear=False,
            ),
            mock.patch("subprocess.run", side_effect=_run),
            mock.patch("time.strftime", return_value="120102"),
        ):
            pane, window_name, err = cp._tmux_start_codex_window(  # type: ignore[attr-defined]
                session_name="agent",
                cwd="/tmp/project",
                label=None,
            )

        self.assertIsNone(err)
        self.assertEqual(pane, "%4")
        self.assertEqual(window_name, "agent-session-120102")
        cmd = captured.get("cmd")
        self.assertIsInstance(cmd, list)
        cmd_list = cmd if isinstance(cmd, list) else []
        self.assertGreaterEqual(len(cmd_list), 1)
        launch_cmd = cmd_list[-1]
        self.assertIsInstance(launch_cmd, str)
        self.assertIn("/custom/bin/codex", str(launch_cmd))

    def test_chat_db_path_falls_back_to_latest_backup_when_primary_missing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            backup_a = home / "Library" / "Messages" / "db-backups" / "20260215-010101"
            backup_b = home / "Library" / "Messages" / "db-backups" / "20260216-020202"
            backup_a.mkdir(parents=True, exist_ok=True)
            backup_b.mkdir(parents=True, exist_ok=True)
            chat_a = backup_a / "chat.db"
            chat_b = backup_b / "chat.db"
            chat_a.write_text("", encoding="utf-8")
            chat_b.write_text("", encoding="utf-8")
            chat_a.touch()
            chat_b.touch()

            with (
                mock.patch.object(cp.Path, "home", return_value=home),
                mock.patch.dict(cp.os.environ, {}, clear=True),
            ):
                resolved = cp._chat_db_path(codex_home=Path("/tmp/codex-home"))  # type: ignore[attr-defined]

        self.assertEqual(resolved, chat_b)

    def test_doctor_report_uses_backup_chat_db_when_primary_missing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            backup = home / "Library" / "Messages" / "db-backups" / "20260216-020202"
            backup.mkdir(parents=True, exist_ok=True)
            chat_db = backup / "chat.db"
            with sqlite3.connect(chat_db):
                pass

            with (
                mock.patch.object(cp.Path, "home", return_value=home),
                mock.patch.dict(cp.os.environ, {}, clear=True),
                mock.patch.object(cp, "_launchd_service_loaded", return_value=(True, "loaded")),
                mock.patch.object(cp, "_read_lock_pid", return_value=12345),
                mock.patch.object(cp, "_is_pid_alive", return_value=True),
            ):
                report = cp._doctor_report(  # type: ignore[attr-defined]
                    codex_home=Path("/tmp/codex-home"),
                    recipient="+15551234567",
                )

        chat_info = report.get("chat_db")
        self.assertIsInstance(chat_info, dict)
        self.assertEqual((chat_info or {}).get("path"), str(chat_db))
        self.assertEqual((chat_info or {}).get("readable"), True)

    def test_doctor_report_includes_launchd_runtime_targets_from_plist(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            codex_home = home / ".codex"
            launchagents = home / "Library" / "LaunchAgents"
            launchagents.mkdir(parents=True, exist_ok=True)
            runtime_python = (
                home
                / "Applications"
                / "AgentChatPython.app"
                / "Contents"
                / "MacOS"
                / "Python"
            )
            plist_path = launchagents / "com.agent-chat.plist"
            plist_path.write_bytes(
                plistlib.dumps(
                    {
                        "Label": "com.agent-chat",
                        "ProgramArguments": [str(runtime_python), "/tmp/agent_chat_control_plane.py", "run"],
                        "EnvironmentVariables": {"AGENT_IMESSAGE_TO": "+15551234567"},
                    },
                    sort_keys=False,
                )
            )
            chat_db = codex_home / "tmp" / "chat.db"
            chat_db.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(chat_db):
                pass

            with (
                mock.patch.object(cp.Path, "home", return_value=home),
                mock.patch.dict(cp.os.environ, {"AGENT_IMESSAGE_CHAT_DB": str(chat_db)}, clear=False),
                mock.patch.object(cp, "_launchd_service_loaded", return_value=(True, "loaded")),
                mock.patch.object(cp, "_read_lock_pid", return_value=12345),
                mock.patch.object(cp, "_is_pid_alive", return_value=True),
            ):
                report = cp._doctor_report(  # type: ignore[attr-defined]
                    codex_home=codex_home,
                    recipient=None,
                )

        launchd = report.get("launchd", {})
        self.assertEqual((launchd or {}).get("runtime_python"), str(runtime_python))
        self.assertEqual(
            (launchd or {}).get("permission_app"),
            str(home / "Applications" / "AgentChatPython.app"),
        )

    def test_drain_fallback_queue_requeues_unsent_entries(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            codex_home = Path(td)
            queue_path = codex_home / "tmp" / "agent_chat_queue.jsonl"
            queue_path.parent.mkdir(parents=True, exist_ok=True)
            queue_path.write_text(
                "\n".join(
                    [
                        json.dumps({"ts": 1, "to": "+15551234567", "text": "first"}),
                        json.dumps({"ts": 2, "to": "+15551234567", "text": "second"}),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            with mock.patch.object(cp.outbound, "_send_imessage", side_effect=[True, False]) as send_mock:
                stats = cp._drain_fallback_queue(  # type: ignore[attr-defined]
                    codex_home=codex_home,
                    dry_run=False,
                    max_items=10,
                )
            remaining = queue_path.read_text(encoding="utf-8").strip().splitlines()

        self.assertEqual(stats.get("attempted"), 2)
        self.assertEqual(stats.get("sent"), 1)
        self.assertEqual(stats.get("retained"), 1)
        self.assertEqual(send_mock.call_count, 2)

        self.assertEqual(len(remaining), 1)
        event = json.loads(remaining[0])
        self.assertEqual(event.get("text"), "second")

    def test_doctor_report_ignores_disabled_warning_if_restored_after(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            codex_home = Path(td)
            tmp_dir = codex_home / "tmp"
            tmp_dir.mkdir(parents=True, exist_ok=True)
            err_log = tmp_dir / "launchd.err.log"
            err_log.write_text(
                "\n".join(
                    [
                        "[agent-chat] inbound disabled: cannot open chat.db",
                        "[agent-chat] inbound chat.db access restored.",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            chat_db = tmp_dir / "chat.db"
            with sqlite3.connect(chat_db):
                pass

            with (
                mock.patch.dict(
                    cp.os.environ,
                    {
                        "AGENT_CHAT_LAUNCHD_ERR_LOG": str(err_log),
                        "AGENT_IMESSAGE_CHAT_DB": str(chat_db),
                    },
                    clear=False,
                ),
                mock.patch.object(cp, "_launchd_service_loaded", return_value=(True, "loaded")),
                mock.patch.object(cp, "_read_lock_pid", return_value=12345),
                mock.patch.object(cp, "_is_pid_alive", return_value=True),
            ):
                report = cp._doctor_report(  # type: ignore[attr-defined]
                    codex_home=codex_home,
                    recipient="+15551234567",
                )

        self.assertEqual(report["launchd"]["inbound_warning"], False)  # type: ignore[index]
        self.assertNotIn(  # type: ignore[arg-type]
            "launchd reports inbound disabled (check chat.db permissions)",
            report.get("issues", []),
        )

    def test_doctor_report_flags_warning_when_disabled_is_latest(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            codex_home = Path(td)
            tmp_dir = codex_home / "tmp"
            tmp_dir.mkdir(parents=True, exist_ok=True)
            err_log = tmp_dir / "launchd.err.log"
            err_log.write_text(
                "\n".join(
                    [
                        "[agent-chat] inbound chat.db access restored.",
                        "[agent-chat] inbound disabled: cannot open chat.db",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            chat_db = tmp_dir / "chat.db"
            with sqlite3.connect(chat_db):
                pass

            with (
                mock.patch.dict(
                    cp.os.environ,
                    {
                        "AGENT_CHAT_LAUNCHD_ERR_LOG": str(err_log),
                        "AGENT_IMESSAGE_CHAT_DB": str(chat_db),
                    },
                    clear=False,
                ),
                mock.patch.object(cp, "_launchd_service_loaded", return_value=(True, "loaded")),
                mock.patch.object(cp, "_read_lock_pid", return_value=12345),
                mock.patch.object(cp, "_is_pid_alive", return_value=True),
            ):
                report = cp._doctor_report(  # type: ignore[attr-defined]
                    codex_home=codex_home,
                    recipient="+15551234567",
                )

        self.assertEqual(report["launchd"]["inbound_warning"], True)  # type: ignore[index]
        self.assertIn(  # type: ignore[arg-type]
            "launchd reports inbound disabled (check chat.db permissions)",
            report.get("issues", []),
        )

    def test_doctor_report_prefers_launchd_restored_status_when_shell_probe_fails(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            codex_home = Path(td)
            with (
                mock.patch.object(cp, "_launchd_service_loaded", return_value=(True, "loaded")),
                mock.patch.object(cp, "_launchd_inbound_warning_active", return_value=False),
                mock.patch.object(cp, "_launchd_inbound_restored_active", return_value=True),
                mock.patch.object(cp, "_read_lock_pid", return_value=12345),
                mock.patch.object(cp, "_is_pid_alive", return_value=True),
                mock.patch.object(
                    cp,
                    "_chat_db_access_status",
                    return_value=(Path("/tmp/chat.db"), False, "OperationalError: unable to open database file"),
                ),
                mock.patch.object(
                    cp,
                    "_chat_db_access_status_for_runtime",
                    return_value=(Path("/tmp/chat.db"), False, "OperationalError: unable to open database file"),
                ),
                mock.patch.object(
                    cp,
                    "_queue_stats",
                    return_value={
                        "path": "/tmp/agent_chat_queue.jsonl",
                        "exists": False,
                        "size_bytes": 0,
                        "lines": 0,
                        "latest_ts": None,
                    },
                ),
            ):
                report = cp._doctor_report(  # type: ignore[attr-defined]
                    codex_home=codex_home,
                    recipient="+15551234567",
                )

        chat_info = report.get("chat_db")
        self.assertIsInstance(chat_info, dict)
        self.assertEqual((chat_info or {}).get("readable"), True)
        self.assertEqual((chat_info or {}).get("source"), "launchd_log")
        self.assertNotIn(  # type: ignore[arg-type]
            "chat.db unreadable for inbound replies",
            report.get("issues", []),
        )

    def test_doctor_report_keeps_chat_db_unreadable_when_restored_not_seen(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            codex_home = Path(td)
            with (
                mock.patch.object(cp, "_launchd_service_loaded", return_value=(True, "loaded")),
                mock.patch.object(cp, "_launchd_inbound_warning_active", return_value=False),
                mock.patch.object(cp, "_launchd_inbound_restored_active", return_value=False),
                mock.patch.object(cp, "_launchd_runtime_targets_from_plist", return_value=(None, None)),
                mock.patch.object(cp, "_read_lock_pid", return_value=12345),
                mock.patch.object(cp, "_is_pid_alive", return_value=True),
                mock.patch.object(
                    cp,
                    "_chat_db_access_status",
                    return_value=(Path("/tmp/chat.db"), False, "OperationalError: unable to open database file"),
                ),
                mock.patch.object(
                    cp,
                    "_chat_db_access_status_for_runtime",
                    return_value=(Path("/tmp/chat.db"), False, "OperationalError: unable to open database file"),
                ),
                mock.patch.object(
                    cp,
                    "_queue_stats",
                    return_value={
                        "path": "/tmp/agent_chat_queue.jsonl",
                        "exists": False,
                        "size_bytes": 0,
                        "lines": 0,
                        "latest_ts": None,
                    },
                ),
            ):
                report = cp._doctor_report(  # type: ignore[attr-defined]
                    codex_home=codex_home,
                    recipient="+15551234567",
                )

        chat_info = report.get("chat_db")
        self.assertIsInstance(chat_info, dict)
        self.assertEqual((chat_info or {}).get("readable"), False)
        self.assertEqual((chat_info or {}).get("source"), "shell")
        self.assertIn(  # type: ignore[arg-type]
            "chat.db unreadable for inbound replies",
            report.get("issues", []),
        )

    def test_doctor_report_flags_notify_hook_when_misscoped(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            codex_home = home / ".codex"
            codex_home.mkdir(parents=True, exist_ok=True)
            config_path = codex_home / "config.toml"
            config_path.write_text(
                "\n".join(
                    [
                        "[notice.model_migrations]",
                        '"gpt-5.2" = "gpt-5.3-codex"',
                        'notify = ["bash", "-lc", "echo notify", "--"]',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            chat_db = codex_home / "tmp" / "chat.db"
            chat_db.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(chat_db):
                pass

            with (
                mock.patch.object(cp.Path, "home", return_value=home),
                mock.patch.dict(cp.os.environ, {"AGENT_IMESSAGE_CHAT_DB": str(chat_db)}, clear=False),
                mock.patch.object(cp, "_launchd_service_loaded", return_value=(True, "loaded")),
                mock.patch.object(cp, "_read_lock_pid", return_value=12345),
                mock.patch.object(cp, "_is_pid_alive", return_value=True),
            ):
                report = cp._doctor_report(  # type: ignore[attr-defined]
                    codex_home=codex_home,
                    recipient="+15551234567",
                )

        notify_hook = report.get("notify_hook")
        self.assertIsInstance(notify_hook, dict)
        self.assertEqual((notify_hook or {}).get("top_level_present"), False)
        self.assertEqual((notify_hook or {}).get("mis_scoped_present"), True)
        self.assertIn(  # type: ignore[arg-type]
            "notify hook is not configured at top-level in ~/.codex/config.toml",
            report.get("issues", []),
        )

    def test_doctor_report_accepts_top_level_notify_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            codex_home = home / ".codex"
            codex_home.mkdir(parents=True, exist_ok=True)
            config_path = codex_home / "config.toml"
            config_path.write_text(
                "\n".join(
                    [
                        'notify = ["bash", "-lc", "echo notify", "--"]',
                        "",
                        "[notice.model_migrations]",
                        '"gpt-5.2" = "gpt-5.3-codex"',
                    ]
                ),
                encoding="utf-8",
            )
            chat_db = codex_home / "tmp" / "chat.db"
            chat_db.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(chat_db):
                pass

            with (
                mock.patch.object(cp.Path, "home", return_value=home),
                mock.patch.dict(cp.os.environ, {"AGENT_IMESSAGE_CHAT_DB": str(chat_db)}, clear=False),
                mock.patch.object(cp, "_launchd_service_loaded", return_value=(True, "loaded")),
                mock.patch.object(cp, "_read_lock_pid", return_value=12345),
                mock.patch.object(cp, "_is_pid_alive", return_value=True),
            ):
                report = cp._doctor_report(  # type: ignore[attr-defined]
                    codex_home=codex_home,
                    recipient="+15551234567",
                )

        notify_hook = report.get("notify_hook")
        self.assertIsInstance(notify_hook, dict)
        self.assertEqual((notify_hook or {}).get("top_level_present"), True)
        self.assertEqual((notify_hook or {}).get("mis_scoped_present"), False)
        self.assertNotIn(  # type: ignore[arg-type]
            "notify hook is not configured at top-level in ~/.codex/config.toml",
            report.get("issues", []),
        )

    def test_run_setup_notify_hook_rewrites_misscoped_notify_into_top_level(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            codex_home = home / ".codex"
            codex_home.mkdir(parents=True, exist_ok=True)
            config_path = codex_home / "config.toml"
            config_path.write_text(
                "\n".join(
                    [
                        'model = "gpt-5.3-codex"',
                        "",
                        "[notice.model_migrations]",
                        '"gpt-5.2" = "gpt-5.3-codex"',
                        'notify = ["bash", "-lc", "echo old-1", "--"]',
                        'notify = ["bash", "-lc", "echo old-2", "--"]',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            script_path = home / "repo" / "agent_chat_control_plane.py"
            script_path.parent.mkdir(parents=True, exist_ok=True)
            script_path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

            with (
                mock.patch.object(cp.Path, "home", return_value=home),
                mock.patch("sys.stdout", new_callable=io.StringIO) as out,
            ):
                rc = cp._run_setup_notify_hook(  # type: ignore[attr-defined]
                    codex_home=codex_home,
                    recipient="+15555550123",
                    python_bin="/opt/homebrew/bin/python3",
                    script_path=script_path,
                )

            self.assertEqual(rc, 0)
            updated = config_path.read_text(encoding="utf-8")
            self.assertLess(
                updated.find("notify = "),
                updated.find("[notice.model_migrations]"),
            )

            parsed = cp.tomllib.loads(updated)  # type: ignore[attr-defined]
            self.assertIsInstance(parsed, dict)
            notify_val = parsed.get("notify")
            self.assertIsInstance(notify_val, list)
            joined = " ".join(notify_val) if isinstance(notify_val, list) else ""
            self.assertIn("AGENT_IMESSAGE_TO=+15555550123", joined)
            self.assertIn(str(script_path.resolve()), joined)

            notice = parsed.get("notice")
            self.assertIsInstance(notice, dict)
            model_migrations = (notice or {}).get("model_migrations")
            self.assertIsInstance(model_migrations, dict)
            self.assertNotIn("notify", model_migrations or {})
            self.assertIn("Restart Codex to apply notify hook changes.", out.getvalue())

    def test_run_setup_notify_hook_allows_telegram_without_imessage_recipient(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            codex_home = home / ".codex"
            codex_home.mkdir(parents=True, exist_ok=True)
            script_path = home / "repo" / "agent_chat_control_plane.py"
            script_path.parent.mkdir(parents=True, exist_ok=True)
            script_path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

            with (
                mock.patch.dict(
                    cp.os.environ,  # type: ignore[attr-defined]
                    {
                        "AGENT_CHAT_TRANSPORT": "telegram",
                        "AGENT_TELEGRAM_BOT_TOKEN": "telegram-token",
                        "AGENT_TELEGRAM_CHAT_ID": "123456",
                    },
                    clear=False,
                ),
                mock.patch("sys.stdout", new_callable=io.StringIO),
            ):
                rc = cp._run_setup_notify_hook(  # type: ignore[attr-defined]
                    codex_home=codex_home,
                    recipient="",
                    python_bin="/opt/homebrew/bin/python3",
                    script_path=script_path,
                )

            self.assertEqual(rc, 0)
            parsed = cp.tomllib.loads((codex_home / "config.toml").read_text(encoding="utf-8"))  # type: ignore[attr-defined]
            self.assertIsInstance(parsed, dict)
            notify_val = parsed.get("notify")
            self.assertIsInstance(notify_val, list)
            joined = " ".join(notify_val) if isinstance(notify_val, list) else ""
            self.assertIn("AGENT_CHAT_TRANSPORT=telegram", joined)
            self.assertIn("AGENT_TELEGRAM_CHAT_ID=123456", joined)
            self.assertIn("AGENT_TELEGRAM_BOT_TOKEN=telegram-token", joined)

    def test_run_setup_notify_hook_requires_telegram_bot_token_with_instructions(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            codex_home = home / ".codex"
            codex_home.mkdir(parents=True, exist_ok=True)
            script_path = home / "repo" / "agent_chat_control_plane.py"
            script_path.parent.mkdir(parents=True, exist_ok=True)
            script_path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

            with (
                mock.patch.dict(
                    cp.os.environ,  # type: ignore[attr-defined]
                    {
                        "AGENT_CHAT_TRANSPORT": "telegram",
                        "AGENT_TELEGRAM_BOT_TOKEN": "",
                        "AGENT_TELEGRAM_CHAT_ID": "123456",
                    },
                    clear=False,
                ),
                mock.patch("sys.stdout", new_callable=io.StringIO) as out,
            ):
                rc = cp._run_setup_notify_hook(  # type: ignore[attr-defined]
                    codex_home=codex_home,
                    recipient="",
                    python_bin="/opt/homebrew/bin/python3",
                    script_path=script_path,
                )

            self.assertEqual(rc, 1)
            text = out.getvalue()
            self.assertIn("AGENT_TELEGRAM_BOT_TOKEN is required", text)
            self.assertIn("@BotFather", text)
            self.assertIn("/newbot", text)
            self.assertIn("/token", text)

    def test_run_setup_notify_hook_writes_claude_hooks(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            claude_home = home / ".claude"
            claude_home.mkdir(parents=True, exist_ok=True)
            settings_path = claude_home / "settings.json"
            settings_path.write_text("{}", encoding="utf-8")
            script_path = home / "repo" / "agent_chat_control_plane.py"
            script_path.parent.mkdir(parents=True, exist_ok=True)
            script_path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

            with (
                mock.patch.dict(cp.os.environ, {"AGENT_CHAT_AGENT": "claude"}, clear=False),
                mock.patch("sys.stdout", new_callable=io.StringIO) as out,
            ):
                rc = cp._run_setup_notify_hook(  # type: ignore[attr-defined]
                    codex_home=claude_home,
                    recipient="+15555550123",
                    python_bin="/opt/homebrew/bin/python3",
                    script_path=script_path,
                )

            self.assertEqual(rc, 0)
            self.assertIn("Restart Claude to apply notify hook changes.", out.getvalue())

            parsed = json.loads(settings_path.read_text(encoding="utf-8"))
            hooks = parsed.get("hooks")
            self.assertIsInstance(hooks, dict)
            if not isinstance(hooks, dict):
                self.fail("expected hooks map in Claude settings")
            for event_name in ("Notification", "Stop"):
                event_hooks = hooks.get(event_name)
                self.assertIsInstance(event_hooks, list)
                if not isinstance(event_hooks, list):
                    self.fail(f"expected hook list for {event_name}")
                self.assertGreaterEqual(len(event_hooks), 1)
                first = event_hooks[0] if event_hooks else None
                self.assertIsInstance(first, dict)
                if not isinstance(first, dict):
                    self.fail(f"expected first hook record for {event_name}")
                hook_entries = first.get("hooks")
                self.assertIsInstance(hook_entries, list)
                if not isinstance(hook_entries, list):
                    self.fail(f"expected nested hooks list for {event_name}")
                command_values: list[str] = []
                for item in hook_entries:
                    if not isinstance(item, dict):
                        continue
                    command = item.get("command")
                    if isinstance(command, str):
                        command_values.append(command)
                self.assertTrue(any("notify" in cmd for cmd in command_values))
                self.assertTrue(any("AGENT_CHAT_AGENT=claude" in cmd for cmd in command_values))

    def test_find_all_session_files_supports_claude_projects_layout(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            claude_home = Path(td)
            session_a = claude_home / "projects" / "-Users-test-repo" / "sid-a.jsonl"
            session_b = claude_home / "projects" / "-Users-test-other" / "nested" / "sid-b.jsonl"
            session_a.parent.mkdir(parents=True, exist_ok=True)
            session_b.parent.mkdir(parents=True, exist_ok=True)
            session_a.write_text("{}", encoding="utf-8")
            session_b.write_text("{}", encoding="utf-8")

            with mock.patch.dict(cp.os.environ, {"AGENT_CHAT_AGENT": "claude"}, clear=False):
                found = cp._find_all_session_files(codex_home=claude_home)  # type: ignore[attr-defined]

        found_set = {str(path) for path in found}
        self.assertEqual(
            found_set,
            {
                str(session_a),
                str(session_b),
            },
        )

    def test_send_structured_uses_claude_header_when_agent_is_claude(self) -> None:
        sent: list[str] = []

        def _capture_send(*, recipient: str, message: str) -> bool:
            del recipient
            sent.append(message)
            return True

        with (
            tempfile.TemporaryDirectory() as td,
            mock.patch.dict(cp.os.environ, {"AGENT_CHAT_AGENT": "claude"}, clear=False),
            mock.patch.object(cp.outbound, "_send_imessage", side_effect=_capture_send),
        ):
            cp._send_structured(  # type: ignore[attr-defined]
                codex_home=Path(td),
                recipient="+15551234567",
                session_id="sid-123",
                kind="responded",
                text="done",
                max_message_chars=1800,
                dry_run=False,
                message_index={},
            )

        self.assertGreaterEqual(len(sent), 1)
        self.assertIn("[Claude] sid-123 — responded — ", sent[0])

    def test_send_structured_uses_telegram_transport_when_enabled(self) -> None:
        sent_telegram: list[tuple[str, str, str]] = []

        def _capture_telegram(*, token: str, chat_id: str, message: str, timeout_s: float = 10.0) -> bool:
            del timeout_s
            sent_telegram.append((token, chat_id, message))
            return True

        with (
            tempfile.TemporaryDirectory() as td,
            mock.patch.dict(
                cp.os.environ,  # type: ignore[attr-defined]
                {
                    "AGENT_CHAT_TRANSPORT": "telegram",
                    "AGENT_TELEGRAM_BOT_TOKEN": "test-bot-token",
                    "AGENT_TELEGRAM_CHAT_ID": "123456",
                },
                clear=False,
            ),
            mock.patch.object(cp, "_send_telegram_message", side_effect=_capture_telegram),
            mock.patch.object(cp.outbound, "_send_imessage") as imessage_send,
        ):
            cp._send_structured(  # type: ignore[attr-defined]
                codex_home=Path(td),
                recipient="+15551234567",
                session_id="sid-123",
                kind="responded",
                text="done",
                max_message_chars=1800,
                dry_run=False,
                message_index={},
            )

        self.assertEqual(imessage_send.call_count, 0)
        self.assertGreaterEqual(len(sent_telegram), 1)
        self.assertEqual(sent_telegram[0][0], "test-bot-token")
        self.assertEqual(sent_telegram[0][1], "123456")
        self.assertIn("sid-123", sent_telegram[0][2])

    def test_fetch_telegram_updates_parses_text_messages(self) -> None:
        class _FakeHTTPResponse:
            def __init__(self, body: str) -> None:
                self._body = body.encode("utf-8")

            def __enter__(self) -> "_FakeHTTPResponse":
                return self

            def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
                del exc_type, exc, tb
                return False

            def read(self) -> bytes:
                return self._body

        payload = {
            "ok": True,
            "result": [
                {
                    "update_id": 42,
                    "message": {
                        "chat": {"id": 123456},
                        "text": "help",
                    },
                }
            ],
        }

        with mock.patch.object(
            cp.urllib_request,  # type: ignore[attr-defined]
            "urlopen",
            return_value=_FakeHTTPResponse(json.dumps(payload)),
        ):
            updates = cp._fetch_telegram_updates(  # type: ignore[attr-defined]
                token="test-bot-token",
                chat_id="123456",
                after_update_id=0,
            )

        self.assertEqual(len(updates), 1)
        self.assertEqual(updates[0][0], 42)
        self.assertEqual(updates[0][1], "help")

    def test_fetch_telegram_updates_captures_reply_to_message_text(self) -> None:
        class _FakeHTTPResponse:
            def __init__(self, body: str) -> None:
                self._body = body.encode("utf-8")

            def __enter__(self) -> "_FakeHTTPResponse":
                return self

            def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
                del exc_type, exc, tb
                return False

            def read(self) -> bytes:
                return self._body

        payload = {
            "ok": True,
            "result": [
                {
                    "update_id": 52,
                    "message": {
                        "chat": {"id": 123456},
                        "text": "continue",
                        "reply_to_message": {"text": "[Codex] sid-123 — responded — done"},
                    },
                }
            ],
        }

        with mock.patch.object(
            cp.urllib_request,  # type: ignore[attr-defined]
            "urlopen",
            return_value=_FakeHTTPResponse(json.dumps(payload)),
        ):
            updates = cp._fetch_telegram_updates(  # type: ignore[attr-defined]
                token="test-bot-token",
                chat_id="123456",
                after_update_id=0,
            )

        self.assertEqual(len(updates), 1)
        self.assertEqual(updates[0][0], 52)
        self.assertEqual(updates[0][1], "continue")
        self.assertEqual(updates[0][2], "[Codex] sid-123 — responded — done")

    def test_process_inbound_telegram_replies_passes_reply_reference_texts(self) -> None:
        with (
            mock.patch.object(
                cp,
                "_fetch_telegram_updates",
                return_value=[(77, "continue", "[Codex] sid-123 — responded — done")],
            ),
            mock.patch.object(cp, "_process_inbound_replies", return_value=77) as process_mock,
            mock.patch.object(cp, "_telegram_bot_token", return_value="token"),
            mock.patch.object(cp, "_telegram_chat_id", return_value="123456"),
        ):
            rowid = cp._process_inbound_telegram_replies(  # type: ignore[attr-defined]
                codex_home=Path("/tmp/codex-home"),
                recipient="+15551234567",
                after_update_id=0,
                max_message_chars=1800,
                min_prefix=6,
                dry_run=False,
            )

        self.assertEqual(rowid, 77)
        ref_texts_fn = process_mock.call_args.kwargs.get("reference_texts_fn")
        self.assertTrue(callable(ref_texts_fn))
        if not callable(ref_texts_fn):
            self.fail("expected reference_texts_fn callback")
        probe_conn = sqlite3.connect(":memory:")
        try:
            resolved = ref_texts_fn(conn=probe_conn, rowid=77, fallback_guid=None)
        finally:
            probe_conn.close()
        self.assertEqual(resolved, ["[Codex] sid-123 — responded — done"])

    def test_main_notify_works_without_imessage_recipient_when_telegram_enabled(self) -> None:
        called: list[dict[str, object]] = []

        def _capture_notify(**kwargs: object) -> None:
            called.append(dict(kwargs))

        with (
            mock.patch.dict(
                cp.os.environ,  # type: ignore[attr-defined]
                {
                    "AGENT_CHAT_HOME": "/tmp/codex-home",
                    "AGENT_CHAT_TRANSPORT": "telegram",
                    "AGENT_TELEGRAM_BOT_TOKEN": "test-bot-token",
                    "AGENT_TELEGRAM_CHAT_ID": "123456",
                },
                clear=False,
            ),
            mock.patch.object(cp, "_handle_notify_payload", side_effect=_capture_notify),
        ):
            rc = cp.main(["notify", '{"type":"agent-turn-complete","session_id":"sid-123"}'])

        self.assertEqual(rc, 0)
        self.assertEqual(len(called), 1)

    def test_doctor_report_includes_routing_snapshot_and_last_dispatch_error(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            codex_home = Path(td)
            tmp_dir = codex_home / "tmp"
            tmp_dir.mkdir(parents=True, exist_ok=True)
            registry_path = tmp_dir / "agent_chat_session_registry.json"
            registry_path.write_text(
                json.dumps(
                    {
                        "sessions": {},
                        "aliases": {},
                        "last_dispatch_error": {
                            "ts": 1771209000,
                            "session_id": "sid-123",
                            "mode": "tmux_failed",
                            "reason": "ack_timeout",
                        },
                    }
                ),
                encoding="utf-8",
            )
            chat_db = tmp_dir / "chat.db"
            with sqlite3.connect(chat_db):
                pass

            with (
                mock.patch.dict(
                    cp.os.environ,
                    {
                        "AGENT_IMESSAGE_CHAT_DB": str(chat_db),
                        "AGENT_CHAT_TMUX_SOCKET": "/tmp/tmux-501/default",
                    },
                    clear=False,
                ),
                mock.patch.object(cp, "_launchd_service_loaded", return_value=(True, "loaded")),
                mock.patch.object(cp, "_read_lock_pid", return_value=12345),
                mock.patch.object(cp, "_is_pid_alive", return_value=True),
                mock.patch.object(
                    cp,
                    "_tmux_active_codex_panes",
                    return_value={
                        "socket": "/tmp/tmux-501/default",
                        "count": 2,
                        "sample": [{"pane_id": "%1"}, {"pane_id": "%2"}],
                    },
                ),
            ):
                report = cp._doctor_report(  # type: ignore[attr-defined]
                    codex_home=codex_home,
                    recipient="+15551234567",
                )

        routing = report.get("routing", {})
        self.assertIsInstance(routing, dict)
        self.assertEqual(routing.get("strict_tmux"), True)
        self.assertEqual(routing.get("tmux_socket"), "/tmp/tmux-501/default")
        self.assertEqual((routing.get("active_codex_panes") or {}).get("count"), 2)  # type: ignore[union-attr]
        self.assertEqual((report.get("state") or {}).get("last_dispatch_error", {}).get("reason"), "ack_timeout")  # type: ignore[union-attr]

    def test_main_doctor_runs_without_recipient(self) -> None:
        report = {
            "ok": False,
            "codex_home": "/tmp/codex-home",
            "recipient": None,
            "launchd": {"loaded": False, "label": "com.agent-chat", "detail": "missing"},
            "lock": {"pid": None, "pid_alive": False, "path": "/tmp/codex-home/tmp/agent_chat_control_plane.lock"},
            "chat_db": {"readable": False, "path": "/tmp/chat.db", "error": "permission denied"},
            "queue": {"lines": 3, "size_bytes": 120, "path": "/tmp/queue.jsonl"},
            "issues": ["missing recipient (AGENT_IMESSAGE_TO)"],
        }

        with (
            mock.patch.dict(cp.os.environ, {"AGENT_CHAT_HOME": "/tmp/codex-home"}, clear=False),
            mock.patch.object(cp, "_doctor_report", return_value=report),
            mock.patch("sys.stdout", new_callable=io.StringIO) as out,
        ):
            rc = cp.main(["doctor"])

        self.assertEqual(rc, 0)
        text = out.getvalue()
        self.assertIn("Agent iMessage doctor: DEGRADED", text)
        self.assertIn("Recipient: (missing)", text)

    def test_main_doctor_prints_launchd_runtime_targets(self) -> None:
        report = {
            "ok": True,
            "codex_home": "/tmp/codex-home",
            "recipient": "+15551234567",
            "launchd": {
                "loaded": True,
                "label": "com.agent-chat",
                "detail": "loaded",
                "runtime_python": "/Users/test/Applications/AgentChatPython.app/Contents/MacOS/Python",
                "permission_app": "/Users/test/Applications/AgentChatPython.app",
            },
            "lock": {"pid": 123, "pid_alive": True, "path": "/tmp/lock"},
            "chat_db": {"readable": True, "path": "/tmp/chat.db", "error": None},
            "queue": {"lines": 0, "size_bytes": 0, "path": "/tmp/queue.jsonl"},
            "routing": {
                "strict_tmux": True,
                "require_session_ref": True,
                "tmux_socket": "/tmp/tmux",
                "active_codex_panes": {"count": 1},
            },
            "issues": [],
        }
        with (
            mock.patch.dict(cp.os.environ, {"AGENT_CHAT_HOME": "/tmp/codex-home"}, clear=False),
            mock.patch.object(cp, "_doctor_report", return_value=report),
            mock.patch("sys.stdout", new_callable=io.StringIO) as out,
        ):
            rc = cp.main(["doctor"])

        self.assertEqual(rc, 0)
        text = out.getvalue()
        self.assertIn("runtime_python:", text)
        self.assertIn("permission_app:", text)

    def test_main_doctor_json_output(self) -> None:
        report = {"ok": True, "codex_home": "/tmp/codex-home"}
        with (
            mock.patch.dict(
                cp.os.environ,
                {"AGENT_CHAT_HOME": "/tmp/codex-home", "AGENT_IMESSAGE_TO": "+15551234567"},
                clear=False,
            ),
            mock.patch.object(cp, "_doctor_report", return_value=report),
            mock.patch("sys.stdout", new_callable=io.StringIO) as out,
        ):
            rc = cp.main(["doctor", "--json"])

        self.assertEqual(rc, 0)
        payload = json.loads(out.getvalue())
        self.assertEqual(payload.get("ok"), True)
        self.assertEqual(payload.get("codex_home"), "/tmp/codex-home")

    def test_run_setup_permissions_returns_zero_when_chat_db_already_readable(self) -> None:
        with (
            mock.patch.object(
                cp,
                "_chat_db_access_status",
                return_value=(Path("/tmp/chat.db"), True, None),
            ),
            mock.patch("sys.stdout", new_callable=io.StringIO) as out,
        ):
            rc = cp._run_setup_permissions(  # type: ignore[attr-defined]
                codex_home=Path("/tmp/codex-home"),
                timeout_s=10.0,
                poll_s=0.1,
                open_settings=False,
            )

        self.assertEqual(rc, 0)
        text = out.getvalue()
        self.assertIn("already granted", text)
        self.assertIn("Python binary:", text)

    def test_resolve_launchd_runtime_python_prefers_friendly_app_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            home.mkdir(parents=True, exist_ok=True)

            python_bin = root / "opt" / "python" / "bin" / "python3"
            python_bin.parent.mkdir(parents=True, exist_ok=True)
            python_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            python_bin.chmod(0o755)

            source_app = root / "opt" / "python" / "Resources" / "Python.app"
            source_exec = source_app / "Contents" / "MacOS" / "Python"
            source_exec.parent.mkdir(parents=True, exist_ok=True)
            source_exec.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            source_exec.chmod(0o755)

            with mock.patch.object(cp.Path, "home", return_value=home):
                runtime_python, permission_app, detail = cp._resolve_launchd_runtime_python(  # type: ignore[attr-defined]
                    python_bin=str(python_bin)
                )

            expected_app = home / "Applications" / "AgentChatPython.app"
            self.assertEqual(
                runtime_python,
                str(expected_app / "Contents" / "MacOS" / "Python"),
            )
            self.assertEqual(permission_app, expected_app)
            self.assertIsNone(detail)
            self.assertTrue((expected_app / "Contents" / "MacOS" / "Python").exists())
            self.assertTrue(expected_app.is_symlink())
            self.assertEqual(expected_app.resolve(), source_app.resolve())

    def test_prepare_friendly_python_app_replaces_existing_copy_with_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            home = root / "home"
            home.mkdir(parents=True, exist_ok=True)

            source_app = root / "opt" / "python" / "Resources" / "Python.app"
            source_exec = source_app / "Contents" / "MacOS" / "Python"
            source_exec.parent.mkdir(parents=True, exist_ok=True)
            source_exec.write_text("source", encoding="utf-8")

            target_app = home / "Applications" / "AgentChatPython.app"
            target_exec = target_app / "Contents" / "MacOS" / "Python"
            target_exec.parent.mkdir(parents=True, exist_ok=True)
            target_exec.write_text("stale-copy", encoding="utf-8")

            with mock.patch.object(cp.Path, "home", return_value=home):
                target_app, detail = cp._prepare_friendly_python_app(  # type: ignore[attr-defined]
                    source_app=source_app
                )

            self.assertEqual(
                target_app,
                home / "Applications" / "AgentChatPython.app",
            )
            self.assertIsNone(detail)
            if target_app is None:
                self.fail("expected target app path")
            self.assertTrue(target_app.is_symlink())
            self.assertEqual(target_app.resolve(), source_app.resolve())

    def test_default_friendly_python_app_name_is_agent_chat_python(self) -> None:
        self.assertEqual(cp._DEFAULT_FRIENDLY_PYTHON_APP_NAME, "AgentChatPython.app")  # type: ignore[attr-defined]

    def test_run_setup_permissions_opens_settings_and_waits_until_readable(self) -> None:
        with (
            mock.patch.object(
                cp,
                "_chat_db_access_status",
                side_effect=[
                    (Path("/tmp/chat.db"), False, "PermissionError: denied"),
                    (Path("/tmp/chat.db"), False, "PermissionError: denied"),
                    (Path("/tmp/chat.db"), True, None),
                ],
            ),
            mock.patch.object(cp, "_open_full_disk_access_settings", return_value=True) as open_mock,
            mock.patch.object(cp.time, "sleep") as sleep_mock,
            mock.patch.object(cp.time, "monotonic", side_effect=[0.0, 0.0, 0.5]),
            mock.patch("sys.stdout", new_callable=io.StringIO) as out,
        ):
            rc = cp._run_setup_permissions(  # type: ignore[attr-defined]
                codex_home=Path("/tmp/codex-home"),
                timeout_s=1.0,
                poll_s=0.1,
                open_settings=True,
            )

        self.assertEqual(rc, 0)
        open_mock.assert_called_once()
        self.assertGreaterEqual(sleep_mock.call_count, 1)
        self.assertIn("Opened System Settings", out.getvalue())
        self.assertIn("Full Disk Access confirmed", out.getvalue())

    def test_open_full_disk_access_settings_does_not_fallback_to_generic_window(self) -> None:
        commands: list[list[str]] = []

        def fake_run(cmd: list[str], **kwargs: object) -> mock.Mock:
            del kwargs
            commands.append(cmd)
            return mock.Mock(returncode=1)

        with mock.patch.object(cp.subprocess, "run", side_effect=fake_run):
            ok = cp._open_full_disk_access_settings()  # type: ignore[attr-defined]

        self.assertFalse(ok)
        self.assertEqual(commands, [["open", cp._FULL_DISK_ACCESS_SETTINGS_URL]])  # type: ignore[attr-defined]

    def test_run_setup_permissions_prefers_app_target_message_when_provided(self) -> None:
        app_path = Path("/Users/test/Applications/AgentChatPython.app")
        with (
            mock.patch.object(
                cp,
                "_chat_db_access_status_for_runtime",
                side_effect=[
                    (Path("/tmp/chat.db"), False, "PermissionError: denied"),
                    (Path("/tmp/chat.db"), False, "PermissionError: denied"),
                ],
            ),
            mock.patch.object(cp, "_open_full_disk_access_settings", return_value=False),
            mock.patch.object(cp.time, "sleep"),
            mock.patch.object(cp.time, "monotonic", side_effect=[0.0, 0.0, 1.6]),
            mock.patch("sys.stdout", new_callable=io.StringIO) as out,
        ):
            rc = cp._run_setup_permissions(  # type: ignore[attr-defined]
                codex_home=Path("/tmp/codex-home"),
                timeout_s=1.0,
                poll_s=0.1,
                open_settings=False,
                probe_python_bin="/tmp/friendly-python",
                permission_app_path=app_path,
            )

        self.assertEqual(rc, 1)
        text = out.getvalue()
        self.assertIn("Grant Full Disk Access to this app", text)
        self.assertIn(str(app_path), text)
        self.assertIn("System Settings > Privacy & Security > Full Disk Access", text)
        self.assertIn("Add one of these targets", text)

    def test_run_setup_permissions_prints_explicit_action_and_wait_target(self) -> None:
        app_path = Path("/Users/test/Applications/AgentChatPython.app")
        with (
            mock.patch.object(
                cp,
                "_chat_db_access_status_for_runtime",
                side_effect=[
                    (Path("/tmp/chat.db"), False, "PermissionError: denied"),
                    (Path("/tmp/chat.db"), False, "PermissionError: denied"),
                ],
            ),
            mock.patch.object(cp.time, "sleep"),
            mock.patch.object(cp.time, "monotonic", side_effect=[0.0, 0.0, 1.2]),
            mock.patch("sys.stdout", new_callable=io.StringIO) as out,
        ):
            rc = cp._run_setup_permissions(  # type: ignore[attr-defined]
                codex_home=Path("/tmp/codex-home"),
                timeout_s=1.0,
                poll_s=0.1,
                open_settings=False,
                probe_python_bin="/tmp/friendly-python",
                permission_app_path=app_path,
            )

        self.assertEqual(rc, 1)
        text = out.getvalue()
        self.assertIn("Detailed steps before the Settings window opens:", text)
        self.assertIn(f"1) In Full Disk Access, add and enable this app: {app_path}", text)
        self.assertIn("Action required now:", text)
        self.assertIn(f"Waiting for Full Disk Access grant for app: {app_path}", text)

    def test_run_setup_permissions_flushes_guidance_before_opening_settings(self) -> None:
        app_path = Path("/Users/test/Applications/AgentChatPython.app")
        observed: dict[str, str] = {"text_at_open": ""}

        class _BufferedStdout:
            def __init__(self) -> None:
                self._pending: list[str] = []
                self._visible: list[str] = []

            def write(self, text: str) -> int:
                self._pending.append(text)
                return len(text)

            def flush(self) -> None:
                self._visible.extend(self._pending)
                self._pending = []

            def getvalue(self) -> str:
                return "".join(self._visible)

        buffered_stdout = _BufferedStdout()

        def fake_open_settings() -> bool:
            observed["text_at_open"] = buffered_stdout.getvalue()
            return True

        with (
            mock.patch.object(
                cp,
                "_chat_db_access_status_for_runtime",
                side_effect=[
                    (Path("/tmp/chat.db"), False, "PermissionError: denied"),
                    (Path("/tmp/chat.db"), False, "PermissionError: denied"),
                    (Path("/tmp/chat.db"), True, None),
                ],
            ),
            mock.patch.object(cp, "_open_full_disk_access_settings", side_effect=fake_open_settings),
            mock.patch.object(cp.time, "sleep"),
            mock.patch.object(cp.time, "monotonic", side_effect=[0.0, 0.0, 0.2, 0.4]),
            mock.patch("sys.stdout", new=buffered_stdout),
        ):
            rc = cp._run_setup_permissions(  # type: ignore[attr-defined]
                codex_home=Path("/tmp/codex-home"),
                timeout_s=1.0,
                poll_s=0.1,
                open_settings=True,
                probe_python_bin="/tmp/friendly-python",
                permission_app_path=app_path,
            )

        self.assertEqual(rc, 0)
        text_at_open = observed["text_at_open"]
        self.assertIn("Permission to grant: Full Disk Access", text_at_open)
        self.assertIn(f"Grant Full Disk Access to this app: {app_path}", text_at_open)
        self.assertIn("Detailed steps before the Settings window opens:", text_at_open)
        self.assertIn(f"1) In Full Disk Access, add and enable this app: {app_path}", text_at_open)
        self.assertIn("Action required now:", text_at_open)

    def test_run_setup_permissions_opens_settings_after_first_poll_cycle(self) -> None:
        events: list[str] = []
        results = iter(
            [
                (Path("/tmp/chat.db"), False, "PermissionError: denied"),
                (Path("/tmp/chat.db"), False, "PermissionError: denied"),
                (Path("/tmp/chat.db"), True, None),
            ]
        )

        def fake_probe(*, codex_home: Path, runtime_python_bin: str) -> tuple[Path, bool, str | None]:
            del codex_home, runtime_python_bin
            events.append("poll")
            return next(results)

        with (
            mock.patch.object(
                cp,
                "_chat_db_access_status_for_runtime",
                side_effect=fake_probe,
            ) as probe_mock,
            mock.patch.object(cp, "_open_full_disk_access_settings", side_effect=lambda: events.append("open") or True),
            mock.patch.object(cp.time, "sleep"),
            mock.patch.object(cp.time, "monotonic", side_effect=[0.0, 0.0, 0.3, 0.6]),
            mock.patch("sys.stdout", new_callable=io.StringIO),
        ):
            rc = cp._run_setup_permissions(  # type: ignore[attr-defined]
                codex_home=Path("/tmp/codex-home"),
                timeout_s=1.0,
                poll_s=0.1,
                open_settings=True,
                probe_python_bin="/tmp/friendly-python",
            )

        self.assertEqual(rc, 0)
        self.assertGreaterEqual(probe_mock.call_count, 3)
        self.assertEqual(events[:3], ["poll", "poll", "open"])

    def test_run_setup_permissions_times_out_when_chat_db_unreadable(self) -> None:
        with (
            mock.patch.object(
                cp,
                "_chat_db_access_status",
                side_effect=[
                    (Path("/tmp/chat.db"), False, "PermissionError: denied"),
                    (Path("/tmp/chat.db"), False, "PermissionError: denied"),
                    (Path("/tmp/chat.db"), False, "PermissionError: denied"),
                ],
            ),
            mock.patch.object(cp, "_open_full_disk_access_settings", return_value=False) as open_mock,
            mock.patch.object(cp.time, "sleep"),
            mock.patch.object(cp.time, "monotonic", side_effect=[0.0, 0.0, 0.6, 1.2]),
            mock.patch("sys.stdout", new_callable=io.StringIO) as out,
        ):
            rc = cp._run_setup_permissions(  # type: ignore[attr-defined]
                codex_home=Path("/tmp/codex-home"),
                timeout_s=1.0,
                poll_s=0.1,
                open_settings=True,
            )

        self.assertEqual(rc, 1)
        open_mock.assert_called_once()
        self.assertIn("Timed out waiting for chat.db access", out.getvalue())

    def test_main_setup_permissions_runs_without_recipient(self) -> None:
        with (
            mock.patch.dict(cp.os.environ, {"AGENT_CHAT_HOME": "/tmp/codex-home"}, clear=False),
            mock.patch.object(
                cp,
                "_launchd_runtime_targets_from_plist",
                return_value=(None, None),
            ),
            mock.patch.object(cp, "_run_setup_permissions", return_value=0) as setup_mock,
        ):
            rc = cp.main(
                [
                    "setup-permissions",
                    "--timeout",
                    "5",
                    "--poll",
                    "0.2",
                    "--no-open",
                ]
            )

        self.assertEqual(rc, 0)
        setup_mock.assert_called_once_with(
            codex_home=Path("/tmp/codex-home"),
            timeout_s=5.0,
            poll_s=0.2,
            open_settings=False,
        )

    def test_main_setup_notify_hook_uses_new_command(self) -> None:
        with (
            mock.patch.dict(
                cp.os.environ,
                {"AGENT_CHAT_HOME": "/tmp/codex-home", "AGENT_IMESSAGE_TO": "+15551234567"},
                clear=False,
            ),
            mock.patch.object(cp, "_ensure_tmux_available_for_setup", return_value=("/opt/homebrew/bin/tmux", None)) as tmux_mock,
            mock.patch.object(cp, "_run_setup_notify_hook", return_value=0) as setup_mock,
        ):
            rc = cp.main(
                [
                    "setup-notify-hook",
                    "--python-bin",
                    "/usr/bin/python3",
                ]
            )

        self.assertEqual(rc, 0)
        setup_mock.assert_called_once_with(
            codex_home=Path("/tmp/codex-home"),
            recipient="+15551234567",
            python_bin="/usr/bin/python3",
            script_path=Path(cp.__file__).resolve(),  # type: ignore[attr-defined]
        )
        tmux_mock.assert_called_once()

    def test_main_setup_notify_hook_stops_when_tmux_setup_fails(self) -> None:
        with (
            mock.patch.dict(
                cp.os.environ,
                {"AGENT_CHAT_HOME": "/tmp/codex-home", "AGENT_IMESSAGE_TO": "+15551234567"},
                clear=False,
            ),
            mock.patch.object(
                cp,
                "_ensure_tmux_available_for_setup",
                return_value=(None, "tmux install failed\n"),
            ),
            mock.patch.object(cp, "_run_setup_notify_hook") as setup_mock,
            mock.patch("sys.stdout", new_callable=io.StringIO) as out,
        ):
            rc = cp.main(
                [
                    "setup-notify-hook",
                    "--python-bin",
                    "/usr/bin/python3",
                ]
            )

        self.assertEqual(rc, 1)
        setup_mock.assert_not_called()
        self.assertIn("tmux install failed", out.getvalue())

    def test_main_setup_permissions_prefers_launchd_runtime_targets(self) -> None:
        with (
            mock.patch.dict(cp.os.environ, {"AGENT_CHAT_HOME": "/tmp/codex-home"}, clear=False),
            mock.patch.object(
                cp,
                "_launchd_runtime_targets_from_plist",
                return_value=(
                    "/tmp/runtime-python",
                    "/Users/test/Applications/AgentChatPython.app",
                ),
            ),
            mock.patch.object(cp, "_run_setup_permissions", return_value=0) as setup_mock,
        ):
            rc = cp.main(
                [
                    "setup-permissions",
                    "--timeout",
                    "5",
                    "--poll",
                    "0.2",
                    "--no-open",
                ]
            )

        self.assertEqual(rc, 0)
        setup_mock.assert_called_once_with(
            codex_home=Path("/tmp/codex-home"),
            timeout_s=5.0,
            poll_s=0.2,
            open_settings=False,
            probe_python_bin="/tmp/runtime-python",
            permission_app_path=Path("/Users/test/Applications/AgentChatPython.app"),
        )

    def test_run_setup_launchd_writes_plist_and_bootstraps(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            codex_home = home / ".codex"
            script_path = home / "repo" / "agent_chat_control_plane.py"
            script_path.parent.mkdir(parents=True, exist_ok=True)
            script_path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

            with (
                mock.patch.object(cp.Path, "home", return_value=home),
                mock.patch.object(cp, "_run_setup_permissions", return_value=0) as setup_mock,
                mock.patch.object(
                    cp,
                    "_resolve_launchd_runtime_python",
                    return_value=("/opt/homebrew/bin/python3", None, None),
                ),
                mock.patch.object(cp.subprocess, "run", return_value=mock.Mock(returncode=0, stderr="")) as run_mock,
                mock.patch("sys.stdout", new_callable=io.StringIO),
            ):
                rc = cp._run_setup_launchd(  # type: ignore[attr-defined]
                    codex_home=codex_home,
                    recipient="+15551234567",
                    label="com.agent-chat",
                    python_bin="/opt/homebrew/bin/python3",
                    script_path=script_path,
                    setup_permissions=True,
                    timeout_s=15.0,
                    poll_s=0.5,
                    open_settings=False,
                )

            self.assertEqual(rc, 0)
            setup_mock.assert_called_once_with(
                codex_home=codex_home,
                timeout_s=15.0,
                poll_s=0.5,
                open_settings=False,
                probe_python_bin="/opt/homebrew/bin/python3",
                permission_app_path=None,
            )

            plist_path = home / "Library" / "LaunchAgents" / "com.agent-chat.plist"
            self.assertTrue(plist_path.exists())
            with plist_path.open("rb") as f:
                payload = plistlib.load(f)
            self.assertEqual(payload.get("Label"), "com.agent-chat")
            self.assertEqual(payload.get("ProgramArguments", [None])[0], "/opt/homebrew/bin/python3")
            program_args = payload.get("ProgramArguments", [None, None])
            self.assertEqual(Path(program_args[1]).resolve(), script_path.resolve())  # type: ignore[index]

            commands = [call.args[0] for call in run_mock.call_args_list]
            self.assertIn(
                ["launchctl", "bootstrap", f"gui/{cp.os.getuid()}", str(plist_path)],  # type: ignore[attr-defined]
                commands,
            )
            self.assertIn(
                ["launchctl", "kickstart", "-k", f"gui/{cp.os.getuid()}/com.agent-chat"],  # type: ignore[attr-defined]
                commands,
            )

    def test_run_setup_launchd_requires_recipient(self) -> None:
        with (
            mock.patch("sys.stdout", new_callable=io.StringIO) as out,
            mock.patch.object(cp.Path, "home", return_value=Path("/tmp/fake-home")),
        ):
            rc = cp._run_setup_launchd(  # type: ignore[attr-defined]
                codex_home=Path("/tmp/codex-home"),
                recipient="",
                label="com.agent-chat",
                python_bin="/usr/bin/python3",
                script_path=Path("/tmp/agent_chat_control_plane.py"),
                setup_permissions=False,
                timeout_s=10.0,
                poll_s=1.0,
                open_settings=False,
            )
        self.assertEqual(rc, 1)
        self.assertIn("AGENT_IMESSAGE_TO is required", out.getvalue())

    def test_run_setup_launchd_allows_missing_recipient_for_telegram_transport(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            codex_home = home / ".codex"
            script_path = home / "repo" / "agent_chat_control_plane.py"
            script_path.parent.mkdir(parents=True, exist_ok=True)
            script_path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

            with (
                mock.patch.dict(
                    cp.os.environ,  # type: ignore[attr-defined]
                    {
                        "AGENT_CHAT_TRANSPORT": "telegram",
                        "AGENT_TELEGRAM_BOT_TOKEN": "telegram-token",
                        "AGENT_TELEGRAM_CHAT_ID": "123456",
                    },
                    clear=False,
                ),
                mock.patch.object(cp.Path, "home", return_value=home),
                mock.patch.object(cp, "_run_setup_permissions", return_value=0),
                mock.patch.object(
                    cp,
                    "_resolve_launchd_runtime_python",
                    return_value=("/opt/homebrew/bin/python3", None, None),
                ),
                mock.patch.object(cp.subprocess, "run", return_value=mock.Mock(returncode=0, stderr="")),
                mock.patch("sys.stdout", new_callable=io.StringIO),
            ):
                rc = cp._run_setup_launchd(  # type: ignore[attr-defined]
                    codex_home=codex_home,
                    recipient="",
                    label="com.agent-chat",
                    python_bin="/opt/homebrew/bin/python3",
                    script_path=script_path,
                    setup_permissions=True,
                    timeout_s=15.0,
                    poll_s=0.5,
                    open_settings=False,
                )

            self.assertEqual(rc, 0)
            plist_path = home / "Library" / "LaunchAgents" / "com.agent-chat.plist"
            with plist_path.open("rb") as f:
                payload = plistlib.load(f)
            env_vars = payload.get("EnvironmentVariables")
            self.assertIsInstance(env_vars, dict)
            self.assertEqual((env_vars or {}).get("AGENT_CHAT_TRANSPORT"), "telegram")
            self.assertEqual((env_vars or {}).get("AGENT_TELEGRAM_CHAT_ID"), "123456")
            self.assertEqual((env_vars or {}).get("AGENT_TELEGRAM_BOT_TOKEN"), "telegram-token")
            self.assertNotIn("AGENT_IMESSAGE_TO", env_vars or {})

    def test_run_setup_launchd_requires_telegram_bot_token_with_instructions(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            codex_home = home / ".codex"
            script_path = home / "repo" / "agent_chat_control_plane.py"
            script_path.parent.mkdir(parents=True, exist_ok=True)
            script_path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

            with (
                mock.patch.dict(
                    cp.os.environ,  # type: ignore[attr-defined]
                    {
                        "AGENT_CHAT_TRANSPORT": "telegram",
                        "AGENT_TELEGRAM_BOT_TOKEN": "",
                        "AGENT_TELEGRAM_CHAT_ID": "123456",
                    },
                    clear=False,
                ),
                mock.patch("sys.stdout", new_callable=io.StringIO) as out,
            ):
                rc = cp._run_setup_launchd(  # type: ignore[attr-defined]
                    codex_home=codex_home,
                    recipient="",
                    label="com.agent-chat",
                    python_bin="/opt/homebrew/bin/python3",
                    script_path=script_path,
                    setup_permissions=False,
                    timeout_s=15.0,
                    poll_s=0.5,
                    open_settings=False,
                )

            self.assertEqual(rc, 1)
            text = out.getvalue()
            self.assertIn("AGENT_TELEGRAM_BOT_TOKEN is required", text)
            self.assertIn("@BotFather", text)
            self.assertIn("/newbot", text)
            self.assertIn("/token", text)

    def test_run_setup_launchd_enables_service_before_bootstrap(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            codex_home = home / ".codex"
            script_path = home / "repo" / "agent_chat_control_plane.py"
            script_path.parent.mkdir(parents=True, exist_ok=True)
            script_path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

            with (
                mock.patch.object(cp.Path, "home", return_value=home),
                mock.patch.object(cp, "_run_setup_permissions", return_value=0),
                mock.patch.object(
                    cp,
                    "_resolve_launchd_runtime_python",
                    return_value=("/opt/homebrew/bin/python3", None, None),
                ),
                mock.patch.object(cp.subprocess, "run", return_value=mock.Mock(returncode=0, stderr="")) as run_mock,
                mock.patch("sys.stdout", new_callable=io.StringIO),
            ):
                rc = cp._run_setup_launchd(  # type: ignore[attr-defined]
                    codex_home=codex_home,
                    recipient="+15551234567",
                    label="com.agent-chat",
                    python_bin="/opt/homebrew/bin/python3",
                    script_path=script_path,
                    setup_permissions=True,
                    timeout_s=15.0,
                    poll_s=0.5,
                    open_settings=False,
                )

        self.assertEqual(rc, 0)
        commands = [call.args[0] for call in run_mock.call_args_list]
        enable_cmd = ["launchctl", "enable", f"gui/{cp.os.getuid()}/com.agent-chat"]  # type: ignore[attr-defined]
        bootstrap_cmd_prefix = ["launchctl", "bootstrap", f"gui/{cp.os.getuid()}"]  # type: ignore[attr-defined]

        enable_index = next(i for i, cmd in enumerate(commands) if cmd == enable_cmd)
        bootstrap_index = next(
            i
            for i, cmd in enumerate(commands)
            if len(cmd) >= 3 and cmd[:3] == bootstrap_cmd_prefix
        )
        self.assertLess(enable_index, bootstrap_index)

    def test_run_setup_launchd_fails_when_launchd_still_cannot_read_chat_db(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            codex_home = home / ".codex"
            script_path = home / "repo" / "agent_chat_control_plane.py"
            script_path.parent.mkdir(parents=True, exist_ok=True)
            script_path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")

            with (
                mock.patch.object(cp.Path, "home", return_value=home),
                mock.patch.object(cp, "_run_setup_permissions", return_value=0),
                mock.patch.object(cp.subprocess, "run", return_value=mock.Mock(returncode=0, stderr="")),
                mock.patch.object(cp, "_launchd_inbound_warning_active", return_value=True),
                mock.patch.object(cp, "_chat_db_access_status", return_value=(Path("/tmp/chat.db"), True, None)),
                mock.patch.object(cp.time, "sleep"),
                mock.patch("sys.stdout", new_callable=io.StringIO) as out,
            ):
                rc = cp._run_setup_launchd(  # type: ignore[attr-defined]
                    codex_home=codex_home,
                    recipient="+15551234567",
                    label="com.agent-chat",
                    python_bin="/opt/homebrew/bin/python3",
                    script_path=script_path,
                    setup_permissions=True,
                    timeout_s=15.0,
                    poll_s=0.5,
                    open_settings=False,
                )

        self.assertEqual(rc, 1)
        text = out.getvalue()
        self.assertIn("launchd runtime still cannot read chat.db", text)
        self.assertIn("Full Disk Access app above (preferred)", text)
        self.assertIn("System Settings > Privacy & Security > Full Disk Access", text)

    def test_run_setup_launchd_reports_tcc_mismatch_hint(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            codex_home = home / ".codex"
            script_path = home / "repo" / "agent_chat_control_plane.py"
            script_path.parent.mkdir(parents=True, exist_ok=True)
            script_path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
            permission_app = home / "Applications" / "AgentChatPython.app"

            with (
                mock.patch.object(cp.Path, "home", return_value=home),
                mock.patch.object(cp, "_run_setup_permissions", return_value=0),
                mock.patch.object(
                    cp,
                    "_resolve_launchd_runtime_python",
                    return_value=("/opt/homebrew/bin/python3", permission_app, None),
                ),
                mock.patch.object(cp.subprocess, "run", return_value=mock.Mock(returncode=0, stderr="")),
                mock.patch.object(cp, "_launchd_inbound_warning_active", return_value=True),
                mock.patch.object(cp, "_chat_db_access_status", return_value=(Path("/tmp/chat.db"), True, None)),
                mock.patch.object(cp, "_app_bundle_identifier", return_value="org.python.python"),
                mock.patch.object(cp, "_tcc_log_has_code_requirement_mismatch", return_value=True),
                mock.patch.object(cp.time, "sleep"),
                mock.patch("sys.stdout", new_callable=io.StringIO) as out,
            ):
                rc = cp._run_setup_launchd(  # type: ignore[attr-defined]
                    codex_home=codex_home,
                    recipient="+15551234567",
                    label="com.agent-chat",
                    python_bin="/opt/homebrew/bin/python3",
                    script_path=script_path,
                    setup_permissions=True,
                    timeout_s=15.0,
                    poll_s=0.5,
                    open_settings=False,
                )

        self.assertEqual(rc, 1)
        text = out.getvalue()
        self.assertIn("stale TCC code-requirement mismatch", text)
        self.assertIn("tccutil reset SystemPolicyAllFiles org.python.python", text)

    def test_run_setup_launchd_repair_tcc_recovers_and_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            codex_home = home / ".codex"
            script_path = home / "repo" / "agent_chat_control_plane.py"
            script_path.parent.mkdir(parents=True, exist_ok=True)
            script_path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
            permission_app = home / "Applications" / "AgentChatPython.app"

            with (
                mock.patch.object(cp.Path, "home", return_value=home),
                mock.patch.object(cp, "_run_setup_permissions", side_effect=[0, 0]) as setup_mock,
                mock.patch.object(
                    cp,
                    "_resolve_launchd_runtime_python",
                    return_value=("/opt/homebrew/bin/python3", permission_app, None),
                ),
                mock.patch.object(cp.subprocess, "run", return_value=mock.Mock(returncode=0, stderr="")),
                mock.patch.object(cp, "_launchd_inbound_warning_active", side_effect=[True, False]),
                mock.patch.object(cp, "_chat_db_access_status", return_value=(Path("/tmp/chat.db"), True, None)),
                mock.patch.object(cp, "_app_bundle_identifier", return_value="org.python.python"),
                mock.patch.object(cp, "_reset_tcc_full_disk_access", return_value=(True, None)) as reset_mock,
                mock.patch.object(cp.time, "sleep"),
                mock.patch("sys.stdout", new_callable=io.StringIO) as out,
            ):
                rc = cp._run_setup_launchd(  # type: ignore[attr-defined]
                    codex_home=codex_home,
                    recipient="+15551234567",
                    label="com.agent-chat",
                    python_bin="/opt/homebrew/bin/python3",
                    script_path=script_path,
                    setup_permissions=True,
                    timeout_s=15.0,
                    poll_s=0.5,
                    open_settings=False,
                    repair_tcc=True,
                )

        self.assertEqual(rc, 0)
        self.assertEqual(setup_mock.call_count, 2)
        reset_mock.assert_called_once_with(bundle_id="org.python.python")
        self.assertIn("Launchd inbound access verified after TCC repair", out.getvalue())

    def test_main_setup_launchd_uses_new_command(self) -> None:
        with (
            mock.patch.dict(
                cp.os.environ,
                {"AGENT_CHAT_HOME": "/tmp/codex-home", "AGENT_IMESSAGE_TO": "+15551234567"},
                clear=False,
            ),
            mock.patch.object(cp, "_ensure_tmux_available_for_setup", return_value=("/opt/homebrew/bin/tmux", None)) as tmux_mock,
            mock.patch.object(cp, "_run_setup_launchd", return_value=0) as setup_mock,
        ):
            rc = cp.main(
                [
                    "setup-launchd",
                    "--label",
                    "com.agent-chat",
                    "--python-bin",
                    "/usr/bin/python3",
                    "--timeout",
                    "12",
                    "--poll",
                    "0.3",
                    "--no-open",
                    "--skip-permissions",
                ]
            )

        self.assertEqual(rc, 0)
        setup_mock.assert_called_once_with(
            codex_home=Path("/tmp/codex-home"),
            recipient="+15551234567",
            label="com.agent-chat",
            python_bin="/usr/bin/python3",
            script_path=Path(cp.__file__).resolve(),  # type: ignore[attr-defined]
            setup_permissions=False,
            timeout_s=12.0,
            poll_s=0.3,
            open_settings=False,
            repair_tcc=False,
        )
        tmux_mock.assert_called_once()



if __name__ == "__main__":
    unittest.main()
