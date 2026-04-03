import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import agent_chat_control_plane as cp


class TestMultiAgentExpansion(unittest.TestCase):
    def test_parse_agent_choice_response_supports_pi(self) -> None:
        self.assertEqual(cp._parse_agent_choice_response(text="3"), "pi")  # type: ignore[attr-defined]
        self.assertEqual(cp._parse_agent_choice_response(text="pi"), "pi")  # type: ignore[attr-defined]

    def test_transport_list_supports_discord(self) -> None:
        with mock.patch.dict(cp.os.environ, {"AGENT_CHAT_TRANSPORTS": "telegram,discord"}, clear=False):
            self.assertEqual(cp._transport_list(), ["telegram", "discord"])  # type: ignore[attr-defined]
            self.assertTrue(cp._transport_discord_enabled())  # type: ignore[attr-defined]
            self.assertTrue(cp._transport_telegram_enabled())  # type: ignore[attr-defined]

    def test_load_registry_migrates_legacy_telegram_bindings_into_conversation_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            codex_home = Path(td)
            registry_path = codex_home / "tmp" / "agent_chat_session_registry.json"
            registry_path.parent.mkdir(parents=True, exist_ok=True)
            registry_path.write_text(
                '{"sessions":{"sid-1":{"session_id":"sid-1","telegram_chat_id":"123","telegram_message_thread_id":456}},'
                '"aliases":{},"telegram_thread_bindings":{"123:456":"sid-1"}}',
                encoding="utf-8",
            )
            loaded = cp._load_registry(codex_home=codex_home)  # type: ignore[attr-defined]

        bindings = loaded.get("conversation_bindings")
        self.assertIsInstance(bindings, dict)
        if not isinstance(bindings, dict):
            self.fail("expected conversation_bindings")
        self.assertEqual(bindings.get("telegram:123:456"), "sid-1")

    def test_send_structured_uses_discord_transport_when_enabled(self) -> None:
        sent: list[tuple[str, str, str]] = []

        def _capture(*, token: str, channel_id: str, message: str) -> bool:
            sent.append((token, channel_id, message))
            return True

        with (
            mock.patch.dict(
                cp.os.environ,
                {
                    "AGENT_CHAT_TRANSPORTS": "discord",
                    "AGENT_DISCORD_BOT_TOKEN": "discord-token",
                    "AGENT_DISCORD_CHANNEL_ID": "chan-1",
                },
                clear=False,
            ),
            mock.patch.object(cp, "_send_discord_message", side_effect=_capture),
            mock.patch.object(cp.outbound, "_send_imessage") as imessage_send,
        ):
            cp._send_structured(  # type: ignore[attr-defined]
                codex_home=Path("/tmp/codex-home"),
                recipient="+15551234567",
                session_id=None,
                kind="status",
                text="hello discord",
                max_message_chars=1800,
                dry_run=False,
                message_index={"messages": []},
                discord_channel_id="thread-9",
            )

        self.assertEqual(imessage_send.call_count, 0)
        self.assertEqual(sent[0][0], "discord-token")
        self.assertEqual(sent[0][1], "thread-9")
        self.assertIn("hello discord", sent[0][2])

    def test_send_structured_auto_creates_discord_session_channel_when_enabled(self) -> None:
        sent: list[tuple[str, str, str]] = []
        registry = {
            "sessions": {
                "pi-sid": {
                    "session_id": "pi-sid",
                    "agent": "pi",
                    "cwd": "/tmp/project",
                }
            },
            "aliases": {},
            "conversation_bindings": {},
            "pending_new_session_choice": None,
            "pending_new_session_choice_by_context": {},
            "pending_new_session_choice_by_thread": {},
            "telegram_thread_bindings": {},
        }

        def _capture(*, token: str, channel_id: str, message: str) -> bool:
            sent.append((token, channel_id, message))
            return True

        with (
            mock.patch.dict(
                cp.os.environ,
                {
                    "AGENT_CHAT_TRANSPORTS": "discord",
                    "AGENT_DISCORD_BOT_TOKEN": "discord-token",
                    "AGENT_DISCORD_CHANNEL_ID": "control-1",
                    "AGENT_DISCORD_CONTROL_CHANNEL_ID": "control-1",
                    "AGENT_DISCORD_SESSION_CHANNELS": "1",
                },
                clear=False,
            ),
            mock.patch.object(cp, "_load_registry", return_value=registry),
            mock.patch.object(cp, "_save_registry"),
            mock.patch.object(
                cp,
                "_discord_get_channel",
                return_value={"id": "control-1", "guild_id": "guild-1", "parent_id": "cat-1"},
            ),
            mock.patch.object(cp, "_discord_create_text_channel", return_value=("chan-9", "pi-project-pi-sid")),
            mock.patch.object(cp, "_send_discord_message", side_effect=_capture),
            mock.patch.object(cp.outbound, "_send_imessage") as imessage_send,
        ):
            cp._send_structured(  # type: ignore[attr-defined]
                codex_home=Path("/tmp/codex-home"),
                recipient="+15551234567",
                session_id="pi-sid",
                kind="update",
                text="assistant output",
                max_message_chars=1800,
                dry_run=False,
                message_index={"messages": []},
                agent="pi",
            )

        self.assertEqual(imessage_send.call_count, 0)
        self.assertEqual(sent[0][1], "chan-9")
        self.assertIn("assistant output", sent[0][2])
        self.assertEqual(registry["conversation_bindings"].get("discord:chan-9:0"), "pi-sid")
        self.assertEqual(registry["sessions"]["pi-sid"].get("discord_channel_id"), "chan-9")

    def test_process_inbound_replies_control_channel_does_not_bind_session_when_session_channels_enabled(self) -> None:
        sid = "pi-sid-12345678"
        ref = cp._session_ref(sid)  # type: ignore[attr-defined]
        registry = {
            "sessions": {sid: {"session_id": sid, "agent": "pi"}},
            "aliases": {},
            "conversation_bindings": {},
            "pending_new_session_choice": None,
            "pending_new_session_choice_by_context": {},
            "pending_new_session_choice_by_thread": {},
            "telegram_thread_bindings": {},
        }
        sent: list[dict[str, object]] = []

        def _capture_send(**kwargs: object) -> None:
            sent.append(dict(kwargs))

        with (
            sqlite3.connect(":memory:") as conn,
            mock.patch.dict(
                cp.os.environ,
                {
                    "AGENT_CHAT_TRANSPORTS": "discord",
                    "AGENT_DISCORD_SESSION_CHANNELS": "1",
                    "AGENT_DISCORD_CONTROL_CHANNEL_ID": "control-1",
                },
                clear=False,
            ),
            mock.patch.object(cp.reply, "_fetch_new_replies", return_value=[(204, f"@{ref} continue", None)]),
            mock.patch.object(cp.reply, "_is_attention_message", return_value=False),
            mock.patch.object(cp.reply, "_is_bot_message", return_value=False),
            mock.patch.object(cp, "_load_registry", return_value=registry),
            mock.patch.object(cp, "_load_message_index", return_value={"messages": []}),
            mock.patch.object(cp, "_load_attention_index", return_value={}),
            mock.patch.object(cp, "_load_last_attention_state", return_value=None),
            mock.patch.object(cp, "_resolve_session_agent", return_value="pi"),
            mock.patch.object(cp, "_dispatch_prompt_to_session", return_value=("resume", "ok")),
            mock.patch.object(cp, "_send_structured", side_effect=_capture_send),
            mock.patch.object(cp, "_save_registry"),
            mock.patch.object(cp, "_save_message_index"),
        ):
            rowid = cp._process_inbound_replies(  # type: ignore[attr-defined]
                conn=conn,
                after_rowid=0,
                handle_ids=[],
                codex_home=Path("/tmp/codex-home"),
                recipient="+15551234567",
                max_message_chars=1800,
                min_prefix=6,
                dry_run=False,
                row_contexts_fn=lambda **_: {
                    204: {
                        "transport": "discord",
                        "discord_parent_channel_id": "control-1",
                        "discord_channel_id": "control-1",
                        "discord_sender_user_id": "owner-1",
                    }
                },
            )

        self.assertEqual(rowid, 204)
        self.assertEqual(registry["conversation_bindings"], {})
        self.assertTrue(any(msg.get("session_id") == sid for msg in sent))

    def test_process_session_file_emits_discord_update_for_pi_assistant_message(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            codex_home = Path(td)
            session_path = codex_home / "sessions" / "sample.jsonl"
            session_path.parent.mkdir(parents=True, exist_ok=True)
            session_path.write_text(
                "\n".join(
                    [
                        json.dumps({"type": "session", "id": "pi-sid", "cwd": "/tmp/project"}),
                        json.dumps(
                            {
                                "type": "message",
                                "message": {
                                    "role": "assistant",
                                    "content": [{"type": "text", "text": "hello from pi"}],
                                },
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            registry = {
                "sessions": {"pi-sid": {"session_id": "pi-sid", "agent": "pi", "pending_completion": False}},
                "aliases": {},
                "conversation_bindings": {},
            }
            sent: list[dict[str, object]] = []

            with (
                mock.patch.dict(
                    cp.os.environ,
                    {"AGENT_CHAT_TRANSPORTS": "discord", "AGENT_DISCORD_SESSION_CHANNELS": "1"},
                    clear=False,
                ),
                mock.patch.object(cp, "_agent_for_session_path", return_value="pi"),
                mock.patch.object(cp, "_send_structured", side_effect=lambda **kwargs: sent.append(dict(kwargs))),
            ):
                offset = cp._process_session_file(  # type: ignore[attr-defined]
                    codex_home=codex_home,
                    session_path=session_path,
                    offset=0,
                    recipient="+15551234567",
                    max_message_chars=1800,
                    dry_run=False,
                    registry=registry,
                    message_index={"messages": []},
                    session_id_cache={},
                    call_id_to_name={},
                    seen_needs_input_call_ids={},
                )

        self.assertGreater(offset, 0)
        self.assertTrue(any(msg.get("kind") == "update" and msg.get("session_id") == "pi-sid" for msg in sent))

    def test_process_session_file_quiet_notification_level_suppresses_final_response(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            codex_home = Path(td)
            session_path = codex_home / "sessions" / "sample.jsonl"
            session_path.parent.mkdir(parents=True, exist_ok=True)
            session_path.write_text(
                "\n".join(
                    [
                        json.dumps({"type": "session", "id": "sid-quiet", "cwd": "/tmp/project"}),
                        json.dumps(
                            {
                                "type": "message",
                                "message": {
                                    "role": "assistant",
                                    "content": [{"type": "text", "text": "done quietly"}],
                                },
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            registry = {
                "sessions": {"sid-quiet": {"session_id": "sid-quiet", "agent": "pi", "pending_completion": True}},
                "aliases": {},
                "conversation_bindings": {},
            }
            sent: list[dict[str, object]] = []

            with (
                mock.patch.dict(cp.os.environ, {"AGENT_CHAT_NOTIFICATION_LEVEL": "quiet"}, clear=False),
                mock.patch.object(cp, "_agent_for_session_path", return_value="pi"),
                mock.patch.object(cp, "_send_structured", side_effect=lambda **kwargs: sent.append(dict(kwargs))),
            ):
                cp._process_session_file(  # type: ignore[attr-defined]
                    codex_home=codex_home,
                    session_path=session_path,
                    offset=0,
                    recipient="+15551234567",
                    max_message_chars=1800,
                    dry_run=False,
                    registry=registry,
                    message_index={"messages": []},
                    session_id_cache={},
                    call_id_to_name={},
                    seen_needs_input_call_ids={},
                )

        self.assertFalse(any(msg.get("kind") == "responded" for msg in sent))
        self.assertFalse(registry["sessions"]["sid-quiet"]["pending_completion"])

    def test_process_session_file_verbose_notification_level_emits_progress_update_without_discord(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            codex_home = Path(td)
            session_path = codex_home / "sessions" / "sample.jsonl"
            session_path.parent.mkdir(parents=True, exist_ok=True)
            session_path.write_text(
                "\n".join(
                    [
                        json.dumps({"type": "session", "id": "sid-verbose", "cwd": "/tmp/project"}),
                        json.dumps(
                            {
                                "type": "message",
                                "message": {
                                    "role": "assistant",
                                    "content": [{"type": "text", "text": "progress update"}],
                                },
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            registry = {
                "sessions": {"sid-verbose": {"session_id": "sid-verbose", "agent": "pi", "pending_completion": False}},
                "aliases": {},
                "conversation_bindings": {},
            }
            sent: list[dict[str, object]] = []

            with (
                mock.patch.dict(cp.os.environ, {"AGENT_CHAT_NOTIFICATION_LEVEL": "verbose"}, clear=False),
                mock.patch.object(cp, "_agent_for_session_path", return_value="pi"),
                mock.patch.object(cp, "_send_structured", side_effect=lambda **kwargs: sent.append(dict(kwargs))),
            ):
                cp._process_session_file(  # type: ignore[attr-defined]
                    codex_home=codex_home,
                    session_path=session_path,
                    offset=0,
                    recipient="+15551234567",
                    max_message_chars=1800,
                    dry_run=False,
                    registry=registry,
                    message_index={"messages": []},
                    session_id_cache={},
                    call_id_to_name={},
                    seen_needs_input_call_ids={},
                )

        self.assertTrue(any(msg.get("kind") == "update" and msg.get("session_id") == "sid-verbose" for msg in sent))

    def test_process_inbound_replies_implicit_discord_binding_resolves_target_first(self) -> None:
        registry = {
            "sessions": {"sid-dis": {"session_id": "sid-dis", "agent": "pi"}},
            "aliases": {},
            "conversation_bindings": {"discord:chan-1:thread-9": "sid-dis"},
            "pending_new_session_choice": None,
            "pending_new_session_choice_by_context": {},
            "pending_new_session_choice_by_thread": {},
            "telegram_thread_bindings": {},
        }
        sent: list[dict[str, object]] = []

        def _capture_send(**kwargs: object) -> None:
            sent.append(dict(kwargs))

        with (
            sqlite3.connect(":memory:") as conn,
            mock.patch.object(cp.reply, "_fetch_new_replies", return_value=[(201, "continue", None)]),
            mock.patch.object(cp.reply, "_is_attention_message", return_value=False),
            mock.patch.object(cp.reply, "_is_bot_message", return_value=False),
            mock.patch.object(cp, "_load_registry", return_value=registry),
            mock.patch.object(cp, "_load_message_index", return_value={"messages": []}),
            mock.patch.object(cp, "_load_attention_index", return_value={}),
            mock.patch.object(cp, "_load_last_attention_state", return_value=None),
            mock.patch.object(cp, "_resolve_session_agent", return_value="pi"),
            mock.patch.object(cp, "_dispatch_prompt_to_session", return_value=("resume", "ok")) as dispatch_mock,
            mock.patch.object(cp, "_send_structured", side_effect=_capture_send),
            mock.patch.object(cp, "_save_registry"),
            mock.patch.object(cp, "_save_message_index"),
        ):
            rowid = cp._process_inbound_replies(  # type: ignore[attr-defined]
                conn=conn,
                after_rowid=0,
                handle_ids=[],
                codex_home=Path("/tmp/codex-home"),
                recipient="+15551234567",
                max_message_chars=1800,
                min_prefix=6,
                dry_run=False,
                row_contexts_fn=lambda **_: {
                    201: {
                        "transport": "discord",
                        "discord_parent_channel_id": "chan-1",
                        "discord_channel_id": "thread-9",
                        "discord_sender_user_id": "owner-1",
                    }
                },
            )

        self.assertEqual(rowid, 201)
        self.assertEqual(dispatch_mock.call_args.kwargs.get("target_sid"), "sid-dis")
        self.assertTrue(any(msg.get("session_id") == "sid-dis" for msg in sent))

    def test_process_inbound_replies_unresolved_discord_context_sets_context_pending_choice(self) -> None:
        registry = {
            "sessions": {},
            "aliases": {},
            "conversation_bindings": {},
            "pending_new_session_choice": None,
            "pending_new_session_choice_by_context": {},
            "pending_new_session_choice_by_thread": {},
            "telegram_thread_bindings": {},
        }
        sent: list[dict[str, object]] = []

        def _capture_send(**kwargs: object) -> None:
            sent.append(dict(kwargs))

        with (
            sqlite3.connect(":memory:") as conn,
            mock.patch.object(cp.reply, "_fetch_new_replies", return_value=[(202, "continue", None)]),
            mock.patch.object(cp.reply, "_is_attention_message", return_value=False),
            mock.patch.object(cp.reply, "_is_bot_message", return_value=False),
            mock.patch.object(cp, "_load_registry", return_value=registry),
            mock.patch.object(cp, "_load_message_index", return_value={"messages": []}),
            mock.patch.object(cp, "_load_attention_index", return_value={}),
            mock.patch.object(cp, "_load_last_attention_state", return_value=None),
            mock.patch.object(
                cp,
                "_resolve_session_from_reply_context",
                return_value=(None, "No tracked sessions. Use @<ref> ... or new <label>: ..."),
            ),
            mock.patch.object(cp, "_default_new_session_cwd", return_value="/tmp/project"),
            mock.patch.object(cp, "_send_structured", side_effect=_capture_send),
            mock.patch.object(cp, "_save_registry"),
            mock.patch.object(cp, "_save_message_index"),
        ):
            rowid = cp._process_inbound_replies(  # type: ignore[attr-defined]
                conn=conn,
                after_rowid=0,
                handle_ids=[],
                codex_home=Path("/tmp/codex-home"),
                recipient="+15551234567",
                max_message_chars=1800,
                min_prefix=6,
                dry_run=False,
                row_contexts_fn=lambda **_: {
                    202: {
                        "transport": "discord",
                        "discord_parent_channel_id": "chan-1",
                        "discord_channel_id": "thread-9",
                        "discord_sender_user_id": "owner-1",
                    }
                },
            )

        self.assertEqual(rowid, 202)
        pending = registry.get("pending_new_session_choice_by_context")
        self.assertIsInstance(pending, dict)
        if not isinstance(pending, dict):
            self.fail("expected pending context map")
        self.assertIn("discord:chan-1:thread-9", pending)
        self.assertTrue(any(msg.get("kind") == "needs_input" for msg in sent))

    def test_process_inbound_replies_pending_discord_context_binds_created_session(self) -> None:
        registry = {
            "sessions": {},
            "aliases": {},
            "conversation_bindings": {},
            "pending_new_session_choice": None,
            "pending_new_session_choice_by_context": {
                "discord:chan-1:thread-9": {
                    "prompt": "continue",
                    "action": "implicit",
                    "source_text": "continue",
                    "source_ref": None,
                    "label": None,
                    "cwd": "/tmp/project",
                    "created_ts": 1,
                }
            },
            "pending_new_session_choice_by_thread": {},
            "telegram_thread_bindings": {},
        }
        sent: list[dict[str, object]] = []

        def _capture_send(**kwargs: object) -> None:
            sent.append(dict(kwargs))

        with (
            sqlite3.connect(":memory:") as conn,
            mock.patch.object(cp.reply, "_fetch_new_replies", return_value=[(203, "3", None)]),
            mock.patch.object(cp.reply, "_is_attention_message", return_value=False),
            mock.patch.object(cp.reply, "_is_bot_message", return_value=False),
            mock.patch.object(cp, "_load_registry", return_value=registry),
            mock.patch.object(cp, "_load_message_index", return_value={"messages": []}),
            mock.patch.object(cp, "_load_attention_index", return_value={}),
            mock.patch.object(cp, "_load_last_attention_state", return_value=None),
            mock.patch.object(cp, "_create_new_session_in_tmux", return_value=("pi-sid", "/tmp/pi-sid.jsonl", "%5", None)),
            mock.patch.object(cp.outbound, "_read_session_cwd", return_value="/tmp/project"),
            mock.patch.object(cp, "_send_structured", side_effect=_capture_send),
            mock.patch.object(cp, "_save_registry"),
            mock.patch.object(cp, "_save_message_index"),
        ):
            rowid = cp._process_inbound_replies(  # type: ignore[attr-defined]
                conn=conn,
                after_rowid=0,
                handle_ids=[],
                codex_home=Path("/tmp/codex-home"),
                recipient="+15551234567",
                max_message_chars=1800,
                min_prefix=6,
                dry_run=False,
                row_contexts_fn=lambda **_: {
                    203: {
                        "transport": "discord",
                        "discord_parent_channel_id": "chan-1",
                        "discord_channel_id": "thread-9",
                        "discord_sender_user_id": "owner-1",
                    }
                },
            )

        self.assertEqual(rowid, 203)
        self.assertEqual(registry["conversation_bindings"].get("discord:chan-1:thread-9"), "pi-sid")
        self.assertEqual(registry["sessions"]["pi-sid"].get("agent"), "pi")
        self.assertTrue(any(msg.get("session_id") == "pi-sid" for msg in sent))

    def test_process_inbound_replies_pending_discord_pi_choice_does_not_fallback_without_tmux(self) -> None:
        registry = {
            "sessions": {},
            "aliases": {},
            "conversation_bindings": {},
            "pending_new_session_choice": None,
            "pending_new_session_choice_by_context": {
                "discord:chan-1:thread-9": {
                    "prompt": "continue",
                    "action": "implicit",
                    "source_text": "continue",
                    "source_ref": None,
                    "label": None,
                    "cwd": "/tmp/project",
                    "created_ts": 1,
                }
            },
            "pending_new_session_choice_by_thread": {},
            "telegram_thread_bindings": {},
        }
        sent: list[dict[str, object]] = []

        def _capture_send(**kwargs: object) -> None:
            sent.append(dict(kwargs))

        with (
            sqlite3.connect(":memory:") as conn,
            mock.patch.object(cp.reply, "_fetch_new_replies", return_value=[(204, "3", None)]),
            mock.patch.object(cp.reply, "_is_attention_message", return_value=False),
            mock.patch.object(cp.reply, "_is_bot_message", return_value=False),
            mock.patch.object(cp, "_load_registry", return_value=registry),
            mock.patch.object(cp, "_load_message_index", return_value={"messages": []}),
            mock.patch.object(cp, "_load_attention_index", return_value={}),
            mock.patch.object(cp, "_load_last_attention_state", return_value=None),
            mock.patch.object(cp, "_create_new_session_in_tmux", return_value=(None, None, None, "tmux failed")),
            mock.patch.object(cp, "_create_new_session") as fallback_mock,
            mock.patch.object(cp, "_send_structured", side_effect=_capture_send),
            mock.patch.object(cp, "_save_registry"),
            mock.patch.object(cp, "_save_message_index"),
        ):
            rowid = cp._process_inbound_replies(  # type: ignore[attr-defined]
                conn=conn,
                after_rowid=0,
                handle_ids=[],
                codex_home=Path("/tmp/codex-home"),
                recipient="+15551234567",
                max_message_chars=1800,
                min_prefix=6,
                dry_run=False,
                row_contexts_fn=lambda **_: {
                    204: {
                        "transport": "discord",
                        "discord_parent_channel_id": "chan-1",
                        "discord_channel_id": "thread-9",
                        "discord_sender_user_id": "owner-1",
                    }
                },
            )

        self.assertEqual(rowid, 204)
        fallback_mock.assert_not_called()
        self.assertEqual(registry.get("conversation_bindings"), {})
        pending = registry.get("pending_new_session_choice_by_context")
        self.assertIsInstance(pending, dict)
        if not isinstance(pending, dict):
            self.fail("expected pending context map")
        self.assertIn("discord:chan-1:thread-9", pending)
        self.assertTrue(any(msg.get("kind") == "error" for msg in sent))
        self.assertTrue(any("tmux-backed pi session" in str(msg.get("text", "")).lower() for msg in sent))
