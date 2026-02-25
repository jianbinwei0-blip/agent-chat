import os
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


import agent_chat_outbound_lib as bridge


class TestAgentChatOutboundBridge(unittest.TestCase):
    def test_redact_keeps_semver_and_domain_text(self) -> None:
        text = (
            "Latest Codex CLI: 0.80.0\n"
            "- GitHub releases: https://github.com/openai/codex/releases\n"
            "- Codex changelog: https://developers.openai.com/codex/changelog"
        )
        redacted = bridge._redact(text)  # type: ignore[attr-defined]
        self.assertIn("0.80.0", redacted)
        self.assertIn("https://developers.openai.com/codex/changelog", redacted)
        self.assertNotIn("<JWT_REDACTED>", redacted)

    def test_redact_masks_jwt_like_tokens(self) -> None:
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        text = f"token={jwt}"
        redacted = bridge._redact(text)  # type: ignore[attr-defined]
        self.assertNotIn(jwt, redacted)
        self.assertIn("token=<JWT_REDACTED>", redacted)

    def test_extract_user_message_text(self) -> None:
        payload = {
            "type": "message",
            "role": "user",
            "content": [
                {"type": "input_text", "text": "Hello"},
                {"type": "input_text", "text": " world"},
            ],
        }
        extracted = bridge._extract_message_text_from_payload(payload)  # type: ignore[attr-defined]
        self.assertEqual(extracted, ("user", "Hello world"))

    def test_extract_assistant_message_text(self) -> None:
        payload = {
            "type": "message",
            "role": "assistant",
            "content": [
                {"type": "output_text", "text": "Answer"},
                {"type": "output_text", "text": " here"},
            ],
        }
        extracted = bridge._extract_message_text_from_payload(payload)  # type: ignore[attr-defined]
        self.assertEqual(extracted, ("assistant", "Answer here"))

    def test_extract_request_user_input_questions(self) -> None:
        args = {
            "questions": [
                {
                    "header": "Scope",
                    "id": "scope_target",
                    "question": "Where should this live?",
                    "options": [
                        {"label": "Option A", "description": "First option", "value": "a"},
                        {"label": "Option B", "description": "Second option", "value": "b"},
                    ],
                }
            ]
        }
        payload = {
            "type": "function_call",
            "name": "request_user_input",
            "arguments": json.dumps(args),
            "call_id": "call_123",
        }
        rendered = bridge._extract_request_user_input_text(payload)  # type: ignore[attr-defined]
        self.assertIsInstance(rendered, str)
        if not isinstance(rendered, str):
            self.fail("expected rendered request_user_input text")
        self.assertIn("Where should this live?", rendered)
        self.assertIn("1. Option A", rendered)
        self.assertIn("2. Option B", rendered)

    def test_extract_tool_call_exec_command(self) -> None:
        payload = {
            "type": "function_call",
            "name": "exec_command",
            "arguments": json.dumps({"cmd": "echo hi", "yield_time_ms": 1000}),
            "call_id": "call_abc",
        }
        extracted = bridge._extract_tool_call(payload)  # type: ignore[attr-defined]
        self.assertIsNotNone(extracted)
        kind, text = extracted  # type: ignore[misc]
        self.assertEqual(kind, "tool_call:exec_command")
        self.assertIn("ToolCall: exec_command", text)
        self.assertIn("echo hi", text)

    def test_extract_tool_result_includes_tool_name_when_mapped(self) -> None:
        payload = {
            "type": "function_call_output",
            "call_id": "call_abc",
            "output": "Chunk ID: 123\\nOutput: ok",
        }
        extracted = bridge._extract_tool_result(payload, call_id_to_name={"call_abc": "exec_command"})  # type: ignore[attr-defined]
        self.assertIsNotNone(extracted)
        kind, text = extracted  # type: ignore[misc]
        self.assertEqual(kind, "tool_result:exec_command")
        self.assertIn("ToolResult: exec_command", text)
        self.assertIn("Output: ok", text)

    def test_split_message_reassembles_body(self) -> None:
        header = "[Codex] sid — assistant — 2026-02-05T12:00:00-08:00"
        body = ("0123456789\n" * 30) + "tail\n"
        messages = bridge._split_message(header, body, max_message_chars=120)  # type: ignore[attr-defined]
        self.assertGreater(len(messages), 1)
        for msg in messages:
            self.assertLessEqual(len(msg), 120)

        def extract_chunk(message: str) -> str:
            first_nl = message.find("\n")
            self.assertNotEqual(first_nl, -1)
            rest = message[first_nl + 1 :]
            if rest.startswith("Part "):
                second_nl = rest.find("\n")
                self.assertNotEqual(second_nl, -1)
                return rest[second_nl + 1 :]
            return rest

        reconstructed = "".join(extract_chunk(m) for m in messages)
        self.assertEqual(reconstructed, body)

    def test_process_session_path_assistant_only_role_filter(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            session_path = Path(td) / "session.jsonl"
            queue_path = Path(td) / "queue.jsonl"
            session_path.write_text(
                "\n".join(
                    [
                        json.dumps({"type": "session_meta", "payload": {"id": "sid-1"}}),
                        json.dumps(
                            {
                                "type": "response_item",
                                "payload": {
                                    "type": "message",
                                    "role": "user",
                                    "content": [{"type": "input_text", "text": "Hello"}],
                                },
                            }
                        ),
                        json.dumps(
                            {
                                "type": "response_item",
                                "payload": {
                                    "type": "message",
                                    "role": "assistant",
                                    "content": [{"type": "output_text", "text": "Hi there"}],
                                },
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            sent_kinds: list[str] = []

            def _capture_send_structured(**kwargs: object) -> None:
                sent_kinds.append(str(kwargs.get("kind")))

            with mock.patch.dict(
                os.environ,
                {"AGENT_CHAT_MIRROR_ROLES": "assistant", "AGENT_CHAT_ONLY_NEEDS_INPUT": "0"},
                clear=False,
            ):
                with mock.patch.object(bridge, "_send_structured", side_effect=_capture_send_structured):
                    bridge._process_session_path(  # type: ignore[attr-defined]
                        codex_home=Path(td),
                        session_path=session_path,
                        offset=0,
                        recipient="+15551234567",
                        mirror_roles=bridge._parse_mirror_roles(os.environ.get("AGENT_CHAT_MIRROR_ROLES")),  # type: ignore[attr-defined]
                        max_message_chars=1800,
                        dry_run=True,
                        queue_path=queue_path,
                        session_id_cache={},
                        call_id_to_name={},
                        seen_needs_input_call_ids={},
                    )

            self.assertEqual(sent_kinds, ["assistant"])

    def test_process_session_path_defaults_to_needs_input_only(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            session_path = Path(td) / "session.jsonl"
            queue_path = Path(td) / "queue.jsonl"
            request_args = {
                "questions": [
                    {
                        "header": "Approval",
                        "id": "approve_run",
                        "question": "Allow elevated command?",
                        "options": [
                            {"label": "Yes", "description": "Proceed"},
                            {"label": "No", "description": "Cancel"},
                        ],
                    }
                ]
            }
            session_path.write_text(
                "\n".join(
                    [
                        json.dumps({"type": "session_meta", "payload": {"id": "sid-2"}}),
                        json.dumps(
                            {
                                "type": "response_item",
                                "payload": {
                                    "type": "message",
                                    "role": "assistant",
                                    "content": [{"type": "output_text", "text": "Working on it"}],
                                },
                            }
                        ),
                        json.dumps(
                            {
                                "type": "response_item",
                                "payload": {
                                    "type": "function_call",
                                    "name": "request_user_input",
                                    "call_id": "call_approve_1",
                                    "arguments": json.dumps(request_args),
                                },
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            sent_kinds: list[str] = []

            def _capture_send_structured(**kwargs: object) -> None:
                sent_kinds.append(str(kwargs.get("kind")))

            with mock.patch.dict(
                os.environ,
                {"AGENT_CHAT_MIRROR_TOOLS": "1", "AGENT_CHAT_ONLY_NEEDS_INPUT": "1"},
                clear=False,
            ):
                with mock.patch.object(bridge, "_send_structured", side_effect=_capture_send_structured):
                    bridge._process_session_path(  # type: ignore[attr-defined]
                        codex_home=Path(td),
                        session_path=session_path,
                        offset=0,
                        recipient="+15551234567",
                        mirror_roles=bridge._parse_mirror_roles(os.environ.get("AGENT_CHAT_MIRROR_ROLES")),  # type: ignore[attr-defined]
                        max_message_chars=1800,
                        dry_run=True,
                        queue_path=queue_path,
                        session_id_cache={},
                        call_id_to_name={},
                        seen_needs_input_call_ids={},
                    )

            self.assertEqual(sent_kinds, ["needs_input"])

    def test_process_session_path_can_disable_needs_input_gate(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            session_path = Path(td) / "session.jsonl"
            queue_path = Path(td) / "queue.jsonl"
            request_args = {
                "questions": [
                    {
                        "header": "Scope",
                        "id": "scope_target",
                        "question": "Which option should I use?",
                        "options": [
                            {"label": "A", "description": "Option A"},
                            {"label": "B", "description": "Option B"},
                        ],
                    }
                ]
            }
            session_path.write_text(
                "\n".join(
                    [
                        json.dumps({"type": "session_meta", "payload": {"id": "sid-3"}}),
                        json.dumps(
                            {
                                "type": "response_item",
                                "payload": {
                                    "type": "message",
                                    "role": "assistant",
                                    "content": [{"type": "output_text", "text": "Here is an update"}],
                                },
                            }
                        ),
                        json.dumps(
                            {
                                "type": "response_item",
                                "payload": {
                                    "type": "function_call",
                                    "name": "request_user_input",
                                    "call_id": "call_scope_1",
                                    "arguments": json.dumps(request_args),
                                },
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            sent_kinds: list[str] = []

            def _capture_send_structured(**kwargs: object) -> None:
                sent_kinds.append(str(kwargs.get("kind")))

            with mock.patch.dict(
                os.environ,
                {
                    "AGENT_CHAT_MIRROR_ROLES": "assistant",
                    "AGENT_CHAT_MIRROR_TOOLS": "1",
                    "AGENT_CHAT_ONLY_NEEDS_INPUT": "0",
                },
                clear=False,
            ):
                with mock.patch.object(bridge, "_send_structured", side_effect=_capture_send_structured):
                    bridge._process_session_path(  # type: ignore[attr-defined]
                        codex_home=Path(td),
                        session_path=session_path,
                        offset=0,
                        recipient="+15551234567",
                        mirror_roles=bridge._parse_mirror_roles(os.environ.get("AGENT_CHAT_MIRROR_ROLES")),  # type: ignore[attr-defined]
                        max_message_chars=1800,
                        dry_run=True,
                        queue_path=queue_path,
                        session_id_cache={},
                        call_id_to_name={},
                        seen_needs_input_call_ids={},
                    )

            self.assertEqual(sent_kinds, ["assistant", "needs_input"])

    def test_process_session_path_skips_seen_needs_input_call_id(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            session_path = Path(td) / "session.jsonl"
            queue_path = Path(td) / "queue.jsonl"
            request_args = {
                "questions": [
                    {
                        "header": "Approval",
                        "id": "approve_run",
                        "question": "Allow elevated command?",
                        "options": [
                            {"label": "Yes", "description": "Proceed"},
                            {"label": "No", "description": "Cancel"},
                        ],
                    }
                ]
            }
            session_path.write_text(
                "\n".join(
                    [
                        json.dumps({"type": "session_meta", "payload": {"id": "sid-4"}}),
                        json.dumps(
                            {
                                "type": "response_item",
                                "payload": {
                                    "type": "function_call",
                                    "name": "request_user_input",
                                    "call_id": "call_approve_1",
                                    "arguments": json.dumps(request_args),
                                },
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            sent_kinds: list[str] = []

            def _capture_send_structured(**kwargs: object) -> None:
                sent_kinds.append(str(kwargs.get("kind")))

            seen = {f"{str(session_path)}:call_approve_1": 1}
            with mock.patch.dict(
                os.environ,
                {"AGENT_CHAT_MIRROR_TOOLS": "1", "AGENT_CHAT_ONLY_NEEDS_INPUT": "1"},
                clear=False,
            ):
                with mock.patch.object(bridge, "_send_structured", side_effect=_capture_send_structured):
                    bridge._process_session_path(  # type: ignore[attr-defined]
                        codex_home=Path(td),
                        session_path=session_path,
                        offset=0,
                        recipient="+15551234567",
                        mirror_roles=bridge._parse_mirror_roles(os.environ.get("AGENT_CHAT_MIRROR_ROLES")),  # type: ignore[attr-defined]
                        max_message_chars=1800,
                        dry_run=True,
                        queue_path=queue_path,
                        session_id_cache={},
                        call_id_to_name={},
                        seen_needs_input_call_ids=seen,
                    )

            self.assertEqual(sent_kinds, [])

    def test_process_session_path_records_seen_needs_input_call_id(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            session_path = Path(td) / "session.jsonl"
            queue_path = Path(td) / "queue.jsonl"
            request_args = {
                "questions": [
                    {
                        "header": "Approval",
                        "id": "approve_run",
                        "question": "Allow elevated command?",
                        "options": [
                            {"label": "Yes", "description": "Proceed"},
                            {"label": "No", "description": "Cancel"},
                        ],
                    }
                ]
            }
            session_path.write_text(
                "\n".join(
                    [
                        json.dumps({"type": "session_meta", "payload": {"id": "sid-5"}}),
                        json.dumps(
                            {
                                "type": "response_item",
                                "payload": {
                                    "type": "function_call",
                                    "name": "request_user_input",
                                    "call_id": "call_approve_2",
                                    "arguments": json.dumps(request_args),
                                },
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            sent_kinds: list[str] = []

            def _capture_send_structured(**kwargs: object) -> None:
                sent_kinds.append(str(kwargs.get("kind")))

            seen: dict[str, int] = {}
            with mock.patch.dict(
                os.environ,
                {"AGENT_CHAT_MIRROR_TOOLS": "1", "AGENT_CHAT_ONLY_NEEDS_INPUT": "1"},
                clear=False,
            ):
                with mock.patch.object(bridge, "_send_structured", side_effect=_capture_send_structured):
                    bridge._process_session_path(  # type: ignore[attr-defined]
                        codex_home=Path(td),
                        session_path=session_path,
                        offset=0,
                        recipient="+15551234567",
                        mirror_roles=bridge._parse_mirror_roles(os.environ.get("AGENT_CHAT_MIRROR_ROLES")),  # type: ignore[attr-defined]
                        max_message_chars=1800,
                        dry_run=True,
                        queue_path=queue_path,
                        session_id_cache={},
                        call_id_to_name={},
                        seen_needs_input_call_ids=seen,
                    )

            self.assertEqual(sent_kinds, ["needs_input"])
            self.assertIn(f"{str(session_path)}:call_approve_2", seen)

    def test_process_session_path_semantic_dedupe_same_question_different_call_id(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            session_path = Path(td) / "session.jsonl"
            queue_path = Path(td) / "queue.jsonl"
            request_args = {
                "questions": [
                    {
                        "header": "Approval",
                        "id": "approve_run",
                        "question": "Implement this plan?",
                        "options": [
                            {"label": "Yes, implement this plan", "description": "Switch to Default and start coding."},
                            {"label": "No, stay in Plan mode", "description": "Continue planning with the model."},
                        ],
                    }
                ]
            }
            session_path.write_text(
                "\n".join(
                    [
                        json.dumps({"type": "session_meta", "payload": {"id": "sid-6"}}),
                        json.dumps(
                            {
                                "type": "response_item",
                                "payload": {
                                    "type": "function_call",
                                    "name": "request_user_input",
                                    "call_id": "call_plan_1",
                                    "arguments": json.dumps(request_args),
                                },
                            }
                        ),
                        json.dumps(
                            {
                                "type": "response_item",
                                "payload": {
                                    "type": "function_call",
                                    "name": "request_user_input",
                                    "call_id": "call_plan_2",
                                    "arguments": json.dumps(request_args),
                                },
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            sent_kinds: list[str] = []

            def _capture_send_structured(**kwargs: object) -> None:
                sent_kinds.append(str(kwargs.get("kind")))

            with mock.patch.dict(
                os.environ,
                {"AGENT_CHAT_MIRROR_TOOLS": "1", "AGENT_CHAT_ONLY_NEEDS_INPUT": "1"},
                clear=False,
            ):
                with mock.patch.object(bridge, "_send_structured", side_effect=_capture_send_structured):
                    bridge._process_session_path(  # type: ignore[attr-defined]
                        codex_home=Path(td),
                        session_path=session_path,
                        offset=0,
                        recipient="+15551234567",
                        mirror_roles=bridge._parse_mirror_roles(os.environ.get("AGENT_CHAT_MIRROR_ROLES")),  # type: ignore[attr-defined]
                        max_message_chars=1800,
                        dry_run=True,
                        queue_path=queue_path,
                        session_id_cache={},
                        call_id_to_name={},
                        seen_needs_input_call_ids={},
                    )

            self.assertEqual(sent_kinds, ["needs_input"])

    def test_process_session_path_semantic_dedupe_same_question_without_call_id(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            session_path = Path(td) / "session.jsonl"
            queue_path = Path(td) / "queue.jsonl"
            request_args = {
                "questions": [
                    {
                        "header": "Approval",
                        "id": "approve_run",
                        "question": "Implement this plan?",
                        "options": [
                            {"label": "Yes, implement this plan", "description": "Switch to Default and start coding."},
                            {"label": "No, stay in Plan mode", "description": "Continue planning with the model."},
                        ],
                    }
                ]
            }
            session_path.write_text(
                "\n".join(
                    [
                        json.dumps({"type": "session_meta", "payload": {"id": "sid-7"}}),
                        json.dumps(
                            {
                                "type": "response_item",
                                "payload": {
                                    "type": "function_call",
                                    "name": "request_user_input",
                                    "arguments": json.dumps(request_args),
                                },
                            }
                        ),
                        json.dumps(
                            {
                                "type": "response_item",
                                "payload": {
                                    "type": "function_call",
                                    "name": "request_user_input",
                                    "arguments": json.dumps(request_args),
                                },
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            sent_kinds: list[str] = []

            def _capture_send_structured(**kwargs: object) -> None:
                sent_kinds.append(str(kwargs.get("kind")))

            with mock.patch.dict(
                os.environ,
                {"AGENT_CHAT_MIRROR_TOOLS": "1", "AGENT_CHAT_ONLY_NEEDS_INPUT": "1"},
                clear=False,
            ):
                with mock.patch.object(bridge, "_send_structured", side_effect=_capture_send_structured):
                    bridge._process_session_path(  # type: ignore[attr-defined]
                        codex_home=Path(td),
                        session_path=session_path,
                        offset=0,
                        recipient="+15551234567",
                        mirror_roles=bridge._parse_mirror_roles(os.environ.get("AGENT_CHAT_MIRROR_ROLES")),  # type: ignore[attr-defined]
                        max_message_chars=1800,
                        dry_run=True,
                        queue_path=queue_path,
                        session_id_cache={},
                        call_id_to_name={},
                        seen_needs_input_call_ids={},
                    )

            self.assertEqual(sent_kinds, ["needs_input"])

    def test_process_session_path_needs_input_persists_attention_context(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            codex_home = Path(td)
            session_path = codex_home / "session.jsonl"
            queue_path = codex_home / "queue.jsonl"
            request_args = {
                "questions": [
                    {
                        "header": "Approval",
                        "id": "approve_run",
                        "question": "Allow elevated command?",
                        "options": [
                            {"label": "Yes", "description": "Proceed"},
                            {"label": "No", "description": "Cancel"},
                        ],
                    }
                ]
            }
            session_path.write_text(
                "\n".join(
                    [
                        json.dumps({"type": "session_meta", "payload": {"id": "sid-attn-1", "cwd": "/Users/testuser/project-a"}}),
                        json.dumps(
                            {
                                "type": "response_item",
                                "payload": {
                                    "type": "function_call",
                                    "name": "request_user_input",
                                    "call_id": "call_attn_1",
                                    "arguments": json.dumps(request_args),
                                },
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            with mock.patch.dict(
                os.environ,
                {"AGENT_CHAT_MIRROR_TOOLS": "1", "AGENT_CHAT_ONLY_NEEDS_INPUT": "1"},
                clear=False,
            ):
                with mock.patch.object(bridge, "_send_structured", return_value=None):
                    bridge._process_session_path(  # type: ignore[attr-defined]
                        codex_home=codex_home,
                        session_path=session_path,
                        offset=0,
                        recipient="+15551234567",
                        mirror_roles=bridge._parse_mirror_roles(None),  # type: ignore[attr-defined]
                        max_message_chars=1800,
                        dry_run=True,
                        queue_path=queue_path,
                        session_id_cache={},
                        call_id_to_name={},
                        seen_needs_input_call_ids={},
                    )

            last_attention_path = codex_home / "tmp" / "agent_chat_last_attention.json"
            attention_index_path = codex_home / "tmp" / "agent_chat_attention_index.json"
            self.assertTrue(last_attention_path.exists())
            self.assertTrue(attention_index_path.exists())

            last_attention = json.loads(last_attention_path.read_text(encoding="utf-8"))
            attention_index = json.loads(attention_index_path.read_text(encoding="utf-8"))

            self.assertEqual(last_attention.get("session_id"), "sid-attn-1")
            self.assertEqual(last_attention.get("cwd"), "/Users/testuser/project-a")
            self.assertEqual(last_attention.get("session_path"), str(session_path))
            self.assertEqual(last_attention.get("to"), "+15551234567")

            self.assertIn("sid-attn-1", attention_index)
            idx_record = attention_index["sid-attn-1"]
            self.assertEqual(idx_record.get("session_path"), str(session_path))
            self.assertEqual(idx_record.get("cwd"), "/Users/testuser/project-a")

    def test_process_session_path_non_needs_input_does_not_persist_attention_context(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            codex_home = Path(td)
            session_path = codex_home / "session.jsonl"
            queue_path = codex_home / "queue.jsonl"
            session_path.write_text(
                "\n".join(
                    [
                        json.dumps({"type": "session_meta", "payload": {"id": "sid-attn-2", "cwd": "/Users/testuser/project-b"}}),
                        json.dumps(
                            {
                                "type": "response_item",
                                "payload": {
                                    "type": "message",
                                    "role": "assistant",
                                    "content": [{"type": "output_text", "text": "Progress update"}],
                                },
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            with mock.patch.dict(
                os.environ,
                {
                    "AGENT_CHAT_MIRROR_ROLES": "assistant",
                    "AGENT_CHAT_MIRROR_TOOLS": "1",
                    "AGENT_CHAT_ONLY_NEEDS_INPUT": "0",
                },
                clear=False,
            ):
                with mock.patch.object(bridge, "_send_structured", return_value=None):
                    bridge._process_session_path(  # type: ignore[attr-defined]
                        codex_home=codex_home,
                        session_path=session_path,
                        offset=0,
                        recipient="+15551234567",
                        mirror_roles=bridge._parse_mirror_roles(os.environ.get("AGENT_CHAT_MIRROR_ROLES")),  # type: ignore[attr-defined]
                        max_message_chars=1800,
                        dry_run=True,
                        queue_path=queue_path,
                        session_id_cache={},
                        call_id_to_name={},
                        seen_needs_input_call_ids={},
                    )

            self.assertFalse((codex_home / "tmp" / "agent_chat_last_attention.json").exists())
            self.assertFalse((codex_home / "tmp" / "agent_chat_attention_index.json").exists())

    def test_process_session_path_missing_session_id_does_not_create_index_entry(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            codex_home = Path(td)
            session_path = codex_home / "session.jsonl"
            queue_path = codex_home / "queue.jsonl"
            request_args = {
                "questions": [
                    {
                        "header": "Approval",
                        "id": "approve_run",
                        "question": "Allow elevated command?",
                        "options": [
                            {"label": "Yes", "description": "Proceed"},
                            {"label": "No", "description": "Cancel"},
                        ],
                    }
                ]
            }
            session_path.write_text(
                "\n".join(
                    [
                        json.dumps({"type": "session_meta", "payload": {"cwd": "/Users/testuser/project-c"}}),
                        json.dumps(
                            {
                                "type": "response_item",
                                "payload": {
                                    "type": "function_call",
                                    "name": "request_user_input",
                                    "call_id": "call_attn_2",
                                    "arguments": json.dumps(request_args),
                                },
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            with mock.patch.dict(
                os.environ,
                {"AGENT_CHAT_MIRROR_TOOLS": "1", "AGENT_CHAT_ONLY_NEEDS_INPUT": "1"},
                clear=False,
            ):
                with mock.patch.object(bridge, "_send_structured", return_value=None):
                    bridge._process_session_path(  # type: ignore[attr-defined]
                        codex_home=codex_home,
                        session_path=session_path,
                        offset=0,
                        recipient="+15551234567",
                        mirror_roles=bridge._parse_mirror_roles(None),  # type: ignore[attr-defined]
                        max_message_chars=1800,
                        dry_run=True,
                        queue_path=queue_path,
                        session_id_cache={},
                        call_id_to_name={},
                        seen_needs_input_call_ids={},
                    )

            last_attention_path = codex_home / "tmp" / "agent_chat_last_attention.json"
            attention_index_path = codex_home / "tmp" / "agent_chat_attention_index.json"
            self.assertTrue(last_attention_path.exists())
            last_attention = json.loads(last_attention_path.read_text(encoding="utf-8"))
            self.assertIsNone(last_attention.get("session_id"))

            if attention_index_path.exists():
                attention_index = json.loads(attention_index_path.read_text(encoding="utf-8"))
                self.assertEqual(attention_index, {})

    def test_send_imessage_uses_repo_local_script(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            module_file = Path(td) / "agent_chat_outbound_lib.py"
            script_path = Path(td) / "scripts" / "send-imessage.applescript"
            script_path.parent.mkdir(parents=True, exist_ok=True)
            script_path.write_text("on run argv\nend run\n", encoding="utf-8")

            proc = mock.Mock()
            proc.returncode = 0

            with (
                mock.patch.object(bridge, "__file__", str(module_file)),
                mock.patch.object(bridge.subprocess, "run", return_value=proc) as run_mock,
            ):
                sent = bridge._send_imessage(recipient="+15551234567", message="hello")  # type: ignore[attr-defined]

            self.assertTrue(sent)
            cmd = run_mock.call_args.args[0]
            self.assertEqual(cmd[0], "osascript")
            self.assertEqual(Path(cmd[1]).resolve(), script_path.resolve())


if __name__ == "__main__":
    unittest.main()
