import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import agent_chat_outbound_lib as bridge
import agent_chat_notify as notify


class TestAgentChatNotify(unittest.TestCase):
    def test_read_last_request_user_input_from_session_extracts_questions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session_path = Path(tmp) / "session.jsonl"
            args = {
                "questions": [
                    {
                        "header": "Scope",
                        "id": "scope_target",
                        "question": "Where should this live?",
                        "options": [
                            {
                                "label": "Option A",
                                "description": "First option",
                                "value": "a",
                            },
                            {
                                "label": "Option B",
                                "description": "Second option",
                                "value": "b",
                            },
                        ],
                    }
                ]
            }
            session_path.write_text(
                "\n".join(
                    [
                        json.dumps({"type": "session_meta", "payload": {"id": "sid-123"}}),
                        json.dumps(
                            {
                                "type": "response_item",
                                "payload": {
                                    "type": "function_call",
                                    "name": "request_user_input",
                                    "arguments": json.dumps(args),
                                    "call_id": "call_123",
                                },
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            parsed = notify._read_last_request_user_input_from_session(session_path)  # type: ignore[attr-defined]
            self.assertIsInstance(parsed, dict)
            questions = parsed.get("questions")
            self.assertIsInstance(questions, list)
            self.assertEqual(questions[0]["id"], "scope_target")

    def test_read_last_request_user_input_from_session_falls_back_to_latest_answered_questions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session_path = Path(tmp) / "session.jsonl"
            args = {
                "questions": [
                    {
                        "header": "Scope",
                        "id": "scope_target",
                        "question": "Where should this live?",
                        "options": [
                            {
                                "label": "Option A",
                                "description": "First option",
                                "value": "a",
                            },
                            {
                                "label": "Option B",
                                "description": "Second option",
                                "value": "b",
                            },
                        ],
                    }
                ]
            }
            session_path.write_text(
                "\n".join(
                    [
                        json.dumps({"type": "session_meta", "payload": {"id": "sid-123"}}),
                        json.dumps(
                            {
                                "type": "response_item",
                                "payload": {
                                    "type": "function_call",
                                    "name": "request_user_input",
                                    "arguments": json.dumps(args),
                                    "call_id": "call_123",
                                },
                            }
                        ),
                        json.dumps(
                            {
                                "type": "response_item",
                                "payload": {
                                    "type": "function_call_output",
                                    "call_id": "call_123",
                                    "output": json.dumps({"answers": {"scope_target": {"answers": ["a"]}}}),
                                },
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            parsed = notify._read_last_request_user_input_from_session(session_path)  # type: ignore[attr-defined]
            self.assertIsInstance(parsed, dict)
            questions = parsed.get("questions")
            self.assertIsInstance(questions, list)
            self.assertEqual(questions[0]["id"], "scope_target")

    def test_read_last_request_user_input_from_session_returns_latest_pending(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session_path = Path(tmp) / "session.jsonl"
            first = {
                "questions": [
                    {
                        "header": "First",
                        "id": "first_scope",
                        "question": "First question?",
                        "options": [{"label": "A", "description": "A", "value": "a"}],
                    }
                ]
            }
            second = {
                "questions": [
                    {
                        "header": "Second",
                        "id": "second_scope",
                        "question": "Second question?",
                        "options": [{"label": "B", "description": "B", "value": "b"}],
                    }
                ]
            }
            session_path.write_text(
                "\n".join(
                    [
                        json.dumps({"type": "session_meta", "payload": {"id": "sid-123"}}),
                        json.dumps(
                            {
                                "type": "response_item",
                                "payload": {
                                    "type": "function_call",
                                    "name": "request_user_input",
                                    "arguments": json.dumps(first),
                                    "call_id": "call_first",
                                },
                            }
                        ),
                        json.dumps(
                            {
                                "type": "response_item",
                                "payload": {
                                    "type": "function_call_output",
                                    "call_id": "call_first",
                                    "output": json.dumps({"answers": {"first_scope": {"answers": ["a"]}}}),
                                },
                            }
                        ),
                        json.dumps(
                            {
                                "type": "response_item",
                                "payload": {
                                    "type": "function_call",
                                    "name": "request_user_input",
                                    "arguments": json.dumps(second),
                                    "call_id": "call_second",
                                },
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            parsed = notify._read_last_request_user_input_from_session(session_path)  # type: ignore[attr-defined]
            self.assertIsInstance(parsed, dict)
            questions = parsed.get("questions")
            self.assertIsInstance(questions, list)
            self.assertEqual(questions[0]["id"], "second_scope")

    def test_read_last_request_user_input_from_session_ignores_missing_call_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session_path = Path(tmp) / "session.jsonl"
            args = {
                "questions": [
                    {
                        "header": "Scope",
                        "id": "scope_target",
                        "question": "Where should this live?",
                        "options": [{"label": "Option A", "description": "First option", "value": "a"}],
                    }
                ]
            }
            session_path.write_text(
                "\n".join(
                    [
                        json.dumps({"type": "session_meta", "payload": {"id": "sid-123"}}),
                        json.dumps(
                            {
                                "type": "response_item",
                                "payload": {
                                    "type": "function_call",
                                    "name": "request_user_input",
                                    "arguments": json.dumps(args),
                                },
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            parsed = notify._read_last_request_user_input_from_session(session_path)  # type: ignore[attr-defined]
            self.assertIsNone(parsed)

    def test_format_attention_message_includes_questions(self) -> None:
        questions_text = notify._format_request_user_input_for_imessage(  # type: ignore[attr-defined]
            {
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
        )

        msg = notify._format_attention_message(  # type: ignore[call-arg]
            cwd="proj",
            need="Waiting on question",
            session_id="sid-123",
            request="last assistant text",
            questions=questions_text,
        )
        self.assertNotIn("Dir:", msg)
        self.assertIn("Questions:", msg)
        self.assertIn("Where should this live?", msg)
        self.assertIn("1. Option A", msg)
        self.assertIn("2. Option B", msg)

    def test_main_attention_state_only_skips_imessage_send(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp)
            with mock.patch.dict(
                "os.environ",
                {
                    "CODEX_HOME": str(codex_home),
                    "CODEX_IMESSAGE_TO": "+15551234567",
                    "CODEX_IMESSAGE_NOTIFY_MODE": "state_only",
                },
                clear=False,
            ):
                with mock.patch.object(notify, "_write_last_attention_state") as write_state:
                    with mock.patch.object(notify, "_send_imessage", return_value=True) as send_imessage:
                        rc = notify.main(["attention", "--cwd", "proj"])

            self.assertEqual(rc, 0)
            self.assertTrue(write_state.called)
            send_imessage.assert_not_called()

    def test_main_attention_send_mode_sends_imessage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp)
            with mock.patch.dict(
                "os.environ",
                {
                    "CODEX_HOME": str(codex_home),
                    "CODEX_IMESSAGE_TO": "+15551234567",
                    "CODEX_IMESSAGE_NOTIFY_MODE": "send",
                },
                clear=False,
            ):
                with mock.patch.object(notify, "_write_last_attention_state") as write_state:
                    with mock.patch.object(notify, "_send_imessage", return_value=True) as send_imessage:
                        rc = notify.main(["attention", "--cwd", "proj"])

            self.assertEqual(rc, 0)
            self.assertTrue(write_state.called)
            self.assertGreaterEqual(send_imessage.call_count, 1)

    def test_main_route_sends_final_status_on_completion_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp)
            payload = {"type": "agent-turn-complete", "thread-id": "sid-123", "cwd": "/Users/testuser"}
            assistant_response = (
                "Latest Codex CLI release is 0.98.0 (tag: rust-v0.98.0), "
                "published on February 5, 2026."
            )
            with mock.patch.dict(
                "os.environ",
                {
                    "CODEX_HOME": str(codex_home),
                    "CODEX_IMESSAGE_TO": "+15551234567",
                    "CODEX_IMESSAGE_NOTIFY_MODE": "route",
                },
                clear=False,
            ):
                with mock.patch.object(notify, "_read_last_assistant_text", return_value=assistant_response):
                    with mock.patch.object(notify, "_send_imessage", return_value=True) as send_imessage:
                        rc = notify.main(["route", "--cwd", "proj", json.dumps(payload)])

            self.assertEqual(rc, 0)
            self.assertEqual(send_imessage.call_count, 1)
            message = send_imessage.call_args.kwargs["message"]
            self.assertIn(assistant_response, message)
            self.assertNotIn("Dir:", message)
            self.assertNotIn("Turn completed.", message)

    def test_main_route_completion_falls_back_when_assistant_response_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp)
            payload = {"type": "agent-turn-complete", "thread-id": "sid-123", "cwd": "/Users/testuser"}
            with mock.patch.dict(
                "os.environ",
                {
                    "CODEX_HOME": str(codex_home),
                    "CODEX_IMESSAGE_TO": "+15551234567",
                    "CODEX_IMESSAGE_NOTIFY_MODE": "route",
                },
                clear=False,
            ):
                with mock.patch.object(notify, "_read_last_assistant_text", return_value=None):
                    with mock.patch.object(notify, "_send_imessage", return_value=True) as send_imessage:
                        rc = notify.main(["route", "--cwd", "proj", json.dumps(payload)])

            self.assertEqual(rc, 0)
            self.assertEqual(send_imessage.call_count, 1)
            message = send_imessage.call_args.kwargs["message"]
            self.assertIn("Turn completed.", message)
            self.assertNotIn("Dir:", message)

    def test_main_route_completion_does_not_use_user_history_when_assistant_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp)
            history_path = codex_home / "history.jsonl"
            user_prompt = "please do not echo this user prompt in completion notifications"
            history_path.write_text(json.dumps({"text": user_prompt}) + "\n", encoding="utf-8")
            payload = {"type": "agent-turn-complete", "thread-id": "sid-123", "cwd": "/Users/testuser"}
            with mock.patch.dict(
                "os.environ",
                {
                    "CODEX_HOME": str(codex_home),
                    "CODEX_HISTORY_PATH": str(history_path),
                    "CODEX_IMESSAGE_TO": "+15551234567",
                    "CODEX_IMESSAGE_NOTIFY_MODE": "route",
                },
                clear=False,
            ):
                with mock.patch.object(notify, "_read_last_assistant_text", return_value=None):
                    with mock.patch.object(notify, "_send_imessage", return_value=True) as send_imessage:
                        rc = notify.main(["route", "--cwd", "proj", json.dumps(payload)])

            self.assertEqual(rc, 0)
            self.assertEqual(send_imessage.call_count, 1)
            message = send_imessage.call_args.kwargs["message"]
            self.assertIn("Turn completed.", message)
            self.assertNotIn(user_prompt, message)

    def test_main_route_fallback_input_when_question_text_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp)
            payload = {"type": "needs-input", "thread-id": "sid-123", "cwd": "/Users/testuser"}
            with mock.patch.dict(
                "os.environ",
                {
                    "CODEX_HOME": str(codex_home),
                    "CODEX_IMESSAGE_TO": "+15551234567",
                    "CODEX_IMESSAGE_NOTIFY_MODE": "route",
                    "CODEX_IMESSAGE_NOTIFY_FALLBACK_INPUT": "1",
                },
                clear=False,
            ):
                with mock.patch.object(notify, "_send_imessage", return_value=True) as send_imessage:
                    with mock.patch.object(notify, "_read_last_request_user_input_from_session", return_value=None):
                        rc = notify.main(["route", "--cwd", "proj", json.dumps(payload)])

            self.assertEqual(rc, 0)
            self.assertEqual(send_imessage.call_count, 1)

    def test_main_route_dedupes_repeated_completion_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp)
            payload = {"type": "agent-turn-complete", "thread-id": "sid-123", "cwd": "/Users/testuser"}
            with mock.patch.dict(
                "os.environ",
                {
                    "CODEX_HOME": str(codex_home),
                    "CODEX_IMESSAGE_TO": "+15551234567",
                    "CODEX_IMESSAGE_NOTIFY_MODE": "route",
                },
                clear=False,
            ):
                with mock.patch.object(notify, "_send_imessage", return_value=True) as send_imessage:
                    first = notify.main(["route", "--cwd", "proj", json.dumps(payload)])
                    second = notify.main(["route", "--cwd", "proj", json.dumps(payload)])

            self.assertEqual(first, 0)
            self.assertEqual(second, 0)
            self.assertEqual(send_imessage.call_count, 1)

    def test_main_route_ignores_missing_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp)
            with mock.patch.dict(
                "os.environ",
                {
                    "CODEX_HOME": str(codex_home),
                    "CODEX_IMESSAGE_TO": "+15551234567",
                    "CODEX_IMESSAGE_NOTIFY_MODE": "route",
                },
                clear=False,
            ):
                with mock.patch.object(notify, "_send_imessage", return_value=True) as send_imessage:
                    rc = notify.main(["route", "--cwd", "proj"])

            self.assertEqual(rc, 0)
            self.assertEqual(send_imessage.call_count, 0)

    def test_main_route_turn_completed_method_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp)
            payload = {"method": "turn/completed", "params": {"threadId": "sid-123"}}
            with mock.patch.dict(
                "os.environ",
                {
                    "CODEX_HOME": str(codex_home),
                    "CODEX_IMESSAGE_TO": "+15551234567",
                    "CODEX_IMESSAGE_NOTIFY_MODE": "route",
                },
                clear=False,
            ):
                with mock.patch.object(notify, "_send_imessage", return_value=True) as send_imessage:
                    rc = notify.main(["route", "--cwd", "proj", json.dumps(payload)])

            self.assertEqual(rc, 0)
            self.assertEqual(send_imessage.call_count, 1)

    def test_main_route_stop_hook_event_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp)
            payload = {"hook_event_name": "Stop", "session_id": "sid-123"}
            with mock.patch.dict(
                "os.environ",
                {
                    "CODEX_HOME": str(codex_home),
                    "CODEX_IMESSAGE_TO": "+15551234567",
                    "CODEX_IMESSAGE_NOTIFY_MODE": "route",
                },
                clear=False,
            ):
                with mock.patch.object(notify, "_send_imessage", return_value=True) as send_imessage:
                    rc = notify.main(["route", "--cwd", "proj", json.dumps(payload)])

            self.assertEqual(rc, 0)
            self.assertEqual(send_imessage.call_count, 1)

    def test_main_route_exec_approval_request_uses_input_flow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp)
            payload = {"type": "exec_approval_request", "thread-id": "sid-123", "cwd": "/Users/testuser"}
            with mock.patch.dict(
                "os.environ",
                {
                    "CODEX_HOME": str(codex_home),
                    "CODEX_IMESSAGE_TO": "+15551234567",
                    "CODEX_IMESSAGE_NOTIFY_MODE": "route",
                    "CODEX_IMESSAGE_NOTIFY_FALLBACK_INPUT": "1",
                },
                clear=False,
            ):
                with mock.patch.object(notify, "_send_imessage", return_value=True) as send_imessage:
                    with mock.patch.object(notify, "_read_last_request_user_input_from_session", return_value=None):
                        rc = notify.main(["route", "--cwd", "proj", json.dumps(payload)])

            self.assertEqual(rc, 0)
            self.assertEqual(send_imessage.call_count, 1)

    def test_route_and_outbound_share_needs_input_call_id_dedupe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp)
            session_path = codex_home / "session.jsonl"
            queue_path = codex_home / "queue.jsonl"
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
                        json.dumps({"type": "session_meta", "payload": {"id": "sid-123"}}),
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
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            payload = {
                "type": "request_user_input",
                "thread-id": "sid-123",
                "call_id": "call_plan_1",
                "cwd": str(codex_home),
            }
            with mock.patch.dict(
                "os.environ",
                {
                    "CODEX_HOME": str(codex_home),
                    "CODEX_SESSION_PATH": str(session_path),
                    "CODEX_IMESSAGE_TO": "+15551234567",
                    "CODEX_IMESSAGE_NOTIFY_MODE": "route",
                    "CODEX_IMESSAGE_NOTIFY_FALLBACK_INPUT": "1",
                },
                clear=False,
            ):
                with mock.patch.object(notify, "_send_imessage", return_value=True) as send_imessage:
                    first_rc = notify.main(["route", "--cwd", "proj", json.dumps(payload)])

                outbound_kinds: list[str] = []

                def _capture_send_structured(**kwargs: object) -> None:
                    outbound_kinds.append(str(kwargs.get("kind")))

                with mock.patch.object(bridge, "_send_structured", side_effect=_capture_send_structured):
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

            self.assertEqual(first_rc, 0)
            self.assertEqual(send_imessage.call_count, 1)
            self.assertEqual(outbound_kinds, [])

    def test_upsert_attention_index_writes_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp)
            index_path = codex_home / "attention_index.json"

            record = {
                "ts": 123,
                "to": "+15551234567",
                "cwd": "/Users/testuser/session-a",
                "session_path": "/tmp/session-a.jsonl",
                "tmux_pane": "%1",
            }

            with mock.patch.dict(
                "os.environ",
                {"CODEX_IMESSAGE_ATTENTION_INDEX": str(index_path)},
                clear=False,
            ):
                notify._upsert_attention_index(  # type: ignore[attr-defined]
                    codex_home=codex_home,
                    session_id="11111111-1111-1111-1111-111111111111",
                    record=record,
                )

            data = json.loads(index_path.read_text(encoding="utf-8"))
            self.assertIn("11111111-1111-1111-1111-111111111111", data)
            self.assertEqual(data["11111111-1111-1111-1111-111111111111"]["tmux_pane"], "%1")

    def test_upsert_attention_index_ignores_missing_session_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp)
            index_path = codex_home / "attention_index.json"

            with mock.patch.dict(
                "os.environ",
                {"CODEX_IMESSAGE_ATTENTION_INDEX": str(index_path)},
                clear=False,
            ):
                notify._upsert_attention_index(  # type: ignore[attr-defined]
                    codex_home=codex_home,
                    session_id=None,
                    record={"ts": 123},
                )

            self.assertFalse(index_path.exists())

    def test_prune_attention_index_limits_size(self) -> None:
        now = 10_000
        index: dict[str, object] = {}
        # 101 entries with increasing timestamps; pruning should keep newest 100.
        for i in range(101):
            sid = f"sid-{i}"
            index[sid] = {"ts": now - 100 + i}

        pruned = notify._prune_attention_index(index, now_ts=now)  # type: ignore[attr-defined]
        self.assertEqual(len(pruned), 100)
        self.assertNotIn("sid-0", pruned)

    def test_send_imessage_uses_repo_local_script(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            module_file = Path(td) / "agent_chat_notify.py"
            script_path = Path(td) / "scripts" / "send-imessage.applescript"
            script_path.parent.mkdir(parents=True, exist_ok=True)
            script_path.write_text("on run argv\nend run\n", encoding="utf-8")

            proc = mock.Mock()
            proc.returncode = 0

            with (
                mock.patch.object(notify, "__file__", str(module_file)),
                mock.patch.object(notify.subprocess, "run", return_value=proc) as run_mock,
            ):
                sent = notify._send_imessage(recipient="+15551234567", message="hello")  # type: ignore[attr-defined]

            self.assertTrue(sent)
            cmd = run_mock.call_args.args[0]
            self.assertEqual(cmd[0], "osascript")
            self.assertEqual(Path(cmd[1]).resolve(), script_path.resolve())
