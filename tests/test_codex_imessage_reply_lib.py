import io
import os
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import codex_imessage_reply_lib as bridge


class TestCodexIMessageReplyBridge(unittest.TestCase):
    def test_tmux_send_prompt_falls_back_to_c_m_key(self) -> None:
        ok = subprocess.CompletedProcess(args=[], returncode=0)
        fail = subprocess.CompletedProcess(args=[], returncode=1)
        with (
            mock.patch.object(bridge, "_resolve_tmux_bin", return_value="tmux", create=True),
            mock.patch.object(bridge, "_tmux_socket_from_env", return_value=None, create=True),
            mock.patch("subprocess.run", side_effect=[ok, fail, ok]) as run_mock,
            mock.patch("time.sleep") as sleep_mock,
        ):
            sent = bridge._tmux_send_prompt(pane="%51", prompt="from imessage")  # type: ignore[attr-defined]

        self.assertTrue(sent)
        self.assertEqual(run_mock.call_count, 3)
        sleep_mock.assert_called_once()
        first_cmd = run_mock.call_args_list[0].args[0]
        second_cmd = run_mock.call_args_list[1].args[0]
        third_cmd = run_mock.call_args_list[2].args[0]
        self.assertEqual(first_cmd[:4], ["tmux", "send-keys", "-t", "%51"])
        self.assertEqual(second_cmd[-1], "C-m")
        self.assertEqual(third_cmd[-1], "Enter")

    def test_tmux_send_prompt_uses_explicit_tmux_socket(self) -> None:
        ok = subprocess.CompletedProcess(args=[], returncode=0)
        with (
            mock.patch.object(bridge, "_resolve_tmux_bin", return_value="/opt/homebrew/bin/tmux", create=True),
            mock.patch("subprocess.run", side_effect=[ok, ok]) as run_mock,
            mock.patch("time.sleep"),
        ):
            sent = bridge._tmux_send_prompt(  # type: ignore[attr-defined]
                pane="%51",
                prompt="from imessage",
                tmux_socket="/tmp/tmux-501/default",
            )

        self.assertTrue(sent)
        first_cmd = run_mock.call_args_list[0].args[0]
        second_cmd = run_mock.call_args_list[1].args[0]
        self.assertEqual(
            first_cmd[:6],
            ["/opt/homebrew/bin/tmux", "-S", "/tmp/tmux-501/default", "send-keys", "-t", "%51"],
        )
        self.assertEqual(second_cmd[-1], "C-m")

    def test_tmux_send_prompt_only_uses_c_m_and_enter_submit_keys(self) -> None:
        ok = subprocess.CompletedProcess(args=[], returncode=0)
        fail = subprocess.CompletedProcess(args=[], returncode=1)
        with (
            mock.patch.object(bridge, "_resolve_tmux_bin", return_value="tmux", create=True),
            mock.patch.object(bridge, "_tmux_socket_from_env", return_value=None, create=True),
            mock.patch("subprocess.run", side_effect=[ok, fail, fail]) as run_mock,
            mock.patch("time.sleep"),
        ):
            sent = bridge._tmux_send_prompt(pane="%51", prompt="from imessage")  # type: ignore[attr-defined]

        self.assertFalse(sent)
        self.assertEqual(run_mock.call_count, 3)
        submit_keys = [run_mock.call_args_list[1].args[0][-1], run_mock.call_args_list[2].args[0][-1]]
        self.assertEqual(submit_keys, ["C-m", "Enter"])

    def test_handle_prompt_dry_run_prints_command(self) -> None:
        stdout = io.StringIO()
        with mock.patch("sys.stdout", stdout):
            bridge._handle_prompt(  # type: ignore[attr-defined]
                recipient="+15551234567",
                session_id="11111111-1111-1111-1111-111111111111",
                cwd="/Users/testuser",
                prompt="hello",
                codex_home=Path("/tmp/codex-home"),
                dry_run=True,
            )
        self.assertIn("codex", stdout.getvalue())

    def test_handle_prompt_runs_codex_and_does_not_send_reply_by_default(self) -> None:
        codex_home = Path("/tmp/codex-home")
        with (
            mock.patch.object(bridge, "_run_codex_resume", return_value="assistant reply") as run_mock,  # type: ignore[attr-defined]
            mock.patch.object(bridge, "_send_imessage", return_value=True) as send_mock,  # type: ignore[attr-defined]
        ):
            bridge._handle_prompt(  # type: ignore[attr-defined]
                recipient="+15551234567",
                session_id="11111111-1111-1111-1111-111111111111",
                cwd="/Users/testuser",
                prompt="do the thing",
                codex_home=codex_home,
                dry_run=False,
            )

        run_mock.assert_called_once()
        send_mock.assert_not_called()

    def test_handle_prompt_sends_reply_when_send_reply_enabled(self) -> None:
        codex_home = Path("/tmp/codex-home")
        with (
            mock.patch.dict(os.environ, {"CODEX_IMESSAGE_SEND_REPLY": "1"}, clear=True),
            mock.patch.object(bridge, "_run_codex_resume", return_value="assistant reply") as run_mock,  # type: ignore[attr-defined]
            mock.patch.object(bridge, "_send_imessage", return_value=True) as send_mock,  # type: ignore[attr-defined]
        ):
            bridge._handle_prompt(  # type: ignore[attr-defined]
                recipient="+15551234567",
                session_id="11111111-1111-1111-1111-111111111111",
                cwd="/Users/testuser",
                prompt="do the thing",
                codex_home=codex_home,
                dry_run=False,
            )

        run_mock.assert_called_once()
        send_mock.assert_called_once()

    def test_handle_prompt_echo_prints_reply(self) -> None:
        stdout = io.StringIO()
        codex_home = Path("/tmp/codex-home")
        with (
            mock.patch("sys.stdout", stdout),
            mock.patch.object(bridge, "_run_codex_resume", return_value="assistant reply") as run_mock,  # type: ignore[attr-defined]
            mock.patch.object(bridge, "_send_imessage", return_value=True) as send_mock,  # type: ignore[attr-defined]
        ):
            bridge._handle_prompt(  # type: ignore[attr-defined]
                recipient="+15551234567",
                session_id="11111111-1111-1111-1111-111111111111",
                cwd="/Users/testuser",
                prompt="do the thing",
                codex_home=codex_home,
                dry_run=False,
                echo=True,
                rowid=123,
            )

        run_mock.assert_called_once()
        send_mock.assert_not_called()
        out = stdout.getvalue()
        self.assertIn("rowid=123", out)
        self.assertIn("assistant reply", out)

    def test_handle_prompt_tmux_does_not_fallback_when_tmux_send_fails(self) -> None:
        session_id = "11111111-1111-1111-1111-111111111111"
        with tempfile.TemporaryDirectory() as tmp:
            session_path = Path(tmp) / f"session-{session_id}.jsonl"
            session_path.write_text("", encoding="utf-8")
            codex_home = Path(tmp)
            with (
                mock.patch.object(bridge, "_tmux_send_prompt", return_value=False) as tmux_send_mock,  # type: ignore[attr-defined]
                mock.patch.object(bridge, "_run_codex_resume", return_value="assistant reply") as run_mock,  # type: ignore[attr-defined]
                mock.patch.object(bridge, "_send_imessage", return_value=True) as send_mock,  # type: ignore[attr-defined]
            ):
                bridge._handle_prompt(  # type: ignore[attr-defined]
                    recipient="+15551234567",
                    session_id=session_id,
                    cwd="/Users/testuser",
                    prompt="from imessage",
                    codex_home=codex_home,
                    dry_run=False,
                    use_tmux=True,
                    tmux_pane="%51",
                    session_path=str(session_path),
                )

        tmux_send_mock.assert_called_once()
        run_mock.assert_not_called()
        send_mock.assert_not_called()

    def test_handle_prompt_tmux_does_not_fallback_when_no_target_session_ack(self) -> None:
        session_id = "11111111-1111-1111-1111-111111111111"
        with tempfile.TemporaryDirectory() as tmp:
            session_path = Path(tmp) / f"session-{session_id}.jsonl"
            session_path.write_text("", encoding="utf-8")
            codex_home = Path(tmp)
            with (
                mock.patch.object(bridge, "_tmux_send_prompt", return_value=True) as tmux_send_mock,  # type: ignore[attr-defined]
                mock.patch.object(bridge, "_wait_for_new_user_text", return_value=None) as user_wait_mock,  # type: ignore[attr-defined]
                mock.patch.object(bridge.subprocess, "run", return_value=subprocess.CompletedProcess(args=[], returncode=0)),
                mock.patch.object(bridge, "_run_codex_resume", return_value="assistant reply") as run_mock,  # type: ignore[attr-defined]
                mock.patch.object(bridge, "_send_imessage", return_value=True) as send_mock,  # type: ignore[attr-defined]
            ):
                bridge._handle_prompt(  # type: ignore[attr-defined]
                    recipient="+15551234567",
                    session_id=session_id,
                    cwd="/Users/testuser",
                    prompt="from imessage",
                    codex_home=codex_home,
                    dry_run=False,
                    use_tmux=True,
                    tmux_pane="%51",
                    session_path=str(session_path),
                )

        tmux_send_mock.assert_called_once()
        self.assertGreaterEqual(user_wait_mock.call_count, 2)
        run_mock.assert_not_called()
        send_mock.assert_not_called()

    def test_handle_prompt_tmux_skips_when_session_path_mismatch(self) -> None:
        session_id = "11111111-1111-1111-1111-111111111111"
        with tempfile.TemporaryDirectory() as tmp:
            session_path = Path(tmp) / "session-other.jsonl"
            session_path.write_text("", encoding="utf-8")
            codex_home = Path(tmp)
            with (
                mock.patch.object(bridge, "_tmux_send_prompt", return_value=True) as tmux_send_mock,  # type: ignore[attr-defined]
                mock.patch.object(bridge, "_run_codex_resume", return_value="assistant reply") as run_mock,  # type: ignore[attr-defined]
                mock.patch.object(bridge, "_send_imessage", return_value=True) as send_mock,  # type: ignore[attr-defined]
            ):
                bridge._handle_prompt(  # type: ignore[attr-defined]
                    recipient="+15551234567",
                    session_id=session_id,
                    cwd="/Users/testuser",
                    prompt="from imessage",
                    codex_home=codex_home,
                    dry_run=False,
                    use_tmux=True,
                    tmux_pane="%51",
                    session_path=str(session_path),
                )

        tmux_send_mock.assert_not_called()
        run_mock.assert_called_once()
        send_mock.assert_not_called()

    def test_run_codex_resume_defaults_to_no_timeout(self) -> None:
        fixed_time = 1700000000
        fixed_pid = 12345
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp)
            out_dir = codex_home / "tmp"
            out_dir.mkdir(parents=True, exist_ok=True)

            out_path = out_dir / f"imessage_last_response_{fixed_time}_{fixed_pid}.txt"
            out_path.write_text("assistant reply", encoding="utf-8")

            observed_timeout: object = object()

            def fake_run(*args, **kwargs):  # type: ignore[no-untyped-def]
                nonlocal observed_timeout
                observed_timeout = kwargs.get("timeout")
                return subprocess.CompletedProcess(args[0], 0)

            with (
                mock.patch.dict(os.environ, {}, clear=True),
                mock.patch.object(bridge.time, "time", return_value=fixed_time),
                mock.patch.object(bridge.os, "getpid", return_value=fixed_pid),
                mock.patch.object(bridge.subprocess, "run", side_effect=fake_run),
            ):
                result = bridge._run_codex_resume(  # type: ignore[attr-defined]
                    session_id="11111111-1111-1111-1111-111111111111",
                    cwd=None,
                    prompt="hello",
                    codex_home=codex_home,
                    timeout_s=None,
                )
        self.assertIsNone(observed_timeout)
        self.assertEqual(result, "assistant reply")

    def test_wait_for_new_assistant_text_allows_none_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session_path = Path(tmp) / "session.jsonl"
            session_path.write_text("", encoding="utf-8")

            # Should not raise; "no timeout" means "don't wait" for this helper.
            result = bridge._wait_for_new_assistant_text(  # type: ignore[attr-defined]
                session_path=session_path,
                before=None,
                timeout_s=None,
            )

        self.assertIsNone(result)

    def test_open_chat_db_sets_readonly_pragmas(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "chat.db"
            db_path.write_text("", encoding="utf-8")

            fake_conn = mock.Mock()
            fake_conn.execute = mock.Mock()

            with mock.patch.object(bridge.sqlite3, "connect", return_value=fake_conn) as connect_mock:
                conn = bridge._open_chat_db(db_path)  # type: ignore[attr-defined]

            self.assertIs(conn, fake_conn)
            self.assertEqual(connect_mock.call_count, 1)

            executed = [call.args[0] for call in fake_conn.execute.call_args_list]
            self.assertIn("PRAGMA query_only = 1", executed)
            self.assertTrue(any("PRAGMA busy_timeout" in stmt for stmt in executed))

    def test_resolve_session_id_uses_reply_to_guid_when_present(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT)")
        conn.execute(
            """
            CREATE TABLE message (
              ROWID INTEGER PRIMARY KEY,
              guid TEXT,
              reply_to_guid TEXT,
              text TEXT,
              attributedBody BLOB,
              handle_id INTEGER
            )
            """
        )

        conn.execute("INSERT INTO handle (ROWID, id) VALUES (1, '+15551234567')")
        referenced_guid = "AAAA-BBBB"
        referenced_session = "11111111-1111-1111-1111-111111111111"
        conn.execute(
            "INSERT INTO message (ROWID, guid, reply_to_guid, text, handle_id) VALUES (1, ?, NULL, ?, 1)",
            [referenced_guid, f"Session: {referenced_session}"],
        )

        resolved = bridge._resolve_session_id(  # type: ignore[attr-defined]
            conn=conn,
            reply_text="yes",
            reply_to_guid=referenced_guid,
            fallback_session_id="22222222-2222-2222-2222-222222222222",
        )
        self.assertEqual(resolved, referenced_session)

    def test_fetch_new_replies_uses_associated_message_guid_when_reply_to_guid_missing(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT)")
        conn.execute(
            """
            CREATE TABLE message (
              ROWID INTEGER PRIMARY KEY,
              text TEXT,
              attributedBody BLOB,
              reply_to_guid TEXT,
              associated_message_guid TEXT,
              handle_id INTEGER
            )
            """
        )
        conn.execute("INSERT INTO handle (ROWID, id) VALUES (1, '+15551234567')")
        conn.execute(
            """
            INSERT INTO message (ROWID, text, attributedBody, reply_to_guid, associated_message_guid, handle_id)
            VALUES (1, 'hello', NULL, NULL, 'AAAA-BBBB', 1)
            """
        )

        replies = bridge._fetch_new_replies(  # type: ignore[attr-defined]
            conn=conn,
            after_rowid=0,
            handle_ids=["+15551234567"],
        )

        self.assertEqual(replies, [(1, "hello", "AAAA-BBBB")])

    def test_fetch_new_replies_ignores_outbound_is_from_me(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT)")
        conn.execute(
            """
            CREATE TABLE message (
              ROWID INTEGER PRIMARY KEY,
              text TEXT,
              attributedBody BLOB,
              reply_to_guid TEXT,
              associated_message_guid TEXT,
              handle_id INTEGER,
              is_from_me INTEGER
            )
            """
        )

        conn.execute("INSERT INTO handle (ROWID, id) VALUES (1, '+15551234567')")

        # Outbound message from this Mac (should be ignored).
        conn.execute(
            "INSERT INTO message (ROWID, text, handle_id, is_from_me) VALUES (1, ?, 1, 1)",
            ["Codex needs your attention\nSession: 11111111-1111-1111-1111-111111111111"],
        )
        # Inbound reply from the recipient (should be processed).
        conn.execute(
            "INSERT INTO message (ROWID, text, handle_id, is_from_me) VALUES (2, ?, 1, 0)",
            ["yes"],
        )

        replies = bridge._fetch_new_replies(  # type: ignore[attr-defined]
            conn=conn,
            after_rowid=0,
            handle_ids=["+15551234567"],
        )
        self.assertEqual(replies, [(2, "yes", None)])

    def test_single_instance_lock_blocks_second_instance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            codex_home = Path(tmp)
            lock1 = bridge._acquire_single_instance_lock(codex_home=codex_home)  # type: ignore[attr-defined]
            if lock1 is None or not hasattr(lock1, "close"):
                # Locking not supported in this environment; nothing to assert.
                return
            try:
                lock2 = bridge._acquire_single_instance_lock(codex_home=codex_home)  # type: ignore[attr-defined]
                self.assertIsNone(lock2)
            finally:
                lock1.close()  # type: ignore[union-attr]

    def test_select_attention_context_prefers_session_index(self) -> None:
        session_id = "11111111-1111-1111-1111-111111111111"
        attention_index = {
            session_id: {
                "ts": 123,
                "to": "+15551234567",
                "cwd": "/Users/testuser/session-a",
                "session_path": "/tmp/session-a.jsonl",
                "tmux_pane": "%1",
            }
        }
        last_attention_state = {
            "ts": 999,
            "to": "+15551234567",
            "cwd": "/Users/testuser/session-b",
            "session_path": "/tmp/session-b.jsonl",
            "tmux_pane": "%2",
        }

        ctx = bridge._select_attention_context(  # type: ignore[attr-defined]
            session_id=session_id,
            attention_index=attention_index,
            last_attention_state=last_attention_state,
        )

        self.assertEqual(ctx.get("tmux_pane"), "%1")
        self.assertEqual(ctx.get("cwd"), "/Users/testuser/session-a")
        self.assertEqual(ctx.get("session_path"), "/tmp/session-a.jsonl")

    def test_select_attention_context_falls_back_to_last_attention_state(self) -> None:
        session_id = "11111111-1111-1111-1111-111111111111"
        attention_index = {
            "22222222-2222-2222-2222-222222222222": {"tmux_pane": "%1"},
        }
        last_attention_state = {
            "session_id": session_id,
            "cwd": "/Users/testuser/session-b",
            "session_path": "/tmp/session-b.jsonl",
            "tmux_pane": "%2",
        }

        ctx = bridge._select_attention_context(  # type: ignore[attr-defined]
            session_id=session_id,
            attention_index=attention_index,
            last_attention_state=last_attention_state,
        )

        self.assertEqual(ctx.get("tmux_pane"), "%2")
        self.assertEqual(ctx.get("cwd"), "/Users/testuser/session-b")
        self.assertEqual(ctx.get("session_path"), "/tmp/session-b.jsonl")

    def test_select_attention_context_ignores_last_attention_state_from_different_session(self) -> None:
        session_id = "11111111-1111-1111-1111-111111111111"
        attention_index = {
            "22222222-2222-2222-2222-222222222222": {"tmux_pane": "%1"},
        }
        last_attention_state = {
            "session_id": "33333333-3333-3333-3333-333333333333",
            "cwd": "/Users/testuser/session-b",
            "session_path": "/tmp/session-b.jsonl",
            "tmux_pane": "%2",
        }

        ctx = bridge._select_attention_context(  # type: ignore[attr-defined]
            session_id=session_id,
            attention_index=attention_index,
            last_attention_state=last_attention_state,
        )

        self.assertEqual(ctx, {})

    def test_select_attention_context_legacy_last_attention_without_session_id_still_falls_back(self) -> None:
        session_id = "11111111-1111-1111-1111-111111111111"
        attention_index = {
            "22222222-2222-2222-2222-222222222222": {"tmux_pane": "%1"},
        }
        last_attention_state = {
            "cwd": "/Users/testuser/session-b",
            "session_path": "/tmp/session-b.jsonl",
            "tmux_pane": "%2",
        }

        ctx = bridge._select_attention_context(  # type: ignore[attr-defined]
            session_id=session_id,
            attention_index=attention_index,
            last_attention_state=last_attention_state,
        )

        self.assertEqual(ctx.get("tmux_pane"), "%2")
        self.assertEqual(ctx.get("cwd"), "/Users/testuser/session-b")
        self.assertEqual(ctx.get("session_path"), "/tmp/session-b.jsonl")

    def test_select_attention_context_merges_missing_fields(self) -> None:
        session_id = "11111111-1111-1111-1111-111111111111"
        attention_index = {
            session_id: {
                "tmux_pane": "%1",
            }
        }
        last_attention_state = {
            "session_id": session_id,
            "cwd": "/Users/testuser/session-b",
            "session_path": "/tmp/session-b.jsonl",
            "tmux_pane": "%2",
        }

        ctx = bridge._select_attention_context(  # type: ignore[attr-defined]
            session_id=session_id,
            attention_index=attention_index,
            last_attention_state=last_attention_state,
        )

        self.assertEqual(ctx.get("tmux_pane"), "%1")
        self.assertEqual(ctx.get("cwd"), "/Users/testuser/session-b")
        self.assertEqual(ctx.get("session_path"), "/tmp/session-b.jsonl")

    def test_select_attention_context_includes_tmux_socket(self) -> None:
        session_id = "11111111-1111-1111-1111-111111111111"
        attention_index = {
            session_id: {
                "tmux_pane": "%1",
                "tmux_socket": "/tmp/tmux-501/default",
            }
        }

        ctx = bridge._select_attention_context(  # type: ignore[attr-defined]
            session_id=session_id,
            attention_index=attention_index,
            last_attention_state=None,
        )

        self.assertEqual(ctx.get("tmux_socket"), "/tmp/tmux-501/default")

    def test_select_attention_context_falls_back_to_session_registry(self) -> None:
        session_id = "11111111-1111-1111-1111-111111111111"
        session_registry = {
            "sessions": {
                session_id: {
                    "cwd": "/Users/testuser/session-registry",
                    "session_path": "/tmp/session-registry.jsonl",
                    "tmux_pane": "%9",
                    "tmux_socket": "/tmp/tmux-501/default",
                }
            }
        }

        ctx = bridge._select_attention_context(  # type: ignore[attr-defined]
            session_id=session_id,
            attention_index=None,
            last_attention_state=None,
            session_registry=session_registry,
        )

        self.assertEqual(ctx.get("tmux_pane"), "%9")
        self.assertEqual(ctx.get("cwd"), "/Users/testuser/session-registry")
        self.assertEqual(ctx.get("session_path"), "/tmp/session-registry.jsonl")
        self.assertEqual(ctx.get("tmux_socket"), "/tmp/tmux-501/default")

    def test_send_imessage_uses_repo_local_script(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            module_file = Path(td) / "codex_imessage_reply_lib.py"
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
