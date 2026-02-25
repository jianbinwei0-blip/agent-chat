from __future__ import annotations

from pathlib import Path
import unittest


class TestCleanupDocs(unittest.TestCase):
    def test_cleanup_uninstall_avoids_repo_script_path(self) -> None:
        root = Path(__file__).resolve().parents[1]
        cleanup_doc = root / "docs" / "cleanup.md"
        text = cleanup_doc.read_text(encoding="utf-8")

        self.assertIn("Uninstall is host-scoped", text)
        self.assertNotIn(
            "python3 /ABSOLUTE/PATH/TO/agent-chat/agent_chat_control_plane.py doctor",
            text,
        )
        self.assertIn("agent-chat-control-plane doctor", text)
        self.assertIn("tccutil reset SystemPolicyAllFiles", text)
        self.assertIn("org.python.python", text)
        self.assertNotIn("com.mitchellh.", text)


if __name__ == "__main__":
    unittest.main()
