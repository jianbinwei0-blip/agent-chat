from __future__ import annotations

from pathlib import Path
import unittest


class TestDocsSystemOfRecord(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(__file__).resolve().parents[1]
        self.agents = (self.root / "AGENTS.md").read_text(encoding="utf-8")
        self.docs_index = (self.root / "docs" / "index.md").read_text(encoding="utf-8")

    def test_agents_is_map_not_manual(self) -> None:
        self.assertIn("map, not the manual", self.agents)
        self.assertIn("docs/index.md", self.agents)
        self.assertLessEqual(len(self.agents.splitlines()), 120)

    def test_docs_index_is_authoritative_toc(self) -> None:
        self.assertIn("system of record", self.docs_index)
        for required in (
            "docs/architecture.md",
            "docs/control-plane.md",
            "docs/troubleshooting.md",
            "docs/cleanup.md",
            "docs/security.md",
            "docs/exec-plans/",
        ):
            self.assertIn(required, self.docs_index)

    def test_exec_plan_structure_exists(self) -> None:
        self.assertTrue((self.root / "docs" / "exec-plans" / "README.md").exists())
        self.assertTrue((self.root / "docs" / "exec-plans" / "active").is_dir())
        self.assertTrue((self.root / "docs" / "exec-plans" / "completed").is_dir())
        self.assertTrue(
            (self.root / "docs" / "exec-plans" / "tech-debt-tracker.md").exists()
        )


if __name__ == "__main__":
    unittest.main()
