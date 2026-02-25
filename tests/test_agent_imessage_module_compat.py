import importlib
import unittest


class TestAgentIMessageModuleCompat(unittest.TestCase):
    def test_agent_modules_exist_and_expose_main(self) -> None:
        module_names = (
            "agent_imessage_control_plane",
            "agent_imessage_notify",
            "agent_imessage_outbound_lib",
            "agent_imessage_reply_lib",
            "agent_imessage_dedupe",
        )

        for module_name in module_names:
            with self.subTest(module=module_name):
                module = importlib.import_module(module_name)
                if module_name != "agent_imessage_dedupe":
                    self.assertTrue(callable(getattr(module, "main", None)))

    def test_legacy_codex_shims_remain_importable(self) -> None:
        module_names = (
            "codex_imessage_control_plane",
            "codex_imessage_notify",
            "codex_imessage_outbound_lib",
            "codex_imessage_reply_lib",
            "codex_imessage_dedupe",
        )

        for module_name in module_names:
            with self.subTest(module=module_name):
                module = importlib.import_module(module_name)
                if module_name != "codex_imessage_dedupe":
                    self.assertTrue(callable(getattr(module, "main", None)))
