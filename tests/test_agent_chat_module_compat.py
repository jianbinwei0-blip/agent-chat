import importlib
import unittest


class TestAgentChatModuleCompat(unittest.TestCase):
    def test_agent_chat_modules_exist_and_expose_main(self) -> None:
        module_names = (
            "agent_chat_control_plane",
            "agent_chat_notify",
            "agent_chat_outbound_lib",
            "agent_chat_reply_lib",
            "agent_chat_dedupe",
        )

        for module_name in module_names:
            with self.subTest(module=module_name):
                module = importlib.import_module(module_name)
                if module_name != "agent_chat_dedupe":
                    self.assertTrue(callable(getattr(module, "main", None)))
