from __future__ import annotations


def main(argv: list[str]) -> int:
    from agent_chat_control_plane import main as legacy_main

    return legacy_main(argv)
