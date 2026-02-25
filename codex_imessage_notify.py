#!/usr/bin/env python3
"""Backward-compatible shim for agent_imessage_notify."""

from __future__ import annotations

import sys

from agent_imessage_notify import *  # noqa: F401,F403
from agent_imessage_notify import main


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
