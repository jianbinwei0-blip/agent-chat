#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="$REPO_ROOT/.env.telegram.local"

cd "$REPO_ROOT"

echo "agent-chat Telegram easy setup"
echo ""

PYTHON_BIN="${PYTHON_BIN:-$(command -v python3 || true)}"
if [ -z "$PYTHON_BIN" ]; then
  echo "python3 was not found in PATH. Install Python 3.11+ and retry."
  exit 1
fi

if ! "$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
  echo "Python 3.11+ is required. Current: $("$PYTHON_BIN" --version 2>&1)"
  exit 1
fi

echo "Python: $("$PYTHON_BIN" --version 2>&1)"

DEFAULT_AGENT="${AGENT_CHAT_AGENT:-codex}"
AGENT_INPUT=""
read -r -p "Choose runtime [codex/claude] (default: $DEFAULT_AGENT): " AGENT_INPUT || true
if [ -n "${AGENT_INPUT:-}" ]; then
  DEFAULT_AGENT="$AGENT_INPUT"
fi
DEFAULT_AGENT="$(printf '%s' "$DEFAULT_AGENT" | tr '[:upper:]' '[:lower:]')"
if [ "$DEFAULT_AGENT" != "codex" ] && [ "$DEFAULT_AGENT" != "claude" ]; then
  echo "Invalid runtime '$DEFAULT_AGENT'. Use codex or claude."
  exit 1
fi

TOKEN_INPUT="${AGENT_TELEGRAM_BOT_TOKEN:-}"
if [ -z "$TOKEN_INPUT" ]; then
  read -r -p "Paste your Telegram bot token (from @BotFather): " TOKEN_INPUT
fi
if [ -z "${TOKEN_INPUT:-}" ]; then
  echo "A Telegram bot token is required."
  exit 1
fi

if [ ! -f "$ENV_FILE" ]; then
  cp "$REPO_ROOT/env.telegram.example" "$ENV_FILE"
fi

upsert_env_var() {
  local key="$1"
  local value="$2"
  "$PYTHON_BIN" - "$ENV_FILE" "$key" "$value" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
key = sys.argv[2]
value = sys.argv[3]

lines = path.read_text(encoding="utf-8").splitlines()
prefix = f"export {key}="
safe = value.replace("\\", "\\\\").replace('"', '\\"')
new_line = f'export {key}="{safe}"'

out = []
updated = False
for line in lines:
    if line.startswith(prefix):
        out.append(new_line)
        updated = True
    else:
        out.append(line)

if not updated:
    out.append(new_line)

path.write_text("\n".join(out) + "\n", encoding="utf-8")
PY
}

upsert_env_var "AGENT_CHAT_TRANSPORT" "telegram"
upsert_env_var "AGENT_CHAT_AGENT" "$DEFAULT_AGENT"
upsert_env_var "AGENT_TELEGRAM_BOT_TOKEN" "$TOKEN_INPUT"

if ! grep -q '^unset AGENT_IMESSAGE_TO$' "$ENV_FILE"; then
  printf '\nunset AGENT_IMESSAGE_TO\n' >> "$ENV_FILE"
fi

set +u
# shellcheck disable=SC1090
source "$ENV_FILE"
set -u

echo ""
echo "Saved setup config: $ENV_FILE"
echo ""
echo "Before continuing in Telegram:"
echo "1) Create your target group in Telegram (New Group)"
echo "2) If you want topic routing, enable Topics (Group Info -> Edit -> Topics)"
echo "3) In @BotFather, run /setprivacy and set your bot to Disable"
echo "4) Add the bot to that group"
echo "5) Promote the bot to admin (Group Info -> Administrators -> Add Admin)"
echo ""
echo "Running setup commands..."

"$PYTHON_BIN" agent_chat_control_plane.py setup-notify-hook --agent "$AGENT_CHAT_AGENT" --python-bin "$PYTHON_BIN"

echo ""
echo "If setup-launchd pauses waiting for Telegram bootstrap, send one plain message in your target group/topic now."
"$PYTHON_BIN" agent_chat_control_plane.py setup-launchd --agent "$AGENT_CHAT_AGENT" --python-bin "$PYTHON_BIN"
"$PYTHON_BIN" agent_chat_control_plane.py doctor --agent "$AGENT_CHAT_AGENT"

echo ""
echo "Setup complete. First-use check:"
echo "1) In the target topic/group, send: list"
echo "2) Send once: @<session_ref> hello"
echo "3) Then send plain text in that topic (no @ mention needed every time)"
