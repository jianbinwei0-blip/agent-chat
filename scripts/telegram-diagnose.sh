#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/telegram-diagnose.sh [--label <launchd-label>] [--offset <update_id>] [--tail <n>] [--pause-launchd]

Description:
  Diagnoses agent-chat Telegram routing for both Codex and Claude runtimes by checking:
  - launchd/env config (transport, chat IDs, trace, etc.)
  - inbound cursor state
  - recent control-plane log signals (getUpdates/inbound/dispatch)
  - direct getUpdates probe (optionally with launchd temporarily paused)

Options:
  --label <label>       launchd label (default: AGENT_CHAT_LAUNCHD_LABEL or com.agent-chat)
  --offset <id>         override getUpdates offset (default: cursor+1)
  --tail <n>            number of matching log lines to show (default: 60)
  --pause-launchd       temporarily stop launchd service for deterministic getUpdates probe, then restart it
  -h, --help            show this help
EOF
}

LABEL="${AGENT_CHAT_LAUNCHD_LABEL:-com.agent-chat}"
OFFSET_OVERRIDE=""
TAIL_N=60
PAUSE_LAUNCHD=0

while (($#)); do
  case "$1" in
    --label)
      LABEL="${2:-}"
      shift 2
      ;;
    --offset)
      OFFSET_OVERRIDE="${2:-}"
      shift 2
      ;;
    --tail)
      TAIL_N="${2:-}"
      shift 2
      ;;
    --pause-launchd)
      PAUSE_LAUNCHD=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

PLIST="$HOME/Library/LaunchAgents/${LABEL}.plist"
if [[ ! -f "$PLIST" ]]; then
  echo "launchd plist not found: $PLIST" >&2
  exit 1
fi

TRANSPORT=""
AGENT=""
CHAT_HOME=""
BOT_TOKEN=""
CHAT_ID=""
CHAT_IDS=""
OWNER_IDS=""
ACCEPT_ALL=""
TRACE=""
STDERR_PATH=""
CFG_TMP="$(mktemp)"
python3 - "$PLIST" >"$CFG_TMP" <<'PY'
import plistlib, sys
from pathlib import Path
p=Path(sys.argv[1])
cfg=plistlib.loads(p.read_bytes())
env=cfg.get("EnvironmentVariables",{}) if isinstance(cfg,dict) else {}
pairs={
  "TRANSPORT": str(env.get("AGENT_CHAT_TRANSPORT","imessage")),
  "AGENT": str(env.get("AGENT_CHAT_AGENT","codex")),
  "CHAT_HOME": str(env.get("AGENT_CHAT_HOME", str(Path.home()/".codex"))),
  "BOT_TOKEN": str(env.get("AGENT_TELEGRAM_BOT_TOKEN","")),
  "CHAT_ID": str(env.get("AGENT_TELEGRAM_CHAT_ID","")),
  "CHAT_IDS": str(env.get("AGENT_TELEGRAM_CHAT_IDS","")),
  "OWNER_IDS": str(env.get("AGENT_TELEGRAM_OWNER_USER_IDS","")),
  "ACCEPT_ALL": str(env.get("AGENT_TELEGRAM_ACCEPT_ALL_CHATS","0")),
  "TRACE": str(env.get("AGENT_CHAT_TRACE","0")),
  "STDERR_PATH": str(cfg.get("StandardErrorPath", str(Path.home()/ "Library/Logs/agent-chat.launchd.err.log"))),
}
for k,v in pairs.items():
  print(f"{k}={v}")
PY
while IFS='=' read -r k v; do
  case "$k" in
    TRANSPORT) TRANSPORT="$v" ;;
    AGENT) AGENT="$v" ;;
    CHAT_HOME) CHAT_HOME="$v" ;;
    BOT_TOKEN) BOT_TOKEN="$v" ;;
    CHAT_ID) CHAT_ID="$v" ;;
    CHAT_IDS) CHAT_IDS="$v" ;;
    OWNER_IDS) OWNER_IDS="$v" ;;
    ACCEPT_ALL) ACCEPT_ALL="$v" ;;
    TRACE) TRACE="$v" ;;
    STDERR_PATH) STDERR_PATH="$v" ;;
  esac
done <"$CFG_TMP"
rm -f "$CFG_TMP"

if [[ -z "$CHAT_HOME" ]]; then
  CHAT_HOME="$HOME/.codex"
fi
CURSOR_PATH="${AGENT_TELEGRAM_INBOUND_CURSOR:-${CHAT_HOME}/tmp/telegram_inbound_cursor.json}"
TOKEN="${BOT_TOKEN}"

mask_token() {
  local t="$1"
  if [[ -z "$t" ]]; then
    echo "(missing)"
    return
  fi
  local n=${#t}
  if ((n <= 12)); then
    echo "***"
    return
  fi
  echo "${t:0:6}...${t: -4}"
}

echo "== agent-chat telegram diagnose =="
echo "label: ${LABEL}"
echo "agent: ${AGENT}"
echo "transport: ${TRANSPORT}"
echo "chat_home: ${CHAT_HOME}"
echo "bot_token: $(mask_token "$TOKEN")"
echo "chat_id: ${CHAT_ID:-(missing)}"
echo "chat_ids: ${CHAT_IDS:-(empty)}"
echo "owner_user_ids: ${OWNER_IDS:-(empty)}"
echo "accept_all_chats: ${ACCEPT_ALL}"
echo "trace: ${TRACE}"
echo "stderr_log: ${STDERR_PATH}"
echo "cursor_path: ${CURSOR_PATH}"
echo

if ! launchctl print "gui/$(id -u)/${LABEL}" >/tmp/telegram-diagnose-launchd.$$ 2>/dev/null; then
  echo "launchd_state: not loaded"
else
  echo "launchd_state:"
  if command -v rg >/dev/null 2>&1; then
    rg -n "state =|pid =|runs =" /tmp/telegram-diagnose-launchd.$$ || true
  else
    grep -nE "state =|pid =|runs =" /tmp/telegram-diagnose-launchd.$$ || true
  fi
fi
rm -f /tmp/telegram-diagnose-launchd.$$
echo

LAST_UPDATE_ID=0
if [[ -f "$CURSOR_PATH" ]]; then
  python3 - "$CURSOR_PATH" <<'PY'
import json, sys
from pathlib import Path
p=Path(sys.argv[1])
raw=json.loads(p.read_text())
print("cursor_json:", json.dumps(raw, ensure_ascii=False))
print("cursor_last_update_id:", int(raw.get("last_update_id",0)) if isinstance(raw,dict) else 0)
PY
  LAST_UPDATE_ID="$(python3 - "$CURSOR_PATH" <<'PY'
import json, sys
from pathlib import Path
p=Path(sys.argv[1])
raw=json.loads(p.read_text())
print(int(raw.get("last_update_id",0)) if isinstance(raw,dict) else 0)
PY
)"
else
  echo "cursor_json: (missing)"
fi
echo

if [[ -f "$STDERR_PATH" ]]; then
  echo "recent_telegram_log_signals:"
  if command -v rg >/dev/null 2>&1; then
    rg -n "telegram getUpdates|inbound rowid=|dispatch mode=tmux" "$STDERR_PATH" | tail -n "$TAIL_N" || true
  else
    grep -nE "telegram getUpdates|inbound rowid=|dispatch mode=tmux" "$STDERR_PATH" | tail -n "$TAIL_N" || true
  fi
else
  echo "recent_telegram_log_signals: log file missing"
fi
echo

if [[ -z "$TOKEN" ]]; then
  echo "direct_getupdates: skipped (missing AGENT_TELEGRAM_BOT_TOKEN)"
  exit 0
fi

OFFSET="${OFFSET_OVERRIDE:-$((LAST_UPDATE_ID + 1))}"
echo "direct_getupdates_offset: ${OFFSET}"

restart_launchd() {
  local uid
  uid="$(id -u)"
  launchctl bootstrap "gui/${uid}" "$PLIST" >/dev/null 2>&1 || true
  launchctl kickstart -k "gui/${uid}/${LABEL}" >/dev/null 2>&1 || true
}

if [[ "$PAUSE_LAUNCHD" -eq 1 ]]; then
  echo "pause_launchd: true (stopping ${LABEL} for direct probe)"
  launchctl bootout "gui/$(id -u)/${LABEL}" >/dev/null 2>&1 || true
  trap restart_launchd EXIT
fi

python3 - "$TOKEN" "$OFFSET" <<'PY'
import json, sys, urllib.request, urllib.parse, urllib.error
token=sys.argv[1].strip()
offset=int(sys.argv[2])
params={
  "offset": str(offset),
  "timeout": "4",
  "allowed_updates": json.dumps(["message","edited_message","channel_post","edited_channel_post"]),
}
url=f"https://api.telegram.org/bot{token}/getUpdates?{urllib.parse.urlencode(params)}"
try:
  with urllib.request.urlopen(url, timeout=20) as r:
    data=json.loads(r.read().decode("utf-8","replace"))
except urllib.error.HTTPError as e:
  body=e.read().decode("utf-8","replace")
  print(f"direct_getupdates_http_error: {e.code}")
  print(f"direct_getupdates_http_body: {body[:400]}")
  if e.code == 409:
    print("hint: another getUpdates consumer is active for this bot token (or webhook conflict).")
  raise SystemExit(0)
except Exception as e:
  print(f"direct_getupdates_error: {type(e).__name__}: {e}")
  raise SystemExit(0)

ok = bool(data.get("ok")) if isinstance(data, dict) else False
res = data.get("result") if isinstance(data, dict) else None
count = len(res) if isinstance(res, list) else -1
print(f"direct_getupdates_ok: {ok}")
print(f"direct_getupdates_count: {count}")
if isinstance(res, list):
  for upd in res[:10]:
    if not isinstance(upd, dict):
      continue
    uid = upd.get("update_id")
    msg = upd.get("message") or upd.get("edited_message") or upd.get("channel_post") or upd.get("edited_channel_post") or {}
    chat = msg.get("chat") if isinstance(msg, dict) else {}
    sender = msg.get("from") if isinstance(msg, dict) else {}
    text = (msg.get("text") or msg.get("caption") or "") if isinstance(msg, dict) else ""
    thread_id = msg.get("message_thread_id") if isinstance(msg, dict) else None
    print(f"update_id={uid} chat_id={chat.get('id') if isinstance(chat, dict) else None} "
          f"thread_id={thread_id} sender={sender.get('id') if isinstance(sender, dict) else None} "
          f"text={text[:120]!r}")
PY

echo
echo "done"
