# Cleanup / Uninstall

Use this guide to remove Codex <-> iMessage integration from a macOS host.

Uninstall is host-scoped: it only modifies machine/user state under `$HOME`
(`~/Library`, `~/.codex`) and must not edit files inside an `agent-chat`
checkout.

## What This Removes

- launchd service (`com.codex.imessage-control-plane`)
- LaunchAgent plist (`~/Library/LaunchAgents/com.codex.imessage-control-plane.plist`)
- runtime app bundle (`~/Applications/Codex iMessage Python.app`)
- tmux-managed background control-plane session (`codex_imessage_control_plane`)
- Codex notify hook wiring to `codex_imessage_control_plane.py notify`
- integration runtime state under `~/.codex/tmp/imessage_*`
- integration tmux log (`~/.codex/log/imessage-control-plane-tmux.log`)
- Full Disk Access TCC grants commonly used by this integration (`org.python.python`)

## One-shot Cleanup

Run from any shell:

```bash
set -euo pipefail
LABEL='com.codex.imessage-control-plane'
UID_NUM="$(id -u)"
SERVICE="gui/${UID_NUM}/${LABEL}"
PLIST="$HOME/Library/LaunchAgents/${LABEL}.plist"
APP="$HOME/Applications/Codex iMessage Python.app"
OUT_LOG="$HOME/Library/Logs/codex-imessage-control-plane.launchd.out.log"
ERR_LOG="$HOME/Library/Logs/codex-imessage-control-plane.launchd.err.log"
CONFIG="$HOME/.codex/config.toml"
TMP_DIR="$HOME/.codex/tmp"
TMUX_LOG="$HOME/.codex/log/imessage-control-plane-tmux.log"

launchctl bootout "$SERVICE" >/dev/null 2>&1 || true
launchctl disable "$SERVICE" >/dev/null 2>&1 || true
tmux kill-session -t codex_imessage_control_plane >/dev/null 2>&1 || true
pkill -f 'codex_imessage_control_plane.py run' >/dev/null 2>&1 || true

rm -f "$PLIST"
rm -rf "$APP"
rm -f "$OUT_LOG" "$ERR_LOG"
rm -f "$TMUX_LOG"

for BUNDLE_ID in org.python.python; do
  tccutil reset SystemPolicyAllFiles "$BUNDLE_ID" >/dev/null 2>&1 || true
done

python3 - <<'PY'
from pathlib import Path
from datetime import datetime

config = Path.home() / ".codex" / "config.toml"
if not config.exists():
    raise SystemExit(0)
text = config.read_text(encoding="utf-8")
backup = config.with_suffix(config.suffix + ".bak-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
backup.write_text(text, encoding="utf-8")
lines = [line for line in text.splitlines() if "codex_imessage_control_plane.py notify" not in line]
new_text = "\n".join(lines)
if text.endswith("\n") and not new_text.endswith("\n"):
    new_text += "\n"
config.write_text(new_text, encoding="utf-8")
print(f"config backup: {backup}")
PY

if [ -d "$TMP_DIR" ]; then
  find "$TMP_DIR" -maxdepth 1 -type f \
    \( -name 'imessage_*' -o -name 'imessage_queue.jsonl' -o -name 'imessage_control_plane.lock' -o -name 'imessage_reply_cursor.json' \) \
    -delete
fi
find "$TMP_DIR" -maxdepth 1 -type f -name 'imessage_queue.jsonl.drain.*' -delete 2>/dev/null || true
```

Note:
- `tccutil reset` is bundle-id scoped and can affect unrelated workflows that use the same app/runtime.
- If you still use Python with Full Disk Access elsewhere, re-enable that entry after uninstall.

## Verify Cleanup

Run all checks below. A reset is complete only when every check passes.

```bash
# 1) launchd service absent
launchctl print gui/$(id -u)/com.codex.imessage-control-plane

# 2) no imessage control-plane tmux session/window
tmux list-windows -a -F '#{session_name}:#{window_name}' 2>/dev/null | rg -i 'imessage|codex_imessage|control_plane'

# 3) no active control-plane process
pgrep -af 'codex_imessage|imessage_control_plane|send-imessage|osascript'

# 4) no active notify hook wiring in live config
rg -n 'imessage|codex_imessage|send-imessage|notify\\s*=\\s*\\[' ~/.codex/config.toml

# 5) launch agent/app removed
[ -e ~/Library/LaunchAgents/com.codex.imessage-control-plane.plist ] && echo "present" || echo "absent"
[ -e ~/Applications/Codex\\ iMessage\\ Python.app ] && echo "present" || echo "absent"

# 6) no imessage runtime state/log leftovers
ls -la ~/.codex/tmp | rg -n '^.*imessage'
ls -la ~/.codex/log | rg -n 'imessage|codex-imessage' -i
```

Expected:
- checks 1-4 and 6 return non-zero / empty output
- checks 5 print `absent`

Optional post-cleanup doctor check (installed entrypoint only, no repo path):

```bash
if command -v codex-imessage-control-plane >/dev/null 2>&1; then
  PYTHONDONTWRITEBYTECODE=1 codex-imessage-control-plane doctor
fi
```

Expected doctor post-cleanup state:
- launchd not loaded
- recipient missing (unless separately exported)
- no active control-plane lock PID

This `DEGRADED` state is expected after uninstall.
