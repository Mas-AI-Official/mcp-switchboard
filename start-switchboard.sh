#!/usr/bin/env bash
# ============================================================================
#  MCP Switchboard - one-command launcher (macOS / Linux)
#
#  One governed MCP endpoint in front of all your MCP servers. Run it, and the
#  gateway plus its web dashboard start; your browser opens when it's ready.
#
#  First run: installs dependencies, builds, and writes a starter config.
#  Stop it with Ctrl+C.
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")"

command -v node >/dev/null 2>&1 || {
  echo "[MCP Switchboard] Node 18.18+ is required - install it from https://nodejs.org" >&2
  exit 1
}

[ -d node_modules ] || { echo "[MCP Switchboard] Installing dependencies (first run)..."; npm install; }
[ -f dist/cli.js ]  || { echo "[MCP Switchboard] Building...";                              npm run build; }
[ -f switchboard.config.yaml ] || { echo "[MCP Switchboard] Creating a starter config..."; node dist/cli.js init; }

PORT="$(node -e "const fs=require('fs');try{const m=String(fs.readFileSync('switchboard.config.yaml','utf8')).match(/port:\s*(\d+)/);process.stdout.write(m?m[1]:'8088')}catch(e){process.stdout.write('8088')}" 2>/dev/null || echo 8088)"
URL="http://127.0.0.1:${PORT}"

# Open the browser once the port is live (best-effort, backgrounded).
(
  for _ in $(seq 1 240); do
    if (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null; then
      exec 3>&- 3<&-
      if command -v open >/dev/null 2>&1; then open "$URL"
      elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL"
      fi
      break
    fi
    sleep 0.5
  done
) &

echo
echo "  MCP Switchboard is starting on ${URL}"
echo "  The dashboard will open in your browser automatically."
echo "  Press Ctrl+C to stop."
echo
exec node dist/cli.js dashboard
