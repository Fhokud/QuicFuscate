#!/usr/bin/env bash
# Description: Developer utility: run-local-ui.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: util-run-local-ui.sh [--admin-port N] [--desktop-port N]

Starts a tmux session with:
- admin window: Rust server + built web admin assets
- desktop window: desktop UI vite preview

This script is for full local stack orchestration.
For frontend-only detached dev servers, use util-dev-uis-start.sh / util-dev-uis-stop.sh.

Options:
  --admin-port N    Admin UI bind port (default: 9000)
  --desktop-port N  Desktop UI preview port (default: 4173)
  -h, --help        Show help
EOF
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SESSION="qf-ui"
PID_DIR="$ROOT/scripts/out/run/dev-uis"

ADMIN_PORT="${ADMIN_PORT:-9000}"
DESKTOP_PORT="${DESKTOP_PORT:-4173}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --admin-port) ADMIN_PORT="${2:-}"; shift 2 ;;
    --desktop-port) DESKTOP_PORT="${2:-}"; shift 2 ;;
    -h|--help|help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

[[ "$ADMIN_PORT" =~ ^[0-9]+$ ]] || { echo "Invalid --admin-port: $ADMIN_PORT" >&2; exit 2; }
[[ "$DESKTOP_PORT" =~ ^[0-9]+$ ]] || { echo "Invalid --desktop-port: $DESKTOP_PORT" >&2; exit 2; }

if ! command -v tmux >/dev/null 2>&1; then
  echo "tmux is required but not found in PATH" >&2
  exit 127
fi

if [[ -f "$PID_DIR/web-admin-ui.pid" || -f "$PID_DIR/desktop-ui.pid" ]]; then
  echo "Detected detached UI dev servers in $PID_DIR." >&2
  echo "Stop them first via scripts/utils/util-dev-uis-stop.sh, then run this full-stack script." >&2
  exit 2
fi

CERT_PATH="$(ls -1t "${ROOT}"/config/local/dev-certs/*.crt 2>/dev/null | head -n 1 || true)"
KEY_PATH="$(ls -1t "${ROOT}"/config/local/dev-certs/*.key 2>/dev/null | head -n 1 || true)"
if [[ -z "$CERT_PATH" || -z "$KEY_PATH" ]]; then
  CERT_PATH="$(ls -1t "${ROOT}"/config/dev-certs/*.crt 2>/dev/null | head -n 1 || true)"
  KEY_PATH="$(ls -1t "${ROOT}"/config/dev-certs/*.key 2>/dev/null | head -n 1 || true)"
fi
[[ -n "$CERT_PATH" ]] || { echo "Missing cert in config/local/dev-certs/ (or legacy config/dev-certs/)" >&2; exit 2; }
[[ -n "$KEY_PATH" ]] || { echo "Missing key in config/local/dev-certs/ (or legacy config/dev-certs/)" >&2; exit 2; }

echo "[qf] root: ${ROOT}"
echo "[qf] ports: admin=${ADMIN_PORT} desktop=${DESKTOP_PORT}"

if tmux has-session -t "${SESSION}" 2>/dev/null; then
  tmux kill-session -t "${SESSION}"
fi

tmux new-session -d -s "${SESSION}" -n "admin"

tmux send-keys -t "${SESSION}:admin" "cd \"${ROOT}\"" C-m
tmux send-keys -t "${SESSION}:admin" "cargo build -q" C-m
tmux send-keys -t "${SESSION}:admin" "bash scripts/build/build-web-admin.sh" C-m
tmux send-keys -t "${SESSION}:admin" "env RUST_LOG=info target/debug/quicfuscate server --listen 127.0.0.1:4433 --cert \"${CERT_PATH}\" --key \"${KEY_PATH}\" --config config/server-linux.default.toml --admin-web 127.0.0.1:${ADMIN_PORT} --admin-web-root assets/web-admin --admin-web-user admin --admin-web-password 123" C-m

tmux new-window -t "${SESSION}" -n "desktop"
tmux send-keys -t "${SESSION}:desktop" "cd \"${ROOT}/apps/desktop\"" C-m
tmux send-keys -t "${SESSION}:desktop" "bun install" C-m
tmux send-keys -t "${SESSION}:desktop" "bun run build" C-m
tmux send-keys -t "${SESSION}:desktop" "./node_modules/.bin/vite preview --port ${DESKTOP_PORT} --strictPort --host 127.0.0.1" C-m

echo "[qf] started tmux session: ${SESSION}"
echo "[qf] web admin UI: http://127.0.0.1:${ADMIN_PORT}/ (login: admin / 123)"
echo "[qf] desktop UI:   http://127.0.0.1:${DESKTOP_PORT}/"
echo "[qf] attach: tmux attach -t ${SESSION}"
