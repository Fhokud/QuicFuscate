#!/usr/bin/env bash
# Description: Developer utility: dev-uis-start.
set -Eeuo pipefail

# Start the Web Admin UI and Desktop UI dev servers as background processes.
# This is meant for local development when you want the servers to stay running
# after the command returns (for example in Codex or other non-interactive runners).
#
# PIDs are written under scripts/out/run/dev-uis/ so they can be stopped via
# scripts/utils/util-dev-uis-stop.sh.
#
# Scope boundary:
# - This script manages frontend dev servers only.
# - It does not start/stop the Rust server stack.
# - For full stack orchestration (Rust server + UI), use util-run-local-ui.sh.

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || "${1:-}" == "help" ]]; then
  cat <<'EOF'
Usage: util-dev-uis-start.sh

Starts the Svelte admin UI and Svelte desktop UI dev servers as detached background
processes. PID and logs are written to scripts/out/run/dev-uis/.
Does not start the Rust server.
EOF
  exit 0
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

if command -v tmux >/dev/null 2>&1; then
  if tmux has-session -t "qf-ui" 2>/dev/null; then
    echo "[dev-uis] tmux session 'qf-ui' is active (full local stack)." >&2
    echo "[dev-uis] stop it first or use util-run-local-ui.sh exclusively." >&2
    exit 2
  fi
fi

if ! command -v bun >/dev/null 2>&1; then
  echo "[dev-uis] bun is required but not found in PATH" >&2
  exit 127
fi

PID_DIR="$ROOT/scripts/out/run/dev-uis"
mkdir -p "$PID_DIR"

start_one() {
  local name="$1"
  local workdir="$2"
  local cmd="$3"
  local pidfile="$PID_DIR/${name}.pid"
  local logfile="$PID_DIR/${name}.log"

  if [[ -f "$pidfile" ]]; then
    local old_pid
    old_pid="$(cat "$pidfile" 2>/dev/null || true)"
    if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
      echo "[dev-uis] already running: $name (pid=$old_pid)"
      return 0
    fi
    rm -f "$pidfile"
  fi

  echo "[dev-uis] starting $name"
  (
    cd "$workdir"
    # Use nohup so the process keeps running if the parent exits.
    # Redirect to a log file to avoid blocking on stdout pipes.
    nohup bash -lc "$cmd" >"$logfile" 2>&1 &
    echo $! >"$pidfile"
  )

  local pid
  pid="$(cat "$pidfile" 2>/dev/null || true)"
  if [[ -z "$pid" ]]; then
    echo "[dev-uis] failed to start $name (no pid written)" >&2
    return 1
  fi
  echo "[dev-uis] $name pid=$pid log=$logfile"
}

# Web Admin UI
start_one \
  "admin-ui" \
  "$ROOT/apps/svelte-admin" \
  "bun run dev"

# Desktop UI (browser dev mode, not Tauri)
start_one \
  "desktop-ui" \
  "$ROOT/apps/svelte-desktop" \
  "bun run dev"

echo "[dev-uis] urls:"
echo "[dev-uis]   admin-ui:   http://localhost:1430"
echo "[dev-uis]   desktop-ui:   http://localhost:4173"
