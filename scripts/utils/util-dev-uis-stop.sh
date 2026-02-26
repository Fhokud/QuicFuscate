#!/usr/bin/env bash
# Description: Developer utility: dev-uis-stop.
set -Eeuo pipefail

# Stop dev servers started by scripts/utils/util-dev-uis-start.sh.
#
# Scope boundary:
# - Stops only detached frontend dev servers tracked in scripts/out/run/dev-uis/.
# - Does not manage tmux full-stack sessions; use util-stop-local-ui.sh for that.

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || "${1:-}" == "help" ]]; then
  cat <<'EOF'
Usage: util-dev-uis-stop.sh

Stops background UI dev servers started by util-dev-uis-start.sh using PID files
from scripts/out/run/dev-uis/.
Does not stop full stack tmux sessions.
EOF
  exit 0
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

PID_DIR="$ROOT/scripts/out/run/dev-uis"

stop_one() {
  local name="$1"
  local pidfile="$PID_DIR/${name}.pid"

  if [[ ! -f "$pidfile" ]]; then
    echo "[dev-uis] not running: $name (missing pid file)"
    return 0
  fi

  local pid
  pid="$(cat "$pidfile" 2>/dev/null || true)"
  if [[ -z "$pid" ]]; then
    rm -f "$pidfile"
    echo "[dev-uis] not running: $name (empty pid file)"
    return 0
  fi

  if ! kill -0 "$pid" 2>/dev/null; then
    rm -f "$pidfile"
    echo "[dev-uis] not running: $name (stale pid=$pid)"
    return 0
  fi

  echo "[dev-uis] stopping $name pid=$pid"
  kill "$pid" 2>/dev/null || true

  # Wait a bit, then force kill if needed.
  for _ in 1 2 3 4 5; do
    if ! kill -0 "$pid" 2>/dev/null; then
      rm -f "$pidfile"
      echo "[dev-uis] stopped $name"
      return 0
    fi
    sleep 0.25
  done

  echo "[dev-uis] force stopping $name pid=$pid"
  kill -9 "$pid" 2>/dev/null || true
  rm -f "$pidfile"
  echo "[dev-uis] stopped $name"
}

stop_one "desktop-ui"
stop_one "web-admin-ui"
