#!/usr/bin/env bash
# Description: Unified frontend dev launcher (TODO-174 Phase 2).
#
# Consolidates all UI launcher/stopper scripts behind a single entry point
# with subcommands. The original 6 scripts are kept as thin wrappers that
# delegate here for backwards compatibility.
#
# Subcommands:
#   start       - Start detached frontend dev servers (admin + desktop)
#   stop        - Stop detached frontend dev servers
#   web         - Start full-stack tmux session (Rust server + web admin UI)
#   desktop     - Start full-stack tmux session (Rust server + both UIs)
#   stop-web    - Stop the web-only tmux session
#   stop-all    - Stop the full-stack tmux session
#   status      - Show running dev server status
#
# Subcommand "start" and "stop" manage detached background processes (no tmux).
# Subcommand "web" and "desktop" manage tmux sessions with Rust server + UI.
#
# Extra flags per subcommand are passed through to the underlying script.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

PID_DIR="$ROOT/scripts/out/run/dev-uis"

usage() {
  cat <<'EOF'
Usage: dev.sh <subcommand> [flags...]

Unified frontend development launcher.

Subcommands:
  start       Start detached frontend dev servers (admin + desktop)
  stop        Stop detached frontend dev servers
  web         Start tmux session: Rust server + web admin UI only
  desktop     Start tmux session: Rust server + web admin + desktop UI
  stop-web    Stop the web-only tmux session (qf-admin-web)
  stop-all    Stop the full-stack tmux session (qf-ui)
  status      Show running dev server status

Extra flags are forwarded to the underlying launcher (e.g. --admin-port 8080).

Examples:
  dev.sh start                     # detached admin + desktop dev servers
  dev.sh stop                      # stop the above
  dev.sh web --admin-port 8080     # tmux session with admin on port 8080
  dev.sh desktop                   # tmux session with all UIs + Rust server
  dev.sh status                    # check what is running
EOF
}

show_status() {
  echo "[dev] Status:"
  echo ""

  # Detached dev servers
  for name in admin-ui desktop-ui; do
    local pidfile="$PID_DIR/${name}.pid"
    if [[ -f "$pidfile" ]]; then
      local pid
      pid="$(cat "$pidfile" 2>/dev/null || true)"
      if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        echo "  [running] $name (pid=$pid, detached)"
      else
        echo "  [stale]   $name (pid=$pid, process gone)"
      fi
    else
      echo "  [stopped] $name (detached)"
    fi
  done

  # Tmux sessions
  if command -v tmux >/dev/null 2>&1; then
    for session in qf-ui qf-admin-web; do
      if tmux has-session -t "$session" 2>/dev/null; then
        echo "  [running] tmux:$session"
      else
        echo "  [stopped] tmux:$session"
      fi
    done
  else
    echo "  [n/a]     tmux not installed"
  fi
}

if [[ $# -eq 0 ]]; then
  usage
  exit 2
fi

SUBCMD="$1"
shift

case "$SUBCMD" in
  start)
    exec bash "$SCRIPT_DIR/util-dev-uis-start.sh" "$@"
    ;;
  stop)
    exec bash "$SCRIPT_DIR/util-dev-uis-stop.sh" "$@"
    ;;
  web)
    exec bash "$SCRIPT_DIR/util-run-local-admin-web.sh" "$@"
    ;;
  desktop)
    exec bash "$SCRIPT_DIR/util-run-local-ui.sh" "$@"
    ;;
  stop-web)
    exec bash "$SCRIPT_DIR/util-stop-local-admin-web.sh" "$@"
    ;;
  stop-all)
    exec bash "$SCRIPT_DIR/util-stop-local-ui.sh" "$@"
    ;;
  status)
    show_status
    ;;
  -h|--help|help)
    usage
    exit 0
    ;;
  *)
    echo "Unknown subcommand: $SUBCMD" >&2
    echo "Run 'dev.sh --help' for usage." >&2
    exit 2
    ;;
esac
