#!/usr/bin/env bash
# Description: Developer utility: stop-local-ui.
set -euo pipefail

SESSION="qf-ui"

case "${1:-}" in
  -h|--help|help)
    cat <<'EOF'
Usage: util-stop-local-ui.sh

Stops tmux session "qf-ui" created by util-run-local-ui.sh.
EOF
    exit 0
    ;;
esac

if tmux has-session -t "${SESSION}" 2>/dev/null; then
  tmux kill-session -t "${SESSION}"
  echo "[qf] stopped tmux session: ${SESSION}"
else
  echo "[qf] no tmux session: ${SESSION}"
fi
