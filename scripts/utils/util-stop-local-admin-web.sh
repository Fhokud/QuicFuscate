#!/usr/bin/env bash
# Description: Developer utility: stop-local-admin-web.
set -euo pipefail

SESSION="qf-admin-web"

case "${1:-}" in
  -h|--help|help)
    cat <<'EOF'
Usage: util-stop-local-admin-web.sh

Stops tmux session "qf-admin-web" created by util-run-local-admin-web.sh.
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
