#!/usr/bin/env bash
# Description: Test suite runner: desktop unit + web-admin unit + rust integration.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""; RUSTFLAGS_EXTRA=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --rustflags) RUSTFLAGS_EXTRA="$2"; shift;;
    --dry-run) DRY_RUN=1;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1; set -x;;
    --help|-h)
      echo "Usage: $(basename "$0") [--output-dir DIR] [--rustflags STR] [--dry-run] [--verbose]"
      exit 0
      ;;
    *) break;;
  esac
  shift
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"
exec > >(tee -a "$LOG_FILE") 2>&1

[[ -n "${RUSTFLAGS_EXTRA:-}" ]] && export RUSTFLAGS="${RUSTFLAGS_EXTRA} ${RUSTFLAGS:-}"

echo "==============================================================="
echo "  Targeted Validation Suite"
echo "  - Desktop Unit"
echo "  - Web-Admin Unit"
echo "  - Rust Integration (6 targeted tests)"
echo "==============================================================="
echo "Output: $OUTPUT_DIR"

run bash -lc "cd \"$PROJECT_ROOT/apps/desktop\" && bun run test:unit"
run bash -lc "cd \"$PROJECT_ROOT/apps/web-admin-ui\" && bun run test:unit"
run cargo test \
  --test it-engine-control-plane \
  --test it-interface-capabilities \
  --test it-masque-runtime-integration \
  --test it-orchestrator-runtime-activation \
  --test it-qkey-auth-integration \
  --test it-stealth-mode-matrix

echo
echo "[OK] Targeted validation suite passed. Log: $LOG_FILE"
