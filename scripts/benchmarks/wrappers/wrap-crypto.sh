#!/usr/bin/env bash
# Description: Benchmark wrapper entrypoint: wrap-crypto.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../../tests/lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../../tests/lib/lib-common.sh"

OUTPUT_DIR=""; RUSTFLAGS_EXTRA=""; FAST=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --rustflags) RUSTFLAGS_EXTRA="$2"; shift;;
    --fast) FAST=1;;
    --dry-run) DRY_RUN=1;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1; set -x;;
    --help|-h) echo "Usage: $(basename "$0") [--output-dir DIR] [--rustflags STR] [--fast]"; exit 0;;
    *) break;;
  esac; shift
done
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/benchmarks/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"; LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"; exec > >(tee -a "$LOG_FILE") 2>&1
[[ -n "${RUSTFLAGS_EXTRA:-}" ]] && export RUSTFLAGS="${RUSTFLAGS_EXTRA} ${RUSTFLAGS:-}"

echo "==============================================================="
echo "  Cryptography Performance Benchmarks"
echo "==============================================================="

# Delegate to comprehensive crypto benches for unified behavior
delegate=(
  --output-dir "$OUTPUT_DIR"
)
[[ -n "${RUSTFLAGS_EXTRA:-}" ]] && delegate+=(--rustflags "$RUSTFLAGS_EXTRA")
(( FAST )) && delegate+=(--fast)
[[ -n "${DRY_RUN:-}" ]] && delegate+=(--dry-run)
[[ -n "${QUICFUSCATE_DEBUG_SCRIPTS:-}" ]] && delegate+=(--verbose)

exec "$SCRIPT_DIR/../suites/bench-crypto.sh" "${delegate[@]}" "$@"
