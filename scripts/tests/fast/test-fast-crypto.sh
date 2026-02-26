#!/usr/bin/env bash
# Description: Fast test helper: fast-crypto.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""
if [[ $# -gt 0 && "${1:-}" != --* ]]; then
  OUTPUT_DIR="$1"
  shift
fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --rustflags) RUSTFLAGS_EXTRA="$2"; shift;;
    --dry-run) DRY_RUN=1;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h) echo "Usage: $(basename "$0") [--output-dir DIR] [--rustflags STR]"; exit 0;;
    *) echo "Unknown flag: " >&2; exit 2;;
  esac
  shift
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "tests_fast_crypto"; JSON_FIRST_RUN=1

print_system_banner || true
log "Running fast crypto sanity checks"

run_cargo test --test rt-tls-cover-cipher -- --nocapture
run_cargo test --lib test_wiedemann_scalar_telemetry_increments -- --nocapture

json_end "$JSON"
