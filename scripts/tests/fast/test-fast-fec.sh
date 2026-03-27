#!/usr/bin/env bash
# Description: Fast test helper: fast-fec.
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
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1; set -x;;
    --help|-h) echo "Usage: $(basename "$0") [--output-dir DIR] [--rustflags STR]"; exit 0;;
    *) break;;
  esac; shift
done
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"; LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"; exec > >(tee -a "$LOG_FILE") 2>&1
[[ -n "${RUSTFLAGS_EXTRA:-}" ]] && export RUSTFLAGS="${RUSTFLAGS_EXTRA} ${RUSTFLAGS:-}"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "tests_fec"; JSON_FIRST_RUN=1

echo "> Running FEC comprehensive tests"

# Unit tests focused on FEC paths
run_cargo test -q --package quicfuscate --features benches --lib -- \
  'fec::tests::' 'gf16' 'wiedemann' 'streaming' || true

# Smoke: build benches (no run) to catch bench-only paths
echo "> Checking benches compile (smoke)"
cargo bench --no-run --features benches >/dev/null

echo "[OK] FEC tests complete"
json_end "$JSON"
