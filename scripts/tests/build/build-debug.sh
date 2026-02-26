#!/usr/bin/env bash
# Description: Build helper: build-debug.
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
    --help|-h) echo "Usage: $(basename "$0") [--output-dir DIR] [--rustflags STR]"; exit 0;;
    *) break;;
  esac; shift
done
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/build/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"; LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"; exec > >(tee -a "$LOG_FILE") 2>&1
[[ -n "${RUSTFLAGS_EXTRA:-}" ]] && export RUSTFLAGS="${RUSTFLAGS_EXTRA} ${RUSTFLAGS:-}"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "build_debug"; JSON_FIRST_RUN=1

echo "==============================================================="
echo "  QuicFuscate Debug Build"
echo "==============================================================="

# Build debug binary with debug assertions
echo -e "\n> Building debug binary..."
RUSTFLAGS="-C debuginfo=2" cargo build

# Build with optional features for Linux
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo -e "\n> Building with Linux-specific features (debug)..."
    RUSTFLAGS="-C debuginfo=2" cargo build --features "uring xdp"
fi

# Display binary info
echo -e "\n> Binary information:"
ls -lh target/debug/quicfuscate
file target/debug/quicfuscate

echo -e "\n[OK] Debug build complete: target/debug/quicfuscate"
json_end "$JSON"
