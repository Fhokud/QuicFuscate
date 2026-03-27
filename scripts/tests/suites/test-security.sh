#!/usr/bin/env bash
# Description: Test suite runner: test-security.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --jobs) JOBS="$2"; shift;;
    --features) CARGO_FEATURES="$2"; shift;;
    --rustflags) RUSTFLAGS_EXTRA="$2"; shift;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h)
      echo "Usage: $(basename "$0") [options]"; echo "Security Test Suite"; usage_common_flags 2>/dev/null || true; exit 0;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac; shift
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/tests-security-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/security-tests.log"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "tests_security"; JSON_FIRST_RUN=1

exec > >(tee -a "$LOG_FILE") 2>&1

if [[ -n "${RUSTFLAGS_EXTRA:-}" ]]; then
  export RUSTFLAGS="${RUSTFLAGS_EXTRA} ${RUSTFLAGS:-}"
fi

echo "==============================================================="
echo "  Security Test Suite"
echo "==============================================================="

echo -e "\n> Running Security Suite..."
run_cargo test --release \
  --test rt-security-suite \
  -- --nocapture

echo -e "\n> Running Property Suite..."
run_cargo test --release \
  --test rt-property-suite \
  -- --nocapture

echo -e "\n[OK] Security Tests Complete"
json_end "$JSON"
