#!/usr/bin/env bash
# Description: Test suite runner: test-core.
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
    --dry-run) DRY_RUN=1;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h)
      echo "Usage: $(basename "$0") [options]"; echo "Core Integration Test Suite"; usage_common_flags 2>/dev/null || true; exit 0;;
    *) echo "Unknown flag: " >&2; exit 2;;
  esac
  shift
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/tests-core-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/core-tests.log"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "tests_core_integration"; JSON_FIRST_RUN=1

if [[ -n "${RUSTFLAGS_EXTRA:-}" ]]; then
  export RUSTFLAGS="${RUSTFLAGS_EXTRA} ${RUSTFLAGS:-}"
fi

echo "==============================================================="
echo "  Core Integration Test Suite"
echo "==============================================================="

# CLI and harness
run_cargo test --release --test rt-cli-help -- --nocapture
run_cargo test --release --test rt-harness-cli -- --nocapture

# Core wiring and config
run_cargo test --release --test rt-core-connection-basics -- --nocapture
run_cargo test --release --test rt-interface -- --nocapture
run_cargo test --release --test rt-compress-preprocessor -- --nocapture

# Telemetry + profiles
run_cargo test --release --test rt-telemetry-http -- --nocapture
run_cargo test --release --test rt-profile-aegis-selection -- --nocapture
run_cargo test --release --test rt-qftls-profiles -- --nocapture
run_cargo test --release --test rt-admin-http-contract -- --nocapture

# Reality fallback
run_cargo test --release --test rt-reality-targets -- --nocapture

echo -e "\n[OK] Core Integration Tests Complete"
json_end "$JSON"
