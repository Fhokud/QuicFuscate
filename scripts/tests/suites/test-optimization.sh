#!/usr/bin/env bash
# Description: Test suite runner: test-optimization.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

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
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"; LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"; exec > >(tee -a "$LOG_FILE") 2>&1
[[ -n "${RUSTFLAGS_EXTRA:-}" ]] && export RUSTFLAGS="${RUSTFLAGS_EXTRA} ${RUSTFLAGS:-}"
RESULTS_JSON="$OUTPUT_DIR/results.json"; json_begin "$RESULTS_JSON" "tests_optimization"; JSON_FIRST_RUN=1

echo "==============================================================="
echo "  Optimization & Hardware Acceleration Test Suite"
echo "==============================================================="

TOTAL=0; PASSED=0; FAILED=0; SKIPPED=0
TEST_LIST_FILE="$OUTPUT_DIR/testlist.txt"

ensure_test_list() {
  if [[ ! -f "$TEST_LIST_FILE" ]]; then
    run_cargo test --release -- --list > "$TEST_LIST_FILE" 2>/dev/null || true
  fi
}

test_pattern_exists() {
  local pattern="$1"
  if (( FAST )); then
    # In fast mode we execute a curated test set directly to avoid
    # expensive global test-list discovery.
    return 0
  fi
  ensure_test_list
  grep -q "$pattern" "$TEST_LIST_FILE" 2>/dev/null
}

append_json() {
  local name="$1" status="$2" dur="$3"
  if [[ $JSON_FIRST_RUN -eq 0 ]]; then echo "," >> "$RESULTS_JSON"; fi
  JSON_FIRST_RUN=0
  echo -n '  {"name":'"\"$name\""',"status":'"\"$status\""',"duration_sec":'"$dur"'}' >> "$RESULTS_JSON"
}

run_case() {
  local name="$1"; shift
  local envs="$1"; shift
  local cmd=("$@")
  local start=$(date +%s)
  TOTAL=$((TOTAL+1))
  echo -e "\n> [$TOTAL] $name"
  [[ -n "$envs" ]] && echo "  Env: $envs"
  echo "  Cmd: ${cmd[*]}"
  if [[ -n "$envs" ]]; then
    if [[ "${cmd[0]}" == "cargo" ]]; then
      if ( eval "export $envs"; run_cargo "${cmd[@]:1}" ); then
        PASSED=$((PASSED+1)); append_json "$name" "ok" $(( $(date +%s) - start )); return 0
      fi
    else
      if run env $envs "${cmd[@]}"; then
        PASSED=$((PASSED+1)); append_json "$name" "ok" $(( $(date +%s) - start )); return 0
      fi
    fi
  else
    if [[ "${cmd[0]}" == "cargo" ]]; then
      if run_cargo "${cmd[@]:1}"; then
        PASSED=$((PASSED+1)); append_json "$name" "ok" $(( $(date +%s) - start )); return 0
      fi
    else
      if run "${cmd[@]}"; then
        PASSED=$((PASSED+1)); append_json "$name" "ok" $(( $(date +%s) - start )); return 0
      fi
    fi
  fi
  FAILED=$((FAILED+1))
  append_json "$name" "fail" $(( $(date +%s) - start ))
  return 0
}

run_named_test() {
  local label="$1"; shift
  local pattern="$1"; shift
  if test_pattern_exists "$pattern"; then
    run_case "$label" "" cargo test --release --lib "$pattern" -- --nocapture
  else
    warn "Skipping ${label} (no matching tests)"
    SKIPPED=$((SKIPPED+1))
    append_json "$label" "skipped" 0
  fi
}

# Test I/O batch sizing
echo -e "\n> Testing I/O Batch Sizing..."
run_named_test "I/O batch sizing" "normalized_batch_size"

if (( FAST )); then
  echo -e "\n> Fast mode enabled (reduced optimization matrix)"
  run_named_test "CPU profile telemetry mask" "cpu_profile_mask"
  run_named_test "FEC batch processing" "test_batch_"
  if test_pattern_exists "telemetry"; then
    run_case "Telemetry system" "QUICFUSCATE_TELEMETRY=1" cargo test --release --lib telemetry -- --nocapture
  else
    warn "Skipping telemetry tests (no matching tests)"
    SKIPPED=$((SKIPPED+1)); append_json "Telemetry system" "skipped" 0
  fi

  FEATURES="${CARGO_FEATURES:-rust-tests}"
  if [[ ",${FEATURES}," != *",rust-tests,"* ]]; then
    FEATURES="${FEATURES},rust-tests"
  fi
  if [[ ",${FEATURES}," != *",simd-selfcheck,"* ]]; then
    FEATURES="${FEATURES},simd-selfcheck"
  fi
  SIMD_FAST_TEST_ARGS=(
    --test rt-argsort-parity
    --test rt-bitmap-range-parity
    --test rt-brain-activation-parity
    --test rt-iter-reductions
    --test rt-simd-selfcheck
    --test rt-telemetry-counters
  )
  if [[ "$(uname -m)" == "x86_64" ]]; then
    SIMD_FAST_TEST_ARGS+=(--test rt-ack-merge-parity --test rt-xor-sse2-parity)
  fi
  run_case "SIMD/Accelerate integration" "" cargo test --release --features "$FEATURES" \
    "${SIMD_FAST_TEST_ARGS[@]}" \
    -- --nocapture

  echo -e "\n==============================================================="
  echo "  Optimization Test Summary"
  echo "==============================================================="
  echo "  Total:   $TOTAL"
  echo "  Passed:  $PASSED"
  echo "  Failed:  $FAILED"
  echo "  Skipped: $SKIPPED"
  json_end "$RESULTS_JSON"
  if [[ "$FAILED" -gt 0 ]]; then
    echo -e "\n[FAIL] Optimization Tests completed with failures"
    exit 1
  fi
  echo -e "\n[OK] Optimization Fast Tests Complete"
  exit 0
fi

# Test NUMA awareness
echo -e "\n> Testing NUMA Awareness..."
if test_pattern_exists "numa"; then
  run_case "NUMA local" "QUICFUSCATE_NUMA_POLICY=local" cargo test --release --lib numa -- --nocapture
  run_case "NUMA interleave" "QUICFUSCATE_NUMA_POLICY=interleave" cargo test --release --lib numa -- --nocapture
  run_case "NUMA preferred" "QUICFUSCATE_NUMA_POLICY=preferred:0" cargo test --release --lib numa -- --nocapture
else
  warn "Skipping NUMA tests (no matching tests)"
  SKIPPED=$((SKIPPED+1)); append_json "NUMA awareness" "skipped" 0
fi

# Test HugePages
echo -e "\n> Testing HugePages Support..."
if test_pattern_exists "hugepages"; then
  run_case "HugePages" "QUICFUSCATE_MADVISE_HUGEPAGE=1" cargo test --release --lib hugepages -- --nocapture
else
  warn "Skipping HugePages (no matching tests)"
  SKIPPED=$((SKIPPED+1)); append_json "HugePages" "skipped" 0
fi

# Test SIMD paths (x86_64)
echo -e "\n> Testing x86_64 SIMD Paths..."
if [[ $(uname -m) == "x86_64" ]]; then
    echo "  - Testing SSE2..."
    if test_pattern_exists "sse2"; then
      run_case "SSE2 paths" "RUSTFLAGS=-Ctarget-feature=+sse2" cargo test --release --lib sse2 -- --nocapture
    else
      warn "Skipping SSE2 tests (no matching tests)"
      SKIPPED=$((SKIPPED+1)); append_json "SSE2 paths" "skipped" 0
    fi
    
    echo "  - Testing AVX2..."
    if test_pattern_exists "avx2"; then
      run_case "AVX2 paths" "RUSTFLAGS=-Ctarget-feature=+avx2" cargo test --release --lib avx2 -- --nocapture
    else
      warn "Skipping AVX2 tests (no matching tests)"
      SKIPPED=$((SKIPPED+1)); append_json "AVX2 paths" "skipped" 0
    fi
    
    echo "  - Testing AVX-512..."
    if test_pattern_exists "avx512"; then
      run_case "AVX-512 paths" "RUSTFLAGS=-Ctarget-feature=+avx512f" cargo test --release --lib avx512 -- --nocapture
    else
      warn "Skipping AVX-512 tests (no matching tests)"
      SKIPPED=$((SKIPPED+1)); append_json "AVX-512 paths" "skipped" 0
    fi
else
    echo "  Skipping (x86_64 only)"
    SKIPPED=$((SKIPPED+1)); append_json "x86_64 SIMD paths" "skipped" 0
fi

# Test SIMD paths (ARM)
echo -e "\n> Testing ARM SIMD Paths..."
if [[ $(uname -m) == "aarch64" ]] || [[ $(uname -m) == "arm64" ]]; then
    echo "  - Testing NEON..."
    if test_pattern_exists "neon"; then
      run_case "NEON paths" "" cargo test --release --lib neon -- --nocapture
    else
      warn "Skipping NEON tests (no matching tests)"
      SKIPPED=$((SKIPPED+1)); append_json "NEON paths" "skipped" 0
    fi
    
    echo "  - Testing PMULL..."
    if test_pattern_exists "pmull"; then
      run_case "PMULL paths" "" cargo test --release --lib pmull -- --nocapture
    else
      warn "Skipping PMULL tests (no matching tests)"
      SKIPPED=$((SKIPPED+1)); append_json "PMULL paths" "skipped" 0
    fi
else
    echo "  Skipping (ARM only)"
    SKIPPED=$((SKIPPED+1)); append_json "ARM SIMD paths" "skipped" 0
fi

# Test CPU feature detection
echo -e "\n> Testing CPU Feature Detection..."
run_named_test "CPU feature detection" "cpu_features"

# Test prefetching
echo -e "\n> Testing Prefetch Hints..."
run_named_test "Prefetch hints" "prefetch"

# Test cache alignment
echo -e "\n> Testing Cache Line Alignment..."
run_named_test "Cache alignment" "cache_alignment"

# Test zero-copy operations
echo -e "\n> Testing Zero-Copy Operations..."
if test_pattern_exists "zero_copy"; then
  run_case "Zero-copy operations" "" cargo test --release --features zero_copy_dgram --lib zero_copy -- --nocapture
else
  warn "Skipping zero_copy (no matching tests)"
  SKIPPED=$((SKIPPED+1)); append_json "Zero-copy operations" "skipped" 0
fi

# Test batch processing
echo -e "\n> Testing Batch Processing..."
run_named_test "Batch processing" "batch_processing"

# Test telemetry
echo -e "\n> Testing Telemetry System..."
if test_pattern_exists "telemetry"; then
  run_case "Telemetry system" "QUICFUSCATE_TELEMETRY=1" cargo test --release --lib telemetry -- --nocapture
else
  warn "Skipping telemetry tests (no matching tests)"
  SKIPPED=$((SKIPPED+1)); append_json "Telemetry system" "skipped" 0
fi

# Integration fixtures (SIMD/accelerate/telemetry)
FEATURES="${CARGO_FEATURES:-rust-tests}"
if [[ ",${FEATURES}," != *",rust-tests,"* ]]; then
  FEATURES="${FEATURES},rust-tests"
fi
if [[ ",${FEATURES}," != *",simd-selfcheck,"* ]]; then
  FEATURES="${FEATURES},simd-selfcheck"
fi
echo -e "\n> Running SIMD/Accelerate Integration Fixtures..."
SIMD_FULL_TEST_ARGS=(
  --test rt-argsort-parity
  --test rt-base64-decode-parity
  --test rt-bitmap-range-parity
  --test rt-bitstream-parity
  --test rt-brain-activation-parity
  --test rt-brain-histogram
  --test rt-ecn-popcount
  --test rt-header-validate-parity
  --test rt-iter-reduction-telemetry
  --test rt-iter-reductions
  --test rt-moving-average-parity
  --test rt-packet-number-parity
  --test rt-random-aes-ctr
  --test rt-ring-buffer-parity
  --test rt-shuffle-parity
  --test rt-simd-selfcheck
  --test rt-telemetry-counters
  --test rt-transpose-parity
  --test rt-varint-roundtrip
  --test rt-xor-parity
)
if [[ "$(uname -m)" == "x86_64" ]]; then
  SIMD_FULL_TEST_ARGS+=(--test rt-ack-merge-parity --test rt-xor-sse2-parity)
fi
run_case "SIMD/Accelerate integration" "" cargo test --release --features "$FEATURES" \
  "${SIMD_FULL_TEST_ARGS[@]}" \
  -- --nocapture

# Combined optimization test
echo -e "\n> Running Optimization Stress Test..."
if test_pattern_exists "optimization_stress"; then
  run_case "Optimization stress" "QUICFUSCATE_NUMA_POLICY=interleave QUICFUSCATE_MADVISE_HUGEPAGE=1 QUICFUSCATE_TELEMETRY=1 RUSTFLAGS=-Ctarget-cpu=native" \
    run_cargo test --release --lib optimization_stress -- --nocapture --test-threads=1
else
  warn "Skipping optimization_stress (no matching tests)"
  SKIPPED=$((SKIPPED+1)); append_json "Optimization stress" "skipped" 0
fi

echo -e "\n==============================================================="
echo "  Optimization Test Summary"
echo "==============================================================="
echo "  Total:   $TOTAL"
echo "  Passed:  $PASSED"
echo "  Failed:  $FAILED"
echo "  Skipped: $SKIPPED"
json_end "$RESULTS_JSON"
if [[ "$FAILED" -gt 0 ]]; then
  echo -e "\n[FAIL] Optimization Tests completed with failures"
  exit 1
fi
echo -e "\n[OK] Optimization Tests Complete"
