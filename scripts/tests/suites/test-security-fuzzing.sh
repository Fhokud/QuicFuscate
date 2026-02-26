#!/usr/bin/env bash
# Description: Test suite runner: test-security-fuzzing.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""; RUSTFLAGS_EXTRA=""; FUZZ_DURATION=60; FUZZ_JOBS=4
FUZZ_FORCE="${QUICFUSCATE_FORCE_FUZZ:-0}"
TOOLCHAIN_PIN="nightly"
if [[ -f "$PROJECT_ROOT/rust-toolchain.toml" ]]; then
  TOOLCHAIN_PIN=$(sed -n 's/^channel = "\(.*\)"/\1/p' "$PROJECT_ROOT/rust-toolchain.toml" | head -n 1)
  if [[ -z "$TOOLCHAIN_PIN" ]]; then
    TOOLCHAIN_PIN="nightly"
  fi
fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --rustflags) RUSTFLAGS_EXTRA="$2"; shift;;
    --duration) FUZZ_DURATION="$2"; shift;;
    --jobs) FUZZ_JOBS="$2"; shift;;
    --dry-run) DRY_RUN=1;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1; set -x;;
    --help|-h) echo "Usage: $(basename "$0") [--output-dir DIR] [--rustflags STR] [--duration SEC] [--jobs N]"; exit 0;;
    *) break;;
  esac; shift
done
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"; LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"; exec > >(tee -a "$LOG_FILE") 2>&1
[[ -n "${RUSTFLAGS_EXTRA:-}" ]] && export RUSTFLAGS="${RUSTFLAGS_EXTRA} ${RUSTFLAGS:-}"
RESULTS_JSON="$OUTPUT_DIR/results.json"; json_begin "$RESULTS_JSON" "tests_security_fuzzing"; JSON_FIRST_RUN=1

echo "==============================================================="
echo "  Security & Fuzzing Test Suite"
echo "==============================================================="

TOTAL=0; PASSED=0; FAILED=0; SKIPPED=0
TEST_LIST_FILE="$OUTPUT_DIR/testlist.txt"

ensure_test_list() {
  if [[ ! -f "$TEST_LIST_FILE" ]]; then
    run cargo test --features rust-tests -- --list > "$TEST_LIST_FILE" 2>/dev/null || true
  fi
}

test_pattern_exists() {
  local pattern="$1"
  ensure_test_list
  grep -q "$pattern" "$TEST_LIST_FILE" 2>/dev/null
}

has_nightly_rustc() {
  if command -v rustup >/dev/null 2>&1; then
    if rustup toolchain list 2>/dev/null | grep -q "${TOOLCHAIN_PIN}"; then
      return 0
    fi
    if command -v rg >/dev/null 2>&1; then
      rustup run "${TOOLCHAIN_PIN}" rustc -Vv 2>/dev/null | rg -q 'nightly' && return 0
    else
      rustup run "${TOOLCHAIN_PIN}" rustc -Vv 2>/dev/null | grep -q 'nightly' && return 0
    fi
  fi
  if command -v rg >/dev/null 2>&1; then
    rustc -Vv 2>/dev/null | rg -q 'nightly'
    return $?
  fi
  rustc -Vv 2>/dev/null | grep -q 'nightly'
}

tsan_supported() {
  local os arch
  os="$(uname -s 2>/dev/null || echo unknown)"
  arch="$(uname -m 2>/dev/null || echo unknown)"
  if [[ "$os" == "Darwin" && "$arch" == "arm64" ]]; then
    return 1
  fi
  return 0
}

fuzz_enabled_on_host() {
  local os arch
  os="$(uname -s 2>/dev/null || echo unknown)"
  arch="$(uname -m 2>/dev/null || echo unknown)"
  if [[ "$os" == "Darwin" && "$arch" == "arm64" && "$FUZZ_FORCE" != "1" ]]; then
    return 1
  fi
  return 0
}

append_json() {
  local name="$1" status="$2" dur="$3"
  if [[ $JSON_FIRST_RUN -eq 0 ]]; then echo "," >> "$RESULTS_JSON"; fi
  JSON_FIRST_RUN=0
  echo -n '  {"name":'"\"$name\""',"status":'"\"$status\""',"duration_sec":'"$dur"'}' >> "$RESULTS_JSON"
}

run_case() {
  local name="$1"; shift
  local envs=()
  while [[ "$#" -gt 0 && "$1" != "--" ]]; do
    envs+=("$1")
    shift
  done
  if [[ "${1:-}" == "--" ]]; then
    shift
  fi
  local cmd=("$@")
  local start=$(date +%s)
  TOTAL=$((TOTAL+1))
  echo -e "\n> [$TOTAL] $name"
  if [[ ${#envs[@]} -gt 0 ]]; then
    echo "  Env: ${envs[*]}"
  fi
  echo "  Cmd: ${cmd[*]}"
  if [[ ${#envs[@]} -gt 0 ]]; then
    if [[ "${cmd[0]}" == "cargo" && "${cmd[1]:-}" != "fuzz" ]]; then
      if run env "${envs[@]}" cargo "${cmd[@]:1}"; then
        PASSED=$((PASSED+1)); append_json "$name" "ok" $(( $(date +%s) - start )); return 0
      fi
    else
      if run env "${envs[@]}" "${cmd[@]}"; then
        PASSED=$((PASSED+1)); append_json "$name" "ok" $(( $(date +%s) - start )); return 0
      fi
    fi
  else
    if [[ "${cmd[0]}" == "cargo" && "${cmd[1]:-}" != "fuzz" ]]; then
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
    run_case "$label" -- cargo test --release --features rust-tests --lib "$pattern" -- --nocapture
  else
    warn "Skipping ${label} (no matching tests)"
    SKIPPED=$((SKIPPED+1))
    append_json "$label" "skipped" 0
  fi
}

# Fuzzing configuration
FUZZ_DURATION=${FUZZ_DURATION:-60}  # seconds per target
FUZZ_JOBS=${FUZZ_JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu || echo 4)}
FUZZ_ARTIFACT_ROOT="$OUTPUT_DIR/fuzz"
FUZZ_TARGET_DIR="${QUICFUSCATE_FUZZ_TARGET_DIR:-$SCRIPT_DIR/../../out/tests/_fuzz-target-cache}"
FUZZ_CORPUS_ROOT="$FUZZ_ARTIFACT_ROOT/corpus"
FUZZ_CRASH_ROOT="$FUZZ_ARTIFACT_ROOT/artifacts"
FUZZ_DIR="$PROJECT_ROOT/scripts/tests/fuzz"
FUZZ_SEED_ROOT="$FUZZ_DIR/seeds"
FUZZ_MANIFEST="$FUZZ_DIR/Cargo.toml"
mkdir -p "$FUZZ_TARGET_DIR" "$FUZZ_CORPUS_ROOT" "$FUZZ_CRASH_ROOT"

echo -e "\n> Configuration:"
echo "  Fuzz duration: ${FUZZ_DURATION}s per target"
echo "  Parallel jobs: ${FUZZ_JOBS}"
echo "  Host fuzz enabled: $(fuzz_enabled_on_host && echo yes || echo no)"
echo "  Fuzz seeds: ${FUZZ_SEED_ROOT}"
echo "  Runtime corpus: ${FUZZ_CORPUS_ROOT}"
echo "  Runtime crashes: ${FUZZ_CRASH_ROOT}"
echo "  Shared fuzz target dir: ${FUZZ_TARGET_DIR}"

# Build with fuzzing support
echo -e "\n> Building with fuzzing instrumentation..."
if command -v cargo-fuzz &> /dev/null && [[ -f "$FUZZ_MANIFEST" ]]; then
    if has_nightly_rustc && fuzz_enabled_on_host; then
      run_case "Fuzz build" RUSTUP_TOOLCHAIN="${TOOLCHAIN_PIN}" CARGO_TARGET_DIR="$FUZZ_TARGET_DIR" -- cargo fuzz build --fuzz-dir "$FUZZ_DIR" || true
    elif has_nightly_rustc && ! fuzz_enabled_on_host; then
      warn "Skipping cargo-fuzz on macOS arm64 by default (set QUICFUSCATE_FORCE_FUZZ=1 to force)"
      SKIPPED=$((SKIPPED+1))
      append_json "Fuzz build" "skipped" 0
    else
      warn "cargo-fuzz installed but nightly rustc is not active; skipping fuzz build"
      SKIPPED=$((SKIPPED+1))
      append_json "Fuzz build" "skipped" 0
    fi
else
    if has_nightly_rustc; then
      echo "  cargo-fuzz not available; using nightly ASAN build"
      run_case "ASAN build" RUSTUP_TOOLCHAIN="${TOOLCHAIN_PIN}" RUSTFLAGS="-Zsanitizer=address" -- cargo build --release || true
    else
      warn "cargo-fuzz not available or fuzz manifest missing; skipping sanitizer build"
      SKIPPED=$((SKIPPED+1))
      append_json "Sanitizer build" "skipped" 0
    fi
fi

# Input validation tests
echo -e "\n=== Input Validation Tests ==="

echo -e "\n> Testing malformed packets..."
run_named_test "Malformed packets" "malformed_packet"

echo -e "\n> Testing oversized inputs..."
run_named_test "Oversized inputs" "oversized_input"

echo -e "\n> Testing boundary conditions..."
run_named_test "Boundary conditions" "boundary_conditions"

echo -e "\n> Testing integer overflows..."
run_case "Integer overflow checks" RUSTFLAGS="-Coverflow-checks=on" -- cargo test --release --features rust-tests --lib integer_overflow -- --nocapture

# Memory safety tests
echo -e "\n=== Memory Safety Tests ==="

echo -e "\n> Testing buffer overflows..."
run_named_test "Buffer overflow" "buffer_overflow"

echo -e "\n> Testing use-after-free..."
run_named_test "Use-after-free" "use_after_free"

echo -e "\n> Testing double-free..."
run_named_test "Double-free" "double_free"

# Concurrency tests
echo -e "\n=== Concurrency Safety Tests ==="

echo -e "\n> Testing data races..."
if test_pattern_exists "data_race"; then
  if has_nightly_rustc && tsan_supported; then
    run_case "Data races (TSAN)" RUSTUP_TOOLCHAIN="${TOOLCHAIN_PIN}" RUSTFLAGS="-Zsanitizer=thread -Cunsafe-allow-abi-mismatch=sanitizer" -- cargo test --release --features rust-tests --lib data_race -- --nocapture
  else
    run_case "Data races" -- cargo test --release --features rust-tests --lib data_race -- --nocapture
  fi
else
  warn "Skipping data_race (no matching tests)"
  SKIPPED=$((SKIPPED+1))
  append_json "Data races" "skipped" 0
fi

echo -e "\n> Testing deadlocks..."
if test_pattern_exists "deadlock_detection"; then
  run_case "Deadlock detection" -- cargo test --release --features rust-tests --lib deadlock_detection -- --nocapture --test-threads=8
else
  warn "Skipping deadlock_detection (no matching tests)"
  SKIPPED=$((SKIPPED+1))
  append_json "Deadlock detection" "skipped" 0
fi

echo -e "\n> Testing race conditions..."
if test_pattern_exists "race_conditions"; then
  run_case "Race conditions" -- cargo test --release --features rust-tests --lib race_conditions -- --nocapture --test-threads=16
else
  warn "Skipping race_conditions (no matching tests)"
  SKIPPED=$((SKIPPED+1))
  append_json "Race conditions" "skipped" 0
fi

# Crypto security tests
echo -e "\n=== Cryptographic Security Tests ==="

echo -e "\n> Testing timing attacks resistance..."
run_named_test "Timing attack resistance" "timing_attack"

echo -e "\n> Testing key material handling..."
run_named_test "Key material handling" "key_material"

echo -e "\n> Testing PRNG quality..."
run_named_test "PRNG quality" "prng_quality"

# Protocol security tests
echo -e "\n=== Protocol Security Tests ==="

echo -e "\n> Testing replay attacks..."
run_named_test "Replay attacks" "replay_attack"

echo -e "\n> Testing amplification attacks..."
run_named_test "Amplification attacks" "amplification_attack"

echo -e "\n> Testing resource exhaustion..."
run_named_test "Resource exhaustion" "resource_exhaustion"

echo -e "\n> Testing active probe detection invariants..."
run_case "Active probe detection invariants" -- cargo test --release --features rust-tests --test rt-probe-detection -- --nocapture

# Fuzzing targets
if command -v cargo-fuzz &> /dev/null && [[ -f "$FUZZ_MANIFEST" ]] && has_nightly_rustc && fuzz_enabled_on_host; then
    echo -e "\n=== Fuzzing Tests ==="
    
    FUZZ_TARGETS=(
        "packet_parsing"
        "frame_decoding"
        "crypto_operations"
        "fec_encoding"
        "varint_parsing"
        "connection_handling"
    )
    
    for target in "${FUZZ_TARGETS[@]}"; do
        runtime_corpus="$FUZZ_CORPUS_ROOT/${target}"
        runtime_crash="$FUZZ_CRASH_ROOT/${target}"
        seed_corpus="$FUZZ_SEED_ROOT/${target}"
        mkdir -p "$runtime_corpus" "$runtime_crash"
        if [[ -d "$seed_corpus" ]]; then
          cp -a "$seed_corpus/." "$runtime_corpus/" 2>/dev/null || true
        fi
        run_case "Fuzz ${target}" RUSTUP_TOOLCHAIN="${TOOLCHAIN_PIN}" CARGO_TARGET_DIR="$FUZZ_TARGET_DIR" -- cargo fuzz run --fuzz-dir "$FUZZ_DIR" "$target" -- -jobs=${FUZZ_JOBS} -max_total_time=${FUZZ_DURATION} -max_len=65536 -timeout=10 -artifact_prefix="$runtime_crash/" "$runtime_corpus"
    done
else
    warn "Fuzz targets skipped (cargo-fuzz missing, fuzz manifest missing, nightly rustc not active, or host gating active)"
    SKIPPED=$((SKIPPED+1))
    append_json "Fuzz targets" "skipped" 0
fi

# Property-based testing
echo -e "\n=== Property-Based Tests ==="

echo -e "\n> Running dedicated property suite..."
run_case "Property suite (proptest)" -- cargo test --release --features rust-tests --test rt-property-suite -- --nocapture

echo -e "\n> Testing FEC properties..."
run_named_test "FEC properties" "fec_properties"

echo -e "\n> Testing crypto properties..."
run_named_test "Crypto properties" "crypto_properties"

echo -e "\n> Testing transport invariants..."
run_named_test "Transport invariants" "transport_invariants"

# Sanitizer tests
echo -e "\n=== Sanitizer Tests ==="

if [[ "$OSTYPE" == "linux-gnu"* ]] || [[ "$OSTYPE" == "darwin"* ]]; then
    if has_nightly_rustc; then
      SYSROOT=$(rustc +"${TOOLCHAIN_PIN}" --print sysroot)
      HOST_TRIPLE=$(rustc +"${TOOLCHAIN_PIN}" -vV | sed -n 's/^host: //p')
      ASAN_RT="${SYSROOT}/lib/rustlib/${HOST_TRIPLE}/lib/librustc-nightly_rt.asan.dylib"
      UBSAN_RT="${SYSROOT}/lib/rustlib/${HOST_TRIPLE}/lib/librustc-nightly_rt.ubsan.dylib"

      echo -e "\n> Running with AddressSanitizer..."
      if [[ "$OSTYPE" == "darwin"* && "$(uname -m 2>/dev/null || true)" == "arm64" ]]; then
        warn "ASAN full test is unstable on macOS arm64 in this toolchain setup; skipping"
        SKIPPED=$((SKIPPED+1)); append_json "ASAN full test" "skipped" 0
      elif [[ "$OSTYPE" == "darwin"* && -f "$ASAN_RT" ]]; then
        run_case "ASAN full test" RUSTUP_TOOLCHAIN="${TOOLCHAIN_PIN}" RUSTFLAGS="-Zsanitizer=address" DYLD_INSERT_LIBRARIES="${ASAN_RT}" DYLD_FORCE_FLAT_NAMESPACE=1 -- cargo test --release --features rust-tests || true
      else
        run_case "ASAN full test" RUSTUP_TOOLCHAIN="${TOOLCHAIN_PIN}" RUSTFLAGS="-Zsanitizer=address" -- cargo test --release --features rust-tests || true
      fi

      echo -e "\n> Running with MemorySanitizer..."
      if [[ "$OSTYPE" == "darwin"* ]]; then
        warn "MSAN is not supported on macOS; skipping"
        SKIPPED=$((SKIPPED+1)); append_json "MSAN full test" "skipped" 0
      else
        run_case "MSAN full test" RUSTUP_TOOLCHAIN="${TOOLCHAIN_PIN}" RUSTFLAGS="-Zsanitizer=memory" -- cargo test --release --features rust-tests || true
      fi

      echo -e "\n> Running with UndefinedBehaviorSanitizer..."
      if [[ "$OSTYPE" == "darwin"* && ! -f "$UBSAN_RT" ]]; then
        warn "UBSAN runtime not available for this toolchain; skipping"
        SKIPPED=$((SKIPPED+1)); append_json "UBSAN full test" "skipped" 0
      else
        run_case "UBSAN full test" RUSTUP_TOOLCHAIN="${TOOLCHAIN_PIN}" RUSTFLAGS="-Zsanitizer=undefined" -- cargo test --release --features rust-tests || true
      fi
    else
      warn "Sanitizers require nightly rustc; skipping"
      SKIPPED=$((SKIPPED+1)); append_json "ASAN full test" "skipped" 0
      SKIPPED=$((SKIPPED+1)); append_json "MSAN full test" "skipped" 0
      SKIPPED=$((SKIPPED+1)); append_json "UBSAN full test" "skipped" 0
    fi
fi

echo -e "\n==============================================================="
echo "  Security & Fuzzing Summary"
echo "==============================================================="
echo "  Total:   $TOTAL"
echo "  Passed:  $PASSED"
echo "  Failed:  $FAILED"
echo "  Skipped: $SKIPPED"
json_end "$RESULTS_JSON"
if [[ "$FAILED" -gt 0 ]]; then
  echo -e "\n[FAIL] Security & Fuzzing Tests completed with failures"
  exit 1
fi
echo -e "\n[OK] Security & Fuzzing Tests Complete"
