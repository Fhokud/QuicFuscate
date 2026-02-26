#!/usr/bin/env bash
# Description: Test suite runner: test-fec.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""
REFRACTOR=0
REFRACTOR_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --jobs) JOBS="$2"; shift;;
    --features) CARGO_FEATURES="$2"; shift;;
    --rustflags) RUSTFLAGS_EXTRA="$2"; shift;;
    --refactor) REFRACTOR=1;;
    --refactor-only) REFRACTOR=1; REFRACTOR_ONLY=1;;
    --dry-run) DRY_RUN=1;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h)
      echo "Usage: $(basename "$0") [options]"
      echo "FEC Comprehensive Test Suite"
      echo "  --refactor            Include refactor validation checks"
      echo "  --refactor-only       Only run refactor validation checks"
      usage_common_flags 2>/dev/null || true
      exit 0;;
    *) echo "Unknown flag: " >&2; exit 2;;
  esac; shift
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/tests-fec-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/fec-tests.log"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "tests_fec_comprehensive"; JSON_FIRST_RUN=1

echo "==============================================================="
echo "  FEC Comprehensive Test Suite"
echo "==============================================================="

export -f run run_cargo
run_cargo_logged() {
  local envs="$1"; shift
  if [[ -n "$envs" ]]; then
    run bash -lc "export $envs; run_cargo $*"
  else
    run bash -lc "run_cargo $*"
  fi
}

if [[ "$REFRACTOR_ONLY" -eq 0 ]]; then
  # Test all FEC modes and configurations
  echo -e "\n> Testing FEC Zero Mode (no overhead at 0% loss)..."
  run_cargo_logged "QUICFUSCATE_FEC_INITIAL_MODE=zero" test --release fec:: -- --nocapture

  echo -e "\n> Testing FEC Light Mode..."
  run_cargo_logged "QUICFUSCATE_FEC_INITIAL_MODE=light" test --release fec:: -- --nocapture

  echo -e "\n> Testing FEC Normal Mode..."
  run_cargo_logged "QUICFUSCATE_FEC_INITIAL_MODE=normal" test --release fec:: -- --nocapture

  echo -e "\n> Testing FEC Medium Mode..."
  run_cargo_logged "QUICFUSCATE_FEC_INITIAL_MODE=medium" test --release fec:: -- --nocapture

  echo -e "\n> Testing FEC Strong Mode..."
  run_cargo_logged "QUICFUSCATE_FEC_INITIAL_MODE=strong" test --release fec:: -- --nocapture

  echo -e "\n> Testing FEC Extreme Mode..."
  run_cargo_logged "QUICFUSCATE_FEC_INITIAL_MODE=extreme" test --release fec:: -- --nocapture

  echo -e "\n> Testing FEC Streaming Mode (Tetrys-like)..."
  run_cargo_logged "QUICFUSCATE_FEC_INITIAL_MODE=streaming" test --release fec:: -- --nocapture

  # Test adaptive FEC
  echo -e "\n> Testing Adaptive FEC..."
  run_cargo_logged "QUICFUSCATE_FEC_USE_ADAPTIVE=1" test --release adaptive_fec -- --nocapture

  # Test partial recovery
  echo -e "\n> Testing FEC Partial Recovery..."
  run_cargo_logged "QUICFUSCATE_FEC_PARTIAL=1" test --release partial_recover -- --nocapture

  # Test GF(2^8) Wiedemann solver
  echo -e "\n> Testing GF(2^8) Wiedemann Solver..."
  run_cargo_logged "QUICFUSCATE_FEC_KERNEL=wiedemann" test --release gf8_decoder -- --nocapture

  # Test GF(2^16) SIMD paths
  echo -e "\n> Testing GF(2^16) SIMD Optimizations..."
  run_cargo_logged "QUICFUSCATE_GF16_SIMD=1 QUICFUSCATE_GF16_NIBBLE=1" test --release gf16 -- --nocapture

  # Test Rayon parallelization
  echo -e "\n> Testing FEC with Rayon Parallelization..."
  run_cargo_logged "QUICFUSCATE_RAYON_THREADS=4" test --release fec::encoder -- --nocapture

  # Combined stress test
  echo -e "\n> Running FEC Stress Test (high loss simulation)..."
  run_cargo_logged "QUICFUSCATE_FEC_INITIAL_MODE=extreme QUICFUSCATE_FEC_USE_ADAPTIVE=1 QUICFUSCATE_FEC_PARTIAL=1 QUICFUSCATE_RAYON_THREADS=8" \
    test --release fec_stress -- --nocapture --test-threads=1
fi

if [[ "$REFRACTOR" -eq 1 ]]; then
  echo -e "\n=== FEC Refactor Validation (focused) ==="
  run_cargo_logged "" test --release --lib stream_raw_roundtrip -- --nocapture
  run_cargo_logged "" test --release --lib test_batch_normal -- --nocapture
  run_cargo_logged "QUICFUSCATE_FEC_INITIAL_MODE=extreme" test --release --lib test_batch_extreme_gf16 -- --nocapture
  run_cargo_logged "" test --release --lib test_streaming_tetrys -- --nocapture
  run_cargo_logged "QUICFUSCATE_GF16_SIMD=1" test --release --lib gf16 -- --nocapture
  run_cargo_logged "" test --release --lib test_batch_extreme_gf16_coeff_len -- --nocapture
  run_cargo_logged "" test --release --lib test_streaming_repairs_have_nonzero_coeffs -- --nocapture
  run_cargo_logged "" test --release --lib test_streaming_tetrys_burst_loss_recovery -- --nocapture
  run_cargo_logged "QUICFUSCATE_FEC_STREAM_EVERY=3" test --release --lib test_streaming_emit_every_n -- --nocapture

  if cargo bench --no-run --features benches >/dev/null 2>&1; then
    run cargo bench --features benches fec_encode_gf8
  else
    warn "No Rust benches detected; skipping fec_encode_gf8 benchmark check"
  fi

  require_cmd rg
  run bash -c "! rg -n 'struct KalmanFilter.*error_cov' src"
  run rg -n "pub mem_pool: Arc<MemoryPool>" src/fec.rs
  run rg -n "impl Drop for FecPacket" src/fec.rs
fi

echo -e "\n[OK] FEC Comprehensive Tests Complete"
json_end "$JSON"
