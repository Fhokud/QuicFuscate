#!/usr/bin/env bash
# Description: Benchmark suite runner: bench-fec.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../../tests/lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../../tests/lib/lib-common.sh"

OUTPUT_DIR=""; RUSTFLAGS_EXTRA=""; FAST=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --rustflags) RUSTFLAGS_EXTRA="$2"; shift;;
    --fast) FAST=1;;
    --full) FAST=0;;
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
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "bench_fec_all"; JSON_FIRST_RUN=1

echo "==============================================================="
echo "  FEC Performance Benchmarks"
echo "==============================================================="

# Skip gracefully if no Rust benches present; fallback suggestion
if ! cargo bench --no-run --features benches >/dev/null 2>&1; then
  echo "No Rust benches detected; consider running:"
  echo "  $SCRIPT_DIR/bench-fec-simulation.sh --output-dir ${OUTPUT_DIR:-$SCRIPT_DIR/../../out/benchmarks}"
  if [[ $JSON_FIRST_RUN -eq 0 ]]; then echo "," >> "$JSON"; fi; JSON_FIRST_RUN=0
  echo -n '  {"status":"skipped","reason":"no_rust_benches"}' >> "$JSON"
  json_end "$JSON"
  exit 0
fi

# Build with optimizations
run_cargo build --release --features benches

if (( FAST )); then
  echo -e "\n> Benchmarking FEC Encoder (GF8)..."
  run env QUICFUSCATE_FEC_KERNEL=standard cargo bench --features benches -- fec_encode

  echo -e "\n> Benchmarking FEC Decoder (GF8)..."
  run env QUICFUSCATE_FEC_KERNEL=standard cargo bench --features benches -- fec_decode

  echo -e "\n> Benchmarking Adaptive FEC Mode Switching..."
  run env QUICFUSCATE_FEC_USE_ADAPTIVE=1 cargo bench --features benches -- adaptive_fec

  echo -e "\n> Benchmarking Rayon Parallelization (representative thread count)..."
  run env QUICFUSCATE_RAYON_THREADS=4 cargo bench --features benches -- parallel_fec

  echo -e "\n> Benchmarking XOR Operations (SIMD)..."
  run cargo bench --features benches -- fast_xor
else
  echo -e "\n> Benchmarking FEC Encoder (GF8)..."
  run env QUICFUSCATE_FEC_KERNEL=standard cargo bench --features benches -- fec_encode

  echo -e "\n> Benchmarking FEC Decoder (GF8)..."
  run env QUICFUSCATE_FEC_KERNEL=standard cargo bench --features benches -- fec_decode

  echo -e "\n> Benchmarking Wiedemann Solver..."
  run env QUICFUSCATE_FEC_KERNEL=wiedemann cargo bench --features benches -- wiedemann

  echo -e "\n> Benchmarking GF16 SIMD Operations..."
  run env QUICFUSCATE_GF16_SIMD=1 cargo bench --features benches -- gf16

  echo -e "\n> Benchmarking Adaptive FEC Mode Switching..."
  run env QUICFUSCATE_FEC_USE_ADAPTIVE=1 cargo bench --features benches -- adaptive_fec

  echo -e "\n> Benchmarking Streaming Recovery (Tetrys)..."
  run env QUICFUSCATE_FEC_INITIAL_MODE=streaming cargo bench --features benches -- streaming

  echo -e "\n> Benchmarking Rayon Parallelization..."
  for threads in 1 2 4 8; do
      echo "  - Testing with $threads threads"
      run env QUICFUSCATE_RAYON_THREADS=$threads cargo bench --features benches -- parallel_fec
  done
  echo -e "\n> Benchmarking XOR Operations (SIMD)..."
  run cargo bench --features benches -- fast_xor
fi

# Export results
OUTPUT_FILE="$OUTPUT_DIR/fec-bench.json"

echo -e "\n> Exporting results to $OUTPUT_FILE..."
run cargo bench --features benches --no-run --message-format=json > "$OUTPUT_FILE" 2>&1 || true

echo -e "\n[OK] FEC Benchmarks Complete"
json_end "$JSON"
