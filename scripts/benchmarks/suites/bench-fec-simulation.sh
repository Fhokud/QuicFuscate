#!/usr/bin/env bash
# Description: Benchmark suite runner: bench-fec-simulation.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../../tests/lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../../tests/lib/lib-common.sh"

OUTPUT_DIR=""; FAST=0; RUSTFLAGS_EXTRA=""; CARGO_FEATURES=""; JOBS=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --fast) FAST=1;;
    --full) FAST=0;;
    --jobs) JOBS="$2"; shift;;
    --features) CARGO_FEATURES="$2"; shift;;
    --rustflags) RUSTFLAGS_EXTRA="$2"; shift;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h) echo "Usage: $(basename "$0") [options]"; echo "FEC Simulation Benchmarks"; usage_common_flags 2>/dev/null || true; exit 0;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac; shift
done

export CARGO_FEATURES JOBS

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/benchmarks/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"; LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"

echo "===============================================================" | tee -a "$LOG_FILE"
echo "  FEC Internal Machine-Room Simulation Benchmark Suite" | tee -a "$LOG_FILE"
echo "===============================================================" | tee -a "$LOG_FILE"
print_system_banner | tee -a "$LOG_FILE"

# Try cargo bench harness; skip gracefully if not present.
if ! cargo bench --no-run --features benches >/dev/null 2>&1; then
  warn "No Rust bench harness; falling back to timed test loops"
fi

MODES=(normal streaming extreme)
LOSSES=(0.0 0.05 0.20 0.40)
THREADS=(1 4 8)
if (( FAST )); then MODES=(normal streaming); LOSSES=(0.0 0.20); THREADS=(4); fi

RESULTS_JSON="$OUTPUT_DIR/bench_results.json"; json_begin "$RESULTS_JSON" "bench_fec_simulation"; FIRST=true
TOTAL=0

export -f run run_cargo
run_cargo_logged() {
  local envs="$1"; shift
  if [[ -n "$envs" ]]; then
    run bash -lc "export $envs; run_cargo $*"
  else
    run bash -lc "run_cargo $*"
  fi
}

bench_one() {
  local mode="$1" loss="$2" th="$3"
  local envs=(
    "QUICFUSCATE_FEC_INITIAL_MODE=${mode}"
    "QUICFUSCATE_RS_LOSS=${loss}"
    "QUICFUSCATE_RAYON_THREADS=${th}"
  )
  echo -e "\n> Bench: mode=${mode}, loss=${loss}, threads=${th}" | tee -a "$LOG_FILE"
  local start=$(date +%s)
  # Timed run of a tight subset to approximate performance
  run_cargo_logged "${envs[*]} RUSTFLAGS=${RUSTFLAGS_EXTRA:-}" test --release --lib \
    'fec::test_auto_mode_streaming_selection' \
    -- --nocapture >>"$LOG_FILE" 2>&1 || true
  run_cargo_logged "${envs[*]} RUSTFLAGS=${RUSTFLAGS_EXTRA:-}" test --release --lib \
    'fec::test_batch_normal_par_counts' \
    -- --nocapture >>"$LOG_FILE" 2>&1 || true
  local end=$(date +%s); local dur=$((end-start))
  TOTAL=$((TOTAL+1))
  if [[ "$FIRST" == "true" ]]; then FIRST=false; else echo "," >> "$RESULTS_JSON"; fi
  echo -n '  {"mode":"'$mode'","loss":'$loss',"threads":'$th',"duration_sec":'$dur'}' >> "$RESULTS_JSON"
}

for m in "${MODES[@]}"; do
  for l in "${LOSSES[@]}"; do
    for t in "${THREADS[@]}"; do
      bench_one "$m" "$l" "$t"
    done
  done
done

json_end "$RESULTS_JSON"

echo -e "\n===============================================================" | tee -a "$LOG_FILE"
echo "  FEC Simulation Bench Summary" | tee -a "$LOG_FILE"
echo "===============================================================" | tee -a "$LOG_FILE"
echo "  Total benches: $TOTAL" | tee -a "$LOG_FILE"
echo "  Output: $OUTPUT_DIR" | tee -a "$LOG_FILE"

echo "[OK] Bench suite complete"
