#!/usr/bin/env bash
# Description: Benchmark suite runner: bench-qpack-encode.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../../tests/lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../../tests/lib/lib-common.sh"

OUTPUT_DIR=""; RUSTFLAGS_EXTRA="-C target-cpu=native"; FAST=0; SIZES="64k 256k 1m"; JSON=""; JOBS=""; FEATURES=""; DRY_RUN="";
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --rustflags) RUSTFLAGS_EXTRA="$2"; shift;;
    --fast) FAST=1;;
    --sizes) SIZES="$2"; shift;;
    --features) FEATURES="$2"; shift;;
    --jobs) JOBS="$2"; shift;;
    --dry-run) DRY_RUN=1;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1; set -x;;
    --help|-h)
      echo "Usage: $(basename "$0") [--output-dir DIR] [--rustflags STR] [--fast] [--sizes '64k 256k 1m'] [--features STR] [--jobs N]"; exit 0;;
    *) break;;
  esac; shift
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/benchmarks/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"; LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"; exec > >(tee -a "$LOG_FILE") 2>&1
[[ -n "${RUSTFLAGS_EXTRA:-}" ]] && export RUSTFLAGS="${RUSTFLAGS_EXTRA} ${RUSTFLAGS:-}"
[[ -n "${FEATURES:-}" ]] && export CARGO_FEATURES="$FEATURES"
[[ -n "${JOBS:-}" ]] && export JOBS
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "bench_qpack_encode"; JSON_FIRST_RUN=1

print_system_banner
info "Building developer harness (src/bin/harness.rs)"
run_cargo build --release

# Fast mode reduces sizes
if [[ "$FAST" -eq 1 ]]; then
  SIZES="64k 256k"
fi

size_to_bytes() {
  local s="$1"; case "$s" in
    *k|*K) echo $(( ${s%[kK]} * 1024 ));;
    *m|*M) echo $(( ${s%[mM]} * 1024 * 1024 ));;
    *) echo "$s";;
  esac
}

echo "==============================================================="
echo "  QPACK Encode Benchmark (scalar vs AVX2 vs NEON)"
echo "==============================================================="

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

for sz in $SIZES; do
  BYTES=$(size_to_bytes "$sz")
  info "Running size=$sz ($BYTES bytes)"
  run target/release/harness qpack-encode --input "$BYTES" --iters 200 | tee -a "$OUTPUT_DIR/run_$sz.txt"
  # Append each line as JSON item
  while IFS= read -r line; do
    esc_line=$(json_escape "$line")
    if [[ "$JSON_FIRST_RUN" -eq 0 ]]; then echo "," >> "$JSON"; fi
    JSON_FIRST_RUN=0
    echo -n '  {"size":"'"$sz"'","line":"'"$esc_line"'"}' >> "$JSON"
  done < "$OUTPUT_DIR/run_$sz.txt"

done

json_end "$JSON"
info "Results JSON: $JSON"
info "Done."
