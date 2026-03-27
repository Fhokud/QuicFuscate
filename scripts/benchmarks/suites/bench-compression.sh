#!/usr/bin/env bash
# Description: Compression micro-benchmark harness (text/binary payloads)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$ROOT"
[[ -f "$SCRIPT_DIR/../../tests/lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../../tests/lib/lib-common.sh"

OUTPUT_DIR=""
ITER=50
SIZE=$((256 * 1024))
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --iterations) ITER="$2"; shift;;
    --size) SIZE="$2"; shift;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1; set -x;;
    --help|-h)
      echo "Usage: $(basename "$0") [--output-dir DIR] [--iterations N] [--size BYTES]"
      usage_common_flags 2>/dev/null || true
      exit 0
      ;;
    *) echo "Unknown argument: $1" >&2; exit 2;;
  esac
  shift
done

TS=$(date +%Y%m%d_%H%M%S)
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$ROOT/scripts/out/benchmarks/bench-compression-$TS"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/bench.log"
RESULTS_JSON="$OUTPUT_DIR/results.json"; json_begin "$RESULTS_JSON" "bench_compression"; JSON_FIRST_RUN=1

run_bench() {
  local mode="$1"
  local outfile="$OUTPUT_DIR/${mode}.json"
  echo "[bench] mode=$mode size=$SIZE iterations=$ITER"
  run cargo run --release --example compress_bench -- \
    --dataset "$mode" \
    --size "$SIZE" \
    --iterations "$ITER" \
    --json >"$outfile"
  echo "  -> $outfile"
}

run_bench text
run_bench binary

json_end "$RESULTS_JSON"
echo "Artifacts stored in $OUTPUT_DIR"
