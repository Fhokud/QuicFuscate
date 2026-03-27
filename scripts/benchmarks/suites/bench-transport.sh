#!/usr/bin/env bash
# Description: Benchmark suite runner: bench-transport.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../../tests/lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../../tests/lib/lib-common.sh"

OUTPUT_DIR=""; FAST=0; RUSTFLAGS_EXTRA=""; JOBS=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --fast) FAST=1;;
    --jobs) JOBS="$2"; shift;;
    --features) CARGO_FEATURES="$2"; shift;;
    --rustflags) RUSTFLAGS_EXTRA="$2"; shift;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h) echo "Usage: $(basename "$0") [options]"; echo "Transport Benchmarks"; usage_common_flags 2>/dev/null || true; exit 0;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac; shift
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/benchmarks/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"

echo "==============================================================="
echo "  Transport Layer Performance Benchmarks"
echo "==============================================================="
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "bench_transport_all"; JSON_FIRST_RUN=1

# Skip gracefully if bench harness absent
if ! cargo bench --no-run --features benches >/dev/null 2>&1; then
  echo "No Rust benches detected; skipping transport benches."
  if [[ $JSON_FIRST_RUN -eq 0 ]]; then echo "," >> "$JSON"; fi; JSON_FIRST_RUN=0
  echo -n '  {"status":"skipped","reason":"no_rust_benches"}' >> "$JSON"
  json_end "$JSON"
  exit 0
fi

BENCH_JOBS=()
[[ -n "$JOBS" ]] && BENCH_JOBS+=("-j" "$JOBS")
[[ -n "${RUSTFLAGS_EXTRA:-}" ]] && export RUSTFLAGS="${RUSTFLAGS_EXTRA}"

run_cargo build --release --features "${CARGO_FEATURES:-benches}"

# Benchmark varint encoding/decoding
echo -e "\n> Benchmarking Varint Operations..."
run cargo bench "${BENCH_JOBS[@]}" --features benches -- varint

# Benchmark packet number encoding
echo -e "\n> Benchmarking Packet Number Encode..."
run cargo bench "${BENCH_JOBS[@]}" --features benches -- packet_number

# Export results
OUTPUT_FILE="$OUTPUT_DIR/transport-bench.json"

echo -e "\n> Exporting results to $OUTPUT_FILE..."
run cargo bench "${BENCH_JOBS[@]}" --features benches --no-run --message-format=json > "$OUTPUT_FILE" 2>&1 || true

echo -e "\n[OK] Transport Benchmarks Complete"
json_end "$JSON"
