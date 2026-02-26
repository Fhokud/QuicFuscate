#!/usr/bin/env bash
# Description: Benchmark suite runner: bench-optimization.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../../tests/lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../../tests/lib/lib-common.sh"

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
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/benchmarks/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"; LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"; exec > >(tee -a "$LOG_FILE") 2>&1
[[ -n "${RUSTFLAGS_EXTRA:-}" ]] && export RUSTFLAGS="${RUSTFLAGS_EXTRA} ${RUSTFLAGS:-}"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "bench_optimization_all"; JSON_FIRST_RUN=1

echo "==============================================================="
echo "  Optimization & Hardware Acceleration Benchmarks"
echo "==============================================================="

# Skip gracefully if bench harness absent
if ! cargo bench --no-run --features benches >/dev/null 2>&1; then
  echo "No Rust benches detected; skipping optimization benches."
  if [[ $JSON_FIRST_RUN -eq 0 ]]; then echo "," >> "$JSON"; fi; JSON_FIRST_RUN=0
  echo -n '  {"status":"skipped","reason":"no_rust_benches"}' >> "$JSON"
  json_end "$JSON"
  exit 0
fi

# Build with native optimizations
run_cargo build --release --features benches

# Benchmark memory pool
echo -e "\n> Benchmarking Memory Pool..."
(( ! FAST )) && run cargo bench --features benches -- memory_pool

# Benchmark NUMA configurations
echo -e "\n> Benchmarking NUMA Policies..."
for policy in local interleave "preferred:0"; do
    echo "  - Policy: $policy"
    (( ! FAST )) && run env QUICFUSCATE_NUMA_POLICY=$policy cargo bench --features benches -- numa
done

# Benchmark with/without HugePages
echo -e "\n> Benchmarking HugePages Impact..."
echo "  - Without HugePages"
(( ! FAST )) && run env QUICFUSCATE_MADVISE_HUGEPAGE=0 cargo bench --features benches -- memory_access

echo "  - With HugePages"
(( ! FAST )) && run env QUICFUSCATE_MADVISE_HUGEPAGE=1 cargo bench --features benches -- memory_access

# Benchmark SIMD paths
echo -e "\n> Benchmarking SIMD Operations..."
run env RUSTFLAGS="-C target-cpu=native" cargo bench --features benches -- simd

# Benchmark prefetching
echo -e "\n> Benchmarking Prefetch Impact..."
(( ! FAST )) && run cargo bench --features benches -- prefetch

# Benchmark zero-copy
echo -e "\n> Benchmarking Zero-Copy Operations..."
(( ! FAST )) && run cargo bench --features "benches zero_copy_dgram" -- zero_copy

# Export results
OUTPUT_FILE="$OUTPUT_DIR/optimization-bench.json"

echo -e "\n> Exporting results to $OUTPUT_FILE..."
run cargo bench --features benches --no-run --message-format=json > "$OUTPUT_FILE" 2>&1 || true

echo -e "\n[OK] Optimization Benchmarks Complete"
json_end "$JSON"
