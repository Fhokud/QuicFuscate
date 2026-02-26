#!/usr/bin/env bash
# Description: Benchmark suite runner: bench-stealth.
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
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h) echo "Usage: $(basename "$0") [--output-dir DIR] [--rustflags STR] [--fast]"; exit 0;;
    *) break;;
  esac; shift
done
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/benchmarks/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"; LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"; exec > >(tee -a "$LOG_FILE") 2>&1
[[ -n "${RUSTFLAGS_EXTRA:-}" ]] && export RUSTFLAGS="${RUSTFLAGS_EXTRA} ${RUSTFLAGS:-}"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "bench_stealth_all"; JSON_FIRST_RUN=1

echo "==============================================================="
echo "  Stealth & Masquerading Benchmarks"
echo "==============================================================="

# Skip gracefully if bench harness absent
if ! cargo bench --no-run --features benches >/dev/null 2>&1; then
  echo "No Rust benches detected; skipping stealth benches."
  if [[ $JSON_FIRST_RUN -eq 0 ]]; then echo "," >> "$JSON"; fi; JSON_FIRST_RUN=0
  echo -n '  {"status":"skipped","reason":"no_rust_benches"}' >> "$JSON"
  json_end "$JSON"
  exit 0
fi

# Build benches
run_cargo build --release --features benches

run_bench() {
  local name="$1"; shift
  local pattern="$1"; shift
  local envs="${1:-}"; shift || true
  local outfile="$OUTPUT_DIR/${name}.txt"
  echo -e "\n> $name"
  if [[ -n "$envs" ]]; then
    run env $envs cargo bench --features benches -- "$pattern" 2>&1 | tee "$outfile"
  else
    run cargo bench --features benches -- "$pattern" 2>&1 | tee "$outfile"
  fi
}

# Core stealth benches (if available in repo)
run_bench "Padding_Generation" "padding_gen" "QUICFUSCATE_STEALTH_PADDING=1"
run_bench "XOR_Obfuscation" "xor_obfuscate" "QUICFUSCATE_XOR_KEY=0123456789abcdef0123456789abcdef"
run_bench "Fingerprint_Rotation" "fingerprint" "QUICFUSCATE_FINGERPRINT_ROTATION_INTERVAL=30"
(( ! FAST )) && run_bench "Browser_Mimicry" "browser_mimic" "QUICFUSCATE_BROWSER_PROFILE=chrome QUICFUSCATE_OS_PROFILE=windows"

# Masquerade & HTTP/3 related (if implemented as benches)
(( ! FAST )) && run_bench "QPACK_Huffman" "qpack_huffman"
(( ! FAST )) && run_bench "H3_Headers_Encode" "h3_headers"

# Summary
echo -e "\nSummary (last metrics):"
grep -E "time:.*\[.*\]|thrpt:.*\[.*\]" "$OUTPUT_DIR"/*.txt 2>/dev/null | tail -20 || true

echo -e "\n[OK] Stealth benchmarks complete. Artifacts: $OUTPUT_DIR"
json_end "$JSON"
