#!/usr/bin/env bash
# Description: Retained crypto backend evidence runner.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
source "$SCRIPT_DIR/../../tests/lib/lib-common.sh" || { echo "ERROR: lib-common.sh not found" >&2; exit 1; }

OUTPUT_DIR=""
FAST=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --fast) FAST=1;;
    --help|-h)
      echo "Usage: $(basename "$0") [--output-dir DIR] [--fast]"
      exit 0
      ;;
    *)
      echo "Unknown flag: $1" >&2
      exit 2
      ;;
  esac
  shift
done

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/benchmarks/bench-retained-crypto-backends-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
SUMMARY_FILE="$OUTPUT_DIR/summary.txt"
CSV_FILE="$OUTPUT_DIR/results.csv"

if (( FAST )); then
  SIZES=("1200B" "16KiB" "64KiB")
  ITERS=200
else
  SIZES=("1200B" "4KiB" "16KiB" "64KiB")
  ITERS=1000
fi

BACKENDS=("aegis128l" "aegis128x4" "aegis128x8" "morus")

echo "suite=bench-retained-crypto-backends" > "$SUMMARY_FILE"
echo "output_dir=$OUTPUT_DIR" >> "$SUMMARY_FILE"
echo "iters=$ITERS" >> "$SUMMARY_FILE"
echo "sizes=${SIZES[*]}" >> "$SUMMARY_FILE"

PROFILE_LINE="$(cargo run --release --features benches --quiet --example crypto_backend_bench -- profile)"
echo "$PROFILE_LINE" > "$OUTPUT_DIR/profile.txt"
echo "$PROFILE_LINE" >> "$SUMMARY_FILE"

echo "backend,size,mbps,instantiations" > "$CSV_FILE"

run_one() {
  local backend="$1"
  local size="$2"
  local line
  line="$(cargo run --release --features benches --quiet --example crypto_backend_bench -- run "$backend" "$size" "$ITERS")"
  echo "$line" > "$OUTPUT_DIR/${backend}-${size}.txt"
  local mbps
  local instantiations
  mbps="$(echo "$line" | awk -F',' '{for(i=1;i<=NF;i++) if($i=="mbps") {print $(i+1)}}')"
  instantiations="$(echo "$line" | awk -F',' '{for(i=1;i<=NF;i++) if($i=="instantiations") {print $(i+1)}}')"
  echo "${backend},${size},${mbps},${instantiations}" >> "$CSV_FILE"
}

for size in "${SIZES[@]}"; do
  for backend in "${BACKENDS[@]}"; do
    run_one "$backend" "$size"
  done
done

python3 - "$CSV_FILE" "$SUMMARY_FILE" <<'PY'
import csv
import sys
from collections import defaultdict

csv_path, summary_path = sys.argv[1], sys.argv[2]
rows = list(csv.DictReader(open(csv_path, newline="")))
by_size = defaultdict(list)
for row in rows:
    by_size[row["size"]].append(row)

with open(summary_path, "a") as out:
    for size, items in by_size.items():
        best = max(items, key=lambda row: float(row["mbps"]))
        out.write(f"best_backend[{size}]={best['backend']}\n")
        out.write(f"best_mbps[{size}]={best['mbps']}\n")
PY

echo "ok=1" >> "$SUMMARY_FILE"
echo "failed=0" >> "$SUMMARY_FILE"
echo "$OUTPUT_DIR"
