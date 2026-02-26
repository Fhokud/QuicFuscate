#!/usr/bin/env bash
# Description: Analysis helper: analysis-coverage-summary.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""; FAST=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --fast) FAST=1;;
    --dry-run) DRY_RUN=1;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h) echo "Usage: $(basename "$0") [--output-dir DIR] [--fast]"; exit 0;;
    *) break;;
  esac; shift
done
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/audits/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"; LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"; exec > >(tee -a "$LOG_FILE") 2>&1
RESULTS_JSON="$OUTPUT_DIR/results.json"; json_begin "$RESULTS_JSON" "analysis_coverage"; JSON_FIRST_RUN=1

echo "==============================================================="
echo "  Coverage Summary"
echo "==============================================================="

if command -v cargo-llvm-cov >/dev/null 2>&1; then
  info "Using cargo-llvm-cov"
  run cargo llvm-cov clean --workspace
  run cargo llvm-cov --summary-only --workspace --lcov --output-path "$OUTPUT_DIR/lcov.info"
  run cargo llvm-cov report --summary-only --workspace | tee "$OUTPUT_DIR/coverage.txt"
  # Append a JSON item with the summary line
  if [[ -f "$OUTPUT_DIR/coverage.txt" ]]; then
    summary=$(tail -n 1 "$OUTPUT_DIR/coverage.txt" | sed 's/"/\"/g')
    if [[ $JSON_FIRST_RUN -eq 0 ]]; then echo "," >> "$RESULTS_JSON"; fi; JSON_FIRST_RUN=0
    echo -n '  {"summary":'"\"$summary\""'}' >> "$RESULTS_JSON"
  fi
else
  warn "cargo-llvm-cov not installed; falling back to simple stats"
  run_cargo test --quiet
  require_cmd rg
  # Simple proxy metric: ratio of test fns to total fns
  total_fns=$(rg -N "^\s*(pub\s+)?(async\s+)?fn\s+" src -n --color=never | wc -l | tr -d ' ')
  test_fns=$(rg -N "#\[(tokio::)?test\b" src scripts/tests/rust -n --color=never | wc -l | tr -d ' ')
  echo "Total functions: $total_fns" | tee "$OUTPUT_DIR/coverage.txt"
  echo "Test functions:  $test_fns" | tee -a "$OUTPUT_DIR/coverage.txt"
  if [[ $JSON_FIRST_RUN -eq 0 ]]; then echo "," >> "$RESULTS_JSON"; fi; JSON_FIRST_RUN=0
  echo -n '  {"total_functions":'"$total_fns"',"test_functions":'"$test_fns"'}' >> "$RESULTS_JSON"
fi

echo -e "\nArtifacts: $OUTPUT_DIR"
json_end "$RESULTS_JSON"
