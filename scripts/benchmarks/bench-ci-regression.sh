#!/usr/bin/env bash
# Description: Benchmark regression gate for criterion output.
# Two-tier thresholds: WARN_THRESHOLD (soft) and ERROR_THRESHOLD (hard).
# Designed for CI use with GitHub Job Summary output.

set -euo pipefail

BASELINE="main"
WARN_THRESHOLD=15
ERROR_THRESHOLD=30

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help|help)
      cat <<'EOF'
Usage: bench-ci-regression.sh [--baseline NAME] [--warn PERCENT] [--error PERCENT]

Runs criterion benchmarks and compares them against a named baseline.

Options:
  --baseline   Name of the baseline to compare against (default: main)
  --warn       Warning threshold percentage (default: 15)
  --error      Error threshold percentage (default: 30)

Exit codes:
  0  All benchmarks within warning threshold
  1  At least one benchmark exceeds error threshold
  2  Infrastructure failure (missing tools, build failure)
EOF
      exit 0
      ;;
    --baseline)  BASELINE="$2"; shift 2 ;;
    --warn)      WARN_THRESHOLD="$2"; shift 2 ;;
    --error)     ERROR_THRESHOLD="$2"; shift 2 ;;
    *)           echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

# Detect GitHub Actions environment for job summary output
SUMMARY_FILE="${GITHUB_STEP_SUMMARY:-}"

summary() {
  echo "$1"
  if [[ -n "$SUMMARY_FILE" ]]; then
    echo "$1" >> "$SUMMARY_FILE"
  fi
}

if ! cargo bench --bench ci_regression --features benches --no-run 2>/dev/null; then
  echo "[SKIP] No criterion bench targets found; skipping CI regression benchmarks."
  exit 0
fi

echo "=== QuicFuscate CI Benchmark Regression Detection ==="
echo "Baseline:        $BASELINE"
echo "Warn threshold:  ${WARN_THRESHOLD}%"
echo "Error threshold: ${ERROR_THRESHOLD}%"
echo ""

# Ensure critcmp is available
if ! command -v critcmp &>/dev/null; then
  echo "Installing critcmp..."
  cargo install critcmp --locked 2>/dev/null || {
    echo "ERROR: Failed to install critcmp" >&2
    exit 2
  }
fi

# Run benchmarks and save as current PR baseline
echo "Running benchmarks..."
cargo bench --bench ci_regression --features benches -- --save-baseline pr 2>&1 || {
  echo "ERROR: cargo bench failed" >&2
  exit 2
}

# Compare against baseline if it exists
BASELINE_DIR="target/criterion/${BASELINE}"
if [[ ! -d "$BASELINE_DIR" ]]; then
  echo "WARNING: No baseline '$BASELINE' found. Saving current run as baseline."
  cargo bench --bench ci_regression --features benches -- --save-baseline "$BASELINE" 2>&1 || true
  summary "## Benchmark Results"
  summary ""
  summary "Baseline \`$BASELINE\` created (first run). No comparison possible."
  exit 0
fi

echo ""
echo "Comparing against baseline '$BASELINE'..."
echo ""

# Run critcmp and capture output
COMPARISON=$(critcmp "$BASELINE" pr 2>&1) || {
  echo "ERROR: critcmp failed" >&2
  exit 2
}

echo "$COMPARISON"
echo ""

# Parse critcmp output for regressions exceeding thresholds
# critcmp outputs lines like: "bench_name  baseline: 100.0 ns  pr: 115.0 ns  (+15.00%)"
WARN_COUNT=0
ERROR_COUNT=0
WARN_LINES=""
ERROR_LINES=""

while IFS= read -r line; do
  if echo "$line" | grep -qE '\+[0-9]+\.[0-9]+%'; then
    PCT=$(echo "$line" | grep -oE '\+[0-9]+\.[0-9]+' | head -1 | tr -d '+')
    if [[ -z "$PCT" ]]; then
      continue
    fi
    IS_ERROR=$(echo "$PCT >= $ERROR_THRESHOLD" | bc -l 2>/dev/null || echo 0)
    IS_WARN=$(echo "$PCT >= $WARN_THRESHOLD" | bc -l 2>/dev/null || echo 0)
    if [[ "$IS_ERROR" == "1" ]]; then
      echo "ERROR: $line (exceeds ${ERROR_THRESHOLD}% error threshold)"
      ERROR_COUNT=$((ERROR_COUNT + 1))
      ERROR_LINES="${ERROR_LINES}${line}\n"
    elif [[ "$IS_WARN" == "1" ]]; then
      echo "WARNING: $line (exceeds ${WARN_THRESHOLD}% warn threshold)"
      WARN_COUNT=$((WARN_COUNT + 1))
      WARN_LINES="${WARN_LINES}${line}\n"
    fi
  fi
done <<< "$COMPARISON"

# Write GitHub Job Summary
summary "## Benchmark Regression Report"
summary ""
summary "| Metric | Value |"
summary "|--------|-------|"
summary "| Baseline | \`$BASELINE\` |"
summary "| Warn threshold | ${WARN_THRESHOLD}% |"
summary "| Error threshold | ${ERROR_THRESHOLD}% |"
summary "| Warnings | $WARN_COUNT |"
summary "| Errors | $ERROR_COUNT |"
summary ""

if [[ "$ERROR_COUNT" -gt 0 ]]; then
  summary "### Regressions exceeding ${ERROR_THRESHOLD}% (ERROR)"
  summary ""
  summary '```'
  summary "$(echo -e "$ERROR_LINES")"
  summary '```'
  summary ""
fi

if [[ "$WARN_COUNT" -gt 0 ]]; then
  summary "### Regressions exceeding ${WARN_THRESHOLD}% (WARNING)"
  summary ""
  summary '```'
  summary "$(echo -e "$WARN_LINES")"
  summary '```'
  summary ""
fi

if [[ "$ERROR_COUNT" -gt 0 ]]; then
  summary "**FAIL**: $ERROR_COUNT benchmark(s) exceeded ${ERROR_THRESHOLD}% error threshold."
  exit 1
fi

if [[ "$WARN_COUNT" -gt 0 ]]; then
  summary "**WARN**: $WARN_COUNT benchmark(s) exceeded ${WARN_THRESHOLD}% warn threshold (soft fail)."
  exit 0
fi

summary "**PASS**: All benchmarks within ${WARN_THRESHOLD}% threshold."
exit 0
