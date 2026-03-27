#!/usr/bin/env bash
# Description: Unified FEC benchmark dispatcher (TODO-174 Phase 2).
#
# Consolidates all FEC-related benchmark scripts behind a single entry point.
# Use --mode to select which benchmark dimension to run, or omit it to run all.
#
# Modes:
#   unit         - FEC unit benchmarks (encoder, decoder, adaptive, Rayon, XOR)
#   simulation   - FEC simulation benchmarks (parameter matrix: mode x loss x threads)
#   smoke        - Quick FEC benchmark sanity check (delegates to simulation --fast)
#   all          - Run all modes sequentially (default)
#
# All flags after --mode are passed through to the underlying script.
# Common pass-through flags: --output-dir, --fast, --full, --verbose
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MODE="all"
PASSTHROUGH_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="$2"
      shift 2
      ;;
    --help|-h)
      cat <<'EOF'
Usage: bench-fec-all.sh [--mode MODE] [passthrough-flags...]

Unified FEC benchmark dispatcher. Runs one or all FEC benchmark dimensions.

Modes:
  unit         FEC unit benchmarks (cargo bench: encoder, decoder, adaptive, XOR)
  simulation   FEC simulation benchmarks (timed test matrix)
  smoke        Quick FEC benchmark sanity check
  all          Run all modes sequentially (default)

All other flags are passed through to the underlying script.
Common flags: --output-dir DIR, --fast, --full, --verbose
EOF
      exit 0
      ;;
    *)
      PASSTHROUGH_ARGS+=("$1")
      shift
      ;;
  esac
done

resolve_script() {
  case "$1" in
    unit)       echo "$SCRIPT_DIR/bench-fec.sh" ;;
    simulation) echo "$SCRIPT_DIR/bench-fec-simulation.sh" ;;
    smoke)      echo "$SCRIPT_DIR/bench-fec-simulation.sh" ;;
    *)          echo "" ;;
  esac
}

if [[ "$MODE" != "all" ]]; then
  SCRIPT="$(resolve_script "$MODE")"
  if [[ -z "$SCRIPT" ]]; then
    echo "Unknown mode: $MODE" >&2
    echo "Valid modes: unit, simulation, smoke, all" >&2
    exit 2
  fi
  exec bash "$SCRIPT" "${PASSTHROUGH_ARGS[@]}"
fi

# all mode: run each dimension sequentially, collect results
echo "==============================================================="
echo "  FEC Unified Benchmark Suite - All Modes"
echo "==============================================================="

FAILURES=0
MODES_RUN=0

for m in smoke unit simulation; do
  SCRIPT="$(resolve_script "$m")"
  echo ""
  echo "--- [$m] $(basename "$SCRIPT") ---"
  MODES_RUN=$((MODES_RUN + 1))
  # smoke runs bench-fec-simulation.sh in fast mode to avoid full duplication with simulation
  EXTRA_ARGS=()
  if [[ "$m" == "smoke" ]]; then EXTRA_ARGS=(--fast); fi
  if bash "$SCRIPT" "${EXTRA_ARGS[@]}" "${PASSTHROUGH_ARGS[@]}"; then
    echo "--- [$m] OK ---"
  else
    echo "--- [$m] FAILED ---"
    FAILURES=$((FAILURES + 1))
  fi
done

echo ""
echo "==============================================================="
echo "  FEC Unified Bench Summary: $((MODES_RUN - FAILURES))/$MODES_RUN passed"
echo "==============================================================="

if [[ $FAILURES -gt 0 ]]; then
  echo "[FAIL] $FAILURES FEC bench mode(s) failed"
  exit 1
fi

echo "[OK] All FEC bench modes passed"
exit 0
