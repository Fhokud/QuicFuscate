#!/usr/bin/env bash
# Description: Micro-benchmark runner: micro-udpfast-throughput.
set -euo pipefail

# Microbench: UDP fast-path throughput (loopback by default, optional LAN target)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../../tests/lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../../tests/lib/lib-common.sh"

OUTPUT_DIR=""
SIZE="1200"
ITERS=10000
BATCH=32
BIND="0.0.0.0:0"
REMOTE=""
FAST=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --size) SIZE="$2"; shift;;
    --iters) ITERS="$2"; shift;;
    --batch) BATCH="$2"; shift;;
    --bind) BIND="$2"; shift;;
    --remote) REMOTE="$2"; shift;;
    --fast) FAST=1;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h)
      echo "Usage: $(basename "$0") [--size N] [--iters N] [--batch N] [--bind IP:PORT] [--remote IP:PORT] [--fast]"
      usage_common_flags 2>/dev/null || true
      exit 0
      ;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac
  shift
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/benchmarks/${BASE_NAME}-${TIMESTAMP}"
ARTIFACTS_DIR="$(prepare_artifacts "$OUTPUT_DIR")"
LOG_FILE="$ARTIFACTS_DIR/${BASE_NAME}.log"; exec > >(tee -a "$LOG_FILE") 2>&1
RESULTS_JSON="$ARTIFACTS_DIR/${BASE_NAME}.json"; JSON="$RESULTS_JSON"; json_begin "$RESULTS_JSON" "$BASE_NAME"; JSON_FIRST_RUN=1

if [[ "$FAST" -eq 1 ]]; then
  ITERS=2000
  BATCH=16
fi

print_system_banner
info "UDP fast-path throughput: size=$SIZE bytes iters=$ITERS batch=$BATCH bind=$BIND"
if [[ -f "$RESULTS_JSON" ]]; then
  echo "  {\"meta\":{\"size\":$SIZE,\"iters\":$ITERS,\"batch\":$BATCH,\"bind\":\"$BIND\",\"remote\":\"$REMOTE\"}}" >> "$RESULTS_JSON"
  JSON_FIRST_RUN=0
fi

run_cargo build --release

RESULTS="$ARTIFACTS_DIR/${BASE_NAME}.txt"
if [[ -n "$REMOTE" ]]; then
  info "Running LAN mode (remote=$REMOTE)"
  run target/release/harness udp-throughput --size "$SIZE" --iters "$ITERS" --batch "$BATCH" --bind "$BIND" --remote "$REMOTE" | tee -a "$RESULTS"
else
  info "Running loopback mode (receiver spawned locally)"
  run target/release/harness udp-throughput --size "$SIZE" --iters "$ITERS" --batch "$BATCH" --bind "$BIND" | tee -a "$RESULTS"
fi

json_end "$RESULTS_JSON"
info "Results saved to: $ARTIFACTS_DIR"
