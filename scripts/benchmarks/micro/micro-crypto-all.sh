#!/usr/bin/env bash
# Description: Micro-benchmark runner: micro-crypto-all.
set -euo pipefail

# Microbench Suite (Crypto): AES block, GHASH, AES-GCM, ChaCha x4
# Consistent with existing scripts: uses scripts/tests/lib/lib-common.sh, scripts/out paths, flags

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../../tests/lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../../tests/lib/lib-common.sh"

# Defaults
ITERS=500
SIZES=(256B 1KiB 16KiB 1MiB)
OUTPUT_DIR=""
DRY_RUN=""
RUSTFLAGS_EXTRA=""
CARGO_FEATURES="benches"
JOBS=""
FAST=0

# Flags
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --iters) ITERS="$2"; shift;;
    --sizes) shift; SIZES=( ); while [[ $# -gt 0 ]] && [[ ! "$1" =~ ^-- ]]; do SIZES+=("$1"); shift; done; continue;;
    --dry-run) DRY_RUN=1;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --features) CARGO_FEATURES="$2"; shift;;
    --jobs) JOBS="$2"; shift;;
    --rustflags) RUSTFLAGS_EXTRA="$2"; shift;;
    --fast) FAST=1;;
    --help|-h) echo "Usage: $(basename "$0") [--output-dir DIR] [--iters N] [--sizes <list>]"; usage_common_flags 2>/dev/null || true; exit 0;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac; shift
done

if [[ "$FAST" -eq 1 ]]; then
  SIZES=(256B 16KiB)
  ITERS=200
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/benchmarks/${BASE_NAME}-${TIMESTAMP}"
ARTIFACTS_DIR="$(prepare_artifacts "$OUTPUT_DIR")"
LOG_FILE="$ARTIFACTS_DIR/${BASE_NAME}.log"; exec > >(tee -a "$LOG_FILE") 2>&1
RESULTS_JSON="$ARTIFACTS_DIR/results.json"; json_begin "$RESULTS_JSON" "$BASE_NAME"; JSON_FIRST_RUN=1
OUT_CSV="$ARTIFACTS_DIR/microbench.csv"

print_system_banner
info "Microbench sizes: ${SIZES[*]} | iters=$ITERS"
if [[ -f "$RESULTS_JSON" ]]; then
  echo "  {\"meta\":{\"iters\":$ITERS,\"sizes\":\"${SIZES[*]}\",\"fast\":$FAST}}" >> "$RESULTS_JSON"
  JSON_FIRST_RUN=0
fi

echo "ts,$(date -Iseconds)" | tee "$OUT_CSV" >/dev/null

microbench_run() {
  local kind="$1"; shift
  local envs=( )
  [[ -n "$RUSTFLAGS_EXTRA" ]] && envs+=("RUSTFLAGS=${RUSTFLAGS_EXTRA}")
  local cmd=(cargo run --release -q)
  [[ -n "$CARGO_FEATURES" ]] && cmd+=(--features "$CARGO_FEATURES")
  [[ -n "$JOBS" ]] && cmd+=(-j "$JOBS")
  cmd+=(--example microbench -- "$kind" "$@")
  if [[ -n "$DRY_RUN" ]]; then
    echo "DRY-RUN: ${cmd[*]}"
    return 0
  fi
  run env "${envs[@]}" "${cmd[@]}"
}

microbench_capture() {
  local kind="$1"; shift
  local envs=( )
  [[ -n "$RUSTFLAGS_EXTRA" ]] && envs+=("RUSTFLAGS=${RUSTFLAGS_EXTRA}")
  local cmd=(cargo run --release -q)
  [[ -n "$CARGO_FEATURES" ]] && cmd+=(--features "$CARGO_FEATURES")
  [[ -n "$JOBS" ]] && cmd+=(-j "$JOBS")
  cmd+=(--example microbench -- "$kind" "$@")
  if [[ -n "$DRY_RUN" ]]; then
    echo "DRY-RUN ${cmd[*]}"
    return 0
  fi
  env "${envs[@]}" "${cmd[@]}"
}

PROFILE_LINE="$(microbench_capture profile)"
info "CPU profile: $PROFILE_LINE"
echo "$PROFILE_LINE" | tee -a "$OUT_CSV" >/dev/null
if [[ -f "$RESULTS_JSON" ]]; then
  if [[ "$JSON_FIRST_RUN" -eq 0 ]]; then echo "," >> "$RESULTS_JSON"; fi; JSON_FIRST_RUN=0
  echo "  {\"profile_info\": \"$PROFILE_LINE\"}" >> "$RESULTS_JSON"
fi

for sz in "${SIZES[@]}"; do
  info "Running microbenches for size=$sz, iters=$ITERS"
  microbench_run aes-block "$sz" "$ITERS"   | tee -a "$OUT_CSV"
  microbench_run ghash     "$sz" "$ITERS"   | tee -a "$OUT_CSV"
  microbench_run aes-gcm   "$sz" "$ITERS"   | tee -a "$OUT_CSV"
  microbench_run chacha-x4 "$sz" "$ITERS"   | tee -a "$OUT_CSV"
  microbench_run morus-enc "$sz" "$ITERS"   | tee -a "$OUT_CSV"
  microbench_run morus-dec "$sz" "$ITERS"   | tee -a "$OUT_CSV"
  microbench_run poly1305-mac "$sz" "$ITERS" | tee -a "$OUT_CSV"
  microbench_run sha256    "$sz" "$ITERS"   | tee -a "$OUT_CSV"
  microbench_run hmac-sha256 "$sz" "$ITERS" | tee -a "$OUT_CSV"
  echo "---" | tee -a "$OUT_CSV"
  if [[ -f "$RESULTS_JSON" ]]; then
    if [[ "$JSON_FIRST_RUN" -eq 0 ]]; then echo "," >> "$RESULTS_JSON"; fi; JSON_FIRST_RUN=0
    echo -n '  {"size":"'"$sz"'","iters":'"$ITERS"',"csv":"microbench.csv"}' >> "$RESULTS_JSON"
  fi
done

json_end "$RESULTS_JSON"
info "Results saved to: $ARTIFACTS_DIR"
