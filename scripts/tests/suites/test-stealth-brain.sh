#!/usr/bin/env bash
# Description: Test suite runner: test-stealth-brain.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""; FAST=0; FULL=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --fast) FAST=1;;
    --full) FULL=1; FAST=0;;
    --jobs) JOBS="$2"; shift;;
    --features) CARGO_FEATURES="$2"; shift;;
    --rustflags) RUSTFLAGS_EXTRA="$2"; shift;;
    --dry-run) DRY_RUN=1;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h)
      echo "Usage: $(basename "$0") [options]"; echo "Stealth Brain Comprehensive Suite"; usage_common_flags 2>/dev/null || true; exit 0;;
    *) echo "Unknown flag: " >&2; exit 2;;
  esac; shift
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"; LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"

echo "===============================================================" | tee -a "$LOG_FILE"
echo "  Stealth + Brain Comprehensive Suite" | tee -a "$LOG_FILE"
echo "===============================================================" | tee -a "$LOG_FILE"
print_system_banner | tee -a "$LOG_FILE"

# Parameter matrix (affects StealthBrainConfig::from_env and Stealth behavior)
# Short default profile: broad enough to be informative, intentionally not exhaustive.
ACK_MAX=(6 12)
JITTER_US=(500 1500)
EXPLORE=(0.00 0.10)
PAD_MAX=(64 256)
if (( FULL )); then
  ACK_MAX=(6 8 12)
  JITTER_US=(500 1000 1500)
  EXPLORE=(0.00 0.02 0.10)
  PAD_MAX=(64 128 256)
fi
if (( FAST )); then
  ACK_MAX=(8); JITTER_US=(1000); EXPLORE=(0.02); PAD_MAX=(128)
fi

RESULTS_JSON="$OUTPUT_DIR/results.json"; json_begin "$RESULTS_JSON" "stealth_brain"; FIRST=true
TOTAL=0; PASS=0; FAIL=0

run_cargo_logged() {
  local envs="$1"
  shift
  if [[ -n "$envs" ]]; then
    # shellcheck disable=SC2206
    local env_array=($envs)
    run env "${env_array[@]}" cargo "$@"
  else
    run cargo "$@"
  fi
}

run_one() {
  local amax="$1" jut="$2" exp="$3" pmax="$4"
  local envs=(
    "QUICFUSCATE_BRAIN_ACK_MAX=${amax}"
    "QUICFUSCATE_BRAIN_JITTER_MAX_US=${jut}"
    "QUICFUSCATE_BRAIN_EXPLORE=${exp}"
    "QUICFUSCATE_STEALTH_MODE=stealth"
    "QUICFUSCATE_PADDING_STRATEGY=2" # Adaptive
  )

  echo -e "\n> ack_max=${amax}, jitter_us=${jut}, explore=${exp}, pad_max=${pmax}" | tee -a "$LOG_FILE"
  local start=$(date +%s); ok=1

  # Update padding maximum via runtime env mapped in config parsing where applicable
  # Fallback: use extra RUSTFLAGS to ensure optimized code path
  export RUSTFLAGS="${RUSTFLAGS_EXTRA:-}"

  # Stealth module unit-tests (in-module)
  if ! run_cargo_logged "${envs[*]} QUICFUSCATE_STEALTH_MAX_PADDING=${pmax}" test --release --lib stealth:: -- --nocapture >>"$LOG_FILE" 2>&1; then ok=0; fi

  # Brain-focused tests
  if ! run_cargo_logged "${envs[*]}" test --release --lib brain:: -- --nocapture >>"$LOG_FILE" 2>&1; then ok=0; fi

  # Run E2E brain probe example (logs rich metrics) if available
  METR="$OUTPUT_DIR/brain_metrics.txt"
  if run_cargo_logged "" run --release --example brain_probe -- --iters 50 --jitter 5ms >>"$METR" 2>&1; then
    # Extract metrics from trace line pattern
    # Capture ack_thr, pacing, jitter_us, ivl, red_ppm
    awk '/brain: policy/ {
      for (i=1;i<=NF;i++) {
        if ($i ~ /ack_thr=/) { split($i,a,"="); sub(/\*/,"",a[2]); print "ACK_THR " a[2]; }
        if ($i ~ /pacing=/) { split($i,a,"="); sub(/\*/,"",a[2]); print "PACING " a[2]; }
        if ($i ~ /ivl=/)    { split($i,a,"="); sub(/\*/,"",a[2]); print "IVL " a[2]; }
      }
    }' "$METR" > "$OUTPUT_DIR/brain_kv.txt" || true
    # Compute summary stats for ACK_THR
    ACK_SUM=0; ACK_CNT=0; ACK_MIN=999999; ACK_MAX=0
    while read -r k v; do
      if [[ "$k" == "ACK_THR" ]]; then
        n=${v%%[^0-9]*}
        [[ -z "$n" ]] && continue
        (( ACK_SUM += n )); (( ACK_CNT += 1 )); (( n < ACK_MIN )) && ACK_MIN=$n; (( n > ACK_MAX )) && ACK_MAX=$n
      fi
    done < "$OUTPUT_DIR/brain_kv.txt"
    if (( ACK_CNT > 0 )); then ACK_AVG=$((ACK_SUM/ACK_CNT)); else ACK_AVG=0; fi
  else
    echo "(brain_probe example not available or failed)" >>"$LOG_FILE"
    ACK_MIN=0; ACK_MAX=0; ACK_AVG=0
  fi

  local end=$(date +%s); local dur=$((end-start))
  TOTAL=$((TOTAL+1)); if (( ok )); then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi

  if [[ "$FIRST" == "true" ]]; then FIRST=false; else echo "," >> "$RESULTS_JSON"; fi
  echo -n '  {"ack_max":'$amax',"jitter_us":'$jut',"explore":'$exp',"pad_max":'$pmax',"duration_sec":'$dur',"ok":'$ok',"ack_thr_min":'$ACK_MIN',"ack_thr_max":'$ACK_MAX',"ack_thr_avg":'$ACK_AVG'}' >> "$RESULTS_JSON"
}

for a in "${ACK_MAX[@]}"; do
  for j in "${JITTER_US[@]}"; do
    for e in "${EXPLORE[@]}"; do
      for p in "${PAD_MAX[@]}"; do
        run_one "$a" "$j" "$e" "$p"
      done
    done
  done
done

json_end "$RESULTS_JSON"

echo -e "\n===============================================================" | tee -a "$LOG_FILE"
echo "  Stealth + Brain Summary" | tee -a "$LOG_FILE"
echo "===============================================================" | tee -a "$LOG_FILE"
echo "  Total runs:  $TOTAL" | tee -a "$LOG_FILE"
echo "  [OK] Passed:    $PASS" | tee -a "$LOG_FILE"
echo "  [FAIL] Failed:    $FAIL" | tee -a "$LOG_FILE"
echo "  Artifacts:   $OUTPUT_DIR" | tee -a "$LOG_FILE"

exit $(( FAIL > 0 ))
