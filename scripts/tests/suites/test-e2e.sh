#!/usr/bin/env bash
# Description: Test suite runner: test-e2e.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""; FAST=0; INTEGRATION=0; RUSTFLAGS_EXTRA=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --rustflags) RUSTFLAGS_EXTRA="$2"; shift;;
    --fast) FAST=1;;
    --integration) INTEGRATION=1;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h) echo "Usage: $(basename "$0") [--output-dir DIR] [--rustflags STR] [--fast] [--integration]"; exit 0;;
    *) break;;
  esac; shift
done
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"; LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"; exec > >(tee -a "$LOG_FILE") 2>&1
[[ -n "${RUSTFLAGS_EXTRA:-}" ]] && export RUSTFLAGS="${RUSTFLAGS_EXTRA} ${RUSTFLAGS:-}"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "tests_e2e_end2end"; JSON_FIRST_RUN=1

echo "==============================================================="
echo "  End-to-End (E2E) Scenario Tests"
echo "==============================================================="

run_case() {
  local name="$1"; shift
  local envs="$1"; shift
  local target="$1"; shift
  local pattern="$1"; shift
  echo -e "\n> $name"
  local -a env_keys=()
  local -a env_vals=()
  local -a env_set=()
  if [[ -n "$envs" ]]; then
    local -a env_pairs=()
    local IFS=' '
    read -r -a env_pairs <<< "$envs"
    for pair in "${env_pairs[@]}"; do
      local key="${pair%%=*}"
      local val="${pair#*=}"
      env_keys+=("$key")
      if [[ -n "${!key+x}" ]]; then
        env_set+=("1")
        env_vals+=("${!key}")
      else
        env_set+=("0")
        env_vals+=("")
      fi
      export "$key=$val"
    done
  fi

  local -a cmd=(cargo test --release)
  if [[ "$target" == "lib" ]]; then
    cmd+=(--lib "$pattern" -- --nocapture --test-threads=1)
  elif [[ "$target" == test:* ]]; then
    cmd+=(--features rust-tests --test "${target#test:}" "$pattern" -- --nocapture --test-threads=1)
  else
    echo "[FAIL] Unknown E2E target selector: $target"
    return 1
  fi

  local case_slug
  case_slug=$(printf "%s" "$name" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '_')
  local case_log="$OUTPUT_DIR/case_${case_slug}.log"

  set +e
  "${cmd[@]}" 2>&1 | tee "$case_log"
  local test_status=${PIPESTATUS[0]}
  set -e

  if [[ ${#env_keys[@]} -gt 0 ]]; then
    for i in "${!env_keys[@]}"; do
      if [[ "${env_set[$i]}" == "1" ]]; then
        export "${env_keys[$i]}=${env_vals[$i]}"
      else
        unset "${env_keys[$i]}"
      fi
    done
  fi

  if [[ "$test_status" -ne 0 ]]; then
    return "$test_status"
  fi

  if grep -q "^running 0 tests$" "$case_log"; then
    echo "[FAIL] $name resolved to zero tests (target=$target, pattern=$pattern)"
    return 1
  fi
}

# Baseline HTTP/3 request with QPACK Huffman
run_case "E2E HTTP/3 + QPACK Huffman" \
  "QUICFUSCATE_H3_MASQUERADE=1 QUICFUSCATE_QPACK=1" \
  "test:rt-harness-cli" \
  "harness_qpack_encode_runs_with_small_input"

# Server push pipeline end-to-end
run_case "E2E H3 Server Push (Promise->Headers->Data->FIN)" \
  "QUICFUSCATE_H3_MASQUERADE=1" \
  "test:it-stealth-mode-matrix" \
  "test_should_trigger_server_push_mode_matrix"

# Internal machine-room FEC streaming recovery under 6% loss
run_case "E2E Internal FEC Streaming @6% loss" \
  "QUICFUSCATE_FEC_INITIAL_MODE=streaming QUICFUSCATE_RS_LOSS=0.06 QUICFUSCATE_FEC_USE_ADAPTIVE=1" \
  "lib" \
  "test_streaming_tetrys_style_recovery_single_loss"

# Transport migration validation control-path
run_case "Transport Migration Validation Control Path" \
  "" \
  "test:rt-transport-connection" \
  "connection_migrate_emits_path_events_in_order"

# Zero-RTT
run_case "E2E 0-RTT Resume" \
  "" \
  "test:rt-transport-frames-roundtrip" \
  "ack_in_zero_rtt_is_invalid"

# Full-stack stealth
(( ! FAST )) && run_case "E2E Full-Stack Stealth" \
  "QUICFUSCATE_STEALTH_MODE=anti_dpi QUICFUSCATE_BROWSER=chrome QUICFUSCATE_OS=windows QUICFUSCATE_DOH=1 QUICFUSCATE_H3_MASQUERADE=1 QUICFUSCATE_STEALTH_PADDING=1" \
  "test:it-stealth-mode-matrix" \
  "test_mode_feature_matrix_core_expectations"

if (( INTEGRATION )); then
  run_case "E2E Client-Server Connection" \
    "" \
    "test:it-engine-control-plane" \
    "test_control_plane_start_stop_commands"

  run_case "E2E FEC (Adaptive Mode)" \
    "QUICFUSCATE_FEC_USE_ADAPTIVE=1 QUICFUSCATE_FEC_INITIAL_MODE=auto" \
    "lib" \
    "test_replayed_loss_trace_drives_end_to_end_adaptation"

  run_case "E2E Stealth Mode" \
    "QUICFUSCATE_STEALTH_MODE=anti_dpi QUICFUSCATE_BROWSER_PROFILE=chrome QUICFUSCATE_OS_PROFILE=windows" \
    "test:it-stealth-mode-matrix" \
    "test_anti_dpi_escalation_stack_is_cumulative_and_reversible"

  run_case "E2E Packet Loss (10%)" \
    "QUICFUSCATE_RS_LOSS=0.10" \
    "lib" \
    "test_long_running_mixed_loss_trace_stays_operational"

  run_case "E2E Performance Under Load" \
    "" \
    "lib" \
    "test_hotpath_perf_smoke_thresholds_pass"
fi

echo -e "\n[OK] E2E scenarios complete. Artifacts: $OUTPUT_DIR"
json_end "$JSON"
