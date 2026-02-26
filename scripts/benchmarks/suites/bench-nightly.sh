#!/usr/bin/env bash
# Description: Benchmark suite runner: bench-nightly.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
cd "${PROJECT_ROOT}"
[[ -f "$SCRIPT_DIR/../../tests/lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../../tests/lib/lib-common.sh"

OUTPUT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --dry-run) DRY_RUN=1;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h) echo "Usage: $(basename "$0") [--output-dir DIR]"; exit 0;;
    *) echo "Unknown flag: " >&2; exit 2;;
  esac
  shift
done

RUN_TS="$(date +%Y%m%d-%H%M%S)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/benchmarks/bench-nightly-${RUN_TS}"
ARTIFACT_DIR="$OUTPUT_DIR"
mkdir -p "${ARTIFACT_DIR}"
COMMANDS_FILE="${ARTIFACT_DIR}/commands.txt"
LOG_FILE="${ARTIFACT_DIR}/bench-nightly.log"
RESULTS_JSON="${ARTIFACT_DIR}/results.json"; json_begin "$RESULTS_JSON" "bench_nightly"; JSON_FIRST_RUN=1

# Default bench scripts (ordered by priority)
BENCH_SCRIPTS=(
  "${SCRIPT_DIR}/../micro/micro-crypto-all.sh --fast"
  "${SCRIPT_DIR}/../smoke/smoke-fec-quick.sh"
  "${SCRIPT_DIR}/bench-transport.sh --fast"
  "${SCRIPT_DIR}/bench-stealth.sh --fast"
)

log "writing artifacts to ${ARTIFACT_DIR}"

for cmd in "${BENCH_SCRIPTS[@]}"; do
  script_path="${cmd%% *}"
  script_name="$(basename "${script_path}" .sh)"
  suite_dir="${ARTIFACT_DIR}/${script_name}"
  script_args=()
  if [[ "$cmd" != "$script_path" ]]; then
    read -r -a script_args <<< "${cmd#"$script_path"}"
  fi

  mkdir -p "$suite_dir"
  echo "${script_path} --output-dir ${suite_dir} ${script_args[*]}" >> "${COMMANDS_FILE}"
  log "running ${cmd}"
  if [[ -n "${DRY_RUN:-}" ]]; then
    echo "DRY-RUN: ${script_path} --output-dir ${suite_dir} ${script_args[*]}"
  else
    run "$script_path" --output-dir "$suite_dir" "${script_args[@]}"
  fi
  log "completed ${cmd}"
 done

log "nightly bench suite finished"
json_end "$RESULTS_JSON"
