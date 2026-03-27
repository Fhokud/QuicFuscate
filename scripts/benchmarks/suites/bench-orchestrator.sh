#!/usr/bin/env bash
# Description: Benchmark suite runner: bench-orchestrator.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../../tests/lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../../tests/lib/lib-common.sh"

OUTPUT_DIR=""
FAST=0
DRY_RUN=0
SUITE_FILTER=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --fast) FAST=1;;
    --suite) SUITE_FILTER="$2"; shift;;
    --dry-run) DRY_RUN=1;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --list) LIST_ONLY=1;;
    --help|-h)
      echo "Usage: $(basename "$0") [options]"
      echo "Benchmark Orchestrator Suite"; usage_common_flags 2>/dev/null || true;
      echo "  --suite list     Comma-separated suite list (e.g., crypto,fec,transport)";
      echo "  --list           Print available suites";
      exit 0
      ;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac
  shift
 done

SUITE_CMDS=()
if (( FAST )); then
  SUITE_CMDS+=("micro-crypto-all:$SCRIPT_DIR/../micro/micro-crypto-all.sh --fast")
  SUITE_CMDS+=("fec-simulation-fast:$SCRIPT_DIR/bench-fec-simulation.sh --fast")
  SUITE_CMDS+=("transport:$SCRIPT_DIR/bench-transport.sh --fast")
  SUITE_CMDS+=("stealth:$SCRIPT_DIR/bench-stealth.sh --fast")
else
  SUITE_CMDS+=("crypto:$SCRIPT_DIR/bench-crypto.sh")
  SUITE_CMDS+=("fec:$SCRIPT_DIR/bench-fec.sh")
  SUITE_CMDS+=("transport:$SCRIPT_DIR/bench-transport.sh")
  SUITE_CMDS+=("compression:$SCRIPT_DIR/bench-compression.sh")
  SUITE_CMDS+=("optimization:$SCRIPT_DIR/bench-optimization.sh")
  SUITE_CMDS+=("stealth:$SCRIPT_DIR/bench-stealth.sh")
  SUITE_CMDS+=("stealth-brain:$SCRIPT_DIR/bench-stealth-brain.sh")
  SUITE_CMDS+=("qpack-encode:$SCRIPT_DIR/bench-qpack-encode.sh")
fi

if [[ -n "${LIST_ONLY:-}" ]]; then
  echo "Available suites:"
  for entry in "${SUITE_CMDS[@]}"; do
    echo "  - ${entry%%:*}"
  done
  exit 0
fi

if [[ -n "$SUITE_FILTER" ]]; then
  IFS=',' read -r -a requested <<< "$SUITE_FILTER"
  FILTERED=()
  for entry in "${SUITE_CMDS[@]}"; do
    name="${entry%%:*}"
    for want in "${requested[@]}"; do
      if [[ "$name" == "$want" ]]; then
        FILTERED+=("$entry")
        break
      fi
    done
  done
  SUITE_CMDS=("${FILTERED[@]}")
fi

if [[ ${#SUITE_CMDS[@]} -eq 0 ]]; then
  echo "No suites selected; exiting."
  exit 0
fi

RUN_TS="$(date +%Y%m%d_%H%M%S)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/benchmarks/bench-orchestrator-${RUN_TS}"
mkdir -p "$OUTPUT_DIR"
COMMANDS_FILE="$OUTPUT_DIR/commands.txt"
SUMMARY_FILE="$OUTPUT_DIR/summary.txt"
MANIFEST="$OUTPUT_DIR/manifest.json"

json_begin "$MANIFEST" "bench_orchestrator"
JSON_FIRST_RUN=1

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

append_item() {
  local name="$1"
  local cmd="$2"
  local rc="$3"
  local dur="$4"
  local log="$5"
  if [[ "$JSON_FIRST_RUN" -eq 0 ]]; then
    echo "," >> "$MANIFEST"
  fi
  JSON_FIRST_RUN=0
  local cmd_esc; cmd_esc=$(json_escape "$cmd")
  local log_esc; log_esc=$(json_escape "$log")
  echo -n "  {\"name\":\"${name}\",\"cmd\":\"${cmd_esc}\",\"rc\":${rc},\"duration_sec\":${dur},\"log\":\"${log_esc}\"}" >> "$MANIFEST"
}

print_system_banner
log "writing artifacts to ${OUTPUT_DIR}"

: > "$SUMMARY_FILE"

for entry in "${SUITE_CMDS[@]}"; do
  name="${entry%%:*}"
  cmd="${entry#*:}"
  suite_dir="$OUTPUT_DIR/${name}"
  mkdir -p "$suite_dir"
  echo "$cmd --output-dir $suite_dir" >> "$COMMANDS_FILE"

  log "running suite: ${name}"
  start_ts=$(date +%s)
  if (( DRY_RUN )); then
    echo "DRY-RUN: $cmd --output-dir $suite_dir"
    rc=0
  else
    bash -lc "$cmd --output-dir $suite_dir" > "$suite_dir/${name}.log" 2>&1
    rc=$?
  fi
  end_ts=$(date +%s)
  duration=$(( end_ts - start_ts ))
  append_item "$name" "$cmd --output-dir $suite_dir" "$rc" "$duration" "$suite_dir/${name}.log"
  printf '%s rc=%s duration=%ss\n' "$name" "$rc" "$duration" >> "$SUMMARY_FILE"
  if [[ "$rc" -ne 0 ]]; then
    warn "suite ${name} exited with rc=${rc}"
  else
    info "suite ${name} completed"
  fi
 done

json_end "$MANIFEST"

log "benchmark orchestrator finished"
