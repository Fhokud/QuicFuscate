#!/usr/bin/env bash
# Description: Build helper: build-env-doctor.
set -euo pipefail

# Environment diagnostics and toolchain verification.
# Shows CPU/OS/toolchain/time availability and QUICFUSCATE_* env.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

SCRIPT_NAME="$(basename "$0")"
DESC="$(grep -m1 '^# Description:' "$0" | sed 's/^# Description:[[:space:]]*//')"
print_help() { echo "Usage: $SCRIPT_NAME"; [ -n "$DESC" ] && echo "$DESC"; exit 0; }

OUTPUT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1; set -x;;
    --help|-h) print_help;;
    *) break;;
  esac; shift
done
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/build/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"; LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"; exec > >(tee -a "$LOG_FILE") 2>&1
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "build_env_doctor"; JSON_FIRST_RUN=1

# Resolve repo root (this script lives at scripts/tests/build/, so three levels up)
ROOT_DIR="$(cd "$(dirname "$0")/../../.." && pwd -P)"
cd "$ROOT_DIR"

echo '=== Host Info ==='
uname -a || true
sysctl -n machdep.cpu.brand_string 2>/dev/null || lscpu 2>/dev/null || true

echo '=== Toolchain ==='
rustc -V || true
cargo -V || true
if command -v gtime >/dev/null 2>&1; then echo 'gtime: OK'; else echo 'gtime: missing'; fi
if /usr/bin/time -v true >/dev/null 2>&1; then echo '/usr/bin/time -v: OK'; else echo '/usr/bin/time -v: missing or unsupported'; fi

echo '=== Env (QUICFUSCATE_*) ==='
env | grep -E '^QUICFUSCATE_' || echo '(none)'
json_end "$JSON"
