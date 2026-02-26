#!/usr/bin/env bash
# Description: Release readiness gate runner (clippy + audit + deny + geiger).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
SCRIPT_NAME="$(basename "$0" .sh)"

[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"
OUTPUT_DIR=""
STRICT_GEIGER=0

usage() {
  cat <<'USAGE'
Usage: audit-readiness-gates.sh [--output-dir DIR] [--strict-geiger]

Runs a deterministic readiness gate:
  1) cargo clippy --all-targets --all-features -- -D warnings
  2) cargo audit --json
  3) cargo deny check
  4) cargo geiger --package quicfuscate --all-targets --all-features --forbid-only --output-format Json

Options:
  --output-dir DIR      Output directory (default: scripts/out/audits/readiness-<timestamp>)
  --strict-geiger       Fail if geiger reports unsafe in any checked scope
  -h, --help            Show help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="${2:-}"; shift 2;;
    --strict-geiger) STRICT_GEIGER=1; shift;;
    -h|--help|help) usage; exit 0;;
    *) echo "Unknown flag: $1" >&2; usage; exit 2;;
  esac
done

require_cmd cargo
require_cmd cargo-audit
require_cmd cargo-deny
require_cmd cargo-geiger
require_cmd jq

TS="$(date +%Y%m%d_%H%M%S)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$PROJECT_ROOT/scripts/out/audits/$SCRIPT_NAME-$TS"
mkdir -p "$OUTPUT_DIR"

LOG_DIR="$OUTPUT_DIR/logs"
mkdir -p "$LOG_DIR"
CLIPPY_LOG="$LOG_DIR/cargo-clippy.log"
AUDIT_LOG="$LOG_DIR/cargo-audit.log"
AUDIT_JSON="$LOG_DIR/cargo-audit.json"
DENY_LOG="$LOG_DIR/cargo-deny.log"
GEIGER_JSON="$LOG_DIR/cargo-geiger.json"
GEIGER_LOG="$LOG_DIR/cargo-geiger.log"
SUMMARY="$OUTPUT_DIR/summary.txt"

touch "$SUMMARY"

TOTAL_CHECKS=0
FAILED_CHECKS=0

logkpi() {
  local check="$1"
  local status="$2"
  local details="$3"
  if [[ "$status" == "PASS" ]]; then
    echo "[PASS] $check: $details"
  elif [[ "$status" == "WARN" ]]; then
    echo "[WARN] $check: $details"
  else
    echo "[FAIL] $check: $details"
  fi
  printf '%s\t%s\t%s\n' "$check" "$status" "$details" >> "$SUMMARY"
}

run_success_or_fail() {
  local check="$1"; local log_path="$2"
  shift 2
  set +e
  "$@" > "$log_path" 2>&1
  local rc=$?
  set -e
  ((TOTAL_CHECKS += 1))
  if [[ $rc -eq 0 ]]; then
    logkpi "$check" "PASS" "command returned 0"
    return 0
  fi
  ((FAILED_CHECKS += 1))
  logkpi "$check" "FAIL" "command returned rc=$rc"
  return "$rc"
}

echo "==============================================================="
echo "  Quicfuscate upload-readiness gate"
echo "  Output: $OUTPUT_DIR"
echo "==============================================================="

{
  echo "---------------------------------------------------------------"
  echo "RUN START"
  date
  echo "Project root: $PROJECT_ROOT"
  echo "---------------------------------------------------------------"
} > "$SUMMARY"

# 1) Clippy strict
echo "[RUN] cargo clippy strict"
run_success_or_fail "ClippyStrict" "$CLIPPY_LOG" cargo clippy --all-targets --all-features -- -D warnings || true

# 2) cargo audit JSON
echo "[RUN] cargo audit JSON"
set +e
cargo audit --json > "$AUDIT_JSON" 2> "$AUDIT_LOG"
AUDIT_RC=$?
set -e
((TOTAL_CHECKS += 1))
if [[ $AUDIT_RC -ne 0 ]]; then
  ((FAILED_CHECKS += 1))
  logkpi "CargoAudit" "FAIL" "audit command returned rc=$AUDIT_RC"
else
  if ! jq -e . "$AUDIT_JSON" >/dev/null 2>&1; then
    ((FAILED_CHECKS += 1))
    logkpi "CargoAudit" "FAIL" "invalid audit JSON output"
  else
    AUDIT_VULN_FOUND="$(jq -r '.vulnerabilities.found // false' "$AUDIT_JSON")"
    AUDIT_VULN_COUNT="$(jq -r '.vulnerabilities.count // 0' "$AUDIT_JSON")"
    AUDIT_WARNING_IDS="$(jq -r '[
      (.warnings.unmaintained // []),
      (.warnings.unsound // []),
      (.warnings.notice // []),
      (.warnings.yanked // [])
    ] | add | map(.advisory.id) | unique | sort | join(", ")' "$AUDIT_JSON")"
    AUDIT_WARNING_COUNT="$(jq -r '[
      (.warnings.unmaintained // []),
      (.warnings.unsound // []),
      (.warnings.notice // []),
      (.warnings.yanked // [])
    ] | add | length' "$AUDIT_JSON")"
    if [[ "$AUDIT_VULN_FOUND" == "true" || "$AUDIT_VULN_COUNT" -gt 0 ]]; then
      ((FAILED_CHECKS += 1))
      logkpi "CargoAudit" "FAIL" "vulnerabilities found: count=$AUDIT_VULN_COUNT (found=$AUDIT_VULN_FOUND)"
    elif [[ "$AUDIT_WARNING_COUNT" -gt 0 ]]; then
      ((FAILED_CHECKS += 1))
      logkpi "CargoAudit" "FAIL" "informational warnings found: count=$AUDIT_WARNING_COUNT, ids=$AUDIT_WARNING_IDS"
    else
      logkpi "CargoAudit" "PASS" "no vulnerabilities or warnings"
    fi
  fi
fi
cat "$AUDIT_JSON" >> "$AUDIT_LOG"

# 3) deny
echo "[RUN] cargo deny check"
run_success_or_fail "CargoDeny" "$DENY_LOG" cargo deny check || true

# 4) geiger deterministic
echo "[RUN] cargo geiger strict"
set +e
cargo geiger --package quicfuscate --all-features --all-targets --forbid-only --output-format Json > "$GEIGER_JSON" 2>> "$GEIGER_LOG"
GEIGER_RC=$?
set -e
((TOTAL_CHECKS += 1))
if [[ $GEIGER_RC -ne 0 ]]; then
  if [[ $STRICT_GEIGER -eq 1 ]]; then
    ((FAILED_CHECKS += 1))
    logkpi "CargoGeiger" "FAIL" "command failed rc=$GEIGER_RC"
  else
    logkpi "CargoGeiger" "WARN" "command failed rc=$GEIGER_RC (non-blocking without --strict-geiger)"
  fi
else
  if ! jq -e . "$GEIGER_JSON" >/dev/null 2>&1; then
    ((FAILED_CHECKS += 1))
    logkpi "CargoGeiger" "FAIL" "invalid geiger JSON output"
  else
    GEIGER_ROOT_UNSAFE="$(jq -r '[.packages[] | select(.package.id.name == "quicfuscate")] | first | .forbids_unsafe // false' "$GEIGER_JSON")"
    GEIGER_UNSAFE_DEPS="$(jq -r '[.packages[] | select(.forbids_unsafe and .package.id.name != "quicfuscate")] | length' "$GEIGER_JSON")"
    if [[ "$GEIGER_ROOT_UNSAFE" == "true" ]]; then
      ((FAILED_CHECKS += 1))
      logkpi "CargoGeiger" "FAIL" "root crate allows unsafe-by-design"
    elif [[ "$STRICT_GEIGER" -eq 1 && "$GEIGER_UNSAFE_DEPS" -gt 0 ]]; then
      ((FAILED_CHECKS += 1))
      logkpi "CargoGeiger" "FAIL" "strict mode blocked: dependency unsafe count=$GEIGER_UNSAFE_DEPS"
    else
      logkpi "CargoGeiger" "PASS" "root crate has no unsafe-invoking API in deny-only mode; dependency unsafe count=$GEIGER_UNSAFE_DEPS"
    fi
  fi
fi
cat "$GEIGER_JSON" >> "$GEIGER_LOG"

{
  echo "---------------------------------------------------------------"
  echo "RUN END"
  date
  echo "Total checks: $TOTAL_CHECKS"
  echo "Failed: $FAILED_CHECKS"
  if [[ "$FAILED_CHECKS" -eq 0 ]]; then
    echo "Result: PASS"
  elif [[ "$FAILED_CHECKS" -lt "$TOTAL_CHECKS" ]]; then
    echo "Result: PARTIAL"
  else
    echo "Result: FAIL"
  fi
  echo "---------------------------------------------------------------"
} >> "$SUMMARY"

cat "$SUMMARY"

if [[ "$FAILED_CHECKS" -ne 0 ]]; then
  exit 1
fi

exit 0
