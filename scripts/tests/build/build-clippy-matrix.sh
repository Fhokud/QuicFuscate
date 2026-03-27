#!/usr/bin/env bash
# Description: Build helper: build-clippy-matrix.
set -euo pipefail

# QuicFuscate Clippy Matrix - Comprehensive lint check.
# Ensures all feature combinations compile without warnings.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || "${1:-}" == "help" ]]; then
  cat <<'EOF'
Usage: build-clippy-matrix.sh

Runs the project clippy matrix over core feature combinations and fails on warnings.
EOF
  exit 0
fi
if [[ $# -gt 0 ]]; then
  echo "Unknown argument: $1" >&2
  exit 2
fi

# Do not exit on first failure; collect all and report at the end
set +e

echo "[INFO] QuicFuscate Clippy Matrix - Starting comprehensive lint checks..."
echo "=================================================================="

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track failures
FAILURES=0
TOTAL_CHECKS=0

# Function to run clippy check
run_clippy_check() {
    local feature_args="$1"
    local description="$2"
    
    echo -n "Testing: $description ... "
    
    if cargo clippy --all-targets $feature_args -- -D warnings; then
        echo -e "${GREEN}OK PASS${NC}"
    else
        echo -e "${RED}FAIL FAIL${NC}"
        ((FAILURES += 1))
    fi
    ((TOTAL_CHECKS += 1))
}

echo "[INFO] Working directory: $(pwd)"
echo "[INFO] Rust version: $(rustc --version)"
echo ""

# Run clippy matrix
echo "[INFO] Running clippy matrix..."
echo ""

run_clippy_check "" "Base configuration"
run_clippy_check "--features internal_wiedemann" "Internal Wiedemann"
run_clippy_check "--features unsafe_rust" "Unsafe Rust"
run_clippy_check "--features unsafe_rust,compression_zstd_ffi" "Unsafe Rust + Zstd FFI"
run_clippy_check "--features simd-selfcheck" "SIMD self-check"
run_clippy_check "--features orchestrator" "Orchestrator"
run_clippy_check "--features orchestrator,rate_limiter" "Orchestrator + Rate limiter"
run_clippy_check "--features sse2,simd-selfcheck" "SSE2 + SIMD self-check"
run_clippy_check "--features vaes,simd-selfcheck" "VAES + SIMD self-check"

echo ""
echo "=================================================================="
echo "[INFO] CLIPPY MATRIX RESULTS:"
echo "   Total checks: $TOTAL_CHECKS"
echo -e "   Passed: $((TOTAL_CHECKS - FAILURES)) ${GREEN}OK${NC}"
echo -e "   Failed: $FAILURES ${RED}FAIL${NC}"

if [ $FAILURES -eq 0 ]; then
    echo -e "\n[OK] ${GREEN}All clippy checks passed!${NC}"
    echo "[INFO] Codebase is lint-clean across all feature combinations."
    exit 0
else
    echo -e "\n[FAIL] ${RED}Clippy matrix detected $FAILURES failure(s).${NC}"
    echo "[INFO] Please fix the warnings above before merging/pushing."
    exit 1
fi
