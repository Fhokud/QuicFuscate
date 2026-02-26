#!/usr/bin/env bash
# Description: Build helper: build-dev-tools.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""; RUSTFLAGS_EXTRA=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --rustflags) RUSTFLAGS_EXTRA="$2"; shift;;
    --dry-run) DRY_RUN=1;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1; set -x;;
    --help|-h) echo "Usage: $(basename "$0") [--output-dir DIR] [--rustflags STR]"; exit 0;;
    *) break;;
  esac; shift
done
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/build/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"; LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"; exec > >(tee -a "$LOG_FILE") 2>&1
[[ -n "${RUSTFLAGS_EXTRA:-}" ]] && export RUSTFLAGS="${RUSTFLAGS_EXTRA} ${RUSTFLAGS:-}"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "build_dev_tools"; JSON_FIRST_RUN=1

echo "==============================================================="
echo "  Development Tools & Code Quality Check"
echo "==============================================================="

# Format check
echo -e "\n> Checking code formatting..."
if ! cargo fmt --check 2>/dev/null; then
    echo "  [WARN]  Code needs formatting. Run: cargo fmt"
    echo "  Files needing format:"
    cargo fmt --check 2>&1 | grep "Diff" | cut -d' ' -f2
else
    echo "  [OK] Code formatting OK"
fi

# Clippy analysis with detailed output
echo -e "\n> Running Clippy analysis..."
CLIPPY_OUTPUT=$(cargo clippy --all-targets --all-features -- -W clippy::all 2>&1 || true)
CLIPPY_WARNINGS=$(echo "$CLIPPY_OUTPUT" | grep -c "warning:" || true)
CLIPPY_ERRORS=$(echo "$CLIPPY_OUTPUT" | grep -c "error:" || true)

if [ "$CLIPPY_ERRORS" -gt 0 ]; then
    echo "  [FAIL] Clippy found $CLIPPY_ERRORS errors"
    echo "$CLIPPY_OUTPUT" | grep "error:" | head -5
elif [ "$CLIPPY_WARNINGS" -gt 0 ]; then
    echo "  [WARN]  Clippy found $CLIPPY_WARNINGS warnings"
    echo "$CLIPPY_OUTPUT" | grep "warning:" | head -5
else
    echo "  [OK] No Clippy issues"
fi

# Documentation coverage
echo -e "\n> Checking documentation coverage..."
UNDOCUMENTED=$(cargo doc --no-deps 2>&1 | grep -c "warning: missing documentation" || true)
if [ "$UNDOCUMENTED" -gt 0 ]; then
    echo "  [WARN]  $UNDOCUMENTED items missing documentation"
else
    echo "  [OK] Documentation complete"
fi

# Dependency tree analysis
echo -e "\n> Analyzing dependency tree..."
TOTAL_DEPS=$(cargo tree --no-dedupe 2>/dev/null | wc -l)
UNIQUE_DEPS=$(cargo tree 2>/dev/null | wc -l)
echo "  Total dependencies: $TOTAL_DEPS"
echo "  Unique dependencies: $UNIQUE_DEPS"
echo "  Duplicate dependencies: $((TOTAL_DEPS - UNIQUE_DEPS))"

# Feature combinations check
echo -e "\n> Checking feature combinations..."
for features in "" "with_aegis" "uring" "xdp" "benches" "uring,xdp" "with_aegis,uring,xdp"; do
    if [ -z "$features" ]; then
        echo -n "  Default features: "
    else
        echo -n "  Features [$features]: "
    fi
    if cargo check --features "$features" &>/dev/null; then
        echo "[OK]"
    else
        echo "[FAIL]"
    fi
done

# Binary size analysis
echo -e "\n> Binary size analysis..."
if [ -f "target/release/quicfuscate" ]; then
    SIZE_BYTES=$(stat -f%z "target/release/quicfuscate" 2>/dev/null || stat -c%s "target/release/quicfuscate" 2>/dev/null || echo "0")
    SIZE_MB=$((SIZE_BYTES / 1024 / 1024))
    echo "  Release binary: ${SIZE_MB}MB"
    
    # Symbol analysis
    SYMBOLS=$(nm target/release/quicfuscate 2>/dev/null | wc -l || echo "0")
    echo "  Total symbols: $SYMBOLS"
fi

# Toolchain info
echo -e "\n> Toolchain information..."
rustc --version
cargo --version
echo "  Target: $(rustc --print target-list | grep -E "$(uname -m)" | head -1)"

echo -e "\n[OK] Development tools check complete"
json_end "$JSON"
