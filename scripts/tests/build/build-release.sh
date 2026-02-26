#!/usr/bin/env bash
# Description: Build helper: build-release.
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
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "build_release"; JSON_FIRST_RUN=1

echo "==============================================================="
echo "  QuicFuscate Release Build"
echo "==============================================================="

# Clean previous builds
echo -e "\n> Cleaning previous builds..."
cargo clean

# Build release binary with all optimizations
echo -e "\n> Building release binary..."
RUSTFLAGS="-C target-cpu=native -C opt-level=3 -C lto=fat -C codegen-units=1" \
cargo build --release

# Build with optional features for Linux
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo -e "\n> Building with Linux-specific features..."
    RUSTFLAGS="-C target-cpu=native -C opt-level=3 -C lto=fat -C codegen-units=1" \
    cargo build --release --features "uring xdp"
fi

# Strip debug symbols
echo -e "\n> Stripping debug symbols..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    strip target/release/quicfuscate
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    strip --strip-all target/release/quicfuscate
fi

# Display binary info
echo -e "\n> Binary information:"
ls -lh target/release/quicfuscate
file target/release/quicfuscate

# Create release directory with timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RELEASE_DIR="$OUTPUT_DIR/release-${TIMESTAMP}"
mkdir -p "$RELEASE_DIR"

# Copy binary to release directory
echo -e "\n> Copying to $RELEASE_DIR..."
cp target/release/quicfuscate "$RELEASE_DIR/"

# Generate checksums
echo -e "\n> Generating checksums..."
if command -v sha256sum &> /dev/null; then
    (cd "$RELEASE_DIR" && sha256sum quicfuscate > quicfuscate.sha256)
else
    (cd "$RELEASE_DIR" && shasum -a 256 quicfuscate > quicfuscate.sha256)
fi

echo -e "\n[OK] Release build complete: $RELEASE_DIR/quicfuscate"
json_end "$JSON"
