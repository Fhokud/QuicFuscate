#!/usr/bin/env bash
# Description: Test suite runner: test-crypto.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""
FAST=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --fast) FAST=1;;
    --jobs) JOBS="$2"; shift;;
    --features) CARGO_FEATURES="$2"; shift;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h) echo "Usage: $(basename "$0") [options]"; echo "Crypto & AEAD Comprehensive Test Suite"; usage_common_flags 2>/dev/null || true; exit 0;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac; shift
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/tests-crypto-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/crypto-tests.log"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "tests_crypto_comprehensive"; JSON_FIRST_RUN=1

echo "==============================================================="
echo "  Crypto & AEAD Comprehensive Test Suite"
echo "==============================================================="

if (( FAST )); then
  echo -e "\n> Fast mode enabled (minimal crypto confidence set)"
  run_cargo test --release --lib aegis128l -- --nocapture
  run_cargo test --release --lib morus -- --nocapture
  run_cargo test --release --lib aes_gcm -- --nocapture
  run_cargo test --release \
    --test rt-tls-cover-cipher \
    --test rt-ghash-sse-parity \
    -- --nocapture
  echo -e "\n[OK] Crypto Fast Tests Complete"
  json_end "$JSON"
  exit 0
fi

# Test AEGIS-128L
echo -e "\n> Testing AEGIS-128L..."
run_cargo test --release --lib aegis128l -- --nocapture

# Test MORUS-1280-128
echo -e "\n> Testing MORUS-1280-128..."
run_cargo test --release --lib morus -- --nocapture

# Test AES-GCM with hardware acceleration
echo -e "\n> Testing AES-GCM (Hardware Accelerated)..."
run_cargo test --release --lib aes_gcm -- --nocapture

# Test GHASH PMULL (ARM)
echo -e "\n> Testing GHASH with PMULL (ARM)..."
run env QUICFUSCATE_GHASH_PMULL=1 cargo test --release --lib ghash -- --nocapture

# Test ChaCha20-Poly1305 fallback
echo -e "\n> Testing ChaCha20-Poly1305..."
run_cargo test --release --lib chacha20poly1305 -- --nocapture

# Test AES header-protection key setup (key derivation path)
echo -e "\n> Testing AES Header-Protection Key Derivation..."
run_cargo test --release --lib aes_hp -- --nocapture

# Test SIMD paths (x86_64)
echo -e "\n> Testing SIMD Paths (AVX2/SSE2)..."
run env RUSTFLAGS="-C target-cpu=native" cargo test --release --lib simd -- --nocapture

# Integration fixtures (Rust tests)
echo -e "\n> Running Crypto Integration Fixtures..."
run_cargo test --release \
  --test rt-baseline-oracles \
  --test rt-tls-cover-cipher \
  --test rt-ghash-sse-parity \
  --test rt-chacha-x4-parity \
  --test rt-chacha-x16-parity \
  --test rt-fake-hmac \
  -- --nocapture

echo -e "\n[OK] Crypto Comprehensive Tests Complete"
json_end "$JSON"
