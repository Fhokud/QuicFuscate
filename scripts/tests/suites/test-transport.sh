#!/usr/bin/env bash
# Description: Test suite runner: test-transport.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

OUTPUT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --jobs) JOBS="$2"; shift;;
    --features) CARGO_FEATURES="$2"; shift;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h)
      echo "Usage: $(basename "$0") [options]"; echo "Transport Layer Comprehensive Test Suite"; usage_common_flags 2>/dev/null || true; exit 0;;
    *) echo "Unknown flag: $1" >&2; exit 2;;
  esac; shift
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/tests/tests-transport-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/transport-tests.log"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "tests_transport_comprehensive"; JSON_FIRST_RUN=1

echo "==============================================================="
echo "  Transport Layer Comprehensive Test Suite (validated migration contract)"
echo "==============================================================="

echo -e "\n> Testing Basic Transport (unit tests)..."
run_cargo test --release --lib transport:: -- --nocapture

# Test io_uring fast path (Linux)
echo -e "\n> Testing io_uring UDP Fast Path..."
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    QUICFUSCATE_FASTPATH=auto \
    run_cargo test --release --features io_uring --test rt-transport-uring -- --nocapture
else
    echo "  Skipping (Linux only)"
fi

echo -e "\n> Testing Linux Kernel Hotpath Smoke..."
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    QUICFUSCATE_FASTPATH=auto \
    run_cargo test --release --features io_uring --test rt-io-hotpath-kernel-integration -- --nocapture
else
    echo "  Skipping (Linux only)"
fi

# Test XDP fast path (Linux)
echo -e "\n> Testing XDP Fast Path..."
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    run_cargo test --release --test rt-transport-xdp -- --nocapture
else
    echo "  Skipping (Linux only)"
fi

echo -e "\n> Testing Anti-Replay Strike Register..."
run_cargo test --features rust-tests --test rt-anti-replay -- --nocapture

echo -e "\n> Testing Congestion Control Algorithms..."
run_cargo test --features rust-tests --test rt-cc-algorithms -- --nocapture

echo -e "\n> Testing Transport Integration Targets..."
run_cargo test --release \
  --test rt-transport-connection \
  --test rt-transport-config \
  --test rt-transport-batch-processor \
  --test rt-transport-frames-roundtrip \
  --test rt-transport-packet-headers \
  --test rt-transport-recovery \
  --test rt-transport-udpfast \
  --test rt-transport-h3 \
  --test rt-pnspace-ack-policy \
  --test rt-udp-batch-send \
  --test rt-harness-udpfast \
  -- --nocapture

echo -e "\n[OK] Transport Comprehensive Tests Complete"
json_end "$JSON"
