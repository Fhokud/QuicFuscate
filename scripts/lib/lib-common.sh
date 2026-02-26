#!/usr/bin/env bash
# Description: Central script library bridge for non-test script families.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../tests/lib/lib-common.sh"
