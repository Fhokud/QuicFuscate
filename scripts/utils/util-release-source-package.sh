#!/usr/bin/env bash
# Description: Build a clean source-first release archive (v1) without transient artifacts.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
OUT_ROOT="$ROOT/scripts/out/releases/source"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT_FILE="$OUT_ROOT/quicfuscate-v1-source-${STAMP}.tar.gz"

usage() {
  cat <<USAGE
Usage: util-release-source-package.sh [--output FILE] [--dry-run]

Creates a clean source archive from the local workspace while excluding transient data.

Options:
  --output FILE   Output tar.gz path (default: scripts/out/releases/source/quicfuscate-v1-source-<ts>.tar.gz)
  --dry-run       Print archive command and exit
  -h, --help      Show this help
USAGE
}

DRY_RUN=0
while (($#)); do
  case "$1" in
    --output)
      OUT_FILE="${2:?missing value for --output}"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

mkdir -p "$(dirname "$OUT_FILE")"

EXCLUDES=(
  --exclude=".git"
  --exclude="target"
  --exclude="archive"
  --exclude="scripts/out"
  --exclude="**/node_modules"
  --exclude="**/dist"
  --exclude="**/test-results"
  --exclude="**/.DS_Store"
  --exclude="**/*.log"
  --exclude="tmp"
)

CMD=(tar -czf "$OUT_FILE" "${EXCLUDES[@]}" -C "$(dirname "$ROOT")" "$(basename "$ROOT")")

if [[ "$DRY_RUN" -eq 1 ]]; then
  printf 'dry-run: '
  printf '%q ' "${CMD[@]}"
  echo
  exit 0
fi

"${CMD[@]}"

SIZE="$(du -h "$OUT_FILE" | awk '{print $1}')"
echo "source package created: $OUT_FILE ($SIZE)"
