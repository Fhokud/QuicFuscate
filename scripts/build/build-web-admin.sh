#!/usr/bin/env bash
# Description: Build the React web-admin UI and publish bundle to assets/web-admin.
set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || "${1:-}" == "help" ]]; then
  cat <<'EOF'
Usage: build-web-admin.sh

Builds apps/web-admin-ui with Bun and copies dist/* to assets/web-admin.
If assets/web-admin already exists and is non-empty, it is archived under archive/.
EOF
  exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

REACT_APP_DIR="$PROJECT_ROOT/apps/web-admin-ui"

if [ ! -d "$REACT_APP_DIR" ] || [ ! -f "$REACT_APP_DIR/package.json" ]; then
  echo "React web-admin UI not found at: $REACT_APP_DIR" >&2
  exit 1
fi

if ! command -v bun >/dev/null 2>&1; then
  echo "bun not found. Install Bun to build the React web-admin UI." >&2
  exit 1
fi

cd "$REACT_APP_DIR"
bun install --no-progress
bun run build
SOURCE="$REACT_APP_DIR/dist"
DEST="$PROJECT_ROOT/assets/web-admin"

if [ ! -d "$SOURCE" ]; then
  echo "Error: Build output not found at $SOURCE" >&2
  exit 1
fi

if [ -d "$DEST" ] && [ "$(ls -A "$DEST" 2>/dev/null)" ]; then
  ARCHIVE_ROOT="$PROJECT_ROOT/archive"
  TS="$(date +"%Y%m%d_%H%M%S")"
  ARCHIVE_DIR="$ARCHIVE_ROOT/web-admin-assets-$TS"
  mkdir -p "$ARCHIVE_DIR"
  cp -R "$DEST"/. "$ARCHIVE_DIR"/
  printf "archived_from=%s\narchived_at=%s\n" "$DEST" "$TS" > "$ARCHIVE_DIR/metadata.txt"
fi

rm -rf "$DEST"
mkdir -p "$DEST"
cp -R "$SOURCE"/. "$DEST"/

echo "Web admin assets copied to: $DEST"
