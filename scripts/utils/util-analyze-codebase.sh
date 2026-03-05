#!/usr/bin/env bash
# Description: Utility script: util-analyze-codebase.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
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
  esac
  shift
done

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$PROJECT_ROOT/scripts/out/audits/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"
exec > >(tee -a "$LOG_FILE") 2>&1
[[ -n "${RUSTFLAGS_EXTRA:-}" ]] && export RUSTFLAGS="${RUSTFLAGS_EXTRA} ${RUSTFLAGS:-}"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "utils_analyze_codebase"; JSON_FIRST_RUN=1

count_matches() {
  local pattern="$1"
  shift
  (rg --no-messages -- "$pattern" "$@" || true) | wc -l | tr -d '[:space:]'
}

echo "==============================================================="
echo "  QuicFuscate Codebase Analysis"
echo "==============================================================="

echo -e "\n+===============================================================+"
echo "|                    CODE STATISTICS                             |"
echo "+===============================================================+"

echo -e "\n> Lines of Code:"
echo "  Rust source:"
find src -name "*.rs" -type f -exec wc -l {} + | tail -1 | awk '{printf "    Total: %d lines\n", $1}'
find src -name "*.rs" -type f | wc -l | awk '{printf "    Files: %d\n", $1}'

echo -e "\n  By module:"
for dir in src/*/; do
    if [[ -d "$dir" ]]; then
        module=$(basename "$dir")
        lines=$(find "$dir" -name "*.rs" -type f -exec wc -l {} + 2>/dev/null | tail -1 | awk '{print $1}')
        [[ -n "$lines" ]] && echo "    $module: $lines lines"
    fi
done

echo -e "\n+===============================================================+"
echo "|                    MODULE ANALYSIS                             |"
echo "+===============================================================+"

echo -e "\n> Core modules:"
for module in crypto fec stealth transport optimize interface; do
    if [[ -f "src/$module.rs" ]]; then
        lines=$(wc -l "src/$module.rs" | awk '{print $1}')
        functions=$(count_matches '^[[:space:]]*(pub )?(async )?fn ' "src/$module.rs")
        structs=$(count_matches '^[[:space:]]*(pub )?struct ' "src/$module.rs")
        impls=$(count_matches '^[[:space:]]*impl ' "src/$module.rs")
        tests=$(count_matches '#\[test\]' "src/$module.rs")
        unsafe_blocks=$(count_matches '\bunsafe\b' "src/$module.rs")

        echo -e "\n  $module.rs:"
        echo "    Lines: $lines | Functions: $functions | Structs: $structs"
        echo "    Impls: $impls | Tests: $tests | Unsafe: $unsafe_blocks"
    fi
done

echo -e "\n+===============================================================+"
echo "|                   FEATURE ANALYSIS                             |"
echo "+===============================================================+"

echo -e "\n> Conditional compilation:"
echo "  Linux-specific code blocks: $(count_matches 'target_os.*linux' src/ --glob '*.rs')"
echo "  macOS-specific code blocks: $(count_matches 'target_os.*macos' src/ --glob '*.rs')"
echo "  Windows-specific code blocks: $(count_matches 'target_os.*windows' src/ --glob '*.rs')"
echo "  x86_64 SIMD blocks: $(count_matches 'target_arch.*x86_64' src/ --glob '*.rs')"
echo "  ARM SIMD blocks: $(count_matches 'target_arch.*aarch64' src/ --glob '*.rs')"

echo -e "\n> Feature gates:"
echo "  with_aegis: $(count_matches 'feature.*with_aegis' src/ --glob '*.rs') uses"
echo "  uring: $(count_matches 'feature.*uring' src/ --glob '*.rs') uses"
echo "  xdp: $(count_matches 'feature.*xdp' src/ --glob '*.rs') uses"
echo "  benches: $(count_matches 'feature.*benches' src/ --glob '*.rs') uses"

echo -e "\n+===============================================================+"
echo "|                OPTIMIZATION ANALYSIS                           |"
echo "+===============================================================+"

echo -e "\n> Performance annotations:"
echo "  #[inline(always)]: $(count_matches '#\[inline\(always\)\]' src/ --glob '*.rs')"
echo "  #[inline]: $(count_matches '#\[inline\]' src/ --glob '*.rs')"
echo "  #[cold]: $(count_matches '#\[cold\]' src/ --glob '*.rs')"
echo "  #[hot]: $(count_matches '#\[hot\]' src/ --glob '*.rs')"

echo -e "\n> SIMD usage:"
echo "  _mm_ intrinsics: $(count_matches '_mm_' src/ --glob '*.rs')"
echo "  vld/vst intrinsics: $(count_matches 'vld|vst' src/ --glob '*.rs')"
echo "  target_feature: $(count_matches 'target_feature' src/ --glob '*.rs')"

echo -e "\n+===============================================================+"
echo "|                 DEPENDENCY ANALYSIS                            |"
echo "+===============================================================+"

echo -e "\n> Direct dependencies:"
grep "^[a-z]" Cargo.toml | grep "=" | wc -l | awk '{print "  Count: " $1}'

echo -e "\n> Most used external crates:"
(
  rg --no-messages --no-filename '^use ' src/ --glob '*.rs' || true
) |
  (rg --no-messages -v 'use crate|use super|use std' || true) |
  sed -E 's/^use ([^:; ]+).*/\1/' |
  sort | uniq -c | sort -rn | head -10 |
  while read -r count crate; do
      [[ -n "${count:-}" && -n "${crate:-}" ]] || continue
      echo "  $crate: $count uses"
  done

echo -e "\n+===============================================================+"
echo "|                  COMPLEXITY METRICS                            |"
echo "+===============================================================+"

echo -e "\n> Function complexity:"
longest_fn=$( (
  rg --no-messages '^[[:space:]]*(pub )?fn ' src/ --glob '*.rs' -n || true
) | head -1 )
if [[ -n "$longest_fn" ]]; then
  echo "  Sample function location: $longest_fn"
else
  echo "  Sample function location: n/a"
fi

echo -e "\n> File complexity:"
largest_file=$(find src -name "*.rs" -exec wc -l {} + | sort -rn | head -2 | tail -1)
echo "  Largest file: $largest_file"

echo -e "\n> Test coverage:"
test_count=$(count_matches '#\[test\]' src/ --glob '*.rs')
test_modules=$(count_matches '#\[cfg\(test\)\]' src/ --glob '*.rs')
echo "  Test functions: $test_count"
echo "  Test modules: $test_modules"

echo -e "\n+===============================================================+"
echo "|                      SUMMARY                                   |"
echo "+===============================================================+"

total_lines=$(find src -name "*.rs" -exec wc -l {} + | tail -1 | awk '{print $1}')
total_files=$(find src -name "*.rs" | wc -l)
unsafe_total=$(count_matches '\bunsafe\b' src/ --glob '*.rs')
test_total=$(count_matches '#\[test\]' src/ --glob '*.rs')

echo -e "\n  Total Rust code: $total_lines lines in $total_files files"
echo "  Code density: $((total_lines / total_files)) lines/file average"
echo "  Unsafe usage: $unsafe_total blocks"
echo "  Test coverage: $test_total test functions"
safe_ratio="n/a"
if command -v bc >/dev/null 2>&1; then
  safe_ratio=$(echo "scale=2; ($total_lines - $unsafe_total) * 100 / $total_lines" | bc)
fi
echo "  Safety ratio: ${safe_ratio}% safe code"

echo -e "\n[OK] Analysis complete"
if [[ $JSON_FIRST_RUN -eq 0 ]]; then echo "," >> "$JSON"; fi; JSON_FIRST_RUN=0
echo -n '  {"total_lines":'"$total_lines"',"total_files":'"$total_files"',"unsafe_blocks":'"$unsafe_total"',"test_functions":'"$test_total"',"safety_ratio_percent":'"\"$safe_ratio\""'}' >> "$JSON"
json_end "$JSON"
