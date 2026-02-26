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
  esac; shift
done
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$PROJECT_ROOT/scripts/out/audits/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"; LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"; exec > >(tee -a "$LOG_FILE") 2>&1
[[ -n "${RUSTFLAGS_EXTRA:-}" ]] && export RUSTFLAGS="${RUSTFLAGS_EXTRA} ${RUSTFLAGS:-}"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "utils_analyze_codebase"; JSON_FIRST_RUN=1

echo "==============================================================="
echo "  QuicFuscate Codebase Analysis"
echo "==============================================================="

# Code statistics
echo -e "\n+===============================================================+"
echo "|                    CODE STATISTICS                             |"
echo "+===============================================================+"

echo -e "\n> Lines of Code:"
echo "  Rust source:"
find src -name "*.rs" -type f -exec wc -l {} + | tail -1 | awk '{printf "    Total: %d lines\n", $1}'
find src -name "*.rs" -type f | wc -l | awk '{printf "    Files: %d\n", $1}'

echo -e "\n  By module:"
for dir in src/*/; do
    if [ -d "$dir" ]; then
        module=$(basename "$dir")
        lines=$(find "$dir" -name "*.rs" -exec wc -l {} + 2>/dev/null | tail -1 | awk '{print $1}')
        [ -n "$lines" ] && echo "    $module: $lines lines"
    fi
done

# Module analysis
echo -e "\n+===============================================================+"
echo "|                    MODULE ANALYSIS                             |"
echo "+===============================================================+"

echo -e "\n> Core modules:"
for module in crypto fec stealth transport optimize interface; do
    if [ -f "src/$module.rs" ]; then
        lines=$(wc -l "src/$module.rs" | awk '{print $1}')
        functions=$(grep -c "^pub fn\|^fn\|^pub async fn" "src/$module.rs" || echo 0)
        structs=$(grep -c "^pub struct\|^struct" "src/$module.rs" || echo 0)
        impls=$(grep -c "^impl" "src/$module.rs" || echo 0)
        tests=$(grep -c "#\[test\]" "src/$module.rs" || echo 0)
        unsafe_blocks=$(grep -c "unsafe" "src/$module.rs" || echo 0)
        
        echo -e "\n  $module.rs:"
        echo "    Lines: $lines | Functions: $functions | Structs: $structs"
        echo "    Impls: $impls | Tests: $tests | Unsafe: $unsafe_blocks"
    fi
done

# Feature analysis
echo -e "\n+===============================================================+"
echo "|                   FEATURE ANALYSIS                             |"
echo "+===============================================================+"

echo -e "\n> Conditional compilation:"
echo "  Linux-specific code blocks: $(grep -r "target_os.*linux" src/ --include="*.rs" | wc -l)"
echo "  macOS-specific code blocks: $(grep -r "target_os.*macos" src/ --include="*.rs" | wc -l)"
echo "  Windows-specific code blocks: $(grep -r "target_os.*windows" src/ --include="*.rs" | wc -l)"
echo "  x86_64 SIMD blocks: $(grep -r "target_arch.*x86_64" src/ --include="*.rs" | wc -l)"
echo "  ARM SIMD blocks: $(grep -r "target_arch.*aarch64" src/ --include="*.rs" | wc -l)"

echo -e "\n> Feature gates:"
echo "  with_aegis: $(grep -r 'feature.*with_aegis' src/ --include="*.rs" | wc -l) uses"
echo "  uring: $(grep -r 'feature.*uring' src/ --include="*.rs" | wc -l) uses"
echo "  xdp: $(grep -r 'feature.*xdp' src/ --include="*.rs" | wc -l) uses"
echo "  benches: $(grep -r 'feature.*benches' src/ --include="*.rs" | wc -l) uses"

# Optimization analysis
echo -e "\n+===============================================================+"
echo "|                OPTIMIZATION ANALYSIS                           |"
echo "+===============================================================+"

echo -e "\n> Performance annotations:"
echo "  #[inline(always)]: $(grep -r "#\[inline(always)\]" src/ --include="*.rs" | wc -l)"
echo "  #[inline]: $(grep -r "#\[inline\]" src/ --include="*.rs" | grep -v "inline(always)" | wc -l)"
echo "  #[cold]: $(grep -r "#\[cold\]" src/ --include="*.rs" | wc -l)"
echo "  #[hot]: $(grep -r "#\[hot\]" src/ --include="*.rs" | wc -l)"

echo -e "\n> SIMD usage:"
echo "  _mm_ intrinsics: $(grep -r "_mm_" src/ --include="*.rs" | wc -l)"
echo "  vld/vst intrinsics: $(grep -r "vld\|vst" src/ --include="*.rs" | wc -l)"
echo "  target_feature: $(grep -r "target_feature" src/ --include="*.rs" | wc -l)"

# Dependency analysis
echo -e "\n+===============================================================+"
echo "|                 DEPENDENCY ANALYSIS                            |"
echo "+===============================================================+"

echo -e "\n> Direct dependencies:"
grep "^[a-z]" Cargo.toml | grep "=" | wc -l | awk '{print "  Count: " $1}'

echo -e "\n> Most used external crates:"
grep -h "^use " src/*.rs src/**/*.rs 2>/dev/null | \
    grep -v "use crate\|use super\|use std" | \
    cut -d':' -f1 | cut -d' ' -f2 | \
    sort | uniq -c | sort -rn | head -10 | \
    while read count crate; do
        echo "  $crate: $count uses"
    done

# Complexity metrics
echo -e "\n+===============================================================+"
echo "|                  COMPLEXITY METRICS                            |"
echo "+===============================================================+"

echo -e "\n> Function complexity:"
longest_fn=$(grep -r "^fn \|^pub fn " src/ --include="*.rs" -A 50 | \
    awk '/^src.*fn /{name=$0} /^--$/{print NR-start, name; start=NR}' | \
    sort -rn | head -1)
echo "  Longest function: ~$(echo $longest_fn | cut -d' ' -f1) lines"

echo -e "\n> File complexity:"
largest_file=$(find src -name "*.rs" -exec wc -l {} + | sort -rn | head -2 | tail -1)
echo "  Largest file: $largest_file"

echo -e "\n> Test coverage:"
test_count=$(grep -r "#\[test\]" src/ --include="*.rs" | wc -l)
test_modules=$(grep -r "#\[cfg(test)\]" src/ --include="*.rs" | wc -l)
echo "  Test functions: $test_count"
echo "  Test modules: $test_modules"

# Generate summary
echo -e "\n+===============================================================+"
echo "|                      SUMMARY                                   |"
echo "+===============================================================+"

total_lines=$(find src -name "*.rs" -exec wc -l {} + | tail -1 | awk '{print $1}')
total_files=$(find src -name "*.rs" | wc -l)
unsafe_total=$(grep -r "unsafe" src/ --include="*.rs" | wc -l)
test_total=$(grep -r "#\[test\]" src/ --include="*.rs" | wc -l)

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
