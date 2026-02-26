#!/usr/bin/env bash
# Description: Analysis helper: analysis-dead-code-report.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"

# Flags
OUTPUT_DIR=""; RUSTFLAGS_EXTRA=""; DRY_RUN=""; QUICFUSCATE_DEBUG_SCRIPTS=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --rustflags) RUSTFLAGS_EXTRA="$2"; shift;;
    --dry-run) DRY_RUN=1;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1; set -x;;
    --help|-h) echo "Usage: $(basename "$0") [--output-dir DIR] [--rustflags STR] [--dry-run] [--verbose]"; exit 0;;
    *) break;;
  esac; shift
done
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_NAME="$(basename "$0" .sh)"
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/audits/${BASE_NAME}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/${BASE_NAME}.log"
exec > >(tee -a "$LOG_FILE") 2>&1
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "analysis_dead_code"; JSON_FIRST_RUN=1
[[ -n "${RUSTFLAGS_EXTRA:-}" ]] && export RUSTFLAGS="${RUSTFLAGS_EXTRA} ${RUSTFLAGS:-}"

echo "==============================================================="
echo "  Dead Code Analysis Report"
echo "==============================================================="
echo "  Analyzing unused code across the entire codebase"
echo "==============================================================="

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

# Statistics
total_dead_code=0
dead_code_by_module=""

echo -e "\n${YELLOW}=== Dead Code Markers by Module ===${NC}"

# Analyze each source file
for file in src/*.rs; do
    basename=$(basename "$file")
    count=$(grep -c "#\[allow(dead_code)\]" "$file" 2>/dev/null || echo 0)
    total_dead_code=$((total_dead_code + count))
    
    if [ $count -gt 0 ]; then
        echo -e "  ${basename}: ${RED}${count}${NC} dead code markers"
        
        # Show specific items marked as dead code
        echo -e "    ${BLUE}Items:${NC}"
        grep -B 1 "#\[allow(dead_code)\]" "$file" | grep -E "^(pub |)?(fn |struct |enum |const |static |type |trait |impl )" | \
            sed 's/^/      - /' | head -10
        
        if [ $count -gt 10 ]; then
            echo "      ... and $((count - 10)) more"
        fi
    else
        echo -e "  ${basename}: ${GREEN}0${NC} dead code markers"
    fi
done

echo -e "\n${YELLOW}=== Unused Functions Analysis ===${NC}"

# Find potentially unused private functions
echo "Searching for potentially unused private functions..."

for file in src/*.rs; do
    basename=$(basename "$file")
    echo -e "\n  ${BLUE}${basename}:${NC}"
    
    # Find private functions (not pub)
    private_fns=$(grep -E "^[[:space:]]*fn [a-z_][a-z0-9_]*\(" "$file" 2>/dev/null | \
                  grep -v "^[[:space:]]*pub" | \
                  sed 's/.*fn \([a-z_][a-z0-9_]*\).*/\1/' | \
                  sort -u)
    
    if [ -z "$private_fns" ]; then
        echo "    No private functions found"
        continue
    fi
    
    for fn_name in $private_fns; do
        # Count usages (excluding the definition)
        usage_count=$(grep -c "\b${fn_name}(" "$file" 2>/dev/null || echo 0)
        usage_count=$((usage_count - 1)) # Subtract the definition itself
        
        if [ $usage_count -eq 0 ]; then
            echo -e "    ${RED}[WARN]${NC} $fn_name: appears unused"
        elif [ $usage_count -eq 1 ]; then
            echo -e "    ${YELLOW}?${NC} $fn_name: used only once"
        fi
    done
done

echo -e "\n${YELLOW}=== Unused Structs/Enums Analysis ===${NC}"

# Find potentially unused types
for file in src/*.rs; do
    basename=$(basename "$file")
    echo -e "\n  ${BLUE}${basename}:${NC}"
    
    # Find private structs/enums
    private_types=$(grep -E "^[[:space:]]*(struct|enum) [A-Z][A-Za-z0-9]*" "$file" 2>/dev/null | \
                    grep -v "^[[:space:]]*pub" | \
                    sed 's/.*\(struct\|enum\) \([A-Z][A-Za-z0-9]*\).*/\2/' | \
                    sort -u)
    
    if [ -z "$private_types" ]; then
        echo "    No private types found"
        continue
    fi
    
    for type_name in $private_types; do
        # Count usages across all files
        usage_count=$(grep -r "\b${type_name}\b" src/ --include="*.rs" 2>/dev/null | \
                      grep -v "struct ${type_name}\|enum ${type_name}" | \
                      wc -l)
        
        if [ $usage_count -eq 0 ]; then
            echo -e "    ${RED}[WARN]${NC} $type_name: appears unused"
        elif [ $usage_count -le 2 ]; then
            echo -e "    ${YELLOW}?${NC} $type_name: minimal usage ($usage_count references)"
        fi
    done
done

echo -e "\n${YELLOW}=== Feature-Gated Code Analysis ===${NC}"

# Find feature gates that might hide dead code
echo "Checking feature-gated code blocks..."

feature_gates=$(grep -r "#\[cfg(" src/ --include="*.rs" | \
                sed 's/.*#\[cfg(\([^)]*\)).*/\1/' | \
                sort -u)

if [ -n "$feature_gates" ]; then
    echo "Found feature gates:"
    for gate in $feature_gates; do
        count=$(grep -r "#\[cfg($gate)" src/ --include="*.rs" | wc -l)
        echo -e "  ${BLUE}$gate${NC}: $count occurrences"
    done
else
    echo "No feature gates found"
fi

echo -e "\n${YELLOW}=== TODO/FIXME/HACK Comments ===${NC}"

# Find technical debt markers
for marker in "TODO" "FIXME" "HACK" "XXX" "STUB"; do
    count=$(grep -r "$marker" src/ --include="*.rs" | wc -l)
    if [ $count -gt 0 ]; then
        echo -e "  ${YELLOW}$marker${NC}: $count occurrences"
        grep -r "$marker" src/ --include="*.rs" | head -3 | sed 's/^/    /'
        if [ $count -gt 3 ]; then
            echo "    ... and $((count - 3)) more"
        fi
    fi
done

echo -e "\n${YELLOW}=== Unused Dependencies Check ===${NC}"

# Check for potentially unused dependencies
echo "Analyzing Cargo.toml dependencies..."

deps=$(grep -E "^[a-z-]+ =" Cargo.toml | sed 's/ =.*//' | sort -u)

for dep in $deps; do
    # Check if dependency is used in any source file
    usage=$(grep -r "use $dep\|extern crate $dep\|$dep::" src/ --include="*.rs" 2>/dev/null | wc -l)
    
    if [ $usage -eq 0 ]; then
        # Check for macro usage or other patterns
        usage=$(grep -r "\b$dep\b" src/ --include="*.rs" 2>/dev/null | wc -l)
        if [ $usage -eq 0 ]; then
            echo -e "  ${RED}[WARN]${NC} $dep: appears unused"
        elif [ $usage -le 2 ]; then
            echo -e "  ${YELLOW}?${NC} $dep: minimal usage"
        fi
    fi
done

echo -e "\n${YELLOW}=== Summary ===${NC}"
echo -e "  Total dead code markers: ${RED}$total_dead_code${NC}"
echo -e "  Modules with most dead code:"

# Sort modules by dead code count
for file in src/*.rs; do
    count=$(grep -c "#\[allow(dead_code)\]" "$file" 2>/dev/null || echo 0)
    if [ $count -gt 0 ]; then
        echo "$count $(basename $file)"
    fi
done | sort -rn | head -5 | while read count file; do
    echo -e "    ${RED}$count${NC} in $file"
done

echo -e "\n${YELLOW}=== Recommendations ===${NC}"
echo "1. Review items marked with #[allow(dead_code)] - they may be removable"
echo "2. Consider removing or implementing stub functions"
echo "3. Check if feature-gated code is still needed"
echo "4. Review TODO/FIXME comments for unfinished work"
echo "5. Audit dependencies for actual usage"

echo -e "\n${RED}[WARN] WARNING:${NC} Do NOT automatically remove dead code!"
echo "Some code may be:"
echo "  - Used by tests or benchmarks"
echo "  - Required for future features"
echo "  - Platform-specific implementations"
echo "  - Public API that external users depend on"

echo -e "\n${GREEN}[OK] Dead Code Analysis Complete${NC}"
if [[ $JSON_FIRST_RUN -eq 0 ]]; then echo "," >> "$JSON"; fi; JSON_FIRST_RUN=0
echo -n '  {"total_dead_code_markers":'"$total_dead_code"'}' >> "$JSON"
json_end "$JSON"
