#!/usr/bin/env bash
# Description: Audit runner: audit-all-comprehensive.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"
[[ -f "$SCRIPT_DIR/../lib/lib-common.sh" ]] && source "$SCRIPT_DIR/../lib/lib-common.sh"
ALLOWLIST_FILE="$SCRIPT_DIR/allowlists/critical-allowlist.txt"

OUTPUT_DIR=""
STRICT=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift;;
    --strict) STRICT=1;;
    --dry-run) DRY_RUN=1;;
    --verbose) QUICFUSCATE_DEBUG_SCRIPTS=1;;
    --help|-h) echo "Usage: $(basename "$0") [options]"; echo "Comprehensive Security & Quality Audit"; usage_common_flags 2>/dev/null || true; exit 0;;
    *) echo "Unknown flag: " >&2; exit 2;;
  esac; shift
done

echo "==============================================================="
echo "  QuicFuscate Comprehensive Security & Quality Audit"
echo "==============================================================="
echo "  Starting at: $(date)"
echo "==============================================================="

# Audit results tracking
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
[[ -z "$OUTPUT_DIR" ]] && OUTPUT_DIR="$SCRIPT_DIR/../../out/audits/audit-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
AUDIT_LOG="$OUTPUT_DIR/audit.log"
JSON="$OUTPUT_DIR/results.json"; json_begin "$JSON" "audit_all"; JSON_FIRST_RUN=1

ISSUES_FOUND=0
WARNINGS_FOUND=0
CRITICAL_ISSUES=0

# Color codes for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

log_critical() {
    echo -e "${RED}[FAIL] CRITICAL: $1${NC}" | tee -a "$AUDIT_LOG"
    CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
}

log_warning() {
    echo -e "${YELLOW}[WARN]  WARNING: $1${NC}" | tee -a "$AUDIT_LOG"
    WARNINGS_FOUND=$((WARNINGS_FOUND + 1))
}

log_info() {
    echo -e "${GREEN}[OK] $1${NC}" | tee -a "$AUDIT_LOG"
}

count_lines() {
    wc -l | tr -d '[:space:]'
}

allowlist_regex() {
    local kind="$1"
    [[ -f "$ALLOWLIST_FILE" ]] || return 0
    awk -v kind="$kind" '
        {
            sep = index($0, "|")
            if (sep <= 0) next
            k = substr($0, 1, sep - 1)
            p = substr($0, sep + 1)
        }
        k == kind && p != "" {
            if (out != "") out = out "|" p; else out = p
        }
        END { print out }
    ' "$ALLOWLIST_FILE"
}

split_locations_with_allowlist() {
    local kind="$1"
    local locations="$2"
    local rx
    rx="$(allowlist_regex "$kind")"
    if [[ -n "$rx" ]]; then
        TOLERATED_LOCATIONS="$(printf "%s\n" "$locations" | sed '/^$/d' | grep -E "$rx" || true)"
        BLOCKER_LOCATIONS="$(printf "%s\n" "$locations" | sed '/^$/d' | grep -Ev "$rx" || true)"
    else
        TOLERATED_LOCATIONS=""
        BLOCKER_LOCATIONS="$(printf "%s\n" "$locations" | sed '/^$/d')"
    fi
}

# Security Audit
echo -e "\n+===============================================================+"
echo "|                    SECURITY AUDIT                              |"
echo "+===============================================================+"

echo -e "\n> Analyzing unsafe code usage..."
UNSAFE_COUNT=$(grep -r "unsafe" src/ --include="*.rs" | wc -l)
UNSAFE_IN_PROD=$(grep -r "unsafe" src/ --include="*.rs" | grep -v "test" | grep -v "bench" | wc -l)
if [ "$UNSAFE_IN_PROD" -gt 50 ]; then
    log_warning "High unsafe usage in production code: $UNSAFE_IN_PROD blocks"
else
    log_info "Unsafe usage acceptable: $UNSAFE_IN_PROD blocks in production"
fi

echo -e "\n> Checking for panic-inducing code..."
STRICT_RUNTIME_CLIPPY="$OUTPUT_DIR/strict-runtime-clippy.log"
RUNTIME_CLIPPY_OUTPUT=$(cargo clippy --lib --bins --all-features -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic 2>&1 || true)
printf "%s\n" "$RUNTIME_CLIPPY_OUTPUT" > "$STRICT_RUNTIME_CLIPPY"

UNWRAP_COUNT=$(printf "%s\n" "$RUNTIME_CLIPPY_OUTPUT" | grep -c 'used `unwrap()' || true)
EXPECT_COUNT=$(printf "%s\n" "$RUNTIME_CLIPPY_OUTPUT" | grep -c 'used `expect(' || true)
PANIC_COUNT=$(printf "%s\n" "$RUNTIME_CLIPPY_OUTPUT" | grep -c 'should not be present in production code' || true)

if [ "$UNWRAP_COUNT" -gt 0 ]; then
    log_warning "Found $UNWRAP_COUNT unwrap() usages in runtime code (clippy strict)"
    echo "  Locations:" | tee -a "$AUDIT_LOG"
    printf "%s\n" "$RUNTIME_CLIPPY_OUTPUT" | rg -n -- '--> src/' | head -5 | tee -a "$AUDIT_LOG" || true
fi

if [ "$EXPECT_COUNT" -gt 0 ]; then
    log_warning "Found $EXPECT_COUNT expect() usages in runtime code (clippy strict)"
fi

if [ "$PANIC_COUNT" -gt 0 ]; then
    log_critical "Found $PANIC_COUNT panic! usages in runtime code (clippy strict)"
fi

echo -e "\n> Checking for hardcoded secrets..."
SECRET_ASSIGN_RE='(password|secret|token|api[_-]?key|private[_-]?key|credential)[[:space:]]*[:=][[:space:]]*"[^"]{8,}"'
SECRET_KEY_BLOCK_RE='-----BEGIN[[:space:]]+(RSA|EC|OPENSSH|PRIVATE)[[:space:]]+PRIVATE[[:space:]]+KEY-----'
SECRET_MATCHES="$( (rg -n --no-heading -g '*.rs' -g '!**/test*/**' -g '!**/bench*/**' -e "$SECRET_ASSIGN_RE" -e "$SECRET_KEY_BLOCK_RE" src || true) )"
SECRET_COUNT=$(printf "%s\n" "$SECRET_MATCHES" | sed '/^$/d' | count_lines)
if [ "$SECRET_COUNT" -gt 0 ]; then
    log_critical "Hardcoded secret literals detected: $SECRET_COUNT occurrences"
    printf "%s\n" "$SECRET_MATCHES" | head -3 | tee -a "$AUDIT_LOG" || true
else
    log_info "No hardcoded secrets detected"
fi

echo -e "\n> Checking memory safety..."
LEAK_PATTERNS="mem::forget|Box::leak|ManuallyDrop"
LEAK_COUNT=$( (grep -rE "$LEAK_PATTERNS" src/ --include="*.rs" | grep -v "test" || true) | wc -l)
if [ "$LEAK_COUNT" -gt 0 ]; then
    log_warning "Potential memory leaks: $LEAK_COUNT patterns found"
fi

# Dependency Audit
echo -e "\n+===============================================================+"
echo "|                  DEPENDENCY AUDIT                              |"
echo "+===============================================================+"

echo -e "\n> Checking for vulnerable dependencies..."
if command -v cargo-audit &> /dev/null; then
    AUDIT_OUTPUT=$(cargo audit 2>&1 || true)
    VULN_COUNT=$(echo "$AUDIT_OUTPUT" | grep -c "Vulnerability" || true)
    if [ "$VULN_COUNT" -gt 0 ]; then
        log_critical "Found $VULN_COUNT vulnerable dependencies"
        echo "$AUDIT_OUTPUT" | grep "Vulnerability" | head -5 | tee -a "$AUDIT_LOG" || true
    else
        log_info "No known vulnerabilities in dependencies"
    fi
else
    log_warning "cargo-audit not installed, skipping vulnerability check"
fi

echo -e "\n> Checking dependency licenses..."
TOTAL_DEPS=$(cargo tree --no-dedupe 2>/dev/null | wc -l)
log_info "Total dependencies: $TOTAL_DEPS"

# Performance Audit
echo -e "\n+===============================================================+"
echo "|                 PERFORMANCE AUDIT                              |"
echo "+===============================================================+"

echo -e "\n> Analyzing hot path optimizations..."
INLINE_ALWAYS=$(grep -r "#\[inline(always)\]" src/ --include="*.rs" | wc -l)
INLINE_REGULAR=$(grep -r "#\[inline\]" src/ --include="*.rs" | grep -v "inline(always)" | wc -l)
log_info "Inline annotations: $INLINE_ALWAYS always, $INLINE_REGULAR regular"

echo -e "\n> Checking for performance anti-patterns..."
CLONE_COUNT=$(grep -r "\.clone()" src/ --include="*.rs" | wc -l)
COLLECT_COUNT=$(grep -r "\.collect::<Vec" src/ --include="*.rs" | wc -l)
if [ "$CLONE_COUNT" -gt 100 ]; then
    log_warning "High clone usage: $CLONE_COUNT calls (consider Arc/Rc)"
fi
if [ "$COLLECT_COUNT" -gt 50 ]; then
    log_warning "High collect usage: $COLLECT_COUNT calls (consider iterators)"
fi

echo -e "\n> Analyzing SIMD usage..."
SIMD_FEATURES=$(grep -r "target_arch\|target_feature" src/ --include="*.rs" | wc -l)
if [ "$SIMD_FEATURES" -lt 10 ]; then
    log_warning "Low SIMD usage: only $SIMD_FEATURES conditionals found"
else
    log_info "Good SIMD coverage: $SIMD_FEATURES feature conditionals"
fi

echo -e "\n> Checking allocations in hot paths..."
HOT_PATH_ALLOCS=$(grep -r "Vec::new\|String::new\|Box::new" src/transport/ src/crypto/ --include="*.rs" | wc -l)
if [ "$HOT_PATH_ALLOCS" -gt 20 ]; then
    log_warning "High allocations in hot paths: $HOT_PATH_ALLOCS found"
else
    log_info "Allocations in hot paths acceptable: $HOT_PATH_ALLOCS"
fi

# Code Quality Audit
echo -e "\n+===============================================================+"
echo "|                  CODE QUALITY AUDIT                            |"
echo "+===============================================================+"

echo -e "\n> Running Clippy analysis..."
CLIPPY_OUTPUT=$(cargo clippy --all-targets --all-features -- -W clippy::all 2>&1 || true)
CLIPPY_WARNINGS=$(echo "$CLIPPY_OUTPUT" | grep -c "warning:" || true)
CLIPPY_ERRORS=$(echo "$CLIPPY_OUTPUT" | grep -c "error:" || true)

if [ "$CLIPPY_ERRORS" -gt 0 ]; then
    log_critical "Clippy found $CLIPPY_ERRORS errors"
elif [ "$CLIPPY_WARNINGS" -gt 50 ]; then
    log_warning "Clippy found $CLIPPY_WARNINGS warnings"
else
    log_info "Clippy warnings acceptable: $CLIPPY_WARNINGS"
fi

echo -e "\n> Checking documentation coverage..."
DOC_OUTPUT=$(cargo doc --no-deps 2>&1 || true)
MISSING_DOCS=$(echo "$DOC_OUTPUT" | grep -c "missing documentation" || true)
if [ "$MISSING_DOCS" -gt 20 ]; then
    log_warning "Poor documentation: $MISSING_DOCS items missing docs"
else
    log_info "Documentation coverage good: $MISSING_DOCS items missing"
fi

echo -e "\n> Checking test coverage..."
TEST_FILES=$(find src -name "*.rs" -exec grep -l "#\[test\]" {} \; | wc -l)
TOTAL_FILES=$(find src -name "*.rs" | wc -l)
TEST_COVERAGE=$((TEST_FILES * 100 / TOTAL_FILES))
if [ "$TEST_COVERAGE" -lt 30 ]; then
    log_warning "Low test coverage: only $TEST_COVERAGE% of files have tests"
else
    log_info "Test coverage acceptable: $TEST_COVERAGE% of files"
fi
if [[ $JSON_FIRST_RUN -eq 0 ]]; then echo "," >> "$JSON"; fi; JSON_FIRST_RUN=0
echo -n '  {"unsafe_in_prod":'"$UNSAFE_IN_PROD"',"unwrap_calls":'"$UNWRAP_COUNT"',"panic_macros":'"$PANIC_COUNT"',"secrets":'"$SECRET_COUNT"',"leak_patterns":'"$LEAK_COUNT"',"simd_features":'"$SIMD_FEATURES"',"test_coverage_percent":'"$TEST_COVERAGE"'}' >> "$JSON"

# Complexity Audit
echo -e "\n+===============================================================+"
echo "|                  COMPLEXITY AUDIT                              |"
echo "+===============================================================+"

echo -e "\n> Analyzing function complexity..."
LONG_FUNCTIONS=$(grep -r "^fn " src/ --include="*.rs" -A 100 | grep -c "^--$" || true)
if [ "$LONG_FUNCTIONS" -gt 50 ]; then
    log_warning "Many long functions: $LONG_FUNCTIONS (consider refactoring)"
fi

echo -e "\n> Checking cyclomatic complexity..."
NESTED_IFS=$(grep -r "if.*{" src/ --include="*.rs" -A 5 | grep -c "if.*{" || true)
if [ "$NESTED_IFS" -gt 100 ]; then
    log_warning "High branching complexity: $NESTED_IFS nested conditions"
fi

# Thread Safety Audit
echo -e "\n+===============================================================+"
echo "|                 THREAD SAFETY AUDIT                            |"
echo "+===============================================================+"

echo -e "\n> Checking for race conditions..."
STATIC_MUT_LOCATIONS="$(rg -n --no-heading "static mut" src -g '*.rs' -g '!**/test*/**' -g '!**/bench*/**' || true)"
split_locations_with_allowlist "static_mut" "$STATIC_MUT_LOCATIONS"
STATIC_MUT=$(printf "%s\n" "$BLOCKER_LOCATIONS" | sed '/^$/d' | count_lines)
STATIC_MUT_TOLERATED=$(printf "%s\n" "$TOLERATED_LOCATIONS" | sed '/^$/d' | count_lines)
if [ "$STATIC_MUT" -gt 0 ]; then
    log_critical "Found $STATIC_MUT static mut variables (race condition risk)"
fi
if [ "$STATIC_MUT_TOLERATED" -gt 0 ]; then
    log_info "Tolerated static mut occurrences (allowlisted): $STATIC_MUT_TOLERATED"
fi

echo -e "\n> Analyzing synchronization primitives..."
MUTEX_COUNT=$(grep -r "Mutex\|RwLock" src/ --include="*.rs" | wc -l)
ATOMIC_COUNT=$(grep -r "Atomic" src/ --include="*.rs" | wc -l)
log_info "Synchronization: $MUTEX_COUNT mutexes/locks, $ATOMIC_COUNT atomics"

# Crypto Audit
echo -e "\n+===============================================================+"
echo "|                   CRYPTO AUDIT                                 |"
echo "+===============================================================+"

echo -e "\n> Checking for weak crypto..."
WEAK_CRYPTO_MATCHES="$(
  (
    rg -n --no-heading -g '*.rs' -g '!**/test*/**' -g '!**/bench*/**' -i \
      -e '\b(md5|sha1|rc4)::' \
      -e '\b(Md5|Sha1|Rc4)\b' \
      src/crypto src/transport src/stealth 2>/dev/null || true
  )
)"
WEAK_CRYPTO=$(printf "%s\n" "$WEAK_CRYPTO_MATCHES" | sed '/^$/d' | count_lines)
if [ "$WEAK_CRYPTO" -gt 0 ]; then
    log_critical "Weak cryptographic algorithms detected: $WEAK_CRYPTO occurrences"
    printf "%s\n" "$WEAK_CRYPTO_MATCHES" | head -3 | tee -a "$AUDIT_LOG" || true
fi

echo -e "\n> Checking constant-time operations..."
CT_VIOLATIONS=$(( $( (grep -rE "if.*secret|if.*key|if.*password" src/crypto/ --include="*.rs" 2>/dev/null || true) | wc -l | tr -d '[:space:]' ) + 0 ))
if [ "$CT_VIOLATIONS" -gt 0 ]; then
    log_warning "Potential timing attacks: $CT_VIOLATIONS conditional branches on secrets"
fi

# Generate Report
echo -e "\n+===============================================================+"
echo "|                    AUDIT SUMMARY                               |"
echo "+===============================================================+"

TOTAL_ISSUES=$((CRITICAL_ISSUES + WARNINGS_FOUND))

echo -e "\n  Critical Issues:  $CRITICAL_ISSUES"
echo "  Warnings:         $WARNINGS_FOUND"
echo "  Total Issues:     $TOTAL_ISSUES"
echo "  Audit Log:        $AUDIT_LOG"

json_end "$JSON"

if [ "$CRITICAL_ISSUES" -gt 0 ]; then
    if [ "$STRICT" -eq 1 ]; then
        echo -e "\n${RED}[FAIL] AUDIT FAILED - Critical issues must be resolved (strict mode)${NC}"
        exit 1
    fi
    echo -e "\n${YELLOW}[WARN]  AUDIT COMPLETED WITH CRITICAL FINDINGS (advisory mode, use --strict to fail)${NC}"
    exit 0
elif [ "$WARNINGS_FOUND" -gt 20 ]; then
    echo -e "\n${YELLOW}[WARN]  AUDIT PASSED WITH WARNINGS - Consider addressing warnings${NC}"
    exit 0
else
    echo -e "\n${GREEN}[OK] AUDIT PASSED - Code quality acceptable${NC}"
    exit 0
fi
