#![cfg(target_arch = "x86_64")]
//! x86 SIMD helpers for QUIC header validation

use std::arch::x86_64::*;

/// AVX-512 fast-path header validation
/// Checks QUIC fixed bit and basic length guards.
#[target_feature(enable = "avx512f")]
pub unsafe fn validate_header_avx512(header: &[u8]) -> bool {
    if header.is_empty() {
        return false;
    }
    // For now, the fixed-bit check dominates; widening here keeps the door
    // open for extended validations (e.g., DCID/SCID bounds) without branches.
    let first = *header.get_unchecked(0);
    (first & 0x40) != 0
}
