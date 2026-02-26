//! Consolidated acceleration primitives across subsystems.
//!
//! This module aggregates the various `accel.rs` implementations that used to
//! live in the individual subsystem folders (random, sort, iter, string, brain,
//! stealth, transport, memory). Each submodule preserves the original
//! functions, allowing consumers to access them via `crate::accelerate::<area>`.

use crate::optimize::{CpuProfile, FeatureDetector};

// Re-export optimization submodules under `accelerate::*` for legacy call sites.
// This avoids compiling the same file twice via `#[path = ...] mod ...`, which causes
// duplicate modules and bloats compile time/binary size.
pub use crate::optimize::udp as transport_io;
pub use crate::optimize::{
    brain, compress, iter, memory, random, sort, stealth, string, transport,
};

/// Count ASCII printable bytes (0x20..=0x7E) using SIMD acceleration where available.
#[inline(always)]
pub fn count_ascii_printable(bytes: &[u8]) -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        let profile = FeatureDetector::instance().profile();
        if matches!(
            profile,
            CpuProfile::X86_P1a
                | CpuProfile::X86_P1b
                | CpuProfile::X86_P1f
                | CpuProfile::X86_P2a
                | CpuProfile::X86_P2b
                | CpuProfile::X86_P3a
                | CpuProfile::X86_P3b
                | CpuProfile::X86_P3c
                | CpuProfile::X86_P3d
                | CpuProfile::X86_P3e
        ) {
            unsafe { return count_ascii_printable_sse2(bytes) };
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        let profile = FeatureDetector::instance().profile();
        if matches!(
            profile,
            CpuProfile::ARM_A0
                | CpuProfile::ARM_A1a
                | CpuProfile::ARM_A1b
                | CpuProfile::ARM_A1c
                | CpuProfile::ARM_A1d
                | CpuProfile::ARM_A2
                | CpuProfile::Apple_M
        ) {
            unsafe { return count_ascii_printable_neon(bytes) };
        }
    }

    count_ascii_printable_scalar(bytes)
}

#[inline(always)]
fn count_ascii_printable_scalar(bytes: &[u8]) -> usize {
    bytes.iter().filter(|b| matches!(b, 0x20..=0x7E)).count()
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn count_ascii_printable_sse2(bytes: &[u8]) -> usize {
    use std::arch::x86_64::*;

    let len = bytes.len();
    let mut i = 0usize;
    let mut total = 0usize;
    let lower = _mm_set1_epi8((0x20 - 1) as i8);
    let upper = _mm_set1_epi8(0x7F as i8);

    while i + 16 <= len {
        let ptr = bytes.as_ptr().add(i) as *const __m128i;
        let v = _mm_loadu_si128(ptr);
        let gt = _mm_cmpgt_epi8(v, lower);
        let lt = _mm_cmplt_epi8(v, upper);
        let mask = _mm_and_si128(gt, lt);
        let bits = _mm_movemask_epi8(mask) as u32;
        total += bits.count_ones() as usize;
        i += 16;
    }

    total + count_ascii_printable_scalar(&bytes[i..])
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn count_ascii_printable_neon(bytes: &[u8]) -> usize {
    use std::arch::aarch64::*;

    let len = bytes.len();
    let mut i = 0usize;
    let mut total = 0usize;
    let lower = vdupq_n_u8(0x20);
    let upper = vdupq_n_u8(0x7E);
    let ones = vdupq_n_u8(1);

    while i + 16 <= len {
        let ptr = bytes.as_ptr().add(i);
        let v = vld1q_u8(ptr);
        let ge = vcgeq_u8(v, lower);
        let le = vcleq_u8(v, upper);
        let mask = vandq_u8(ge, le);
        let masked = vandq_u8(mask, ones);
        total += vaddvq_u8(masked) as usize;
        i += 16;
    }

    total + count_ascii_printable_scalar(&bytes[i..])
}

// `transport` and `memory` are re-exported above.
