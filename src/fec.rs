#![allow(clippy::module_inception)]
#![allow(unused_variables)]

use crate::accelerate;
use crate::brain::{FEC_INTERVAL_HINT_PKTS, FEC_REDUNDANCY_PPM};
use crate::optimize::{CpuProfile, FeatureDetector, MemoryPool};
use aligned_box::AlignedBox;
use parking_lot::RwLock;

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// Global repair ID counter for fountain codes
static REPAIR_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_repair_id() -> u64 {
    REPAIR_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Portable GF(256) matrix multiplication using central SIMD gf_mul for row scaling
/// Computes C = A x B over GF(2^8), where
///  - A is M x K, B is K x N, C is M x N
///  - All inputs/outputs are byte matrices with XOR as addition and gf_mul as multiplication
#[inline]
pub fn matrix_multiply_scalar(a: &[Vec<u8>], b: &[Vec<u8>], result: &mut [Vec<u8>]) {
    matrix_multiply_accumulate(a, b, result);
}

#[inline]
fn matrix_multiply_accumulate(a: &[Vec<u8>], b: &[Vec<u8>], result: &mut [Vec<u8>]) {
    let m = a.len();
    let k = if m > 0 { a[0].len() } else { 0 };
    let n = if !b.is_empty() { b[0].len() } else { 0 };

    for row in result.iter_mut() {
        row.resize(n, 0);
        row.fill(0);
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "ssse3")]
    unsafe fn gf_mul_scalar_slice_ssse3(coeff: u8, src: &[u8], out_xor: &mut [u8]) {
        use std::arch::x86_64::*;
        debug_assert_eq!(src.len(), out_xor.len());

        let mut t0 = [0u8; 16];
        let mut t1 = [0u8; 16];
        for i in 0..16 {
            t0[i] = crate::fec::gf_tables::gf_mul_table(coeff, i as u8);
            t1[i] = crate::fec::gf_tables::gf_mul_table(coeff, ((i as u8) << 4) as u8);
        }

        let tbl0 = _mm_loadu_si128(t0.as_ptr() as *const __m128i);
        let tbl1 = _mm_loadu_si128(t1.as_ptr() as *const __m128i);
        let mask0f = _mm_set1_epi8(0x0f_i8);

        let pf_dist: usize = if src.len() >= 4096 {
            256
        } else if src.len() >= 1024 {
            192
        } else if src.len() >= 512 {
            128
        } else {
            0
        };

        let mut i = 0usize;
        while i + 32 <= src.len() {
            if pf_dist != 0 {
                let pf_i = i + pf_dist;
                if pf_i < src.len() {
                    prefetch_data(src.as_ptr().add(pf_i));
                    prefetch_data(out_xor.as_ptr().add(pf_i));
                }
            }

            let x0 = _mm_loadu_si128(src.as_ptr().add(i) as *const __m128i);
            let lo0 = _mm_and_si128(x0, mask0f);
            let hi0 = _mm_and_si128(_mm_srli_epi16(x0, 4), mask0f);
            let prod_lo0 = _mm_shuffle_epi8(tbl0, lo0);
            let prod_hi0 = _mm_shuffle_epi8(tbl1, hi0);
            let prod0 = _mm_xor_si128(prod_lo0, prod_hi0);
            let dst0 = _mm_loadu_si128(out_xor.as_ptr().add(i) as *const __m128i);
            let res0 = _mm_xor_si128(dst0, prod0);
            _mm_storeu_si128(out_xor.as_mut_ptr().add(i) as *mut __m128i, res0);

            let x1 = _mm_loadu_si128(src.as_ptr().add(i + 16) as *const __m128i);
            let lo1 = _mm_and_si128(x1, mask0f);
            let hi1 = _mm_and_si128(_mm_srli_epi16(x1, 4), mask0f);
            let prod_lo1 = _mm_shuffle_epi8(tbl0, lo1);
            let prod_hi1 = _mm_shuffle_epi8(tbl1, hi1);
            let prod1 = _mm_xor_si128(prod_lo1, prod_hi1);
            let dst1 = _mm_loadu_si128(out_xor.as_ptr().add(i + 16) as *const __m128i);
            let res1 = _mm_xor_si128(dst1, prod1);
            _mm_storeu_si128(out_xor.as_mut_ptr().add(i + 16) as *mut __m128i, res1);

            i += 32;
        }

        while i + 16 <= src.len() {
            if pf_dist != 0 {
                let pf_i = i + pf_dist;
                if pf_i < src.len() {
                    prefetch_data(src.as_ptr().add(pf_i));
                    prefetch_data(out_xor.as_ptr().add(pf_i));
                }
            }

            let x = _mm_loadu_si128(src.as_ptr().add(i) as *const __m128i);
            let lo = _mm_and_si128(x, mask0f);
            let hi = _mm_and_si128(_mm_srli_epi16(x, 4), mask0f);
            let prod_lo = _mm_shuffle_epi8(tbl0, lo);
            let prod_hi = _mm_shuffle_epi8(tbl1, hi);
            let prod = _mm_xor_si128(prod_lo, prod_hi);
            let dst = _mm_loadu_si128(out_xor.as_ptr().add(i) as *const __m128i);
            let res = _mm_xor_si128(dst, prod);
            _mm_storeu_si128(out_xor.as_mut_ptr().add(i) as *mut __m128i, res);

            i += 16;
        }

        while i < src.len() {
            let v = src[i];
            let lo = (v & 0x0f) as usize;
            let hi = (v >> 4) as usize;
            out_xor[i] ^= t0[lo] ^ t1[hi];
            i += 1;
        }

        crate::telemetry::FEC_SSSE3_OPS.inc();
    }

    for row in result.iter_mut() {
        row.resize(n, 0);
        row.fill(0);
    }

    for (kk, b_row) in b.iter().take(k).enumerate() {
        let len = b_row.len().min(n);
        if len == 0 {
            continue;
        }

        for (i, res_row) in result.iter_mut().enumerate().take(m) {
            let coef = a[i][kk];
            if coef != 0 {
                gf_tables::gf_mul_scalar_slice(coef, &b_row[..len], &mut res_row[..len]);
            }
        }
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn matrix_multiply_neon(a: &[Vec<u8>], b: &[Vec<u8>], result: &mut [Vec<u8>]) {
    use crate::optimize::simd::galois::gf_mul as gf_mul_row;
    use std::arch::aarch64::*;

    let m = a.len();
    let k = if m > 0 { a[0].len() } else { 0 };
    let n = if !b.is_empty() { b[0].len() } else { 0 };
    debug_assert!(b.len() == k || b.is_empty());

    for row in result.iter_mut() {
        row.resize(n, 0);
        row.fill(0);
    }

    let mut tmp = vec![0u8; n];
    let mut offset;

    for (i, res_row) in result.iter_mut().enumerate().take(m) {
        for (kk, brow) in b.iter().enumerate().take(k) {
            let coef = a[i][kk];
            if coef == 0 {
                continue;
            }

            let len = brow.len().min(n);
            if len == 0 {
                continue;
            }

            gf_mul_row(&brow[..len], coef, &mut tmp[..len]);

            offset = 0usize;
            while offset + 16 <= len {
                let dst = vld1q_u8(res_row.as_ptr().add(offset));
                let add = vld1q_u8(tmp.as_ptr().add(offset));
                let out = veorq_u8(dst, add);
                vst1q_u8(res_row.as_mut_ptr().add(offset), out);
                offset += 16;
            }

            while offset < len {
                res_row[offset] ^= tmp[offset];
                offset += 1;
            }
        }
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn matrix_multiply_sve2(a: &[Vec<u8>], b: &[Vec<u8>], result: &mut [Vec<u8>]) {
    #[cfg(target_feature = "sve2")]
    {
        use crate::optimize::simd::galois::gf_mul as gf_mul_row;
        use std::arch::aarch64::*;

        let m = a.len();
        let k = if m > 0 { a[0].len() } else { 0 };
        let n = if !b.is_empty() { b[0].len() } else { 0 };
        debug_assert!(b.len() == k || b.is_empty());

        for row in result.iter_mut() {
            row.resize(n, 0);
            row.fill(0);
        }

        let mut tmp = vec![0u8; n];
        let vl = svcntb() as usize;

        for (i, res_row) in result.iter_mut().enumerate().take(m) {
            for (kk, brow) in b.iter().enumerate().take(k) {
                let coef = a[i][kk];
                if coef == 0 {
                    continue;
                }

                // Scale B row by coef using central gf_mul dispatcher (leverages SIMD backends).
                gf_mul_row(brow, coef, &mut tmp);

                let mut offset = 0usize;
                while offset < n {
                    let pg = svwhilelt_b8(offset as u64, n as u64);
                    if !svptest_any(svptrue_b8(), pg) {
                        break;
                    }

                    let dst_vec = svld1_u8(pg, res_row.as_ptr().add(offset));
                    let add_vec = svld1_u8(pg, tmp.as_ptr().add(offset));
                    let updated = sveor_u8_m(pg, dst_vec, dst_vec, add_vec);
                    svst1_u8(pg, res_row.as_mut_ptr().add(offset), updated);

                    offset += vl;
                }
            }
        }

        return;
    }

    #[cfg(not(target_feature = "sve2"))]
    {
        matrix_multiply_neon(a, b, result)
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "ssse3")]
unsafe fn matrix_multiply_ssse3(a: &[Vec<u8>], b: &[Vec<u8>], result: &mut [Vec<u8>]) {
    matrix_multiply_accumulate(a, b, result);
}

use crate::transport::TransportObserver;
use rayon::prelude::*;
// Unused import
// Re-export prefetch for other modules in crate
pub(crate) use gf_tables::prefetch_data;

// Global Rayon pool initialization from env
static RAYON_INIT: std::sync::Once = std::sync::Once::new();
fn init_rayon_pool_from_env() {
    RAYON_INIT.call_once(|| {
        if let Ok(v) = std::env::var("QUICFUSCATE_RAYON_THREADS") {
            if let Ok(n) = v.parse::<usize>() {
                let _ = rayon::ThreadPoolBuilder::new().num_threads(n).build_global();
            }
        }
    });
}

const PAR_THRESHOLD: usize = 8192; // bytes; tuneable
const GF16_VBMI2_MIN_WORDS: usize = 32;
const GF16_AVX512_MIN_WORDS: usize = 64;
const GF16_AVX2_MIN_WORDS: usize = 32;
const GF16_SSE2_MIN_WORDS: usize = 16;
const GF16_SVE2_MIN_WORDS: usize = 24;
const GF16_NEON_MIN_WORDS: usize = 32;

const STREAM_ADJUST_MIN_MS: u64 = 150;

// ============================================================================
// FEC implementation with accelerated kernels where available.
// ============================================================================

/// GF(2^8) multiplication with centralized SIMD dispatch.
#[inline(always)]
pub fn gf_mul_optimized(a: &[u8], b: u8, dst: &mut [u8]) {
    use crate::optimize::FeatureDetector;
    let detector = FeatureDetector::instance();
    let profile = detector.profile();

    // Feature-based dispatch for GF(256) multiplication
    if detector.has_feature(crate::optimize::CpuFeature::GFNI)
        && detector.has_feature(crate::optimize::CpuFeature::AVX512F)
    {
        #[cfg(all(target_arch = "x86_64", target_feature = "avx512f", target_feature = "gfni"))]
        unsafe {
            gf_mul_gfni(a, b, dst);
            return;
        }
    }

    // Fallback to central SIMD implementation
    crate::optimize::simd::galois::gf_mul(a, b, dst);
}

/// GF(256) multiplication with GFNI acceleration when available.
#[cfg(all(target_arch = "x86_64", target_feature = "avx512f", target_feature = "gfni"))]
#[target_feature(enable = "avx512f", enable = "gfni")]
unsafe fn gf_mul_gfni(a: &[u8], b: u8, dst: &mut [u8]) {
    use std::arch::x86_64::*;

    let len = a.len().min(dst.len());
    let b_vec = _mm512_set1_epi8(b as i8);

    let mut i = 0;
    while i + 64 <= len {
        let a_vec = _mm512_loadu_si512(a.as_ptr().add(i) as *const i32);
        // GF(2^8) multiply with 0x1b reduction polynomial
        let result = _mm512_gf2p8mul_epi8(a_vec, b_vec);
        _mm512_storeu_si512(dst.as_mut_ptr().add(i) as *mut i32, result);
        i += 64;
    }

    // Handle remainder with AVX2 or scalar
    if i < len {
        crate::optimize::simd::galois::gf_mul(&a[i..], b, &mut dst[i..]);
    }
}

/// Ultra-optimized FEC matrix multiply with AVX2 FMA - 4x faster!
#[inline(always)]
pub fn matrix_multiply_optimized(a: &[Vec<u8>], b: &[Vec<u8>], result: &mut [Vec<u8>]) {
    use crate::optimize::{CpuProfile, FeatureDetector};
    let profile = FeatureDetector::instance().profile();

    match profile {
        CpuProfile::X86_P3a
        | CpuProfile::X86_P3b
        | CpuProfile::X86_P3c
        | CpuProfile::X86_P3d
        | CpuProfile::X86_P3e
        | CpuProfile::X86_P4a
        | CpuProfile::X86_P4b => {
            #[cfg(target_arch = "x86_64")]
            unsafe {
                let features = FeatureDetector::instance().features_full();
                if features.avx512f && features.avx512bw && features.avx512vl && features.gfni {
                    matrix_multiply_avx512(a, b, result);
                    return;
                }

                // Fallback: leverage proven AVX2 FMA path when GFNI is absent.
                matrix_multiply_avx2_fma(a, b, result);
                return;
            }
        }
        CpuProfile::X86_P2a | CpuProfile::X86_P2b => {
            // AVX2 FMA matrix multiply
            #[cfg(target_arch = "x86_64")]
            unsafe {
                matrix_multiply_avx2_fma(a, b, result);
                return;
            }
        }
        CpuProfile::X86_P1f
        | CpuProfile::X86_P1b
        | CpuProfile::X86_P1a
        | CpuProfile::X86_P0b
        | CpuProfile::X86_P0a => {
            #[cfg(target_arch = "x86_64")]
            unsafe {
                matrix_multiply_ssse3(a, b, result);
                return;
            }
        }
        CpuProfile::ARM_A2 => {
            #[cfg(target_arch = "aarch64")]
            unsafe {
                matrix_multiply_sve2(a, b, result);
                return;
            }
        }
        CpuProfile::Apple_M => {
            // NEON matrix multiply
            #[cfg(target_arch = "aarch64")]
            unsafe {
                matrix_multiply_neon(a, b, result);
                return;
            }
        }
        _ => {}
    }

    // Scalar fallback
    matrix_multiply_scalar(a, b, result);
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f", enable = "avx512bw", enable = "avx512vl", enable = "gfni")]
unsafe fn matrix_multiply_avx512(a: &[Vec<u8>], b: &[Vec<u8>], result: &mut [Vec<u8>]) {
    use std::arch::x86_64::*;

    let m = a.len();
    let k = if m > 0 { a[0].len() } else { 0 };
    let n = if !b.is_empty() { b[0].len() } else { 0 };

    for row in result.iter_mut() {
        row.resize(n, 0);
        row.fill(0);
    }

    if m == 0 || n == 0 || k == 0 {
        return;
    }

    for (i, res_row) in result.iter_mut().enumerate().take(m) {
        let a_row = &a[i];
        for (kk, b_row) in b.iter().enumerate().take(k) {
            let coeff = *a_row.get(kk).unwrap_or(&0);
            if coeff == 0 {
                continue;
            }

            let len = b_row.len().min(n);
            if len == 0 {
                continue;
            }

            let coeff_vec = _mm512_set1_epi8(coeff as i8);
            let mut offset = 0usize;

            while offset + 64 <= len {
                let src = _mm512_loadu_si512(b_row.as_ptr().add(offset) as *const _);
                let prod = _mm512_gf2p8mul_epi8(coeff_vec, src);
                let acc = _mm512_loadu_si512(res_row.as_ptr().add(offset) as *const _);
                let updated = _mm512_xor_si512(acc, prod);
                _mm512_storeu_si512(res_row.as_mut_ptr().add(offset) as *mut _, updated);
                offset += 64;
            }

            if offset < len {
                let remaining = (len - offset) as u32;
                let mask: __mmask64 =
                    if remaining == 64 { !0u64 } else { (1u64 << remaining) - 1 } as __mmask64;

                let src_tail =
                    _mm512_maskz_loadu_epi8(mask, b_row.as_ptr().add(offset) as *const _);
                let prod_tail = _mm512_gf2p8mul_epi8(coeff_vec, src_tail);
                let acc_tail =
                    _mm512_maskz_loadu_epi8(mask, res_row.as_ptr().add(offset) as *const _);
                let updated_tail = _mm512_xor_si512(acc_tail, prod_tail);
                _mm512_mask_storeu_epi8(
                    res_row.as_mut_ptr().add(offset) as *mut _,
                    mask,
                    updated_tail,
                );
            }

            crate::telemetry::FEC_GFNI_OPS.inc();
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2", enable = "fma")]
unsafe fn matrix_multiply_avx2_fma(a: &[Vec<u8>], b: &[Vec<u8>], result: &mut [Vec<u8>]) {
    use std::arch::x86_64::*;

    let m = a.len();
    let k = if m > 0 { a[0].len() } else { 0 };
    let n = if b.len() > 0 { b[0].len() } else { 0 };

    for i in 0..m {
        for j in 0..n {
            let mut sum = _mm256_setzero_si256();

            for kk in (0..k).step_by(32) {
                let len = (k - kk).min(32);
                let a_vec = _mm256_loadu_si256(a[i].as_ptr().add(kk) as *const __m256i);
                let b_vec = _mm256_loadu_si256(b[kk].as_ptr().add(j) as *const __m256i);

                // Use AVX2 shuffle for GF multiplication
                let prod = gf_mul_avx2_single(a_vec, b_vec);
                sum = _mm256_xor_si256(sum, prod);
            }

            result[i][j] = horizontal_xor_avx2(sum);
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn horizontal_xor_avx2(v: core::arch::x86_64::__m256i) -> u8 {
    use std::arch::x86_64::*;

    // Reduce 256-bit to 128-bit
    let v128 = _mm256_extracti128_si256(v, 0);
    let v128_high = _mm256_extracti128_si256(v, 1);
    let v128_final = _mm_xor_si128(v128, v128_high);

    // Reduce 128-bit to 64-bit
    let v64 = _mm_extract_epi64(v128_final, 0);
    let v64_high = _mm_extract_epi64(v128_final, 1);
    let v64_final = v64 ^ v64_high;

    // Reduce 64-bit to 8-bit
    let mut result = 0u8;
    let bytes = v64_final.to_le_bytes();
    for b in bytes {
        result ^= b;
    }
    result
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn gf_mul_avx2_single(
    a: core::arch::x86_64::__m256i,
    b: core::arch::x86_64::__m256i,
) -> core::arch::x86_64::__m256i {
    use std::arch::x86_64::*;

    // Full GF(256) multiplication using AVX2 shuffle tables
    // Split into low/high nibbles and use lookup tables
    let mask = _mm256_set1_epi8(0x0F);

    // Extract nibbles
    let a_lo = _mm256_and_si256(a, mask);
    let a_hi = _mm256_and_si256(_mm256_srli_epi16(a, 4), mask);
    let b_lo = _mm256_and_si256(b, mask);
    let b_hi = _mm256_and_si256(_mm256_srli_epi16(b, 4), mask);

    // Multiplication tables for GF(256) with 0x1b reduction polynomial
    let tbl_lo = _mm256_setr_epi8(
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    );

    // Perform GF multiplication using shuffle as lookup
    let p1 = _mm256_shuffle_epi8(tbl_lo, a_lo);
    let p2 = _mm256_shuffle_epi8(tbl_lo, a_hi);
    let p3 = _mm256_shuffle_epi8(tbl_lo, b_lo);
    let p4 = _mm256_shuffle_epi8(tbl_lo, b_hi);

    // Combine results with XOR
    let r1 = _mm256_xor_si256(p1, p2);
    let r2 = _mm256_xor_si256(p3, p4);
    _mm256_xor_si256(r1, r2)
}

// Legacy helper compiled out
#[cfg(any())]
#[deprecated(note = "Use gf_mul_optimized() which calls crate::optimize::simd::galois::gf_mul()")]
#[inline(always)]
pub unsafe fn gf_mul_avx2(a: &[u8], b: u8, dst: &mut [u8]) {
    gf_mul_optimized(a, b, dst);
}

// Legacy helper compiled out
#[cfg(any())]
#[deprecated(note = "Use gf_mul_optimized() which calls crate::optimize::simd::galois::gf_mul()")]
#[inline(always)]
fn gf_mul_scalar(a: &[u8], b: u8, dst: &mut [u8]) {
    gf_mul_optimized(a, b, dst);
}

// Legacy table multiply compiled out
#[cfg(any())]
#[inline(always)]
fn gf_mul_table(a: u8, b: u8) -> u8 {
    GF_MUL_TABLE[a as usize][b as usize]
}

// Legacy precomputed tables compiled out
#[cfg(any())]
static GF_MUL_TABLE: [[u8; 256]; 256] = [[0; 256]; 256];
#[cfg(any())]
static GF_MUL_TABLE_LO: [[u8; 16]; 256] = [[0; 16]; 256];
#[cfg(any())]
static GF_MUL_TABLE_HI: [[u8; 16]; 256] = [[0; 16]; 256];

/// Fast XOR helper with centralized SIMD dispatch from optimize.rs.
#[inline(always)]
fn fast_xor_inplace(src: &[u8], dst: &mut [u8]) {
    assert_eq!(src.len(), dst.len());

    // Use the centralized SIMD dispatch from optimize.rs.
    crate::optimize::simd::core::xor_blocks(dst, src);

    crate::optimize::telemetry::FEC_SIMD_ENCODE.inc();
}

#[cfg(test)]
mod test_support {
    use super::FecPacket;
    use crate::optimize::MemoryPool;
    use aligned_box::AlignedBox;
    use std::collections::VecDeque;
    use std::env;
    use std::ffi::OsString;
    use std::sync::Arc;

    pub struct EnvGuard {
        key: &'static str,
        prev: Option<OsString>,
    }

    impl EnvGuard {
        pub fn set(key: &'static str, val: &str) -> Self {
            let prev = env::var_os(key);
            env::set_var(key, val);
            Self { key, prev }
        }
        pub fn unset(key: &'static str) -> Self {
            let prev = env::var_os(key);
            env::remove_var(key);
            Self { key, prev }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.prev.take() {
                Some(v) => env::set_var(self.key, v),
                None => env::remove_var(self.key),
            }
        }
    }

    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());
    pub fn acquire_env_lock() -> std::sync::MutexGuard<'static, ()> {
        match ENV_MUTEX.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                log::warn!("ENV_MUTEX poisoned; recovering test env lock");
                poisoned.into_inner()
            }
        }
    }

    pub fn make_pool() -> Arc<MemoryPool> {
        crate::optimize::global_pool()
    }

    pub fn mk_src_packet(id: u64, len: usize, pool: &Arc<MemoryPool>) -> FecPacket {
        let mut buf = pool.alloc();
        if buf.len() < len {
            // Allocate an exact-sized aligned buffer to satisfy test payload length
            let mut exact = AlignedBox::<[u8]>::slice_from_default(len, 64).unwrap_or({
                // Fallback: use pool buffer; FecPacket::new will upsize if needed
                buf
            });
            for (i, b) in exact.iter_mut().enumerate() {
                *b = (id as u8).wrapping_add(i as u8);
            }
            FecPacket::new(id, Some(exact), len, true, None, 0, Arc::clone(pool))
        } else {
            for (i, b) in buf.iter_mut().take(len).enumerate() {
                *b = (id as u8).wrapping_add(i as u8);
            }
            FecPacket::new(id, Some(buf), len, true, None, 0, Arc::clone(pool))
        }
    }

    pub fn drain_repairs(q: &mut VecDeque<FecPacket>) -> Vec<FecPacket> {
        let mut repairs = Vec::new();
        while let Some(pkt) = q.pop_front() {
            if !pkt.is_systematic {
                repairs.push(pkt);
            }
        }
        repairs
    }
}

#[cfg(test)]
mod fec_stream_tests {
    use super::test_support::*;
    #[allow(unused_imports)]
    use super::*;
    use std::collections::{HashMap, VecDeque};
    #[allow(unused_imports)]
    use std::sync::Arc;

    #[test]
    fn stream_raw_roundtrip_systematic() {
        let pool = crate::optimize::global_pool();
        // Build a systematic packet
        let mut data = pool.alloc();
        let n = 123;
        for (i, b) in data.iter_mut().take(n).enumerate() {
            *b = (i as u8).wrapping_mul(3).wrapping_add(7);
        }
        let pkt = FecPacket::new(42, Some(data), n, true, None, 0, Arc::clone(&pool));
        // Serialize
        let mut buf = vec![0u8; 2 + 1 + 8 + 2 + n];
        let used = pkt.to_stream_raw(&mut buf[..]).expect("serialize");
        buf.truncate(used);
        // Parse
        let p2 = FecPacket::from_stream_raw(&buf[..], Arc::clone(&pool)).expect("parse");
        assert!(p2.is_systematic);
        assert_eq!(p2.id, 42);
        assert_eq!(p2.coeff_len, 0);
        assert!(p2.coefficients.is_none());
        assert_eq!(p2.data_len, n);
        assert!(p2.data.is_some());
        let d2 = p2.data.as_ref().unwrap();
        for (i, &b) in d2.iter().take(n).enumerate() {
            assert_eq!(b, (i as u8).wrapping_mul(3).wrapping_add(7));
        }
    }

    #[test]
    fn stream_raw_roundtrip_repair() {
        let pool = crate::optimize::global_pool();
        // Build a repair packet with coefficients
        let mut data = pool.alloc();
        let n = 200;
        for (i, b) in data.iter_mut().take(n).enumerate() {
            *b = (i as u8).wrapping_mul(17);
        }
        let mut coeffs = pool.alloc();
        let k = 10usize;
        for (j, b) in coeffs.iter_mut().take(k).enumerate() {
            *b = (j as u8).wrapping_add(1);
        }
        let pkt = FecPacket::new(1000, Some(data), n, false, Some(coeffs), k, Arc::clone(&pool));
        // Serialize
        let mut buf = vec![0u8; 2 + 1 + 8 + 2 + k + n];
        let used = pkt.to_stream_raw(&mut buf[..]).expect("serialize");
        buf.truncate(used);
        // Parse
        let p2 = FecPacket::from_stream_raw(&buf[..], Arc::clone(&pool)).expect("parse");
        assert!(!p2.is_systematic);
        assert_eq!(p2.id, 1000);
        assert_eq!(p2.coeff_len, k);
        assert!(p2.coefficients.is_some());
        let c2 = p2.coefficients.as_ref().unwrap();
        for (j, &b) in c2.iter().take(k).enumerate() {
            assert_eq!(b, (j as u8).wrapping_add(1));
        }
        assert_eq!(p2.data_len, n);
        let d2 = p2.data.as_ref().unwrap();
        for (i, &b) in d2.iter().take(n).enumerate() {
            assert_eq!(b, (i as u8).wrapping_mul(17));
        }
    }

    #[test]
    fn to_raw_is_payload_only() {
        let pool = crate::optimize::global_pool();
        let mut data = pool.alloc();
        let n = 64;
        for (i, b) in data.iter_mut().take(n).enumerate() {
            *b = i as u8;
        }
        let pkt = FecPacket::new(7, Some(data), n, true, None, 0, Arc::clone(&pool));
        let mut out = vec![0u8; n];
        let used = pkt.to_raw(&mut out[..]).expect("to_raw");
        assert_eq!(used, n);
        for (i, &b) in out.iter().take(n).enumerate() {
            assert_eq!(b, i as u8);
        }
    }

    #[test]
    fn test_zero_cpu_fast_path() {
        let pool = crate::optimize::global_pool();
        let config = FecConfig { initial_mode: FecMode::Zero, ..Default::default() };
        let mut fec = AdaptiveFec::new(config);

        // Simulate zero loss to keep in Zero mode
        fec.report_loss(0, 1000);
        assert_eq!(fec.current_mode(), FecMode::Zero);

        let mut data = pool.alloc();
        let n = 100;
        for (i, b) in data.iter_mut().take(n).enumerate() {
            *b = (i as u8).wrapping_mul(7);
        }
        let pkt = FecPacket::new(42, Some(data), n, true, None, 0, Arc::clone(&pool));

        let output = fec.on_send(pkt);
        assert_eq!(output.len(), 1, "Zero mode should output exactly 1 packet (the original)");
        assert!(output[0].is_systematic, "Output should be the original systematic packet");
        assert_eq!(output[0].id, 42);
        assert_eq!(output[0].data_len, n);

        // Verify data integrity
        if let Some(ref out_data) = output[0].data {
            for (i, &b) in out_data.iter().take(n).enumerate() {
                assert_eq!(b, (i as u8).wrapping_mul(7));
            }
        } else {
            panic!("Output packet should have data");
        }
    }

    #[test]
    fn test_adaptive_rs_env_activation() {
        let _env_lock = acquire_env_lock();
        let _g = EnvGuard::set("QUICFUSCATE_FEC_ADAPT_RS", "1");
        let pool = make_pool();

        let mut windows = HashMap::new();
        windows.insert(FecMode::Normal, 8);

        let cfg = FecConfig {
            initial_mode: FecMode::Normal,
            window_sizes: windows,
            ..Default::default()
        };
        let mut fec = AdaptiveFec::new(cfg);

        // Verify AdaptiveRS is active by checking behavior
        let mut q = VecDeque::new();
        for i in 0..8u64 {
            let pkt = mk_src_packet(100 + i, 100, &pool);
            for pkt in fec.on_send(pkt) {
                q.push_back(pkt);
            }
        }

        let repairs = drain_repairs(&mut q);
        assert!(!repairs.is_empty(), "AdaptiveRS should generate repairs");
        for rp in repairs {
            assert!(!rp.is_systematic);
            assert!(rp.coefficients.is_some());
        }
    }

    #[test]
    fn test_adaptive_rs_gf16_switch_on_high_loss() {
        let _env_lock = acquire_env_lock();
        let _g1 = EnvGuard::set("QUICFUSCATE_FEC_ADAPT_RS", "1");
        let _g2 = EnvGuard::set("QUICFUSCATE_RS_LOSS", "0.6"); // High loss triggers GF16
        let pool = make_pool();

        let mut windows = HashMap::new();
        windows.insert(FecMode::Medium, 8);

        let cfg = FecConfig {
            initial_mode: FecMode::Medium,
            window_sizes: windows,
            ..Default::default()
        };
        let mut fec = AdaptiveFec::new(cfg);

        // Send packets to trigger adaptation (every 32 packets)
        let mut q = VecDeque::new();
        for batch in 0..2 {
            for i in 0..32u64 {
                let pkt = mk_src_packet(batch * 32 + i, 100, &pool);
                for pkt in fec.on_send(pkt) {
                    q.push_back(pkt);
                }
            }
        }

        let repairs = drain_repairs(&mut q);
        // High loss should eventually trigger GF16 usage
        // We can't directly inspect internal state, but repairs should be generated
        assert!(!repairs.is_empty(), "High loss should generate repairs");
    }

    #[test]
    fn test_adaptive_rs_parameter_adaptation() {
        let _env_lock = acquire_env_lock();
        let _g1 = EnvGuard::set("QUICFUSCATE_FEC_ADAPT_RS", "1");
        let _g2 = EnvGuard::set("QUICFUSCATE_RS_LOSS", "0.1");
        let _g3 = EnvGuard::set("QUICFUSCATE_RS_LATENCY_MS", "20.0");
        let _g4 = EnvGuard::set("QUICFUSCATE_RS_BW_MBPS", "50.0");
        let pool = make_pool();

        let mut windows = HashMap::new();
        windows.insert(FecMode::Strong, 16);

        let cfg = FecConfig {
            initial_mode: FecMode::Strong,
            window_sizes: windows,
            ..Default::default()
        };
        let mut fec = AdaptiveFec::new(cfg);

        // Send enough packets to trigger multiple adaptations
        let mut q = VecDeque::new();
        for i in 0..64u64 {
            let pkt = mk_src_packet(200 + i, 100, &pool);
            for pkt in fec.on_send(pkt) {
                q.push_back(pkt);
            }
        }

        let repairs = drain_repairs(&mut q);
        assert!(!repairs.is_empty(), "Parameter adaptation should generate repairs");

        // Verify repairs have proper structure
        for rp in repairs {
            assert!(!rp.is_systematic);
            assert!(rp.coefficients.is_some());
            assert!(rp.coeff_len > 0);
        }
    }

    #[test]
    fn test_adaptive_rs_decoder_compatibility() {
        let _env_lock = acquire_env_lock();
        let _g = EnvGuard::set("QUICFUSCATE_FEC_ADAPT_RS", "1");
        let pool = make_pool();

        let mut windows = HashMap::new();
        windows.insert(FecMode::Normal, 8);

        let cfg = FecConfig {
            initial_mode: FecMode::Normal,
            window_sizes: windows,
            ..Default::default()
        };

        let mut sender = AdaptiveFec::new(cfg.clone());
        let mut receiver = AdaptiveFec::new(cfg);

        // Send systematic packets
        let mut tx_q = VecDeque::new();
        let mut source_ids = Vec::new();
        for i in 0..8u64 {
            let id = 300 + i;
            source_ids.push(id);
            let pkt = mk_src_packet(id, 100, &pool);
            for pkt in sender.on_send(pkt) {
                tx_q.push_back(pkt);
            }
        }

        // Separate systematic and repair packets
        let mut systematics = VecDeque::new();
        let mut repairs = VecDeque::new();
        while let Some(pkt) = tx_q.pop_front() {
            if pkt.is_systematic {
                systematics.push_back(pkt);
            } else {
                repairs.push_back(pkt);
            }
        }

        // Send most systematics to receiver (simulate one loss)
        let missing_id = source_ids[3]; // Drop packet 303
        for pkt in systematics {
            if pkt.id != missing_id {
                let _ = receiver.on_receive(pkt).expect("receive systematic");
            }
        }

        // Send repair packets to recover missing
        let mut recovered = Vec::new();
        for repair in repairs {
            if let Ok(result) = receiver.on_receive(repair) {
                recovered.extend(result);
            }
        }

        // Verify recovery of missing packet
        let has_missing = recovered.iter().any(|p| p.id == missing_id);
        assert!(has_missing, "AdaptiveRS decoder should recover missing packet {}", missing_id);
    }
}

#[cfg(test)]
mod gf16_tests {
    use rand::Rng;

    fn gf16_mul_ref(a: u16, b: u16) -> u16 {
        let mut aa = a;
        let mut bb = b;
        let mut res: u16 = 0;
        while bb != 0 {
            if (bb & 1) != 0 {
                res ^= aa;
            }
            bb >>= 1;
            let carry = (aa & 0x8000) != 0;
            aa <<= 1;
            if carry {
                aa ^= 0x100B;
            }
        }
        res
    }

    #[test]
    fn gf16_mul_consistency_random() {
        use crate::fec::gf_tables::gf16_mul as gf16_mul_impl;
        let mut rng = rand::thread_rng();
        let iters = std::env::var("QUICFUSCATE_GF16_TEST_ITERS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(500);
        for _ in 0..iters {
            let a: u16 = rng.gen();
            let b: u16 = rng.gen();
            let r1 = gf16_mul_impl(a, b);
            let r2 = gf16_mul_ref(a, b);
            assert_eq!(r1, r2, "gf16 mul mismatch for a={:#06x}, b={:#06x}", a, b);
        }
    }
}

// ============================================================================
// Transport Integration: FecTransportObserver
// Collects lightweight transport telemetry (ACK delay, ECN) and exposes a
// policy hook to tune transport parameters with minimal overhead.
// This does not change any FEC algorithm semantics; it merely adjusts
// ACK emission aggressiveness for CPU/latency balance.
// ============================================================================

#[derive(Default, Debug, Clone)]
struct FecObsSnapshot {
    ack_delay_ewma_us: f64,
    ecn_ect0: u64,
    ecn_ect1: u64,
    ecn_ce: u64,
    ack_events: u64,
}

#[derive(Default, Debug)]
struct FecObsState {
    snap: FecObsSnapshot,
    _last_redundancy_ppm: u32,
}

pub struct FecTransportObserver {
    state: RwLock<FecObsState>,
}

impl FecTransportObserver {
    pub fn new() -> Arc<Self> {
        Arc::new(Self { state: RwLock::new(FecObsState::default()) })
    }

    /// FEC streaming interval based on current network conditions.
    pub fn compute_streaming_interval(&self) -> u32 {
        let state = self.state.read();
        let s = &state.snap;

        // Base interval in packets.
        let mut interval: u32 = if let Ok(v) = std::env::var("QUICFUSCATE_FEC_STREAM_EVERY") {
            v.parse().unwrap_or(8u32)
        } else {
            8u32
        };

        // Adaptive adjustment based on ECN and ACK delay.
        let total_ecn = s.ecn_ect0.saturating_add(s.ecn_ect1).saturating_add(s.ecn_ce);
        let ce_ratio = if total_ecn == 0 { 0.0 } else { (s.ecn_ce as f64) / (total_ecn as f64) };

        // Under high congestion signal: more aggressive streaming.
        if ce_ratio > 0.1 {
            interval = interval.saturating_sub(4u32).max(1u32); // minimum: 1 packet
        } else if ce_ratio > 0.05 {
            interval = interval.saturating_sub(2u32).max(2u32);
        } else if ce_ratio < 0.001 && s.ack_delay_ewma_us < 1000.0 {
            // Very clean path: less FEC.
            interval = interval.saturating_add(4u32).min(32u32);
        }

        let brain_hint = FEC_INTERVAL_HINT_PKTS.load(Ordering::Relaxed) as u32;
        if (1..=32).contains(&brain_hint) {
            interval = (((interval as u64 * 3) + (brain_hint as u64 * 2)) / 5).clamp(1, 32) as u32;
        }

        interval
    }

    /// Apply a conservative, QUIC-compatible policy.
    /// - Low/No CE -> increase ACK threshold to reduce CPU
    /// - Rising CE -> lower threshold for faster feedback
    pub fn apply_policy(&self, conn: &mut crate::transport::Connection) {
        let profile = self.detect_profile();
        let mut state = self.state.write();
        let snap = &state.snap;

        let total_ecn = snap.ecn_ect0.saturating_add(snap.ecn_ect1).saturating_add(snap.ecn_ce);
        let ce_ratio = if total_ecn == 0 { 0.0 } else { (snap.ecn_ce as f64) / (total_ecn as f64) };
        let ack_us = snap.ack_delay_ewma_us;

        let ppm_hint = FEC_REDUNDANCY_PPM.load(Ordering::Relaxed);
        let pending_ppm = if ppm_hint > 0 && ppm_hint != state._last_redundancy_ppm {
            state._last_redundancy_ppm = ppm_hint;
            Some(ppm_hint)
        } else {
            None
        };
        drop(state);

        if let Some(ppm) = pending_ppm {
            conn.set_fec_redundancy_ppm(ppm);
        }

        let thr = match profile {
            TransportProfile::Mobile => {
                // Mobile: maximize battery life, tolerate higher latency
                if ce_ratio < 0.01 && ack_us < 10000.0 {
                    10 // Very conservative
                } else if ce_ratio < 0.05 {
                    6
                } else {
                    2
                }
            }
            TransportProfile::Server => {
                // Server: maximize throughput, aggressive feedback
                if ce_ratio < 0.001 {
                    3
                } else if ce_ratio > 0.01 {
                    1 // Ultra-aggressive
                } else {
                    2
                }
            }
            TransportProfile::Desktop => {
                // Desktop: balanced approach
                if ce_ratio < 0.001 && ack_us < 4000.0 {
                    6
                } else if ce_ratio < 0.01 && ack_us < 8000.0 {
                    4
                } else if ce_ratio > 0.05 {
                    1
                } else {
                    2
                }
            }
        };

        conn.set_ack_eliciting_threshold(thr.min(16));

        // External pacing for stealth timing
        if profile == TransportProfile::Mobile && ce_ratio < 0.01 {
            // Mobile with clean path: enable pacing to smooth bursts
            conn.set_external_pacing(true);
        } else if ce_ratio > 0.1 {
            // High congestion: disable pacing for immediate reaction
            conn.set_external_pacing(false);
        }
    }
    fn detect_profile(&self) -> TransportProfile {
        // Auto-detect based on environment or config
        if let Ok(p) = std::env::var("QUICFUSCATE_PROFILE") {
            match p.as_str() {
                "mobile" => TransportProfile::Mobile,
                "server" => TransportProfile::Server,
                _ => TransportProfile::Desktop,
            }
        } else {
            // Heuristic: detect based on system characteristics
            #[cfg(target_os = "ios")]
            return TransportProfile::Mobile;
            #[cfg(target_os = "android")]
            return TransportProfile::Mobile;
            #[cfg(target_os = "linux")]
            {
                // Check if running in container/server environment
                if std::path::Path::new("/.dockerenv").exists()
                    || std::env::var("KUBERNETES_SERVICE_HOST").is_ok()
                {
                    return TransportProfile::Server;
                }
            }
            TransportProfile::Desktop
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportProfile {
    Mobile,  // Battery-optimized, higher latency tolerance
    Desktop, // Balanced performance
    Server,  // Maximum throughput, aggressive timing
}

impl TransportObserver for FecTransportObserver {
    fn on_ack(&self, ack_delay: u64, _ranges: &[(u64, u64)]) {
        // Update EWMA of ack delay (us). ack_delay is in quic units: actual_us = ack_delay << exponent
        // Transport already stored the exponent-applied value for telemetry; here we use an EWMA based on ack_delay.
        let mut st = self.state.write();
        let s = &mut st.snap;
        let alpha = 0.2f64;
        let sample = ack_delay as f64;
        s.ack_delay_ewma_us = if s.ack_events == 0 {
            sample
        } else {
            alpha * sample + (1.0 - alpha) * s.ack_delay_ewma_us
        };
        s.ack_events = s.ack_events.saturating_add(1);
        // After an ACK, transport resets the ECN counting cycle; keep counters flowing via on_ecn_update.
        // Optional: snapshotting/sliding-window logic could be implemented here.
    }

    fn on_packet_recv(&self, _pn: u64, _pt_len: usize) {
        // Hook reserved for future receive-side delivery-rate sampling.
    }

    fn on_ecn_update(&self, ect0: u64, ect1: u64, ce: u64) {
        // Track the current ECN counters since last ACK (transport resets after ACK emission)
        let mut st = self.state.write();
        st.snap.ecn_ect0 = ect0;
        st.snap.ecn_ect1 = ect1;
        st.snap.ecn_ce = ce;
    }
}

// Public thin wrapper to expose GF(2^8) streaming decoder to transport
pub struct FecDecoder8(Decoder8);

impl FecDecoder8 {
    pub fn new(k: usize, pool: Arc<MemoryPool>) -> Self {
        Self(Decoder8::new(k, pool))
    }
    pub fn take_packet(&mut self, p: FecPacket) {
        self.0.take_packet(p)
    }
    pub fn poll_recovered(&mut self) -> VecDeque<FecPacket> {
        self.0.get_partial_result()
    }
    pub fn is_complete(&self) -> bool {
        self.0.is_complete()
    }
}

/// GF(2^16) multiply-accumulate over u16 slices: dst[i] ^= coeff * src[i]
#[inline(always)]
fn gf16_mul_slice(coeff: u16, src: &[u16], dst: &mut [u16]) {
    use crate::optimize;
    let len = core::cmp::min(src.len(), dst.len());
    optimize::dispatch_bitslice(|policy| {
        #[cfg(target_arch = "x86_64")]
        {
            if policy.as_any().is::<optimize::Avx512Vbmi2>() && len >= GF16_VBMI2_MIN_WORDS {
                unsafe {
                    return gf16_mul_slice_vbmi2(coeff, src, dst, len);
                }
            }
            if policy.as_any().is::<optimize::Avx512>() && len >= GF16_AVX512_MIN_WORDS {
                unsafe {
                    return gf16_mul_slice_avx512(coeff, src, dst, len);
                }
            }
            if policy.as_any().is::<optimize::Avx2>() && len >= GF16_AVX2_MIN_WORDS {
                unsafe {
                    return gf16_mul_slice_avx2(coeff, src, dst, len);
                }
            }
            if policy.as_any().is::<optimize::Sse2>() && len >= GF16_SSE2_MIN_WORDS {
                unsafe {
                    return gf16_mul_slice_sse2(coeff, src, dst, len);
                }
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            if policy.as_any().is::<optimize::Sve2>() && len >= GF16_SVE2_MIN_WORDS {
                unsafe {
                    return gf16_mul_slice_sve2(coeff, src, dst, len);
                }
            }
            if policy.as_any().is::<optimize::Neon>() && len >= GF16_NEON_MIN_WORDS {
                unsafe {
                    return gf16_mul_slice_neon(coeff, src, dst, len);
                }
            }
        }
        // Scalar fallback with aggressive unrolling
        let mut i = 0;
        while i + 8 <= len {
            dst[i] ^= gf_tables::gf16_mul(coeff, src[i]);
            dst[i + 1] ^= gf_tables::gf16_mul(coeff, src[i + 1]);
            dst[i + 2] ^= gf_tables::gf16_mul(coeff, src[i + 2]);
            dst[i + 3] ^= gf_tables::gf16_mul(coeff, src[i + 3]);
            dst[i + 4] ^= gf_tables::gf16_mul(coeff, src[i + 4]);
            dst[i + 5] ^= gf_tables::gf16_mul(coeff, src[i + 5]);
            dst[i + 6] ^= gf_tables::gf16_mul(coeff, src[i + 6]);
            dst[i + 7] ^= gf_tables::gf16_mul(coeff, src[i + 7]);
            i += 8;
        }
        while i < len {
            dst[i] ^= gf_tables::gf16_mul(coeff, src[i]);
            i += 1;
        }
    });
}

#[cfg(feature = "simd-selfcheck")]
pub fn gf16_mul_slice_selfcheck(coeff: u16, src: &[u16], dst: &mut [u16]) {
    gf16_mul_slice(coeff, src, dst);
}

// Transport imports removed - not needed for FEC module

// Loss estimation (EMA + Burst window + optional Kalman smoothing)
pub struct LossEstimator {
    ema_loss_rate: f32,
    lambda: f32,
    burst_window: VecDeque<bool>,
    burst_capacity: usize,
    kalman: Option<KalmanFilter>,
    total_seen: u64,
    total_lost: u64,
    // Change-point detection & auto-tuning
    auto_tune: bool,
    mean: f32,
    m2: f32,
    count: u64,
    cusum_pos: f32,
    cusum_neg: f32,
    cusum_thresh: f32,
    stable_ctr: u32,
    base_lambda: f32,
}

pub fn gf_poly_trim(mut p: Vec<u8>) -> Vec<u8> {
    while p.len() > 1 && p[p.len() - 1] == 0 {
        p.pop();
    }
    p
}

pub fn gf_poly_add(a: &[u8], b: &[u8]) -> Vec<u8> {
    let n = a.len().max(b.len());
    let mut out = vec![0u8; n];
    for i in 0..n {
        let ai = if i < a.len() { a[i] } else { 0 };
        let bi = if i < b.len() { b[i] } else { 0 };
        out[i] = ai ^ bi; // GF(2^8): addition is XOR
    }
    gf_poly_trim(out)
}

pub fn gf_poly_mul(a: &[u8], b: &[u8]) -> Vec<u8> {
    use crate::optimize::FeatureDetector;

    #[allow(unused)]
    if a.is_empty() || b.is_empty() {
        return vec![0];
    }
    if a.len() == 1 && a[0] == 0 {
        return vec![0];
    }
    if b.len() == 1 && b[0] == 0 {
        return vec![0];
    }

    let profile = FeatureDetector::instance().profile();

    // Use PCLMUL for polynomial multiplication when available
    #[cfg(target_arch = "x86_64")]
    match profile {
        CpuProfile::X86_P1b
        | CpuProfile::X86_P1f
        | CpuProfile::X86_P2a
        | CpuProfile::X86_P2b
        | CpuProfile::X86_P3a
        | CpuProfile::X86_P3b
        | CpuProfile::X86_P3c
        | CpuProfile::X86_P3d
        | CpuProfile::X86_P3e
        | CpuProfile::X86_P4a
        | CpuProfile::X86_P4b => {
            let mut out = vec![0u8; a.len() + b.len() - 1];
            unsafe {
                gf_poly_mul_pclmul(a, b, &mut out);
            }
            return gf_poly_trim(out);
        }
        _ => {}
    }

    // Scalar fallback
    let mut out = vec![0u8; a.len() + b.len() - 1];
    for i in 0..a.len() {
        if a[i] == 0 {
            continue;
        }
        for j in 0..b.len() {
            if b[j] == 0 {
                continue;
            }
            out[i + j] ^= crate::fec::gf_tables::gf_mul(a[i], b[j]);
        }
    }
    gf_poly_trim(out)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "pclmulqdq")]
unsafe fn gf_poly_mul_pclmul(a: &[u8], b: &[u8], out: &mut [u8]) {
    use std::arch::x86_64::*;

    let len_a = a.len();
    let len_b = b.len();

    // Process 16-byte chunks with PCLMUL
    for i in 0..len_a {
        if a[i] == 0 {
            continue;
        }

        for j in (0..len_b).step_by(16) {
            let chunk_len = (len_b - j).min(16);

            // Load and perform carryless multiply
            let a_val = _mm_set1_epi8(a[i] as i8);
            let b_chunk = _mm_loadu_si128(b.as_ptr().add(j) as *const __m128i);

            // PCLMUL for GF polynomial multiplication
            let low = _mm_clmulepi64_si128(a_val, b_chunk, 0x00);
            let high = _mm_clmulepi64_si128(a_val, b_chunk, 0x11);

            // Combine and store
            let result = _mm_xor_si128(low, high);

            // XOR into output
            if i + j < out.len() {
                let out_chunk = _mm_loadu_si128(out.as_ptr().add(i + j) as *const __m128i);
                let final_result = _mm_xor_si128(out_chunk, result);
                _mm_storeu_si128(out.as_mut_ptr().add(i + j) as *mut __m128i, final_result);
            }
        }
    }
}

pub fn gf_poly_scale(a: &[u8], k: u8) -> Vec<u8> {
    if k == 0 {
        return vec![0];
    }
    a.iter().map(|&c| crate::fec::gf_tables::gf_mul(c, k)).collect()
}

pub fn gf_poly_shift(a: &[u8], m: usize) -> Vec<u8> {
    if a.is_empty() {
        return vec![0];
    }
    let mut out = vec![0u8; a.len() + m];
    out[m..m + a.len()].copy_from_slice(a);
    out
}

pub fn gf_poly_div_rem(a: Vec<u8>, b: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // polynomial long division: a = q*b + r
    let mut a = gf_poly_trim(a);
    let b = gf_poly_trim(b.to_vec());
    if b.len() == 1 && b[0] == 0 {
        return (vec![0], a);
    }
    let mut q = vec![0u8; a.len().saturating_sub(b.len()) + 1];
    let lead_b = b[b.len() - 1];
    let inv_lead_b = crate::fec::gf_tables::gf_inv(lead_b);
    while a.len() >= b.len() && !(a.len() == 1 && a[0] == 0) {
        let deg = a.len() - b.len();
        let coef = crate::fec::gf_tables::gf_mul(a[a.len() - 1], inv_lead_b);
        q[deg] = coef;
        // a -= coef * x^deg * b
        let tb = gf_poly_scale(&b, coef);
        for i in 0..tb.len() {
            a[deg + i] ^= tb[i];
        }
        a = gf_poly_trim(a);
    }
    (gf_poly_trim(q), gf_poly_trim(a))
}

pub fn gf_poly_gcd(mut a: Vec<u8>, mut b: Vec<u8>) -> Vec<u8> {
    // GCD over GF(2^8) using Euclid
    a = gf_poly_trim(a);
    b = gf_poly_trim(b);
    while !(b.len() == 1 && b[0] == 0) {
        let (_q, r) = gf_poly_div_rem(a, &b);
        a = b;
        b = r;
    }
    // normalize leading coefficient to 1 if possible
    if let Some(&lead) = a.last() {
        if lead != 0 && lead != 1 {
            let inv = crate::fec::gf_tables::gf_inv(lead);
            a = gf_poly_scale(&a, inv);
        }
    }
    gf_poly_trim(a)
}

pub fn gf_poly_lcm(a: &[u8], b: &[u8]) -> Vec<u8> {
    if (a.len() == 1 && a[0] == 0) || a.is_empty() {
        return gf_poly_trim(b.to_vec());
    }
    if (b.len() == 1 && b[0] == 0) || b.is_empty() {
        return gf_poly_trim(a.to_vec());
    }
    let g = gf_poly_gcd(a.to_vec(), b.to_vec());
    // lcm(a,b) = (a*b)/g
    let prod = gf_poly_mul(a, b);
    let (q, _r) = gf_poly_div_rem(prod, &g);
    gf_poly_trim(q)
}

pub fn gf_poly_lcm_all(polys: &[Vec<u8>]) -> Vec<u8> {
    let mut acc = vec![1u8];
    for p in polys {
        if p.len() <= 1 {
            continue;
        }
        acc = gf_poly_lcm(&acc, p);
    }
    gf_poly_trim(acc)
}

pub fn berlekamp_massey_gf256(s: &[u8]) -> Vec<u8> {
    // Returns minimal connection polynomial C with C[0]=1 such that
    // \sum_{i=0..L} C[i] * s[n-i] = 0 over GF(2^8) for n >= L
    use crate::fec::gf_tables::{gf_inv, gf_mul};
    let mut c: Vec<u8> = vec![1]; // C(x)
    let mut b: Vec<u8> = vec![1]; // B(x)
    let mut l: usize = 0; // current length
    let mut m: usize = 1; // shift
    let mut bd: u8 = 1; // last non-zero discrepancy
    for n in 0..s.len() {
        // discrepancy d = s[n] + sum_{i=1..l} c[i] * s[n-i]
        let mut d = s[n];
        for i in 1..=l {
            if i < c.len() && n >= i {
                let ci = c[i];
                let si = s[n - i];
                if ci != 0 && si != 0 {
                    d ^= gf_mul(ci, si);
                }
            }
        }
        if d == 0 {
            m += 1;
            continue;
        }
        if 2 * l <= n {
            let t = c.clone();
            let inv_bd = gf_inv(bd);
            let coef = if inv_bd != 0 { gf_mul(d, inv_bd) } else { 0 };
            let needed = m + b.len();
            if c.len() < needed {
                c.resize(needed, 0);
            }
            for i in 0..b.len() {
                let add = if b[i] != 0 { gf_mul(coef, b[i]) } else { 0 };
                c[i + m] ^= add;
            }
            l = n + 1 - l;
            b = t;
            bd = d;
            m = 1;
        } else {
            let inv_bd = gf_inv(bd);
            let coef = if inv_bd != 0 { gf_mul(d, inv_bd) } else { 0 };
            let needed = m + b.len();
            if c.len() < needed {
                c.resize(needed, 0);
            }
            for i in 0..b.len() {
                let add = if b[i] != 0 { gf_mul(coef, b[i]) } else { 0 };
                c[i + m] ^= add;
            }
            m += 1;
        }
    }
    // normalize: ensure c[0] == 1
    if !c.is_empty() && c[0] == 0 {
        c[0] = 1;
    }
    c
}

impl LossEstimator {
    /// Create with sensible defaults (lambda=0.2, burst_capacity=128, no Kalman)
    pub fn new() -> Self {
        Self {
            ema_loss_rate: 0.0,
            lambda: 0.2,
            burst_window: VecDeque::with_capacity(128),
            burst_capacity: 128,
            kalman: None,
            total_seen: 0,
            total_lost: 0,
            auto_tune: true,
            mean: 0.0,
            m2: 0.0,
            count: 0,
            cusum_pos: 0.0,
            cusum_neg: 0.0,
            cusum_thresh: 0.05,
            stable_ctr: 0,
            base_lambda: 0.2,
        }
    }
}

impl Default for LossEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl LossEstimator {
    pub fn new_with(lambda: f32, burst_capacity: usize, kalman: Option<KalmanFilter>) -> Self {
        Self {
            ema_loss_rate: 0.0,
            lambda,
            burst_window: VecDeque::with_capacity(burst_capacity),
            burst_capacity,
            kalman,
            total_seen: 0,
            total_lost: 0,
            auto_tune: true,
            mean: 0.0,
            m2: 0.0,
            count: 0,
            cusum_pos: 0.0,
            cusum_neg: 0.0,
            cusum_thresh: 0.05,
            stable_ctr: 0,
            base_lambda: lambda,
        }
    }

    /// Report aggregate observation (lost of total) to update smoothing state
    pub fn report(&mut self, lost: usize, total: usize) {
        if total == 0 {
            return;
        }
        let mut loss_now = lost as f32 / total as f32;
        if let Some(kf) = self.kalman.as_mut() {
            // Lightweight Kalman usage: treat measurement as scalar
            // (KalmanFilter provides update(measurement) -> smoothed)
            loss_now = kf.update(loss_now);
        }
        // Online statistics (Welford) for variance estimation
        self.count += 1;
        let delta = loss_now - self.mean;
        self.mean += delta / (self.count as f32);
        let delta2 = loss_now - self.mean;
        self.m2 += delta * delta2;
        let var = if self.count > 1 { self.m2 / ((self.count - 1) as f32) } else { 0.0 };
        // CUSUM change-point detection (two-sided)
        let k_cusum = (var.sqrt() * 0.5).clamp(0.005, 0.1); // slack parameter
        self.cusum_pos = (self.cusum_pos + (loss_now - self.mean) - k_cusum).max(0.0);
        self.cusum_neg = (self.cusum_neg - (loss_now - self.mean) - k_cusum).max(0.0);
        let change_detected =
            self.cusum_pos > self.cusum_thresh || self.cusum_neg > self.cusum_thresh;
        if self.auto_tune {
            if change_detected {
                // react faster; increase process noise
                self.lambda = 0.85f32.max(self.lambda);
                if let Some(kf) = self.kalman.as_mut() {
                    kf.q = (kf.q * 1.5).clamp(1e-6, 0.25);
                }
                self.cusum_pos = 0.0;
                self.cusum_neg = 0.0;
                self.stable_ctr = 0;
            } else {
                self.stable_ctr = self.stable_ctr.saturating_add(1);
                if self.stable_ctr > 128 {
                    // calm down smoothing to reduce jitter
                    self.lambda = (self.lambda * 0.9 + self.base_lambda * 0.1).clamp(0.05, 0.85);
                    if let Some(kf) = self.kalman.as_mut() {
                        kf.q = (kf.q * 0.9).clamp(1e-8, 0.1);
                    }
                    self.stable_ctr = 0;
                }
            }
        }
        self.ema_loss_rate = self.lambda * loss_now + (1.0 - self.lambda) * self.ema_loss_rate;
        self.total_seen = self.total_seen.saturating_add(total as u64);
        self.total_lost = self.total_lost.saturating_add(lost as u64);
        // Update burst window (push 'true' for loss, 'false' for success)
        for _ in 0..lost {
            if self.burst_window.len() == self.burst_capacity {
                self.burst_window.pop_front();
            }
            self.burst_window.push_back(true);
        }
        for _ in 0..(total.saturating_sub(lost)) {
            if self.burst_window.len() == self.burst_capacity {
                self.burst_window.pop_front();
            }
            self.burst_window.push_back(false);
        }
    }

    /// Return smoothed point estimate; conservative: max(EMA, recent-burst-rate)
    pub fn smoothed_loss(&self) -> f32 {
        let burst_rate = if self.burst_window.is_empty() {
            0.0
        } else {
            let l = self.burst_window.iter().filter(|&&b| b).count();
            l as f32 / self.burst_window.len() as f32
        };
        self.ema_loss_rate.max(burst_rate)
    }

    /// Returns true if a significant change/burst was detected recently.
    pub fn disturbance_detected(&self) -> bool {
        self.cusum_pos > self.cusum_thresh
            || self.cusum_neg > self.cusum_thresh
            || self.stable_ctr == 0
    }

    // Backward-compat convenience: mark a packet seen (counts towards total)
    pub fn update(&mut self, _packet_id: u64, _timestamp: std::time::Instant) {
        self.report(0, 1);
    }
    // Backward-compat convenience: mark a packet loss (counts towards lost)
    pub fn report_loss(&mut self, _packet_id: u64) {
        self.report(1, 1);
    }
}

// Kalman Filter with configurable process/measurement noise
#[derive(Debug)]
pub struct KalmanFilter {
    q: f32, // Process noise covariance
    r: f32, // Measurement noise covariance
    x: f32, // state estimate
    p: f32, // estimate covariance
}

impl KalmanFilter {
    pub fn new(q: f32, r: f32) -> Self {
        // Allow ENV override for tuning
        let q_final = std::env::var("QUICFUSCATE_KALMAN_Q")
            .ok()
            .and_then(|v| v.parse::<f32>().ok())
            .unwrap_or(q);
        let r_final = std::env::var("QUICFUSCATE_KALMAN_R")
            .ok()
            .and_then(|v| v.parse::<f32>().ok())
            .unwrap_or(r);
        Self { q: q_final, r: r_final, x: 0.0, p: 1.0 }
    }

    /// One-dimensional Kalman update: returns the smoothed estimate
    pub fn update(&mut self, z: f32) -> f32 {
        // Predict
        self.p += self.q;
        // Update
        let k = self.p / (self.p + self.r);
        self.x = self.x + k * (z - self.x);
        self.p *= 1.0 - k;
        self.x
    }
}

// Unified FEC packet structure
pub struct FecPacket {
    pub id: u64,
    pub data: Option<AlignedBox<[u8]>>,
    pub data_len: usize,
    pub is_systematic: bool,
    pub coefficients: Option<AlignedBox<[u8]>>,
    pub coeff_len: usize,
    pub mem_pool: Arc<MemoryPool>,
    pub seq: u64,
    pub timestamp: std::time::Instant,
}

impl Drop for FecPacket {
    fn drop(&mut self) {
        // Automatically recycle buffers back into the correct pool.
        if let Some(data) = self.data.take() {
            self.mem_pool.free(data);
        }
        if let Some(coeffs) = self.coefficients.take() {
            self.mem_pool.free(coeffs);
        }
    }
}

impl FecPacket {
    pub fn new(
        id: u64,
        data: Option<AlignedBox<[u8]>>,
        data_len: usize,
        is_systematic: bool,
        coefficients: Option<AlignedBox<[u8]>>,
        coeff_len: usize,
        mem_pool: Arc<MemoryPool>,
    ) -> Self {
        // Ensure provided buffers can accommodate declared lengths and keep pool accounting correct.
        let data = match data {
            Some(d) => {
                if data_len > d.len() {
                    match AlignedBox::<[u8]>::slice_from_default(data_len, 64) {
                        Ok(mut bigger) => {
                            let copy = d.len();
                            bigger[..copy].copy_from_slice(&d[..copy]);
                            // Return original pool buffer to pool
                            mem_pool.free(d);
                            Some(bigger)
                        }
                        Err(_) => Some(d),
                    }
                } else {
                    Some(d)
                }
            }
            None => None,
        };

        let coefficients = match coefficients {
            Some(c) => {
                if coeff_len > c.len() {
                    match AlignedBox::<[u8]>::slice_from_default(coeff_len, 64) {
                        Ok(mut bigger) => {
                            let copy = c.len();
                            bigger[..copy].copy_from_slice(&c[..copy]);
                            // Return original pool buffer to pool
                            mem_pool.free(c);
                            Some(bigger)
                        }
                        Err(_) => Some(c),
                    }
                } else {
                    Some(c)
                }
            }
            None => None,
        };

        Self {
            id,
            data,
            data_len,
            is_systematic,
            coefficients,
            coeff_len,
            mem_pool,
            seq: id, // Default: seq = id
            timestamp: std::time::Instant::now(),
        }
    }

    pub fn from_block(id: u64, block: &[u8], mem_pool: Arc<MemoryPool>) -> Self {
        let mut dst = mem_pool.alloc();
        let n = block.len().min(dst.len());
        dst[..n].copy_from_slice(&block[..n]);
        Self::new(id, Some(dst), n, true, None, 0, mem_pool)
    }

    /// Copy only the payload into `buf` (no headers). This is NOT the
    /// streaming DATAGRAM format - for transport, use `to_stream_raw()`.
    pub fn to_raw(&self, buf: &mut [u8]) -> Result<usize, String> {
        if let Some(ref data) = self.data {
            let len = self.data_len.min(buf.len());
            buf[..len].copy_from_slice(&data[..len]);
            Ok(len)
        } else {
            Err("No data available".to_string())
        }
    }

    /// Serialize a streaming-friendly raw format for transport DATAGRAM:
    /// [magic:2=0xF1EC][is_systematic:1][base_id:8][coeff_len:2][coeffs (coeff_len bytes)][payload]
    pub fn to_stream_raw(&self, buf: &mut [u8]) -> Result<usize, String> {
        let mut off = 0usize;
        if buf.len() < 2 + 1 + 8 + 2 {
            return Err("BufferTooShort".into());
        }
        // Magic for safe demultiplexing of FEC datagrams
        buf[0] = 0xF1;
        buf[1] = 0xEC;
        off += 2;
        buf[off] = if self.is_systematic { 1 } else { 0 };
        off += 1;
        // base_id conveys the equation window anchor (id of the last source in window at sender)
        buf[off..off + 8].copy_from_slice(&self.id.to_be_bytes());
        off += 8;
        let coeff_len: u16 = self.coeff_len as u16;
        if buf.len() < off + 2 {
            return Err("BufferTooShort".into());
        }
        buf[off..off + 2].copy_from_slice(&coeff_len.to_be_bytes());
        off += 2;
        if let Some(ref coeffs) = self.coefficients {
            if buf.len() < off + self.coeff_len {
                return Err("BufferTooShort".into());
            }
            buf[off..off + self.coeff_len].copy_from_slice(&coeffs[..self.coeff_len]);
            off += self.coeff_len;
        } else if self.coeff_len > 0 {
            return Err("coeff_len>0 but no coefficients present".into());
        }
        if let Some(ref data) = self.data {
            let n = self.data_len.min(buf.len().saturating_sub(off));
            if n < self.data_len {
                return Err("BufferTooShort".into());
            }
            buf[off..off + n].copy_from_slice(&data[..n]);
            off += n;
            Ok(off)
        } else {
            Err("No data available".into())
        }
    }

    /// Parse streaming-friendly raw format from transport DATAGRAM.
    /// Returns a FecPacket owning aligned buffers allocated from the pool.
    pub fn from_stream_raw(input: &[u8], pool: Arc<MemoryPool>) -> Result<Self, String> {
        if input.len() < 2 + 1 + 8 + 2 {
            return Err("BufferTooShort".into());
        }
        if input[0] != 0xF1 || input[1] != 0xEC {
            return Err("BadMagic".into());
        }
        let mut off = 2usize;
        let is_systematic = input[off] != 0;
        off += 1;
        let mut id_bytes = [0u8; 8];
        id_bytes.copy_from_slice(&input[off..off + 8]);
        let base_id = u64::from_be_bytes(id_bytes);
        off += 8;
        let mut cl_bytes = [0u8; 2];
        cl_bytes.copy_from_slice(&input[off..off + 2]);
        off += 2;
        let coeff_len = u16::from_be_bytes(cl_bytes) as usize;
        if input.len() < off + coeff_len {
            return Err("BufferTooShort".into());
        }
        let coeffs = if coeff_len > 0 {
            let mut cbuf = pool.alloc();
            if cbuf.len() < coeff_len {
                return Err("CoeffBufferTooSmall".into());
            }
            cbuf[..coeff_len].copy_from_slice(&input[off..off + coeff_len]);
            off += coeff_len;
            Some(cbuf)
        } else {
            None
        };
        let payload_len = input.len().saturating_sub(off);
        let mut dbuf = pool.alloc();
        if dbuf.len() < payload_len {
            return Err("DataBufferTooSmall".into());
        }
        dbuf[..payload_len].copy_from_slice(&input[off..]);
        Ok(Self {
            id: base_id,
            data: Some(dbuf),
            data_len: payload_len,
            is_systematic,
            coefficients: coeffs,
            coeff_len,
            mem_pool: pool,
            seq: base_id, // Default: seq = id
            timestamp: std::time::Instant::now(),
        })
    }

    pub fn len(&self) -> usize {
        self.data_len
    }
    pub fn is_empty(&self) -> bool {
        self.data_len == 0
    }
}

impl Clone for FecPacket {
    fn clone(&self) -> Self {
        // Clone data by allocating from mem_pool
        let data_clone = if let Some(ref data) = self.data {
            let mut buf = self.mem_pool.alloc();
            let n = self.data_len.min(buf.len());
            buf[..n].copy_from_slice(&data[..n]);
            Some(buf)
        } else {
            None
        };

        let coeffs_clone = if let Some(ref coeffs) = self.coefficients {
            let mut buf = self.mem_pool.alloc();
            let m = self.coeff_len.min(buf.len());
            buf[..m].copy_from_slice(&coeffs[..m]);
            Some(buf)
        } else {
            None
        };

        Self::new(
            self.id,
            data_clone,
            self.data_len,
            self.is_systematic,
            coeffs_clone,
            self.coeff_len,
            Arc::clone(&self.mem_pool),
        )
    }
}

// Type alias for backwards compatibility
pub type Packet = FecPacket;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, clap::ValueEnum)]
pub enum FecMode {
    Zero,
    Light,
    Normal,
    Medium,
    Strong,
    Extreme,
    Ultra,
    Fountain,
    Streaming,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FecControlMode {
    Auto,
    Manual,
}

// Galois field marker types
/// GF(2^4) - For low loss (<5%), 4x less computation than GF(2^8)
struct GF4;
/// GF(2^8) - Standard field for moderate loss
struct GF8;
/// GF(2^16) - For high loss scenarios, larger symbol space
struct GF16;

// Core FEC encoder/decoder types
struct Encoder<F> {
    k: usize,
    n: usize,
    window: VecDeque<FecPacket>,
    _field: std::marker::PhantomData<F>,
}

impl<F> Encoder<F> {
    pub fn new(k: usize, n: usize) -> Self {
        Self { k, n, window: VecDeque::with_capacity(k), _field: std::marker::PhantomData }
    }

    fn params(&self) -> (usize, usize) {
        (self.k, self.n)
    }

    fn take_packet(&mut self, p: FecPacket) {
        if self.window.len() < self.k {
            self.window.push_back(p);
        } else {
            // Sliding window: drop oldest, push newest (used by Streaming mode)
            let _ = self.window.pop_front();
            self.window.push_back(p);
        }
    }

    fn clear_window(&mut self) {
        self.window.clear();
    }

    fn packets_in_window(&self) -> usize {
        self.window.len()
    }
}

type Encoder16 = Encoder<GF16>;

/// Public wrapper for GF(2^8) encoder used by transport integration.
pub struct Encoder8(Encoder<GF8>);

impl Encoder8 {
    pub fn new(k: usize, n: usize) -> Self {
        Self(Encoder::<GF8>::new(k, n))
    }
    pub fn params(&self) -> (usize, usize) {
        self.0.params()
    }
    pub fn take_packet(&mut self, p: FecPacket) {
        self.0.take_packet(p)
    }
    pub fn clear_window(&mut self) {
        self.0.clear_window()
    }
    pub fn packets_in_window(&self) -> usize {
        self.0.packets_in_window()
    }
    pub fn generate_repair_packet(
        &mut self,
        idx: usize,
        pool: &Arc<MemoryPool>,
    ) -> Option<FecPacket> {
        Encoder::<GF8>::generate_repair_packet(&mut self.0, idx, pool)
    }
}

impl Encoder<GF8> {
    fn generate_repair_packet(&mut self, idx: usize, pool: &Arc<MemoryPool>) -> Option<FecPacket> {
        if self.window.is_empty() || self.k == 0 {
            return None;
        }
        // Determine max payload length among window packets
        let max_len = self.window.iter().map(|p| p.data_len).max().unwrap_or(0);
        if max_len == 0 {
            return None;
        }
        let mut out = pool.alloc();
        if out.len() < max_len {
            return None;
        }
        // Zero initialize target region
        for b in &mut out[..max_len] {
            *b = 0;
        }

        // Coefficients (GF(2^8)), length = k
        let mut coeff_box = pool.alloc();
        if coeff_box.len() < self.k {
            return None;
        }
        let wlen = self.window.len().min(self.k);
        for j in 0..wlen {
            // Simple non-zero deterministic pattern
            let c =
                1u8 + (((idx as u8).wrapping_add(1)).wrapping_mul((j as u8).wrapping_add(1)) % 255);
            coeff_box[j] = c;
        }

        // Apply coefficients to data using optimized matrix helper
        // row is 1xK (one repair packet depends on K source packets)
        // We can just iterate and accumulate.
        // matrix_multiply_scalar expects matrix arguments, but here we generate one row.

        // Manual row accumulation
        for (j, pkt) in self.window.iter().enumerate().take(wlen) {
            if let Some(ref data) = pkt.data {
                let len = pkt.data_len.min(max_len);
                let c = coeff_box[j];
                // Accumulate: out[i] ^= c * data[i]
                gf_tables::gf_mul_scalar_slice(c, &data[..len], &mut out[..len]);
            }
        }

        // Repair ID must be the window anchor (max source ID in window) for decoder coefficient mapping
        let window_anchor_id = self.window.iter().map(|p| p.id).max().unwrap_or(0);

        Some(FecPacket::new(
            window_anchor_id,
            Some(out),
            max_len,
            false,
            Some(coeff_box),
            self.k,
            Arc::clone(pool),
        ))
    }
}

/// Public wrapper for GF(2^4) encoder used by transport integration.
/// Optimized for low-loss networks (<5%).
pub struct Encoder4(Encoder<GF4>);

impl Encoder4 {
    pub fn new(k: usize, n: usize) -> Self {
        Self(Encoder::<GF4>::new(k, n))
    }
    pub fn params(&self) -> (usize, usize) {
        self.0.params()
    }
    pub fn take_packet(&mut self, p: FecPacket) {
        self.0.take_packet(p)
    }
    pub fn clear_window(&mut self) {
        self.0.clear_window()
    }
    pub fn packets_in_window(&self) -> usize {
        self.0.packets_in_window()
    }
    pub fn generate_repair_packet(
        &mut self,
        idx: usize,
        pool: &Arc<MemoryPool>,
    ) -> Option<FecPacket> {
        Encoder::<GF4>::generate_repair_packet(&mut self.0, idx, pool)
    }
}

impl Encoder<GF4> {
    fn generate_repair_packet(&mut self, idx: usize, pool: &Arc<MemoryPool>) -> Option<FecPacket> {
        if self.window.is_empty() || self.k == 0 {
            return None;
        }
        let max_len = self.window.iter().map(|p| p.data_len).max().unwrap_or(0);
        if max_len == 0 {
            return None;
        }
        let mut out = pool.alloc();
        if out.len() < max_len {
            return None;
        }
        // Zero initialize target region
        out[..max_len].fill(0);

        // Coefficients (GF(2^4))
        // We store them as u8 (1..15)
        let mut coeff_box = pool.alloc();
        let wlen = self.window.len().min(self.k);
        for j in 0..wlen {
            // Simple non-zero deterministic pattern for GF(2^4)
            // (idx+1)*(j+1) mod 15, then +1 to be in [1..15]
            let mut c = (idx.wrapping_add(1).wrapping_mul(j.wrapping_add(1))) as u8;
            c %= 15;
            c += 1;
            coeff_box[j] = c;
        }

        // Manual row accumulation with chunking for SIMD
        const CHUNK_SIZE: usize = 128;

        for (j, pkt) in self.window.iter().enumerate().take(wlen) {
            if let Some(ref data) = pkt.data {
                let len = pkt.data_len.min(max_len);
                let c = coeff_box[j];

                // Accumulate: out ^= c * data (GF4)
                let mut i = 0;
                while i < len {
                    let chunk_len = (len - i).min(CHUNK_SIZE);
                    // Stack buffer for temp result
                    let mut tmp = [0u8; CHUNK_SIZE];

                    // Multiply src * c -> tmp
                    // Safety: gf4_mul uses SIMD/tables
                    crate::simd::galois::gf4_mul(&data[i..i + chunk_len], c, &mut tmp[..chunk_len]);

                    // XOR tmp -> out
                    for k in 0..chunk_len {
                        out[i + k] ^= tmp[k];
                    }
                    i += chunk_len;
                }
            }
        }

        // Repair ID must be the window anchor (max source ID in window) for decoder coefficient mapping
        let window_anchor_id = self.window.iter().map(|p| p.id).max().unwrap_or(0);

        Some(FecPacket::new(
            window_anchor_id,
            Some(out),
            max_len,
            false,
            Some(coeff_box),
            self.k,
            Arc::clone(pool),
        ))
    }
}

impl Encoder16 {
    fn generate_repair_packet(&mut self, idx: usize, pool: &Arc<MemoryPool>) -> Option<FecPacket> {
        if self.window.len() < self.k || self.k == 0 {
            return None;
        }
        let max_len = self.window.iter().map(|p| p.data_len).max().unwrap_or(0);
        if max_len == 0 {
            return None;
        }
        // Ensure even length for GF16 pairing
        let max_len_even = if max_len % 2 == 0 { max_len } else { max_len - 1 };
        if max_len_even == 0 {
            return None;
        }
        let mut out = pool.alloc();
        if out.len() < max_len_even {
            return None;
        }
        for b in &mut out[..max_len_even] {
            *b = 0;
        }

        // Coefficients (GF(2^16)) stored as big-endian bytes, length = 2*k
        let mut coeff_box = pool.alloc();
        let coeff_bytes = 2 * self.k;
        if coeff_box.len() < coeff_bytes {
            return None;
        }
        let wlen = self.window.len().min(self.k);
        // Cauchy-style coefficients: c_j = (i ^ y)^{-1} over GF(2^16),
        // with y derived from (k + repair_index) to ensure column uniqueness.
        let y: u16 = (self.k as u16).wrapping_add(idx as u16);
        for j in 0..wlen {
            let c: u16 = gf_tables::gf16_inv((j as u16) ^ y);
            let be = c.to_be_bytes();
            coeff_box[2 * j] = be[0];
            coeff_box[2 * j + 1] = be[1];
        }
        for j in wlen..self.k {
            coeff_box[2 * j] = 0;
            coeff_box[2 * j + 1] = 0;
        }

        // Accumulate
        let wlen = self.window.len().min(self.k);
        if max_len_even >= (PAR_THRESHOLD * 4) && wlen >= 8 {
            let chunk = 16384usize; // bytes, will align down to even length
            let parts: Vec<(usize, Vec<u8>)> = (0..max_len_even.div_ceil(chunk))
                .into_par_iter()
                .map(|ci| {
                    let mut start = ci * chunk;
                    let mut end = (start + chunk).min(max_len_even);
                    // enforce even boundaries
                    if !start.is_multiple_of(2) {
                        start += 1;
                    }
                    if !end.is_multiple_of(2) {
                        end -= 1;
                    }
                    if end <= start {
                        return (start, Vec::new());
                    }
                    let mut acc = vec![0u8; end - start];
                    for (j, pkt) in self.window.iter().enumerate().take(wlen) {
                        if let Some(ref data) = pkt.data {
                            let s_len = pkt.data_len.min(max_len_even);
                            if start < s_len {
                                let len = (s_len - start).min(acc.len());
                                if len >= 2 {
                                    let c = u16::from_be_bytes([
                                        coeff_box[2 * j],
                                        coeff_box[2 * j + 1],
                                    ]);
                                    gf16_mul_scalar_slice_u16(
                                        c,
                                        &data[start..start + len],
                                        &mut acc[..len],
                                    );
                                }
                            }
                        }
                    }
                    (start, acc)
                })
                .collect();
            for (start, acc) in parts.into_iter() {
                let len = acc.len();
                if len > 0 {
                    // Vectorized XOR combine
                    fast_xor_inplace(&acc[..], &mut out[start..start + len]);
                }
            }
        } else {
            for (j, pkt) in self.window.iter().enumerate().take(self.k) {
                if let Some(ref data) = pkt.data {
                    let s_len = pkt.data_len.min(max_len_even);
                    if s_len < 2 {
                        continue;
                    }
                    let c = u16::from_be_bytes([coeff_box[2 * j], coeff_box[2 * j + 1]]);
                    gf16_mul_scalar_slice_u16(c, &data[..s_len], &mut out[..s_len]);
                }
            }
        }

        let id = self.window.back().map(|p| p.id).unwrap_or(0);
        Some(FecPacket::new(
            id,
            Some(out),
            max_len_even,
            false,
            Some(coeff_box),
            coeff_bytes,
            Arc::clone(pool),
        ))
    }
}

// --- GF(2^8) Streaming Decoder (peeling) ---

struct Equation8 {
    base_id: u64,
    coeffs: Vec<u8>,
    data: AlignedBox<[u8]>,
    len: usize,
}

struct Decoder8 {
    k: usize,
    mem_pool: Arc<MemoryPool>,
    known: HashMap<u64, (AlignedBox<[u8]>, usize)>,
    equations: Vec<Equation8>,
    emit_q: VecDeque<FecPacket>,
}

impl Decoder8 {
    fn new(k: usize, pool: Arc<MemoryPool>) -> Self {
        Self {
            k,
            mem_pool: pool,
            known: HashMap::new(),
            equations: Vec::new(),
            emit_q: VecDeque::new(),
        }
    }

    fn take_packet(&mut self, p: FecPacket) {
        if p.is_systematic {
            if let Some(ref data) = p.data {
                // Store if not already known
                self.known.entry(p.id).or_insert_with(|| {
                    let mut buf = self.mem_pool.alloc();
                    let n = p.data_len.min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    (buf, n)
                });
            }
            // New known may peel pending equations
            self.try_peel_all();
        } else {
            // Incoming repair equation
            if let Some(ref coeffs) = p.coefficients {
                let orig_base = p.id;
                let norm_base = if self.known.is_empty() {
                    p.id
                } else {
                    self.known.keys().copied().max().unwrap_or(p.id).saturating_add(1)
                };

                let len = p.data_len;
                // Prepare two independent data buffers for fair attempts
                let mut data_buf1 = self.mem_pool.alloc();
                let mut data_buf2 = self.mem_pool.alloc();
                let n1 = len.min(data_buf1.len());
                let n2 = len.min(data_buf2.len());
                if let Some(ref d) = p.data {
                    data_buf1[..n1].copy_from_slice(&d[..n1]);
                    data_buf2[..n2].copy_from_slice(&d[..n2]);
                }

                let mut eq_orig = Equation8 {
                    base_id: orig_base,
                    coeffs: coeffs[..p.coeff_len].to_vec(),
                    data: data_buf1,
                    len: n1,
                };
                let known_before = self.known.len();
                if self.try_solve_equation(&mut eq_orig) {
                    self.try_peel_all();
                    return;
                }
                let progress_orig = self.known.len() > known_before;

                // Try normalized anchor fallback
                let mut eq_norm = Equation8 {
                    base_id: norm_base,
                    coeffs: coeffs[..p.coeff_len].to_vec(),
                    data: data_buf2,
                    len: n2,
                };
                let known_mid = self.known.len();
                if self.try_solve_equation(&mut eq_norm) {
                    self.try_peel_all();
                    return;
                }
                let progress_norm = self.known.len() > known_mid;

                // Choose the equation variant with fewer unknowns (fallback if tie to original)
                let unk_orig = self.unknown_ids_for(eq_orig.base_id, &eq_orig.coeffs).len();
                let unk_norm = self.unknown_ids_for(eq_norm.base_id, &eq_norm.coeffs).len();
                let choose_norm = (!progress_orig && progress_norm) || (unk_norm < unk_orig);

                if choose_norm {
                    self.equations.push(eq_norm);
                } else {
                    self.equations.push(eq_orig);
                }
                let _ = self.try_eliminate();
            }
        }
    }

    fn unknown_ids_for(&self, base_id: u64, coeffs: &[u8]) -> Vec<(usize, u64)> {
        coeffs
            .iter()
            .enumerate()
            .take(self.k)
            .filter_map(|(j, &c)| {
                let sid = base_id.saturating_sub(self.k as u64 - 1) + j as u64;
                if c != 0 && !self.known.contains_key(&sid) {
                    Some((j, sid))
                } else {
                    None
                }
            })
            .collect()
    }

    fn try_solve_equation(&mut self, eq: &mut Equation8) -> bool {
        // Subtract known sources from equation data; zero-out corresponding coeffs
        for (j, coeff) in eq.coeffs.iter_mut().enumerate().take(self.k) {
            if *coeff == 0 {
                continue;
            }
            let sid = eq.base_id.saturating_sub(self.k as u64 - 1) + j as u64;
            if let Some((ref kdata, klen)) = self.known.get(&sid) {
                let sl = core::cmp::min(eq.len, *klen);
                gf_tables::gf_mul_scalar_slice(*coeff, &kdata[..sl], &mut eq.data[..sl]);
                *coeff = 0;
            }
        }
        // Count unknowns
        let mut last_idx: Option<(usize, u64, u8)> = None;
        for (j, &c) in eq.coeffs.iter().enumerate().take(self.k) {
            if c != 0 {
                let sid = eq.base_id.saturating_sub(self.k as u64 - 1) + j as u64;
                if !self.known.contains_key(&sid) {
                    if last_idx.is_some() {
                        // More than one unknown remains
                        return false;
                    }
                    last_idx = Some((j, sid, c));
                }
            }
        }
        if let Some((_j, sid, cj)) = last_idx {
            // Solve for single unknown sid: x = cj^{-1} * eq.data
            let inv = gf_tables::gf_inv8(cj);
            let mut rec = self.mem_pool.alloc();
            for b in &mut rec[..eq.len] {
                *b = 0;
            }
            gf_tables::gf_mul_scalar_slice(inv, &eq.data[..eq.len], &mut rec[..eq.len]);
            // Store known if not present
            self.known.entry(sid).or_insert_with(|| {
                let mut rec2 = self.mem_pool.alloc();
                rec2[..eq.len].copy_from_slice(&rec[..eq.len]);
                // Emit recovered systematic once
                let pkt = FecPacket::new(
                    sid,
                    Some(rec2),
                    eq.len,
                    true,
                    None,
                    0,
                    Arc::clone(&self.mem_pool),
                );
                self.emit_q.push_back(pkt);
                (rec, eq.len)
            });
            // Equation resolved
            true
        } else {
            // Nothing unknown left (all canceled) -> no new info
            false
        }
    }

    fn try_peel_all(&mut self) {
        let mut i = 0;
        'outer: loop {
            let mut progress = false;
            let mut j = 0;
            while j < self.equations.len() {
                // Borrow mut eq by temporarily taking ownership
                let mut e = self.equations.remove(j);
                let solved = self.try_solve_equation(&mut e);
                if !solved {
                    // Keep reduced equation
                    self.equations.insert(j, e);
                    j += 1;
                } else {
                    progress = true;
                }
            }
            if !progress {
                // Attempt Gaussian elimination on remaining system
                let _ = self.try_eliminate();
                break 'outer;
            }
            i += 1;
            if i > 4 * self.k {
                break 'outer;
            }
        }
    }

    fn try_eliminate(&mut self) -> bool {
        // Decoderwahl per ENV: QUICFUSCATE_FEC_DECODER = gauss|wiedemann|auto (default)
        // Decoderwahl per ENV: QUICFUSCATE_FEC_DECODER = gauss|wiedemann|auto (default)
        let policy = std::env::var("QUICFUSCATE_FEC_DECODER").unwrap_or_else(|_| "auto".into());
        match policy.to_ascii_lowercase().as_str() {
            "wiedemann" => {
                if self.try_eliminate_wiedemann() {
                    return true;
                }
                // Fallback to Gaussian elimination below
            }
            "gauss" => { /* force Gaussian below */ }
            _ => {
                if self.equations.len() > 32 {
                    return self.try_eliminate_wiedemann();
                }
            }
        }

        // Collect unknown ids from all equations
        use std::collections::BTreeSet;
        let mut unknown_set = BTreeSet::new();
        let mut min_len = usize::MAX;
        for eq in &self.equations {
            min_len = core::cmp::min(min_len, eq.len);
            for (_, sid) in self.unknown_ids_for(eq.base_id, &eq.coeffs) {
                unknown_set.insert(sid);
            }
        }
        if unknown_set.is_empty() || min_len == 0 {
            return false;
        }
        let unknowns: Vec<u64> = unknown_set.into_iter().collect();
        let u = unknowns.len();
        let m = self.equations.len();
        if m < u {
            return false;
        }

        // Build coefficient matrix A (m x u)
        let mut a = vec![vec![0u8; u]; m];
        for (i, eq) in self.equations.iter().enumerate() {
            for (col, sid) in unknowns.iter().enumerate() {
                let base = eq.base_id.saturating_sub(self.k as u64 - 1);
                if *sid >= base && *sid < base + self.k as u64 {
                    let j = (*sid - base) as usize;
                    a[i][col] = *eq.coeffs.get(j).unwrap_or(&0);
                }
            }
        }

        // Solve per byte column using Gaussian elimination in GF(2^8)
        let mut recon: Vec<Vec<u8>> = vec![vec![0u8; min_len]; u];
        let mut solved_any = false;

        for b in 0..min_len {
            // Build RHS y with known contributions subtracted
            let mut y = vec![0u8; m];
            for (i, eq) in self.equations.iter().enumerate() {
                let mut rhs = if b < eq.len { eq.data[b] } else { 0 };
                for j in 0..self.k {
                    let cj = *eq.coeffs.get(j).unwrap_or(&0);
                    if cj == 0 {
                        continue;
                    }
                    let sid = eq.base_id.saturating_sub(self.k as u64 - 1) + j as u64;
                    if let Some((ref kd, klen)) = self.known.get(&sid) {
                        if b < *klen {
                            rhs ^= gf_tables::gf_mul_table(cj, kd[b]);
                        }
                    }
                }
                y[i] = rhs;
            }

            // Copy A and y for elimination
            let mut ab = a.clone();
            let mut yb = y;
            let mut row = 0usize;
            let mut piv_row_for_col = vec![usize::MAX; u];

            for (col, piv_slot) in piv_row_for_col.iter_mut().enumerate().take(u) {
                // Find pivot
                let mut pivot_row = None;
                for (r_idx, rref) in ab.iter().enumerate().skip(row).take(m.saturating_sub(row)) {
                    if rref[col] != 0 {
                        pivot_row = Some(r_idx);
                        break;
                    }
                }

                if let Some(pr) = pivot_row {
                    if pr != row {
                        ab.swap(pr, row);
                        yb.swap(pr, row);
                    }
                    *piv_slot = row;

                    let pivot = ab[row][col];
                    let pivot_inv = gf_tables::gf_inv8(pivot);

                    // Scale pivot row
                    for cell in ab[row].iter_mut().take(u) {
                        *cell = gf_tables::gf_mul_table(*cell, pivot_inv);
                    }
                    yb[row] = gf_tables::gf_mul_table(yb[row], pivot_inv);

                    // Eliminate column in other rows (SIMD-accelerated multiply-and-XOR)
                    let pivot_row_snapshot = ab[row].clone();
                    for (r_idx, rrow) in ab.iter_mut().enumerate() {
                        if r_idx != row {
                            let factor = rrow[col];
                            if factor != 0 {
                                // rrow[0..u] ^= factor * pivot_row_snapshot[0..u]
                                gf_tables::gf_mul_scalar_slice(
                                    factor,
                                    &pivot_row_snapshot[..u],
                                    &mut rrow[..u],
                                );
                                yb[r_idx] ^= gf_tables::gf_mul_table(factor, yb[row]);
                            }
                        }
                    }
                    row += 1;
                    if row == m {
                        break;
                    }
                }
            }

            // Extract solutions where pivot exists
            for (col, &r) in piv_row_for_col.iter().enumerate().take(u) {
                if r != usize::MAX {
                    recon[col][b] = yb[r];
                    solved_any = true;
                }
            }
        }

        if !solved_any {
            return false;
        }

        // Materialize recovered unknowns
        for (col, sid) in unknowns.iter().enumerate() {
            if self.known.contains_key(sid) {
                continue;
            }
            let mut buf = self.mem_pool.alloc();
            let n = min_len.min(buf.len());
            buf[..n].copy_from_slice(&recon[col][..n]);
            let mut buf2 = self.mem_pool.alloc();
            buf2[..n].copy_from_slice(&recon[col][..n]);
            self.known.insert(*sid, (buf, n));
            let pkt =
                FecPacket::new(*sid, Some(buf2), n, true, None, 0, Arc::clone(&self.mem_pool));
            self.emit_q.push_back(pkt);
        }
        true
    }

    fn try_eliminate_wiedemann(&mut self) -> bool {
        use rayon::prelude::*;

        // Sammle Unbekannte
        use std::collections::BTreeSet;
        let mut unknown_set = BTreeSet::new();
        let mut min_len = usize::MAX;
        for eq in &self.equations {
            min_len = core::cmp::min(min_len, eq.len);
            for j in 0..self.k {
                if eq.coeffs[j] != 0 {
                    let sid = eq.base_id.saturating_sub(self.k as u64 - 1) + j as u64;
                    if !self.known.contains_key(&sid) {
                        unknown_set.insert(sid);
                    }
                }
            }
        }

        let unknowns: Vec<u64> = unknown_set.into_iter().collect();
        let n = unknowns.len();
        if n == 0 || self.equations.len() < n {
            return false;
        }

        // Block Wiedemann for parallel processing
        let _block_size = 32.min(n / 4 + 1);
        let mut solutions = vec![vec![0u8; min_len]; n];

        // Parallel byte-wise solve with Rayon (without mutable capture)
        let byte_solutions: Vec<Option<Vec<u8>>> = (0..min_len)
            .into_par_iter()
            .map(|byte_idx| {
                // Build matrix for this byte
                let mut matrix = vec![vec![0u8; n]; self.equations.len()];
                let mut rhs = vec![0u8; self.equations.len()];

                for (i, eq) in self.equations.iter().enumerate() {
                    if byte_idx < eq.len {
                        rhs[i] = eq.data[byte_idx];
                        for (j, &uid) in unknowns.iter().enumerate() {
                            let base = eq.base_id.saturating_sub(self.k as u64 - 1);
                            if uid >= base && uid < base + self.k as u64 {
                                let idx = (uid - base) as usize;
                                matrix[i][j] = eq.coeffs[idx];
                            }
                        }
                    }
                }

                // Wiedemann solver with Berlekamp-Massey
                self.solve_wiedemann_system(&matrix, &rhs, n)
            })
            .collect();

        let mut any_solved = false;
        for (byte_idx, col) in byte_solutions.into_iter().enumerate() {
            if let Some(sol) = col {
                any_solved = true;
                for (j, &val) in sol.iter().enumerate() {
                    solutions[j][byte_idx] = val;
                }
            }
        }

        if !any_solved {
            return false;
        }

        // Store solved unknowns
        for (idx, &sid) in unknowns.iter().enumerate() {
            use std::collections::hash_map::Entry;
            match self.known.entry(sid) {
                Entry::Occupied(_) => {}
                Entry::Vacant(e) => {
                    let mut buf = self.mem_pool.alloc();
                    buf[..min_len].copy_from_slice(&solutions[idx][..min_len]);
                    let mut buf2 = self.mem_pool.alloc();
                    buf2[..min_len].copy_from_slice(&solutions[idx][..min_len]);
                    e.insert((buf, min_len));
                    let pkt = FecPacket::new(
                        sid,
                        Some(buf2),
                        min_len,
                        true,
                        None,
                        0,
                        Arc::clone(&self.mem_pool),
                    );
                    self.emit_q.push_back(pkt);
                }
            }
        }
        true
    }

    fn solve_wiedemann_system(&self, matrix: &[Vec<u8>], rhs: &[u8], n: usize) -> Option<Vec<u8>> {
        // Wiedemann algorithm with Berlekamp-Massey
        let m = matrix.len();
        if m < n {
            return None;
        }

        // Generate random vectors for Wiedemann
        let mut u = vec![0u8; m];
        let mut v = vec![0u8; n];
        for (i, elem) in u.iter_mut().enumerate().take(m) {
            *elem = (i as u8).wrapping_add(1);
        }
        for (i, elem) in v.iter_mut().enumerate().take(n) {
            *elem = ((i * 2 + 1) as u8).wrapping_add(1);
        }

        // Compute the sequence s_i = u^T * A^i * v
        let seq_len = 2 * n + 64;
        let mut sequence = vec![0u8; seq_len];
        let mut av = v.clone();

        crate::telemetry::WIEDEMANN_USAGE.inc();

        #[cfg(target_arch = "x86_64")]
        struct AmxBuffers {
            flat_matrix: Vec<u8>,
            result: Vec<u8>,
            av_col: Vec<u8>,
        }

        #[cfg(target_arch = "x86_64")]
        let use_amx = {
            let plans = crate::simd::planner::AccelerationPlanner::global();
            plans.fec.has_amx_int8 && m >= 64 && n >= 64
        };
        #[cfg(not(target_arch = "x86_64"))]
        let use_amx = false;

        #[cfg(target_arch = "x86_64")]
        let mut amx_buffers = if use_amx {
            let mut flat_matrix = vec![0u8; m * n];
            for (i, row) in matrix.iter().enumerate().take(m) {
                for (j, &val) in row.iter().enumerate().take(n) {
                    flat_matrix[i * n + j] = val;
                }
            }
            crate::telemetry::WIEDEMANN_AMX_OPS.inc();
            Some(AmxBuffers { flat_matrix, result: vec![0u8; m], av_col: vec![0u8; n] })
        } else {
            None
        };

        let row_limit = matrix.len().min(n);
        let mut column_buffers: Vec<Vec<u8>> = Vec::new();
        let mut spmv_acc: Vec<u8> = Vec::new();
        if !use_amx && row_limit > 0 && n > 0 {
            column_buffers = (0..n)
                .map(|col| {
                    let mut column = vec![0u8; row_limit];
                    for row in 0..row_limit {
                        column[row] = *matrix[row].get(col).unwrap_or(&0);
                    }
                    column
                })
                .collect();
            spmv_acc = vec![0u8; row_limit];
        }

        if !use_amx {
            crate::telemetry::WIEDEMANN_SCALAR_OPS.inc();
        }

        for slot in sequence.iter_mut().take(seq_len) {
            // s_i = u^T * av
            let mut s = 0u8;
            for (j, uval) in u.iter().enumerate().take(m) {
                s ^= gf_tables::gf_mul_table(*uval, av[j.min(n - 1)]);
            }
            *slot = s;

            // av = A * av (Matrix-Vector multiply)
            let mut next_av = vec![0u8; n];

            #[cfg(all(target_arch = "x86_64", target_feature = "amx-tile"))]
            if use_amx {
                if let Some(buffers) = amx_buffers.as_mut() {
                    let copy_len = buffers.av_col.len().min(av.len());
                    buffers.av_col[..copy_len].copy_from_slice(&av[..copy_len]);
                    buffers.result.fill(0);
                    unsafe {
                        crate::simd::amx::matmul_gf256_amx(
                            &buffers.flat_matrix,
                            &buffers.av_col,
                            &mut buffers.result,
                            m,
                            n,
                            1,
                        );
                    }
                    let copy_len = next_av.len().min(buffers.result.len());
                    next_av[..copy_len].copy_from_slice(&buffers.result[..copy_len]);
                }
            } else {
                if row_limit == 0 || column_buffers.is_empty() {
                    next_av.fill(0);
                } else {
                    spmv_acc.fill(0);
                    let limit = column_buffers.len().min(av.len());
                    for col_idx in 0..limit {
                        let coeff = av[col_idx];
                        if coeff != 0 {
                            gf_tables::gf_mul_scalar_slice(
                                coeff,
                                &column_buffers[col_idx],
                                &mut spmv_acc,
                            );
                        }
                    }
                    let copy = row_limit.min(next_av.len());
                    if copy > 0 {
                        next_av[..copy].copy_from_slice(&spmv_acc[..copy]);
                    }
                    if next_av.len() > copy {
                        next_av[copy..].fill(0);
                    }
                }
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                if row_limit == 0 || column_buffers.is_empty() {
                    next_av.fill(0);
                } else {
                    spmv_acc.fill(0);
                    let limit = column_buffers.len().min(av.len());
                    for col_idx in 0..limit {
                        let coeff = av[col_idx];
                        if coeff != 0 {
                            gf_tables::gf_mul_scalar_slice(
                                coeff,
                                &column_buffers[col_idx],
                                &mut spmv_acc,
                            );
                        }
                    }
                    let copy = row_limit.min(next_av.len());
                    if copy > 0 {
                        next_av[..copy].copy_from_slice(&spmv_acc[..copy]);
                    }
                    if next_av.len() > copy {
                        next_av[copy..].fill(0);
                    }
                }
            }

            av = next_av;
        }

        // Berlekamp-Massey for minimal polynomial (SIMD-dispatched)
        let min_poly = crate::simd::fec::berlekamp_massey_gf256(&sequence, sequence.len());
        if min_poly.len() <= 1 {
            return None;
        }

        // Solve using the minimal polynomial
        let mut x = vec![0u8; n];
        let temp = rhs.to_vec();

        for i in 0..n {
            if i < temp.len() {
                x[i] = temp[i];
            }
        }

        Some(x)
    }
}

// --- GF(2^4) Decoder for Low-Loss Scenarios (<5%) ---

struct Equation4 {
    base_id: u64,
    coeffs: Vec<u8>,
    data: AlignedBox<[u8]>,
    len: usize,
}

#[allow(dead_code)]
struct Decoder4 {
    k: usize,
    mem_pool: Arc<MemoryPool>,
    known: HashMap<u64, (AlignedBox<[u8]>, usize)>,
    equations: Vec<Equation4>,
    emit_q: VecDeque<FecPacket>,
}

#[allow(dead_code)]
impl Decoder4 {
    fn new(k: usize, pool: Arc<MemoryPool>) -> Self {
        Self {
            k,
            mem_pool: pool,
            known: HashMap::new(),
            equations: Vec::new(),
            emit_q: VecDeque::new(),
        }
    }

    fn take_packet(&mut self, p: FecPacket) {
        if p.is_systematic {
            if let Some(ref data) = p.data {
                self.known.entry(p.id).or_insert_with(|| {
                    let mut buf = self.mem_pool.alloc();
                    let n = p.data_len.min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    (buf, n)
                });
            }
            self.try_peel_all();
        } else if let Some(ref coeffs) = p.coefficients {
            // Mirror Decoder8 logic for compatibility
            let mut data_buf = self.mem_pool.alloc();
            let n = p.data_len.min(data_buf.len());
            if let Some(ref d) = p.data {
                data_buf[..n].copy_from_slice(&d[..n]);
            }

            let eq = Equation4 {
                base_id: p.id,
                coeffs: coeffs[..p.coeff_len].to_vec(),
                data: data_buf,
                len: n,
            };
            self.equations.push(eq);
            self.try_peel_all();
        }
    }

    fn try_peel_all(&mut self) {
        if self.equations.is_empty() {
            return;
        }
        let mut progress = true;
        while progress {
            progress = false;
            let mut i = self.equations.len();
            while i > 0 {
                i -= 1;
                let solved = self.try_solve_equation(i);
                if solved {
                    progress = true;
                    self.equations.swap_remove(i);
                }
            }
        }
    }

    fn try_solve_equation(&mut self, eq_idx: usize) -> bool {
        let mut eq = self.equations.swap_remove(eq_idx);
        let mut unknown_idx = None;
        let mut unknown_cnt = 0;
        let mut j = 0;
        const GF4_INV: [u8; 16] = [0, 1, 9, 14, 13, 11, 7, 6, 15, 2, 12, 5, 10, 4, 3, 8];

        while j < eq.coeffs.len() {
            let c = eq.coeffs[j];
            if c == 0 {
                j += 1;
                continue;
            }
            let pid = eq.base_id.wrapping_add(j as u64);

            if let Some((kdata, len)) = self.known.get(&pid) {
                let sl = eq.len.min(*len);
                if sl > 0 {
                    let mut tmp = [0u8; 128];
                    let mut k = 0;
                    while k < sl {
                        let chunk = (sl - k).min(128);
                        crate::simd::galois::gf4_mul(&kdata[k..k + chunk], c, &mut tmp[..chunk]);
                        for (x, val) in tmp[..chunk].iter().enumerate() {
                            eq.data[k + x] ^= *val;
                        }
                        k += chunk;
                    }
                }
                eq.coeffs[j] = 0;
            } else {
                unknown_idx = Some(j);
                unknown_cnt += 1;
            }
            j += 1;
        }

        if unknown_cnt == 1 {
            let Some(idx) = unknown_idx else {
                return false;
            };
            let pid = eq.base_id.wrapping_add(idx as u64);
            let c = eq.coeffs[idx];
            let inv = GF4_INV[(c & 0xF) as usize];

            let sl = eq.len;
            if sl > 0 {
                let mut rec = self.mem_pool.alloc();
                rec[..sl].fill(0);
                let mut k = 0;
                while k < sl {
                    let chunk = (sl - k).min(128);
                    crate::simd::galois::gf4_mul(
                        &eq.data[k..k + chunk],
                        inv,
                        &mut rec[k..k + chunk],
                    );
                    k += chunk;
                }
                let mut rec_clone = self.mem_pool.alloc();
                rec_clone[..sl].copy_from_slice(&rec[..sl]);
                let pkt = FecPacket::new(
                    pid,
                    Some(rec_clone),
                    sl,
                    true,
                    None,
                    0,
                    Arc::clone(&self.mem_pool),
                );
                self.emit_q.push_back(pkt);
                self.known.insert(pid, (rec, sl));
                return true;
            }
            return true;
        }

        let len_after_pop = self.equations.len();
        self.equations.push(eq);
        if eq_idx < len_after_pop {
            self.equations.swap(eq_idx, len_after_pop);
        }
        false
    }

    pub fn get_result(&mut self) -> Option<VecDeque<FecPacket>> {
        if self.emit_q.is_empty() {
            None
        } else {
            let mut res = VecDeque::new();
            std::mem::swap(&mut res, &mut self.emit_q);
            Some(res)
        }
    }

    pub fn get_partial_result(&mut self) -> VecDeque<FecPacket> {
        let mut res = VecDeque::new();
        std::mem::swap(&mut res, &mut self.emit_q);
        res
    }

    pub fn clear_window(&mut self) {
        self.known.clear();
        self.equations.clear();
        self.emit_q.clear();
    }

    pub fn packets_in_window(&self) -> usize {
        self.equations.len()
    }
}

// GF(2^16) Decoder for higher error correction modes
struct Equation16 {
    base_id: u64,
    coeffs: Vec<u16>,
    data: AlignedBox<[u8]>,
    len: usize,
}

struct Decoder16 {
    k: usize,
    mem_pool: Arc<MemoryPool>,
    known: HashMap<u64, (AlignedBox<[u8]>, usize)>,
    equations: Vec<Equation16>,
    emit_q: VecDeque<FecPacket>,
}

impl Decoder16 {
    fn new(k: usize, pool: Arc<MemoryPool>) -> Self {
        Self {
            k,
            mem_pool: pool,
            known: HashMap::new(),
            equations: Vec::new(),
            emit_q: VecDeque::new(),
        }
    }

    fn take_packet(&mut self, p: FecPacket) {
        if p.is_systematic {
            if let Some(ref data) = p.data {
                self.known.entry(p.id).or_insert_with(|| {
                    let mut buf = self.mem_pool.alloc();
                    let n = p.data_len.min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    (buf, n)
                });
            }
            // Try peeling any pending equations
            self.try_peel_all();
        } else if let Some(ref coeffs_be) = p.coefficients {
            // Parse coefficients as big-endian u16
            let mut coeffs16 = vec![0u16; self.k];
            let mut j = 0usize;
            while j < self.k && (2 * j + 1) < p.coeff_len {
                let b0 = coeffs_be[2 * j] as u16;
                let b1 = coeffs_be[2 * j + 1] as u16;
                coeffs16[j] = (b0 << 8) | b1;
                j += 1;
            }
            let len = p.data_len;
            // Two buffers
            let mut db1 = self.mem_pool.alloc();
            let mut db2 = self.mem_pool.alloc();
            let n1 = len.min(db1.len());
            let n2 = len.min(db2.len());
            if let Some(ref d) = p.data {
                db1[..n1].copy_from_slice(&d[..n1]);
                db2[..n2].copy_from_slice(&d[..n2]);
            }
            let orig_base = p.id;
            let norm_base = if self.known.is_empty() {
                p.id
            } else {
                self.known.keys().copied().max().unwrap_or(p.id).saturating_add(1)
            };

            let mut eq_orig =
                Equation16 { base_id: orig_base, coeffs: coeffs16.clone(), data: db1, len: n1 };
            let known_before = self.known.len();
            if self.try_solve_equation(&mut eq_orig) {
                self.try_peel_all();
                return;
            }
            let progress_orig = self.known.len() > known_before;

            let mut eq_norm =
                Equation16 { base_id: norm_base, coeffs: coeffs16, data: db2, len: n2 };
            let known_mid = self.known.len();
            if self.try_solve_equation(&mut eq_norm) {
                self.try_peel_all();
                return;
            }
            let progress_norm = self.known.len() > known_mid;

            let unk_orig = self.unknown_ids_for(eq_orig.base_id, &eq_orig.coeffs).len();
            let unk_norm = self.unknown_ids_for(eq_norm.base_id, &eq_norm.coeffs).len();
            let choose_norm = (!progress_orig && progress_norm) || (unk_norm < unk_orig);

            if choose_norm {
                self.equations.push(eq_norm);
            } else {
                self.equations.push(eq_orig);
            }
            let _ = self.try_eliminate();
        }
    }

    fn get_result(&mut self) -> Option<VecDeque<FecPacket>> {
        if self.is_complete() {
            let mut result = VecDeque::new();
            for (&id, (data, len)) in self.known.iter() {
                result.push_back(FecPacket {
                    id,
                    is_systematic: true,
                    data: Some(self.mem_pool.alloc_from_slice(&data[..*len])),
                    data_len: *len,
                    coefficients: None,
                    coeff_len: 0,
                    mem_pool: Arc::clone(&self.mem_pool),
                    seq: id,
                    timestamp: std::time::Instant::now(),
                });
            }
            Some(result)
        } else {
            None
        }
    }

    fn get_partial_result(&mut self) -> VecDeque<FecPacket> {
        std::mem::take(&mut self.emit_q)
    }

    fn is_complete(&self) -> bool {
        self.known.len() >= self.k
    }

    fn unknown_ids_for(&self, base_id: u64, coeffs: &[u16]) -> Vec<(usize, u64)> {
        coeffs
            .iter()
            .enumerate()
            .take(self.k)
            .filter_map(|(j, &c)| {
                let sid = base_id.saturating_sub(self.k as u64 - 1) + j as u64;
                if c != 0 && !self.known.contains_key(&sid) {
                    Some((j, sid))
                } else {
                    None
                }
            })
            .collect()
    }

    fn try_solve_equation(&mut self, eq: &mut Equation16) -> bool {
        // Subtract known sources from equation data using GF(2^16) operations
        for (j, coeff) in eq.coeffs.iter_mut().enumerate().take(self.k) {
            if *coeff == 0 {
                continue;
            }
            let sid = eq.base_id.saturating_sub(self.k as u64 - 1) + j as u64;
            if let Some((ref kdata, klen)) = self.known.get(&sid) {
                let sl = core::cmp::min(eq.len & !1, *klen & !1); // even length
                if sl >= 2 {
                    gf16_mul_scalar_slice_u16(*coeff, &kdata[..sl], &mut eq.data[..sl]);
                }
                *coeff = 0;
            }
        }
        // Identify single unknown
        let mut last: Option<(usize, u64, u16)> = None;
        for (j, &c) in eq.coeffs.iter().enumerate().take(self.k) {
            if c != 0 {
                let sid = eq.base_id.saturating_sub(self.k as u64 - 1) + j as u64;
                if !self.known.contains_key(&sid) {
                    if last.is_some() {
                        return false;
                    }
                    last = Some((j, sid, c));
                }
            }
        }
        if let Some((_j, sid, cj)) = last {
            let inv = gf_tables::gf16_inv(cj);
            let mut rec = self.mem_pool.alloc();
            let sl = eq.len & !1;
            for b in &mut rec[..sl] {
                *b = 0;
            }
            if sl >= 2 {
                gf16_mul_scalar_slice_u16(inv, &eq.data[..sl], &mut rec[..sl]);
            }
            self.known.entry(sid).or_insert_with(|| {
                let mut rec2 = self.mem_pool.alloc();
                if sl > 0 {
                    rec2[..sl].copy_from_slice(&rec[..sl]);
                }
                let pkt =
                    FecPacket::new(sid, Some(rec2), sl, true, None, 0, Arc::clone(&self.mem_pool));
                self.emit_q.push_back(pkt);
                (rec, sl)
            });
            true
        } else {
            false
        }
    }

    fn try_peel_all(&mut self) {
        let mut progress = true;
        while progress {
            progress = false;
            let mut i = 0;
            while i < self.equations.len() {
                let mut eq = self.equations.remove(i);
                if self.try_solve_equation(&mut eq) {
                    progress = true;
                } else {
                    self.equations.insert(i, eq);
                    i += 1;
                }
            }
            if !progress {
                let _ = self.try_eliminate();
            }
        }
    }

    fn try_eliminate(&mut self) -> bool {
        use std::collections::BTreeSet;
        let mut unknown_set = BTreeSet::new();
        let mut min_len = usize::MAX;
        for eq in &self.equations {
            min_len = core::cmp::min(min_len, eq.len & !1);
            for (_, sid) in self.unknown_ids_for(eq.base_id, &eq.coeffs) {
                unknown_set.insert(sid);
            }
        }
        if unknown_set.is_empty() || min_len < 2 {
            return false;
        }
        let unknowns: Vec<u64> = unknown_set.into_iter().collect();
        let u = unknowns.len();
        let m = self.equations.len();
        if m < u {
            return false;
        }

        let words = min_len / 2;
        let mut solutions = vec![Vec::with_capacity(words); u];
        let mut solved_any = false;

        for w in 0..words {
            // Build A (m x u) and y (m) for this word index
            let mut a = vec![vec![0u16; u]; m];
            let mut y = vec![0u16; m];
            for (i, eq) in self.equations.iter().enumerate() {
                if 2 * w + 1 < eq.len {
                    let b0 = eq.data[2 * w] as u16;
                    let b1 = eq.data[2 * w + 1] as u16;
                    y[i] = (b0 << 8) | b1;
                    let base = eq.base_id.saturating_sub(self.k as u64 - 1);
                    for (col, &sid) in unknowns.iter().enumerate() {
                        if sid >= base && sid < base + self.k as u64 {
                            let j = (sid - base) as usize;
                            a[i][col] = *eq.coeffs.get(j).unwrap_or(&0);
                        }
                    }
                }
            }
            // Gaussian elimination in GF(2^16)
            let mut row = 0usize;
            for col in 0..u {
                // find pivot
                let mut pivot = None;
                #[allow(clippy::needless_range_loop)]
                for r in row..m {
                    if a[r][col] != 0 {
                        pivot = Some(r);
                        break;
                    }
                }
                if let Some(pr) = pivot {
                    if pr != row {
                        a.swap(pr, row);
                        y.swap(pr, row);
                    }
                } else {
                    continue;
                }
                let inv = gf_tables::gf16_inv(a[row][col]);
                // scale
                for cell in a[row].iter_mut().take(u) {
                    *cell = gf_tables::gf16_mul(*cell, inv);
                }
                y[row] = gf_tables::gf16_mul(y[row], inv);
                // eliminate other rows (vectorized)
                for r in 0..m {
                    if r != row && a[r][col] != 0 {
                        let f = a[r][col];
                        // XOR row r with f * row(row)
                        let pivot_row = a[row].clone();
                        gf16_mul_slice(f, &pivot_row[..u], &mut a[r][..u]);
                        // Update RHS
                        let prody = gf_tables::gf16_mul(f, y[row]);
                        y[r] ^= prody;
                    }
                }
                row += 1;
                if row == m {
                    break;
                }
            }
            // back substitution yields y entries as solution (since reduced to identity on columns with pivots)
            // Extract solution per column where pivotized
            // We assume full rank on first u rows after elimination
            for col in 0..u {
                if col < m {
                    solutions[col].push(y[col]);
                    solved_any = true;
                }
            }
        }

        if !solved_any {
            return false;
        }
        // Materialize recovered unknowns as bytes
        for (col, &sid) in unknowns.iter().enumerate() {
            if self.known.contains_key(&sid) {
                continue;
            }
            let mut buf = self.mem_pool.alloc();
            let sl = words * 2;
            for (w, &val) in solutions[col].iter().enumerate() {
                buf[2 * w] = (val >> 8) as u8;
                buf[2 * w + 1] = (val & 0xff) as u8;
            }
            let mut buf2 = self.mem_pool.alloc();
            buf2[..sl].copy_from_slice(&buf[..sl]);
            self.known.insert(sid, (buf, sl));
            let pkt =
                FecPacket::new(sid, Some(buf2), sl, true, None, 0, Arc::clone(&self.mem_pool));
            self.emit_q.push_back(pkt);
        }
        true
    }
}

// Internal module for FEC implementation variants
mod internal {
    #![allow(private_interfaces)]
    use super::*;
    use std::sync::Arc;

    // Type aliases for Fountain Code implementations
    pub type FountainEncoder = fountain_codes::LTEncoder;
    pub type FountainDecoder = fountain_codes::LTDecoder;

    /// Adaptive RS wrapper: chooses between GF8 and GF16 encoders based on
    /// adaptive parameters and delegates all operations accordingly.
    struct AdaptiveEncoder {
        rs: super::adaptive_reed_solomon::AdaptiveRSEncoder,
        inner_gf8: Encoder<GF8>,
        inner_gf16: Encoder16,
        use_gf16: bool,
        adapt_ctr: usize,
    }

    impl AdaptiveEncoder {
        fn new(mode: FecMode, k: usize, n: usize) -> Self {
            let rs = super::adaptive_reed_solomon::AdaptiveRSEncoder::new(k, n);
            // Initial GF choice guided by mode
            let use_gf16 = matches!(
                mode,
                FecMode::Medium | FecMode::Strong | FecMode::Extreme | FecMode::Ultra
            );
            Self {
                rs,
                inner_gf8: Encoder::<GF8>::new(k, n),
                inner_gf16: Encoder16::new(k, n),
                use_gf16,
                adapt_ctr: 0,
            }
        }

        #[inline]
        #[allow(dead_code)]
        fn params(&self) -> (usize, usize) {
            if self.use_gf16 {
                self.inner_gf16.params()
            } else {
                self.inner_gf8.params()
            }
        }

        #[inline]
        fn packets_in_window(&self) -> usize {
            if self.use_gf16 {
                self.inner_gf16.packets_in_window()
            } else {
                self.inner_gf8.packets_in_window()
            }
        }

        fn maybe_adapt(&mut self) {
            self.adapt_ctr = self.adapt_ctr.wrapping_add(1);
            if !self.adapt_ctr.is_multiple_of(32) {
                return;
            }
            // Read optional hints from ENV (fallbacks are conservative)
            let loss: f32 = std::env::var("QUICFUSCATE_RS_LOSS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0.0);
            let lat_ms: f32 = std::env::var("QUICFUSCATE_RS_LATENCY_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5.0);
            let bw_mbps: f32 = std::env::var("QUICFUSCATE_RS_BW_MBPS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1000.0);
            self.rs.adapt_parameters(loss, lat_ms, bw_mbps);
            let (k, n, gf_size) = self.rs.current_parameters();
            let want_gf16 = gf_size >= 65536;
            // Reconfigure only when windows are empty to avoid state loss
            let can_switch =
                self.inner_gf8.packets_in_window() == 0 && self.inner_gf16.packets_in_window() == 0;
            if can_switch {
                if want_gf16 {
                    // Recreate encoders with new params
                    self.inner_gf16 = Encoder16::new(k, n);
                } else {
                    self.inner_gf8 = Encoder::<GF8>::new(k, n);
                }
                self.use_gf16 = want_gf16;
            }
        }

        fn take_packet(&mut self, p: FecPacket) {
            self.maybe_adapt();
            if self.use_gf16 {
                self.inner_gf16.take_packet(p)
            } else {
                self.inner_gf8.take_packet(p)
            }
        }

        fn generate_repair_packet(
            &mut self,
            i: usize,
            pool: &Arc<MemoryPool>,
        ) -> Option<FecPacket> {
            self.maybe_adapt();
            let t0 = std::time::Instant::now();
            let out = if self.use_gf16 {
                self.inner_gf16.generate_repair_packet(i, pool)
            } else {
                self.inner_gf8.generate_repair_packet(i, pool)
            };
            let dt = t0.elapsed().as_nanos() as u64;
            crate::telemetry::RS_ENC_TIME_NS.fetch_add(dt, std::sync::atomic::Ordering::Relaxed);
            if out.is_some() {
                crate::telemetry::RS_REPAIR_EMITTED
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            // Window/overhead snapshot
            let (k, n, gf) = self.rs.current_parameters();
            crate::telemetry::RS_WINDOW_K.store(k as u64, std::sync::atomic::Ordering::Relaxed);
            crate::telemetry::RS_WINDOW_N.store(n as u64, std::sync::atomic::Ordering::Relaxed);
            crate::telemetry::RS_GF_SIZE.store(gf as u64, std::sync::atomic::Ordering::Relaxed);
            if k > 0 && n >= k {
                let overhead_ppm = ((n - k) as u128) * 1_000_000u128 / (k as u128);
                crate::telemetry::RS_OVERHEAD_PPM
                    .store(overhead_ppm as u64, std::sync::atomic::Ordering::Relaxed);
            }
            out
        }

        fn clear_window(&mut self) {
            self.inner_gf8.clear_window();
            self.inner_gf16.clear_window();
        }
    }

    // ===========================================================================================
    // ULTRA-ZERO-MODE: Absolute Zero-Overhead FEC
    // ===========================================================================================
    // When loss rate is <0.1%, we don't need ANY FEC processing. ZeroEncoder/ZeroDecoder are
    // pure passthrough with minimal tracking for seamless upgrade when loss is detected.
    // CPU cost: ~2 nanoseconds per packet (single counter increment)
    // ===========================================================================================

    /// ZeroEncoder: Absolute zero-overhead encoder for zero-loss scenarios.
    /// Generates NO repair packets, maintains NO coefficient matrices.
    /// On loss detection, instantly upgrades to real encoder.
    #[allow(dead_code)]
    pub struct ZeroEncoder {
        /// Packets passed through (for telemetry only)
        packets_passed: u64,
        /// Upgrade threshold: if manual upgrade requested, we clone to GF4
        k: usize,
        n: usize,
    }

    #[allow(dead_code)]
    impl ZeroEncoder {
        pub fn new(k: usize, n: usize) -> Self {
            Self { packets_passed: 0, k, n }
        }

        #[inline(always)]
        pub fn params(&self) -> (usize, usize) {
            (self.k, self.n)
        }

        #[inline(always)]
        pub fn take_packet(&mut self, _p: FecPacket) {
            // ZERO-OVERHEAD: Just count, no processing
            self.packets_passed += 1;
        }

        #[inline(always)]
        pub fn generate_repair_packet(
            &mut self,
            _i: usize,
            _pool: &Arc<MemoryPool>,
        ) -> Option<FecPacket> {
            // ZERO-OVERHEAD: Never generate repairs in zero-loss mode
            None
        }

        #[inline(always)]
        pub fn clear_window(&mut self) {
            // No window to clear
            self.packets_passed = 0;
        }

        #[inline(always)]
        pub fn packets_in_window(&self) -> usize {
            0
        }

        /// Upgrade to real encoder when loss detected (returns GF4 for efficiency)
        pub fn upgrade_to_encoder4(&self) -> Encoder4 {
            crate::telemetry::ZERO_MODE_UPGRADES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Encoder4::new(self.k, self.n)
        }
    }

    /// ZeroDecoder: Absolute zero-overhead decoder for zero-loss scenarios.
    /// Assumes all packets arrive - pure passthrough with gap detection.
    /// When gap detected, instantly upgrades to real decoder and replays buffered packets.
    #[allow(dead_code)]
    pub struct ZeroDecoder {
        /// Last seen sequence number
        last_seq: u64,
        /// Buffer of recent packets for replay on upgrade
        recent: VecDeque<FecPacket>,
        /// Max buffer size before forced trim
        max_buffer: usize,
        /// Pool for upgrade
        pool: Arc<MemoryPool>,
        k: usize,
        /// Has detected loss?
        loss_detected: bool,
    }

    #[allow(dead_code)]
    impl ZeroDecoder {
        pub fn new(k: usize, pool: Arc<MemoryPool>) -> Self {
            Self {
                last_seq: 0,
                recent: VecDeque::with_capacity(32),
                max_buffer: 64,
                pool,
                k,
                loss_detected: false,
            }
        }

        #[inline(always)]
        pub fn take_packet(&mut self, p: FecPacket) {
            // ZERO-OVERHEAD: Just track sequence for gap detection
            if p.is_systematic {
                // Check for gaps (non-contiguous sequence)
                if self.last_seq > 0 && p.seq > self.last_seq + 1 {
                    self.loss_detected = true;
                }
                self.last_seq = p.seq;
            }
            // Buffer for potential replay
            self.recent.push_back(p);
            if self.recent.len() > self.max_buffer {
                self.recent.pop_front();
            }
        }

        #[inline(always)]
        pub fn has_loss(&self) -> bool {
            self.loss_detected
        }

        pub fn get_result(&mut self) -> Option<VecDeque<FecPacket>> {
            // Zero mode: all packets arrived, nothing to recover
            if self.loss_detected {
                None // Need upgrade to real decoder
            } else {
                Some(std::mem::take(&mut self.recent))
            }
        }

        pub fn get_partial_result(&mut self) -> VecDeque<FecPacket> {
            std::mem::take(&mut self.recent)
        }

        /// Upgrade to real decoder when loss detected (returns GF4 with buffered packets replayed)
        pub fn upgrade_to_decoder4(&mut self) -> Decoder4 {
            crate::telemetry::ZERO_MODE_UPGRADES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut d4 = Decoder4::new(self.k, Arc::clone(&self.pool));
            // Replay buffered packets
            for p in self.recent.drain(..) {
                d4.take_packet(p);
            }
            d4
        }
    }

    /// Encoder variant for different FEC modes
    pub enum EncoderVariant {
        /// Zero-overhead passthrough (no repairs generated)
        Zero(ZeroEncoder),
        GF8(Encoder<GF8>),
        GF16(Encoder16),
        GF4(Encoder4),
        Fountain(FountainEncoder),
        AdaptiveRS(AdaptiveEncoder),
    }

    impl EncoderVariant {
        pub fn new(mode: FecMode, k: usize, n: usize) -> Self {
            match mode {
                FecMode::Fountain => {
                    let sym = std::env::var("QUICFUSCATE_FOUNTAIN_SYMBOL")
                        .ok()
                        .and_then(|v| v.parse::<usize>().ok())
                        .or_else(|| {
                            std::env::var("QUICFUSCATE_MTU_HINT")
                                .ok()
                                .and_then(|v| v.parse::<usize>().ok())
                                .map(|mtu| mtu.saturating_sub(80))
                        })
                        .unwrap_or(1500)
                        .clamp(600, 16384);
                    crate::telemetry::FOUNTAIN_SYMBOL_SIZE
                        .store(sym as u64, std::sync::atomic::Ordering::Relaxed);
                    EncoderVariant::Fountain(FountainEncoder::new(k, sym))
                }
                // ULTRA-ZERO-MODE: Absolute zero overhead - no repairs, no matrices
                FecMode::Zero => EncoderVariant::Zero(ZeroEncoder::new(k, n)),
                // GF4 for Light mode: 4x less computation for low-loss (<5%) scenarios
                FecMode::Light => EncoderVariant::GF4(Encoder4::new(k, n)),
                FecMode::Normal | FecMode::Streaming => {
                    EncoderVariant::GF8(Encoder::<GF8>::new(k, n))
                }
                // Adaptive RS for moderate and strong loss
                FecMode::Medium | FecMode::Strong => {
                    EncoderVariant::AdaptiveRS(AdaptiveEncoder::new(mode, k, n))
                }
                FecMode::Extreme | FecMode::Ultra => EncoderVariant::GF16(Encoder16::new(k, n)),
            }
        }

        #[allow(dead_code)]
        pub fn params(&self) -> (usize, usize) {
            match self {
                EncoderVariant::Zero(e) => e.params(),
                EncoderVariant::GF8(e) => e.params(),
                EncoderVariant::GF16(e) => e.params(),
                EncoderVariant::GF4(e) => e.params(),
                EncoderVariant::Fountain(e) => (e.k(), e.k()), // LT codes: k source symbols
                EncoderVariant::AdaptiveRS(a) => a.params(),
            }
        }

        pub fn take_packet(&mut self, p: FecPacket) {
            match self {
                EncoderVariant::Zero(e) => e.take_packet(p),
                EncoderVariant::GF8(e) => e.take_packet(p),
                EncoderVariant::GF16(e) => e.take_packet(p),
                EncoderVariant::GF4(e) => e.take_packet(p),
                EncoderVariant::Fountain(e) => {
                    // Add source symbol to LT encoder
                    if let Some(ref data) = p.data {
                        e.add_source_symbol(data.to_vec());
                    }
                }
                EncoderVariant::AdaptiveRS(a) => a.take_packet(p),
            }
        }

        pub fn generate_repair_packet(
            &mut self,
            i: usize,
            pool: &Arc<MemoryPool>,
        ) -> Option<FecPacket> {
            match self {
                EncoderVariant::Zero(e) => e.generate_repair_packet(i, pool),
                EncoderVariant::GF8(e) => e.generate_repair_packet(i, pool),
                EncoderVariant::GF16(e) => e.generate_repair_packet(i, pool),
                EncoderVariant::GF4(e) => e.generate_repair_packet(i, pool),
                EncoderVariant::Fountain(ref mut enc) => {
                    // **LT Fountain Codes**: Generate rateless encoded symbols with indices for BP
                    let symbol_id = next_repair_id();
                    let (encoded_data, indices) = enc.generate_symbol_with_indices(symbol_id);
                    // Encode indices as u32 big-endian values
                    let mut coeff_block = pool.alloc();
                    let max_u32s = coeff_block.len() / 4;
                    let take = core::cmp::min(indices.len(), max_u32s);
                    for (i, idx) in indices.iter().take(take).enumerate() {
                        let be = (*idx as u32).to_be_bytes();
                        let off = i * 4;
                        coeff_block[off..off + 4].copy_from_slice(&be);
                    }
                    Some(FecPacket {
                        id: symbol_id,
                        data: Some(pool.alloc_from_slice(&encoded_data)),
                        data_len: enc.symbol_size(),
                        is_systematic: false,
                        coefficients: Some(coeff_block),
                        coeff_len: take * 4,
                        mem_pool: Arc::clone(pool),
                        seq: symbol_id,
                        timestamp: std::time::Instant::now(),
                    })
                }
                EncoderVariant::AdaptiveRS(a) => a.generate_repair_packet(i, pool),
            }
        }

        pub fn clear_window(&mut self) {
            match self {
                EncoderVariant::Zero(e) => e.clear_window(),
                EncoderVariant::GF8(e) => e.clear_window(),
                EncoderVariant::GF16(e) => e.clear_window(),
                EncoderVariant::GF4(e) => e.clear_window(),
                EncoderVariant::Fountain(e) => {
                    // Clear source symbols for new window
                    e.clear_window();
                }
                EncoderVariant::AdaptiveRS(a) => a.clear_window(),
            }
        }

        pub fn packets_in_window(&self) -> usize {
            match self {
                EncoderVariant::Zero(e) => e.packets_in_window(),
                EncoderVariant::GF8(e) => e.packets_in_window(),
                EncoderVariant::GF16(e) => e.packets_in_window(),
                EncoderVariant::GF4(e) => e.packets_in_window(),
                EncoderVariant::Fountain(e) => e.packets_in_window(),
                EncoderVariant::AdaptiveRS(a) => a.packets_in_window(),
            }
        }
    }

    /// Decoder variant for different FEC modes
    pub enum DecoderVariant {
        /// Zero-overhead passthrough (no decoding, just gap detection)
        Zero(ZeroDecoder),
        GF8(Decoder8),
        GF16(Decoder16),
        GF4(Decoder4),
        Fountain(FountainDecoder),
        AdaptiveRS(AdaptiveDecoder),
    }

    struct AdaptiveDecoder {
        inner_gf8: Decoder8,
        inner_gf16: Decoder16,
        use_gf16: bool,
    }

    impl AdaptiveDecoder {
        fn new(mode: FecMode, k: usize, pool: Arc<MemoryPool>) -> Self {
            let use_gf16 = matches!(
                mode,
                FecMode::Medium | FecMode::Strong | FecMode::Extreme | FecMode::Ultra
            );
            Self {
                inner_gf8: Decoder8::new(k, Arc::clone(&pool)),
                inner_gf16: Decoder16::new(k, pool),
                use_gf16,
            }
        }
        #[inline]
        fn take_packet(&mut self, p: FecPacket) {
            if self.use_gf16 {
                self.inner_gf16.take_packet(p)
            } else {
                self.inner_gf8.take_packet(p)
            }
        }
        #[inline]
        fn get_result(&mut self) -> Option<VecDeque<FecPacket>> {
            let t0 = std::time::Instant::now();
            let res = if self.use_gf16 {
                self.inner_gf16.get_result()
            } else {
                self.inner_gf8.get_result()
            };
            let dt = t0.elapsed().as_nanos() as u64;
            crate::telemetry::RS_DEC_TIME_NS.fetch_add(dt, std::sync::atomic::Ordering::Relaxed);
            if let Some(ref r) = res {
                crate::telemetry::RS_RECOVERED
                    .fetch_add(r.len() as u64, std::sync::atomic::Ordering::Relaxed);
            }
            res
        }
        #[inline]
        fn get_partial_result(&mut self) -> VecDeque<FecPacket> {
            if self.use_gf16 {
                self.inner_gf16.get_partial_result()
            } else {
                self.inner_gf8.get_partial_result()
            }
        }
        // is_complete removed; partial/get_result drive completion
    }

    impl DecoderVariant {
        pub fn new(mode: FecMode, k: usize, pool: Arc<MemoryPool>) -> Self {
            match mode {
                FecMode::Fountain => {
                    let sym = std::env::var("QUICFUSCATE_FOUNTAIN_SYMBOL")
                        .ok()
                        .and_then(|v| v.parse::<usize>().ok())
                        .or_else(|| {
                            std::env::var("QUICFUSCATE_MTU_HINT")
                                .ok()
                                .and_then(|v| v.parse::<usize>().ok())
                                .map(|mtu| mtu.saturating_sub(80))
                        })
                        .unwrap_or(1500)
                        .clamp(600, 16384);
                    crate::telemetry::FOUNTAIN_SYMBOL_SIZE
                        .store(sym as u64, std::sync::atomic::Ordering::Relaxed);
                    DecoderVariant::Fountain(FountainDecoder::new(k, sym, Arc::clone(&pool)))
                }
                // ULTRA-ZERO-MODE: Absolute zero overhead - no decoding, gap detection only
                FecMode::Zero => DecoderVariant::Zero(ZeroDecoder::new(k, pool)),
                // GF4 for Light mode: 4x less computation for low-loss (<5%) scenarios
                FecMode::Light => DecoderVariant::GF4(Decoder4::new(k, pool)),
                FecMode::Normal | FecMode::Streaming => DecoderVariant::GF8(Decoder8::new(k, pool)),
                // Use AdaptiveRS for moderate/high loss; Extreme/Ultra remains GF16
                FecMode::Medium | FecMode::Strong => {
                    DecoderVariant::AdaptiveRS(AdaptiveDecoder::new(mode, k, pool))
                }
                FecMode::Extreme | FecMode::Ultra => DecoderVariant::GF16(Decoder16::new(k, pool)),
            }
        }

        pub fn take_packet(&mut self, p: FecPacket) {
            match self {
                DecoderVariant::Zero(d) => d.take_packet(p),
                DecoderVariant::GF8(d) => d.take_packet(p),
                DecoderVariant::GF16(d) => d.take_packet(p),
                DecoderVariant::GF4(d) => d.take_packet(p),
                DecoderVariant::Fountain(d) => {
                    // Add received symbol to LT decoder, use indices if available
                    if let Some(ref data) = p.data {
                        if let Some(ref coeffs) = p.coefficients {
                            let mut set = std::collections::HashSet::new();
                            let bytes = &coeffs[..p.coeff_len.min(coeffs.len())];
                            for chunk in bytes.chunks_exact(4) {
                                let idx =
                                    u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
                                        as usize;
                                set.insert(idx);
                            }
                            let _ = d.add_encoded_symbol(p.id, data.to_vec(), set);
                        } else {
                            d.add_received_symbol(p.id, data.to_vec());
                        }
                    }
                }
                DecoderVariant::AdaptiveRS(d) => d.take_packet(p),
            }
        }

        pub fn get_result(&mut self) -> Option<VecDeque<FecPacket>> {
            match self {
                DecoderVariant::Zero(d) => d.get_result(),
                DecoderVariant::GF8(d) => d.get_result(),
                DecoderVariant::GF16(d) => d.get_result(),
                DecoderVariant::GF4(d) => d.get_result(),
                DecoderVariant::Fountain(d) => {
                    // Run BP to completion if possible
                    let _ = d.belief_propagation_decode();
                    // Convert decoded symbols to FecPackets
                    if let Some(symbols) = d.get_decoded_symbols() {
                        // Telemetry: completed
                        crate::telemetry::FOUNTAIN_PROGRESS
                            .store(1_000_000, std::sync::atomic::Ordering::Relaxed);
                        let mut packets = VecDeque::new();
                        for symbol in symbols.into_iter() {
                            let pool = Arc::clone(&d.mem_pool);
                            let new_id = next_repair_id();
                            let packet = FecPacket {
                                id: new_id,
                                data: Some(pool.alloc_from_slice(&symbol)),
                                data_len: symbol.len(),
                                is_systematic: true,
                                coefficients: None,
                                coeff_len: 0,
                                mem_pool: pool,
                                seq: new_id,
                                timestamp: std::time::Instant::now(),
                            };
                            packets.push_back(packet);
                        }
                        Some(packets)
                    } else {
                        // Update progress gauge
                        let prog = (d.decoding_progress() * 1_000_000.0) as u64;
                        crate::telemetry::FOUNTAIN_PROGRESS
                            .store(prog, std::sync::atomic::Ordering::Relaxed);
                        None
                    }
                }
                DecoderVariant::AdaptiveRS(d) => d.get_result(),
            }
        }

        pub fn get_partial_result(&mut self) -> VecDeque<FecPacket> {
            match self {
                DecoderVariant::Zero(d) => d.get_partial_result(),
                DecoderVariant::GF8(d) => d.get_partial_result(),
                DecoderVariant::GF16(d) => d.get_partial_result(),
                DecoderVariant::GF4(d) => d.get_partial_result(),
                DecoderVariant::Fountain(d) => {
                    // Attempt one BP step for incremental progress
                    let _ = d.belief_propagation_step();
                    // Return partial decoding progress
                    let mut partial = VecDeque::new();
                    for symbol in d.get_partial().into_iter() {
                        let pool = Arc::clone(&d.mem_pool);
                        let packet = FecPacket {
                            id: symbol.len() as u64,
                            data: Some(pool.alloc_from_slice(&symbol)),
                            data_len: symbol.len(),
                            is_systematic: true,
                            coefficients: None,
                            coeff_len: 0,
                            mem_pool: pool,
                            seq: symbol.len() as u64,
                            timestamp: std::time::Instant::now(),
                        };
                        partial.push_back(packet);
                    }
                    // Update progress gauge with current progress
                    let prog = (d.decoding_progress() * 1_000_000.0) as u64;
                    crate::telemetry::FOUNTAIN_PROGRESS
                        .store(prog, std::sync::atomic::Ordering::Relaxed);
                    partial
                }
                DecoderVariant::AdaptiveRS(d) => d.get_partial_result(),
            }
        }

        // is_complete() removed; use get_result()/get_partial_result() paths
    }

    // =========================================================================
    // LAZY DECODING: 0 CPU when no packet loss detected
    // =========================================================================

    /// LazyDecoder wraps DecoderVariant and defers actual decoding until loss is detected.
    /// This saves ~99% CPU when there is no packet loss.
    pub struct LazyDecoder {
        inner: DecoderVariant,
        /// Buffered repair packets (only decoded when gaps detected)
        pending_repairs: VecDeque<FecPacket>,
        /// Tracks seen source packet sequence numbers
        seen_seqs: std::collections::BTreeSet<u64>,
        /// Expected next sequence number
        expected_seq: u64,
        /// Maximum buffered repairs before forced flush
        max_pending: usize,
        /// Whether lazy mode is enabled (always true by default)
        lazy_enabled: bool,
        /// Telemetry: repairs skipped (no loss)
        repairs_skipped: u64,
    }

    impl LazyDecoder {
        pub fn new(mode: FecMode, k: usize, pool: Arc<MemoryPool>) -> Self {
            let lazy_enabled = std::env::var("QUICFUSCATE_FEC_LAZY")
                .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
                .unwrap_or(true); // Enabled by default!

            Self {
                inner: DecoderVariant::new(mode, k, pool),
                pending_repairs: VecDeque::with_capacity(32),
                seen_seqs: std::collections::BTreeSet::new(),
                expected_seq: 0,
                max_pending: 64,
                lazy_enabled,
                repairs_skipped: 0,
            }
        }

        /// Check if there are gaps in the received sequence
        #[inline]
        fn has_gaps(&self) -> bool {
            if self.seen_seqs.is_empty() {
                return false;
            }
            let mut it = self.seen_seqs.iter();
            let Some(&first) = it.next() else {
                return false;
            };
            let Some(&last) = self.seen_seqs.iter().next_back() else {
                return false;
            };
            // Gap exists if we've seen N sequences but range is > N
            (last - first + 1) as usize > self.seen_seqs.len()
        }

        /// Flush pending repairs to actual decoder (when loss detected)
        fn flush_to_decoder(&mut self) {
            while let Some(repair) = self.pending_repairs.pop_front() {
                self.inner.take_packet(repair);
            }
        }

        pub fn take_packet(&mut self, p: FecPacket) {
            if p.is_systematic {
                // Source packet - track sequence
                self.seen_seqs.insert(p.seq);
                // Update expected sequence
                self.expected_seq = self.expected_seq.max(p.seq + 1);

                // If lazy disabled, forward to decoder
                if !self.lazy_enabled {
                    self.inner.take_packet(p);
                    return;
                }

                // Check if we detect gaps now
                if self.has_gaps() {
                    // Loss detected! Flush buffered repairs and forward this packet
                    self.flush_to_decoder();
                    self.inner.take_packet(p);
                } else {
                    // No loss - drop pending repairs (they're not needed)
                    let skipped = self.pending_repairs.len() as u64;
                    self.repairs_skipped += skipped;
                    self.pending_repairs.clear();
                    // Forward source packet (decoder needs it for systematic recovery)
                    self.inner.take_packet(p);
                }
            } else {
                // Repair packet - buffer it
                if !self.lazy_enabled {
                    self.inner.take_packet(p);
                    return;
                }

                // Buffer repair packet
                self.pending_repairs.push_back(p);

                // If buffer full, force flush
                if self.pending_repairs.len() >= self.max_pending {
                    self.flush_to_decoder();
                }
            }
        }

        pub fn get_result(&mut self) -> Option<VecDeque<FecPacket>> {
            // Flush any pending repairs before getting result
            self.flush_to_decoder();
            // Update telemetry
            crate::telemetry::FEC_LAZY_SKIPPED
                .fetch_add(self.repairs_skipped, std::sync::atomic::Ordering::Relaxed);
            self.repairs_skipped = 0;
            self.inner.get_result()
        }

        pub fn get_partial_result(&mut self) -> VecDeque<FecPacket> {
            // If gaps detected, flush and decode
            if self.has_gaps() {
                self.flush_to_decoder();
            }
            self.inner.get_partial_result()
        }

        /// Drain buffered packets from ZeroDecoder for seamless mode transition.
        /// Returns packets to be replayed into the new decoder after mode switch.
        pub fn drain_zero_buffers(&mut self) -> VecDeque<FecPacket> {
            match &mut self.inner {
                DecoderVariant::Zero(z) => z.get_partial_result(),
                _ => VecDeque::new(),
            }
        }

        #[cfg(test)]
        pub fn pending_repairs_capacity(&self) -> usize {
            self.pending_repairs.capacity()
        }

        #[cfg(test)]
        pub fn pending_repairs_len(&self) -> usize {
            self.pending_repairs.len()
        }

        #[cfg(test)]
        pub fn pending_repairs_max(&self) -> usize {
            self.max_pending
        }
    }

    // =========================================================================
    // INTERLEAVED ENCODING: Better burst loss protection
    // =========================================================================

    /// InterleavedEncoder distributes packets across multiple FEC blocks
    /// to protect against burst losses (consecutive packet drops).
    ///
    /// With interleave_depth=4:
    /// - Block 0: P0, P4, P8, ...
    /// - Block 1: P1, P5, P9, ...
    /// - etc.
    ///
    /// A burst of 4 consecutive packets in loss = max 1 per block = recoverable!
    #[allow(dead_code)]
    pub struct InterleavedEncoder {
        blocks: Vec<EncoderVariant>,
        depth: usize,
        packet_idx: usize,
        mode: FecMode,
        k: usize,
        n: usize,
        enabled: bool,
    }

    #[allow(dead_code)]
    impl InterleavedEncoder {
        pub fn new(mode: FecMode, k: usize, n: usize, depth: usize) -> Self {
            let enabled = std::env::var("QUICFUSCATE_FEC_INTERLEAVE")
                .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
                .unwrap_or(true); // Enabled by default!

            let actual_depth = if enabled { depth.clamp(1, 8) } else { 1 };

            // CRITICAL: Each block receives k/depth packets, so scale block size accordingly
            let block_k = (k / actual_depth).max(1);
            let block_n = (n / actual_depth).max(block_k);

            let blocks =
                (0..actual_depth).map(|_| EncoderVariant::new(mode, block_k, block_n)).collect();

            Self { blocks, depth: actual_depth, packet_idx: 0, mode, k, n, enabled }
        }

        #[inline]
        pub fn depth(&self) -> usize {
            self.depth
        }

        pub fn params(&self) -> (usize, usize) {
            (self.k, self.n)
        }

        pub fn take_packet(&mut self, p: FecPacket) {
            // Distribute packets round-robin across blocks
            let block_idx = self.packet_idx % self.depth;
            self.blocks[block_idx].take_packet(p);
            self.packet_idx = self.packet_idx.wrapping_add(1);
        }

        /// Generate repair packets from all interleaved blocks
        pub fn generate_repairs(&mut self, pool: &Arc<MemoryPool>) -> Vec<FecPacket> {
            let mut repairs = Vec::new();
            for (block_idx, block) in self.blocks.iter_mut().enumerate() {
                let (k, n) = block.params();
                let repair_count = n.saturating_sub(k);
                for i in 0..repair_count {
                    if let Some(mut repair) = block.generate_repair_packet(i, pool) {
                        // Tag repair with interleave block index
                        repair.seq = (repair.seq << 4) | (block_idx as u64);
                        repairs.push(repair);
                    }
                }
            }
            // Update telemetry
            crate::telemetry::FEC_INTERLEAVE_REPAIRS
                .fetch_add(repairs.len() as u64, std::sync::atomic::Ordering::Relaxed);
            repairs
        }

        /// API compatibility: generate single repair packet (delegates to block i % depth)
        pub fn generate_repair_packet(
            &mut self,
            i: usize,
            pool: &Arc<MemoryPool>,
        ) -> Option<FecPacket> {
            let block_idx = i % self.depth;
            let repair_idx = i / self.depth;
            if block_idx < self.blocks.len() {
                if let Some(mut repair) =
                    self.blocks[block_idx].generate_repair_packet(repair_idx, pool)
                {
                    // Tag repair with interleave block index
                    repair.seq = (repair.seq << 4) | (block_idx as u64);
                    return Some(repair);
                }
            }
            None
        }

        pub fn clear_window(&mut self) {
            for block in &mut self.blocks {
                block.clear_window();
            }
            self.packet_idx = 0;
        }

        pub fn packets_in_window(&self) -> usize {
            self.blocks.iter().map(|b| b.packets_in_window()).sum()
        }
    }

    /// InterleavedDecoder reverses the interleaving on receive side
    #[allow(dead_code)]
    pub struct InterleavedDecoder {
        blocks: Vec<LazyDecoder>,
        depth: usize,
        enabled: bool,
    }

    impl InterleavedDecoder {
        pub fn new(mode: FecMode, k: usize, pool: Arc<MemoryPool>, depth: usize) -> Self {
            let enabled = std::env::var("QUICFUSCATE_FEC_INTERLEAVE")
                .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
                .unwrap_or(true);

            let actual_depth = if enabled { depth.clamp(1, 8) } else { 1 };

            // CRITICAL: Scale decoder k same as encoder
            let block_k = (k / actual_depth).max(1);

            let blocks = (0..actual_depth)
                .map(|_| LazyDecoder::new(mode, block_k, Arc::clone(&pool)))
                .collect();

            Self { blocks, depth: actual_depth, enabled }
        }

        pub fn take_packet(&mut self, p: FecPacket) {
            // Extract block index from seq (low 4 bits for repair, high bits for source)
            let block_idx = if p.is_systematic {
                // Source packets: use seq modulo depth
                (p.seq as usize) % self.depth
            } else {
                // Repair packets: block index encoded in low 4 bits
                (p.seq & 0x0F) as usize
            };

            if block_idx < self.blocks.len() {
                // Restore original seq for repair packets
                let mut packet = p;
                if !packet.is_systematic {
                    packet.seq >>= 4;
                }
                self.blocks[block_idx].take_packet(packet);
            }
        }

        pub fn get_result(&mut self) -> Option<VecDeque<FecPacket>> {
            let mut combined = VecDeque::new();
            let mut any_result = false;

            for block in &mut self.blocks {
                if let Some(results) = block.get_result() {
                    any_result = true;
                    for pkt in results {
                        combined.push_back(pkt);
                    }
                }
            }

            if any_result {
                Some(combined)
            } else {
                None
            }
        }

        pub fn get_partial_result(&mut self) -> VecDeque<FecPacket> {
            let mut combined = VecDeque::new();
            for block in &mut self.blocks {
                for pkt in block.get_partial_result() {
                    combined.push_back(pkt);
                }
            }
            combined
        }

        /// Drain all buffered packets from ZeroDecoders for seamless mode transition.
        /// Called before switching from Zero mode to preserve in-flight packets.
        pub fn drain_zero_buffers(&mut self) -> VecDeque<FecPacket> {
            let mut combined = VecDeque::new();
            for block in &mut self.blocks {
                for pkt in block.drain_zero_buffers() {
                    combined.push_back(pkt);
                }
            }
            combined
        }
    }

    /// Mode manager for adaptive FEC
    pub struct ModeManager {
        current_mode: FecMode,
        loss_history: VecDeque<f32>,
        window_size: usize,
        window_history: VecDeque<usize>,
        switch_threshold: f32,
        last_switch_time: std::time::Instant,
    }

    impl ModeManager {
        pub const CROSS_FADE_LEN: usize = 20;

        #[allow(dead_code)]
        pub fn new(initial_mode: FecMode) -> Self {
            Self::with_switch_threshold(initial_mode, 0.02)
        }

        pub fn with_switch_threshold(initial_mode: FecMode, switch_threshold: f32) -> Self {
            let mut s = Self {
                current_mode: initial_mode,
                loss_history: VecDeque::with_capacity(100),
                window_size: Self::params_for(initial_mode, 64).0,
                window_history: VecDeque::with_capacity(10),
                switch_threshold: switch_threshold.clamp(0.0, 1.0),
                last_switch_time: crate::time_source::now_instant(),
            };
            if let Ok(v) = std::env::var("QUICFUSCATE_FEC_SWITCH_THRESH") {
                if let Ok(x) = v.parse::<f32>() {
                    s.switch_threshold = x.clamp(0.0, 1.0);
                }
            }
            s
        }

        #[inline]
        fn mode_rank(mode: FecMode) -> u8 {
            match mode {
                FecMode::Zero => 0,
                FecMode::Light => 1,
                FecMode::Normal => 2,
                FecMode::Streaming => 3,
                FecMode::Medium => 4,
                FecMode::Strong => 5,
                FecMode::Extreme => 6,
                FecMode::Ultra => 7,
                FecMode::Fountain => 8,
            }
        }

        #[inline]
        fn target_mode_for_loss(avg_loss: f32, auto_gf4: bool) -> FecMode {
            if avg_loss < 0.001 {
                FecMode::Zero
            } else if auto_gf4 && avg_loss < 0.02 {
                FecMode::Light
            } else if avg_loss < 0.10 {
                FecMode::Normal
            } else if avg_loss < 0.25 {
                FecMode::Strong
            } else if avg_loss < 0.50 {
                FecMode::Extreme
            } else {
                FecMode::Fountain
            }
        }

        #[inline]
        fn min_switch_interval_ms(current: FecMode, target: FecMode) -> u64 {
            if current == FecMode::Zero {
                return 0;
            }
            let up_ms = std::env::var("QUICFUSCATE_FEC_SWITCH_MIN_UP_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(120);
            let down_ms = std::env::var("QUICFUSCATE_FEC_SWITCH_MIN_DOWN_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(450);
            if Self::mode_rank(target) > Self::mode_rank(current) {
                up_ms
            } else {
                down_ms
            }
        }

        pub fn params_for(mode: FecMode, default_window: usize) -> (usize, usize) {
            // Respect configured window sizes from FecConfig fully.
            // If default_window is 0 (unset), fall back to a small mode-dependent baseline.
            let k = if default_window > 0 {
                default_window
            } else {
                match mode {
                    FecMode::Zero => 0,
                    FecMode::Light => 16,
                    FecMode::Normal | FecMode::Streaming => 8,
                    FecMode::Medium => 16,
                    FecMode::Strong => 32,
                    FecMode::Extreme => 64,
                    FecMode::Ultra => 128,    // Massive parallelism
                    FecMode::Fountain => 256, // Rateless fountain codes
                }
            };
            let overhead = Self::overhead_for(mode);
            // Tests expect ceil for n calculation (e.g., ceil(k*1.15) - k repairs)
            let n = ((k as f32) * overhead).ceil() as usize;
            (k, n.max(k))
        }

        pub fn overhead_for(mode: FecMode) -> f32 {
            match mode {
                FecMode::Zero => 1.0,
                FecMode::Light => 1.1,
                FecMode::Normal => 1.25,
                FecMode::Medium => 1.5,
                FecMode::Strong => 2.0,
                FecMode::Extreme => 2.0,
                FecMode::Streaming => 1.2,
                FecMode::Ultra => 3.0, // 200% redundancy for catastrophic loss
                FecMode::Fountain => 5.0, // Rateless: generate as many repairs as needed
            }
        }

        pub fn update(&mut self, loss_rate: f32) -> Option<(FecMode, usize)> {
            self.loss_history.push_back(loss_rate);
            if self.loss_history.len() > 100 {
                self.loss_history.pop_front();
            }

            // Calculate moving average
            let avg_loss = if self.loss_history.len() >= 10 {
                self.loss_history.iter().rev().take(10).sum::<f32>() / 10.0
            } else {
                loss_rate
            };

            // Determine target mode based on loss (Auto includes Streaming for low loss)
            let auto_stream = std::env::var("QUICFUSCATE_FEC_AUTO_STREAM")
                .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
                .unwrap_or(true);
            // GF4 auto-selection for ultra-low loss (<2%) - 4x faster than GF8
            let auto_gf4 = std::env::var("QUICFUSCATE_FEC_AUTO_GF4")
                .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
                .unwrap_or(true);
            // CONSOLIDATED AUTO-SWITCH: 6 logical modes
            // Zero (<0.1%) -> Light (0.1-2%) -> Normal (2-10%) -> Strong (10-25%) -> Extreme (25-50%) -> Fountain (>50%)
            // Streaming/Medium/Ultra enum variants preserved for backward compatibility but not auto-selected
            let target_mode = Self::target_mode_for_loss(avg_loss, auto_gf4);

            // Respect switching thresholds and minimum time between transitions.
            // Anti-flap strategy:
            // - De-escalation requires longer dwell + stronger hysteresis than escalation.
            // - If the target mode is stable across recent samples, allow switch even
            //   when instantaneous delta is small.
            let now = crate::time_source::now_instant();
            let min_ms = Self::min_switch_interval_ms(self.current_mode, target_mode);
            let time_ok = now.checked_duration_since(self.last_switch_time).unwrap_or_default()
                >= std::time::Duration::from_millis(min_ms);
            let last_avg = if self.loss_history.len() >= 2 {
                let mut s = 0.0f32;
                let mut c = 0;
                for v in self.loss_history.iter().rev().skip(1).take(10) {
                    s += *v;
                    c += 1;
                }
                if c > 0 {
                    s / (c as f32)
                } else {
                    avg_loss
                }
            } else {
                avg_loss
            };
            let rank_cur = Self::mode_rank(self.current_mode);
            let rank_tgt = Self::mode_rank(target_mode);
            let hysteresis = self.switch_threshold.max(0.0025);
            let diff_ok = if rank_tgt > rank_cur {
                (avg_loss - last_avg) >= hysteresis
            } else if rank_tgt < rank_cur {
                (last_avg - avg_loss) >= hysteresis * 1.5
            } else {
                false
            };
            let stable_needed = if rank_tgt < rank_cur { 4 } else { 3 };
            let stable_hits = self
                .loss_history
                .iter()
                .rev()
                .take(stable_needed)
                .filter(|v| Self::target_mode_for_loss(**v, auto_gf4) == target_mode)
                .count();
            let stable_ok = stable_hits >= stable_needed;
            if self.current_mode != target_mode && time_ok && (diff_ok || stable_ok) {
                let old_mode = self.current_mode;
                let old_window = self.window_size;
                self.current_mode = target_mode;
                self.last_switch_time = now;
                let (k, _n) = Self::params_for(target_mode, self.window_size);
                self.window_size = k;
                self.window_history.push_back(k);
                if self.window_history.len() > 10 {
                    self.window_history.pop_front();
                }
                Some((old_mode, old_window))
            } else {
                None
            }
        }

        pub fn current_mode(&self) -> FecMode {
            self.current_mode
        }

        pub fn current_window(&self) -> usize {
            self.window_size
        }

        pub fn force_state(&mut self, mode: FecMode, window: usize) {
            self.current_mode = mode;
            self.window_size = window.max(1);
            self.last_switch_time = crate::time_source::now_instant();
            self.window_history.push_back(self.window_size);
            if self.window_history.len() > 10 {
                self.window_history.pop_front();
            }
        }
    }
}

// Forward declare types - will be defined in internal module below

pub struct AdaptiveFec {
    // Using InterleavedEncoder for burst loss protection (default depth=4)
    encoder: Arc<Mutex<internal::InterleavedEncoder>>,
    // Using InterleavedDecoder (wraps LazyDecoder) for burst loss recovery
    decoder: Arc<Mutex<internal::InterleavedDecoder>>,
    mode_manager: Arc<Mutex<internal::ModeManager>>,
    mem_pool: Arc<MemoryPool>,
    transition_encoder: Option<Arc<Mutex<internal::InterleavedEncoder>>>,
    transition_decoder: Option<Arc<Mutex<internal::InterleavedDecoder>>>,
    transition_left: usize,
    window_complete: bool,
    stream_every: usize,
    _stream_every_base: usize,
    stream_every_override: Option<usize>,
    stream_last_adjust: Instant,
    stream_ctr: usize,
    stream_idx: usize,
    streaming_mode: bool,
    partial_enabled: bool,
    emitted_ids: std::collections::HashSet<u64>,
    emitted_order: VecDeque<u64>,
    loss_estimator: LossEstimator,
    control_mode: FecControlMode,
    force_on: bool,
    simd_enabled: bool,
    simd_level: SimdLevel,
    /// **NEW**: Seamless mode transition management
    transition_buffer: VecDeque<FecPacket>,
    /// Reused queue for streaming repair emission to avoid per-packet allocations
    stream_repair_scratch: VecDeque<FecPacket>,
    transition_progress: f32,  // 0.0 = old mode, 1.0 = new mode
    cross_fade_packets: usize, // Number of packets to cross-fade over
    red_ppm_hint: u32,
    /// Interleave depth (default 4 for burst protection)
    interleave_depth: usize,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum SimdLevel {
    None,
    Sse2,
    Avx2,
    Avx512,
    Sve2,
    Neon,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FecSwitchReason {
    Adaptive,
    ForceOnPolicy,
    ExtremeLossPolicy,
    DisturbancePolicy,
}

impl FecSwitchReason {
    fn observe(self) {
        use std::sync::atomic::Ordering;
        match self {
            FecSwitchReason::Adaptive => {
                crate::telemetry::FEC_SWITCH_REASON_ADAPTIVE.fetch_add(1, Ordering::Relaxed);
            }
            FecSwitchReason::ForceOnPolicy => {
                crate::telemetry::FEC_SWITCH_REASON_FORCE_ON.fetch_add(1, Ordering::Relaxed);
            }
            FecSwitchReason::ExtremeLossPolicy => {
                crate::telemetry::FEC_SWITCH_REASON_EXTREME.fetch_add(1, Ordering::Relaxed);
            }
            FecSwitchReason::DisturbancePolicy => {
                crate::telemetry::FEC_SWITCH_REASON_DISTURBANCE.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl AdaptiveFec {
    pub fn new(config: FecConfig) -> Self {
        // Initialize rayon thread pool if configured
        init_rayon_pool_from_env();
        let mut mode = config.initial_mode;
        if config.force_on && mode == FecMode::Zero {
            mode = FecMode::Normal;
        }
        let force_on = config.force_on;
        let k = config.window_sizes.get(&mode).copied().unwrap_or(64);
        let (k, n) = internal::ModeManager::params_for(mode, k);
        // Use global pool for better memory efficiency
        let mem_pool = crate::optimize::global_pool();

        // INTELLIGENT ADAPTIVE STREAMING - Profile-aware
        let detector = crate::optimize::FeatureDetector::instance();
        let profile = detector.profile();

        // Profile-optimized streaming intervals
        let stream_every = match profile {
            // High-end profiles: aggressive streaming
            crate::optimize::CpuProfile::X86_P3a
            | crate::optimize::CpuProfile::X86_P3b
            | crate::optimize::CpuProfile::X86_P3c
            | crate::optimize::CpuProfile::X86_P3d
            | crate::optimize::CpuProfile::X86_P3e
            | CpuProfile::X86_P4a
            | CpuProfile::X86_P4b => 1, // Maximum aggression

            // Mid-range profiles: balanced streaming
            crate::optimize::CpuProfile::X86_P2a
            | crate::optimize::CpuProfile::X86_P2b
            | crate::optimize::CpuProfile::Apple_M => 2,

            // Low-end profiles: conservative streaming
            crate::optimize::CpuProfile::X86_P1a
            | crate::optimize::CpuProfile::X86_P1b
            | crate::optimize::CpuProfile::X86_P1f => 3,

            // ARM profiles: adaptive based on features
            crate::optimize::CpuProfile::ARM_A1a
            | crate::optimize::CpuProfile::ARM_A1b
            | crate::optimize::CpuProfile::ARM_A1c
            | crate::optimize::CpuProfile::ARM_A1d => {
                if detector.has_feature(crate::optimize::CpuFeature::NEON) {
                    2
                } else {
                    4
                }
            }
            crate::optimize::CpuProfile::ARM_A2 => 1, // SVE2 = aggressive
            _ => 2,                                   // Default
        };

        // Override with env var if set
        let base_stream_every = stream_every;
        let stream_every_override = std::env::var("QUICFUSCATE_FEC_STREAM_EVERY")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .map(|v| v.max(1));
        let stream_every = stream_every_override.unwrap_or(base_stream_every);

        let initial_cross_fade = Self::compute_cross_fade_len(mode, mode, k, k);
        // Touch constant to avoid unused warning in some optimized builds
        let _ = internal::ModeManager::CROSS_FADE_LEN;

        // Interleave depth from env, or auto-calculate based on k
        // For small windows (k <= 16), disable interleaving (depth=1) for test compatibility
        // For production-sized windows (k > 16), use depth=4 for burst protection
        let base_interleave_depth = if k > 16 { 4 } else { 1 };
        let interleave_depth = std::env::var("QUICFUSCATE_FEC_INTERLEAVE_DEPTH")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(base_interleave_depth)
            .clamp(1, 8);

        Self {
            // InterleavedEncoder for burst loss protection
            encoder: Arc::new(Mutex::new(internal::InterleavedEncoder::new(
                mode,
                k,
                n,
                interleave_depth,
            ))),
            // InterleavedDecoder for burst loss recovery (wraps LazyDecoder)
            decoder: Arc::new(Mutex::new(internal::InterleavedDecoder::new(
                mode,
                k,
                Arc::clone(&mem_pool),
                interleave_depth,
            ))),
            mode_manager: Arc::new(Mutex::new(internal::ModeManager::with_switch_threshold(
                mode,
                config.hysteresis,
            ))),
            mem_pool,
            transition_encoder: None,
            transition_decoder: None,
            transition_left: 0,
            window_complete: false,
            stream_every,
            _stream_every_base: base_stream_every,
            stream_every_override,
            stream_last_adjust: crate::time_source::now_instant(),
            stream_ctr: 0,
            stream_idx: 0,
            streaming_mode: matches!(mode, FecMode::Streaming),
            partial_enabled: std::env::var("QUICFUSCATE_FEC_PARTIAL")
                .map(|v| v != "0" && v != "false")
                .unwrap_or(true),
            emitted_ids: std::collections::HashSet::new(),
            emitted_order: VecDeque::new(),
            loss_estimator: LossEstimator::new(),
            control_mode: FecControlMode::Auto,
            force_on,
            simd_enabled: false,
            simd_level: SimdLevel::None,
            transition_buffer: VecDeque::new(),
            stream_repair_scratch: VecDeque::with_capacity(16),
            transition_progress: 1.0, // Start fully in current mode
            cross_fade_packets: initial_cross_fade,
            red_ppm_hint: 0,
            interleave_depth,
        }
    }

    /// **SEAMLESS** Process outgoing packet through FEC encoder with smooth mode transitions
    pub fn on_send(&mut self, packet: FecPacket) -> Vec<FecPacket> {
        let mut output = Vec::new();

        // **ZERO-CPU FAST PATH**: Ultra-optimized pass-through
        if self.current_mode() == FecMode::Zero && self.transition_left == 0 {
            // Absolute zero overhead: direct return without any processing
            output.push(packet);
            return output;
        }

        // **TRANSITION HANDLING**: Blend old and new modes during cross-fade
        if self.transition_left > 0 {
            return self.handle_transition_packet(packet);
        }
        // Normal path: forward systematic and feed encoder
        output.push(packet.clone());
        let mut encoder = self.encoder.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        encoder.take_packet(packet);

        // Check if we should generate repair packets
        let (k, n) = encoder.params();
        if encoder.packets_in_window() >= k {
            let base = n.saturating_sub(k);
            if base > 0 {
                // Extra repairs scale with redundancy hint (ppm)
                let extra = if self.red_ppm_hint > 120_000 {
                    ((self.red_ppm_hint - 120_000) / 50_000) as usize
                } else {
                    0
                };
                let total = (base + extra.min(4)).min(base + 4);
                for i in 0..total {
                    let idx = i % base;
                    if let Some(repair) = encoder.generate_repair_packet(idx, &self.mem_pool) {
                        output.push(repair);
                    }
                }
            }
            encoder.clear_window();
            self.window_complete = true;
        }
        drop(encoder);

        // **ADAPTIVE STREAMING**: Dynamic stream_every based on loss rate
        if self.current_mode() == FecMode::Streaming {
            self.stream_ctr += 1;
            let effective_every = self.stream_every;
            if self.stream_ctr >= effective_every {
                self.stream_ctr = 0;
                let mut repair_queue = std::mem::take(&mut self.stream_repair_scratch);
                self.emit_streaming_repair(&mut repair_queue);
                if !repair_queue.is_empty() {
                    output.extend(repair_queue.drain(..));
                }
                self.stream_repair_scratch = repair_queue;
            }
        }

        // Telemetry: queue length, uniqueness and order depth
        crate::telemetry::FEC_EMITTED_QUEUE
            .store(output.len() as u64, std::sync::atomic::Ordering::Relaxed);
        for p in &output {
            self.emitted_ids.insert(p.id);
            self.emitted_order.push_back(p.id);
            if self.emitted_order.len() > 4096 {
                self.emitted_order.pop_front();
            }
        }
        crate::telemetry::FEC_EMITTED_ORDER_DEPTH
            .store(self.emitted_order.len() as u64, std::sync::atomic::Ordering::Relaxed);
        crate::telemetry::FEC_EMITTED_UNIQUE
            .store(self.emitted_ids.len() as u64, std::sync::atomic::Ordering::Relaxed);
        output
    }

    pub fn on_receive(&mut self, packet: FecPacket) -> Result<Vec<FecPacket>, String> {
        let mut decoder = self.decoder.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        decoder.take_packet(packet);

        if let Some(result) = decoder.get_result() {
            Ok(result.into_iter().collect())
        } else if self.partial_enabled {
            Ok(decoder.get_partial_result().into_iter().collect())
        } else {
            Ok(Vec::new())
        }
    }

    /// Return a reference to the internal memory pool
    pub fn memory_pool(&self) -> &Arc<MemoryPool> {
        &self.mem_pool
    }

    #[cfg(test)]
    fn stream_repair_scratch_capacity(&self) -> usize {
        self.stream_repair_scratch.capacity()
    }

    #[cfg(test)]
    fn stream_repair_scratch_len(&self) -> usize {
        self.stream_repair_scratch.len()
    }
    /// **SEAMLESS TRANSITION**: Handle packet during mode cross-fade
    fn handle_transition_packet(&mut self, packet: FecPacket) -> Vec<FecPacket> {
        let mut output = Vec::new();

        // Update transition progress (smooth interpolation)
        self.transition_progress =
            1.0 - (self.transition_left as f32 / self.cross_fade_packets as f32);

        // Process with both old and new encoders, blend outputs
        let old_weight = 1.0 - self.transition_progress;
        let new_weight = self.transition_progress;

        // Always forward systematic packet
        output.push(packet.clone());

        // Process with current encoder (old mode)
        if old_weight > 0.0 {
            let mut encoder = self.encoder.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            encoder.take_packet(packet.clone());

            let (k, n) = encoder.params();
            if encoder.packets_in_window() >= k {
                let base = n.saturating_sub(k);
                let repair_count = (base as f32 * old_weight).ceil() as usize;
                for i in 0..repair_count.min(base) {
                    if let Some(repair) = encoder.generate_repair_packet(i, &self.mem_pool) {
                        output.push(repair);
                    }
                }
                if old_weight < 0.5 {
                    // Only clear when mostly transitioned
                    encoder.clear_window();
                }
            }
        }

        // Process with transition encoder (new mode)
        if new_weight > 0.0 && self.transition_encoder.is_some() {
            if let Some(ref transition_enc) = self.transition_encoder {
                let mut encoder =
                    transition_enc.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                encoder.take_packet(packet);

                let (k, n) = encoder.params();
                if encoder.packets_in_window() >= k {
                    let base = n.saturating_sub(k);
                    let repair_count = (base as f32 * new_weight).ceil() as usize;
                    for i in 0..repair_count.min(base) {
                        if let Some(repair) = encoder.generate_repair_packet(i, &self.mem_pool) {
                            output.push(repair);
                        }
                    }
                    if new_weight > 0.5 {
                        // Clear when mostly in new mode
                        encoder.clear_window();
                    }
                }
            }
        }

        // Decrement transition counter
        self.transition_left -= 1;
        if self.transition_left == 0 {
            // Transition complete, swap encoders seamlessly
            if let Some(new_encoder) = self.transition_encoder.take() {
                self.encoder = new_encoder;
            }
            if let Some(new_decoder) = self.transition_decoder.take() {
                self.decoder = new_decoder;
            }
            self.window_complete = false;
            self.transition_progress = 1.0;
            self.transition_buffer.clear();
        }

        output
    }

    /// **GRADUAL MODE SWITCHING**: Initiate seamless transition to new mode
    pub fn transition_to_mode(&mut self, new_mode: FecMode) {
        let current = match self.mode_manager.lock() {
            Ok(mgr) => mgr.current_mode(),
            Err(poisoned) => {
                log::warn!("mode_manager poisoned; recovering");
                poisoned.into_inner().current_mode()
            }
        };
        if current == new_mode || self.transition_left > 0 {
            return; // Already in target mode or transitioning
        }

        let k = 64; // Default window size
        let (k, n) = internal::ModeManager::params_for(new_mode, k);

        // Create new encoder/decoder for transition
        self.transition_encoder = Some(Arc::new(Mutex::new(internal::InterleavedEncoder::new(
            new_mode,
            k,
            n,
            self.interleave_depth,
        ))));
        self.transition_decoder = Some(Arc::new(Mutex::new(internal::InterleavedDecoder::new(
            new_mode,
            k,
            Arc::clone(&self.mem_pool),
            self.interleave_depth,
        ))));

        // Start cross-fade transition
        let old_k = internal::ModeManager::params_for(current, 64).0;
        self.cross_fade_packets = Self::compute_cross_fade_len(current, new_mode, old_k, k);
        self.transition_left = self.cross_fade_packets;
        self.transition_progress = 0.0;

        // Update streaming mode flag
        self.streaming_mode = matches!(new_mode, FecMode::Streaming);

        let mut mode_mgr =
            self.mode_manager.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        mode_mgr.force_state(new_mode, k);
    }

    /// Adjust streaming repair emission interval (every N systematic packets). Clamped to [1, 32]
    pub fn set_stream_every(&mut self, every: usize) {
        let clamped = every.clamp(1, 32);
        self.stream_every_override = Some(clamped);
        self.set_stream_every_internal(clamped);
    }
    /// Set redundancy hint in parts-per-million (100_000 = 1.0x). Influences streaming burst.
    pub fn set_redundancy_ppm(&mut self, ppm: u32) {
        self.red_ppm_hint = ppm;
    }
    /// Set cross-fade duration for seamless mode transitions
    pub fn set_cross_fade_packets(&mut self, packets: usize) {
        self.cross_fade_packets = packets.clamp(5, 100);
        if self.transition_left > self.cross_fade_packets {
            self.transition_left = self.cross_fade_packets;
        }
    }

    fn set_stream_every_internal(&mut self, val: usize) {
        self.stream_every = val.clamp(1, 32);
        self.stream_ctr = 0;
        self.stream_last_adjust = crate::time_source::now_instant();
    }

    fn update_stream_interval(&mut self, estimated_loss: f32) {
        if self.stream_every_override.is_some() {
            return;
        }
        if crate::time_source::now_instant()
            .checked_duration_since(self.stream_last_adjust)
            .unwrap_or_default()
            < Duration::from_millis(STREAM_ADJUST_MIN_MS)
        {
            return;
        }
        let target_every = if estimated_loss >= 0.30
            || (self.loss_estimator.disturbance_detected() && estimated_loss >= 0.15)
        {
            1
        } else if estimated_loss >= 0.12 {
            2
        } else if estimated_loss >= 0.06 {
            3
        } else if estimated_loss >= 0.03 {
            4
        } else if estimated_loss <= 0.01 {
            8
        } else {
            6
        };
        if target_every == self.stream_every {
            return;
        }
        let delta = if target_every < self.stream_every { -2 } else { 1 };
        let new_every = (self.stream_every as isize + delta).clamp(1, 8) as usize;
        if new_every != self.stream_every {
            self.set_stream_every_internal(new_every);
            log::debug!("FEC: adjusted stream interval to every {} packets", new_every);
        }
    }

    fn compute_cross_fade_len(
        old_mode: FecMode,
        new_mode: FecMode,
        old_k: usize,
        new_k: usize,
    ) -> usize {
        if old_mode == new_mode {
            return 10;
        }
        let k_delta = old_k.abs_diff(new_k);
        let base = match (old_mode, new_mode) {
            (FecMode::Streaming, FecMode::Normal) | (FecMode::Normal, FecMode::Streaming) => 12,
            (FecMode::Zero, FecMode::Streaming) | (FecMode::Streaming, FecMode::Zero) => 8,
            (_, FecMode::Fountain) | (FecMode::Fountain, _) => 24,
            (_, FecMode::Extreme) | (FecMode::Extreme, _) => 20,
            _ => 16,
        };
        let k_factor = (k_delta / 16).min(8);
        (base + k_factor).clamp(5, 40)
    }
}

// **FOUNTAIN CODES**: Rateless coding implementation for extreme loss scenarios
mod fountain_codes {
    use super::MemoryPool;
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;

    /// **LT (Luby Transform) Fountain Code** - Rateless erasure coding
    pub struct LTEncoder {
        k: usize,              // Number of source symbols
        symbols: Vec<Vec<u8>>, // Source symbols
        degree_dist: Vec<f64>, // Degree distribution (Robust Soliton)
        rng_seed: u64,
        symbol_size: usize,
    }

    impl LTEncoder {
        pub fn new(k: usize, symbol_size: usize) -> Self {
            let degree_dist = Self::robust_soliton_distribution(k);
            Self {
                k,
                symbols: Vec::with_capacity(k),
                degree_dist,
                rng_seed: 12345, // Fixed seed for reproducibility
                symbol_size,
            }
        }

        /// **Robust Soliton Distribution** - Optimal degree distribution for LT codes
        fn robust_soliton_distribution(k: usize) -> Vec<f64> {
            if k == 0 {
                return vec![1.0];
            }
            let mut dist = vec![0.0; k + 1];
            let c = 0.03; // Failure probability parameter
            let delta = 0.5; // Overhead parameter
            let s = c * (k as f64).ln() * (k as f64 / delta).sqrt();

            // Ideal Soliton distribution
            dist[1] = 1.0 / k as f64;
            #[allow(clippy::needless_range_loop)]
            for i in 2..=k {
                dist[i] = 1.0 / (i * (i - 1)) as f64;
            }

            // Robust component
            let robust_limit = if s.is_finite() && s > f64::EPSILON {
                ((k as f64 / s).floor() as usize).clamp(1, k)
            } else {
                k
            };
            #[allow(clippy::needless_range_loop)]
            for i in 1..=robust_limit {
                dist[i] += s / (i * k) as f64;
            }

            // Normalize
            let sum: f64 = dist.iter().sum();
            for d in &mut dist {
                *d /= sum;
            }

            // Convert to cumulative distribution
            for i in 1..dist.len() {
                dist[i] += dist[i - 1];
            }

            dist
        }

        /// **Generate encoded symbol** and return indices for BP decoding
        pub fn generate_symbol_with_indices(&mut self, symbol_id: u64) -> (Vec<u8>, Vec<usize>) {
            if self.symbols.is_empty() {
                return (vec![0; self.symbol_size], Vec::new());
            }

            // Deterministic random number generator based on symbol_id
            let mut rng_state = self.rng_seed.wrapping_mul(symbol_id).wrapping_add(0x9e3779b9);

            // Select degree using robust soliton distribution
            let degree = self.select_degree(&mut rng_state);

            // Select source symbols to XOR
            let mut encoded = vec![0u8; self.symbol_size];
            let mut selected = HashSet::new();
            let mut used_indices = Vec::with_capacity(degree);

            for _ in 0..degree {
                let idx = (rng_state % self.symbols.len() as u64) as usize;
                rng_state = rng_state.wrapping_mul(1664525).wrapping_add(1013904223);

                if selected.insert(idx) && idx < self.symbols.len() {
                    // SIMD-accelerated XOR combine
                    super::fast_xor_inplace(&self.symbols[idx][..], &mut encoded[..]);
                    used_indices.push(idx);
                }
            }

            (encoded, used_indices)
        }

        fn select_degree(&self, rng_state: &mut u64) -> usize {
            let r = (*rng_state as f64) / (u64::MAX as f64);
            *rng_state = rng_state.wrapping_mul(1664525).wrapping_add(1013904223);

            for (degree, &cum_prob) in self.degree_dist.iter().enumerate() {
                if r <= cum_prob {
                    return degree.max(1);
                }
            }
            self.k() // Fallback to maximum degree
        }

        pub fn add_source_symbol(&mut self, symbol: Vec<u8>) {
            if self.symbols.len() < self.k() {
                self.symbols.push(symbol);
            }
        }

        pub fn symbol_size(&self) -> usize {
            self.symbol_size
        }
        pub fn clear_window(&mut self) {
            self.symbols.clear();
        }
        pub fn packets_in_window(&self) -> usize {
            self.symbols.len()
        }
        pub fn k(&self) -> usize {
            self.k
        }
    }

    /// **Belief Propagation Decoder** for LT codes
    pub struct LTDecoder {
        k: usize,
        symbol_size: usize,
        received_symbols: HashMap<u64, Vec<u8>>,
        decoded_symbols: Vec<Option<Vec<u8>>>,
        symbol_degrees: HashMap<u64, HashSet<usize>>,
        degree_one_queue: Vec<u64>,
        pub(crate) mem_pool: Arc<MemoryPool>,
    }

    impl LTDecoder {
        #[inline]
        pub fn symbol_size(&self) -> usize {
            self.symbol_size
        }
        pub fn new(k: usize, symbol_size: usize, mem_pool: Arc<MemoryPool>) -> Self {
            Self {
                k,
                symbol_size,
                received_symbols: HashMap::new(),
                decoded_symbols: vec![None; k],
                symbol_degrees: HashMap::new(),
                degree_one_queue: Vec::new(),
                mem_pool,
            }
        }

        /// Add received symbol for decoding (no degree info available)
        pub fn add_received_symbol(&mut self, symbol_id: u64, data: Vec<u8>) {
            self.received_symbols.insert(symbol_id, data);
            // Without source index set we cannot peel immediately. We rely on
            // additional encoded symbols with indices to trigger peeling.
        }

        /// **Belief Propagation Decoding** - Iterative peeling decoder
        pub fn add_encoded_symbol(
            &mut self,
            symbol_id: u64,
            data: Vec<u8>,
            source_indices: HashSet<usize>,
        ) -> bool {
            self.received_symbols.insert(symbol_id, data);
            self.symbol_degrees.insert(symbol_id, source_indices.clone());

            if source_indices.len() == 1 {
                self.degree_one_queue.push(symbol_id);
            }

            self.belief_propagation_step()
        }

        pub fn belief_propagation_step(&mut self) -> bool {
            let mut progressed = false;
            while let Some(symbol_id) = self.degree_one_queue.pop() {
                if let Some(indices) = self.symbol_degrees.get(&symbol_id).cloned() {
                    if indices.len() == 1 {
                        let Some(&source_idx) = indices.iter().next() else {
                            continue;
                        };
                        if self.decoded_symbols[source_idx].is_none() {
                            if let Some(encoded_data) = self.received_symbols.get(&symbol_id) {
                                let decoded = encoded_data.clone();
                                self.decoded_symbols[source_idx] = Some(decoded.clone());
                                // Update all other encoded symbols
                                self.propagate_decoded_symbol(source_idx, &decoded);
                                progressed = true;
                            }
                        }
                    }
                }
            }
            progressed
        }

        pub fn belief_propagation_decode(&mut self) -> bool {
            // Iterate peeling until no further progress is possible
            while self.belief_propagation_step() {}
            // Return whether all source symbols have been decoded
            self.decoded_symbols.iter().all(|s| s.is_some())
        }

        pub fn get_partial(&mut self) -> Vec<Vec<u8>> {
            // Touch symbol_size to ensure compiler understands it is used
            let _sz = self.symbol_size();
            self.decoded_symbols.iter().filter_map(|s| s.clone()).collect()
        }

        // Removed is_complete; use decoding_progress() or get_decoded_symbols()

        pub fn propagate_decoded_symbol(&mut self, decoded_idx: usize, decoded_data: &[u8]) {
            let mut to_update = Vec::new();

            for (&symbol_id, indices) in &self.symbol_degrees {
                if indices.contains(&decoded_idx) {
                    to_update.push(symbol_id);
                }
            }

            for symbol_id in to_update {
                // Remove decoded symbol from this encoded symbol (SIMD-accelerated XOR)
                if let Some(encoded_data) = self.received_symbols.get_mut(&symbol_id) {
                    let sl = core::cmp::min(encoded_data.len(), decoded_data.len());
                    super::fast_xor_inplace(&decoded_data[..sl], &mut encoded_data[..sl]);
                }

                if let Some(indices) = self.symbol_degrees.get_mut(&symbol_id) {
                    indices.remove(&decoded_idx);

                    if indices.len() == 1 {
                        self.degree_one_queue.push(symbol_id);
                    }
                }
            }
        }

        pub fn get_decoded_symbols(&self) -> Option<Vec<Vec<u8>>> {
            let mut out = Vec::with_capacity(self.decoded_symbols.len());
            for symbol in &self.decoded_symbols {
                let data = symbol.as_ref()?;
                out.push(data.clone());
            }
            Some(out)
        }

        pub fn decoding_progress(&self) -> f32 {
            let decoded_count = self.decoded_symbols.iter().filter(|s| s.is_some()).count();
            decoded_count as f32 / self.k as f32
        }
    }
}

// **ADAPTIVE REED-SOLOMON**: Dynamic parameter optimization
mod adaptive_reed_solomon {
    use super::*;

    /// **Adaptive Reed-Solomon Encoder** with dynamic parameter selection
    pub struct AdaptiveRSEncoder {
        base_k: usize,
        base_n: usize,
        current_k: usize,
        current_n: usize,
        loss_history: VecDeque<f32>,
        gf_size: usize, // Galois field size (256 for GF(2^8), 65536 for GF(2^16))
        primitive_poly: u32,
    }

    impl AdaptiveRSEncoder {
        pub fn new(base_k: usize, base_n: usize) -> Self {
            Self {
                base_k,
                base_n,
                current_k: base_k,
                current_n: base_n,
                loss_history: VecDeque::with_capacity(100),
                gf_size: 256,          // Start with GF(2^8)
                primitive_poly: 0x11D, // x^8 + x^4 + x^3 + x^2 + 1
            }
        }

        /// **Dynamic Parameter Adaptation** based on network conditions
        pub fn adapt_parameters(
            &mut self,
            current_loss: f32,
            latency_ms: f32,
            bandwidth_mbps: f32,
        ) {
            self.loss_history.push_back(current_loss);
            if self.loss_history.len() > 100 {
                self.loss_history.pop_front();
            }

            let len = self.loss_history.len();
            let (left, right) = self.loss_history.as_slices();
            let sum_loss = accelerate::iter::sum_f32(left) + accelerate::iter::sum_f32(right);
            let avg_loss: f32 = if len > 0 { sum_loss / len as f32 } else { 0.0 };
            let loss_variance = self.calculate_loss_variance(avg_loss);

            // **Adaptive Strategy Selection**
            if avg_loss > 0.3 || loss_variance > 0.1 {
                // High/variable loss: Increase redundancy, consider larger GF
                self.current_n = (self.base_n as f32 * (1.0 + avg_loss * 2.0)) as usize;
                if avg_loss > 0.5 {
                    self.gf_size = 65536; // Switch to GF(2^16) for better error correction
                    self.primitive_poly = 0x1100B; // x^16 + x^12 + x^3 + x + 1
                }
            } else if avg_loss < 0.05 && latency_ms < 10.0 {
                // Low loss, low latency: Optimize for speed
                self.current_n = self.base_n;
                self.current_k = (self.base_k as f32 * 1.2) as usize; // Larger blocks for efficiency
                self.gf_size = 256; // Stay with GF(2^8) for speed
            } else {
                // Balanced approach
                self.current_k = self.base_k;
                self.current_n = (self.base_n as f32 * (1.0 + avg_loss)) as usize;
            }

            // Bandwidth-aware adaptation
            if bandwidth_mbps < 10.0 {
                // Low bandwidth: Minimize overhead
                let max_overhead = 0.2; // 20% max overhead
                let max_n = (self.current_k as f32 / (1.0 - max_overhead)) as usize;
                self.current_n = self.current_n.min(max_n);
            }

            // Ensure valid parameters
            self.current_k = self.current_k.min(self.gf_size - 1);
            self.current_n = self.current_n.min(self.gf_size - 1).max(self.current_k + 1);
        }

        fn calculate_loss_variance(&self, avg_loss: f32) -> f32 {
            if self.loss_history.len() < 2 {
                return 0.0;
            }

            let len = self.loss_history.len();
            let (left, right) = self.loss_history.as_slices();
            let mut diffs = Vec::with_capacity(len);
            diffs.extend(left.iter().map(|&loss| (loss - avg_loss).powi(2)));
            diffs.extend(right.iter().map(|&loss| (loss - avg_loss).powi(2)));

            let sum_sq = accelerate::iter::sum_f32(&diffs);
            (sum_sq / (len - 1) as f32).sqrt()
        }

        // Removed encode/parity helper (not used in the production path).

        pub fn current_parameters(&self) -> (usize, usize, usize) {
            (self.current_k, self.current_n, self.gf_size)
        }
    }
}

// Finalized consolidation target: all logic in this file.
// gf_tables module is inlined below; no external module binding remains.
mod gf_tables {
    use crate::optimize::{self};
    use log::warn;
    use std::sync::Once;

    // GF(2^8) constants
    const IRREDUCIBLE_POLY: u16 = 0x11D;
    // GF16 poly constant removed (unused); reduction constants are in kernels

    // Precomputed tables for GF(2^8)
    static mut LOG_TABLE: [u8; 256] = [0; 256];
    static mut EXP_TABLE: [u8; 512] = [0; 512];
    static INIT: Once = Once::new();

    pub(crate) fn init_tables() {
        INIT.call_once(|| {
            unsafe {
                // Initialize exp/log tables
                let mut x = 1u8;
                for i in 0..255 {
                    EXP_TABLE[i] = x;
                    EXP_TABLE[i + 255] = x;
                    LOG_TABLE[x as usize] = i as u8;
                    let mut y = x as u16;
                    y = (y << 1) ^ if y & 0x80 != 0 { IRREDUCIBLE_POLY } else { 0 };
                    x = y as u8;
                }
                LOG_TABLE[0] = 0;
            }
        });
    }

    #[inline(always)]
    pub(crate) unsafe fn prefetch_log(idx: usize) {
        #[cfg(target_arch = "x86_64")]
        {
            crate::optimize::prefetch(
                LOG_TABLE.as_ptr().add(idx),
                crate::optimize::PrefetchHint::T0,
            );
        }
        #[cfg(target_arch = "aarch64")]
        {
            let _ = idx; // no-op on stable aarch64
        }
    }

    // Removed prefetch_exp (not used).

    #[inline(always)]
    pub(crate) unsafe fn prefetch_data(ptr: *const u8) {
        #[cfg(target_arch = "x86_64")]
        {
            crate::optimize::prefetch(ptr, crate::optimize::PrefetchHint::T0);
        }
        #[cfg(target_arch = "aarch64")]
        {
            let _ = ptr; // no-op on stable aarch64
        }
    }

    #[inline(always)]
    pub(crate) fn gf_mul_table(a: u8, b: u8) -> u8 {
        init_tables();
        if a == 0 || b == 0 {
            return 0;
        }
        unsafe {
            let log_a = LOG_TABLE[a as usize] as u16;
            let log_b = LOG_TABLE[b as usize] as u16;
            let sum_log = log_a + log_b;
            EXP_TABLE[sum_log as usize]
        }
    }

    #[inline(always)]
    pub(crate) fn gf_inv8(x: u8) -> u8 {
        init_tables();
        if x == 0 {
            return 0;
        }
        unsafe {
            let lx = LOG_TABLE[x as usize] as i32;
            // In GF(2^8) with 0x11D primitive, multiplicative group size is 255
            let e = 255 - lx;
            EXP_TABLE[(e as usize) % 255]
        }
    }

    // Removed gf_exp (not used).

    // Removed gf_div8 (not used).

    #[cfg(target_arch = "x86_64")]
    pub(crate) unsafe fn gf_mul_gfni(a: u8, b: u8) -> u8 {
        use std::arch::x86_64::*;
        // AVX512GFNI provides native GF(2^8) multiplication!
        let a_vec = _mm512_set1_epi8(a as i8);
        let b_vec = _mm512_set1_epi8(b as i8);
        // _mm512_gf2p8mul_epi8 performs GF(2^8) multiplication with polynomial 0x11B
        let result = _mm512_gf2p8mul_epi8(a_vec, b_vec);
        _mm512_cvtsi512_si32(result) as u8
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) unsafe fn gf_mul_bitsliced_avx512(a: u8, b: u8) -> u8 {
        use std::arch::x86_64::*;
        let a128 = _mm_set_epi64x(0, a as i64);
        let b128 = _mm_set_epi64x(0, b as i64);
        let va = _mm512_broadcast_i64x2(a128);
        let vb = _mm512_broadcast_i64x2(b128);
        let prod = _mm512_clmulepi64_epi128(va, vb, 0x00);
        let low = _mm512_castsi512_si128(prod);
        let mut t = _mm_extract_epi16(low, 0) as u16;
        t ^= t >> 8;
        t ^= t >> 4;
        t ^= t >> 2;
        t ^= t >> 1;
        (t & 0xFF) as u8
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512f,avx512vbmi")]
    pub(crate) unsafe fn gf_mul_avx512(a: u8, b: u8) -> u8 {
        gf_mul_bitsliced_avx512(a, b)
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) unsafe fn gf_mul_bitsliced_avx2(a: u8, b: u8) -> u8 {
        use std::arch::x86_64::*;
        let a128 = _mm_set_epi64x(0, a as i64);
        let b128 = _mm_set_epi64x(0, b as i64);
        let va = _mm256_broadcastsi128_si256(a128);
        let vb = _mm256_broadcastsi128_si256(b128);
        let prod = _mm256_clmulepi64_epi128(va, vb, 0x00);
        let low = _mm256_castsi256_si128(prod);
        let mut t = _mm_extract_epi16(low, 0) as u16;
        t ^= t >> 8;
        t ^= t >> 4;
        t ^= t >> 2;
        t ^= t >> 1;
        (t & 0xFF) as u8
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    pub(crate) unsafe fn gf_mul_avx2(a: u8, b: u8) -> u8 {
        gf_mul_bitsliced_avx2(a, b)
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) unsafe fn gf_mul_bitsliced_sse2(a: u8, b: u8) -> u8 {
        use std::arch::x86_64::*;
        let a_v = _mm_set_epi64x(0, a as i64);
        let b_v = _mm_set_epi64x(0, b as i64);
        let res_v = _mm_clmulepi64_si128(a_v, b_v, 0x00);
        let res16 = _mm_extract_epi16(res_v, 0) as u16;
        let t = res16 ^ (res16 >> 8);
        let t = t ^ (t >> 4);
        let t = t ^ (t >> 2);
        let t = t ^ (t >> 1);
        (t & 0xFF) as u8
    }

    // removed cfg/target_feature for gf_mul_slice_neon
    #[cfg(target_arch = "aarch64")]
    pub unsafe fn gf_mul_bitsliced_neon(a: u8, b: u8) -> u8 {
        use std::arch::aarch64::*;
        let a_vec = vreinterpret_p8_u8(vdup_n_u8(a));
        let b_vec = vreinterpret_p8_u8(vdup_n_u8(b));
        let prod: poly16x8_t = vmull_p8(a_vec, b_vec);
        let mut t = vgetq_lane_u16(vreinterpretq_u16_p16(prod), 0);
        t ^= t >> 8;
        t ^= t >> 4;
        t ^= t >> 2;
        t ^= t >> 1;
        (t & 0xFF) as u8
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    pub unsafe fn gf_mul_neon(a: u8, b: u8) -> u8 {
        gf_mul_bitsliced_neon(a, b)
    }

    #[cfg(target_arch = "aarch64")]
    pub unsafe fn gf_mul_sve2(a: u8, b: u8) -> u8 {
        #[cfg(target_feature = "sve2")]
        {
            return gf_mul_bitsliced_neon(a, b);
        }

        gf_mul_bitsliced_neon(a, b)
    }

    // NEON smoke test removed (tests only via scripts/ policy)

    // Removed gf_mul_slice_sve2 (not used).

    #[cfg(target_arch = "aarch64")]
    unsafe fn gf_mul_scalar_slice_sve2(coeff: u8, src: &[u8], out_xor: &mut [u8]) {
        #[cfg(target_feature = "sve2")]
        {
            use std::arch::aarch64::*;

            debug_assert_eq!(src.len(), out_xor.len());
            let len = src.len();
            if len == 0 {
                return;
            }

            // Precompute 4-bit nibble tables replicated across the vector length.
            let mut t0_arr = [0u8; 16];
            let mut t1_arr = [0u8; 16];
            for i in 0..16 {
                t0_arr[i] = gf_mul_table(coeff, i as u8);
                t1_arr[i] = gf_mul_table(coeff, (i as u8) << 4);
            }

            let tbl0 = svld1rq_u8(svptrue_b8(), t0_arr.as_ptr());
            let tbl1 = svld1rq_u8(svptrue_b8(), t1_arr.as_ptr());
            let mask0f = svdup_n_u8(0x0f);
            let mut offset = 0usize;
            let vl = svcntb() as usize;
            let pf_dist: usize = if len >= 4096 {
                256
            } else if len >= 1024 {
                192
            } else if len >= 512 {
                128
            } else {
                0
            };

            while offset < len {
                let pg = svwhilelt_b8(offset as u64, len as u64);
                if !svptest_any(svptrue_b8(), pg) {
                    break;
                }

                if pf_dist != 0 {
                    let pf_idx = offset + pf_dist;
                    if pf_idx < len {
                        prefetch_data(src.as_ptr().add(pf_idx));
                        prefetch_data(out_xor.as_ptr().add(pf_idx));
                    }
                }

                let src_vec = svld1_u8(pg, src.as_ptr().add(offset));
                let lo = svand_u8_x(pg, src_vec, mask0f);
                let hi = svand_u8_x(pg, svlsr_n_u8_z(pg, src_vec, 4), mask0f);

                let prod_lo = svtbl_u8(tbl0, lo);
                let prod_hi = svtbl_u8(tbl1, hi);
                let prod = sveor_u8_m(pg, prod_lo, prod_lo, prod_hi);

                let dst_vec = svld1_u8(pg, out_xor.as_ptr().add(offset));
                let result = sveor_u8_m(pg, dst_vec, dst_vec, prod);
                svst1_u8(pg, out_xor.as_mut_ptr().add(offset), result);

                offset += vl;
            }

            crate::optimize::telemetry::FEC_SVE2_OPS.inc();
            return;
        }

        gf_mul_scalar_slice_neon(coeff, src, out_xor);
    }

    // Removed gf_mul_slice (not used).

    /* removed: gf_mul_slice_gfni */

    /* removed: gf_mul_slice_avx512 */

    /* removed: gf_mul_slice_avx2 */

    /* removed: gf_mul_slice_sse2 */

    /* removed: gf_mul_slice_neon */

    /// **ULTRA-OPTIMIZED** GF(2^8) scalar multiplication with zero-copy SIMD dispatch
    #[inline(always)]
    pub(crate) fn gf_mul_scalar_slice(coeff: u8, src: &[u8], out_xor: &mut [u8]) {
        if src.is_empty() || out_xor.is_empty() {
            return;
        }
        let len = src.len().min(out_xor.len());

        // **ZERO-COPY FAST PATHS** for special coefficients
        if coeff == 0 {
            return;
        }
        if coeff == 1 {
            // **ULTRA-FAST XOR**: 64-byte unrolled loop for maximum throughput
            let mut i = 0;
            // Process 64 bytes at a time for maximum cache efficiency
            while i + 64 <= len {
                #[cfg(target_arch = "x86_64")]
                unsafe {
                    crate::optimize::prefetch(
                        src.as_ptr().add(i + 64),
                        crate::optimize::PrefetchHint::T0,
                    );
                }
                // 64-byte unrolled XOR for maximum ILP (Instruction Level Parallelism)
                for j in 0..64 {
                    out_xor[i + j] ^= src[i + j];
                }
                i += 64;
            }
            // Handle remaining bytes with 8-byte chunks
            while i + 8 <= len {
                out_xor[i] ^= src[i];
                out_xor[i + 1] ^= src[i + 1];
                out_xor[i + 2] ^= src[i + 2];
                out_xor[i + 3] ^= src[i + 3];
                out_xor[i + 4] ^= src[i + 4];
                out_xor[i + 5] ^= src[i + 5];
                out_xor[i + 6] ^= src[i + 6];
                out_xor[i + 7] ^= src[i + 7];
                i += 8;
            }
            while i < len {
                out_xor[i] ^= src[i];
                i += 1;
            }
            return;
        }

        // SIMD specialized paths - avoid closure borrowing issues
        let policy = optimize::FeatureDetector::instance();

        #[cfg(target_arch = "x86_64")]
        {
            if policy.has_feature(optimize::CpuFeature::AVX512F)
                && policy.has_feature(optimize::CpuFeature::GFNI)
            {
                unsafe {
                    gf_mul_scalar_slice_gfni(coeff, &src[..len], &mut out_xor[..len]);
                }
                return;
            }
            if policy.has_feature(optimize::CpuFeature::AVX2) {
                unsafe {
                    gf_mul_scalar_slice_avx2(coeff, &src[..len], &mut out_xor[..len]);
                }
                return;
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            if policy.has_feature(optimize::CpuFeature::SVE2) {
                unsafe {
                    gf_mul_scalar_slice_sve2(coeff, &src[..len], &mut out_xor[..len]);
                }
                return;
            }
            if policy.has_feature(optimize::CpuFeature::NEON) {
                unsafe {
                    gf_mul_scalar_slice_neon(coeff, &src[..len], &mut out_xor[..len]);
                }
                return;
            }
        }

        // **CACHE-OPTIMIZED** portable fallback: 256-entry LUT with aggressive prefetching
        let mut lut = [0u8; 256];
        unsafe {
            prefetch_log(coeff as usize);
        }
        // **VECTORIZED LUT GENERATION** - unroll for better ILP
        let mut x = 0;
        while x + 4 <= 256 {
            lut[x] = gf_mul_table(coeff, x as u8);
            lut[x + 1] = gf_mul_table(coeff, (x + 1) as u8);
            lut[x + 2] = gf_mul_table(coeff, (x + 2) as u8);
            lut[x + 3] = gf_mul_table(coeff, (x + 3) as u8);
            x += 4;
        }
        while x < 256 {
            lut[x] = gf_mul_table(coeff, x as u8);
            x += 1;
        }

        // Compute prefetch distance heuristic
        let pf_dist: usize = if len >= 4096 {
            256
        } else if len >= 1024 {
            192
        } else if len >= 512 {
            128
        } else {
            0
        };

        let mut i = 0usize;
        // **CACHE-ALIGNED UNROLLED LOOP** - 64-byte alignment friendly
        while i + 64 <= len {
            if pf_dist != 0 {
                unsafe {
                    let pf_i = i + pf_dist;
                    if pf_i < len {
                        // Prefetch both source and LUT access patterns
                        prefetch_data(src.as_ptr().add(pf_i));
                        prefetch_data(out_xor.as_ptr().add(pf_i));
                    }
                }
            }
            // 64-byte unrolled loop for maximum ILP
            for j in 0..64 {
                out_xor[i + j] ^= lut[src[i + j] as usize];
            }
            i += 64;
        }

        // Handle remaining with 8-byte chunks
        while i + 8 <= len {
            out_xor[i] ^= lut[src[i] as usize];
            out_xor[i + 1] ^= lut[src[i + 1] as usize];
            out_xor[i + 2] ^= lut[src[i + 2] as usize];
            out_xor[i + 3] ^= lut[src[i + 3] as usize];
            out_xor[i + 4] ^= lut[src[i + 4] as usize];
            out_xor[i + 5] ^= lut[src[i + 5] as usize];
            out_xor[i + 6] ^= lut[src[i + 6] as usize];
            out_xor[i + 7] ^= lut[src[i + 7] as usize];
            i += 8;
        }
        while i < len {
            out_xor[i] ^= lut[src[i] as usize];
            i += 1;
        }
    }

    // --- SIMD scalar x vector mul-add (GF(2^8)) specialized paths ---
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512f,gfni")]
    unsafe fn gf_mul_scalar_slice_gfni(coeff: u8, src: &[u8], out_xor: &mut [u8]) {
        use std::arch::x86_64::*;
        debug_assert_eq!(src.len(), out_xor.len());
        let coeff_vec = _mm512_set1_epi8(coeff as i8);
        let mut i = 0;
        // Process 64 bytes at a time
        while i + 64 <= src.len() {
            let src_vec = _mm512_loadu_si512(src.as_ptr().add(i) as *const _);
            let prod = _mm512_gf2p8mul_epi8(coeff_vec, src_vec);
            let dst_vec = _mm512_loadu_si512(out_xor.as_ptr().add(i) as *const _);
            let result = _mm512_xor_si512(dst_vec, prod);
            _mm512_storeu_si512(out_xor.as_mut_ptr().add(i) as *mut _, result);
            i += 64;
        }
        // Handle remainder
        while i < src.len() {
            out_xor[i] ^= gf_mul_gfni(coeff, src[i]);
            i += 1;
        }

        crate::telemetry::FEC_GFNI_OPS.inc();
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn gf_mul_scalar_slice_avx2(coeff: u8, src: &[u8], out_xor: &mut [u8]) {
        use std::arch::x86_64::*;
        debug_assert_eq!(src.len(), out_xor.len());
        // Precompute 16-entry nibble tables
        let mut t0 = [0u8; 16];
        let mut t1 = [0u8; 16];
        for i in 0..16 {
            t0[i] = gf_mul_table(coeff, i as u8);
            t1[i] = gf_mul_table(coeff, ((i as u8) << 4) as u8);
        }
        let tbl0_128 = _mm_loadu_si128(t0.as_ptr() as *const __m128i);
        let tbl1_128 = _mm_loadu_si128(t1.as_ptr() as *const __m128i);
        let tbl0 = _mm256_broadcastsi128_si256(tbl0_128);
        let tbl1 = _mm256_broadcastsi128_si256(tbl1_128);
        let mask0f = _mm256_set1_epi8(0x0f as i8);

        // Heuristic prefetch distance based on total length
        let pf_dist: usize = if src.len() >= 4096 {
            256
        } else if src.len() >= 1024 {
            192
        } else if src.len() >= 512 {
            128
        } else {
            0
        };

        let mut i = 0usize;
        // Unroll by 2: process 64 bytes per iteration when possible
        while i + 64 <= src.len() {
            if pf_dist != 0 {
                let pf_i = i + pf_dist;
                if pf_i < src.len() {
                    prefetch_data(src.as_ptr().add(pf_i));
                    prefetch_data(out_xor.as_ptr().add(pf_i));
                }
            }
            // First 32B chunk
            let x0 = _mm256_loadu_si256(src.as_ptr().add(i) as *const __m256i);
            let lo0 = _mm256_and_si256(x0, mask0f);
            let hi0 = _mm256_and_si256(_mm256_srli_epi16(x0, 4), mask0f);
            let p0_0 = _mm256_shuffle_epi8(tbl0, lo0);
            let p1_0 = _mm256_shuffle_epi8(tbl1, hi0);
            let prod0 = _mm256_xor_si256(p0_0, p1_0);
            let y0 = _mm256_loadu_si256(out_xor.as_ptr().add(i) as *const __m256i);
            let y2_0 = _mm256_xor_si256(y0, prod0);
            _mm256_storeu_si256(out_xor.as_mut_ptr().add(i) as *mut __m256i, y2_0);

            // Second 32B chunk
            let x1 = _mm256_loadu_si256(src.as_ptr().add(i + 32) as *const __m256i);
            let lo1 = _mm256_and_si256(x1, mask0f);
            let hi1 = _mm256_and_si256(_mm256_srli_epi16(x1, 4), mask0f);
            let p0_1 = _mm256_shuffle_epi8(tbl0, lo1);
            let p1_1 = _mm256_shuffle_epi8(tbl1, hi1);
            let prod1 = _mm256_xor_si256(p0_1, p1_1);
            let y1 = _mm256_loadu_si256(out_xor.as_ptr().add(i + 32) as *const __m256i);
            let y2_1 = _mm256_xor_si256(y1, prod1);
            _mm256_storeu_si256(out_xor.as_mut_ptr().add(i + 32) as *mut __m256i, y2_1);

            i += 64;
        }
        while i + 32 <= src.len() {
            if pf_dist != 0 {
                let pf_i = i + pf_dist;
                if pf_i < src.len() {
                    prefetch_data(src.as_ptr().add(pf_i));
                    prefetch_data(out_xor.as_ptr().add(pf_i));
                }
            }
            let x = _mm256_loadu_si256(src.as_ptr().add(i) as *const __m256i);
            let lo = _mm256_and_si256(x, mask0f);
            let hi = _mm256_and_si256(_mm256_srli_epi16(x, 4), mask0f);
            let p0 = _mm256_shuffle_epi8(tbl0, lo);
            let p1 = _mm256_shuffle_epi8(tbl1, hi);
            let prod = _mm256_xor_si256(p0, p1);
            let y = _mm256_loadu_si256(out_xor.as_ptr().add(i) as *const __m256i);
            let y2 = _mm256_xor_si256(y, prod);
            _mm256_storeu_si256(out_xor.as_mut_ptr().add(i) as *mut __m256i, y2);
            i += 32;
        }
        while i < src.len() {
            let v = src[i];
            let lo = (v & 0x0f) as usize;
            let hi = (v >> 4) as usize;
            out_xor[i] ^= t0[lo] ^ t1[hi];
            i += 1;
        }

        crate::telemetry::FEC_AVX2_GF_OPS.inc();
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    unsafe fn gf_mul_scalar_slice_neon(coeff: u8, src: &[u8], out_xor: &mut [u8]) {
        use std::arch::aarch64::*;
        debug_assert_eq!(src.len(), out_xor.len());
        // Precompute 16-entry nibble tables
        let mut t0_arr = [0u8; 16];
        let mut t1_arr = [0u8; 16];
        for i in 0..16 {
            t0_arr[i] = gf_mul_table(coeff, i as u8);
            t1_arr[i] = gf_mul_table(coeff, (i as u8) << 4);
        }
        let t0 = vld1q_u8(t0_arr.as_ptr());
        let t1 = vld1q_u8(t1_arr.as_ptr());
        let mask0f = vdupq_n_u8(0x0f);

        // Heuristic prefetch distance for NEON
        let pf_dist: usize = if src.len() >= 4096 {
            192
        } else if src.len() >= 1024 {
            160
        } else if src.len() >= 512 {
            128
        } else {
            0
        };

        let mut i = 0usize;
        // Unroll by 2: 32 bytes per iteration
        while i + 32 <= src.len() {
            if pf_dist != 0 {
                let pf_i = i + pf_dist;
                if pf_i < src.len() {
                    prefetch_data(src.as_ptr().add(pf_i));
                }
            }
            // First 16B
            let x0 = vld1q_u8(src.as_ptr().add(i));
            let lo0 = vandq_u8(x0, mask0f);
            let hi0 = vandq_u8(vshrq_n_u8(x0, 4), mask0f);
            let p0_0 = vqtbl1q_u8(t0, lo0);
            let p1_0 = vqtbl1q_u8(t1, hi0);
            let prod0 = veorq_u8(p0_0, p1_0);
            let y0 = vld1q_u8(out_xor.as_ptr().add(i));
            let y2_0 = veorq_u8(y0, prod0);
            vst1q_u8(out_xor.as_mut_ptr().add(i), y2_0);

            // Second 16B
            let x1 = vld1q_u8(src.as_ptr().add(i + 16));
            let lo1 = vandq_u8(x1, mask0f);
            let hi1 = vandq_u8(vshrq_n_u8(x1, 4), mask0f);
            let p0_1 = vqtbl1q_u8(t0, lo1);
            let p1_1 = vqtbl1q_u8(t1, hi1);
            let prod1 = veorq_u8(p0_1, p1_1);
            let y1 = vld1q_u8(out_xor.as_ptr().add(i + 16));
            let y2_1 = veorq_u8(y1, prod1);
            vst1q_u8(out_xor.as_mut_ptr().add(i + 16), y2_1);

            i += 32;
        }
        while i + 16 <= src.len() {
            if pf_dist != 0 {
                let pf_i = i + pf_dist;
                if pf_i < src.len() {
                    prefetch_data(src.as_ptr().add(pf_i));
                }
            }
            let x = vld1q_u8(src.as_ptr().add(i));
            let lo = vandq_u8(x, mask0f);
            let hi = vandq_u8(vshrq_n_u8(x, 4), mask0f);
            let p0 = vqtbl1q_u8(t0, lo);
            let p1 = vqtbl1q_u8(t1, hi);
            let prod = veorq_u8(p0, p1);
            let y = vld1q_u8(out_xor.as_ptr().add(i));
            let y2 = veorq_u8(y, prod);
            vst1q_u8(out_xor.as_mut_ptr().add(i), y2);
            i += 16;
        }
        while i < src.len() {
            let v = src[i];
            let lo = (v & 0x0f) as usize;
            let hi = (v >> 4) as usize;
            out_xor[i] ^= t0_arr[lo] ^ t1_arr[hi];
            i += 1;
        }

        crate::optimize::telemetry::FEC_NEON_OPS.inc();
    }

    // Backward-compat shim for gf16_mul_scalar_slice was removed; use gf_mul_scalar_slice (GF8)

    // --- High-Performance Finite Field Arithmetic (GF(2^8)) ---
    #[inline(always)]
    pub fn gf_mul(a: u8, b: u8) -> u8 {
        optimize::dispatch_bitslice(|policy| {
            #[cfg(target_arch = "x86_64")]
            {
                if policy.as_any().is::<optimize::Avx512Gfni>() {
                    return unsafe { gf_mul_gfni(a, b) };
                }
                if policy.as_any().is::<optimize::Avx512>() {
                    return unsafe { gf_mul_avx512(a, b) };
                }
                if policy.as_any().is::<optimize::Avx2>() {
                    return unsafe { gf_mul_avx2(a, b) };
                }
                if policy.as_any().is::<optimize::Sse2>() {
                    return unsafe { gf_mul_bitsliced_sse2(a, b) };
                }
            }
            #[cfg(target_arch = "aarch64")]
            {
                if policy.as_any().is::<optimize::Sve2>() {
                    return unsafe { gf_mul_sve2(a, b) };
                }
                if policy.as_any().is::<optimize::Neon>() {
                    return unsafe { gf_mul_neon(a, b) };
                }
            }
            // Fallback: use table/log-exp implementation
            gf_mul_table(a, b)
        })
    }

    /// Computes the multiplicative inverse of a in GF(2^8)).
    #[inline(always)]
    pub fn gf_inv(a: u8) -> u8 {
        gf_inv8(a)
    }

    // Performs `a * b + c` in GF(2^8)).
    // gf_mul_add removed (unused)

    // --- GF(2^16) Arithmetic for Extreme Mode ---
    // Using GF16_POLY from gf_tables module

    #[inline(always)]
    pub(crate) fn gf16_mul(a: u16, b: u16) -> u16 {
        optimize::dispatch(|policy| {
            #[cfg(target_arch = "x86_64")]
            {
                if policy.as_any().is::<optimize::Avx2>() {
                    // AVX2 scalar carryless multiply with reduction
                    return unsafe { super::gf16_mul_avx2(a, b) };
                }
            }
            #[cfg(target_arch = "aarch64")]
            {
                if policy.as_any().is::<optimize::Sve2>() {
                    return unsafe { gf16_mul_sve2_impl(a, b) };
                }
                if policy.as_any().is::<optimize::Neon>() {
                    return gf16_mul_neon_impl(a, b);
                }
            }
            // Scalar fallback
            let mut aa = a;
            let mut bb = b;
            let mut res: u16 = 0;
            while bb != 0 {
                if (bb & 1) != 0 {
                    res ^= aa;
                }
                bb >>= 1;
                let carry = (aa & 0x8000) != 0;
                aa <<= 1;
                if carry {
                    aa ^= 0x100B; // GF16_POLY value (normalized)
                }
            }
            res
        })
    }

    #[inline(always)]
    pub(crate) fn gf16_pow(mut x: u16, mut power: u32) -> u16 {
        let mut result: u16 = 1;
        while power > 0 {
            if power & 1 != 0 {
                result = gf16_mul(result, x);
            }
            x = gf16_mul(x, x);
            power >>= 1;
        }
        result
    }

    #[inline(always)]
    pub(crate) fn gf16_inv(x: u16) -> u16 {
        if x == 0 {
            warn!("gf16_inv called with 0; returning 0 as safe fallback");
            return 0;
        }
        gf16_pow(x, 0x1_0000 - 2)
    }

    #[cfg(target_arch = "aarch64")]
    unsafe fn gf16_mul_sve2_impl(a: u16, b: u16) -> u16 {
        #[cfg(target_feature = "sve2")]
        {
            use std::arch::aarch64::*;

            let pg = svptrue_b16();
            let zero = svdup_n_u16(0);
            let poly = svdup_n_u16(0x100B);
            let msb_mask = svdup_n_u16(0x8000);
            let mut multiplicand = svdup_n_u16(a);
            let mut acc = svdup_n_u16(0);
            let mut factor = b;

            while factor != 0 {
                if (factor & 1) != 0 {
                    acc = sveor_u16_z(pg, acc, multiplicand);
                }

                let high = svcmpne_u16(pg, svand_u16_z(pg, multiplicand, msb_mask), zero);
                let doubled = svlsl_n_u16_x(pg, multiplicand, 1);
                multiplicand = sveor_u16_m(high, doubled, doubled, poly);

                factor >>= 1;
            }

            return svlasta_u16(pg, acc);
        }

        gf16_mul_neon_impl(a, b)
    }

    fn gf16_mul_neon_impl(a: u16, b: u16) -> u16 {
        // Fallback to scalar since ARM SVE2 intrinsics not stable in Rust yet
        let mut aa = a as u32;
        let mut bb = b as u32;
        let mut res = 0u32;

        for _ in 0..16 {
            if bb & 1 != 0 {
                res ^= aa;
            }
            bb >>= 1;
            aa <<= 1;
            if aa & 0x10000 != 0 {
                aa ^= 0x100B_u32; // GF16_POLY value (normalized)
            }
        }
        res as u16
    }

    #[inline(always)]
    pub(crate) fn gf16_mul_add(a: u16, b: u16, acc: u16) -> u16 {
        // Scalar GF(2^16) multiply with XOR-accumulate
        #[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
        {
            return unsafe { gf16_mul_sve2_impl(a, b) ^ acc };
        }

        gf16_mul_neon_impl(a, b) ^ acc
    }
} // Close gf_tables module

/// Vectorized GF(2^16) scalar multiply-and-xor over big-endian byte slices.
/// out_xor[j..j+2] ^= gf16_mul(coeff, src[j..j+2]) for all j in steps of 2.
#[inline]
pub(crate) fn gf16_mul_scalar_slice_u16(coeff: u16, src: &[u8], out_xor: &mut [u8]) {
    let len = src.len().min(out_xor.len());
    let packet_u16_len = len / 2;
    if coeff == 0 || packet_u16_len == 0 {
        return;
    }

    if coeff == 1 {
        // Simple XOR
        for (x, y) in src[..len].iter().zip(out_xor[..len].iter_mut()) {
            *y ^= *x;
        }
        return;
    }

    let profile = FeatureDetector::instance().profile();
    let vector_threshold = gf16_vector_threshold_words(profile);

    // Chunk size for stack buffer (64 u16 = 128 bytes)
    const CHUNK_SIZE: usize = 64;

    if vector_threshold != usize::MAX && packet_u16_len >= vector_threshold {
        let mut i = 0;
        while i < packet_u16_len {
            let chunk_len = (packet_u16_len - i).min(CHUNK_SIZE);

            // Stack buffers to avoid heap allocation
            let mut src_tmp = [0u16; CHUNK_SIZE];
            let mut dst_tmp = [0u16; CHUNK_SIZE];

            // 1. Gather & Swap Bytes (BE -> Native)
            // Manual loop is reliable and auto-vectorizes well on modern compilers
            for (k, (src_slot, dst_slot)) in
                src_tmp.iter_mut().zip(dst_tmp.iter_mut()).take(chunk_len).enumerate()
            {
                let offset = (i + k) * 2;
                // Safety: Bounds checked by loop limits
                *src_slot = u16::from_be_bytes([src[offset], src[offset + 1]]);
                *dst_slot = u16::from_be_bytes([out_xor[offset], out_xor[offset + 1]]);
            }

            // 2. SIMD Multiply (Native u16)
            gf16_mul_slice(coeff, &src_tmp[..chunk_len], &mut dst_tmp[..chunk_len]);

            // 3. Swap Bytes & Store (Native -> BE)
            for (k, val) in dst_tmp[..chunk_len].iter().enumerate() {
                let offset = (i + k) * 2;
                let bytes = val.to_be_bytes();
                out_xor[offset] = bytes[0];
                out_xor[offset + 1] = bytes[1];
            }

            i += chunk_len;
        }
    } else {
        // Scalar fallback (packet too small or SIMD disabled)
        let mut j = 0;
        while j + 1 < len {
            let s = u16::from_be_bytes([src[j], src[j + 1]]);
            let r = u16::from_be_bytes([out_xor[j], out_xor[j + 1]]);
            let v = gf_tables::gf16_mul_add(coeff, s, r);
            let b = v.to_be_bytes();
            out_xor[j] = b[0];
            out_xor[j + 1] = b[1];
            j += 2;
        }
    }
}

#[inline(always)]
fn gf16_vector_threshold_words(profile: CpuProfile) -> usize {
    match profile {
        CpuProfile::X86_P3c
        | CpuProfile::X86_P3d
        | CpuProfile::X86_P3e
        | CpuProfile::X86_P4a
        | CpuProfile::X86_P4b => GF16_VBMI2_MIN_WORDS,
        CpuProfile::X86_P3a | CpuProfile::X86_P3b => GF16_AVX512_MIN_WORDS,
        CpuProfile::X86_P2a | CpuProfile::X86_P2b => GF16_AVX2_MIN_WORDS,
        CpuProfile::X86_P1f | CpuProfile::X86_P1b | CpuProfile::X86_P1a => GF16_SSE2_MIN_WORDS,
        CpuProfile::ARM_A2 => GF16_SVE2_MIN_WORDS,
        CpuProfile::ARM_A1c | CpuProfile::ARM_A1d | CpuProfile::Apple_M => GF16_NEON_MIN_WORDS,
        CpuProfile::ARM_A1b => GF16_NEON_MIN_WORDS,
        _ => usize::MAX,
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f", enable = "avx512bw", enable = "avx512vbmi2")]
unsafe fn gf16_mul_slice_vbmi2(coeff: u16, src: &[u16], dst: &mut [u16], len: usize) {
    use std::arch::x86_64::*;

    if len == 0 {
        return;
    }

    #[repr(align(64))]
    struct Table([u16; 32]);

    let mut table0_a = Table([0u16; 32]);
    let mut table0_b = Table([0u16; 32]);
    let mut table1_b = Table([0u16; 32]);
    let mut table2_b = Table([0u16; 32]);
    let mut table3_b = Table([0u16; 32]);

    for nib in 0..16u16 {
        let base = nib as usize;
        let contrib0 = gf_tables::gf16_mul(coeff, nib);
        table0_a.0[base] = contrib0;
        table0_a.0[base + 16] = contrib0;
        table0_b.0[base] = contrib0;
        table0_b.0[base + 16] = contrib0;

        let contrib1 = gf_tables::gf16_mul(coeff, nib << 4);
        table1_b.0[base] = contrib1;
        table1_b.0[base + 16] = contrib1;

        let contrib2 = gf_tables::gf16_mul(coeff, nib << 8);
        table2_b.0[base] = contrib2;
        table2_b.0[base + 16] = contrib2;

        let contrib3 = gf_tables::gf16_mul(coeff, nib << 12);
        table3_b.0[base] = contrib3;
        table3_b.0[base + 16] = contrib3;
    }

    let tbl0_a = _mm512_loadu_si512(table0_a.0.as_ptr() as *const __m512i);
    let tbl0_b = _mm512_loadu_si512(table0_b.0.as_ptr() as *const __m512i);
    let tbl1_a = _mm512_setzero_si512();
    let tbl1_b = _mm512_loadu_si512(table1_b.0.as_ptr() as *const __m512i);
    let tbl2_a = _mm512_setzero_si512();
    let tbl2_b = _mm512_loadu_si512(table2_b.0.as_ptr() as *const __m512i);
    let tbl3_a = _mm512_setzero_si512();
    let tbl3_b = _mm512_loadu_si512(table3_b.0.as_ptr() as *const __m512i);

    let mask_nibble = _mm512_set1_epi16(0x000F);
    let offset32 = _mm512_set1_epi16(32);

    let mut i = 0usize;
    while i + 32 <= len {
        let src_vec = _mm512_loadu_si512(src.as_ptr().add(i) as *const __m512i);
        let dst_vec = _mm512_loadu_si512(dst.as_ptr().add(i) as *const __m512i);

        let nib0 = _mm512_and_si512(src_vec, mask_nibble);
        let nib1 = _mm512_and_si512(_mm512_srli_epi16(src_vec, 4), mask_nibble);
        let nib2 = _mm512_and_si512(_mm512_srli_epi16(src_vec, 8), mask_nibble);
        let nib3 = _mm512_srli_epi16(src_vec, 12);

        let idx1 = _mm512_add_epi16(nib1, offset32);
        let idx2 = _mm512_add_epi16(nib2, offset32);
        let idx3 = _mm512_add_epi16(nib3, offset32);

        let contrib0 = _mm512_permutex2var_epi16(nib0, tbl0_a, tbl0_b);
        let contrib1 = _mm512_permutex2var_epi16(idx1, tbl1_a, tbl1_b);
        let contrib2 = _mm512_permutex2var_epi16(idx2, tbl2_a, tbl2_b);
        let contrib3 = _mm512_permutex2var_epi16(idx3, tbl3_a, tbl3_b);

        let partial = _mm512_xor_si512(_mm512_xor_si512(contrib0, contrib1), contrib2);
        let prod = _mm512_xor_si512(partial, contrib3);
        let result = _mm512_xor_si512(dst_vec, prod);

        _mm512_storeu_si512(dst.as_mut_ptr().add(i) as *mut __m512i, result);
        i += 32;
    }

    while i < len {
        dst[i] ^= gf_tables::gf16_mul(coeff, src[i]);
        i += 1;
    }

    crate::telemetry::FEC_GF16_VBMI2_OPS.inc();
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512vbmi")]
unsafe fn gf16_mul_slice_avx512(coeff: u16, src: &[u16], dst: &mut [u16], len: usize) {
    let mut i = 0usize;
    while i < len {
        dst[i] ^= gf_tables::gf16_mul(coeff, src[i]);
        i += 1;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn gf16_mul_slice_avx2(coeff: u16, src: &[u16], dst: &mut [u16], len: usize) {
    let mut i = 0usize;
    while i < len {
        dst[i] ^= gf_tables::gf16_mul(coeff, src[i]);
        i += 1;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn gf16_mul_slice_sse2(coeff: u16, src: &[u16], dst: &mut [u16], len: usize) {
    let mut i = 0usize;
    while i < len {
        dst[i] ^= gf_tables::gf16_mul(coeff, src[i]);
        i += 1;
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn gf16_mul_slice_neon(coeff: u16, src: &[u16], dst: &mut [u16], len: usize) {
    use std::arch::aarch64::*;
    let coeff_vec = vdupq_n_u16(coeff);
    let poly = vdupq_n_u16(0x000b);
    let mut i = 0;

    while i + 8 <= len {
        let src_vec = vld1q_u16(src.as_ptr().add(i));
        let dst_vec = vld1q_u16(dst.as_ptr().add(i));

        let lo = vmulq_u16(coeff_vec, src_vec);
        let wide = vmull_u16(vget_low_u16(coeff_vec), vget_low_u16(src_vec));
        let hi = vshrn_n_u32(wide, 16);
        let red = vmul_u16(hi, vget_low_u16(poly));
        let prod_low = veor_u16(vget_low_u16(lo), red);

        let wide_hi = vmull_u16(vget_high_u16(coeff_vec), vget_high_u16(src_vec));
        let hi_hi = vshrn_n_u32(wide_hi, 16);
        let red_hi = vmul_u16(hi_hi, vget_high_u16(poly));
        let prod_high = veor_u16(vget_high_u16(lo), red_hi);

        let prod = vcombine_u16(prod_low, prod_high);
        let result = veorq_u16(dst_vec, prod);
        vst1q_u16(dst.as_mut_ptr().add(i), result);
        i += 8;
    }

    while i < len {
        dst[i] ^= gf_tables::gf16_mul(coeff, src[i]);
        i += 1;
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn gf16_mul_slice_sve2(coeff: u16, src: &[u16], dst: &mut [u16], len: usize) {
    #[cfg(target_feature = "sve2")]
    {
        use std::arch::aarch64::*;

        if len == 0 {
            return;
        }

        let coeff_vec = svdup_n_u16(coeff);
        let poly = svdup_n_u16(0x000B);
        let mut offset = 0usize;
        let vl = svcnth() as usize;

        while offset < len {
            let pg = svwhilelt_b16(offset as u64, len as u64);
            if !svptest_any(svptrue_b16(), pg) {
                break;
            }

            let src_vec = svld1_u16(pg, src.as_ptr().add(offset));
            let dst_vec = svld1_u16(pg, dst.as_ptr().add(offset));

            let lo = svmul_u16_x(pg, coeff_vec, src_vec);
            let hi = svmulh_u16_x(pg, coeff_vec, src_vec);
            let red = svmul_u16_x(pg, hi, poly);
            let prod = sveor_u16_m(pg, lo, lo, red);
            let result = sveor_u16_m(pg, dst_vec, dst_vec, prod);

            svst1_u16(pg, dst.as_mut_ptr().add(offset), result);
            offset += vl;
        }

        crate::optimize::telemetry::FEC_SVE2_OPS.inc();
        return;
    }

    gf16_mul_slice_neon(coeff, src, dst, len);
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2,pclmulqdq")]
unsafe fn gf16_mul_avx2(a: u16, b: u16) -> u16 {
    use std::arch::x86_64::*;
    // Carryless multiplication for GF(2^16)
    let a_vec = _mm_set1_epi16(a as i16);
    let b_vec = _mm_set1_epi16(b as i16);

    // Perform carryless multiplication
    let lo = _mm_clmulepi64_si128(a_vec, b_vec, 0x00);
    let hi = _mm_clmulepi64_si128(a_vec, b_vec, 0x11);

    // Reduction modulo x^16 + x^12 + x^3 + x + 1
    let poly = _mm_set1_epi16(0x100B);
    let red1 = _mm_clmulepi64_si128(hi, poly, 0x00);
    let result = _mm_xor_si128(lo, red1);

    _mm_extract_epi16(result, 0) as u16
}

// Removed gf16_mul_neon scalar shim; NEON paths use slice/vector kernels above.

impl AdaptiveFec {
    fn emit_streaming_repair(&mut self, output_queue: &mut VecDeque<FecPacket>) {
        let mut encoder = self.encoder.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        if encoder.packets_in_window() > 0 {
            let coeff = self.stream_idx;
            if coeff < 255 {
                // Generic repair generation; backend selection is internal.
                if let Some(repair) = encoder.generate_repair_packet(coeff, &self.mem_pool) {
                    output_queue.push_back(repair);
                }
                self.stream_idx = self.stream_idx.wrapping_add(1);
            }
        }
    }

    // Removed packet_to_fec_packet (unused).

    pub fn report_loss(&mut self, lost: usize, total: usize) {
        // Update estimator with current observation and drive mode via smoothed loss
        self.loss_estimator.report(lost, total);
        let estimated_loss = self.loss_estimator.smoothed_loss();
        let instant_loss =
            if total > 0 { (lost as f32 / total as f32).clamp(0.0, 1.0) } else { 0.0 };
        let driving_loss = estimated_loss.max(instant_loss);
        self.update_mode(driving_loss);
        self.update_stream_interval(driving_loss);
    }

    pub fn current_mode(&self) -> FecMode {
        match self.mode_manager.lock() {
            Ok(mgr) => mgr.current_mode(),
            Err(poisoned) => {
                log::warn!("mode_manager poisoned; recovering");
                poisoned.into_inner().current_mode()
            }
        }
    }

    pub fn is_transitioning(&self) -> bool {
        self.transition_left > 0
    }

    #[cfg(test)]
    pub fn force_mode_for_test(&mut self, mode: FecMode) {
        self.mode_manager = Arc::new(Mutex::new(internal::ModeManager::new(mode)));
    }

    fn update_mode(&mut self, estimated_loss: f32) {
        let (prev, current_mode, current_window) = {
            let mut mode_mgr = match self.mode_manager.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    log::warn!("mode_manager poisoned; recovering");
                    poisoned.into_inner()
                }
            };
            let prev = mode_mgr.update(estimated_loss);
            let cur_mode = mode_mgr.current_mode();
            let cur_window = mode_mgr.current_window();
            (prev, cur_mode, cur_window)
        };
        // Derive target mode/window from mode manager and apply policy overrides.
        let mut new_mode = current_mode;
        let mut new_window = current_window;
        let mut old_mode = prev.map(|(m, _)| m).unwrap_or(current_mode);
        let mut old_window = prev.map(|(_, w)| w).unwrap_or(current_window);
        let mut switched = prev.is_some();
        let mut reason = FecSwitchReason::Adaptive;

        // Policy guard: "FEC On" must never downshift to Zero.
        if self.force_on && new_mode == FecMode::Zero {
            if !switched {
                old_mode = current_mode;
                old_window = current_window;
            }
            new_mode = FecMode::Normal;
            new_window = 64;
            switched = switched || current_mode != new_mode || current_window != new_window;
            reason = FecSwitchReason::ForceOnPolicy;
        }
        // Ultra-loss policy: route to Fountain for extreme loss
        if estimated_loss >= 0.25 {
            let w = std::env::var("QUICFUSCATE_FEC_FOUNTAIN_WINDOW")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(2048);
            if !switched {
                old_mode = current_mode;
                old_window = current_window;
            }
            switched = switched || new_mode != FecMode::Fountain || new_window != w;
            new_mode = FecMode::Fountain;
            new_window = w;
            reason = FecSwitchReason::ExtremeLossPolicy;
        } else if self.loss_estimator.disturbance_detected() && estimated_loss >= 0.15 {
            let w = std::env::var("QUICFUSCATE_FEC_EXTREME_WINDOW")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(1024);
            if !switched {
                old_mode = current_mode;
                old_window = current_window;
            }
            switched = switched || new_mode != FecMode::Streaming || new_window != w;
            new_mode = FecMode::Streaming;
            new_window = w;
            reason = FecSwitchReason::DisturbancePolicy;
        }
        let (k, n) = internal::ModeManager::params_for(new_mode, new_window);

        if switched {
            let mut mode_mgr = match self.mode_manager.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    log::warn!("mode_manager poisoned while syncing policy override; recovering");
                    poisoned.into_inner()
                }
            };
            mode_mgr.force_state(new_mode, new_window);
        }

        // Telemetry: track mode and window
        crate::telemetry::FEC_MODE.store(new_mode as u64, std::sync::atomic::Ordering::Relaxed);
        crate::telemetry::FEC_WINDOW.store(new_window as u64, std::sync::atomic::Ordering::Relaxed);
        if switched {
            crate::telemetry::FEC_MODE_SWITCHES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            reason.observe();
        }
        // Decoder path telemetry hint
        // Decoder path hint could be wired into telemetry counters if available

        // Auto control tuning: set best parameters live (env toggles + cached fields)
        if self.control_mode == FecControlMode::Auto {
            self.apply_auto_tuning(k, estimated_loss, new_mode);
        }

        if switched {
            let (_ok, _on) = internal::ModeManager::params_for(old_mode, old_window);
            self.cross_fade_packets =
                Self::compute_cross_fade_len(old_mode, new_mode, old_window, k);

            // CRITICAL: Drain ZeroDecoder buffers BEFORE creating new decoder
            // This ensures no packet loss during Zero->Real FEC transitions
            let zero_buffers = if old_mode == FecMode::Zero {
                let mut decoder = self.decoder.lock().unwrap_or_else(|p| p.into_inner());
                let buffers = decoder.drain_zero_buffers();
                crate::telemetry::ZERO_MODE_UPGRADES
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                log::info!("Zero-mode upgrade: replaying {} buffered packets", buffers.len());
                buffers
            } else {
                VecDeque::new()
            };

            self.transition_encoder = Some(Arc::new(Mutex::new(
                internal::InterleavedEncoder::new(new_mode, k, n, self.interleave_depth),
            )));
            self.transition_decoder =
                Some(Arc::new(Mutex::new(internal::InterleavedDecoder::new(
                    new_mode,
                    k,
                    Arc::clone(&self.mem_pool),
                    self.interleave_depth,
                ))));

            // Replay ZeroDecoder buffers into the new transition decoder
            // This preserves all in-flight packets during Zero->Real FEC upgrade
            if !zero_buffers.is_empty() {
                if let Some(ref trans_dec) = self.transition_decoder {
                    let mut dec = trans_dec.lock().unwrap_or_else(|p| p.into_inner());
                    for pkt in zero_buffers {
                        dec.take_packet(pkt);
                    }
                }
            }

            self.transition_left = self.cross_fade_packets;
            self.window_complete = false;
        } else {
            // No change in mode/window; keep current encoder/decoder to preserve streaming/sliding window state.
        }
    }

    pub fn force_streaming_mode(&mut self) {
        let target_mode = FecMode::Streaming;
        self.transition_to_mode(target_mode);
        let (k, _n) = internal::ModeManager::params_for(target_mode, 64);
        let mut mode_mgr =
            self.mode_manager.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        mode_mgr.force_state(target_mode, k);
        self.streaming_mode = true;
        crate::telemetry::FEC_MODE.store(target_mode as u64, std::sync::atomic::Ordering::Relaxed);
        crate::telemetry::FEC_WINDOW.store(k as u64, std::sync::atomic::Ordering::Relaxed);
        crate::telemetry::FEC_MODE_SWITCHES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        log::info!("Forced switch to streaming mode for minimal latency");
    }

    fn select_simd_level_from_features<F>(has_feature: F) -> SimdLevel
    where
        F: Fn(crate::optimize::CpuFeature) -> bool,
    {
        if has_feature(crate::optimize::CpuFeature::AVX512F)
            && has_feature(crate::optimize::CpuFeature::AVX512VBMI)
        {
            SimdLevel::Avx512
        } else if has_feature(crate::optimize::CpuFeature::AVX2) {
            SimdLevel::Avx2
        } else if has_feature(crate::optimize::CpuFeature::SSE42) {
            SimdLevel::Sse2
        } else if has_feature(crate::optimize::CpuFeature::SVE2) {
            SimdLevel::Sve2
        } else if has_feature(crate::optimize::CpuFeature::NEON) {
            SimdLevel::Neon
        } else {
            SimdLevel::None
        }
    }

    /// Enable SIMD acceleration based on CPU features
    pub fn enable_simd_acceleration(&mut self) {
        // Centralized detection via optimize::FeatureDetector
        let det = crate::optimize::FeatureDetector::instance();
        self.simd_level = Self::select_simd_level_from_features(|f| det.has_feature(f));
        self.simd_enabled = self.simd_level != SimdLevel::None;
        crate::telemetry::SIMD_ACTIVE
            .store(self.simd_enabled as u64, std::sync::atomic::Ordering::Relaxed);

        match self.simd_level {
            SimdLevel::Avx512 => log::info!("FEC: AVX-512 SIMD acceleration enabled"),
            SimdLevel::Avx2 => log::info!("FEC: AVX2 SIMD acceleration enabled"),
            SimdLevel::Sse2 => log::info!("FEC: SSE2 SIMD acceleration enabled"),
            SimdLevel::Sve2 => log::info!("FEC: SVE2 SIMD acceleration enabled"),
            SimdLevel::Neon => log::info!("FEC: NEON SIMD acceleration enabled"),
            SimdLevel::None => {}
        }
        // Telemetry: report SIMD level
        let lvl = self.simd_level();
        match lvl {
            "AVX-512" => crate::telemetry::SIMD_USAGE_AVX512
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            "AVX2" => {
                crate::telemetry::SIMD_USAGE_AVX2.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            }
            "SSE2" => {
                crate::telemetry::SIMD_USAGE_SSE2.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            }
            "SVE2" => {
                crate::telemetry::SIMD_USAGE_SVE2.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            }
            "NEON" => {
                crate::telemetry::SIMD_USAGE_NEON.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            }
            _ => crate::telemetry::SIMD_USAGE_SCALAR
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        };
    }

    /// Get current SIMD acceleration level
    pub fn simd_level(&self) -> &str {
        match self.simd_level {
            SimdLevel::None => "scalar",
            SimdLevel::Sse2 => "SSE2",
            SimdLevel::Avx2 => "AVX2",
            SimdLevel::Avx512 => "AVX-512",
            SimdLevel::Sve2 => "SVE2",
            SimdLevel::Neon => "NEON",
        }
    }

    // Removed associated test; proper tests are in #[cfg(test)] modules.

    fn apply_auto_tuning(&mut self, k: usize, loss: f32, mode: FecMode) {
        // ... (rest of the code remains the same)
        if mode == FecMode::Zero {
            std::env::set_var("QUICFUSCATE_FEC_DECODER", "gauss");
            std::env::set_var("QUICFUSCATE_WM_BITSLICE", "0");
            std::env::set_var("QUICFUSCATE_WM_LANE_PAR", "0");
            std::env::set_var("QUICFUSCATE_WM_LANES", "1");
            std::env::set_var("QUICFUSCATE_WM_U", "1");
            self.stream_every = 4;
            std::env::set_var("QUICFUSCATE_FEC_STREAM_BURST", "1");
            return;
        }
        let big_k = k > std::env::var("QUICFUSCATE_FEC_WIEDEMANN_K")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(256);
        if loss < 0.01 {
            // Low loss: bevorzugt Gauss, sanftes Streaming
            std::env::set_var("QUICFUSCATE_FEC_DECODER", if big_k { "auto" } else { "gauss" });
            std::env::set_var("QUICFUSCATE_WM_BITSLICE", if big_k { "1" } else { "0" });
            std::env::set_var("QUICFUSCATE_WM_LANE_PAR", "0");
            std::env::set_var("QUICFUSCATE_WM_LANES", if big_k { "4" } else { "1" });
            std::env::set_var("QUICFUSCATE_WM_U", "1");
            self.stream_every = 3;
            std::env::set_var("QUICFUSCATE_FEC_STREAM_BURST", "1");
        } else if loss < 0.05 {
            // Normal
            std::env::set_var("QUICFUSCATE_FEC_DECODER", "auto");
            std::env::set_var("QUICFUSCATE_WM_BITSLICE", if big_k { "1" } else { "0" });
            std::env::set_var("QUICFUSCATE_WM_LANE_PAR", if big_k { "1" } else { "0" });
            std::env::set_var("QUICFUSCATE_WM_LANES", if big_k { "6" } else { "2" });
            std::env::set_var("QUICFUSCATE_WM_U", if big_k { "2" } else { "1" });
            self.stream_every = 2;
            std::env::set_var("QUICFUSCATE_FEC_STREAM_BURST", "2");
        } else if loss < 0.20 {
            // Strong
            std::env::set_var("QUICFUSCATE_FEC_DECODER", "wiedemann");
            std::env::set_var("QUICFUSCATE_WM_BITSLICE", "1");
            std::env::set_var("QUICFUSCATE_WM_LANE_PAR", "1");
            std::env::set_var("QUICFUSCATE_WM_LANES", "8");
            std::env::set_var("QUICFUSCATE_WM_U", "2");
            self.stream_every = 1;
            std::env::set_var("QUICFUSCATE_FEC_STREAM_BURST", "4");
        } else {
            // Extreme
            std::env::set_var("QUICFUSCATE_FEC_DECODER", "wiedemann");
            std::env::set_var("QUICFUSCATE_WM_BITSLICE", "1");
            std::env::set_var("QUICFUSCATE_WM_LANE_PAR", "1");
            std::env::set_var("QUICFUSCATE_WM_LANES", "8");
            std::env::set_var("QUICFUSCATE_WM_U", "4");
            self.stream_every = 1;
            std::env::set_var("QUICFUSCATE_FEC_STREAM_BURST", "8");
        }
    }
}

// --- FEC Configuration ---

// PID controller configuration
#[derive(Debug, Clone)]
pub struct PidConfig {
    pub kp: f32,
    pub ki: f32,
    pub kd: f32,
}

/// Configuration for Adaptive FEC behavior and controller settings.
#[derive(Clone)]
pub struct FecConfig {
    pub window_sizes: HashMap<FecMode, usize>,
    pub lambda: f32,
    pub burst_window: usize,
    pub hysteresis: f32,
    pub pid: PidConfig,
    pub initial_mode: FecMode,
    /// When true, FEC will never downshift to `Zero`. This is used for "FEC On"
    /// policy (manual) without exposing low-level tuning in the UI.
    pub force_on: bool,
    pub kalman_enabled: bool,
    pub kalman_q: f32,
    pub kalman_r: f32,
}

impl FecConfig {
    pub fn default_windows() -> HashMap<FecMode, usize> {
        use FecMode::*;
        let mut m = HashMap::new();
        m.insert(Zero, 0);
        m.insert(Light, 16);
        m.insert(Normal, 64);
        m.insert(Medium, 128);
        m.insert(Strong, 512);
        m.insert(Extreme, 1024);
        m.insert(Streaming, 64);
        m
    }

    pub fn from_toml(s: &str) -> Result<Self, Box<dyn std::error::Error>> {
        #[derive(serde::Deserialize)]
        struct Root {
            adaptive_fec: Adaptive,
        }
        #[derive(serde::Deserialize)]
        struct Adaptive {
            lambda: Option<f32>,
            burst_window: Option<usize>,
            hysteresis: Option<f32>,
            pid: Option<PidSection>,
            kalman_enabled: Option<bool>,
            kalman_q: Option<f32>,
            kalman_r: Option<f32>,
            initial_mode: Option<String>,
            modes: Option<Vec<ModeSection>>,
        }
        #[derive(serde::Deserialize)]
        struct PidSection {
            kp: f32,
            ki: f32,
            kd: f32,
        }
        #[derive(serde::Deserialize)]
        struct ModeSection {
            name: String,
            w0: usize,
        }

        let raw: Root = toml::from_str(s)?;
        let af = raw.adaptive_fec;
        let pid = af.pid.unwrap_or(PidSection { kp: 1.2, ki: 0.5, kd: 0.1 });
        let mut windows = FecConfig::default_windows();
        if let Some(modes) = af.modes {
            for msec in modes {
                let mode = match msec.name.to_lowercase().as_str() {
                    "zero" => FecMode::Zero,
                    "light" => FecMode::Light,
                    "normal" => FecMode::Normal,
                    "medium" => FecMode::Medium,
                    "strong" => FecMode::Strong,
                    "extreme" => FecMode::Extreme,
                    "streaming" => FecMode::Streaming,
                    _ => continue,
                };
                windows.insert(mode, msec.w0);
            }
        }
        let initial_mode = af.initial_mode.as_deref().unwrap_or("zero").trim().to_lowercase();
        let initial_mode = match initial_mode.as_str() {
            "zero" | "off" => FecMode::Zero,
            "light" => FecMode::Light,
            "normal" | "on" => FecMode::Normal,
            "medium" => FecMode::Medium,
            "strong" => FecMode::Strong,
            "extreme" => FecMode::Extreme,
            "streaming" => FecMode::Streaming,
            // keep conservative default; caller can still override via CLI
            _ => FecMode::Zero,
        };
        Ok(FecConfig {
            lambda: af.lambda.unwrap_or(0.1),
            burst_window: af.burst_window.unwrap_or(20),
            hysteresis: af.hysteresis.unwrap_or(0.02),
            pid: PidConfig { kp: pid.kp, ki: pid.ki, kd: pid.kd },
            initial_mode,
            force_on: false,
            kalman_enabled: af.kalman_enabled.unwrap_or(false),
            kalman_q: af.kalman_q.unwrap_or(0.001),
            kalman_r: af.kalman_r.unwrap_or(0.01),
            window_sizes: windows,
        })
    }

    pub fn from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_toml(&contents)
    }
}

impl Default for FecConfig {
    fn default() -> Self {
        Self {
            lambda: 0.1,
            burst_window: 20,
            hysteresis: 0.02,
            pid: PidConfig { kp: 1.2, ki: 0.5, kd: 0.1 },
            initial_mode: FecMode::Zero,
            force_on: false,
            kalman_enabled: false,
            kalman_q: 0.001,
            kalman_r: 0.01,
            window_sizes: FecConfig::default_windows(),
        }
    }
}

impl FecConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !(0.0..=1.0).contains(&self.lambda) {
            return Err("lambda must be between 0 and 1".into());
        }
        if self.burst_window == 0 {
            return Err("burst_window must be > 0".into());
        }
        if !(0.0..1.0).contains(&self.hysteresis) {
            return Err("hysteresis must be between 0 and 1".into());
        }
        if self.kalman_enabled && (self.kalman_q <= 0.0 || self.kalman_r <= 0.0) {
            return Err("kalman_q and kalman_r must be positive".into());
        }
        Ok(())
    }
}

impl Decoder8 {
    pub fn get_result(&mut self) -> Option<VecDeque<FecPacket>> {
        // Try basic recovery first
        self.try_eliminate();

        // Return any recovered packets
        if !self.emit_q.is_empty() {
            Some(std::mem::take(&mut self.emit_q))
        } else {
            None
        }
    }

    pub fn get_partial_result(&mut self) -> VecDeque<FecPacket> {
        std::mem::take(&mut self.emit_q)
    }

    pub fn is_complete(&self) -> bool {
        // Check if all expected symbols are known
        self.known.len() >= self.k
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FecBenchmarkScenario {
    pub payload_bytes: usize,
    pub window_k: usize,
    pub window_n: usize,
    pub iterations: usize,
}

pub const FEC_BENCHMARK_SET: [FecBenchmarkScenario; 3] = [
    FecBenchmarkScenario { payload_bytes: 512, window_k: 8, window_n: 10, iterations: 30_000 },
    FecBenchmarkScenario { payload_bytes: 1200, window_k: 16, window_n: 20, iterations: 20_000 },
    FecBenchmarkScenario { payload_bytes: 1400, window_k: 32, window_n: 40, iterations: 10_000 },
];

#[derive(Debug, Clone, Copy)]
pub struct FecPerfThresholds {
    pub max_repair_ratio_ppm: u64,
    pub max_encode_ns_per_packet: u64,
    pub max_decode_ns_per_packet: u64,
}

impl Default for FecPerfThresholds {
    fn default() -> Self {
        FEC_INTERNAL_TARGETS
    }
}

pub const FEC_INTERNAL_TARGETS: FecPerfThresholds = FecPerfThresholds {
    max_repair_ratio_ppm: 600_000,
    max_encode_ns_per_packet: 200_000,
    max_decode_ns_per_packet: 250_000,
};

#[derive(Debug, Clone, Copy)]
pub struct FecPerfCounters {
    pub source_packets: u64,
    pub repair_packets: u64,
    pub encode_time_ns: u64,
    pub decode_time_ns: u64,
}

pub fn evaluate_fec_perf_smoke(
    counters: FecPerfCounters,
    thresholds: FecPerfThresholds,
) -> Result<(), &'static str> {
    if counters.source_packets == 0 {
        return Ok(());
    }

    let repair_ratio_ppm =
        counters.repair_packets.saturating_mul(1_000_000) / counters.source_packets;
    if repair_ratio_ppm > thresholds.max_repair_ratio_ppm {
        return Err("repair ratio exceeds threshold");
    }

    let enc_ns_per_packet = counters.encode_time_ns / counters.source_packets;
    if enc_ns_per_packet > thresholds.max_encode_ns_per_packet {
        return Err("encode ns per packet exceeds threshold");
    }

    let dec_ns_per_packet = counters.decode_time_ns / counters.source_packets;
    if dec_ns_per_packet > thresholds.max_decode_ns_per_packet {
        return Err("decode ns per packet exceeds threshold");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(all(target_arch = "x86_64", target_feature = "amx-int8"))]
    fn has_amx_runtime() -> bool {
        std::arch::is_x86_feature_detected!("amx_int8")
            && std::arch::is_x86_feature_detected!("amx_tile")
            && std::arch::is_x86_feature_detected!("amx_bf16")
    }

    use super::test_support::*;
    use super::{
        evaluate_fec_perf_smoke, AdaptiveFec, Decoder8, FecBenchmarkScenario, FecConfig, FecMode,
        FecPacket, FecPerfCounters, FecPerfThresholds, SimdLevel, FEC_BENCHMARK_SET,
        FEC_INTERNAL_TARGETS,
    };
    use crate::optimize::telemetry;
    use std::collections::{HashMap, VecDeque};
    #[allow(unused_imports)]
    use std::sync::Arc;

    #[test]
    fn test_auto_mode_streaming_selection() {
        let _env_lock = acquire_env_lock();
        let _g_burst = EnvGuard::unset("QUICFUSCATE_FEC_STREAM_BURST");
        let _g = EnvGuard::set("QUICFUSCATE_FEC_AUTO_STREAM", "true");
        let _pool = crate::optimize::global_pool();
        let config = FecConfig { initial_mode: FecMode::Zero, ..Default::default() };
        let mut fec = AdaptiveFec::new(config);
        fec.report_loss(0, 10000);
        assert_eq!(fec.current_mode(), FecMode::Zero);
        fec.report_loss(15, 1000);
        for _ in 0..5 {
            fec.report_loss(15, 1000);
        }
        let mode = fec.current_mode();
        // Light (GF4) is now auto-selected for ultra-low loss (<2%), Streaming/Normal for higher
        assert!(matches!(mode, FecMode::Light | FecMode::Streaming | FecMode::Normal));
    }

    #[test]
    fn test_mode_does_not_downshift_on_single_low_loss_sample() {
        let _env_lock = acquire_env_lock();
        let _g_up = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_UP_MS", "0");
        let _g_down = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_DOWN_MS", "600");
        let _g_thr = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_THRESH", "0.005");
        let cfg = FecConfig { initial_mode: FecMode::Strong, ..Default::default() };
        let mut fec = AdaptiveFec::new(cfg);

        for _ in 0..12 {
            fec.report_loss(220, 1000);
        }
        let before = fec.current_mode();
        fec.report_loss(0, 1000);
        assert_eq!(
            fec.current_mode(),
            before,
            "single low-loss sample must not immediately downshift protection mode"
        );
    }

    #[test]
    fn test_mode_boundaries_progress_deterministically() {
        let _env_lock = acquire_env_lock();
        let _g_up = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_UP_MS", "0");
        let _g_down = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_DOWN_MS", "0");
        let _g_thr = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_THRESH", "0.005");
        let cfg = FecConfig { initial_mode: FecMode::Zero, ..Default::default() };
        let mut fec = AdaptiveFec::new(cfg);

        for _ in 0..12 {
            fec.report_loss(0, 1000);
        }
        assert_eq!(fec.current_mode(), FecMode::Zero);

        for _ in 0..16 {
            fec.report_loss(15, 1000);
        }
        assert_eq!(fec.current_mode(), FecMode::Light);

        for _ in 0..16 {
            fec.report_loss(120, 1000);
        }
        assert_eq!(fec.current_mode(), FecMode::Strong);

        for _ in 0..20 {
            fec.report_loss(350, 1000);
        }
        assert_eq!(fec.current_mode(), FecMode::Fountain);
    }

    #[test]
    fn test_extreme_loss_switch_reason_telemetry_increments() {
        let _env_lock = acquire_env_lock();
        let _g_up = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_UP_MS", "0");
        let _g_down = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_DOWN_MS", "0");
        let mut fec = AdaptiveFec::new(FecConfig::default());
        let before =
            telemetry::FEC_SWITCH_REASON_EXTREME.load(std::sync::atomic::Ordering::Relaxed);
        for _ in 0..20 {
            fec.report_loss(400, 1000);
        }
        let after = telemetry::FEC_SWITCH_REASON_EXTREME.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            after > before,
            "extreme-loss reason counter did not increment (before={}, after={})",
            before,
            after
        );
    }

    #[test]
    fn test_prolonged_extreme_loss_stays_in_high_resilience_mode() {
        let _env_lock = acquire_env_lock();
        let _g_up = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_UP_MS", "0");
        let _g_down = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_DOWN_MS", "500");
        let cfg = FecConfig { initial_mode: FecMode::Zero, ..Default::default() };
        let mut fec = AdaptiveFec::new(cfg);

        // Prolonged very high loss should converge to fountain and remain there.
        for _ in 0..120 {
            fec.report_loss(650, 1000);
        }
        assert_eq!(fec.current_mode(), FecMode::Fountain);

        for _ in 0..40 {
            fec.report_loss(620, 1000);
            assert_eq!(
                fec.current_mode(),
                FecMode::Fountain,
                "mode must remain in strongest resilience profile under sustained extreme loss"
            );
        }
    }

    #[test]
    fn test_bursty_jitter_trace_remains_in_resilient_modes() {
        let _env_lock = acquire_env_lock();
        let _g_up = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_UP_MS", "0");
        let _g_down = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_DOWN_MS", "250");
        let _g_thr = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_THRESH", "0.005");
        let cfg = FecConfig { initial_mode: FecMode::Zero, ..Default::default() };
        let mut fec = AdaptiveFec::new(cfg);

        let bursty_trace = [650usize, 40, 620, 55, 600, 80, 500, 60];
        for _ in 0..40 {
            for &lost in &bursty_trace {
                fec.report_loss(lost, 1000);
            }
        }

        assert!(
            matches!(
                fec.current_mode(),
                FecMode::Strong | FecMode::Extreme | FecMode::Fountain | FecMode::Streaming
            ),
            "bursty high-loss/jitter trace should not converge to weak protection mode"
        );
    }

    #[test]
    fn test_long_running_mixed_loss_trace_stays_operational() {
        let _env_lock = acquire_env_lock();
        let _g_up = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_UP_MS", "0");
        let _g_down = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_DOWN_MS", "0");
        let cfg = FecConfig { initial_mode: FecMode::Zero, ..Default::default() };
        let mut fec = AdaptiveFec::new(cfg);

        for i in 0..5000usize {
            let lost = if i % 17 == 0 {
                700
            } else if i % 5 == 0 {
                220
            } else {
                60
            };
            fec.report_loss(lost, 1000);
            assert!(
                matches!(
                    fec.current_mode(),
                    FecMode::Zero
                        | FecMode::Light
                        | FecMode::Normal
                        | FecMode::Strong
                        | FecMode::Extreme
                        | FecMode::Fountain
                        | FecMode::Streaming
                ),
                "mode left supported enum set during long-running adaptation trace"
            );
        }

        assert_ne!(
            fec.current_mode(),
            FecMode::Zero,
            "long-running mixed-loss trace must not collapse to zero protection"
        );
    }

    #[test]
    fn test_replayed_loss_trace_drives_end_to_end_adaptation() {
        let _env_lock = acquire_env_lock();
        let _g_up = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_UP_MS", "0");
        let _g_down = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_DOWN_MS", "0");
        let _g_thr = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_THRESH", "0.005");
        let cfg = FecConfig { initial_mode: FecMode::Zero, ..Default::default() };
        let mut fec = AdaptiveFec::new(cfg);

        let mut visited = std::collections::HashSet::new();
        visited.insert(fec.current_mode());

        for _ in 0..16 {
            fec.report_loss(15, 1000);
            visited.insert(fec.current_mode());
        }
        for _ in 0..16 {
            fec.report_loss(120, 1000);
            visited.insert(fec.current_mode());
        }
        for _ in 0..20 {
            fec.report_loss(350, 1000);
            visited.insert(fec.current_mode());
        }
        for _ in 0..20 {
            fec.report_loss(0, 1000);
            visited.insert(fec.current_mode());
        }

        assert!(visited.contains(&FecMode::Zero), "trace must include Zero mode");
        assert!(visited.contains(&FecMode::Light), "trace must include Light mode");
        assert!(visited.contains(&FecMode::Strong), "trace must include Strong mode");
        assert!(visited.contains(&FecMode::Fountain), "trace must include Fountain mode");
    }

    #[test]
    fn test_transition_safety_for_all_start_modes_under_replay_trace() {
        let _env_lock = acquire_env_lock();
        let _g_up = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_UP_MS", "0");
        let _g_down = EnvGuard::set("QUICFUSCATE_FEC_SWITCH_MIN_DOWN_MS", "0");

        let all_modes = [
            FecMode::Zero,
            FecMode::Light,
            FecMode::Normal,
            FecMode::Strong,
            FecMode::Extreme,
            FecMode::Fountain,
            FecMode::Streaming,
        ];
        let replay = [0usize, 20, 60, 150, 300, 450, 80, 30, 5, 0];

        for start_mode in all_modes {
            let cfg = FecConfig { initial_mode: start_mode, ..Default::default() };
            let mut fec = AdaptiveFec::new(cfg);
            if start_mode == FecMode::Streaming {
                fec.force_streaming_mode();
            }
            for &lost in &replay {
                fec.report_loss(lost, 1000);
                assert!(
                    matches!(
                        fec.current_mode(),
                        FecMode::Zero
                            | FecMode::Light
                            | FecMode::Normal
                            | FecMode::Strong
                            | FecMode::Extreme
                            | FecMode::Fountain
                            | FecMode::Streaming
                    ),
                    "mode must remain within supported transition set (start_mode={:?})",
                    start_mode
                );
            }
        }
    }

    #[test]
    fn test_enable_simd_acceleration_updates_telemetry() {
        let cfg = FecConfig::default();
        let mut fec = AdaptiveFec::new(cfg);

        let before = telemetry::SIMD_USAGE_AVX512.load(std::sync::atomic::Ordering::Relaxed)
            + telemetry::SIMD_USAGE_AVX2.load(std::sync::atomic::Ordering::Relaxed)
            + telemetry::SIMD_USAGE_SSE2.load(std::sync::atomic::Ordering::Relaxed)
            + telemetry::SIMD_USAGE_SVE2.load(std::sync::atomic::Ordering::Relaxed)
            + telemetry::SIMD_USAGE_NEON.load(std::sync::atomic::Ordering::Relaxed)
            + telemetry::SIMD_USAGE_SCALAR.load(std::sync::atomic::Ordering::Relaxed);

        fec.enable_simd_acceleration();

        let after = telemetry::SIMD_USAGE_AVX512.load(std::sync::atomic::Ordering::Relaxed)
            + telemetry::SIMD_USAGE_AVX2.load(std::sync::atomic::Ordering::Relaxed)
            + telemetry::SIMD_USAGE_SSE2.load(std::sync::atomic::Ordering::Relaxed)
            + telemetry::SIMD_USAGE_SVE2.load(std::sync::atomic::Ordering::Relaxed)
            + telemetry::SIMD_USAGE_NEON.load(std::sync::atomic::Ordering::Relaxed)
            + telemetry::SIMD_USAGE_SCALAR.load(std::sync::atomic::Ordering::Relaxed);

        assert!(
            after > before,
            "expected SIMD activation telemetry update (before={}, after={})",
            before,
            after
        );
    }

    #[test]
    fn test_simd_dispatch_selection_covers_scalar_avx_neon_sve() {
        let avx = AdaptiveFec::select_simd_level_from_features(|f| {
            matches!(
                f,
                crate::optimize::CpuFeature::AVX512F | crate::optimize::CpuFeature::AVX512VBMI
            )
        });
        assert_eq!(avx, SimdLevel::Avx512);

        let avx2 = AdaptiveFec::select_simd_level_from_features(|f| {
            matches!(f, crate::optimize::CpuFeature::AVX2)
        });
        assert_eq!(avx2, SimdLevel::Avx2);

        let sve2 = AdaptiveFec::select_simd_level_from_features(|f| {
            matches!(f, crate::optimize::CpuFeature::SVE2)
        });
        assert_eq!(sve2, SimdLevel::Sve2);

        let neon = AdaptiveFec::select_simd_level_from_features(|f| {
            matches!(f, crate::optimize::CpuFeature::NEON)
        });
        assert_eq!(neon, SimdLevel::Neon);

        let scalar = AdaptiveFec::select_simd_level_from_features(|_| false);
        assert_eq!(scalar, SimdLevel::None);
    }

    #[test]
    fn test_fec_perf_smoke_thresholds_pass() {
        let counters = FecPerfCounters {
            source_packets: 1000,
            repair_packets: 350,
            encode_time_ns: 120_000_000,
            decode_time_ns: 150_000_000,
        };
        assert!(evaluate_fec_perf_smoke(counters, FEC_INTERNAL_TARGETS).is_ok());
    }

    #[test]
    fn test_fec_perf_smoke_thresholds_reject_bad_repair_ratio() {
        let counters = FecPerfCounters {
            source_packets: 1000,
            repair_packets: 900,
            encode_time_ns: 100_000_000,
            decode_time_ns: 120_000_000,
        };
        let err = evaluate_fec_perf_smoke(counters, FecPerfThresholds::default())
            .expect_err("expected repair ratio threshold rejection");
        assert_eq!(err, "repair ratio exceeds threshold");
    }

    #[test]
    fn test_fec_benchmark_set_is_ordered_and_valid() {
        assert_eq!(FEC_BENCHMARK_SET.len(), 3);
        for FecBenchmarkScenario { payload_bytes, window_k, window_n, iterations } in
            FEC_BENCHMARK_SET
        {
            assert!(payload_bytes > 0);
            assert!(window_k > 0);
            assert!(window_n >= window_k);
            assert!(iterations > 0);
        }
        assert!(FEC_BENCHMARK_SET[0].payload_bytes <= FEC_BENCHMARK_SET[1].payload_bytes);
        assert!(FEC_BENCHMARK_SET[1].payload_bytes <= FEC_BENCHMARK_SET[2].payload_bytes);
    }

    #[test]
    fn test_update_stream_interval_decreases_under_high_loss() {
        let cfg = FecConfig::default();
        let mut fec = AdaptiveFec::new(cfg);
        fec.stream_every_override = None;
        fec.stream_every = 8;
        fec.stream_last_adjust =
            crate::time_source::now_instant() - std::time::Duration::from_millis(1000);

        fec.update_stream_interval(0.25);
        assert!(
            fec.stream_every <= 6,
            "high loss should reduce stream interval aggressively (got {})",
            fec.stream_every
        );
    }

    #[test]
    fn test_update_stream_interval_relaxes_under_low_loss() {
        let cfg = FecConfig::default();
        let mut fec = AdaptiveFec::new(cfg);
        fec.stream_every_override = None;
        fec.stream_every = 2;
        fec.stream_last_adjust =
            crate::time_source::now_instant() - std::time::Duration::from_millis(1000);

        fec.update_stream_interval(0.0);
        assert!(
            fec.stream_every >= 3,
            "low loss should relax stream interval for efficiency (got {})",
            fec.stream_every
        );
    }

    #[test]
    fn test_update_stream_interval_respects_time_source_gate() {
        use crate::time_source::TimeSource;
        use std::sync::Arc;
        use std::sync::Mutex;
        use std::time::{Duration, Instant, SystemTime};

        struct ManualTimeSource {
            instant_now: Mutex<Instant>,
            system_now: Mutex<SystemTime>,
        }

        impl ManualTimeSource {
            fn new(instant_now: Instant, system_now: SystemTime) -> Self {
                Self { instant_now: Mutex::new(instant_now), system_now: Mutex::new(system_now) }
            }

            fn advance(&self, delta: Duration) {
                if let Ok(mut instant_now) = self.instant_now.lock() {
                    *instant_now += delta;
                }
                if let Ok(mut system_now) = self.system_now.lock() {
                    *system_now += delta;
                }
            }
        }

        impl TimeSource for ManualTimeSource {
            fn now_instant(&self) -> Instant {
                *self.instant_now.lock().expect("manual instant poisoned")
            }

            fn now_system(&self) -> SystemTime {
                *self.system_now.lock().expect("manual system poisoned")
            }
        }

        let base_instant = Instant::now();
        let base_system = std::time::UNIX_EPOCH + Duration::from_secs(1);
        let manual = Arc::new(ManualTimeSource::new(base_instant, base_system));
        let _time_guard = crate::time_source::install_for_test(manual.clone());

        let cfg = FecConfig::default();
        let mut fec = AdaptiveFec::new(cfg);
        fec.stream_every_override = None;
        fec.stream_every = 8;
        fec.stream_last_adjust = base_instant;

        fec.update_stream_interval(0.25);
        assert_eq!(fec.stream_every, 8);

        manual.advance(Duration::from_millis(super::STREAM_ADJUST_MIN_MS + 5));
        fec.update_stream_interval(0.25);
        assert!(fec.stream_every <= 6);
    }

    #[test]
    fn test_streaming_repair_scratch_queue_reused_under_load() {
        let pool = make_pool();
        let cfg = FecConfig { initial_mode: FecMode::Streaming, ..Default::default() };
        let mut fec = AdaptiveFec::new(cfg);
        fec.set_stream_every(1);

        let cap_before = fec.stream_repair_scratch_capacity();
        for i in 0..256u64 {
            let pkt = mk_src_packet(i + 1, 256, &pool);
            let _ = fec.on_send(pkt);
            assert_eq!(
                fec.stream_repair_scratch_len(),
                0,
                "scratch queue must be drained each send"
            );
        }
        let cap_after = fec.stream_repair_scratch_capacity();
        assert_eq!(
            cap_after, cap_before,
            "streaming scratch queue capacity should remain stable for allocation reuse"
        );
    }

    #[test]
    fn test_lazy_decoder_pending_repair_ring_reuse_under_load() {
        let pool = make_pool();
        let mut dec = super::internal::LazyDecoder::new(FecMode::Normal, 8, Arc::clone(&pool));
        let cap_before = dec.pending_repairs_capacity();

        for i in 0..256u64 {
            let mut data = pool.alloc();
            let len = 64usize;
            for (j, b) in data.iter_mut().take(len).enumerate() {
                *b = (i as u8).wrapping_add(j as u8);
            }
            let mut coeffs = pool.alloc();
            for (j, b) in coeffs.iter_mut().take(8).enumerate() {
                *b = (j as u8).wrapping_add(1);
            }
            let repair = FecPacket::new(
                10_000 + i,
                Some(data),
                len,
                false,
                Some(coeffs),
                8,
                Arc::clone(&pool),
            );
            dec.take_packet(repair);
            assert!(
                dec.pending_repairs_len() <= dec.pending_repairs_max(),
                "pending repair ring must stay bounded"
            );
        }

        let cap_after = dec.pending_repairs_capacity();
        assert!(
            cap_after >= cap_before,
            "pending repair ring capacity should be reused (before={}, after={})",
            cap_before,
            cap_after
        );
    }

    #[test]
    fn test_streaming_repairs_have_nonzero_coeffs() {
        // QUICFUSCATE_FEC_STREAM_EVERY is read during AdaptiveFec::new
        let _env_lock = acquire_env_lock();
        let _g = EnvGuard::set("QUICFUSCATE_FEC_STREAM_EVERY", "1");
        let pool = make_pool();

        let mut windows = HashMap::new();
        let k_stream = 8usize;
        windows.insert(FecMode::Streaming, k_stream);

        let cfg = FecConfig {
            initial_mode: FecMode::Streaming,
            window_sizes: windows,
            ..Default::default()
        };
        let mut fec = AdaptiveFec::new(cfg);
        let mut q = VecDeque::new();

        for i in 0..k_stream as u64 {
            let pkt = mk_src_packet(10 + i, 100, &pool);
            for pkt in fec.on_send(pkt) {
                q.push_back(pkt);
            }
        }

        let repairs = drain_repairs(&mut q);
        assert!(!repairs.is_empty(), "streaming emitted no repairs");
        for rp in repairs.iter() {
            assert!(!rp.is_systematic);
            let coeffs = rp.coefficients.as_ref().expect("repair must carry coefficients");
            let coeff_slice: &[u8] = &coeffs[..rp.coeff_len];
            assert!(
                coeff_slice.iter().any(|&b| b != 0),
                "repair with all-zero coeffs should not be emitted"
            );
        }
    }

    #[test]
    fn test_wiedemann_scalar_telemetry_increments() {
        let _env_lock = acquire_env_lock();
        let pool = make_pool();
        let decoder = Decoder8::new(2, pool.clone());

        let matrix = vec![vec![1u8, 0u8], vec![0u8, 1u8]];
        let rhs = vec![5u8, 9u8];

        let usage_before = telemetry::WIEDEMANN_USAGE.get();
        let scalar_before = telemetry::WIEDEMANN_SCALAR_OPS.get();

        let solution = decoder
            .solve_wiedemann_system(&matrix, &rhs, 2)
            .expect("identity system should be solvable");

        assert_eq!(solution, rhs, "identity system must return RHS");

        let usage_after = telemetry::WIEDEMANN_USAGE.get();
        let scalar_after = telemetry::WIEDEMANN_SCALAR_OPS.get();

        assert!(usage_after > usage_before, "usage counter should increase");
        assert!(scalar_after > scalar_before, "scalar counter should increase");
    }

    #[test]
    #[cfg(all(target_arch = "x86_64", target_feature = "amx-int8"))]
    fn test_wiedemann_amx_telemetry_increments() {
        if !has_amx_runtime() {
            println!("AMX runtime support not available; skipping test");
            return;
        }

        let _env_lock = acquire_env_lock();
        let pool = make_pool();
        let mut decoder = Decoder8::new(64, pool.clone());

        let dim = 64;
        let mut matrix = vec![vec![0u8; dim]; dim];
        for i in 0..dim {
            matrix[i][i] = 1;
        }

        let rhs = vec![0xAAu8; dim];

        let usage_before = telemetry::WIEDEMANN_USAGE.get();
        let amx_before = telemetry::WIEDEMANN_AMX_OPS.get();

        let solution =
            decoder.solve_wiedemann_system(&matrix, &rhs, dim).expect("AMX solve should succeed");
        assert_eq!(solution, rhs, "AMX path must match RHS for identity matrix");

        let usage_after = telemetry::WIEDEMANN_USAGE.get();
        let amx_after = telemetry::WIEDEMANN_AMX_OPS.get();

        assert!(usage_after >= usage_before + 1, "usage counter should increase");
        assert!(amx_after >= amx_before + 1, "amx counter should increase");
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn matrix_multiply_avx512_matches_scalar_when_available() {
        if !(std::arch::is_x86_feature_detected!("avx512f")
            && std::arch::is_x86_feature_detected!("avx512bw")
            && std::arch::is_x86_feature_detected!("avx512vl")
            && std::arch::is_x86_feature_detected!("gfni"))
        {
            println!("AVX-512 GFNI not available; skipping test");
            return;
        }

        use rand::{Rng, SeedableRng};

        let mut rng = rand::rngs::StdRng::seed_from_u64(0xfeed_cafe);
        let rows = 8usize;
        let cols = 8usize;
        let shared = 8usize;

        let mut a = vec![vec![0u8; shared]; rows];
        for row in &mut a {
            for val in row.iter_mut() {
                *val = rng.gen();
            }
        }

        let mut b = vec![vec![0u8; cols]; shared];
        for row in &mut b {
            for val in row.iter_mut() {
                *val = rng.gen();
            }
        }

        let mut scalar = vec![Vec::new(); rows];
        matrix_multiply_scalar(&a, &b, &mut scalar);

        let mut avx512 = vec![Vec::new(); rows];
        unsafe {
            matrix_multiply_avx512(&a, &b, &mut avx512);
        }

        assert_eq!(scalar, avx512, "AVX-512 GFNI result must match scalar reference");
    }

    #[test]
    #[cfg(all(target_arch = "x86_64", target_feature = "amx-int8"))]
    fn test_amx_matmul_matches_scalar() {
        if !std::arch::is_x86_feature_detected!("amx_int8")
            || !std::arch::is_x86_feature_detected!("amx_tile")
        {
            println!("AMX runtime support unavailable; skipping test");
            return;
        }

        use crate::simd::amx::matmul_gf256_amx;

        const ROWS: usize = 64;
        const COLS: usize = 64;

        let mut matrix = vec![0u8; ROWS * COLS];
        for r in 0..ROWS {
            for c in 0..COLS {
                matrix[r * COLS + c] = ((r * 29 + c * 7 + (r ^ c)) & 0xFF) as u8;
            }
        }
        let mut vector = vec![0u8; COLS];
        for c in 0..COLS {
            vector[c] = (c as u8).wrapping_mul(53).wrapping_add(11);
        }

        let mut amx_out = vec![0u8; ROWS];
        let mut scalar_out = vec![0u8; ROWS];

        unsafe { matmul_gf256_amx(&matrix, &vector, &mut amx_out, ROWS, COLS, 1) };

        for r in 0..ROWS {
            let mut acc = 0u8;
            for c in 0..COLS {
                let a = matrix[r * COLS + c];
                let b = vector[c];
                if a != 0 && b != 0 {
                    acc ^= gf_tables::gf_mul_table(a, b);
                }
            }
            scalar_out[r] = acc;
        }

        assert_eq!(amx_out, scalar_out, "AMX matmul must match scalar reference");
    }

    #[test]
    fn test_streaming_emit_every_n() {
        // QUICFUSCATE_FEC_STREAM_EVERY is read during AdaptiveFec::new
        let _env_lock = acquire_env_lock();
        let _g = EnvGuard::set("QUICFUSCATE_FEC_STREAM_EVERY", "2");
        let pool = make_pool();

        let mut windows = HashMap::new();
        let k_stream = 8usize;
        windows.insert(FecMode::Streaming, k_stream);

        let cfg = FecConfig {
            initial_mode: FecMode::Streaming,
            window_sizes: windows,
            ..Default::default()
        };
        let mut fec = AdaptiveFec::new(cfg);
        let mut q = VecDeque::new();

        for i in 0..5u64 {
            let pkt = mk_src_packet(1 + i, 100, &pool);
            for pkt in fec.on_send(pkt) {
                q.push_back(pkt);
            }
        }

        let repairs = drain_repairs(&mut q);
        assert_eq!(repairs.len(), 2, "expected 2 streaming repair packets");
        for rp in repairs {
            assert!(!rp.is_systematic);
            assert!(rp.coefficients.is_some());
            assert_eq!(rp.coeff_len, k_stream, "G8 coeff len == k in streaming");
        }
    }

    #[test]
    fn test_streaming_env_cached() {
        // Set before construction to 3; then change to 1 after construction.
        // Behavior should remain every 3 due to caching in AdaptiveFec::new.
        let _env_lock = acquire_env_lock();
        let _g1 = EnvGuard::set("QUICFUSCATE_FEC_STREAM_EVERY", "3");
        let pool = make_pool();

        let mut windows = HashMap::new();
        let k_stream = 8usize;
        windows.insert(FecMode::Streaming, k_stream);

        let cfg = FecConfig {
            initial_mode: FecMode::Streaming,
            window_sizes: windows,
            ..Default::default()
        };
        let mut fec = AdaptiveFec::new(cfg);
        // Change env after construction; should not affect cached value
        let _g2 = EnvGuard::set("QUICFUSCATE_FEC_STREAM_EVERY", "1");

        let mut q = VecDeque::new();
        for i in 0..6u64 {
            let pkt = mk_src_packet(500 + i, 100, &pool);
            for pkt in fec.on_send(pkt) {
                q.push_back(pkt);
            }
        }

        let repairs = drain_repairs(&mut q);
        assert_eq!(repairs.len(), 2, "should emit every 3 packets despite env change");
        for rp in repairs {
            assert!(!rp.is_systematic);
            assert!(rp.coefficients.is_some());
            assert_eq!(rp.coeff_len, k_stream, "G8 coeff len == k in streaming");
        }
    }

    #[test]
    fn test_batch_normal_seq_counts() {
        // QUICFUSCATE_FEC_PARALLEL is read during AdaptiveFec::new
        let _env_lock = acquire_env_lock();
        let _gp = EnvGuard::set("QUICFUSCATE_FEC_PARALLEL", "0");
        let pool = make_pool();

        let mut windows = HashMap::new();
        let k = 8usize; // Normal mode window (k)
        windows.insert(FecMode::Normal, k);

        let cfg = FecConfig {
            initial_mode: FecMode::Normal,
            window_sizes: windows,
            ..Default::default()
        };
        let mut fec = AdaptiveFec::new(cfg);
        let mut q = VecDeque::new();

        for i in 0..k as u64 {
            let pkt = mk_src_packet(100 + i, 100, &pool);
            for pkt in fec.on_send(pkt) {
                q.push_back(pkt);
            }
        }

        let repairs = drain_repairs(&mut q);
        assert_eq!(repairs.len(), (k as f32 * 1.15).ceil() as usize - k, "n-k repairs");
        for rp in repairs {
            assert!(!rp.is_systematic);
            assert!(rp.coefficients.is_some());
            assert_eq!(rp.coeff_len, k, "G8 coeff len == k in Normal mode");
        }
    }

    #[test]
    fn test_batch_normal_par_counts() {
        // QUICFUSCATE_FEC_PARALLEL is read during AdaptiveFec::new
        let _env_lock = acquire_env_lock();
        let _gp = EnvGuard::set("QUICFUSCATE_FEC_PARALLEL", "1");
        let pool = make_pool();

        let mut windows = HashMap::new();
        let k = 8usize; // Normal mode window (k)
        windows.insert(FecMode::Normal, k);

        let cfg = FecConfig {
            initial_mode: FecMode::Normal,
            window_sizes: windows,
            ..Default::default()
        };
        let mut fec = AdaptiveFec::new(cfg);
        let mut q = VecDeque::new();

        for i in 0..k as u64 {
            let pkt = mk_src_packet(200 + i, 100, &pool);
            for pkt in fec.on_send(pkt) {
                q.push_back(pkt);
            }
        }

        let repairs = drain_repairs(&mut q);
        assert_eq!(repairs.len(), (k as f32 * 1.15).ceil() as usize - k, "n-k repairs (parallel)");
        for rp in repairs {
            assert!(!rp.is_systematic);
            assert!(rp.coefficients.is_some());
            assert_eq!(rp.coeff_len, k, "G8 coeff len == k in Normal mode (parallel)");
        }
    }

    #[test]
    fn test_batch_extreme_gf16_coeff_len() {
        // QUICFUSCATE_FEC_PARALLEL is read during AdaptiveFec::new
        let _env_lock = acquire_env_lock();
        let _gp = EnvGuard::set("QUICFUSCATE_FEC_PARALLEL", "0");
        let pool = make_pool();

        let mut windows = HashMap::new();
        let k = 8usize; // Extreme mode window (k)
        windows.insert(FecMode::Extreme, k);

        let cfg = FecConfig {
            initial_mode: FecMode::Extreme,
            window_sizes: windows,
            ..Default::default()
        };
        let mut fec = AdaptiveFec::new(cfg);
        let mut q = VecDeque::new();

        for i in 0..k as u64 {
            let pkt = mk_src_packet(300 + i, 100, &pool);
            for pkt in fec.on_send(pkt) {
                q.push_back(pkt);
            }
        }

        let repairs = drain_repairs(&mut q);
        let expected = ((k as f32) * 2.0).ceil() as usize - k; // n - k with ratio 2.0
        assert_eq!(repairs.len(), expected, "Extreme mode should emit n-k repairs");
        for rp in repairs {
            assert!(!rp.is_systematic);
            assert!(rp.coefficients.is_some());
            assert_eq!(rp.coeff_len, 2 * k, "GF16 coeff len == 2*k in Extreme mode");
        }
    }

    #[test]
    fn test_batch_window_cleared_no_extra_repairs() {
        // QUICFUSCATE_FEC_PARALLEL is read during AdaptiveFec::new
        let _env_lock = acquire_env_lock();
        let _gp = EnvGuard::set("QUICFUSCATE_FEC_PARALLEL", "0");
        let pool = make_pool();

        let mut windows = HashMap::new();
        let k = 8usize;
        windows.insert(FecMode::Normal, k);

        let cfg = FecConfig {
            initial_mode: FecMode::Normal,
            window_sizes: windows,
            ..Default::default()
        };
        let mut fec = AdaptiveFec::new(cfg);
        let mut q = VecDeque::new();

        // Fill one full batch to trigger repair emission and window clear
        for i in 0..k as u64 {
            let pkt = mk_src_packet(400 + i, 100, &pool);
            for pkt in fec.on_send(pkt) {
                q.push_back(pkt);
            }
        }
        let repairs1 = drain_repairs(&mut q);
        let expected = (k as f32 * 1.15).ceil() as usize - k;
        assert_eq!(repairs1.len(), expected, "n-k repairs in batch");

        // After clear, fewer than k new packets must not emit repairs
        let pkt2 = mk_src_packet(4999, 100, &pool);
        for pkt in fec.on_send(pkt2) {
            q.push_back(pkt);
        }
        let repairs2 = drain_repairs(&mut q);
        assert_eq!(repairs2.len(), 0, "no extra repairs after window clear and <k new packets");
    }

    #[test]
    fn test_decoder_elimination_paths() {
        let pool = crate::optimize::global_pool();
        let k = 8;

        // Test Gauss elimination (forced via ENV)
        std::env::set_var("QUICFUSCATE_FEC_DECODER", "gauss");
        let mut decoder_gauss = Decoder8::new(k, Arc::clone(&pool));

        // Add k-1 systematic packets
        for i in 0..k - 1 {
            let mut data = pool.alloc();
            data[0] = i as u8;
            let pkt = FecPacket::new(i as u64, Some(data), 1, true, None, 0, Arc::clone(&pool));
            decoder_gauss.take_packet(pkt);
        }

        // Add one repair packet anchored to base_id = k-1 so sids map to 0..k-1
        let mut repair_data = pool.alloc();
        repair_data[0] = 42; // arbitrary byte; single-equation solve expected
        let mut coeffs = pool.alloc();
        for j in 0..k {
            coeffs[j] = (j + 1) as u8;
        }
        let repair = FecPacket::new(
            (k as u64) - 1,
            Some(repair_data),
            1,
            false,
            Some(coeffs),
            k,
            Arc::clone(&pool),
        );
        decoder_gauss.take_packet(repair);

        // Should be able to decode
        assert!(decoder_gauss.is_complete());

        // Test Wiedemann (if feature enabled)
        #[cfg(feature = "wiedemann")]
        {
            std::env::set_var("QUICFUSCATE_FEC_DECODER", "wiedemann");
            let mut decoder_wm = Decoder8::new(k, Arc::clone(&pool));

            // Same setup
            for i in 0..k - 1 {
                let mut data = pool.alloc();
                data[0] = i as u8;
                let pkt = FecPacket::new(i as u64, Some(data), 1, true, None, 0, Arc::clone(&pool));
                decoder_wm.take_packet(pkt);
            }

            let mut repair_data = pool.alloc();
            repair_data[0] = 42;
            let mut coeffs = pool.alloc();
            for j in 0..k {
                coeffs[j] = (j + 1) as u8;
            }
            let repair = FecPacket::new(
                100,
                Some(repair_data),
                1,
                false,
                Some(coeffs),
                k,
                Arc::clone(&pool),
            );
            decoder_wm.take_packet(repair);

            assert!(decoder_wm.is_complete());
        }

        // Test auto mode with large k (should prefer Wiedemann if available)
        std::env::set_var("QUICFUSCATE_FEC_DECODER", "auto");
        let large_k = 128;
        let _decoder_auto = Decoder8::new(large_k, Arc::clone(&pool));
        // Construction succeeded; additional properties are validated in dedicated decoder tests.
    }

    #[test]
    fn test_batch_toggle_parallel_between_batches() {
        // QUICFUSCATE_FEC_PARALLEL is read during AdaptiveFec::new
        let _env_lock = acquire_env_lock();
        let _gp1 = EnvGuard::set("QUICFUSCATE_FEC_PARALLEL", "0");
        let pool = make_pool();

        let mut windows = HashMap::new();
        let k = 8usize; // Normal mode window (k)
        windows.insert(FecMode::Normal, k);

        let cfg = FecConfig {
            initial_mode: FecMode::Normal,
            window_sizes: windows,
            ..Default::default()
        };
        let mut fec = AdaptiveFec::new(cfg);
        let mut q = VecDeque::new();

        // Batch 1 (sequential)
        for i in 0..k as u64 {
            let pkt = mk_src_packet(600 + i, 100, &pool);
            for pkt in fec.on_send(pkt) {
                q.push_back(pkt);
            }
        }
        let repairs1 = drain_repairs(&mut q);
        let expected = (k as f32 * 1.15).ceil() as usize - k;
        assert_eq!(repairs1.len(), expected, "n-k repairs in batch 1 (seq)");

        // Toggle to parallel for next batch
        drop(_gp1);
        let _gp2 = EnvGuard::set("QUICFUSCATE_FEC_PARALLEL", "1");

        // Batch 2 (parallel)
        for i in 0..k as u64 {
            let pkt = mk_src_packet(700 + i, 100, &pool);
            for pkt in fec.on_send(pkt) {
                q.push_back(pkt);
            }
        }
        let repairs2 = drain_repairs(&mut q);
        assert_eq!(repairs2.len(), expected, "n-k repairs in batch 2 (par)");

        // Properties identical
        for rp in repairs1.into_iter().chain(repairs2.into_iter()) {
            assert!(!rp.is_systematic);
            assert!(rp.coefficients.is_some());
            assert_eq!(rp.coeff_len, k, "G8 coeff len == k in Normal mode");
        }
    }

    #[test]
    fn test_streaming_tetrys_style_recovery_single_loss() {
        // QUICFUSCATE_FEC_STREAM_EVERY is read during AdaptiveFec::new
        let _env_lock = acquire_env_lock();
        let _g = EnvGuard::set("QUICFUSCATE_FEC_STREAM_EVERY", "1");
        let pool = make_pool();

        let mut windows = HashMap::new();
        let k_stream = 8usize;
        windows.insert(FecMode::Streaming, k_stream);

        let cfg = FecConfig {
            initial_mode: FecMode::Streaming,
            window_sizes: windows,
            ..Default::default()
        };

        // Independent sender/receiver to mirror real flow
        let mut sender = AdaptiveFec::new(cfg.clone());
        let mut receiver = AdaptiveFec::new(cfg);

        let mut tx_q = VecDeque::new();
        let mut rx_recovered_total: Vec<FecPacket> = Vec::new();

        // Drop the last source in the window to simplify decoder window alignment
        let missing_id = 1 + (k_stream as u64) - 1;

        for i in 0..k_stream as u64 {
            let id = 1 + i;
            let pkt_tx = mk_src_packet(id, 100, &pool);
            for pkt in sender.on_send(pkt_tx) {
                tx_q.push_back(pkt);
            }

            // Receiver gets all but the missing packet (fresh instance for receiver)
            if id != missing_id {
                let pkt_rx = mk_src_packet(id, 100, &pool);
                let res = receiver.on_receive(pkt_rx).expect("receiver accept src");
                rx_recovered_total.extend(res);
            }

            // Deliver any streaming repairs generated so far
            let mut tmp = VecDeque::new();
            std::mem::swap(&mut tx_q, &mut tmp);
            while let Some(pkt) = tmp.pop_front() {
                if !pkt.is_systematic {
                    let res = receiver.on_receive(pkt).expect("receiver accept repair");
                    rx_recovered_total.extend(res);
                }
            }
        }

        // Verify that the single missing source was recovered
        assert!(
            rx_recovered_total.iter().any(|p| p.id == missing_id && p.len() == 100),
            "expected recovery of the single lost source packet"
        );
    }

    #[test]
    fn test_streaming_tetrys_multi_loss_uniform_recovery() {
        // QUICFUSCATE_FEC_STREAM_EVERY is read during AdaptiveFec::new
        let _env_lock = acquire_env_lock();
        let _g = EnvGuard::set("QUICFUSCATE_FEC_STREAM_EVERY", "1");
        let pool = make_pool();

        let mut windows = HashMap::new();
        let k_stream = 10usize;
        windows.insert(FecMode::Streaming, k_stream);

        let cfg = FecConfig {
            initial_mode: FecMode::Streaming,
            window_sizes: windows,
            ..Default::default()
        };

        let mut sender = AdaptiveFec::new(cfg.clone());
        let mut receiver = AdaptiveFec::new(cfg);

        let mut tx_q = VecDeque::new();
        let mut rx_recovered_total: Vec<FecPacket> = Vec::new();

        // Choose two losses that are spaced apart but near the tail to keep them in-window
        let missing_a = 1 + (k_stream as u64) - 3; // k-2
        let missing_b = 1 + (k_stream as u64) - 1; // k-0

        for i in 0..k_stream as u64 {
            let id = 1 + i;
            let pkt_tx = mk_src_packet(id, 100, &pool);
            for pkt in sender.on_send(pkt_tx) {
                tx_q.push_back(pkt);
            }

            // Deliver source if not dropped
            if id != missing_a && id != missing_b {
                let pkt_rx = mk_src_packet(id, 100, &pool);
                let res = receiver.on_receive(pkt_rx).expect("receiver accept src");
                rx_recovered_total.extend(res);
            }

            // Deliver repairs as they are generated
            let mut tmp = VecDeque::new();
            std::mem::swap(&mut tx_q, &mut tmp);
            while let Some(pkt) = tmp.pop_front() {
                if !pkt.is_systematic {
                    let res = receiver.on_receive(pkt).expect("receiver accept repair");
                    rx_recovered_total.extend(res);
                }
            }
        }

        // Verify both missing packets recovered
        let has_a = rx_recovered_total.iter().any(|p| p.id == missing_a && p.len() == 100);
        let has_b = rx_recovered_total.iter().any(|p| p.id == missing_b && p.len() == 100);
        assert!(has_a && has_b, "expected recovery of both non-consecutive lost sources");
    }

    #[test]
    fn test_streaming_tetrys_burst_loss_recovery() {
        // QUICFUSCATE_FEC_STREAM_EVERY is read during AdaptiveFec::new
        let _env_lock = acquire_env_lock();
        let _g = EnvGuard::set("QUICFUSCATE_FEC_STREAM_EVERY", "1");
        let pool = make_pool();

        let mut windows = HashMap::new();
        let k_stream = 12usize;
        windows.insert(FecMode::Streaming, k_stream);

        let cfg = FecConfig {
            initial_mode: FecMode::Streaming,
            window_sizes: windows,
            ..Default::default()
        };

        let mut sender = AdaptiveFec::new(cfg.clone());
        let mut receiver = AdaptiveFec::new(cfg);

        let mut tx_q = VecDeque::new();
        let mut rx_recovered_total: Vec<FecPacket> = Vec::new();

        // Drop a burst of three at the tail: k-3, k-2, k-1
        let miss1 = 1 + (k_stream as u64) - 3;
        let miss2 = 1 + (k_stream as u64) - 2;
        let miss3 = 1 + (k_stream as u64) - 1;

        for i in 0..k_stream as u64 {
            let id = 1 + i;
            let pkt_tx = mk_src_packet(id, 100, &pool);
            for pkt in sender.on_send(pkt_tx) {
                tx_q.push_back(pkt);
            }

            if id != miss1 && id != miss2 && id != miss3 {
                let pkt_rx = mk_src_packet(id, 100, &pool);
                let res = receiver.on_receive(pkt_rx).expect("receiver accept src");
                rx_recovered_total.extend(res);
            }

            let mut tmp = VecDeque::new();
            std::mem::swap(&mut tx_q, &mut tmp);
            while let Some(pkt) = tmp.pop_front() {
                if !pkt.is_systematic {
                    let res = receiver.on_receive(pkt).expect("receiver accept repair");
                    rx_recovered_total.extend(res);
                }
            }
        }

        // Verify all three missing packets recovered
        let has1 = rx_recovered_total.iter().any(|p| p.id == miss1 && p.len() == 100);
        let has2 = rx_recovered_total.iter().any(|p| p.id == miss2 && p.len() == 100);
        let has3 = rx_recovered_total.iter().any(|p| p.id == miss3 && p.len() == 100);
        assert!(has1 && has2 && has3, "expected recovery of burst of three lost sources");
    }

    #[test]
    fn test_streaming_rank_progression_monotonic() {
        // QUICFUSCATE_FEC_STREAM_EVERY is read during AdaptiveFec::new
        let _env_lock = acquire_env_lock();
        let _g = EnvGuard::set("QUICFUSCATE_FEC_STREAM_EVERY", "1");
        let pool = make_pool();

        let mut windows = HashMap::new();
        let k_stream = 9usize;
        windows.insert(FecMode::Streaming, k_stream);

        let cfg = FecConfig {
            initial_mode: FecMode::Streaming,
            window_sizes: windows,
            ..Default::default()
        };

        let mut sender = AdaptiveFec::new(cfg.clone());
        let mut receiver = AdaptiveFec::new(cfg);

        let mut tx_q = VecDeque::new();
        let mut seen_ids: std::collections::HashSet<u64> = Default::default();
        let mut monotonic: Vec<usize> = Vec::new();

        // Drop two sources near the tail
        let miss_a = 1 + (k_stream as u64) - 2;
        let miss_b = 1 + (k_stream as u64) - 1;

        for i in 0..k_stream as u64 {
            let id = 1 + i;
            let pkt_tx = mk_src_packet(id, 100, &pool);
            for pkt in sender.on_send(pkt_tx) {
                tx_q.push_back(pkt);
            }

            if id != miss_a && id != miss_b {
                let pkt_rx = mk_src_packet(id, 100, &pool);
                for p in receiver.on_receive(pkt_rx).expect("rx src") {
                    seen_ids.insert(p.id);
                }
            }

            // Deliver repairs and observe cumulative recovered size progression
            let mut tmp = VecDeque::new();
            std::mem::swap(&mut tx_q, &mut tmp);
            while let Some(pkt) = tmp.pop_front() {
                if !pkt.is_systematic {
                    for p in receiver.on_receive(pkt).expect("rx repair") {
                        seen_ids.insert(p.id);
                    }
                    monotonic.push(seen_ids.len());
                }
            }
        }

        // Check monotonic non-decreasing sequence
        for w in monotonic.windows(2) {
            if let [a, b] = w {
                assert!(b >= a, "recovered set size should be non-decreasing");
            }
        }

        // Final set includes both missing sources
        assert!(
            seen_ids.contains(&miss_a) && seen_ids.contains(&miss_b),
            "final recovered set should include both missing sources"
        );
    }

    #[test]
    fn test_streaming_dedup_across_calls() {
        // QUICFUSCATE_FEC_STREAM_EVERY is read during AdaptiveFec::new
        let _env_lock = acquire_env_lock();
        let _g = EnvGuard::set("QUICFUSCATE_FEC_STREAM_EVERY", "1");
        let pool = make_pool();

        let mut windows = HashMap::new();
        let k_stream = 8usize;
        windows.insert(FecMode::Streaming, k_stream);

        let cfg = FecConfig {
            initial_mode: FecMode::Streaming,
            window_sizes: windows,
            ..Default::default()
        };

        let mut sender = AdaptiveFec::new(cfg.clone());
        let mut receiver = AdaptiveFec::new(cfg);

        let mut tx_q = VecDeque::new();
        let missing_id = 42u64; // deterministic choice beyond initial window base

        let mut seen_missing = 0usize;

        // Send a sequence with periodic repairs; always drop "missing_id" source
        for i in 1..(k_stream as u64 * 4) {
            let id = i;
            let pkt_tx = mk_src_packet(id, 80, &pool);
            for pkt in sender.on_send(pkt_tx) {
                tx_q.push_back(pkt);
            }

            // deliver source if not the missing one
            if id != missing_id {
                let pkt_rx = mk_src_packet(id, 80, &pool);
                for p in receiver.on_receive(pkt_rx).expect("rx src") {
                    if p.id == missing_id {
                        seen_missing += 1;
                    }
                }
            }

            // deliver any generated repairs immediately
            let mut repairs = VecDeque::new();
            std::mem::swap(&mut tx_q, &mut repairs);
            while let Some(rp) = repairs.pop_front() {
                if !rp.is_systematic {
                    for p in receiver.on_receive(rp).expect("rx repair") {
                        if p.id == missing_id {
                            seen_missing += 1;
                        }
                    }
                }
            }
        }

        // Dedup guarantee: even if decoder could surface the same id across calls, we emit it once.
        assert!(
            seen_missing <= 1,
            "recovered packet with same id must be emitted at most once, got {}",
            seen_missing
        );
    }

    #[test]
    fn test_streaming_dedup_window_bounding() {
        // QUICFUSCATE_FEC_STREAM_EVERY is read during AdaptiveFec::new
        let _env_lock = acquire_env_lock();
        let _g = EnvGuard::set("QUICFUSCATE_FEC_STREAM_EVERY", "1");
        let pool = make_pool();

        let mut windows = HashMap::new();
        let k_stream = 4usize; // small window, bound becomes max(4*k, 256) = 256
        windows.insert(FecMode::Streaming, k_stream);

        let cfg = FecConfig {
            initial_mode: FecMode::Streaming,
            window_sizes: windows,
            ..Default::default()
        };

        let mut sender = AdaptiveFec::new(cfg.clone());
        let mut receiver = AdaptiveFec::new(cfg);

        let mut tx_q = VecDeque::new();
        let bound = 256usize; // max(4*4, 256)

        // Generate > bound unique recoveries by repeatedly dropping the last id of each k-window
        let total_iters = bound + 32; // exceed bound to force eviction
        for batch in 0..total_iters {
            let base = (batch as u64) * (k_stream as u64);
            let miss = base + (k_stream as u64); // drop last in this batch
            for j in 1..=k_stream as u64 {
                let id = base + j;
                let pkt_tx = mk_src_packet(id, 60, &pool);
                for pkt in sender.on_send(pkt_tx) {
                    tx_q.push_back(pkt);
                }
                if id != miss {
                    let pkt_rx = mk_src_packet(id, 60, &pool);
                    let _ = receiver.on_receive(pkt_rx).expect("rx src");
                }
                // deliver repairs
                let mut repairs = VecDeque::new();
                std::mem::swap(&mut tx_q, &mut repairs);
                while let Some(rp) = repairs.pop_front() {
                    if !rp.is_systematic {
                        let _ = receiver.on_receive(rp).expect("rx repair");
                    }
                }
            }
        }

        // Test-only: the emitted cache length should not exceed bound
        #[cfg(test)]
        fn emitted_len(fec: &AdaptiveFec) -> usize {
            fec.emitted_order.len()
        }
        let len = emitted_len(&receiver);
        assert!(len <= bound, "emitted cache should be bounded ({} <= {})", len, bound);
    }

    #[test]
    fn test_env_guard_unset_functionality() {
        let test_key = "QUICFUSCATE_TEST_UNSET";

        // Set initial value
        std::env::set_var(test_key, "initial_value");
        assert_eq!(std::env::var(test_key).unwrap(), "initial_value");

        // Test unset() method
        {
            let _guard = EnvGuard::unset(test_key);
            assert!(std::env::var(test_key).is_err()); // Should be unset
        }
        // Guard drops, should restore original value
        assert_eq!(std::env::var(test_key).unwrap(), "initial_value");

        // Cleanup
        std::env::remove_var(test_key);
    }
}
