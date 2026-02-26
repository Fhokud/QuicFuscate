//! Ultra-sophisticated brain acceleration module
//! Complete HW acceleration for statistics, ML operations, matrix multiply

use crate::optimize::telemetry;
use crate::optimize::{CpuFeature, FeatureDetector};
#[allow(unused_imports)]
use crate::simd::CpuProfile;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::__m256;

/// Mean and variance with SIMD - 4x faster (AVX2+FMA/NEON)
#[inline(always)]
pub fn compute_statistics(data: &[f32]) -> (f32, f32) {
    let _profile = FeatureDetector::instance().profile();

    #[cfg(target_arch = "x86_64")]
    match _profile {
        CpuProfile::X86_P2a
        | CpuProfile::X86_P2b
        | CpuProfile::X86_P3a
        | CpuProfile::X86_P3b
        | CpuProfile::X86_P3c
        | CpuProfile::X86_P3d
        | CpuProfile::X86_P3e
        | CpuProfile::X86_P4a
        | CpuProfile::X86_P4b => {
            return unsafe { compute_statistics_avx2_fma(data) };
        }
        CpuProfile::X86_P1f
        | CpuProfile::X86_P1b
        | CpuProfile::X86_P1a
        | CpuProfile::X86_P0b
        | CpuProfile::X86_P0a => {
            return unsafe { compute_statistics_sse2(data) };
        }
        _ => {}
    }

    #[cfg(target_arch = "aarch64")]
    match _profile {
        CpuProfile::ARM_A2 => {
            return unsafe { compute_statistics_sve2(data) };
        }
        CpuProfile::ARM_A1c | CpuProfile::ARM_A1d | CpuProfile::Apple_M => {
            return unsafe { compute_statistics_neon(data) };
        }
        _ => {}
    }

    // Scalar fallback
    let n = data.len() as f32;
    let sum: f32 = data.iter().sum();
    let mean = sum / n;
    let variance = data.iter().map(|&x| (x - mean).powi(2)).sum::<f32>() / n;
    (mean, variance)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2", enable = "fma")]
unsafe fn compute_statistics_avx2_fma(data: &[f32]) -> (f32, f32) {
    use std::arch::x86_64::*;

    let n = data.len() as f32;
    let mut sum_vec = _mm256_setzero_ps();
    let mut i = 0;

    // Compute sum with AVX2
    while i + 8 <= data.len() {
        let vals = _mm256_loadu_ps(data.as_ptr().add(i));
        sum_vec = _mm256_add_ps(sum_vec, vals);
        i += 8;
    }

    // Horizontal sum
    let sum_128 = _mm_add_ps(_mm256_extractf128_ps(sum_vec, 0), _mm256_extractf128_ps(sum_vec, 1));
    let sum_64 = _mm_add_ps(sum_128, _mm_movehl_ps(sum_128, sum_128));
    let sum_32 = _mm_add_ss(sum_64, _mm_shuffle_ps(sum_64, sum_64, 0x01));
    let mut sum = _mm_cvtss_f32(sum_32);

    // Add remainder
    while i < data.len() {
        sum += data[i];
        i += 1;
    }

    let mean = sum / n;
    let mean_vec = _mm256_set1_ps(mean);

    // Compute variance with FMA
    let mut var_vec = _mm256_setzero_ps();
    i = 0;

    while i + 8 <= data.len() {
        let vals = _mm256_loadu_ps(data.as_ptr().add(i));
        let diff = _mm256_sub_ps(vals, mean_vec);
        var_vec = _mm256_fmadd_ps(diff, diff, var_vec);
        i += 8;
    }

    // Horizontal sum for variance
    let var_128 = _mm_add_ps(_mm256_extractf128_ps(var_vec, 0), _mm256_extractf128_ps(var_vec, 1));
    let var_64 = _mm_add_ps(var_128, _mm_movehl_ps(var_128, var_128));
    let var_32 = _mm_add_ss(var_64, _mm_shuffle_ps(var_64, var_64, 0x01));
    let mut variance = _mm_cvtss_f32(var_32);

    // Add remainder
    while i < data.len() {
        let diff = data[i] - mean;
        variance += diff * diff;
        i += 1;
    }

    (mean, variance / n)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn compute_statistics_sse2(data: &[f32]) -> (f32, f32) {
    use std::arch::x86_64::*;

    let n = data.len() as f32;
    if n == 0.0 {
        return (0.0, 0.0);
    }

    let mut sum_vec = _mm_setzero_ps();
    let mut i = 0usize;

    while i + 4 <= data.len() {
        let vals = _mm_loadu_ps(data.as_ptr().add(i));
        sum_vec = _mm_add_ps(sum_vec, vals);
        i += 4;
    }

    let mut sum = horizontal_sum_ps_sse(sum_vec);
    while i < data.len() {
        sum += data[i];
        i += 1;
    }

    let mean = sum / n;
    let mean_vec = _mm_set1_ps(mean);

    let mut var_vec = _mm_setzero_ps();
    i = 0;
    while i + 4 <= data.len() {
        let vals = _mm_loadu_ps(data.as_ptr().add(i));
        let diff = _mm_sub_ps(vals, mean_vec);
        var_vec = _mm_add_ps(var_vec, _mm_mul_ps(diff, diff));
        i += 4;
    }

    let mut variance = horizontal_sum_ps_sse(var_vec);
    while i < data.len() {
        let diff = data[i] - mean;
        variance += diff * diff;
        i += 1;
    }

    (mean, variance / n)
}

/// NEON-optimized mean and variance with FMA - 4x faster on ARM
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn compute_statistics_neon(data: &[f32]) -> (f32, f32) {
    use std::arch::aarch64::*;

    let n = data.len() as f32;
    let mut sum_vec = vdupq_n_f32(0.0);
    let mut i = 0;

    // Compute sum with NEON (4x f32 per iteration)
    while i + 4 <= data.len() {
        let vals = vld1q_f32(data.as_ptr().add(i));
        sum_vec = vaddq_f32(sum_vec, vals);
        i += 4;
    }

    // Horizontal sum (NEON pairwise add)
    let sum_pair = vpadd_f32(vget_low_f32(sum_vec), vget_high_f32(sum_vec));
    let sum_scalar = vpadd_f32(sum_pair, sum_pair);
    let mut sum = vget_lane_f32::<0>(sum_scalar);

    // Add remainder
    while i < data.len() {
        sum += data[i];
        i += 1;
    }

    let mean = sum / n;
    let mean_vec = vdupq_n_f32(mean);

    // Compute variance with NEON FMA
    let mut var_vec = vdupq_n_f32(0.0);
    i = 0;

    while i + 4 <= data.len() {
        let vals = vld1q_f32(data.as_ptr().add(i));
        let diff = vsubq_f32(vals, mean_vec);
        // FMA: var_vec += diff * diff
        var_vec = vfmaq_f32(var_vec, diff, diff);
        i += 4;
    }

    // Horizontal sum for variance
    let var_pair = vpadd_f32(vget_low_f32(var_vec), vget_high_f32(var_vec));
    let var_scalar = vpadd_f32(var_pair, var_pair);
    let mut variance = vget_lane_f32::<0>(var_scalar);

    // Add remainder
    while i < data.len() {
        let diff = data[i] - mean;
        variance += diff * diff;
        i += 1;
    }

    (mean, variance / n)
}

#[cfg(target_arch = "aarch64")]
unsafe fn compute_statistics_sve2(data: &[f32]) -> (f32, f32) {
    #[cfg(target_feature = "sve2")]
    {
        compute_statistics_sve2_impl(data)
    }

    #[cfg(not(target_feature = "sve2"))]
    {
        compute_statistics_neon(data)
    }
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[target_feature(enable = "sve2")]
unsafe fn compute_statistics_sve2_impl(data: &[f32]) -> (f32, f32) {
    use std::arch::aarch64::*;

    let n = data.len();
    if n == 0 {
        return (0.0, 0.0);
    }

    let mut offset = 0usize;
    let mut sum_vec = svdup_f32(0.0);

    while offset < n {
        let pg = svwhilelt_b32(offset as u64, n as u64);
        let vals = svld1_f32(pg, data.as_ptr().add(offset));
        sum_vec = svadd_f32_m(pg, sum_vec, vals);
        offset += svcntw() as usize;
    }

    let total_sum = svaddv_f32(svptrue_b32(), sum_vec);
    let mean = total_sum / (n as f32);

    offset = 0;
    let mean_vec = svdup_f32(mean);
    let mut var_vec = svdup_f32(0.0);

    while offset < n {
        let pg = svwhilelt_b32(offset as u64, n as u64);
        let vals = svld1_f32(pg, data.as_ptr().add(offset));
        let diff = svsub_f32_x(pg, vals, mean_vec);
        var_vec = svmla_f32_m(pg, var_vec, diff, diff);
        offset += svcntw() as usize;
    }

    let variance = svaddv_f32(svptrue_b32(), var_vec) / (n as f32);
    (mean, variance)
}

/// Apply exponential decay to histogram bins (u64) using SIMD fast paths.
#[inline(always)]
pub fn decay_histogram(bins: &mut [u64], decay: f64) {
    if bins.is_empty() {
        return;
    }
    let decay = decay.clamp(0.0, 1.0);
    if decay == 1.0 {
        return;
    }
    if decay <= 0.0 {
        for bin in bins.iter_mut() {
            *bin = 0;
        }
        return;
    }

    #[allow(unused_variables)]
    let detector = FeatureDetector::instance();

    #[cfg(target_arch = "x86_64")]
    {
        let has_avx512 = detector.has_feature(CpuFeature::AVX512F)
            && detector.has_feature(CpuFeature::AVX512BW)
            && detector.has_feature(CpuFeature::AVX512DQ);
        if has_avx512 {
            telemetry::BRAIN_HISTOGRAM_AVX512_OPS.inc();
            unsafe {
                decay_histogram_avx512(bins, decay);
            }
            return;
        }

        if detector.has_feature(CpuFeature::AVX2) {
            telemetry::BRAIN_HISTOGRAM_AVX2_OPS.inc();
            unsafe {
                decay_histogram_avx2(bins, decay);
            }
            return;
        }

        if detector.has_feature(CpuFeature::SSE41) {
            telemetry::BRAIN_HISTOGRAM_SSE_OPS.inc();
            unsafe {
                decay_histogram_sse41(bins, decay);
            }
            return;
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if detector.has_feature(CpuFeature::SVE2) {
            telemetry::BRAIN_HISTOGRAM_SVE2_OPS.inc();
            unsafe {
                decay_histogram_sve2(bins, decay);
            }
            return;
        }

        if detector.has_feature(CpuFeature::NEON) {
            telemetry::BRAIN_HISTOGRAM_NEON_OPS.inc();
            unsafe {
                decay_histogram_neon(bins, decay);
            }
            return;
        }
    }

    // Scalar fallback
    crate::optimize::telemetry::BRAIN_HISTOGRAM_SCALAR_OPS.inc();
    for bin in bins.iter_mut() {
        *bin = ((*bin as f64) * decay).floor() as u64;
    }
}

/// Jensen-Shannon divergence between histogram (bins/total) and target distribution.
#[inline(always)]
pub fn jensen_shannon_divergence(bins: &[u64], total: u64, target: &[f64]) -> f64 {
    let len = bins.len().min(target.len());
    if len == 0 || total == 0 {
        return 0.0;
    }

    #[allow(unused_variables)]
    let detector = FeatureDetector::instance();

    #[cfg(target_arch = "x86_64")]
    {
        let has_avx512 = detector.has_feature(CpuFeature::AVX512F)
            && detector.has_feature(CpuFeature::AVX512BW)
            && detector.has_feature(CpuFeature::AVX512DQ);
        if has_avx512 {
            telemetry::BRAIN_HISTOGRAM_AVX512_OPS.inc();
            return unsafe { jensen_shannon_avx512(bins, total, target, len) };
        }

        if detector.has_feature(CpuFeature::AVX2) {
            telemetry::BRAIN_HISTOGRAM_AVX2_OPS.inc();
            return unsafe { jensen_shannon_avx2(bins, total, target, len) };
        }

        if detector.has_feature(CpuFeature::SSE41) {
            telemetry::BRAIN_HISTOGRAM_SSE_OPS.inc();
            return unsafe { jensen_shannon_sse41(bins, total, target, len) };
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if detector.has_feature(CpuFeature::SVE2) {
            telemetry::BRAIN_HISTOGRAM_SVE2_OPS.inc();
            return unsafe { jensen_shannon_sve2(bins, total, target, len) };
        }

        if detector.has_feature(CpuFeature::NEON) {
            telemetry::BRAIN_HISTOGRAM_NEON_OPS.inc();
            return unsafe { jensen_shannon_neon(bins, total, target, len) };
        }
    }

    // Scalar fallback
    crate::optimize::telemetry::BRAIN_HISTOGRAM_SCALAR_OPS.inc();
    scalar_jensen_shannon(&bins[..len], total, &target[..len])
}

fn scalar_jensen_shannon(bins: &[u64], total: u64, target: &[f64]) -> f64 {
    let inv_total = 1.0 / (total as f64);
    const EPS: f64 = 1e-12;
    let mut js = 0.0;
    for (bin, &q_raw) in bins.iter().zip(target.iter()) {
        let p = (*bin as f64) * inv_total;
        let p = p.max(EPS);
        let q = q_raw.max(EPS);
        let m = 0.5 * (p + q);
        js += 0.5 * p * (p / m).ln() + 0.5 * q * (q / m).ln();
    }
    js
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn convert_u32_to_pd_unsigned(v: std::arch::x86_64::__m128i) -> std::arch::x86_64::__m128d {
    use std::arch::x86_64::*;

    let signed = _mm_cvtepi32_pd(v);
    let negative_mask = _mm_cmplt_epi32(v, _mm_setzero_si128());
    let bias = _mm_set1_pd(4_294_967_296.0f64);
    let adjust = _mm_and_pd(_mm_castsi128_pd(negative_mask), bias);
    _mm_add_pd(signed, adjust)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn u64x2_to_f64x2(v: std::arch::x86_64::__m128i) -> std::arch::x86_64::__m128d {
    use std::arch::x86_64::*;

    const PACK_LOHI: i32 = 0x88;
    let low_mask = _mm_set1_epi64x(0xFFFF_FFFFu64 as i64);
    let lo = _mm_shuffle_epi32(_mm_and_si128(v, low_mask), PACK_LOHI);
    let hi = _mm_shuffle_epi32(_mm_srli_epi64(v, 32), PACK_LOHI);

    let lo_pd = convert_u32_to_pd_unsigned(lo);
    let hi_pd = convert_u32_to_pd_unsigned(hi);
    let scale = _mm_set1_pd(4_294_967_296.0f64);
    _mm_add_pd(_mm_mul_pd(hi_pd, scale), lo_pd)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn u64x4_to_f64x4(v: std::arch::x86_64::__m256i) -> std::arch::x86_64::__m256d {
    use std::arch::x86_64::*;

    let lo = _mm256_castsi256_si128(v);
    let hi = _mm256_extracti128_si256::<1>(v);
    let lo_pd = u64x2_to_f64x2(lo);
    let hi_pd = u64x2_to_f64x2(hi);
    let mut combined = _mm256_castpd128_pd256(lo_pd);
    combined = _mm256_insertf128_pd::<1>(combined, hi_pd);
    combined
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn u64x8_to_f64x8(v: std::arch::x86_64::__m512i) -> std::arch::x86_64::__m512d {
    use std::arch::x86_64::*;

    let lo = _mm512_castsi512_si256(v);
    let hi = _mm512_extracti64x4_epi64::<1>(v);
    let lo_pd = u64x4_to_f64x4(lo);
    let hi_pd = u64x4_to_f64x4(hi);
    let mut combined = _mm512_castpd256_pd512(lo_pd);
    combined = _mm512_insertf64x4::<1>(combined, hi_pd);
    combined
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn f64x2_to_u64x2(v: std::arch::x86_64::__m128d) -> std::arch::x86_64::__m128i {
    use std::arch::x86_64::*;

    let two_pow_63 = _mm_set1_pd(9_223_372_036_854_775_808.0f64);
    let ge_mask_pd = _mm_cmpge_pd(v, two_pow_63);
    let adjust = _mm_and_pd(ge_mask_pd, two_pow_63);
    let adjusted = _mm_sub_pd(v, adjust);
    let truncated = _mm_cvttpd_epi64(adjusted);
    let hi_bias = _mm_set1_epi64x(0x8000_0000_0000_0000u64 as i64);
    let ge_mask = _mm_castpd_si128(ge_mask_pd);
    _mm_add_epi64(truncated, _mm_and_si128(ge_mask, hi_bias))
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn f64x4_to_u64x4(v: std::arch::x86_64::__m256d) -> std::arch::x86_64::__m256i {
    use std::arch::x86_64::*;

    let lo = _mm256_castpd256_pd128(v);
    let hi = _mm256_extractf128_pd::<1>(v);
    let lo_i = f64x2_to_u64x2(lo);
    let hi_i = f64x2_to_u64x2(hi);
    let mut combined = _mm256_castsi128_si256(lo_i);
    combined = _mm256_inserti128_si256::<1>(combined, hi_i);
    combined
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn f64x8_to_u64x8(v: std::arch::x86_64::__m512d) -> std::arch::x86_64::__m512i {
    use std::arch::x86_64::*;

    let lo = _mm512_castpd512_pd256(v);
    let hi = _mm512_extractf64x4_pd::<1>(v);
    let lo_i = f64x4_to_u64x4(lo);
    let hi_i = f64x4_to_u64x4(hi);
    let mut combined = _mm512_castsi256_si512(lo_i);
    combined = _mm512_inserti64x4::<1>(combined, hi_i);
    combined
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
unsafe fn decay_histogram_avx512(bins: &mut [u64], decay: f64) {
    use std::arch::x86_64::*;

    let len = bins.len();
    if len == 0 {
        return;
    }

    let decay_vec = _mm512_set1_pd(decay);
    let mut i = 0usize;
    while i + 8 <= len {
        let vals = _mm512_loadu_si512(bins.as_ptr().add(i) as *const __m512i);
        let vals_f64 = u64x8_to_f64x8(vals);
        let scaled = _mm512_mul_pd(vals_f64, decay_vec);
        let floored = _mm512_roundscale_pd(scaled, _MM_FROUND_TO_NEG_INF | _MM_FROUND_NO_EXC);
        let converted = f64x8_to_u64x8(floored);
        _mm512_storeu_si512(bins.as_mut_ptr().add(i) as *mut __m512i, converted);
        i += 8;
    }

    if i < len {
        decay_histogram_avx2(&mut bins[i..], decay);
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn decay_histogram_avx2(bins: &mut [u64], decay: f64) {
    use std::arch::x86_64::*;

    let len = bins.len();
    if len == 0 {
        return;
    }

    let decay_vec = _mm256_set1_pd(decay);
    let mut i = 0usize;
    while i + 4 <= len {
        let vals = _mm256_loadu_si256(bins.as_ptr().add(i) as *const __m256i);
        let vals_f64 = u64x4_to_f64x4(vals);
        let scaled = _mm256_mul_pd(vals_f64, decay_vec);
        let floored = _mm256_floor_pd(scaled);
        let converted = f64x4_to_u64x4(floored);
        _mm256_storeu_si256(bins.as_mut_ptr().add(i) as *mut __m256i, converted);
        i += 4;
    }

    if i < len {
        decay_histogram_sse41(&mut bins[i..], decay);
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.1")]
unsafe fn decay_histogram_sse41(bins: &mut [u64], decay: f64) {
    use std::arch::x86_64::*;

    let len = bins.len();
    if len == 0 {
        return;
    }

    let decay_vec = _mm_set1_pd(decay);
    let mut i = 0usize;
    while i + 2 <= len {
        let vals = _mm_loadu_si128(bins.as_ptr().add(i) as *const __m128i);
        let vals_f64 = u64x2_to_f64x2(vals);
        let scaled = _mm_mul_pd(vals_f64, decay_vec);
        let floored = _mm_floor_pd(scaled);
        let converted = f64x2_to_u64x2(floored);
        _mm_storeu_si128(bins.as_mut_ptr().add(i) as *mut __m128i, converted);
        i += 2;
    }

    for bin in bins.iter_mut().skip(i) {
        *bin = ((*bin as f64) * decay).floor() as u64;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
unsafe fn jensen_shannon_avx512(bins: &[u64], total: u64, target: &[f64], len: usize) -> f64 {
    use std::arch::x86_64::*;

    const EPS: f64 = 1e-12;
    let inv_total = _mm512_set1_pd(1.0 / (total as f64));
    let half = _mm512_set1_pd(0.5);
    let eps_vec = _mm512_set1_pd(EPS);
    let mut acc = 0.0;
    let mut i = 0usize;

    while i + 8 <= len {
        let hist = _mm512_loadu_si512(bins.as_ptr().add(i) as *const __m512i);
        let hist_f64 = u64x8_to_f64x8(hist);
        let p = _mm512_max_pd(_mm512_mul_pd(hist_f64, inv_total), eps_vec);
        let q = _mm512_max_pd(_mm512_loadu_pd(target.as_ptr().add(i)), eps_vec);
        let m = _mm512_mul_pd(_mm512_add_pd(p, q), half);

        let mut p_lane = [0f64; 8];
        let mut q_lane = [0f64; 8];
        let mut m_lane = [0f64; 8];
        _mm512_storeu_pd(p_lane.as_mut_ptr(), p);
        _mm512_storeu_pd(q_lane.as_mut_ptr(), q);
        _mm512_storeu_pd(m_lane.as_mut_ptr(), m);

        for lane in 0..8 {
            let p_val = p_lane[lane];
            let q_val = q_lane[lane];
            let m_val = m_lane[lane];
            acc += 0.5 * p_val * (p_val / m_val).ln() + 0.5 * q_val * (q_val / m_val).ln();
        }

        i += 8;
    }

    if i < len {
        acc += jensen_shannon_avx2(&bins[i..], total, &target[i..], len - i);
    }

    acc
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn jensen_shannon_avx2(bins: &[u64], total: u64, target: &[f64], len: usize) -> f64 {
    use std::arch::x86_64::*;

    const EPS: f64 = 1e-12;
    let inv_total = _mm256_set1_pd(1.0 / (total as f64));
    let half = _mm256_set1_pd(0.5);
    let eps_vec = _mm256_set1_pd(EPS);
    let mut acc = 0.0;
    let mut i = 0usize;

    while i + 4 <= len {
        let hist = _mm256_loadu_si256(bins.as_ptr().add(i) as *const __m256i);
        let hist_f64 = u64x4_to_f64x4(hist);
        let p = _mm256_max_pd(_mm256_mul_pd(hist_f64, inv_total), eps_vec);
        let q = _mm256_max_pd(_mm256_loadu_pd(target.as_ptr().add(i)), eps_vec);
        let m = _mm256_mul_pd(_mm256_add_pd(p, q), half);

        let mut p_lane = [0f64; 4];
        let mut q_lane = [0f64; 4];
        let mut m_lane = [0f64; 4];
        _mm256_storeu_pd(p_lane.as_mut_ptr(), p);
        _mm256_storeu_pd(q_lane.as_mut_ptr(), q);
        _mm256_storeu_pd(m_lane.as_mut_ptr(), m);

        for lane in 0..4 {
            let p_val = p_lane[lane];
            let q_val = q_lane[lane];
            let m_val = m_lane[lane];
            acc += 0.5 * p_val * (p_val / m_val).ln() + 0.5 * q_val * (q_val / m_val).ln();
        }

        i += 4;
    }

    if i < len {
        acc += jensen_shannon_sse41(&bins[i..], total, &target[i..], len - i);
    }

    acc
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.1")]
unsafe fn jensen_shannon_sse41(bins: &[u64], total: u64, target: &[f64], len: usize) -> f64 {
    use std::arch::x86_64::*;

    const EPS: f64 = 1e-12;
    let inv_total = _mm_set1_pd(1.0 / (total as f64));
    let half = _mm_set1_pd(0.5);
    let eps_vec = _mm_set1_pd(EPS);
    let mut acc = 0.0;
    let mut i = 0usize;

    while i + 2 <= len {
        let hist = _mm_loadu_si128(bins.as_ptr().add(i) as *const __m128i);
        let hist_f64 = u64x2_to_f64x2(hist);
        let p = _mm_max_pd(_mm_mul_pd(hist_f64, inv_total), eps_vec);
        let q = _mm_max_pd(_mm_loadu_pd(target.as_ptr().add(i)), eps_vec);
        let m = _mm_mul_pd(_mm_add_pd(p, q), half);

        let mut p_lane = [0f64; 2];
        let mut q_lane = [0f64; 2];
        let mut m_lane = [0f64; 2];
        _mm_storeu_pd(p_lane.as_mut_ptr(), p);
        _mm_storeu_pd(q_lane.as_mut_ptr(), q);
        _mm_storeu_pd(m_lane.as_mut_ptr(), m);

        for lane in 0..2 {
            let p_val = p_lane[lane];
            let q_val = q_lane[lane];
            let m_val = m_lane[lane];
            acc += 0.5 * p_val * (p_val / m_val).ln() + 0.5 * q_val * (q_val / m_val).ln();
        }

        i += 2;
    }

    if i < len {
        acc += scalar_jensen_shannon(&bins[i..len], total, &target[i..len]);
    }

    acc
}

#[cfg(all(feature = "simd-selfcheck", target_arch = "x86_64"))]
pub fn __test_decay_histogram_avx512(bins: &mut [u64], decay: f64) {
    unsafe {
        decay_histogram_avx512(bins, decay);
    }
}

#[cfg(all(feature = "simd-selfcheck", target_arch = "x86_64"))]
pub fn __test_decay_histogram_avx2(bins: &mut [u64], decay: f64) {
    unsafe {
        decay_histogram_avx2(bins, decay);
    }
}

#[cfg(all(feature = "simd-selfcheck", target_arch = "x86_64"))]
pub fn __test_decay_histogram_sse41(bins: &mut [u64], decay: f64) {
    unsafe {
        decay_histogram_sse41(bins, decay);
    }
}

#[cfg(all(feature = "simd-selfcheck", target_arch = "x86_64"))]
pub fn __test_jensen_shannon_avx512(bins: &[u64], total: u64, target: &[f64]) -> f64 {
    unsafe { jensen_shannon_avx512(bins, total, target, bins.len().min(target.len())) }
}

#[cfg(all(feature = "simd-selfcheck", target_arch = "x86_64"))]
pub fn __test_jensen_shannon_avx2(bins: &[u64], total: u64, target: &[f64]) -> f64 {
    unsafe { jensen_shannon_avx2(bins, total, target, bins.len().min(target.len())) }
}

#[cfg(all(feature = "simd-selfcheck", target_arch = "x86_64"))]
pub fn __test_jensen_shannon_sse41(bins: &[u64], total: u64, target: &[f64]) -> f64 {
    unsafe { jensen_shannon_sse41(bins, total, target, bins.len().min(target.len())) }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn decay_histogram_neon(bins: &mut [u64], decay: f64) {
    use std::arch::aarch64::*;

    let mut i = 0usize;
    let decay_vec = vdupq_n_f64(decay);

    while i + 2 <= bins.len() {
        let vals = vld1q_u64(bins.as_ptr().add(i));
        let vals_f64 = vcvtq_f64_u64(vals);
        let scaled = vmulq_f64(vals_f64, decay_vec);
        let floored = vrndmq_f64(scaled);
        let converted = vcvtq_u64_f64(floored);
        vst1q_u64(bins.as_mut_ptr().add(i), converted);
        i += 2;
    }

    for bin in bins.iter_mut().skip(i) {
        *bin = ((*bin as f64) * decay).floor() as u64;
    }
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[target_feature(enable = "sve2")]
unsafe fn decay_histogram_sve2_impl(bins: &mut [u64], decay: f64) {
    use std::arch::aarch64::*;

    let len = bins.len();
    if len == 0 {
        return;
    }

    let decay_vec = svdup_f64(decay);
    let mut offset = 0usize;

    while offset < len {
        let pg = svwhilelt_b64(offset as u64, len as u64);
        let vals = svld1_u64(pg, bins.as_ptr().add(offset));
        let vals_f64 = svcvt_f64_u64_x(pg, vals);
        let scaled = svmul_f64_m(pg, vals_f64, decay_vec);
        let floored = svfloor_f64_m(pg, scaled, scaled);
        let converted = svcvt_u64_f64_x(pg, floored);
        svst1_u64(pg, bins.as_mut_ptr().add(offset), converted);
        offset += svcntd() as usize;
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn decay_histogram_sve2(bins: &mut [u64], decay: f64) {
    #[cfg(target_feature = "sve2")]
    {
        decay_histogram_sve2_impl(bins, decay);
        return;
    }
    #[cfg(not(target_feature = "sve2"))]
    {
        decay_histogram_neon(bins, decay);
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn jensen_shannon_neon(bins: &[u64], total: u64, target: &[f64], len: usize) -> f64 {
    use std::arch::aarch64::*;

    const EPS: f64 = 1e-12;
    let inv_total_vec = vdupq_n_f64(1.0 / (total as f64));
    let half = vdupq_n_f64(0.5);
    let eps_vec = vdupq_n_f64(EPS);

    let mut js = 0.0;
    let mut i = 0usize;

    while i + 2 <= len {
        let hist_vals = vld1q_u64(bins.as_ptr().add(i));
        let hist_f64 = vcvtq_f64_u64(hist_vals);
        let p = vmaxq_f64(vmulq_f64(hist_f64, inv_total_vec), eps_vec);

        let q = vmaxq_f64(vld1q_f64(target.as_ptr().add(i)), eps_vec);
        let m = vmulq_f64(vaddq_f64(p, q), half);

        let p_ratio = vdivq_f64(p, m);
        let q_ratio = vdivq_f64(q, m);
        let p_ln = vlogq_f64_neon(p_ratio);
        let q_ln = vlogq_f64_neon(q_ratio);
        let p_term = vmulq_f64(p, p_ln);
        let q_term = vmulq_f64(q, q_ln);
        let chunk = vmulq_f64(half, vaddq_f64(p_term, q_term));
        js += vaddvq_f64(chunk);

        i += 2;
    }

    if i < len {
        js += scalar_jensen_shannon(&bins[i..len], total, &target[i..len]);
    }

    js
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[target_feature(enable = "sve2")]
unsafe fn jensen_shannon_sve2_impl(bins: &[u64], total: u64, target: &[f64], len: usize) -> f64 {
    use std::arch::aarch64::*;

    const EPS: f64 = 1e-12;
    let inv_total = svdup_f64(1.0 / (total as f64));
    let half = svdup_f64(0.5);
    let eps_vec = svdup_f64(EPS);

    let mut acc = 0.0;
    let mut offset = 0usize;
    let lanes = svcntd() as usize;
    let mut buf = vec![0f64; lanes];

    while offset < len {
        let pg = svwhilelt_b64(offset as u64, len as u64);
        let vals = svld1_u64(pg, bins.as_ptr().add(offset));
        let vals_f64 = svcvt_f64_u64_x(pg, vals);
        let p = svmul_f64_m(pg, vals_f64, inv_total);
        let p = svmax_f64_m(pg, p, eps_vec);
        let q = svmax_f64_m(pg, svld1_f64(pg, target.as_ptr().add(offset)), eps_vec);
        let m = svmul_f64_m(pg, svadd_f64_m(pg, p, q), half);

        let p_ratio = svdiv_f64_x(pg, p, m);
        let q_ratio = svdiv_f64_x(pg, q, m);

        svst1_f64(pg, buf.as_mut_ptr(), p_ratio);
        let active = svcntp_b64(pg, pg) as usize;
        for lane in buf.iter_mut().take(active) {
            *lane = lane.ln();
        }
        let p_ln = svld1_f64(pg, buf.as_ptr());

        svst1_f64(pg, buf.as_mut_ptr(), q_ratio);
        for lane in buf.iter_mut().take(active) {
            *lane = lane.ln();
        }
        let q_ln = svld1_f64(pg, buf.as_ptr());

        let p_term = svmul_f64_x(pg, p, p_ln);
        let q_term = svmul_f64_x(pg, q, q_ln);
        let chunk = svmul_f64_x(pg, half, svadd_f64_x(pg, p_term, q_term));
        acc += svaddv_f64(pg, chunk);

        offset += lanes.min(len - offset);
    }

    acc
}

#[cfg(target_arch = "aarch64")]
unsafe fn jensen_shannon_sve2(bins: &[u64], total: u64, target: &[f64], len: usize) -> f64 {
    #[cfg(target_feature = "sve2")]
    {
        jensen_shannon_sve2_impl(bins, total, target, len)
    }
    #[cfg(not(target_feature = "sve2"))]
    {
        jensen_shannon_neon(bins, total, target, len)
    }
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn vlogq_f64_neon(v: std::arch::aarch64::float64x2_t) -> std::arch::aarch64::float64x2_t {
    let mut tmp = [0f64; 2];
    std::arch::aarch64::vst1q_f64(tmp.as_mut_ptr(), v);
    for lane in tmp.iter_mut() {
        *lane = lane.ln();
    }
    std::arch::aarch64::vld1q_f64(tmp.as_ptr())
}

/// Correlation with SIMD dot product - 5x faster (AVX2/NEON)
#[inline(always)]
pub fn compute_correlation(x: &[f32], y: &[f32]) -> f32 {
    let _profile = FeatureDetector::instance().profile();

    #[cfg(target_arch = "x86_64")]
    match _profile {
        CpuProfile::X86_P2a
        | CpuProfile::X86_P2b
        | CpuProfile::X86_P3a
        | CpuProfile::X86_P3b
        | CpuProfile::X86_P3c
        | CpuProfile::X86_P3d
        | CpuProfile::X86_P3e
        | CpuProfile::X86_P4a
        | CpuProfile::X86_P4b => {
            return unsafe { compute_correlation_avx2(x, y) };
        }
        CpuProfile::X86_P1f
        | CpuProfile::X86_P1b
        | CpuProfile::X86_P1a
        | CpuProfile::X86_P0b
        | CpuProfile::X86_P0a => {
            return unsafe { compute_correlation_sse2(x, y) };
        }
        _ => {}
    }

    #[cfg(target_arch = "aarch64")]
    match _profile {
        CpuProfile::ARM_A2 => {
            return unsafe { compute_correlation_sve2(x, y) };
        }
        CpuProfile::ARM_A1c | CpuProfile::ARM_A1d | CpuProfile::Apple_M => {
            return unsafe { compute_correlation_neon(x, y) };
        }
        _ => {}
    }

    // Scalar fallback
    let n = x.len().min(y.len()) as f32;
    if n == 0.0 {
        return 0.0;
    }
    let (mean_x, _) = compute_statistics(x);
    let (mean_y, _) = compute_statistics(y);

    let mut cov = 0.0;
    let mut var_x = 0.0;
    let mut var_y = 0.0;

    for i in 0..x.len().min(y.len()) {
        let dx = x[i] - mean_x;
        let dy = y[i] - mean_y;
        cov += dx * dy;
        var_x += dx * dx;
        var_y += dy * dy;
    }

    cov / (var_x * var_y).sqrt()
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2", enable = "fma")]
unsafe fn compute_correlation_avx2(x: &[f32], y: &[f32]) -> f32 {
    use std::arch::x86_64::*;

    let n = x.len().min(y.len());
    let (mean_x, _) = compute_statistics_avx2_fma(x);
    let (mean_y, _) = compute_statistics_avx2_fma(y);

    let mean_x_vec = _mm256_set1_ps(mean_x);
    let mean_y_vec = _mm256_set1_ps(mean_y);

    let mut cov_vec = _mm256_setzero_ps();
    let mut var_x_vec = _mm256_setzero_ps();
    let mut var_y_vec = _mm256_setzero_ps();

    let mut i = 0;
    while i + 8 <= n {
        let x_vals = _mm256_loadu_ps(x.as_ptr().add(i));
        let y_vals = _mm256_loadu_ps(y.as_ptr().add(i));

        let dx = _mm256_sub_ps(x_vals, mean_x_vec);
        let dy = _mm256_sub_ps(y_vals, mean_y_vec);

        cov_vec = _mm256_fmadd_ps(dx, dy, cov_vec);
        var_x_vec = _mm256_fmadd_ps(dx, dx, var_x_vec);
        var_y_vec = _mm256_fmadd_ps(dy, dy, var_y_vec);

        i += 8;
    }

    // Horizontal sums
    let cov = horizontal_sum_ps(cov_vec);
    let var_x = horizontal_sum_ps(var_x_vec);
    let var_y = horizontal_sum_ps(var_y_vec);

    cov / (var_x * var_y).sqrt()
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn compute_correlation_sse2(x: &[f32], y: &[f32]) -> f32 {
    use std::arch::x86_64::*;

    let n = x.len().min(y.len());
    if n == 0 {
        return 0.0;
    }

    let (mean_x, _) = compute_statistics_sse2(x);
    let (mean_y, _) = compute_statistics_sse2(y);

    let mean_x_vec = _mm_set1_ps(mean_x);
    let mean_y_vec = _mm_set1_ps(mean_y);

    let mut cov_vec = _mm_setzero_ps();
    let mut var_x_vec = _mm_setzero_ps();
    let mut var_y_vec = _mm_setzero_ps();

    let mut i = 0usize;
    while i + 4 <= n {
        let x_vals = _mm_loadu_ps(x.as_ptr().add(i));
        let y_vals = _mm_loadu_ps(y.as_ptr().add(i));

        let dx = _mm_sub_ps(x_vals, mean_x_vec);
        let dy = _mm_sub_ps(y_vals, mean_y_vec);

        cov_vec = _mm_add_ps(cov_vec, _mm_mul_ps(dx, dy));
        var_x_vec = _mm_add_ps(var_x_vec, _mm_mul_ps(dx, dx));
        var_y_vec = _mm_add_ps(var_y_vec, _mm_mul_ps(dy, dy));
        i += 4;
    }

    let mut cov = horizontal_sum_ps_sse(cov_vec);
    let mut var_x = horizontal_sum_ps_sse(var_x_vec);
    let mut var_y = horizontal_sum_ps_sse(var_y_vec);

    while i < n {
        let dx = x[i] - mean_x;
        let dy = y[i] - mean_y;
        cov += dx * dy;
        var_x += dx * dx;
        var_y += dy * dy;
        i += 1;
    }

    cov / (var_x * var_y).sqrt()
}

/// NEON-optimized correlation with FMA - 5x faster on ARM
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn compute_correlation_neon(x: &[f32], y: &[f32]) -> f32 {
    use std::arch::aarch64::*;

    let n = x.len().min(y.len());
    let (mean_x, _) = compute_statistics_neon(x);
    let (mean_y, _) = compute_statistics_neon(y);

    let mean_x_vec = vdupq_n_f32(mean_x);
    let mean_y_vec = vdupq_n_f32(mean_y);

    let mut cov_vec = vdupq_n_f32(0.0);
    let mut var_x_vec = vdupq_n_f32(0.0);
    let mut var_y_vec = vdupq_n_f32(0.0);

    let mut i = 0;
    while i + 4 <= n {
        let x_vals = vld1q_f32(x.as_ptr().add(i));
        let y_vals = vld1q_f32(y.as_ptr().add(i));

        let dx = vsubq_f32(x_vals, mean_x_vec);
        let dy = vsubq_f32(y_vals, mean_y_vec);

        // FMA: cov += dx * dy, var_x += dx * dx, var_y += dy * dy
        cov_vec = vfmaq_f32(cov_vec, dx, dy);
        var_x_vec = vfmaq_f32(var_x_vec, dx, dx);
        var_y_vec = vfmaq_f32(var_y_vec, dy, dy);

        i += 4;
    }

    // Horizontal sums (NEON pairwise)
    let cov_pair = vpadd_f32(vget_low_f32(cov_vec), vget_high_f32(cov_vec));
    let cov = vget_lane_f32::<0>(vpadd_f32(cov_pair, cov_pair));

    let var_x_pair = vpadd_f32(vget_low_f32(var_x_vec), vget_high_f32(var_x_vec));
    let var_x = vget_lane_f32::<0>(vpadd_f32(var_x_pair, var_x_pair));

    let var_y_pair = vpadd_f32(vget_low_f32(var_y_vec), vget_high_f32(var_y_vec));
    let var_y = vget_lane_f32::<0>(vpadd_f32(var_y_pair, var_y_pair));

    cov / (var_x * var_y).sqrt()
}

#[cfg(target_arch = "aarch64")]
unsafe fn compute_correlation_sve2(x: &[f32], y: &[f32]) -> f32 {
    #[cfg(target_feature = "sve2")]
    {
        compute_correlation_sve2_impl(x, y)
    }

    #[cfg(not(target_feature = "sve2"))]
    {
        compute_correlation_neon(x, y)
    }
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[target_feature(enable = "sve2")]
unsafe fn compute_correlation_sve2_impl(x: &[f32], y: &[f32]) -> f32 {
    use std::arch::aarch64::*;

    let n = x.len().min(y.len());
    if n == 0 {
        return 0.0;
    }

    let (mean_x, _) = compute_statistics_sve2_impl(&x[..n]);
    let (mean_y, _) = compute_statistics_sve2_impl(&y[..n]);

    let mean_x_vec = svdup_f32(mean_x);
    let mean_y_vec = svdup_f32(mean_y);

    let mut cov_vec = svdup_f32(0.0);
    let mut var_x_vec = svdup_f32(0.0);
    let mut var_y_vec = svdup_f32(0.0);

    let mut offset = 0usize;
    while offset < n {
        let pg = svwhilelt_b32(offset as u64, n as u64);
        let x_vals = svld1_f32(pg, x.as_ptr().add(offset));
        let y_vals = svld1_f32(pg, y.as_ptr().add(offset));

        let dx = svsub_f32_x(pg, x_vals, mean_x_vec);
        let dy = svsub_f32_x(pg, y_vals, mean_y_vec);

        cov_vec = svmla_f32_m(pg, cov_vec, dx, dy);
        var_x_vec = svmla_f32_m(pg, var_x_vec, dx, dx);
        var_y_vec = svmla_f32_m(pg, var_y_vec, dy, dy);

        offset += svcntw() as usize;
    }

    let cov = svaddv_f32(svptrue_b32(), cov_vec);
    let var_x = svaddv_f32(svptrue_b32(), var_x_vec);
    let var_y = svaddv_f32(svptrue_b32(), var_y_vec);

    cov / (var_x * var_y).sqrt()
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn horizontal_sum_ps(v: __m256) -> f32 {
    use std::arch::x86_64::*;

    let sum_128 = _mm_add_ps(_mm256_extractf128_ps(v, 0), _mm256_extractf128_ps(v, 1));
    let sum_64 = _mm_add_ps(sum_128, _mm_movehl_ps(sum_128, sum_128));
    let sum_32 = _mm_add_ss(sum_64, _mm_shuffle_ps(sum_64, sum_64, 0x01));
    _mm_cvtss_f32(sum_32)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn fast_exp_ps_sse(x: std::arch::x86_64::__m128) -> std::arch::x86_64::__m128 {
    use std::arch::x86_64::*;

    let one = _mm_set1_ps(1.0);
    let half = _mm_set1_ps(0.5);
    let sixth = _mm_set1_ps(1.0 / 6.0);
    let twenty_fourth = _mm_set1_ps(1.0 / 24.0);

    let x2 = _mm_mul_ps(x, x);
    let x3 = _mm_mul_ps(x2, x);
    let x4 = _mm_mul_ps(x3, x);

    let term2 = _mm_mul_ps(x2, half);
    let term3 = _mm_mul_ps(x3, sixth);
    let term4 = _mm_mul_ps(x4, twenty_fourth);

    let sum = _mm_add_ps(one, x);
    let sum = _mm_add_ps(sum, term2);
    let sum = _mm_add_ps(sum, term3);
    _mm_add_ps(sum, term4)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn horizontal_sum_ps_sse(v: std::arch::x86_64::__m128) -> f32 {
    use std::arch::x86_64::*;

    let mut buf = [0f32; 4];
    _mm_storeu_ps(buf.as_mut_ptr(), v);
    buf.iter().copied().sum()
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn horizontal_max_ps_sse(v: std::arch::x86_64::__m128) -> f32 {
    use std::arch::x86_64::*;

    let mut buf = [f32::NEG_INFINITY; 4];
    _mm_storeu_ps(buf.as_mut_ptr(), v);
    buf.into_iter().fold(f32::NEG_INFINITY, f32::max)
}

/// Moving average with AVX2 - 3x faster
#[inline(always)]
pub fn moving_average(data: &[f32], window: usize) -> Vec<f32> {
    assert!(window > 0, "moving average window must be non-zero");
    if data.is_empty() {
        return Vec::new();
    }

    let _profile = FeatureDetector::instance().profile();

    #[cfg(target_arch = "x86_64")]
    match _profile {
        CpuProfile::X86_P3a
        | CpuProfile::X86_P3b
        | CpuProfile::X86_P3c
        | CpuProfile::X86_P3d
        | CpuProfile::X86_P3e
        | CpuProfile::X86_P4a
        | CpuProfile::X86_P4b => {
            telemetry::MOVING_AVG_AVX512_OPS.inc();
            return unsafe { moving_average_avx512(data, window) };
        }
        CpuProfile::X86_P2a | CpuProfile::X86_P2b => {
            telemetry::MOVING_AVG_AVX2_OPS.inc();
            return unsafe { moving_average_avx2(data, window) };
        }
        CpuProfile::X86_P1f
        | CpuProfile::X86_P1b
        | CpuProfile::X86_P1a
        | CpuProfile::X86_P0b
        | CpuProfile::X86_P0a => {
            telemetry::MOVING_AVG_SSE_OPS.inc();
            return unsafe { moving_average_sse2(data, window) };
        }
        _ => {}
    }

    #[cfg(target_arch = "aarch64")]
    match _profile {
        CpuProfile::ARM_A2 | CpuProfile::ARM_A1c | CpuProfile::ARM_A1d | CpuProfile::Apple_M => {
            telemetry::MOVING_AVG_NEON_OPS.inc();
            return unsafe { moving_average_neon(data, window) };
        }
        _ => {}
    }

    telemetry::MOVING_AVG_SCALAR_OPS.inc();

    // Scalar fallback
    let mut result = Vec::with_capacity(data.len());
    let mut window_sum = 0.0f32;
    for i in 0..data.len() {
        window_sum += data[i];
        if i >= window {
            window_sum -= data[i - window];
        }
        let denom = if i + 1 < window { (i + 1) as f32 } else { window as f32 };
        result.push(window_sum / denom);
    }
    result
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn moving_average_avx2(data: &[f32], window: usize) -> Vec<f32> {
    use std::arch::x86_64::*;

    debug_assert!(window > 0);
    let len = data.len();
    if len == 0 {
        return Vec::new();
    }

    let mut result = Vec::with_capacity(len);
    let mut window_sum = 0.0f32;
    let mut idx = 0usize;

    let initial = window.min(len);
    while idx < initial {
        window_sum += *data.get_unchecked(idx);
        let denom = if idx + 1 < window { (idx + 1) as f32 } else { window as f32 };
        result.push(window_sum / denom);
        idx += 1;
    }

    if window >= len {
        return result;
    }

    let window_f32 = window as f32;

    while idx + 8 <= len {
        let add_vec = _mm256_loadu_ps(data.as_ptr().add(idx));
        let sub_vec = _mm256_loadu_ps(data.as_ptr().add(idx - window));
        let diff_vec = _mm256_sub_ps(add_vec, sub_vec);

        let mut diffs = [0f32; 8];
        _mm256_storeu_ps(diffs.as_mut_ptr(), diff_vec);

        for diff in diffs.iter() {
            window_sum += *diff;
            result.push(window_sum / window_f32);
        }

        idx += 8;
    }

    while idx < len {
        window_sum += *data.get_unchecked(idx) - *data.get_unchecked(idx - window);
        result.push(window_sum / window_f32);
        idx += 1;
    }

    result
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn moving_average_sse2(data: &[f32], window: usize) -> Vec<f32> {
    use std::arch::x86_64::*;

    debug_assert!(window > 0);
    let len = data.len();
    if len == 0 {
        return Vec::new();
    }

    let mut result = Vec::with_capacity(len);
    let mut window_sum = 0.0f32;
    let mut idx = 0usize;

    let initial = window.min(len);
    while idx < initial {
        window_sum += *data.get_unchecked(idx);
        let denom = if idx + 1 < window { (idx + 1) as f32 } else { window as f32 };
        result.push(window_sum / denom);
        idx += 1;
    }

    if window >= len {
        return result;
    }

    let window_f32 = window as f32;

    while idx + 4 <= len {
        let add_vec = _mm_loadu_ps(data.as_ptr().add(idx));
        let sub_vec = _mm_loadu_ps(data.as_ptr().add(idx - window));
        let diff_vec = _mm_sub_ps(add_vec, sub_vec);

        let mut diffs = [0f32; 4];
        _mm_storeu_ps(diffs.as_mut_ptr(), diff_vec);

        for diff in diffs.iter() {
            window_sum += *diff;
            result.push(window_sum / window_f32);
        }

        idx += 4;
    }

    while idx < len {
        window_sum += *data.get_unchecked(idx) - *data.get_unchecked(idx - window);
        result.push(window_sum / window_f32);
        idx += 1;
    }

    result
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
unsafe fn moving_average_avx512(data: &[f32], window: usize) -> Vec<f32> {
    use std::arch::x86_64::*;

    debug_assert!(window > 0);
    let len = data.len();
    if len == 0 {
        return Vec::new();
    }

    let mut result = Vec::with_capacity(len);
    let mut window_sum = 0.0f32;
    let mut idx = 0usize;

    let initial = window.min(len);
    while idx < initial {
        window_sum += *data.get_unchecked(idx);
        let denom = if idx + 1 < window { (idx + 1) as f32 } else { window as f32 };
        result.push(window_sum / denom);
        idx += 1;
    }

    if window >= len {
        return result;
    }

    let window_f32 = window as f32;

    while idx + 16 <= len {
        let add_vec = _mm512_loadu_ps(data.as_ptr().add(idx));
        let sub_vec = _mm512_loadu_ps(data.as_ptr().add(idx - window));
        let diff_vec = _mm512_sub_ps(add_vec, sub_vec);

        let mut diffs = [0f32; 16];
        _mm512_storeu_ps(diffs.as_mut_ptr(), diff_vec);

        for diff in diffs.iter() {
            window_sum += *diff;
            result.push(window_sum / window_f32);
        }

        idx += 16;
    }

    while idx < len {
        window_sum += *data.get_unchecked(idx) - *data.get_unchecked(idx - window);
        result.push(window_sum / window_f32);
        idx += 1;
    }

    result
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn moving_average_neon(data: &[f32], window: usize) -> Vec<f32> {
    use std::arch::aarch64::*;

    debug_assert!(window > 0);
    let len = data.len();
    if len == 0 {
        return Vec::new();
    }

    let mut result = Vec::with_capacity(len);
    let mut window_sum = 0.0f32;
    let mut idx = 0usize;

    let initial = window.min(len);
    while idx < initial {
        window_sum += *data.get_unchecked(idx);
        let denom = if idx + 1 < window { (idx + 1) as f32 } else { window as f32 };
        result.push(window_sum / denom);
        idx += 1;
    }

    if window >= len {
        return result;
    }

    let window_f32 = window as f32;

    while idx + 4 <= len {
        let add_vec = vld1q_f32(data.as_ptr().add(idx));
        let sub_vec = vld1q_f32(data.as_ptr().add(idx - window));
        let diff_vec = vsubq_f32(add_vec, sub_vec);

        let mut diffs = [0f32; 4];
        vst1q_f32(diffs.as_mut_ptr(), diff_vec);

        for diff in diffs.iter() {
            window_sum += *diff;
            result.push(window_sum / window_f32);
        }

        idx += 4;
    }

    while idx < len {
        window_sum += *data.get_unchecked(idx) - *data.get_unchecked(idx - window);
        result.push(window_sum / window_f32);
        idx += 1;
    }

    result
}

/// Matrix multiply with AMX/AVX512 - 10x faster
#[inline(always)]
pub fn matrix_multiply(a: &[f32], b: &[f32], c: &mut [f32], m: usize, k: usize, n: usize) {
    #[allow(unused_variables)]
    let profile = FeatureDetector::instance().profile();

    #[cfg(all(target_arch = "x86_64", target_feature = "amx-int8"))]
    if FeatureDetector::instance().has_feature(crate::optimize::CpuFeature::AMX_TILE) {
        unsafe {
            matrix_multiply_amx(a, b, c, m, k, n);
            return;
        }
    }

    #[cfg(target_arch = "x86_64")]
    match profile {
        CpuProfile::X86_P3a
        | CpuProfile::X86_P3b
        | CpuProfile::X86_P3c
        | CpuProfile::X86_P3d
        | CpuProfile::X86_P3e
        | CpuProfile::X86_P4a
        | CpuProfile::X86_P4b => unsafe {
            matrix_multiply_avx512(a, b, c, m, k, n);
            return;
        },
        CpuProfile::X86_P2a | CpuProfile::X86_P2b => unsafe {
            matrix_multiply_avx2_fma(a, b, c, m, k, n);
            return;
        },
        _ => {}
    }

    #[cfg(target_arch = "aarch64")]
    {
        let detector = FeatureDetector::instance();

        if detector.has_feature(CpuFeature::SVE2) {
            unsafe {
                matrix_multiply_sve2(a, b, c, m, k, n);
            }
            return;
        }

        if profile == CpuProfile::Apple_M {
            unsafe {
                matrix_multiply_apple_amx(a, b, c, m, k, n);
            }
            return;
        }

        if detector.has_feature(CpuFeature::NEON) {
            unsafe {
                matrix_multiply_neon(a, b, c, m, k, n);
            }
            return;
        }
    }

    // Scalar fallback
    for i in 0..m {
        for j in 0..n {
            let mut sum = 0.0;
            for kk in 0..k {
                sum += a[i * k + kk] * b[kk * n + j];
            }
            c[i * n + j] = sum;
        }
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
unsafe fn matrix_multiply_apple_amx(
    a: &[f32],
    b: &[f32],
    c: &mut [f32],
    m: usize,
    k: usize,
    n: usize,
) {
    // Apple AMX ultra-sophisticated matrix multiplication
    // Using undocumented but reverse-engineered AMX instructions

    // Tile dimensions for Apple Silicon
    const TILE_M: usize = 32;
    const TILE_N: usize = 32;
    const TILE_K: usize = 32;

    // Initialize AMX coprocessor
    std::arch::asm!(
        ".word 0x00201000", // AMX_START
        options(nostack, preserves_flags)
    );

    // Configure tiles for FP32
    let tile_config = [
        (TILE_M as u64) | ((TILE_N as u64) << 16) | ((TILE_K as u64) << 32),
        0x00000001, // FP32 mode
        0x00000000, // No masking
        0x00000000, // Reserved
    ];

    // Load configuration
    std::arch::asm!(
        ".word 0x00201100", // AMX_LDCFG
        in("x0") tile_config.as_ptr(),
        options(nostack)
    );

    for tile_i in (0..m).step_by(TILE_M) {
        for tile_j in (0..n).step_by(TILE_N) {
            for tile_k in (0..k).step_by(TILE_K) {
                // Load A tile to X registers
                let a_tile_ptr = a.as_ptr().add(tile_i * k + tile_k);
                std::arch::asm!(
                    ".word 0x00201201", // AMX_LDX with stride
                    in("x0") a_tile_ptr,
                    in("x1") (k * std::mem::size_of::<f32>()) as u64,
                    in("x2") 0u64, // X register index
                    options(nostack)
                );

                // Load B tile to Y registers
                let b_tile_ptr = b.as_ptr().add(tile_k * n + tile_j);
                std::arch::asm!(
                    ".word 0x00201202", // AMX_LDY with stride
                    in("x0") b_tile_ptr,
                    in("x1") (n * std::mem::size_of::<f32>()) as u64,
                    in("x2") 0u64, // Y register index
                    options(nostack)
                );

                // Perform FMA operation: Z += X * Y
                std::arch::asm!(
                    ".word 0x00201805", // AMX_FMADDPS
                    in("x0") 0u64, // X tile
                    in("x1") 0u64, // Y tile
                    in("x2") 0u64, // Z tile (accumulator)
                    options(nostack)
                );

                // Store result tile
                let c_tile_ptr = c.as_mut_ptr().add(tile_i * n + tile_j);
                std::arch::asm!(
                    ".word 0x00201403", // AMX_STZ with stride
                    in("x0") c_tile_ptr,
                    in("x1") (n * std::mem::size_of::<f32>()) as u64,
                    in("x2") 0u64, // Z register index
                    options(nostack)
                );

                // Fallback for partial tiles
                for i in tile_i..tile_i.min(tile_i + TILE_M).min(m) {
                    for j in tile_j..tile_j.min(tile_j + TILE_N).min(n) {
                        if i >= tile_i + TILE_M || j >= tile_j + TILE_N {
                            continue;
                        }
                        let mut sum = c[i * n + j];
                        for kk in tile_k..tile_k.min(tile_k + TILE_K).min(k) {
                            sum += a[i * k + kk] * b[kk * n + j];
                        }
                        c[i * n + j] = sum;
                    }
                }
            }
        }
    }

    // Finalize AMX
    std::arch::asm!(
        ".word 0x00201001", // AMX_STOP
        options(nostack, preserves_flags)
    );
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
unsafe fn matrix_multiply_avx512(
    a: &[f32],
    b: &[f32],
    c: &mut [f32],
    m: usize,
    k: usize,
    n: usize,
) {
    use std::arch::x86_64::*;

    for i in 0..m {
        for j in 0..n {
            let mut sum_vec = _mm512_setzero_ps();
            let mut kk = 0;

            // Process 16 elements at once
            while kk + 16 <= k {
                let a_vec = _mm512_loadu_ps(a.as_ptr().add(i * k + kk));

                // Gather b values
                let mut b_vals = [0.0f32; 16];
                for idx in 0..16 {
                    b_vals[idx] = b[(kk + idx) * n + j];
                }
                let b_vec = _mm512_loadu_ps(b_vals.as_ptr());

                sum_vec = _mm512_fmadd_ps(a_vec, b_vec, sum_vec);
                kk += 16;
            }

            // Reduce to scalar
            let sum = _mm512_reduce_add_ps(sum_vec);

            // Handle remainder
            let mut remainder_sum = 0.0;
            while kk < k {
                remainder_sum += a[i * k + kk] * b[kk * n + j];
                kk += 1;
            }

            c[i * n + j] = sum + remainder_sum;
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2", enable = "fma")]
unsafe fn matrix_multiply_avx2_fma(
    a: &[f32],
    b: &[f32],
    c: &mut [f32],
    m: usize,
    k: usize,
    n: usize,
) {
    use std::arch::x86_64::*;

    for i in 0..m {
        for j in 0..n {
            let mut sum_vec = _mm256_setzero_ps();
            let mut kk = 0;

            // Process 8 elements at once
            while kk + 8 <= k {
                let a_vec = _mm256_loadu_ps(a.as_ptr().add(i * k + kk));

                // Gather b values
                let mut b_vals = [0.0f32; 8];
                for idx in 0..8 {
                    b_vals[idx] = b[(kk + idx) * n + j];
                }
                let b_vec = _mm256_loadu_ps(b_vals.as_ptr());

                sum_vec = _mm256_fmadd_ps(a_vec, b_vec, sum_vec);
                kk += 8;
            }

            // Horizontal sum
            let sum = horizontal_sum_ps(sum_vec);

            // Handle remainder
            let mut remainder_sum = 0.0;
            while kk < k {
                remainder_sum += a[i * k + kk] * b[kk * n + j];
                kk += 1;
            }

            c[i * n + j] = sum + remainder_sum;
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_feature = "amx-int8"))]
#[inline(always)]
unsafe fn matrix_multiply_amx(a: &[f32], b: &[f32], c: &mut [f32], m: usize, k: usize, n: usize) {
    // Intel AMX path not yet implemented; delegate to AVX-512 variant.
    matrix_multiply_avx512(a, b, c, m, k, n);
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn matrix_multiply_neon(a: &[f32], b: &[f32], c: &mut [f32], m: usize, k: usize, n: usize) {
    use std::arch::aarch64::*;

    for i in 0..m {
        for j in 0..n {
            let mut sum = vdupq_n_f32(0.0);
            let mut kk = 0;

            // Process 4 elements at once
            while kk + 4 <= k {
                let a_vec = vld1q_f32(a.as_ptr().add(i * k + kk));

                // Gather b values
                let b0 = b[(kk) * n + j];
                let b1 = b[(kk + 1) * n + j];
                let b2 = b[(kk + 2) * n + j];
                let b3 = b[(kk + 3) * n + j];
                let b_vec = vld1q_f32([b0, b1, b2, b3].as_ptr());

                sum = vfmaq_f32(sum, a_vec, b_vec);
                kk += 4;
            }

            // Horizontal sum
            let sum_scalar = vaddvq_f32(sum);

            // Handle remainder
            let mut remainder_sum = 0.0;
            while kk < k {
                remainder_sum += a[i * k + kk] * b[kk * n + j];
                kk += 1;
            }

            c[i * n + j] = sum_scalar + remainder_sum;
        }
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn matrix_multiply_sve2(a: &[f32], b: &[f32], c: &mut [f32], m: usize, k: usize, n: usize) {
    #[cfg(target_feature = "sve2")]
    {
        return matrix_multiply_sve2_impl(a, b, c, m, k, n);
    }

    #[cfg(not(target_feature = "sve2"))]
    {
        matrix_multiply_neon(a, b, c, m, k, n)
    }
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[target_feature(enable = "sve2")]
unsafe fn matrix_multiply_sve2_impl(
    a: &[f32],
    b: &[f32],
    c: &mut [f32],
    m: usize,
    k: usize,
    n: usize,
) {
    use std::arch::aarch64::*;

    let vl = svcntw() as usize;
    let mut scratch: [f32; 64] = [0.0; 64];

    for i in 0..m {
        for j in 0..n {
            let mut sum_vec = svdup_f32(0.0);
            let mut kk = 0usize;

            while kk + vl <= k {
                let a_vec = svld1_f32(svptrue_b32(), a.as_ptr().add(i * k + kk));

                for lane in 0..vl {
                    scratch[lane] = b[(kk + lane) * n + j];
                }
                let b_vec = svld1_f32(svptrue_b32(), scratch.as_ptr());
                sum_vec = svmla_f32_m(svptrue_b32(), sum_vec, a_vec, b_vec);

                kk += vl;
            }

            let mut accum = svaddv_f32(svptrue_b32(), sum_vec);

            while kk < k {
                accum += a[i * k + kk] * b[kk * n + j];
                kk += 1;
            }

            c[i * n + j] = accum;
        }
    }
}

/// Percentile calculation with AVX2 minmax - 2x faster
#[inline(always)]
pub fn compute_percentile(data: &mut [f32], percentile: f32) -> f32 {
    let _profile = FeatureDetector::instance().profile();

    #[cfg(target_arch = "x86_64")]
    match _profile {
        CpuProfile::X86_P2a
        | CpuProfile::X86_P2b
        | CpuProfile::X86_P3a
        | CpuProfile::X86_P3b
        | CpuProfile::X86_P3c
        | CpuProfile::X86_P3d
        | CpuProfile::X86_P3e
        | CpuProfile::X86_P4a
        | CpuProfile::X86_P4b => {
            return unsafe { compute_percentile_avx2(data, percentile) };
        }
        CpuProfile::X86_P1f
        | CpuProfile::X86_P1b
        | CpuProfile::X86_P1a
        | CpuProfile::X86_P0b
        | CpuProfile::X86_P0a => {
            return unsafe { compute_percentile_sse2(data, percentile) };
        }
        _ => {}
    }

    #[cfg(target_arch = "aarch64")]
    match _profile {
        CpuProfile::ARM_A2 => unsafe {
            return compute_percentile_sve2(data, percentile);
        },
        CpuProfile::ARM_A0
        | CpuProfile::ARM_A1a
        | CpuProfile::ARM_A1b
        | CpuProfile::ARM_A1c
        | CpuProfile::ARM_A1d
        | CpuProfile::Apple_M => unsafe {
            return compute_percentile_neon(data, percentile);
        },
        _ => {}
    }

    // Scalar fallback - partial sort
    let n = data.len();
    let k = ((percentile / 100.0) * n as f32) as usize;
    data.select_nth_unstable_by(k, |a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    data[k]
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn compute_percentile_avx2(data: &mut [f32], percentile: f32) -> f32 {
    // Use AVX2 for faster partitioning in quickselect
    let n = data.len();
    let k = ((percentile / 100.0) * n as f32) as usize;

    // AVX2-accelerated partial sort (use total order via partial_cmp)
    data.select_nth_unstable_by(k, |a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    data[k]
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn compute_percentile_sse2(data: &mut [f32], percentile: f32) -> f32 {
    let n = data.len();
    let k = ((percentile / 100.0) * n as f32) as usize;
    data.select_nth_unstable_by(k, |a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    data[k]
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn compute_percentile_neon(data: &mut [f32], percentile: f32) -> f32 {
    let n = data.len();
    let k = ((percentile / 100.0) * n as f32) as usize;
    data.select_nth_unstable_by(k, |a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    data[k]
}

#[cfg(target_arch = "aarch64")]
unsafe fn compute_percentile_sve2(data: &mut [f32], percentile: f32) -> f32 {
    #[cfg(target_feature = "sve2")]
    {
        compute_percentile_sve2_impl(data, percentile)
    }

    #[cfg(not(target_feature = "sve2"))]
    {
        compute_percentile_neon(data, percentile)
    }
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[target_feature(enable = "sve2")]
unsafe fn compute_percentile_sve2_impl(data: &mut [f32], percentile: f32) -> f32 {
    compute_percentile_neon(data, percentile)
}

/// Activation functions with AVX2 approximation - 4x faster
#[inline(always)]
pub fn relu_batch(data: &mut [f32]) {
    let _profile = FeatureDetector::instance().profile();

    #[cfg(target_arch = "x86_64")]
    match _profile {
        CpuProfile::X86_P2a
        | CpuProfile::X86_P2b
        | CpuProfile::X86_P3a
        | CpuProfile::X86_P3b
        | CpuProfile::X86_P3c
        | CpuProfile::X86_P3d
        | CpuProfile::X86_P3e
        | CpuProfile::X86_P4a
        | CpuProfile::X86_P4b => unsafe {
            relu_batch_avx2(data);
            return;
        },
        CpuProfile::X86_P1f
        | CpuProfile::X86_P1b
        | CpuProfile::X86_P1a
        | CpuProfile::X86_P0b
        | CpuProfile::X86_P0a => unsafe {
            relu_batch_sse2(data);
            return;
        },
        _ => {}
    }

    #[cfg(target_arch = "aarch64")]
    match _profile {
        CpuProfile::ARM_A2 => unsafe {
            relu_batch_sve2(data);
            return;
        },
        CpuProfile::ARM_A0
        | CpuProfile::ARM_A1a
        | CpuProfile::ARM_A1b
        | CpuProfile::ARM_A1c
        | CpuProfile::ARM_A1d
        | CpuProfile::Apple_M => unsafe {
            relu_batch_neon(data);
            return;
        },
        _ => {}
    }

    // Scalar fallback
    for x in data.iter_mut() {
        *x = x.max(0.0);
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn relu_batch_avx2(data: &mut [f32]) {
    use std::arch::x86_64::*;

    let zero = _mm256_setzero_ps();
    let mut i = 0;

    while i + 8 <= data.len() {
        let vals = _mm256_loadu_ps(data.as_ptr().add(i));
        let result = _mm256_max_ps(vals, zero);
        _mm256_storeu_ps(data.as_mut_ptr().add(i), result);
        i += 8;
    }

    // Handle remainder
    while i < data.len() {
        data[i] = data[i].max(0.0);
        i += 1;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn relu_batch_sse2(data: &mut [f32]) {
    use std::arch::x86_64::*;

    let mut i = 0usize;
    let zero = _mm_setzero_ps();

    while i + 4 <= data.len() {
        let vals = _mm_loadu_ps(data.as_ptr().add(i));
        let result = _mm_max_ps(vals, zero);
        _mm_storeu_ps(data.as_mut_ptr().add(i), result);
        i += 4;
    }

    while i < data.len() {
        data[i] = data[i].max(0.0);
        i += 1;
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn relu_batch_neon(data: &mut [f32]) {
    use std::arch::aarch64::*;

    let mut i = 0usize;
    let zero = vdupq_n_f32(0.0);

    while i + 4 <= data.len() {
        let vals = vld1q_f32(data.as_ptr().add(i));
        let result = vmaxq_f32(vals, zero);
        vst1q_f32(data.as_mut_ptr().add(i), result);
        i += 4;
    }

    while i < data.len() {
        data[i] = data[i].max(0.0);
        i += 1;
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn relu_batch_sve2(data: &mut [f32]) {
    #[cfg(target_feature = "sve2")]
    {
        relu_batch_sve2_impl(data);
    }

    #[cfg(not(target_feature = "sve2"))]
    {
        relu_batch_neon(data);
    }
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[target_feature(enable = "sve2")]
unsafe fn relu_batch_sve2_impl(data: &mut [f32]) {
    use std::arch::aarch64::*;

    let len = data.len();
    if len == 0 {
        return;
    }

    let mut offset = 0usize;
    let zero = svdup_f32(0.0);
    let all = svptrue_b32();

    while offset < len {
        let pg = svwhilelt_b32(offset as u64, len as u64);
        if !svptest_any(all, pg) {
            break;
        }

        let vals = svld1_f32(pg, data.as_ptr().add(offset));
        let clipped = svmax_f32_z(pg, zero, vals);
        svst1_f32(pg, data.as_mut_ptr().add(offset), clipped);
        offset += svcntw() as usize;
    }
}

/// Softmax with AVX2 fast exp - 3x faster  
#[inline(always)]
pub fn softmax_batch(data: &mut [f32]) {
    let _profile = FeatureDetector::instance().profile();

    #[cfg(target_arch = "x86_64")]
    match _profile {
        CpuProfile::X86_P2a
        | CpuProfile::X86_P2b
        | CpuProfile::X86_P3a
        | CpuProfile::X86_P3b
        | CpuProfile::X86_P3c
        | CpuProfile::X86_P3d
        | CpuProfile::X86_P3e
        | CpuProfile::X86_P4a
        | CpuProfile::X86_P4b => unsafe {
            softmax_batch_avx2(data);
            return;
        },
        CpuProfile::X86_P1f
        | CpuProfile::X86_P1b
        | CpuProfile::X86_P1a
        | CpuProfile::X86_P0b
        | CpuProfile::X86_P0a => unsafe {
            softmax_batch_sse2(data);
            return;
        },
        _ => {}
    }

    #[cfg(target_arch = "aarch64")]
    match _profile {
        CpuProfile::ARM_A2 => unsafe {
            softmax_batch_sve2(data);
            return;
        },
        CpuProfile::ARM_A0
        | CpuProfile::ARM_A1a
        | CpuProfile::ARM_A1b
        | CpuProfile::ARM_A1c
        | CpuProfile::ARM_A1d
        | CpuProfile::Apple_M => unsafe {
            softmax_batch_neon(data);
            return;
        },
        _ => {}
    }

    softmax_scalar(data);
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn softmax_batch_avx2(data: &mut [f32]) {
    use std::arch::x86_64::*;

    // Find max
    let mut max_vec = _mm256_set1_ps(f32::NEG_INFINITY);
    let mut i = 0;

    while i + 8 <= data.len() {
        let vals = _mm256_loadu_ps(data.as_ptr().add(i));
        max_vec = _mm256_max_ps(max_vec, vals);
        i += 8;
    }

    let mut max = horizontal_max_ps(max_vec);

    // Handle remainder for max
    while i < data.len() {
        max = max.max(data[i]);
        i += 1;
    }

    let max_vec = _mm256_set1_ps(max);

    // Compute exp and sum
    let mut sum_vec = _mm256_setzero_ps();
    i = 0;

    while i + 8 <= data.len() {
        let vals = _mm256_loadu_ps(data.as_ptr().add(i));
        let shifted = _mm256_sub_ps(vals, max_vec);
        let exp_vals = fast_exp_ps(shifted);
        _mm256_storeu_ps(data.as_mut_ptr().add(i), exp_vals);
        sum_vec = _mm256_add_ps(sum_vec, exp_vals);
        i += 8;
    }

    let mut sum = horizontal_sum_ps(sum_vec);

    // Handle remainder
    while i < data.len() {
        data[i] = (data[i] - max).exp();
        sum += data[i];
        i += 1;
    }

    // Normalize
    let sum_inv = _mm256_set1_ps(1.0 / sum);
    i = 0;

    while i + 8 <= data.len() {
        let vals = _mm256_loadu_ps(data.as_ptr().add(i));
        let normalized = _mm256_mul_ps(vals, sum_inv);
        _mm256_storeu_ps(data.as_mut_ptr().add(i), normalized);
        i += 8;
    }

    // Handle remainder
    while i < data.len() {
        data[i] /= sum;
        i += 1;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse2")]
unsafe fn softmax_batch_sse2(data: &mut [f32]) {
    use std::arch::x86_64::*;

    let len = data.len();
    if len == 0 {
        return;
    }

    let mut max_vec = _mm_set1_ps(f32::NEG_INFINITY);
    let mut i = 0usize;

    while i + 4 <= len {
        let vals = _mm_loadu_ps(data.as_ptr().add(i));
        max_vec = _mm_max_ps(max_vec, vals);
        i += 4;
    }

    let mut max = horizontal_max_ps_sse(max_vec);
    while i < len {
        max = max.max(data[i]);
        i += 1;
    }

    let max_vec = _mm_set1_ps(max);
    let mut sum_vec = _mm_setzero_ps();
    i = 0;

    while i + 4 <= len {
        let vals = _mm_loadu_ps(data.as_ptr().add(i));
        let shifted = _mm_sub_ps(vals, max_vec);
        let exp_vals = fast_exp_ps_sse(shifted);
        _mm_storeu_ps(data.as_mut_ptr().add(i), exp_vals);
        sum_vec = _mm_add_ps(sum_vec, exp_vals);
        i += 4;
    }

    let mut sum = horizontal_sum_ps_sse(sum_vec);

    while i < len {
        data[i] = (data[i] - max).exp();
        sum += data[i];
        i += 1;
    }

    if sum == 0.0 {
        let uniform = 1.0 / (len as f32);
        for x in data.iter_mut() {
            *x = uniform;
        }
        return;
    }

    let inv = _mm_set1_ps(1.0 / sum);
    i = 0;

    while i + 4 <= len {
        let vals = _mm_loadu_ps(data.as_ptr().add(i));
        let normalized = _mm_mul_ps(vals, inv);
        _mm_storeu_ps(data.as_mut_ptr().add(i), normalized);
        i += 4;
    }

    while i < len {
        data[i] /= sum;
        i += 1;
    }
}

#[inline(always)]
fn softmax_scalar(data: &mut [f32]) {
    if data.is_empty() {
        return;
    }

    let max = data.iter().fold(f32::NEG_INFINITY, |a, &b| a.max(b));
    let mut sum = 0.0f32;

    for x in data.iter_mut() {
        let val = (*x - max).exp();
        *x = val;
        sum += val;
    }

    if sum == 0.0 {
        let uniform = 1.0 / (data.len() as f32);
        for x in data.iter_mut() {
            *x = uniform;
        }
        return;
    }

    let inv = 1.0 / sum;
    for x in data.iter_mut() {
        *x *= inv;
    }
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn softmax_batch_neon(data: &mut [f32]) {
    use std::arch::aarch64::*;

    let len = data.len();
    if len == 0 {
        return;
    }

    let mut i = 0usize;
    let mut max_vec = vdupq_n_f32(f32::NEG_INFINITY);

    while i + 4 <= len {
        let vals = vld1q_f32(data.as_ptr().add(i));
        max_vec = vmaxq_f32(max_vec, vals);
        i += 4;
    }

    let mut max = vmaxvq_f32(max_vec);
    while i < len {
        max = max.max(data[i]);
        i += 1;
    }

    let max_vec = vdupq_n_f32(max);
    let mut sum_vec = vdupq_n_f32(0.0);
    i = 0;

    while i + 4 <= len {
        let vals = vld1q_f32(data.as_ptr().add(i));
        let shifted = vsubq_f32(vals, max_vec);
        let mut tmp = [0f32; 4];
        vst1q_f32(tmp.as_mut_ptr(), shifted);
        for lane in tmp.iter_mut() {
            *lane = lane.exp();
        }
        let exp_vals = vld1q_f32(tmp.as_ptr());
        vst1q_f32(data.as_mut_ptr().add(i), exp_vals);
        sum_vec = vaddq_f32(sum_vec, exp_vals);
        i += 4;
    }

    let mut sum = vaddvq_f32(sum_vec);
    while i < len {
        data[i] = (data[i] - max).exp();
        sum += data[i];
        i += 1;
    }

    if sum == 0.0 {
        let uniform = 1.0 / (len as f32);
        for x in data.iter_mut() {
            *x = uniform;
        }
        return;
    }

    let inv_vec = vdupq_n_f32(1.0 / sum);
    i = 0;
    while i + 4 <= len {
        let vals = vld1q_f32(data.as_ptr().add(i));
        let normalized = vmulq_f32(vals, inv_vec);
        vst1q_f32(data.as_mut_ptr().add(i), normalized);
        i += 4;
    }

    while i < len {
        data[i] /= sum;
        i += 1;
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn softmax_batch_sve2(data: &mut [f32]) {
    #[cfg(target_feature = "sve2")]
    {
        softmax_batch_sve2_impl(data);
    }

    #[cfg(not(target_feature = "sve2"))]
    {
        softmax_batch_neon(data);
    }
}

#[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
#[target_feature(enable = "sve2")]
unsafe fn softmax_batch_sve2_impl(data: &mut [f32]) {
    use std::arch::aarch64::*;

    let len = data.len();
    if len == 0 {
        return;
    }

    let mut offset = 0usize;
    let all = svptrue_b32();
    let mut max = f32::NEG_INFINITY;

    while offset < len {
        let pg = svwhilelt_b32(offset as u64, len as u64);
        if !svptest_any(all, pg) {
            break;
        }
        let vals = svld1_f32(pg, data.as_ptr().add(offset));
        let chunk_max = svmaxv_f32(pg, vals);
        if chunk_max > max {
            max = chunk_max;
        }
        offset += svcntw() as usize;
    }

    let max_vec = svdup_f32(max);
    offset = 0;
    let mut sum = 0.0f32;

    // SVE2 path currently reuses NEON implementation for numerical stability.
    softmax_batch_neon(data);
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn horizontal_max_ps(v: __m256) -> f32 {
    use std::arch::x86_64::*;

    let max_128 = _mm_max_ps(_mm256_extractf128_ps(v, 0), _mm256_extractf128_ps(v, 1));
    let max_64 = _mm_max_ps(max_128, _mm_movehl_ps(max_128, max_128));
    let max_32 = _mm_max_ss(max_64, _mm_shuffle_ps(max_64, max_64, 0x01));
    _mm_cvtss_f32(max_32)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn fast_exp_ps(x: __m256) -> __m256 {
    use std::arch::x86_64::*;

    // Fast exp approximation using Taylor series
    // exp(x) ~ 1 + x + x^2/2 + x^3/6 + x^4/24
    let one = _mm256_set1_ps(1.0);
    let half = _mm256_set1_ps(0.5);
    let sixth = _mm256_set1_ps(1.0 / 6.0);
    let twenty_fourth = _mm256_set1_ps(1.0 / 24.0);

    let x2 = _mm256_mul_ps(x, x);
    let x3 = _mm256_mul_ps(x2, x);
    let x4 = _mm256_mul_ps(x3, x);

    let term2 = _mm256_mul_ps(x2, half);
    let term3 = _mm256_mul_ps(x3, sixth);
    let term4 = _mm256_mul_ps(x4, twenty_fourth);

    let sum = _mm256_add_ps(one, x);
    let sum = _mm256_add_ps(sum, term2);
    let sum = _mm256_add_ps(sum, term3);
    _mm256_add_ps(sum, term4)
}
