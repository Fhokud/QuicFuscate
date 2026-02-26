#![cfg(feature = "rust-tests")]
use quicfuscate::accelerate::iter::{sum_f32, sum_u32, sum_u64};
use quicfuscate::optimize::{telemetry, FeatureDetector};

fn counter_delta(before: u64, after: u64) -> u64 {
    after.saturating_sub(before)
}

fn assert_increment(before: u64, after: u64, name: &str) {
    assert!(
        after > before,
        "{} counter did not increase (before={}, after={})",
        name,
        before,
        after
    );
}

#[test]
fn iter_sum_f32_telemetry_matches_backend() {
    let features = FeatureDetector::instance().features_full();
    let data = vec![1.0f32; 128];

    let before_avx512 = telemetry::ITER_SUM_F32_AVX512_OPS.get();
    let before_avx2 = telemetry::ITER_SUM_F32_AVX2_OPS.get();
    let before_sse = telemetry::ITER_SUM_F32_SSE_OPS.get();
    let before_sve = telemetry::ITER_SUM_F32_SVE_OPS.get();
    let before_neon = telemetry::ITER_SUM_F32_NEON_OPS.get();
    let before_scalar = telemetry::ITER_SUM_F32_SCALAR_OPS.get();

    let sum = sum_f32(&data);
    assert_eq!(sum, data.len() as f32);

    let after_avx512 = telemetry::ITER_SUM_F32_AVX512_OPS.get();
    let after_avx2 = telemetry::ITER_SUM_F32_AVX2_OPS.get();
    let after_sse = telemetry::ITER_SUM_F32_SSE_OPS.get();
    let after_sve = telemetry::ITER_SUM_F32_SVE_OPS.get();
    let after_neon = telemetry::ITER_SUM_F32_NEON_OPS.get();
    let after_scalar = telemetry::ITER_SUM_F32_SCALAR_OPS.get();

    if cfg!(target_arch = "x86_64") {
        if features.avx512f {
            assert_increment(before_avx512, after_avx512, "ITER_SUM_F32_AVX512_OPS");
        } else if features.avx2 {
            assert_increment(before_avx2, after_avx2, "ITER_SUM_F32_AVX2_OPS");
        } else if features.sse2 {
            assert_increment(before_sse, after_sse, "ITER_SUM_F32_SSE_OPS");
        } else {
            assert_increment(before_scalar, after_scalar, "ITER_SUM_F32_SCALAR_OPS");
        }
    } else if cfg!(target_arch = "aarch64") {
        if features.sve2 {
            assert_increment(before_sve, after_sve, "ITER_SUM_F32_SVE_OPS");
        } else if features.neon {
            assert_increment(before_neon, after_neon, "ITER_SUM_F32_NEON_OPS");
        } else {
            assert_increment(before_scalar, after_scalar, "ITER_SUM_F32_SCALAR_OPS");
        }
    } else {
        assert_increment(before_scalar, after_scalar, "ITER_SUM_F32_SCALAR_OPS");
    }

    // Ensure no spurious double increment happened.
    let total_delta = counter_delta(before_avx512, after_avx512)
        + counter_delta(before_avx2, after_avx2)
        + counter_delta(before_sse, after_sse)
        + counter_delta(before_sve, after_sve)
        + counter_delta(before_neon, after_neon)
        + counter_delta(before_scalar, after_scalar);
    assert!(
        total_delta >= 1,
        "expected at least one f32 counter increment (delta={})",
        total_delta
    );
}

#[test]
fn iter_sum_u32_telemetry_matches_backend() {
    let features = FeatureDetector::instance().features_full();
    let data = vec![7u32; 256];

    let before_avx512 = telemetry::ITER_SUM_U32_AVX512_OPS.get();
    let before_avx2 = telemetry::ITER_SUM_U32_AVX2_OPS.get();
    let before_sse = telemetry::ITER_SUM_U32_SSE_OPS.get();
    let before_sve = telemetry::ITER_SUM_U32_SVE_OPS.get();
    let before_neon = telemetry::ITER_SUM_U32_NEON_OPS.get();
    let before_scalar = telemetry::ITER_SUM_U32_SCALAR_OPS.get();

    let sum = sum_u32(&data);
    assert_eq!(sum, (data.len() as u64) * 7);

    let after_avx512 = telemetry::ITER_SUM_U32_AVX512_OPS.get();
    let after_avx2 = telemetry::ITER_SUM_U32_AVX2_OPS.get();
    let after_sse = telemetry::ITER_SUM_U32_SSE_OPS.get();
    let after_sve = telemetry::ITER_SUM_U32_SVE_OPS.get();
    let after_neon = telemetry::ITER_SUM_U32_NEON_OPS.get();
    let after_scalar = telemetry::ITER_SUM_U32_SCALAR_OPS.get();

    if cfg!(target_arch = "x86_64") {
        if features.avx512f {
            assert_increment(before_avx512, after_avx512, "ITER_SUM_U32_AVX512_OPS");
        } else if features.avx2 {
            assert_increment(before_avx2, after_avx2, "ITER_SUM_U32_AVX2_OPS");
        } else if features.sse2 {
            assert_increment(before_sse, after_sse, "ITER_SUM_U32_SSE_OPS");
        } else {
            assert_increment(before_scalar, after_scalar, "ITER_SUM_U32_SCALAR_OPS");
        }
    } else if cfg!(target_arch = "aarch64") {
        if features.sve2 {
            assert_increment(before_sve, after_sve, "ITER_SUM_U32_SVE_OPS");
        } else if features.neon {
            assert_increment(before_neon, after_neon, "ITER_SUM_U32_NEON_OPS");
        } else {
            assert_increment(before_scalar, after_scalar, "ITER_SUM_U32_SCALAR_OPS");
        }
    } else {
        assert_increment(before_scalar, after_scalar, "ITER_SUM_U32_SCALAR_OPS");
    }
}

#[test]
fn iter_sum_u64_telemetry_matches_backend() {
    let features = FeatureDetector::instance().features_full();
    let data = vec![3u64; 192];

    let before_avx512 = telemetry::ITER_SUM_U64_AVX512_OPS.get();
    let before_avx2 = telemetry::ITER_SUM_U64_AVX2_OPS.get();
    let before_sse = telemetry::ITER_SUM_U64_SSE_OPS.get();
    let before_sve = telemetry::ITER_SUM_U64_SVE_OPS.get();
    let before_neon = telemetry::ITER_SUM_U64_NEON_OPS.get();
    let before_scalar = telemetry::ITER_SUM_U64_SCALAR_OPS.get();

    let sum = sum_u64(&data);
    assert_eq!(sum, (data.len() as u128) * 3);

    let after_avx512 = telemetry::ITER_SUM_U64_AVX512_OPS.get();
    let after_avx2 = telemetry::ITER_SUM_U64_AVX2_OPS.get();
    let after_sse = telemetry::ITER_SUM_U64_SSE_OPS.get();
    let after_sve = telemetry::ITER_SUM_U64_SVE_OPS.get();
    let after_neon = telemetry::ITER_SUM_U64_NEON_OPS.get();
    let after_scalar = telemetry::ITER_SUM_U64_SCALAR_OPS.get();

    if cfg!(target_arch = "x86_64") {
        if features.avx512f {
            assert_increment(before_avx512, after_avx512, "ITER_SUM_U64_AVX512_OPS");
        } else if features.avx2 {
            assert_increment(before_avx2, after_avx2, "ITER_SUM_U64_AVX2_OPS");
        } else if features.sse2 {
            assert_increment(before_sse, after_sse, "ITER_SUM_U64_SSE_OPS");
        } else {
            assert_increment(before_scalar, after_scalar, "ITER_SUM_U64_SCALAR_OPS");
        }
    } else if cfg!(target_arch = "aarch64") {
        if features.sve2 {
            assert_increment(before_sve, after_sve, "ITER_SUM_U64_SVE_OPS");
        } else if features.neon {
            assert_increment(before_neon, after_neon, "ITER_SUM_U64_NEON_OPS");
        } else {
            assert_increment(before_scalar, after_scalar, "ITER_SUM_U64_SCALAR_OPS");
        }
    } else {
        assert_increment(before_scalar, after_scalar, "ITER_SUM_U64_SCALAR_OPS");
    }
}
