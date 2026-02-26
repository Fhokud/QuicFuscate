#![cfg(feature = "rust-tests")]
use quicfuscate::accelerate::iter;
use quicfuscate::optimize::telemetry;

fn random_f32_data() -> Vec<f32> {
    let mut data = Vec::new();
    for i in -64..128 {
        data.push(i as f32 * 0.25);
    }
    data
}

fn random_u32_data() -> Vec<u32> {
    (0..257).map(|v| (v as u32).wrapping_mul(37)).collect()
}

fn random_u64_data() -> Vec<u64> {
    (0..193).map(|v| (v as u64).wrapping_mul(1_000_003)).collect()
}

#[test]
fn sum_f32_matches_scalar() {
    let data = random_f32_data();
    let before = (
        telemetry::ITER_SUM_F32_AVX512_OPS.get(),
        telemetry::ITER_SUM_F32_AVX2_OPS.get(),
        telemetry::ITER_SUM_F32_NEON_OPS.get(),
        telemetry::ITER_SUM_F32_SCALAR_OPS.get(),
    );

    for len in 0..=data.len() {
        let expected: f32 = data[..len].iter().copied().sum();
        let simd = iter::sum_f32(&data[..len]);
        assert!((expected - simd).abs() < 1e-4, "len={} expected={} simd={}", len, expected, simd);
    }

    let after = (
        telemetry::ITER_SUM_F32_AVX512_OPS.get(),
        telemetry::ITER_SUM_F32_AVX2_OPS.get(),
        telemetry::ITER_SUM_F32_NEON_OPS.get(),
        telemetry::ITER_SUM_F32_SCALAR_OPS.get(),
    );
    assert!(
        after.0 > before.0 || after.1 > before.1 || after.2 > before.2 || after.3 > before.3,
        "no sum_f32 telemetry delta"
    );
}

#[test]
fn sum_u32_matches_scalar() {
    let data = random_u32_data();
    let before = (
        telemetry::ITER_SUM_U32_AVX512_OPS.get(),
        telemetry::ITER_SUM_U32_AVX2_OPS.get(),
        telemetry::ITER_SUM_U32_NEON_OPS.get(),
        telemetry::ITER_SUM_U32_SCALAR_OPS.get(),
    );

    for len in 0..=data.len() {
        let expected: u64 = data[..len].iter().fold(0u64, |acc, &v| acc + v as u64);
        let simd = iter::sum_u32(&data[..len]);
        assert_eq!(expected, simd, "len={} expected={} simd={}", len, expected, simd);
    }

    let after = (
        telemetry::ITER_SUM_U32_AVX512_OPS.get(),
        telemetry::ITER_SUM_U32_AVX2_OPS.get(),
        telemetry::ITER_SUM_U32_NEON_OPS.get(),
        telemetry::ITER_SUM_U32_SCALAR_OPS.get(),
    );
    assert!(
        after.0 > before.0 || after.1 > before.1 || after.2 > before.2 || after.3 > before.3,
        "no sum_u32 telemetry delta"
    );
}

#[test]
fn sum_u64_matches_scalar() {
    let data = random_u64_data();
    let before = (
        telemetry::ITER_SUM_U64_AVX512_OPS.get(),
        telemetry::ITER_SUM_U64_AVX2_OPS.get(),
        telemetry::ITER_SUM_U64_NEON_OPS.get(),
        telemetry::ITER_SUM_U64_SCALAR_OPS.get(),
    );

    for len in 0..=data.len() {
        let expected: u128 = data[..len].iter().fold(0u128, |acc, &v| acc + v as u128);
        let simd = iter::sum_u64(&data[..len]);
        assert_eq!(expected, simd, "len={} expected={} simd={}", len, expected, simd);
    }

    let after = (
        telemetry::ITER_SUM_U64_AVX512_OPS.get(),
        telemetry::ITER_SUM_U64_AVX2_OPS.get(),
        telemetry::ITER_SUM_U64_NEON_OPS.get(),
        telemetry::ITER_SUM_U64_SCALAR_OPS.get(),
    );
    assert!(
        after.0 > before.0 || after.1 > before.1 || after.2 > before.2 || after.3 > before.3,
        "no sum_u64 telemetry delta"
    );
}
