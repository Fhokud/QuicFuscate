#![cfg(feature = "rust-tests")]

use std::sync::Mutex;

use quicfuscate::optimize::{self, CpuProfile};

static OVERRIDE_LOCK: Mutex<()> = Mutex::new(());

#[cfg(target_arch = "x86_64")]
#[test]
fn sum_u32_sse2_matches_scalar() {
    let _guard = OVERRIDE_LOCK.lock().unwrap();
    let mut rng = fastrand::Rng::with_seed(0xD15EA5E5);
    let data: Vec<u32> = (0..4096).map(|_| rng.u32(..)).collect();

    optimize::clear_profile_override_for_tests();
    assert!(optimize::set_profile_override_for_tests(CpuProfile::Scalar));
    let scalar = optimize::iter::sum_u32(&data);

    assert!(optimize::set_profile_override_for_tests(CpuProfile::X86_P0a));
    let simd = optimize::iter::sum_u32(&data);

    optimize::clear_profile_override_for_tests();
    assert_eq!(scalar, simd);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn sum_u32_neon_matches_scalar() {
    let _guard = OVERRIDE_LOCK.lock().unwrap();
    let mut rng = fastrand::Rng::with_seed(0xD15EA5E5);
    let data: Vec<u32> = (0..4096).map(|_| rng.u32(..)).collect();

    optimize::clear_profile_override_for_tests();
    assert!(optimize::set_profile_override_for_tests(CpuProfile::Scalar));
    let scalar = optimize::iter::sum_u32(&data);

    assert!(optimize::set_profile_override_for_tests(CpuProfile::ARM_A0));
    let simd = optimize::iter::sum_u32(&data);

    optimize::clear_profile_override_for_tests();
    assert_eq!(scalar, simd);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn sum_f32_sse2_matches_scalar() {
    let _guard = OVERRIDE_LOCK.lock().unwrap();
    let mut rng = fastrand::Rng::with_seed(0xC0FFEE42);
    let data: Vec<f32> = (0..2048).map(|_| rng.f32() * 2000.0 - 1000.0).collect();

    optimize::clear_profile_override_for_tests();
    assert!(optimize::set_profile_override_for_tests(CpuProfile::Scalar));
    let scalar = optimize::iter::sum_f32(&data);

    assert!(optimize::set_profile_override_for_tests(CpuProfile::X86_P0a));
    let simd = optimize::iter::sum_f32(&data);

    optimize::clear_profile_override_for_tests();
    let diff = (scalar - simd).abs();
    let tol = (data.len() as f32) * 1e-3;
    assert!(diff <= tol, "sum_f32 mismatch: scalar={scalar} simd={simd} diff={diff} tol={tol}");
}

#[cfg(target_arch = "aarch64")]
#[test]
fn sum_f32_neon_matches_scalar() {
    let _guard = OVERRIDE_LOCK.lock().unwrap();
    let mut rng = fastrand::Rng::with_seed(0xC0FFEE42);
    let data: Vec<f32> = (0..2048).map(|_| rng.f32() * 2000.0 - 1000.0).collect();

    optimize::clear_profile_override_for_tests();
    assert!(optimize::set_profile_override_for_tests(CpuProfile::Scalar));
    let scalar = optimize::iter::sum_f32(&data);

    assert!(optimize::set_profile_override_for_tests(CpuProfile::ARM_A0));
    let simd = optimize::iter::sum_f32(&data);

    optimize::clear_profile_override_for_tests();
    let diff = (scalar - simd).abs();
    let tol = (data.len() as f32) * 1e-3;
    assert!(diff <= tol, "sum_f32 mismatch: scalar={scalar} simd={simd} diff={diff} tol={tol}");
}

#[cfg(target_arch = "x86_64")]
#[test]
fn compress_classify_sse2_matches_scalar() {
    let _guard = OVERRIDE_LOCK.lock().unwrap();
    let mut rng = fastrand::Rng::with_seed(0x5A11_0C0D);
    let bytes: Vec<u8> = (0..8192).map(|_| rng.u8(..)).collect();

    optimize::clear_profile_override_for_tests();
    assert!(optimize::set_profile_override_for_tests(CpuProfile::Scalar));
    let scalar = optimize::compress::classify(&bytes);

    assert!(optimize::set_profile_override_for_tests(CpuProfile::X86_P0a));
    let simd = optimize::compress::classify(&bytes);

    optimize::clear_profile_override_for_tests();
    assert_eq!(scalar.len, simd.len);
    assert_eq!(scalar.ascii_printable, simd.ascii_printable);
    assert_eq!(scalar.newline, simd.newline);
    assert_eq!(scalar.carriage_return, simd.carriage_return);
    assert_eq!(scalar.tab, simd.tab);
    assert_eq!(scalar.nulls, simd.nulls);
    assert_eq!(scalar.high_bytes, simd.high_bytes);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn compress_classify_neon_matches_scalar() {
    let _guard = OVERRIDE_LOCK.lock().unwrap();
    let mut rng = fastrand::Rng::with_seed(0x5A11_0C0D);
    let bytes: Vec<u8> = (0..8192).map(|_| rng.u8(..)).collect();

    optimize::clear_profile_override_for_tests();
    assert!(optimize::set_profile_override_for_tests(CpuProfile::Scalar));
    let scalar = optimize::compress::classify(&bytes);

    assert!(optimize::set_profile_override_for_tests(CpuProfile::ARM_A0));
    let simd = optimize::compress::classify(&bytes);

    optimize::clear_profile_override_for_tests();
    assert_eq!(scalar.len, simd.len);
    assert_eq!(scalar.ascii_printable, simd.ascii_printable);
    assert_eq!(scalar.newline, simd.newline);
    assert_eq!(scalar.carriage_return, simd.carriage_return);
    assert_eq!(scalar.tab, simd.tab);
    assert_eq!(scalar.nulls, simd.nulls);
    assert_eq!(scalar.high_bytes, simd.high_bytes);
}
