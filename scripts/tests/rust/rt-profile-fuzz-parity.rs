#![cfg(feature = "rust-tests")]

use std::sync::Mutex;

use quicfuscate::optimize::{self, CpuProfile};

static OVERRIDE_LOCK: Mutex<()> = Mutex::new(());

fn run_sum_f32_cases(simd_profile: CpuProfile) {
    let mut rng = fastrand::Rng::with_seed(0xA11C_EE1D);
    for len in [1usize, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 256, 511, 1024] {
        for _ in 0..64 {
            let mut data = Vec::with_capacity(len);
            for _ in 0..len {
                data.push(rng.f32() * 2000.0 - 1000.0);
            }

            optimize::clear_profile_override_for_tests();
            assert!(optimize::set_profile_override_for_tests(CpuProfile::Scalar));
            let scalar = optimize::iter::sum_f32(&data);

            assert!(optimize::set_profile_override_for_tests(simd_profile));
            let simd = optimize::iter::sum_f32(&data);

            let diff = (scalar - simd).abs();
            let tol = (len as f32).max(1.0) * 1e-3;
            assert!(
                diff <= tol,
                "sum_f32 mismatch: len={len} scalar={scalar} simd={simd} diff={diff} tol={tol}"
            );
        }
    }
}

fn run_sum_u32_cases(simd_profile: CpuProfile) {
    let mut rng = fastrand::Rng::with_seed(0xB16B_00B5);
    for len in [1usize, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 256, 1024] {
        for _ in 0..64 {
            let mut data = Vec::with_capacity(len);
            for _ in 0..len {
                data.push(rng.u32(..));
            }

            optimize::clear_profile_override_for_tests();
            assert!(optimize::set_profile_override_for_tests(CpuProfile::Scalar));
            let scalar = optimize::iter::sum_u32(&data);

            assert!(optimize::set_profile_override_for_tests(simd_profile));
            let simd = optimize::iter::sum_u32(&data);

            assert_eq!(scalar, simd, "sum_u32 mismatch: len={len}");
        }
    }
}

fn run_sum_u64_cases(simd_profile: CpuProfile) {
    let mut rng = fastrand::Rng::with_seed(0xFEED_BEEF);
    for len in [1usize, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 256] {
        for _ in 0..64 {
            let mut data = Vec::with_capacity(len);
            for _ in 0..len {
                let hi = rng.u32(..) as u64;
                let lo = rng.u32(..) as u64;
                data.push((hi << 32) | lo);
            }

            optimize::clear_profile_override_for_tests();
            assert!(optimize::set_profile_override_for_tests(CpuProfile::Scalar));
            let scalar = optimize::iter::sum_u64(&data);

            assert!(optimize::set_profile_override_for_tests(simd_profile));
            let simd = optimize::iter::sum_u64(&data);

            assert_eq!(scalar, simd, "sum_u64 mismatch: len={len}");
        }
    }
}

fn run_compress_cases(simd_profile: CpuProfile) {
    let mut rng = fastrand::Rng::with_seed(0x5A11_0C0D);
    for len in [1usize, 2, 7, 8, 15, 16, 31, 64, 127, 256, 1024, 4096] {
        for _ in 0..32 {
            let bytes: Vec<u8> = (0..len).map(|_| rng.u8(..)).collect();

            optimize::clear_profile_override_for_tests();
            assert!(optimize::set_profile_override_for_tests(CpuProfile::Scalar));
            let scalar = optimize::compress::classify(&bytes);

            assert!(optimize::set_profile_override_for_tests(simd_profile));
            let simd = optimize::compress::classify(&bytes);

            assert_eq!(scalar.len, simd.len);
            assert_eq!(scalar.ascii_printable, simd.ascii_printable);
            assert_eq!(scalar.newline, simd.newline);
            assert_eq!(scalar.carriage_return, simd.carriage_return);
            assert_eq!(scalar.tab, simd.tab);
            assert_eq!(scalar.nulls, simd.nulls);
            assert_eq!(scalar.high_bytes, simd.high_bytes);
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
fn fuzz_parity_x86_sse2() {
    let _guard = OVERRIDE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let simd_profile = CpuProfile::X86_P0a;
    assert!(optimize::set_profile_override_for_tests(simd_profile));
    optimize::clear_profile_override_for_tests();

    run_sum_f32_cases(simd_profile);
    run_sum_u32_cases(simd_profile);
    run_sum_u64_cases(simd_profile);
    run_compress_cases(simd_profile);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn fuzz_parity_arm_neon() {
    let _guard = OVERRIDE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let simd_profile = CpuProfile::ARM_A0;
    assert!(optimize::set_profile_override_for_tests(simd_profile));
    optimize::clear_profile_override_for_tests();

    run_sum_f32_cases(simd_profile);
    run_sum_u32_cases(simd_profile);
    run_sum_u64_cases(simd_profile);
    run_compress_cases(simd_profile);
}
