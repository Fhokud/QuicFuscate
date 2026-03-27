#![cfg(feature = "rust-tests")]
use quicfuscate::accelerate::stealth;
use quicfuscate::optimize::simd::compress;
use quicfuscate::optimize::telemetry::{
    PATTERN_NEON_OPS, PATTERN_SVE2_OPS, PLAN_DECISIONS_DEFAULT, PLAN_DECISIONS_LEN,
    PLAN_DECISIONS_TOTAL,
};
use quicfuscate::simd::CryptoAeadPlan;

fn run_pattern_workload() {
    let mut buffer = vec![0u8; 256];
    for (idx, byte) in buffer.iter_mut().enumerate() {
        *byte = (idx as u8).wrapping_mul(13);
    }
    let pattern = b"\xAA\xBB\xCC\x00";
    let positions = [8usize, 64, 128];
    stealth::inject_pattern(&mut buffer, pattern, &positions);

    let haystack = buffer.clone();
    let _ = compress::histogram(&haystack);
    let _ = compress::find_pattern(&haystack, pattern);
}

#[test]
fn telemetry_counters_snapshot() {
    let base_total = PLAN_DECISIONS_TOTAL.get();
    let base_default = PLAN_DECISIONS_DEFAULT.get();
    let base_len = PLAN_DECISIONS_LEN.get();
    let base_pattern_neon = PATTERN_NEON_OPS.get();
    let base_pattern_sve2 = PATTERN_SVE2_OPS.get();

    // Exercise the AEAD planner in both default and length-sensitive modes.
    CryptoAeadPlan::select();
    for len in [32usize, 512, 4096, 1 << 15] {
        CryptoAeadPlan::select_for_len(len);
    }

    // Exercise stealth pattern helpers (NEON on Apple M profiles, SVE2 if available).
    run_pattern_workload();

    let total = PLAN_DECISIONS_TOTAL.get();
    let default = PLAN_DECISIONS_DEFAULT.get();
    let len = PLAN_DECISIONS_LEN.get();
    let pattern_neon = PATTERN_NEON_OPS.get();
    let pattern_sve2 = PATTERN_SVE2_OPS.get();

    assert!(
        total > base_total,
        "expected PLAN_DECISIONS_TOTAL to increase ({} -> {})",
        base_total,
        total
    );
    assert!(
        default > base_default,
        "expected PLAN_DECISIONS_DEFAULT to increase ({} -> {})",
        base_default,
        default
    );
    assert!(
        len >= base_len + 4,
        "expected PLAN_DECISIONS_LEN to increase by >=4 ({} -> {})",
        base_len,
        len
    );
    // NEON is only available on aarch64; on x86_64 the counter stays at zero.
    if cfg!(target_arch = "aarch64") {
        assert!(
            pattern_neon > base_pattern_neon,
            "expected PATTERN_NEON_OPS to increase on aarch64 ({} -> {})",
            base_pattern_neon,
            pattern_neon
        );
    } else {
        assert!(
            pattern_neon >= base_pattern_neon,
            "PATTERN_NEON_OPS should be monotonic on non-aarch64 ({} -> {})",
            base_pattern_neon,
            pattern_neon
        );
    }

    // SVE2 may be unavailable on the current host; record the observed value for telemetry audit.
    println!(
        "telemetry_snapshot: total={} default={} len={} pattern_neon={} pattern_sve2={}",
        total, default, len, pattern_neon, pattern_sve2
    );
    assert!(
        pattern_sve2 >= base_pattern_sve2,
        "PATTERN_SVE2_OPS should be monotonic ({} -> {})",
        base_pattern_sve2,
        pattern_sve2
    );
}
