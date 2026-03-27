#![cfg(feature = "rust-tests")]
use rand::{rngs::StdRng, Rng, SeedableRng};

fn scalar_decay(mut bins: Vec<u64>, decay: f64) -> Vec<u64> {
    let decay = decay.clamp(0.0, 1.0);
    if decay == 1.0 {
        return bins;
    }
    if decay == 0.0 {
        bins.iter_mut().for_each(|b| *b = 0);
        return bins;
    }
    for b in bins.iter_mut() {
        *b = ((*b as f64) * decay).floor() as u64;
    }
    bins
}

fn scalar_js(bins: &[u64], total: u64, target: &[f64]) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let inv_total = 1.0 / (total as f64);
    const EPS: f64 = 1e-12;
    bins.iter()
        .zip(target.iter())
        .map(|(&bin, &q_raw)| {
            let p = (bin as f64) * inv_total;
            let p = p.max(EPS);
            let q = q_raw.max(EPS);
            let m = 0.5 * (p + q);
            0.5 * p * (p / m).ln() + 0.5 * q * (q / m).ln()
        })
        .sum()
}

#[test]
fn decay_histogram_matches_scalar() {
    let mut rng = StdRng::seed_from_u64(0xBAD5_EED5);
    for &decay in &[0.0, 0.25, 0.5, 0.98, 1.0] {
        let bins: Vec<u64> = (0..32).map(|_| rng.random_range(0..10_000)).collect();
        let mut accel_bins = bins.clone();
        quicfuscate::accelerate::brain::decay_histogram(&mut accel_bins, decay);
        let expected = scalar_decay(bins.clone(), decay);
        assert_eq!(accel_bins, expected, "decay {} mismatch", decay);
    }
}

#[test]
fn jensen_shannon_matches_scalar() {
    let mut rng = StdRng::seed_from_u64(0xFEED_C0DE);
    for bins_len in [8usize, 16, 31, 64] {
        let mut bins: Vec<u64> = (0..bins_len).map(|_| rng.random_range(0..5000)).collect();
        if bins.iter().all(|&v| v == 0) {
            bins[0] = 1;
        }
        let total = bins.iter().sum::<u64>().max(1);
        let mut target: Vec<f64> =
            (0..bins_len).map(|_| rng.random_range(0.0..1.0) + 1e-6).collect();
        let target_sum: f64 = target.iter().sum();
        for v in target.iter_mut() {
            *v /= target_sum;
        }

        let expected = scalar_js(&bins, total, &target);
        let accel =
            quicfuscate::accelerate::brain::jensen_shannon_divergence(&bins, total, &target);
        assert!(
            (expected - accel).abs() < 1e-9,
            "divergence mismatch (len={bins_len}): expected {expected}, accel {accel}"
        );
    }
}

#[test]
fn jensen_shannon_extreme_shapes() {
    fn normalize(target: &mut [f64]) {
        let sum: f64 = target.iter().copied().sum::<f64>().max(1e-12);
        for v in target.iter_mut() {
            *v /= sum;
            *v = v.max(1e-12);
        }
    }

    let cases: &[(Vec<u64>, Vec<f64>, &str)] = &[
        (vec![10_000, 0, 0, 0], vec![0.97, 0.01, 0.01, 0.01], "single_peak_bins_vs_soft_target"),
        (vec![1, 0, 0, 0], vec![0.25, 0.25, 0.25, 0.25], "delta_bins_vs_uniform_target"),
        (vec![1, 1, 1, 1], vec![0.999_996, 1e-6, 1e-6, 1e-6], "flat_bins_vs_spiky_target"),
        (vec![0, 0, 0, 1], vec![1e-6, 1e-6, 0.5, 0.5 - 2e-6], "tail_heavy_bins_vs_tail_target"),
    ];

    for (mut bins, mut target, label) in cases.iter().cloned() {
        if bins.iter().all(|&v| v == 0) {
            bins[0] = 1;
        }
        normalize(&mut target);
        let total = bins.iter().sum::<u64>().max(1);
        let expected = scalar_js(&bins, total, &target);
        let accel =
            quicfuscate::accelerate::brain::jensen_shannon_divergence(&bins, total, &target);
        assert!(
            (expected - accel).abs() < 1e-9,
            "divergence mismatch ({label}): expected {expected}, accel {accel}"
        );
    }
}

#[test]
fn decay_histogram_extremes() {
    let decay_values = [0.0, 0.01, 0.5, 0.999, 1.0];
    let cases: &[(&str, Vec<u64>)] = &[
        ("single_peak", vec![10_000, 0, 0, 0]),
        ("saturated", vec![u64::MAX, u64::MAX / 2, 42, 0]),
        ("tiny_counts", vec![1, 1, 0, 0]),
    ];

    for &decay in &decay_values {
        for (label, bins) in cases {
            let mut accel_bins = bins.clone();
            quicfuscate::accelerate::brain::decay_histogram(&mut accel_bins, decay);
            let expected = scalar_decay(bins.clone(), decay);
            assert_eq!(accel_bins, expected, "decay {decay} mismatch ({label})");
        }
    }
}

#[cfg(all(feature = "simd-selfcheck", target_arch = "x86_64"))]
#[test]
fn decay_histogram_x86_backends_match_scalar() {
    let mut rng = StdRng::seed_from_u64(0x5EED_1DEA);
    for &decay in &[0.0, 0.125, 0.5, 0.9375, 1.0] {
        let bins: Vec<u64> = (0..32).map(|_| rng.random_range(0..100_000)).collect();
        let expected = scalar_decay(bins.clone(), decay);

        if std::is_x86_feature_detected!("avx512f")
            && std::is_x86_feature_detected!("avx512bw")
            && std::is_x86_feature_detected!("avx512dq")
        {
            let mut avx512_bins = bins.clone();
            quicfuscate::accelerate::brain::__test_decay_histogram_avx512(&mut avx512_bins, decay);
            assert_eq!(avx512_bins, expected, "AVX-512 decay mismatch for decay={decay}");
        }

        if std::is_x86_feature_detected!("avx2") {
            let mut avx2_bins = bins.clone();
            quicfuscate::accelerate::brain::__test_decay_histogram_avx2(&mut avx2_bins, decay);
            assert_eq!(avx2_bins, expected, "AVX2 decay mismatch for decay={decay}");
        }

        if std::is_x86_feature_detected!("sse4.1") {
            let mut sse_bins = bins.clone();
            quicfuscate::accelerate::brain::__test_decay_histogram_sse41(&mut sse_bins, decay);
            assert_eq!(sse_bins, expected, "SSE4.1 decay mismatch for decay={decay}");
        }
    }
}

#[cfg(all(feature = "simd-selfcheck", target_arch = "x86_64"))]
#[test]
fn jensen_shannon_x86_backends_match_scalar() {
    let mut rng = StdRng::seed_from_u64(0xD0C5_1DED);
    for bins_len in [8usize, 16, 31, 64] {
        let mut bins: Vec<u64> = (0..bins_len).map(|_| rng.random_range(0..10_000)).collect();
        if bins.iter().all(|&v| v == 0) {
            bins[0] = 1;
        }
        let total = bins.iter().sum::<u64>().max(1);
        let mut target: Vec<f64> =
            (0..bins_len).map(|_| rng.random_range(0.0..1.0) + 1e-6).collect();
        let target_sum: f64 = target.iter().sum();
        for v in target.iter_mut() {
            *v /= target_sum;
        }

        let expected = scalar_js(&bins, total, &target);

        if std::is_x86_feature_detected!("avx512f")
            && std::is_x86_feature_detected!("avx512bw")
            && std::is_x86_feature_detected!("avx512dq")
        {
            let val =
                quicfuscate::accelerate::brain::__test_jensen_shannon_avx512(&bins, total, &target);
            assert!((expected - val).abs() < 1e-9, "AVX-512 JS divergence mismatch");
        }

        if std::is_x86_feature_detected!("avx2") {
            let val =
                quicfuscate::accelerate::brain::__test_jensen_shannon_avx2(&bins, total, &target);
            assert!((expected - val).abs() < 1e-9, "AVX2 JS divergence mismatch");
        }

        if std::is_x86_feature_detected!("sse4.1") {
            let val =
                quicfuscate::accelerate::brain::__test_jensen_shannon_sse41(&bins, total, &target);
            assert!((expected - val).abs() < 1e-9, "SSE4.1 JS divergence mismatch");
        }
    }
}
