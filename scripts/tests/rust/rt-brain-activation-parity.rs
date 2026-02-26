#![cfg(feature = "rust-tests")]
use quicfuscate::accelerate::brain::{compute_percentile, relu_batch, softmax_batch};

fn scalar_relu(data: &mut [f32]) {
    for x in data.iter_mut() {
        *x = x.max(0.0);
    }
}

fn scalar_softmax(data: &mut [f32]) {
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

fn scalar_percentile(mut data: Vec<f32>, percentile: f32) -> f32 {
    let n = data.len();
    let k = ((percentile / 100.0) * n as f32) as usize;
    data.select_nth_unstable_by(k, |a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    data[k]
}

#[test]
fn relu_batch_matches_scalar() {
    let mut rng = fastrand::Rng::with_seed(0x6DE0_BA53_1234_5678);

    for len in [1usize, 2, 3, 4, 7, 8, 16, 31, 64, 127, 256] {
        for _ in 0..64 {
            let mut simd = (0..len).map(|_| rng.f32() * 40.0 - 20.0).collect::<Vec<f32>>();
            let mut scalar = simd.clone();

            relu_batch(&mut simd);
            scalar_relu(&mut scalar);

            assert!(
                simd.iter().zip(&scalar).all(|(a, b)| a.to_bits() == b.to_bits()),
                "relu mismatch for len={}: simd={:?}, scalar={:?}",
                len,
                simd,
                scalar
            );
        }
    }
}

#[test]
fn softmax_batch_matches_scalar() {
    let mut rng = fastrand::Rng::with_seed(0x1357_9BDF_2468_ABCD);

    for len in [1usize, 2, 3, 4, 5, 7, 8, 16, 32, 64, 96] {
        for _ in 0..64 {
            let mut simd = (0..len).map(|_| rng.f32() * 12.0 - 6.0).collect::<Vec<f32>>();
            let mut scalar = simd.clone();

            softmax_batch(&mut simd);
            scalar_softmax(&mut scalar);

            let mut diff_sum = 0.0f32;
            for (a, b) in simd.iter().zip(&scalar) {
                assert!(
                    (*a - *b).abs() <= 1e-3,
                    "softmax lane mismatch len={}, a={}, b={}",
                    len,
                    a,
                    b
                );
                diff_sum += *a;
            }

            assert!(
                (diff_sum - 1.0).abs() <= 1e-3,
                "softmax sum != 1 (len={}, sum={})",
                len,
                diff_sum
            );
        }
    }
}

#[test]
fn percentile_matches_scalar() {
    let mut rng = fastrand::Rng::with_seed(0x4242_1701_DEAD_BEEF);
    let percentiles = [0.0f32, 5.0, 12.5, 25.0, 50.0, 75.0, 90.0, 95.0, 99.0];

    for len in [1usize, 5, 16, 31, 64, 128, 257] {
        for &pct in &percentiles {
            let data = (0..len).map(|_| rng.f32() * 200.0 - 100.0).collect::<Vec<f32>>();
            let mut simd_data = data.clone();

            let reference = scalar_percentile(data.clone(), pct);
            let simd_value = compute_percentile(&mut simd_data, pct);

            assert!(
                (simd_value - reference).abs() <= 1e-5,
                "percentile mismatch len={}, pct={}, simd={}, reference={}",
                len,
                pct,
                simd_value,
                reference
            );
        }
    }
}
