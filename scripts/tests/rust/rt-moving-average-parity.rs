#![cfg(feature = "rust-tests")]
use quicfuscate::accelerate::brain::moving_average;

fn moving_average_scalar_reference(data: &[f32], window: usize) -> Vec<f32> {
    assert!(window > 0, "window must be positive");
    if data.is_empty() {
        return Vec::new();
    }

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

fn assert_almost_eq(lhs: &[f32], rhs: &[f32]) {
    assert_eq!(lhs.len(), rhs.len(), "length mismatch: {} vs {}", lhs.len(), rhs.len());
    for (idx, (a, b)) in lhs.iter().zip(rhs.iter()).enumerate() {
        let diff = (a - b).abs();
        let tol = 1e-4f32.max(1e-6f32 * a.abs().max(b.abs()));
        assert!(
            diff <= tol,
            "mismatch at index {}: lhs={} rhs={} diff={} tol={}",
            idx,
            a,
            b,
            diff,
            tol
        );
    }
}

#[test]
fn moving_average_matches_scalar_on_various_windows() {
    let fixtures: &[&[f32]] =
        &[&[], &[1.0], &[1.0, 2.0], &[3.0, -1.0, 4.0, 2.0], &[0.5, -0.5, 1.5, -1.5, 2.5]];

    for &data in fixtures {
        for window in 1..=8 {
            let output = moving_average(data, window);
            let expected = if data.is_empty() {
                Vec::new()
            } else {
                moving_average_scalar_reference(data, window)
            };
            assert_almost_eq(&output, &expected);
        }
    }
}

#[test]
fn moving_average_randomised_regression() {
    let mut rng = fastrand::Rng::new();
    for _ in 0..128 {
        let len = rng.usize(0..=128);
        let window = rng.usize(1..=192);
        let mut data = Vec::with_capacity(len);
        for _ in 0..len {
            data.push(rng.f32() * 200.0 - 100.0);
        }

        let simd = moving_average(&data, window);
        let scalar = if data.is_empty() {
            Vec::new()
        } else {
            moving_average_scalar_reference(&data, window)
        };
        assert_almost_eq(&simd, &scalar);
    }
}
