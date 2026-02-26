#![cfg(feature = "rust-tests")]
use quicfuscate::accelerate::sort::argsort;

fn expected_indices<T: PartialOrd>(data: &[T]) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..data.len()).collect();
    idx.sort_unstable_by(|&i, &j| data[i].partial_cmp(&data[j]).unwrap());
    idx
}

#[test]
fn argsort_f32_small_matches_scalar() {
    let samples: Vec<Vec<f32>> = vec![
        vec![],
        vec![42.0],
        vec![3.0, -1.0],
        vec![8.0, 4.0, 2.0, 7.0, 6.0, 1.0, 3.0, 5.0],
        vec![1.5, 1.5, -2.0, 9.0, 0.0],
    ];

    for sample in samples {
        assert_eq!(argsort(&sample), expected_indices(&sample));
    }

    let mut rng = fastrand::Rng::with_seed(12345);
    for _ in 0..32 {
        let len = rng.usize(..=8);
        let mut data = Vec::with_capacity(len);
        for _ in 0..len {
            data.push(rng.f32() * 200.0 - 100.0);
        }
        assert_eq!(argsort(&data), expected_indices(&data));
    }
}

#[test]
fn argsort_f32_large_matches_scalar() {
    let mut rng = fastrand::Rng::with_seed(6789);
    for len in [16usize, 64, 257] {
        let mut data = Vec::with_capacity(len);
        for _ in 0..len {
            data.push(rng.f32());
        }
        assert_eq!(argsort(&data), expected_indices(&data));
    }
}

#[test]
fn argsort_generic_types() {
    let ints = vec![5i32, 2, 9, 1, -3, 1];
    let floats = vec![5.0f64, -2.0, 0.5, 0.5];

    assert_eq!(argsort(&ints), expected_indices(&ints));
    assert_eq!(argsort(&floats), expected_indices(&floats));
}
