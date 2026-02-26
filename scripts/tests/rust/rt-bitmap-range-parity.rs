#![cfg(feature = "rust-tests")]
use quicfuscate::accelerate::transport::bitmap_set_range;

fn bitmap_set_range_reference(bitmap: &mut [u64], start: usize, end: usize) {
    for i in start..=end {
        let word = i / 64;
        let bit = i % 64;
        if word < bitmap.len() {
            bitmap[word] |= 1u64 << bit;
        }
    }
}

#[test]
fn bitmap_range_matches_scalar_reference() {
    let mut rng = fastrand::Rng::with_seed(0x4F1D_2A37_9C85_FB10);

    for words in [1usize, 2, 3, 4, 8, 16, 32, 48] {
        for _ in 0..1_000 {
            let max_bit = words * 64 + 256;
            let start = rng.usize(..max_bit);
            let span = rng.usize(..512);
            let end = start.saturating_add(span);

            let mut simd = vec![0u64; words];
            let mut scalar = vec![0u64; words];

            bitmap_set_range(&mut simd, start, end);
            bitmap_set_range_reference(&mut scalar, start, end);

            assert_eq!(simd, scalar, "mismatch for words={}, start={}, end={}", words, start, end);
        }
    }
}

#[test]
fn bitmap_range_handles_edge_cases() {
    let mut bitmap = vec![0u64; 4];
    bitmap_set_range(&mut bitmap, 0, 0);
    let mut reference = vec![0u64; 4];
    bitmap_set_range_reference(&mut reference, 0, 0);
    assert_eq!(bitmap, reference);

    bitmap.fill(0);
    reference.fill(0);
    bitmap_set_range(&mut bitmap, 10, 250);
    bitmap_set_range_reference(&mut reference, 10, 250);
    assert_eq!(bitmap, reference);

    bitmap.fill(0);
    reference.fill(0);
    bitmap_set_range(&mut bitmap, 250, 10);
    bitmap_set_range_reference(&mut reference, 250, 10);
    assert_eq!(bitmap, reference);

    bitmap.fill(0);
    reference.fill(0);
    bitmap_set_range(&mut bitmap, 1024, 1500);
    bitmap_set_range_reference(&mut reference, 1024, 1500);
    assert_eq!(bitmap, reference);

    let mut empty: Vec<u64> = Vec::new();
    bitmap_set_range(&mut empty, 0, 10);
}
