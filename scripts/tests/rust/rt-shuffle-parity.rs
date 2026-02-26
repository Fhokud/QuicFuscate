#![cfg(feature = "rust-tests")]
use quicfuscate::accelerate::random;

#[test]
fn shuffle_preserves_multiset_small_arrays() {
    for len in 2..=8 {
        let mut data: Vec<u32> = (0..len as u32).collect();
        random::shuffle(&mut data);
        let mut sorted = data.clone();
        sorted.sort_unstable();
        let expected: Vec<u32> = (0..len as u32).collect();
        assert_eq!(sorted, expected, "shuffle corrupted elements for len={}", len);
    }
}

#[test]
fn shuffle_preserves_multiset_medium_arrays() {
    let mut data: Vec<u32> = (0..64).collect();
    for _ in 0..16 {
        random::shuffle(&mut data);
        let mut sorted = data.clone();
        sorted.sort_unstable();
        let expected: Vec<u32> = (0..64).collect();
        assert_eq!(sorted, expected);
    }
}
