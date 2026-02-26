#![cfg(feature = "rust-tests")]
use quicfuscate::optimize::simd::core::xor_repeating_key_32;

fn xor_scalar(dst: &mut [u8], key32: &[u8; 32]) {
    for i in 0..dst.len() {
        dst[i] ^= key32[i % 32];
    }
}

#[test]
fn xor_repeating_key_32_parity_various_lengths() {
    let key: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];
    let lengths = [0usize, 1, 15, 16, 31, 32, 33, 64, 127, 128, 513];

    for &n in &lengths {
        let mut a: Vec<u8> = (0..n as u32).map(|x| (x as u8).wrapping_mul(17)).collect();
        let mut b = a.clone();

        xor_repeating_key_32(&mut a, &key);
        xor_scalar(&mut b, &key);

        assert_eq!(a, b, "parity mismatch at length {}", n);
    }
}
