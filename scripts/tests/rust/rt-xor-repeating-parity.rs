#![cfg(feature = "rust-tests")]
use quicfuscate::optimize::simd::core::xor_repeating_key;

fn xor_scalar(dst: &mut [u8], key: &[u8], start: usize) {
    if key.is_empty() {
        return;
    }
    let key_len = key.len();
    let mut idx = start % key_len;
    for byte in dst.iter_mut() {
        *byte ^= key[idx];
        idx += 1;
        if idx == key_len {
            idx = 0;
        }
    }
}

#[test]
fn xor_repeating_matches_scalar_across_sizes() {
    let mut rng = fastrand::Rng::with_seed(0xC0FFEE);
    let key_lengths = [1usize, 2, 3, 4, 5, 7, 8, 16, 24, 32, 33, 48, 64, 96, 128];
    let payload_lengths = [0usize, 1, 3, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 511, 512];

    for &key_len in &key_lengths {
        let mut key = vec![0u8; key_len];
        rng.fill(&mut key);

        for &payload_len in &payload_lengths {
            let mut data = vec![0u8; payload_len];
            rng.fill(&mut data);

            // Try several start offsets, including > key_len.
            for start in [0usize, 1, key_len / 2, key_len.saturating_sub(1), key_len * 3 + 5] {
                let mut simd = data.clone();
                let mut reference = data.clone();

                xor_repeating_key(&mut simd, &key, start);
                xor_scalar(&mut reference, &key, start);

                assert_eq!(
                    simd, reference,
                    "mismatch for key_len={}, payload_len={}, start={}",
                    key_len, payload_len, start
                );
            }
        }
    }
}

#[test]
fn xor_repeating_honours_empty_inputs() {
    let mut buffer = Vec::<u8>::new();
    xor_repeating_key(&mut buffer, &[], 0);
    assert!(buffer.is_empty());
}
