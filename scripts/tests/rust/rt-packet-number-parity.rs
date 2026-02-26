#![cfg(feature = "rust-tests")]
use quicfuscate::accelerate::transport::decode_packet_number;

fn decode_packet_number_scalar(encoded: u32, expected: u64, pn_len: u8) -> u64 {
    if pn_len == 0 {
        return expected;
    }

    let pn_bits = (pn_len as u32) * 8;
    let mask = if pn_bits == 64 { u64::MAX } else { (1u64 << pn_bits) - 1 };
    let truncated = encoded as u64 & mask;
    let expected_pn = expected.wrapping_add(1);
    let candidate = (expected_pn & !mask) | truncated;

    let range = 1u128 << pn_bits;
    let pn_win = 1u128 << (pn_bits - 1);
    let candidate128 = candidate as u128;
    let expected128 = expected_pn as u128;

    if candidate128 + pn_win <= expected128 {
        (candidate128 + range) as u64
    } else if candidate128 > expected128 + pn_win && candidate128 >= range {
        (candidate128 - range) as u64
    } else {
        candidate
    }
}

#[test]
fn packet_number_decode_matches_scalar_reference() {
    let mut rng = fastrand::Rng::with_seed(0x1357_2468_9ABC_DEF0);

    for pn_len in 1u8..=4 {
        for _ in 0..10_000 {
            let encoded = rng.u32(..);
            let expected = rng.u64(..);

            let simd = decode_packet_number(encoded, expected, pn_len);
            let reference = decode_packet_number_scalar(encoded, expected, pn_len);
            assert_eq!(
                simd, reference,
                "mismatch for pn_len={}, encoded={:#x}, expected={:#x}",
                pn_len, encoded, expected
            );
        }
    }
}

#[test]
fn packet_number_decode_handles_boundaries() {
    let test_vectors = [
        (0x00u32, 0u64, 1u8),
        (0xFFu32, u64::MAX - 255, 1u8),
        (0xFFFFu32, u64::MAX - 65_535, 2u8),
        (0x12_34_56u32, 0xFFFF_FFFFu64, 3u8),
        (0x89_AB_CDu32, 0x1234_5678_9ABC_DEF0u64, 4u8),
    ];

    for &(encoded, expected, pn_len) in &test_vectors {
        let simd = decode_packet_number(encoded, expected, pn_len);
        let reference = decode_packet_number_scalar(encoded, expected, pn_len);
        assert_eq!(
            simd, reference,
            "boundary mismatch for pn_len={}, encoded={:#x}, expected={:#x}",
            pn_len, encoded, expected
        );
    }
}
