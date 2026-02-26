#![cfg(feature = "rust-tests")]
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use quicfuscate::accelerate::string::base64_decode;

#[test]
fn base64_decode_matches_scalar_reference() {
    let mut rng = fastrand::Rng::new();

    let mut lens = vec![
        0usize, 1, 2, 3, 4, 5, 6, 7, 8, 15, 16, 17, 23, 24, 25, 31, 32, 33, 47, 48, 63, 64, 65,
        127, 128, 129, 255, 256, 257, 511, 512,
    ];
    lens.extend((0..128).map(|_| rng.usize(0..1024)));

    for len in lens {
        let data: Vec<u8> = (0..len).map(|_| rng.u8(0..=255)).collect();
        let encoded = STANDARD.encode(&data);

        let decoded =
            base64_decode(&encoded).expect("SIMD base64 decode should succeed on valid input");
        assert_eq!(decoded, data, "decoded payload must match original for len {}", len);
    }
}

#[test]
fn base64_decode_rejects_invalid_input() {
    let invalid_inputs = [
        "****",
        "abc%",
        "A===A",
        "YWJj\r\nZGU=", // unsolicited whitespace
    ];

    for s in invalid_inputs {
        assert!(base64_decode(s).is_none(), "input {:?} must be rejected", s);
    }
}
