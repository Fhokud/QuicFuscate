#![cfg(feature = "rust-tests")]
use quicfuscate::simd::transport as t;

#[test]
fn varint_roundtrip_boundaries() {
    let values: [u64; 9] = [
        0,
        1,
        63,               // 1-byte max
        64,               // 2-byte start
        16_383,           // 2-byte max
        16_384,           // 4-byte start
        (1u64 << 30) - 1, // 4-byte max
        1u64 << 30,       // 8-byte start
        (1u64 << 62) - 1, // 8-byte max
    ];

    for &v in &values {
        let mut buf = [0u8; 16];
        let len = t::encode_varint(v, &mut buf);
        assert!(len > 0 && len <= 8, "encode_varint len invalid for {}: {}", v, len);
        let (dec, used) = t::decode_varint(&buf[..len]).expect("decode_varint failed");
        assert_eq!(dec, v, "roundtrip value mismatch for {}", v);
        assert_eq!(used, len, "decode used != encode len for {}", v);
    }
}
