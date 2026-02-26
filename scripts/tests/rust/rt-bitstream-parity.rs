#![cfg(feature = "rust-tests")]

use quicfuscate::simd::bitstream;

#[test]
fn bitstream_pack_unpack_roundtrip_all_widths() {
    for bit_width in 1u8..=8 {
        let values_len = 257usize;
        let mask = if bit_width == 8 { 0xFF } else { (1u16 << bit_width) as u8 - 1 };
        let mut src = vec![0u8; values_len];
        for (i, v) in src.iter_mut().enumerate() {
            *v = ((i.wrapping_mul(37) + bit_width as usize) as u8) & mask;
        }

        let expected_bytes = (values_len * bit_width as usize).div_ceil(8);
        let mut packed = vec![0u8; expected_bytes];
        let used = bitstream::pack_bits(&src, bit_width, &mut packed);
        assert_eq!(used, expected_bytes, "pack_bytes mismatch for width {}", bit_width);

        let mut out = vec![0u8; values_len];
        let written = bitstream::unpack_bits(&packed[..used], bit_width, &mut out);
        assert_eq!(written, values_len, "unpack_len mismatch for width {}", bit_width);
        assert_eq!(out, src, "roundtrip mismatch for width {}", bit_width);
    }
}

#[test]
fn bitstream_rejects_invalid_widths() {
    let src = [1u8, 2, 3];
    let mut packed = [0u8; 8];
    let mut out = [0u8; 8];
    assert_eq!(bitstream::pack_bits(&src, 0, &mut packed), 0);
    assert_eq!(bitstream::pack_bits(&src, 9, &mut packed), 0);
    assert_eq!(bitstream::unpack_bits(&packed, 0, &mut out), 0);
    assert_eq!(bitstream::unpack_bits(&packed, 9, &mut out), 0);
}
