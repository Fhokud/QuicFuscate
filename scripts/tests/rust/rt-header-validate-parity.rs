#![cfg(target_arch = "x86_64")]
#![cfg(feature = "rust-tests")]

#[test]
fn header_validate_avx512_matches_scalar() {
    if !std::is_x86_feature_detected!("avx512f") {
        return;
    }

    // Valid long header (fixed bit set)
    let mut long_ok = [0u8; 64];
    long_ok[0] = 0xC0; // fixed bit set
    assert!(unsafe { quicfuscate::simd::x86_header::validate_header_avx512(&long_ok) });

    // Invalid: fixed bit cleared
    let mut no_fixed = [0u8; 64];
    no_fixed[0] = 0x00;
    assert!(!unsafe { quicfuscate::simd::x86_header::validate_header_avx512(&no_fixed) });

    // Random cases
    let mut buf = [0u8; 64];
    for i in 0..64 {
        buf.fill(0);
        buf[0] = (i as u8) << 2;
        let scalar = quicfuscate::simd::scalar::validate_header(&buf);
        let simd = unsafe { quicfuscate::simd::x86_header::validate_header_avx512(&buf) };
        assert_eq!(scalar, simd);
    }
}

#[test]
fn header_validate_sse2_matches_scalar() {
    if !std::is_x86_feature_detected!("sse2") {
        return;
    }

    let mut long_ok = [0u8; 64];
    long_ok[0] = 0xC0; // fixed bit set
    assert!(unsafe { quicfuscate::simd::x86::validate_header_sse2(&long_ok) });

    let mut no_fixed = [0u8; 64];
    no_fixed[0] = 0x00;
    assert!(!unsafe { quicfuscate::simd::x86::validate_header_sse2(&no_fixed) });

    // Reserved bits cleared for short header
    let mut short_ok = [0u8; 8];
    short_ok[0] = 0x40; // fixed=1, short=1, reserved=0
    assert!(unsafe { quicfuscate::simd::x86::validate_header_sse2(&short_ok) });

    // Reserved bits set -> invalid
    let mut short_bad = [0u8; 8];
    short_bad[0] = 0x58; // 0b0101_1000: fixed=1, reserved!=0
    assert!(!unsafe { quicfuscate::simd::x86::validate_header_sse2(&short_bad) });
}
