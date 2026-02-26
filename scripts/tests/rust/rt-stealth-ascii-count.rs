#![cfg(feature = "rust-tests")]
use quicfuscate::accelerate;

#[test]
fn count_ascii_printable_matches_scalar() {
    let mut data = Vec::new();
    for byte in 0u8..=255 {
        data.push(byte);
    }
    let fast = accelerate::count_ascii_printable(&data);
    let slow = data.iter().filter(|b| matches!(b, 0x20..=0x7E)).count();
    assert_eq!(fast, slow);
}

#[test]
fn count_ascii_printable_handles_empty() {
    assert_eq!(accelerate::count_ascii_printable(&[]), 0);
}
