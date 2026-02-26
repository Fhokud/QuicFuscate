#![no_main]

use libfuzzer_sys::fuzz_target;

use quicfuscate::crypto::aead_legacy::{AeadOpen, AeadSeal};
use quicfuscate::crypto::chacha20poly1305::ChaCha20Poly1305;
use quicfuscate::error::ConnectionError;

fuzz_target!(|data: &[u8]| {
    if data.len() < 44 {
        return;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&data[..32]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&data[32..44]);
    let payload_len = (data.len() - 44).min(256);
    let mut buf = vec![0u8; payload_len + 16];
    buf[..payload_len].copy_from_slice(&data[44..44 + payload_len]);

    let seal = ChaCha20Poly1305::new(&key, &nonce);
    let sealed = seal.seal_with_u64_counter(1, b"ad", &mut buf, payload_len, None);
    if sealed.is_err() {
        return;
    }
    if let Ok(opened) = ChaCha20Poly1305::new(&key, &nonce).open_with_u64_counter(1, b"ad", &mut buf) {
        let _ = opened;
    } else {
        let _ = ConnectionError::CryptoFail;
    }
});
