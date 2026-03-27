
/// QUIC packet protection algorithm identifier.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug)]
pub enum Algorithm {
    /// AES-128-GCM as specified in RFC 9001.
    AES128_GCM,
}
/// QUIC encryption level.
#[derive(Clone, Copy, Debug)]
pub enum Level {
    /// Initial encryption level.
    Initial,
    /// 0-RTT encryption level.
    ZeroRTT,
    /// Handshake encryption level.
    Handshake,
    /// 1-RTT (application data) encryption level.
    OneRTT,
}
/// Trait for AEAD decryption (open) operations.
pub trait AeadOpen {
    fn open_with_u64_counter(
        &self,
        _counter: u64,
        _ad: &[u8],
        _buf: &mut [u8],
    ) -> Result<usize, crate::error::ConnectionError> {
        Err(crate::error::ConnectionError::CryptoError("crypto failure".into()))
    }
}
/// Trait for AEAD encryption (seal) operations.
pub trait AeadSeal {
    fn seal_with_u64_counter(
        &self,
        _counter: u64,
        _ad: &[u8],
        _buf: &mut [u8],
        _len: usize,
        _extra_in: Option<&[u8]>,
    ) -> Result<usize, crate::error::ConnectionError> {
        Err(crate::error::ConnectionError::CryptoError("crypto failure".into()))
    }
}

/// Trait for QUIC header protection mask application/removal.
pub trait HeaderProtector {
    fn apply(&self, sample: &[u8], mask: &mut [u8]);
    fn remove(&self, sample: &[u8], mask: &mut [u8]);
}

/// Callbacks for TLS key schedule events (secret installation).
pub trait KeyScheduleHooks {
    fn set_read_secret(&mut self, level: Level, alg: Algorithm, secret: &[u8]);
    fn set_write_secret(&mut self, level: Level, alg: Algorithm, secret: &[u8]);
}

/// AES-based QUIC header protection using single-block AES encryption.
pub struct AesHp {
    key: [u8; 16],
}

impl AesHp {
    /// Create a new header protector from the first 16 bytes of `secret`.
    pub fn new(secret: &[u8]) -> Self {
        let mut key = [0u8; 16];
        key.copy_from_slice(&secret[..16.min(secret.len())]);
        Self { key }
    }
}

impl HeaderProtector for AesHp {
    fn apply(&self, sample: &[u8], mask: &mut [u8]) {
        let sample_block: [u8; 16] = sample[..16].try_into().unwrap_or([0u8; 16]);
        let block = crate::crypto::aes128_encrypt_block_fast(&self.key, &sample_block);
        for (i, m) in mask.iter_mut().enumerate() {
            *m ^= block[i % 16];
        }
    }

    fn remove(&self, sample: &[u8], mask: &mut [u8]) {
        self.apply(sample, mask); // XOR is self-inverse
    }
}

impl crate::transport::packet::HeaderProtector for AesHp {
    fn new_mask(&self, sample: &[u8]) -> [u8; 5] {
        let sample_block: [u8; 16] = sample[..16].try_into().unwrap_or([0u8; 16]);
        let block = crate::crypto::aes128_encrypt_block_fast(&self.key, &sample_block);
        let mut mask = [0u8; 5];
        mask.copy_from_slice(&block[..5]);
        mask
    }
}
