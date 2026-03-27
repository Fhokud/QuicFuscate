use sha2::Digest;

/// One-shot SHA-256 digest of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// HMAC-SHA-256 keyed hash.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::Mac;
    type HmacSha256 = hmac::Hmac<sha2::Sha256>;
    // new_from_slice() only fails for zero-length keys; HMAC accepts any key length per RFC 2104.
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    let result = mac.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result.into_bytes());
    out
}

/// HKDF-Extract: derive a pseudorandom key from salt and input keying material.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let (prk, _) = hkdf::Hkdf::<sha2::Sha256>::extract(Some(salt), ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(&prk);
    out
}

/// HKDF-Expand: expand a pseudorandom key with context info to `out_len` bytes.
///
/// # Panics
/// Panics if `out_len` exceeds the RFC 5869 limit of 255 * HashLen = 8160 bytes for SHA-256.
pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], out_len: usize) -> Vec<u8> {
    // RFC 5869 §2.3: L must be <= 255*HashLen. For SHA-256 that is 255*32 = 8160 bytes.
    assert!(
        out_len <= 255 * 32,
        "HKDF-Expand: out_len {} exceeds RFC 5869 limit of 8160 bytes",
        out_len
    );
    // from_prk() only fails when prk is shorter than HashLen; our fixed [u8; 32] always satisfies this.
    let hk = hkdf::Hkdf::<sha2::Sha256>::from_prk(prk).expect("PRK length is valid for SHA-256");
    let mut out = vec![0u8; out_len];
    // expand() only fails when out_len exceeds the RFC limit, which we already assert above.
    hk.expand(info, &mut out).expect("output length within HKDF limits");
    out
}
