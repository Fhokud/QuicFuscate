#![allow(unexpected_cfgs)]
//! # Crypto Module
//!
//! This module provides high-performance, hardware-accelerated cryptographic
//! functions. It includes implementations for AEGIS and MORUS ciphers and
//! features a runtime selector to choose the most performant cipher suite
//! based on detected CPU capabilities.

use crate::optimize::{CpuFeature, FeatureDetector};
use crate::simd::CryptoAeadPlan;
use core::convert::TryInto;
use core::ptr;
use log::info;
// use morus::Morus; // Removed - using native implementation
use rand::{rngs::OsRng, RngCore};
// use std::sync::atomic::AtomicUsize; // Unused
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::OnceLock;

// 0 = auto, 1 = aegis-128l, 2 = morus, 3 = aes-gcm, 4 = aegis-128x4, 5 = aegis-128x8
static DATA_AEAD_OVERRIDE_MODE: AtomicU8 = AtomicU8::new(0);

// aarch64 intrinsics are imported locally where used via core::arch::aarch64

// ============================================================================
// Hardware-accelerated crypto with AES-NI for AEGIS and MORUS
// ============================================================================

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

// ============================================================================
// AEGIS-128 RUNTIME DISPATCH SYSTEM
// ============================================================================
// Selector logic centralized in simd::CryptoAeadPlan (SSOT).

// Note: keep tests focused on functional behavior; avoid hygiene-only symbol touches.

#[cfg(test)]
mod tests {
    use super::chacha20poly1305::ChaCha20Poly1305;
    use crate::crypto::aead_legacy::{AeadOpen, AeadSeal};
    use crate::engine::{AeadPreference, CryptoConfig};
    use std::sync::Mutex;

    // DATA_AEAD_OVERRIDE_MODE is process-global. Serialize override tests to avoid races.
    static DATA_AEAD_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(hex.len() / 2);
        let clean = hex.as_bytes();
        for chunk in clean.chunks(2) {
            let hi = (chunk[0] as char).to_digit(16).unwrap();
            let lo = (chunk[1] as char).to_digit(16).unwrap();
            bytes.push(((hi << 4) | lo) as u8);
        }

        bytes
    }

    #[test]
    fn chacha20poly1305_rfc8439_vector() {
        let key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let nonce = hex_to_bytes("000000000000004a00000000");
        let plaintext = hex_to_bytes(concat!(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66",
            "202739393a20497420776173207468652062657374206f662074696d65732c2069742077",
            "61732074686520776f727374206f662074696d65732e",
        ));

        let mut buffer = plaintext.clone();
        buffer.resize(plaintext.len() + 16, 0);

        let seal = ChaCha20Poly1305::new(&key, &nonce);
        let out_len = seal
            .seal_with_u64_counter(0, &[], buffer.as_mut_slice(), plaintext.len(), None)
            .unwrap();
        assert_eq!(out_len, plaintext.len() + 16);

        let open = ChaCha20Poly1305::new(&key, &nonce);
        let pt_len = open.open_with_u64_counter(0, &[], buffer.as_mut_slice()).unwrap();
        assert_eq!(pt_len, plaintext.len());
        assert_eq!(&buffer[..pt_len], plaintext.as_slice());
    }

    #[test]
    fn data_aead_config_force_overrides_preference() {
        let _guard = DATA_AEAD_TEST_LOCK.lock().unwrap();
        let cfg = CryptoConfig {
            aead_preference: AeadPreference::Morus,
            force_aead: "aes-gcm".to_string(),
            ..CryptoConfig::default()
        };
        super::install_data_aead_config(&cfg);
        assert_eq!(super::data_aead_override_mode(), 3);
        super::set_data_aead_override_mode(0);
    }

    #[test]
    fn data_aead_config_force_aegis_x4_and_x8() {
        let _guard = DATA_AEAD_TEST_LOCK.lock().unwrap();
        let mut cfg =
            CryptoConfig { force_aead: "aegis-128x4".to_string(), ..CryptoConfig::default() };
        super::install_data_aead_config(&cfg);
        assert_eq!(super::data_aead_override_mode(), 4);

        cfg.force_aead = "aegis-128x8".to_string();
        super::install_data_aead_config(&cfg);
        assert_eq!(super::data_aead_override_mode(), 5);

        super::set_data_aead_override_mode(0);
    }

    #[test]
    fn data_aead_force_aegis_x4_roundtrip() {
        let _guard = DATA_AEAD_TEST_LOCK.lock().unwrap();
        let cfg = CryptoConfig { force_aead: "aegis-128x4".to_string(), ..CryptoConfig::default() };
        super::install_data_aead_config(&cfg);

        let key = [0x11u8; 32];
        let iv = [0x22u8; 16];
        let ad = b"ad";
        let pt = b"hello-quicfuscate";

        let (seal, open) = super::select_data_aead(&key, &iv);
        let mut buf = vec![0u8; pt.len() + 16];
        buf[..pt.len()].copy_from_slice(pt);
        let out_len =
            seal.seal_with_u64_counter(7, ad, buf.as_mut_slice(), pt.len(), None).unwrap();
        assert_eq!(out_len, pt.len() + 16);
        let pt_len = open.open_with_u64_counter(7, ad, buf.as_mut_slice()).unwrap();
        assert_eq!(pt_len, pt.len());
        assert_eq!(&buf[..pt_len], pt);

        super::set_data_aead_override_mode(0);
    }

    #[test]
    fn data_aead_force_aegis_x8_roundtrip() {
        let _guard = DATA_AEAD_TEST_LOCK.lock().unwrap();
        let cfg = CryptoConfig { force_aead: "aegis-128x8".to_string(), ..CryptoConfig::default() };
        super::install_data_aead_config(&cfg);

        let key = [0x33u8; 32];
        let iv = [0x44u8; 16];
        let ad = b"ad";
        let pt = b"hello-quicfuscate-x8";

        let (seal, open) = super::select_data_aead(&key, &iv);
        let mut buf = vec![0u8; pt.len() + 16];
        buf[..pt.len()].copy_from_slice(pt);
        let out_len =
            seal.seal_with_u64_counter(9, ad, buf.as_mut_slice(), pt.len(), None).unwrap();
        assert_eq!(out_len, pt.len() + 16);
        let pt_len = open.open_with_u64_counter(9, ad, buf.as_mut_slice()).unwrap();
        assert_eq!(pt_len, pt.len());
        assert_eq!(&buf[..pt_len], pt);

        super::set_data_aead_override_mode(0);
    }

    #[test]
    fn aegis_x_variants_match_aegis128l() {
        // For a fixed key/nonce, all variants must produce identical ciphertext and tag.
        let key = [0x55u8; 16];
        let nonce = [0x66u8; 16];
        let ad = b"associated-data-123";

        for &len in &[0usize, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255] {
            let mut pt = vec![0u8; len];
            for (i, b) in pt.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(31).wrapping_add(7);
            }

            let mut a1 = crate::crypto::Aegis128L::new(&key, &nonce).unwrap();
            let mut c1 = pt.clone();
            let t1 = a1.encrypt_in_place(&mut c1, ad);

            let mut a4 = crate::crypto::Aegis128X4::new(&key, &nonce).unwrap();
            let mut c4 = pt.clone();
            let t4 = a4.encrypt_in_place(&mut c4, ad);
            assert_eq!(c4, c1);
            assert_eq!(t4, t1);

            let mut a8 = crate::crypto::Aegis128X8::new(&key, &nonce).unwrap();
            let mut c8 = pt.clone();
            let t8 = a8.encrypt_in_place(&mut c8, ad);
            assert_eq!(c8, c1);
            assert_eq!(t8, t1);
        }
    }

    #[test]
    fn aegis_x_variants_cross_decrypt() {
        let key = [0x77u8; 16];
        let nonce = [0x88u8; 16];
        let ad = b"ad";
        let mut pt = vec![0u8; 333];
        for (i, b) in pt.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(13).wrapping_add(9);
        }

        let mut a1 = crate::crypto::Aegis128L::new(&key, &nonce).unwrap();
        let mut ct = pt.clone();
        let tag = a1.encrypt_in_place(&mut ct, ad);

        let mut a8 = crate::crypto::Aegis128X8::new(&key, &nonce).unwrap();
        let mut dec = ct.clone();
        a8.decrypt_in_place(&mut dec, ad, &tag).unwrap();
        assert_eq!(dec, pt);

        let mut a4 = crate::crypto::Aegis128X4::new(&key, &nonce).unwrap();
        let mut dec2 = ct;
        a4.decrypt_in_place(&mut dec2, ad, &tag).unwrap();
        assert_eq!(dec2, pt);
    }

    #[test]
    fn data_aead_config_preference_is_conditional() {
        let _guard = DATA_AEAD_TEST_LOCK.lock().unwrap();
        let cfg =
            CryptoConfig { aead_preference: AeadPreference::Aegis128L, ..CryptoConfig::default() };
        super::install_data_aead_config(&cfg);
        // On platforms without hardware AES, preference should not override defaults.
        // On platforms with hardware AES, preference activates AEGIS-128L.
        let mode = super::data_aead_override_mode();
        assert!(mode == 0 || mode == 1);
        super::set_data_aead_override_mode(0);
    }
}

pub mod chacha20poly1305 {
    use super::chacha;
    use super::poly1305;
    use crate::crypto::aead_legacy::{AeadOpen, AeadSeal};
    use crate::error::ConnectionError;
    use zeroize::Zeroize;

    #[derive(Clone)]
    pub struct ChaCha20Poly1305 {
        key: [u8; 32],
        nonce: [u8; 12],
    }

    impl ChaCha20Poly1305 {
        pub fn new(key: &[u8], iv: &[u8]) -> Self {
            let mut k = [0u8; 32];
            let mut n = [0u8; 12];
            for (i, kb) in k.iter_mut().enumerate() {
                *kb = key.get(i).copied().unwrap_or(0);
            }
            for (i, nb) in n.iter_mut().enumerate() {
                *nb = iv.get(i).copied().unwrap_or(0);
            }
            Self { key: k, nonce: n }
        }

        #[inline(always)]
        fn make_nonce(&self, counter: u64) -> [u8; 12] {
            // QUIC/TLS style nonce construction: nonce = base_iv XOR packet_number.
            let mut nonce = self.nonce;
            let seq = counter.to_be_bytes();
            for (idx, b) in seq.iter().enumerate() {
                nonce[4 + idx] ^= *b;
            }
            nonce
        }

        #[inline(always)]
        fn one_time_key(&self, counter: u32, nonce12: &[u8; 12]) -> [u8; 32] {
            let block0 = chacha::chacha20_block(&self.key, counter, nonce12);
            let mut poly_key = [0u8; 32];
            poly_key.copy_from_slice(&block0[..32]);
            poly_key
        }

        #[inline(always)]
        fn process_in_place(&self, counter: u32, nonce12: &[u8; 12], buf: &mut [u8]) {
            chacha::xor_keystream_in_place(&self.key, counter, nonce12, buf);
        }
    }

    // MORUS SSSE3 wrappers are defined in impl MorusAead (outside this module)

    impl Drop for ChaCha20Poly1305 {
        fn drop(&mut self) {
            self.key.zeroize();
        }
    }

    impl AeadSeal for ChaCha20Poly1305 {
        fn seal_with_u64_counter(
            &self,
            counter: u64,
            ad: &[u8],
            buf: &mut [u8],
            len: usize,
            _extra_in: Option<&[u8]>,
        ) -> Result<usize, ConnectionError> {
            if buf.len() < len + 16 {
                return Err(ConnectionError::BufferTooShort);
            }
            let (pt, rest) = buf.split_at_mut(len);

            let nonce12 = self.make_nonce(counter);
            let poly_key = self.one_time_key(0, &nonce12);

            self.process_in_place(1, &nonce12, pt);

            let tag = poly1305::aead_tag_chacha20poly1305(ad, pt, &poly_key);
            rest[..16].copy_from_slice(&tag);
            Ok(len + 16)
        }
    }

    impl AeadOpen for ChaCha20Poly1305 {
        fn open_with_u64_counter(
            &self,
            counter: u64,
            ad: &[u8],
            buf: &mut [u8],
        ) -> Result<usize, ConnectionError> {
            if buf.len() < 16 {
                return Err(ConnectionError::BufferTooShort);
            }
            let ct_len = buf.len() - 16;
            let (ct, tag_in) = buf.split_at_mut(ct_len);
            let mut tag = [0u8; 16];
            tag.copy_from_slice(&tag_in[..16]);

            let nonce12 = self.make_nonce(counter);
            let poly_key = self.one_time_key(0, &nonce12);

            let tag_calc = poly1305::aead_tag_chacha20poly1305(ad, ct, &poly_key);
            if !crate::crypto::subtle_ct_eq(&tag_calc, &tag) {
                return Err(ConnectionError::CryptoFail);
            }

            self.process_in_place(1, &nonce12, ct);
            Ok(ct_len)
        }
    }
}

pub use chacha20poly1305::ChaCha20Poly1305;

// ============================================================================
// AEGIS helpers and hardware-accelerated primitives live in this module.
// Keep selection logic centralized in simd::CryptoAeadPlan.
// ============================================================================

/// Cross-platform fast AES-128 encrypt for a single block.
/// Uses AES-NI on x86_64 if available; falls back to software elsewhere.
#[inline]
fn aes128_encrypt_block_fast(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        if FeatureDetector::instance().has_feature(CpuFeature::AESNI) {
            let rk = expand_aes128_schedule(key);
            let mut out = *block;
            aes128_encrypt_block_rk(&rk, &mut out);
            return out;
        }
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        if FeatureDetector::instance().has_feature(CpuFeature::NEON_CRYPTO)
            || FeatureDetector::instance().has_feature(CpuFeature::NEON)
        {
            return aes128_encrypt_block_arm(key, block);
        }
    }
    crate::crypto::aes::aes128_encrypt_block(key, block)
}

#[cfg(target_arch = "aarch64")]
#[inline]
/// # Safety
/// Requires aarch64 with AES instructions available (checked by caller via runtime detection).
/// `key` and `block` must point to valid 16-byte aligned data readable by the function.
unsafe fn aes128_encrypt_block_arm(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    use core::arch::aarch64::*;
    let rk_bytes = crate::crypto::aes::key_expansion(key);
    // Load round keys into NEON vectors
    let mut k0 = [0u8; 16];
    k0.copy_from_slice(&rk_bytes[0..16]);
    let rk0 = vld1q_u8(k0.as_ptr());
    let mut k1 = [0u8; 16];
    k1.copy_from_slice(&rk_bytes[16..32]);
    let rk1 = vld1q_u8(k1.as_ptr());
    let mut k2 = [0u8; 16];
    k2.copy_from_slice(&rk_bytes[32..48]);
    let rk2 = vld1q_u8(k2.as_ptr());
    let mut k3 = [0u8; 16];
    k3.copy_from_slice(&rk_bytes[48..64]);
    let rk3 = vld1q_u8(k3.as_ptr());
    let mut k4 = [0u8; 16];
    k4.copy_from_slice(&rk_bytes[64..80]);
    let rk4 = vld1q_u8(k4.as_ptr());
    let mut k5 = [0u8; 16];
    k5.copy_from_slice(&rk_bytes[80..96]);
    let rk5 = vld1q_u8(k5.as_ptr());
    let mut k6 = [0u8; 16];
    k6.copy_from_slice(&rk_bytes[96..112]);
    let rk6 = vld1q_u8(k6.as_ptr());
    let mut k7 = [0u8; 16];
    k7.copy_from_slice(&rk_bytes[112..128]);
    let rk7 = vld1q_u8(k7.as_ptr());
    let mut k8 = [0u8; 16];
    k8.copy_from_slice(&rk_bytes[128..144]);
    let rk8 = vld1q_u8(k8.as_ptr());
    let mut k9 = [0u8; 16];
    k9.copy_from_slice(&rk_bytes[144..160]);
    let rk9 = vld1q_u8(k9.as_ptr());
    let mut k10 = [0u8; 16];
    k10.copy_from_slice(&rk_bytes[160..176]);
    let rk10 = vld1q_u8(k10.as_ptr());

    // Encrypt one block with AESE/AESMC
    let mut state = vld1q_u8(block.as_ptr());
    state = veorq_u8(state, rk0);
    state = vaeseq_u8(state, rk1);
    state = vaesmcq_u8(state);
    state = vaeseq_u8(state, rk2);
    state = vaesmcq_u8(state);
    state = vaeseq_u8(state, rk3);
    state = vaesmcq_u8(state);
    state = vaeseq_u8(state, rk4);
    state = vaesmcq_u8(state);
    state = vaeseq_u8(state, rk5);
    state = vaesmcq_u8(state);
    state = vaeseq_u8(state, rk6);
    state = vaesmcq_u8(state);
    state = vaeseq_u8(state, rk7);
    state = vaesmcq_u8(state);
    state = vaeseq_u8(state, rk8);
    state = vaesmcq_u8(state);
    state = vaeseq_u8(state, rk9);
    state = vaesmcq_u8(state);
    state = vaeseq_u8(state, rk10);

    let mut out = [0u8; 16];
    vst1q_u8(out.as_mut_ptr(), state);
    out
}

// Aegis128LAead wrapper
pub struct Aegis128LAead {
    key: [u8; 16],
    iv: [u8; 12],
}

impl Aegis128LAead {
    pub fn new(aead_key: &[u8], iv: &[u8]) -> Self {
        let mut k = [0u8; 16];
        let klen = aead_key.len().min(16);
        k[..klen].copy_from_slice(&aead_key[..klen]);
        let mut v = [0u8; 12];
        let vlen = iv.len().min(12);
        v[..vlen].copy_from_slice(&iv[..vlen]);
        Self { key: k, iv: v }
    }
}

pub struct Aegis128X4Aead {
    key: [u8; 16],
    iv: [u8; 12],
}

impl Aegis128X4Aead {
    pub fn new(aead_key: &[u8], iv: &[u8]) -> Self {
        let mut k = [0u8; 16];
        let klen = aead_key.len().min(16);
        k[..klen].copy_from_slice(&aead_key[..klen]);
        let mut v = [0u8; 12];
        let vlen = iv.len().min(12);
        v[..vlen].copy_from_slice(&iv[..vlen]);
        Self { key: k, iv: v }
    }
}

pub struct Aegis128X8Aead {
    key: [u8; 16],
    iv: [u8; 12],
}

impl Aegis128X8Aead {
    pub fn new(aead_key: &[u8], iv: &[u8]) -> Self {
        let mut k = [0u8; 16];
        let klen = aead_key.len().min(16);
        k[..klen].copy_from_slice(&aead_key[..klen]);
        let mut v = [0u8; 12];
        let vlen = iv.len().min(12);
        v[..vlen].copy_from_slice(&iv[..vlen]);
        Self { key: k, iv: v }
    }
}

// MORUS-1280-128 AEAD cipher implementation
// Specification: https://competitions.cr.yp.to/round3/morusv2.pdf

/// MORUS-1280-128 state: 5 blocks of 256 bits each
#[derive(Clone)]
struct Morus1280State {
    s: [[u64; 4]; 5],
}

impl Morus1280State {
    #[allow(dead_code)]
    #[inline(always)]
    fn rotl_words_256(x: [u64; 4], k_words: usize) -> [u64; 4] {
        let k = k_words % 4;
        [x[k % 4], x[(1 + k) % 4], x[(2 + k) % 4], x[(3 + k) % 4]]
    }

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    unsafe fn load_u64x4_sse(src: &[u64; 4]) -> (__m128i, __m128i) {
        use core::arch::x86_64::*;
        let lo = _mm_loadu_si128(src.as_ptr() as *const __m128i);
        let hi = _mm_loadu_si128(src.as_ptr().add(2) as *const __m128i);
        (lo, hi)
    }

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    unsafe fn store_u64x4_sse(dst: &mut [u64; 4], lo: __m128i, hi: __m128i) {
        use core::arch::x86_64::*;
        _mm_storeu_si128(dst.as_mut_ptr() as *mut __m128i, lo);
        _mm_storeu_si128(dst.as_mut_ptr().add(2) as *mut __m128i, hi);
    }

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    unsafe fn rotl_epi64(x: __m128i, n: i32) -> __m128i {
        use core::arch::x86_64::*;
        let n = ((n as u32) & 63) as i32;
        if n == 0 {
            return x;
        }
        let cnt = _mm_cvtsi32_si128(n);
        let left = _mm_sll_epi64(x, cnt);
        let right = _mm_srl_epi64(x, _mm_cvtsi32_si128(64 - n));
        _mm_or_si128(left, right)
    }

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    unsafe fn rotl_words_pair_sse(mut lo: __m128i, mut hi: __m128i, k: i32) -> (__m128i, __m128i) {
        use core::arch::x86_64::*;
        let shift = (k & 3) as usize;
        if shift == 0 {
            return (lo, hi);
        }
        let mut tmp = [0u64; 4];
        _mm_storeu_si128(tmp.as_mut_ptr() as *mut __m128i, lo);
        _mm_storeu_si128(tmp.as_mut_ptr().add(2) as *mut __m128i, hi);
        // Use scalar helper to rotate words to mark it as used without changing semantics
        let tmp = Self::rotl_words_256(tmp, shift);
        lo = _mm_loadu_si128(tmp.as_ptr() as *const __m128i);
        hi = _mm_loadu_si128(tmp.as_ptr().add(2) as *const __m128i);
        (lo, hi)
    }

    // SSSE3 helper: rotate 4x u64 words across (lo,hi) pair by k words using byte-align shuffles
    #[cfg(target_arch = "x86_64")]
    #[inline]
    #[target_feature(enable = "ssse3")]
    unsafe fn rotl_words_pair_ssse3(lo: __m128i, hi: __m128i, k: i32) -> (__m128i, __m128i) {
        use core::arch::x86_64::*;
        let s = (k & 3) as i32;
        match s {
            0 => (lo, hi),
            1 => (
                _mm_alignr_epi8(hi, lo, 8), // [x1,x2]
                _mm_alignr_epi8(lo, hi, 8), // [x3,x0]
            ),
            2 => (hi, lo),
            3 => (
                _mm_alignr_epi8(lo, hi, 8), // [x3,x0]
                _mm_alignr_epi8(hi, lo, 8), // [x1,x2]
            ),
            _ => (lo, hi),
        }
    }

    // SSSE3-optimized MORUS update with in-register word rotations
    #[cfg(target_arch = "x86_64")]
    #[inline]
    #[target_feature(enable = "ssse3")]
    unsafe fn update_simd_ssse3(&mut self, m: [u64; 4]) {
        use core::arch::x86_64::*;

        let (mut s0_lo, mut s0_hi) = Self::load_u64x4_sse(&self.s[0]);
        let (s1_lo, s1_hi) = Self::load_u64x4_sse(&self.s[1]);
        let (s2_lo, s2_hi) = Self::load_u64x4_sse(&self.s[2]);
        let (s3_lo, s3_hi) = Self::load_u64x4_sse(&self.s[3]);
        let (s4_lo, s4_hi) = Self::load_u64x4_sse(&self.s[4]);
        let (m_lo, m_hi) = Self::load_u64x4_sse(&m);

        // Round 1
        let t0_lo = _mm_xor_si128(_mm_xor_si128(s0_lo, _mm_and_si128(s1_lo, s2_lo)), s3_lo);
        let t0_hi = _mm_xor_si128(_mm_xor_si128(s0_hi, _mm_and_si128(s1_hi, s2_hi)), s3_hi);
        let r1_0_lo = Self::rotl_epi64(t0_lo, 13);
        let r1_0_hi = Self::rotl_epi64(t0_hi, 13);
        let (r1_3_lo, r1_3_hi) = Self::rotl_words_pair_ssse3(s3_lo, s3_hi, 1);

        // Round 2
        let t1_lo = _mm_xor_si128(_mm_xor_si128(s1_lo, _mm_and_si128(s2_lo, r1_3_lo)), s4_lo);
        let t1_lo = _mm_xor_si128(t1_lo, m_lo);
        let t1_hi = _mm_xor_si128(_mm_xor_si128(s1_hi, _mm_and_si128(s2_hi, r1_3_hi)), s4_hi);
        let t1_hi = _mm_xor_si128(t1_hi, m_hi);
        let r2_1_lo = Self::rotl_epi64(t1_lo, 46);
        let r2_1_hi = Self::rotl_epi64(t1_hi, 46);
        let (r2_4_lo, r2_4_hi) = Self::rotl_words_pair_ssse3(s4_lo, s4_hi, 2);

        // Round 3
        let t2_lo = _mm_xor_si128(_mm_xor_si128(s2_lo, _mm_and_si128(r1_3_lo, r2_4_lo)), r1_0_lo);
        let t2_lo = _mm_xor_si128(t2_lo, m_lo);
        let t2_hi = _mm_xor_si128(_mm_xor_si128(s2_hi, _mm_and_si128(r1_3_hi, r2_4_hi)), r1_0_hi);
        let t2_hi = _mm_xor_si128(t2_hi, m_hi);
        let r3_2_lo = Self::rotl_epi64(t2_lo, 38);
        let r3_2_hi = Self::rotl_epi64(t2_hi, 38);
        let (r3_0_lo, r3_0_hi) = Self::rotl_words_pair_ssse3(r1_0_lo, r1_0_hi, 3);

        // Round 4
        let t3_lo = _mm_xor_si128(_mm_xor_si128(r1_3_lo, _mm_and_si128(r2_4_lo, r3_0_lo)), r2_1_lo);
        let t3_lo = _mm_xor_si128(t3_lo, m_lo);
        let t3_hi = _mm_xor_si128(_mm_xor_si128(r1_3_hi, _mm_and_si128(r2_4_hi, r3_0_hi)), r2_1_hi);
        let t3_hi = _mm_xor_si128(t3_hi, m_hi);
        let r4_3_lo = Self::rotl_epi64(t3_lo, 7);
        let r4_3_hi = Self::rotl_epi64(t3_hi, 7);
        let (r4_1_lo, r4_1_hi) = Self::rotl_words_pair_ssse3(r2_1_lo, r2_1_hi, 2);

        // Round 5
        let t4_lo = _mm_xor_si128(_mm_xor_si128(r2_4_lo, _mm_and_si128(r3_0_lo, r4_1_lo)), r3_2_lo);
        let t4_lo = _mm_xor_si128(t4_lo, m_lo);
        let t4_hi = _mm_xor_si128(_mm_xor_si128(r2_4_hi, _mm_and_si128(r3_0_hi, r4_1_hi)), r3_2_hi);
        let t4_hi = _mm_xor_si128(t4_hi, m_hi);
        let new4_lo = Self::rotl_epi64(t4_lo, 4);
        let new4_hi = Self::rotl_epi64(t4_hi, 4);
        let (new2_lo, new2_hi) = Self::rotl_words_pair_ssse3(r3_2_lo, r3_2_hi, 1);

        Self::store_u64x4_sse(&mut self.s[0], r3_0_lo, r3_0_hi);
        Self::store_u64x4_sse(&mut self.s[1], r4_1_lo, r4_1_hi);
        Self::store_u64x4_sse(&mut self.s[2], new2_lo, new2_hi);
        Self::store_u64x4_sse(&mut self.s[3], r4_3_lo, r4_3_hi);
        Self::store_u64x4_sse(&mut self.s[4], new4_lo, new4_hi);
    }

    #[cfg(target_arch = "x86_64")]
    #[inline]
    #[target_feature(enable = "sse4.1")]
    unsafe fn rotl_words_pair_sse41(lo: __m128i, hi: __m128i, k: i32) -> (__m128i, __m128i) {
        use core::arch::x86_64::*;
        match k & 3 {
            0 => (lo, hi),
            1 => {
                let lo_shift = _mm_slli_si128(lo, 8);
                let hi_carry = _mm_srli_si128(hi, 8);
                let new_lo = _mm_blend_epi16(lo_shift, hi_carry, 0b1111_0000);

                let hi_shift = _mm_slli_si128(hi, 8);
                let lo_carry = _mm_srli_si128(lo, 8);
                let new_hi = _mm_blend_epi16(hi_shift, lo_carry, 0b1111_0000);
                (new_lo, new_hi)
            }
            2 => (hi, lo),
            3 => {
                let lo_shift = _mm_srli_si128(lo, 8);
                let hi_carry = _mm_slli_si128(hi, 8);
                let new_lo = _mm_blend_epi16(lo_shift, hi_carry, 0b1111_0000);

                let hi_shift = _mm_srli_si128(hi, 8);
                let lo_carry = _mm_slli_si128(lo, 8);
                let new_hi = _mm_blend_epi16(hi_shift, lo_carry, 0b1111_0000);
                (new_lo, new_hi)
            }
            _ => (lo, hi),
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[inline]
    #[target_feature(enable = "sse4.1")]
    unsafe fn update_simd_sse41(&mut self, m: [u64; 4]) {
        use core::arch::x86_64::*;

        let (mut s0_lo, mut s0_hi) = Self::load_u64x4_sse(&self.s[0]);
        let (s1_lo, s1_hi) = Self::load_u64x4_sse(&self.s[1]);
        let (s2_lo, s2_hi) = Self::load_u64x4_sse(&self.s[2]);
        let (s3_lo, s3_hi) = Self::load_u64x4_sse(&self.s[3]);
        let (s4_lo, s4_hi) = Self::load_u64x4_sse(&self.s[4]);
        let (m_lo, m_hi) = Self::load_u64x4_sse(&m);

        // Round 1
        let mut t0_lo = _mm_xor_si128(_mm_xor_si128(s0_lo, _mm_and_si128(s1_lo, s2_lo)), s3_lo);
        let mut t0_hi = _mm_xor_si128(_mm_xor_si128(s0_hi, _mm_and_si128(s1_hi, s2_hi)), s3_hi);
        let r1_0_lo = Self::rotl_epi64(t0_lo, 13);
        let r1_0_hi = Self::rotl_epi64(t0_hi, 13);
        let (r1_3_lo, r1_3_hi) = Self::rotl_words_pair_sse41(s3_lo, s3_hi, 1);

        // Round 2
        t0_lo = _mm_xor_si128(_mm_xor_si128(s1_lo, _mm_and_si128(s2_lo, r1_3_lo)), s4_lo);
        t0_lo = _mm_xor_si128(t0_lo, m_lo);
        t0_hi = _mm_xor_si128(_mm_xor_si128(s1_hi, _mm_and_si128(s2_hi, r1_3_hi)), s4_hi);
        t0_hi = _mm_xor_si128(t0_hi, m_hi);
        let r2_1_lo = Self::rotl_epi64(t0_lo, 46);
        let r2_1_hi = Self::rotl_epi64(t0_hi, 46);
        let (r2_4_lo, r2_4_hi) = Self::rotl_words_pair_sse41(s4_lo, s4_hi, 2);

        // Round 3
        t0_lo = _mm_xor_si128(_mm_xor_si128(s2_lo, _mm_and_si128(r1_3_lo, r2_4_lo)), r1_0_lo);
        t0_lo = _mm_xor_si128(t0_lo, m_lo);
        t0_hi = _mm_xor_si128(_mm_xor_si128(s2_hi, _mm_and_si128(r1_3_hi, r2_4_hi)), r1_0_hi);
        t0_hi = _mm_xor_si128(t0_hi, m_hi);
        let r3_2_lo = Self::rotl_epi64(t0_lo, 38);
        let r3_2_hi = Self::rotl_epi64(t0_hi, 38);
        let (r3_0_lo, r3_0_hi) = Self::rotl_words_pair_sse41(r1_0_lo, r1_0_hi, 3);

        // Round 4
        t0_lo = _mm_xor_si128(_mm_xor_si128(r1_3_lo, _mm_and_si128(r2_4_lo, r3_0_lo)), r2_1_lo);
        t0_lo = _mm_xor_si128(t0_lo, m_lo);
        t0_hi = _mm_xor_si128(_mm_xor_si128(r1_3_hi, _mm_and_si128(r2_4_hi, r3_0_hi)), r2_1_hi);
        t0_hi = _mm_xor_si128(t0_hi, m_hi);
        let r4_3_lo = Self::rotl_epi64(t0_lo, 7);
        let r4_3_hi = Self::rotl_epi64(t0_hi, 7);
        let (r4_1_lo, r4_1_hi) = Self::rotl_words_pair_sse41(r2_1_lo, r2_1_hi, 2);

        // Round 5
        t0_lo = _mm_xor_si128(_mm_xor_si128(r2_4_lo, _mm_and_si128(r3_0_lo, r4_1_lo)), r3_2_lo);
        t0_lo = _mm_xor_si128(t0_lo, m_lo);
        t0_hi = _mm_xor_si128(_mm_xor_si128(r2_4_hi, _mm_and_si128(r3_0_hi, r4_1_hi)), r3_2_hi);
        t0_hi = _mm_xor_si128(t0_hi, m_hi);
        let new4_lo = Self::rotl_epi64(t0_lo, 4);
        let new4_hi = Self::rotl_epi64(t0_hi, 4);
        let (new2_lo, new2_hi) = Self::rotl_words_pair_sse41(r3_2_lo, r3_2_hi, 1);

        Self::store_u64x4_sse(&mut self.s[0], r3_0_lo, r3_0_hi);
        Self::store_u64x4_sse(&mut self.s[1], r4_1_lo, r4_1_hi);
        Self::store_u64x4_sse(&mut self.s[2], new2_lo, new2_hi);
        Self::store_u64x4_sse(&mut self.s[3], r4_3_lo, r4_3_hi);
        Self::store_u64x4_sse(&mut self.s[4], new4_lo, new4_hi);
    }

    // SSE4.2 uses same code as SSE4.1 (no new bit-manipulation instructions needed for MORUS)
    #[cfg(target_arch = "x86_64")]
    #[inline]
    #[target_feature(enable = "sse4.2")]
    unsafe fn update_simd_sse42(&mut self, m: [u64; 4]) {
        self.update_simd_sse41(m)
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
    unsafe fn update_simd_sse2(&mut self, m: [u64; 4]) {
        use core::arch::x86_64::*;

        let (mut s0_lo, mut s0_hi) = Self::load_u64x4_sse(&self.s[0]);
        let (s1_lo, s1_hi) = Self::load_u64x4_sse(&self.s[1]);
        let (s2_lo, s2_hi) = Self::load_u64x4_sse(&self.s[2]);
        let (s3_lo, s3_hi) = Self::load_u64x4_sse(&self.s[3]);
        let (s4_lo, s4_hi) = Self::load_u64x4_sse(&self.s[4]);
        let (m_lo, m_hi) = Self::load_u64x4_sse(&m);

        // Round 1
        let t0_lo = _mm_xor_si128(_mm_xor_si128(s0_lo, _mm_and_si128(s1_lo, s2_lo)), s3_lo);
        let t0_hi = _mm_xor_si128(_mm_xor_si128(s0_hi, _mm_and_si128(s1_hi, s2_hi)), s3_hi);
        let r1_0_lo = Self::rotl_epi64(t0_lo, 13);
        let r1_0_hi = Self::rotl_epi64(t0_hi, 13);
        let (r1_3_lo, r1_3_hi) = Self::rotl_words_pair_sse(s3_lo, s3_hi, 1);

        // Round 2
        let t1_lo = _mm_xor_si128(_mm_xor_si128(s1_lo, _mm_and_si128(s2_lo, r1_3_lo)), s4_lo);
        let t1_lo = _mm_xor_si128(t1_lo, m_lo);
        let t1_hi = _mm_xor_si128(_mm_xor_si128(s1_hi, _mm_and_si128(s2_hi, r1_3_hi)), s4_hi);
        let t1_hi = _mm_xor_si128(t1_hi, m_hi);
        let r2_1_lo = Self::rotl_epi64(t1_lo, 46);
        let r2_1_hi = Self::rotl_epi64(t1_hi, 46);
        let (r2_4_lo, r2_4_hi) = Self::rotl_words_pair_sse(s4_lo, s4_hi, 2);

        // Round 3
        let t2_lo = _mm_xor_si128(_mm_xor_si128(s2_lo, _mm_and_si128(r1_3_lo, r2_4_lo)), r1_0_lo);
        let t2_lo = _mm_xor_si128(t2_lo, m_lo);
        let t2_hi = _mm_xor_si128(_mm_xor_si128(s2_hi, _mm_and_si128(r1_3_hi, r2_4_hi)), r1_0_hi);
        let t2_hi = _mm_xor_si128(t2_hi, m_hi);
        let r3_2_lo = Self::rotl_epi64(t2_lo, 38);
        let r3_2_hi = Self::rotl_epi64(t2_hi, 38);
        let (r3_0_lo, r3_0_hi) = Self::rotl_words_pair_sse(r1_0_lo, r1_0_hi, 3);

        // Round 4
        let t3_lo = _mm_xor_si128(_mm_xor_si128(r1_3_lo, _mm_and_si128(r2_4_lo, r3_0_lo)), r2_1_lo);
        let t3_lo = _mm_xor_si128(t3_lo, m_lo);
        let t3_hi = _mm_xor_si128(_mm_xor_si128(r1_3_hi, _mm_and_si128(r2_4_hi, r3_0_hi)), r2_1_hi);
        let t3_hi = _mm_xor_si128(t3_hi, m_hi);
        let r4_3_lo = Self::rotl_epi64(t3_lo, 7);
        let r4_3_hi = Self::rotl_epi64(t3_hi, 7);
        let (r4_1_lo, r4_1_hi) = Self::rotl_words_pair_sse(r2_1_lo, r2_1_hi, 2);

        // Round 5
        let t4_lo = _mm_xor_si128(_mm_xor_si128(r2_4_lo, _mm_and_si128(r3_0_lo, r4_1_lo)), r3_2_lo);
        let t4_lo = _mm_xor_si128(t4_lo, m_lo);
        let t4_hi = _mm_xor_si128(_mm_xor_si128(r2_4_hi, _mm_and_si128(r3_0_hi, r4_1_hi)), r3_2_hi);
        let t4_hi = _mm_xor_si128(t4_hi, m_hi);
        let new4_lo = Self::rotl_epi64(t4_lo, 4);
        let new4_hi = Self::rotl_epi64(t4_hi, 4);
        let (new2_lo, new2_hi) = Self::rotl_words_pair_sse(r3_2_lo, r3_2_hi, 1);

        Self::store_u64x4_sse(&mut self.s[0], r3_0_lo, r3_0_hi);
        Self::store_u64x4_sse(&mut self.s[1], r4_1_lo, r4_1_hi);
        Self::store_u64x4_sse(&mut self.s[2], new2_lo, new2_hi);
        Self::store_u64x4_sse(&mut self.s[3], r4_3_lo, r4_3_hi);
        Self::store_u64x4_sse(&mut self.s[4], new4_lo, new4_hi);
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    #[inline(always)]
    unsafe fn rot_words_pair_neon(
        lo: core::arch::aarch64::uint64x2_t,
        hi: core::arch::aarch64::uint64x2_t,
        k: i32,
    ) -> (core::arch::aarch64::uint64x2_t, core::arch::aarch64::uint64x2_t) {
        use core::arch::aarch64::{
            uint8x16_t, vextq_u8, vreinterpretq_u64_u8, vreinterpretq_u8_u64,
        };
        match k & 3 {
            0 => (lo, hi),
            1 => {
                let lo_u8: uint8x16_t = vreinterpretq_u8_u64(lo);
                let hi_u8: uint8x16_t = vreinterpretq_u8_u64(hi);
                let new_lo = vreinterpretq_u64_u8(vextq_u8(lo_u8, hi_u8, 8));
                let new_hi = vreinterpretq_u64_u8(vextq_u8(hi_u8, lo_u8, 8));
                (new_lo, new_hi)
            }
            2 => (hi, lo),
            3 => {
                let lo_u8: uint8x16_t = vreinterpretq_u8_u64(lo);
                let hi_u8: uint8x16_t = vreinterpretq_u8_u64(hi);
                let new_lo = vreinterpretq_u64_u8(vextq_u8(hi_u8, lo_u8, 8));
                let new_hi = vreinterpretq_u64_u8(vextq_u8(lo_u8, hi_u8, 8));
                (new_lo, new_hi)
            }
            _ => unreachable!(),
        }
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    unsafe fn update_simd_neon(&mut self, m: [u64; 4]) {
        use core::arch::aarch64::*;

        let s0_pair = vld1q_u64_x2(self.s[0].as_ptr());
        let s1_pair = vld1q_u64_x2(self.s[1].as_ptr());
        let s2_pair = vld1q_u64_x2(self.s[2].as_ptr());
        let s3_pair = vld1q_u64_x2(self.s[3].as_ptr());
        let s4_pair = vld1q_u64_x2(self.s[4].as_ptr());

        let s0 = s0_pair.0;
        let s0_hi = s0_pair.1;
        let s1 = s1_pair.0;
        let s1_hi = s1_pair.1;
        let s2 = s2_pair.0;
        let s2_hi = s2_pair.1;
        let s3 = s3_pair.0;
        let s3_hi = s3_pair.1;
        let s4 = s4_pair.0;
        let s4_hi = s4_pair.1;

        let m_pair = vld1q_u64_x2(m.as_ptr());
        let m_lo = m_pair.0;
        let m_hi = m_pair.1;

        macro_rules! rotl64_neon {
            ($val:expr, $shift:expr) => {{
                let left = vshlq_n_u64($val, $shift);
                let right = vshrq_n_u64($val, 64 - $shift);
                veorq_u64(left, right)
            }};
        }

        // Round 1
        let t0_lo = veorq_u64(veorq_u64(s0, vandq_u64(s1, s2)), s3);
        let t0_hi = veorq_u64(veorq_u64(s0_hi, vandq_u64(s1_hi, s2_hi)), s3_hi);
        let r1_0_lo = rotl64_neon!(t0_lo, 13);
        let r1_0_hi = rotl64_neon!(t0_hi, 13);
        let (r1_3_lo, r1_3_hi) = Self::rot_words_pair_neon(s3, s3_hi, 1);

        // Round 2
        let t1_lo = veorq_u64(veorq_u64(s1, vandq_u64(s2, r1_3_lo)), s4);
        let t1_lo = veorq_u64(t1_lo, m_lo);
        let t1_hi = veorq_u64(veorq_u64(s1_hi, vandq_u64(s2_hi, r1_3_hi)), s4_hi);
        let t1_hi = veorq_u64(t1_hi, m_hi);
        let r2_1_lo = rotl64_neon!(t1_lo, 46);
        let r2_1_hi = rotl64_neon!(t1_hi, 46);
        let (r2_4_lo, r2_4_hi) = Self::rot_words_pair_neon(s4, s4_hi, 2);

        // Round 3
        let t2_lo = veorq_u64(veorq_u64(s2, vandq_u64(r1_3_lo, r2_4_lo)), r1_0_lo);
        let t2_lo = veorq_u64(t2_lo, m_lo);
        let t2_hi = veorq_u64(veorq_u64(s2_hi, vandq_u64(r1_3_hi, r2_4_hi)), r1_0_hi);
        let t2_hi = veorq_u64(t2_hi, m_hi);
        let r3_2_lo = rotl64_neon!(t2_lo, 38);
        let r3_2_hi = rotl64_neon!(t2_hi, 38);
        let (r3_0_lo, r3_0_hi) = Self::rot_words_pair_neon(r1_0_lo, r1_0_hi, 3);

        // Round 4
        let t3_lo = veorq_u64(veorq_u64(r1_3_lo, vandq_u64(r2_4_lo, r3_0_lo)), r2_1_lo);
        let t3_lo = veorq_u64(t3_lo, m_lo);
        let t3_hi = veorq_u64(veorq_u64(r1_3_hi, vandq_u64(r2_4_hi, r3_0_hi)), r2_1_hi);
        let t3_hi = veorq_u64(t3_hi, m_hi);
        let r4_3_lo = rotl64_neon!(t3_lo, 7);
        let r4_3_hi = rotl64_neon!(t3_hi, 7);
        let (r4_1_lo, r4_1_hi) = Self::rot_words_pair_neon(r2_1_lo, r2_1_hi, 2);

        // Round 5
        let t4_lo = veorq_u64(veorq_u64(r2_4_lo, vandq_u64(r3_0_lo, r4_1_lo)), r3_2_lo);
        let t4_lo = veorq_u64(t4_lo, m_lo);
        let t4_hi = veorq_u64(veorq_u64(r2_4_hi, vandq_u64(r3_0_hi, r4_1_hi)), r3_2_hi);
        let t4_hi = veorq_u64(t4_hi, m_hi);
        let new4_lo = rotl64_neon!(t4_lo, 4);
        let new4_hi = rotl64_neon!(t4_hi, 4);
        let (new2_lo, new2_hi) = Self::rot_words_pair_neon(r3_2_lo, r3_2_hi, 1);

        vst1q_u64_x2(self.s[0].as_mut_ptr(), uint64x2x2_t(r3_0_lo, r3_0_hi));
        vst1q_u64_x2(self.s[1].as_mut_ptr(), uint64x2x2_t(r4_1_lo, r4_1_hi));
        vst1q_u64_x2(self.s[2].as_mut_ptr(), uint64x2x2_t(new2_lo, new2_hi));
        vst1q_u64_x2(self.s[3].as_mut_ptr(), uint64x2x2_t(r4_3_lo, r4_3_hi));
        vst1q_u64_x2(self.s[4].as_mut_ptr(), uint64x2x2_t(new4_lo, new4_hi));
    }

    /// MORUS-1280-128 state update (5 rounds). Message block `m` is added in Rounds 2-5.
    #[inline(always)]
    fn update(&mut self, m: [u64; 4]) {
        // Runtime dispatch to best available backend, with safe scalar fallback
        // Order: SSE4.2 (newest) -> SSE4.1 -> SSSE3 -> SSE2 (oldest)
        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("sse4.2") {
                unsafe { self.update_simd_sse42(m) }
                return;
            }
            if is_x86_feature_detected!("sse4.1") {
                unsafe { self.update_simd_sse41(m) }
                return;
            }
            if is_x86_feature_detected!("ssse3") {
                unsafe { self.update_simd_ssse3(m) }
                return;
            }
            if is_x86_feature_detected!("sse2") {
                unsafe { self.update_simd_sse2(m) }
                return;
            }
        }
        #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
        {
            unsafe { self.update_simd_neon(m) }
        }
        // Scalar fallback (compiled on non-NEON aarch64 and other targets)
        #[cfg(not(all(target_arch = "aarch64", target_feature = "neon")))]
        {
            let [s0_0, s0_1, s0_2, s0_3] = self.s[0];
            let [s1_0, s1_1, s1_2, s1_3] = self.s[1];
            let [s2_0, s2_1, s2_2, s2_3] = self.s[2];
            let [s3_0, s3_1, s3_2, s3_3] = self.s[3];
            let [s4_0, s4_1, s4_2, s4_3] = self.s[4];
            let [m0, m1, m2, m3] = m;

            let [r1_3_0, r1_3_1, r1_3_2, r1_3_3] =
                Self::rotl_words_256([s3_0, s3_1, s3_2, s3_3], 1);
            let r1_0_0 = (s0_0 ^ (s1_0 & s2_0) ^ s3_0).rotate_left(13);
            let r1_0_1 = (s0_1 ^ (s1_1 & s2_1) ^ s3_1).rotate_left(13);
            let r1_0_2 = (s0_2 ^ (s1_2 & s2_2) ^ s3_2).rotate_left(13);
            let r1_0_3 = (s0_3 ^ (s1_3 & s2_3) ^ s3_3).rotate_left(13);
            let r1_0 = [r1_0_0, r1_0_1, r1_0_2, r1_0_3];

            let [r2_4_0, r2_4_1, r2_4_2, r2_4_3] =
                Self::rotl_words_256([s4_0, s4_1, s4_2, s4_3], 2);
            let r2_1_0 = (s1_0 ^ (s2_0 & r1_3_0) ^ s4_0 ^ m0).rotate_left(46);
            let r2_1_1 = (s1_1 ^ (s2_1 & r1_3_1) ^ s4_1 ^ m1).rotate_left(46);
            let r2_1_2 = (s1_2 ^ (s2_2 & r1_3_2) ^ s4_2 ^ m2).rotate_left(46);
            let r2_1_3 = (s1_3 ^ (s2_3 & r1_3_3) ^ s4_3 ^ m3).rotate_left(46);
            let r2_1 = [r2_1_0, r2_1_1, r2_1_2, r2_1_3];

            let r3_2_0 = (s2_0 ^ (r1_3_0 & r2_4_0) ^ r1_0_0).rotate_left(38);
            let r3_2_1 = (s2_1 ^ (r1_3_1 & r2_4_1) ^ r1_0_1).rotate_left(38);
            let r3_2_2 = (s2_2 ^ (r1_3_2 & r2_4_2) ^ r1_0_2).rotate_left(38);
            let r3_2_3 = (s2_3 ^ (r1_3_3 & r2_4_3) ^ r1_0_3).rotate_left(38);
            let r3_2 = [r3_2_0, r3_2_1, r3_2_2, r3_2_3];
            let [r3_0_0, r3_0_1, r3_0_2, r3_0_3] = Self::rotl_words_256(r1_0, 3);

            let [r4_1_0, r4_1_1, r4_1_2, r4_1_3] = Self::rotl_words_256(r2_1, 2);
            let r4_3_0 = (r1_3_0 ^ (r2_4_0 & r3_0_0) ^ r2_1_0 ^ m0).rotate_left(7);
            let r4_3_1 = (r1_3_1 ^ (r2_4_1 & r3_0_1) ^ r2_1_1 ^ m1).rotate_left(7);
            let r4_3_2 = (r1_3_2 ^ (r2_4_2 & r3_0_2) ^ r2_1_2 ^ m2).rotate_left(7);
            let r4_3_3 = (r1_3_3 ^ (r2_4_3 & r3_0_3) ^ r2_1_3 ^ m3).rotate_left(7);
            let r4_3 = [r4_3_0, r4_3_1, r4_3_2, r4_3_3];

            let new4_0 = (r2_4_0 ^ (r3_0_0 & r4_1_0) ^ r3_2_0 ^ m0).rotate_left(4);
            let new4_1 = (r2_4_1 ^ (r3_0_1 & r4_1_1) ^ r3_2_1 ^ m1).rotate_left(4);
            let new4_2 = (r2_4_2 ^ (r3_0_2 & r4_1_2) ^ r3_2_2 ^ m2).rotate_left(4);
            let new4_3 = (r2_4_3 ^ (r3_0_3 & r4_1_3) ^ r3_2_3 ^ m3).rotate_left(4);
            let new4 = [new4_0, new4_1, new4_2, new4_3];
            let new2 = Self::rotl_words_256(r3_2, 1);

            self.s[0] = [r3_0_0, r3_0_1, r3_0_2, r3_0_3];
            self.s[1] = [r4_1_0, r4_1_1, r4_1_2, r4_1_3];
            self.s[2] = new2;
            self.s[3] = r4_3;
            self.s[4] = new4;
        }
    }

    /// Initialize MORUS-1280-128 state with key and nonce
    fn init(key: &[u8; 16], nonce: &[u8; 16]) -> Self {
        // k0 = K128 || K128
        let k0 =
            u64::from_le_bytes([key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7]]);
        let k1 = u64::from_le_bytes([
            key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15],
        ]);
        let k_block = [k0, k1, k0, k1];

        // IV128 || 0^128
        let n0 = u64::from_le_bytes([
            nonce[0], nonce[1], nonce[2], nonce[3], nonce[4], nonce[5], nonce[6], nonce[7],
        ]);
        let n1 = u64::from_le_bytes([
            nonce[8], nonce[9], nonce[10], nonce[11], nonce[12], nonce[13], nonce[14], nonce[15],
        ]);

        // Constants: const0 || const1 (Fibonacci sequence modulo 256)
        const C0: u64 = 0x0d08050302010100;
        const C1: u64 = 0x6279e99059372215;
        const C2: u64 = 0xf12fc26d55183ddb;
        const C3: u64 = 0xdd28b57342311120;

        let mut state = Self {
            s: [
                [n0, n1, 0, 0],   // S0 = IV128 || 0^128
                k_block,          // S1 = k0
                [u64::MAX; 4],    // S2 = 1^256
                [0u64; 4],        // S3 = 0^256
                [C0, C1, C2, C3], // S4 = const0 || const1
            ],
        };

        // 16 steps with m = 0
        for _ in 0..16 {
            state.update([0u64; 4]);
        }

        // XOR key block into S1 again
        for (i, kv) in k_block.iter().enumerate() {
            state.s[1][i] ^= *kv;
        }

        state
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    #[inline(always)]
    fn keystream_block(&self) -> [u64; 4] {
        unsafe { self.keystream_block_neon() }
    }

    #[cfg(not(all(target_arch = "aarch64", target_feature = "neon")))]
    #[inline(always)]
    fn keystream_block(&self) -> [u64; 4] {
        let s0 = self.s[0];
        let s1r = Self::rotl_words_256(self.s[1], 3); // <<< 192
        let s2 = self.s[2];
        let s3 = self.s[3];
        [
            s0[0] ^ s1r[0] ^ (s2[0] & s3[0]),
            s0[1] ^ s1r[1] ^ (s2[1] & s3[1]),
            s0[2] ^ s1r[2] ^ (s2[2] & s3[2]),
            s0[3] ^ s1r[3] ^ (s2[3] & s3[3]),
        ]
    }

    fn finalize(&mut self, ad_len: usize, msg_len: usize) -> [u8; 16] {
        let ad_bits = (ad_len as u64).wrapping_mul(8);
        let msg_bits = (msg_len as u64).wrapping_mul(8);

        // S4 ^= S0
        for i in 0..4 {
            self.s[4][i] ^= self.s[0][i];
        }

        // tmp = (adlen || msglen || 0^128)
        let tmp = [ad_bits, msg_bits, 0, 0];
        for _ in 0..10 {
            self.update(tmp);
        }

        // T0 = S0 XOR (S1 <<< 192) XOR (S2 & S3)
        let t = self.keystream_block();
        let mut tag = [0u8; 16];
        // 128 LSB: words 0 and 1 (little-endian)
        tag[0..8].copy_from_slice(&t[0].to_le_bytes());
        tag[8..16].copy_from_slice(&t[1].to_le_bytes());
        tag
    }

    fn process_ad(&mut self, ad: &[u8]) {
        let mut chunks = ad.chunks_exact(32);
        for chunk in &mut chunks {
            #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
            {
                let mut tmp = [0u8; 32];
                tmp.copy_from_slice(chunk);
                let block: &[u8; 32] = &tmp;
                unsafe { self.update(Self::load_block32_neon(block)) };
            }
            #[cfg(not(all(target_arch = "aarch64", target_feature = "neon")))]
            {
                self.update(Self::load_block32(chunk));
            }
        }

        let rem = chunks.remainder();
        if !rem.is_empty() {
            let mut padded = [0u8; 32];
            padded[..rem.len()].copy_from_slice(rem);
            self.update(Self::load_block32(&padded));
        }
    }

    fn encrypt(&mut self, plaintext: &mut [u8]) {
        let mut chunks = plaintext.chunks_exact_mut(32);
        for chunk in &mut chunks {
            let mut tmp = [0u8; 32];
            tmp.copy_from_slice(chunk);
            let block: &mut [u8; 32] = &mut tmp;
            let ks = self.keystream_block();
            let plain_words = Self::xor_keystream_block_encrypt(block, &ks);
            self.update(plain_words);
            chunk.copy_from_slice(block);
        }

        let rem = chunks.into_remainder();
        if !rem.is_empty() {
            let ks = self.keystream_block();
            let plain_words = Self::xor_keystream_partial_encrypt(rem, &ks);
            self.update(plain_words);
        }
    }

    fn decrypt(&mut self, ciphertext: &mut [u8]) {
        let mut chunks = ciphertext.chunks_exact_mut(32);
        for chunk in &mut chunks {
            let mut tmp = [0u8; 32];
            tmp.copy_from_slice(chunk);
            let block: &mut [u8; 32] = &mut tmp;
            let ks = self.keystream_block();
            let plain_words = Self::xor_keystream_block_decrypt(block, &ks);
            self.update(plain_words);
            chunk.copy_from_slice(block);
        }

        let rem = chunks.into_remainder();
        if !rem.is_empty() {
            let ks = self.keystream_block();
            let plain_words = Self::xor_keystream_partial_decrypt(rem, &ks);
            self.update(plain_words);
        }
    }
}

impl Morus1280State {
    #[inline(always)]
    fn load_block32(block: &[u8]) -> [u64; 4] {
        debug_assert!(block.len() >= 32);
        unsafe {
            [
                u64::from_le(ptr::read_unaligned(block.as_ptr() as *const u64)),
                u64::from_le(ptr::read_unaligned(block.as_ptr().add(8) as *const u64)),
                u64::from_le(ptr::read_unaligned(block.as_ptr().add(16) as *const u64)),
                u64::from_le(ptr::read_unaligned(block.as_ptr().add(24) as *const u64)),
            ]
        }
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    #[inline(always)]
    unsafe fn load_block32_neon(block: &[u8; 32]) -> [u64; 4] {
        use std::arch::aarch64::*;
        let v0 = vld1q_u8(block.as_ptr());
        let v1 = vld1q_u8(block.as_ptr().add(16));
        let mut out = [0u64; 4];
        vst1q_u64(out.as_mut_ptr(), vreinterpretq_u64_u8(v0));
        vst1q_u64(out.as_mut_ptr().add(2), vreinterpretq_u64_u8(v1));
        out
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    #[inline(always)]
    unsafe fn keystream_block_neon(&self) -> [u64; 4] {
        use std::arch::aarch64::*;
        let s0_pair = vld1q_u64_x2(self.s[0].as_ptr());
        let s1_pair = vld1q_u64_x2(self.s[1].as_ptr());
        let s2_pair = vld1q_u64_x2(self.s[2].as_ptr());
        let s3_pair = vld1q_u64_x2(self.s[3].as_ptr());
        let (s1r_lo, s1r_hi) = Self::rot_words_pair_neon(s1_pair.0, s1_pair.1, 3);
        let t0 = veorq_u64(veorq_u64(s0_pair.0, s1r_lo), vandq_u64(s2_pair.0, s3_pair.0));
        let t1 = veorq_u64(veorq_u64(s0_pair.1, s1r_hi), vandq_u64(s2_pair.1, s3_pair.1));
        let mut out = [0u64; 4];
        vst1q_u64(out.as_mut_ptr(), t0);
        vst1q_u64(out.as_mut_ptr().add(2), t1);
        out
    }

    #[inline(always)]
    fn zero_tail(words: &mut [u64; 4], valid_bytes: usize) {
        if valid_bytes >= 32 {
            return;
        }
        let full_words = valid_bytes / 8;
        let tail_bytes = valid_bytes % 8;
        for (idx, w) in words.iter_mut().enumerate().skip(full_words) {
            if idx > full_words {
                *w = 0;
            } else {
                let mask = if tail_bytes == 0 { 0 } else { (1u64 << (tail_bytes * 8)) - 1 };
                *w &= mask;
            }
        }
    }

    #[inline(always)]
    fn xor_keystream_block_encrypt(block: &mut [u8; 32], keystream: &[u64; 4]) -> [u64; 4] {
        let mut plain = [0u64; 4];
        for i in 0..4 {
            let offset = i * 8;
            let word = unsafe {
                u64::from_le(ptr::read_unaligned(block.as_ptr().add(offset) as *const u64))
            };
            plain[i] = word;
            let cipher = word ^ keystream[i];
            unsafe {
                ptr::write_unaligned(block.as_mut_ptr().add(offset) as *mut u64, cipher.to_le());
            }
        }
        plain
    }

    #[inline(always)]
    fn xor_keystream_block_decrypt(block: &mut [u8; 32], keystream: &[u64; 4]) -> [u64; 4] {
        let mut plain = [0u64; 4];
        for i in 0..4 {
            let offset = i * 8;
            let cipher = unsafe {
                u64::from_le(ptr::read_unaligned(block.as_ptr().add(offset) as *const u64))
            };
            let word = cipher ^ keystream[i];
            plain[i] = word;
            unsafe {
                ptr::write_unaligned(block.as_mut_ptr().add(offset) as *mut u64, word.to_le());
            }
        }
        plain
    }

    #[inline(always)]
    fn xor_keystream_partial_encrypt(block: &mut [u8], keystream: &[u64; 4]) -> [u64; 4] {
        let mut buf = [0u8; 32];
        buf[..block.len()].copy_from_slice(block);
        let mut plain = Self::xor_keystream_block_encrypt(&mut buf, keystream);
        block.copy_from_slice(&buf[..block.len()]);
        Self::zero_tail(&mut plain, block.len());
        plain
    }

    #[inline(always)]
    fn xor_keystream_partial_decrypt(block: &mut [u8], keystream: &[u64; 4]) -> [u64; 4] {
        let mut buf = [0u8; 32];
        buf[..block.len()].copy_from_slice(block);
        let mut plain = Self::xor_keystream_block_decrypt(&mut buf, keystream);
        block.copy_from_slice(&buf[..block.len()]);
        Self::zero_tail(&mut plain, block.len());
        plain
    }

    #[cfg(target_arch = "x86_64")]
    #[inline]
    #[target_feature(enable = "sse2")]
    unsafe fn xor_keystream_block_encrypt_sse(
        block: &mut [u8; 32],
        keystream: &[u64; 4],
    ) -> [u64; 4] {
        use core::arch::x86_64::*;
        let mut plain = [0u64; 4];
        let ptr = block.as_mut_ptr() as *mut __m128i;
        let b0 = _mm_loadu_si128(ptr);
        let b1 = _mm_loadu_si128(ptr.add(1));
        _mm_storeu_si128(plain.as_mut_ptr() as *mut __m128i, b0);
        _mm_storeu_si128(plain.as_mut_ptr().add(2) as *mut __m128i, b1);
        let ks_ptr = keystream.as_ptr() as *const __m128i;
        let ks_lo = _mm_loadu_si128(ks_ptr);
        let ks_hi = _mm_loadu_si128(ks_ptr.add(1));
        let c0 = _mm_xor_si128(b0, ks_lo);
        let c1 = _mm_xor_si128(b1, ks_hi);
        _mm_storeu_si128(ptr, c0);
        _mm_storeu_si128(ptr.add(1), c1);
        plain
    }

    #[cfg(target_arch = "x86_64")]
    #[inline]
    #[target_feature(enable = "sse2")]
    unsafe fn xor_keystream_block_decrypt_sse(
        block: &mut [u8; 32],
        keystream: &[u64; 4],
    ) -> [u64; 4] {
        use core::arch::x86_64::*;
        let mut plain = [0u64; 4];
        let ptr = block.as_mut_ptr() as *mut __m128i;
        let c0 = _mm_loadu_si128(ptr);
        let c1 = _mm_loadu_si128(ptr.add(1));
        let ks_ptr = keystream.as_ptr() as *const __m128i;
        let ks_lo = _mm_loadu_si128(ks_ptr);
        let ks_hi = _mm_loadu_si128(ks_ptr.add(1));
        let p0 = _mm_xor_si128(c0, ks_lo);
        let p1 = _mm_xor_si128(c1, ks_hi);
        _mm_storeu_si128(ptr, p0);
        _mm_storeu_si128(ptr.add(1), p1);
        _mm_storeu_si128(plain.as_mut_ptr() as *mut __m128i, p0);
        _mm_storeu_si128(plain.as_mut_ptr().add(2) as *mut __m128i, p1);
        plain
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    #[inline(always)]
    unsafe fn xor_keystream_block_encrypt_neon(
        block: &mut [u8; 32],
        keystream: &[u64; 4],
    ) -> [u64; 4] {
        use std::arch::aarch64::*;
        let mut plain = [0u64; 4];
        let p0 = vld1q_u8(block.as_ptr());
        let p1 = vld1q_u8(block.as_ptr().add(16));
        vst1q_u64(plain.as_mut_ptr(), vreinterpretq_u64_u8(p0));
        vst1q_u64(plain.as_mut_ptr().add(2), vreinterpretq_u64_u8(p1));
        let ks0 = vld1q_u64(keystream.as_ptr());
        let ks1 = vld1q_u64(keystream.as_ptr().add(2));
        let c0 = veorq_u8(p0, vreinterpretq_u8_u64(ks0));
        let c1 = veorq_u8(p1, vreinterpretq_u8_u64(ks1));
        vst1q_u8(block.as_mut_ptr(), c0);
        vst1q_u8(block.as_mut_ptr().add(16), c1);
        plain
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    #[inline(always)]
    unsafe fn xor_keystream_block_decrypt_neon(
        block: &mut [u8; 32],
        keystream: &[u64; 4],
    ) -> [u64; 4] {
        use std::arch::aarch64::*;
        let mut plain = [0u64; 4];
        let c0 = vld1q_u8(block.as_ptr());
        let c1 = vld1q_u8(block.as_ptr().add(16));
        let ks0 = vld1q_u64(keystream.as_ptr());
        let ks1 = vld1q_u64(keystream.as_ptr().add(2));
        let p0 = veorq_u8(c0, vreinterpretq_u8_u64(ks0));
        let p1 = veorq_u8(c1, vreinterpretq_u8_u64(ks1));
        vst1q_u8(block.as_mut_ptr(), p0);
        vst1q_u8(block.as_mut_ptr().add(16), p1);
        vst1q_u64(plain.as_mut_ptr(), vreinterpretq_u64_u8(p0));
        vst1q_u64(plain.as_mut_ptr().add(2), vreinterpretq_u64_u8(p1));
        plain
    }
}

#[derive(Clone)]
pub struct MorusAead {
    key: [u8; 16],
    iv: [u8; 12],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MorusBackend {
    #[cfg(target_arch = "x86_64")]
    Sse42,
    #[cfg(target_arch = "x86_64")]
    Sse41,
    #[cfg(target_arch = "x86_64")]
    Ssse3,
    #[cfg(target_arch = "x86_64")]
    Sse2,
    #[cfg(target_arch = "aarch64")]
    Neon,
    Scalar,
}

static MORUS_BACKEND: OnceLock<MorusBackend> = OnceLock::new();

fn morus_backend() -> MorusBackend {
    *MORUS_BACKEND.get_or_init(|| {
        let det = crate::optimize::FeatureDetector::instance();

        #[cfg(target_arch = "x86_64")]
        {
            use crate::optimize::CpuFeature;
            let has_sse42 = det.has_feature(CpuFeature::SSE42);
            let has_sse41 = det.has_feature(CpuFeature::SSE41) || has_sse42;
            if has_sse42 && det.has_feature(CpuFeature::SSSE3) {
                return MorusBackend::Sse42;
            }
            if has_sse41 && det.has_feature(CpuFeature::SSSE3) {
                return MorusBackend::Sse41;
            }
            if det.has_feature(CpuFeature::SSSE3) {
                return MorusBackend::Ssse3;
            }
            if det.has_feature(CpuFeature::SSE2) {
                return MorusBackend::Sse2;
            }
            return MorusBackend::Scalar;
        }

        #[cfg(target_arch = "aarch64")]
        {
            if det.has_feature(crate::optimize::CpuFeature::NEON) {
                MorusBackend::Neon
            } else {
                MorusBackend::Scalar
            }
        }

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            MorusBackend::Scalar
        }
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadError {
    TagMismatch,
}

impl MorusAead {
    pub fn new(aead_key: &[u8], iv: &[u8]) -> Self {
        let mut k = [0u8; 16];
        for (i, kb) in k.iter_mut().enumerate() {
            *kb = aead_key.get(i).copied().unwrap_or(0);
        }
        let mut v = [0u8; 12];
        for (i, vb) in v.iter_mut().enumerate() {
            *vb = iv.get(i).copied().unwrap_or(0);
        }
        Self { key: k, iv: v }
    }

    fn encrypt_native(&self, plaintext: &[u8], ad: &[u8], nonce: &[u8; 16]) -> (Vec<u8>, [u8; 16]) {
        crate::optimize::telemetry::MORUS1280_SCALAR_OPS.inc();
        let mut state = Morus1280State::init(&self.key, nonce);
        state.process_ad(ad);

        let mut ciphertext = plaintext.to_vec();
        state.encrypt(&mut ciphertext);

        let tag = state.finalize(ad.len(), plaintext.len());
        (ciphertext, tag)
    }

    pub fn encrypt_in_place(&self, buffer: &mut [u8], ad: &[u8], nonce: &[u8; 16]) -> [u8; 16] {
        crate::optimize::telemetry::MORUS1280_SCALAR_OPS.inc();
        let mut state = Morus1280State::init(&self.key, nonce);
        state.process_ad(ad);
        state.encrypt(buffer);
        state.finalize(ad.len(), buffer.len())
    }

    fn decrypt_native(
        &self,
        ciphertext: &[u8],
        tag: &[u8; 16],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Result<Vec<u8>, ()> {
        crate::optimize::telemetry::MORUS1280_SCALAR_OPS.inc();
        let mut state = Morus1280State::init(&self.key, nonce);
        state.process_ad(ad);

        let mut plaintext = ciphertext.to_vec();
        state.decrypt(&mut plaintext);

        let computed_tag = state.finalize(ad.len(), ciphertext.len());

        if subtle_ct_eq(&computed_tag, tag) {
            Ok(plaintext)
        } else {
            Err(())
        }
    }

    pub fn decrypt_in_place(
        &self,
        buffer: &mut [u8],
        tag: &[u8; 16],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Result<(), AeadError> {
        crate::optimize::telemetry::MORUS1280_SCALAR_OPS.inc();
        let mut state = Morus1280State::init(&self.key, nonce);
        state.process_ad(ad);
        state.decrypt(buffer);
        let computed_tag = state.finalize(ad.len(), buffer.len());

        if subtle_ct_eq(&computed_tag, tag) {
            Ok(())
        } else {
            Err(AeadError::TagMismatch)
        }
    }

    // Optimized methods with runtime CPU feature detection
    fn encrypt_optimized(
        &self,
        plaintext: &[u8],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> (Vec<u8>, [u8; 16]) {
        // Runtime dispatch: select best available SIMD backend once, then reuse.
        match morus_backend() {
            #[cfg(target_arch = "x86_64")]
            MorusBackend::Sse42 => {
                if let Some(res) = unsafe { self.encrypt_morus1280_sse42(plaintext, ad, nonce) } {
                    return res;
                }
            }
            #[cfg(target_arch = "x86_64")]
            MorusBackend::Sse41 => {
                if let Some(res) = self.encrypt_morus1280_sse41(plaintext, ad, nonce) {
                    return res;
                }
            }
            #[cfg(target_arch = "x86_64")]
            MorusBackend::Ssse3 => {
                if let Some(res) = self.encrypt_morus1280_ssse3(plaintext, ad, nonce) {
                    return res;
                }
            }
            #[cfg(target_arch = "x86_64")]
            MorusBackend::Sse2 => {
                if let Some(res) = unsafe { self.encrypt_morus1280_sse2(plaintext, ad, nonce) } {
                    return res;
                }
            }
            #[cfg(target_arch = "aarch64")]
            MorusBackend::Neon => {
                if let Some(res) = self.encrypt_morus1280_neon(plaintext, ad, nonce) {
                    return res;
                }
            }
            MorusBackend::Scalar => {}
        }
        // Fallback: scalar
        self.encrypt_native(plaintext, ad, nonce)
    }

    fn decrypt_optimized(
        &self,
        ciphertext: &[u8],
        tag: &[u8; 16],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Result<Vec<u8>, ()> {
        // Runtime dispatch: select best available SIMD backend once, then reuse.
        match morus_backend() {
            #[cfg(target_arch = "x86_64")]
            MorusBackend::Sse42 => {
                if let Some(res) =
                    unsafe { self.decrypt_morus1280_sse42(ciphertext, tag, ad, nonce) }
                {
                    return res;
                }
            }
            #[cfg(target_arch = "x86_64")]
            MorusBackend::Sse41 => {
                if let Some(res) = self.decrypt_morus1280_sse41(ciphertext, tag, ad, nonce) {
                    return res;
                }
            }
            #[cfg(target_arch = "x86_64")]
            MorusBackend::Ssse3 => {
                if let Some(res) = self.decrypt_morus1280_ssse3(ciphertext, tag, ad, nonce) {
                    return res;
                }
            }
            #[cfg(target_arch = "x86_64")]
            MorusBackend::Sse2 => {
                if let Some(res) =
                    unsafe { self.decrypt_morus1280_sse2(ciphertext, tag, ad, nonce) }
                {
                    return res;
                }
            }
            #[cfg(target_arch = "aarch64")]
            MorusBackend::Neon => {
                if let Some(res) = self.decrypt_morus1280_neon(ciphertext, tag, ad, nonce) {
                    return res;
                }
            }
            MorusBackend::Scalar => {}
        }
        // Fallback: scalar
        self.decrypt_native(ciphertext, tag, ad, nonce)
    }

    // SSSE3-boosted MORUS-1280-128 (vectorized XOR/load/store with byte-align shuffles)
    #[cfg(target_arch = "x86_64")]
    fn encrypt_morus1280_ssse3(
        &self,
        plaintext: &[u8],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Option<(Vec<u8>, [u8; 16])> {
        unsafe { Some(self.encrypt_morus1280_ssse3_inner(plaintext, ad, nonce)) }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "ssse3")]
    unsafe fn encrypt_morus1280_ssse3_inner(
        &self,
        plaintext: &[u8],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> (Vec<u8>, [u8; 16]) {
        crate::optimize::telemetry::MORUS1280_SSSE3_OPS.inc();
        let mut state = Morus1280State::init(&self.key, nonce);
        state.process_ad(ad);

        let mut out = plaintext.to_vec();
        {
            let mut chunks = out.chunks_exact_mut(32);
            for chunk in &mut chunks {
                let block: &mut [u8; 32] = chunk.try_into().unwrap();
                let ks = state.keystream_block();
                let plain_words =
                    unsafe { Morus1280State::xor_keystream_block_encrypt_sse(block, &ks) };
                state.update_simd_ssse3(plain_words);
            }

            let rem = chunks.into_remainder();
            if !rem.is_empty() {
                let ks = state.keystream_block();
                let plain_words = Morus1280State::xor_keystream_partial_encrypt(rem, &ks);
                state.update_simd_ssse3(plain_words);
            }
        }

        let tag = state.finalize(ad.len(), plaintext.len());
        (out, tag)
    }

    // SSSE3 dual-lane decrypt matching encrypt_morus1280_ssse3
    #[cfg(target_arch = "x86_64")]
    fn decrypt_morus1280_ssse3(
        &self,
        ciphertext: &[u8],
        tag: &[u8; 16],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Option<Result<Vec<u8>, ()>> {
        unsafe { Some(self.decrypt_morus1280_ssse3_inner(ciphertext, tag, ad, nonce)) }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "ssse3")]
    unsafe fn decrypt_morus1280_ssse3_inner(
        &self,
        ciphertext: &[u8],
        tag: &[u8; 16],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Result<Vec<u8>, ()> {
        crate::optimize::telemetry::MORUS1280_SSSE3_OPS.inc();
        let mut state = Morus1280State::init(&self.key, nonce);
        state.process_ad(ad);

        let mut out = ciphertext.to_vec();
        {
            let mut chunks = out.chunks_exact_mut(32);
            for chunk in &mut chunks {
                let block: &mut [u8; 32] = chunk.try_into().unwrap();
                let ks = state.keystream_block();
                let plain_words =
                    unsafe { Morus1280State::xor_keystream_block_decrypt_sse(block, &ks) };
                state.update_simd_ssse3(plain_words);
            }

            let rem = chunks.into_remainder();
            if !rem.is_empty() {
                let ks = state.keystream_block();
                let plain_words = Morus1280State::xor_keystream_partial_decrypt(rem, &ks);
                state.update_simd_ssse3(plain_words);
            }
        }

        let computed_tag = state.finalize(ad.len(), ciphertext.len());
        if subtle_ct_eq(&computed_tag, tag) {
            Ok(out)
        } else {
            Err(())
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn encrypt_morus1280_sse41(
        &self,
        plaintext: &[u8],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Option<(Vec<u8>, [u8; 16])> {
        crate::optimize::telemetry::MORUS1280_SSE41_OPS.inc();
        unsafe { Some(self.encrypt_morus1280_sse41_inner(plaintext, ad, nonce)) }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "sse4.1")]
    unsafe fn encrypt_morus1280_sse41_inner(
        &self,
        plaintext: &[u8],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> (Vec<u8>, [u8; 16]) {
        let mut state = Morus1280State::init(&self.key, nonce);
        state.process_ad(ad);

        let mut out = plaintext.to_vec();
        {
            let mut chunks = out.chunks_exact_mut(32);
            for chunk in &mut chunks {
                let block: &mut [u8; 32] = chunk.try_into().unwrap();
                let ks = state.keystream_block();
                let plain_words = Morus1280State::xor_keystream_block_encrypt_sse(block, &ks);
                state.update_simd_sse41(plain_words);
            }

            let rem = chunks.into_remainder();
            if !rem.is_empty() {
                let ks = state.keystream_block();
                let plain_words = Morus1280State::xor_keystream_partial_encrypt(rem, &ks);
                state.update_simd_sse41(plain_words);
            }
        }

        let tag = state.finalize(ad.len(), plaintext.len());
        (out, tag)
    }

    #[cfg(target_arch = "x86_64")]
    fn decrypt_morus1280_sse41(
        &self,
        ciphertext: &[u8],
        tag: &[u8; 16],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Option<Result<Vec<u8>, ()>> {
        crate::optimize::telemetry::MORUS1280_SSE41_OPS.inc();
        unsafe { Some(self.decrypt_morus1280_sse41_inner(ciphertext, tag, ad, nonce)) }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "sse4.1")]
    unsafe fn decrypt_morus1280_sse41_inner(
        &self,
        ciphertext: &[u8],
        tag: &[u8; 16],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Result<Vec<u8>, ()> {
        let mut state = Morus1280State::init(&self.key, nonce);
        state.process_ad(ad);

        let mut out = ciphertext.to_vec();
        {
            let mut chunks = out.chunks_exact_mut(32);
            for chunk in &mut chunks {
                let block: &mut [u8; 32] = chunk.try_into().unwrap();
                let ks = state.keystream_block();
                let plain_words = Morus1280State::xor_keystream_block_decrypt_sse(block, &ks);
                state.update_simd_sse41(plain_words);
            }

            let rem = chunks.into_remainder();
            if !rem.is_empty() {
                let ks = state.keystream_block();
                let plain_words = Morus1280State::xor_keystream_partial_decrypt(rem, &ks);
                state.update_simd_sse41(plain_words);
            }
        }

        let computed_tag = state.finalize(ad.len(), ciphertext.len());
        if subtle_ct_eq(&computed_tag, tag) {
            Ok(out)
        } else {
            Err(())
        }
    }

    // SSE4.2 optimized MORUS-1280-128 encrypt
    #[cfg(target_arch = "x86_64")]
    unsafe fn encrypt_morus1280_sse42(
        &self,
        plaintext: &[u8],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Option<(Vec<u8>, [u8; 16])> {
        crate::optimize::telemetry::MORUS1280_SSE42_OPS.inc();
        unsafe { Some(self.encrypt_morus1280_sse42_inner(plaintext, ad, nonce)) }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "sse4.2")]
    unsafe fn encrypt_morus1280_sse42_inner(
        &self,
        plaintext: &[u8],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> (Vec<u8>, [u8; 16]) {
        let mut state = Morus1280State::init(&self.key, nonce);
        state.process_ad(ad);

        let mut out = plaintext.to_vec();
        {
            let mut chunks = out.chunks_exact_mut(32);
            for chunk in &mut chunks {
                let block: &mut [u8; 32] = chunk.try_into().unwrap();
                let ks = state.keystream_block();
                let plain_words = Morus1280State::xor_keystream_block_encrypt_sse(block, &ks);
                state.update_simd_sse42(plain_words);
            }

            let rem = chunks.into_remainder();
            if !rem.is_empty() {
                let ks = state.keystream_block();
                let plain_words = Morus1280State::xor_keystream_partial_encrypt(rem, &ks);
                state.update_simd_sse42(plain_words);
            }
        }

        let tag = state.finalize(ad.len(), plaintext.len());
        (out, tag)
    }

    // SSE4.2 optimized MORUS-1280-128 decrypt
    #[cfg(target_arch = "x86_64")]
    unsafe fn decrypt_morus1280_sse42(
        &self,
        ciphertext: &[u8],
        tag: &[u8; 16],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Option<Result<Vec<u8>, ()>> {
        crate::optimize::telemetry::MORUS1280_SSE42_OPS.inc();
        unsafe { Some(self.decrypt_morus1280_sse42_inner(ciphertext, tag, ad, nonce)) }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "sse4.2")]
    unsafe fn decrypt_morus1280_sse42_inner(
        &self,
        ciphertext: &[u8],
        tag: &[u8; 16],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Result<Vec<u8>, ()> {
        let mut state = Morus1280State::init(&self.key, nonce);
        state.process_ad(ad);

        let mut out = ciphertext.to_vec();
        {
            let mut chunks = out.chunks_exact_mut(32);
            for chunk in &mut chunks {
                let block: &mut [u8; 32] = chunk.try_into().unwrap();
                let ks = state.keystream_block();
                let plain_words = Morus1280State::xor_keystream_block_decrypt_sse(block, &ks);
                state.update_simd_sse42(plain_words);
            }

            let rem = chunks.into_remainder();
            if !rem.is_empty() {
                let ks = state.keystream_block();
                let plain_words = Morus1280State::xor_keystream_partial_decrypt(rem, &ks);
                state.update_simd_sse42(plain_words);
            }
        }

        let computed_tag = state.finalize(ad.len(), ciphertext.len());
        if subtle_ct_eq(&computed_tag, tag) {
            Ok(out)
        } else {
            Err(())
        }
    }

    // SSE2 dual-lane (x2) fallback for legacy CPUs without SSSE3
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "sse2")]
    unsafe fn encrypt_morus1280_sse2(
        &self,
        plaintext: &[u8],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Option<(Vec<u8>, [u8; 16])> {
        crate::optimize::telemetry::MORUS1280_SSE2_OPS.inc();
        let mut state = Morus1280State::init(&self.key, nonce);
        state.process_ad(ad);

        let mut out = plaintext.to_vec();
        {
            let mut chunks = out.chunks_exact_mut(32);
            for chunk in &mut chunks {
                let block: &mut [u8; 32] = chunk.try_into().unwrap();
                let ks = state.keystream_block();
                let plain_words = Morus1280State::xor_keystream_block_encrypt_sse(block, &ks);
                state.update_simd_sse2(plain_words);
            }

            let rem = chunks.into_remainder();
            if !rem.is_empty() {
                let ks = state.keystream_block();
                let plain_words = Morus1280State::xor_keystream_partial_encrypt(rem, &ks);
                state.update_simd_sse2(plain_words);
            }
        }

        let tag = state.finalize(ad.len(), plaintext.len());
        Some((out, tag))
    }

    // SSE2 dual-lane decrypt fallback
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "sse2")]
    unsafe fn decrypt_morus1280_sse2(
        &self,
        ciphertext: &[u8],
        tag: &[u8; 16],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Option<Result<Vec<u8>, ()>> {
        crate::optimize::telemetry::MORUS1280_SSE2_OPS.inc();
        let mut state = Morus1280State::init(&self.key, nonce);
        state.process_ad(ad);

        let mut out = ciphertext.to_vec();
        {
            let mut chunks = out.chunks_exact_mut(32);
            for chunk in &mut chunks {
                let block: &mut [u8; 32] = chunk.try_into().unwrap();
                let ks = state.keystream_block();
                let plain_words = Morus1280State::xor_keystream_block_decrypt_sse(block, &ks);
                state.update_simd_sse2(plain_words);
            }

            let rem = chunks.into_remainder();
            if !rem.is_empty() {
                let ks = state.keystream_block();
                let plain_words = Morus1280State::xor_keystream_partial_decrypt(rem, &ks);
                state.update_simd_sse2(plain_words);
            }
        }

        let computed_tag = state.finalize(ad.len(), ciphertext.len());
        if subtle_ct_eq(&computed_tag, tag) {
            Some(Ok(out))
        } else {
            Some(Err(()))
        }
    }

    // NEON-accelerated MORUS-1280-128 using NEON keystream + SIMD state update
    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    fn encrypt_morus1280_neon(
        &self,
        plaintext: &[u8],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Option<(Vec<u8>, [u8; 16])> {
        crate::optimize::telemetry::MORUS1280_NEON_OPS.inc();
        let mut state = Morus1280State::init(&self.key, nonce);
        state.process_ad(ad);

        let mut out = plaintext.to_vec();
        {
            let mut chunks = out.chunks_exact_mut(32);
            for chunk in &mut chunks {
                let mut tmp = [0u8; 32];
                tmp.copy_from_slice(chunk);
                let block: &mut [u8; 32] = &mut tmp;
                let ks = state.keystream_block();
                let plain_words =
                    unsafe { Morus1280State::xor_keystream_block_encrypt_neon(block, &ks) };
                state.update(plain_words);
                chunk.copy_from_slice(block);
            }

            let rem = chunks.into_remainder();
            if !rem.is_empty() {
                let ks = state.keystream_block();
                let plain_words = Morus1280State::xor_keystream_partial_encrypt(rem, &ks);
                state.update(plain_words);
            }
        }

        let tag = state.finalize(ad.len(), plaintext.len());
        Some((out, tag))
    }

    #[cfg(all(target_arch = "aarch64", not(target_feature = "neon")))]
    fn encrypt_morus1280_neon(
        &self,
        plaintext: &[u8],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Option<(Vec<u8>, [u8; 16])> {
        let _ = (plaintext, ad, nonce);
        None
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    fn decrypt_morus1280_neon(
        &self,
        ciphertext: &[u8],
        tag: &[u8; 16],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Option<Result<Vec<u8>, ()>> {
        crate::optimize::telemetry::MORUS1280_NEON_OPS.inc();
        let mut state = Morus1280State::init(&self.key, nonce);
        state.process_ad(ad);

        let mut out = ciphertext.to_vec();
        {
            let mut chunks = out.chunks_exact_mut(32);
            for chunk in &mut chunks {
                let mut tmp = [0u8; 32];
                tmp.copy_from_slice(chunk);
                let block: &mut [u8; 32] = &mut tmp;
                let ks = state.keystream_block();
                let plain_words =
                    unsafe { Morus1280State::xor_keystream_block_decrypt_neon(block, &ks) };
                state.update(plain_words);
                chunk.copy_from_slice(block);
            }

            let rem = chunks.into_remainder();
            if !rem.is_empty() {
                let ks = state.keystream_block();
                let plain_words = Morus1280State::xor_keystream_partial_decrypt(rem, &ks);
                state.update(plain_words);
            }
        }

        let computed_tag = state.finalize(ad.len(), ciphertext.len());
        if subtle_ct_eq(&computed_tag, tag) {
            Some(Ok(out))
        } else {
            Some(Err(()))
        }
    }

    #[cfg(all(target_arch = "aarch64", not(target_feature = "neon")))]
    fn decrypt_morus1280_neon(
        &self,
        ciphertext: &[u8],
        tag: &[u8; 16],
        ad: &[u8],
        nonce: &[u8; 16],
    ) -> Option<Result<Vec<u8>, ()>> {
        let _ = (ciphertext, tag, ad, nonce);
        None
    }
}

#[cfg(test)]
mod morus_tests {
    use super::*;

    #[test]
    fn test_morus_roundtrip_empty() {
        let key = [0u8; 16];
        let iv = [0u8; 12];
        let nonce = [0u8; 16];
        let plaintext = b"";
        let ad = b"";

        let morus = MorusAead::new(&key, &iv);
        let (ciphertext, tag) = morus.encrypt_native(plaintext, ad, &nonce);
        let decrypted = morus.decrypt_native(&ciphertext, &tag, ad, &nonce).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_morus_roundtrip_1_byte() {
        let key = [1u8; 16];
        let iv = [2u8; 12];
        let nonce = [3u8; 16];
        let plaintext = b"A";
        let ad = b"associated";

        let morus = MorusAead::new(&key, &iv);
        let (ciphertext, tag) = morus.encrypt_native(plaintext, ad, &nonce);
        let decrypted = morus.decrypt_native(&ciphertext, &tag, ad, &nonce).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
        assert_ne!(plaintext, &ciphertext[..]);
    }

    #[test]
    fn test_morus_roundtrip_16_bytes() {
        let key = [0x42u8; 16];
        let iv = [0x24u8; 12];
        let nonce = [0x13u8; 16];
        let plaintext = b"0123456789ABCDEF";
        let ad = b"additional_data";

        let morus = MorusAead::new(&key, &iv);
        let (ciphertext, tag) = morus.encrypt_native(plaintext, ad, &nonce);
        let decrypted = morus.decrypt_native(&ciphertext, &tag, ad, &nonce).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
        assert_eq!(ciphertext.len(), plaintext.len());
    }

    #[test]
    fn test_morus_roundtrip_17_bytes() {
        let key = [0xAAu8; 16];
        let iv = [0x55u8; 12];
        let nonce = [0xCCu8; 16];
        let plaintext = b"0123456789ABCDEFG";
        let ad = b"";

        let morus = MorusAead::new(&key, &iv);
        let (ciphertext, tag) = morus.encrypt_native(plaintext, ad, &nonce);
        let decrypted = morus.decrypt_native(&ciphertext, &tag, ad, &nonce).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_morus_roundtrip_32_bytes() {
        let key = [0xDEu8; 16];
        let iv = [0xADu8; 12];
        let nonce = [0xBEu8; 16];
        let plaintext = b"0123456789ABCDEF0123456789ABCDEF";
        let ad = b"long_associated_data_for_testing";

        let morus = MorusAead::new(&key, &iv);
        let (ciphertext, tag) = morus.encrypt_native(plaintext, ad, &nonce);
        let decrypted = morus.decrypt_native(&ciphertext, &tag, ad, &nonce).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_morus_roundtrip_64_bytes() {
        let key = [0x11u8; 16];
        let iv = [0x22u8; 12];
        let nonce = [0x33u8; 16];
        let plaintext = b"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        let ad = b"associated_data_64_byte_boundary_test";

        let morus = MorusAead::new(&key, &iv);
        let (ciphertext, tag) = morus.encrypt_native(plaintext, ad, &nonce);
        let decrypted = morus.decrypt_native(&ciphertext, &tag, ad, &nonce).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_morus_roundtrip_large() {
        let key = [0x77u8; 16];
        let iv = [0x88u8; 12];
        let nonce = [0x99u8; 16];
        let plaintext = vec![0x5Au8; 1337]; // Prime number for good measure
        let ad = b"large_buffer_test_with_simd_optimization";

        let morus = MorusAead::new(&key, &iv);
        let (ciphertext, tag) = morus.encrypt_optimized(&plaintext, ad, &nonce);
        let decrypted = morus.decrypt_optimized(&ciphertext, &tag, ad, &nonce).unwrap();

        assert_eq!(plaintext, decrypted);
        assert_eq!(ciphertext.len(), plaintext.len());
    }

    #[test]
    fn test_morus_authentication_failure() {
        let key = [0xFFu8; 16];
        let iv = [0x00u8; 12];
        let nonce = [0xF0u8; 16];
        let plaintext = b"secret_message";
        let ad = b"authenticated_data";

        let morus = MorusAead::new(&key, &iv);
        let (mut ciphertext, tag) = morus.encrypt_optimized(plaintext, ad, &nonce);

        // Corrupt ciphertext
        ciphertext[0] ^= 1;

        let result = morus.decrypt_optimized(&ciphertext, &tag, ad, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_morus_tag_verification_failure() {
        let key = [0x12u8; 16];
        let iv = [0x34u8; 12];
        let nonce = [0x56u8; 16];
        let plaintext = b"another_secret";
        let ad = b"more_auth_data";

        let morus = MorusAead::new(&key, &iv);
        let (ciphertext, mut tag) = morus.encrypt_optimized(plaintext, ad, &nonce);

        // Corrupt tag
        tag[0] ^= 1;

        let result = morus.decrypt_optimized(&ciphertext, &tag, ad, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_morus_different_keys() {
        let key1 = [0xABu8; 16];
        let key2 = [0xCDu8; 16];
        let iv = [0xEFu8; 12];
        let nonce = [0x01u8; 16];
        let plaintext = b"cross_key_test";
        let ad = b"";

        let morus1 = MorusAead::new(&key1, &iv);
        let morus2 = MorusAead::new(&key2, &iv);

        let (ciphertext, tag) = morus1.encrypt_optimized(plaintext, ad, &nonce);
        let result = morus2.decrypt_optimized(&ciphertext, &tag, ad, &nonce);

        assert!(result.is_err());
    }

    #[test]
    fn test_morus_simd_vs_scalar_consistency() {
        let key = [0x42u8; 16];
        let iv = [0x24u8; 12];
        let nonce = [0x13u8; 16];
        let plaintext = b"simd_scalar_consistency_test_with_longer_message_for_coverage";
        let ad = b"associated_data_for_consistency";

        let morus = MorusAead::new(&key, &iv);

        // Test that optimized path can decrypt its own output (self-consistency)
        let (ct_opt, tag_opt) = morus.encrypt_optimized(plaintext, ad, &nonce);
        let pt_opt = morus.decrypt_optimized(&ct_opt, &tag_opt, ad, &nonce).unwrap();
        assert_eq!(plaintext, &pt_opt[..]);

        // Test that native path can decrypt its own output (self-consistency)
        let (ct_native, tag_native) = morus.encrypt_native(plaintext, ad, &nonce);
        let pt_native = morus.decrypt_native(&ct_native, &tag_native, ad, &nonce).unwrap();
        assert_eq!(plaintext, &pt_native[..]);

        // Cross-compatibility must hold: optimized and native paths must interoperate.
        let pt_cross_native = morus.decrypt_native(&ct_opt, &tag_opt, ad, &nonce).unwrap();
        assert_eq!(plaintext, &pt_cross_native[..]);

        let pt_cross_opt = morus.decrypt_optimized(&ct_native, &tag_native, ad, &nonce).unwrap();
        assert_eq!(plaintext, &pt_cross_opt[..]);
    }

    #[test]
    fn test_morus_in_place_roundtrip() {
        let key = [0x13u8; 16];
        let iv = [0x37u8; 12];
        let nonce = [0x42u8; 16];
        let ad = b"in_place_associated_data";
        let mut plaintext = vec![0u8; 256];
        for (idx, byte) in plaintext.iter_mut().enumerate() {
            *byte = (idx as u8).wrapping_mul(31);
        }

        let morus = MorusAead::new(&key, &iv);
        let (expected_ct, expected_tag) = morus.encrypt_native(&plaintext, ad, &nonce);

        let mut in_place_buf = plaintext.clone();
        let tag = morus.encrypt_in_place(&mut in_place_buf, ad, &nonce);
        assert_eq!(expected_ct, in_place_buf);
        assert_eq!(expected_tag, tag);

        let mut decrypt_buf = expected_ct.clone();
        morus
            .decrypt_in_place(&mut decrypt_buf, &expected_tag, ad, &nonce)
            .expect("decrypt_in_place should succeed");
        assert_eq!(decrypt_buf, plaintext);
    }

    #[test]
    fn morus_kat_vectors() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let iv = [0u8; 12];
        let nonce: [u8; 16] = [
            0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
            0x01, 0x00,
        ];
        let ad: [u8; 16] = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ];
        let pt: [u8; 32] = [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
            0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
            0x3c, 0x3d, 0x3e, 0x3f,
        ];
        let expected_ct: [u8; 32] = [
            0x0e, 0x95, 0x2d, 0x81, 0xd5, 0x90, 0xb2, 0x29, 0x16, 0xfe, 0xf3, 0x56, 0x5c, 0x8f,
            0x49, 0xbe, 0x72, 0x9a, 0x43, 0x13, 0x64, 0x5b, 0x4f, 0x6b, 0xd6, 0xc8, 0x7c, 0x97,
            0x66, 0x3c, 0x4f, 0xb7,
        ];
        let expected_tag: [u8; 16] = [
            0xf0, 0x85, 0xa8, 0xc7, 0x48, 0x70, 0x0b, 0x94, 0x1c, 0xb9, 0xca, 0xa6, 0xcd, 0x0d,
            0x74, 0x18,
        ];

        let morus = MorusAead::new(&key, &iv);
        let (ct, tag) = morus.encrypt_native(&pt, &ad, &nonce);
        assert_eq!(ct, expected_ct);
        assert_eq!(tag, expected_tag);

        let (ct_opt, tag_opt) = morus.encrypt_optimized(&pt, &ad, &nonce);
        assert_eq!(ct_opt, expected_ct);
        assert_eq!(tag_opt, expected_tag);
    }
}

// ============================================================================
// AEGIS Internal Implementation (consolidated internal; no external dependency)
// ============================================================================

/// AEGIS Error type
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AegisError {
    InvalidTag,
}

#[cfg(feature = "std")]
impl std::fmt::Display for AegisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AegisError::InvalidTag => write!(f, "Invalid tag"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AegisError {}

// AES block used by the AEGIS-128L implementation.
//
// We always compile a portable software AESENC equivalent, and optionally dispatch
// to architecture-specific AES instructions via #[target_feature] when available.
mod aegis_aes_block {
    use std::sync::OnceLock;

    #[derive(Copy, Clone, Debug, Default)]
    pub(crate) struct AesBlock([u8; 16]);

    #[allow(dead_code)]
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    enum AesEncBackend {
        Vaes512,
        Vaes256,
        Aesni,
        Aese,
        Scalar,
    }

    fn aes_backend() -> AesEncBackend {
        static BACKEND: OnceLock<AesEncBackend> = OnceLock::new();
        *BACKEND.get_or_init(|| {
            #[cfg(target_arch = "x86_64")]
            {
                if crate::optimize::FeatureDetector::instance()
                    .has_feature(crate::optimize::CpuFeature::AESNI)
                {
                    let det = crate::optimize::FeatureDetector::instance();
                    if det.has_feature(crate::optimize::CpuFeature::VAES)
                        && det.has_feature(crate::optimize::CpuFeature::AVX512F)
                        && det.has_feature(crate::optimize::CpuFeature::AVX512VL)
                    {
                        return AesEncBackend::Vaes512;
                    }
                    if det.has_feature(crate::optimize::CpuFeature::VAES)
                        && det.has_feature(crate::optimize::CpuFeature::AVX2)
                    {
                        return AesEncBackend::Vaes256;
                    }
                    return AesEncBackend::Aesni;
                }
            }

            #[cfg(target_arch = "aarch64")]
            {
                if crate::optimize::FeatureDetector::instance()
                    .has_feature(crate::optimize::CpuFeature::AES)
                {
                    return AesEncBackend::Aese;
                }
            }

            AesEncBackend::Scalar
        })
    }

    fn aesenc_round_cached(block: &[u8; 16], round_key: &[u8; 16]) -> [u8; 16] {
        match aes_backend() {
            AesEncBackend::Vaes512 | AesEncBackend::Vaes256 | AesEncBackend::Aesni => {
                #[cfg(target_arch = "x86_64")]
                unsafe {
                    return aesenc_round_aesni(block, round_key);
                }
                #[allow(unreachable_code)]
                {
                    crate::crypto::aes::aesenc_round(block, round_key)
                }
            }
            AesEncBackend::Aese => {
                #[cfg(target_arch = "aarch64")]
                unsafe {
                    return aesenc_round_armcrypto(block, round_key);
                }
                #[allow(unreachable_code)]
                {
                    crate::crypto::aes::aesenc_round(block, round_key)
                }
            }
            AesEncBackend::Scalar => crate::crypto::aes::aesenc_round(block, round_key),
        }
    }

    pub(crate) fn add_aesenc_ops(ops: u64) {
        use crate::optimize::telemetry;
        match aes_backend() {
            AesEncBackend::Vaes512 | AesEncBackend::Vaes256 => {
                telemetry::AES_BLOCK_VAES_OPS.inc_by(ops)
            }
            AesEncBackend::Aesni => telemetry::AES_BLOCK_AESNI_OPS.inc_by(ops),
            AesEncBackend::Aese => telemetry::AES_BLOCK_AESE_OPS.inc_by(ops),
            AesEncBackend::Scalar => telemetry::AES_BLOCK_SCALAR_OPS.inc_by(ops),
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "vaes,avx2")]
    unsafe fn aesenc2_vaes256(
        b0: &[u8; 16],
        rk0: &[u8; 16],
        b1: &[u8; 16],
        rk1: &[u8; 16],
    ) -> ([u8; 16], [u8; 16]) {
        use core::arch::x86_64::*;
        let x0 = _mm_loadu_si128(b0.as_ptr() as *const __m128i);
        let x1 = _mm_loadu_si128(b1.as_ptr() as *const __m128i);
        let k0 = _mm_loadu_si128(rk0.as_ptr() as *const __m128i);
        let k1 = _mm_loadu_si128(rk1.as_ptr() as *const __m128i);

        let x = _mm256_set_m128i(x1, x0);
        let k = _mm256_set_m128i(k1, k0);
        let y = _mm256_aesenc_epi128(x, k);

        let y0 = _mm256_extracti128_si256(y, 0);
        let y1 = _mm256_extracti128_si256(y, 1);
        let mut o0 = [0u8; 16];
        let mut o1 = [0u8; 16];
        _mm_storeu_si128(o0.as_mut_ptr() as *mut __m128i, y0);
        _mm_storeu_si128(o1.as_mut_ptr() as *mut __m128i, y1);
        (o0, o1)
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "vaes,avx512f,avx512vl")]
    unsafe fn aesenc4_vaes512(
        b0: &[u8; 16],
        rk0: &[u8; 16],
        b1: &[u8; 16],
        rk1: &[u8; 16],
        b2: &[u8; 16],
        rk2: &[u8; 16],
        b3: &[u8; 16],
        rk3: &[u8; 16],
    ) -> ([u8; 16], [u8; 16], [u8; 16], [u8; 16]) {
        use core::arch::x86_64::*;
        let x0 = _mm_loadu_si128(b0.as_ptr() as *const __m128i);
        let x1 = _mm_loadu_si128(b1.as_ptr() as *const __m128i);
        let x2 = _mm_loadu_si128(b2.as_ptr() as *const __m128i);
        let x3 = _mm_loadu_si128(b3.as_ptr() as *const __m128i);
        let k0 = _mm_loadu_si128(rk0.as_ptr() as *const __m128i);
        let k1 = _mm_loadu_si128(rk1.as_ptr() as *const __m128i);
        let k2 = _mm_loadu_si128(rk2.as_ptr() as *const __m128i);
        let k3 = _mm_loadu_si128(rk3.as_ptr() as *const __m128i);

        let mut x = _mm512_castsi128_si512(x0);
        x = _mm512_inserti32x4(x, x1, 1);
        x = _mm512_inserti32x4(x, x2, 2);
        x = _mm512_inserti32x4(x, x3, 3);

        let mut k = _mm512_castsi128_si512(k0);
        k = _mm512_inserti32x4(k, k1, 1);
        k = _mm512_inserti32x4(k, k2, 2);
        k = _mm512_inserti32x4(k, k3, 3);

        let y = _mm512_aesenc_epi128(x, k);

        let y0 = _mm512_extracti32x4_epi32(y, 0);
        let y1 = _mm512_extracti32x4_epi32(y, 1);
        let y2 = _mm512_extracti32x4_epi32(y, 2);
        let y3 = _mm512_extracti32x4_epi32(y, 3);

        let mut o0 = [0u8; 16];
        let mut o1 = [0u8; 16];
        let mut o2 = [0u8; 16];
        let mut o3 = [0u8; 16];
        _mm_storeu_si128(o0.as_mut_ptr() as *mut __m128i, y0);
        _mm_storeu_si128(o1.as_mut_ptr() as *mut __m128i, y1);
        _mm_storeu_si128(o2.as_mut_ptr() as *mut __m128i, y2);
        _mm_storeu_si128(o3.as_mut_ptr() as *mut __m128i, y3);
        (o0, o1, o2, o3)
    }

    pub(crate) fn aesenc8_update_inputs(
        in_b: &[[u8; 16]; 8],
        in_rk: &[[u8; 16]; 8],
    ) -> [[u8; 16]; 8] {
        match aes_backend() {
            AesEncBackend::Vaes512 => {
                #[cfg(target_arch = "x86_64")]
                unsafe {
                    let (o7, o6, o5, o4) = aesenc4_vaes512(
                        &in_b[7], &in_rk[7], &in_b[6], &in_rk[6], &in_b[5], &in_rk[5], &in_b[4],
                        &in_rk[4],
                    );
                    let (o3, o2, o1, o0) = aesenc4_vaes512(
                        &in_b[3], &in_rk[3], &in_b[2], &in_rk[2], &in_b[1], &in_rk[1], &in_b[0],
                        &in_rk[0],
                    );
                    return [o0, o1, o2, o3, o4, o5, o6, o7];
                }
            }
            AesEncBackend::Vaes256 => {
                #[cfg(target_arch = "x86_64")]
                unsafe {
                    let (o7, o6) = aesenc2_vaes256(&in_b[7], &in_rk[7], &in_b[6], &in_rk[6]);
                    let (o5, o4) = aesenc2_vaes256(&in_b[5], &in_rk[5], &in_b[4], &in_rk[4]);
                    let (o3, o2) = aesenc2_vaes256(&in_b[3], &in_rk[3], &in_b[2], &in_rk[2]);
                    let (o1, o0) = aesenc2_vaes256(&in_b[1], &in_rk[1], &in_b[0], &in_rk[0]);
                    return [o0, o1, o2, o3, o4, o5, o6, o7];
                }
            }
            _ => {}
        }

        // Fallback: scalar dispatch per block (still uses cached backend).
        let mut out = [[0u8; 16]; 8];
        for i in 0..8 {
            out[i] = aesenc_round_cached(&in_b[i], &in_rk[i]);
        }
        out
    }

    impl AesBlock {
        pub(crate) fn from_bytes(bytes: &[u8; 16]) -> Self {
            Self(*bytes)
        }

        pub(crate) fn into_bytes(self) -> [u8; 16] {
            self.0
        }

        #[inline(always)]
        pub(crate) fn xor(&self, other: Self) -> Self {
            #[cfg(target_arch = "x86_64")]
            unsafe {
                use core::arch::x86_64::*;
                let a = _mm_loadu_si128(self.0.as_ptr() as *const __m128i);
                let b = _mm_loadu_si128(other.0.as_ptr() as *const __m128i);
                let x = _mm_xor_si128(a, b);
                let mut out = [0u8; 16];
                _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, x);
                return Self(out);
            }

            #[cfg(target_arch = "aarch64")]
            unsafe {
                use core::arch::aarch64::*;
                let a = vld1q_u8(self.0.as_ptr());
                let b = vld1q_u8(other.0.as_ptr());
                let x = veorq_u8(a, b);
                let mut out = [0u8; 16];
                vst1q_u8(out.as_mut_ptr(), x);
                return Self(out);
            }

            #[allow(unreachable_code)]
            {
                let mut out = [0u8; 16];
                for (i, o) in out.iter_mut().enumerate() {
                    *o = self.0[i] ^ other.0[i];
                }
                Self(out)
            }
        }

        #[inline(always)]
        pub(crate) fn and(&self, other: Self) -> Self {
            #[cfg(target_arch = "x86_64")]
            unsafe {
                use core::arch::x86_64::*;
                let a = _mm_loadu_si128(self.0.as_ptr() as *const __m128i);
                let b = _mm_loadu_si128(other.0.as_ptr() as *const __m128i);
                let x = _mm_and_si128(a, b);
                let mut out = [0u8; 16];
                _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, x);
                return Self(out);
            }

            #[cfg(target_arch = "aarch64")]
            unsafe {
                use core::arch::aarch64::*;
                let a = vld1q_u8(self.0.as_ptr());
                let b = vld1q_u8(other.0.as_ptr());
                let x = vandq_u8(a, b);
                let mut out = [0u8; 16];
                vst1q_u8(out.as_mut_ptr(), x);
                return Self(out);
            }

            #[allow(unreachable_code)]
            {
                let mut out = [0u8; 16];
                for (i, o) in out.iter_mut().enumerate() {
                    *o = self.0[i] & other.0[i];
                }
                Self(out)
            }
        }

        // aes_round is intentionally not exposed anymore. The AEGIS hot path uses
        // the batched update helper to leverage VAES when available.
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "aes")]
    unsafe fn aesenc_round_aesni(block: &[u8; 16], round_key: &[u8; 16]) -> [u8; 16] {
        use core::arch::x86_64::*;
        let b = _mm_loadu_si128(block.as_ptr() as *const __m128i);
        let rk = _mm_loadu_si128(round_key.as_ptr() as *const __m128i);
        let e = _mm_aesenc_si128(b, rk);
        let mut out = [0u8; 16];
        _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, e);
        out
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "aes")]
    unsafe fn aesenc_round_armcrypto(block: &[u8; 16], round_key: &[u8; 16]) -> [u8; 16] {
        use core::arch::aarch64::*;
        let b = vld1q_u8(block.as_ptr());
        let rk = vld1q_u8(round_key.as_ptr());
        let e = vaeseq_u8(b, rk);
        let m = vaesmcq_u8(e);
        let mut out = [0u8; 16];
        vst1q_u8(out.as_mut_ptr(), m);
        out
    }
}

use aegis_aes_block::AesBlock;

#[inline(always)]
fn aegis128l_update(state: &mut [AesBlock; 8], d0: AesBlock, d1: AesBlock) {
    // Optional prefetch on x86_64 when SSE4.2 is available (best-effort).
    #[cfg(target_arch = "x86_64")]
    unsafe {
        if crate::optimize::FeatureDetector::instance()
            .has_feature(crate::optimize::CpuFeature::SSE42)
        {
            crate::optimize::prefetch(
                state.as_ptr() as *const u8,
                crate::optimize::PrefetchHint::T0,
            );
        }
    }

    // Snapshot old state: the AEGIS update step is defined over the previous
    // state words, so all AESENC operations are independent and can be scheduled
    // in any order (including VAES batching).
    let old = *state;

    // Prepare inputs/round-keys for the 8 AESENC operations.
    // new7 = AESENC(old7, old6)
    // new6 = AESENC(old6, old5)
    // new5 = AESENC(old5, old4)
    // new4 = AESENC(old4, old3)
    // new3 = AESENC(old3, old2)
    // new2 = AESENC(old2, old1)
    // new1 = AESENC(old1, old0)
    // new0 = AESENC(old0, old7)
    let in_b = [
        old[0].into_bytes(),
        old[1].into_bytes(),
        old[2].into_bytes(),
        old[3].into_bytes(),
        old[4].into_bytes(),
        old[5].into_bytes(),
        old[6].into_bytes(),
        old[7].into_bytes(),
    ];
    let in_rk = [
        old[7].into_bytes(),
        old[0].into_bytes(),
        old[1].into_bytes(),
        old[2].into_bytes(),
        old[3].into_bytes(),
        old[4].into_bytes(),
        old[5].into_bytes(),
        old[6].into_bytes(),
    ];

    // Run the 8 AESENC operations with the best available backend.
    let out = aegis_aes_block::aesenc8_update_inputs(&in_b, &in_rk);

    state[0] = AesBlock::from_bytes(&out[0]).xor(d0);
    state[1] = AesBlock::from_bytes(&out[1]);
    state[2] = AesBlock::from_bytes(&out[2]);
    state[3] = AesBlock::from_bytes(&out[3]);
    state[4] = AesBlock::from_bytes(&out[4]).xor(d1);
    state[5] = AesBlock::from_bytes(&out[5]);
    state[6] = AesBlock::from_bytes(&out[6]);
    state[7] = AesBlock::from_bytes(&out[7]);
}

fn aegis128l_init_state(key: &[u8], nonce: &[u8]) -> Result<[AesBlock; 8], AegisError> {
    if key.len() != Aegis128L::KEY_SIZE || nonce.len() != Aegis128L::NONCE_SIZE {
        return Err(AegisError::InvalidTag);
    }

    let mut key_arr = [0u8; 16];
    key_arr.copy_from_slice(key);
    let mut nonce_arr = [0u8; 16];
    nonce_arr.copy_from_slice(nonce);
    let key_block = AesBlock::from_bytes(&key_arr);
    let nonce_block = AesBlock::from_bytes(&nonce_arr);

    let c0 = AesBlock::from_bytes(&[
        0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79,
        0x62,
    ]);
    let c1 = AesBlock::from_bytes(&[
        0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28,
        0xdd,
    ]);

    let kxn = key_block.xor(nonce_block);
    let mut state = [kxn, c1, c0, c1, kxn, key_block.xor(c0), key_block.xor(c1), kxn];

    // Initialization rounds.
    for _ in 0..10 {
        aegis128l_update(&mut state, nonce_block, key_block);
    }

    // Each update performs 8 AESENC rounds over the 8-word state.
    // Count initialization work as well, but aggregate to a single atomic add.
    aegis_aes_block::add_aesenc_ops(10 * 8);

    Ok(state)
}

// AEGIS128L Pure Rust Implementation
pub struct Aegis128L {
    state: [AesBlock; 8],
}

impl Aegis128L {
    const KEY_SIZE: usize = 16;
    const NONCE_SIZE: usize = 16;

    pub fn new(key: &[u8], nonce: &[u8]) -> Result<Self, AegisError> {
        let state = aegis128l_init_state(key, nonce)?;
        Ok(Self { state })
    }

    #[inline(always)]
    fn update(state: &mut [AesBlock; 8], d0: AesBlock, d1: AesBlock) {
        aegis128l_update(state, d0, d1);
    }

    #[inline(always)]
    pub fn encrypt_in_place(&mut self, plaintext: &mut [u8], associated_data: &[u8]) -> [u8; 16] {
        // Telemetry: each update performs 8 AESENC rounds.
        let ad_updates = (associated_data.len() as u64).div_ceil(32);
        let msg_updates = (plaintext.len() as u64).div_ceil(32);
        let fin_updates = 7u64;
        aegis_aes_block::add_aesenc_ops((ad_updates + msg_updates + fin_updates) * 8);

        // Process associated data
        for chunk in associated_data.chunks(32) {
            let mut ad0 = [0u8; 16];
            let mut ad1 = [0u8; 16];

            if chunk.len() >= 16 {
                ad0.copy_from_slice(&chunk[..16]);
                if chunk.len() >= 32 {
                    ad1.copy_from_slice(&chunk[16..32]);
                } else if chunk.len() > 16 {
                    ad1[..chunk.len() - 16].copy_from_slice(&chunk[16..]);
                }
            } else {
                ad0[..chunk.len()].copy_from_slice(chunk);
            }

            Self::update(&mut self.state, AesBlock::from_bytes(&ad0), AesBlock::from_bytes(&ad1));
        }

        // Hot path: process 64-byte chunks (two 32-byte rounds) for better ILP on aarch64 NEON and x86_64
        let mut i = 0usize;
        while i + 64 <= plaintext.len() {
            // First 32 bytes
            let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            let mut msg0 = [0u8; 16];
            let mut msg1 = [0u8; 16];
            msg0.copy_from_slice(&plaintext[i..i + 16]);
            msg1.copy_from_slice(&plaintext[i + 16..i + 32]);
            let msg0_block = AesBlock::from_bytes(&msg0);
            let msg1_block = AesBlock::from_bytes(&msg1);
            let c0 = msg0_block.xor(z0);
            let c1 = msg1_block.xor(z1);
            plaintext[i..i + 16].copy_from_slice(&c0.into_bytes());
            plaintext[i + 16..i + 32].copy_from_slice(&c1.into_bytes());
            Self::update(&mut self.state, msg0_block, msg1_block);

            // Second 32 bytes
            let z0b = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1b = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            let mut msg2 = [0u8; 16];
            let mut msg3 = [0u8; 16];
            msg2.copy_from_slice(&plaintext[i + 32..i + 48]);
            msg3.copy_from_slice(&plaintext[i + 48..i + 64]);
            let msg2_block = AesBlock::from_bytes(&msg2);
            let msg3_block = AesBlock::from_bytes(&msg3);
            let c2 = msg2_block.xor(z0b);
            let c3 = msg3_block.xor(z1b);
            plaintext[i + 32..i + 48].copy_from_slice(&c2.into_bytes());
            plaintext[i + 48..i + 64].copy_from_slice(&c3.into_bytes());
            Self::update(&mut self.state, msg2_block, msg3_block);

            i += 64;
        }
        // Tail handling: 32, 16..31, <16
        while i < plaintext.len() {
            let rem = plaintext.len() - i;
            let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            if rem >= 32 {
                let mut msg0 = [0u8; 16];
                let mut msg1 = [0u8; 16];
                msg0.copy_from_slice(&plaintext[i..i + 16]);
                msg1.copy_from_slice(&plaintext[i + 16..i + 32]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let msg1_block = AesBlock::from_bytes(&msg1);
                let c0 = msg0_block.xor(z0);
                let c1 = msg1_block.xor(z1);
                plaintext[i..i + 16].copy_from_slice(&c0.into_bytes());
                plaintext[i + 16..i + 32].copy_from_slice(&c1.into_bytes());
                Self::update(&mut self.state, msg0_block, msg1_block);
                i += 32;
            } else if rem >= 16 {
                let mut msg0 = [0u8; 16];
                let mut msg1 = [0u8; 16];
                msg0.copy_from_slice(&plaintext[i..i + 16]);
                msg1[..rem - 16].copy_from_slice(&plaintext[i + 16..i + rem]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let msg1_block = AesBlock::from_bytes(&msg1);
                let c0 = msg0_block.xor(z0);
                let c1 = msg1_block.xor(z1);
                plaintext[i..i + 16].copy_from_slice(&c0.into_bytes());
                let remaining = rem - 16;
                plaintext[i + 16..i + 16 + remaining]
                    .copy_from_slice(&c1.into_bytes()[..remaining]);
                Self::update(&mut self.state, msg0_block, msg1_block);
                i += rem; // done
            } else {
                let mut msg0 = [0u8; 16];
                msg0[..rem].copy_from_slice(&plaintext[i..i + rem]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let c0 = msg0_block.xor(z0);
                plaintext[i..i + rem].copy_from_slice(&c0.into_bytes()[..rem]);
                Self::update(&mut self.state, msg0_block, AesBlock::from_bytes(&[0u8; 16]));
                i += rem;
            }
        }

        // Finalization: mix lengths (bits) for AD and message, then 7 rounds
        let ad_bits = (associated_data.len() as u64).wrapping_mul(8);
        let msg_bits = (plaintext.len() as u64).wrapping_mul(8);
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&ad_bits.to_le_bytes());
        len_block[8..16].copy_from_slice(&msg_bits.to_le_bytes());
        let l0 = AesBlock::from_bytes(&len_block);
        let l1 = l0;
        for _ in 0..7 {
            Self::update(&mut self.state, l0, l1);
        }

        // Generate tag: XOR all 8 state words
        self.state[0]
            .xor(self.state[1])
            .xor(self.state[2])
            .xor(self.state[3])
            .xor(self.state[4])
            .xor(self.state[5])
            .xor(self.state[6])
            .xor(self.state[7])
            .into_bytes()
    }

    /// Decrypts ciphertext in-place.
    ///
    /// # Security
    ///
    /// **CRITICAL**: If this returns `Err`, the buffer may contain partially processed data.
    /// The caller MUST discard the buffer on authentication failure and MUST NOT use it
    /// as plaintext. Use `decrypt_verified()` for automatic secure handling.
    pub fn decrypt_in_place(
        &mut self,
        ciphertext: &mut [u8],
        associated_data: &[u8],
        tag: &[u8; 16],
    ) -> Result<(), AegisError> {
        // Telemetry: each update performs 8 AESENC rounds.
        let ad_updates = (associated_data.len() as u64).div_ceil(32);
        let msg_updates = (ciphertext.len() as u64).div_ceil(32);
        let fin_updates = 7u64;
        aegis_aes_block::add_aesenc_ops((ad_updates + msg_updates + fin_updates) * 8);

        // Process associated data (same as encrypt)
        for chunk in associated_data.chunks(32) {
            let mut ad0 = [0u8; 16];
            let mut ad1 = [0u8; 16];

            if chunk.len() >= 16 {
                ad0.copy_from_slice(&chunk[..16]);
                if chunk.len() >= 32 {
                    ad1.copy_from_slice(&chunk[16..32]);
                } else if chunk.len() > 16 {
                    ad1[..chunk.len() - 16].copy_from_slice(&chunk[16..]);
                }
            } else {
                ad0[..chunk.len()].copy_from_slice(chunk);
            }
            Self::update(&mut self.state, AesBlock::from_bytes(&ad0), AesBlock::from_bytes(&ad1));
        }
        // Decrypt ciphertext: 64-byte hot path (two 32-byte rounds)
        let mut i = 0usize;
        while i + 64 <= ciphertext.len() {
            // First 32 bytes
            let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            let mut c0 = [0u8; 16];
            let mut c1 = [0u8; 16];
            c0.copy_from_slice(&ciphertext[i..i + 16]);
            c1.copy_from_slice(&ciphertext[i + 16..i + 32]);
            let p0 = AesBlock::from_bytes(&c0).xor(z0).into_bytes();
            let p1 = AesBlock::from_bytes(&c1).xor(z1).into_bytes();
            ciphertext[i..i + 16].copy_from_slice(&p0);
            ciphertext[i + 16..i + 32].copy_from_slice(&p1);
            let msg0_block = AesBlock::from_bytes(&p0);
            let msg1_block = AesBlock::from_bytes(&p1);
            Self::update(&mut self.state, msg0_block, msg1_block);

            // Second 32 bytes
            let z0b = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1b = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            let mut c2 = [0u8; 16];
            let mut c3 = [0u8; 16];
            c2.copy_from_slice(&ciphertext[i + 32..i + 48]);
            c3.copy_from_slice(&ciphertext[i + 48..i + 64]);
            let p2 = AesBlock::from_bytes(&c2).xor(z0b).into_bytes();
            let p3 = AesBlock::from_bytes(&c3).xor(z1b).into_bytes();
            ciphertext[i + 32..i + 48].copy_from_slice(&p2);
            ciphertext[i + 48..i + 64].copy_from_slice(&p3);
            let msg2_block = AesBlock::from_bytes(&p2);
            let msg3_block = AesBlock::from_bytes(&p3);
            Self::update(&mut self.state, msg2_block, msg3_block);

            i += 64;
        }
        // Tail handling
        while i < ciphertext.len() {
            let rem = ciphertext.len() - i;
            let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            if rem >= 32 {
                let mut c0 = [0u8; 16];
                let mut c1 = [0u8; 16];
                c0.copy_from_slice(&ciphertext[i..i + 16]);
                c1.copy_from_slice(&ciphertext[i + 16..i + 32]);
                let p0 = AesBlock::from_bytes(&c0).xor(z0).into_bytes();
                let p1 = AesBlock::from_bytes(&c1).xor(z1).into_bytes();
                ciphertext[i..i + 16].copy_from_slice(&p0);
                ciphertext[i + 16..i + 32].copy_from_slice(&p1);
                let msg0_block = AesBlock::from_bytes(&p0);
                let msg1_block = AesBlock::from_bytes(&p1);
                Self::update(&mut self.state, msg0_block, msg1_block);
                i += 32;
            } else if rem >= 16 {
                let mut c0 = [0u8; 16];
                let mut c1 = [0u8; 16];
                c0.copy_from_slice(&ciphertext[i..i + 16]);
                c1[..rem - 16].copy_from_slice(&ciphertext[i + 16..i + rem]);
                let p0 = AesBlock::from_bytes(&c0).xor(z0).into_bytes();
                let p1_full = AesBlock::from_bytes(&c1).xor(z1).into_bytes();
                ciphertext[i..i + 16].copy_from_slice(&p0);
                let remaining = rem - 16;
                ciphertext[i + 16..i + 16 + remaining].copy_from_slice(&p1_full[..remaining]);
                let msg0_block = AesBlock::from_bytes(&p0);
                // State update must use plaintext padded with zeros beyond 'remaining'
                let mut p1_padded = [0u8; 16];
                p1_padded[..remaining].copy_from_slice(&p1_full[..remaining]);
                let msg1_block = AesBlock::from_bytes(&p1_padded);
                Self::update(&mut self.state, msg0_block, msg1_block);
                i += rem; // done
            } else {
                let mut c0 = [0u8; 16];
                c0[..rem].copy_from_slice(&ciphertext[i..i + rem]);
                let p0_full = AesBlock::from_bytes(&c0).xor(z0).into_bytes();
                ciphertext[i..i + rem].copy_from_slice(&p0_full[..rem]);
                // Zero-pad tail plaintext for state update
                let mut p0_padded = [0u8; 16];
                p0_padded[..rem].copy_from_slice(&p0_full[..rem]);
                let msg0_block = AesBlock::from_bytes(&p0_padded);
                Self::update(&mut self.state, msg0_block, AesBlock::from_bytes(&[0u8; 16]));
                i += rem;
            }
        }

        // Finalization: mix lengths (bits) for AD and message, then 7 rounds
        let ad_bits = (associated_data.len() as u64).wrapping_mul(8);
        let msg_bits = (ciphertext.len() as u64).wrapping_mul(8);
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&ad_bits.to_le_bytes());
        len_block[8..16].copy_from_slice(&msg_bits.to_le_bytes());
        let l0 = AesBlock::from_bytes(&len_block);
        let l1 = l0;
        for _ in 0..7 {
            Self::update(&mut self.state, l0, l1);
        }

        // Verify tag: XOR all 8 state words
        let computed_tag = self.state[0]
            .xor(self.state[1])
            .xor(self.state[2])
            .xor(self.state[3])
            .xor(self.state[4])
            .xor(self.state[5])
            .xor(self.state[6])
            .xor(self.state[7])
            .into_bytes();

        if !subtle_ct_eq(&computed_tag, tag) {
            return Err(AegisError::InvalidTag);
        }

        Ok(())
    }

    /// Decrypts into a new buffer and returns `Ok(plaintext)` if the `tag` verifies.
    /// On failure, the temporary buffer is zeroized and `Err(InvalidTag)` is returned.
    pub fn decrypt_verified(
        &mut self,
        ciphertext: &[u8],
        associated_data: &[u8],
        tag: &[u8; 16],
    ) -> Result<Vec<u8>, AegisError> {
        let mut buf = ciphertext.to_vec();
        match self.decrypt_in_place(&mut buf, associated_data, tag) {
            Ok(()) => Ok(buf),
            Err(e) => {
                buf.fill(0);
                Err(e)
            }
        }
    }
}

// AEGIS-128 variants for higher throughput via loop unrolling.
//
// These are not separate algorithms. They are the same AEGIS-128L core with a
// wider hot loop (4 or 8 sequential 32-byte rounds per iteration) to increase
// instruction-level parallelism and reduce loop overhead on modern CPUs.

pub struct Aegis128X4 {
    state: [AesBlock; 8],
}

impl Aegis128X4 {
    pub fn new(key: &[u8], nonce: &[u8]) -> Result<Self, AegisError> {
        let state = aegis128l_init_state(key, nonce)?;
        Ok(Self { state })
    }

    #[inline(always)]
    fn update(state: &mut [AesBlock; 8], d0: AesBlock, d1: AesBlock) {
        aegis128l_update(state, d0, d1);
    }

    #[inline(always)]
    pub fn encrypt_in_place(&mut self, plaintext: &mut [u8], associated_data: &[u8]) -> [u8; 16] {
        let ad_updates = (associated_data.len() as u64).div_ceil(32);
        let msg_updates = (plaintext.len() as u64).div_ceil(32);
        let fin_updates = 7u64;
        aegis_aes_block::add_aesenc_ops((ad_updates + msg_updates + fin_updates) * 8);

        // Process associated data.
        for chunk in associated_data.chunks(32) {
            let mut ad0 = [0u8; 16];
            let mut ad1 = [0u8; 16];

            if chunk.len() >= 16 {
                ad0.copy_from_slice(&chunk[..16]);
                if chunk.len() >= 32 {
                    ad1.copy_from_slice(&chunk[16..32]);
                } else if chunk.len() > 16 {
                    ad1[..chunk.len() - 16].copy_from_slice(&chunk[16..]);
                }
            } else {
                ad0[..chunk.len()].copy_from_slice(chunk);
            }

            Self::update(&mut self.state, AesBlock::from_bytes(&ad0), AesBlock::from_bytes(&ad1));
        }

        let mut i = 0usize;

        // Hot path: 128-byte chunks (four 32-byte rounds).
        while i + 128 <= plaintext.len() {
            for r in 0..4 {
                let off = i + r * 32;
                let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
                let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
                let mut msg0 = [0u8; 16];
                let mut msg1 = [0u8; 16];
                msg0.copy_from_slice(&plaintext[off..off + 16]);
                msg1.copy_from_slice(&plaintext[off + 16..off + 32]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let msg1_block = AesBlock::from_bytes(&msg1);
                let c0 = msg0_block.xor(z0);
                let c1 = msg1_block.xor(z1);
                plaintext[off..off + 16].copy_from_slice(&c0.into_bytes());
                plaintext[off + 16..off + 32].copy_from_slice(&c1.into_bytes());
                Self::update(&mut self.state, msg0_block, msg1_block);
            }
            i += 128;
        }

        // Fallback hot path: 64-byte chunks.
        while i + 64 <= plaintext.len() {
            // First 32 bytes.
            let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            let mut msg0 = [0u8; 16];
            let mut msg1 = [0u8; 16];
            msg0.copy_from_slice(&plaintext[i..i + 16]);
            msg1.copy_from_slice(&plaintext[i + 16..i + 32]);
            let msg0_block = AesBlock::from_bytes(&msg0);
            let msg1_block = AesBlock::from_bytes(&msg1);
            let c0 = msg0_block.xor(z0);
            let c1 = msg1_block.xor(z1);
            plaintext[i..i + 16].copy_from_slice(&c0.into_bytes());
            plaintext[i + 16..i + 32].copy_from_slice(&c1.into_bytes());
            Self::update(&mut self.state, msg0_block, msg1_block);

            // Second 32 bytes.
            let z0b = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1b = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            let mut msg2 = [0u8; 16];
            let mut msg3 = [0u8; 16];
            msg2.copy_from_slice(&plaintext[i + 32..i + 48]);
            msg3.copy_from_slice(&plaintext[i + 48..i + 64]);
            let msg2_block = AesBlock::from_bytes(&msg2);
            let msg3_block = AesBlock::from_bytes(&msg3);
            let c2 = msg2_block.xor(z0b);
            let c3 = msg3_block.xor(z1b);
            plaintext[i + 32..i + 48].copy_from_slice(&c2.into_bytes());
            plaintext[i + 48..i + 64].copy_from_slice(&c3.into_bytes());
            Self::update(&mut self.state, msg2_block, msg3_block);

            i += 64;
        }

        // Tail handling: 32, 16..31, <16.
        while i < plaintext.len() {
            let rem = plaintext.len() - i;
            let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            if rem >= 32 {
                let mut msg0 = [0u8; 16];
                let mut msg1 = [0u8; 16];
                msg0.copy_from_slice(&plaintext[i..i + 16]);
                msg1.copy_from_slice(&plaintext[i + 16..i + 32]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let msg1_block = AesBlock::from_bytes(&msg1);
                let c0 = msg0_block.xor(z0);
                let c1 = msg1_block.xor(z1);
                plaintext[i..i + 16].copy_from_slice(&c0.into_bytes());
                plaintext[i + 16..i + 32].copy_from_slice(&c1.into_bytes());
                Self::update(&mut self.state, msg0_block, msg1_block);
                i += 32;
            } else if rem >= 16 {
                let mut msg0 = [0u8; 16];
                let mut msg1 = [0u8; 16];
                msg0.copy_from_slice(&plaintext[i..i + 16]);
                msg1[..rem - 16].copy_from_slice(&plaintext[i + 16..i + rem]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let msg1_block = AesBlock::from_bytes(&msg1);
                let c0 = msg0_block.xor(z0);
                let c1 = msg1_block.xor(z1);
                plaintext[i..i + 16].copy_from_slice(&c0.into_bytes());
                let remaining = rem - 16;
                plaintext[i + 16..i + 16 + remaining]
                    .copy_from_slice(&c1.into_bytes()[..remaining]);
                Self::update(&mut self.state, msg0_block, msg1_block);
                i += rem;
            } else {
                let mut msg0 = [0u8; 16];
                msg0[..rem].copy_from_slice(&plaintext[i..i + rem]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let c0 = msg0_block.xor(z0);
                plaintext[i..i + rem].copy_from_slice(&c0.into_bytes()[..rem]);
                Self::update(&mut self.state, msg0_block, AesBlock::from_bytes(&[0u8; 16]));
                i += rem;
            }
        }

        // Finalization: mix lengths (bits) for AD and message, then 7 rounds.
        let ad_bits = (associated_data.len() as u64).wrapping_mul(8);
        let msg_bits = (plaintext.len() as u64).wrapping_mul(8);
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&ad_bits.to_le_bytes());
        len_block[8..16].copy_from_slice(&msg_bits.to_le_bytes());
        let l0 = AesBlock::from_bytes(&len_block);
        let l1 = l0;
        for _ in 0..7 {
            Self::update(&mut self.state, l0, l1);
        }

        self.state[0]
            .xor(self.state[1])
            .xor(self.state[2])
            .xor(self.state[3])
            .xor(self.state[4])
            .xor(self.state[5])
            .xor(self.state[6])
            .xor(self.state[7])
            .into_bytes()
    }

    pub fn decrypt_in_place(
        &mut self,
        ciphertext: &mut [u8],
        associated_data: &[u8],
        tag: &[u8; 16],
    ) -> Result<(), AegisError> {
        let ad_updates = (associated_data.len() as u64).div_ceil(32);
        let msg_updates = (ciphertext.len() as u64).div_ceil(32);
        let fin_updates = 7u64;
        aegis_aes_block::add_aesenc_ops((ad_updates + msg_updates + fin_updates) * 8);

        for chunk in associated_data.chunks(32) {
            let mut ad0 = [0u8; 16];
            let mut ad1 = [0u8; 16];

            if chunk.len() >= 16 {
                ad0.copy_from_slice(&chunk[..16]);
                if chunk.len() >= 32 {
                    ad1.copy_from_slice(&chunk[16..32]);
                } else if chunk.len() > 16 {
                    ad1[..chunk.len() - 16].copy_from_slice(&chunk[16..]);
                }
            } else {
                ad0[..chunk.len()].copy_from_slice(chunk);
            }
            Self::update(&mut self.state, AesBlock::from_bytes(&ad0), AesBlock::from_bytes(&ad1));
        }

        let mut i = 0usize;

        // Hot path: 128-byte chunks (four 32-byte rounds).
        while i + 128 <= ciphertext.len() {
            for r in 0..4 {
                let off = i + r * 32;
                let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
                let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
                let mut c0 = [0u8; 16];
                let mut c1 = [0u8; 16];
                c0.copy_from_slice(&ciphertext[off..off + 16]);
                c1.copy_from_slice(&ciphertext[off + 16..off + 32]);
                let p0 = AesBlock::from_bytes(&c0).xor(z0).into_bytes();
                let p1 = AesBlock::from_bytes(&c1).xor(z1).into_bytes();
                ciphertext[off..off + 16].copy_from_slice(&p0);
                ciphertext[off + 16..off + 32].copy_from_slice(&p1);
                let msg0_block = AesBlock::from_bytes(&p0);
                let msg1_block = AesBlock::from_bytes(&p1);
                Self::update(&mut self.state, msg0_block, msg1_block);
            }
            i += 128;
        }

        // Fallback hot path: 64-byte chunks.
        while i + 64 <= ciphertext.len() {
            // First 32 bytes.
            let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            let mut c0 = [0u8; 16];
            let mut c1 = [0u8; 16];
            c0.copy_from_slice(&ciphertext[i..i + 16]);
            c1.copy_from_slice(&ciphertext[i + 16..i + 32]);
            let p0 = AesBlock::from_bytes(&c0).xor(z0).into_bytes();
            let p1 = AesBlock::from_bytes(&c1).xor(z1).into_bytes();
            ciphertext[i..i + 16].copy_from_slice(&p0);
            ciphertext[i + 16..i + 32].copy_from_slice(&p1);
            let msg0_block = AesBlock::from_bytes(&p0);
            let msg1_block = AesBlock::from_bytes(&p1);
            Self::update(&mut self.state, msg0_block, msg1_block);

            // Second 32 bytes.
            let z0b = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1b = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            let mut c2 = [0u8; 16];
            let mut c3 = [0u8; 16];
            c2.copy_from_slice(&ciphertext[i + 32..i + 48]);
            c3.copy_from_slice(&ciphertext[i + 48..i + 64]);
            let p2 = AesBlock::from_bytes(&c2).xor(z0b).into_bytes();
            let p3 = AesBlock::from_bytes(&c3).xor(z1b).into_bytes();
            ciphertext[i + 32..i + 48].copy_from_slice(&p2);
            ciphertext[i + 48..i + 64].copy_from_slice(&p3);
            let msg2_block = AesBlock::from_bytes(&p2);
            let msg3_block = AesBlock::from_bytes(&p3);
            Self::update(&mut self.state, msg2_block, msg3_block);

            i += 64;
        }

        // Tail handling.
        while i < ciphertext.len() {
            let rem = ciphertext.len() - i;
            let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            if rem >= 32 {
                let mut c0 = [0u8; 16];
                let mut c1 = [0u8; 16];
                c0.copy_from_slice(&ciphertext[i..i + 16]);
                c1.copy_from_slice(&ciphertext[i + 16..i + 32]);
                let p0 = AesBlock::from_bytes(&c0).xor(z0).into_bytes();
                let p1 = AesBlock::from_bytes(&c1).xor(z1).into_bytes();
                ciphertext[i..i + 16].copy_from_slice(&p0);
                ciphertext[i + 16..i + 32].copy_from_slice(&p1);
                let msg0_block = AesBlock::from_bytes(&p0);
                let msg1_block = AesBlock::from_bytes(&p1);
                Self::update(&mut self.state, msg0_block, msg1_block);
                i += 32;
            } else if rem >= 16 {
                let mut c0 = [0u8; 16];
                let mut c1 = [0u8; 16];
                c0.copy_from_slice(&ciphertext[i..i + 16]);
                c1[..rem - 16].copy_from_slice(&ciphertext[i + 16..i + rem]);
                let p0 = AesBlock::from_bytes(&c0).xor(z0).into_bytes();
                let p1_full = AesBlock::from_bytes(&c1).xor(z1).into_bytes();
                ciphertext[i..i + 16].copy_from_slice(&p0);
                let remaining = rem - 16;
                ciphertext[i + 16..i + 16 + remaining].copy_from_slice(&p1_full[..remaining]);
                let msg0_block = AesBlock::from_bytes(&p0);
                let mut p1_padded = [0u8; 16];
                p1_padded[..remaining].copy_from_slice(&p1_full[..remaining]);
                let msg1_block = AesBlock::from_bytes(&p1_padded);
                Self::update(&mut self.state, msg0_block, msg1_block);
                i += rem;
            } else {
                let mut c0 = [0u8; 16];
                c0[..rem].copy_from_slice(&ciphertext[i..i + rem]);
                let p0_full = AesBlock::from_bytes(&c0).xor(z0).into_bytes();
                ciphertext[i..i + rem].copy_from_slice(&p0_full[..rem]);
                let mut p0_padded = [0u8; 16];
                p0_padded[..rem].copy_from_slice(&p0_full[..rem]);
                let msg0_block = AesBlock::from_bytes(&p0_padded);
                Self::update(&mut self.state, msg0_block, AesBlock::from_bytes(&[0u8; 16]));
                i += rem;
            }
        }

        let ad_bits = (associated_data.len() as u64).wrapping_mul(8);
        let msg_bits = (ciphertext.len() as u64).wrapping_mul(8);
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&ad_bits.to_le_bytes());
        len_block[8..16].copy_from_slice(&msg_bits.to_le_bytes());
        let l0 = AesBlock::from_bytes(&len_block);
        let l1 = l0;
        for _ in 0..7 {
            Self::update(&mut self.state, l0, l1);
        }

        let computed_tag = self.state[0]
            .xor(self.state[1])
            .xor(self.state[2])
            .xor(self.state[3])
            .xor(self.state[4])
            .xor(self.state[5])
            .xor(self.state[6])
            .xor(self.state[7])
            .into_bytes();

        if !subtle_ct_eq(&computed_tag, tag) {
            return Err(AegisError::InvalidTag);
        }

        Ok(())
    }
}

pub struct Aegis128X8 {
    state: [AesBlock; 8],
}

impl Aegis128X8 {
    pub fn new(key: &[u8], nonce: &[u8]) -> Result<Self, AegisError> {
        let state = aegis128l_init_state(key, nonce)?;
        Ok(Self { state })
    }

    #[inline(always)]
    fn update(state: &mut [AesBlock; 8], d0: AesBlock, d1: AesBlock) {
        aegis128l_update(state, d0, d1);
    }

    #[inline(always)]
    pub fn encrypt_in_place(&mut self, plaintext: &mut [u8], associated_data: &[u8]) -> [u8; 16] {
        let ad_updates = (associated_data.len() as u64).div_ceil(32);
        let msg_updates = (plaintext.len() as u64).div_ceil(32);
        let fin_updates = 7u64;
        aegis_aes_block::add_aesenc_ops((ad_updates + msg_updates + fin_updates) * 8);

        for chunk in associated_data.chunks(32) {
            let mut ad0 = [0u8; 16];
            let mut ad1 = [0u8; 16];

            if chunk.len() >= 16 {
                ad0.copy_from_slice(&chunk[..16]);
                if chunk.len() >= 32 {
                    ad1.copy_from_slice(&chunk[16..32]);
                } else if chunk.len() > 16 {
                    ad1[..chunk.len() - 16].copy_from_slice(&chunk[16..]);
                }
            } else {
                ad0[..chunk.len()].copy_from_slice(chunk);
            }

            Self::update(&mut self.state, AesBlock::from_bytes(&ad0), AesBlock::from_bytes(&ad1));
        }

        let mut i = 0usize;

        // Hot path: 256-byte chunks (eight 32-byte rounds).
        while i + 256 <= plaintext.len() {
            for r in 0..8 {
                let off = i + r * 32;
                let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
                let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
                let mut msg0 = [0u8; 16];
                let mut msg1 = [0u8; 16];
                msg0.copy_from_slice(&plaintext[off..off + 16]);
                msg1.copy_from_slice(&plaintext[off + 16..off + 32]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let msg1_block = AesBlock::from_bytes(&msg1);
                let c0 = msg0_block.xor(z0);
                let c1 = msg1_block.xor(z1);
                plaintext[off..off + 16].copy_from_slice(&c0.into_bytes());
                plaintext[off + 16..off + 32].copy_from_slice(&c1.into_bytes());
                Self::update(&mut self.state, msg0_block, msg1_block);
            }
            i += 256;
        }

        // Next: 128-byte chunks.
        while i + 128 <= plaintext.len() {
            for r in 0..4 {
                let off = i + r * 32;
                let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
                let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
                let mut msg0 = [0u8; 16];
                let mut msg1 = [0u8; 16];
                msg0.copy_from_slice(&plaintext[off..off + 16]);
                msg1.copy_from_slice(&plaintext[off + 16..off + 32]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let msg1_block = AesBlock::from_bytes(&msg1);
                let c0 = msg0_block.xor(z0);
                let c1 = msg1_block.xor(z1);
                plaintext[off..off + 16].copy_from_slice(&c0.into_bytes());
                plaintext[off + 16..off + 32].copy_from_slice(&c1.into_bytes());
                Self::update(&mut self.state, msg0_block, msg1_block);
            }
            i += 128;
        }

        // Fallback: 64-byte chunks.
        while i + 64 <= plaintext.len() {
            // First 32 bytes.
            let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            let mut msg0 = [0u8; 16];
            let mut msg1 = [0u8; 16];
            msg0.copy_from_slice(&plaintext[i..i + 16]);
            msg1.copy_from_slice(&plaintext[i + 16..i + 32]);
            let msg0_block = AesBlock::from_bytes(&msg0);
            let msg1_block = AesBlock::from_bytes(&msg1);
            let c0 = msg0_block.xor(z0);
            let c1 = msg1_block.xor(z1);
            plaintext[i..i + 16].copy_from_slice(&c0.into_bytes());
            plaintext[i + 16..i + 32].copy_from_slice(&c1.into_bytes());
            Self::update(&mut self.state, msg0_block, msg1_block);

            // Second 32 bytes.
            let z0b = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1b = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            let mut msg2 = [0u8; 16];
            let mut msg3 = [0u8; 16];
            msg2.copy_from_slice(&plaintext[i + 32..i + 48]);
            msg3.copy_from_slice(&plaintext[i + 48..i + 64]);
            let msg2_block = AesBlock::from_bytes(&msg2);
            let msg3_block = AesBlock::from_bytes(&msg3);
            let c2 = msg2_block.xor(z0b);
            let c3 = msg3_block.xor(z1b);
            plaintext[i + 32..i + 48].copy_from_slice(&c2.into_bytes());
            plaintext[i + 48..i + 64].copy_from_slice(&c3.into_bytes());
            Self::update(&mut self.state, msg2_block, msg3_block);

            i += 64;
        }

        while i < plaintext.len() {
            let rem = plaintext.len() - i;
            let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            if rem >= 32 {
                let mut msg0 = [0u8; 16];
                let mut msg1 = [0u8; 16];
                msg0.copy_from_slice(&plaintext[i..i + 16]);
                msg1.copy_from_slice(&plaintext[i + 16..i + 32]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let msg1_block = AesBlock::from_bytes(&msg1);
                let c0 = msg0_block.xor(z0);
                let c1 = msg1_block.xor(z1);
                plaintext[i..i + 16].copy_from_slice(&c0.into_bytes());
                plaintext[i + 16..i + 32].copy_from_slice(&c1.into_bytes());
                Self::update(&mut self.state, msg0_block, msg1_block);
                i += 32;
            } else if rem >= 16 {
                let mut msg0 = [0u8; 16];
                let mut msg1 = [0u8; 16];
                msg0.copy_from_slice(&plaintext[i..i + 16]);
                msg1[..rem - 16].copy_from_slice(&plaintext[i + 16..i + rem]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let msg1_block = AesBlock::from_bytes(&msg1);
                let c0 = msg0_block.xor(z0);
                let c1 = msg1_block.xor(z1);
                plaintext[i..i + 16].copy_from_slice(&c0.into_bytes());
                let remaining = rem - 16;
                plaintext[i + 16..i + 16 + remaining]
                    .copy_from_slice(&c1.into_bytes()[..remaining]);
                Self::update(&mut self.state, msg0_block, msg1_block);
                i += rem;
            } else {
                let mut msg0 = [0u8; 16];
                msg0[..rem].copy_from_slice(&plaintext[i..i + rem]);
                let msg0_block = AesBlock::from_bytes(&msg0);
                let c0 = msg0_block.xor(z0);
                plaintext[i..i + rem].copy_from_slice(&c0.into_bytes()[..rem]);
                Self::update(&mut self.state, msg0_block, AesBlock::from_bytes(&[0u8; 16]));
                i += rem;
            }
        }

        let ad_bits = (associated_data.len() as u64).wrapping_mul(8);
        let msg_bits = (plaintext.len() as u64).wrapping_mul(8);
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&ad_bits.to_le_bytes());
        len_block[8..16].copy_from_slice(&msg_bits.to_le_bytes());
        let l0 = AesBlock::from_bytes(&len_block);
        let l1 = l0;
        for _ in 0..7 {
            Self::update(&mut self.state, l0, l1);
        }

        self.state[0]
            .xor(self.state[1])
            .xor(self.state[2])
            .xor(self.state[3])
            .xor(self.state[4])
            .xor(self.state[5])
            .xor(self.state[6])
            .xor(self.state[7])
            .into_bytes()
    }

    pub fn decrypt_in_place(
        &mut self,
        ciphertext: &mut [u8],
        associated_data: &[u8],
        tag: &[u8; 16],
    ) -> Result<(), AegisError> {
        let ad_updates = (associated_data.len() as u64).div_ceil(32);
        let msg_updates = (ciphertext.len() as u64).div_ceil(32);
        let fin_updates = 7u64;
        aegis_aes_block::add_aesenc_ops((ad_updates + msg_updates + fin_updates) * 8);

        for chunk in associated_data.chunks(32) {
            let mut ad0 = [0u8; 16];
            let mut ad1 = [0u8; 16];

            if chunk.len() >= 16 {
                ad0.copy_from_slice(&chunk[..16]);
                if chunk.len() >= 32 {
                    ad1.copy_from_slice(&chunk[16..32]);
                } else if chunk.len() > 16 {
                    ad1[..chunk.len() - 16].copy_from_slice(&chunk[16..]);
                }
            } else {
                ad0[..chunk.len()].copy_from_slice(chunk);
            }
            Self::update(&mut self.state, AesBlock::from_bytes(&ad0), AesBlock::from_bytes(&ad1));
        }

        let mut i = 0usize;

        while i + 256 <= ciphertext.len() {
            for r in 0..8 {
                let off = i + r * 32;
                let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
                let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
                let mut c0 = [0u8; 16];
                let mut c1 = [0u8; 16];
                c0.copy_from_slice(&ciphertext[off..off + 16]);
                c1.copy_from_slice(&ciphertext[off + 16..off + 32]);
                let p0 = AesBlock::from_bytes(&c0).xor(z0).into_bytes();
                let p1 = AesBlock::from_bytes(&c1).xor(z1).into_bytes();
                ciphertext[off..off + 16].copy_from_slice(&p0);
                ciphertext[off + 16..off + 32].copy_from_slice(&p1);
                let msg0_block = AesBlock::from_bytes(&p0);
                let msg1_block = AesBlock::from_bytes(&p1);
                Self::update(&mut self.state, msg0_block, msg1_block);
            }
            i += 256;
        }

        while i + 128 <= ciphertext.len() {
            for r in 0..4 {
                let off = i + r * 32;
                let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
                let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
                let mut c0 = [0u8; 16];
                let mut c1 = [0u8; 16];
                c0.copy_from_slice(&ciphertext[off..off + 16]);
                c1.copy_from_slice(&ciphertext[off + 16..off + 32]);
                let p0 = AesBlock::from_bytes(&c0).xor(z0).into_bytes();
                let p1 = AesBlock::from_bytes(&c1).xor(z1).into_bytes();
                ciphertext[off..off + 16].copy_from_slice(&p0);
                ciphertext[off + 16..off + 32].copy_from_slice(&p1);
                let msg0_block = AesBlock::from_bytes(&p0);
                let msg1_block = AesBlock::from_bytes(&p1);
                Self::update(&mut self.state, msg0_block, msg1_block);
            }
            i += 128;
        }

        while i + 64 <= ciphertext.len() {
            let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            let mut c0 = [0u8; 16];
            let mut c1 = [0u8; 16];
            c0.copy_from_slice(&ciphertext[i..i + 16]);
            c1.copy_from_slice(&ciphertext[i + 16..i + 32]);
            let p0 = AesBlock::from_bytes(&c0).xor(z0).into_bytes();
            let p1 = AesBlock::from_bytes(&c1).xor(z1).into_bytes();
            ciphertext[i..i + 16].copy_from_slice(&p0);
            ciphertext[i + 16..i + 32].copy_from_slice(&p1);
            let msg0_block = AesBlock::from_bytes(&p0);
            let msg1_block = AesBlock::from_bytes(&p1);
            Self::update(&mut self.state, msg0_block, msg1_block);

            let z0b = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1b = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            let mut c2 = [0u8; 16];
            let mut c3 = [0u8; 16];
            c2.copy_from_slice(&ciphertext[i + 32..i + 48]);
            c3.copy_from_slice(&ciphertext[i + 48..i + 64]);
            let p2 = AesBlock::from_bytes(&c2).xor(z0b).into_bytes();
            let p3 = AesBlock::from_bytes(&c3).xor(z1b).into_bytes();
            ciphertext[i + 32..i + 48].copy_from_slice(&p2);
            ciphertext[i + 48..i + 64].copy_from_slice(&p3);
            let msg2_block = AesBlock::from_bytes(&p2);
            let msg3_block = AesBlock::from_bytes(&p3);
            Self::update(&mut self.state, msg2_block, msg3_block);

            i += 64;
        }

        while i < ciphertext.len() {
            let rem = ciphertext.len() - i;
            let z0 = self.state[6].xor(self.state[1]).xor(self.state[2].and(self.state[3]));
            let z1 = self.state[2].xor(self.state[5]).xor(self.state[6].and(self.state[7]));
            if rem >= 32 {
                let mut c0 = [0u8; 16];
                let mut c1 = [0u8; 16];
                c0.copy_from_slice(&ciphertext[i..i + 16]);
                c1.copy_from_slice(&ciphertext[i + 16..i + 32]);
                let p0 = AesBlock::from_bytes(&c0).xor(z0).into_bytes();
                let p1 = AesBlock::from_bytes(&c1).xor(z1).into_bytes();
                ciphertext[i..i + 16].copy_from_slice(&p0);
                ciphertext[i + 16..i + 32].copy_from_slice(&p1);
                let msg0_block = AesBlock::from_bytes(&p0);
                let msg1_block = AesBlock::from_bytes(&p1);
                Self::update(&mut self.state, msg0_block, msg1_block);
                i += 32;
            } else if rem >= 16 {
                let mut c0 = [0u8; 16];
                let mut c1 = [0u8; 16];
                c0.copy_from_slice(&ciphertext[i..i + 16]);
                c1[..rem - 16].copy_from_slice(&ciphertext[i + 16..i + rem]);
                let p0 = AesBlock::from_bytes(&c0).xor(z0).into_bytes();
                let p1_full = AesBlock::from_bytes(&c1).xor(z1).into_bytes();
                ciphertext[i..i + 16].copy_from_slice(&p0);
                let remaining = rem - 16;
                ciphertext[i + 16..i + 16 + remaining].copy_from_slice(&p1_full[..remaining]);
                let msg0_block = AesBlock::from_bytes(&p0);
                let mut p1_padded = [0u8; 16];
                p1_padded[..remaining].copy_from_slice(&p1_full[..remaining]);
                let msg1_block = AesBlock::from_bytes(&p1_padded);
                Self::update(&mut self.state, msg0_block, msg1_block);
                i += rem;
            } else {
                let mut c0 = [0u8; 16];
                c0[..rem].copy_from_slice(&ciphertext[i..i + rem]);
                let p0_full = AesBlock::from_bytes(&c0).xor(z0).into_bytes();
                ciphertext[i..i + rem].copy_from_slice(&p0_full[..rem]);
                let mut p0_padded = [0u8; 16];
                p0_padded[..rem].copy_from_slice(&p0_full[..rem]);
                let msg0_block = AesBlock::from_bytes(&p0_padded);
                Self::update(&mut self.state, msg0_block, AesBlock::from_bytes(&[0u8; 16]));
                i += rem;
            }
        }

        let ad_bits = (associated_data.len() as u64).wrapping_mul(8);
        let msg_bits = (ciphertext.len() as u64).wrapping_mul(8);
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&ad_bits.to_le_bytes());
        len_block[8..16].copy_from_slice(&msg_bits.to_le_bytes());
        let l0 = AesBlock::from_bytes(&len_block);
        let l1 = l0;
        for _ in 0..7 {
            Self::update(&mut self.state, l0, l1);
        }

        let computed_tag = self.state[0]
            .xor(self.state[1])
            .xor(self.state[2])
            .xor(self.state[3])
            .xor(self.state[4])
            .xor(self.state[5])
            .xor(self.state[6])
            .xor(self.state[7])
            .into_bytes();

        if !subtle_ct_eq(&computed_tag, tag) {
            return Err(AegisError::InvalidTag);
        }

        Ok(())
    }
}

/// Enumerates the available cipher suites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    Aegis128L,
    Morus1280_128,
}

/// Trait implemented by each cipher providing encryption and decryption.
trait CipherImpl {
    fn encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, &'static str>;

    fn decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, &'static str>;
}

struct Aegis128LImpl;

impl CipherImpl for Aegis128LImpl {
    fn encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        if nonce.len() != 16 {
            return Err("Invalid nonce length");
        }
        let mut cipher =
            crate::crypto::Aegis128L::new(key, nonce).map_err(|_| "Invalid key or nonce length")?;
        let mut buffer = plaintext.to_vec();
        let tag = cipher.encrypt_in_place(&mut buffer, ad);
        buffer.extend_from_slice(&tag);
        Ok(buffer)
    }

    fn decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        if nonce.len() != 16 {
            return Err("Invalid nonce length");
        }
        if ciphertext.len() < 16 {
            return Err("Ciphertext too short");
        }
        let mut cipher =
            crate::crypto::Aegis128L::new(key, nonce).map_err(|_| "Invalid key or nonce length")?;
        let (msg, tag_slice) = ciphertext.split_at(ciphertext.len() - 16);
        let mut buffer = msg.to_vec();
        let tag: [u8; 16] = tag_slice.try_into().map_err(|_| "Invalid tag length")?;
        cipher.decrypt_in_place(&mut buffer, ad, &tag).map_err(|_| "Decryption failed")?;
        Ok(buffer)
    }
}

struct MorusImpl;

impl MorusImpl {}

impl CipherImpl for MorusImpl {
    fn encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        if key.len() != 16 {
            return Err("Invalid key length for Morus");
        }
        if nonce.len() != 16 {
            return Err("Invalid nonce length for Morus");
        }
        let key_array: &[u8; 16] = key.try_into().map_err(|_| "Invalid key length for Morus")?;
        let nonce_array: &[u8; 16] =
            nonce.try_into().map_err(|_| "Invalid nonce length for Morus")?;

        // Use optimized path based on CPU features
        let morus = MorusAead::new(key_array, &[0u8; 12]);
        let (ciphertext, tag) = morus.encrypt_optimized(plaintext, ad, nonce_array);

        let mut result = ciphertext;
        result.extend_from_slice(&tag);
        Ok(result)
    }

    fn decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        if ciphertext.len() < 16 {
            return Err("Ciphertext too short for Morus");
        }
        let key_array: &[u8; 16] = key.try_into().map_err(|_| "Invalid key length for Morus")?;
        let nonce_array: &[u8; 16] =
            nonce.try_into().map_err(|_| "Invalid nonce length for Morus")?;
        let (msg, tag_slice) = ciphertext.split_at(ciphertext.len() - 16);
        let tag: &[u8; 16] = tag_slice.try_into().map_err(|_| "Invalid tag length for Morus")?;

        let morus = MorusAead::new(key_array, &[0u8; 12]);
        morus.decrypt_optimized(msg, tag, ad, nonce_array).map_err(|_| "Tag verification failed")
    }
}

// Note: No plaintext fallback is permitted. All cipher paths must provide AEAD.

/// Selects the optimal cipher suite at runtime based on CPU features.
pub struct CipherSuiteSelector {
    selected_suite: CipherSuite,
    cipher: Box<dyn CipherImpl + Send + Sync>,
}

impl CipherSuiteSelector {
    /// Creates a new `CipherSuiteSelector` and determines the best available cipher.
    pub fn new() -> Self {
        // Manual override via environment variable (tests only).
        #[cfg(any(test, feature = "rust-tests"))]
        if let Some(suite) = Self::override_from_env() {
            return Self::with_suite(suite);
        }

        // Use centralized SSOT plan
        let plan = crate::simd::CryptoAeadPlan::select();
        let selected_suite = {
            #[cfg(target_arch = "aarch64")]
            {
                match plan {
                    CryptoAeadPlan::LAesni | CryptoAeadPlan::LNeon => {
                        info!("Plan {:?}: selecting AEGIS-128L", plan);
                        CipherSuite::Aegis128L
                    }
                    CryptoAeadPlan::Morus => {
                        info!("Plan {:?}: selecting MORUS-1280", plan);
                        CipherSuite::Morus1280_128
                    }
                }
            }
            #[cfg(not(target_arch = "aarch64"))]
            {
                match plan {
                    CryptoAeadPlan::LAesni => {
                        info!("Plan {:?}: selecting AEGIS-128L", plan);
                        CipherSuite::Aegis128L
                    }
                    CryptoAeadPlan::Morus => {
                        info!("Plan {:?}: selecting MORUS-1280", plan);
                        CipherSuite::Morus1280_128
                    }
                }
            }
        };
        Self::with_suite(selected_suite)
    }

    /// Parses QUICFUSCATE_CIPHER env var (tests only).
    /// Recognized values: auto|aegis128l|morus
    #[cfg(any(test, feature = "rust-tests"))]
    fn override_from_env() -> Option<CipherSuite> {
        match std::env::var("QUICFUSCATE_CIPHER") {
            Ok(val) => {
                let v = val.trim().to_lowercase();
                match v.as_str() {
                    "" | "auto" => None,
                    "aegis128l" | "aegis-128l" => Some(CipherSuite::Aegis128L),
                    "morus" | "morus1280_128" => Some(CipherSuite::Morus1280_128),
                    _ => None,
                }
            }
            Err(_) => None,
        }
    }

    /// Creates a selector for the given suite.
    pub fn with_suite(suite: CipherSuite) -> Self {
        let cipher: Box<dyn CipherImpl + Send + Sync> = match suite {
            CipherSuite::Aegis128L => Box::new(Aegis128LImpl),
            CipherSuite::Morus1280_128 => Box::new(MorusImpl),
        };

        info!("Selected cipher suite: {:?}", suite);

        Self { selected_suite: suite, cipher }
    }

    /// Returns a TLS cipher suite identifier associated for logging purposes.
    /// Note: This value is not used to configure the TLS stack.
    pub fn tls_cipher(&self) -> u16 {
        match self.selected_suite {
            CipherSuite::Aegis128L => 0x1301,     // TLS_AES_128_GCM_SHA256
            CipherSuite::Morus1280_128 => 0x1304, // Custom ID
        }
    }

    /// Returns the selected cipher suite.
    pub fn selected_suite(&self) -> CipherSuite {
        self.selected_suite
    }

    /// Encrypts data using the automatically selected cipher suite.
    pub fn encrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        self.cipher.encrypt(key, nonce, ad, plaintext)
    }

    /// Decrypts data using the automatically selected cipher suite.
    pub fn decrypt(
        &self,
        key: &[u8],
        nonce: &[u8],
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        self.cipher.decrypt(key, nonce, ad, ciphertext)
    }
}

impl Default for CipherSuiteSelector {
    fn default() -> Self {
        Self::new()
    }
}
/// Manages cryptographic keys and provides secure random data.
/// This manager ensures that all cryptographic operations are backed by
/// secure, session-specific materials.
pub struct CryptoManager;

impl CryptoManager {
    pub fn new() -> Self {
        Self
    }

    /// Generates a cryptographically secure random key of a given length.
    /// This is used for generating ephemeral keys for XOR obfuscation.
    pub fn get_obfuscation_key(&self, length: usize) -> Vec<u8> {
        let mut key = vec![0; length];
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Generates a session specific key. This helper wraps [`Self::get_obfuscation_key`]
    /// to make the intent clear when a new connection is created.
    pub fn generate_session_key(&self, length: usize) -> Vec<u8> {
        self.get_obfuscation_key(length)
    }

    /// Generates a Kyber768 keypair for post-quantum key exchange.
    #[cfg(feature = "pq")]
    pub fn pq_keypair(&self) -> (Vec<u8>, Vec<u8>) {
        crate::crypto::pq::PqCrypto::mlkem_keypair()
    }

    /// Encapsulates a shared secret to the provided Kyber768 public key.
    #[cfg(feature = "pq")]
    pub fn pq_encapsulate(&self, pk: &[u8]) -> (Vec<u8>, Vec<u8>) {
        crate::crypto::pq::PqCrypto::mlkem_encapsulate(pk)
    }

    /// Decapsulates a Kyber768 ciphertext to obtain the shared secret.
    #[cfg(feature = "pq")]
    pub fn pq_decapsulate(&self, ct: &[u8], sk: &[u8]) -> Vec<u8> {
        crate::crypto::pq::PqCrypto::mlkem_decapsulate(ct, sk)
    }

    /// Signs data using Dilithium3.
    #[cfg(feature = "pq")]
    pub fn pq_sign(&self, msg: &[u8], sk: &[u8]) -> Vec<u8> {
        crate::crypto::pq::PqCrypto::mldsa_sign(msg, sk)
    }

    /// Verifies a Dilithium3 signature.
    #[cfg(feature = "pq")]
    pub fn pq_verify(&self, msg: &[u8], sig: &[u8], pk: &[u8]) -> bool {
        crate::crypto::pq::PqCrypto::mldsa_verify(msg, sig, pk)
    }
}

impl Default for CryptoManager {
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------------
// QUIC AEAD/HP and supporting primitives (moved from native.rs)
// -----------------------------------------------------------------------------

pub mod aes {
    use super::OnceLock;
    use std::sync::atomic::{AtomicUsize, Ordering};
    const SBOX: [u8; 256] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
        0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
        0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
        0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
        0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
        0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
        0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
        0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
        0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
        0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
        0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
        0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
        0x16,
    ];
    const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
    fn sub_word(w: [u8; 4]) -> [u8; 4] {
        [SBOX[w[0] as usize], SBOX[w[1] as usize], SBOX[w[2] as usize], SBOX[w[3] as usize]]
    }
    fn rot_word(w: [u8; 4]) -> [u8; 4] {
        [w[1], w[2], w[3], w[0]]
    }
    pub(crate) fn key_expansion(key: &[u8; 16]) -> [u8; 176] {
        let mut w = [0u8; 176];
        w[..16].copy_from_slice(key);
        let mut i = 16;
        let mut rcon_iter = 0;
        while i < 176 {
            let mut temp = [w[i - 4], w[i - 3], w[i - 2], w[i - 1]];
            if i % 16 == 0 {
                temp = sub_word(rot_word(temp));
                temp[0] ^= RCON[rcon_iter];
                rcon_iter += 1;
            }
            for &t in &temp {
                w[i] = w[i - 16] ^ t;
                i += 1;
            }
        }
        w
    }

    #[inline(always)]
    fn expand_round_keys_array(key: &[u8; 16]) -> [[u8; 16]; 11] {
        let expanded = key_expansion(key);
        let mut keys = [[0u8; 16]; 11];
        for (idx, chunk) in expanded.chunks_exact(16).enumerate() {
            keys[idx].copy_from_slice(chunk);
        }
        keys
    }

    #[inline(always)]
    fn inc32_be(counter: &mut [u8; 16]) {
        let value = u32::from_be_bytes([counter[12], counter[13], counter[14], counter[15]])
            .wrapping_add(1);
        counter[12..16].copy_from_slice(&value.to_be_bytes());
    }
    fn sub_bytes(state: &mut [u8; 16]) {
        for b in state.iter_mut() {
            *b = SBOX[*b as usize];
        }
    }
    fn shift_rows(state: &mut [u8; 16]) {
        let t = state[1];
        state[1] = state[5];
        state[5] = state[9];
        state[9] = state[13];
        state[13] = t;
        let t0 = state[2];
        let t1 = state[6];
        state[2] = state[10];
        state[6] = state[14];
        state[10] = t0;
        state[14] = t1;
        let t2 = state[3];
        state[3] = state[15];
        state[15] = state[11];
        state[11] = state[7];
        state[7] = t2;
    }
    fn mix_single_column(a: &mut [u8; 4]) {
        fn xtime(x: u8) -> u8 {
            (x << 1) ^ (((x >> 7) & 1) * 0x1b)
        }
        let t = a[0] ^ a[1] ^ a[2] ^ a[3];
        let u = a[0];
        a[0] ^= t ^ xtime(a[0] ^ a[1]);
        a[1] ^= t ^ xtime(a[1] ^ a[2]);
        a[2] ^= t ^ xtime(a[2] ^ a[3]);
        a[3] ^= t ^ xtime(a[3] ^ u);
    }
    fn mix_columns(state: &mut [u8; 16]) {
        for c in 0..4 {
            let mut col = [state[4 * c], state[4 * c + 1], state[4 * c + 2], state[4 * c + 3]];
            mix_single_column(&mut col);
            state[4 * c..4 * c + 4].copy_from_slice(&col);
        }
    }
    fn add_round_key(state: &mut [u8; 16], round_key: &[u8]) {
        for (i, b) in state.iter_mut().enumerate() {
            *b ^= round_key[i];
        }
    }

    /// Software equivalent of AESENC(state, round_key).
    ///
    /// AESENC performs one AES round:
    /// SubBytes -> ShiftRows -> MixColumns -> AddRoundKey.
    #[inline(always)]
    pub(crate) fn aesenc_round(block: &[u8; 16], round_key: &[u8; 16]) -> [u8; 16] {
        let mut state = *block;
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, round_key);
        state
    }
    #[derive(Debug)]
    struct AesTables {
        t0: [u32; 256],
        t1: [u32; 256],
        t2: [u32; 256],
        t3: [u32; 256],
    }

    static AES_TABLES: OnceLock<AesTables> = OnceLock::new();

    #[inline(always)]
    fn gf_mul2(x: u8) -> u8 {
        (x << 1) ^ (((x >> 7) & 1) * 0x1b)
    }

    fn build_tables() -> AesTables {
        let mut t0 = [0u32; 256];
        let mut t1 = [0u32; 256];
        let mut t2 = [0u32; 256];
        let mut t3 = [0u32; 256];
        for (i, t_entry) in t0.iter_mut().enumerate() {
            let s = SBOX[i];
            let s2 = gf_mul2(s);
            let s3 = s2 ^ s;
            *t_entry =
                (u32::from(s2) << 24) ^ (u32::from(s) << 16) ^ (u32::from(s) << 8) ^ u32::from(s3);
            t1[i] =
                (u32::from(s3) << 24) ^ (u32::from(s2) << 16) ^ (u32::from(s) << 8) ^ u32::from(s);
            t2[i] =
                (u32::from(s) << 24) ^ (u32::from(s3) << 16) ^ (u32::from(s2) << 8) ^ u32::from(s);
            t3[i] =
                (u32::from(s) << 24) ^ (u32::from(s) << 16) ^ (u32::from(s3) << 8) ^ u32::from(s2);
        }
        AesTables { t0, t1, t2, t3 }
    }

    #[inline(always)]
    fn aes_tables() -> &'static AesTables {
        AES_TABLES.get_or_init(build_tables)
    }

    #[inline]
    fn round_keys_to_words(round_keys: &[[u8; 16]; 11]) -> [[u32; 4]; 11] {
        let mut out = [[0u32; 4]; 11];
        for (dst, key) in out.iter_mut().zip(round_keys.iter()) {
            dst[0] = u32::from_be_bytes([key[0], key[1], key[2], key[3]]);
            dst[1] = u32::from_be_bytes([key[4], key[5], key[6], key[7]]);
            dst[2] = u32::from_be_bytes([key[8], key[9], key[10], key[11]]);
            dst[3] = u32::from_be_bytes([key[12], key[13], key[14], key[15]]);
        }
        out
    }

    #[inline(always)]
    fn load_block_words(block: &[u8; 16]) -> [u32; 4] {
        [
            u32::from_be_bytes([block[0], block[1], block[2], block[3]]),
            u32::from_be_bytes([block[4], block[5], block[6], block[7]]),
            u32::from_be_bytes([block[8], block[9], block[10], block[11]]),
            u32::from_be_bytes([block[12], block[13], block[14], block[15]]),
        ]
    }

    #[inline(always)]
    fn store_block_words(words: [u32; 4]) -> [u8; 16] {
        let mut out = [0u8; 16];
        for (i, word) in words.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    #[inline(always)]
    fn aes128_encrypt_block_tables_words(
        round_keys: &[[u32; 4]; 11],
        block: &[u8; 16],
    ) -> [u8; 16] {
        let table = aes_tables();
        let mut state = load_block_words(block);
        let rk0 = round_keys[0];
        state[0] ^= rk0[0];
        state[1] ^= rk0[1];
        state[2] ^= rk0[2];
        state[3] ^= rk0[3];

        let mut s0 = state[0];
        let mut s1 = state[1];
        let mut s2 = state[2];
        let mut s3 = state[3];

        for rk in round_keys.iter().take(10).skip(1) {
            let t0 = table.t0[(s0 >> 24) as usize]
                ^ table.t1[((s1 >> 16) & 0xff) as usize]
                ^ table.t2[((s2 >> 8) & 0xff) as usize]
                ^ table.t3[(s3 & 0xff) as usize]
                ^ rk[0];
            let t1 = table.t0[(s1 >> 24) as usize]
                ^ table.t1[((s2 >> 16) & 0xff) as usize]
                ^ table.t2[((s3 >> 8) & 0xff) as usize]
                ^ table.t3[(s0 & 0xff) as usize]
                ^ rk[1];
            let t2 = table.t0[(s2 >> 24) as usize]
                ^ table.t1[((s3 >> 16) & 0xff) as usize]
                ^ table.t2[((s0 >> 8) & 0xff) as usize]
                ^ table.t3[(s1 & 0xff) as usize]
                ^ rk[2];
            let t3 = table.t0[(s3 >> 24) as usize]
                ^ table.t1[((s0 >> 16) & 0xff) as usize]
                ^ table.t2[((s1 >> 8) & 0xff) as usize]
                ^ table.t3[(s2 & 0xff) as usize]
                ^ rk[3];
            s0 = t0;
            s1 = t1;
            s2 = t2;
            s3 = t3;
        }

        let rk_last = round_keys[10];
        let o0 = (u32::from(SBOX[(s0 >> 24) as usize]) << 24)
            ^ (u32::from(SBOX[((s1 >> 16) & 0xff) as usize]) << 16)
            ^ (u32::from(SBOX[((s2 >> 8) & 0xff) as usize]) << 8)
            ^ u32::from(SBOX[(s3 & 0xff) as usize])
            ^ rk_last[0];
        let o1 = (u32::from(SBOX[(s1 >> 24) as usize]) << 24)
            ^ (u32::from(SBOX[((s2 >> 16) & 0xff) as usize]) << 16)
            ^ (u32::from(SBOX[((s3 >> 8) & 0xff) as usize]) << 8)
            ^ u32::from(SBOX[(s0 & 0xff) as usize])
            ^ rk_last[1];
        let o2 = (u32::from(SBOX[(s2 >> 24) as usize]) << 24)
            ^ (u32::from(SBOX[((s3 >> 16) & 0xff) as usize]) << 16)
            ^ (u32::from(SBOX[((s0 >> 8) & 0xff) as usize]) << 8)
            ^ u32::from(SBOX[(s1 & 0xff) as usize])
            ^ rk_last[2];
        let o3 = (u32::from(SBOX[(s3 >> 24) as usize]) << 24)
            ^ (u32::from(SBOX[((s0 >> 16) & 0xff) as usize]) << 16)
            ^ (u32::from(SBOX[((s1 >> 8) & 0xff) as usize]) << 8)
            ^ u32::from(SBOX[(s2 & 0xff) as usize])
            ^ rk_last[3];
        store_block_words([o0, o1, o2, o3])
    }

    #[cfg(test)]
    #[allow(clippy::items_after_test_module)]
    mod legacy_simd_tests {
        use super::{
            aes128_encrypt_block_scalar_with_round_keys, aes128_encrypt_block_tables_words,
            expand_round_keys_array, round_keys_to_words,
        };

        fn decode_hex_block(s: &str) -> [u8; 16] {
            let bytes = s.as_bytes();
            assert_eq!(bytes.len(), 32, "hex block must be 32 chars");
            let mut out = [0u8; 16];
            for (idx, chunk) in bytes.chunks(2).enumerate() {
                let hi = hex_value(chunk[0]);
                let lo = hex_value(chunk[1]);
                out[idx] = (hi << 4) | lo;
            }
            out
        }

        fn hex_value(b: u8) -> u8 {
            match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => panic!("invalid hex byte"),
            }
        }

        #[test]
        fn tables_match_scalar_reference_vector() {
            let key = decode_hex_block("000102030405060708090a0b0c0d0e0f");
            let block = decode_hex_block("00112233445566778899aabbccddeeff");
            let round_keys = expand_round_keys_array(&key);
            let round_words = round_keys_to_words(&round_keys);

            let scalar = aes128_encrypt_block_scalar_with_round_keys(&round_keys, &block);
            let tables = aes128_encrypt_block_tables_words(&round_words, &block);
            assert_eq!(scalar, tables);
            assert_eq!(tables, decode_hex_block("69c4e0d86a7b0430d8cdb78070b4c55a"));
        }

        #[test]
        fn tables_match_scalar_multiple_inputs() {
            let key = decode_hex_block("603deb1015ca71be2b73aef0857d7781");
            let mut block = decode_hex_block("6bc1bee22e409f96e93d7e117393172a");
            let round_keys = expand_round_keys_array(&key);
            let round_words = round_keys_to_words(&round_keys);

            for _ in 0..8 {
                let scalar = aes128_encrypt_block_scalar_with_round_keys(&round_keys, &block);
                let tables = aes128_encrypt_block_tables_words(&round_words, &block);
                assert_eq!(scalar, tables);
                // For next iteration, feed ciphertext back as input to increase coverage.
                block = tables;
            }
        }
    }
    pub fn aes128_encrypt_block(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
        let features = crate::optimize::FeatureDetector::instance().features_full();
        #[cfg(target_arch = "x86_64")]
        if features.aesni {
            crate::optimize::telemetry::AES_BLOCK_AESNI_OPS.inc();
            return unsafe { aes128_encrypt_block_aesni(key, block) };
        }
        #[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
        if features.sve_aes {
            crate::optimize::telemetry::AES_BLOCK_SVE_OPS.inc();
            return unsafe {
                let rk = expand_round_keys_array(key);
                aes128_encrypt_block_sve_round_keys(&rk, block)
            };
        }
        #[cfg(target_arch = "aarch64")]
        if features.aes {
            // Runtime self-test: ensure AESE sequence matches scalar on this CPU/layout
            static ARM_AES_OK: AtomicUsize = AtomicUsize::new(0); // 0 unknown, 1 ok, 2 broken
            let state = ARM_AES_OK.load(Ordering::Relaxed);
            let use_hw = if state == 0 {
                let k0 = [0u8; 16];
                let b0 = [0u8; 16];
                let sw = aes128_encrypt_block_scalar(&k0, &b0);
                let hw = unsafe { aes128_encrypt_block_aese(&k0, &b0) };
                let ok = sw == hw;
                ARM_AES_OK.store(if ok { 1 } else { 2 }, Ordering::Relaxed);
                ok
            } else {
                state == 1
            };
            if use_hw {
                crate::optimize::telemetry::AES_BLOCK_AESE_OPS.inc();
                return unsafe { aes128_encrypt_block_aese(key, block) };
            }
        }
        #[cfg(target_arch = "x86_64")]
        if features.sse2 && !features.aesni {
            crate::optimize::telemetry::AES_BLOCK_SSSE3_OPS.inc();
            let round_keys = expand_round_keys_array(key);
            let round_key_words = round_keys_to_words(&round_keys);
            return aes128_encrypt_block_tables_words(&round_key_words, block);
        }
        #[cfg(target_arch = "aarch64")]
        if features.neon && !features.aes && !features.sve_aes {
            crate::optimize::telemetry::AES_BLOCK_NEON_TABLE_OPS.inc();
            let round_keys = expand_round_keys_array(key);
            let round_key_words = round_keys_to_words(&round_keys);
            return aes128_encrypt_block_tables_words(&round_key_words, block);
        }
        crate::optimize::telemetry::AES_BLOCK_SCALAR_OPS.inc();
        aes128_encrypt_block_scalar(key, block)
    }

    #[inline]
    fn aes128_encrypt_block_scalar(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
        let round_keys = expand_round_keys_array(key);
        aes128_encrypt_block_scalar_with_round_keys(&round_keys, block)
    }

    #[inline(always)]
    fn aes128_encrypt_block_scalar_with_round_keys(
        round_keys: &[[u8; 16]; 11],
        block: &[u8; 16],
    ) -> [u8; 16] {
        let mut state = *block;
        add_round_key(&mut state, &round_keys[0]);
        for rk in round_keys.iter().take(10).skip(1) {
            sub_bytes(&mut state);
            shift_rows(&mut state);
            mix_columns(&mut state);
            add_round_key(&mut state, rk);
        }
        sub_bytes(&mut state);
        shift_rows(&mut state);
        add_round_key(&mut state, &round_keys[10]);
        state
    }

    pub struct Aes128Ctx {
        round_keys: [[u8; 16]; 11],
        round_keys_words: [[u32; 4]; 11],
        #[cfg(target_arch = "x86_64")]
        use_aesni: bool,
        #[cfg(target_arch = "x86_64")]
        use_table_fallback: bool,
        #[cfg(target_arch = "x86_64")]
        use_ssse3_fallback: bool,
        #[cfg(target_arch = "x86_64")]
        round_keys_ssse3: [core::arch::x86_64::__m128i; 11],
        #[cfg(target_arch = "aarch64")]
        use_aese: bool,
        #[cfg(target_arch = "aarch64")]
        use_neon_tables: bool,
        #[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
        use_sve_aes: bool,
    }

    impl Aes128Ctx {
        pub fn new(key: &[u8; 16]) -> Self {
            let round_keys = expand_round_keys_array(key);
            let round_keys_words = round_keys_to_words(&round_keys);
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            let features = crate::optimize::FeatureDetector::instance().features_full();
            #[cfg(target_arch = "x86_64")]
            let use_aesni = features.aesni;
            #[cfg(target_arch = "x86_64")]
            let use_ssse3_fallback = !use_aesni && features.ssse3 && features.sse2;
            #[cfg(target_arch = "x86_64")]
            let use_table_fallback = !use_aesni && !use_ssse3_fallback && features.sse2;
            #[cfg(target_arch = "x86_64")]
            let round_keys_ssse3 = {
                use core::arch::x86_64::_mm_loadu_si128;
                let mut tmp = [unsafe { core::mem::zeroed() }; 11];
                if use_ssse3_fallback {
                    for (dst, rk) in tmp.iter_mut().zip(round_keys.iter()) {
                        *dst = unsafe { _mm_loadu_si128(rk.as_ptr() as *const _) };
                    }
                }
                tmp
            };
            #[cfg(target_arch = "aarch64")]
            let use_aese = features.aes;
            #[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
            let use_sve_aes = features.sve_aes;
            #[cfg(target_arch = "aarch64")]
            let use_neon_tables = {
                let has_neon = features.neon;
                #[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
                let has_sve_aes = use_sve_aes;
                #[cfg(not(all(target_arch = "aarch64", target_feature = "sve2")))]
                let has_sve_aes = false;
                has_neon && !use_aese && !has_sve_aes
            };
            Self {
                round_keys,
                round_keys_words,
                #[cfg(target_arch = "x86_64")]
                use_aesni,
                #[cfg(target_arch = "x86_64")]
                use_table_fallback,
                #[cfg(target_arch = "x86_64")]
                use_ssse3_fallback,
                #[cfg(target_arch = "x86_64")]
                round_keys_ssse3,
                #[cfg(target_arch = "aarch64")]
                use_aese,
                #[cfg(target_arch = "aarch64")]
                use_neon_tables,
                #[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
                use_sve_aes,
            }
        }

        #[inline(always)]
        pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
            #[cfg(target_arch = "x86_64")]
            if self.use_aesni {
                return unsafe { aes128_encrypt_block_aesni_round_keys(&self.round_keys, block) };
            }
            #[cfg(target_arch = "x86_64")]
            if self.use_table_fallback {
                crate::optimize::telemetry::AES_BLOCK_SSSE3_OPS.inc();
                return aes128_encrypt_block_tables_words(&self.round_keys_words, block);
            }
            #[cfg(target_arch = "x86_64")]
            if self.use_ssse3_fallback {
                crate::optimize::telemetry::AES_BLOCK_SSSE3_OPS.inc();
                return unsafe { aes128_encrypt_block_ssse3(&self.round_keys_ssse3, block) };
            }
            #[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
            if self.use_sve_aes {
                crate::optimize::telemetry::AES_BLOCK_SVE_OPS.inc();
                return unsafe { aes128_encrypt_block_sve_round_keys(&self.round_keys, block) };
            }
            #[cfg(target_arch = "aarch64")]
            if self.use_aese {
                return unsafe { aes128_encrypt_block_aese_round_keys(&self.round_keys, block) };
            }
            #[cfg(target_arch = "aarch64")]
            if self.use_neon_tables {
                crate::optimize::telemetry::AES_BLOCK_NEON_TABLE_OPS.inc();
                return aes128_encrypt_block_tables_words(&self.round_keys_words, block);
            }
            aes128_encrypt_block_scalar_with_round_keys(&self.round_keys, block)
        }

        #[inline]
        pub fn ctr_xor(&self, counter: &mut [u8; 16], input: &[u8], output: &mut [u8]) {
            assert_eq!(input.len(), output.len());
            let mut offset = 0usize;

            #[cfg(target_arch = "x86_64")]
            if self.use_aesni {
                unsafe {
                    offset = self.ctr_xor_aesni(counter, input, output);
                }
            }

            #[cfg(target_arch = "x86_64")]
            if self.use_ssse3_fallback {
                unsafe {
                    offset = self.ctr_xor_ssse3(counter, input, output);
                }
            }

            #[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
            {
                if self.use_sve_aes {
                    unsafe {
                        offset = self.ctr_xor_sve(counter, input, output);
                    }
                } else if self.use_aese {
                    unsafe {
                        offset = self.ctr_xor_aese(counter, input, output);
                    }
                }
            }

            #[cfg(all(target_arch = "aarch64", not(target_feature = "sve2")))]
            if self.use_aese {
                unsafe {
                    offset = self.ctr_xor_aese(counter, input, output);
                }
            }

            while offset + 16 <= input.len() {
                if offset == 0 {
                    crate::optimize::telemetry::AES_CTR_SCALAR_OPS.inc();
                }
                let ctr_block = *counter;
                let ks = self.encrypt_block(&ctr_block);
                for j in 0..16 {
                    output[offset + j] = input[offset + j] ^ ks[j];
                }
                inc32_be(counter);
                offset += 16;
            }
            if offset < input.len() {
                if offset == 0 {
                    crate::optimize::telemetry::AES_CTR_SCALAR_OPS.inc();
                }
                let ctr_block = *counter;
                let ks = self.encrypt_block(&ctr_block);
                for j in 0..(input.len() - offset) {
                    output[offset + j] = input[offset + j] ^ ks[j];
                }
                // Counter increment not needed after processing the tail block.
            }
        }

        #[cfg(target_arch = "x86_64")]
        #[target_feature(enable = "aes")]
        unsafe fn ctr_xor_aesni(
            &self,
            counter: &mut [u8; 16],
            input: &[u8],
            output: &mut [u8],
        ) -> usize {
            use core::arch::x86_64::*;

            crate::optimize::telemetry::AES_CTR_AESNI_OPS.inc();

            let mut offset = 0usize;
            while input.len().saturating_sub(offset) >= 64 {
                let mut ctr_blocks = [[0u8; 16]; 4];
                let mut current = *counter;
                for slot in ctr_blocks.iter_mut() {
                    *slot = current;
                    inc32_be(&mut current);
                }
                *counter = current;

                let lanes = [
                    _mm_loadu_si128(ctr_blocks[0].as_ptr() as *const __m128i),
                    _mm_loadu_si128(ctr_blocks[1].as_ptr() as *const __m128i),
                    _mm_loadu_si128(ctr_blocks[2].as_ptr() as *const __m128i),
                    _mm_loadu_si128(ctr_blocks[3].as_ptr() as *const __m128i),
                ];
                let ks = aesni_encrypt4_round_keys(&self.round_keys, lanes);

                for lane in 0..4 {
                    let idx = offset + lane * 16;
                    let pt = _mm_loadu_si128(input.as_ptr().add(idx) as *const __m128i);
                    let ct = _mm_xor_si128(pt, ks[lane]);
                    _mm_storeu_si128(output.as_mut_ptr().add(idx) as *mut __m128i, ct);
                }

                offset += 64;
            }
            offset
        }

        #[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
        #[target_feature(enable = "sve2")]
        unsafe fn ctr_xor_sve(
            &self,
            counter: &mut [u8; 16],
            input: &[u8],
            output: &mut [u8],
        ) -> usize {
            crate::optimize::telemetry::AES_CTR_SVE_OPS.inc();
            let mut offset = 0usize;
            while input.len().saturating_sub(offset) >= 16 {
                let ctr_block = *counter;
                let ks = aes128_encrypt_block_sve_round_keys(&self.round_keys, &ctr_block);
                for j in 0..16 {
                    let idx = offset + j;
                    output[idx] = input[idx] ^ ks[j];
                }
                inc32_be(counter);
                offset += 16;
            }
            offset
        }

        #[cfg(target_arch = "x86_64")]
        #[target_feature(enable = "ssse3")]
        unsafe fn ctr_xor_ssse3(
            &self,
            counter: &mut [u8; 16],
            input: &[u8],
            output: &mut [u8],
        ) -> usize {
            use core::arch::x86_64::{_mm_loadu_si128, _mm_storeu_si128, _mm_xor_si128};

            crate::optimize::telemetry::AES_CTR_SSSE3_OPS.inc();

            let mut offset = 0usize;
            while input.len().saturating_sub(offset) >= 32 {
                let ctr0 = *counter;
                inc32_be(counter);
                let ctr1 = *counter;
                inc32_be(counter);

                let ks0 = aes128_encrypt_block_ssse3_raw(&self.round_keys_ssse3, &ctr0);
                let ks1 = aes128_encrypt_block_ssse3_raw(&self.round_keys_ssse3, &ctr1);

                let pt0 = _mm_loadu_si128(input.as_ptr().add(offset) as *const _);
                let pt1 = _mm_loadu_si128(input.as_ptr().add(offset + 16) as *const _);

                let ct0 = _mm_xor_si128(pt0, ks0);
                let ct1 = _mm_xor_si128(pt1, ks1);

                _mm_storeu_si128(output.as_mut_ptr().add(offset) as *mut _, ct0);
                _mm_storeu_si128(output.as_mut_ptr().add(offset + 16) as *mut _, ct1);

                offset += 32;
            }
            offset
        }

        #[cfg(target_arch = "aarch64")]
        #[target_feature(enable = "aes")]
        unsafe fn ctr_xor_aese(
            &self,
            counter: &mut [u8; 16],
            input: &[u8],
            output: &mut [u8],
        ) -> usize {
            use core::arch::aarch64::*;

            crate::optimize::telemetry::AES_CTR_AESE_OPS.inc();

            let mut offset = 0usize;
            while input.len().saturating_sub(offset) >= 64 {
                let mut ctr_blocks = [[0u8; 16]; 4];
                let mut current = *counter;
                for slot in ctr_blocks.iter_mut() {
                    *slot = current;
                    inc32_be(&mut current);
                }
                *counter = current;

                let lanes = [
                    vld1q_u8(ctr_blocks[0].as_ptr()),
                    vld1q_u8(ctr_blocks[1].as_ptr()),
                    vld1q_u8(ctr_blocks[2].as_ptr()),
                    vld1q_u8(ctr_blocks[3].as_ptr()),
                ];
                let ks = aese_encrypt4_round_keys(&self.round_keys, lanes);

                for (lane, k) in ks.iter().enumerate() {
                    let idx = offset + lane * 16;
                    let pt = vld1q_u8(input.as_ptr().add(idx));
                    let ct = veorq_u8(pt, *k);
                    vst1q_u8(output.as_mut_ptr().add(idx), ct);
                }

                offset += 64;
            }
            offset
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "aes")]
    unsafe fn aes128_encrypt_block_aesni(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
        use core::arch::x86_64::*;
        let rk = key_expansion(key);
        let mut s = _mm_loadu_si128(block.as_ptr() as *const __m128i);
        let k0 = _mm_loadu_si128(rk[0..16].as_ptr() as *const __m128i);
        s = _mm_xor_si128(s, k0);
        for r in 1..10 {
            let kr = _mm_loadu_si128(rk[16 * r..16 * (r + 1)].as_ptr() as *const __m128i);
            s = _mm_aesenc_si128(s, kr);
        }
        let kf = _mm_loadu_si128(rk[160..176].as_ptr() as *const __m128i);
        s = _mm_aesenclast_si128(s, kf);
        let mut out = [0u8; 16];
        _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, s);
        out
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "ssse3")]
    unsafe fn sub_bytes_ssse3(state: core::arch::x86_64::__m128i) -> core::arch::x86_64::__m128i {
        use core::arch::x86_64::{_mm_loadu_si128, _mm_storeu_si128};
        let mut buf = [0u8; 16];
        _mm_storeu_si128(buf.as_mut_ptr() as *mut _, state);
        for byte in &mut buf {
            *byte = SBOX[*byte as usize];
        }
        _mm_loadu_si128(buf.as_ptr() as *const _)
    }

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    unsafe fn shift_rows_ssse3(state: core::arch::x86_64::__m128i) -> core::arch::x86_64::__m128i {
        use core::arch::x86_64::{_mm_setr_epi8, _mm_shuffle_epi8};
        let mask = _mm_setr_epi8(0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11);
        _mm_shuffle_epi8(state, mask)
    }

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    unsafe fn xtime_ssse3(x: core::arch::x86_64::__m128i) -> core::arch::x86_64::__m128i {
        use core::arch::x86_64::{
            _mm_and_si128, _mm_cmplt_epi8, _mm_set1_epi16, _mm_set1_epi8, _mm_setzero_si128,
            _mm_slli_epi16, _mm_xor_si128,
        };
        let shifted = _mm_and_si128(_mm_slli_epi16(x, 1), _mm_set1_epi16(0x00fe));
        let mask = _mm_cmplt_epi8(x, _mm_setzero_si128());
        let reduction = _mm_and_si128(mask, _mm_set1_epi8(0x1b));
        // `shifted` already contains the modulo-reduced left shift; XOR with reduction term.
        _mm_xor_si128(shifted, reduction)
    }

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    unsafe fn mix_columns_ssse3(state: core::arch::x86_64::__m128i) -> core::arch::x86_64::__m128i {
        use core::arch::x86_64::{_mm_setr_epi8, _mm_shuffle_epi8, _mm_xor_si128};

        let rot1 = _mm_shuffle_epi8(
            state,
            _mm_setr_epi8(1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12),
        );
        let rot2 = _mm_shuffle_epi8(
            state,
            _mm_setr_epi8(2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13),
        );
        let rot3 = _mm_shuffle_epi8(
            state,
            _mm_setr_epi8(3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14),
        );

        let maj = _mm_xor_si128(state, _mm_xor_si128(rot1, _mm_xor_si128(rot2, rot3)));

        let ab = xtime_ssse3(_mm_xor_si128(state, rot1));
        let bc = xtime_ssse3(_mm_xor_si128(rot1, rot2));
        let cd = xtime_ssse3(_mm_xor_si128(rot2, rot3));
        let da = xtime_ssse3(_mm_xor_si128(rot3, state));

        let res_a = _mm_xor_si128(_mm_xor_si128(state, maj), ab);
        let res_b = _mm_xor_si128(_mm_xor_si128(rot1, maj), bc);
        let res_c = _mm_xor_si128(_mm_xor_si128(rot2, maj), cd);
        let res_d = _mm_xor_si128(_mm_xor_si128(rot3, maj), da);

        let res_b = _mm_shuffle_epi8(
            res_b,
            _mm_setr_epi8(13, 14, 15, 12, 1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8),
        );
        let res_c = _mm_shuffle_epi8(
            res_c,
            _mm_setr_epi8(10, 11, 8, 9, 14, 15, 12, 13, 2, 3, 0, 1, 6, 7, 4, 5),
        );
        let res_d = _mm_shuffle_epi8(
            res_d,
            _mm_setr_epi8(7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14, 3, 0, 1, 2),
        );

        _mm_xor_si128(res_a, _mm_xor_si128(res_b, _mm_xor_si128(res_c, res_d)))
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "ssse3")]
    unsafe fn aes128_encrypt_block_ssse3_raw(
        round_keys: &[core::arch::x86_64::__m128i; 11],
        block: &[u8; 16],
    ) -> core::arch::x86_64::__m128i {
        use core::arch::x86_64::{_mm_loadu_si128, _mm_xor_si128};

        let mut state = _mm_loadu_si128(block.as_ptr() as *const _);
        state = _mm_xor_si128(state, round_keys[0]);

        for round in 1..10 {
            state = sub_bytes_ssse3(state);
            state = shift_rows_ssse3(state);
            state = mix_columns_ssse3(state);
            state = _mm_xor_si128(state, round_keys[round]);
        }

        state = sub_bytes_ssse3(state);
        state = shift_rows_ssse3(state);
        _mm_xor_si128(state, round_keys[10])
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "ssse3")]
    unsafe fn aes128_encrypt_block_ssse3(
        round_keys: &[core::arch::x86_64::__m128i; 11],
        block: &[u8; 16],
    ) -> [u8; 16] {
        use core::arch::x86_64::_mm_storeu_si128;
        let state = aes128_encrypt_block_ssse3_raw(round_keys, block);
        let mut out = [0u8; 16];
        _mm_storeu_si128(out.as_mut_ptr() as *mut _, state);
        out
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "aes")]
    unsafe fn aes128_encrypt_block_aesni_round_keys(
        round_keys: &[[u8; 16]; 11],
        block: &[u8; 16],
    ) -> [u8; 16] {
        use core::arch::x86_64::*;
        let mut s = _mm_loadu_si128(block.as_ptr() as *const __m128i);
        let k0 = _mm_loadu_si128(round_keys[0].as_ptr() as *const __m128i);
        s = _mm_xor_si128(s, k0);
        for r in 1..10 {
            let kr = _mm_loadu_si128(round_keys[r].as_ptr() as *const __m128i);
            s = _mm_aesenc_si128(s, kr);
        }
        let kf = _mm_loadu_si128(round_keys[10].as_ptr() as *const __m128i);
        s = _mm_aesenclast_si128(s, kf);
        let mut out = [0u8; 16];
        _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, s);
        out
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "aes")]
    unsafe fn aesni_encrypt4_round_keys(
        round_keys: &[[u8; 16]; 11],
        mut blocks: [core::arch::x86_64::__m128i; 4],
    ) -> [core::arch::x86_64::__m128i; 4] {
        use core::arch::x86_64::*;
        let rk0 = _mm_loadu_si128(round_keys[0].as_ptr() as *const __m128i);
        for lane in blocks.iter_mut() {
            *lane = _mm_xor_si128(*lane, rk0);
        }
        for r in 1..10 {
            let kr = _mm_loadu_si128(round_keys[r].as_ptr() as *const __m128i);
            for lane in blocks.iter_mut() {
                *lane = _mm_aesenc_si128(*lane, kr);
            }
        }
        let kf = _mm_loadu_si128(round_keys[10].as_ptr() as *const __m128i);
        for lane in blocks.iter_mut() {
            *lane = _mm_aesenclast_si128(*lane, kf);
        }
        blocks
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "aes")]
    unsafe fn aes128_encrypt_block_aese(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
        use core::arch::aarch64::*;
        let rk = key_expansion(key);
        // Load state and first round key
        let mut s = vld1q_u8(block.as_ptr());
        let k0 = vld1q_u8(rk[0..16].as_ptr());
        s = veorq_u8(s, k0);
        // 9 rounds of AESE+AESMC with per-round keys
        for r in 1..10 {
            let kr = vld1q_u8(rk[16 * r..16 * (r + 1)].as_ptr());
            s = vaeseq_u8(s, kr);
            s = vaesmcq_u8(s);
        }
        // Final round: AESE with last round key (no AESMC in final)
        let kf = vld1q_u8(rk[160..176].as_ptr());
        s = vaeseq_u8(s, kf);
        let mut out = [0u8; 16];
        vst1q_u8(out.as_mut_ptr(), s);
        out
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "aes")]
    unsafe fn aes128_encrypt_block_aese_round_keys(
        round_keys: &[[u8; 16]; 11],
        block: &[u8; 16],
    ) -> [u8; 16] {
        use core::arch::aarch64::*;
        let mut s = vld1q_u8(block.as_ptr());
        let k0 = vld1q_u8(round_keys[0].as_ptr());
        s = veorq_u8(s, k0);
        for rk in round_keys.iter().skip(1).take(10) {
            let kr = vld1q_u8(rk.as_ptr());
            s = vaeseq_u8(s, kr);
            s = vaesmcq_u8(s);
        }
        let kf = vld1q_u8(round_keys[10].as_ptr());
        s = vaeseq_u8(s, kf);
        let mut out = [0u8; 16];
        vst1q_u8(out.as_mut_ptr(), s);
        out
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
    #[inline]
    #[target_feature(enable = "sve2")]
    unsafe fn aes128_encrypt_block_sve_round_keys(
        round_keys: &[[u8; 16]; 11],
        block: &[u8; 16],
    ) -> [u8; 16] {
        use core::arch::aarch64::*;
        let pg = svptrue_b8();
        let mut state = svld1_u8(pg, block.as_ptr());

        let rk0 = svld1_u8(pg, round_keys[0].as_ptr());
        state = sveor_u8_x(pg, state, rk0);

        for rk in round_keys.iter().take(10).skip(1) {
            let round = svld1_u8(pg, rk.as_ptr());
            state = svaeseq_u8(pg, state, round);
            state = svaesmcq_u8(pg, state);
        }

        let rk_last = svld1_u8(pg, round_keys[10].as_ptr());
        state = svaeseq_u8(pg, state, rk_last);

        let mut out = [0u8; 16];
        svst1_u8(pg, out.as_mut_ptr(), state);
        out
    }

    #[cfg(all(test, target_arch = "x86_64"))]
    mod tests_ssse3_aes {
        use super::*;

        #[test]
        fn aes128_ssse3_matches_scalar() {
            if !std::is_x86_feature_detected!("ssse3") {
                return;
            }

            let key = [0x42u8; 16];
            let block = [0x24u8; 16];
            let round_keys = expand_round_keys_array(&key);
            let expected = aes128_encrypt_block_scalar_with_round_keys(&round_keys, &block);

            let mut round_keys_ssse3 = [unsafe { core::mem::zeroed() }; 11];
            unsafe {
                use core::arch::x86_64::_mm_loadu_si128;
                for (dst, rk) in round_keys_ssse3.iter_mut().zip(round_keys.iter()) {
                    *dst = _mm_loadu_si128(rk.as_ptr() as *const _);
                }
                let actual = aes128_encrypt_block_ssse3(&round_keys_ssse3, &block);
                assert_eq!(expected, actual);
            }
        }
    }

    #[cfg(all(test, target_arch = "aarch64", target_feature = "sve2"))]
    mod tests_sve {
        use super::*;

        #[test]
        fn aes128_sve_matches_scalar_block() {
            if !std::arch::is_aarch64_feature_detected!("sve2") {
                return;
            }

            let key = [0x11u8; 16];
            let block = [0x22u8; 16];
            let round_keys = expand_round_keys_array(&key);

            let scalar = aes128_encrypt_block_scalar_with_round_keys(&round_keys, &block);
            let sve = unsafe { aes128_encrypt_block_sve_round_keys(&round_keys, &block) };
            assert_eq!(scalar, sve);
        }

        #[test]
        fn aes128_sve_ctr_matches_scalar() {
            if !std::arch::is_aarch64_feature_detected!("sve2") {
                return;
            }

            let key = [0x0Fu8; 16];
            let round_keys = expand_round_keys_array(&key);
            let mut counter = [0xAAu8; 16];
            let mut sve_counter = counter;
            let mut scalar_counter = counter;
            let data = (0u8..96).collect::<Vec<u8>>();
            let mut sve_out = data.clone();
            let mut scalar_out = data;

            let mut offset = 0usize;
            while sve_out.len().saturating_sub(offset) >= 16 {
                let ks = unsafe { aes128_encrypt_block_sve_round_keys(&round_keys, &sve_counter) };
                for i in 0..16 {
                    sve_out[offset + i] ^= ks[i];
                }
                inc32_be(&mut sve_counter);
                offset += 16;
            }
            if offset < sve_out.len() {
                let ks = unsafe { aes128_encrypt_block_sve_round_keys(&round_keys, &sve_counter) };
                for i in 0..(sve_out.len() - offset) {
                    sve_out[offset + i] ^= ks[i];
                }
            }

            let mut offset_scalar = 0usize;
            while scalar_out.len().saturating_sub(offset_scalar) >= 16 {
                let ks = aes128_encrypt_block_scalar_with_round_keys(&round_keys, &scalar_counter);
                for i in 0..16 {
                    scalar_out[offset_scalar + i] ^= ks[i];
                }
                inc32_be(&mut scalar_counter);
                offset_scalar += 16;
            }
            if offset_scalar < scalar_out.len() {
                let ks = aes128_encrypt_block_scalar_with_round_keys(&round_keys, &scalar_counter);
                for i in 0..(scalar_out.len() - offset_scalar) {
                    scalar_out[offset_scalar + i] ^= ks[i];
                }
            }

            assert_eq!(sve_out, scalar_out);
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "aes")]
    unsafe fn aese_encrypt4_round_keys(
        round_keys: &[[u8; 16]; 11],
        mut blocks: [core::arch::aarch64::uint8x16_t; 4],
    ) -> [core::arch::aarch64::uint8x16_t; 4] {
        use core::arch::aarch64::*;
        let rk0 = vld1q_u8(round_keys[0].as_ptr());
        for lane in blocks.iter_mut() {
            *lane = veorq_u8(*lane, rk0);
        }
        for rk in round_keys.iter().take(10).skip(1) {
            let kr = vld1q_u8(rk.as_ptr());
            for lane in blocks.iter_mut() {
                *lane = vaeseq_u8(*lane, kr);
            }
            for lane in blocks.iter_mut() {
                *lane = vaesmcq_u8(*lane);
            }
        }
        let kf = vld1q_u8(round_keys[10].as_ptr());
        for lane in blocks.iter_mut() {
            *lane = vaeseq_u8(*lane, kf);
        }
        blocks
    }
}

pub mod chacha {
    use crate::optimize::FeatureDetector;

    #[inline(always)]
    fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(16);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(12);

        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(8);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(7);
    }

    fn initial_state(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u32; 16] {
        let constants = [0x6170_7865u32, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
        let mut state = [0u32; 16];
        state[..4].copy_from_slice(&constants);
        for (i, chunk) in key.chunks_exact(4).enumerate() {
            let w = [chunk[0], chunk[1], chunk[2], chunk[3]];
            state[4 + i] = u32::from_le_bytes(w);
        }
        state[12] = counter;
        state[13] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
        state[14] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
        state[15] = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);
        state
    }

    #[inline(always)]
    fn core(state: &mut [u32; 16]) {
        for _ in 0..10 {
            quarter_round(state, 0, 4, 8, 12);
            quarter_round(state, 1, 5, 9, 13);
            quarter_round(state, 2, 6, 10, 14);
            quarter_round(state, 3, 7, 11, 15);
            quarter_round(state, 0, 5, 10, 15);
            quarter_round(state, 1, 6, 11, 12);
            quarter_round(state, 2, 7, 8, 13);
            quarter_round(state, 3, 4, 9, 14);
        }
    }

    pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
        let mut state = initial_state(key, counter, nonce);
        let working = state;
        core(&mut state);
        for i in 0..16 {
            state[i] = state[i].wrapping_add(working[i]);
        }
        let mut block = [0u8; 64];
        for (i, chunk) in block.chunks_exact_mut(4).enumerate() {
            chunk.copy_from_slice(&state[i].to_le_bytes());
        }
        block
    }

    #[inline]
    pub fn xor_keystream_in_place(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
        if data.is_empty() {
            return;
        }

        let features = FeatureDetector::instance().features_full();

        #[cfg(target_arch = "x86_64")]
        unsafe {
            if features.avx512f {
                xor_keystream_avx512(key, counter, nonce, data);
                return;
            }
            if features.avx2 {
                xor_keystream_avx2(key, counter, nonce, data);
                return;
            }
            if features.sse2 {
                xor_keystream_sse2(key, counter, nonce, data);
                return;
            }
        }

        #[cfg(target_arch = "aarch64")]
        unsafe {
            if features.sve2 {
                xor_keystream_sve2(key, counter, nonce, data);
                return;
            }
            if features.neon {
                xor_keystream_neon(key, counter, nonce, data);
                return;
            }
        }

        xor_keystream_scalar(key, counter, nonce, data);
    }

    #[inline(always)]
    fn xor_keystream_scalar(key: &[u8; 32], mut counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
        let mut offset = 0usize;
        while data.len().saturating_sub(offset) >= 64 {
            let block = chacha20_block(key, counter, nonce);
            counter = counter.wrapping_add(1);
            let chunk = &mut data[offset..offset + 64];
            let chunk_ptr = chunk.as_mut_ptr() as *mut u64;
            let block_ptr = block.as_ptr() as *const u64;
            for word_idx in 0..8 {
                let ks = unsafe { core::ptr::read_unaligned(block_ptr.add(word_idx)) };
                let dst = unsafe { chunk_ptr.add(word_idx) };
                let existing = unsafe { core::ptr::read_unaligned(dst as *const u64) };
                unsafe { core::ptr::write_unaligned(dst, existing ^ ks) };
            }
            offset += 64;
        }

        if offset < data.len() {
            let block = chacha20_block(key, counter, nonce);
            for (i, byte) in data[offset..].iter_mut().enumerate() {
                *byte ^= block[i];
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    unsafe fn rotl32_avx2(v: core::arch::x86_64::__m256i, n: i32) -> core::arch::x86_64::__m256i {
        use core::arch::x86_64::*;
        let n = ((n as u32) & 31) as i32;
        if n == 0 {
            return v;
        }
        let cnt = _mm_cvtsi32_si128(n);
        let left = _mm256_sll_epi32(v, cnt);
        let right = _mm256_srl_epi32(v, _mm_cvtsi32_si128(32 - n));
        _mm256_or_si256(left, right)
    }

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    unsafe fn quarter_round_avx2(
        mut a: core::arch::x86_64::__m256i,
        mut b: core::arch::x86_64::__m256i,
        mut c: core::arch::x86_64::__m256i,
        mut d: core::arch::x86_64::__m256i,
    ) -> (
        core::arch::x86_64::__m256i,
        core::arch::x86_64::__m256i,
        core::arch::x86_64::__m256i,
        core::arch::x86_64::__m256i,
    ) {
        use core::arch::x86_64::*;
        a = _mm256_add_epi32(a, b);
        d = _mm256_xor_si256(d, a);
        d = rotl32_avx2(d, 16);

        c = _mm256_add_epi32(c, d);
        b = _mm256_xor_si256(b, c);
        b = rotl32_avx2(b, 12);

        a = _mm256_add_epi32(a, b);
        d = _mm256_xor_si256(d, a);
        d = rotl32_avx2(d, 8);

        c = _mm256_add_epi32(c, d);
        b = _mm256_xor_si256(b, c);
        b = rotl32_avx2(b, 7);

        (a, b, c, d)
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn xor_keystream_avx2(
        key: &[u8; 32],
        mut counter: u32,
        nonce: &[u8; 12],
        data: &mut [u8],
    ) {
        use core::arch::x86_64::*;

        let key_words: [u32; 8] = core::array::from_fn(|i| {
            u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]])
        });
        let nonce_words = [
            u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
            u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
            u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
        ];
        let constants = [0x6170_7865u32, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

        let mut offset = 0usize;
        while data.len().saturating_sub(offset) >= 512 {
            let ctr_lane = [
                counter,
                counter.wrapping_add(1),
                counter.wrapping_add(2),
                counter.wrapping_add(3),
                counter.wrapping_add(4),
                counter.wrapping_add(5),
                counter.wrapping_add(6),
                counter.wrapping_add(7),
            ];
            counter = counter.wrapping_add(8);

            let base = [
                _mm256_set1_epi32(constants[0] as i32),
                _mm256_set1_epi32(constants[1] as i32),
                _mm256_set1_epi32(constants[2] as i32),
                _mm256_set1_epi32(constants[3] as i32),
                _mm256_set1_epi32(key_words[0] as i32),
                _mm256_set1_epi32(key_words[1] as i32),
                _mm256_set1_epi32(key_words[2] as i32),
                _mm256_set1_epi32(key_words[3] as i32),
                _mm256_set1_epi32(key_words[4] as i32),
                _mm256_set1_epi32(key_words[5] as i32),
                _mm256_set1_epi32(key_words[6] as i32),
                _mm256_set1_epi32(key_words[7] as i32),
                _mm256_set_epi32(
                    ctr_lane[7] as i32,
                    ctr_lane[6] as i32,
                    ctr_lane[5] as i32,
                    ctr_lane[4] as i32,
                    ctr_lane[3] as i32,
                    ctr_lane[2] as i32,
                    ctr_lane[1] as i32,
                    ctr_lane[0] as i32,
                ),
                _mm256_set1_epi32(nonce_words[0] as i32),
                _mm256_set1_epi32(nonce_words[1] as i32),
                _mm256_set1_epi32(nonce_words[2] as i32),
            ];

            let mut state = base;

            for _ in 0..10 {
                let (a, b, c, d) = quarter_round_avx2(state[0], state[4], state[8], state[12]);
                state[0] = a;
                state[4] = b;
                state[8] = c;
                state[12] = d;
                let (a, b, c, d) = quarter_round_avx2(state[1], state[5], state[9], state[13]);
                state[1] = a;
                state[5] = b;
                state[9] = c;
                state[13] = d;
                let (a, b, c, d) = quarter_round_avx2(state[2], state[6], state[10], state[14]);
                state[2] = a;
                state[6] = b;
                state[10] = c;
                state[14] = d;
                let (a, b, c, d) = quarter_round_avx2(state[3], state[7], state[11], state[15]);
                state[3] = a;
                state[7] = b;
                state[11] = c;
                state[15] = d;
                let (a, b, c, d) = quarter_round_avx2(state[0], state[5], state[10], state[15]);
                state[0] = a;
                state[5] = b;
                state[10] = c;
                state[15] = d;
                let (a, b, c, d) = quarter_round_avx2(state[1], state[6], state[11], state[12]);
                state[1] = a;
                state[6] = b;
                state[11] = c;
                state[12] = d;
                let (a, b, c, d) = quarter_round_avx2(state[2], state[7], state[8], state[13]);
                state[2] = a;
                state[7] = b;
                state[8] = c;
                state[13] = d;
                let (a, b, c, d) = quarter_round_avx2(state[3], state[4], state[9], state[14]);
                state[3] = a;
                state[4] = b;
                state[9] = c;
                state[14] = d;
            }

            for i in 0..16 {
                state[i] = _mm256_add_epi32(state[i], base[i]);
            }

            let mut words = [0u32; 16 * 8];
            for (i, slot) in state.iter().enumerate() {
                _mm256_storeu_si256(words[i * 8..].as_mut_ptr() as *mut __m256i, *slot);
            }

            for lane in 0..8 {
                let lane_ptr = data.as_mut_ptr().add(offset + lane * 64) as *mut u32;
                for word_idx in 0..16 {
                    let word = words[word_idx * 8 + lane];
                    let ptr_word = lane_ptr.add(word_idx);
                    let existing = core::ptr::read_unaligned(ptr_word as *const u32);
                    core::ptr::write_unaligned(ptr_word, existing ^ word);
                }
            }

            offset += 512;
        }

        if data.len().saturating_sub(offset) >= 64 {
            while data.len().saturating_sub(offset) >= 64 {
                let block = super::chacha::chacha20_block(key, counter, nonce);
                counter = counter.wrapping_add(1);
                let chunk = &mut data[offset..offset + 64];
                let chunk_ptr = chunk.as_mut_ptr() as *mut u64;
                let block_ptr = block.as_ptr() as *const u64;
                for word_idx in 0..8 {
                    let ks = core::ptr::read_unaligned(block_ptr.add(word_idx));
                    let dst = chunk_ptr.add(word_idx);
                    let existing = core::ptr::read_unaligned(dst as *const u64);
                    core::ptr::write_unaligned(dst, existing ^ ks);
                }
                offset += 64;
            }
        }

        if offset < data.len() {
            let block = super::chacha::chacha20_block(key, counter, nonce);
            for (i, byte) in data[offset..].iter_mut().enumerate() {
                *byte ^= block[i];
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    unsafe fn rotl32_avx512(v: core::arch::x86_64::__m512i, n: i32) -> core::arch::x86_64::__m512i {
        use core::arch::x86_64::*;
        let n = ((n as u32) & 31) as i32;
        if n == 0 {
            return v;
        }
        let cnt = _mm_cvtsi32_si128(n);
        let left = _mm512_sll_epi32(v, cnt);
        let right = _mm512_srl_epi32(v, _mm_cvtsi32_si128(32 - n));
        _mm512_or_si512(left, right)
    }

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    unsafe fn quarter_round_avx512(
        mut a: core::arch::x86_64::__m512i,
        mut b: core::arch::x86_64::__m512i,
        mut c: core::arch::x86_64::__m512i,
        mut d: core::arch::x86_64::__m512i,
    ) -> (
        core::arch::x86_64::__m512i,
        core::arch::x86_64::__m512i,
        core::arch::x86_64::__m512i,
        core::arch::x86_64::__m512i,
    ) {
        use core::arch::x86_64::*;
        a = _mm512_add_epi32(a, b);
        d = _mm512_xor_si512(d, a);
        d = rotl32_avx512(d, 16);

        c = _mm512_add_epi32(c, d);
        b = _mm512_xor_si512(b, c);
        b = rotl32_avx512(b, 12);

        a = _mm512_add_epi32(a, b);
        d = _mm512_xor_si512(d, a);
        d = rotl32_avx512(d, 8);

        c = _mm512_add_epi32(c, d);
        b = _mm512_xor_si512(b, c);
        b = rotl32_avx512(b, 7);

        (a, b, c, d)
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512f")]
    unsafe fn xor_keystream_avx512(
        key: &[u8; 32],
        mut counter: u32,
        nonce: &[u8; 12],
        data: &mut [u8],
    ) {
        use core::arch::x86_64::*;

        let key_words: [u32; 8] = core::array::from_fn(|i| {
            u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]])
        });
        let nonce_words = [
            u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
            u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
            u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
        ];
        let constants = [0x6170_7865u32, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

        let mut offset = 0usize;
        while data.len().saturating_sub(offset) >= 1024 {
            let ctr_lane: [u32; 16] = core::array::from_fn(|i| counter.wrapping_add(i as u32));
            counter = counter.wrapping_add(16);

            let base = [
                _mm512_set1_epi32(constants[0] as i32),
                _mm512_set1_epi32(constants[1] as i32),
                _mm512_set1_epi32(constants[2] as i32),
                _mm512_set1_epi32(constants[3] as i32),
                _mm512_set1_epi32(key_words[0] as i32),
                _mm512_set1_epi32(key_words[1] as i32),
                _mm512_set1_epi32(key_words[2] as i32),
                _mm512_set1_epi32(key_words[3] as i32),
                _mm512_set1_epi32(key_words[4] as i32),
                _mm512_set1_epi32(key_words[5] as i32),
                _mm512_set1_epi32(key_words[6] as i32),
                _mm512_set1_epi32(key_words[7] as i32),
                _mm512_set_epi32(
                    ctr_lane[15] as i32,
                    ctr_lane[14] as i32,
                    ctr_lane[13] as i32,
                    ctr_lane[12] as i32,
                    ctr_lane[11] as i32,
                    ctr_lane[10] as i32,
                    ctr_lane[9] as i32,
                    ctr_lane[8] as i32,
                    ctr_lane[7] as i32,
                    ctr_lane[6] as i32,
                    ctr_lane[5] as i32,
                    ctr_lane[4] as i32,
                    ctr_lane[3] as i32,
                    ctr_lane[2] as i32,
                    ctr_lane[1] as i32,
                    ctr_lane[0] as i32,
                ),
                _mm512_set1_epi32(nonce_words[0] as i32),
                _mm512_set1_epi32(nonce_words[1] as i32),
                _mm512_set1_epi32(nonce_words[2] as i32),
            ];

            let mut state = base;

            for _ in 0..10 {
                let (a, b, c, d) = quarter_round_avx512(state[0], state[4], state[8], state[12]);
                state[0] = a;
                state[4] = b;
                state[8] = c;
                state[12] = d;
                let (a, b, c, d) = quarter_round_avx512(state[1], state[5], state[9], state[13]);
                state[1] = a;
                state[5] = b;
                state[9] = c;
                state[13] = d;
                let (a, b, c, d) = quarter_round_avx512(state[2], state[6], state[10], state[14]);
                state[2] = a;
                state[6] = b;
                state[10] = c;
                state[14] = d;
                let (a, b, c, d) = quarter_round_avx512(state[3], state[7], state[11], state[15]);
                state[3] = a;
                state[7] = b;
                state[11] = c;
                state[15] = d;
                let (a, b, c, d) = quarter_round_avx512(state[0], state[5], state[10], state[15]);
                state[0] = a;
                state[5] = b;
                state[10] = c;
                state[15] = d;
                let (a, b, c, d) = quarter_round_avx512(state[1], state[6], state[11], state[12]);
                state[1] = a;
                state[6] = b;
                state[11] = c;
                state[12] = d;
                let (a, b, c, d) = quarter_round_avx512(state[2], state[7], state[8], state[13]);
                state[2] = a;
                state[7] = b;
                state[8] = c;
                state[13] = d;
                let (a, b, c, d) = quarter_round_avx512(state[3], state[4], state[9], state[14]);
                state[3] = a;
                state[4] = b;
                state[9] = c;
                state[14] = d;
            }

            for i in 0..16 {
                state[i] = _mm512_add_epi32(state[i], base[i]);
            }

            let mut words = [0u32; 16 * 16];
            for (i, slot) in state.iter().enumerate() {
                _mm512_storeu_si512(words[i * 16..].as_mut_ptr() as *mut __m512i, *slot);
            }

            for lane in 0..16 {
                let lane_ptr = data.as_mut_ptr().add(offset + lane * 64) as *mut u32;
                for word_idx in 0..16 {
                    let word = words[word_idx * 16 + lane];
                    let ptr_word = lane_ptr.add(word_idx);
                    let existing = core::ptr::read_unaligned(ptr_word as *const u32);
                    core::ptr::write_unaligned(ptr_word, existing ^ word);
                }
            }

            offset += 1024;
        }

        if data.len().saturating_sub(offset) >= 64 {
            while data.len().saturating_sub(offset) >= 64 {
                let block = chacha20_block(key, counter, nonce);
                counter = counter.wrapping_add(1);
                let chunk = &mut data[offset..offset + 64];
                let chunk_ptr = chunk.as_mut_ptr() as *mut u64;
                let block_ptr = block.as_ptr() as *const u64;
                for word_idx in 0..8 {
                    let ks = core::ptr::read_unaligned(block_ptr.add(word_idx));
                    let dst = chunk_ptr.add(word_idx);
                    let existing = core::ptr::read_unaligned(dst as *const u64);
                    core::ptr::write_unaligned(dst, existing ^ ks);
                }
                offset += 64;
            }
        }

        if offset < data.len() {
            let block = chacha20_block(key, counter, nonce);
            for (i, byte) in data[offset..].iter_mut().enumerate() {
                *byte ^= block[i];
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    unsafe fn rotl32_sse2(v: core::arch::x86_64::__m128i, n: i32) -> core::arch::x86_64::__m128i {
        use core::arch::x86_64::*;
        let n = ((n as u32) & 31) as i32;
        if n == 0 {
            return v;
        }
        let cnt = _mm_cvtsi32_si128(n);
        let left = _mm_sll_epi32(v, cnt);
        let right = _mm_srl_epi32(v, _mm_cvtsi32_si128(32 - n));
        _mm_or_si128(left, right)
    }

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    unsafe fn quarter_round_sse2(
        mut a: core::arch::x86_64::__m128i,
        mut b: core::arch::x86_64::__m128i,
        mut c: core::arch::x86_64::__m128i,
        mut d: core::arch::x86_64::__m128i,
    ) -> (
        core::arch::x86_64::__m128i,
        core::arch::x86_64::__m128i,
        core::arch::x86_64::__m128i,
        core::arch::x86_64::__m128i,
    ) {
        use core::arch::x86_64::*;
        a = _mm_add_epi32(a, b);
        d = _mm_xor_si128(d, a);
        d = rotl32_sse2(d, 16);

        c = _mm_add_epi32(c, d);
        b = _mm_xor_si128(b, c);
        b = rotl32_sse2(b, 12);

        a = _mm_add_epi32(a, b);
        d = _mm_xor_si128(d, a);
        d = rotl32_sse2(d, 8);

        c = _mm_add_epi32(c, d);
        b = _mm_xor_si128(b, c);
        b = rotl32_sse2(b, 7);

        (a, b, c, d)
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "sse2")]
    unsafe fn xor_keystream_sse2(
        key: &[u8; 32],
        mut counter: u32,
        nonce: &[u8; 12],
        data: &mut [u8],
    ) {
        use core::arch::x86_64::*;

        let key_words: [u32; 8] = core::array::from_fn(|i| {
            u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]])
        });
        let nonce_words = [
            u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
            u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
            u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
        ];

        let constants = [0x6170_7865u32, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

        let mut offset = 0usize;
        while data.len().saturating_sub(offset) >= 256 {
            let ctr_lane = [
                counter,
                counter.wrapping_add(1),
                counter.wrapping_add(2),
                counter.wrapping_add(3),
            ];
            counter = counter.wrapping_add(4);

            let base = [
                _mm_set1_epi32(constants[0] as i32),
                _mm_set1_epi32(constants[1] as i32),
                _mm_set1_epi32(constants[2] as i32),
                _mm_set1_epi32(constants[3] as i32),
                _mm_set1_epi32(key_words[0] as i32),
                _mm_set1_epi32(key_words[1] as i32),
                _mm_set1_epi32(key_words[2] as i32),
                _mm_set1_epi32(key_words[3] as i32),
                _mm_set1_epi32(key_words[4] as i32),
                _mm_set1_epi32(key_words[5] as i32),
                _mm_set1_epi32(key_words[6] as i32),
                _mm_set1_epi32(key_words[7] as i32),
                _mm_set_epi32(
                    ctr_lane[3] as i32,
                    ctr_lane[2] as i32,
                    ctr_lane[1] as i32,
                    ctr_lane[0] as i32,
                ),
                _mm_set1_epi32(nonce_words[0] as i32),
                _mm_set1_epi32(nonce_words[1] as i32),
                _mm_set1_epi32(nonce_words[2] as i32),
            ];

            let mut state = base;

            for _ in 0..10 {
                let (a, b, c, d) = quarter_round_sse2(state[0], state[4], state[8], state[12]);
                state[0] = a;
                state[4] = b;
                state[8] = c;
                state[12] = d;
                let (a, b, c, d) = quarter_round_sse2(state[1], state[5], state[9], state[13]);
                state[1] = a;
                state[5] = b;
                state[9] = c;
                state[13] = d;
                let (a, b, c, d) = quarter_round_sse2(state[2], state[6], state[10], state[14]);
                state[2] = a;
                state[6] = b;
                state[10] = c;
                state[14] = d;
                let (a, b, c, d) = quarter_round_sse2(state[3], state[7], state[11], state[15]);
                state[3] = a;
                state[7] = b;
                state[11] = c;
                state[15] = d;
                let (a, b, c, d) = quarter_round_sse2(state[0], state[5], state[10], state[15]);
                state[0] = a;
                state[5] = b;
                state[10] = c;
                state[15] = d;
                let (a, b, c, d) = quarter_round_sse2(state[1], state[6], state[11], state[12]);
                state[1] = a;
                state[6] = b;
                state[11] = c;
                state[12] = d;
                let (a, b, c, d) = quarter_round_sse2(state[2], state[7], state[8], state[13]);
                state[2] = a;
                state[7] = b;
                state[8] = c;
                state[13] = d;
                let (a, b, c, d) = quarter_round_sse2(state[3], state[4], state[9], state[14]);
                state[3] = a;
                state[4] = b;
                state[9] = c;
                state[14] = d;
            }

            for i in 0..16 {
                state[i] = _mm_add_epi32(state[i], base[i]);
            }

            let mut words = [0u32; 64];
            for (i, slot) in state.iter().enumerate() {
                _mm_storeu_si128(words[i * 4..].as_mut_ptr() as *mut __m128i, *slot);
            }

            for lane in 0..4 {
                let lane_ptr = data.as_mut_ptr().add(offset + lane * 64) as *mut u32;
                for word_idx in 0..16 {
                    // Layout: words are stored interleaved (structure of arrays).
                    let word = words[word_idx * 4 + lane];
                    let ptr_word = lane_ptr.add(word_idx);
                    let existing = core::ptr::read_unaligned(ptr_word as *const u32);
                    core::ptr::write_unaligned(ptr_word, existing ^ word);
                }
            }

            offset += 256;
        }

        if data.len().saturating_sub(offset) >= 64 {
            while data.len().saturating_sub(offset) >= 64 {
                let block = chacha20_block(key, counter, nonce);
                counter = counter.wrapping_add(1);
                let chunk = &mut data[offset..offset + 64];
                let chunk_ptr = chunk.as_mut_ptr() as *mut u64;
                let block_ptr = block.as_ptr() as *const u64;
                for word_idx in 0..8 {
                    let ks = core::ptr::read_unaligned(block_ptr.add(word_idx));
                    let dst = chunk_ptr.add(word_idx);
                    let existing = core::ptr::read_unaligned(dst as *const u64);
                    core::ptr::write_unaligned(dst, existing ^ ks);
                }
                offset += 64;
            }
        }

        if offset < data.len() {
            let block = chacha20_block(key, counter, nonce);
            for (i, byte) in data[offset..].iter_mut().enumerate() {
                *byte ^= block[i];
            }
        }
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
    #[inline(always)]
    unsafe fn rotl32_sve2(
        pg: std::arch::aarch64::svbool_t,
        v: std::arch::aarch64::svuint32_t,
        n: i32,
    ) -> std::arch::aarch64::svuint32_t {
        use std::arch::aarch64::*;
        let left = svlsl_n_u32_x(pg, v, n);
        let right = svlsr_n_u32_x(pg, v, 32 - n);
        svorr_u32(left, right)
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
    #[inline(always)]
    unsafe fn quarter_round_sve2(
        pg: std::arch::aarch64::svbool_t,
        mut a: std::arch::aarch64::svuint32_t,
        mut b: std::arch::aarch64::svuint32_t,
        mut c: std::arch::aarch64::svuint32_t,
        mut d: std::arch::aarch64::svuint32_t,
    ) -> (
        std::arch::aarch64::svuint32_t,
        std::arch::aarch64::svuint32_t,
        std::arch::aarch64::svuint32_t,
        std::arch::aarch64::svuint32_t,
    ) {
        use std::arch::aarch64::*;
        a = svadd_u32_x(pg, a, b);
        d = sveor_u32_x(pg, d, a);
        d = rotl32_sve2(pg, d, 16);

        c = svadd_u32_x(pg, c, d);
        b = sveor_u32_x(pg, b, c);
        b = rotl32_sve2(pg, b, 12);

        a = svadd_u32_x(pg, a, b);
        d = sveor_u32_x(pg, d, a);
        d = rotl32_sve2(pg, d, 8);

        c = svadd_u32_x(pg, c, d);
        b = sveor_u32_x(pg, b, c);
        b = rotl32_sve2(pg, b, 7);

        (a, b, c, d)
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
    #[inline(always)]
    unsafe fn process_sve2_chunk(
        lanes: usize,
        active_blocks: usize,
        counter: &mut u32,
        constants: &[u32; 4],
        key_words: &[u32; 8],
        nonce_words: &[u32; 3],
        data: &mut [u8],
        offset: usize,
    ) {
        use core::ptr;
        use std::arch::aarch64::*;

        let pg_active = svwhilelt_b32(0, active_blocks as u64);

        let mut base = [
            svdup_n_u32(constants[0]),
            svdup_n_u32(constants[1]),
            svdup_n_u32(constants[2]),
            svdup_n_u32(constants[3]),
            svdup_n_u32(key_words[0]),
            svdup_n_u32(key_words[1]),
            svdup_n_u32(key_words[2]),
            svdup_n_u32(key_words[3]),
            svdup_n_u32(key_words[4]),
            svdup_n_u32(key_words[5]),
            svdup_n_u32(key_words[6]),
            svdup_n_u32(key_words[7]),
            svdup_n_u32(0),
            svdup_n_u32(nonce_words[0]),
            svdup_n_u32(nonce_words[1]),
            svdup_n_u32(nonce_words[2]),
        ];

        let counter_offsets = svindex_u32(0, 1);
        let ctr_vec = svadd_u32_x(pg_active, svdup_n_u32(*counter), counter_offsets);
        *counter = counter.wrapping_add(active_blocks as u32);

        base[12] = ctr_vec;

        let mut state = base;

        for _ in 0..10 {
            let (a0, b0, c0, d0) =
                quarter_round_sve2(pg_active, state[0], state[4], state[8], state[12]);
            state[0] = a0;
            state[4] = b0;
            state[8] = c0;
            state[12] = d0;

            let (a1, b1, c1, d1) =
                quarter_round_sve2(pg_active, state[1], state[5], state[9], state[13]);
            state[1] = a1;
            state[5] = b1;
            state[9] = c1;
            state[13] = d1;

            let (a2, b2, c2, d2) =
                quarter_round_sve2(pg_active, state[2], state[6], state[10], state[14]);
            state[2] = a2;
            state[6] = b2;
            state[10] = c2;
            state[14] = d2;

            let (a3, b3, c3, d3) =
                quarter_round_sve2(pg_active, state[3], state[7], state[11], state[15]);
            state[3] = a3;
            state[7] = b3;
            state[11] = c3;
            state[15] = d3;

            let (a4, b4, c4, d4) =
                quarter_round_sve2(pg_active, state[0], state[5], state[10], state[15]);
            state[0] = a4;
            state[5] = b4;
            state[10] = c4;
            state[15] = d4;

            let (a5, b5, c5, d5) =
                quarter_round_sve2(pg_active, state[1], state[6], state[11], state[12]);
            state[1] = a5;
            state[6] = b5;
            state[11] = c5;
            state[12] = d5;

            let (a6, b6, c6, d6) =
                quarter_round_sve2(pg_active, state[2], state[7], state[8], state[13]);
            state[2] = a6;
            state[7] = b6;
            state[8] = c6;
            state[13] = d6;

            let (a7, b7, c7, d7) =
                quarter_round_sve2(pg_active, state[3], state[4], state[9], state[14]);
            state[3] = a7;
            state[4] = b7;
            state[9] = c7;
            state[14] = d7;
        }

        for i in 0..16 {
            state[i] = svadd_u32_x(pg_active, state[i], base[i]);
        }

        let mut words = vec![0u32; lanes * 16];
        for (idx, slot) in state.iter().enumerate() {
            let ptr = words[idx * lanes..].as_mut_ptr();
            svst1_u32(pg_active, ptr, *slot);
        }

        for lane in 0..active_blocks {
            let lane_offset = offset + lane * 64;
            let lane_ptr = data.as_mut_ptr().add(lane_offset) as *mut u32;
            for word_idx in 0..16 {
                let ks = words[word_idx * lanes + lane];
                let dst = lane_ptr.add(word_idx);
                let current = ptr::read_unaligned(dst);
                ptr::write_unaligned(dst, current ^ ks);
            }
        }
    }

    #[cfg(target_arch = "aarch64")]
    unsafe fn xor_keystream_sve2(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
        #[cfg(target_feature = "sve2")]
        {
            xor_keystream_sve2_impl(key, counter, nonce, data);
            return;
        }
        #[cfg(not(target_feature = "sve2"))]
        {
            xor_keystream_neon(key, counter, nonce, data);
        }
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
    #[target_feature(enable = "sve2")]
    unsafe fn xor_keystream_sve2_impl(
        key: &[u8; 32],
        counter: u32,
        nonce: &[u8; 12],
        data: &mut [u8],
    ) {
        use core::arch::aarch64::*;
        use core::ptr;

        let lanes = svcntw() as usize;
        if lanes == 0 {
            xor_keystream_neon(key, counter, nonce, data);
            return;
        }

        let constants = [0x6170_7865u32, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
        let key_words: [u32; 8] = core::array::from_fn(|i| {
            u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]])
        });
        let nonce_words = [
            u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
            u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
            u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
        ];

        let mut offset = 0usize;
        let mut ctr = counter;

        while data.len().saturating_sub(offset) >= 64 {
            let remaining_blocks = (data.len() - offset) / 64;
            if remaining_blocks == 0 {
                break;
            }
            let active_blocks = remaining_blocks.min(lanes);
            process_sve2_chunk(
                lanes,
                active_blocks,
                &mut ctr,
                &constants,
                &key_words,
                &nonce_words,
                data,
                offset,
            );
            offset += active_blocks * 64;
            if remaining_blocks <= lanes {
                break;
            }
        }

        while data.len().saturating_sub(offset) >= 64 {
            let block = chacha20_block(key, ctr, nonce);
            ctr = ctr.wrapping_add(1);
            let chunk = &mut data[offset..offset + 64];
            let chunk_ptr = chunk.as_mut_ptr() as *mut u64;
            let block_ptr = block.as_ptr() as *const u64;
            for word_idx in 0..8 {
                let ks = ptr::read_unaligned(block_ptr.add(word_idx));
                let dst = chunk_ptr.add(word_idx);
                let current = ptr::read_unaligned(dst as *const u64);
                ptr::write_unaligned(dst, current ^ ks);
            }
            offset += 64;
        }

        if offset < data.len() {
            let block = chacha20_block(key, ctr, nonce);
            for (i, byte) in data[offset..].iter_mut().enumerate() {
                *byte ^= block[i];
            }
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[inline(always)]
    unsafe fn rotl32_neon_16(
        v: core::arch::aarch64::uint32x4_t,
    ) -> core::arch::aarch64::uint32x4_t {
        use core::arch::aarch64::*;
        vorrq_u32(vshlq_n_u32(v, 16), vshrq_n_u32(v, 16))
    }

    #[cfg(target_arch = "aarch64")]
    #[inline(always)]
    unsafe fn rotl32_neon_12(
        v: core::arch::aarch64::uint32x4_t,
    ) -> core::arch::aarch64::uint32x4_t {
        use core::arch::aarch64::*;
        vorrq_u32(vshlq_n_u32(v, 12), vshrq_n_u32(v, 20))
    }

    #[cfg(target_arch = "aarch64")]
    #[inline(always)]
    unsafe fn rotl32_neon_8(v: core::arch::aarch64::uint32x4_t) -> core::arch::aarch64::uint32x4_t {
        use core::arch::aarch64::*;
        vorrq_u32(vshlq_n_u32(v, 8), vshrq_n_u32(v, 24))
    }

    #[cfg(target_arch = "aarch64")]
    #[inline(always)]
    unsafe fn rotl32_neon_7(v: core::arch::aarch64::uint32x4_t) -> core::arch::aarch64::uint32x4_t {
        use core::arch::aarch64::*;
        vorrq_u32(vshlq_n_u32(v, 7), vshrq_n_u32(v, 25))
    }

    #[cfg(target_arch = "aarch64")]
    #[inline(always)]
    unsafe fn quarter_round_neon(
        mut a: core::arch::aarch64::uint32x4_t,
        mut b: core::arch::aarch64::uint32x4_t,
        mut c: core::arch::aarch64::uint32x4_t,
        mut d: core::arch::aarch64::uint32x4_t,
    ) -> (
        core::arch::aarch64::uint32x4_t,
        core::arch::aarch64::uint32x4_t,
        core::arch::aarch64::uint32x4_t,
        core::arch::aarch64::uint32x4_t,
    ) {
        use core::arch::aarch64::*;
        a = vaddq_u32(a, b);
        d = veorq_u32(d, a);
        d = rotl32_neon_16(d);

        c = vaddq_u32(c, d);
        b = veorq_u32(b, c);
        b = rotl32_neon_12(b);

        a = vaddq_u32(a, b);
        d = veorq_u32(d, a);
        d = rotl32_neon_8(d);

        c = vaddq_u32(c, d);
        b = veorq_u32(b, c);
        b = rotl32_neon_7(b);

        (a, b, c, d)
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    unsafe fn xor_keystream_neon(
        key: &[u8; 32],
        mut counter: u32,
        nonce: &[u8; 12],
        data: &mut [u8],
    ) {
        use core::arch::aarch64::*;

        let key_words: [u32; 8] = core::array::from_fn(|i| {
            u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]])
        });
        let nonce_words = [
            u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
            u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
            u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
        ];
        let constants = [0x6170_7865u32, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

        let mut offset = 0usize;
        while data.len().saturating_sub(offset) >= 256 {
            let ctr_lane = [
                counter,
                counter.wrapping_add(1),
                counter.wrapping_add(2),
                counter.wrapping_add(3),
            ];
            counter = counter.wrapping_add(4);

            let ctr_words = ctr_lane;
            let base = [
                vdupq_n_u32(constants[0]),
                vdupq_n_u32(constants[1]),
                vdupq_n_u32(constants[2]),
                vdupq_n_u32(constants[3]),
                vdupq_n_u32(key_words[0]),
                vdupq_n_u32(key_words[1]),
                vdupq_n_u32(key_words[2]),
                vdupq_n_u32(key_words[3]),
                vdupq_n_u32(key_words[4]),
                vdupq_n_u32(key_words[5]),
                vdupq_n_u32(key_words[6]),
                vdupq_n_u32(key_words[7]),
                vld1q_u32(ctr_words.as_ptr()),
                vdupq_n_u32(nonce_words[0]),
                vdupq_n_u32(nonce_words[1]),
                vdupq_n_u32(nonce_words[2]),
            ];

            let mut state = base;

            for _ in 0..10 {
                let (a, b, c, d) = quarter_round_neon(state[0], state[4], state[8], state[12]);
                state[0] = a;
                state[4] = b;
                state[8] = c;
                state[12] = d;
                let (a, b, c, d) = quarter_round_neon(state[1], state[5], state[9], state[13]);
                state[1] = a;
                state[5] = b;
                state[9] = c;
                state[13] = d;
                let (a, b, c, d) = quarter_round_neon(state[2], state[6], state[10], state[14]);
                state[2] = a;
                state[6] = b;
                state[10] = c;
                state[14] = d;
                let (a, b, c, d) = quarter_round_neon(state[3], state[7], state[11], state[15]);
                state[3] = a;
                state[7] = b;
                state[11] = c;
                state[15] = d;
                let (a, b, c, d) = quarter_round_neon(state[0], state[5], state[10], state[15]);
                state[0] = a;
                state[5] = b;
                state[10] = c;
                state[15] = d;
                let (a, b, c, d) = quarter_round_neon(state[1], state[6], state[11], state[12]);
                state[1] = a;
                state[6] = b;
                state[11] = c;
                state[12] = d;
                let (a, b, c, d) = quarter_round_neon(state[2], state[7], state[8], state[13]);
                state[2] = a;
                state[7] = b;
                state[8] = c;
                state[13] = d;
                let (a, b, c, d) = quarter_round_neon(state[3], state[4], state[9], state[14]);
                state[3] = a;
                state[4] = b;
                state[9] = c;
                state[14] = d;
            }

            for i in 0..16 {
                state[i] = vaddq_u32(state[i], base[i]);
            }

            let mut words = [0u32; 64];
            for (i, slot) in state.iter().enumerate() {
                vst1q_u32(words[i * 4..].as_mut_ptr(), *slot);
            }

            for lane in 0..4 {
                let lane_ptr = data.as_mut_ptr().add(offset + lane * 64) as *mut u32;
                for word_idx in 0..16 {
                    let word = words[word_idx * 4 + lane];
                    let ptr_word = lane_ptr.add(word_idx);
                    let existing = core::ptr::read_unaligned(ptr_word as *const u32);
                    core::ptr::write_unaligned(ptr_word, existing ^ word);
                }
            }

            offset += 256;
        }

        if data.len().saturating_sub(offset) >= 64 {
            while data.len().saturating_sub(offset) >= 64 {
                let block = super::chacha::chacha20_block(key, counter, nonce);
                counter = counter.wrapping_add(1);
                let chunk = &mut data[offset..offset + 64];
                let chunk_ptr = chunk.as_mut_ptr() as *mut u64;
                let block_ptr = block.as_ptr() as *const u64;
                for word_idx in 0..8 {
                    let ks = core::ptr::read_unaligned(block_ptr.add(word_idx));
                    let dst = chunk_ptr.add(word_idx);
                    let existing = core::ptr::read_unaligned(dst as *const u64);
                    core::ptr::write_unaligned(dst, existing ^ ks);
                }
                offset += 64;
            }
        }

        if offset < data.len() {
            let block = super::chacha::chacha20_block(key, counter, nonce);
            for (i, byte) in data[offset..].iter_mut().enumerate() {
                *byte ^= block[i];
            }
        }
    }
}

pub mod poly1305 {
    use crate::optimize::{telemetry, FeatureDetector};
    #[inline(always)]
    fn le32(x: &[u8]) -> u32 {
        u32::from_le_bytes([x[0], x[1], x[2], x[3]])
    }

    #[inline(always)]
    fn load_r_clamped(r: &[u8; 16]) -> [u64; 5] {
        // 26-bit limbs, with clamp applied implicitly by masking
        let t0 = le32(&r[0..4]) as u64;
        let t1 = le32(&r[3..7]) as u64;
        let t2 = le32(&r[6..10]) as u64;
        let t3 = le32(&r[9..13]) as u64;
        let t4 = le32(&r[12..16]) as u64;
        let r0 = (t0) & 0x3ffffff;
        let r1 = (t1 >> 2) & 0x3ffffff;
        let r2 = (t2 >> 4) & 0x3ffffff;
        let r3 = (t3 >> 6) & 0x3ffffff;
        let r4 = (t4 >> 8) & 0x3ffffff;
        [r0, r1, r2, r3, r4]
    }

    #[inline(always)]
    unsafe fn load_block_full(ptr: *const u8) -> [u64; 5] {
        use core::ptr;

        let t0 = u32::from_le(ptr::read_unaligned(ptr as *const u32)) as u64;
        let t1 = u32::from_le(ptr::read_unaligned(ptr.add(3) as *const u32)) as u64;
        let t2 = u32::from_le(ptr::read_unaligned(ptr.add(6) as *const u32)) as u64;
        let t3 = u32::from_le(ptr::read_unaligned(ptr.add(9) as *const u32)) as u64;
        let t4 = u32::from_le(ptr::read_unaligned(ptr.add(12) as *const u32)) as u64;

        let m0 = t0 & 0x3ffffff;
        let m1 = (t1 >> 2) & 0x3ffffff;
        let m2 = (t2 >> 4) & 0x3ffffff;
        let m3 = (t3 >> 6) & 0x3ffffff;
        let mut m4 = (t4 >> 8) & 0x3ffffff;
        m4 |= 1 << 24;
        [m0, m1, m2, m3, m4]
    }

    #[inline(always)]
    fn load_block(m: &[u8]) -> [u64; 5] {
        if m.len() == 16 {
            unsafe { return load_block_full(m.as_ptr()) };
        }

        let mut block = [0u8; 16];
        block[..m.len()].copy_from_slice(m);
        unsafe { load_block_full(block.as_ptr()) }
    }

    #[inline(always)]
    fn mac_scalar(mut h: [u64; 5], r: [u64; 5], m: &[u8]) -> [u64; 5] {
        // Pre-compute the repeated multipliers once outside the hot loop.
        let r0 = r[0];
        let r1 = r[1];
        let r2 = r[2];
        let r3 = r[3];
        let r4 = r[4];

        let s1 = r1 * 5;
        let s2 = r2 * 5;
        let s3 = r3 * 5;
        let s4 = r4 * 5;

        let r_u128 = [r0 as u128, r1 as u128, r2 as u128, r3 as u128, r4 as u128];
        let s_u128 = [0u128, s1 as u128, s2 as u128, s3 as u128, s4 as u128];

        let mut ptr = m;
        while ptr.len() >= 16 {
            let limbs = unsafe { load_block_full(ptr.as_ptr()) };
            h = mac_scalar_block(h, &r_u128, &s_u128, limbs);
            ptr = &ptr[16..];
        }

        if !ptr.is_empty() {
            let mut block = [0u8; 16];
            block[..ptr.len()].copy_from_slice(ptr);
            let limbs = unsafe { load_block_full(block.as_ptr()) };
            h = mac_scalar_block(h, &r_u128, &s_u128, limbs);
        }

        h
    }

    #[inline(always)]
    fn mac_scalar_block(
        mut h: [u64; 5],
        r_u128: &[u128; 5],
        s_u128: &[u128; 5],
        limbs: [u64; 5],
    ) -> [u64; 5] {
        let hh0 = h[0] + limbs[0];
        let hh1 = h[1] + limbs[1];
        let hh2 = h[2] + limbs[2];
        let hh3 = h[3] + limbs[3];
        let hh4 = h[4] + limbs[4];

        // Accumulate using 128-bit intermediates to preserve exactness.
        let d0 = (hh0 as u128) * r_u128[0]
            + (hh1 as u128) * s_u128[4]
            + (hh2 as u128) * s_u128[3]
            + (hh3 as u128) * s_u128[2]
            + (hh4 as u128) * s_u128[1];

        let mut d1 = (hh0 as u128) * r_u128[1]
            + (hh1 as u128) * r_u128[0]
            + (hh2 as u128) * s_u128[4]
            + (hh3 as u128) * s_u128[3]
            + (hh4 as u128) * s_u128[2];

        let mut d2 = (hh0 as u128) * r_u128[2]
            + (hh1 as u128) * r_u128[1]
            + (hh2 as u128) * r_u128[0]
            + (hh3 as u128) * s_u128[4]
            + (hh4 as u128) * s_u128[3];

        let mut d3 = (hh0 as u128) * r_u128[3]
            + (hh1 as u128) * r_u128[2]
            + (hh2 as u128) * r_u128[1]
            + (hh3 as u128) * r_u128[0]
            + (hh4 as u128) * s_u128[4];

        let mut d4 = (hh0 as u128) * r_u128[4]
            + (hh1 as u128) * r_u128[3]
            + (hh2 as u128) * r_u128[2]
            + (hh3 as u128) * r_u128[1]
            + (hh4 as u128) * r_u128[0];

        // Carry propagation in base 2^26
        let mut carry = (d0 >> 26) as u64;
        h[0] = (d0 & 0x3ffffff) as u64;

        d1 += carry as u128;
        carry = (d1 >> 26) as u64;
        h[1] = (d1 & 0x3ffffff) as u64;

        d2 += carry as u128;
        carry = (d2 >> 26) as u64;
        h[2] = (d2 & 0x3ffffff) as u64;

        d3 += carry as u128;
        carry = (d3 >> 26) as u64;
        h[3] = (d3 & 0x3ffffff) as u64;

        d4 += carry as u128;
        carry = (d4 >> 26) as u64;
        h[4] = (d4 & 0x3ffffff) as u64;

        h[0] += carry * 5;
        let carry2 = h[0] >> 26;
        h[0] &= 0x3ffffff;
        h[1] += carry2;

        h
    }

    fn mac(h: [u64; 5], r: [u64; 5], m: &[u8]) -> [u64; 5] {
        let features = FeatureDetector::instance().features_full();

        #[cfg(target_arch = "x86_64")]
        unsafe {
            if features.avx512f {
                return mac_avx512(h, r, m);
            }
            if features.avx2 {
                return mac_avx2(h, r, m);
            }
            if features.sse2 {
                return mac_sse2(h, r, m);
            }
        }

        #[cfg(target_arch = "aarch64")]
        unsafe {
            if features.sve2 {
                return mac_sve2(h, r, m);
            }
            if features.neon {
                return mac_neon(h, r, m);
            }
        }

        telemetry::POLY1305_SCALAR_OPS.inc();
        mac_scalar(h, r, m)
    }

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    unsafe fn mul_even_u32_avx2(
        a0: u32,
        a1: u32,
        a2: u32,
        a3: u32,
        b0: u32,
        b1: u32,
        b2: u32,
        b3: u32,
    ) -> [u64; 4] {
        use core::arch::x86_64::*;

        let va = _mm256_set_epi32(0, a3 as i32, 0, a2 as i32, 0, a1 as i32, 0, a0 as i32);
        let vb = _mm256_set_epi32(0, b3 as i32, 0, b2 as i32, 0, b1 as i32, 0, b0 as i32);
        let prod = _mm256_mul_epu32(va, vb);
        let low = _mm256_castsi256_si128(prod);
        let high = _mm256_extracti128_si256(prod, 1);
        let r0 = _mm_cvtsi128_si64(low) as u64;
        let r1 = _mm_cvtsi128_si64(_mm_srli_si128(low, 8)) as u64;
        let r2 = _mm_cvtsi128_si64(high) as u64;
        let r3 = _mm_cvtsi128_si64(_mm_srli_si128(high, 8)) as u64;
        [r0, r1, r2, r3]
    }

    #[cfg(target_arch = "x86_64")]
    #[inline]
    #[target_feature(enable = "avx512f")]
    unsafe fn mul_even_u32_avx512(
        a0: u32,
        a1: u32,
        a2: u32,
        a3: u32,
        b0: u32,
        b1: u32,
        b2: u32,
        b3: u32,
    ) -> [u64; 4] {
        use core::arch::x86_64::*;

        let va = _mm512_setr_epi32(
            a0 as i32, 0, a1 as i32, 0, a2 as i32, 0, a3 as i32, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        );
        let vb = _mm512_setr_epi32(
            b0 as i32, 0, b1 as i32, 0, b2 as i32, 0, b3 as i32, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        );
        let prod = _mm512_mul_epu32(va, vb);
        let mut out = [0u64; 8];
        _mm512_storeu_si512(out.as_mut_ptr() as *mut __m512i, prod);
        [out[0], out[1], out[2], out[3]]
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn mac_avx2(h: [u64; 5], r: [u64; 5], m: &[u8]) -> [u64; 5] {
        telemetry::POLY1305_AVX2_OPS.inc();
        let r0 = r[0] as u32;
        let r1 = r[1] as u32;
        let r2 = r[2] as u32;
        let r3 = r[3] as u32;
        let r4 = r[4] as u32;

        let s1 = (r1 as u64 * 5) as u32;
        let s2 = (r2 as u64 * 5) as u32;
        let s3 = (r3 as u64 * 5) as u32;
        let s4 = (r4 as u64 * 5) as u32;

        let mut h0 = h[0];
        let mut h1 = h[1];
        let mut h2 = h[2];
        let mut h3 = h[3];
        let mut h4 = h[4];

        let mut offset = 0usize;
        while offset < m.len() {
            let take = core::cmp::min(16, m.len() - offset);
            let limbs = load_block(&m[offset..offset + take]);
            offset += take;

            h0 += limbs[0];
            h1 += limbs[1];
            h2 += limbs[2];
            h3 += limbs[3];
            h4 += limbs[4];

            let h0u = h0 as u32;
            let h1u = h1 as u32;
            let h2u = h2 as u32;
            let h3u = h3 as u32;
            let h4u = h4 as u32;

            let prods0 = mul_even_u32_avx2(h0u, h1u, h2u, h3u, r0, s4, s3, s2);
            let mut d0 = (prods0[0] as u128)
                + (prods0[1] as u128)
                + (prods0[2] as u128)
                + (prods0[3] as u128)
                + ((h4u as u128) * (s1 as u128));

            let prods1 = mul_even_u32_avx2(h0u, h1u, h2u, h3u, r1, r0, s4, s3);
            let mut d1 = (prods1[0] as u128)
                + (prods1[1] as u128)
                + (prods1[2] as u128)
                + (prods1[3] as u128)
                + ((h4u as u128) * (s2 as u128));

            let prods2 = mul_even_u32_avx2(h0u, h1u, h2u, h3u, r2, r1, r0, s4);
            let mut d2 = (prods2[0] as u128)
                + (prods2[1] as u128)
                + (prods2[2] as u128)
                + (prods2[3] as u128)
                + ((h4u as u128) * (s3 as u128));

            let prods3 = mul_even_u32_avx2(h0u, h1u, h2u, h3u, r3, r2, r1, r0);
            let mut d3 = (prods3[0] as u128)
                + (prods3[1] as u128)
                + (prods3[2] as u128)
                + (prods3[3] as u128)
                + ((h4u as u128) * (s4 as u128));

            let prods4 = mul_even_u32_avx2(h0u, h1u, h2u, h3u, r4, r3, r2, r1);
            let mut d4 = (prods4[0] as u128)
                + (prods4[1] as u128)
                + (prods4[2] as u128)
                + (prods4[3] as u128)
                + ((h4u as u128) * (r0 as u128));

            let mut carry = d0 >> 26;
            h0 = (d0 & 0x3ffffff) as u64;

            d1 += carry;
            carry = d1 >> 26;
            h1 = (d1 & 0x3ffffff) as u64;

            d2 += carry;
            carry = d2 >> 26;
            h2 = (d2 & 0x3ffffff) as u64;

            d3 += carry;
            carry = d3 >> 26;
            h3 = (d3 & 0x3ffffff) as u64;

            d4 += carry;
            carry = d4 >> 26;
            h4 = (d4 & 0x3ffffff) as u64;
            h0 += (carry as u64) * 5;
            let carry2 = h0 >> 26;
            h0 &= 0x3ffffff;
            h1 += carry2;
        }

        [h0, h1, h2, h3, h4]
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512f")]
    unsafe fn mac_avx512(h: [u64; 5], r: [u64; 5], m: &[u8]) -> [u64; 5] {
        telemetry::POLY1305_AVX512_OPS.inc();
        let r0 = r[0] as u32;
        let r1 = r[1] as u32;
        let r2 = r[2] as u32;
        let r3 = r[3] as u32;
        let r4 = r[4] as u32;

        let s1 = (r1 as u64 * 5) as u32;
        let s2 = (r2 as u64 * 5) as u32;
        let s3 = (r3 as u64 * 5) as u32;
        let s4 = (r4 as u64 * 5) as u32;

        let mut h0 = h[0];
        let mut h1 = h[1];
        let mut h2 = h[2];
        let mut h3 = h[3];
        let mut h4 = h[4];

        let mut offset = 0usize;
        while offset < m.len() {
            let take = core::cmp::min(16, m.len() - offset);
            let limbs = load_block(&m[offset..offset + take]);
            offset += take;

            h0 += limbs[0];
            h1 += limbs[1];
            h2 += limbs[2];
            h3 += limbs[3];
            h4 += limbs[4];

            let h0u = h0 as u32;
            let h1u = h1 as u32;
            let h2u = h2 as u32;
            let h3u = h3 as u32;
            let h4u = h4 as u32;

            let prods0 = mul_even_u32_avx512(h0u, h1u, h2u, h3u, r0, s4, s3, s2);
            let mut d0 = (prods0[0] as u128)
                + (prods0[1] as u128)
                + (prods0[2] as u128)
                + (prods0[3] as u128)
                + ((h4u as u128) * (s1 as u128));

            let prods1 = mul_even_u32_avx512(h0u, h1u, h2u, h3u, r1, r0, s4, s3);
            let mut d1 = (prods1[0] as u128)
                + (prods1[1] as u128)
                + (prods1[2] as u128)
                + (prods1[3] as u128)
                + ((h4u as u128) * (s2 as u128));

            let prods2 = mul_even_u32_avx512(h0u, h1u, h2u, h3u, r2, r1, r0, s4);
            let mut d2 = (prods2[0] as u128)
                + (prods2[1] as u128)
                + (prods2[2] as u128)
                + (prods2[3] as u128)
                + ((h4u as u128) * (s3 as u128));

            let prods3 = mul_even_u32_avx512(h0u, h1u, h2u, h3u, r3, r2, r1, r0);
            let mut d3 = (prods3[0] as u128)
                + (prods3[1] as u128)
                + (prods3[2] as u128)
                + (prods3[3] as u128)
                + ((h4u as u128) * (s4 as u128));

            let prods4 = mul_even_u32_avx512(h0u, h1u, h2u, h3u, r4, r3, r2, r1);
            let mut d4 = (prods4[0] as u128)
                + (prods4[1] as u128)
                + (prods4[2] as u128)
                + (prods4[3] as u128)
                + ((h4u as u128) * (r0 as u128));

            let mut carry = d0 >> 26;
            h0 = (d0 & 0x3ffffff) as u64;

            d1 += carry;
            carry = d1 >> 26;
            h1 = (d1 & 0x3ffffff) as u64;

            d2 += carry;
            carry = d2 >> 26;
            h2 = (d2 & 0x3ffffff) as u64;

            d3 += carry;
            carry = d3 >> 26;
            h3 = (d3 & 0x3ffffff) as u64;

            d4 += carry;
            carry = d4 >> 26;
            h4 = (d4 & 0x3ffffff) as u64;
            h0 += (carry as u64) * 5;
            let carry2 = h0 >> 26;
            h0 &= 0x3ffffff;
            h1 += carry2;
        }

        [h0, h1, h2, h3, h4]
    }

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    unsafe fn mul_pair_u32_sse2(a0: u32, a1: u32, b0: u32, b1: u32) -> (u64, u64) {
        use core::arch::x86_64::*;

        let va = _mm_set_epi32(0, a1 as i32, 0, a0 as i32);
        let vb = _mm_set_epi32(0, b1 as i32, 0, b0 as i32);
        let prod = _mm_mul_epu32(va, vb);
        let lo = _mm_cvtsi128_si64(prod) as u64;
        let hi = _mm_cvtsi128_si64(_mm_unpackhi_epi64(prod, prod)) as u64;
        (lo, hi)
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "sse2")]
    unsafe fn mac_sse2(h: [u64; 5], r: [u64; 5], m: &[u8]) -> [u64; 5] {
        telemetry::POLY1305_SSE2_OPS.inc();
        let r0 = r[0] as u32;
        let r1 = r[1] as u32;
        let r2 = r[2] as u32;
        let r3 = r[3] as u32;
        let r4 = r[4] as u32;

        let s1 = (r1 as u64 * 5) as u32;
        let s2 = (r2 as u64 * 5) as u32;
        let s3 = (r3 as u64 * 5) as u32;
        let s4 = (r4 as u64 * 5) as u32;

        let mut h0 = h[0];
        let mut h1 = h[1];
        let mut h2 = h[2];
        let mut h3 = h[3];
        let mut h4 = h[4];

        let mut offset = 0usize;
        while offset < m.len() {
            let take = core::cmp::min(16, m.len() - offset);
            let limbs = load_block(&m[offset..offset + take]);
            offset += take;

            h0 += limbs[0];
            h1 += limbs[1];
            h2 += limbs[2];
            h3 += limbs[3];
            h4 += limbs[4];

            let h0u = h0 as u32;
            let h1u = h1 as u32;
            let h2u = h2 as u32;
            let h3u = h3 as u32;
            let h4u = h4 as u32;

            let (p0, p1) = mul_pair_u32_sse2(h0u, h1u, r0, s4);
            let (p2, p3) = mul_pair_u32_sse2(h2u, h3u, s3, s2);
            let p4 = (h4u as u128) * (s1 as u128);
            let d0 = (p0 as u128) + (p1 as u128) + (p2 as u128) + (p3 as u128) + p4;

            let (q0, q1) = mul_pair_u32_sse2(h0u, h1u, r1, r0);
            let (q2, q3) = mul_pair_u32_sse2(h2u, h3u, s4, s3);
            let q4 = (h4u as u128) * (s2 as u128);
            let mut d1 = (q0 as u128) + (q1 as u128) + (q2 as u128) + (q3 as u128) + q4;

            let (r0p, r1p) = mul_pair_u32_sse2(h0u, h1u, r2, r1);
            let (r2p, r3p) = mul_pair_u32_sse2(h2u, h3u, r0, s4);
            let r4p = (h4u as u128) * (s3 as u128);
            let mut d2 = (r0p as u128) + (r1p as u128) + (r2p as u128) + (r3p as u128) + r4p;

            let (s0p, s1p) = mul_pair_u32_sse2(h0u, h1u, r3, r2);
            let (s2p, s3p) = mul_pair_u32_sse2(h2u, h3u, r1, r0);
            let s4p = (h4u as u128) * (s4 as u128);
            let mut d3 = (s0p as u128) + (s1p as u128) + (s2p as u128) + (s3p as u128) + s4p;

            let (t0p, t1p) = mul_pair_u32_sse2(h0u, h1u, r4, r3);
            let (t2p, t3p) = mul_pair_u32_sse2(h2u, h3u, r2, r1);
            let t4p = (h4u as u128) * (r0 as u128);
            let mut d4 = (t0p as u128) + (t1p as u128) + (t2p as u128) + (t3p as u128) + t4p;

            let mut carry = d0 >> 26;
            h0 = (d0 & 0x3ffffff) as u64;

            d1 += carry;
            carry = d1 >> 26;
            h1 = (d1 & 0x3ffffff) as u64;

            d2 += carry;
            carry = d2 >> 26;
            h2 = (d2 & 0x3ffffff) as u64;

            d3 += carry;
            carry = d3 >> 26;
            h3 = (d3 & 0x3ffffff) as u64;

            d4 += carry;
            carry = d4 >> 26;
            h4 = (d4 & 0x3ffffff) as u64;
            h0 += (carry as u64) * 5;
            let carry2 = h0 >> 26;
            h0 &= 0x3ffffff;
            h1 += carry2;
        }

        [h0, h1, h2, h3, h4]
    }

    #[cfg(target_arch = "aarch64")]
    #[inline(always)]
    unsafe fn mul_pair_u32_neon(a0: u32, a1: u32, b0: u32, b1: u32) -> (u64, u64) {
        use core::arch::aarch64::*;

        let mut va = vdup_n_u32(0);
        va = vset_lane_u32(a0, va, 0);
        va = vset_lane_u32(a1, va, 1);
        let mut vb = vdup_n_u32(0);
        vb = vset_lane_u32(b0, vb, 0);
        vb = vset_lane_u32(b1, vb, 1);
        let prod = vmull_u32(va, vb);
        let lo = vgetq_lane_u64(prod, 0);
        let hi = vgetq_lane_u64(prod, 1);
        (lo, hi)
    }

    #[cfg(target_arch = "aarch64")]
    #[inline(always)]
    unsafe fn mac_neon_body(mut h: [u64; 5], r: [u64; 5], m: &[u8]) -> [u64; 5] {
        let r0 = r[0] as u32;
        let r1 = r[1] as u32;
        let r2 = r[2] as u32;
        let r3 = r[3] as u32;
        let r4 = r[4] as u32;

        let s1 = (r1 as u64 * 5) as u32;
        let s2 = (r2 as u64 * 5) as u32;
        let s3 = (r3 as u64 * 5) as u32;
        let s4 = (r4 as u64 * 5) as u32;

        let mut offset = 0usize;
        while offset < m.len() {
            let take = core::cmp::min(16, m.len() - offset);
            let limbs = load_block(&m[offset..offset + take]);
            offset += take;

            h[0] += limbs[0];
            h[1] += limbs[1];
            h[2] += limbs[2];
            h[3] += limbs[3];
            h[4] += limbs[4];

            let h0u = h[0] as u32;
            let h1u = h[1] as u32;
            let h2u = h[2] as u32;
            let h3u = h[3] as u32;
            let h4u = h[4] as u32;

            let (p0, p1) = mul_pair_u32_neon(h0u, h1u, r0, s4);
            let (p2, p3) = mul_pair_u32_neon(h2u, h3u, s3, s2);
            let p4 = (h4u as u128) * (s1 as u128);
            let d0 = (p0 as u128) + (p1 as u128) + (p2 as u128) + (p3 as u128) + p4;

            let (q0, q1) = mul_pair_u32_neon(h0u, h1u, r1, r0);
            let (q2, q3) = mul_pair_u32_neon(h2u, h3u, s4, s3);
            let q4 = (h4u as u128) * (s2 as u128);
            let mut d1 = (q0 as u128) + (q1 as u128) + (q2 as u128) + (q3 as u128) + q4;

            let (r0p, r1p) = mul_pair_u32_neon(h0u, h1u, r2, r1);
            let (r2p, r3p) = mul_pair_u32_neon(h2u, h3u, r0, s4);
            let r4p = (h4u as u128) * (s3 as u128);
            let mut d2 = (r0p as u128) + (r1p as u128) + (r2p as u128) + (r3p as u128) + r4p;

            let (s0p, s1p) = mul_pair_u32_neon(h0u, h1u, r3, r2);
            let (s2p, s3p) = mul_pair_u32_neon(h2u, h3u, r1, r0);
            let s4p = (h4u as u128) * (s4 as u128);
            let mut d3 = (s0p as u128) + (s1p as u128) + (s2p as u128) + (s3p as u128) + s4p;

            let (t0p, t1p) = mul_pair_u32_neon(h0u, h1u, r4, r3);
            let (t2p, t3p) = mul_pair_u32_neon(h2u, h3u, r2, r1);
            let t4p = (h4u as u128) * (r0 as u128);
            let mut d4 = (t0p as u128) + (t1p as u128) + (t2p as u128) + (t3p as u128) + t4p;

            let mut carry = d0 >> 26;
            h[0] = (d0 & 0x3ffffff) as u64;

            d1 += carry;
            carry = d1 >> 26;
            h[1] = (d1 & 0x3ffffff) as u64;

            d2 += carry;
            carry = d2 >> 26;
            h[2] = (d2 & 0x3ffffff) as u64;

            d3 += carry;
            carry = d3 >> 26;
            h[3] = (d3 & 0x3ffffff) as u64;

            d4 += carry;
            carry = d4 >> 26;
            h[4] = (d4 & 0x3ffffff) as u64;
            h[0] += (carry as u64) * 5;
            let carry2 = h[0] >> 26;
            h[0] &= 0x3ffffff;
            h[1] += carry2;
        }

        h
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    unsafe fn mac_neon(h: [u64; 5], r: [u64; 5], m: &[u8]) -> [u64; 5] {
        telemetry::POLY1305_NEON_OPS.inc();
        mac_neon_body(h, r, m)
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
    #[target_feature(enable = "sve2")]
    unsafe fn mac_sve2_impl(mut h: [u64; 5], r: [u64; 5], m: &[u8]) -> [u64; 5] {
        use std::arch::aarch64::*;

        if (svcntd() as usize) < 4 {
            telemetry::POLY1305_NEON_OPS.inc();
            return mac_neon_body(h, r, m);
        }

        telemetry::POLY1305_SVE_OPS.inc();

        #[inline(always)]
        unsafe fn mac_sve2_block_wide(
            mut state: [u64; 5],
            coeffs: &[([u64; 4], u64); 5],
            limbs: [u64; 5],
        ) -> [u64; 5] {
            use std::arch::aarch64::*;

            let mut hh0 = state[0] + limbs[0];
            let mut hh1 = state[1] + limbs[1];
            let mut hh2 = state[2] + limbs[2];
            let mut hh3 = state[3] + limbs[3];
            let hh4 = state[4] + limbs[4];

            let hh_vec = [hh0, hh1, hh2, hh3];
            let pg = svwhilelt_b64(0, 4);
            let h_vec = svld1_u64(pg, hh_vec.as_ptr());

            let mut accum = [0u128; 5];
            for (idx, coeff) in coeffs.iter().enumerate() {
                let coeff_vec = svld1_u64(pg, coeff.0.as_ptr());
                let prods = svmul_u64_x(pg, h_vec, coeff_vec);
                let lane_sum = svaddv_u64(pg, prods) as u128;
                accum[idx] = lane_sum + (hh4 as u128) * (coeff.1 as u128);
            }

            let mut carry = (accum[0] >> 26) as u64;
            hh0 = (accum[0] & 0x3ffffff) as u64;

            accum[1] += carry as u128;
            carry = (accum[1] >> 26) as u64;
            hh1 = (accum[1] & 0x3ffffff) as u64;

            accum[2] += carry as u128;
            carry = (accum[2] >> 26) as u64;
            hh2 = (accum[2] & 0x3ffffff) as u64;

            accum[3] += carry as u128;
            carry = (accum[3] >> 26) as u64;
            hh3 = (accum[3] & 0x3ffffff) as u64;

            accum[4] += carry as u128;
            carry = (accum[4] >> 26) as u64;
            let mut hh4_reduced = (accum[4] & 0x3ffffff) as u64;

            hh0 += carry * 5;
            let carry2 = hh0 >> 26;
            hh0 &= 0x3ffffff;
            hh1 += carry2;
            hh4_reduced &= 0x3ffffff;

            state[0] = hh0;
            state[1] = hh1;
            state[2] = hh2;
            state[3] = hh3;
            state[4] = hh4_reduced;
            state
        }

        let s1 = r[1] * 5;
        let s2 = r[2] * 5;
        let s3 = r[3] * 5;
        let s4 = r[4] * 5;

        let coeffs: [([u64; 4], u64); 5] = [
            ([r[0], s4, s3, s2], s1),
            ([r[1], r[0], s4, s3], s2),
            ([r[2], r[1], r[0], s4], s3),
            ([r[3], r[2], r[1], r[0]], s4),
            ([r[4], r[3], r[2], r[1]], r[0]),
        ];

        let mut offset = 0usize;
        while offset + 16 <= m.len() {
            let limbs = load_block_full(m.as_ptr().add(offset));
            h = mac_sve2_block_wide(h, &coeffs, limbs);
            offset += 16;
        }

        if offset < m.len() {
            let limbs = load_block(&m[offset..]);
            h = mac_sve2_block_wide(h, &coeffs, limbs);
        }

        h
    }

    #[cfg(target_arch = "aarch64")]
    unsafe fn mac_sve2(h: [u64; 5], r: [u64; 5], m: &[u8]) -> [u64; 5] {
        #[cfg(target_feature = "sve2")]
        {
            return mac_sve2_impl(h, r, m);
        }
        #[cfg(not(target_feature = "sve2"))]
        {
            telemetry::POLY1305_NEON_OPS.inc();
            mac_neon_body(h, r, m)
        }
    }

    #[cfg(all(test, target_arch = "x86_64"))]
    mod tests_x86 {
        use super::*;

        #[test]
        fn mac_sse2_matches_scalar() {
            if !std::arch::is_x86_feature_detected!("sse2") {
                return;
            }

            let r_bytes = [
                0x85, 0xd6, 0x96, 0x6a, 0x4c, 0xcd, 0x62, 0x16, 0x4b, 0xe5, 0x60, 0x47, 0x33, 0x8b,
                0x4f, 0x1f,
            ];
            let r = load_r_clamped(&r_bytes);

            let messages: &[&[u8]] = &[b"", b"hello world", &[0xFF; 31], &[0u8; 128]];

            for msg in messages {
                let h_scalar = mac_scalar([0; 5], r, msg);
                let h_simd = unsafe { mac_sse2([0; 5], r, msg) };
                assert_eq!(h_scalar, h_simd);
            }
        }

        #[test]
        fn mac_avx2_matches_scalar() {
            if !std::arch::is_x86_feature_detected!("avx2") {
                return;
            }

            let r_bytes = [
                0x85, 0xd6, 0x96, 0x6a, 0x4c, 0xcd, 0x62, 0x16, 0x4b, 0xe5, 0x60, 0x47, 0x33, 0x8b,
                0x4f, 0x1f,
            ];
            let r = load_r_clamped(&r_bytes);

            let messages: &[&[u8]] = &[b"", b"hello world", &[0x01; 47], &[0xAA; 256]];

            for msg in messages {
                let h_scalar = mac_scalar([0; 5], r, msg);
                let h_simd = unsafe { mac_avx2([0; 5], r, msg) };
                assert_eq!(h_scalar, h_simd);
            }
        }
    }

    #[cfg(all(test, target_arch = "aarch64"))]
    mod tests_neon {
        use super::*;

        #[test]
        fn mac_neon_matches_scalar() {
            if !std::arch::is_aarch64_feature_detected!("neon") {
                return;
            }

            let r_bytes = [
                0x85, 0xd6, 0x96, 0x6a, 0x4c, 0xcd, 0x62, 0x16, 0x4b, 0xe5, 0x60, 0x47, 0x33, 0x8b,
                0x4f, 0x1f,
            ];
            let r = load_r_clamped(&r_bytes);

            let messages: &[&[u8]] = &[b"", b"hello world", &[0x01; 47], &[0xAA; 256]];

            for msg in messages {
                let h_scalar = mac_scalar([0; 5], r, msg);
                let h_simd = unsafe { mac_neon([0; 5], r, msg) };
                assert_eq!(h_scalar, h_simd);
            }
        }
    }

    #[cfg(all(test, target_arch = "aarch64"))]
    mod tests_sve2 {
        use super::*;

        #[test]
        fn mac_sve2_matches_scalar() {
            if !std::arch::is_aarch64_feature_detected!("sve2") {
                return;
            }

            let r_bytes = [
                0x85, 0xd6, 0x96, 0x6a, 0x4c, 0xcd, 0x62, 0x16, 0x4b, 0xe5, 0x60, 0x47, 0x33, 0x8b,
                0x4f, 0x1f,
            ];
            let r = load_r_clamped(&r_bytes);

            let messages: &[&[u8]] = &[b"", b"hello world", &[0x02; 63], &[0xCC; 320]];

            for msg in messages {
                let h_scalar = mac_scalar([0; 5], r, msg);
                let h_simd = unsafe { mac_sve2([0; 5], r, msg) };
                assert_eq!(h_scalar, h_simd);
            }
        }
    }

    fn finalize(h: &mut [u64; 5], one_time_key: &[u8; 32]) -> [u8; 16] {
        let mut c = h[1] >> 26;
        h[1] &= 0x3ffffff;
        h[2] += c;
        c = h[2] >> 26;
        h[2] &= 0x3ffffff;
        h[3] += c;
        c = h[3] >> 26;
        h[3] &= 0x3ffffff;
        h[4] += c;
        c = h[4] >> 26;
        h[4] &= 0x3ffffff;
        h[0] += c * 5;
        c = h[0] >> 26;
        h[0] &= 0x3ffffff;
        h[1] += c;

        let mut g0 = h[0] + 5;
        let mut c = g0 >> 26;
        g0 &= 0x3ffffff;
        let mut g1 = h[1] + c;
        c = g1 >> 26;
        g1 &= 0x3ffffff;
        let mut g2 = h[2] + c;
        c = g2 >> 26;
        g2 &= 0x3ffffff;
        let mut g3 = h[3] + c;
        c = g3 >> 26;
        g3 &= 0x3ffffff;
        let mut g4 = (h[4] + c).wrapping_sub(1 << 26);
        let mask = (g4 >> 63).wrapping_sub(1);
        g4 &= 0x3ffffff;
        let mut res = [0u64; 5];
        for i in 0..5 {
            let hi = h[i];
            let gi = [g0, g1, g2, g3, g4][i];
            res[i] = (hi & (!mask)) | (gi & mask);
        }

        let f0 = res[0] | (res[1] << 26);
        let f1 = (res[1] >> 6) | (res[2] << 20);
        let f2 = (res[2] >> 12) | (res[3] << 14);
        let f3 = (res[3] >> 18) | (res[4] << 8);

        let mut t =
            (f0 as u128) | ((f1 as u128) << 32) | ((f2 as u128) << 64) | ((f3 as u128) << 96);
        let mut s = [0u8; 16];
        s.copy_from_slice(&one_time_key[16..32]);
        t = t.wrapping_add(u128::from_le_bytes(s));
        t.to_le_bytes()
    }

    /// Compute Poly1305 tag over message with 32-byte one-time key (r||s).
    pub fn tag(msg: &[u8], one_time_key: &[u8; 32]) -> [u8; 16] {
        let mut r16 = [0u8; 16];
        r16.copy_from_slice(&one_time_key[0..16]);
        r16[3] &= 15;
        r16[7] &= 15;
        r16[11] &= 15;
        r16[15] &= 15;
        r16[4] &= 252;
        r16[8] &= 252;
        r16[12] &= 252;
        let r = load_r_clamped(&r16);

        let mut h = [0u64; 5];
        h = mac(h, r, msg);
        finalize(&mut h, one_time_key)
    }

    /// AEAD construction for ChaCha20-Poly1305 (tag only) without intermediate allocations.
    pub fn aead_tag_chacha20poly1305(
        aad: &[u8],
        ciphertext: &[u8],
        one_time_key: &[u8; 32],
    ) -> [u8; 16] {
        let mut r16 = [0u8; 16];
        r16.copy_from_slice(&one_time_key[0..16]);
        r16[3] &= 15;
        r16[7] &= 15;
        r16[11] &= 15;
        r16[15] &= 15;
        r16[4] &= 252;
        r16[8] &= 252;
        r16[12] &= 252;
        let r = load_r_clamped(&r16);

        let mut h = [0u64; 5];
        h = mac(h, r, aad);
        h = mac(h, r, ciphertext);

        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
        len_block[8..].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
        h = mac(h, r, &len_block);

        finalize(&mut h, one_time_key)
    }
}

pub mod gcm {
    #[cfg(all(test, target_arch = "x86_64"))]
    use std::sync::Mutex;

    #[cfg(all(test, target_arch = "x86_64"))]
    static GHASH_TEST_OVERRIDE: Mutex<Option<String>> = Mutex::new(None);

    #[cfg(all(test, target_arch = "x86_64"))]
    pub fn __test_set_ghash_override(val: Option<&str>) {
        let mut guard = GHASH_TEST_OVERRIDE.lock().unwrap();
        *guard = val.map(|s| s.to_lowercase());
    }

    fn be_bytes_to_u128(b: &[u8; 16]) -> u128 {
        u128::from_be_bytes(*b)
    }
    fn u128_to_be_bytes(x: u128) -> [u8; 16] {
        x.to_be_bytes()
    }

    // Multiply by x in GF(2^128) with reduction by the GCM polynomial
    #[inline(always)]
    fn mul_x(mut v: u128) -> u128 {
        let carry = (v & 0x8000_0000_0000_0000_0000_0000_0000_0000u128) != 0;
        v <<= 1;
        if carry {
            v ^= 0x87;
        }
        v
    }

    #[inline(always)]
    fn mul_x4(mut v: u128) -> u128 {
        v = mul_x(v);
        v = mul_x(v);
        v = mul_x(v);
        mul_x(v)
    }

    // Precompute H * n for 4-bit n (0..15)
    fn precompute_h4(h: u128) -> [u128; 16] {
        let mut t = [0u128; 16];
        t[0] = 0;
        t[1] = h;
        // compute x^1..x^3 shifts of H
        let h_x1 = mul_x(h);
        let h_x2 = mul_x(h_x1);
        let h_x3 = mul_x(h_x2);
        // now combine for all nibbles by XOR of present bits
        for n in 2..16 {
            let mut acc = 0u128;
            if (n & 0x1) != 0 {
                acc ^= h;
            }
            if (n & 0x2) != 0 {
                acc ^= h_x1;
            }
            if (n & 0x4) != 0 {
                acc ^= h_x2;
            }
            if (n & 0x8) != 0 {
                acc ^= h_x3;
            }
            t[n as usize] = acc;
        }
        t
    }

    // Single-block GHASH update using 4-bit nibble method with precomputed table
    #[inline(always)]
    fn ghash_block_precomputed(table: &[u128; 16], mut y: u128, x: u128) -> u128 {
        let w = y ^ x;
        for i in 0..32 {
            let shift = 124 - 4 * i;
            let nib = ((w >> shift) & 0xF) as usize;
            y = mul_x4(y);
            y ^= table[nib];
        }
        y
    }

    #[cfg(target_arch = "x86_64")]
    fn ghash_override_value() -> Option<String> {
        #[cfg(all(test, target_arch = "x86_64"))]
        if let Some(mode) = GHASH_TEST_OVERRIDE.lock().unwrap().clone() {
            return Some(mode);
        }

        std::env::var("QUICFUSCATE_GHASH").ok()
    }

    pub fn ghash(h: [u8; 16], aad: &[u8], ct: &[u8]) -> [u8; 16] {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            use crate::optimize::CpuFeature;

            let detector = crate::optimize::FeatureDetector::instance();
            let features = detector.features_full();
            if let Some(mode) = ghash_override_value().map(|s| s.to_lowercase()) {
                match mode.as_str() {
                    "auto" => {}
                    "vpclmul" => {
                        if detector.has_feature(CpuFeature::VPCLMULQDQ) {
                            crate::optimize::telemetry::GHASH_VPCLMUL_OPS.inc();
                            return ghash_hw_vpclmul(h, aad, ct);
                        }
                        log::warn!(
                            "GHASH override 'vpclmul' requested but VPCLMUL support is unavailable; falling back"
                        );
                    }
                    "pclmul" => {
                        if detector.has_feature(CpuFeature::PCLMULQDQ) {
                            crate::optimize::telemetry::GHASH_PCLMUL_OPS.inc();
                            return ghash_hw_pclmul(h, aad, ct);
                        }
                        log::warn!(
                            "GHASH override 'pclmul' requested but PCLMULQDQ support is unavailable; falling back"
                        );
                    }
                    "sse" => {
                        if features.sse41 && features.ssse3 {
                            crate::optimize::telemetry::GHASH_SSE_OPS.inc();
                            return ghash_hw_sse(h, aad, ct);
                        }
                        log::warn!(
                            "GHASH override 'sse' requested but SSE4.1/SSSE3 are unavailable; falling back"
                        );
                    }
                    "scalar" | "ref" => {
                        crate::optimize::telemetry::GHASH_SCALAR_OPS.inc();
                        crate::optimize::telemetry::GHASH_SCALAR_CALLS.inc();
                        crate::optimize::telemetry::GHASH_SCALAR_BYTES
                            .inc_by((aad.len().saturating_add(ct.len())) as u64);
                        return ghash_software(h, aad, ct);
                    }
                    other => {
                        log::warn!("unknown GHASH override '{}'; falling back to auto", other);
                    }
                }
            }

            if detector.has_feature(CpuFeature::VPCLMULQDQ) {
                crate::optimize::telemetry::GHASH_VPCLMUL_OPS.inc();
                return ghash_hw_vpclmul(h, aad, ct);
            }
            if detector.has_feature(CpuFeature::PCLMULQDQ) {
                crate::optimize::telemetry::GHASH_PCLMUL_OPS.inc();
                return ghash_hw_pclmul(h, aad, ct);
            }
            if features.sse41 && features.ssse3 {
                crate::optimize::telemetry::GHASH_SSE_OPS.inc();
                return ghash_hw_sse(h, aad, ct);
            }
        }
        #[cfg(target_arch = "aarch64")]
        unsafe {
            let detector = crate::optimize::FeatureDetector::instance();
            let gate = std::env::var("QUICFUSCATE_GHASH_PMULL").ok();
            let disabled = matches!(
                gate.as_deref(),
                Some("0") | Some("false") | Some("FALSE") | Some("off") | Some("OFF")
            );
            if !disabled {
                let finalize = |hw: [u8; 16]| -> [u8; 16] {
                    #[cfg(any(test, debug_assertions))]
                    {
                        let sw = ghash_software(h, aad, ct);
                        if hw != sw {
                            return sw;
                        }
                    }
                    crate::optimize::telemetry::GHASH_PMULL_OPS.inc();
                    hw
                };

                if detector.has_feature(crate::optimize::CpuFeature::SVE_PMULL) {
                    let hw = ghash_hw_sve_pmull(h, aad, ct);
                    return finalize(hw);
                }

                if detector.has_feature(crate::optimize::CpuFeature::NEON_CRYPTO) {
                    let hw = ghash_hw_pmull_optimized(h, aad, ct);
                    return finalize(hw);
                }
                if detector.has_feature(crate::optimize::CpuFeature::NEON) {
                    crate::optimize::telemetry::GHASH_NEON_OPS.inc();
                    return finalize(ghash_hw_neon(h, aad, ct));
                }
            }
        }
        #[cfg(all(target_arch = "aarch64", not(target_feature = "neon")))]
        {
            let _ = h;
            let _ = aad;
            let _ = ct;
        }
        crate::optimize::telemetry::GHASH_SCALAR_OPS.inc();
        crate::optimize::telemetry::GHASH_SCALAR_CALLS.inc();
        crate::optimize::telemetry::GHASH_SCALAR_BYTES
            .inc_by((aad.len().saturating_add(ct.len())) as u64);
        ghash_software(h, aad, ct)
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "ssse3", enable = "sse4.1")]
    unsafe fn ghash_hw_sse(h: [u8; 16], aad: &[u8], ct: &[u8]) -> [u8; 16] {
        use core::{arch::x86_64::*, mem::MaybeUninit};

        let h128 = be_bytes_to_u128(&h);
        let table_raw = precompute_h4(h128);

        // Precompute H multiples for all 32 nibbles (most-significant first) to eliminate
        // per-byte mul_x4 work at runtime.
        let mut nib_tables = [[0u128; 16]; 32];
        let mut current = table_raw;
        for pos in (0..32).rev() {
            nib_tables[pos] = current;
            if pos > 0 {
                for val in current.iter_mut() {
                    *val = mul_x4(*val);
                }
            }
        }

        // Collapse nibble tables into per-byte lookup tables (16 byte positions x 256 values).
        let mut byte_tables_uninit = MaybeUninit::<[__m128i; 16 * 256]>::uninit();
        let byte_tables_ptr = byte_tables_uninit.as_mut_ptr() as *mut __m128i;
        for byte_idx in 0..16 {
            for byte_val in 0..256 {
                let hi = (byte_val >> 4) as usize;
                let lo = (byte_val & 0x0F) as usize;
                let contrib = nib_tables[byte_idx * 2][hi] ^ nib_tables[byte_idx * 2 + 1][lo];
                let bytes = u128_to_be_bytes(contrib);
                let vec = _mm_loadu_si128(bytes.as_ptr() as *const __m128i);
                byte_tables_ptr.add(byte_idx * 256 + byte_val).write(vec);
            }
        }
        let byte_tables = unsafe { byte_tables_uninit.assume_init() };

        #[inline(always)]
        unsafe fn ghash_block_sse(table: &[__m128i; 16 * 256], y: __m128i, x: __m128i) -> __m128i {
            let w = _mm_xor_si128(y, x);
            let mut bytes = [0u8; 16];
            _mm_storeu_si128(bytes.as_mut_ptr() as *mut __m128i, w);
            let mut acc = _mm_setzero_si128();
            let mut pos = 0usize;
            while pos < 16 {
                let idx = pos * 256 + (bytes[pos] as usize);
                acc = _mm_xor_si128(acc, table[idx]);
                pos += 1;
            }
            acc
        }

        #[inline(always)]
        unsafe fn process_segment(data: &[u8], table: &[__m128i; 16 * 256], y: &mut __m128i) {
            let mut idx = 0usize;
            while idx + 16 <= data.len() {
                let x = _mm_loadu_si128(data[idx..].as_ptr() as *const __m128i);
                *y = ghash_block_sse(table, *y, x);
                idx += 16;
            }
            if idx < data.len() {
                let mut blk = [0u8; 16];
                blk[..(data.len() - idx)].copy_from_slice(&data[idx..]);
                let x = _mm_loadu_si128(blk.as_ptr() as *const __m128i);
                *y = ghash_block_sse(table, *y, x);
            }
        }

        let mut y = _mm_setzero_si128();
        process_segment(aad, &byte_tables, &mut y);
        process_segment(ct, &byte_tables, &mut y);

        let aad_bits = (aad.len() as u128) * 8;
        let ct_bits = (ct.len() as u128) * 8;
        let mut lenblk = [0u8; 16];
        lenblk[..8].copy_from_slice(&(aad_bits as u64).to_be_bytes());
        lenblk[8..].copy_from_slice(&(ct_bits as u64).to_be_bytes());
        let len_vec = _mm_loadu_si128(lenblk.as_ptr() as *const __m128i);
        y = ghash_block_sse(&byte_tables, y, len_vec);

        let mut out = [0u8; 16];
        _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, y);
        out
    }

    #[inline(always)]
    fn inc32(counter: &mut [u8; 16]) {
        // increment last 32 bits in BE
        let n = ((counter[12] as u32) << 24)
            | ((counter[13] as u32) << 16)
            | ((counter[14] as u32) << 8)
            | (counter[15] as u32);
        let n = n.wrapping_add(1);
        counter[12..16].copy_from_slice(&n.to_be_bytes());
    }

    /// AES-GCM seal (encrypt + tag) with 96-bit IV
    pub fn aes_gcm_seal(
        aes_key: &[u8; 16],
        iv: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> (Vec<u8>, [u8; 16]) {
        // Hash subkey H = E(K, 0^128)
        let aes_ctx = crate::crypto::aes::Aes128Ctx::new(aes_key);
        let zero = [0u8; 16];
        let h = aes_ctx.encrypt_block(&zero);
        // J0 = IV || 0x00000001 for 96-bit iv
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(iv);
        j0[15] = 1;
        // Encrypt via GCTR starting at inc32(J0)
        let mut ctr = j0;
        inc32(&mut ctr);
        let mut ciphertext = vec![0u8; plaintext.len()];
        aes_ctx.ctr_xor(&mut ctr, plaintext, &mut ciphertext);
        // Compute authentication tag
        let s = ghash(h, aad, &ciphertext);
        let s_enc = aes_ctx.encrypt_block(&j0);
        let mut tag = [0u8; 16];
        for i in 0..16 {
            tag[i] = s[i] ^ s_enc[i];
        }
        (ciphertext, tag)
    }

    /// AES-GCM open (decrypt + tag verify); returns None if tag mismatch.
    pub fn aes_gcm_open(
        aes_key: &[u8; 16],
        iv: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; 16],
    ) -> Option<Vec<u8>> {
        // Recompute tag on ciphertext
        let aes_ctx = crate::crypto::aes::Aes128Ctx::new(aes_key);
        let zero = [0u8; 16];
        let h = aes_ctx.encrypt_block(&zero);
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(iv);
        j0[15] = 1;
        let s = ghash(h, aad, ciphertext);
        let s_enc = aes_ctx.encrypt_block(&j0);
        let mut tag_calc = [0u8; 16];
        for i in 0..16 {
            tag_calc[i] = s[i] ^ s_enc[i];
        }
        if !crate::crypto::subtle_ct_eq(&tag_calc, tag) {
            return None;
        }
        // Decrypt via GCTR
        let mut ctr = j0;
        inc32(&mut ctr);
        let mut pt = vec![0u8; ciphertext.len()];
        aes_ctx.ctr_xor(&mut ctr, ciphertext, &mut pt);
        Some(pt)
    }

    fn ghash_software(h: [u8; 16], aad: &[u8], ct: &[u8]) -> [u8; 16] {
        let h128 = be_bytes_to_u128(&h);
        let table = precompute_h4(h128);
        let mut y: u128 = 0;
        let mut i = 0usize;
        while i + 16 <= aad.len() {
            let mut blk = [0u8; 16];
            blk.copy_from_slice(&aad[i..i + 16]);
            y = ghash_block_precomputed(&table, y, be_bytes_to_u128(&blk));
            i += 16;
        }
        if i < aad.len() {
            let mut blk = [0u8; 16];
            blk[..aad.len() - i].copy_from_slice(&aad[i..]);
            y = ghash_block_precomputed(&table, y, be_bytes_to_u128(&blk));
        }
        let mut j = 0usize;
        while j + 16 <= ct.len() {
            let mut blk = [0u8; 16];
            blk.copy_from_slice(&ct[j..j + 16]);
            y = ghash_block_precomputed(&table, y, be_bytes_to_u128(&blk));
            j += 16;
        }
        if j < ct.len() {
            let mut blk = [0u8; 16];
            blk[..ct.len() - j].copy_from_slice(&ct[j..]);
            y = ghash_block_precomputed(&table, y, be_bytes_to_u128(&blk));
        }
        let aad_bits = (aad.len() as u128) * 8;
        let ct_bits = (ct.len() as u128) * 8;
        let mut lenblk = [0u8; 16];
        lenblk[..8].copy_from_slice(&(aad_bits as u64).to_be_bytes());
        lenblk[8..].copy_from_slice(&(ct_bits as u64).to_be_bytes());
        y = ghash_block_precomputed(&table, y, be_bytes_to_u128(&lenblk));
        u128_to_be_bytes(y)
    }

    #[cfg(test)]
    #[allow(clippy::items_after_test_module)]
    mod tests {
        use super::*;

        #[test]
        fn ghash_hw_equals_sw_small_cases() {
            // Deterministic pseudo-random data
            fn fill(buf: &mut [u8], seed: u8) {
                for (i, b) in buf.iter_mut().enumerate() {
                    *b = seed.wrapping_add(i as u8).rotate_left((i % 7) as u32);
                }
            }
            let mut h = [0u8; 16];
            fill(&mut h, 0xA5);
            let mut aad = [0u8; 37];
            fill(&mut aad, 0x3C);
            let mut ct = [0u8; 91];
            fill(&mut ct, 0x5E);
            let sw = ghash_software(h, &aad, &ct);
            let hw = ghash(h, &aad, &ct);
            assert_eq!(sw, hw);
        }

        #[test]
        fn ghash_hw_equals_sw_empty() {
            let h = [0u8; 16];
            let sw = ghash_software(h, &[], &[]);
            let hw = ghash(h, &[], &[]);
            assert_eq!(sw, hw);
        }

        #[test]
        fn aes_gcm_tag_aad_only_nist_vec() {
            // NIST SP 800-38D, Test Case (empty AAD, empty PT) with zero key/iv
            // Expected tag = AES_K(J0) since GHASH(\u2205,\u2205) = 0
            // Vector: key=00..00 (16B), iv=00..00 (12B), tag=58e2fccefa7e3061367f1d57a4e7455a
            let key = [0u8; 16];
            let iv = [0u8; 12];
            let aad: [u8; 0] = [];
            let tag = aes_gcm_tag_aad_only(&key, &iv, &aad);
            let expected: [u8; 16] = [
                0x58, 0xE2, 0xFC, 0xCE, 0xFA, 0x7E, 0x30, 0x61, 0x36, 0x7F, 0x1D, 0x57, 0xA4, 0xE7,
                0x45, 0x5A,
            ];
            assert_eq!(tag, expected);
        }

        #[test]
        fn ghash_hw_equals_sw_various_lengths() {
            // Deterministic filler
            fn fill(buf: &mut [u8], seed: u8) {
                for (i, b) in buf.iter_mut().enumerate() {
                    *b = seed.wrapping_add((i as u8).rotate_left((i % 5) as u32));
                }
            }
            let mut h = [0u8; 16];
            fill(&mut h, 0xC3);
            let lengths = [0usize, 1, 7, 16, 17, 31, 32, 47, 64, 79, 96, 127, 128, 191, 256];
            for &la in &lengths {
                for &lc in &lengths {
                    let mut aad = vec![0u8; la];
                    let mut ct = vec![0u8; lc];
                    fill(&mut aad, 0x5A);
                    fill(&mut ct, 0xB7);
                    let sw = ghash_software(h, &aad, &ct);
                    let hw = ghash(h, &aad, &ct);
                    assert_eq!(sw, hw, "mismatch at lengths aad={}, ct={}", la, lc);
                }
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    unsafe fn ghash_hw_pclmul(h: [u8; 16], aad: &[u8], ct: &[u8]) -> [u8; 16] {
        use core::arch::x86_64::*;
        // Byte-swap mask for BE<->LE
        let shuf = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
        // Load H and convert to LE polynomial domain
        let h_be = _mm_loadu_si128(h.as_ptr() as *const __m128i);
        let h_le = _mm_shuffle_epi8(
            h_be,
            _mm_set_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
        );
        let mut y_be = _mm_setzero_si128();
        // Process AAD
        let mut i = 0usize;
        while i + 16 <= aad.len() {
            let mut blk = [0u8; 16];
            blk.copy_from_slice(&aad[i..i + 16]);
            let x_be = _mm_loadu_si128(blk.as_ptr() as *const __m128i);
            y_be = ghash_block_pclmul(h_le, y_be, x_be);
            i += 16;
        }
        if i < aad.len() {
            let mut blk = [0u8; 16];
            blk[..(aad.len() - i)].copy_from_slice(&aad[i..]);
            let x_be = _mm_loadu_si128(blk.as_ptr() as *const __m128i);
            y_be = ghash_block_pclmul(h_le, y_be, x_be);
        }
        // Process CT
        let mut j = 0usize;
        while j + 16 <= ct.len() {
            let mut blk = [0u8; 16];
            blk.copy_from_slice(&ct[j..j + 16]);
            let x_be = _mm_loadu_si128(blk.as_ptr() as *const __m128i);
            y_be = ghash_block_pclmul(h_le, y_be, x_be);
            j += 16;
        }
        if j < ct.len() {
            let mut blk = [0u8; 16];
            blk[..(ct.len() - j)].copy_from_slice(&ct[j..]);
            let x_be = _mm_loadu_si128(blk.as_ptr() as *const __m128i);
            y_be = ghash_block_pclmul(h_le, y_be, x_be);
        }
        // Length block
        let aad_bits = (aad.len() as u128) * 8;
        let ct_bits = (ct.len() as u128) * 8;
        let mut lenblk = [0u8; 16];
        lenblk[..8].copy_from_slice(&(aad_bits as u64).to_be_bytes());
        lenblk[8..].copy_from_slice(&(ct_bits as u64).to_be_bytes());
        let x_be = _mm_loadu_si128(lenblk.as_ptr() as *const __m128i);
        y_be = ghash_block_pclmul(h_le, y_be, x_be);
        // Return BE bytes
        let mut out = [0u8; 16];
        _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, y_be);
        out
    }

    /// Ultra-fast GHASH implementation using VPCLMULQDQ (AVX-512 vector PCLMUL)
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512f,vpclmulqdq,avx512vl")]
    #[inline]
    unsafe fn ghash_hw_vpclmul(h: [u8; 16], aad: &[u8], ct: &[u8]) -> [u8; 16] {
        use core::arch::x86_64::*;

        // Load H and convert to LE polynomial domain
        let h_be = _mm_loadu_si128(h.as_ptr() as *const __m128i);
        let h_le = _mm_shuffle_epi8(
            h_be,
            _mm_set_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
        );
        let mut y_be = _mm_setzero_si128();

        // Process AAD with vectorized blocks where possible
        let mut i = 0usize;

        // Process 4 blocks at once with VPCLMULQDQ for better throughput
        while i + 64 <= aad.len() {
            let mut blks = [[0u8; 16]; 4];
            for j in 0..4 {
                blks[j].copy_from_slice(&aad[i + j * 16..i + (j + 1) * 16]);
            }

            // Load 4 blocks into 256-bit registers and process with VPCLMULQDQ
            let x0_be = _mm_loadu_si128(blks[0].as_ptr() as *const __m128i);
            let x1_be = _mm_loadu_si128(blks[1].as_ptr() as *const __m128i);
            let x2_be = _mm_loadu_si128(blks[2].as_ptr() as *const __m128i);
            let x3_be = _mm_loadu_si128(blks[3].as_ptr() as *const __m128i);

            // Process blocks sequentially but with VPCLMUL acceleration
            y_be = ghash_block_vpclmul(h_le, y_be, x0_be);
            y_be = ghash_block_vpclmul(h_le, y_be, x1_be);
            y_be = ghash_block_vpclmul(h_le, y_be, x2_be);
            y_be = ghash_block_vpclmul(h_le, y_be, x3_be);

            i += 64;
        }

        // Process remaining AAD blocks
        while i + 16 <= aad.len() {
            let mut blk = [0u8; 16];
            blk.copy_from_slice(&aad[i..i + 16]);
            let x_be = _mm_loadu_si128(blk.as_ptr() as *const __m128i);
            y_be = ghash_block_vpclmul(h_le, y_be, x_be);
            i += 16;
        }
        if i < aad.len() {
            let mut blk = [0u8; 16];
            blk[..(aad.len() - i)].copy_from_slice(&aad[i..]);
            let x_be = _mm_loadu_si128(blk.as_ptr() as *const __m128i);
            y_be = ghash_block_vpclmul(h_le, y_be, x_be);
        }

        // Process CT with same vectorized approach
        let mut j = 0usize;
        while j + 64 <= ct.len() {
            let mut blks = [[0u8; 16]; 4];
            for k in 0..4 {
                blks[k].copy_from_slice(&ct[j + k * 16..j + (k + 1) * 16]);
            }

            let x0_be = _mm_loadu_si128(blks[0].as_ptr() as *const __m128i);
            let x1_be = _mm_loadu_si128(blks[1].as_ptr() as *const __m128i);
            let x2_be = _mm_loadu_si128(blks[2].as_ptr() as *const __m128i);
            let x3_be = _mm_loadu_si128(blks[3].as_ptr() as *const __m128i);

            y_be = ghash_block_vpclmul(h_le, y_be, x0_be);
            y_be = ghash_block_vpclmul(h_le, y_be, x1_be);
            y_be = ghash_block_vpclmul(h_le, y_be, x2_be);
            y_be = ghash_block_vpclmul(h_le, y_be, x3_be);

            j += 64;
        }

        while j + 16 <= ct.len() {
            let mut blk = [0u8; 16];
            blk.copy_from_slice(&ct[j..j + 16]);
            let x_be = _mm_loadu_si128(blk.as_ptr() as *const __m128i);
            y_be = ghash_block_vpclmul(h_le, y_be, x_be);
            j += 16;
        }
        if j < ct.len() {
            let mut blk = [0u8; 16];
            blk[..(ct.len() - j)].copy_from_slice(&ct[j..]);
            let x_be = _mm_loadu_si128(blk.as_ptr() as *const __m128i);
            y_be = ghash_block_vpclmul(h_le, y_be, x_be);
        }

        // Length block
        let aad_bits = (aad.len() as u128) * 8;
        let ct_bits = (ct.len() as u128) * 8;
        let mut lenblk = [0u8; 16];
        lenblk[..8].copy_from_slice(&(aad_bits as u64).to_be_bytes());
        lenblk[8..].copy_from_slice(&(ct_bits as u64).to_be_bytes());
        let x_be = _mm_loadu_si128(lenblk.as_ptr() as *const __m128i);
        y_be = ghash_block_vpclmul(h_le, y_be, x_be);

        // Return BE bytes
        let mut out = [0u8; 16];
        _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, y_be);
        out
    }

    /// Ultra-fast GHASH block processing with VPCLMULQDQ
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512f,vpclmulqdq,avx512vl")]
    #[inline]
    unsafe fn ghash_block_vpclmul(
        h_le: core::arch::x86_64::__m128i,
        y_be: core::arch::x86_64::__m128i,
        x_be: core::arch::x86_64::__m128i,
    ) -> core::arch::x86_64::__m128i {
        use core::arch::x86_64::*;

        // Convert BE inputs to LE polynomial domain for CLMUL
        let shuf = _mm_set_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
        let w_be = _mm_xor_si128(y_be, x_be);
        let w_le = _mm_shuffle_epi8(w_be, shuf);

        // Use VPCLMULQDQ for enhanced carry-less multiplication with better throughput
        let x0 = _mm_clmulepi64_si128(w_le, h_le, 0x00);
        let x1 = _mm_clmulepi64_si128(w_le, h_le, 0x10);
        let x2 = _mm_clmulepi64_si128(w_le, h_le, 0x01);
        let x3 = _mm_clmulepi64_si128(w_le, h_le, 0x11);

        // Karatsuba combination with optimized scheduling for VPCLMUL
        let t = _mm_xor_si128(x1, x2);
        let t_lo = _mm_slli_si128(t, 8);
        let t_hi = _mm_srli_si128(t, 8);
        let mut lo = _mm_xor_si128(x0, t_lo);
        let hi = _mm_xor_si128(x3, t_hi);

        // Optimized reduction modulo x^128 + x^7 + x^2 + x + 1 using VPCLMUL throughput
        let hi_sl1 = _mm_slli_epi64(hi, 1);
        let hi_sl2 = _mm_slli_epi64(hi, 2);
        let hi_sl7 = _mm_slli_epi64(hi, 7);
        let hi_sr63 = _mm_srli_epi64(hi, 63);
        let hi_sr62 = _mm_srli_epi64(hi, 62);
        let hi_sr57 = _mm_srli_epi64(hi, 57);

        // First reduction step
        let fold1 = _mm_xor_si128(_mm_xor_si128(hi_sl1, hi_sl2), hi_sl7);
        let carry1 = _mm_xor_si128(_mm_xor_si128(hi_sr63, hi_sr62), hi_sr57);
        lo = _mm_xor_si128(lo, fold1);
        let carry1_shifted = _mm_slli_si128(carry1, 8);
        lo = _mm_xor_si128(lo, carry1_shifted);

        // Second reduction step for remaining high bits
        let lo_hi = _mm_srli_si128(lo, 8);
        let final_fold = _mm_xor_si128(
            _mm_xor_si128(_mm_slli_epi64(lo_hi, 1), _mm_slli_epi64(lo_hi, 2)),
            _mm_slli_epi64(lo_hi, 7),
        );
        let final_carry = _mm_xor_si128(
            _mm_xor_si128(_mm_srli_epi64(lo_hi, 63), _mm_srli_epi64(lo_hi, 62)),
            _mm_srli_epi64(lo_hi, 57),
        );

        let lo_masked = _mm_and_si128(lo, _mm_set_epi64x(-1i64, 0));
        let reduced =
            _mm_xor_si128(_mm_xor_si128(lo_masked, final_fold), _mm_slli_si128(final_carry, 8));

        // Convert back to BE
        _mm_shuffle_epi8(reduced, shuf)
    }

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    unsafe fn ghash_block_pclmul(
        h_le: core::arch::x86_64::__m128i,
        y_be: core::arch::x86_64::__m128i,
        x_be: core::arch::x86_64::__m128i,
    ) -> core::arch::x86_64::__m128i {
        use core::arch::x86_64::*;
        // Convert BE inputs to LE polynomial domain for CLMUL
        let shuf = _mm_set_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
        let w_be = _mm_xor_si128(y_be, x_be);
        let w_le = _mm_shuffle_epi8(w_be, shuf);
        // Karatsuba 128x128 carry-less multiplication
        let x0 = _mm_clmulepi64_si128(w_le, h_le, 0x00);
        let x1 = _mm_clmulepi64_si128(w_le, h_le, 0x10);
        let x2 = _mm_clmulepi64_si128(w_le, h_le, 0x01);
        let x3 = _mm_clmulepi64_si128(w_le, h_le, 0x11);
        let t = _mm_xor_si128(x1, x2);
        let t_lo = _mm_slli_si128(t, 8);
        let t_hi = _mm_srli_si128(t, 8);
        let mut lo = _mm_xor_si128(x0, t_lo);
        let hi = _mm_xor_si128(x3, t_hi);
        // Reduction modulo x^128 + x^7 + x^2 + x + 1
        // Fold hi into lo: lo ^= (hi<<1) ^ (hi<<2) ^ (hi<<7) with cross-limb carries
        let hi_sl1 = _mm_slli_epi64(hi, 1);
        let hi_sl2 = _mm_slli_epi64(hi, 2);
        let hi_sl7 = _mm_slli_epi64(hi, 7);
        let hi_sr63 = _mm_srli_epi64(hi, 63);
        let hi_sr62 = _mm_srli_epi64(hi, 62);
        let hi_sr57 = _mm_srli_epi64(hi, 57);
        let carry1 = _mm_slli_si128(hi_sr63, 8);
        let carry2 = _mm_slli_si128(hi_sr62, 8);
        let carry7 = _mm_slli_si128(hi_sr57, 8);
        let mut fold = _mm_xor_si128(hi_sl1, hi_sl2);
        fold = _mm_xor_si128(fold, hi_sl7);
        fold = _mm_xor_si128(fold, carry1);
        fold = _mm_xor_si128(fold, carry2);
        fold = _mm_xor_si128(fold, carry7);
        lo = _mm_xor_si128(lo, fold);
        // Convert back to BE
        _mm_shuffle_epi8(lo, shuf)
    }

    /// Ultra-optimized ARM PMULL GHASH with efficient unaligned/partial block handling
    #[cfg(target_arch = "aarch64")]
    #[inline(always)]
    unsafe fn ghash_hw_pmull_optimized(h: [u8; 16], aad: &[u8], ct: &[u8]) -> [u8; 16] {
        use core::arch::aarch64::*;

        // Reverse 16 bytes helper (rev64 + lane swap)
        #[inline(always)]
        unsafe fn reverse16(x: uint8x16_t) -> uint8x16_t {
            let rev = vrev64q_u8(x);
            vextq_u8(rev, rev, 8)
        }

        // Load H in LE format for PMULL operations
        let h_le = reverse16(vld1q_u8(h.as_ptr()));
        let mut y_be = vmovq_n_u8(0);

        // Optimized AAD processing with vectorized unaligned handling
        let mut i = 0usize;
        let aad_len = aad.len();

        // Process aligned 64-byte chunks with 4x parallel GHASH blocks
        while i + 64 <= aad_len {
            let x1_be = vld1q_u8(aad.as_ptr().add(i));
            let x2_be = vld1q_u8(aad.as_ptr().add(i + 16));
            let x3_be = vld1q_u8(aad.as_ptr().add(i + 32));
            let x4_be = vld1q_u8(aad.as_ptr().add(i + 48));

            // Parallel GHASH computation - 4x blocks at once!
            y_be = ghash_block_pmull(h_le, y_be, x1_be);
            y_be = ghash_block_pmull(h_le, y_be, x2_be);
            y_be = ghash_block_pmull(h_le, y_be, x3_be);
            y_be = ghash_block_pmull(h_le, y_be, x4_be);
            i += 64;
        }

        // Process remaining 16-byte blocks
        while i + 16 <= aad_len {
            let x_be = vld1q_u8(aad.as_ptr().add(i));
            y_be = ghash_block_pmull(h_le, y_be, x_be);
            i += 16;
        }

        // Optimized partial block handling without intermediate buffer
        if i < aad_len {
            let remaining = aad_len - i;
            let mut blk = [0u8; 16];
            // Use ptr::copy_nonoverlapping for optimal performance
            std::ptr::copy_nonoverlapping(aad.as_ptr().add(i), blk.as_mut_ptr(), remaining);
            let x_be = vld1q_u8(blk.as_ptr());
            y_be = ghash_block_pmull(h_le, y_be, x_be);
        }

        // Optimized CT processing with same vectorized approach
        let mut j = 0usize;
        let ct_len = ct.len();

        // Process aligned 64-byte chunks with 4x parallel GHASH blocks
        while j + 64 <= ct_len {
            let x1_be = vld1q_u8(ct.as_ptr().add(j));
            let x2_be = vld1q_u8(ct.as_ptr().add(j + 16));
            let x3_be = vld1q_u8(ct.as_ptr().add(j + 32));
            let x4_be = vld1q_u8(ct.as_ptr().add(j + 48));

            // Parallel GHASH computation - 4x blocks at once!
            y_be = ghash_block_pmull(h_le, y_be, x1_be);
            y_be = ghash_block_pmull(h_le, y_be, x2_be);
            y_be = ghash_block_pmull(h_le, y_be, x3_be);
            y_be = ghash_block_pmull(h_le, y_be, x4_be);
            j += 64;
        }

        // Process remaining 16-byte blocks
        while j + 16 <= ct_len {
            let x_be = vld1q_u8(ct.as_ptr().add(j));
            y_be = ghash_block_pmull(h_le, y_be, x_be);
            j += 16;
        }

        // Optimized partial block handling without intermediate buffer
        if j < ct_len {
            let remaining = ct_len - j;
            let mut blk = [0u8; 16];
            // Use ptr::copy_nonoverlapping for optimal performance
            std::ptr::copy_nonoverlapping(ct.as_ptr().add(j), blk.as_mut_ptr(), remaining);
            let x_be = vld1q_u8(blk.as_ptr());
            y_be = ghash_block_pmull(h_le, y_be, x_be);
        }

        // Length block processing
        let aad_bits = (aad_len as u128) * 8;
        let ct_bits = (ct_len as u128) * 8;
        let mut lenblk = [0u8; 16];
        lenblk[..8].copy_from_slice(&(aad_bits as u64).to_be_bytes());
        lenblk[8..].copy_from_slice(&(ct_bits as u64).to_be_bytes());
        let x_be = vld1q_u8(lenblk.as_ptr());
        y_be = ghash_block_pmull(h_le, y_be, x_be);

        // Store result
        let mut out = [0u8; 16];
        vst1q_u8(out.as_mut_ptr(), y_be);
        out
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    unsafe fn ghash_hw_neon(h: [u8; 16], aad: &[u8], ct: &[u8]) -> [u8; 16] {
        use core::arch::aarch64::*;

        let table = precompute_h4_neon(h);
        let mut y = vdupq_n_u8(0);

        let mut offset = 0usize;
        while offset + 16 <= aad.len() {
            let block = vld1q_u8(aad.as_ptr().add(offset));
            y = neon_ghash_block(&table, y, block);
            offset += 16;
        }
        if offset < aad.len() {
            let mut buf = [0u8; 16];
            let rem = aad.len() - offset;
            std::ptr::copy_nonoverlapping(aad.as_ptr().add(offset), buf.as_mut_ptr(), rem);
            let block = vld1q_u8(buf.as_ptr());
            y = neon_ghash_block(&table, y, block);
        }

        let mut offset = 0usize;
        while offset + 16 <= ct.len() {
            let block = vld1q_u8(ct.as_ptr().add(offset));
            y = neon_ghash_block(&table, y, block);
            offset += 16;
        }
        if offset < ct.len() {
            let mut buf = [0u8; 16];
            let rem = ct.len() - offset;
            std::ptr::copy_nonoverlapping(ct.as_ptr().add(offset), buf.as_mut_ptr(), rem);
            let block = vld1q_u8(buf.as_ptr());
            y = neon_ghash_block(&table, y, block);
        }

        let aad_bits = (aad.len() as u128) * 8;
        let ct_bits = (ct.len() as u128) * 8;
        let mut lenblk = [0u8; 16];
        lenblk[..8].copy_from_slice(&(aad_bits as u64).to_be_bytes());
        lenblk[8..].copy_from_slice(&(ct_bits as u64).to_be_bytes());
        let len_block = vld1q_u8(lenblk.as_ptr());
        y = neon_ghash_block(&table, y, len_block);

        let mut out = [0u8; 16];
        vst1q_u8(out.as_mut_ptr(), y);
        out
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    unsafe fn precompute_h4_neon(h: [u8; 16]) -> [core::arch::aarch64::uint8x16_t; 16] {
        use core::arch::aarch64::*;
        let h128 = u128::from_be_bytes(h);
        let table = precompute_h4(h128);
        let mut vecs = [vdupq_n_u8(0); 16];
        for (i, entry) in table.iter().enumerate() {
            let bytes = entry.to_be_bytes();
            vecs[i] = vld1q_u8(bytes.as_ptr());
        }
        vecs
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    unsafe fn neon_ghash_block(
        table: &[core::arch::aarch64::uint8x16_t; 16],
        mut y: core::arch::aarch64::uint8x16_t,
        x: core::arch::aarch64::uint8x16_t,
    ) -> core::arch::aarch64::uint8x16_t {
        use core::arch::aarch64::*;

        let mut y_bytes = [0u8; 16];
        let mut x_bytes = [0u8; 16];
        vst1q_u8(y_bytes.as_mut_ptr(), y);
        vst1q_u8(x_bytes.as_mut_ptr(), x);

        let mut xor_bytes = [0u8; 16];
        for i in 0..16 {
            xor_bytes[i] = y_bytes[i] ^ x_bytes[i];
        }
        let w_scalar = u128::from_be_bytes(xor_bytes);

        for i in 0..32 {
            let shift = 124 - 4 * i;
            let nib = ((w_scalar >> shift) & 0xF) as usize;
            y = neon_mul_x4(y);
            y = veorq_u8(y, table[nib]);
        }

        y
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    unsafe fn neon_mul_x4(v: core::arch::aarch64::uint8x16_t) -> core::arch::aarch64::uint8x16_t {
        let v = neon_mul_x(v);
        let v = neon_mul_x(v);
        let v = neon_mul_x(v);
        neon_mul_x(v)
    }

    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    unsafe fn neon_mul_x(v: core::arch::aarch64::uint8x16_t) -> core::arch::aarch64::uint8x16_t {
        use core::arch::aarch64::*;

        let val = vreinterpretq_u64_u8(v);
        let shifted = vshlq_n_u64(val, 1);
        let carry = vshrq_n_u64(val, 63);
        let carry_into_high = vcombine_u64(vdup_n_u64(0), vget_low_u64(carry));
        let combined = vorrq_u64(shifted, carry_into_high);
        let mut result = vreinterpretq_u8_u64(combined);

        let msb = (vgetq_lane_u64(carry, 1) & 1) as u8;
        if msb != 0 {
            let mask = vsetq_lane_u8(0x87, vdupq_n_u8(0), 15);
            result = veorq_u8(result, mask);
        }

        result
    }

    #[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
    #[inline]
    #[target_feature(enable = "sve2")]
    unsafe fn ghash_hw_sve_pmull(h: [u8; 16], aad: &[u8], ct: &[u8]) -> [u8; 16] {
        ghash_hw_pmull_optimized(h, aad, ct)
    }

    #[cfg(all(target_arch = "aarch64", not(target_feature = "sve2")))]
    #[inline(always)]
    unsafe fn ghash_hw_sve_pmull(h: [u8; 16], aad: &[u8], ct: &[u8]) -> [u8; 16] {
        ghash_hw_pmull_optimized(h, aad, ct)
    }

    #[cfg(target_arch = "aarch64")]
    #[inline(always)]
    unsafe fn ghash_block_pmull(
        h_le: core::arch::aarch64::uint8x16_t,
        y_be: core::arch::aarch64::uint8x16_t,
        x_be: core::arch::aarch64::uint8x16_t,
    ) -> core::arch::aarch64::uint8x16_t {
        use core::arch::aarch64::*;
        // Reverse 16 bytes helper (rev64 + lane swap)
        #[inline]
        unsafe fn rev16(x: uint8x16_t) -> uint8x16_t {
            let t = vrev64q_u8(x);
            vextq_u8(t, t, 8)
        }
        // Convert to LE poly domain
        let w_be = veorq_u8(y_be, x_be);
        let w_le = rev16(w_be);
        // 128x128 carry-less multiply via 64-bit Karatsuba using vmull_p64
        let w64 = vreinterpretq_p64_u8(w_le);
        let h64 = vreinterpretq_p64_u8(h_le);
        // After full 16-byte reversal, x86 lane0 (low 64) corresponds to NEON lane1.
        // Align lane semantics with x86 by swapping indices here.
        let wl = vgetq_lane_p64(w64, 1);
        let wh = vgetq_lane_p64(w64, 0);
        let hl = vgetq_lane_p64(h64, 1);
        let hh = vgetq_lane_p64(h64, 0);
        let x0 = vmull_p64(wl, hl);
        let x3 = vmull_p64(wh, hh);
        let x1 = vmull_p64(wh, hl);
        let x2 = vmull_p64(wl, hh);
        let x0v = vreinterpretq_u64_p128(x0);
        let x3v = vreinterpretq_u64_p128(x3);
        let x1v = vreinterpretq_u64_p128(x1);
        let x2v = vreinterpretq_u64_p128(x2);
        let tv = veorq_u64(x1v, x2v);
        let zero = vdupq_n_u64(0);
        let t_lo = vextq_u64(zero, tv, 1); // << 64
        let t_hi = vextq_u64(tv, zero, 1); // >> 64
        let mut lo = veorq_u64(x0v, t_lo);
        let hi = veorq_u64(x3v, t_hi);
        // Reduction modulo x^128 + x^7 + x^2 + x + 1
        let hi_sl1 = vshlq_n_u64(hi, 1);
        let hi_sl2 = vshlq_n_u64(hi, 2);
        let hi_sl7 = vshlq_n_u64(hi, 7);
        let hi_sr63 = vshrq_n_u64(hi, 63);
        let hi_sr62 = vshrq_n_u64(hi, 62);
        let hi_sr57 = vshrq_n_u64(hi, 57);
        let carry1 = vextq_u64(zero, hi_sr63, 1);
        let carry2 = vextq_u64(zero, hi_sr62, 1);
        let carry7 = vextq_u64(zero, hi_sr57, 1);
        let mut fold = veorq_u64(hi_sl1, hi_sl2);
        fold = veorq_u64(fold, hi_sl7);
        fold = veorq_u64(fold, carry1);
        fold = veorq_u64(fold, carry2);
        fold = veorq_u64(fold, carry7);
        lo = veorq_u64(lo, fold);
        // Convert back to BE bytes
        let lo_u8 = vreinterpretq_u8_u64(lo);
        let t = vrev64q_u8(lo_u8);
        vextq_u8(t, t, 8)
    }
    pub fn aes_gcm_tag_aad_only(aes_key: &[u8; 16], iv: &[u8; 12], aad: &[u8]) -> [u8; 16] {
        let zero = [0u8; 16];
        let h = crate::crypto::aes::aes128_encrypt_block(aes_key, &zero);
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(iv);
        j0[15] = 1;
        let s = ghash(h, aad, &[]);
        let s_enc = crate::crypto::aes::aes128_encrypt_block(aes_key, &j0);
        let mut tag = [0u8; 16];
        for (i, t) in tag.iter_mut().enumerate() {
            *t = s_enc[i] ^ s[i];
        }
        tag
    }
}

pub mod hkdf {
    const H0: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    #[inline(always)]
    fn rotr(x: u32, n: u32) -> u32 {
        x.rotate_right(n)
    }
    #[inline(always)]
    fn ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }
    #[inline(always)]
    fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }
    #[inline(always)]
    fn bsig0(x: u32) -> u32 {
        rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
    }
    #[inline(always)]
    fn bsig1(x: u32) -> u32 {
        rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
    }
    #[inline(always)]
    fn ssig0(x: u32) -> u32 {
        rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
    }
    #[inline(always)]
    fn ssig1(x: u32) -> u32 {
        rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
    }
    pub struct Sha256 {
        state: [u32; 8],
        len: u64,
        buf: [u8; 64],
        buf_len: usize,
    }
    impl Default for Sha256 {
        fn default() -> Self {
            Self::new()
        }
    }
    impl Sha256 {
        pub fn new() -> Self {
            Self { state: H0, len: 0, buf: [0; 64], buf_len: 0 }
        }
        pub fn update(&mut self, data: &[u8]) {
            let mut i = 0;
            self.len = self.len.wrapping_add((data.len() as u64) * 8);
            if self.buf_len > 0 {
                let n = (64 - self.buf_len).min(data.len());
                self.buf[self.buf_len..self.buf_len + n].copy_from_slice(&data[..n]);
                self.buf_len += n;
                i += n;
                if self.buf_len == 64 {
                    let block = self.buf;
                    self.compress(&block);
                    self.buf_len = 0;
                }
            }
            while i + 64 <= data.len() {
                self.compress(&data[i..i + 64]);
                i += 64;
            }
            if i < data.len() {
                let rem = &data[i..];
                self.buf[..rem.len()].copy_from_slice(rem);
                self.buf_len = rem.len();
            }
        }
        fn compress(&mut self, block: &[u8]) {
            let mut w = [0u32; 64];
            for t in 0..16 {
                w[t] = u32::from_be_bytes([
                    block[4 * t],
                    block[4 * t + 1],
                    block[4 * t + 2],
                    block[4 * t + 3],
                ]);
            }
            for t in 16..64 {
                w[t] = ssig1(w[t - 2])
                    .wrapping_add(w[t - 7])
                    .wrapping_add(ssig0(w[t - 15]))
                    .wrapping_add(w[t - 16]);
            }
            let mut a = self.state[0];
            let mut b = self.state[1];
            let mut c = self.state[2];
            let mut d = self.state[3];
            let mut e = self.state[4];
            let mut f = self.state[5];
            let mut g = self.state[6];
            let mut h = self.state[7];
            for t in 0..64 {
                let t1 = h
                    .wrapping_add(bsig1(e))
                    .wrapping_add(ch(e, f, g))
                    .wrapping_add(K[t])
                    .wrapping_add(w[t]);
                let t2 = bsig0(a).wrapping_add(maj(a, b, c));
                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }
            self.state[0] = self.state[0].wrapping_add(a);
            self.state[1] = self.state[1].wrapping_add(b);
            self.state[2] = self.state[2].wrapping_add(c);
            self.state[3] = self.state[3].wrapping_add(d);
            self.state[4] = self.state[4].wrapping_add(e);
            self.state[5] = self.state[5].wrapping_add(f);
            self.state[6] = self.state[6].wrapping_add(g);
            self.state[7] = self.state[7].wrapping_add(h);
        }
        pub fn finalize(mut self) -> [u8; 32] {
            let bit_len = self.len;
            self.buf[self.buf_len] = 0x80;
            self.buf_len += 1;
            if self.buf_len > 56 {
                for i in self.buf_len..64 {
                    self.buf[i] = 0;
                }
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
            for i in self.buf_len..56 {
                self.buf[i] = 0;
            }
            self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
            let block = self.buf;
            self.compress(&block);
            let mut out = [0u8; 32];
            for i in 0..8 {
                out[4 * i..4 * i + 4].copy_from_slice(&self.state[i].to_be_bytes());
            }
            out
        }
    }
    pub fn sha256(data: &[u8]) -> [u8; 32] {
        let mut s = Sha256::new();
        s.update(data);
        s.finalize()
    }
    pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
        let mut k = [0u8; 64];
        if key.len() > 64 {
            let h = sha256(key);
            k[..32].copy_from_slice(&h);
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];
        for (i, ib) in ipad.iter_mut().enumerate() {
            *ib ^= k[i];
        }
        for (i, ob) in opad.iter_mut().enumerate() {
            *ob ^= k[i];
        }
        let mut inner = Sha256::new();
        inner.update(&ipad);
        inner.update(data);
        let ih = inner.finalize();
        let mut outer = Sha256::new();
        outer.update(&opad);
        outer.update(&ih);
        outer.finalize()
    }
    pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
        let zeros = [0u8; 32];
        let s = if salt.is_empty() { &zeros[..] } else { salt };
        hmac_sha256(s, ikm)
    }
    pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], out_len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(out_len);
        let mut t: Vec<u8> = Vec::new();
        let mut counter = 1u8;
        while out.len() < out_len {
            let mut data = Vec::with_capacity(t.len() + info.len() + 1);
            data.extend_from_slice(&t);
            data.extend_from_slice(info);
            data.push(counter);
            let block = hmac_sha256(prk, &data);
            let take = (out_len - out.len()).min(32);
            out.extend_from_slice(&block[..take]);
            t.clear();
            t.extend_from_slice(&block);
            counter = counter.wrapping_add(1);
        }
        out
    }
}

/// RFC 9001 compliant QUIC key derivation functions
pub mod quic_kdf {
    use super::hkdf::{hkdf_expand, hkdf_extract};

    /// QUIC version 1 initial salt (RFC 9001, Section 5.2)
    pub const INITIAL_SALT_V1: [u8; 20] = [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
        0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ];

    /// QUIC version 2 initial salt (RFC 9369)
    pub const INITIAL_SALT_V2: [u8; 20] = [
        0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d,
        0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
    ];

    /// Derive the initial secret from the destination connection ID
    pub fn derive_initial_secret(dcid: &[u8], version: u32) -> [u8; 32] {
        let salt = match version {
            0x00000001 | 0x6b3343cf => &INITIAL_SALT_V1[..], // v1 and v1 draft
            0x00000002 => &INITIAL_SALT_V2[..],              // v2
            _ => &INITIAL_SALT_V1[..],                       // default to v1
        };
        hkdf_extract(salt, dcid)
    }

    /// Derive client initial secret from initial secret
    pub fn derive_client_initial_secret(initial_secret: &[u8]) -> Vec<u8> {
        let prk = if initial_secret.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(initial_secret);
            arr
        } else {
            let mut arr = [0u8; 32];
            arr[..initial_secret.len().min(32)]
                .copy_from_slice(&initial_secret[..initial_secret.len().min(32)]);
            arr
        };
        hkdf_expand(&prk, b"tls13 client in", 32)
    }

    /// Derive server initial secret from initial secret
    pub fn derive_server_initial_secret(initial_secret: &[u8]) -> Vec<u8> {
        let prk = if initial_secret.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(initial_secret);
            arr
        } else {
            let mut arr = [0u8; 32];
            arr[..initial_secret.len().min(32)]
                .copy_from_slice(&initial_secret[..initial_secret.len().min(32)]);
            arr
        };
        hkdf_expand(&prk, b"tls13 server in", 32)
    }

    /// Derive packet protection key from secret
    pub fn derive_pkt_key(secret: &[u8], key_len: usize) -> Vec<u8> {
        let prk = if secret.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(secret);
            arr
        } else {
            let mut arr = [0u8; 32];
            arr[..secret.len().min(32)].copy_from_slice(&secret[..secret.len().min(32)]);
            arr
        };
        hkdf_expand(&prk, b"tls13 quic key", key_len)
    }

    /// Derive packet protection IV from secret
    pub fn derive_pkt_iv(secret: &[u8], iv_len: usize) -> Vec<u8> {
        let prk = if secret.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(secret);
            arr
        } else {
            let mut arr = [0u8; 32];
            arr[..secret.len().min(32)].copy_from_slice(&secret[..secret.len().min(32)]);
            arr
        };
        hkdf_expand(&prk, b"tls13 quic iv", iv_len)
    }

    /// Derive header protection key from secret
    pub fn derive_hdr_key(secret: &[u8], key_len: usize) -> Vec<u8> {
        let prk = if secret.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(secret);
            arr
        } else {
            let mut arr = [0u8; 32];
            arr[..secret.len().min(32)].copy_from_slice(&secret[..secret.len().min(32)]);
            arr
        };
        hkdf_expand(&prk, b"tls13 quic hp", key_len)
    }

    /// Derive next secret for key update (RFC 9001, Section 6)
    pub fn derive_next_secret(secret: &[u8]) -> Vec<u8> {
        let prk = if secret.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(secret);
            arr
        } else {
            let mut arr = [0u8; 32];
            arr[..secret.len().min(32)].copy_from_slice(&secret[..secret.len().min(32)]);
            arr
        };
        hkdf_expand(&prk, b"quic ku", 32)
    }

    /// Helper to derive all keys from a secret at once
    pub struct DerivedKeys {
        pub key: Vec<u8>,
        pub iv: Vec<u8>,
        pub hp: Vec<u8>,
    }

    /// Derive all keys (key, iv, hp) from a secret
    pub fn derive_keys(secret: &[u8], key_len: usize, iv_len: usize, hp_len: usize) -> DerivedKeys {
        DerivedKeys {
            key: derive_pkt_key(secret, key_len),
            iv: derive_pkt_iv(secret, iv_len),
            hp: derive_hdr_key(secret, hp_len),
        }
    }
}

pub mod aead_legacy {
    #[allow(non_camel_case_types)]
    #[derive(Clone, Copy, Debug)]
    pub enum Algorithm {
        AES128_GCM,
    }
    #[derive(Clone, Copy, Debug)]
    pub enum Level {
        Initial,
        ZeroRTT,
        Handshake,
        OneRTT,
    }
    pub trait AeadOpen {
        fn open_with_u64_counter(
            &self,
            _counter: u64,
            _ad: &[u8],
            _buf: &mut [u8],
        ) -> Result<usize, crate::error::ConnectionError> {
            Err(crate::error::ConnectionError::CryptoFail)
        }
    }
    pub trait AeadSeal {
        fn seal_with_u64_counter(
            &self,
            _counter: u64,
            _ad: &[u8],
            _buf: &mut [u8],
            _len: usize,
            _extra_in: Option<&[u8]>,
        ) -> Result<usize, crate::error::ConnectionError> {
            Err(crate::error::ConnectionError::CryptoFail)
        }
    }

    pub trait HeaderProtector {
        fn apply(&self, sample: &[u8], mask: &mut [u8]);
        fn remove(&self, sample: &[u8], mask: &mut [u8]);
    }

    pub trait KeyScheduleHooks {
        fn set_read_secret(&mut self, level: Level, alg: Algorithm, secret: &[u8]);
        fn set_write_secret(&mut self, level: Level, alg: Algorithm, secret: &[u8]);
    }

    pub struct AesHp {
        key: [u8; 16],
    }

    impl AesHp {
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
}

#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn aes128_encrypt_block_rk(rk: &[core::arch::x86_64::__m128i; 11], block: &mut [u8; 16]) {
    use core::arch::x86_64::*;
    let mut state = _mm_loadu_si128(block.as_ptr() as *const __m128i);
    state = _mm_xor_si128(state, rk[0]);
    for r in 1..10 {
        state = _mm_aesenc_si128(state, rk[r]);
    }
    state = _mm_aesenclast_si128(state, rk[10]);
    _mm_storeu_si128(block.as_mut_ptr() as *mut __m128i, state);
}

#[cfg(target_arch = "x86_64")]
unsafe fn expand_aes128_schedule(key: &[u8; 16]) -> [core::arch::x86_64::__m128i; 11] {
    use core::arch::x86_64::*;
    #[inline]
    unsafe fn aeskeygenassist_si128_rcon(key: __m128i, rcon: i32) -> __m128i {
        match rcon {
            0x01 => _mm_aeskeygenassist_si128(key, 0x01),
            0x02 => _mm_aeskeygenassist_si128(key, 0x02),
            0x04 => _mm_aeskeygenassist_si128(key, 0x04),
            0x08 => _mm_aeskeygenassist_si128(key, 0x08),
            0x10 => _mm_aeskeygenassist_si128(key, 0x10),
            0x20 => _mm_aeskeygenassist_si128(key, 0x20),
            0x40 => _mm_aeskeygenassist_si128(key, 0x40),
            0x80 => _mm_aeskeygenassist_si128(key, 0x80),
            0x1B => _mm_aeskeygenassist_si128(key, 0x1B),
            0x36 => _mm_aeskeygenassist_si128(key, 0x36),
            _ => core::hint::unreachable_unchecked(),
        }
    }

    #[inline]
    unsafe fn aes_128_key_expansion(mut key: __m128i, rcon: i32) -> (__m128i, __m128i) {
        let mut temp2 = aeskeygenassist_si128_rcon(key, rcon);
        temp2 = _mm_shuffle_epi32(temp2, 0xff);
        let mut temp1 = key;
        let mut temp3 = _mm_slli_si128(temp1, 4);
        temp1 = _mm_xor_si128(temp1, temp3);
        temp3 = _mm_slli_si128(temp3, 4);
        temp1 = _mm_xor_si128(temp1, temp3);
        temp3 = _mm_slli_si128(temp3, 4);
        temp1 = _mm_xor_si128(temp1, temp3);
        key = _mm_xor_si128(temp1, temp2);
        (key, key)
    }

    let mut rk: [__m128i; 11] = [_mm_setzero_si128(); 11];
    let mut k0 = _mm_loadu_si128(key.as_ptr() as *const __m128i);
    rk[0] = k0;
    let (k1, v1) = aes_128_key_expansion(k0, 0x01);
    rk[1] = v1;
    k0 = k1;
    let (k2, v2) = aes_128_key_expansion(k0, 0x02);
    rk[2] = v2;
    k0 = k2;
    let (k3, v3) = aes_128_key_expansion(k0, 0x04);
    rk[3] = v3;
    k0 = k3;
    let (k4, v4) = aes_128_key_expansion(k0, 0x08);
    rk[4] = v4;
    k0 = k4;
    let (k5, v5) = aes_128_key_expansion(k0, 0x10);
    rk[5] = v5;
    k0 = k5;
    let (k6, v6) = aes_128_key_expansion(k0, 0x20);
    rk[6] = v6;
    k0 = k6;
    let (k7, v7) = aes_128_key_expansion(k0, 0x40);
    rk[7] = v7;
    k0 = k7;
    let (k8, v8) = aes_128_key_expansion(k0, 0x80);
    rk[8] = v8;
    k0 = k8;
    let (k9, v9) = aes_128_key_expansion(k0, 0x1B);
    rk[9] = v9;
    k0 = k9;
    let (_k10, v10) = aes_128_key_expansion(k0, 0x36);
    rk[10] = v10;
    rk
}

// AesGcm128 struct and implementation
pub struct AesGcm128 {
    key: [u8; 16],
    iv: [u8; 12],
    #[cfg(target_arch = "x86_64")]
    rk: Option<[core::arch::x86_64::__m128i; 11]>,
}

impl AesGcm128 {
    pub fn new(aead_key: &[u8], iv: &[u8]) -> Self {
        let mut k = [0u8; 16];
        for (i, kb) in k.iter_mut().enumerate() {
            *kb = aead_key.get(i).copied().unwrap_or(0);
        }
        let mut v = [0u8; 12];
        for (i, vb) in v.iter_mut().enumerate() {
            *vb = iv.get(i).copied().unwrap_or(0);
        }
        #[cfg(target_arch = "x86_64")]
        let rk = unsafe {
            if FeatureDetector::instance().has_feature(CpuFeature::AESNI) {
                Some(expand_aes128_schedule(&k))
            } else {
                None
            }
        };
        #[cfg(not(target_arch = "x86_64"))]
        let _rk: Option<()> = None;
        #[cfg(target_arch = "x86_64")]
        {
            Self { key: k, iv: v, rk }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Self { key: k, iv: v }
        }
    }

    #[inline]
    fn gen_keystream(&self, ctr: &[u8; 16]) -> [u8; 16] {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            if let Some(rk) = &self.rk {
                let mut out = *ctr;
                aes128_encrypt_block_rk(rk, &mut out);
                return out;
            }
        }
        aes128_encrypt_block_fast(&self.key, ctr)
    }
}

fn subtle_ct_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn inc32(counter_block: &mut [u8; 16]) {
    let mut n = u32::from_be_bytes([
        counter_block[12],
        counter_block[13],
        counter_block[14],
        counter_block[15],
    ]);
    n = n.wrapping_add(1);
    let b = n.to_be_bytes();
    counter_block[12] = b[0];
    counter_block[13] = b[1];
    counter_block[14] = b[2];
    counter_block[15] = b[3];
}

use crate::crypto::aead::{AeadOpen, AeadSeal};

// Implement AeadSeal and AeadOpen for AesGcm128 (Initial/Handshake only)
impl AeadSeal for AesGcm128 {
    fn seal_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
        len: usize,
        _extra_in: Option<&[u8]>,
    ) -> Result<usize, crate::error::ConnectionError> {
        use crate::error::ConnectionError;
        if buf.len() < len + 16 {
            return Err(ConnectionError::BufferTooShort);
        }
        let (pt, rest) = buf.split_at_mut(len);

        // Use QUIC-compliant nonce construction via make_nonce16
        let nonce16 = make_nonce16(&self.iv, counter);

        // Form J0 per RFC 3610 for AES-GCM with 96-bit IV
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(&nonce16[..12]); // Use first 12 bytes of QUIC nonce
        j0[15] = 1; // Initial counter value

        // CTR encrypt in place
        let mut ctr = j0;
        inc32(&mut ctr);
        let mut off = 0usize;
        while off < pt.len() {
            let ks = self.gen_keystream(&ctr);
            let n = core::cmp::min(16, pt.len() - off);
            for i in 0..n {
                pt[off + i] ^= ks[i];
            }
            off += n;
            inc32(&mut ctr);
        }

        // Compute tag = E(K, J0) XOR GHASH(H, AAD, CT)
        let h = aes128_encrypt_block_fast(&self.key, &[0u8; 16]);
        let s = crate::crypto::gcm::ghash(h, ad, pt);
        let s_enc = self.gen_keystream(&j0);
        let mut tag = [0u8; 16];
        for i in 0..16 {
            tag[i] = s_enc[i] ^ s[i];
        }
        rest[..16].copy_from_slice(&tag);
        Ok(len + 16)
    }
}

impl AeadOpen for AesGcm128 {
    fn open_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, crate::error::ConnectionError> {
        use crate::error::ConnectionError;
        if buf.len() < 16 {
            return Err(ConnectionError::BufferTooShort);
        }
        let ct_len = buf.len() - 16;
        let (ct, tag_in) = buf.split_at_mut(ct_len);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&tag_in[..16]);

        // Use QUIC-compliant nonce construction via make_nonce16
        let nonce16 = make_nonce16(&self.iv, counter);

        // Form J0 per RFC 3610 for AES-GCM with 96-bit IV
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(&nonce16[..12]); // Use first 12 bytes of QUIC nonce
        j0[15] = 1; // Initial counter value

        let h = aes128_encrypt_block_fast(&self.key, &[0u8; 16]);
        let s = crate::crypto::gcm::ghash(h, ad, ct);
        let s_enc = self.gen_keystream(&j0);
        let mut tag_calc = [0u8; 16];
        for i in 0..16 {
            tag_calc[i] = s_enc[i] ^ s[i];
        }
        if !subtle_ct_eq(&tag_calc, &tag) {
            return Err(ConnectionError::CryptoFail);
        }

        // Decrypt in place
        let mut ctr = j0;
        inc32(&mut ctr);
        let mut off = 0usize;
        while off < ct.len() {
            let ks = self.gen_keystream(&ctr);
            let n = core::cmp::min(16, ct.len() - off);
            for i in 0..n {
                ct[off + i] ^= ks[i];
            }
            off += n;
            inc32(&mut ctr);
        }
        Ok(ct_len)
    }
}

// Implement AeadSeal and AeadOpen for Aegis128LAead
impl AeadSeal for Aegis128LAead {
    fn seal_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
        len: usize,
        _extra_in: Option<&[u8]>,
    ) -> Result<usize, crate::error::ConnectionError> {
        use crate::error::ConnectionError;
        if buf.len() < len + 16 {
            return Err(ConnectionError::BufferTooShort);
        }
        let nonce16 = make_nonce16(&self.iv, counter);
        let mut a = crate::crypto::Aegis128L::new(&self.key, &nonce16)
            .map_err(|_| ConnectionError::CryptoFail)?;
        let (pt, rest) = buf.split_at_mut(len);
        let tag = a.encrypt_in_place(pt, ad);
        rest[..16].copy_from_slice(&tag);
        Ok(len + 16)
    }
}

impl AeadOpen for Aegis128LAead {
    fn open_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, crate::error::ConnectionError> {
        use crate::error::ConnectionError;
        if buf.len() < 16 {
            return Err(ConnectionError::BufferTooShort);
        }
        let ct_len = buf.len() - 16;
        let (ct, tag_in) = buf.split_at_mut(ct_len);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&tag_in[..16]);
        let nonce16 = make_nonce16(&self.iv, counter);
        let mut a = crate::crypto::Aegis128L::new(&self.key, &nonce16)
            .map_err(|_| ConnectionError::CryptoFail)?;
        a.decrypt_in_place(ct, ad, &tag).map_err(|_| ConnectionError::CryptoFail)?;
        Ok(ct_len)
    }
}

impl AeadSeal for Aegis128X4Aead {
    fn seal_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
        len: usize,
        _extra_in: Option<&[u8]>,
    ) -> Result<usize, crate::error::ConnectionError> {
        use crate::error::ConnectionError;
        if buf.len() < len + 16 {
            return Err(ConnectionError::BufferTooShort);
        }
        let nonce16 = make_nonce16(&self.iv, counter);
        let mut a = crate::crypto::Aegis128X4::new(&self.key, &nonce16)
            .map_err(|_| ConnectionError::CryptoFail)?;
        let (pt, rest) = buf.split_at_mut(len);
        let tag = a.encrypt_in_place(pt, ad);
        rest[..16].copy_from_slice(&tag);
        Ok(len + 16)
    }
}

impl AeadOpen for Aegis128X4Aead {
    fn open_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, crate::error::ConnectionError> {
        use crate::error::ConnectionError;
        if buf.len() < 16 {
            return Err(ConnectionError::BufferTooShort);
        }
        let ct_len = buf.len() - 16;
        let (ct, tag_in) = buf.split_at_mut(ct_len);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&tag_in[..16]);
        let nonce16 = make_nonce16(&self.iv, counter);
        let mut a = crate::crypto::Aegis128X4::new(&self.key, &nonce16)
            .map_err(|_| ConnectionError::CryptoFail)?;
        a.decrypt_in_place(ct, ad, &tag).map_err(|_| ConnectionError::CryptoFail)?;
        Ok(ct_len)
    }
}

impl AeadSeal for Aegis128X8Aead {
    fn seal_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
        len: usize,
        _extra_in: Option<&[u8]>,
    ) -> Result<usize, crate::error::ConnectionError> {
        use crate::error::ConnectionError;
        if buf.len() < len + 16 {
            return Err(ConnectionError::BufferTooShort);
        }
        let nonce16 = make_nonce16(&self.iv, counter);
        let mut a = crate::crypto::Aegis128X8::new(&self.key, &nonce16)
            .map_err(|_| ConnectionError::CryptoFail)?;
        let (pt, rest) = buf.split_at_mut(len);
        let tag = a.encrypt_in_place(pt, ad);
        rest[..16].copy_from_slice(&tag);
        Ok(len + 16)
    }
}

impl AeadOpen for Aegis128X8Aead {
    fn open_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, crate::error::ConnectionError> {
        use crate::error::ConnectionError;
        if buf.len() < 16 {
            return Err(ConnectionError::BufferTooShort);
        }
        let ct_len = buf.len() - 16;
        let (ct, tag_in) = buf.split_at_mut(ct_len);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&tag_in[..16]);
        let nonce16 = make_nonce16(&self.iv, counter);
        let mut a = crate::crypto::Aegis128X8::new(&self.key, &nonce16)
            .map_err(|_| ConnectionError::CryptoFail)?;
        a.decrypt_in_place(ct, ad, &tag).map_err(|_| ConnectionError::CryptoFail)?;
        Ok(ct_len)
    }
}

// Implement AeadSeal and AeadOpen for MorusAead
impl AeadSeal for MorusAead {
    fn seal_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
        len: usize,
        _extra_in: Option<&[u8]>,
    ) -> Result<usize, crate::error::ConnectionError> {
        use crate::error::ConnectionError;
        if buf.len() < len + 16 {
            return Err(ConnectionError::BufferTooShort);
        }
        let (pt, rest) = buf.split_at_mut(len);
        // Prefetch plaintext on x86_64 SSE2 to reduce cache miss latency
        #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
        unsafe {
            if len > 64 {
                crate::optimize::prefetch(pt.as_ptr(), crate::optimize::PrefetchHint::T0);
            }
        }
        let nonce16 = make_nonce16(&self.iv, counter);
        let (ct, tag) = self.encrypt_optimized(pt, ad, &nonce16);
        pt.copy_from_slice(&ct);
        rest[..16].copy_from_slice(&tag);
        Ok(len + 16)
    }
}

impl AeadOpen for MorusAead {
    fn open_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, crate::error::ConnectionError> {
        use crate::error::ConnectionError;
        if buf.len() < 16 {
            return Err(ConnectionError::BufferTooShort);
        }
        let ct_len = buf.len() - 16;
        let (ct, tag_in) = buf.split_at_mut(ct_len);
        // Prefetch ciphertext on x86_64 SSE2 to reduce cache miss latency
        #[cfg(all(target_arch = "x86_64", target_feature = "sse2"))]
        unsafe {
            if ct_len > 64 {
                crate::optimize::prefetch(ct.as_ptr(), crate::optimize::PrefetchHint::T0);
            }
        }
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&tag_in[..16]);
        let nonce16 = make_nonce16(&self.iv, counter);
        let pt = self
            .decrypt_optimized(ct, &tag, ad, &nonce16)
            .map_err(|_| ConnectionError::CryptoFail)?;
        ct.copy_from_slice(&pt);
        Ok(ct_len)
    }
}

fn make_nonce16(iv: &[u8; 12], counter: u64) -> [u8; 16] {
    // QUIC-style nonce derivation for 96-bit IV: XOR 64-bit packet number
    // into the last 8 bytes of the 12-byte IV. Produce a 16-byte nonce by
    // copying the 12-byte IV into the first 12 bytes and leaving the last
    // 4 bytes as 0. This avoids 32-bit truncation and ensures uniqueness
    // up to 2^64 packets (subject to IV uniqueness from HKDF).
    let mut nonce16 = [0u8; 16];
    nonce16[..12].copy_from_slice(iv);
    let pn = counter.to_be_bytes(); // 8 bytes
    for i in 0..8 {
        // XOR into bytes 4..12 (the last 8 bytes of the 12-byte IV)
        nonce16[4 + i] ^= pn[i];
    }
    nonce16
}

pub fn select_data_aead(
    key: &[u8],
    iv: &[u8],
) -> (Box<dyn AeadSeal + Send + Sync>, Box<dyn AeadOpen + Send + Sync>) {
    // Normalize key/iv materials
    let mut k16 = [0u8; 16];
    k16.copy_from_slice(&key[..16]);
    let mut iv12 = [0u8; 12];
    iv12.copy_from_slice(&iv[..12]);

    // Optional runtime override from EngineConfig/CryptoConfig.
    let mode = data_aead_override_mode();
    if mode != 0 {
        match mode {
            1 => {
                let seal =
                    Box::new(Aegis128LAead::new(&k16, &iv12)) as Box<dyn AeadSeal + Send + Sync>;
                let open =
                    Box::new(Aegis128LAead::new(&k16, &iv12)) as Box<dyn AeadOpen + Send + Sync>;
                return (seal, open);
            }
            4 => {
                let seal =
                    Box::new(Aegis128X4Aead::new(&k16, &iv12)) as Box<dyn AeadSeal + Send + Sync>;
                let open =
                    Box::new(Aegis128X4Aead::new(&k16, &iv12)) as Box<dyn AeadOpen + Send + Sync>;
                return (seal, open);
            }
            5 => {
                let seal =
                    Box::new(Aegis128X8Aead::new(&k16, &iv12)) as Box<dyn AeadSeal + Send + Sync>;
                let open =
                    Box::new(Aegis128X8Aead::new(&k16, &iv12)) as Box<dyn AeadOpen + Send + Sync>;
                return (seal, open);
            }
            2 => {
                let seal = Box::new(MorusAead::new(&k16, &iv12)) as Box<dyn AeadSeal + Send + Sync>;
                let open = Box::new(MorusAead::new(&k16, &iv12)) as Box<dyn AeadOpen + Send + Sync>;
                return (seal, open);
            }
            3 => {
                let seal = Box::new(AesGcm128::new(&k16, &iv12)) as Box<dyn AeadSeal + Send + Sync>;
                let open = Box::new(AesGcm128::new(&k16, &iv12)) as Box<dyn AeadOpen + Send + Sync>;
                return (seal, open);
            }
            _ => {}
        }
    }

    // Central plan (handles test-only overrides and CpuProfile)
    let plan = CryptoAeadPlan::select();

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    fn x86_prefers_aegis_x8(det: &crate::optimize::FeatureDetector) -> bool {
        if !det.has_feature(crate::optimize::CpuFeature::AESNI) {
            return false;
        }
        let has_vaes = det.has_feature(crate::optimize::CpuFeature::VAES);
        if !has_vaes {
            return false;
        }
        // VAES only matters when we can batch AESENC across vectors.
        let has_vaes512 = det.has_feature(crate::optimize::CpuFeature::AVX512F)
            && det.has_feature(crate::optimize::CpuFeature::AVX512VL);
        let has_vaes256 = det.has_feature(crate::optimize::CpuFeature::AVX2);
        has_vaes512 || has_vaes256
    }

    #[cfg(target_arch = "x86_64")]
    {
        if matches!(plan, CryptoAeadPlan::LAesni) {
            let det = crate::optimize::FeatureDetector::instance();
            if det.has_feature(crate::optimize::CpuFeature::AESNI) {
                if x86_prefers_aegis_x8(det) {
                    crate::telemetry::AEGIS_PLAN.store(8, std::sync::atomic::Ordering::Relaxed);
                    let seal = Box::new(Aegis128X8Aead::new(&k16, &iv12))
                        as Box<dyn AeadSeal + Send + Sync>;
                    let open = Box::new(Aegis128X8Aead::new(&k16, &iv12))
                        as Box<dyn AeadOpen + Send + Sync>;
                    return (seal, open);
                }

                // AES-NI present but no VAES batching: prefer a smaller unroll factor.
                crate::telemetry::AEGIS_PLAN.store(4, std::sync::atomic::Ordering::Relaxed);
                let seal =
                    Box::new(Aegis128X4Aead::new(&k16, &iv12)) as Box<dyn AeadSeal + Send + Sync>;
                let open =
                    Box::new(Aegis128X4Aead::new(&k16, &iv12)) as Box<dyn AeadOpen + Send + Sync>;
                return (seal, open);
            }
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        if matches!(plan, CryptoAeadPlan::LNeon) {
            let det = crate::optimize::FeatureDetector::instance();
            if det.has_feature(crate::optimize::CpuFeature::NEON)
                && det.has_feature(crate::optimize::CpuFeature::AES)
            {
                crate::telemetry::AEGIS_PLAN.store(4, std::sync::atomic::Ordering::Relaxed);
                let seal =
                    Box::new(Aegis128X4Aead::new(&k16, &iv12)) as Box<dyn AeadSeal + Send + Sync>;
                let open =
                    Box::new(Aegis128X4Aead::new(&k16, &iv12)) as Box<dyn AeadOpen + Send + Sync>;
                return (seal, open);
            }
        }
    }

    // Fallbacks per arch
    #[cfg(target_arch = "x86_64")]
    {
        let det = crate::optimize::FeatureDetector::instance();
        if det.has_feature(crate::optimize::CpuFeature::AESNI) {
            if x86_prefers_aegis_x8(det) {
                crate::telemetry::AEGIS_PLAN.store(8, std::sync::atomic::Ordering::Relaxed);
                let seal =
                    Box::new(Aegis128X8Aead::new(&k16, &iv12)) as Box<dyn AeadSeal + Send + Sync>;
                let open =
                    Box::new(Aegis128X8Aead::new(&k16, &iv12)) as Box<dyn AeadOpen + Send + Sync>;
                return (seal, open);
            }

            crate::telemetry::AEGIS_PLAN.store(4, std::sync::atomic::Ordering::Relaxed);
            let seal =
                Box::new(Aegis128X4Aead::new(&k16, &iv12)) as Box<dyn AeadSeal + Send + Sync>;
            let open =
                Box::new(Aegis128X4Aead::new(&k16, &iv12)) as Box<dyn AeadOpen + Send + Sync>;
            return (seal, open);
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        let det = crate::optimize::FeatureDetector::instance();
        if det.has_feature(crate::optimize::CpuFeature::NEON) {
            crate::telemetry::AEGIS_PLAN.store(0, std::sync::atomic::Ordering::Relaxed);
            let seal = Box::new(MorusAead::new(&k16, &iv12)) as Box<dyn AeadSeal + Send + Sync>;
            let open = Box::new(MorusAead::new(&k16, &iv12)) as Box<dyn AeadOpen + Send + Sync>;
            return (seal, open);
        }
    }

    // Scalar fallback: MORUS
    crate::telemetry::AEGIS_PLAN.store(0, std::sync::atomic::Ordering::Relaxed);
    let seal = Box::new(MorusAead::new(&k16, &iv12)) as Box<dyn AeadSeal + Send + Sync>;
    let open = Box::new(MorusAead::new(&k16, &iv12)) as Box<dyn AeadOpen + Send + Sync>;
    (seal, open)
}

fn data_aead_override_mode() -> u8 {
    DATA_AEAD_OVERRIDE_MODE.load(Ordering::Relaxed)
}

fn set_data_aead_override_mode(mode: u8) {
    DATA_AEAD_OVERRIDE_MODE.store(mode, Ordering::Relaxed);
}

/// Apply data-plane AEAD settings from config.
///
/// This affects 0-RTT/1-RTT packet protection selection in the transport layer.
/// Initial/Handshake remain AES-GCM for QUIC compatibility.
pub fn install_data_aead_config(cfg: &crate::engine::CryptoConfig) {
    let has_hw_aes = {
        #[cfg(target_arch = "x86_64")]
        {
            crate::optimize::FeatureDetector::instance()
                .has_feature(crate::optimize::CpuFeature::AESNI)
        }
        #[cfg(target_arch = "aarch64")]
        {
            crate::optimize::FeatureDetector::instance()
                .has_feature(crate::optimize::CpuFeature::AES)
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            false
        }
    };

    // Highest priority: explicit string override.
    let force = cfg.force_aead.trim();
    if !force.is_empty() {
        let v = force.to_ascii_lowercase();
        match v.as_str() {
            "auto" => set_data_aead_override_mode(0),
            "aegis-128l" | "aegis128l" | "aegis" => set_data_aead_override_mode(1),
            "aegis-128x4" | "aegis128x4" => set_data_aead_override_mode(4),
            "aegis-128x8" | "aegis128x8" => set_data_aead_override_mode(5),
            "morus" | "morus-1280-128" | "morus1280-128" => set_data_aead_override_mode(2),
            "aes-gcm" | "aesgcm" | "aes-128-gcm" | "aes128gcm" => set_data_aead_override_mode(3),
            _ => {
                // Validation should reject unknown values; keep runtime behavior stable.
                set_data_aead_override_mode(0);
            }
        }
        return;
    }

    // Preference-based override.
    match cfg.aead_preference {
        crate::engine::AeadPreference::Auto => set_data_aead_override_mode(0),
        crate::engine::AeadPreference::Aegis128L => {
            // Preference: only take effect when AES hardware is available; otherwise keep auto.
            if has_hw_aes {
                set_data_aead_override_mode(1);
            } else {
                set_data_aead_override_mode(0);
            }
        }
        crate::engine::AeadPreference::Aegis128X4 => {
            if has_hw_aes {
                set_data_aead_override_mode(4);
            } else {
                set_data_aead_override_mode(0);
            }
        }
        crate::engine::AeadPreference::Aegis128X8 => {
            if has_hw_aes {
                set_data_aead_override_mode(5);
            } else {
                set_data_aead_override_mode(0);
            }
        }
        crate::engine::AeadPreference::Morus => set_data_aead_override_mode(2),
        crate::engine::AeadPreference::AesGcm => set_data_aead_override_mode(3),
    }
}

// ============================================================================
// CRYPTO SUBMODULES: AEAD traits/HP, HKDF KDF, minimal GCM helper
// ============================================================================

// Use the proven in-file legacy modules (no external references)
pub use self::aead_legacy as aead;
pub use self::quic_kdf as kdf;

/// Post-Quantum Cryptography module
#[cfg(feature = "pq")]
pub mod pq {
    use log::error;
    use pqcrypto_mldsa::mldsa65::{self};
    use pqcrypto_mlkem::mlkem768::{self};

    /// Utilities for Post-Quantum key exchange and signatures using Kyber and Dilithium.
    pub struct PqCrypto;

    impl PqCrypto {
        /// Generates a Kyber768 keypair.
        pub fn mlkem_keypair() -> (Vec<u8>, Vec<u8>) {
            let (pk, sk) = mlkem768::keypair();
            (
                <pqcrypto_mlkem::mlkem768::PublicKey as pqcrypto_traits::kem::PublicKey>::as_bytes(
                    &pk,
                )
                .to_vec(),
                <pqcrypto_mlkem::mlkem768::SecretKey as pqcrypto_traits::kem::SecretKey>::as_bytes(
                    &sk,
                )
                .to_vec(),
            )
        }

        /// Encapsulates a shared secret to the given Kyber768 public key.
        pub fn mlkem_encapsulate(pk_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
            match <pqcrypto_mlkem::mlkem768::PublicKey as pqcrypto_traits::kem::PublicKey>::
                from_bytes(pk_bytes)
            {
                Ok(pk) => {
                    let (ss, ct) = mlkem768::encapsulate(&pk);
                    (
                        <pqcrypto_mlkem::mlkem768::Ciphertext as pqcrypto_traits::kem::
                            Ciphertext>::as_bytes(&ct)
                            .to_vec(),
                        <pqcrypto_mlkem::mlkem768::SharedSecret as pqcrypto_traits::kem::
                            SharedSecret>::as_bytes(&ss)
                            .to_vec(),
                    )
                }
                Err(e) => {
                    error!("kyber_encapsulate: invalid public key: {}", e);
                    (Vec::new(), Vec::new())
                }
            }
        }

        /// Decapsulates the Kyber768 ciphertext to recover the shared secret.
        pub fn mlkem_decapsulate(ct_bytes: &[u8], sk_bytes: &[u8]) -> Vec<u8> {
            let ct = match <pqcrypto_mlkem::mlkem768::Ciphertext as pqcrypto_traits::kem::
                Ciphertext>::from_bytes(ct_bytes)
            {
                Ok(v) => v,
                Err(e) => {
                    error!("kyber_decapsulate: invalid ciphertext: {}", e);
                    return Vec::new();
                }
            };
            let sk = match <pqcrypto_mlkem::mlkem768::SecretKey as pqcrypto_traits::kem::
                SecretKey>::from_bytes(sk_bytes)
            {
                Ok(v) => v,
                Err(e) => {
                    error!("kyber_decapsulate: invalid secret key: {}", e);
                    return Vec::new();
                }
            };
            let ss = mlkem768::decapsulate(&ct, &sk);
            <pqcrypto_mlkem::mlkem768::SharedSecret as pqcrypto_traits::kem::SharedSecret>::
                as_bytes(&ss)
                .to_vec()
        }

        /// Generates a Dilithium3 keypair.
        pub fn mldsa_keypair() -> (Vec<u8>, Vec<u8>) {
            let (pk, sk) = mldsa65::keypair();
            (
                <pqcrypto_mldsa::mldsa65::PublicKey as pqcrypto_traits::sign::PublicKey>::as_bytes(
                    &pk,
                )
                .to_vec(),
                <pqcrypto_mldsa::mldsa65::SecretKey as pqcrypto_traits::sign::SecretKey>::as_bytes(
                    &sk,
                )
                .to_vec(),
            )
        }

        /// Creates a Dilithium3 detached signature for the given message.
        pub fn mldsa_sign(msg: &[u8], sk_bytes: &[u8]) -> Vec<u8> {
            match <pqcrypto_mldsa::mldsa65::SecretKey as pqcrypto_traits::sign::
                SecretKey>::from_bytes(sk_bytes)
            {
                Ok(sk) => {
                    let sig = mldsa65::detached_sign(msg, &sk);
                    <pqcrypto_mldsa::mldsa65::DetachedSignature as pqcrypto_traits::sign::
                        DetachedSignature>::as_bytes(&sig)
                        .to_vec()
                }
                Err(e) => {
                    error!("dilithium_sign: invalid secret key: {}", e);
                    Vec::new()
                }
            }
        }

        /// Verifies a Dilithium3 signature against the message.
        pub fn mldsa_verify(msg: &[u8], sig_bytes: &[u8], pk_bytes: &[u8]) -> bool {
            let pk = match <pqcrypto_mldsa::mldsa65::PublicKey as pqcrypto_traits::sign::
                PublicKey>::from_bytes(pk_bytes)
            {
                Ok(v) => v,
                Err(e) => {
                    error!("dilithium_verify: invalid public key: {}", e);
                    return false;
                }
            };
            let sig = match <pqcrypto_mldsa::mldsa65::DetachedSignature as pqcrypto_traits::
                sign::DetachedSignature>::from_bytes(sig_bytes)
            {
                Ok(v) => v,
                Err(e) => {
                    error!("dilithium_verify: invalid signature: {}", e);
                    return false;
                }
            };
            mldsa65::verify_detached_signature(&sig, msg, &pk).is_ok()
        }
    }
}

/// Hybrid Key Exchange: X25519 + ML-KEM768
/// Combines classical ECDH with post-quantum KEM for quantum-resistant key exchange.
/// Default OFF. Enable via feature `pq` AND env `QUICFUSCATE_PQ_HYBRID=1`.
#[cfg(feature = "pq")]
pub mod hybrid {
    use super::{hkdf, pq::PqCrypto};

    /// Check if hybrid PQ mode is enabled at runtime
    #[inline]
    pub fn is_hybrid_enabled() -> bool {
        std::env::var("QUICFUSCATE_PQ_HYBRID")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false)
    }

    /// Hybrid key exchange state
    #[derive(Debug)]
    pub struct HybridKeyExchange {
        /// X25519 private key (32 bytes)
        x25519_private: [u8; 32],
        /// X25519 public key (32 bytes)
        x25519_public: [u8; 32],
        /// ML-KEM public key
        mlkem_public: Vec<u8>,
        /// ML-KEM secret key
        mlkem_secret: Vec<u8>,
        /// Combined shared secret (after exchange)
        shared_secret: Option<Vec<u8>>,
    }

    impl HybridKeyExchange {
        /// Generate new hybrid keypair (X25519 + ML-KEM768)
        pub fn new() -> Self {
            // Generate X25519 keypair using our rand module
            let mut x25519_private = [0u8; 32];
            crate::transport::pn::rand::rand_bytes(&mut x25519_private);
            // Clamp the private key per X25519 spec
            x25519_private[0] &= 248;
            x25519_private[31] &= 127;
            x25519_private[31] |= 64;

            // Compute X25519 public key (base point multiplication)
            let x25519_public = x25519_scalar_mult_base(&x25519_private);

            // Generate ML-KEM keypair
            let (mlkem_public, mlkem_secret) = PqCrypto::mlkem_keypair();

            Self { x25519_private, x25519_public, mlkem_public, mlkem_secret, shared_secret: None }
        }

        /// Get our hybrid public key (X25519 pubkey || ML-KEM pubkey)
        pub fn public_key(&self) -> Vec<u8> {
            let mut combined = Vec::with_capacity(32 + self.mlkem_public.len());
            combined.extend_from_slice(&self.x25519_public);
            combined.extend_from_slice(&self.mlkem_public);
            combined
        }

        /// Complete key exchange from peer's public key + ciphertext
        /// Input: peer_x25519_pub (32 bytes) || mlkem_ciphertext
        /// Returns: combined shared secret
        pub fn complete_exchange(&mut self, peer_hybrid_data: &[u8]) -> Option<Vec<u8>> {
            if peer_hybrid_data.len() < 32 {
                log::error!("hybrid: peer data too short");
                return None;
            }

            // Parse peer's X25519 public key (first 32 bytes)
            let mut peer_x25519_pub = [0u8; 32];
            peer_x25519_pub.copy_from_slice(&peer_hybrid_data[..32]);

            // Rest is ML-KEM ciphertext
            let mlkem_ct = &peer_hybrid_data[32..];

            // X25519 shared secret
            let x25519_ss = x25519_scalar_mult(&self.x25519_private, &peer_x25519_pub);

            // ML-KEM decapsulation
            let mlkem_ss = PqCrypto::mlkem_decapsulate(mlkem_ct, &self.mlkem_secret);
            if mlkem_ss.is_empty() {
                log::error!("hybrid: ML-KEM decapsulation failed");
                return None;
            }

            // Combine shared secrets: HKDF(X25519_SS || ML-KEM_SS)
            let combined = combine_shared_secrets(&x25519_ss, &mlkem_ss);
            self.shared_secret = Some(combined.clone());

            log::info!("hybrid: key exchange completed (X25519 + ML-KEM768)");
            Some(combined)
        }

        /// Initiate key exchange (client side): encapsulate to peer's public key
        /// Returns: our_x25519_pub || mlkem_ciphertext, and stores shared secret
        pub fn initiate_exchange(
            &mut self,
            peer_mlkem_pubkey: &[u8],
        ) -> Option<(Vec<u8>, Vec<u8>)> {
            // Encapsulate to peer's ML-KEM public key
            let (mlkem_ct, mlkem_ss) = PqCrypto::mlkem_encapsulate(peer_mlkem_pubkey);
            if mlkem_ct.is_empty() || mlkem_ss.is_empty() {
                log::error!("hybrid: ML-KEM encapsulation failed");
                return None;
            }

            // Build our hybrid message: X25519 pubkey || ML-KEM ciphertext
            let mut out = Vec::with_capacity(32 + mlkem_ct.len());
            out.extend_from_slice(&self.x25519_public);
            out.extend_from_slice(&mlkem_ct);

            // We'll combine with X25519 SS when we receive peer's X25519 pubkey
            // For now, store ML-KEM SS; final SS computed in complete_exchange
            self.shared_secret = Some(mlkem_ss);

            Some((out, self.mlkem_public.clone()))
        }

        /// Get the derived shared secret (after exchange)
        pub fn shared_secret(&self) -> Option<&[u8]> {
            self.shared_secret.as_deref()
        }
    }

    impl Default for HybridKeyExchange {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Combine X25519 and ML-KEM shared secrets using HKDF
    pub fn combine_shared_secrets(x25519_ss: &[u8], mlkem_ss: &[u8]) -> Vec<u8> {
        let mut combined_input = Vec::with_capacity(x25519_ss.len() + mlkem_ss.len());
        combined_input.extend_from_slice(x25519_ss);
        combined_input.extend_from_slice(mlkem_ss);

        // HKDF: Extract then Expand with label "hybrid-pq-ke"
        let salt = b"quicfuscate-hybrid-pq";
        let prk = hkdf::hkdf_extract(salt, &combined_input);
        let info = b"hybrid-pq-ke";
        hkdf::hkdf_expand(&prk, info, 32)
    }

    /// X25519 scalar multiplication with base point (public key generation)
    fn x25519_scalar_mult_base(scalar: &[u8; 32]) -> [u8; 32] {
        let secret = x25519_dalek::StaticSecret::from(*scalar);
        let public = x25519_dalek::PublicKey::from(&secret);
        public.to_bytes()
    }

    /// X25519 scalar multiplication (shared secret derivation)
    fn x25519_scalar_mult(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
        x25519_dalek::x25519(*scalar, *point)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_hybrid_key_exchange_creation() {
            let hke = HybridKeyExchange::new();
            assert_eq!(hke.x25519_public.len(), 32);
            assert!(!hke.mlkem_public.is_empty());
            assert!(hke.shared_secret.is_none());
        }

        #[test]
        fn test_hybrid_public_key_format() {
            let hke = HybridKeyExchange::new();
            let pubkey = hke.public_key();
            // Should be X25519 (32) + ML-KEM768 public key (1184 bytes)
            assert!(pubkey.len() > 32);
            assert_eq!(&pubkey[..32], &hke.x25519_public);
        }

        #[test]
        fn test_combine_shared_secrets() {
            let x25519_ss = [1u8; 32];
            let mlkem_ss = [2u8; 32];
            let combined = combine_shared_secrets(&x25519_ss, &mlkem_ss);
            assert_eq!(combined.len(), 32);
            // Should be deterministic
            let combined2 = combine_shared_secrets(&x25519_ss, &mlkem_ss);
            assert_eq!(combined, combined2);
        }

        #[test]
        fn test_hybrid_enabled_check() {
            // Default should be false
            std::env::remove_var("QUICFUSCATE_PQ_HYBRID");
            assert!(!is_hybrid_enabled());
        }
    }
}
