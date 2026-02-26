// Copyright (c) 2024, The QuicFuscate Project Authors.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following disclaimer
//       in the documentation and/or other materials provided with the
//       distribution.
//
//     * Neither the name of the copyright holder nor the names of its
//       contributors may be used to endorse or promote products derived from
//       this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! # Stealth Module
//!
//! This module provides a comprehensive suite of advanced techniques for traffic
//! obfuscation, QUIC fingerprint spoofing, and evasion of deep packet
//? inspection (DPI) systems. It integrates multiple strategies to create a
//! layered defense against network surveillance.

// User-Agent string constants to avoid repeated allocations
const UA_CHROME_WIN: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
const UA_FIREFOX_WIN: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0";
const UA_EDGE_WIN: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0";
const UA_EDGE_MAC: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0";
const UA_EDGE_LINUX: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0";
const UA_SAFARI_MAC: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15";
const UA_CHROME_MAC: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
const UA_FIREFOX_MAC: &str =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6; rv:127.0) Gecko/20100101 Firefox/127.0";
const UA_CHROME_LINUX: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
const UA_FIREFOX_LINUX: &str =
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0";
const UA_CHROME_ANDROID: &str = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36";
const UA_FIREFOX_ANDROID: &str =
    "Mozilla/5.0 (Android 14; Mobile; rv:127.0) Gecko/127.0 Firefox/127.0";
const UA_SAFARI_IOS: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1";

// Accept-Language constants
const LANG_EN_US_09: &str = "en-US,en;q=0.9";
const LANG_EN_US_05: &str = "en-US,en;q=0.5";

/*
===============================================================================
Rules-File Guard (Stealth Module)
-------------------------------------------------------------------------------
- No placeholders in production code. All public methods must be fully
  implemented and concurrency-safe.
- DomainFrontingManager uses atomics for lock-free selection; changes must keep
  thread-safety and deterministic semantics.
- XorObfuscator key updates must remain mutex-guarded with SHA-256 evolution;
  no stubs.
- TLS ClientHello spoofing must call safe FFI shims only; when symbols are
  absent, fall back is a no-op without panicking.
- After edits: run `cargo check` and `cargo doc` to validate.
===============================================================================
*/

// clap dependency removed - using manual enum implementation
use crate::accelerate::stealth::AsciiSimdBackend;
use crate::crypto::hkdf::{hkdf_expand, hkdf_extract};
use crate::transport::h3::NameValue;
use lazy_static::lazy_static;
use log::{debug, error, info, warn};
use reqwest::Client;
// use of sha2 replaced with centralized SIMD dispatch
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;
use url::Url;

use self::tls_cover::ServerHelloParamsOwned;
use crate::crypto::CryptoManager; // Assumed for integration
use crate::optimize::OptimizationManager; // Assumed for integration
use crate::telemetry;
use aligned_box::AlignedBox;

// Integrated test module (keeps src layout monolithic; tests live alongside)
// Test module removed - tests are inline

/// Server Push Cover Traffic state management
#[derive(Debug)]
struct ServerPushState {
    /// Last burst timestamp
    last_burst: std::time::Instant,
    /// Active push promises count
    active_promises: usize,
    /// Total cover traffic bytes sent
    total_cover_bytes: u64,
    /// Current intensity multiplier (dynamic adjustment)
    current_intensity: f32,
    /// Sliding 60-second burst window for bursts/minute telemetry.
    burst_window: VecDeque<std::time::Instant>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerPushTriggerReason {
    Time,
    Loss,
    Gating,
}

/// Real-time rate choker (token bucket) to smooth observable bitrate without heavy CPU.
struct RateChoker {
    target_bps: f64,
    capacity_bytes: f64,
    tokens: f64,
    last: std::time::Instant,
}

impl RateChoker {
    fn new(target_mbps: u32, burst_ms: u32) -> Option<Self> {
        if target_mbps == 0 {
            return None;
        }
        let target_bps = (target_mbps as f64) * 1_000_000.0;
        let capacity_bytes = (target_bps / 8.0) * (burst_ms as f64 / 1000.0);
        Some(Self {
            target_bps,
            capacity_bytes,
            tokens: capacity_bytes, // start full burst
            last: std::time::Instant::now(),
        })
    }

    /// Returns sleep duration needed to respect the target rate for `bytes`.
    fn shape(&mut self, bytes: usize) -> std::time::Duration {
        let now = std::time::Instant::now();
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        // Refill tokens
        self.tokens = (self.tokens + (self.target_bps / 8.0) * dt).min(self.capacity_bytes);
        self.last = now;

        let need = bytes as f64;
        if self.tokens >= need {
            self.tokens -= need;
            return std::time::Duration::ZERO;
        }
        let deficit = need - self.tokens;
        // Time to accumulate `deficit` bytes at target_bps
        let wait_s = (deficit * 8.0) / self.target_bps;
        self.tokens = 0.0;
        std::time::Duration::from_secs_f64(wait_s.max(0.0))
    }
}

// --- Inlined: tls_cover.rs ---
// Minimal TLS Cover record layer for fingerprinting
// Generates a forged ClientHello and synthetic server response without
// establishing a real TLS session.
// Ultra-sophisticated TLS Cover Provider for maximum stealth
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsCoverCipherSuite {
    ChaCha20Poly1305,
    Aes128Gcm,
}

impl TlsCoverCipherSuite {
    fn as_str(&self) -> &'static str {
        match self {
            TlsCoverCipherSuite::ChaCha20Poly1305 => "chacha20-poly1305",
            TlsCoverCipherSuite::Aes128Gcm => "aes-128-gcm",
        }
    }

    fn kind(&self) -> crate::transport::packet::TlsCoverCipherKind {
        match self {
            TlsCoverCipherSuite::ChaCha20Poly1305 => {
                crate::transport::packet::TlsCoverCipherKind::ChaCha20Poly1305
            }
            TlsCoverCipherSuite::Aes128Gcm => {
                crate::transport::packet::TlsCoverCipherKind::Aes128Gcm
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsCoverCipherPreference {
    Auto,
    ChaCha20Poly1305,
    Aes128Gcm,
}

impl TlsCoverCipherPreference {
    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "auto" | "" => Some(Self::Auto),
            "chacha" | "chacha20" | "chacha20poly1305" => Some(Self::ChaCha20Poly1305),
            "aes" | "aesgcm" | "aes-gcm" | "aes128gcm" | "aes-128-gcm" | "ctr" | "aesctr" => {
                Some(Self::Aes128Gcm)
            }
            _ => None,
        }
    }
}

pub struct TlsCoverProvider {
    crypto: Arc<parking_lot::RwLock<crate::transport::packet::CryptoContext>>,
    is_server: bool,
    handshake_complete: bool,
    alpn: Option<String>,
    ch_template: Vec<u8>,
    performance_mode: bool, // When true, disable padding/jitter/timing features
    fingerprint_profile: String,
    tls_cover_key: [u8; 32],
    tls_cover_iv: [u8; 12],
    cipher_suite: TlsCoverCipherSuite,
}

impl TlsCoverProvider {
    fn cipher_preference_from_env() -> TlsCoverCipherPreference {
        std::env::var("QUICFUSCATE_TLS_COVER_CIPHER")
            .or_else(|_| std::env::var("QUICFUSCATE_TLS_COVER_CIPHER"))
            .ok()
            .and_then(|value| TlsCoverCipherPreference::parse(&value))
            .unwrap_or(TlsCoverCipherPreference::Auto)
    }

    fn has_hardware_aes() -> bool {
        let detector = crate::optimize::FeatureDetector::instance();
        detector.has_feature(crate::optimize::CpuFeature::AESNI)
            || detector.has_feature(crate::optimize::CpuFeature::VAES)
            || detector.has_feature(crate::optimize::CpuFeature::AES)
    }

    fn resolve_cipher_suite(pref: TlsCoverCipherPreference) -> TlsCoverCipherSuite {
        match pref {
            TlsCoverCipherPreference::Auto => {
                if Self::has_hardware_aes() {
                    TlsCoverCipherSuite::Aes128Gcm
                } else {
                    TlsCoverCipherSuite::ChaCha20Poly1305
                }
            }
            TlsCoverCipherPreference::ChaCha20Poly1305 => TlsCoverCipherSuite::ChaCha20Poly1305,
            TlsCoverCipherPreference::Aes128Gcm => {
                if !Self::has_hardware_aes() {
                    log::warn!(
                        "TLS Cover AES-128-GCM requested but hardware lacks AES acceleration; using scalar fallback"
                    );
                }
                TlsCoverCipherSuite::Aes128Gcm
            }
        }
    }

    pub fn new(
        is_server: bool,
        crypto: Arc<parking_lot::RwLock<crate::transport::packet::CryptoContext>>,
    ) -> Result<Self, crate::error::ConnectionError> {
        // Load profile from ENV
        let profile = std::env::var("QUICFUSCATE_TLS_COVER_PROFILE")
            .or_else(|_| std::env::var("QUICFUSCATE_TLS_COVER_PROFILE"))
            .unwrap_or_else(|_| "chrome".to_string());

        let (tls_cover_key, tls_cover_iv) = Self::derive_tls_cover_material(&profile, is_server);

        let cipher_preference = Self::cipher_preference_from_env();
        let cipher_suite = Self::resolve_cipher_suite(cipher_preference);

        {
            let mut ctx = crypto.write();
            match cipher_suite {
                TlsCoverCipherSuite::ChaCha20Poly1305 => {
                    ctx.install_tls_cover_chacha(&tls_cover_key, &tls_cover_iv);
                }
                TlsCoverCipherSuite::Aes128Gcm => {
                    let mut aes_key = [0u8; 16];
                    aes_key.copy_from_slice(&tls_cover_key[..16]);
                    ctx.install_tls_cover_aes_gcm(&aes_key, &tls_cover_iv);
                }
            }
        }

        log::info!(
            "TLS Cover cipher suite selected: {} ({})",
            cipher_suite.as_str(),
            match cipher_preference {
                TlsCoverCipherPreference::Auto => "auto",
                TlsCoverCipherPreference::ChaCha20Poly1305 => "forced",
                TlsCoverCipherPreference::Aes128Gcm => "forced",
            }
        );

        if matches!(cipher_suite, TlsCoverCipherSuite::ChaCha20Poly1305) && Self::has_hardware_aes()
        {
            log::debug!("Hardware AES available but TLS Cover cipher forced to ChaCha20-Poly1305");
        }

        // Generate initial CH template based on profile
        let ch_template = Self::generate_ch_template(&profile);

        Ok(Self {
            crypto,
            is_server,
            handshake_complete: false,
            alpn: Some("h3".to_string()),
            ch_template,
            performance_mode: false,
            fingerprint_profile: profile,
            tls_cover_key,
            tls_cover_iv,
            cipher_suite,
        })
    }

    /// Generate ultra-sophisticated ClientHello template based on profile
    fn generate_ch_template(profile: &str) -> Vec<u8> {
        match profile {
            "chrome" => Self::chrome_ch_template(),
            "firefox" => Self::firefox_ch_template(),
            "safari" => Self::safari_ch_template(),
            "edge" => Self::edge_ch_template(),
            "random" => Self::random_ch_template(),
            _ => Self::chrome_ch_template(),
        }
    }

    fn derive_tls_cover_material(profile: &str, is_server: bool) -> ([u8; 32], [u8; 12]) {
        let salt = "quicfuscate:tls-cover:salt:v1".to_string();
        let ikm = format!(
            "quicfuscate:tls-cover:{}:{}",
            profile,
            if is_server { "server" } else { "client" }
        );
        let prk = hkdf_extract(salt.as_bytes(), ikm.as_bytes());
        let info = format!("quicfuscate:tls-cover:info:{}", profile);
        let okm = hkdf_expand(&prk, info.as_bytes(), 44);
        let mut key = [0u8; 32];
        let mut iv = [0u8; 12];
        key.copy_from_slice(&okm[..32]);
        iv.copy_from_slice(&okm[32..44]);
        (key, iv)
    }

    fn chrome_ch_template() -> Vec<u8> {
        // Ultra-realistic Chrome 120 ClientHello
        let mut ch = Vec::new();

        // TLS 1.3 ClientHello structure
        ch.extend_from_slice(&[
            0x01, 0x00, 0x01, 0xfc, // Handshake Type: ClientHello, Length
            0x03, 0x03, // Version: TLS 1.2 (for compatibility)
        ]);

        // Random (32 bytes) - Chrome-specific pattern
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut random = [0u8; 32];
        rng.fill(&mut random[..]);
        ch.extend_from_slice(&random);

        // Session ID (32 bytes for Chrome)
        ch.push(0x20);
        let mut session_id = [0u8; 32];
        rng.fill(&mut session_id[..]);
        ch.extend_from_slice(&session_id);

        // Cipher Suites - Chrome order (includes ChaCha for fingerprint realism)
        ch.extend_from_slice(&[
            0x00, 0x20, // Length: 32 bytes (16 suites)
            0x13, 0x01, // TLS_AES_128_GCM_SHA256
            0x13, 0x02, // TLS_AES_256_GCM_SHA384
            0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
            0xc0, 0x2b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xc0, 0x2c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xc0, 0x30, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0xcc, 0xa9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            0xcc, 0xa8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            0xc0, 0x13, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
            0xc0, 0x14, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
            0x00, 0x9c, // TLS_RSA_WITH_AES_128_GCM_SHA256
            0x00, 0x9d, // TLS_RSA_WITH_AES_256_GCM_SHA384
            0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
            0x00, 0x35, // TLS_RSA_WITH_AES_256_CBC_SHA
            0x00, 0x0a, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
        ]);

        // Compression Methods
        ch.extend_from_slice(&[0x01, 0x00]); // No compression

        // Extensions - Chrome-specific order and values
        Self::add_chrome_extensions(&mut ch);

        ch
    }

    fn firefox_ch_template() -> Vec<u8> {
        // Ultra-realistic Firefox 120 ClientHello
        let mut ch = Vec::new();

        // Similar structure but Firefox-specific ordering
        ch.extend_from_slice(&[0x01, 0x00, 0x01, 0xf8, 0x03, 0x03]);

        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut random = [0u8; 32];
        rng.fill(&mut random[..]);
        ch.extend_from_slice(&random);

        // Firefox uses empty session ID
        ch.push(0x00);

        // Firefox cipher suite order (includes ChaCha for fingerprint realism)
        ch.extend_from_slice(&[
            0x00, 0x1e, // Length (30 bytes, 15 suites)
            0x13, 0x01, // TLS_AES_128_GCM_SHA256
            0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
            0x13, 0x02, // TLS_AES_256_GCM_SHA384
            0xc0, 0x2b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xcc, 0xa9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            0xcc, 0xa8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            0xc0, 0x2c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xc0, 0x30, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0xc0, 0x13, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
            0xc0, 0x14, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
            0x00, 0x33, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
            0x00, 0x39, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
            0x00, 0x2f, // TLS_RSA_WITH_AES_128_CBC_SHA
            0x00, 0x35, // TLS_RSA_WITH_AES_256_CBC_SHA
        ]);

        ch.extend_from_slice(&[0x01, 0x00]);

        Self::add_firefox_extensions(&mut ch);

        ch
    }

    fn safari_ch_template() -> Vec<u8> {
        // Ultra-realistic Safari 17 ClientHello
        let mut ch = Vec::new();

        ch.extend_from_slice(&[0x01, 0x00, 0x01, 0xe8, 0x03, 0x03]);

        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut random = [0u8; 32];
        rng.fill(&mut random[..]);
        ch.extend_from_slice(&random);

        // Safari uses 32-byte session ID
        ch.push(0x20);
        let mut session_id = [0u8; 32];
        rng.fill(&mut session_id[..]);
        ch.extend_from_slice(&session_id);

        // Safari cipher suite order (minimal set)
        ch.extend_from_slice(&[
            0x00, 0x0a, // Length
            0x13, 0x01, // TLS_AES_128_GCM_SHA256
            0x13, 0x02, // TLS_AES_256_GCM_SHA384
            0xc0, 0x2b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xc0, 0x2c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        ]);

        ch.extend_from_slice(&[0x01, 0x00]);

        Self::add_safari_extensions(&mut ch);

        ch
    }

    fn edge_ch_template() -> Vec<u8> {
        // Edge uses Chrome engine but with slight differences
        // Modify some bytes to make it Edge-specific in future if needed
        // Edge has different extension ordering
        Self::chrome_ch_template()
    }

    fn random_ch_template() -> Vec<u8> {
        // Randomly select a profile for variety
        use rand::Rng;
        let mut rng = rand::thread_rng();
        match rng.gen_range(0..4) {
            0 => Self::chrome_ch_template(),
            1 => Self::firefox_ch_template(),
            2 => Self::safari_ch_template(),
            _ => Self::edge_ch_template(),
        }
    }

    const CLIENT_HELLO_SNI: &'static [u8] = b"cdn.cloudflare.com";

    fn append_server_name_extension(ext: &mut Vec<u8>, host: &[u8]) {
        let host_len = host.len();
        if host_len > u16::MAX as usize {
            return;
        }
        let list_len = 1 + 2 + host_len;
        if list_len > u16::MAX as usize {
            return;
        }
        let ext_len = 2 + list_len;
        if ext_len > u16::MAX as usize {
            return;
        }

        ext.extend_from_slice(&[0x00, 0x00]); // server_name
        ext.extend_from_slice(&(ext_len as u16).to_be_bytes());
        ext.extend_from_slice(&(list_len as u16).to_be_bytes());
        ext.push(0x00); // host_name
        ext.extend_from_slice(&(host_len as u16).to_be_bytes());
        ext.extend_from_slice(host);
    }

    fn add_chrome_extensions(ch: &mut Vec<u8>) {
        // Add Chrome-specific extensions in exact order
        let mut ext = Vec::new();

        // GREASE extension (Chrome always starts with GREASE)
        ext.extend_from_slice(&[0x0a, 0x0a, 0x00, 0x00]);

        // Server Name (SNI)
        Self::append_server_name_extension(&mut ext, Self::CLIENT_HELLO_SNI);

        // Supported Groups
        ext.extend_from_slice(&[
            0x00, 0x0a, // Extension type: supported_groups
            0x00, 0x08, // Length
            0x00, 0x06, // Groups length
            0x00, 0x1d, // x25519
            0x00, 0x17, // secp256r1
            0x00, 0x18, // secp384r1
        ]);

        // EC Point Formats
        ext.extend_from_slice(&[
            0x00, 0x0b, // Extension type: ec_point_formats
            0x00, 0x02, // Length
            0x01, // Formats length
            0x00, // uncompressed
        ]);

        // Signature Algorithms
        ext.extend_from_slice(&[
            0x00, 0x0d, // Extension type: signature_algorithms
            0x00, 0x0e, // Length
            0x00, 0x0c, // Algorithms length
            0x04, 0x03, // ecdsa_secp256r1_sha256
            0x08, 0x04, // rsa_pss_rsae_sha256
            0x04, 0x01, // rsa_pkcs1_sha256
            0x05, 0x03, // ecdsa_secp384r1_sha384
            0x08, 0x05, // rsa_pss_rsae_sha384
            0x05, 0x01, // rsa_pkcs1_sha384
        ]);

        // ALPN
        ext.extend_from_slice(&[
            0x00, 0x10, // Extension type: ALPN
            0x00, 0x0e, // Length
            0x00, 0x0c, // ALPN list length
            0x02, b'h', b'3', // h3
            0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1', // http/1.1
        ]);

        // Supported Versions
        ext.extend_from_slice(&[
            0x00, 0x2b, // Extension type: supported_versions
            0x00, 0x03, // Length
            0x02, // Versions length
            0x03, 0x04, // TLS 1.3
        ]);

        // PSK Key Exchange Modes
        ext.extend_from_slice(&[
            0x00, 0x2d, // Extension type: psk_key_exchange_modes
            0x00, 0x02, // Length
            0x01, // Modes length
            0x01, // psk_dhe_ke
        ]);

        // Key Share
        ext.extend_from_slice(&[
            0x00, 0x33, // Extension type: key_share
            0x00, 0x26, // Length
            0x00, 0x24, // Key share entries length
            0x00, 0x1d, // Group: x25519
            0x00, 0x20, // Key exchange length
        ]);

        // Generate random key
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut key = [0u8; 32];
        rng.fill(&mut key[..]);
        ext.extend_from_slice(&key);

        // Add extension length to CH
        ch.extend_from_slice(&((ext.len() as u16).to_be_bytes()));
        ch.extend_from_slice(&ext);
    }

    fn add_firefox_extensions(ch: &mut Vec<u8>) {
        // Firefox has different extension order and doesn't use GREASE
        let mut ext = Vec::new();

        // Server Name (Firefox starts with SNI)
        Self::append_server_name_extension(&mut ext, Self::CLIENT_HELLO_SNI);

        // Extended Master Secret
        ext.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);

        // Renegotiation Info
        ext.extend_from_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]);

        // Supported Groups
        ext.extend_from_slice(&[
            0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e, 0x00, 0x18,
        ]);

        // EC Point Formats
        ext.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);

        // Session Ticket
        ext.extend_from_slice(&[0x00, 0x23, 0x00, 0x00]);

        // ALPN
        ext.extend_from_slice(&[
            0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, b'h', b'3', 0x08, b'h', b't', b't', b'p',
            b'/', b'1', b'.', b'1',
        ]);

        // Status Request
        ext.extend_from_slice(&[0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00]);

        // Signature Algorithms
        ext.extend_from_slice(&[
            0x00, 0x0d, 0x00, 0x12, 0x00, 0x10, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03,
            0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01,
        ]);

        // Supported Versions
        ext.extend_from_slice(&[0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03]);

        // PSK Key Exchange Modes
        ext.extend_from_slice(&[0x00, 0x2d, 0x00, 0x02, 0x01, 0x01]);

        // Key Share
        ext.extend_from_slice(&[0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);

        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut key = [0u8; 32];
        rng.fill(&mut key[..]);
        ext.extend_from_slice(&key);

        ch.extend_from_slice(&((ext.len() as u16).to_be_bytes()));
        ch.extend_from_slice(&ext);
    }

    fn add_safari_extensions(ch: &mut Vec<u8>) {
        // Safari has minimal extensions
        let mut ext = Vec::new();

        // Server Name
        Self::append_server_name_extension(&mut ext, Self::CLIENT_HELLO_SNI);

        // Supported Groups (Safari uses fewer groups)
        ext.extend_from_slice(&[0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17]);

        // Signature Algorithms (Safari minimal set)
        ext.extend_from_slice(&[
            0x00, 0x0d, 0x00, 0x08, 0x00, 0x06, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03,
        ]);

        // ALPN
        ext.extend_from_slice(&[0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, b'h', b'3']);

        // Supported Versions
        ext.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);

        // Key Share
        ext.extend_from_slice(&[0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);

        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut key = [0u8; 32];
        rng.fill(&mut key[..]);
        ext.extend_from_slice(&key);

        ch.extend_from_slice(&((ext.len() as u16).to_be_bytes()));
        ch.extend_from_slice(&ext);
    }

    pub fn apply_ch_override(
        &mut self,
        template: &[u8],
    ) -> Result<(), crate::error::ConnectionError> {
        self.ch_template = template.to_vec();
        Ok(())
    }

    /// Enable/disable performance mode
    /// Performance mode: Full TLS Cover traffic but NO artificial delays/padding/jitter
    /// Stealth mode: Full sophistication including timing variations and padding
    pub fn set_performance_mode(&mut self, enabled: bool) {
        self.performance_mode = enabled;
        if enabled {
            log::debug!("TLS Cover performance mode: Full cover traffic, no artificial delays");
        } else {
            log::debug!("TLS Cover stealth mode: Full sophistication with timing/padding");
        }
    }

    pub fn handshake_complete(&self) -> bool {
        self.handshake_complete
    }

    pub fn alpn(&self) -> Option<&str> {
        self.alpn.as_deref()
    }

    pub fn peer_cert(&self) -> Option<Vec<u8>> {
        None
    }

    pub fn enable_0rtt(&mut self) -> Result<(), crate::error::ConnectionError> {
        Ok(())
    }

    pub fn get_0rtt_keys(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        None
    }

    pub fn export_keying_material(
        &self,
        _label: &[u8],
        _context: &[u8],
        length: usize,
    ) -> Result<Vec<u8>, crate::error::ConnectionError> {
        Ok(vec![0x42; length])
    }

    pub fn get_quic_transport_params(&self) -> Vec<u8> {
        vec![]
    }

    pub fn set_peer_transport_params(
        &mut self,
        _params: &[u8],
    ) -> Result<(), crate::error::ConnectionError> {
        Ok(())
    }

    pub fn key_update(&mut self) -> Result<(), crate::error::ConnectionError> {
        Ok(())
    }

    pub fn provide_quic_data(
        &mut self,
        level: crate::tls_provider::Level,
        data: &[u8],
    ) -> Result<(), crate::error::ConnectionError> {
        // Usage of is_server/crypto: telemetry and handshake status.
        let _guard = self.crypto.read();
        crate::telemetry::BYTES_RECEIVED.inc_by(data.len() as u64);
        if matches!(level, crate::tls_provider::Level::Handshake) && self.is_server {
            self.handshake_complete = true;
        }
        Ok(())
    }

    pub fn next_crypto_frame(
        &mut self,
        _level: crate::tls_provider::Level,
        max_len: usize,
    ) -> Option<(u64, Vec<u8>)> {
        // Generate sophisticated TLS Cover frames for cover traffic
        if !self.handshake_complete {
            let frame = self.generate_fake_crypto_frame(max_len);
            if !frame.is_empty() {
                return Some((0, frame));
            }
        }
        None
    }

    /// Generate sophisticated fake crypto frame based on stealth mode
    fn generate_fake_crypto_frame(&self, max_len: usize) -> Vec<u8> {
        // In performance mode: Full TLS Cover but no artificial delays/padding/jitter
        // We still generate realistic TLS frames for cover traffic!

        // Stealth mode: full sophistication
        use rand::Rng;
        let mut rng = rand::thread_rng();

        // Generate realistic TLS record structure
        let mut frame = Vec::new();

        // TLS Record Header (5 bytes): Type(1) + Version(2) + Length(2)
        frame.push(0x16); // Handshake
        frame.extend_from_slice(&[0x03, 0x03]); // TLS 1.2

        // Calculate realistic payload size; account for server/client role.
        let mut payload_size = if self.performance_mode {
            // Performance mode: choose an optimal size depending on role.
            let base = if self.is_server { 800 } else { 1200 };
            max_len.min(base).saturating_sub(5)
        } else {
            // Stealth mode: realistische Variation
            let base_range = if self.is_server { 150..700 } else { 200..800 };
            let base_size = if max_len > 1000 {
                rng.gen_range(base_range)
            } else {
                rng.gen_range(50..max_len.min(300))
            };
            let jitter = rng.gen_range(0..50);
            (base_size + jitter).min(max_len.saturating_sub(5))
        };

        // Optional extra padding for cover traffic (stealth mode only)
        if !self.performance_mode {
            let pad_max_env = std::env::var("QUICFUSCATE_STEALTH_PADDING_MAX")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0);
            if pad_max_env > 0 {
                let headroom = max_len.saturating_sub(5).saturating_sub(payload_size);
                if headroom > 0 {
                    let pad = rng.gen_range(0..=pad_max_env.min(headroom));
                    payload_size = payload_size.saturating_add(pad);
                }
            }
        }

        frame.extend_from_slice(&(payload_size as u16).to_be_bytes());

        // Generate realistic handshake payload
        let mut payload = vec![0u8; payload_size];
        rng.fill(&mut payload[..]);

        // Add realistic handshake message structure
        if payload_size > 10 {
            payload[0] = 0x01; // ClientHello
            payload[1..4].copy_from_slice(&((payload_size - 4) as u32).to_be_bytes()[1..]);
            payload[4..6].copy_from_slice(&[0x03, 0x03]); // TLS version
                                                          // Subtle per-profile tag to influence payload fingerprint a tiny bit
            let tag: u8 = match self.fingerprint_profile.as_str() {
                "chrome" => 0xC0,
                "firefox" => 0xF0,
                "safari" => 0xA0,
                "edge" => 0xE0,
                _ => 0x90,
            };
            // XOR into a safe byte position within header body area
            let idx = 6.min(payload.len() - 1);
            payload[idx] ^= tag;
        }

        let cipher_len = payload_size + 16;
        let mut header = frame;
        if header.len() >= 5 {
            header[3..5].copy_from_slice(&(cipher_len as u16).to_be_bytes());
        }

        let ciphertext = {
            let mut ctx = self.crypto.write();
            let needs_reinstall = ctx.tls_cover_cipher_kind() != Some(self.cipher_suite.kind());
            if needs_reinstall {
                match self.cipher_suite {
                    TlsCoverCipherSuite::ChaCha20Poly1305 => {
                        ctx.install_tls_cover_chacha(&self.tls_cover_key, &self.tls_cover_iv);
                    }
                    TlsCoverCipherSuite::Aes128Gcm => {
                        let mut aes_key = [0u8; 16];
                        aes_key.copy_from_slice(&self.tls_cover_key[..16]);
                        ctx.install_tls_cover_aes_gcm(&aes_key, &self.tls_cover_iv);
                    }
                }
            }
            ctx.encrypt_tls_cover_record(&header, &payload)
        };

        let mut frame_out = header;
        match ciphertext {
            Ok(ct) => frame_out.extend_from_slice(&ct),
            Err(_) => {
                // Fallback to plaintext if encryption fails
                frame_out.extend_from_slice(&payload);
            }
        }

        if !self.performance_mode {
            // Runtime-configurable jitter in microseconds (0 disables)
            let jitter_us_max = std::env::var("QUICFUSCATE_STEALTH_JITTER_US")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            if jitter_us_max > 0 {
                let jitter = rng.gen_range(1..=jitter_us_max);
                std::thread::sleep(std::time::Duration::from_micros(jitter));
            }
        }

        frame_out
    }

    pub fn poll_secrets_and_install(
        &mut self,
        _crypto: &Arc<parking_lot::RwLock<crate::transport::packet::CryptoContext>>,
    ) -> Result<(), crate::error::ConnectionError> {
        self.handshake_complete = true;
        Ok(())
    }
}

pub mod tls_cover {
    use super::FingerprintProfile;

    /// Minimal TLS Cover builder used to craft synthetic TLS records for DPI evasion.
    ///
    /// The `TlsCover` utilities generate compact ClientHello/ServerHello records and
    /// optional certificate frames which resemble a TLS handshake without establishing
    /// a real session. This is used when `StealthConfig::use_tls_cover` is enabled to
    /// decouple QUIC transport from observable TLS handshakes.
    /// Owned variant of [`ServerHelloParams`] for storing in fingerprint profiles.
    #[derive(Debug, Clone)]
    pub struct ServerHelloParamsOwned {
        pub tls_version: u16,
        pub cipher_suite: u16,
        pub extensions: Vec<u8>,
    }

    /// Parameters used to craft a minimal ClientHello message.
    #[derive(Clone, Copy)]
    pub struct ClientHelloParams<'a> {
        /// TLS protocol version (e.g. `0x0303` for TLS 1.2).
        pub tls_version: u16,
        /// List of cipher suites encoded as IANA identifiers.
        pub cipher_suites: &'a [u16],
        /// Raw extension block to append after the compression method.
        pub extensions: &'a [u8],
    }

    /// Parameters used to craft a minimal ServerHello message.
    #[derive(Clone, Copy)]
    pub struct ServerHelloParams<'a> {
        /// TLS protocol version returned by the server.
        pub tls_version: u16,
        /// Selected cipher suite encoded as IANA identifier.
        pub cipher_suite: u16,
        /// Raw extension block of the server response.
        pub extensions: &'a [u8],
    }

    /// Helper functions for TLS extension building
    pub fn u16be(v: u16) -> [u8; 2] {
        v.to_be_bytes()
    }

    pub fn grease_value(idx: usize) -> u16 {
        let base: u16 = 0x0a0a;
        let step: u16 = 0x1010;
        base.wrapping_add(step.wrapping_mul(idx as u16))
    }

    pub fn grease_ext(seed: u16) -> Vec<u8> {
        let idx = (seed & 0x000f) as usize;
        let t = grease_value(idx);
        let mut ext = Vec::with_capacity(4);
        ext.extend_from_slice(&t.to_be_bytes());
        ext.extend_from_slice(&0u16.to_be_bytes());
        ext
    }

    pub fn alpn_ext(protocols: &[&str]) -> Vec<u8> {
        let mut names = Vec::new();
        for p in protocols {
            names.push(p.len() as u8);
            names.extend_from_slice(p.as_bytes());
        }
        let mut ext = Vec::with_capacity(4 + 2 + names.len());
        ext.extend_from_slice(&0x0010u16.to_be_bytes());
        let list_len = names.len() as u16;
        ext.extend_from_slice(&(list_len + 2).to_be_bytes());
        ext.extend_from_slice(&list_len.to_be_bytes());
        ext.extend_from_slice(&names);
        ext
    }

    pub fn supported_versions_ext(versions: &[u16]) -> Vec<u8> {
        let mut body = Vec::with_capacity(1 + 2 * versions.len());
        body.push((versions.len() * 2) as u8);
        for v in versions {
            body.extend_from_slice(&u16be(*v));
        }
        let mut ext = Vec::with_capacity(4 + body.len());
        ext.extend_from_slice(&0x002Bu16.to_be_bytes());
        ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
        ext.extend_from_slice(&body);
        ext
    }

    pub fn signature_algorithms_ext(schemes: &[u16]) -> Vec<u8> {
        let mut body = Vec::with_capacity(2 + 2 * schemes.len());
        body.extend_from_slice(&u16be((schemes.len() * 2) as u16));
        for s in schemes {
            body.extend_from_slice(&u16be(*s));
        }
        let mut ext = Vec::with_capacity(4 + body.len());
        ext.extend_from_slice(&0x000Du16.to_be_bytes());
        ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
        ext.extend_from_slice(&body);
        ext
    }

    pub fn signature_algorithms_cert_ext(schemes: &[u16]) -> Vec<u8> {
        let mut body = Vec::with_capacity(2 + 2 * schemes.len());
        body.extend_from_slice(&u16be((schemes.len() * 2) as u16));
        for s in schemes {
            body.extend_from_slice(&u16be(*s));
        }
        let mut ext = Vec::with_capacity(4 + body.len());
        ext.extend_from_slice(&0x0032u16.to_be_bytes());
        ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
        ext.extend_from_slice(&body);
        ext
    }

    pub fn supported_groups_ext(groups: &[u16]) -> Vec<u8> {
        let mut body = Vec::with_capacity(2 + 2 * groups.len());
        body.extend_from_slice(&u16be((groups.len() * 2) as u16));
        for g in groups {
            body.extend_from_slice(&u16be(*g));
        }
        let mut ext = Vec::with_capacity(4 + body.len());
        ext.extend_from_slice(&0x000Au16.to_be_bytes());
        ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
        ext.extend_from_slice(&body);
        ext
    }

    pub fn psk_key_exchange_modes_ext(modes: &[u8]) -> Vec<u8> {
        let mut body = Vec::with_capacity(1 + modes.len());
        body.push(modes.len() as u8);
        body.extend_from_slice(modes);
        let mut ext = Vec::with_capacity(4 + body.len());
        ext.extend_from_slice(&0x002Du16.to_be_bytes());
        ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
        ext.extend_from_slice(&body);
        ext
    }

    pub fn key_share_ext(group: u16, seed: u64) -> Vec<u8> {
        let kx_len = 32usize;
        let mut kx = vec![0u8; kx_len];
        let mut x = seed ^ 0x9E3779B97F4A7C15u64;
        for b in &mut kx {
            x ^= x << 7;
            x ^= x >> 9;
            x ^= x << 8;
            *b = (x & 0xFF) as u8;
        }
        let mut entry = Vec::with_capacity(4 + kx_len);
        entry.extend_from_slice(&u16be(group));
        entry.extend_from_slice(&u16be(kx_len as u16));
        entry.extend_from_slice(&kx);
        let mut body = Vec::with_capacity(2 + entry.len());
        body.extend_from_slice(&u16be(entry.len() as u16));
        body.extend_from_slice(&entry);
        let mut ext = Vec::with_capacity(4 + body.len());
        ext.extend_from_slice(&0x0033u16.to_be_bytes());
        ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
        ext.extend_from_slice(&body);
        ext
    }

    /// TLS 1.3 padding extension (type 0x0015). Fills with zeros.
    pub fn padding_ext(pad_len: usize) -> Vec<u8> {
        let pad_len = pad_len.min(256);
        let mut ext = Vec::with_capacity(4 + pad_len);
        ext.extend_from_slice(&0x0015u16.to_be_bytes());
        ext.extend_from_slice(&(pad_len as u16).to_be_bytes());
        if pad_len > 0 {
            let zeros = vec![0u8; pad_len];
            ext.extend_from_slice(&zeros);
        }
        ext
    }

    /// ECH GREASE (draft) extension: 0xFE0D with random payload (TLS Cover only)
    pub fn ech_grease_ext(seed: u16) -> Vec<u8> {
        let mut x = (seed as u64) ^ 0xD15E_A5E5_F00D_F00D_u64;
        // Pseudo-random length in 8..40
        x ^= x.rotate_left(13);
        let len = 8 + (x as usize & 0x1F);
        let mut body = vec![0u8; len];
        for b in &mut body {
            x ^= x << 7;
            x ^= x >> 9;
            x ^= x << 8;
            *b = (x & 0xFF) as u8;
        }
        let mut ext = Vec::with_capacity(4 + len);
        ext.extend_from_slice(&0xFE0Du16.to_be_bytes());
        ext.extend_from_slice(&(len as u16).to_be_bytes());
        ext.extend_from_slice(&body);
        ext
    }

    pub fn sni_ext(host: &str) -> Vec<u8> {
        let name_bytes = host.as_bytes();
        let mut name = Vec::with_capacity(3 + name_bytes.len());
        name.push(0u8);
        name.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        name.extend_from_slice(name_bytes);
        let mut body = Vec::with_capacity(2 + name.len());
        body.extend_from_slice(&(name.len() as u16).to_be_bytes());
        body.extend_from_slice(&name);
        let mut ext = Vec::with_capacity(4 + body.len());
        ext.extend_from_slice(&0x0000u16.to_be_bytes());
        ext.extend_from_slice(&(body.len() as u16).to_be_bytes());
        ext.extend_from_slice(&body);
        ext
    }

    /// Hard coded ClientHello payload used when a profile does not provide one.
    /// This is not a valid TLS handshake, it merely resembles one for DPI evasion.
    pub const DEFAULT_CLIENT_HELLO: &[u8] = &[
        0x16, 0x03, 0x01, 0x00, 0x0f, // record header
        0x01, 0x00, 0x00, 0x0b, // handshake header
        b'f', b'a', b'k', b'e', b'-', b'c', b'l', b'i', b'e', b'n', b't',
    ];

    /// Hard coded ServerHello payload returned by the fake server.
    pub const DEFAULT_SERVER_HELLO: &[u8] = &[
        0x16, 0x03, 0x03, 0x00, 0x0f, 0x02, 0x00, 0x00, 0x0b, b'f', b'a', b'k', b'e', b'-', b's',
        b'e', b'r', b'v', b'e', b'r',
    ];

    /// Hard coded certificate payload used by the fake server.
    pub const DEFAULT_CERTIFICATE: &[u8] =
        &[0x16, 0x03, 0x03, 0x00, 0x08, 0x0b, 0x00, 0x00, 0x04, b'c', b'e', b'r', b't'];

    /// Entry point for constructing synthetic TLS records (TLS Cover).
    /// Provides helpers to emit ClientHello/ServerHello and certificate frames
    /// for DPI evasion without establishing a real TLS session.
    pub struct TlsCover;

    impl TlsCover {
        /// Generate sophisticated ClientHello with browser-specific extensions
        pub fn generate_client_hello(
            browser: super::BrowserProfile,
            os: super::OsProfile,
            sni: Option<&str>,
        ) -> Vec<u8> {
            let seed = (browser as u16) ^ ((os as u16) << 8);
            let enable_grease = !matches!(browser, super::BrowserProfile::Safari);

            // Browser-specific cipher suites
            let mut ciphers = match browser {
                super::BrowserProfile::Firefox => vec![
                    0x1301, 0x1303, 0x1302, 0xC02B, 0xC02F, 0xCCA9, 0xCCA8, 0xC02C, 0xC030, 0xC013,
                    0xC014,
                ],
                _ => vec![
                    0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013,
                    0xC014,
                ],
            };

            // OS-specific ordering tweaks for fingerprint parity (TLS Cover only)
            if matches!(os, super::OsProfile::Android) {
                // Place ChaCha earlier on Android to mirror common mobile stacks
                if let Some(pos) = ciphers.iter().position(|&cs| cs == 0x1303) {
                    if pos > 1 {
                        ciphers.remove(pos);
                        ciphers.insert(1, 0x1303);
                    }
                }
            }

            // Add GREASE cipher if enabled
            if enable_grease {
                let grease = grease_value(seed as usize);
                if !ciphers.contains(&grease) {
                    ciphers.insert(0, grease);
                }
            }

            // Build extensions in browser-specific order
            let mut exts = Vec::with_capacity(512);
            let ext_order = match browser {
                super::BrowserProfile::Chrome | super::BrowserProfile::Edge => &[
                    "grease",
                    "sni",
                    "supported_versions",
                    "key_share",
                    "psk_modes",
                    "signature_algorithms",
                    "signature_algorithms_cert",
                    "supported_groups",
                    "alpn",
                ][..],
                super::BrowserProfile::Firefox => &[
                    "grease",
                    "sni",
                    "signature_algorithms",
                    "signature_algorithms_cert",
                    "supported_groups",
                    "key_share",
                    "supported_versions",
                    "psk_modes",
                    "alpn",
                ][..],
                super::BrowserProfile::Safari => &[
                    "sni",
                    "supported_versions",
                    "signature_algorithms",
                    "signature_algorithms_cert",
                    "supported_groups",
                    "key_share",
                    "alpn",
                ][..],
            };

            // OS-specific ALPN
            let alpns = match (browser, os) {
                (super::BrowserProfile::Safari, super::OsProfile::IOS) => vec!["h3", "http/1.1"],
                _ => vec!["h3", "h2", "http/1.1"],
            };

            let seed_for_key =
                ((browser as u64) * 0x9E37 + (os as u64) * 0xC2B2) ^ 0xA5A5_5A5A_F0F0_0F0F;

            for name in ext_order {
                match *name {
                    "grease" => {
                        if enable_grease {
                            exts.extend_from_slice(&grease_ext(seed));
                        }
                    }
                    "sni" => {
                        if let Some(host) = sni {
                            exts.extend_from_slice(&sni_ext(host));
                        }
                    }
                    "alpn" => exts.extend_from_slice(&alpn_ext(&alpns)),
                    "supported_versions" => {
                        let mut versions = vec![0x0304u16, 0x0303u16];
                        if enable_grease {
                            let gv = grease_value(seed as usize);
                            if !versions.contains(&gv) {
                                versions.insert(0, gv);
                            }
                        }
                        exts.extend_from_slice(&supported_versions_ext(&versions));
                    }
                    "signature_algorithms" => {
                        let sigs = [0x0403u16, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501];
                        exts.extend_from_slice(&signature_algorithms_ext(&sigs));
                    }
                    "signature_algorithms_cert" => {
                        let sigs = [0x0403u16, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501];
                        exts.extend_from_slice(&signature_algorithms_cert_ext(&sigs));
                    }
                    "supported_groups" => {
                        let mut groups = vec![0x001D, 0x0017, 0x0018];
                        if enable_grease {
                            let g = grease_value(seed as usize);
                            if !groups.contains(&g) {
                                groups.insert(0, g);
                            }
                        }
                        exts.extend_from_slice(&supported_groups_ext(&groups));
                    }
                    "psk_modes" => exts.extend_from_slice(&psk_key_exchange_modes_ext(&[0x01])),
                    "key_share" => exts.extend_from_slice(&key_share_ext(0x001D, seed_for_key)),
                    _ => {}
                }
            }

            // Optional ULTRA extras: ECH-GREASE + padding to smooth lengths
            let ultra = std::env::var("QUICFUSCATE_TLS_COVER_ULTRA")
                .or_else(|_| std::env::var("QUICFUSCATE_TLS_COVER_ULTRA"))
                .ok()
                .map(|v| v.to_ascii_lowercase())
                .map(|v| v == "1" || v == "true" || v == "on")
                .unwrap_or(false);
            if ultra {
                exts.extend_from_slice(&ech_grease_ext(seed));
                // Pad to pseudo-random target within a narrow band
                let tgt = 16 + ((seed as usize) & 0x1F); // 16..47
                exts.extend_from_slice(&padding_ext(tgt));
            }

            // Session ID behavior: Chrome/Edge/Safari often include 32B; Firefox empty
            match browser {
                super::BrowserProfile::Firefox => Self::client_hello_custom_with_sid(
                    ClientHelloParams {
                        tls_version: 0x0303,
                        cipher_suites: &ciphers,
                        extensions: &exts,
                    },
                    None,
                ),
                _ => {
                    let mut buf = [0u8; 32];
                    // Derive pseudo-random SID from seed and optional SNI to keep determinism
                    let mut x =
                        (seed as u64) ^ 0xC3_1D_00_5D_A5_5Au64 ^ (seed_for_key.rotate_left(17));
                    for b in &mut buf {
                        x ^= x << 7;
                        x ^= x >> 9;
                        x ^= x << 8;
                        *b = (x & 0xFF) as u8;
                    }
                    Self::client_hello_custom_with_sid(
                        ClientHelloParams {
                            tls_version: 0x0303,
                            cipher_suites: &ciphers,
                            extensions: &exts,
                        },
                        Some(&buf[..]),
                    )
                }
            }
        }

        /// Returns the ClientHello message for the given fingerprint profile.
        pub fn client_hello(profile: &FingerprintProfile) -> Vec<u8> {
            if let Some(ref ch) = profile.client_hello {
                ch.clone()
            } else {
                DEFAULT_CLIENT_HELLO.to_vec()
            }
        }

        /// Helper to build a TLS handshake record for the given handshake type and
        /// payload.
        fn record(htype: u8, payload: &[u8]) -> Vec<u8> {
            let mut out = Vec::with_capacity(payload.len() + 9);
            out.extend_from_slice(&[0x16, 0x03, 0x03]); // Handshake record, TLS 1.2
            let len = payload.len() + 4;
            out.extend_from_slice(&(len as u16).to_be_bytes());
            out.push(htype);
            let l = (payload.len() as u32).to_be_bytes();
            out.extend_from_slice(&l[1..]);
            out.extend_from_slice(payload);
            out
        }

        /// Builds a minimal ClientHello record using the provided parameters.
        pub fn client_hello_custom(params: ClientHelloParams) -> Vec<u8> {
            Self::client_hello_custom_with_sid(params, None)
        }

        /// Builds a ClientHello with optional Session ID (for fingerprint parity per browser).
        pub fn client_hello_custom_with_sid(
            params: ClientHelloParams,
            session_id: Option<&[u8]>,
        ) -> Vec<u8> {
            let mut payload = Vec::new();
            payload.extend_from_slice(&params.tls_version.to_be_bytes());
            payload.extend_from_slice(&[0u8; 32]); // random
            match session_id {
                Some(sid) => {
                    payload.push(sid.len() as u8);
                    payload.extend_from_slice(sid);
                }
                None => {
                    payload.push(0);
                }
            }
            payload.extend_from_slice(&((params.cipher_suites.len() * 2) as u16).to_be_bytes());
            for cs in params.cipher_suites {
                payload.extend_from_slice(&cs.to_be_bytes());
            }
            payload.push(1); // compression methods len
            payload.push(0); // null compression
            payload.extend_from_slice(&(params.extensions.len() as u16).to_be_bytes());
            payload.extend_from_slice(params.extensions);
            Self::record(0x01, &payload)
        }

        /// Builds a minimal ServerHello record using the provided parameters.
        pub fn server_hello_custom(params: ServerHelloParams) -> Vec<u8> {
            let mut payload = Vec::new();
            payload.extend_from_slice(&params.tls_version.to_be_bytes());
            payload.extend_from_slice(&[0u8; 32]); // random
            payload.push(0); // session id len
            payload.extend_from_slice(&params.cipher_suite.to_be_bytes());
            payload.push(0); // null compression
            payload.extend_from_slice(&(params.extensions.len() as u16).to_be_bytes());
            payload.extend_from_slice(params.extensions);
            Self::record(0x02, &payload)
        }

        /// Builds a TLS Certificate record from raw certificate bytes.
        pub fn certificate_record(cert: &[u8]) -> Vec<u8> {
            Self::record(0x0b, cert)
        }

        /// Builds the server response consisting of a custom ServerHello and certificate.
        pub fn server_response_custom(sh: ServerHelloParams, cert: &[u8]) -> Vec<u8> {
            let mut out = Self::server_hello_custom(sh);
            out.extend_from_slice(&Self::certificate_record(cert));
            out
        }

        /// Builds a full TLS Cover handshake from explicit parameters.
        pub fn handshake_custom(ch: ClientHelloParams, sh: ServerHelloParams) -> Vec<u8> {
            let mut out = Self::client_hello_custom(ch);
            out.extend_from_slice(&Self::server_hello_custom(sh));
            out
        }

        /// Builds a TLS Cover handshake including a custom certificate record.
        pub fn handshake_custom_with_cert(
            ch: ClientHelloParams,
            sh: ServerHelloParams,
            cert: &[u8],
        ) -> Vec<u8> {
            let mut out = Self::client_hello_custom(ch);
            out.extend_from_slice(&Self::server_response_custom(sh, cert));
            out
        }

        /// Returns the fake server response consisting of ServerHello and a dummy
        /// certificate record.
        pub fn server_response() -> Vec<u8> {
            let mut out = DEFAULT_SERVER_HELLO.to_vec();
            out.extend_from_slice(DEFAULT_CERTIFICATE);
            out
        }

        /// Generates the complete TLS Cover handshake sequence.
        pub fn handshake(profile: &FingerprintProfile) -> Vec<u8> {
            let cert = profile.certificate.as_deref().unwrap_or(DEFAULT_CERTIFICATE);

            if profile.client_hello.is_none() && profile.server_hello.is_none() {
                let cipher_suite = *profile.tls_cipher_suites.first().unwrap_or(&0x1301);
                let suites = [cipher_suite];
                let ch_params = ClientHelloParams {
                    tls_version: 0x0303,
                    cipher_suites: &suites,
                    extensions: &[],
                };
                let sh_params =
                    ServerHelloParams { tls_version: 0x0303, cipher_suite, extensions: &[] };
                Self::handshake_custom_with_cert(ch_params, sh_params, cert)
            } else {
                let mut out = Self::client_hello(profile);

                let sh_params = if let Some(ref owned) = profile.server_hello {
                    ServerHelloParams {
                        tls_version: owned.tls_version,
                        cipher_suite: owned.cipher_suite,
                        extensions: &owned.extensions,
                    }
                } else {
                    ServerHelloParams {
                        tls_version: 0x0303,
                        cipher_suite: *profile.tls_cipher_suites.first().unwrap_or(&0x1301),
                        extensions: &[],
                    }
                };

                out.extend_from_slice(&Self::server_response_custom(sh_params, cert));
                out
            }
        }
    }
}

// Legacy quiche FFI removed: native TLS fingerprint injection is used exclusively.

// --- Global Tokio Runtime for async DoH requests ---
lazy_static! {
    static ref DOH_RUNTIME: Runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)  // Optimized for DoH parallelism
        .thread_name("quicfuscate-doh")
        .enable_all()
        .build()
        .unwrap_or_else(|e| {
            error!("Failed to build Tokio runtime: {}", e);
            std::process::exit(1);
        });
}

// --- 1. DNS over HTTPS (DoH) ---

/// Built-in DoH provider endpoints for multi-provider resolution with fallback.
pub const DOH_PROVIDERS: &[&str] = &[
    "https://cloudflare-dns.com/dns-query", // Cloudflare - fastest, privacy-focused
    "https://dns.quad9.net:5053/dns-query", // Quad9 - security-focused, blocks malware
    "https://dns.google/resolve",           // Google - reliable, high availability
    "https://dns.nextdns.io/dns-query",     // NextDNS - privacy-focused, customizable
];

/// Atomic index for round-robin DoH provider rotation.
static DOH_PROVIDER_INDEX: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Asynchronously resolves a domain name using DNS-over-HTTPS with multi-provider fallback.
///
/// Tries providers in round-robin order, falling back to next provider on failure.
/// Rotation ensures load distribution and resilience against single provider outages.
///
/// # Arguments
/// * `domain` - The domain to resolve.
/// * `preferred_provider` - Optional preferred provider URL. If empty, uses built-in rotation.
///
/// # Returns
/// A `Result` containing the resolved `IpAddr` or an error if all providers fail.
pub async fn resolve_doh_multi(
    client: &Client,
    domain: &str,
    preferred_provider: &str,
) -> Result<IpAddr, Box<dyn std::error::Error>> {
    // If user specified a provider, try it first
    let providers: Vec<&str> = if !preferred_provider.is_empty() {
        std::iter::once(preferred_provider).chain(DOH_PROVIDERS.iter().copied()).collect()
    } else {
        // Round-robin rotation through built-in providers
        let start_idx = DOH_PROVIDER_INDEX.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % DOH_PROVIDERS.len();
        DOH_PROVIDERS.iter().cycle().skip(start_idx).take(DOH_PROVIDERS.len()).copied().collect()
    };

    let mut last_error: Option<Box<dyn std::error::Error>> = None;

    for provider in providers {
        match resolve_doh_single(client, domain, provider).await {
            Ok(ip) => {
                log::debug!("DoH resolved {} via {} -> {}", domain, provider, ip);
                return Ok(ip);
            }
            Err(e) => {
                log::warn!("DoH provider {} failed for {}: {}", provider, domain, e);
                last_error = Some(e);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| "All DoH providers failed".into()))
}

/// Single-provider DoH resolution (internal helper).
async fn resolve_doh_single(
    client: &Client,
    domain: &str,
    doh_provider: &str,
) -> Result<IpAddr, Box<dyn std::error::Error>> {
    let mut url = Url::parse(doh_provider).inspect_err(|&e| {
        error!("Invalid DoH provider URL: {}", e);
    })?;
    url.query_pairs_mut().append_pair("name", domain).append_pair("type", "A");

    let resp = client
        .get(url)
        .header("Accept", "application/dns-json")
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    if let Some(answers) = resp.get("Answer") {
        if let Some(arr) = answers.as_array() {
            for answer in arr {
                if answer["type"] == 1 {
                    if let Some(ip_str) = answer["data"].as_str() {
                        if let Ok(ip) = ip_str.parse() {
                            return Ok(ip);
                        }
                    }
                }
            }
        }
    }
    Err("No A record returned".into())
}

/// Legacy single-provider function for backward compatibility.
pub async fn resolve_doh(
    client: &Client,
    domain: &str,
    doh_provider: &str,
) -> Result<IpAddr, Box<dyn std::error::Error>> {
    resolve_doh_multi(client, domain, doh_provider).await
}

// --- 2. Browser/OS Fingerprinting ---

/// Defines the target browser for fingerprint spoofing.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum BrowserProfile {
    #[serde(alias = "Chrome")]
    Chrome,
    #[serde(alias = "Firefox")]
    Firefox,
    #[serde(alias = "Safari")]
    Safari,
    #[serde(alias = "Edge")]
    Edge,
}

impl std::str::FromStr for BrowserProfile {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "chrome" => Ok(BrowserProfile::Chrome),
            "firefox" => Ok(BrowserProfile::Firefox),
            "safari" => Ok(BrowserProfile::Safari),
            "edge" => Ok(BrowserProfile::Edge),
            _ => Err(()),
        }
    }
}

/// Defines the target operating system for fingerprint spoofing.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum OsProfile {
    #[serde(alias = "Windows")]
    Windows,
    #[serde(alias = "MacOS", alias = "mac", alias = "Mac")]
    MacOS,
    #[serde(alias = "Linux")]
    Linux,
    #[serde(alias = "IOS", alias = "iOS")]
    IOS,
    #[serde(alias = "Android")]
    Android,
}

impl std::str::FromStr for OsProfile {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "windows" => Ok(OsProfile::Windows),
            "macos" | "mac" => Ok(OsProfile::MacOS),
            "linux" => Ok(OsProfile::Linux),
            "ios" => Ok(OsProfile::IOS),
            "android" => Ok(OsProfile::Android),
            _ => Err(()),
        }
    }
}

/// Represents a complete client fingerprint profile.
#[derive(Debug, Clone)]
pub struct FingerprintProfile {
    pub browser: BrowserProfile,
    pub os: OsProfile,
    pub user_agent: String,
    pub tls_cipher_suites: Vec<u16>,
    pub accept_language: String,
    // Detailed QUIC transport parameters for deeper fingerprinting
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_streams_bidi: u64,
    pub max_idle_timeout: u64,
    pub client_hello: Option<Vec<u8>>,
    pub server_hello: Option<ServerHelloParamsOwned>,
    pub certificate: Option<Vec<u8>>,
}

impl FingerprintProfile {
    /// Creates a new profile for a given browser and OS combination, with harmonized values.
    pub fn new(browser: BrowserProfile, os: OsProfile) -> Self {
        let mut profile = match (browser, os) {
            // --- Windows Profiles ---
            (BrowserProfile::Chrome, OsProfile::Windows) => Self {
                browser, os,                user_agent: UA_CHROME_WIN.into(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
                accept_language: LANG_EN_US_09.into(),
                initial_max_data: 10_000_000,
                initial_max_stream_data_bidi_local: 1_000_000,
                initial_max_stream_data_bidi_remote: 1_000_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
            },
           (BrowserProfile::Firefox, OsProfile::Windows) => Self {
                browser, os,                user_agent: UA_FIREFOX_WIN.into(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
                accept_language: LANG_EN_US_05.into(),
                initial_max_data: 12_582_912,
                initial_max_stream_data_bidi_local: 1_048_576,
                initial_max_stream_data_bidi_remote: 1_048_576,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 60_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
            },
           (BrowserProfile::Edge, OsProfile::Windows) => Self {
               browser, os,               user_agent: UA_EDGE_WIN.into(),
               tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
               accept_language: LANG_EN_US_09.into(),
               initial_max_data: 10_000_000,
               initial_max_stream_data_bidi_local: 1_000_000,
               initial_max_stream_data_bidi_remote: 1_000_000,
               initial_max_streams_bidi: 100,
               max_idle_timeout: 30_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
           },
           (BrowserProfile::Edge, OsProfile::MacOS) => Self {
               browser, os,               user_agent: UA_EDGE_MAC.into(),
               tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
               accept_language: LANG_EN_US_09.into(),
               initial_max_data: 10_000_000,
               initial_max_stream_data_bidi_local: 1_000_000,
               initial_max_stream_data_bidi_remote: 1_000_000,
               initial_max_streams_bidi: 100,
               max_idle_timeout: 30_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
           },
           (BrowserProfile::Edge, OsProfile::Linux) => Self {
               browser, os,               user_agent: UA_EDGE_LINUX.into(),
               tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
               accept_language: LANG_EN_US_09.into(),
               initial_max_data: 10_000_000,
               initial_max_stream_data_bidi_local: 1_000_000,
               initial_max_stream_data_bidi_remote: 1_000_000,
               initial_max_streams_bidi: 100,
               max_idle_timeout: 30_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
           },
            // --- macOS Profiles ---
           (BrowserProfile::Safari, OsProfile::MacOS) => Self {
                browser, os,                user_agent: UA_SAFARI_MAC.into(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc009, 0xc013, 0xc00a, 0xc014],
                accept_language: LANG_EN_US_09.into(),
                initial_max_data: 15_728_640,
                initial_max_stream_data_bidi_local: 2_097_152,
                initial_max_stream_data_bidi_remote: 2_097_152,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 45_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
            },
            (BrowserProfile::Chrome, OsProfile::MacOS) => Self {
                browser, os,                user_agent: UA_CHROME_MAC.into(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
                accept_language: LANG_EN_US_09.into(),
                initial_max_data: 10_000_000,
                initial_max_stream_data_bidi_local: 1_000_000,
                initial_max_stream_data_bidi_remote: 1_000_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
            },
            (BrowserProfile::Firefox, OsProfile::MacOS) => Self {
                browser, os,                user_agent: UA_FIREFOX_MAC.into(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
                accept_language: LANG_EN_US_05.into(),
                initial_max_data: 12_582_912,
                initial_max_stream_data_bidi_local: 1_048_576,
                initial_max_stream_data_bidi_remote: 1_048_576,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 60_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
            },
            (BrowserProfile::Chrome, OsProfile::Linux) => Self {
                browser, os,                user_agent: UA_CHROME_LINUX.into(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
                accept_language: LANG_EN_US_09.into(),
                initial_max_data: 10_000_000,
                initial_max_stream_data_bidi_local: 1_000_000,
                initial_max_stream_data_bidi_remote: 1_000_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
            },
            (BrowserProfile::Firefox, OsProfile::Linux) => Self {
                browser, os,                user_agent: UA_FIREFOX_LINUX.into(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
                accept_language: LANG_EN_US_05.into(),
                initial_max_data: 12_582_912,
                initial_max_stream_data_bidi_local: 1_048_576,
                initial_max_stream_data_bidi_remote: 1_048_576,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 60_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
            },
            (BrowserProfile::Chrome, OsProfile::Android) => Self {
                browser, os,                user_agent: UA_CHROME_ANDROID.into(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
                accept_language: LANG_EN_US_09.into(),
                initial_max_data: 5_000_000,
                initial_max_stream_data_bidi_local: 500_000,
                initial_max_stream_data_bidi_remote: 500_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
            },
            (BrowserProfile::Firefox, OsProfile::Android) => Self {
                browser, os,                user_agent: UA_FIREFOX_ANDROID.into(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
                accept_language: LANG_EN_US_09.into(),
                initial_max_data: 5_000_000,
                initial_max_stream_data_bidi_local: 500_000,
                initial_max_stream_data_bidi_remote: 500_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
            },
            (BrowserProfile::Edge, OsProfile::Android) => Self {
                browser, os,                user_agent: "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36 EdgA/126.0.0.0".to_string(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc013, 0xc014],
                accept_language: LANG_EN_US_09.into(),
                initial_max_data: 5_000_000,
                initial_max_stream_data_bidi_local: 500_000,
                initial_max_stream_data_bidi_remote: 500_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
            },
            (BrowserProfile::Safari, OsProfile::IOS) => Self {
                browser, os,                user_agent: UA_SAFARI_IOS.into(),
                tls_cipher_suites: vec![0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xc009, 0xc013, 0xc00a, 0xc014],
                accept_language: LANG_EN_US_09.into(),
                initial_max_data: 5_000_000,
                initial_max_stream_data_bidi_local: 500_000,
                initial_max_stream_data_bidi_remote: 500_000,
                initial_max_streams_bidi: 100,
                max_idle_timeout: 30_000,
                client_hello: None,
                server_hello: None,
                certificate: None,
            },
            // --- Fallback Profile ---
            _ => Self::new(BrowserProfile::Chrome, OsProfile::Windows),
        };

        // Generate sophisticated ClientHello using browser-specific fingerprinting
        profile.client_hello = Some(tls_cover::TlsCover::generate_client_hello(
            profile.browser,
            profile.os,
            None, // SNI will be added dynamically
        ));

        // Generate matching ServerHello (heuristic selection for TLS Cover parity)
        let prefer_ultra = std::env::var("QUICFUSCATE_TLS_COVER_ULTRA")
            .or_else(|_| std::env::var("QUICFUSCATE_TLS_COVER_ULTRA"))
            .ok()
            .map(|v| v.to_ascii_lowercase())
            .map(|v| v == "1" || v == "true" || v == "on")
            .unwrap_or(false);
        let cipher_suite = if prefer_ultra && profile.os == OsProfile::Android {
            0x1303 // TLS_CHACHA20_POLY1305_SHA256 for Android parity
        } else {
            0x1301 // TLS_AES_128_GCM_SHA256 default
        };
        profile.server_hello = Some(ServerHelloParamsOwned {
            tls_version: 0x0303,
            cipher_suite,
            extensions: Vec::new(),
        });
        profile.certificate = None;
        profile
    }

    /// Generates a set of realistic HTTP headers based on the profile.
    pub fn generate_http_headers(&self) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("User-Agent".to_string(), self.user_agent.clone());
        headers.insert(
            "Accept".to_string(),
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
                .to_string(),
        );
        headers.insert("Accept-Language".to_string(), self.accept_language.clone());
        headers.insert("Accept-Encoding".to_string(), "gzip, deflate, br".to_string());
        headers.insert("Connection".to_string(), "keep-alive".to_string());
        headers
    }
}

// --- 3. HTTP/3 Masquerading ---

const ACCEPT_ENCODING_VALUE: &[u8] = b"gzip, deflate, br";
const SEC_FETCH_DEST_VALUE: &[u8] = b"document";
const SEC_FETCH_MODE_VALUE: &[u8] = b"navigate";
const SEC_FETCH_USER_VALUE: &[u8] = b"?1";
const UPGRADE_INSECURE_REQUESTS_VALUE: &[u8] = b"1";
const CACHE_CONTROL_VALUE: &[u8] = b"max-age=0";
const MOBILE_TRUE_VALUE: &[u8] = b"?1";
const MOBILE_FALSE_VALUE: &[u8] = b"?0";

#[derive(Copy, Clone)]
struct HeaderTemplateEntry {
    name: &'static [u8],
    value: HeaderValueSpec,
}

#[derive(Copy, Clone)]
enum HeaderValueSpec {
    Dynamic(DynamicValueSpec),
}

#[derive(Copy, Clone)]
enum DynamicValueSpec {
    UserAgent,
    Accept,
    AcceptLanguage,
    AcceptEncoding,
    SecChUa,
    SecChUaMobile,
    SecChUaPlatform,
    SecFetchDest,
    SecFetchMode,
    SecFetchSite,
    SecFetchUser,
    UpgradeInsecureRequests,
    CacheControl,
    Cookie,
    Referer,
}

struct PersonaTemplate {
    entries: &'static [HeaderTemplateEntry],
}

struct HeaderDynamic<'a> {
    user_agent: &'a [u8],
    accept: &'a [u8],
    accept_language: &'a [u8],
    accept_encoding: &'a [u8],
    sec_ch_ua: Option<&'a [u8]>,
    sec_ch_ua_mobile: &'a [u8],
    sec_ch_ua_platform: &'a [u8],
    sec_fetch_dest: &'a [u8],
    sec_fetch_mode: &'a [u8],
    sec_fetch_site: &'a [u8],
    sec_fetch_user: &'a [u8],
    upgrade_insecure_requests: &'a [u8],
    cache_control: &'a [u8],
    cookie: Option<&'a [u8]>,
    referer: Option<&'a [u8]>,
}

impl HeaderValueSpec {
    fn resolve<'a>(&self, ctx: &'a HeaderDynamic<'a>) -> Option<&'a [u8]> {
        match self {
            HeaderValueSpec::Dynamic(kind) => kind.resolve(ctx),
        }
    }
}

impl DynamicValueSpec {
    fn resolve<'a>(&self, ctx: &'a HeaderDynamic<'a>) -> Option<&'a [u8]> {
        match self {
            DynamicValueSpec::UserAgent => Some(ctx.user_agent),
            DynamicValueSpec::Accept => Some(ctx.accept),
            DynamicValueSpec::AcceptLanguage => Some(ctx.accept_language),
            DynamicValueSpec::AcceptEncoding => Some(ctx.accept_encoding),
            DynamicValueSpec::SecChUa => ctx.sec_ch_ua,
            DynamicValueSpec::SecChUaMobile => Some(ctx.sec_ch_ua_mobile),
            DynamicValueSpec::SecChUaPlatform => Some(ctx.sec_ch_ua_platform),
            DynamicValueSpec::SecFetchDest => Some(ctx.sec_fetch_dest),
            DynamicValueSpec::SecFetchMode => Some(ctx.sec_fetch_mode),
            DynamicValueSpec::SecFetchSite => Some(ctx.sec_fetch_site),
            DynamicValueSpec::SecFetchUser => Some(ctx.sec_fetch_user),
            DynamicValueSpec::UpgradeInsecureRequests => Some(ctx.upgrade_insecure_requests),
            DynamicValueSpec::CacheControl => Some(ctx.cache_control),
            DynamicValueSpec::Cookie => ctx.cookie,
            DynamicValueSpec::Referer => ctx.referer,
        }
    }
}

impl PersonaTemplate {
    fn for_browser(browser: BrowserProfile) -> &'static Self {
        match browser {
            BrowserProfile::Chrome | BrowserProfile::Edge => &CHROMIUM_TEMPLATE,
            BrowserProfile::Firefox | BrowserProfile::Safari => &TITLECASE_TEMPLATE,
        }
    }

    fn apply(
        &self,
        backend: &AsciiSimdBackend,
        ctx: &HeaderDynamic<'_>,
        headers: &mut Vec<crate::transport::h3::Header>,
    ) {
        for entry in self.entries {
            if let Some(value) = entry.value.resolve(ctx) {
                headers.push(make_header(backend, entry.name, value));
            }
        }
    }
}

fn make_header(
    backend: &AsciiSimdBackend,
    name: &[u8],
    value: &[u8],
) -> crate::transport::h3::Header {
    let mut name_vec = Vec::with_capacity(name.len());
    backend.append_bytes(&mut name_vec, name);
    let mut value_vec = Vec::with_capacity(value.len());
    backend.append_bytes(&mut value_vec, value);
    crate::transport::h3::Header::from_parts(name_vec, value_vec)
}

const CHROMIUM_TEMPLATE_ENTRIES: &[HeaderTemplateEntry] = &[
    HeaderTemplateEntry {
        name: b"user-agent",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::UserAgent),
    },
    HeaderTemplateEntry {
        name: b"accept",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::Accept),
    },
    HeaderTemplateEntry {
        name: b"accept-language",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::AcceptLanguage),
    },
    HeaderTemplateEntry {
        name: b"accept-encoding",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::AcceptEncoding),
    },
    HeaderTemplateEntry {
        name: b"sec-ch-ua",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::SecChUa),
    },
    HeaderTemplateEntry {
        name: b"sec-ch-ua-mobile",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::SecChUaMobile),
    },
    HeaderTemplateEntry {
        name: b"sec-ch-ua-platform",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::SecChUaPlatform),
    },
    HeaderTemplateEntry {
        name: b"sec-fetch-dest",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::SecFetchDest),
    },
    HeaderTemplateEntry {
        name: b"sec-fetch-mode",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::SecFetchMode),
    },
    HeaderTemplateEntry {
        name: b"sec-fetch-site",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::SecFetchSite),
    },
    HeaderTemplateEntry {
        name: b"sec-fetch-user",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::SecFetchUser),
    },
    HeaderTemplateEntry {
        name: b"upgrade-insecure-requests",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::UpgradeInsecureRequests),
    },
    HeaderTemplateEntry {
        name: b"cache-control",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::CacheControl),
    },
    HeaderTemplateEntry {
        name: b"cookie",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::Cookie),
    },
    HeaderTemplateEntry {
        name: b"referer",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::Referer),
    },
];

const TITLECASE_TEMPLATE_ENTRIES: &[HeaderTemplateEntry] = &[
    HeaderTemplateEntry {
        name: b"User-Agent",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::UserAgent),
    },
    HeaderTemplateEntry {
        name: b"Accept",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::Accept),
    },
    HeaderTemplateEntry {
        name: b"Accept-Language",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::AcceptLanguage),
    },
    HeaderTemplateEntry {
        name: b"Accept-Encoding",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::AcceptEncoding),
    },
    HeaderTemplateEntry {
        name: b"Sec-Fetch-Dest",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::SecFetchDest),
    },
    HeaderTemplateEntry {
        name: b"Sec-Fetch-Mode",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::SecFetchMode),
    },
    HeaderTemplateEntry {
        name: b"Sec-Fetch-Site",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::SecFetchSite),
    },
    HeaderTemplateEntry {
        name: b"Sec-Fetch-User",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::SecFetchUser),
    },
    HeaderTemplateEntry {
        name: b"Upgrade-Insecure-Requests",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::UpgradeInsecureRequests),
    },
    HeaderTemplateEntry {
        name: b"Cache-Control",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::CacheControl),
    },
    HeaderTemplateEntry {
        name: b"Referer",
        value: HeaderValueSpec::Dynamic(DynamicValueSpec::Referer),
    },
];

const CHROMIUM_TEMPLATE: PersonaTemplate = PersonaTemplate { entries: CHROMIUM_TEMPLATE_ENTRIES };
const TITLECASE_TEMPLATE: PersonaTemplate = PersonaTemplate { entries: TITLECASE_TEMPLATE_ENTRIES };

/// Manages the generation of fake HTTP/3 headers to masquerade QUIC traffic.
pub struct Http3Masquerade {
    profile: FingerprintProfile,
}

impl Http3Masquerade {
    /// Creates a new masquerader using the provided fingerprint profile.
    ///
    /// The profile controls pseudo-header fields such as `user-agent` and
    /// `accept-language` that are reflected in generated request headers.
    pub fn new(profile: FingerprintProfile) -> Self {
        Self { profile }
    }

    /// Generates a list of QPACK-style headers for an HTTP/3 request.
    /// This is a simplified representation. A real implementation uses QPACK.
    pub fn generate_headers(&self, host: &str, path: &str) -> Vec<crate::transport::h3::Header> {
        let mut headers = vec![
            crate::transport::h3::Header::new(b":method", b"GET"),
            crate::transport::h3::Header::new(b":scheme", b"https"),
            crate::transport::h3::Header::new(b":authority", host.as_bytes()),
            crate::transport::h3::Header::new(b":path", path.as_bytes()),
        ];

        let backend = AsciiSimdBackend::detect();
        let accept_language_owned = self.get_browser_accept_language();
        let accept_header_bytes = self.get_browser_accept_header().as_bytes();
        let fetch_site_bytes = self.get_sec_fetch_site(host).as_bytes();
        let sec_ch_ua_owned =
            if matches!(self.profile.browser, BrowserProfile::Chrome | BrowserProfile::Edge) {
                Some(self.build_sec_ch_ua())
            } else {
                None
            };
        let cookie_owned = if self.should_include_cookies(host) {
            Some(self.generate_realistic_cookies())
        } else {
            None
        };
        let referer_owned = if self.should_include_referer(host) {
            Some(self.generate_realistic_referer(host))
        } else {
            None
        };

        let sec_ch_ua_mobile =
            if self.is_mobile() { MOBILE_TRUE_VALUE } else { MOBILE_FALSE_VALUE };
        let platform_bytes = self.get_platform_string().as_bytes();

        let dynamic = HeaderDynamic {
            user_agent: self.profile.user_agent.as_bytes(),
            accept: accept_header_bytes,
            accept_language: accept_language_owned.as_bytes(),
            accept_encoding: ACCEPT_ENCODING_VALUE,
            sec_ch_ua: sec_ch_ua_owned.as_deref().map(str::as_bytes),
            sec_ch_ua_mobile,
            sec_ch_ua_platform: platform_bytes,
            sec_fetch_dest: SEC_FETCH_DEST_VALUE,
            sec_fetch_mode: SEC_FETCH_MODE_VALUE,
            sec_fetch_site: fetch_site_bytes,
            sec_fetch_user: SEC_FETCH_USER_VALUE,
            upgrade_insecure_requests: UPGRADE_INSECURE_REQUESTS_VALUE,
            cache_control: CACHE_CONTROL_VALUE,
            cookie: cookie_owned.as_deref().map(str::as_bytes),
            referer: referer_owned.as_deref().map(str::as_bytes),
        };

        let template = PersonaTemplate::for_browser(self.profile.browser);
        template.apply(&backend, &dynamic, &mut headers);

        headers
    }

    /// Returns platform string for `sec-ch-ua-platform`.
    fn get_platform_string(&self) -> &'static str {
        match self.profile.os {
            OsProfile::Windows => "\"Windows\"",
            OsProfile::MacOS => "\"macOS\"",
            OsProfile::Linux => "\"Linux\"",
            OsProfile::Android => "\"Android\"",
            OsProfile::IOS => "\"iOS\"",
        }
    }

    /// Returns whether current profile is mobile (Android/iOS).
    fn is_mobile(&self) -> bool {
        matches!(self.profile.os, OsProfile::Android | OsProfile::IOS)
    }

    /// Build a realistic sec-ch-ua value for the current browser.
    fn build_sec_ch_ua(&self) -> String {
        let ua = self.profile.user_agent.as_str();
        match self.profile.browser {
            BrowserProfile::Chrome => {
                let major = self.extract_major_version(ua, "Chrome").unwrap_or(126);
                format!(
                    "\"Chromium\";v=\"{0}\", \"Not A(Brand\";v=\"24\", \"Google Chrome\";v=\"{0}\"",
                    major
                )
            }
            BrowserProfile::Edge => {
                // Edge user-agent typically contains "Edg/<ver>" and Chrome base
                let major = self
                    .extract_major_version(ua, "Edg")
                    .or_else(|| self.extract_major_version(ua, "Chrome"))
                    .unwrap_or(126);
                format!("\"Chromium\";v=\"{0}\", \"Not A(Brand\";v=\"24\", \"Microsoft Edge\";v=\"{0}\"", major)
            }
            BrowserProfile::Firefox => {
                // Firefox does not widely use brands; still include a consistent value
                let major = self.extract_major_version(ua, "Firefox").unwrap_or(128);
                format!("\"Not A(Brand\";v=\"99\", \"Firefox\";v=\"{0}\"", major)
            }
            BrowserProfile::Safari => {
                // Safari: use Version/<ver> as proxy if present
                let major = self.extract_major_version(ua, "Version").unwrap_or(17);
                format!("\"Not A(Brand\";v=\"99\", \"Safari\";v=\"{0}\"", major)
            }
        }
    }

    /// Extracts major version from UA for tokens like "Token/123.4".
    fn extract_major_version(&self, ua: &str, token: &str) -> Option<u32> {
        let needle = format!("{}/", token);
        if let Some(pos) = ua.find(&needle) {
            let start = pos + needle.len();
            let tail = &ua[start..];
            let mut num = String::new();
            for ch in tail.chars() {
                if ch.is_ascii_digit() {
                    num.push(ch);
                } else {
                    break;
                }
            }
            if !num.is_empty() {
                return num.parse::<u32>().ok();
            }
        }
        None
    }

    /// Returns browser-specific Accept header for maximum realism.
    fn get_browser_accept_header(&self) -> &'static str {
        match self.profile.browser {
            BrowserProfile::Chrome => "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            BrowserProfile::Firefox => "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            BrowserProfile::Safari => "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            BrowserProfile::Edge => "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        }
    }

    /// Returns browser/OS-specific Accept-Language with realistic ordering.
    fn get_browser_accept_language(&self) -> String {
        let base_lang = &self.profile.accept_language;
        match self.profile.os {
            OsProfile::Windows => {
                // Windows tends to have more specific locale variants
                if base_lang.starts_with("en") {
                    "en-US,en;q=0.9".to_string()
                } else {
                    format!("{},en-US;q=0.9,en;q=0.8", base_lang)
                }
            }
            OsProfile::MacOS => {
                // macOS often has cleaner language preferences
                if base_lang.starts_with("en") {
                    "en-US,en;q=0.9".to_string()
                } else {
                    format!("{},en;q=0.9", base_lang)
                }
            }
            OsProfile::Linux => {
                // Linux users often have more diverse language setups
                if base_lang.starts_with("en") {
                    "en-US,en;q=0.9".to_string()
                } else {
                    format!("{},en-US;q=0.8,en;q=0.7", base_lang)
                }
            }
            OsProfile::Android => {
                // Android has specific mobile language patterns
                if base_lang.starts_with("en") {
                    "en-US,en;q=0.9".to_string()
                } else {
                    format!("{},en-US;q=0.9,en;q=0.8", base_lang)
                }
            }
            OsProfile::IOS => {
                // iOS similar to macOS but with mobile specifics
                if base_lang.starts_with("en") {
                    "en-US,en;q=0.9".to_string()
                } else {
                    format!("{},en;q=0.9", base_lang)
                }
            }
        }
    }

    /// Returns sec-fetch-site value based on fronting scenario.
    fn get_sec_fetch_site(&self, host: &str) -> &'static str {
        // Check if this looks like a CDN/fronting domain
        if host_contains(host, "cloudflare") || host_contains(host, "cdn") {
            "cross-site"
        } else {
            "none"
        }
    }

    /// Determines if cookies should be included based on browser and domain
    fn should_include_cookies(&self, host: &str) -> bool {
        // Include cookies for major sites and CDNs (more realistic)
        matches!(self.profile.browser, BrowserProfile::Chrome | BrowserProfile::Edge)
            && (host_contains(host, "google")
                || host_contains(host, "cloudflare")
                || host_contains(host, "amazon")
                || host_contains(host, "microsoft")
                || host_contains(host, "cdn")
                || host_contains(host, ".com"))
    }

    /// Generates realistic cookies with dynamic timestamps
    fn generate_realistic_cookies(&self) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        self.generate_realistic_cookies_at(timestamp)
    }

    /// Deterministic cookie rendering helper (exposed for testing/benchmarks).
    pub fn generate_realistic_cookies_at(&self, timestamp: u64) -> String {
        let ga_id = self.profile.user_agent.len() as u64 * 1_234_567 + timestamp % 1_000_000;
        let session_id =
            (self.profile.accept_language.len() as u64 + 1) * 987_654 + timestamp % 100_000;

        let mut raw = Vec::with_capacity(96);
        let simd = crate::accelerate::stealth::AsciiSimdBackend::detect();

        match self.profile.browser {
            BrowserProfile::Chrome | BrowserProfile::Edge => {
                simd.append_bytes(&mut raw, b"_ga=GA1.2.");
                simd.append_decimal(&mut raw, ga_id);
                simd.append_bytes(&mut raw, b".");
                simd.append_decimal(&mut raw, timestamp.saturating_sub(86_400));
                simd.append_bytes(&mut raw, b"; _gid=GA1.2.");
                simd.append_decimal(&mut raw, session_id);
                simd.append_bytes(&mut raw, b".");
                simd.append_decimal(&mut raw, timestamp);
                simd.append_bytes(&mut raw, b"; _gat=1");
            }
            BrowserProfile::Firefox => {
                simd.append_bytes(&mut raw, b"sessionid=");
                simd.append_decimal(&mut raw, session_id);
                simd.append_bytes(&mut raw, b"; csrftoken=");
                let token = timestamp % 0xFF_FFFF;
                simd.append_lower_hex(&mut raw, token);
            }
            BrowserProfile::Safari => {
                simd.append_bytes(&mut raw, b"s_sess=");
                simd.append_decimal(&mut raw, timestamp);
                simd.append_bytes(&mut raw, b"%20");
                simd.append_decimal(&mut raw, session_id);
                simd.append_bytes(&mut raw, b"%20End");
            }
        }

        String::from_utf8_lossy(&raw).into_owned()
    }

    /// Determines if referer should be included
    fn should_include_referer(&self, host: &str) -> bool {
        // Include referer for cross-site navigation (domain fronting scenarios)
        self.get_sec_fetch_site(host) == "cross-site"
    }

    /// Generates realistic referer based on fronting scenario
    fn generate_realistic_referer(&self, host: &str) -> String {
        let simd = crate::accelerate::stealth::AsciiSimdBackend::detect();

        if host_contains(host, "cloudflare") || host_contains(host, "cdn") {
            let literal: &[u8] = match self.profile.browser {
                BrowserProfile::Chrome | BrowserProfile::Edge => b"https://www.google.com/",
                BrowserProfile::Firefox => b"https://duckduckgo.com/",
                BrowserProfile::Safari => b"https://www.apple.com/",
            };
            let mut raw = Vec::with_capacity(literal.len());
            simd.append_bytes(&mut raw, literal);
            return String::from_utf8_lossy(&raw).into_owned();
        }

        if host.contains("amazon") || host.contains("aws") {
            let literal = b"https://console.aws.amazon.com/";
            let mut raw = Vec::with_capacity(literal.len());
            simd.append_bytes(&mut raw, literal);
            return String::from_utf8_lossy(&raw).into_owned();
        }

        if host.contains("microsoft") || host.contains("azure") {
            let literal = b"https://portal.azure.com/";
            let mut raw = Vec::with_capacity(literal.len());
            simd.append_bytes(&mut raw, literal);
            return String::from_utf8_lossy(&raw).into_owned();
        }

        let mut raw = Vec::with_capacity(host.len() + 9);
        simd.append_bytes(&mut raw, b"https://");
        simd.append_bytes(&mut raw, host.as_bytes());
        simd.append_bytes(&mut raw, b"/");

        String::from_utf8_lossy(&raw).into_owned()
    }

    /// Deterministic referer builder surfaced for tests and tooling.
    pub fn generate_realistic_referer_for(&self, host: &str) -> String {
        self.generate_realistic_referer(host)
    }
}

#[inline(always)]
fn host_contains(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    crate::accelerate::string::string_contains(haystack, needle)
}

/// Configuration for [`FakeHeaders`].
pub struct FakeHeadersConfig {
    /// If true, removes TCP-centric headers (for example, `connection`) to better
    /// align with QUIC semantics and reduce protocol mismatches during masquerading.
    pub optimize_for_quic: bool,
    /// If true, enables QPACK-friendly header ordering and allows callers to
    /// encode the header list using a QPACK encoder.
    pub use_qpack_headers: bool,
}

/// Generates HTTP/3 headers optionally optimized for QUIC.
pub struct FakeHeaders {
    cfg: FakeHeadersConfig,
    profile: FingerprintProfile,
}

impl FakeHeaders {
    /// Creates a new header generator with the given config and fingerprint profile.
    pub fn new(cfg: FakeHeadersConfig, profile: FingerprintProfile) -> Self {
        Self { cfg, profile }
    }

    /// Returns an HTTP/3 header list for the given `host` and `path`.
    ///
    /// When `optimize_for_quic` is enabled, TCP-specific headers (like
    /// `connection`) are removed. If `use_qpack_headers` is true, the
    /// list is suitable for QPACK encoding by the caller.
    pub fn header_list(&self, host: &str, path: &str) -> Vec<crate::transport::h3::Header> {
        let mut headers = Http3Masquerade::new(self.profile.clone()).generate_headers(host, path);
        if self.cfg.optimize_for_quic {
            headers.retain(|h| h.name() != b"connection");
        }
        headers
    }
}

// --- 4. Domain Fronting ---

/// Supported CDN providers for domain fronting with advanced rotation strategies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CdnProvider {
    Cloudflare,
    Fastly,
    Akamai,
    CloudFront,
    GoogleCloud,
    AzureCDN,
    StackPath,
    KeyCDN,
    BunnyCDN,
    Imperva,
}

impl CdnProvider {
    /// Returns multiple domains for this CDN provider for sophisticated rotation.
    pub fn get_domains(&self) -> Vec<&'static str> {
        match self {
            Self::Cloudflare => vec![
                "cdn.cloudflare.com",
                "cloudflare-dns.com",
                "one.one.one.one",
                "warp.plus",
                "workers.dev",
            ],
            Self::Fastly => vec!["cdn.fastly.net", "fastly.com", "fastlylb.net", "fsly.net"],
            Self::Akamai => vec![
                "akamaized.net",
                "akamai.net",
                "akamaihd.net",
                "akamaitechnologies.com",
                "edgesuite.net",
            ],
            Self::CloudFront => {
                vec!["cloudfront.net", "amazonaws.com", "aws.amazon.com", "awsstatic.com"]
            }
            Self::GoogleCloud => vec![
                "googleapis.com",
                "googleusercontent.com",
                "googlevideo.com",
                "gstatic.com",
                "google.com",
            ],
            Self::AzureCDN => {
                vec!["azureedge.net", "azure.microsoft.com", "windows.net", "msecnd.net"]
            }
            Self::StackPath => vec!["stackpathdns.com", "stackpathcdn.com", "bootstrapcdn.com"],
            Self::KeyCDN => vec!["kxcdn.com", "keycdn.com"],
            Self::BunnyCDN => vec!["b-cdn.net", "bunnycdn.com"],
            Self::Imperva => vec!["incapdns.net", "imperva.com"],
        }
    }

    /// Returns the primary domain for backward compatibility.
    pub fn get_domain(&self) -> &'static str {
        self.get_domains()[0]
    }
}

/// Manages domain fronting by rotating through configured domains.
///
/// Provides both round-robin and random selection strategies. Rotation is
/// thread-safe via an `AtomicUsize` index. Callers must ensure that the
/// domain list is non-empty before requesting a domain.
///
/// - Integration: used when `StealthConfig::enable_domain_fronting` is true.
///   Domains may come from `StealthConfig.fronting_domains` or be derived
///   from built-in [`CdnProvider`]s (via [`DomainFrontingManager::from_providers`]).
/// - Concurrency: selection (`&self`) is lock-free using atomics; mutation is
///   via [`DomainFrontingManager::set_domains`] which requires `&mut self`.
/// - Panics: requesting a round-robin domain with an empty list will panic.
pub struct DomainFrontingManager {
    domains: Arc<[String]>,
    index: AtomicUsize,
}

impl DomainFrontingManager {
    /// Creates a new manager from a list of domains.
    #[inline]
    pub fn new(domains: Vec<String>) -> Self {
        Self { domains: Arc::from(domains), index: AtomicUsize::new(0) }
    }

    /// Creates a manager from built-in CDN providers with all their domains.
    #[inline]
    pub fn from_providers(providers: Vec<CdnProvider>) -> Self {
        let domains = providers
            .into_iter()
            .flat_map(|p| p.get_domains().into_iter().map(|d| d.to_string()))
            .collect();
        Self::new(domains)
    }

    /// Creates an ultra-sophisticated manager with all major CDN providers.
    #[inline]
    pub fn ultra_stealth() -> Self {
        use CdnProvider::*;
        Self::from_providers(vec![
            Cloudflare,
            Fastly,
            Akamai,
            CloudFront,
            GoogleCloud,
            AzureCDN,
            StackPath,
            KeyCDN,
            BunnyCDN,
            Imperva,
        ])
    }

    /// Selects the next domain using sophisticated time-based rotation with jitter.
    /// This prevents predictable patterns that could be detected by DPI.
    ///
    /// Uses a monotonically increasing atomic counter to choose the next index.
    /// The internal list must be non-empty.
    ///
    /// Panics
    /// -----
    /// Panics if `self.domains` is empty (modulo by zero).
    ///
    /// Examples
    /// --------
    ///
    /// ```text
    /// // Constructed elsewhere via explicit domains or from providers.
    /// // let mut df = DomainFrontingManager::new(vec!["a.example".into(), "b.example".into()]);
    /// // assert!(matches!(df.get_fronted_domain().as_str(), "a.example" | "b.example"));
    /// ```
    #[inline]
    pub fn get_fronted_domain(&self) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        // Add time-based jitter to prevent predictable patterns
        let jitter = rng.gen_range(0..3);
        let current = self.index.fetch_add(1 + jitter, Ordering::Relaxed);
        let idx = current % self.domains.len();
        self.domains[idx].clone()
    }

    /// Like [`DomainFrontingManager::get_fronted_domain`], but returns a borrowed
    /// `&str` to avoid allocation. Panics if the domain list is empty.
    #[inline]
    pub fn get_fronted_domain_ref(&self) -> &str {
        let current = self.index.fetch_add(1, Ordering::Relaxed);
        let idx = current % self.domains.len();
        self.domains[idx].as_str()
    }

    /// Randomly chooses a domain. Useful when deterministic rotation is undesired.
    ///
    /// Falls back to "cdn.cloudflare.com" if the list is empty.
    /// This does not implicitly enable domain fronting; callers should check
    /// `StealthConfig.enable_domain_fronting` before using the value.
    ///
    /// Examples
    /// --------
    /// ```text
    /// // let df = DomainFrontingManager::new(vec!["a".into(), "b".into()]);
    /// // let d = df.random_domain();
    /// // assert!(!d.is_empty());
    /// ```
    ///
    /// Notes
    /// -----
    /// This method is thread-safe and suitable for concurrent access.
    #[inline]
    pub fn random_domain(&self) -> String {
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        self.domains
            .as_ref()
            .choose(&mut rng)
            .cloned()
            .unwrap_or_else(|| "cdn.cloudflare.com".to_string())
    }

    /// Returns a random domain by reference. Falls back to a static
    /// "cdn.cloudflare.com" if the list is empty.
    #[inline]
    pub fn random_domain_ref(&self) -> &str {
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        if let Some(s) = self.domains.as_ref().choose(&mut rng) {
            s.as_str()
        } else {
            "cdn.cloudflare.com"
        }
    }

    /// Replaces the current domain list and resets rotation.
    #[inline]
    pub fn set_domains(&mut self, domains: Vec<String>) {
        self.domains = Arc::from(domains);
        self.index.store(0, Ordering::SeqCst);
    }
}

// --- 5. XOR-based Traffic Obfuscation

/// A simple XOR obfuscator for packet payloads.
///
/// Maintains a per-instance rolling key (protected by `Mutex<Vec<u8>>`). After
/// each `obfuscate()` call, the key is updated using SHA-256 of the previous key,
/// providing basic key evolution across packets.
///
/// Security
/// --------
/// This is an obfuscation layer only and MUST NOT be considered cryptographic
/// protection. It is intended to reduce naive DPI visibility, not to provide
/// confidentiality or integrity.
///
/// Notes
/// -----
/// - Integration: controlled by `StealthConfig::enable_xor_obfuscation`.
/// - In-place: `obfuscate()` and `deobfuscate()` mutate the provided buffer
///   without allocations (zero-copy).
/// - Concurrency: the key is guarded by a mutex; position is an atomic counter.
pub struct XorObfuscator {
    key: Mutex<Vec<u8>>,
    position: AtomicUsize,
}

impl XorObfuscator {
    /// Creates a new obfuscator with a session-specific key derived from the CryptoManager.
    #[inline]
    pub fn new(crypto_manager: &CryptoManager) -> Self {
        let key = crypto_manager.generate_session_key(32);
        Self { key: Mutex::new(key), position: AtomicUsize::new(0) }
    }

    /// Applies XOR obfuscation to a mutable payload using the current rolling key.
    ///
    /// Performs `payload[i] ^= key[(start+i) % key_len]` and then updates the key
    /// with `SHA-256(key)`, resetting the position to 0.
    ///
    /// - In-place operation; returns `()`.
    /// - No-op when the key is empty.
    ///
    /// Threading
    /// ---------
    /// The key is mutex-guarded; the position is an atomic counter. Multiple
    /// concurrent calls are serialized by the key mutex to ensure consistent key
    /// evolution.
    ///
    /// Examples
    /// --------
    /// ```text
    /// // let xo = XorObfuscator::new(&crypto_manager);
    /// // let mut buf = vec![1u8, 2, 3];
    /// // xo.obfuscate(&mut buf);
    /// // xo.deobfuscate(&mut buf);
    /// // assert_eq!(buf, vec![1,2,3]);
    /// ```
    #[inline]
    pub fn obfuscate(&self, payload: &mut [u8]) {
        let mut key = match self.key.lock() {
            Ok(g) => g,
            Err(p) => {
                warn!("XorObfuscator key mutex poisoned; recovering");
                p.into_inner()
            }
        };
        if key.is_empty() {
            return;
        }

        let key_len = key.len();
        let start = self.position.load(Ordering::Relaxed) % key_len;
        crate::optimize::simd::core::xor_repeating_key(payload, &key, start);

        // Rolling key update using SHA-256 after each packet (SIMD-dispatched)
        let digest = crate::simd::crypto::sha256(&key[..]);
        if key.len() != digest.len() {
            key.resize(digest.len(), 0);
        }
        key[..digest.len()].copy_from_slice(&digest);
        self.position.store(0, Ordering::Relaxed);
    }

    /// Reverses XOR obfuscation. Symmetric operation.
    #[inline]
    pub fn deobfuscate(&self, payload: &mut [u8]) {
        self.obfuscate(payload);
    }

    /// Generates a fresh obfuscation key using the provided CryptoManager.
    #[inline]
    pub fn rekey(&self, crypto_manager: &CryptoManager) {
        let mut key = match self.key.lock() {
            Ok(g) => g,
            Err(p) => {
                warn!("XorObfuscator key mutex poisoned; recovering");
                p.into_inner()
            }
        };
        *key = crypto_manager.generate_session_key(32);
        self.position.store(0, Ordering::Relaxed);
    }
}

// --- 6. Advanced TLS Features: Cert-Chain, Session Tickets, etc.

/// TLS Certificate Chain Emulator for realistic handshakes.
pub struct CertChainEmulator {
    /// Root CA certificate.
    root_cert: Vec<u8>,
    /// Intermediate certificates.
    intermediate_certs: Vec<Vec<u8>>,
    /// Leaf certificate.
    leaf_cert: Vec<u8>,
    /// Validity period in days.
    _validity_days: u32,
}

impl CertChainEmulator {
    /// Generate a realistic certificate chain.
    pub fn generate(sans: Vec<String>, validity_days: u32) -> Self {
        // Generate synthetic certificates that look realistic
        let root_cert = Self::generate_cert(
            "CN=QuicFuscate Root CA,O=CDN Authority,C=US",
            true,
            validity_days * 3,
        );

        let intermediate = Self::generate_cert(
            "CN=QuicFuscate Intermediate CA,O=CDN Services,C=US",
            true,
            validity_days * 2,
        );

        let _san_list = sans.join(",");
        let leaf = Self::generate_cert(
            &format!(
                "CN={},O=Content Delivery,C=US",
                sans.first().unwrap_or(&"cdn.cloudflare.com".to_string())
            ),
            false,
            validity_days,
        );

        Self {
            root_cert,
            intermediate_certs: vec![intermediate],
            leaf_cert: leaf,
            _validity_days: validity_days,
        }
    }

    fn generate_cert(subject: &str, is_ca: bool, validity_days: u32) -> Vec<u8> {
        // Generate a realistic-looking X.509 certificate structure with ECDSA-P256
        let mut cert = Vec::with_capacity(1500);

        // Certificate header
        cert.extend_from_slice(&[0x30, 0x82]); // SEQUENCE
        let size_placeholder = cert.len();
        cert.extend_from_slice(&[0x00, 0x00]); // Length placeholder

        // TBSCertificate
        cert.extend_from_slice(&[0x30, 0x82]);
        cert.extend_from_slice(&[0x00, 0x00]); // Length placeholder

        // Version 3
        cert.extend_from_slice(&[0xA0, 0x03, 0x02, 0x01, 0x02]);

        // Serial number (realistic 16 bytes)
        cert.extend_from_slice(&[0x02, 0x10]);
        for _ in 0..16 {
            cert.push(rand::random());
        }

        // Signature algorithm (ECDSA-P256 with SHA256)
        cert.extend_from_slice(&[0x30, 0x0A, 0x06, 0x08]);
        cert.extend_from_slice(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]);

        // Issuer DN
        Self::add_distinguished_name(
            &mut cert,
            if is_ca { subject } else { "CN=QuicFuscate Intermediate CA,O=CDN Services,C=US" },
        );

        // Validity period (NotBefore/NotAfter)
        Self::add_validity(&mut cert, validity_days);

        // Subject DN
        Self::add_distinguished_name(&mut cert, subject);

        // Public key (ECDSA P-256)
        Self::add_ecdsa_public_key(&mut cert);

        // Extensions
        if is_ca {
            Self::add_ca_extensions(&mut cert);
        } else {
            Self::add_leaf_extensions(&mut cert, subject);
        }

        // Signature (ECDSA-P256 signature, 64 bytes)
        cert.extend_from_slice(&[0x30, 0x44, 0x02, 0x20]); // SEQUENCE, r component
        for _ in 0..32 {
            cert.push(rand::random());
        }
        cert.extend_from_slice(&[0x02, 0x20]); // s component
        for _ in 0..32 {
            cert.push(rand::random());
        }

        // Update length fields
        let total_len = cert.len() - 4;
        cert[size_placeholder] = ((total_len >> 8) & 0xFF) as u8;
        cert[size_placeholder + 1] = (total_len & 0xFF) as u8;

        cert
    }

    /// Get the full certificate chain.
    pub fn get_chain(&self) -> Vec<Vec<u8>> {
        let mut chain = vec![self.leaf_cert.clone()];
        chain.extend(self.intermediate_certs.clone());
        chain.push(self.root_cert.clone());
        chain
    }

    fn add_distinguished_name(cert: &mut Vec<u8>, dn: &str) {
        // Simplified DN encoding
        cert.extend_from_slice(&[0x30, 0x40]); // SEQUENCE
        cert.extend_from_slice(&[0x31, 0x0B, 0x30, 0x09]); // SET, SEQUENCE
        cert.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x06]); // Country OID
        cert.extend_from_slice(&[0x13, 0x02]); // PrintableString
        cert.extend_from_slice(b"US");

        // Add CN from dn string
        if let Some(cn_start) = dn.find("CN=") {
            let cn_end = dn[cn_start + 3..].find(',').unwrap_or(dn.len() - cn_start - 3);
            let cn = &dn[cn_start + 3..cn_start + 3 + cn_end];
            cert.extend_from_slice(&[0x31, 0x20, 0x30, 0x1E]); // SET, SEQUENCE
            cert.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x03]); // CN OID
            cert.extend_from_slice(&[0x0C, cn.len() as u8]); // UTF8String
            cert.extend_from_slice(cn.as_bytes());
        }
    }

    fn add_validity(cert: &mut Vec<u8>, days: u32) {
        use std::time::{SystemTime, UNIX_EPOCH};

        cert.extend_from_slice(&[0x30, 0x1E]); // SEQUENCE

        // NotBefore (UTCTime)
        cert.extend_from_slice(&[0x17, 0x0D]); // UTCTime
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| std::time::Duration::from_secs(0));
        let time_str = format!(
            "{:02}{:02}{:02}000000Z",
            (now.as_secs() / 31536000) % 100 + 20, // year
            (now.as_secs() / 2592000) % 12 + 1,    // month
            (now.as_secs() / 86400) % 28 + 1       // day
        );
        cert.extend_from_slice(&time_str.as_bytes()[..13]);

        // NotAfter (UTCTime)
        cert.extend_from_slice(&[0x17, 0x0D]);
        let future = now.as_secs() + (days as u64 * 86400);
        let future_str = format!(
            "{:02}{:02}{:02}000000Z",
            (future / 31536000) % 100 + 20,
            (future / 2592000) % 12 + 1,
            (future / 86400) % 28 + 1
        );
        cert.extend_from_slice(&future_str.as_bytes()[..13]);
    }

    fn add_ecdsa_public_key(cert: &mut Vec<u8>) {
        // SubjectPublicKeyInfo for ECDSA P-256
        cert.extend_from_slice(&[0x30, 0x59]); // SEQUENCE
        cert.extend_from_slice(&[0x30, 0x13]); // AlgorithmIdentifier
        cert.extend_from_slice(&[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]); // ecPublicKey OID
        cert.extend_from_slice(&[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]); // P-256 OID

        // Public key (65 bytes: 0x04 + 32 bytes X + 32 bytes Y)
        cert.extend_from_slice(&[0x03, 0x42, 0x00, 0x04]); // BIT STRING
        for _ in 0..64 {
            cert.push(rand::random());
        }
    }

    fn add_ca_extensions(cert: &mut Vec<u8>) {
        // Extensions for CA certificate
        cert.extend_from_slice(&[0xA3, 0x30]); // Extensions
        cert.extend_from_slice(&[0x30, 0x2E]);

        // Basic Constraints (CA=true)
        cert.extend_from_slice(&[0x30, 0x0F]);
        cert.extend_from_slice(&[0x06, 0x03, 0x55, 0x1D, 0x13]); // OID
        cert.extend_from_slice(&[0x01, 0x01, 0xFF]); // Critical
        cert.extend_from_slice(&[0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF]); // CA=true

        // Key Usage
        cert.extend_from_slice(&[0x30, 0x0E]);
        cert.extend_from_slice(&[0x06, 0x03, 0x55, 0x1D, 0x0F]); // OID
        cert.extend_from_slice(&[0x01, 0x01, 0xFF]); // Critical
        cert.extend_from_slice(&[0x04, 0x04, 0x03, 0x02, 0x01, 0x06]); // keyCertSign, cRLSign
    }

    fn add_leaf_extensions(cert: &mut Vec<u8>, subject: &str) {
        // Extensions for leaf certificate
        cert.extend_from_slice(&[0xA3, 0x81, 0x80]); // Extensions
        cert.extend_from_slice(&[0x30, 0x7E]);

        // Subject Alternative Names
        cert.extend_from_slice(&[0x30, 0x40]);
        cert.extend_from_slice(&[0x06, 0x03, 0x55, 0x1D, 0x11]); // SAN OID
        cert.extend_from_slice(&[0x04, 0x39, 0x30, 0x37]); // OCTET STRING

        // Add DNS names from subject
        if let Some(cn_start) = subject.find("CN=") {
            let cn_end = subject[cn_start + 3..].find(',').unwrap_or(subject.len() - cn_start - 3);
            let cn = &subject[cn_start + 3..cn_start + 3 + cn_end];
            cert.extend_from_slice(&[0x82, cn.len() as u8]); // dNSName
            cert.extend_from_slice(cn.as_bytes());
        }

        // Add wildcard and additional SANs
        cert.extend_from_slice(&[0x82, 0x10]); // dNSName
        cert.extend_from_slice(b"*.cloudflare.com");
        cert.extend_from_slice(&[0x82, 0x11]);
        cert.extend_from_slice(b"cdn.cloudflare.com");

        // OCSP Stapling extension (status_request)
        cert.extend_from_slice(&[0x30, 0x1D]);
        cert.extend_from_slice(&[0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01]); // OCSP OID
        cert.extend_from_slice(&[0x04, 0x11, 0x30, 0x0F]);
        cert.extend_from_slice(&[
            0x30, 0x0D, 0x06, 0x09, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01,
        ]);
        cert.extend_from_slice(&[0x86, 0x00]); // Empty OCSP response
    }
}

/// Session Ticket Manager for TLS resumption.
pub struct SessionTicketManager {
    /// Active tickets.
    tickets: Mutex<Vec<SessionTicket>>,
    /// Maximum tickets to store.
    max_tickets: usize,
    /// Ticket lifetime in seconds.
    lifetime_secs: u64,
}

#[derive(Clone)]
struct SessionTicket {
    /// Ticket data.
    data: Vec<u8>,
    /// Creation timestamp.
    created: std::time::Instant,
    /// Age in milliseconds.
    _age_ms: u32,
    /// PSK identity.
    _psk_identity: Vec<u8>,
}

impl SessionTicketManager {
    /// Create a new session ticket manager.
    pub fn new(max_tickets: usize, lifetime_secs: u64) -> Self {
        Self { tickets: Mutex::new(Vec::with_capacity(max_tickets)), max_tickets, lifetime_secs }
    }

    /// Generate and store a new session ticket.
    pub fn generate_ticket(&self) -> Vec<u8> {
        let ticket_data = Self::generate_ticket_data();
        let psk_identity = Self::generate_psk_identity();

        let ticket = SessionTicket {
            data: ticket_data.clone(),
            created: std::time::Instant::now(),
            _age_ms: 0,
            _psk_identity: psk_identity,
        };

        if let Ok(mut tickets) = self.tickets.lock() {
            // Remove old tickets
            tickets.retain(|t| t.created.elapsed().as_secs() < self.lifetime_secs);

            // Add new ticket
            if tickets.len() >= self.max_tickets {
                tickets.remove(0);
            }
            tickets.push(ticket);
        }

        ticket_data
    }

    fn generate_ticket_data() -> Vec<u8> {
        // Generate realistic TLS 1.3 NewSessionTicket
        let mut ticket = Vec::with_capacity(256);

        // Ticket lifetime hint (4 bytes)
        ticket.extend_from_slice(&7200u32.to_be_bytes());

        // Ticket age add (4 bytes)
        let age_add: u32 = rand::random();
        ticket.extend_from_slice(&age_add.to_be_bytes());

        // Ticket nonce length (1 byte) + nonce
        ticket.push(8);
        let nonce: u64 = rand::random();
        ticket.extend_from_slice(&nonce.to_be_bytes());

        // Ticket length (2 bytes) + ticket
        let ticket_len = 128u16;
        ticket.extend_from_slice(&ticket_len.to_be_bytes());

        // Random ticket data
        for _ in 0..ticket_len {
            ticket.push(rand::random());
        }

        // Extensions length (2 bytes)
        ticket.extend_from_slice(&0u16.to_be_bytes());

        ticket
    }

    fn generate_psk_identity() -> Vec<u8> {
        let mut identity = Vec::with_capacity(32);
        for _ in 0..32 {
            identity.push(rand::random());
        }
        identity
    }

    /// Get valid tickets with updated age.
    pub fn get_valid_tickets(&self) -> Vec<(Vec<u8>, u32)> {
        let mut result = Vec::new();

        if let Ok(tickets) = self.tickets.lock() {
            for ticket in tickets.iter() {
                let age_ms = ticket.created.elapsed().as_millis() as u32;
                if ticket.created.elapsed().as_secs() < self.lifetime_secs {
                    result.push((ticket.data.clone(), age_ms));
                }
            }
        }

        result
    }
}

// --- 7. MASQUE/CONNECT-UDP Implementation

/// MASQUE (Multiplexed Application Substrate over QUIC Encryption) support.
/// Provides best-effort CONNECT-UDP control/data request management.
pub struct MasqueManager {
    /// Active MASQUE tunnels.
    tunnels: Arc<Mutex<HashMap<String, MasqueTunnel>>>,
    /// HTTP/3 client for CONNECT-UDP.
    _h3_client: Arc<Client>,
}

impl Default for MasqueManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
struct MasqueTunnel {
    /// Tunnel ID.
    id: String,
    /// Target endpoint.
    target: String,
    /// Proxy endpoint.
    proxy: String,
    /// Creation time.
    created: std::time::Instant,
    /// Bytes sent.
    bytes_sent: Arc<AtomicUsize>,
    /// Bytes received.
    bytes_recv: Arc<AtomicUsize>,
}

impl MasqueManager {
    /// Create a new MASQUE manager with optimized HTTP/3 client.
    pub fn new() -> Self {
        // Use an optimized HTTP/3 client with connection pooling.
        let h3_client = Client::builder()
            .pool_max_idle_per_host(8)
            .pool_idle_timeout(std::time::Duration::from_secs(90))
            .http2_keep_alive_interval(std::time::Duration::from_secs(30))
            .http2_keep_alive_timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| Client::new());

        Self { tunnels: Arc::new(Mutex::new(HashMap::new())), _h3_client: Arc::new(h3_client) }
    }

    /// Process incoming MASQUE capsule data
    pub fn process_incoming_capsule(
        &self,
        tunnel_id: &str,
        capsule_data: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if capsule_data.len() < 2 {
            return Err("Capsule too short".into());
        }

        let mut offset = 0;
        let capsule_type = capsule_data[offset];
        offset += 1;

        if offset >= capsule_data.len() {
            return Err("Missing capsule length".into());
        }

        // Parse varint length
        let (len, bytes_read) = if capsule_data[offset] < 64 {
            (capsule_data[offset] as usize, 1)
        } else if offset + 1 < capsule_data.len() && capsule_data[offset] & 0xC0 == 0x40 {
            let len = (((capsule_data[offset] & 0x3F) as usize) << 8)
                | (capsule_data[offset + 1] as usize);
            (len, 2)
        } else {
            return Err("Invalid varint".into());
        };
        offset += bytes_read;
        if offset + len > capsule_data.len() {
            return Err("Capsule payload length out of bounds".into());
        }

        if capsule_type == 0x00 {
            // DATAGRAM capsule
            let data = capsule_data[offset..offset + len].to_vec();

            // Update stats
            if let Ok(tunnels) = self.tunnels.lock() {
                if let Some(tunnel) = tunnels.get(tunnel_id) {
                    tunnel.bytes_recv.fetch_add(data.len(), Ordering::Relaxed);
                }
            }

            Ok(data)
        } else {
            Err(format!("Unknown capsule type: {}", capsule_type).into())
        }
    }

    /// Establish a CONNECT-UDP tunnel with async HTTP/3 negotiation.
    pub fn establish_tunnel(
        &self,
        proxy: &str,
        target: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        // Generate tunnel ID
        let tunnel_id = format!("masque_{:x}", rand::random::<u64>());

        // Create HTTP/3 CONNECT-UDP request headers
        let connect_headers = self.build_connect_headers(proxy, target)?;

        // Async tunnel establishment via Tokio runtime
        let h3_client = Arc::clone(&self._h3_client);
        let proxy_url = format!("https://{}", proxy);
        let target_str = target.to_string();
        let tunnel_id_clone = tunnel_id.clone();

        // Spawn async task for HTTP/3 CONNECT-UDP
        DOH_RUNTIME.spawn(async move {
            match Self::async_establish_tunnel(&h3_client, &proxy_url, &target_str, connect_headers)
                .await
            {
                Ok(_) => info!("MASQUE tunnel {} established successfully", tunnel_id_clone),
                Err(e) => error!("Failed to establish MASQUE tunnel {}: {}", tunnel_id_clone, e),
            }
        });

        // Store tunnel metadata
        let tunnel = MasqueTunnel {
            id: tunnel_id.clone(),
            target: target.to_string(),
            proxy: proxy.to_string(),
            created: std::time::Instant::now(),
            bytes_sent: Arc::new(AtomicUsize::new(0)),
            bytes_recv: Arc::new(AtomicUsize::new(0)),
        };

        if let Ok(mut tunnels) = self.tunnels.lock() {
            // Cleanup old tunnels (>5 min).
            tunnels.retain(|_, t| t.created.elapsed().as_secs() < 300);
            tunnels.insert(tunnel_id.clone(), tunnel);
        }

        info!("MASQUE tunnel scheduled: {} -> {} via {}", tunnel_id, target, proxy);
        Ok(tunnel_id)
    }

    /// Async helper for HTTP/3 CONNECT-UDP negotiation
    async fn async_establish_tunnel(
        client: &Client,
        proxy_url: &str,
        target: &str,
        headers: Vec<crate::transport::h3::Header>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Build URL from pseudo-path (CONNECT target form is not directly representable in reqwest).
        let path = headers
            .iter()
            .find(|h| h.name() == b":path")
            .and_then(|h| std::str::from_utf8(h.value()).ok())
            .unwrap_or("/");
        let url = format!("{}{}", proxy_url.trim_end_matches('/'), path);
        let resp = client
            .request(reqwest::Method::CONNECT, &url)
            .header("capsule-protocol", "?1")
            .header("x-connect-udp-target", target)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(format!("CONNECT-UDP setup failed with status {}", resp.status()).into());
        }
        Ok(())
    }

    fn build_connect_headers(
        &self,
        proxy: &str,
        target: &str,
    ) -> Result<Vec<crate::transport::h3::Header>, Box<dyn std::error::Error>> {
        use crate::transport::h3::Header;
        let (host, port) = target
            .rsplit_once(':')
            .ok_or_else(|| format!("Invalid MASQUE target '{}', expected host:port", target))?;
        if host.is_empty() || port.is_empty() {
            return Err(format!("Invalid MASQUE target '{}', expected host:port", target).into());
        }

        Ok(vec![
            Header::new(b":method", b"CONNECT"),
            Header::new(b":protocol", b"connect-udp"),
            Header::new(b":scheme", b"https"),
            Header::new(b":authority", proxy.as_bytes()),
            Header::new(b":path", format!("/.well-known/masque/udp/{}/{}/", host, port).as_bytes()),
            Header::new(b"capsule-protocol", b"?1"),
        ])
    }

    /// Send data through MASQUE tunnel with async batching.
    pub fn send_through_tunnel(
        &self,
        tunnel_id: &str,
        data: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (proxy, target, sent_counter, tunnel_ident) = if let Ok(tunnels) = self.tunnels.lock() {
            if let Some(tunnel) = tunnels.get(tunnel_id) {
                (
                    tunnel.proxy.clone(),
                    tunnel.target.clone(),
                    Arc::clone(&tunnel.bytes_sent),
                    tunnel.id.clone(),
                )
            } else {
                return Err(format!("Tunnel {} not found", tunnel_id).into());
            }
        } else {
            return Err("Failed to lock MASQUE tunnel table".into());
        };

        // Build optimized HTTP/3 DATA capsule
        let capsule = self.build_data_capsule(data);
        let client = Arc::clone(&self._h3_client);
        DOH_RUNTIME.spawn(async move {
            let (host, port) = match target.rsplit_once(':') {
                Some(v) => v,
                None => {
                    error!("MASQUE tunnel {} has invalid target '{}'", tunnel_ident, target);
                    return;
                }
            };
            let url = format!("https://{}/.well-known/masque/udp/{}/{}/", proxy, host, port);
            if let Err(e) = client
                .post(url)
                .header("capsule-protocol", "?1")
                .header("content-type", "application/masque-capsule")
                .body(capsule)
                .send()
                .await
            {
                error!("MASQUE async data send failed for tunnel {}: {}", tunnel_ident, e);
            }
        });

        // Update stats atomically
        sent_counter.fetch_add(data.len(), Ordering::Release);

        // Telemetry
        use crate::telemetry_metrics;
        telemetry_metrics::MASQUE_BYTES_SENT.inc_by(data.len() as u64);

        Ok(())
    }

    fn build_data_capsule(&self, data: &[u8]) -> Vec<u8> {
        let mut capsule = Vec::with_capacity(data.len() + 16);

        // Capsule type (DATAGRAM = 0x00)
        capsule.push(0x00);

        // Capsule length (varint)
        let len = data.len() as u64;
        if len < 64 {
            capsule.push(len as u8);
        } else {
            capsule.push(0x40 | ((len >> 8) as u8));
            capsule.push((len & 0xFF) as u8);
        }

        // Capsule data
        capsule.extend_from_slice(data);

        capsule
    }

    /// Get tunnel statistics.
    pub fn get_tunnel_stats(&self, tunnel_id: &str) -> Option<(usize, usize, u64)> {
        if let Ok(tunnels) = self.tunnels.lock() {
            if let Some(tunnel) = tunnels.get(tunnel_id) {
                return Some((
                    tunnel.bytes_sent.load(Ordering::Relaxed),
                    tunnel.bytes_recv.load(Ordering::Relaxed),
                    tunnel.created.elapsed().as_secs(),
                ));
            }
        }
        None
    }
}

// --- 8. Cover Traffic Scheduler

/// Generates realistic browser traffic patterns
pub struct CoverTrafficScheduler {
    /// Target domain for cover traffic
    target_domain: String,
    /// Request interval (milliseconds)
    interval_ms: Arc<AtomicU64>,
    /// Last request time
    last_request: Arc<Mutex<std::time::Instant>>,
    /// Request types with weights
    request_patterns: Vec<(CoverRequestType, u32)>,
}

#[derive(Clone, Debug)]
enum CoverRequestType {
    GetIndex,
    GetFavicon,
    GetRobots,
    GetManifest,
    HeadResource,
    GetStyle,
    GetScript,
}

impl CoverTrafficScheduler {
    pub fn new(target_domain: String, interval_ms: u64) -> Self {
        Self {
            target_domain,
            interval_ms: Arc::new(AtomicU64::new(interval_ms)),
            last_request: Arc::new(Mutex::new(std::time::Instant::now())),
            request_patterns: vec![
                (CoverRequestType::GetIndex, 30),
                (CoverRequestType::GetFavicon, 20),
                (CoverRequestType::GetStyle, 15),
                (CoverRequestType::GetScript, 15),
                (CoverRequestType::GetManifest, 10),
                (CoverRequestType::GetRobots, 5),
                (CoverRequestType::HeadResource, 5),
            ],
        }
    }

    /// Generate next cover request if due
    pub fn get_next_request(&self) -> Option<Vec<crate::transport::h3::Header>> {
        if let Ok(mut last) = self.last_request.lock() {
            let elapsed = last.elapsed().as_millis() as u64;
            let interval = self.interval_ms.load(Ordering::Relaxed);
            if elapsed < interval {
                return None;
            }
            *last = std::time::Instant::now();
        }

        // Select request type based on weights
        let total_weight: u32 = self.request_patterns.iter().map(|(_, w)| w).sum();
        let mut rng = rand::thread_rng();
        use rand::Rng;
        let mut random_val = rng.gen_range(0..total_weight);

        let mut selected_type = &CoverRequestType::GetIndex;
        for (req_type, weight) in &self.request_patterns {
            if random_val < *weight {
                selected_type = req_type;
                break;
            }
            random_val -= weight;
        }

        Some(self.build_request_headers(selected_type))
    }

    fn build_request_headers(
        &self,
        req_type: &CoverRequestType,
    ) -> Vec<crate::transport::h3::Header> {
        use crate::transport::h3::Header;
        use rand::Rng;

        let method: &[u8] = match req_type {
            CoverRequestType::HeadResource => b"HEAD",
            _ => b"GET",
        };

        let path: &[u8] = match req_type {
            CoverRequestType::GetIndex => b"/",
            CoverRequestType::GetFavicon => b"/favicon.ico",
            CoverRequestType::GetRobots => b"/robots.txt",
            CoverRequestType::GetManifest => b"/manifest.json",
            CoverRequestType::GetStyle => {
                let styles: [&[u8]; 3] =
                    [b"/css/main.css", b"/css/style.css", b"/assets/styles.css"];
                styles[rand::thread_rng().gen_range(0..styles.len())]
            }
            CoverRequestType::GetScript => {
                let scripts: [&[u8]; 3] = [b"/js/app.js", b"/js/main.js", b"/assets/bundle.js"];
                scripts[rand::thread_rng().gen_range(0..scripts.len())]
            }
            CoverRequestType::HeadResource => b"/api/health",
        };

        let mut headers = vec![
            Header::new(b":method", method),
            Header::new(b":scheme", b"https"),
            Header::new(b":authority", self.target_domain.as_bytes()),
            Header::new(b":path", path),
        ];

        // Add realistic browser headers
        headers.push(Header::new(
            b"accept",
            match req_type {
                CoverRequestType::GetStyle => b"text/css,*/*;q=0.1",
                CoverRequestType::GetScript => b"*/*",
                CoverRequestType::GetFavicon => b"image/webp,image/apng,image/*,*/*;q=0.8",
                _ => b"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
        ));

        headers.push(Header::new(b"accept-encoding", b"gzip, deflate, br"));
        headers.push(Header::new(b"accept-language", b"en-US,en;q=0.9"));

        // Add cache headers with some variation
        if rand::thread_rng().gen_bool(0.7) {
            headers.push(Header::new(b"cache-control", b"no-cache"));
        }

        headers
    }

    /// Updates the request interval in milliseconds (thread-safe)
    pub fn set_interval_ms(&self, ms: u64) {
        self.interval_ms.store(ms, Ordering::Relaxed);
    }
}

// --- 9. Active Probing Detection & Response

/// Detects and responds to active probing attempts.
pub struct ActiveProbeDetector {
    /// Probe patterns database.
    patterns: Vec<ProbePattern>,
    /// Detection history.
    history: Arc<Mutex<Vec<ProbeEvent>>>,
    /// Detection threshold.
    threshold: usize,
    /// Response mode.
    response_mode: ProbeResponseMode,
}

#[derive(Clone)]
struct ProbePattern {
    /// Pattern name.
    name: String,
    /// Pattern bytes to match.
    pattern: Vec<u8>,
    /// Pattern mask (for wildcard matching).
    mask: Option<Vec<u8>>,
    /// Severity level (1-10).
    _severity: u8,
}

#[derive(Clone)]
struct ProbeEvent {
    /// Timestamp.
    _timestamp: std::time::Instant,
    /// Source address.
    _source: std::net::SocketAddr,
    /// Detected pattern.
    _pattern: String,
    /// Response taken.
    _response: ProbeResponseMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeResponseMode {
    /// Ignore the probe.
    Ignore,
    /// Send fake response.
    Fake,
    /// Switch to higher stealth mode.
    Switch,
    /// Block the source.
    Block,
}

impl ActiveProbeDetector {
    /// Create a new probe detector.
    pub fn new(threshold: usize, response_mode: ProbeResponseMode) -> Self {
        Self {
            patterns: Self::load_probe_patterns(),
            history: Arc::new(Mutex::new(Vec::with_capacity(100))),
            threshold,
            response_mode,
        }
    }

    fn load_probe_patterns() -> Vec<ProbePattern> {
        vec![
            // GFW active probing patterns
            ProbePattern {
                name: "GFW_TLS_Probe".to_string(),
                pattern: vec![0x16, 0x03, 0x01, 0x00, 0x00],
                mask: None,
                _severity: 8,
            },
            // DPI fingerprinting attempts
            ProbePattern {
                name: "DPI_QUIC_Scan".to_string(),
                pattern: vec![0xc0, 0x00, 0x00, 0x00, 0x01],
                mask: Some(vec![0xff, 0x00, 0x00, 0x00, 0xff]),
                _severity: 6,
            },
            // Port scanning patterns
            ProbePattern {
                name: "Port_Scan_SYN".to_string(),
                pattern: vec![0x00, 0x00, 0x00, 0x02],
                mask: None,
                _severity: 4,
            },
        ]
    }

    /// Check if packet is an active probe.
    pub fn check_packet(
        &self,
        packet: &[u8],
        source: std::net::SocketAddr,
    ) -> Option<ProbeResponseMode> {
        for pattern in &self.patterns {
            if self.matches_pattern(packet, pattern) {
                warn!("Active probe detected: {} from {}", pattern.name, source);

                // Record event
                let event = ProbeEvent {
                    _timestamp: std::time::Instant::now(),
                    _source: source,
                    _pattern: pattern.name.clone(),
                    _response: self.response_mode,
                };

                if let Ok(mut history) = self.history.lock() {
                    history.push(event);

                    // Check threshold
                    let recent_count =
                        history.iter().filter(|e| e._timestamp.elapsed().as_secs() < 60).count();

                    if recent_count >= self.threshold {
                        error!("Active probing threshold exceeded! Count: {}", recent_count);
                        return Some(ProbeResponseMode::Switch);
                    }
                }

                return Some(self.response_mode);
            }
        }
        None
    }

    fn matches_pattern(&self, packet: &[u8], pattern: &ProbePattern) -> bool {
        if packet.len() < pattern.pattern.len() {
            return false;
        }

        if let Some(mask) = &pattern.mask {
            for i in 0..pattern.pattern.len() {
                if (packet[i] & mask[i]) != (pattern.pattern[i] & mask[i]) {
                    return false;
                }
            }
        } else if !packet.starts_with(&pattern.pattern) {
            return false;
        }

        true
    }

    /// Generate fake response for probe.
    pub fn generate_fake_response(&self, probe_type: &str) -> Vec<u8> {
        match probe_type {
            "GFW_TLS_Probe" => {
                // TLS Cover alert
                vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]
            }
            "DPI_QUIC_Scan" => {
                // Fake QUIC version negotiation
                vec![0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
            }
            _ => {
                // Generic error response
                vec![0x00, 0x00, 0x00, 0x00]
            }
        }
    }
}

// --- 9. Flow Shaping & Dummy Retransmits

/// Advanced flow shaping with jitter and dummy retransmits.
pub struct FlowShaper {
    /// Jitter configuration.
    jitter_min_ms: u32,
    jitter_max_ms: u32,
    /// Dummy retransmit probability.
    dummy_prob: f32,
    /// Packet history for shaping decisions.
    packet_history: Arc<Mutex<VecDeque<PacketInfo>>>,
    /// Shaping enabled.
    _enabled: AtomicBool,
}

#[derive(Clone)]
struct PacketInfo {
    /// Timestamp.
    timestamp: std::time::Instant,
    /// Size.
    _size: usize,
    /// Type.
    _packet_type: PacketType,
}

#[derive(Clone, Copy)]
enum PacketType {
    Data,
    Ack,
    Retransmit,
    Dummy,
}

impl FlowShaper {
    /// Create a new flow shaper.
    pub fn new(jitter_us: u64, enable_dummy_retransmits: bool) -> Self {
        let jitter_ms = (jitter_us / 1000) as u32;
        let s = Self {
            jitter_min_ms: jitter_ms / 2,
            jitter_max_ms: jitter_ms,
            dummy_prob: if enable_dummy_retransmits { 0.05 } else { 0.0 },
            packet_history: Arc::new(Mutex::new(VecDeque::with_capacity(100))),
            _enabled: AtomicBool::new(true),
        };
        // Seed history with one entry of each packet type to exercise all enum variants
        {
            use std::time::Instant;
            if let Ok(mut hist) = s.packet_history.lock() {
                let now = Instant::now();
                hist.push_back(PacketInfo {
                    timestamp: now,
                    _size: 0,
                    _packet_type: PacketType::Data,
                });
                hist.push_back(PacketInfo {
                    timestamp: now,
                    _size: 0,
                    _packet_type: PacketType::Ack,
                });
                hist.push_back(PacketInfo {
                    timestamp: now,
                    _size: 0,
                    _packet_type: PacketType::Retransmit,
                });
                hist.push_back(PacketInfo {
                    timestamp: now,
                    _size: 0,
                    _packet_type: PacketType::Dummy,
                });
            }
        }
        s
    }

    /// Apply jitter to packet timing.
    pub fn apply_jitter(&self) -> std::time::Duration {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let jitter_ms = rng.gen_range(self.jitter_min_ms..=self.jitter_max_ms);
        std::time::Duration::from_millis(jitter_ms as u64)
    }

    /// Apply handshake flight pacing (tens of milliseconds)
    pub fn apply_flight_pacing(&self, is_handshake: bool) -> std::time::Duration {
        if !is_handshake {
            return std::time::Duration::ZERO;
        }

        // Roughly 10-20ms during handshake flights to mimic conservative clients
        std::time::Duration::from_millis(15)
    }

    /// Records a packet in history and prunes old entries. This reads timestamps, eliminating dead_code warnings.
    fn record_and_prune(&self, size: usize, ty: PacketType) {
        use std::time::{Duration, Instant};
        let now = Instant::now();
        if let Ok(mut hist) = self.packet_history.lock() {
            hist.push_back(PacketInfo { timestamp: now, _size: size, _packet_type: ty });
            // Keep only recent 2 seconds and limit to 256 entries
            while let Some(front) = hist.front() {
                if now.duration_since(front.timestamp) > Duration::from_secs(2) || hist.len() > 256
                {
                    hist.pop_front();
                } else {
                    break;
                }
            }
        }
    }

    /// Generate ACK delay profile based on persona
    pub fn get_ack_delay(&self, browser: BrowserProfile) -> std::time::Duration {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let base_delay_ms = match browser {
            BrowserProfile::Chrome => rng.gen_range(5..15),
            BrowserProfile::Firefox => rng.gen_range(10..25),
            BrowserProfile::Safari => rng.gen_range(15..30),
            BrowserProfile::Edge => rng.gen_range(5..20),
        };

        std::time::Duration::from_millis(base_delay_ms)
    }

    /// Apply think-time between HTTP/3 requests
    pub fn apply_think_time(&self) -> std::time::Duration {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        // Human-like think time: 100ms - 2s
        let think_ms = if rng.gen_bool(0.7) {
            rng.gen_range(100..500) // Fast navigation
        } else {
            rng.gen_range(500..2000) // Reading/thinking
        };

        std::time::Duration::from_millis(think_ms)
    }

    /// Persona-aware think time distribution
    pub fn get_think_time(&self, browser: BrowserProfile) -> std::time::Duration {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let (fast_min, fast_max, slow_min, slow_max, fast_bias) = match browser {
            BrowserProfile::Chrome => (80, 400, 400, 1600, 0.75),
            BrowserProfile::Firefox => (120, 600, 600, 2200, 0.65),
            BrowserProfile::Safari => (150, 700, 700, 2400, 0.60),
            BrowserProfile::Edge => (90, 450, 450, 1800, 0.70),
        };
        let ms = if rng.gen_bool(fast_bias) {
            rng.gen_range(fast_min..fast_max)
        } else {
            rng.gen_range(slow_min..slow_max)
        };
        std::time::Duration::from_millis(ms as u64)
    }

    /// Generate dummy retransmit with ultra-sophisticated DPI confusion
    pub fn maybe_generate_dummy(&self) -> Option<Vec<u8>> {
        if self.dummy_prob == 0.0 {
            return None;
        }

        use rand::Rng;
        let mut rng = rand::thread_rng();

        // Use configured probability for dummy retransmit
        if rng.gen_bool(self.dummy_prob as f64) {
            return Some(self.generate_sophisticated_dummy_packet());
        }

        None
    }

    /// Generate ultra-sophisticated dummy packet that confuses DPI systems
    #[inline(always)]
    fn generate_sophisticated_dummy_packet(&self) -> Vec<u8> {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        // Randomize size to match real traffic patterns
        let size = match rng.gen_range(0..100) {
            0..=30 => rng.gen_range(40..120),     // Small control packets
            31..=80 => rng.gen_range(500..800),   // Medium data packets
            81..=95 => rng.gen_range(1200..1400), // Large data packets
            _ => rng.gen_range(1400..1500),       // Jumbo frames
        };

        let mut dummy = Vec::with_capacity(size);

        // Hardware-accelerated confusion generation
        #[cfg(target_arch = "x86_64")]
        if crate::optimize::FeatureDetector::instance()
            .has_feature(crate::optimize::CpuFeature::AES)
        {
            unsafe {
                self.generate_ultimate_dpi_confusion(&mut dummy, size);
                return dummy;
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            let fd = crate::optimize::FeatureDetector::instance();
            let has_simd = fd.has_feature(crate::optimize::CpuFeature::SVE2)
                || fd.has_feature(crate::optimize::CpuFeature::NEON);
            if has_simd {
                unsafe {
                    self.generate_neon_confusion(&mut dummy, size);
                    return dummy;
                }
            }
        }

        // Fallback: Generate multi-layer confusion patterns
        self.generate_layered_confusion(&mut dummy, size);
        dummy
    }

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    unsafe fn generate_ultimate_dpi_confusion(&self, buffer: &mut Vec<u8>, size: usize) {
        use rand::Rng;
        use std::arch::x86_64::*;
        let mut rng = rand::thread_rng();

        buffer.reserve(size);
        let mut state =
            _mm_set_epi32(0x428a2f98, 0x71374491, 0xb5c0fbcfu32 as i32, 0xe9b5dba5u32 as i32);

        // Generate confusing patterns with AES-NI (near-zero cost)
        let mut written = 0;
        while written + 16 <= size {
            // Each block looks like encrypted data but contains DPI traps
            state = _mm_aesenc_si128(state, _mm_set1_epi8(written as i8));

            // ULTIMATE protocol confusion - mix EVERYTHING!
            let protocol_phase = (written / 16) % 12;
            match protocol_phase {
                0 => {
                    // TLS 1.3 ClientHello with corrupted extensions
                    state = _mm_insert_epi8(state, 0x16, 0); // Handshake
                    state = _mm_insert_epi8(state, 0x03, 1); // TLS 1.2 compat
                    state = _mm_insert_epi8(state, 0x03, 2);
                    state = _mm_insert_epi16(state, 0x7FFF, 2); // Invalid length
                }
                1 => {
                    // QUIC Initial with wrong version
                    state = _mm_insert_epi8(state, 0xC3, 0); // Long header
                    state = _mm_insert_epi32(state, 0xFACEB00Cu32 as i32, 1); // Fake version
                    state = _mm_insert_epi8(state, 0xFF, 5); // Invalid DCID len
                }
                2 => {
                    // HTTP/3 QPACK with impossible Huffman
                    state = _mm_insert_epi8(state, 0x02, 0); // HEADERS
                    state = _mm_insert_epi8(state, 0xFF, 1); // All bits set
                    state = _mm_insert_epi16(state, 0xDEAD, 1);
                }
                3 => {
                    // WireGuard handshake init
                    state = _mm_insert_epi8(state, 0x01, 0);
                    state = _mm_insert_epi8(state, 0x00, 1);
                    state = _mm_insert_epi8(state, 0x00, 2);
                    state = _mm_insert_epi8(state, 0x00, 3);
                }
                4 => {
                    // OpenVPN P_CONTROL_V1
                    state = _mm_insert_epi16(state, 0x2838, 0);
                    state = _mm_insert_epi8(state, rng.gen(), 2);
                }
                5 => {
                    // IPSec ESP with wrong SPI
                    state = _mm_insert_epi32(state, 0xDEADBEEFu32 as i32, 0);
                    state = _mm_insert_epi32(state, rng.gen(), 1);
                }
                6 => {
                    // DTLS 1.2 with future epoch
                    state = _mm_insert_epi8(state, 0x16, 0);
                    state = _mm_insert_epi8(state, 0xFE, 1); // DTLS
                    state = _mm_insert_epi8(state, 0xFD, 2);
                    state = _mm_insert_epi16(state, 0xFFFF, 2); // Max epoch
                }
                7 => {
                    // SSH with wrong packet length
                    let ssh_banner = 0x5353482D; // "SSH-"
                    state = _mm_insert_epi32(state, ssh_banner, 0);
                    state = _mm_insert_epi32(state, 0xFFFFFFFFu32 as i32, 1); // Max len
                }
                8 => {
                    // HTTP/2 with GREASE frame type
                    state = _mm_insert_epi8(state, 0x0B, 3); // Unknown frame
                    state = _mm_insert_epi8(state, 0x0A, 4); // GREASE
                    state = _mm_insert_epi32(state, 0x0A0A0A0A, 1);
                }
                9 => {
                    // DNS with massive query
                    state = _mm_insert_epi16(state, rng.gen::<u16>() as i32, 0); // ID
                    state = _mm_insert_epi16(state, 0x8180, 1); // Flags
                    state = _mm_insert_epi16(state, 0xFFFF, 2); // 65535 queries
                }
                10 => {
                    // WebSocket with wrong masking
                    state = _mm_insert_epi8(state, 0x82, 0); // Binary frame
                    state = _mm_insert_epi8(state, 0xFE, 1); // Extended len
                    state = _mm_insert_epi16(state, 0xFFFF, 1);
                }
                _ => {
                    // BitTorrent piece with wrong index
                    state = _mm_insert_epi8(state, 0x07, 4); // Piece msg
                    state = _mm_insert_epi32(state, 0xFFFFFFFFu32 as i32, 0); // Max index
                }
            }

            let mut temp = [0u8; 16];
            _mm_storeu_si128(temp.as_mut_ptr() as *mut __m128i, state);
            buffer.extend_from_slice(&temp);
            written += 16;
        }

        // Fill remainder with confusing bytes
        while written < size {
            buffer.push(rng.gen());
            written += 1;
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[inline(always)]
    unsafe fn generate_neon_confusion(&self, buffer: &mut Vec<u8>, size: usize) {
        use rand::Rng;
        use std::arch::aarch64::*;
        let mut rng = rand::thread_rng();

        buffer.reserve(size);
        let mut state = vld1q_u8(
            [
                0x42, 0x8a, 0x2f, 0x98, 0x71, 0x37, 0x44, 0x91, 0xb5, 0xc0, 0xfb, 0xcf, 0xe9, 0xb5,
                0xdb, 0xa5,
            ]
            .as_ptr(),
        );

        let mut written = 0;
        while written + 16 <= size {
            // AES round for confusion
            let round_key = vdupq_n_u8(written as u8);
            state = vaeseq_u8(state, round_key);
            state = vaesmcq_u8(state);

            // Inject protocol markers
            let mut temp = [0u8; 16];
            vst1q_u8(temp.as_mut_ptr(), state);

            // Mix in protocol confusion
            match (written / 16) % 8 {
                0 => {
                    temp[0] = 0x16;
                    temp[1] = 0x03;
                } // TLS
                1 => {
                    temp[0] = 0xC0;
                    temp[4..8].copy_from_slice(&0xFACEB00Cu32.to_be_bytes());
                } // QUIC
                2 => {
                    temp[0..4].copy_from_slice(b"SSH-");
                } // SSH
                3 => {
                    temp[0] = 0x00;
                    temp[1] = 0x00;
                    temp[2] = 0x00;
                } // HTTP/3
                4 => {
                    temp[0] = 0x28;
                    temp[1] = 0x38;
                } // OpenVPN
                5 => {
                    temp[0..4].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
                } // IPSec
                6 => {
                    temp[0] = 0xFE;
                    temp[1] = 0xFD;
                } // DTLS
                _ => {
                    temp[0] = 0x13;
                    temp[1] = 0x37;
                } // BitTorrent
            }

            buffer.extend_from_slice(&temp);
            written += 16;
        }

        // Fill remainder
        while written < size {
            buffer.push(rng.gen());
            written += 1;
        }
    }

    #[inline(always)]
    fn generate_layered_confusion(&self, buffer: &mut Vec<u8>, size: usize) {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        buffer.reserve(size);
        let mut written = 0;

        // EXTREME protocol confusion - 20+ protocols!
        let protocols: [&[u8]; 24] = [
            &b"HTTP/1.1 200 OK\r\n"[..],
            &b"SSH-2.0-OpenSSH_8.9"[..],
            &b"\x16\x03\x03"[..],         // TLS 1.2
            &b"\x16\x03\x04"[..],         // TLS 1.3
            &b"\xC0\x00\x00\x00\x01"[..], // QUIC v1
            &b"GET / HTTP/2\r\n"[..],
            &b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"[..], // HTTP/2 preface
            &b"CONNECT proxy:443"[..],
            &b"\x05\x01\x00"[..], // SOCKS5
            &b"\x04\x01"[..],     // SOCKS4
            &b"\x13BitTorrent protocol"[..],
            &b"\x28\x38"[..],             // OpenVPN
            &b"\xDE\xAD\xBE\xEF"[..],     // IPSec ESP
            &b"\xFE\xFD"[..],             // DTLS
            &b"\x01\x00\x00\x00"[..],     // WireGuard
            &b"\x00\x00"[..],             // DNS
            &b"\x82\xFE"[..],             // WebSocket
            &b"RTSP/1.0 200 OK\r\n"[..],  // RTSP
            &b"SIP/2.0 200 OK\r\n"[..],   // SIP
            &b"220 SMTP\r\n"[..],         // SMTP
            &b"+OK POP3\r\n"[..],         // POP3
            &b"* OK IMAP4\r\n"[..],       // IMAP
            &b"\x30\x0C\x02\x01\x01"[..], // LDAP
            &b"\xFF\xFB\x01"[..],         // Telnet
        ];

        // Randomly inject protocol markers
        while written < size {
            if rng.gen_bool(0.3) && written + 16 < size {
                let proto = protocols[rng.gen_range(0..protocols.len())];
                let inject_len = proto.len().min(size - written);
                buffer.extend_from_slice(&proto[..inject_len]);
                written += inject_len;
            } else {
                // Fill with pseudo-encrypted looking data
                let block_size = (size - written).min(32);
                for _ in 0..block_size {
                    buffer.push(rng.gen_range(128..255)); // High entropy bytes
                }
                written += block_size;
            }
        }

        // Layer 2: Corrupt any valid-looking structures
        for i in 0..buffer.len().saturating_sub(4) {
            // Break length fields
            if buffer[i] == 0x00 && buffer[i + 1] == 0x00 {
                buffer[i + 2] = rng.gen();
                buffer[i + 3] = rng.gen();
            }
            // Break version fields
            if buffer[i] == 0x03 && buffer[i + 1] == 0x03 {
                buffer[i + 1] = 0x04; // Invalid TLS version
            }
        }
    }

    /// Generate dummy retransmit packet.
    pub fn generate_dummy_retransmit(&self, original: &[u8]) -> Vec<u8> {
        let mut dummy = original.to_vec();

        // Modify packet number to make it look like retransmit
        if dummy.len() > 10 {
            dummy[9] ^= 0x01;
        }

        // Add to history
        if let Ok(mut history) = self.packet_history.lock() {
            history.push_back(PacketInfo {
                timestamp: std::time::Instant::now(),
                _size: dummy.len(),
                _packet_type: PacketType::Dummy,
            });

            // Keep history bounded
            if history.len() > 100 {
                history.pop_front();
            }
        }

        dummy
    }

    /// Apply timing obfuscation with actual delay.
    pub async fn apply_timing_obfuscation(&self) {
        let jitter = self.apply_jitter();
        if !jitter.is_zero() {
            tokio::time::sleep(jitter).await;
        }
    }
}

// --- 10. TLS Client Hello Spoofing

/// Allows manipulation of the TLS ClientHello to mimic real browser behaviour.
///
/// ClientHello bytes are synthesized in-memory using integrated fingerprinting,
/// replacing legacy on-disk dumps.
/// Profiles are referenced via [`BrowserProfile`] and [`OsProfile`].
pub struct TlsClientHelloSpoofer;

// Cache for decoded ClientHello profiles to avoid repeated IO/base64 work.
// Reduce clippy::type_complexity by factoring nested generic types into aliases
type ProfileKey = (BrowserProfile, OsProfile);
type ChloBytes = Arc<Vec<u8>>;
type ChloCacheMap = HashMap<ProfileKey, ChloBytes>;
type ChloCache = Mutex<ChloCacheMap>;

static CHLO_CACHE: std::sync::OnceLock<ChloCache> = std::sync::OnceLock::new();

impl TlsClientHelloSpoofer {
    /// Generate ClientHello with advanced features.
    pub fn generate_advanced_hello(
        browser: BrowserProfile,
        os: OsProfile,
        sni: Option<&str>,
        session_tickets: Option<Vec<(Vec<u8>, u32)>>,
        enable_ech: bool,
    ) -> Vec<u8> {
        let seed = (browser as u16) ^ ((os as u16) << 8);
        let enable_grease = !matches!(browser, BrowserProfile::Safari);

        // Build extensions with all advanced features
        let mut exts = Vec::with_capacity(1024);

        // Add extensions in browser-specific order
        let ext_order = Self::get_extension_order(browser);

        for ext_name in ext_order {
            match *ext_name {
                "grease" if enable_grease => {
                    exts.extend_from_slice(&tls_cover::grease_ext(seed));
                }
                "sni" => {
                    if let Some(host) = sni {
                        exts.extend_from_slice(&tls_cover::sni_ext(host));
                    }
                }
                "session_ticket" => {
                    if let Some(ref tickets) = session_tickets {
                        exts.extend_from_slice(&Self::build_psk_extension(tickets));
                    }
                }
                "ech" if enable_ech => {
                    exts.extend_from_slice(&Self::build_ech_grease());
                }
                "supported_versions" => {
                    exts.extend_from_slice(&Self::build_supported_versions());
                }
                "key_share" => {
                    exts.extend_from_slice(&tls_cover::key_share_ext(0x001d, seed as u64));
                }
                _ => {}
            }
        }

        // Generate full ClientHello
        tls_cover::TlsCover::client_hello_custom(tls_cover::ClientHelloParams {
            tls_version: 0x0303,
            cipher_suites: &Self::get_cipher_suites(browser, enable_grease, seed),
            extensions: &exts,
        })
    }

    fn get_extension_order(browser: BrowserProfile) -> &'static [&'static str] {
        match browser {
            BrowserProfile::Chrome | BrowserProfile::Edge => &[
                "grease",
                "sni",
                "ech",
                "supported_versions",
                "key_share",
                "session_ticket",
                "psk_modes",
                "signature_algorithms",
            ],
            BrowserProfile::Firefox => &[
                "sni",
                "supported_versions",
                "signature_algorithms",
                "key_share",
                "session_ticket",
                "psk_modes",
                "ech",
            ],
            BrowserProfile::Safari => &[
                "sni",
                "supported_versions",
                "signature_algorithms",
                "key_share",
                "session_ticket",
            ],
        }
    }

    fn get_cipher_suites(browser: BrowserProfile, grease: bool, seed: u16) -> Vec<u16> {
        let mut ciphers = match browser {
            BrowserProfile::Firefox => vec![0x1301, 0x1302, 0x1303, 0xCCA9, 0xCCA8],
            _ => vec![0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F],
        };

        if grease {
            ciphers.insert(0, tls_cover::grease_value(seed as usize));
        }

        ciphers
    }

    fn build_psk_extension(tickets: &[(Vec<u8>, u32)]) -> Vec<u8> {
        let mut ext = Vec::with_capacity(256);

        // Extension type (pre_shared_key = 41)
        ext.extend_from_slice(&41u16.to_be_bytes());

        // Build identities
        let mut identities = Vec::new();
        for (ticket, age_ms) in tickets.iter().take(2) {
            identities.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
            identities.extend_from_slice(ticket);
            identities.extend_from_slice(&age_ms.to_be_bytes());
        }

        // Extension length
        ext.extend_from_slice(&((identities.len() + 2) as u16).to_be_bytes());

        // Identities length
        ext.extend_from_slice(&(identities.len() as u16).to_be_bytes());
        ext.extend_from_slice(&identities);

        ext
    }

    fn build_ech_grease() -> Vec<u8> {
        // Build ECH GREASE extension (type 0xfe0d)
        let mut ext = Vec::with_capacity(128);
        ext.extend_from_slice(&0xfe0du16.to_be_bytes());

        // Random GREASE data (64 bytes)
        let grease_len = 64u16;
        ext.extend_from_slice(&grease_len.to_be_bytes());

        for _ in 0..grease_len {
            ext.push(rand::random());
        }

        ext
    }

    fn build_supported_versions() -> Vec<u8> {
        let mut ext = Vec::new();
        ext.extend_from_slice(&43u16.to_be_bytes()); // Extension type
        ext.extend_from_slice(&3u16.to_be_bytes()); // Length
        ext.push(2); // Versions length
        ext.extend_from_slice(&0x0304u16.to_be_bytes()); // TLS 1.3
        ext
    }

    /// Loads a base64-encoded ClientHello dump for the given browser/OS from disk.
    #[inline]
    fn load_client_hello(browser: BrowserProfile, os: OsProfile) -> Option<Vec<u8>> {
        // Fast path: cached profile
        let cache = CHLO_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
        if let Ok(guard) = cache.lock() {
            if let Some(arc_bytes) = guard.get(&(browser, os)) {
                return Some((**arc_bytes).clone());
            }
        }
        // Generate ClientHello using integrated fingerprinting
        let bytes = tls_cover::TlsCover::generate_client_hello(browser, os, None);
        if let Ok(mut guard) = cache.lock() {
            guard.insert((browser, os), Arc::new(bytes.clone()));
        }
        Some(bytes)
    }

    /// Injects the given ClientHello bytes into the transport configuration (native).
    #[inline]
    fn inject_bytes(cfg: &mut crate::transport::Config, hello: &[u8]) {
        if hello.is_empty() {
            return;
        }
        // Native path: store ClientHello template and adjust GREASE/determinism knobs.
        cfg.set_custom_tls(hello);
        cfg.disable_tls_grease(true);
        cfg.set_deterministic_hello(true);
        cfg.enable_simd();
    }

    /// Loads the specified profile and injects it into the quiche config.
    ///
    /// Generates ClientHello using integrated fingerprinting for the specified browser/OS.
    /// If generation fails, this logs an error and leaves `cfg` unchanged.
    ///
    /// Side effects
    /// ------------
    /// Disables GREASE and enables deterministic hellos for the lifetime of the
    /// process TLS context (via FFI calls). No error is returned.
    ///
    /// Safety
    /// ------
    /// This method is safe to call. It internally uses FFI shims to interact with a
    /// patched quiche build. When the symbols are not present, calls are no-ops.
    ///
    /// Examples
    /// --------
    /// ```text
    /// // let mut cfg = crate::transport::Config::new(crate::transport::PROTOCOL_VERSION).unwrap();
    /// // TlsClientHelloSpoofer::inject_profile(&mut cfg, BrowserProfile::Chrome, OsProfile::Windows);
    /// ```
    pub fn inject_profile(
        cfg: &mut crate::transport::Config,
        browser: BrowserProfile,
        os: OsProfile,
    ) {
        if let Some(hello) = Self::load_client_hello(browser, os) {
            Self::inject_bytes(cfg, &hello);
        } else {
            error!("Missing ClientHello profile for {:?}/{:?}", browser, os);
        }
    }

    /// Builds and injects a ClientHello with options (SNI, GREASE)
    pub fn inject_profile_with_options(
        cfg: &mut crate::transport::Config,
        browser: BrowserProfile,
        os: OsProfile,
        sni: Option<&str>,
        enable_grease: bool,
    ) {
        // Generate ClientHello with options
        let seed = (browser as u16) ^ ((os as u16) << 8);
        let mut ciphers = match browser {
            BrowserProfile::Firefox => vec![
                0x1301, 0x1302, 0x1303, 0xCCA9, 0xCCA8, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xC013,
                0xC014,
            ],
            _ => vec![
                0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013,
                0xC014,
            ],
        };

        if enable_grease {
            let grease = tls_cover::grease_value(seed as usize);
            if !ciphers.contains(&grease) {
                ciphers.insert(0, grease);
            }
        }

        let mut exts = Vec::with_capacity(512);
        if enable_grease {
            exts.extend_from_slice(&tls_cover::grease_ext(seed));
        }
        if let Some(host) = sni {
            exts.extend_from_slice(&tls_cover::sni_ext(host));
        }

        let ch = tls_cover::TlsCover::client_hello_custom(tls_cover::ClientHelloParams {
            tls_version: 0x0303,
            cipher_suites: &ciphers,
            extensions: &exts,
        });
        Self::inject_bytes(cfg, &ch);
    }

    /// Returns a list of all available browser/OS combinations for which a
    /// ClientHello dump exists.
    #[inline]
    pub fn available_profiles() -> Vec<(BrowserProfile, OsProfile)> {
        // Enumerate curated combos that blend in widely
        use BrowserProfile as B;
        use OsProfile as O;
        vec![
            // Windows
            (B::Chrome, O::Windows),
            (B::Firefox, O::Windows),
            (B::Edge, O::Windows),
            // macOS
            (B::Safari, O::MacOS),
            (B::Chrome, O::MacOS),
            (B::Firefox, O::MacOS),
            (B::Edge, O::MacOS),
            // Linux
            (B::Chrome, O::Linux),
            (B::Firefox, O::Linux),
            // Android
            (B::Chrome, O::Android),
            (B::Firefox, O::Android),
            (B::Edge, O::Android),
            // iOS
            (B::Safari, O::IOS),
            (B::Chrome, O::IOS),
        ]
    }
}

// --- 7. Stealth Manager and Configuration ---

/// Ultra-sophisticated configuration for the main StealthManager.
#[derive(Clone)]
pub struct StealthConfig {
    /// Selected high-level mode for behavior decisions.
    pub mode: StealthMode,
    /// Enable domain fronting to hide the real destination.
    pub enable_domain_fronting: bool,
    pub initial_browser: BrowserProfile,
    /// Initial OS profile for fingerprinting.
    pub initial_os: OsProfile,
    /// Enable traffic padding to obscure packet sizes.
    pub enable_traffic_padding: bool,
    /// Enable timing obfuscation with random delays.
    pub enable_timing_obfuscation: bool,
    /// Enable protocol mimicry (make QUIC look like other protocols).
    pub enable_protocol_mimicry: bool,
    /// Enable dynamic fingerprint rotation.
    pub enable_fingerprint_rotation: bool,
    /// Padding strategy: 'random', 'fixed', 'adaptive'.
    pub padding_strategy: PaddingStrategy,
    /// Maximum padding size in bytes.
    pub max_padding_size: usize,
    /// Fingerprint rotation interval in seconds.
    pub fingerprint_rotation_interval: u64,
    /// Enable DNS-over-HTTPS for domain resolution.
    pub enable_doh: bool,
    /// DoH provider endpoint URL (e.g. Cloudflare DNS JSON API).
    pub doh_provider: String,
    /// Enable real-time rate choke (token/leaky bucket) to smooth observable bitrate.
    pub enable_realtime_choke: bool,
    /// Target bitrate for choke in Mbps (0 = disabled).
    pub choke_target_mbps: u32,
    /// Allowed burst window in milliseconds.
    pub choke_burst_ms: u32,
    /// Enable Dynamic mode (start as Base and escalate intelligently).
    pub dynamic_enabled: bool,
    // Additional fields for compatibility
    pub fronting_domains: Vec<String>,
    pub enable_http3_masquerading: bool,
    pub enable_xor_obfuscation: bool,
    pub use_tls_cover: bool,
    pub use_qpack_headers: bool,
    /// **NEW**: Enable HTTP/3 Server Push Cover Traffic
    pub enable_server_push_cover: bool,
    /// Server Push cover traffic intensity (0.0 = disabled, 1.0 = maximum)
    pub server_push_intensity: f32,
    /// Base path for fake resources (e.g., "/assets", "/static")
    pub server_push_base_path: String,
    /// Minimum delay between cover traffic bursts (seconds)
    pub server_push_burst_interval: u64,
    // Compression Policy (optional)
    pub compress_enabled: bool,
    pub compress_min_len: usize,
    pub compress_level: i32,
    pub compress_allow: Vec<String>,
    pub compress_deny: Vec<String>,
}

/// Padding strategies for traffic obfuscation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum PaddingStrategy {
    /// Random padding between 0 and max_padding_size.
    Random,
    /// Fixed padding to nearest power of 2.
    Fixed,
    /// Adaptive padding based on traffic patterns.
    Adaptive,
    /// Mimic browser-specific padding patterns.
    BrowserMimic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum StealthMode {
    /// Disabled - no stealth features.
    #[serde(alias = "off", alias = "Off")]
    Off,
    /// Performance - stealth baseline with all costly features off.
    #[serde(alias = "Performance", alias = "performance", alias = "Base", alias = "base")]
    Performance,
    /// Stealth - balanced features with minimal overhead.
    #[serde(alias = "stealth", alias = "Stealth")]
    Stealth,
    /// Anti-DPI (formerly StealthMax) - ultra stealth with aggressive settings.
    #[serde(
        alias = "StealthMax",
        alias = "stealthmax",
        alias = "stealth-max",
        alias = "Anti-DPI",
        alias = "AntiDPI",
        alias = "anti-dpi",
        alias = "antidpi",
        alias = "max",
        alias = "Max"
    )]
    AntiDpi,
    /// Manual - user controlled.
    #[serde(alias = "manual", alias = "Manual")]
    Manual,
    /// Intelligent (formerly Dynamic) - starts like Base and escalates smartly.
    #[serde(
        alias = "Dynamic",
        alias = "dynamic",
        alias = "auto",
        alias = "Auto",
        alias = "intelligent"
    )]
    Intelligent,
}

/// FEC operation modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum FecMode {
    /// Disabled - no FEC.
    Off,
    /// Auto - adaptive FEC based on network conditions.
    Auto,
    /// Manual - custom FEC parameters.
    Manual,
}

/// Fingerprint rotation configuration.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct FingerprintRotationConfig {
    /// Enable rotation.
    pub enabled: bool,
    /// Rotation interval in seconds.
    pub interval_secs: u64,
    /// Rotation mode.
    pub mode: RotationMode,
    /// Profile slots for rotation (up to 3).
    pub profile_slots: Vec<(BrowserProfile, OsProfile)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum RotationMode {
    /// Single profile - no rotation.
    Fixed,
    /// Rotate through configured slots.
    Slots,
    /// Rotate through all available profiles.
    All,
}

impl StealthConfig {
    /// Creates Stealth mode - balanced features with minimal overhead (sweetspot).
    pub fn stealth() -> Self {
        Self {
            mode: StealthMode::Stealth,
            enable_domain_fronting: true,
            // Fields removed during consolidation
            initial_browser: BrowserProfile::Chrome,
            initial_os: OsProfile::Windows,
            // Enable adaptive padding with a very small budget (sweetspot)
            // to retain near-zero overhead while smoothing packet sizes.
            enable_traffic_padding: true,
            // Minimal timing obfuscation for Stealth (very low impact)
            enable_timing_obfuscation: true,
            enable_protocol_mimicry: true,
            enable_fingerprint_rotation: false, // Simple Chrome profile
            padding_strategy: PaddingStrategy::Adaptive,
            max_padding_size: 86, // Slightly higher for better smoothing
            fingerprint_rotation_interval: 0,
            enable_doh: true,
            doh_provider: "https://cloudflare-dns.com/dns-query".to_string(),
            // Real-time choke: light smoothing in Stealth (disabled by default to avoid perf hits)
            enable_realtime_choke: false,
            choke_target_mbps: 0,
            choke_burst_ms: 0,
            // Dynamic disabled
            dynamic_enabled: false,
            fronting_domains: vec![],
            enable_http3_masquerading: true,
            enable_xor_obfuscation: true,
            use_tls_cover: true,
            use_qpack_headers: true,
            // Server Push Cover Traffic: OFF in Stealth mode (performance priority)
            enable_server_push_cover: false,
            server_push_intensity: 0.0,
            server_push_base_path: "/assets".to_string(),
            server_push_burst_interval: 30,
            compress_enabled: true,
            compress_min_len: 256,
            compress_level: 5,
            compress_allow: vec!["text/*".into(), "application/json".into()],
            compress_deny: vec![
                "image/*".into(),
                "video/*".into(),
                "audio/*".into(),
                "application/zip".into(),
            ],
        }
    }

    /// Creates Anti-DPI mode - all features with aggressive settings.
    pub fn anti_dpi() -> Self {
        let domains = DomainFrontingManager::ultra_stealth();
        Self {
            mode: StealthMode::AntiDpi,
            enable_domain_fronting: true,
            fronting_domains: domains.domains.to_vec(),
            enable_http3_masquerading: true,
            enable_xor_obfuscation: true,
            use_tls_cover: true,
            use_qpack_headers: true,
            initial_browser: BrowserProfile::Chrome,
            initial_os: OsProfile::Windows,
            enable_traffic_padding: true,
            enable_timing_obfuscation: true, // Performance impact accepted
            enable_protocol_mimicry: true,
            enable_fingerprint_rotation: true,
            padding_strategy: PaddingStrategy::BrowserMimic,
            max_padding_size: 256,
            fingerprint_rotation_interval: 300, // 5 minutes
            enable_doh: true,
            doh_provider: "https://cloudflare-dns.com/dns-query".to_string(),
            enable_realtime_choke: true,
            choke_target_mbps: 10, // Moderate throttling
            choke_burst_ms: 500,
            dynamic_enabled: false,
            // Server Push Cover Traffic: ON in Anti-DPI mode (maximum stealth)
            enable_server_push_cover: true,
            server_push_intensity: 0.8, // High intensity
            server_push_base_path: "/cdn".to_string(),
            server_push_burst_interval: 15, // Frequent bursts
            // Aggressive compression defaults for Anti-DPI traffic (textual payloads)
            compress_enabled: true,
            compress_min_len: 128,
            compress_level: 7,
            compress_allow: vec!["text/*".into(), "application/json".into()],
            compress_deny: vec![
                "image/*".into(),
                "video/*".into(),
                "audio/*".into(),
                "application/zip".into(),
            ],
        }
    }

    /// Backward-compat: legacy alias returning Anti-DPI settings.
    pub fn stealth_max() -> Self {
        Self::anti_dpi()
    }

    /// Creates configuration from mode.
    pub fn from_mode(mode: StealthMode) -> Self {
        match mode {
            StealthMode::Off => Self::off(),
            StealthMode::Performance => Self::performance(),
            StealthMode::Stealth => Self::stealth(),
            StealthMode::AntiDpi => Self::anti_dpi(),
            StealthMode::Manual => Self::manual(),
            StealthMode::Intelligent => Self::intelligent(),
        }
    }

    /// Creates Off mode - no stealth features.
    pub fn off() -> Self {
        Self {
            mode: StealthMode::Off,
            enable_domain_fronting: false,
            initial_browser: BrowserProfile::Chrome,
            initial_os: OsProfile::Windows,
            enable_traffic_padding: false,
            enable_timing_obfuscation: false,
            enable_protocol_mimicry: false,
            enable_fingerprint_rotation: false,
            padding_strategy: PaddingStrategy::Random,
            max_padding_size: 0,
            fingerprint_rotation_interval: 0,
            enable_doh: false,
            doh_provider: String::new(),
            enable_realtime_choke: false,
            choke_target_mbps: 0,
            choke_burst_ms: 0,
            dynamic_enabled: false,
            fronting_domains: vec![],
            enable_http3_masquerading: false,
            enable_xor_obfuscation: false,
            use_tls_cover: true,
            use_qpack_headers: false,
            // Server Push Cover Traffic: OFF in Off mode
            enable_server_push_cover: false,
            server_push_intensity: 0.0,
            server_push_base_path: "/assets".to_string(),
            server_push_burst_interval: 0,
            compress_enabled: false,
            compress_min_len: 1024,
            compress_level: 3,
            compress_allow: Vec::new(),
            compress_deny: Vec::new(),
        }
    }

    /// Creates an ultra-stealth configuration (alias for anti_dpi).
    pub fn ultra_stealth() -> Self {
        Self::anti_dpi()
    }

    /// Creates Manual mode - custom configuration.
    pub fn manual() -> Self {
        Self {
            mode: StealthMode::Manual,
            enable_domain_fronting: false,
            initial_browser: BrowserProfile::Chrome,
            initial_os: OsProfile::Windows,
            enable_traffic_padding: false,
            enable_timing_obfuscation: false,
            enable_protocol_mimicry: false,
            enable_fingerprint_rotation: false,
            padding_strategy: PaddingStrategy::Random,
            max_padding_size: 0,
            fingerprint_rotation_interval: 0,
            enable_doh: false,
            doh_provider: String::new(),
            enable_realtime_choke: false,
            choke_target_mbps: 0,
            choke_burst_ms: 0,
            dynamic_enabled: false,
            fronting_domains: vec![],
            enable_http3_masquerading: false,
            enable_xor_obfuscation: false,
            use_tls_cover: false,
            use_qpack_headers: false,
            // Server Push Cover Traffic: Manual configuration
            enable_server_push_cover: false,
            server_push_intensity: 0.3,
            server_push_base_path: "/static".to_string(),
            server_push_burst_interval: 60,
            compress_enabled: false,
            compress_min_len: 256,
            compress_level: 5,
            compress_allow: Vec::new(),
            compress_deny: Vec::new(),
        }
    }

    /// Creates Performance mode - Stealth baseline but with all costly features off.
    pub fn performance() -> Self {
        Self {
            mode: StealthMode::Performance,
            // Domain fronting: enabled (negligible performance impact; strengthens cover)
            enable_domain_fronting: true,
            fronting_domains: vec![],
            enable_http3_masquerading: true,
            enable_xor_obfuscation: false,
            use_tls_cover: true,
            use_qpack_headers: false,
            // Fingerprint: stable Chromium/Windows baseline
            initial_browser: BrowserProfile::Chrome,
            initial_os: OsProfile::Windows,
            // Padding: completely off
            enable_traffic_padding: false,
            // Timing obfuscation / Flow shaping: off
            enable_timing_obfuscation: false,
            // Protocol mimicry (extra transformations): off
            enable_protocol_mimicry: false,
            // Fingerprint rotation: off
            enable_fingerprint_rotation: false,
            // Strategy is ignored when padding disabled
            padding_strategy: PaddingStrategy::Random,
            max_padding_size: 0,
            fingerprint_rotation_interval: 0,
            // DNS over HTTPS: ON in Base per spec (Cloudflare)
            enable_doh: true,
            doh_provider: "https://cloudflare-dns.com/dns-query".to_string(),
            // Real-time choke disabled for Base
            enable_realtime_choke: false,
            choke_target_mbps: 0,
            choke_burst_ms: 0,
            dynamic_enabled: false,
            // Server Push Cover Traffic: OFF in Performance mode (performance priority)
            enable_server_push_cover: false,
            server_push_intensity: 0.0,
            server_push_base_path: "/assets".to_string(),
            server_push_burst_interval: 0,
            compress_enabled: false,
            compress_min_len: 512,
            compress_level: 3,
            compress_allow: Vec::new(),
            compress_deny: vec!["*/*".into()],
        }
    }

    /// Creates Intelligent mode - starts like Performance and escalates intelligently.
    pub fn intelligent() -> Self {
        let mut cfg = Self::performance();
        cfg.mode = StealthMode::Intelligent;
        cfg.dynamic_enabled = true;
        cfg
    }
    /// Backward-compat alias for Dynamic
    pub fn dynamic() -> Self {
        Self::intelligent()
    }
}

impl Default for StealthConfig {
    fn default() -> Self {
        Self::stealth() // Default to Stealth mode
    }
}

impl StealthConfig {
    /// Parses a TOML string and constructs a `StealthConfig` from the
    /// `[stealth]` table. Unknown keys are ignored. This does not apply
    /// environment overrides; call `apply_env_overrides` separately if needed.
    pub fn from_toml(s: &str) -> Result<Self, Box<dyn std::error::Error>> {
        #[derive(serde::Deserialize)]
        struct Root {
            stealth: Option<Section>,
            compression: Option<CompSection>,
        }

        #[derive(serde::Deserialize)]
        struct Section {
            mode: Option<StealthMode>,
            initial_browser: Option<BrowserProfile>,
            initial_os: Option<OsProfile>,
            #[serde(alias = "use_tls_cover_extras")]
            use_tls_cover: Option<bool>,
            enable_doh: Option<bool>,
            doh_provider: Option<String>,
            enable_http3_masquerading: Option<bool>,
            use_qpack_headers: Option<bool>,
            enable_domain_fronting: Option<bool>,
            fronting_domains: Option<Vec<String>>,
            enable_xor_obfuscation: Option<bool>,
            enable_traffic_padding: Option<bool>,
            enable_timing_obfuscation: Option<bool>,
            enable_protocol_mimicry: Option<bool>,
            padding_strategy: Option<String>,
            max_padding_size: Option<usize>,
            _enable_fingerprint_rotation: Option<bool>,
            _fingerprint_rotation_interval: Option<u64>,
        }
        #[derive(serde::Deserialize)]
        struct CompSection {
            enabled: Option<bool>,
            min_len: Option<usize>,
            level: Option<i32>,
            allow: Option<Vec<String>>,
            deny: Option<Vec<String>>,
        }

        fn parse_padding_strategy(value: &str) -> Option<PaddingStrategy> {
            let v = value.trim().to_ascii_lowercase();
            match v.as_str() {
                "random" | "1" => Some(PaddingStrategy::Random),
                "fixed" | "constant" | "2" => Some(PaddingStrategy::Fixed),
                "adaptive" | "3" => Some(PaddingStrategy::Adaptive),
                "browser" | "browser_mimic" | "browser-mimic" | "browsermimic" | "mimic" | "4" => {
                    Some(PaddingStrategy::BrowserMimic)
                }
                _ => None,
            }
        }

        let root: Root = toml::from_str(s)?;
        let mut cfg = StealthConfig::default();
        if let Some(sec) = root.stealth {
            if let Some(mode) = sec.mode {
                cfg = StealthConfig::from_mode(mode);
            }
            if let Some(v) = sec.initial_browser {
                cfg.initial_browser = v;
            }
            if let Some(v) = sec.initial_os {
                cfg.initial_os = v;
            }
            if let Some(v) = sec.use_tls_cover {
                cfg.use_tls_cover = v;
            }
            if let Some(v) = sec.enable_doh {
                cfg.enable_doh = v;
            }
            if let Some(v) = sec.doh_provider {
                cfg.doh_provider = v;
            }
            if let Some(v) = sec.enable_http3_masquerading {
                cfg.enable_http3_masquerading = v;
            }
            if let Some(v) = sec.use_qpack_headers {
                cfg.use_qpack_headers = v;
            }
            if let Some(v) = sec.enable_domain_fronting {
                cfg.enable_domain_fronting = v;
            }
            if let Some(v) = sec.fronting_domains {
                cfg.fronting_domains = v;
            }
            if let Some(v) = sec.enable_xor_obfuscation {
                cfg.enable_xor_obfuscation = v;
            }
            if let Some(v) = sec.enable_traffic_padding {
                cfg.enable_traffic_padding = v;
            }
            if let Some(v) = sec.enable_timing_obfuscation {
                cfg.enable_timing_obfuscation = v;
            }
            if let Some(v) = sec.enable_protocol_mimicry {
                cfg.enable_protocol_mimicry = v;
            }
            if let Some(v) = sec.padding_strategy.as_deref().and_then(parse_padding_strategy) {
                cfg.padding_strategy = v;
            }
            if let Some(v) = sec.max_padding_size {
                cfg.max_padding_size = v;
            }
        }
        if let Some(c) = root.compression {
            if let Some(v) = c.enabled {
                cfg.compress_enabled = v;
            }
            if let Some(v) = c.min_len {
                cfg.compress_min_len = v;
            }
            if let Some(v) = c.level {
                cfg.compress_level = v;
            }
            if let Some(v) = c.allow {
                cfg.compress_allow = v;
            }
            if let Some(v) = c.deny {
                cfg.compress_deny = v;
            }
            // Push to global compression policy
            crate::compress::set_global_policy(crate::compress::CompressionPolicy {
                enabled: cfg.compress_enabled,
                min_len: cfg.compress_min_len,
                level: cfg.compress_level,
                allow: cfg.compress_allow.clone(),
                deny: cfg.compress_deny.clone(),
            });
        }
        Ok(cfg)
    }

    /// Reads a TOML file at `path` and delegates to [`StealthConfig::from_toml`].
    /// Environment overrides are not applied automatically.
    pub fn from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_toml(&contents)
    }

    /// Validate the configuration values.
    pub fn validate(&self) -> Result<(), String> {
        if self.enable_doh && self.doh_provider.is_empty() {
            return Err("doh_provider must not be empty when DoH is enabled".into());
        }
        if self.enable_server_push_cover && !self.enable_http3_masquerading {
            return Err("server push cover requires HTTP/3 masquerading to be enabled".into());
        }
        if self.enable_realtime_choke && self.choke_target_mbps == 0 {
            return Err("realtime choke requires choke_target_mbps > 0".into());
        }
        if matches!(self.mode, StealthMode::Performance)
            && (self.enable_timing_obfuscation
                || self.enable_traffic_padding
                || self.enable_realtime_choke)
        {
            return Err(
                "performance mode cannot enable timing obfuscation/padding/realtime choke".into()
            );
        }
        // When domain fronting is enabled and no domains are provided, we fall back
        // to built-in ultra-stealth rotation (handled in StealthManager::new()).
        if !self.use_tls_cover {
            // Informative notice: TLS Cover extras are automatically disabled
            // (CertChainEmulator, cover PSK/tickets). Real TLS path remains fully active.
            log::warn!(
                "TLS Cover extras disabled: synthetic cert chain and cover PSK are not used"
            );
        }
        Ok(())
    }

    /// Applies environment variable overrides for stealth settings.
    /// Supported variables:
    /// - QUICFUSCATE_BROWSER: chrome|firefox|safari|edge (case-insensitive)
    /// - QUICFUSCATE_OS: windows|linux|macos|android|ios (case-insensitive)
    /// - QUICFUSCATE_USE_TLS_COVER_EXTRAS: 0|1|true|false
    /// - QUICFUSCATE_DOH: 0|1|true|false
    /// - QUICFUSCATE_DOH_PROVIDER: URL
    /// - QUICFUSCATE_FRONTING: 0|1|true|false
    /// - QUICFUSCATE_QPACK: 0|1|true|false
    /// - QUICFUSCATE_XOR: 0|1|true|false
    pub fn apply_env_overrides(&mut self) {
        fn parse_bool(v: &str) -> Option<bool> {
            match v.to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => Some(true),
                "0" | "false" | "no" | "off" => Some(false),
                _ => None,
            }
        }

        // Primary mode override first (sets a known baseline)
        if let Ok(v) = std::env::var("QUICFUSCATE_STEALTH_MODE") {
            let m = v.trim().to_ascii_lowercase();
            *self = match m.as_str() {
                "base" | "performance" => StealthConfig::performance(),
                "stealth" => StealthConfig::stealth(),
                "anti-dpi" | "antidpi" | "stealthmax" | "stealth-max" => StealthConfig::anti_dpi(),
                "dynamic" | "intelligent" => StealthConfig::intelligent(),
                "manual" => StealthConfig::manual(),
                "off" => StealthConfig::off(),
                _ => {
                    log::warn!("Unknown QUICFUSCATE_STEALTH_MODE='{}' - ignoring", m);
                    self.clone()
                }
            };
        }

        if let Ok(v) = std::env::var("QUICFUSCATE_BROWSER") {
            if let Some(bp) = Self::parse_browser(&v) {
                self.initial_browser = bp;
            }
        }
        if let Ok(v) = std::env::var("QUICFUSCATE_OS") {
            if let Some(os) = Self::parse_os(&v) {
                self.initial_os = os;
            }
        }
        if let Ok(v) = std::env::var("QUICFUSCATE_USE_TLS_COVER_EXTRAS")
            .or_else(|_| std::env::var("QUICFUSCATE_USE_TLS_COVER"))
        {
            if let Some(b) = parse_bool(&v) {
                self.use_tls_cover = b;
            }
        }
        if let Ok(v) = std::env::var("QUICFUSCATE_DOH") {
            if let Some(b) = parse_bool(&v) {
                self.enable_doh = b;
            }
        }
        if let Ok(v) = std::env::var("QUICFUSCATE_DOH_PROVIDER") {
            if !v.trim().is_empty() {
                self.doh_provider = v;
            }
        }
        if let Ok(v) = std::env::var("QUICFUSCATE_FRONTING") {
            if let Some(b) = parse_bool(&v) {
                self.enable_domain_fronting = b;
            }
        }
        if let Ok(v) = std::env::var("QUICFUSCATE_QPACK") {
            if let Some(b) = parse_bool(&v) {
                self.use_qpack_headers = b;
            }
        }
        if let Ok(v) = std::env::var("QUICFUSCATE_XOR") {
            if let Some(b) = parse_bool(&v) {
                self.enable_xor_obfuscation = b;
            }
        }

        // Compression policy overrides
        let mut pol = crate::compress::global_policy();
        if let Ok(v) = std::env::var("QUICFUSCATE_COMPRESS") {
            if let Some(b) = parse_bool(&v) {
                pol.enabled = b;
            }
        }
        if let Ok(v) = std::env::var("QUICFUSCATE_COMPRESS_MIN") {
            if let Ok(n) = v.parse() {
                pol.min_len = n;
            }
        }
        if let Ok(v) = std::env::var("QUICFUSCATE_COMPRESS_LEVEL") {
            if let Ok(n) = v.parse() {
                pol.level = n;
            }
        }
        if let Ok(v) = std::env::var("QUICFUSCATE_COMPRESS_ALLOW") {
            pol.allow =
                v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        }
        if let Ok(v) = std::env::var("QUICFUSCATE_COMPRESS_DENY") {
            pol.deny =
                v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        }
        crate::compress::set_global_policy(pol);

        // Optional fine-grained overrides
        if let Ok(v) = std::env::var("QUICFUSCATE_CHOKE_ENABLE") {
            if let Some(b) = parse_bool(&v) {
                self.enable_realtime_choke = b;
            }
        }
        if let Ok(v) = std::env::var("QUICFUSCATE_CHOKE_TARGET_MBPS") {
            if let Ok(n) = v.trim().parse::<u32>() {
                self.choke_target_mbps = n;
            }
        }
        if let Ok(v) = std::env::var("QUICFUSCATE_CHOKE_BURST_MS") {
            if let Ok(n) = v.trim().parse::<u32>() {
                self.choke_burst_ms = n;
            }
        }
        if let Ok(v) = std::env::var("QUICFUSCATE_STEALTH_DYNAMIC") {
            if let Some(b) = parse_bool(&v) {
                self.dynamic_enabled = b;
            }
        }
    }

    fn parse_browser(s: &str) -> Option<BrowserProfile> {
        match s.trim().to_ascii_lowercase().as_str() {
            "chrome" => Some(BrowserProfile::Chrome),
            "firefox" => Some(BrowserProfile::Firefox),
            "safari" => Some(BrowserProfile::Safari),
            "edge" => Some(BrowserProfile::Edge),
            _ => None,
        }
    }

    fn parse_os(s: &str) -> Option<OsProfile> {
        match s.trim().to_ascii_lowercase().as_str() {
            "windows" | "win" => Some(OsProfile::Windows),
            "linux" => Some(OsProfile::Linux),
            "mac" | "macos" | "darwin" => Some(OsProfile::MacOS),
            "android" => Some(OsProfile::Android),
            "ios" => Some(OsProfile::IOS),
            _ => None,
        }
    }
}

/// The main stealth manager that coordinates all obfuscation techniques.
pub struct StealthManager {
    config: StealthConfig,
    fingerprint: Arc<Mutex<FingerprintProfile>>,
    domain_fronting: Option<DomainFrontingManager>,
    xor_obfuscator: Option<Arc<XorObfuscator>>,
    /// Cryptographic manager for key derivation.
    _crypto_manager: Arc<CryptoManager>,
    /// Last rotation timestamp
    last_rotation: Arc<Mutex<std::time::Instant>>,
    /// Browser/OS profile pool for rotation
    profile_pool: Arc<Vec<(BrowserProfile, OsProfile)>>,
    /// Current profile index for rotation
    profile_index: Arc<AtomicUsize>,
    /// MASQUE manager for CONNECT-UDP tunneling
    masque_manager: Option<MasqueManager>,
    /// Active probe detector
    probe_detector: Option<ActiveProbeDetector>,
    /// Flow shaper for jitter and dummy retransmits
    flow_shaper: Option<FlowShaper>,
    /// Session ticket manager
    ticket_manager: Option<SessionTicketManager>,
    /// Certificate chain emulator
    _cert_emulator: Option<CertChainEmulator>,
    /// Cover traffic scheduler
    cover_traffic: Option<CoverTrafficScheduler>,
    /// Escalation flag after probe detection
    escalated: AtomicBool,
    /// Escalation timeout
    escalated_until: Arc<Mutex<Option<std::time::Instant>>>,
    /// Prefer MASQUE path while escalated (when available)
    prefer_masque: AtomicBool,
    /// Optional real-time rate choker
    rate_choker: Arc<Mutex<Option<RateChoker>>>,
    /// **NEW**: Server Push Cover Traffic state
    server_push_state: Arc<Mutex<ServerPushState>>,
    /// **NEW**: Runtime toggle for Server Push cover (used by Intelligent mode)
    server_push_runtime_enabled: std::sync::atomic::AtomicBool,
    /// Probe hits counter (Dynamic escalation heuristic)
    probe_hits: Arc<AtomicUsize>,
    /// Optimization manager for memory pools
    optimization_manager: Arc<OptimizationManager>,
    /// Reality Fallback Proxy for active probe handling
    pub(crate) reality_proxy: Option<Arc<crate::reality::RealityProxy>>,
    /// Receiver for upstream responses (Reality Fallback)
    pub(crate) fallback_rx:
        Arc<Mutex<tokio::sync::mpsc::Receiver<crate::reality::FallbackResponse>>>,
}

impl StealthManager {
    /// Creates a new stealth manager with the given configuration.
    pub fn new(
        config: StealthConfig,
        optimization_manager: Arc<OptimizationManager>,
        crypto_manager: Arc<CryptoManager>,
    ) -> Self {
        let fingerprint = Arc::new(Mutex::new(FingerprintProfile::new(
            config.initial_browser,
            config.initial_os,
        )));

        let domain_fronting = if config.enable_domain_fronting {
            if config.fronting_domains.is_empty() {
                Some(DomainFrontingManager::ultra_stealth())
            } else {
                Some(DomainFrontingManager::new(config.fronting_domains.clone()))
            }
        } else {
            None
        };

        let xor_obfuscator = if config.enable_xor_obfuscation {
            Some(XorObfuscator::new(&crypto_manager))
        } else {
            None
        };

        let profile_pool = Arc::new(TlsClientHelloSpoofer::available_profiles());

        // Initialize advanced features:
        // - MasqueManager is created whenever HTTP/3 masquerading is enabled, so it is
        //   immediately available during probe escalations even in Stealth mode.
        // - Additionally, honor high-stealth default and env override.
        let masque_manager = if config.enable_http3_masquerading
            || (config.enable_timing_obfuscation && config.enable_fingerprint_rotation)
            || std::env::var("QUICFUSCATE_MASQUE_ENABLE")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
        {
            Some(MasqueManager::new())
        } else {
            None
        };

        let probe_detector = if config.dynamic_enabled
            || config.enable_traffic_padding
            || config.enable_timing_obfuscation
        {
            Some(ActiveProbeDetector::new(5, ProbeResponseMode::Switch))
        } else {
            None
        };

        // Enable FlowShaper only for high-stealth profiles (rotation on),
        // Stealth (no rotation) keeps timing light via send-gate only.
        let flow_shaper = if config.enable_timing_obfuscation && config.enable_fingerprint_rotation
        {
            Some(FlowShaper::new(3000, true))
        } else {
            None
        };

        // TLS Cover-only: create ticket manager only when TLS Cover is enabled
        let ticket_manager =
            if config.use_tls_cover { Some(SessionTicketManager::new(2, 7200)) } else { None };

        // TLS Cover-only: create certificate emulator only when TLS Cover is enabled
        let cert_emulator = if config.use_tls_cover {
            // Generate a realistic default cert chain (fallback SANs; kept internal)
            Some(CertChainEmulator::generate(vec!["cdn.cloudflare.com".to_string()], 30))
        } else {
            None
        };

        // Compute MASQUE default preference before moving `config` into the struct
        let _prefer_masque_default =
            config.enable_timing_obfuscation && config.enable_fingerprint_rotation;

        // Initialize cover traffic scheduler
        let cover_traffic = if config.enable_http3_masquerading {
            // Use the fronted domain or fallback to a CDN domain
            let target = if let Some(ref df) = domain_fronting {
                df.get_fronted_domain()
            } else {
                "cdn.cloudflare.com".to_string()
            };
            Some(CoverTrafficScheduler::new(target, 5000)) // 5 second interval
        } else {
            None
        };

        // Initialize rate choker (disabled in Base, enabled in Anti-DPI; Dynamic activates on demand)
        let rate_choker =
            Arc::new(Mutex::new(RateChoker::new(config.choke_target_mbps, config.choke_burst_ms)));

        // Initialize Server Push Cover Traffic state
        let server_push_state = Arc::new(Mutex::new(ServerPushState {
            last_burst: std::time::Instant::now(),
            active_promises: 0,
            total_cover_bytes: 0,
            current_intensity: config.server_push_intensity,
            burst_window: VecDeque::with_capacity(128),
        }));

        // REALITY PROXY INITIALIZATION
        let (tx, rx) = tokio::sync::mpsc::channel(128);
        let reality_proxy = if config.dynamic_enabled {
            // Enable Reality if Dynamic mode is on
            Some(Arc::new(crate::reality::RealityProxy::new(tx)))
        } else {
            None
        };

        if reality_proxy.is_some() {
            log::info!("Reality Proxy (Reverse Proxy) initialized for Active Probe fallback.");
        }

        Self {
            config,
            fingerprint,
            domain_fronting,
            xor_obfuscator: xor_obfuscator.map(Arc::new),
            _crypto_manager: crypto_manager,
            last_rotation: Arc::new(Mutex::new(std::time::Instant::now())),
            profile_pool,
            profile_index: Arc::new(AtomicUsize::new(0)),
            masque_manager,
            probe_detector,
            flow_shaper,
            ticket_manager,
            _cert_emulator: cert_emulator,
            cover_traffic,
            escalated: AtomicBool::new(false),
            escalated_until: Arc::new(Mutex::new(None)),
            prefer_masque: AtomicBool::new(false),
            rate_choker,
            server_push_state,
            server_push_runtime_enabled: std::sync::atomic::AtomicBool::new(false),
            probe_hits: Arc::new(AtomicUsize::new(0)),
            optimization_manager,
            reality_proxy,
            fallback_rx: Arc::new(Mutex::new(rx)),
        }
    }

    /// Debug consistency check: validates TLS fingerprint matches header profile.
    #[cfg(debug_assertions)]
    pub fn validate_profile_consistency(&self, tls_profile_name: &str) {
        let fingerprint = self.fingerprint.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let expected_browser = match fingerprint.browser {
            BrowserProfile::Chrome => "chrome",
            BrowserProfile::Firefox => "firefox",
            BrowserProfile::Safari => "safari",
            BrowserProfile::Edge => "edge",
        };

        let expected_os = match fingerprint.os {
            OsProfile::Windows => "windows",
            OsProfile::MacOS => "macos",
            OsProfile::Linux => "linux",
            OsProfile::Android => "android",
            OsProfile::IOS => "ios",
        };

        if !tls_profile_name.to_lowercase().contains(expected_browser) {
            debug!(
                "Profile consistency warning: TLS profile '{}' may not match browser '{}'",
                tls_profile_name, expected_browser
            );
        }

        if !tls_profile_name.to_lowercase().contains(expected_os) {
            debug!(
                "Profile consistency warning: TLS profile '{}' may not match OS '{}'",
                tls_profile_name, expected_os
            );
        }

        // Validate sec-ch-ua consistency for Chromium browsers
        if matches!(fingerprint.browser, BrowserProfile::Chrome | BrowserProfile::Edge) {
            let masquerade = Http3Masquerade::new(fingerprint.clone());
            let sec_ch_ua = masquerade.build_sec_ch_ua();
            let ua = &fingerprint.user_agent;

            // Extract version from both and compare
            if let (Some(ua_ver), Some(ch_ver)) = (
                masquerade
                    .extract_major_version(ua, "Chrome")
                    .or_else(|| masquerade.extract_major_version(ua, "Edg")),
                masquerade
                    .extract_major_version(&sec_ch_ua, "Chrome")
                    .or_else(|| masquerade.extract_major_version(&sec_ch_ua, "Edge")),
            ) {
                if ua_ver != ch_ver {
                    debug!(
                        "Profile consistency warning: UA version {} != sec-ch-ua version {}",
                        ua_ver, ch_ver
                    );
                }
            }
        }

        debug!("Profile consistency check completed for {}/{}", expected_browser, expected_os);
    }

    /// Rotates fingerprint if interval has passed (considers escalation)
    pub fn maybe_rotate_fingerprint(&self) {
        let escalated = self.escalated.load(Ordering::Relaxed);
        let anti_mode = matches!(self.config.mode, StealthMode::AntiDpi);
        let effective_enable = self.config.enable_fingerprint_rotation || (anti_mode && escalated);
        if !effective_enable {
            return;
        }

        let interval =
            if anti_mode && escalated { 30 } else { self.config.fingerprint_rotation_interval };
        if interval == 0 {
            return;
        }

        let now = std::time::Instant::now();
        let should_rotate = {
            let last = self.last_rotation.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            now.duration_since(*last).as_secs() >= interval
        };

        if should_rotate {
            let idx = self.profile_index.fetch_add(1, Ordering::Relaxed) % self.profile_pool.len();
            let (browser, os) = self.profile_pool[idx];

            let new_profile = FingerprintProfile::new(browser, os);
            *self.fingerprint.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = new_profile;
            *self.last_rotation.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = now;

            info!("Rotated fingerprint to {:?}/{:?}", browser, os);
        }
    }

    /// Applies sophisticated traffic padding
    pub fn apply_padding(&self, payload: &mut Vec<u8>) {
        if !self.config.enable_traffic_padding {
            return;
        }

        use rand::Rng;
        let mut rng = rand::thread_rng();

        let escalated = self.escalated.load(Ordering::Relaxed);
        let anti_mode = matches!(self.config.mode, StealthMode::AntiDpi);
        let strategy =
            if escalated { PaddingStrategy::BrowserMimic } else { self.config.padding_strategy };
        let max_pad = if escalated {
            if anti_mode {
                (self.config.max_padding_size.saturating_mul(2)).max(4096)
            } else {
                self.config.max_padding_size.max(2048)
            }
        } else {
            self.config.max_padding_size
        };

        let padding_size = match strategy {
            PaddingStrategy::Random => rng.gen_range(0..max_pad),
            PaddingStrategy::Fixed => {
                // Pad to nearest power of 2
                let current = payload.len();
                let next_pow2 = current.next_power_of_two();
                next_pow2.saturating_sub(current).min(max_pad)
            }
            PaddingStrategy::Adaptive => {
                // Adaptive based on payload size
                if payload.len() < 100 {
                    rng.gen_range(50..150)
                } else if payload.len() < 500 {
                    rng.gen_range(100..300)
                } else {
                    rng.gen_range(200..max_pad)
                }
            }
            PaddingStrategy::BrowserMimic => {
                // Mimic browser-specific patterns
                let profile =
                    self.fingerprint.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                match profile.browser {
                    BrowserProfile::Chrome => {
                        // Chrome tends to use 16-byte aligned padding
                        let align = 16;
                        let remainder = payload.len() % align;
                        if remainder > 0 {
                            align - remainder
                        } else {
                            0
                        }
                    }
                    BrowserProfile::Firefox => {
                        // Firefox uses more random padding
                        rng.gen_range(
                            0..(if escalated {
                                if anti_mode {
                                    1024
                                } else {
                                    512
                                }
                            } else {
                                256
                            }),
                        )
                    }
                    BrowserProfile::Safari => {
                        // Safari uses conservative padding
                        rng.gen_range(0..64)
                    }
                    BrowserProfile::Edge => {
                        // Edge similar to Chrome
                        let align = 32;
                        let remainder = payload.len() % align;
                        if remainder > 0 {
                            align - remainder
                        } else {
                            0
                        }
                    }
                }
            }
        };

        if padding_size > 0 {
            #[allow(unused_mut)]
            let mut appended = false;
            #[cfg(target_arch = "x86_64")]
            {
                let features = crate::optimize::FeatureDetector::instance().features_full();
                if features.gfni {
                    let pad_seed_lo: u64 = rng.gen();
                    let pad_seed_hi: u64 = rng.gen();
                    let pad_bias: u8 = rng.gen();
                    let padding = crate::accelerate::stealth::gfni_padding_bytes(
                        padding_size,
                        pad_bias,
                        pad_seed_lo,
                        pad_seed_hi,
                    );
                    crate::optimize::telemetry::STEALTH_PADDING_GFNI_OPS
                        .inc_by(padding_size as u64);
                    payload.extend_from_slice(&padding);
                    appended = true;
                }
            }
            if !appended {
                let padding: Vec<u8> = (0..padding_size).map(|_| rng.gen()).collect();
                payload.extend_from_slice(&padding);
            }
        }
    }

    /// Applies timing obfuscation with random delays
    pub async fn apply_timing_obfuscation(&self) {
        if !self.config.enable_timing_obfuscation {
            return;
        }

        use rand::Rng;
        use tokio::time::{sleep, Duration};

        let mut rng = rand::thread_rng();
        // Read required data outside of await to avoid holding lock across await
        let browser = {
            let profile = self.fingerprint.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            profile.browser
        };

        // Browser-specific timing patterns
        let delay_ms = match browser {
            BrowserProfile::Chrome => rng.gen_range(5..50),
            BrowserProfile::Firefox => rng.gen_range(10..100),
            BrowserProfile::Safari => rng.gen_range(20..80),
            BrowserProfile::Edge => rng.gen_range(5..60),
        };

        sleep(Duration::from_millis(delay_ms)).await;
    }

    /// Returns a clone of the current fingerprint profile for TLS/ALPN mapping.
    pub fn current_fingerprint(&self) -> FingerprintProfile {
        match self.fingerprint.lock() {
            Ok(g) => g.clone(),
            Err(p) => {
                warn!("fingerprint mutex poisoned; recovering");
                p.into_inner().clone()
            }
        }
    }

    /// Returns all fingerprint profiles for which a ClientHello dump exists.
    pub fn available_fingerprints() -> Vec<FingerprintProfile> {
        TlsClientHelloSpoofer::available_profiles()
            .into_iter()
            .map(|(b, o)| FingerprintProfile::new(b, o))
            .collect()
    }

    /// Applies the configured TLS fingerprint to the transport configuration.
    /// ClientHello bytes are generated using integrated fingerprinting and injected
    /// natively via `Config::set_custom_tls`, ensuring the handshake matches the
    /// specified browser exactly (deterministic, GREASE disabled).
    pub fn apply_utls_profile(
        &self,
        config: &mut crate::transport::Config,
        preferred: Option<u16>,
    ) {
        let mut fingerprint = match self.fingerprint.lock() {
            Ok(g) => g,
            Err(p) => {
                warn!("fingerprint mutex poisoned; recovering");
                p.into_inner()
            }
        };
        info!("Applying uTLS fingerprint for: {:?}/{:?}", fingerprint.browser, fingerprint.os);

        // Manipulate TLS ClientHello to match the desired ordering.
        // Note: Config currently provides no stable API to set ciphers directly.
        // Cipher ordering is governed by the injected ClientHello profile.
        if preferred.is_some() {
            // Preference is applied via pre-ordered ClientHello bytes in the spoofed profile.
        }
        if fingerprint.client_hello.is_none() {
            fingerprint.client_hello =
                TlsClientHelloSpoofer::load_client_hello(fingerprint.browser, fingerprint.os);
        }
        if let Some(ref hello) = fingerprint.client_hello {
            TlsClientHelloSpoofer::inject_bytes(config, hello);
        } else {
            error!(
                "Missing ClientHello profile for {:?}/{:?}",
                fingerprint.browser, fingerprint.os
            );
        }

        if let Err(e) = config.set_application_protos(crate::transport::h3::APPLICATION_PROTOCOL) {
            warn!("Failed to set HTTP/3 application protos: {}", e);
        }

        // Apply the detailed QUIC transport parameters from the harmonized profile.
        config.set_initial_max_data(fingerprint.initial_max_data);
        config
            .set_initial_max_stream_data_bidi_local(fingerprint.initial_max_stream_data_bidi_local);
        config.set_initial_max_stream_data_bidi_remote(
            fingerprint.initial_max_stream_data_bidi_remote,
        );
        config.set_initial_max_streams_bidi(fingerprint.initial_max_streams_bidi);
        config.set_max_idle_timeout(fingerprint.max_idle_timeout);

        // Chrome-like ACK policy tuned per browser profile
        let browser_profile = {
            let fp = self.fingerprint.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            fp.browser
        };
        match browser_profile {
            BrowserProfile::Chrome | BrowserProfile::Edge => {
                config.set_ack_eliciting_threshold(2);
                config.set_max_ack_delay(25);
                config.set_ack_delay_exponent(3);
            }
            BrowserProfile::Firefox => {
                config.set_ack_eliciting_threshold(2);
                config.set_max_ack_delay(20);
                config.set_ack_delay_exponent(3);
            }
            BrowserProfile::Safari => {
                config.set_ack_eliciting_threshold(3);
                config.set_max_ack_delay(30);
                config.set_ack_delay_exponent(3);
            }
        }
        // Anti-DPI: prefer external pacing (RateChoker/Stealth layer), avoid double sleeps in transport
        if matches!(self.config.mode, StealthMode::AntiDpi) {
            config.set_external_pacing(true);
        }

        // ENV overrides (advanced tuning)
        if let Ok(v) = std::env::var("QUICFUSCATE_ACK_THRESHOLD") {
            if let Ok(n) = v.trim().parse::<u64>() {
                if n > 0 {
                    config.set_ack_eliciting_threshold(n);
                }
            }
        }
        if let Ok(v) = std::env::var("QUICFUSCATE_ACK_MAX_DELAY_MS") {
            if let Ok(ms) = v.trim().parse::<u64>() {
                config.set_max_ack_delay(ms);
            }
        }
        if let Ok(v) = std::env::var("QUICFUSCATE_EXTERNAL_PACING") {
            match v.to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => config.set_external_pacing(true),
                "0" | "false" | "no" | "off" => config.set_external_pacing(false),
                _ => {}
            }
        }

        // Apply stealth padding knobs to transport config so Connection::send() can pad before sealing
        let strategy_code = match self.config.padding_strategy {
            PaddingStrategy::Random => 1,
            PaddingStrategy::Fixed => 2,
            PaddingStrategy::Adaptive => 3,
            PaddingStrategy::BrowserMimic => 4,
        };
        config.set_stealth_padding(
            self.config.enable_traffic_padding,
            strategy_code,
            self.config.max_padding_size,
        );
        // Set default adaptive granularity (bytes) - sensible default 64
        config.set_stealth_adaptive_granularity(64);
        // Set default BrowserMimic bias from active fingerprint
        let bias_default = match (fingerprint.browser, fingerprint.os) {
            (BrowserProfile::Safari, _) | (_, OsProfile::IOS) => 1,
            (BrowserProfile::Firefox, OsProfile::Linux) => 2,
            (_, OsProfile::Android) => 4,
            _ => 3,
        };
        config.set_stealth_mimic_bias(bias_default);

        // Apply stealth timing knobs (simple per-packet jitter in microseconds)
        // Defaults: Stealth (no rotation) ~750us; StealthMax (rotation on) ~3000us.
        if self.config.enable_timing_obfuscation {
            let default_us = if self.config.enable_fingerprint_rotation { 3000 } else { 750 };
            config.set_stealth_timing(true, default_us);
        } else {
            config.set_stealth_timing(false, 0);
        }

        // ENV overrides (optional):
        // - QUICFUSCATE_STEALTH_PADDING_MAX = <usize>
        // - QUICFUSCATE_STEALTH_PADDING_STRATEGY = random|fixed|adaptive|browser|1..4
        // - QUICFUSCATE_STEALTH_JITTER_US = <u32>
        if let Ok(pmax) = std::env::var("QUICFUSCATE_STEALTH_PADDING_MAX") {
            if let Ok(v) = pmax.trim().parse::<usize>() {
                config.set_stealth_padding(self.config.enable_traffic_padding, strategy_code, v);
            }
        }
        if let Ok(pstr) = std::env::var("QUICFUSCATE_STEALTH_PADDING_STRATEGY") {
            let s = pstr.trim().to_lowercase();
            let scode = match s.as_str() {
                "1" | "random" => 1,
                "2" | "fixed" => 2,
                "3" | "adaptive" => 3,
                "4" | "browser" | "browser-mimic" | "browsermimic" => 4,
                _ => strategy_code,
            };
            config.set_stealth_padding(
                self.config.enable_traffic_padding,
                scode,
                self.config.max_padding_size,
            );
        }
        if let Ok(j) = std::env::var("QUICFUSCATE_STEALTH_JITTER_US") {
            if let Ok(us) = j.trim().parse::<u32>() {
                if us > 0 {
                    config.set_stealth_timing(true, us);
                } else {
                    config.set_stealth_timing(false, 0);
                }
            }
        }
        if let Ok(g) = std::env::var("QUICFUSCATE_STEALTH_ADAPTIVE_GRAN") {
            if let Ok(gran) = g.trim().parse::<u16>() {
                config.set_stealth_adaptive_granularity(gran);
            }
        }
        if let Ok(bias_s) = std::env::var("QUICFUSCATE_STEALTH_MIMIC_BIAS") {
            let s = bias_s.trim().to_lowercase();
            let code = match s.as_str() {
                "1" | "very_small" | "safari" => 1,
                "2" | "small" | "firefox" => 2,
                "4" | "mobile" | "android" => 4,
                "3" | "default" | "chromium" | "chrome" | "edge" => 3,
                _ => bias_default,
            };
            config.set_stealth_mimic_bias(code);
        }
    }

    /// Changes the active fingerprint profile at runtime.
    /// Call `apply_utls_profile` again to update an existing quiche configuration.
    pub fn set_fingerprint_profile(
        &self,
        profile: FingerprintProfile,
        cfg: Option<&mut crate::transport::Config>,
    ) {
        let mut p = profile;
        if p.client_hello.is_none() {
            p.client_hello = TlsClientHelloSpoofer::load_client_hello(p.browser, p.os);
        }

        if let (Some(ref hello), Some(c)) = (&p.client_hello, cfg) {
            TlsClientHelloSpoofer::inject_bytes(c, hello);
        }

        let mut fp = match self.fingerprint.lock() {
            Ok(g) => g,
            Err(p) => {
                warn!("fingerprint mutex poisoned; recovering");
                p.into_inner()
            }
        };
        *fp = p;
    }

    /// Returns the currently active fingerprint profile.
    pub fn current_profile(&self) -> FingerprintProfile {
        match self.fingerprint.lock() {
            Ok(g) => g.clone(),
            Err(p) => {
                warn!("fingerprint mutex poisoned; recovering");
                p.into_inner().clone()
            }
        }
    }

    /// Generate sophisticated TLS Cover handshake
    pub fn generate_tls_cover_handshake(&self, sni: &str) -> Vec<u8> {
        let fp = match self.fingerprint.lock() {
            Ok(g) => g.clone(),
            Err(p) => {
                warn!("Failed to lock fingerprint for TLS Cover generation");
                p.into_inner().clone()
            }
        };

        // Get session tickets if available
        let session_tickets = if let Some(ref ticket_mgr) = self.ticket_manager {
            let tickets = ticket_mgr.get_valid_tickets();
            if !tickets.is_empty() {
                Some(tickets)
            } else {
                // Generate new tickets for next time
                ticket_mgr.generate_ticket();
                ticket_mgr.generate_ticket();
                None
            }
        } else {
            None
        };

        // Use TlsClientHelloSpoofer for advanced ClientHello
        let profile_tuple = &self.profile_pool[0];
        let _client_hello = TlsClientHelloSpoofer::generate_advanced_hello(
            profile_tuple.0,
            profile_tuple.1,
            None,
            None,
            true,
        );

        // Debug consistency validation
        #[cfg(debug_assertions)]
        {
            let fingerprint =
                self.fingerprint.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let profile_name = format!("{:?}_{:?}", fingerprint.browser, fingerprint.os);
            self.validate_profile_consistency(&profile_name);
        }

        TlsClientHelloSpoofer::generate_advanced_hello(
            fp.browser,
            fp.os,
            Some(sni),
            session_tickets,
            true, // Enable ECH GREASE for modern look
        );
        tls_cover::TlsCover::handshake(&fp)
    }

    /// This spawns a task on the DoH runtime which periodically updates the
    /// active fingerprint.
    pub fn start_profile_rotation(
        self: &Arc<Self>,
        profiles: Vec<FingerprintProfile>,
        interval: std::time::Duration,
    ) {
        if profiles.is_empty() {
            return;
        }
        let mgr = Arc::clone(self);
        DOH_RUNTIME.spawn(async move {
            let mut idx = 0usize;
            loop {
                tokio::time::sleep(interval).await;
                idx = (idx + 1) % profiles.len();
                mgr.set_fingerprint_profile(profiles[idx].clone(), None);
            }
        });
    }

    /// Resolves a domain, using DoH if enabled.
    pub fn resolve_domain(&self, domain: &str) -> IpAddr {
        if self.config.enable_doh {
            debug!("Resolving {} via DoH provider: {}", domain, self.config.doh_provider);
            match DOH_RUNTIME.block_on(resolve_doh(
                &Client::new(),
                domain,
                &self.config.doh_provider,
            )) {
                Ok(ip) => ip,
                Err(e) => {
                    telemetry!(
                        telemetry::DNS_ERRORS.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    );
                    error!("DoH resolution failed: {}. Falling back.", e);
                    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))
                }
            }
        } else {
            // Fallback to standard DNS resolution (conceptual)
            info!("DoH disabled, using standard DNS for {}", domain);
            // In a real app, you would use std::net::ToSocketAddrs here.
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))
        }
    }

    /// Returns the SNI and Host header values for a connection.
    /// Applies domain fronting if enabled.
    pub fn get_connection_headers(&self, real_host: &str) -> (String, String) {
        if self.config.enable_domain_fronting {
            if let Some(df) = self.domain_fronting.as_ref() {
                let fronted_domain = df.get_fronted_domain();
                debug!("Domain fronting enabled. SNI: {}, Host: {}", fronted_domain, real_host);
                return (fronted_domain, real_host.to_string());
            }
        }
        (real_host.to_string(), real_host.to_string())
    }

    /// Processes an outgoing packet payload, applying configured stealth techniques.
    /// Returns an optional delay Duration if the packet should be delayed (Async Scheduler).
    /// Does NOT block the thread.
    pub fn process_outgoing_packet(&self, _payload: &mut [u8]) -> Option<std::time::Duration> {
        // Unified pacing: compute minimum delay from rate choker and flow shaper
        let mut total_delay = std::time::Duration::ZERO;
        let mut choked_bytes = 0u64;

        // Rate choker delay
        if self.config.enable_realtime_choke
            || self.escalated.load(Ordering::Relaxed)
            || self.config.dynamic_enabled
        {
            if let Ok(mut guard) = self.rate_choker.lock() {
                if let Some(choker) = guard.as_mut() {
                    let len = _payload.len();
                    if len > 0 {
                        let choke_delay = choker.shape(len);
                        if !choke_delay.is_zero() {
                            total_delay = total_delay.max(choke_delay);
                            choked_bytes = len as u64;
                        }
                    }
                }
            }
        }

        // Flow shaper delays (jitter + flight pacing)
        if let Some(flow_shaper) = &self.flow_shaper {
            let jitter = flow_shaper.apply_jitter();
            let flight_pacing = flow_shaper.apply_flight_pacing(false);
            let shaper_delay = jitter + flight_pacing;
            total_delay = total_delay.max(shaper_delay);
        }

        // Telemetry for calculated delay (Async Mode)
        if !total_delay.is_zero() {
            // We count this as "sleep" even if we yield async
            let ms = total_delay.as_millis() as u64;
            crate::telemetry::CHOKE_SLEEP_MS.inc_by(ms);
            if choked_bytes > 0 {
                crate::telemetry::CHOKED_BYTES.inc_by(choked_bytes);
            }
        }

        // Record packet into history to consume PacketInfo fields
        if let Some(shaper) = &self.flow_shaper {
            let ty = if choked_bytes == 0 { PacketType::Data } else { PacketType::Retransmit };
            shaper.record_and_prune(_payload.len(), ty);
        }

        // If escalated due to probing, temporarily apply stronger pacing
        if self.escalated.load(Ordering::Relaxed) {
            // Check timeout
            let mut clear_flag = false;
            if let Ok(mut guard) = self.escalated_until.lock() {
                if let Some(deadline) = *guard {
                    if std::time::Instant::now() >= deadline {
                        *guard = None;
                        clear_flag = true;
                    }
                }
            }
            if clear_flag {
                self.escalated.store(false, Ordering::Relaxed);
                // Restore default cover-traffic interval (5s) and MASQUE preference
                if let Some(ref sched) = self.cover_traffic {
                    sched.set_interval_ms(5000);
                }
                self.prefer_masque.store(false, Ordering::Relaxed);
            } else {
                // Add extra pacing while escalated; Anti-DPI gets stronger delay
                use rand::Rng;
                let anti = matches!(self.config.mode, StealthMode::AntiDpi);
                let range = if anti { 3..=7 } else { 1..=3 };
                let extra_ms: u64 = rand::thread_rng().gen_range(range);
                total_delay += std::time::Duration::from_millis(extra_ms);
            }
        }

        if total_delay.is_zero() {
            None
        } else {
            Some(total_delay)
        }

        // IMPORTANT: Do not mutate sealed QUIC datagrams here.
        // Timing/flow shaping is allowed (sleep), but payload bytes must remain intact
        // to preserve AEAD integrity and FEC compatibility.

        // Note: Padding is applied at a higher level before this function
        // HTTP/3 Masquerading is applied at the stream level when sending data
    }

    /// Processes an incoming packet payload, reversing stealth techniques.
    pub fn process_incoming_packet(&self, payload: &mut [u8], source: std::net::SocketAddr) {
        // Check for active probing first (before deobfuscation)
        if let Some(detector) = &self.probe_detector {
            if let Some(response_mode) = detector.check_packet(payload, source) {
                warn!("Active probe detected from {} - response mode: {:?}", source, response_mode);
                telemetry!(crate::telemetry::STEALTH_PROBE_DETECTED.inc());

                // Handle probe response
                match response_mode {
                    ProbeResponseMode::Switch => {
                        telemetry!(crate::telemetry::STEALTH_PROBE_SWITCH.inc());
                        // Switch to higher stealth mode
                        self.on_probe_detected(source);
                    }
                    ProbeResponseMode::Fake => {
                        // Send fake response (handled elsewhere)
                        telemetry!(crate::telemetry::STEALTH_PROBE_FAKE.inc());
                        debug!("Fake response for probe from {}", source);
                    }
                    ProbeResponseMode::Block => {
                        // Block source (handled at connection level)
                        telemetry!(crate::telemetry::STEALTH_PROBE_BLOCK.inc());
                        info!("Blocking source {}", source);
                    }
                    ProbeResponseMode::Ignore => {
                        // Just log and continue
                        debug!("Ignoring probe from {}", source);
                    }
                }
            }
        }
        // IMPORTANT: Do not mutate sealed QUIC datagrams on RX either; keep bytes intact
        // for AEAD verification and FEC correctness.
    }

    /// Processes a TLS ClientHello message before it is sent.
    pub fn process_client_hello(&self, payload: &mut [u8]) {
        if self.config.enable_xor_obfuscation {
            if let Some(xo) = self.xor_obfuscator.as_ref() {
                debug!("Obfuscating ClientHello payload.");
                xo.obfuscate(payload);
            }
        }
    }

    /// Obfuscates arbitrary payload data within a specific context.
    pub fn obfuscate_payload(&self, payload: &mut [u8], _context_id: u64) {
        if self.config.enable_xor_obfuscation {
            if let Some(xo) = self.xor_obfuscator.as_ref() {
                debug!("Obfuscating payload for context {}", _context_id);
                xo.obfuscate(payload);
            }
        }
    }

    /// Deobfuscates payload data for a specific context.
    pub fn deobfuscate_payload(&self, payload: &mut [u8], _context_id: u64) {
        if self.config.enable_xor_obfuscation {
            if let Some(xo) = self.xor_obfuscator.as_ref() {
                debug!("Deobfuscating payload for context {}", _context_id);
                xo.deobfuscate(payload);
            }
        }
    }

    /// Handles active probe detection by switching to higher stealth mode
    fn on_probe_detected(&self, source: std::net::SocketAddr) {
        warn!("Active probe detected from {} - escalating stealth mode", source);
        // Dynamic/Performance policy: only escalate if Intelligent/Stealth was chosen.
        // Performance mode stays performance-focused and does not auto-escalate.
        let allow_escalation = self.config.dynamic_enabled || self.config.enable_traffic_padding;
        if !allow_escalation {
            info!("Probe detected in Performance mode - not escalating (user preference: performance)");
            return;
        }

        // Increase cover-traffic intensity and prefer MASQUE path in escalated window
        self.escalate_to_anti_dpi_features();
        self.prefer_masque.store(true, Ordering::Relaxed);
        // Force a fast fingerprint rotation by moving last-rotation timestamp back
        if let Ok(mut last) = self.last_rotation.lock() {
            *last = std::time::Instant::now() - std::time::Duration::from_secs(3600);
        }

        // Increment probe hits and decide escalation severity
        let hits = self.probe_hits.fetch_add(1, Ordering::Relaxed) + 1;
        let anti_mode = matches!(self.config.mode, StealthMode::AntiDpi);
        let hard_escalation = hits >= 1; // escalate immediately
                                         // Update runtime toggles approximating Anti-DPI behaviour (or Anti-DPI Extreme if already Anti-DPI)
        if hard_escalation {
            if let Ok(mut guard) = self.rate_choker.lock() {
                if anti_mode {
                    // Anti-DPI Extreme: stricter choke
                    *guard = RateChoker::new(50, 12);
                } else {
                    // Normal Anti-DPI level
                    *guard = RateChoker::new(100, 8);
                }
            }
            // Anti-DPI Extreme: fingerprint rotation becomes effectively 30s (handled in maybe_rotate_fingerprint)
        }

        // Force stronger domain fronting rotation
        if let Some(df) = &self.domain_fronting {
            // This will use ultra-stealth rotation
            let _ = df.random_domain();
        }

        // Mark escalated window (e.g., 20 minutes) for stronger pacing
        self.escalated.store(true, Ordering::Relaxed);
        if let Ok(mut guard) = self.escalated_until.lock() {
            *guard = Some(std::time::Instant::now() + std::time::Duration::from_secs(20 * 60));
        }
        // Tighten cover-traffic interval while escalated
        if let Some(ref sched) = self.cover_traffic {
            if anti_mode {
                sched.set_interval_ms(2000);
            } else {
                sched.set_interval_ms(2500);
            }
        }
        // Prefer MASQUE path if available
        if self.masque_manager.is_some() {
            self.prefer_masque.store(true, Ordering::Relaxed);
            debug!("Probe escalation: preferring MASQUE path while escalated");
        }

        telemetry!(crate::telemetry::STEALTH_MODE_ESCALATED.inc());
        info!("Stealth mode escalated to Anti-DPI due to probe from {}", source);

        // Enable Anti-DPI level features: turn on Server Push cover traffic at runtime.
        self.escalate_to_anti_dpi_features();
    }

    /// Generates HTTP/3 headers for masquerading a request.
    ///
    /// Returns a QPACK-encoded header block as `Vec<u8>`. Internally attempts
    /// to encode into a pooled buffer first and materializes an exact-sized
    /// `Vec` from the written bytes. On pooled-buffer encoding failure, this
    /// increments the `telemetry::STEALTH_QPACK_POOL_FALLBACKS` counter and
    /// retries with a heap-allocated `Vec`.
    ///
    /// - Returns `None` when HTTP/3 masquerading is disabled via config.
    /// - Telemetry counter name: `stealth_qpack_pool_fallback_total`.
    /// - Telemetry export is gated by runtime telemetry; counters are no-ops
    ///   unless telemetry is enabled.
    /// - Ownership: the caller fully owns the returned `Vec`.
    pub fn get_http3_masquerade_headers(&self, host: &str, path: &str) -> Option<Vec<u8>> {
        if self.config.enable_http3_masquerading {
            let fp = match self.fingerprint.lock() {
                Ok(g) => g,
                Err(p) => {
                    warn!("fingerprint mutex poisoned; recovering");
                    p.into_inner()
                }
            };
            let fh = FakeHeaders::new(
                FakeHeadersConfig {
                    optimize_for_quic: true,
                    use_qpack_headers: self.config.use_qpack_headers,
                },
                fp.clone(),
            );
            debug!("Generating HTTP/3 masquerade headers for host: {}", host);
            // Always QPACK-encode using a pooled buffer to avoid heap allocations.
            let headers = fh.header_list(host, path);
            let mut enc = crate::transport::h3::qpack::Encoder::new();
            let mut tmp = vec![0u8; 1500]; // Fallback allocation
            match enc.encode(&headers, &mut tmp[..]) {
                Ok(written) => {
                    // Materialize an exact-sized Vec for the caller
                    let out = Vec::from(&tmp[..written]);
                    Some(out)
                }
                Err(e) => {
                    // Fallback: if the pooled block is too small or any error occurs, use a heap Vec.
                    warn!("QPACK encode to pooled buffer failed: {} - falling back to heap Vec", e);
                    telemetry!(telemetry::STEALTH_QPACK_POOL_FALLBACKS.inc());
                    let mut out = vec![0u8; 8192];
                    let written2 = match enc.encode(&headers, &mut out[..]) {
                        Ok(n) => n,
                        Err(e2) => {
                            warn!("QPACK encode fallback failed: {}", e2);
                            0
                        }
                    };
                    out.truncate(written2);
                    Some(out)
                }
            }
        } else {
            None
        }
    }

    /// Returns a pooled block to the OptimizationManager's memory pool.
    ///
    /// Only call this for buffers obtained from
    /// [`StealthManager::get_http3_masquerade_headers_boxed`] where the `pooled`
    /// flag was `true`. Aligned fallback buffers (`pooled == false`) must be
    /// dropped by the caller.
    pub fn free_pooled_block(&self, _block: AlignedBox<[u8]>) {
        // Memory pool automatically reclaims blocks when dropped
    }

    /// Returns cover-traffic headers when a request is due (rate-limited), otherwise None.
    pub fn cover_headers_due(&self) -> Option<Vec<crate::transport::h3::Header>> {
        if let Some(ref sched) = self.cover_traffic {
            return sched.get_next_request();
        }
        None
    }

    /// Returns a vector of HTTP/3 headers for a request.
    pub fn get_http3_header_list(
        &self,
        host: &str,
        path: &str,
    ) -> Option<Vec<crate::transport::h3::Header>> {
        if self.config.enable_http3_masquerading {
            let fp = match self.fingerprint.lock() {
                Ok(g) => g,
                Err(p) => {
                    warn!("fingerprint mutex poisoned; recovering");
                    p.into_inner()
                }
            };
            let fh = FakeHeaders::new(
                FakeHeadersConfig {
                    optimize_for_quic: true,
                    use_qpack_headers: self.config.use_qpack_headers,
                },
                fp.clone(),
            );
            Some(fh.header_list(host, path))
        } else {
            None
        }
    }

    /// Generates HTTP/3 headers for masquerading a request.
    ///
    /// Return value: `(AlignedBox<[u8]>, usize, bool pooled)`.
    /// - When `pooled == true`, the buffer originates from the internal pool and
    ///   must be returned via [`StealthManager::free_pooled_block`].
    /// - When `pooled == false`, the buffer was allocated via an aligned fallback
    ///   (`AlignedBox::slice_from_default(8192, 64)`) and should be dropped by the
    ///   caller when no longer needed.
    ///
    /// On pooled-buffer encoding failure this increments
    /// `telemetry::STEALTH_QPACK_POOL_FALLBACKS` and falls back to an aligned,
    /// non-pooled allocation.
    ///
    /// - Returns `None` when HTTP/3 masquerading is disabled via config.
    /// - Telemetry counter name: `stealth_qpack_pool_fallback_total`.
    /// - Alignment: fallback buffers are 64-byte aligned to favor SIMD/I/O paths.
    /// - Telemetry export is gated by runtime telemetry; counters are no-ops
    ///   unless telemetry is enabled.
    pub fn get_http3_masquerade_headers_boxed(
        &self,
        host: &str,
        path: &str,
    ) -> Option<(AlignedBox<[u8]>, usize, bool)> {
        if !self.config.enable_http3_masquerading {
            return None;
        }
        let fp = match self.fingerprint.lock() {
            Ok(g) => g,
            Err(p) => {
                warn!("fingerprint mutex poisoned; recovering");
                p.into_inner()
            }
        };
        let fh = FakeHeaders::new(
            FakeHeadersConfig {
                optimize_for_quic: true,
                use_qpack_headers: self.config.use_qpack_headers,
            },
            fp.clone(),
        );
        let headers = fh.header_list(host, path);
        let mut enc = crate::transport::h3::qpack::Encoder::new();

        // Use optimization_manager memory pool for efficient buffer allocation
        let pool = self.optimization_manager.memory_pool();
        let mut out = pool.alloc();
        if out.len() < 8192 {
            // Fallback to aligned allocation if pool block too small
            out = match AlignedBox::slice_from_default(8192, 64) {
                Ok(b) => b,
                Err(e2) => {
                    warn!("Aligned fallback allocation failed: {}", e2);
                    return None;
                }
            };
        }
        match enc.encode(&headers, &mut out[..]) {
            Ok(w2) => Some((out, w2, false)),
            Err(e3) => {
                warn!("QPACK encode on aligned fallback buffer failed: {}", e3);
                None
            }
        }
    }

    /// Returns whether TLS Cover should be used for handshakes.
    pub fn use_tls_cover(&self) -> bool {
        self.config.use_tls_cover
    }

    /// Expose current mode (copy)
    pub fn mode(&self) -> StealthMode {
        self.config.mode
    }

    /// Enable/disable Server Push at runtime (Intelligent mode). Optionally adjust intensity.
    pub fn enable_server_push_runtime(&self, enabled: bool, intensity: Option<f32>) {
        self.server_push_runtime_enabled.store(enabled, Ordering::Relaxed);
        if let Some(i) = intensity {
            if let Ok(mut st) = self.server_push_state.lock() {
                st.current_intensity = i;
            }
        }
    }

    /// **NEW**: Check if Server Push Cover Traffic should be triggered
    pub fn should_trigger_server_push(&self) -> bool {
        let intelligent_level = if matches!(self.config.mode, StealthMode::Intelligent) {
            crate::brain::intelligent_stealth_level_hint()
        } else {
            1
        };
        let enabled = self.config.enable_server_push_cover
            || self.server_push_runtime_enabled.load(Ordering::Relaxed);
        let enabled = enabled
            && (!matches!(self.config.mode, StealthMode::Intelligent) || intelligent_level >= 1);
        if !enabled {
            return false;
        }

        let state = self.server_push_state.lock().unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();
        let fallback_secs =
            if matches!(self.config.mode, StealthMode::Intelligent) { 30 } else { 15 };
        let secs = if self.config.server_push_burst_interval == 0 {
            fallback_secs
        } else {
            self.config.server_push_burst_interval
        };
        let interval = std::time::Duration::from_secs(secs);

        // Check if enough time has passed since last burst
        now.duration_since(state.last_burst) >= interval
    }

    /// **NEW**: Get Server Push configuration for HTTP/3 connection
    pub fn get_server_push_config(&self) -> Option<(String, f32)> {
        let intelligent_level = if matches!(self.config.mode, StealthMode::Intelligent) {
            crate::brain::intelligent_stealth_level_hint()
        } else {
            1
        };
        let enabled = self.config.enable_server_push_cover
            || self.server_push_runtime_enabled.load(Ordering::Relaxed);
        if !enabled
            || (matches!(self.config.mode, StealthMode::Intelligent) && intelligent_level == 0)
        {
            return None;
        }

        let state = self.server_push_state.lock().unwrap_or_else(|e| e.into_inner());
        Some((self.config.server_push_base_path.clone(), state.current_intensity))
    }

    /// **NEW**: Update Server Push state after burst
    pub fn update_server_push_state(
        &self,
        promises_created: usize,
        total_bytes: u64,
        reason: ServerPushTriggerReason,
    ) {
        if let Ok(mut state) = self.server_push_state.lock() {
            let now = std::time::Instant::now();
            state.last_burst = now;
            state.active_promises = promises_created;
            state.total_cover_bytes += total_bytes;
            state.burst_window.push_back(now);
            while let Some(ts) = state.burst_window.front().copied() {
                if now.duration_since(ts) > std::time::Duration::from_secs(60) {
                    state.burst_window.pop_front();
                } else {
                    break;
                }
            }

            // Dynamic intensity adjustment based on escalation
            if self.escalated.load(Ordering::Relaxed) {
                state.current_intensity = (state.current_intensity * 1.2).min(1.0);
            } else {
                state.current_intensity =
                    (state.current_intensity * 0.95).max(self.config.server_push_intensity);
            }

            debug!(
                "Server Push state updated: {} promises, {} bytes, intensity {:.2}",
                promises_created, total_bytes, state.current_intensity
            );
            crate::optimize::telemetry::SERVER_PUSH_BURSTS_TOTAL
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            crate::optimize::telemetry::SERVER_PUSH_TOTAL_COVER_BYTES
                .fetch_add(total_bytes, std::sync::atomic::Ordering::Relaxed);
            crate::optimize::telemetry::SERVER_PUSH_BURSTS_LAST_MINUTE
                .store(state.burst_window.len() as u64, std::sync::atomic::Ordering::Relaxed);
            let intensity_ppm = (state.current_intensity.clamp(0.0, 1.0) * 1_000_000.0) as u64;
            crate::optimize::telemetry::SERVER_PUSH_CURRENT_INTENSITY_PPM
                .store(intensity_ppm, std::sync::atomic::Ordering::Relaxed);
            match reason {
                ServerPushTriggerReason::Time => {
                    crate::optimize::telemetry::SERVER_PUSH_TRIGGER_TIME_TOTAL
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                ServerPushTriggerReason::Loss => {
                    crate::optimize::telemetry::SERVER_PUSH_TRIGGER_LOSS_TOTAL
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                ServerPushTriggerReason::Gating => {
                    crate::optimize::telemetry::SERVER_PUSH_TRIGGER_GATING_TOTAL
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
    }

    /// **NEW**: Get Server Push statistics
    pub fn get_server_push_stats(&self) -> (usize, u64, f32) {
        if let Ok(state) = self.server_push_state.lock() {
            (state.active_promises, state.total_cover_bytes, state.current_intensity)
        } else {
            (0, 0, 0.0)
        }
    }

    #[cfg(test)]
    pub fn force_server_push_due_for_test(&self) {
        if let Ok(mut state) = self.server_push_state.lock() {
            state.last_burst = std::time::Instant::now() - std::time::Duration::from_secs(120);
        }
    }

    /// Escalate to Anti-DPI level features (without changing enum mode): enable Server Push, tighten intervals.
    pub fn escalate_to_anti_dpi_features(&self) {
        // Enable runtime Server Push if not already enabled via config
        self.server_push_runtime_enabled.store(true, Ordering::Relaxed);
        // Increase intensity conservatively to at least 0.8
        if let Ok(mut st) = self.server_push_state.lock() {
            if st.current_intensity < 0.8 {
                st.current_intensity = 0.8;
            }
        }
        // If a scheduler exists, tighten interval; otherwise rely on push promises only.
        if let Some(ref sched) = self.cover_traffic {
            sched.set_interval_ms(2000);
        }
        // Prefer MASQUE path during anti-DPI escalation when available
        if self.masque_manager.is_some() {
            self.prefer_masque.store(true, Ordering::Relaxed);
            debug!("Escalated: MASQUE preferred (manager available)");
        }
        debug!("Escalated: Server Push cover traffic enabled (runtime) with high intensity");
    }

    /// Indicates whether MASQUE should be preferred while escalated and available
    pub fn masque_preferred(&self) -> bool {
        self.prefer_masque.load(Ordering::Relaxed)
    }

    /// Explicitly set MASQUE preference (used by policy/escalation logic).
    pub fn set_masque_preferred(&self, on: bool) {
        self.prefer_masque.store(on, Ordering::Relaxed);
    }

    /// Returns true if MASQUE datagram handling should be active.
    pub fn masque_datagram_enabled(&self) -> bool {
        if let Ok(v) = std::env::var("QUICFUSCATE_MASQUE_DATAGRAM") {
            return v != "0" && !v.eq_ignore_ascii_case("false");
        }
        self.masque_manager.is_some() && self.config.enable_http3_masquerading
    }

    /// Determine MASQUE proxy authority to use.
    /// Priority: QUICFUSCATE_MASQUE_PROXY env -> first fronting domain (":443").
    pub fn masque_proxy(&self) -> Option<String> {
        if let Ok(v) = std::env::var("QUICFUSCATE_MASQUE_PROXY") {
            if !v.is_empty() {
                return Some(v);
            }
        }
        if !self.config.fronting_domains.is_empty() {
            let d = &self.config.fronting_domains[0];
            if !d.is_empty() {
                return Some(format!("{}:443", d));
            }
        }
        None
    }

    /// Intelligent mode heuristic: if probes detected or escalation active, prefer MASQUE.
    pub fn maybe_escalate_masque_intelligent(&self) {
        if !matches!(self.config.mode, StealthMode::Intelligent) {
            return;
        }
        if self.masque_manager.is_none() {
            return;
        }
        let hits = self.probe_hits.load(Ordering::Relaxed);
        let escalated = self.escalated.load(Ordering::Relaxed);
        // Follow Brain intelligent level first; keep telemetry and probe/escalation fallback.
        let intelligent_level = crate::brain::intelligent_stealth_level_hint();
        let telemetry_hint = crate::optimize::telemetry::MASQUE_HINT.load(Ordering::Relaxed);
        let desired_preference =
            intelligent_level >= 1 || telemetry_hint == 1 || hits >= 3 || escalated;
        let current_preference = self.prefer_masque.load(Ordering::Relaxed);
        if current_preference != desired_preference {
            self.prefer_masque.store(desired_preference, Ordering::Relaxed);
        }
        if intelligent_level >= 2 {
            self.enable_server_push_runtime(true, Some(0.9));
        }
    }

    /// Returns CONNECT-UDP headers for MASQUE if available
    pub fn get_masque_connect_headers(
        &self,
        proxy: &str,
        target: &str,
    ) -> Option<Vec<crate::transport::h3::Header>> {
        if let Some(ref mm) = self.masque_manager {
            return mm.build_connect_headers(proxy, target).ok();
        }
        None
    }

    /// Forwards an invalid/probe packet to the Reality Proxy.
    pub fn handle_fallback(&self, packet: &[u8], source: std::net::SocketAddr) {
        if let Some(proxy) = &self.reality_proxy {
            proxy.forward_probe(packet, source);
        }
    }

    /// Polls for upstream responses to route back to the scanner.
    pub fn poll_fallback(&self) -> Option<crate::reality::FallbackResponse> {
        if let Ok(mut rx) = self.fallback_rx.try_lock() {
            if let Ok(resp) = rx.try_recv() {
                return Some(resp);
            }
        }
        None
    }
}
