//! QKey - Compact Connection Key Format
//!
//! A single string that contains all connection parameters.
//! Format: `QKey-<base64url_encoded_config>`
//!
//! The config includes an embedded checksum for accidental tamper detection.
//! Note: The checksum is not a cryptographic signature. Treat the QKey token as the capability.
//!
//! # Example
//! ```text
//! QKey-eyJyZW1vdGUiOiIxOTIuMTY4LjEuMTo0NDMzIiwic25pIjoiZXhhbXBsZS5jb20iLCJtZDUiOiJhM2YyYjhjOSJ9
//! ```

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URLSAFE, Engine as _};
use serde::{Deserialize, Serialize};

/// QKey prefix
pub const QKEY_PREFIX: &str = "QKey-";

// Hard limits to keep parsing safe for untrusted input (copy/paste, clipboard).
const MAX_QKEY_CHARS: usize = 16 * 1024;
const MAX_DECODED_JSON_BYTES: usize = 16 * 1024;

/// Stable QKey id for server-side registries.
///
/// This is *not* a secret. It is used as a compact identifier and should not be relied on for
/// authentication. Authentication must use a separate secret (for example a token verified
/// post-handshake).
pub fn id(qkey: &str) -> String {
    let trimmed = qkey.trim();
    // Canonicalize prefix case for stability. Users often paste keys with different casing,
    // but those should still map to the same stable id.
    let canonical = if trimmed
        .get(..QKEY_PREFIX.len())
        .map(|p| p.eq_ignore_ascii_case(QKEY_PREFIX))
        .unwrap_or(false)
    {
        // Keep the base64 payload byte-for-byte. Only normalize the prefix.
        // This keeps ids stable for server-issued keys ("QKey-...") while making pasted
        // variants ("qkey-...") equivalent.
        let rest = trimmed.get(QKEY_PREFIX.len()..).unwrap_or("");
        // Avoid allocating in the common case.
        if trimmed.starts_with(QKEY_PREFIX) {
            trimmed.to_string()
        } else {
            format!("{}{}", QKEY_PREFIX, rest)
        }
    } else {
        trimmed.to_string()
    };
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let hex = format!("{:x}", hasher.finalize());
    hex.chars().take(12).collect()
}

/// Compact connection parameters for QKey.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QKeyConfig {
    /// Remote server address (host:port)
    pub remote: String,
    /// SNI hostname for TLS
    pub sni: String,
    /// Stealth mode (optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stealth: Option<String>,
    /// FEC mode (optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fec: Option<String>,
    /// Custom parameters (optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<String>,
    /// QKey auth token (hex, optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Checksum string (legacy: 8 hex chars MD5 prefix, current: `s256:<8-hex>`).
    #[serde(rename = "m")]
    pub md5: String,
}

impl QKeyConfig {
    /// Create a new QKey config.
    pub fn new(remote: &str, sni: &str) -> Self {
        let mut cfg = Self {
            remote: remote.to_string(),
            sni: sni.to_string(),
            stealth: None,
            fec: None,
            extra: None,
            token: None,
            md5: String::new(),
        };
        cfg.update_checksum();
        cfg
    }

    /// Set stealth mode.
    pub fn with_stealth(mut self, mode: &str) -> Self {
        self.stealth = Some(mode.to_string());
        self.update_checksum();
        self
    }

    /// Set FEC mode.
    pub fn with_fec(mut self, mode: &str) -> Self {
        self.fec = Some(mode.to_string());
        self.update_checksum();
        self
    }

    /// Set extra parameters.
    pub fn with_extra(mut self, extra: &str) -> Self {
        self.extra = Some(extra.to_string());
        self.update_checksum();
        self
    }

    /// Set token (hex-encoded).
    pub fn with_token(mut self, token: &str) -> Self {
        self.token = Some(token.to_string());
        self.update_checksum();
        self
    }

    /// Compute the checksum data (everything except md5 field).
    fn checksum_data(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}",
            self.remote,
            self.sni,
            self.stealth.as_deref().unwrap_or(""),
            self.fec.as_deref().unwrap_or(""),
            self.extra.as_deref().unwrap_or(""),
            self.token.as_deref().unwrap_or(""),
        )
    }

    fn sha256_prefix8_hex(data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hex = format!("{:x}", hasher.finalize());
        hex.chars().take(8).collect()
    }

    fn is_hex8(s: &str) -> bool {
        s.len() == 8 && s.as_bytes().iter().all(|b| b.is_ascii_hexdigit())
    }

    /// Update the checksum.
    fn update_checksum(&mut self) {
        let data = self.checksum_data();
        // Default to SHA-256 prefix for new keys. Old keys remain valid via validate().
        let prefix = Self::sha256_prefix8_hex(data.as_bytes());
        self.md5 = format!("s256:{}", prefix);
    }

    /// Validate the checksum.
    pub fn validate(&self) -> bool {
        let chk = self.md5.trim();
        let Some(rest) = chk.strip_prefix("s256:") else {
            return false;
        };
        if !Self::is_hex8(rest) {
            return false;
        }
        let data = self.checksum_data();
        let expected = Self::sha256_prefix8_hex(data.as_bytes());
        rest.eq_ignore_ascii_case(&expected)
    }
}

/// Generate a QKey string from config.
pub fn generate(config: &QKeyConfig) -> String {
    let json = serde_json::to_string(config).unwrap_or_default();
    // Prefer URL-safe base64 without padding for copy/paste stability.
    let encoded = BASE64_URLSAFE.encode(json.as_bytes());
    format!("{}{}", QKEY_PREFIX, encoded)
}

/// Parse a QKey string back to config.
pub fn parse(qkey: &str) -> Result<QKeyConfig, QKeyError> {
    let qkey = qkey.trim();
    if qkey.is_empty() {
        return Err(QKeyError::InvalidPrefix);
    }
    if qkey.len() > MAX_QKEY_CHARS {
        return Err(QKeyError::TooLarge);
    }
    // Check prefix
    if qkey.len() < QKEY_PREFIX.len() {
        return Err(QKeyError::InvalidPrefix);
    }
    let (prefix, rest) = qkey.split_at(QKEY_PREFIX.len());
    if !prefix.eq_ignore_ascii_case(QKEY_PREFIX) {
        return Err(QKeyError::InvalidPrefix);
    }

    // Extract base64 part
    let encoded = rest;

    let decoded = BASE64_URLSAFE.decode(encoded).map_err(|_| QKeyError::InvalidBase64)?;

    if decoded.len() > MAX_DECODED_JSON_BYTES {
        return Err(QKeyError::TooLarge);
    }

    // Parse JSON
    let config: QKeyConfig =
        serde_json::from_slice(&decoded).map_err(|_| QKeyError::InvalidJson)?;

    // Validate checksum
    if !config.validate() {
        return Err(QKeyError::InvalidChecksum);
    }

    Ok(config)
}

/// QKey error types.
#[derive(Debug, Clone, PartialEq)]
pub enum QKeyError {
    InvalidPrefix,
    InvalidBase64,
    InvalidJson,
    InvalidChecksum,
    TooLarge,
}

impl std::fmt::Display for QKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPrefix => write!(f, "QKey must start with '{}'", QKEY_PREFIX),
            Self::InvalidBase64 => write!(f, "Invalid base64 encoding"),
            Self::InvalidJson => write!(f, "Invalid JSON format"),
            Self::InvalidChecksum => write!(f, "Checksum validation failed"),
            Self::TooLarge => write!(f, "QKey payload is too large"),
        }
    }
}

impl std::error::Error for QKeyError {}

/// Convert from EngineConfig to QKeyConfig.
impl From<&crate::engine::EngineConfig> for QKeyConfig {
    fn from(cfg: &crate::engine::EngineConfig) -> Self {
        let stealth = match cfg.stealth.mode {
            crate::engine::StealthMode::Off => None,
            crate::engine::StealthMode::Performance => Some("performance".to_string()),
            crate::engine::StealthMode::Stealth => Some("stealth".to_string()),
            crate::engine::StealthMode::AntiDpi => Some("anti-dpi".to_string()),
            crate::engine::StealthMode::Manual => Some("manual".to_string()),
            crate::engine::StealthMode::Auto => Some("auto".to_string()),
        };

        let fec = match cfg.fec.mode {
            crate::engine::FecMode::Off => None,
            crate::engine::FecMode::Auto => Some("auto".to_string()),
        };

        let mut qkey = QKeyConfig::new(&cfg.connection.remote, &cfg.connection.sni);
        if let Some(s) = stealth {
            qkey = qkey.with_stealth(&s);
        }
        if let Some(f) = fec {
            qkey = qkey.with_fec(&f);
        }
        qkey
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qkey_generate_parse() {
        let config = QKeyConfig::new("192.168.1.1:4433", "example.com");

        let qkey = generate(&config);
        assert!(qkey.starts_with(QKEY_PREFIX));

        let parsed = parse(&qkey).unwrap();
        assert_eq!(parsed.remote, "192.168.1.1:4433");
        assert_eq!(parsed.sni, "example.com");
        assert!(parsed.validate());
    }

    #[test]
    fn test_qkey_with_options() {
        let config = QKeyConfig::new("vpn.example.com:443", "cdn.example.com")
            .with_stealth("full")
            .with_fec("auto");

        let qkey = generate(&config);
        let parsed = parse(&qkey).unwrap();

        assert_eq!(parsed.stealth, Some("full".to_string()));
        assert_eq!(parsed.fec, Some("auto".to_string()));
    }

    #[test]
    fn test_qkey_invalid_prefix() {
        let result = parse("Invalid-xyz123");
        assert_eq!(result.unwrap_err(), QKeyError::InvalidPrefix);
    }

    #[test]
    fn test_qkey_invalid_checksum() {
        // Create a valid key
        let config = QKeyConfig::new("test:4433", "test.com");
        // Tamper with it. Base64 encoding prevents simple string replacement, so create a bad checksum instead.

        // Create with wrong checksum manually
        let mut bad_config = config.clone();
        // Use a wrong checksum format to ensure validate() fails.
        bad_config.md5 = "s256:00000000".to_string();
        let json = serde_json::to_string(&bad_config).unwrap();
        let encoded = BASE64_URLSAFE.encode(json.as_bytes());
        let bad_qkey = format!("{}{}", QKEY_PREFIX, encoded);

        let result = parse(&bad_qkey);
        assert_eq!(result.unwrap_err(), QKeyError::InvalidChecksum);
    }

    #[test]
    fn test_qkey_prefix_is_case_insensitive_and_trimmed() {
        let config = QKeyConfig::new("192.168.1.1:4433", "example.com");
        let qkey = generate(&config);
        // Only change the prefix case. Lowercasing the full string would corrupt the base64 payload.
        let rest = &qkey[QKEY_PREFIX.len()..];
        let lower = format!("  {}{}  ", QKEY_PREFIX.to_lowercase(), rest);
        let parsed = parse(&lower).unwrap();
        assert_eq!(parsed.remote, "192.168.1.1:4433");
        assert_eq!(parsed.sni, "example.com");
    }

    #[test]
    fn test_qkey_id_is_stable_across_prefix_case_and_whitespace() {
        let config = QKeyConfig::new("192.168.1.1:4433", "example.com").with_token(&"a".repeat(64));
        let qkey = generate(&config);
        let rest = &qkey[QKEY_PREFIX.len()..];

        let canonical = format!("{}{}", QKEY_PREFIX, rest);
        let lower = format!("  {}{}  ", QKEY_PREFIX.to_lowercase(), rest);

        assert_eq!(id(&canonical), id(&lower));
    }

    #[test]
    fn test_qkey_compactness() {
        let config =
            QKeyConfig::new("vpn.example.com:4433", "cdn.example.com").with_stealth("full");

        let qkey = generate(&config);

        // Should be reasonably compact
        assert!(qkey.len() < 200);
        println!("QKey length: {} chars", qkey.len());
        println!("QKey: {}", qkey);
    }

    #[test]
    fn test_qkey_invalid_base64() {
        let bad = format!("{}{}", QKEY_PREFIX, "$$$not-base64$$$");
        let err = parse(&bad).unwrap_err();
        assert_eq!(err, QKeyError::InvalidBase64);
    }

    #[test]
    fn test_qkey_invalid_json() {
        // Valid base64, invalid JSON.
        let encoded = BASE64_URLSAFE.encode(b"not-json");
        let bad = format!("{}{}", QKEY_PREFIX, encoded);
        let err = parse(&bad).unwrap_err();
        assert_eq!(err, QKeyError::InvalidJson);
    }

    #[test]
    fn test_qkey_too_large_is_rejected() {
        // Exceed MAX_QKEY_CHARS to guarantee fast rejection before decoding.
        let oversized = format!("{}{}", QKEY_PREFIX, "A".repeat(MAX_QKEY_CHARS));
        assert_eq!(parse(&oversized).unwrap_err(), QKeyError::TooLarge);
    }
}
