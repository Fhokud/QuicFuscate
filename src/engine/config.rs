//! QuicFuscate Engine Configuration
//!
//! This module provides comprehensive configuration structures for the QuicFuscate engine.
//! All settings can be loaded from a TOML configuration file.
//!
//! # Example
//!
//! ```ignore
//! use quicfuscate::engine::EngineConfig;
//!
//! let config = EngineConfig::from_file("config/quicfuscate.toml")?;
//! config.validate()?;
//! ```

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;

// Re-export existing configs for aggregation
pub use crate::fec::FecConfig;
pub use crate::optimize::OptimizeConfig;
pub use crate::stealth::StealthConfig;

/// Complete engine configuration aggregating all subsystems.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct EngineConfig {
    /// Engine mode and lifecycle settings
    pub engine: EngineSection,
    /// Connection parameters (remote, TLS, streams)
    pub connection: ConnectionConfig,
    /// Transport layer settings (CC, MTU, pacing)
    pub transport: TransportConfig,
    /// Cryptographic settings (AEAD, PQ)
    pub crypto: CryptoConfig,
    /// TUN/TAP interface settings
    pub interface: InterfaceConfig,
    /// Telemetry and metrics settings
    pub telemetry: TelemetryConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
    /// Forward Error Correction settings
    #[serde(rename = "fec")]
    pub fec: FecSection,
    /// Stealth and obfuscation settings
    pub stealth: StealthSection,
    /// Fingerprint rotation settings
    pub fingerprint_rotation: FingerprintRotationConfig,
    /// Performance optimization settings
    pub optimization: OptimizationConfig,
}

impl EngineConfig {
    /// Load configuration from a TOML file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let contents =
            std::fs::read_to_string(path.as_ref()).map_err(|e| ConfigError::Io(e.to_string()))?;
        Self::from_toml(&contents)
    }

    /// Parse configuration from a TOML string.
    pub fn from_toml(s: &str) -> Result<Self, ConfigError> {
        toml::from_str(s).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    /// Validate all configuration sections.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.engine.validate()?;
        self.connection.validate()?;
        self.transport.validate()?;
        self.crypto.validate()?;
        self.interface.validate()?;
        Ok(())
    }

    /// Create a builder for programmatic configuration.
    pub fn builder() -> EngineConfigBuilder {
        EngineConfigBuilder::default()
    }
}

/// Configuration errors.
#[derive(Debug, Clone)]
pub enum ConfigError {
    Io(String),
    Parse(String),
    Validation(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "IO error: {}", e),
            ConfigError::Parse(e) => write!(f, "Parse error: {}", e),
            ConfigError::Validation(e) => write!(f, "Validation error: {}", e),
        }
    }
}

impl std::error::Error for ConfigError {}

// ============================================================================
// ENGINE SECTION
// ============================================================================

/// Engine lifecycle and mode settings.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct EngineSection {
    /// Engine operation mode: "client" or "server"
    pub mode: EngineMode,
    /// Log level override (trace, debug, info, warn, error)
    pub log_level: String,
    /// Auto-start on engine creation
    pub auto_start: bool,
    /// Graceful shutdown timeout in milliseconds
    pub shutdown_timeout_ms: u64,
}

impl Default for EngineSection {
    fn default() -> Self {
        Self {
            mode: EngineMode::Client,
            log_level: "info".to_string(),
            auto_start: false,
            shutdown_timeout_ms: 5000,
        }
    }
}

impl EngineSection {
    fn validate(&self) -> Result<(), ConfigError> {
        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_levels.contains(&self.log_level.to_lowercase().as_str()) {
            return Err(ConfigError::Validation(format!(
                "Invalid log_level: {}. Must be one of: {:?}",
                self.log_level, valid_levels
            )));
        }
        Ok(())
    }
}

/// Engine operation mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EngineMode {
    #[default]
    Client,
    Server,
}

// ============================================================================
// CONNECTION SECTION
// ============================================================================

/// Connection parameters for QUIC connections.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct ConnectionConfig {
    /// Remote endpoint (server: listen addr, client: server addr)
    pub remote: String,
    /// Local bind address (optional)
    pub local: String,
    /// Verify peer certificate
    pub verify_peer: bool,
    /// Custom CA file path (empty = system CAs)
    pub ca_file: String,
    /// TLS certificate file (server mode)
    pub cert_file: String,
    /// TLS private key file (server mode)
    pub key_file: String,
    /// ALPN protocols
    pub alpn: Vec<String>,
    /// Server Name Indication (client mode)
    pub sni: String,
    /// QKey token (hex, client mode only)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qkey_token: Option<String>,
    /// QKey id (public identifier, client mode only)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qkey_id: Option<String>,
    /// Connection idle timeout in milliseconds
    pub idle_timeout_ms: u64,
    /// Enable 0-RTT early data
    pub enable_0rtt: bool,
    /// Maximum bidirectional streams
    pub max_streams_bidi: u64,
    /// Maximum unidirectional streams
    pub max_streams_uni: u64,
    /// Enable connection migration
    pub enable_migration: bool,
    /// Enable retry tokens (server mode)
    pub enable_retry: bool,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            remote: "0.0.0.0:4433".to_string(),
            local: String::new(),
            verify_peer: true,
            ca_file: String::new(),
            cert_file: String::new(),
            key_file: String::new(),
            alpn: vec!["h3".to_string(), "quicfuscate".to_string()],
            sni: String::new(),
            qkey_token: None,
            qkey_id: None,
            idle_timeout_ms: 30000,
            enable_0rtt: true,
            max_streams_bidi: 100,
            max_streams_uni: 100,
            enable_migration: true,
            enable_retry: true,
        }
    }
}

impl ConnectionConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.remote.is_empty() {
            return Err(ConfigError::Validation("remote address cannot be empty".into()));
        }
        if self.idle_timeout_ms == 0 {
            return Err(ConfigError::Validation("idle_timeout_ms must be > 0".into()));
        }
        if let Some(id) = self.qkey_id.as_deref() {
            let id = id.trim();
            if !id.is_empty() && (id.len() != 12 || !id.bytes().all(|b| b.is_ascii_hexdigit())) {
                return Err(ConfigError::Validation("qkey_id must be 12 hex chars".into()));
            }
        }
        Ok(())
    }
}

// ============================================================================
// TRANSPORT SECTION
// ============================================================================

/// Transport layer configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct TransportConfig {
    /// Congestion control algorithm
    pub cc_algorithm: CcAlgorithm,
    /// Maximum Transmission Unit
    pub mtu: u16,
    /// Maximum UDP payload size
    pub max_udp_payload: u16,
    /// Maximum idle timeout in milliseconds
    pub max_idle_timeout: u64,
    /// Initial RTT estimate in milliseconds
    pub initial_rtt_ms: u64,
    /// Enable spin bit
    pub enable_spin_bit: bool,
    /// Enable pacing
    pub enable_pacing: bool,
    /// Initial maximum data
    pub initial_max_data: u64,
    /// Initial maximum stream data (bidi local)
    pub initial_max_stream_data_bidi_local: u64,
    /// Initial maximum stream data (bidi remote)
    pub initial_max_stream_data_bidi_remote: u64,
    /// Initial maximum stream data (uni)
    pub initial_max_stream_data_uni: u64,
    /// Initial maximum streams (bidi)
    pub initial_max_streams_bidi: u64,
    /// Initial maximum streams (uni)
    pub initial_max_streams_uni: u64,
    /// Enable 0-RTT early data
    pub enable_early_data: bool,
    /// GSO batch size
    pub gso_batch_size: u16,
    /// GRO batch size
    pub gro_batch_size: u16,
    /// QUIC DATAGRAM receive queue length (0 = disabled)
    pub dgram_recv_queue_len: usize,
    /// QUIC DATAGRAM send queue length (0 = disabled)
    pub dgram_send_queue_len: usize,
    /// Disable path MTU discovery
    pub disable_pmtud: bool,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            cc_algorithm: CcAlgorithm::Cubic,
            mtu: 1400,
            max_udp_payload: 1350,
            max_idle_timeout: 30000,
            initial_rtt_ms: 100,
            enable_spin_bit: true,
            enable_pacing: true,
            initial_max_data: 10_000_000,
            initial_max_stream_data_bidi_local: 1_000_000,
            initial_max_stream_data_bidi_remote: 1_000_000,
            initial_max_stream_data_uni: 1_000_000,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
            enable_early_data: false,
            gso_batch_size: 16,
            gro_batch_size: 16,
            dgram_recv_queue_len: 1024,
            dgram_send_queue_len: 1024,
            disable_pmtud: false,
        }
    }
}

impl TransportConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.mtu < 1200 {
            return Err(ConfigError::Validation(format!(
                "MTU must be at least 1200, got {}",
                self.mtu
            )));
        }
        if self.initial_rtt_ms == 0 {
            return Err(ConfigError::Validation("initial_rtt_ms must be > 0".into()));
        }
        if self.dgram_recv_queue_len == 0 && self.dgram_send_queue_len == 0 {
            return Ok(());
        }
        if self.dgram_recv_queue_len == 0 || self.dgram_send_queue_len == 0 {
            return Err(ConfigError::Validation(
                "dgram_recv_queue_len and dgram_send_queue_len must both be 0 or both be > 0"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// Congestion control algorithm.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CcAlgorithm {
    Reno,
    #[default]
    Cubic,
    Bbr,
    Bbr2,
    #[serde(rename = "bbr2_gcongestion")]
    Bbr2Gcongestion,
}

// ============================================================================
// CRYPTO SECTION
// ============================================================================

/// Cryptographic configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct CryptoConfig {
    /// AEAD cipher preference
    pub aead_preference: AeadPreference,
    /// Enable post-quantum cryptography
    pub enable_pq: bool,
    /// Post-quantum signature algorithm
    pub pq_signature: PqSignature,
    /// Force specific AEAD (for testing)
    pub force_aead: String,
    /// Key update interval (packets, 0 = automatic)
    pub key_update_interval: u64,
    /// Header protection algorithm
    pub header_protection: HeaderProtection,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            aead_preference: AeadPreference::Auto,
            enable_pq: false,
            pq_signature: PqSignature::Dilithium3,
            force_aead: String::new(),
            key_update_interval: 0,
            header_protection: HeaderProtection::Aes,
        }
    }
}

impl CryptoConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        let force = self.force_aead.trim();
        if !force.is_empty() {
            let v = force.to_ascii_lowercase();
            let ok = matches!(
                v.as_str(),
                "auto"
                    | "aegis-128l"
                    | "aegis128l"
                    | "aegis"
                    | "aegis-128x4"
                    | "aegis128x4"
                    | "aegis-128x8"
                    | "aegis128x8"
                    | "morus"
                    | "morus-1280-128"
                    | "morus1280-128"
                    | "aes-gcm"
                    | "aesgcm"
                    | "aes-128-gcm"
                    | "aes128gcm"
            );
            if !ok {
                return Err(ConfigError::Validation(format!(
                    "crypto.force_aead has unsupported value: {force}"
                )));
            }
        }

        Ok(())
    }
}

/// AEAD cipher preference.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AeadPreference {
    #[default]
    Auto,
    #[serde(rename = "aegis-128l")]
    Aegis128L,
    #[serde(rename = "aegis-128x4")]
    Aegis128X4,
    #[serde(rename = "aegis-128x8")]
    Aegis128X8,
    Morus,
    #[serde(rename = "aes-gcm")]
    AesGcm,
}

/// Post-quantum signature algorithm.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PqSignature {
    #[default]
    Dilithium3,
    Falcon512,
}

/// Header protection algorithm.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HeaderProtection {
    #[default]
    Aes,
    Chacha20,
}

// ============================================================================
// INTERFACE SECTION
// ============================================================================

/// TUN/TAP interface configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct InterfaceConfig {
    /// Interface type
    #[serde(rename = "type")]
    pub interface_type: InterfaceType,
    /// TUN device name
    pub tun_name: String,
    /// TUN MTU
    pub tun_mtu: u16,
    /// Optional static TUN IP address
    pub tun_ip: Option<IpAddr>,
    /// Optional static TUN netmask
    pub tun_netmask: Option<IpAddr>,
    /// Enable zero-copy preference on TUN runtime path
    pub zero_copy: bool,
    /// Enable GSO
    pub enable_gso: bool,
    /// Enable GRO
    pub enable_gro: bool,
    /// XDP mode (Linux only)
    pub xdp_mode: XdpMode,
    /// XDP flags
    pub xdp_flags: Vec<String>,
}

impl Default for InterfaceConfig {
    fn default() -> Self {
        Self {
            interface_type: InterfaceType::Tun,
            tun_name: "quicfuse0".to_string(),
            tun_mtu: 1500,
            tun_ip: None,
            tun_netmask: None,
            zero_copy: true,
            enable_gso: true,
            enable_gro: true,
            xdp_mode: XdpMode::Skb,
            xdp_flags: vec!["update_if_noexist".to_string()],
        }
    }
}

impl InterfaceConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.tun_mtu < 576 {
            return Err(ConfigError::Validation(format!(
                "tun_mtu must be at least 576, got {}",
                self.tun_mtu
            )));
        }
        match (self.tun_ip, self.tun_netmask) {
            (Some(_), None) | (None, Some(_)) => {
                return Err(ConfigError::Validation(
                    "tun_ip and tun_netmask must be configured together".to_string(),
                ));
            }
            (Some(ip), Some(mask)) if ip.is_ipv4() != mask.is_ipv4() => {
                return Err(ConfigError::Validation(
                    "tun_ip and tun_netmask must use the same address family".to_string(),
                ));
            }
            _ => {}
        }
        Ok(())
    }
}

/// Interface type.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InterfaceType {
    #[default]
    Tun,
    Tap,
    Xdp,
    #[serde(rename = "raw_socket")]
    RawSocket,
}

/// XDP operation mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum XdpMode {
    #[default]
    Skb,
    Driver,
    Hardware,
}

// ============================================================================
// TELEMETRY SECTION
// ============================================================================

/// Telemetry and metrics configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct TelemetryConfig {
    /// Enable telemetry collection
    pub enabled: bool,
    /// Export interval in seconds
    pub export_interval: u64,
    /// Collect packet stats
    pub collect_packet_stats: bool,
    /// Collect stream stats
    pub collect_stream_stats: bool,
    /// Collect congestion stats
    pub collect_congestion_stats: bool,
    /// Collect FEC stats
    pub collect_fec_stats: bool,
    /// Collect stealth stats
    pub collect_stealth_stats: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            export_interval: 60,
            collect_packet_stats: true,
            collect_stream_stats: true,
            collect_congestion_stats: true,
            collect_fec_stats: true,
            collect_stealth_stats: true,
        }
    }
}

// ============================================================================
// LOGGING SECTION
// ============================================================================

/// Logging mode - controls the privacy/verbosity trade-off.
///
/// - `verbose`: Full debug logging, all metadata, disk + stdout.
/// - `normal`: Info-level, optional file output, standard operation.
/// - `minimal`: Warn-level only, no client metadata in log lines.
/// - `no-log`: **Strict privacy mode.** Enforces:
///   - In-memory ring buffer only (capped, overwritten on rotation).
///   - Zero disk writes for log data - `log_to_file` forced off.
///   - Stdout suppressed (`log_to_stdout` forced off).
///   - Systemd journal forwarding disabled (stderr closed).
///   - Client IPs, connection metadata, and session identifiers stripped.
///   - No timestamps in retained buffer entries (monotonic index only).
///   - Syslog facility explicitly not registered.
///   - On shutdown: ring buffer zeroed before deallocation.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LoggingMode {
    Verbose,
    #[default]
    Normal,
    Minimal,
    NoLog,
}

/// Logging configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// Logging mode (verbose | normal | minimal | no-log)
    pub mode: LoggingMode,
    /// Log level (overridden by mode in verbose/minimal/no-log)
    pub level: String,
    /// Log to file (forced off in no-log mode)
    pub log_to_file: bool,
    /// Log file path
    pub log_file_path: String,
    /// Log to stdout (forced off in no-log mode)
    pub log_to_stdout: bool,
    /// In-memory ring buffer capacity (entries). Used in no-log mode.
    pub ring_buffer_capacity: usize,
    /// Strip client metadata (IPs, session IDs) from log entries
    pub strip_metadata: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            mode: LoggingMode::Normal,
            level: "info".to_string(),
            log_to_file: false,
            log_file_path: "/var/log/quicfuscate.log".to_string(),
            log_to_stdout: true,
            ring_buffer_capacity: 512,
            strip_metadata: false,
        }
    }
}

impl LoggingConfig {
    /// Returns the effective configuration after applying mode overrides.
    pub fn effective(&self) -> Self {
        let mut cfg = self.clone();
        match cfg.mode {
            LoggingMode::Verbose => {
                cfg.level = "debug".to_string();
            }
            LoggingMode::Normal => {
                // user settings respected as-is
            }
            LoggingMode::Minimal => {
                cfg.level = "warn".to_string();
                cfg.strip_metadata = true;
            }
            LoggingMode::NoLog => {
                cfg.level = "error".to_string();
                cfg.log_to_file = false;
                cfg.log_to_stdout = false;
                cfg.strip_metadata = true;
            }
        }
        cfg
    }
}

// ============================================================================
// FEC SECTION
// ============================================================================

/// FEC configuration section (wraps detailed FEC settings).
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct FecSection {
    /// FEC mode: off, auto, manual
    pub mode: FecMode,
    /// Initial FEC mode for manual configuration
    pub initial_mode: String,
    /// Window sizes for quality levels
    pub window_excellent: usize,
    pub window_good: usize,
    pub window_fair: usize,
    pub window_poor: usize,
    /// Enable partial recovery
    pub enable_partial: bool,
    /// Enable PID controller
    pub enable_pid: bool,
    /// Enable hysteresis
    pub enable_hysteresis: bool,
    /// Enable Kalman filter
    pub enable_kalman: bool,
    /// Streaming emission period
    pub stream_every: usize,
}

impl Default for FecSection {
    fn default() -> Self {
        Self {
            mode: FecMode::Auto,
            initial_mode: "dynamic".to_string(),
            window_excellent: 0,
            window_good: 10,
            window_fair: 30,
            window_poor: 50,
            enable_partial: true,
            enable_pid: true,
            enable_hysteresis: true,
            enable_kalman: true,
            stream_every: 5,
        }
    }
}

/// FEC operation mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FecMode {
    Off,
    #[default]
    Auto,
    Manual,
}

// ============================================================================
// STEALTH SECTION
// ============================================================================

/// Stealth configuration section.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct StealthSection {
    /// Stealth mode
    pub mode: StealthMode,
    /// Enable domain fronting
    pub enable_domain_fronting: bool,
    /// Enable HTTP/3 masquerading
    pub enable_http3_masquerading: bool,
    /// Enable XOR obfuscation
    pub enable_xor_obfuscation: bool,
    /// Use TLS Cover
    pub use_tls_cover: bool,
    /// Use QPACK headers
    pub use_qpack_headers: bool,
    /// Enable traffic padding
    pub enable_traffic_padding: bool,
    /// Enable timing obfuscation
    pub enable_timing_obfuscation: bool,
    /// Enable protocol mimicry
    pub enable_protocol_mimicry: bool,
    /// Enable DNS-over-HTTPS
    pub enable_doh: bool,
    /// DoH provider URL
    pub doh_provider: String,
    /// Padding strategy
    pub padding_strategy: String,
    /// Maximum padding size
    pub max_padding_size: usize,
    /// Custom fronting domains
    pub fronting_domains: Vec<String>,
    /// Initial browser profile
    pub initial_browser: String,
    /// Initial OS profile
    pub initial_os: String,
}

impl Default for StealthSection {
    fn default() -> Self {
        Self {
            mode: StealthMode::Auto,
            enable_domain_fronting: true,
            enable_http3_masquerading: true,
            enable_xor_obfuscation: true,
            use_tls_cover: true,
            use_qpack_headers: true,
            enable_traffic_padding: false,
            enable_timing_obfuscation: false,
            enable_protocol_mimicry: true,
            enable_doh: true,
            doh_provider: "https://cloudflare-dns.com/dns-query".to_string(),
            padding_strategy: "adaptive".to_string(),
            max_padding_size: 256,
            fronting_domains: Vec::new(),
            initial_browser: "chrome".to_string(),
            initial_os: "windows".to_string(),
        }
    }
}

/// Stealth operation mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StealthMode {
    Off,
    #[default]
    Auto,
    Max,
    Manual,
}

// ============================================================================
// FINGERPRINT ROTATION SECTION
// ============================================================================

/// Fingerprint rotation configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct FingerprintRotationConfig {
    /// Enable rotation
    pub enabled: bool,
    /// Rotation interval in seconds
    pub interval_secs: u64,
    /// Rotation mode
    pub mode: RotationMode,
    /// Profile slots
    pub profile_slots: Vec<String>,
}

impl Default for FingerprintRotationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: 300,
            mode: RotationMode::Fixed,
            profile_slots: vec![
                "chrome:windows".to_string(),
                "firefox:windows".to_string(),
                "safari:macos".to_string(),
            ],
        }
    }
}

/// Rotation mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RotationMode {
    #[default]
    Fixed,
    Slots,
    All,
}

// ============================================================================
// OPTIMIZATION SECTION
// ============================================================================

/// Performance optimization configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct OptimizationConfig {
    /// CPU features detection mode
    pub cpu_features_mode: CpuFeaturesMode,
    /// Manual: enable AVX2
    pub enable_avx2: bool,
    /// Manual: enable AVX-512
    pub enable_avx512: bool,
    /// Manual: enable AES-NI
    pub enable_aesni: bool,
    /// Manual: enable VAES
    pub enable_vaes: bool,
    /// Manual: enable NEON (ARM)
    pub enable_neon: bool,
    /// Memory pool size (bytes)
    pub memory_pool_size: usize,
    /// Memory pool alignment
    pub memory_pool_alignment: usize,
    /// Number of worker threads (0 = auto)
    pub num_worker_threads: usize,
}

impl Default for OptimizationConfig {
    fn default() -> Self {
        Self {
            cpu_features_mode: CpuFeaturesMode::Auto,
            enable_avx2: true,
            enable_avx512: false,
            enable_aesni: true,
            enable_vaes: false,
            enable_neon: false,
            memory_pool_size: 67_108_864, // 64 MB
            memory_pool_alignment: 64,
            num_worker_threads: 0,
        }
    }
}

/// CPU features detection mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CpuFeaturesMode {
    #[default]
    Auto,
    Manual,
    Disabled,
}

// ============================================================================
// BUILDER
// ============================================================================

/// Builder for programmatic configuration.
#[derive(Default)]
pub struct EngineConfigBuilder {
    config: EngineConfig,
}

impl EngineConfigBuilder {
    /// Set engine mode.
    pub fn mode(mut self, mode: EngineMode) -> Self {
        self.config.engine.mode = mode;
        self
    }

    /// Set remote address.
    pub fn remote(mut self, addr: impl Into<String>) -> Self {
        self.config.connection.remote = addr.into();
        self
    }

    /// Set local bind address.
    pub fn local(mut self, addr: impl Into<String>) -> Self {
        self.config.connection.local = addr.into();
        self
    }

    /// Enable/disable peer verification.
    pub fn verify_peer(mut self, verify: bool) -> Self {
        self.config.connection.verify_peer = verify;
        self
    }

    /// Set stealth mode.
    pub fn stealth_mode(mut self, mode: StealthMode) -> Self {
        self.config.stealth.mode = mode;
        self
    }

    /// Set AEAD preference.
    pub fn aead_preference(mut self, pref: AeadPreference) -> Self {
        self.config.crypto.aead_preference = pref;
        self
    }

    /// Enable post-quantum cryptography.
    pub fn enable_pq(mut self, enable: bool) -> Self {
        self.config.crypto.enable_pq = enable;
        self
    }

    /// Set congestion control algorithm.
    pub fn cc_algorithm(mut self, cc: CcAlgorithm) -> Self {
        self.config.transport.cc_algorithm = cc;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> Result<EngineConfig, ConfigError> {
        self.config.validate()?;
        Ok(self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = EngineConfig::default();
        assert_eq!(config.engine.mode, EngineMode::Client);
        assert_eq!(config.transport.cc_algorithm, CcAlgorithm::Cubic);
        assert_eq!(config.crypto.aead_preference, AeadPreference::Auto);
    }

    #[test]
    fn test_builder() {
        let config = EngineConfig::builder()
            .mode(EngineMode::Server)
            .remote("0.0.0.0:4433")
            .stealth_mode(StealthMode::Max)
            .build()
            .unwrap();

        assert_eq!(config.engine.mode, EngineMode::Server);
        assert_eq!(config.stealth.mode, StealthMode::Max);
    }

    #[test]
    fn test_validation_fails_empty_remote() {
        let mut config = EngineConfig::default();
        config.connection.remote = String::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_parse_minimal_toml() {
        let toml = r#"
            [engine]
            mode = "client"
            
            [connection]
            remote = "127.0.0.1:4433"
        "#;

        let config = EngineConfig::from_toml(toml).unwrap();
        assert_eq!(config.engine.mode, EngineMode::Client);
        assert_eq!(config.connection.remote, "127.0.0.1:4433");
    }

    #[test]
    fn test_validation_fails_partial_tun_addressing() {
        let mut config = EngineConfig::default();
        config.interface.tun_ip = Some("10.8.0.1".parse().unwrap());
        config.interface.tun_netmask = None;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_fails_mixed_tun_address_family() {
        let mut config = EngineConfig::default();
        config.interface.tun_ip = Some("10.8.0.1".parse().unwrap());
        config.interface.tun_netmask = Some("ffff:ffff:ffff:ffff::".parse().unwrap());
        assert!(config.validate().is_err());
    }
}
