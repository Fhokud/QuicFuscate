//! QuicFuscate - Performance-focused VPN with stealth transport features.
//!
//! This crate provides the core engine and protocol building blocks.
//!
//! # Features
//! - **SIMD Everything**: AVX512/NEON/SVE2 in all hot paths
//! - **Zero-Copy**: io_uring, huge pages, NUMA-aware memory
//! - **Crypto**: AEGIS-128L and MORUS with automatic hardware selection when available
//! - **FEC Mastery**: Bitsliced Wiedemann, parallel recovery
//! - **Stealth Perfection**: Timing-perfect obfuscation

// Unstable stdarch/core_intrinsics features removed for stable toolchain compatibility.
#![allow(clippy::too_many_arguments)] // Performance over style
#![allow(clippy::large_enum_variant)] // Performance over memory
#![recursion_limit = "1024"]

pub mod accelerate;
pub mod core;
pub mod crypto;
pub mod error {
    use std::fmt;

    #[derive(Debug, Clone, PartialEq)]
    pub enum ConnectionError {
        TransportError(String),
        CryptoError(String),
        CryptoFail,
        FlowControlError,
        StreamLimitError,
        ProtocolViolation,
        InvalidState,
        Timeout,
        BufferExhausted,
        InvalidFrame,
        Done,
        TlsError(String),
        TlsAlert(u64),
        BufferTooShort,
        TlsFail,
        PeerCertificateUnsupported,
        UnknownVersion,
        InvalidPacket,
        InvalidStreamState(u64),
        FinalSize,
        InternalError,
        Fec(String),
        Transport(String),
        TlsHandshake,
        StreamReset,
        StreamStopped,
        IdLimit,
        FlowControl,
        ApplicationError(u64),
        StreamLimit,
        StateError,
        ApplicationProtoError,
        VersionMismatch,
        FrameEncoding,
        InvalidToken,
        ApplicationClosed,
        CryptoBufferExceeded,
        KeyUpdateError,
        AeadLimitReached,
        NoViablePath,
        ConnectionRefused,
        InvalidStreamId,
    }

    #[allow(non_upper_case_globals)]
    impl ConnectionError {
        pub const Fec: Self = ConnectionError::Fec(String::new());
        pub const Transport: Self = ConnectionError::Transport(String::new());
    }

    impl fmt::Display for ConnectionError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                ConnectionError::InvalidPacket => write!(f, "Invalid packet"),
                ConnectionError::InvalidFrame => write!(f, "Invalid frame"),
                ConnectionError::InvalidStreamId => write!(f, "Invalid stream ID"),
                ConnectionError::InvalidStreamState(_) => write!(f, "Invalid stream state"),
                ConnectionError::FlowControl => write!(f, "Flow control violation"),
                ConnectionError::StreamLimit => write!(f, "Stream limit exceeded"),
                ConnectionError::FinalSize => write!(f, "Final size error"),
                ConnectionError::FrameEncoding => write!(f, "Frame encoding error"),
                ConnectionError::ProtocolViolation => write!(f, "Protocol violation"),
                ConnectionError::InvalidToken => write!(f, "Invalid token"),
                ConnectionError::ApplicationError(code) => write!(f, "Application error: {}", code),
                ConnectionError::CryptoBufferExceeded => write!(f, "Crypto buffer exceeded"),
                ConnectionError::KeyUpdateError => write!(f, "Key update error"),
                ConnectionError::AeadLimitReached => write!(f, "AEAD limit reached"),
                ConnectionError::NoViablePath => write!(f, "No viable path"),
                ConnectionError::InternalError => write!(f, "Internal error"),
                ConnectionError::ConnectionRefused => write!(f, "Connection refused"),
                ConnectionError::Timeout => write!(f, "Timeout"),
                ConnectionError::Transport(msg) => write!(f, "Transport error: {}", msg),
                ConnectionError::TlsFail => write!(f, "TLS failure"),
                ConnectionError::TlsAlert(code) => write!(f, "TLS alert: {}", code),
                ConnectionError::PeerCertificateUnsupported => {
                    write!(f, "Peer certificate unsupported")
                }
                ConnectionError::Done => write!(f, "Connection done"),
                ConnectionError::BufferTooShort => write!(f, "Buffer too short"),
                ConnectionError::UnknownVersion => write!(f, "Unknown version"),
                ConnectionError::InvalidState => write!(f, "Invalid state"),
                ConnectionError::Fec(ref msg) => write!(f, "FEC error: {}", msg),
                ConnectionError::TlsHandshake => write!(f, "TLS handshake error"),
                ConnectionError::StreamReset => write!(f, "Stream reset"),
                ConnectionError::StreamStopped => write!(f, "Stream stopped"),
                ConnectionError::IdLimit => write!(f, "ID limit exceeded"),
                ConnectionError::ApplicationClosed => write!(f, "Application closed"),
                _ => write!(f, "Other error"),
            }
        }
    }

    impl std::error::Error for ConnectionError {}

    impl From<String> for ConnectionError {
        fn from(s: String) -> Self {
            ConnectionError::Transport(s)
        }
    }
    impl From<&str> for ConnectionError {
        fn from(s: &str) -> Self {
            ConnectionError::Transport(s.to_string())
        }
    }
    impl From<crate::transport::h3::Error> for ConnectionError {
        fn from(e: crate::transport::h3::Error) -> Self {
            ConnectionError::Transport(format!("H3 error: {:?}", e))
        }
    }
}
pub mod brain;
pub mod compress;
pub mod fec;
pub mod harness;
pub mod instrumentation;
pub mod interface;
pub mod metrics;
pub mod optimize;
pub mod profile;
pub mod qftls;
pub mod reality; // REALITY FALLBACK (REVERSE PROXY)
pub mod simd; // ULTRA-SOPHISTICATED CENTRALIZED SIMD!
pub mod stealth;
pub mod time_source;
pub mod transport;

// Unified Engine API
pub mod engine;

// Production Implementations
pub mod implementations;

// TLS Provider System (consolidated)
// Compatibility aliases for existing paths.
pub use qftls as tls_provider;
pub use qftls as tls_combined;
pub use qftls as RealTLS_rustls;

// integration module removed; system initialization helpers are available via core/interface when needed

// tests module was removed during consolidation
pub use crate::stealth::tls_cover;
// Telemetry module - consolidated from previous scattered modules
pub mod telemetry {
    pub use crate::optimize::telemetry::*;
}

// Telemetry metrics alias for compatibility
pub use telemetry as telemetry_metrics;

// Global functions moved to optimize::telemetry module
pub use crate::optimize::telemetry::{flush, update_memory_usage};

// Re-export main types
#[cfg(feature = "unsafe_rust")]
pub use crate::optimize::r#unsafe::{UnsafeMemoryPool, UnsafePacket};
pub use core::QuicFuscateConnection;
pub use error::ConnectionError;
// FEC types are re-exported from the fec module
pub use optimize::{OptimizationManager, OptimizeConfig};
pub use stealth::{StealthConfig, StealthManager};

// ConnectionError is already defined in error module, no need to redefine

// Re-export app_config from interface module
pub use crate::interface::app_config;

// Re-export EngineConfig for convenient access
pub use crate::engine::EngineConfig;

// Re-export QuicFuscateEngine for convenient access
pub use crate::engine::QuicFuscateEngine;
