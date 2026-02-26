//! Crypto acceleration exports for optimize.

pub mod aegis;
pub mod morus;
pub mod planner;

pub use crate::optimize::simd::crypto::chacha20_blocks_x4;
pub use aegis::{Aegis128L, Aegis128LAead, AegisError};
pub use morus::MorusAead;

pub use planner::{CipherSuite, CipherSuiteSelector, CryptoAeadPlan};
