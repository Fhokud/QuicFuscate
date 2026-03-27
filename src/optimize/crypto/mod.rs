//! Crypto acceleration exports for optimize.

pub mod planner;

pub use crate::optimize::simd::crypto::chacha20_blocks_x4;

pub use planner::CryptoAeadPlan;
