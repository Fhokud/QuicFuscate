//! Legacy crypto profile alias that forwards to the SSOT in `simd::CryptoAeadPlan`.
//! This file exists for compatibility only and does not contain selection logic.

use crate::simd::CryptoAeadPlan;

/// Crypto profile selector based on CPU features.
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(non_camel_case_types)]
pub enum Aegis128Profile {
    /// Single-lane AEGIS-128L with AES-NI
    L_AESNI,
    /// Single-lane AEGIS-128L with ARM AES instructions.
    #[cfg(target_arch = "aarch64")]
    L_NEON,
    /// MORUS-1280 fallback
    Morus1280,
}

impl From<CryptoAeadPlan> for Aegis128Profile {
    fn from(p: CryptoAeadPlan) -> Self {
        match p {
            CryptoAeadPlan::LAesni => Self::L_AESNI,
            #[cfg(target_arch = "aarch64")]
            CryptoAeadPlan::LNeon => Self::L_NEON,
            CryptoAeadPlan::Morus => Self::Morus1280,
        }
    }
}

impl From<Aegis128Profile> for CryptoAeadPlan {
    fn from(p: Aegis128Profile) -> Self {
        match p {
            Aegis128Profile::L_AESNI => Self::LAesni,
            #[cfg(target_arch = "aarch64")]
            Aegis128Profile::L_NEON => Self::LNeon,
            Aegis128Profile::Morus1280 => Self::Morus,
        }
    }
}

impl Aegis128Profile {
    pub fn select() -> Self {
        CryptoAeadPlan::select().into()
    }

    pub fn select_for_len(len: usize) -> Self {
        CryptoAeadPlan::select_for_len(len).into()
    }
}
