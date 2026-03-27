#![cfg(feature = "rust-tests")]

use quicfuscate::profile::Aegis128Profile;
use quicfuscate::simd::CryptoAeadPlan;

#[test]
fn aegis_profile_matches_crypto_plan_for_lengths() {
    let lengths = [0usize, 1, 15, 16, 127, 128, 1024, 4096];
    for len in lengths {
        let profile = Aegis128Profile::select_for_len(len);
        let plan = CryptoAeadPlan::select_for_len(len);
        let expected: Aegis128Profile = plan.into();
        assert_eq!(profile, expected, "len={}", len);
    }
}

#[test]
fn aegis_profile_roundtrip_into_crypto_plan() {
    #[cfg(target_arch = "aarch64")]
    let variants = vec![Aegis128Profile::L_NEON, Aegis128Profile::Morus1280];
    #[cfg(not(target_arch = "aarch64"))]
    let variants = vec![Aegis128Profile::L_AESNI, Aegis128Profile::Morus1280];

    for v in variants {
        let plan: CryptoAeadPlan = v.into();
        let roundtrip: Aegis128Profile = plan.into();
        assert_eq!(roundtrip, v, "variant {:?}", v);
    }
}
