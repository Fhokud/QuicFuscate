#![cfg(feature = "rust-tests")]

use quicfuscate::qftls::{profile_from_fingerprint, TlsProfile};
use quicfuscate::stealth::{BrowserProfile, FingerprintProfile, OsProfile};

fn assert_no_chacha(cipher_suites: &[u16]) {
    let banned = [0x1303u16, 0xCCA8u16, 0xCCA9u16];
    for cs in banned {
        assert!(!cipher_suites.contains(&cs), "cipher suite {:#x} must be filtered out", cs);
    }
}

fn assert_sorted_by_policy(cipher_suites: &[u16]) {
    let key = |cs: u16| match cs {
        0x1301 | 0x1302 => 0,
        0xC02B | 0xC02F | 0xC02C | 0xC030 => 1,
        _ => 2,
    };
    for w in cipher_suites.windows(2) {
        assert!(
            key(w[0]) <= key(w[1]),
            "cipher suites not ordered by policy: {:#x} before {:#x}",
            w[0],
            w[1]
        );
    }
}

#[test]
fn chrome_family_profiles_are_h3_and_aes_only() {
    let profiles = [
        TlsProfile::chrome_130(),
        TlsProfile::edge_130(),
        TlsProfile::opera_115(),
        TlsProfile::brave_1_73(),
    ];

    for p in profiles {
        assert!(!p.alpn_protocols.is_empty(), "ALPN list must not be empty");
        assert_eq!(p.alpn_protocols[0], "h3");
        assert_no_chacha(&p.cipher_suites);
    }
}

#[test]
fn firefox_and_safari_profiles_keep_policy() {
    let firefox = TlsProfile::firefox_133();
    let safari = TlsProfile::safari_18();

    for p in [firefox, safari] {
        assert!(!p.alpn_protocols.is_empty(), "ALPN list must not be empty");
        assert_eq!(p.alpn_protocols[0], "h3");
        assert_no_chacha(&p.cipher_suites);
    }
}

#[test]
fn brave_profile_disables_ech_and_grease() {
    let p = TlsProfile::brave_1_73();
    assert!(!p.enable_ech, "Brave disables ECH per policy");
    assert!(p.grease_values.is_empty(), "Brave should not advertise GREASE");
}

#[test]
fn fingerprint_profile_enforces_cipher_policy() {
    let fp = FingerprintProfile::new(BrowserProfile::Chrome, OsProfile::Windows);
    let p = profile_from_fingerprint(&fp);
    assert_eq!(p.alpn_protocols[0], "h3");
    assert_no_chacha(&p.cipher_suites);
    assert_sorted_by_policy(&p.cipher_suites);
}
