#![cfg(feature = "rust-tests")]

use quicfuscate::compress;
use quicfuscate::stealth::{BrowserProfile, OsProfile, PaddingStrategy, StealthConfig};

struct PolicyGuard(compress::CompressionPolicy);

impl PolicyGuard {
    fn capture() -> Self {
        Self(compress::global_policy())
    }
}

impl Drop for PolicyGuard {
    fn drop(&mut self) {
        compress::set_global_policy(self.0.clone());
    }
}

#[test]
fn stealth_config_from_toml_overrides_fields_and_updates_policy() {
    let _guard = PolicyGuard::capture();
    let toml = r#"
[stealth]
initial_browser = "Firefox"
initial_os = "Linux"
use_tls_cover = true
enable_doh = false
doh_provider = "https://example.com/doh"
enable_http3_masquerading = false
use_qpack_headers = false
enable_domain_fronting = false
fronting_domains = ["front1.example", "front2.example"]
enable_xor_obfuscation = false
enable_traffic_padding = true
enable_timing_obfuscation = true
enable_protocol_mimicry = false
padding_strategy = "fixed"
max_padding_size = 512

[compression]
enabled = false
min_len = 512
level = 7
allow = ["text/plain"]
deny = ["image/*"]
"#;

    let cfg = StealthConfig::from_toml(toml).expect("parse stealth toml");
    assert_eq!(cfg.initial_browser, BrowserProfile::Firefox);
    assert_eq!(cfg.initial_os, OsProfile::Linux);
    assert!(cfg.use_tls_cover);
    assert!(!cfg.enable_doh);
    assert_eq!(cfg.doh_provider, "https://example.com/doh");
    assert!(!cfg.enable_http3_masquerading);
    assert!(!cfg.use_qpack_headers);
    assert!(!cfg.enable_domain_fronting);
    assert_eq!(
        cfg.fronting_domains,
        vec!["front1.example".to_string(), "front2.example".to_string()]
    );
    assert!(!cfg.enable_xor_obfuscation);
    assert!(cfg.enable_traffic_padding);
    assert!(cfg.enable_timing_obfuscation);
    assert!(!cfg.enable_protocol_mimicry);
    assert_eq!(cfg.padding_strategy, PaddingStrategy::Fixed);
    assert_eq!(cfg.max_padding_size, 512);

    let policy = compress::global_policy();
    assert!(!policy.enabled);
    assert_eq!(policy.min_len, 512);
    assert_eq!(policy.level, 7);
    assert_eq!(policy.allow, vec!["text/plain".to_string()]);
    assert_eq!(policy.deny, vec!["image/*".to_string()]);
}

#[test]
fn stealth_config_from_toml_ignores_unknown_keys() {
    let _guard = PolicyGuard::capture();
    let toml = r#"
[stealth]
initial_browser = "Chrome"
unknown_key = 123
"#;

    let cfg = StealthConfig::from_toml(toml).expect("parse with unknown keys");
    assert_eq!(cfg.initial_browser, BrowserProfile::Chrome);
}
