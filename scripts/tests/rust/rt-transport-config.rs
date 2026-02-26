#![cfg(feature = "rust-tests")]

use quicfuscate::error::ConnectionError;
use quicfuscate::transport::{Config, CongestionControlAlgorithm, PROTOCOL_VERSION};

#[test]
fn config_accepts_known_version() {
    let cfg = Config::new_with_version(PROTOCOL_VERSION);
    assert!(cfg.is_ok());
}

#[test]
fn config_rejects_unknown_version() {
    let cfg = Config::new_with_version(PROTOCOL_VERSION + 1);
    assert!(matches!(cfg, Err(ConnectionError::UnknownVersion)));
}

#[test]
fn config_cc_algorithm_name_parsing() {
    let mut cfg = Config::new_with_version(PROTOCOL_VERSION).expect("config");
    cfg.set_cc_algorithm(CongestionControlAlgorithm::BBR2);
    cfg.set_cc_algorithm_name("reno").expect("reno");
    cfg.set_cc_algorithm_name("cubic").expect("cubic");
    cfg.set_cc_algorithm_name("bbr").expect("bbr");
    cfg.set_cc_algorithm_name("bbr2").expect("bbr2");
    cfg.set_cc_algorithm_name("bbr3").expect("bbr3");
    cfg.set_cc_algorithm_name("ledbat").expect("ledbat");
    let err = cfg.set_cc_algorithm_name("not-a-cc").expect_err("invalid name");
    assert!(matches!(err, ConnectionError::InvalidState));
}

#[test]
fn config_wire_format_and_stealth_setters_are_safe() {
    let mut cfg = Config::new_with_version(PROTOCOL_VERSION).expect("config");
    cfg.set_application_protos_wire_format(b"").expect("wire format");
    cfg.set_stealth_padding(true, 2, 128);
    cfg.set_stealth_timing(true, 250);
    cfg.set_ack_eliciting_threshold(3);
    cfg.set_external_pacing(true);
}
