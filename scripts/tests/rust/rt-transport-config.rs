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
    cfg.set_application_protos_wire_format(b"\x02h3\x08http/1.1").expect("wire format");
    cfg.set_stealth_padding(true, 2, 128);
    cfg.set_stealth_timing(true, 250);
    cfg.set_ack_eliciting_threshold(3);
    cfg.set_external_pacing(true);
}

#[test]
fn config_rejects_invalid_wire_format() {
    let mut cfg = Config::new_with_version(PROTOCOL_VERSION).expect("config");
    let err = cfg
        .set_application_protos_wire_format(b"\x03h3")
        .expect_err("invalid wire format must fail");
    assert!(matches!(err, ConnectionError::InvalidState));
}

#[test]
fn config_rejects_missing_cert_key_and_ca_paths() {
    let mut cfg = Config::new_with_version(PROTOCOL_VERSION).expect("config");
    let missing = std::env::temp_dir().join(format!(
        "qf-missing-{}-{}.pem",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos()
    ));
    let missing_str = missing.to_str().expect("utf8 path");

    let cert_err = cfg.load_cert_chain_from_pem_file(missing_str).expect_err("missing cert path");
    assert!(matches!(cert_err, ConnectionError::TlsError(_)));

    let key_err = cfg.load_priv_key_from_pem_file(missing_str).expect_err("missing key path");
    assert!(matches!(key_err, ConnectionError::TlsError(_)));

    let ca_err =
        cfg.load_verify_locations_from_file(missing_str).expect_err("missing ca file path");
    assert!(matches!(ca_err, ConnectionError::TlsError(_)));

    let ca_dir_err =
        cfg.load_verify_locations_from_directory(missing_str).expect_err("missing ca dir path");
    assert!(matches!(ca_dir_err, ConnectionError::TlsError(_)));
}
