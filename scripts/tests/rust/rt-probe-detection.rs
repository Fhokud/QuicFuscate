#![cfg(feature = "rust-tests")]

use std::net::SocketAddr;
use std::sync::Arc;

use quicfuscate::crypto::CryptoManager;
use quicfuscate::optimize::OptimizationManager;
use quicfuscate::stealth::{ActiveProbeDetector, ProbeResponseMode};
use quicfuscate::{telemetry, StealthConfig, StealthManager};

fn loopback_source() -> SocketAddr {
    "127.0.0.1:4433".parse().expect("valid socket")
}

#[test]
fn benign_packet_is_not_flagged_as_probe() {
    let detector = ActiveProbeDetector::new(3, ProbeResponseMode::Fake);
    let benign = [0x01_u8, 0x02, 0x03, 0x04, 0x05, 0x06];
    let result = detector.check_packet(&benign, loopback_source());
    assert_eq!(result, None);
}

#[test]
fn gfw_probe_signature_triggers_configured_response() {
    let detector = ActiveProbeDetector::new(8, ProbeResponseMode::Fake);
    let packet = [0x16_u8, 0x03, 0x01, 0x00, 0x00, 0xff, 0x10];
    let result = detector.check_packet(&packet, loopback_source());
    assert_eq!(result, Some(ProbeResponseMode::Fake));
}

#[test]
fn masked_dpi_probe_signature_is_detected() {
    let detector = ActiveProbeDetector::new(8, ProbeResponseMode::Block);
    let packet = [0xc0_u8, 0xaa, 0xbb, 0xcc, 0x01, 0x99, 0x42];
    let result = detector.check_packet(&packet, loopback_source());
    assert_eq!(result, Some(ProbeResponseMode::Block));
}

#[test]
fn threshold_escalates_to_switch_mode() {
    let detector = ActiveProbeDetector::new(2, ProbeResponseMode::Ignore);
    let probe = [0x16_u8, 0x03, 0x01, 0x00, 0x00, 0x10];

    let first = detector.check_packet(&probe, loopback_source());
    let second = detector.check_packet(&probe, loopback_source());

    assert_eq!(first, Some(ProbeResponseMode::Ignore));
    assert_eq!(second, Some(ProbeResponseMode::Switch));
}

#[test]
fn fake_response_shapes_are_stable() {
    let detector = ActiveProbeDetector::new(3, ProbeResponseMode::Fake);

    let tls_alert = detector.generate_fake_response("GFW_TLS_Probe");
    let quic_vn = detector.generate_fake_response("DPI_QUIC_Scan");
    let generic = detector.generate_fake_response("unknown");

    assert_eq!(tls_alert, vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]);
    assert_eq!(quic_vn, vec![0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
    assert_eq!(generic, vec![0x00, 0x00, 0x00, 0x00]);
}

#[test]
fn mixed_traffic_only_triggers_on_probe_signatures() {
    let detector = ActiveProbeDetector::new(3, ProbeResponseMode::Fake);
    let src = loopback_source();
    let benign = [0x01_u8, 0x02, 0x03, 0x04, 0x05];
    let probe = [0x16_u8, 0x03, 0x01, 0x00, 0x00, 0x90];

    for _ in 0..64 {
        assert_eq!(detector.check_packet(&benign, src), None);
    }

    assert_eq!(detector.check_packet(&probe, src), Some(ProbeResponseMode::Fake));

    for _ in 0..64 {
        assert_eq!(detector.check_packet(&benign, src), None);
    }
}

#[test]
fn stealth_manager_updates_probe_telemetry_counters() {
    let mut cfg = StealthConfig::intelligent();
    cfg.dynamic_enabled = true;
    cfg.enable_traffic_padding = true;
    cfg.enable_timing_obfuscation = true;

    let manager = StealthManager::new(
        cfg,
        Arc::new(OptimizationManager::new()),
        Arc::new(CryptoManager::new()),
    );

    let before_detected = telemetry::STEALTH_PROBE_DETECTED.get();
    let before_switch = telemetry::STEALTH_PROBE_SWITCH.get();
    let before_escalated = telemetry::STEALTH_MODE_ESCALATED.get();

    let mut probe_packet = vec![0x16_u8, 0x03, 0x01, 0x00, 0x00, 0x42];
    manager.process_incoming_packet(&mut probe_packet, loopback_source());

    let after_detected = telemetry::STEALTH_PROBE_DETECTED.get();
    let after_switch = telemetry::STEALTH_PROBE_SWITCH.get();
    let after_escalated = telemetry::STEALTH_MODE_ESCALATED.get();

    assert!(after_detected > before_detected);
    assert!(after_switch > before_switch);
    assert!(after_escalated > before_escalated);
}
