#![cfg(feature = "rust-tests")]

use quicfuscate::harness::run_from_args;

#[test]
fn harness_udpfast_loopback_smoke() {
    let args = vec![
        "harness".to_string(),
        "udp-throughput".to_string(),
        "--size".to_string(),
        "256".to_string(),
        "--iters".to_string(),
        "5".to_string(),
        "--batch".to_string(),
        "4".to_string(),
        "--bind".to_string(),
        "127.0.0.1:0".to_string(),
    ];
    run_from_args(args);
}
