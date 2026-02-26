#![cfg(feature = "rust-tests")]

use quicfuscate::harness::run_from_args;

#[test]
fn harness_qpack_encode_runs_with_small_input() {
    let args = vec![
        "harness".to_string(),
        "qpack-encode".to_string(),
        "--input".to_string(),
        "4k".to_string(),
        "--iters".to_string(),
        "1".to_string(),
    ];
    run_from_args(args);
}
