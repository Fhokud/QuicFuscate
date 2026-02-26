#![cfg(all(target_os = "linux", feature = "uring_sys", feature = "rust-tests"))]

use quicfuscate::transport::uring::IoUringNative;

#[test]
fn uring_rejects_zero_entries() {
    let res = IoUringNative::new(0, 0);
    assert!(res.is_err());
}
