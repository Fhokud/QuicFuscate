#![cfg(all(target_os = "linux", feature = "rust-tests"))]

use quicfuscate::transport::xdp::linux::XdpSocket;

#[test]
fn xdp_rejects_zero_frame_size() {
    let res = XdpSocket::new(0, 0, 0, 1);
    assert!(res.is_err());
}
