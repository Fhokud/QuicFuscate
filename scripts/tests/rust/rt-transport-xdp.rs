#![cfg(all(target_os = "linux", feature = "rust-tests", feature = "internal_af_xdp_experimental"))]

#[test]
fn xdp_rejects_zero_frame_size() {
    let res = quicfuscate::transport::run_xdp_experimental_socket_probe(0, 0, 0, 1);
    assert!(res.is_err());
}
