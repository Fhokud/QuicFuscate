#![cfg(feature = "rust-tests")]

use quicfuscate::transport::batch::BatchProcessor;
use std::net::UdpSocket;

#[test]
fn batch_processor_init_acceleration_is_ok() {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind socket");
    let mut batch = BatchProcessor::new();
    batch.init_acceleration(&socket).expect("init_acceleration");
}
