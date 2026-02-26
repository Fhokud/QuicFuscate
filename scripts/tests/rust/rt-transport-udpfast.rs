#![cfg(feature = "rust-tests")]

use quicfuscate::transport::udpfast::{AlignedBuffer, UdpFastPath};
use std::net::SocketAddr;

#[test]
fn aligned_buffer_is_cacheline_aligned() {
    let buf = AlignedBuffer::new(1);
    let len = buf.as_slice().len();
    assert_eq!(len % 64, 0);
    assert!(len >= 64);
}

#[test]
fn udp_fastpath_initializes_and_counters_zero() {
    let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let fp = UdpFastPath::new(addr).expect("fastpath new");
    assert_eq!(fp.bytes_sent.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(fp.bytes_received.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(fp.packets_sent.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(fp.packets_received.load(std::sync::atomic::Ordering::Relaxed), 0);
}
