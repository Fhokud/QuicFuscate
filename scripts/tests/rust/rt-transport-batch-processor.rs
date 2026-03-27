#![cfg(feature = "rust-tests")]

use quicfuscate::transport::batch::BatchProcessor;
use std::net::UdpSocket;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::time::Duration;

#[test]
fn batch_processor_init_acceleration_is_ok() {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind socket");
    let mut batch = BatchProcessor::new();
    batch.init_acceleration(&socket).expect("init_acceleration");
}

#[cfg(target_os = "linux")]
#[test]
fn batch_processor_fallback_preserves_large_packet_payload() {
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver.set_read_timeout(Some(Duration::from_secs(1))).expect("set read timeout");
    let recv_addr = receiver.local_addr().expect("receiver local addr");

    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let sender_fd = sender.as_raw_fd();

    let mut batch = BatchProcessor::new();
    batch.force_batch_send_fallback(true);

    let payload = vec![0x5Au8; 4096];
    let packets = [(&payload[..], recv_addr)];

    let sent = batch.batch_send(sender_fd, &packets).expect("batch send fallback");
    assert_eq!(sent, 1, "fallback did not send expected packet count");

    let mut recv_buf = vec![0u8; payload.len() + 512];
    let (len, _) = receiver.recv_from(&mut recv_buf).expect("receive packet");
    assert_eq!(len, payload.len(), "payload length truncated in fallback path");
    assert_eq!(&recv_buf[..len], &payload[..], "payload bytes altered in fallback path");
}

#[cfg(target_os = "linux")]
#[test]
fn batch_processor_recv_batch_preserves_large_packet_payload() {
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver.set_nonblocking(true).expect("set nonblocking");
    let recv_addr = receiver.local_addr().expect("receiver local addr");
    let receiver_fd = receiver.as_raw_fd();

    let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let payload = vec![0xA5u8; 4096];
    sender.send_to(&payload, recv_addr).expect("send large packet");

    let mut batch = BatchProcessor::new();
    let packets =
        batch.batch_recv(receiver_fd, Some(Duration::from_millis(5))).expect("batch recv");
    assert_eq!(packets.len(), 1, "expected one packet from batch recv");
    let (data, _addr) = &packets[0];
    assert_eq!(data.len(), payload.len(), "payload length truncated in recv batch path");
    assert_eq!(data, &payload, "payload bytes altered in recv batch path");
}
