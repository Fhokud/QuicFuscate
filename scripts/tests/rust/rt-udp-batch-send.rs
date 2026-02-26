#![cfg(feature = "rust-tests")]

use std::collections::HashSet;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use quicfuscate::transport::udpfast::UdpFastPath;

#[test]
fn udpfast_send_batch_sends_all_packets() {
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver.set_read_timeout(Some(Duration::from_secs(1))).expect("read timeout");
    let recv_addr: SocketAddr = receiver.local_addr().expect("local addr");

    let mut sender =
        UdpFastPath::new("127.0.0.1:0".parse().expect("sender bind")).expect("create sender");

    let payloads: Vec<&[u8]> = vec![b"alpha", b"beta", b"gamma", b"delta"];
    let packets: Vec<(&[u8], SocketAddr)> =
        payloads.iter().map(|payload| (*payload, recv_addr)).collect();

    let sent = sender.send_batch(&packets).expect("batch send");
    assert_eq!(sent, packets.len(), "batch send did not send all packets");

    let mut received = Vec::with_capacity(sent);
    for _ in 0..sent {
        let mut buf = [0u8; 64];
        let (len, _) = receiver.recv_from(&mut buf).expect("recv packet");
        received.push(buf[..len].to_vec());
    }

    let expected: HashSet<Vec<u8>> = payloads.iter().map(|payload| payload.to_vec()).collect();
    let actual: HashSet<Vec<u8>> = received.into_iter().collect();
    assert_eq!(actual, expected, "received payloads mismatch");
}
