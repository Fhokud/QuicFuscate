#![cfg(feature = "rust-tests")]

use std::collections::HashSet;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use quicfuscate::transport::udpfast::UdpFastPath;
use quicfuscate::transport::udpfast::MAX_BATCH_SIZE;

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

#[test]
fn udpfast_send_batch_respects_per_packet_destination() {
    let receiver_a = UdpSocket::bind("127.0.0.1:0").expect("bind receiver_a");
    let receiver_b = UdpSocket::bind("127.0.0.1:0").expect("bind receiver_b");
    receiver_a.set_read_timeout(Some(Duration::from_secs(1))).expect("receiver_a timeout");
    receiver_b.set_read_timeout(Some(Duration::from_secs(1))).expect("receiver_b timeout");

    let recv_addr_a: SocketAddr = receiver_a.local_addr().expect("receiver_a local addr");
    let recv_addr_b: SocketAddr = receiver_b.local_addr().expect("receiver_b local addr");

    let mut sender =
        UdpFastPath::new("127.0.0.1:0".parse().expect("sender bind")).expect("create sender");

    let packets: Vec<(&[u8], SocketAddr)> = vec![
        (b"to-a-1", recv_addr_a),
        (b"to-b-1", recv_addr_b),
        (b"to-a-2", recv_addr_a),
        (b"to-b-2", recv_addr_b),
    ];

    let sent = sender.send_batch(&packets).expect("batch send");
    assert_eq!(sent, packets.len(), "batch send did not send all packets");

    let mut recv_a = HashSet::new();
    let mut recv_b = HashSet::new();
    for _ in 0..2 {
        let mut buf = [0u8; 64];
        let (len, _) = receiver_a.recv_from(&mut buf).expect("recv receiver_a packet");
        recv_a.insert(buf[..len].to_vec());
    }
    for _ in 0..2 {
        let mut buf = [0u8; 64];
        let (len, _) = receiver_b.recv_from(&mut buf).expect("recv receiver_b packet");
        recv_b.insert(buf[..len].to_vec());
    }

    let expected_a: HashSet<Vec<u8>> =
        [b"to-a-1".to_vec(), b"to-a-2".to_vec()].into_iter().collect();
    let expected_b: HashSet<Vec<u8>> =
        [b"to-b-1".to_vec(), b"to-b-2".to_vec()].into_iter().collect();
    assert_eq!(recv_a, expected_a, "receiver_a got wrong destination payload set");
    assert_eq!(recv_b, expected_b, "receiver_b got wrong destination payload set");
}

#[test]
fn udpfast_send_batch_caps_to_max_batch_size() {
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver.set_read_timeout(Some(Duration::from_secs(1))).expect("set read timeout");
    let recv_addr: SocketAddr = receiver.local_addr().expect("receiver local addr");

    let mut sender =
        UdpFastPath::new("127.0.0.1:0".parse().expect("sender bind")).expect("create sender");

    let total_packets = MAX_BATCH_SIZE + 3;
    let payloads: Vec<Vec<u8>> = (0..total_packets)
        .map(|i| {
            vec![0x30u8.wrapping_add((i % 64) as u8), (i & 0xFF) as u8, ((i >> 8) & 0xFF) as u8]
        })
        .collect();
    let packets: Vec<(&[u8], SocketAddr)> =
        payloads.iter().map(|payload| (payload.as_slice(), recv_addr)).collect();

    let sent = sender.send_batch(&packets).expect("batch send");
    assert_eq!(sent, MAX_BATCH_SIZE, "batch send must cap at MAX_BATCH_SIZE");

    let mut received = HashSet::with_capacity(sent);
    for _ in 0..sent {
        let mut buf = [0u8; 64];
        let (len, _) = receiver.recv_from(&mut buf).expect("recv packet");
        received.insert(buf[..len].to_vec());
    }

    let expected: HashSet<Vec<u8>> = payloads.iter().take(MAX_BATCH_SIZE).cloned().collect();
    assert_eq!(received, expected, "received set must match first MAX_BATCH_SIZE payloads");
}
