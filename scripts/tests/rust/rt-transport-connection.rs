#![cfg(feature = "rust-tests")]

use quicfuscate::error::ConnectionError;
use quicfuscate::transport::{packet, Config, ConnectionId, PathEvent, PROTOCOL_VERSION};

#[test]
fn connection_datagram_queues_and_thresholds() {
    let mut cfg = Config::new_with_version(PROTOCOL_VERSION).expect("config");
    let local: std::net::SocketAddr = "127.0.0.1:0".parse().expect("local");
    let peer: std::net::SocketAddr = "127.0.0.1:4433".parse().expect("peer");
    let scid = ConnectionId::from_ref(&[0u8; 8]);
    let mut conn = packet::connect(None, scid.as_ref(), local, peer, &mut cfg).expect("connect");

    conn.set_ack_eliciting_threshold(5);
    assert_eq!(conn.ack_eliciting_threshold(), 5);
    conn.set_external_pacing(true);
    assert!(conn.external_pacing_enabled());

    conn.enable_datagrams(0, 1);
    assert_eq!(conn.dgram_send_queue_len(), 0);
    conn.dgram_send(b"one").expect("dgram send");
    assert_eq!(conn.dgram_send_queue_len(), 1);

    let err = conn.dgram_send(b"two").expect_err("queue full");
    assert!(matches!(err, ConnectionError::InvalidState));
}

#[test]
fn connection_migrate_emits_path_events_in_order() {
    let mut cfg = Config::new_with_version(PROTOCOL_VERSION).expect("config");
    let local: std::net::SocketAddr = "127.0.0.1:0".parse().expect("local");
    let peer: std::net::SocketAddr = "127.0.0.1:4433".parse().expect("peer");
    let scid = ConnectionId::from_ref(&[1u8; 8]);
    let mut conn = packet::connect(None, scid.as_ref(), local, peer, &mut cfg).expect("connect");

    let new_local: std::net::SocketAddr = "127.0.0.1:4444".parse().expect("new local");
    let new_peer: std::net::SocketAddr = "127.0.0.1:5555".parse().expect("new peer");
    let path_id = conn.migrate(new_local, new_peer).expect("migrate");
    assert!(path_id > 0);

    let ev1 = conn.path_event_next().expect("event 1");
    let ev2 = conn.path_event_next().expect("event 2");
    let ev3 = conn.path_event_next().expect("event 3");
    assert!(matches!(ev1, PathEvent::New(_, _)));
    assert!(matches!(ev2, PathEvent::Validated(_, _)));
    assert!(matches!(ev3, PathEvent::PeerMigrated(_, _)));
    assert!(conn.path_event_next().is_none());
}
