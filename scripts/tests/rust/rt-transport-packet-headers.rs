#![cfg(feature = "rust-tests")]

use quicfuscate::error::ConnectionError;
use quicfuscate::transport::packet::{
    encode_pkt_num, format_header, parse_header, Header, PacketType,
};

#[test]
fn short_header_roundtrip() {
    let hdr = Header {
        ty: PacketType::Short,
        version: 0,
        dcid: vec![0xAA, 0xBB, 0xCC, 0xDD],
        scid: Vec::new(),
        pkt_num: 0,
        pkt_num_len: 0,
        token: None,
        versions: None,
        key_phase: true,
    };
    let mut buf = vec![0u8; 64];
    let used = format_header(&hdr, &mut buf).expect("format_header");
    let (parsed, pn_off) = parse_header(&buf[..used], hdr.dcid.len()).expect("parse_header");
    assert_eq!(pn_off, 1 + hdr.dcid.len());
    assert_eq!(parsed.ty, PacketType::Short);
    assert_eq!(parsed.dcid, hdr.dcid);
    assert!(parsed.scid.is_empty());
    assert!(parsed.key_phase);
}

#[test]
fn long_header_roundtrip_initial() {
    let hdr = Header {
        ty: PacketType::Initial,
        version: 0x1,
        dcid: vec![1, 2, 3],
        scid: vec![4, 5],
        pkt_num: 0,
        pkt_num_len: 0,
        token: None,
        versions: None,
        key_phase: false,
    };
    let mut buf = vec![0u8; 64];
    let used = format_header(&hdr, &mut buf).expect("format_header");
    let (parsed, pn_off) = parse_header(&buf[..used], 0).expect("parse_header");
    assert!(pn_off > 0);
    assert_eq!(parsed.ty, PacketType::Initial);
    assert_eq!(parsed.version, hdr.version);
    assert_eq!(parsed.dcid, hdr.dcid);
    assert_eq!(parsed.scid, hdr.scid);
}

#[test]
fn parse_header_rejects_missing_fixed_bit() {
    let buf = [0x00u8, 0x01, 0x02, 0x03];
    let err = parse_header(&buf, 0).expect_err("invalid fixed bit");
    assert!(matches!(err, ConnectionError::InvalidPacket));
}

#[test]
fn encode_packet_number_lengths() {
    let pn = 0xA1B2_C3D4u64;
    let mut out = [0u8; 4];

    let used1 = encode_pkt_num(pn, 1, &mut out[..1]).expect("pn len 1");
    assert_eq!(used1, 1);
    assert_eq!(out[0], (pn & 0xFF) as u8);

    let used2 = encode_pkt_num(pn, 2, &mut out[..2]).expect("pn len 2");
    assert_eq!(used2, 2);
    assert_eq!(&out[..2], &[(pn >> 8) as u8, pn as u8]);

    let used3 = encode_pkt_num(pn, 3, &mut out[..3]).expect("pn len 3");
    assert_eq!(used3, 3);
    assert_eq!(&out[..3], &[(pn >> 16) as u8, (pn >> 8) as u8, pn as u8]);

    let used4 = encode_pkt_num(pn, 4, &mut out[..4]).expect("pn len 4");
    assert_eq!(used4, 4);
    assert_eq!(&out[..4], &(pn as u32).to_be_bytes());
}

#[test]
fn encode_packet_number_rejects_invalid_len() {
    let pn = 0x11u64;
    let mut out = [0u8; 8];
    let err = encode_pkt_num(pn, 5, &mut out).expect_err("invalid length");
    assert!(matches!(err, ConnectionError::InvalidPacket));
}

#[test]
fn encode_packet_number_rejects_short_buffer() {
    let pn = 0x11u64;
    let mut out = [0u8; 1];
    let err = encode_pkt_num(pn, 2, &mut out).expect_err("buffer too short");
    assert!(matches!(err, ConnectionError::BufferTooShort));
}
