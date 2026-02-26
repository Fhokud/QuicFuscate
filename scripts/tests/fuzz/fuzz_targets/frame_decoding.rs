#![no_main]

use libfuzzer_sys::fuzz_target;

use quicfuscate::transport::frames;
use quicfuscate::transport::PacketType;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let pkt_ty = match data[0] % 6 {
        0 => PacketType::Initial,
        1 => PacketType::Handshake,
        2 => PacketType::ZeroRTT,
        3 => PacketType::Retry,
        4 => PacketType::VersionNegotiation,
        _ => PacketType::Short,
    };
    let _ = frames::from_bytes(&data[1..], pkt_ty);
});
