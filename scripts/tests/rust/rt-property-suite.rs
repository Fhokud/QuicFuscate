#![cfg(feature = "rust-tests")]

use std::sync::Arc;

use proptest::prelude::*;
use quicfuscate::crypto::aead_legacy::{AeadOpen, AeadSeal};
use quicfuscate::crypto::chacha20poly1305::ChaCha20Poly1305;
use quicfuscate::fec::{Encoder8, FecDecoder8, FecPacket};
use quicfuscate::optimize::MemoryPool;
use quicfuscate::transport::frames::{from_bytes, to_bytes, wire_len};
use quicfuscate::transport::varint::{read_varint, varint_len, write_varint};
use quicfuscate::transport::{Frame, PacketType};

const MAX_VARINT: u64 = 0x3fff_ffff_ffff_ffff;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn prop_varint_roundtrip(value in 0u64..=MAX_VARINT) {
        let mut buf = vec![0u8; varint_len(value)];
        let used = write_varint(value, &mut buf).expect("write varint");
        let (decoded, used2) = read_varint(&buf).expect("read varint");
        prop_assert_eq!(used, used2);
        prop_assert_eq!(decoded, value);
    }

    #[test]
    fn prop_stream_frame_roundtrip(
        stream_id in 0u64..=1024,
        offset in 0u64..=4096,
        fin in any::<bool>(),
        data in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let frame = Frame::Stream { stream_id, offset, data: data.clone(), fin };
        let len = wire_len(&frame);
        let mut buf = vec![0u8; len];
        let used = to_bytes(&frame, &mut buf).expect("to_bytes");
        let (decoded, used2) = from_bytes(&buf[..used], PacketType::Short).expect("from_bytes");
        prop_assert_eq!(used, len);
        prop_assert_eq!(used2, len);
        prop_assert_eq!(decoded, frame);
    }

    #[test]
    fn prop_chacha20poly1305_roundtrip(
        counter in any::<u64>(),
        plaintext in proptest::collection::vec(any::<u8>(), 0..256),
        aad in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let key = [0xA5u8; 32];
        let nonce = [0x3Cu8; 12];
        let mut buf = vec![0u8; plaintext.len() + 16];
        buf[..plaintext.len()].copy_from_slice(&plaintext);

        let seal = ChaCha20Poly1305::new(&key, &nonce);
        let sealed_len =
            seal.seal_with_u64_counter(counter, &aad, &mut buf, plaintext.len(), None).expect("seal");
        let open = ChaCha20Poly1305::new(&key, &nonce);
        let opened_len = open.open_with_u64_counter(counter, &aad, &mut buf).expect("open");

        prop_assert_eq!(sealed_len, plaintext.len() + 16);
        prop_assert_eq!(opened_len, plaintext.len());
        prop_assert_eq!(&buf[..opened_len], plaintext.as_slice());
    }

    #[test]
    fn prop_fec_single_repair_recovers_one_loss(
        payloads in proptest::collection::vec(proptest::array::uniform32(any::<u8>()), 4),
        drop_index in 0usize..4,
    ) {
        let pool = Arc::new(MemoryPool::new(64, 256));
        let mut enc = Encoder8::new(4, 6);

        for (idx, payload) in payloads.iter().enumerate() {
            let id = (idx + 1) as u64;
            let pkt = FecPacket::new(
                id,
                Some(pool.alloc_from_slice(payload)),
                payload.len(),
                true,
                None,
                0,
                Arc::clone(&pool),
            );
            enc.take_packet(pkt);
        }

        let repair = enc.generate_repair_packet(0, &pool).expect("repair packet");
        let mut dec = FecDecoder8::new(4, Arc::clone(&pool));

        for (idx, payload) in payloads.iter().enumerate() {
            if idx == drop_index {
                continue;
            }
            let id = (idx + 1) as u64;
            let pkt = FecPacket::new(
                id,
                Some(pool.alloc_from_slice(payload)),
                payload.len(),
                true,
                None,
                0,
                Arc::clone(&pool),
            );
            dec.take_packet(pkt);
        }
        dec.take_packet(repair);

        let expected_id = (drop_index + 1) as u64;
        let recovered = dec.poll_recovered().into_iter().find(|p| p.id == expected_id);
        let recovered = recovered.expect("missing packet should be recovered");
        let recovered_data = recovered.data.as_ref().expect("recovered data");
        prop_assert_eq!(&recovered_data[..32], payloads[drop_index].as_slice());
    }
}
