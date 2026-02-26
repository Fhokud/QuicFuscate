use crate::crypto::aead as tls_aead;
use crate::crypto::{select_data_aead, AesGcm128, ChaCha20Poly1305};
use crate::error::ConnectionError;
use crate::optimize::telemetry;
// no direct varint helpers used here

/// Derive 16-byte header protection key from TLS secret (RFC 9001 compliant)
pub fn derive_hp_key(secret: &[u8]) -> [u8; 16] {
    let hp_vec = crate::crypto::kdf::derive_hdr_key(secret, 16);
    let mut hp = [0u8; 16];
    hp.copy_from_slice(&hp_vec[..16]);
    hp
}

pub const FORM_BIT: u8 = 0x80;
pub const FIXED_BIT: u8 = 0x40;
pub const KEY_PHASE_BIT: u8 = 0x04;
pub const TYPE_MASK: u8 = 0x30;
pub const PKT_NUM_MASK: u8 = 0x03;

pub const MAX_CID_LEN: usize = 20;
pub const MAX_PKT_NUM_LEN: usize = 4;
/// Bytes of sample used for HP
pub const SAMPLE_LEN: usize = 16;

/// Header protection trait for masking packet numbers
pub trait HeaderProtector {
    fn new_mask(&self, sample: &[u8]) -> [u8; 5];
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PacketType {
    Initial,
    Retry,
    Handshake,
    ZeroRTT,
    VersionNegotiation,
    Short,
}

// Connection establishment functions (moved from transport.rs to externalize packet module API)

pub fn connect(
    _sni: Option<&str>,
    scid: &[u8],
    local: std::net::SocketAddr,
    peer: std::net::SocketAddr,
    config: &mut crate::transport::Config,
) -> Result<crate::transport::Connection, ConnectionError> {
    let mut conn = crate::transport::Connection::new_client(scid, local, peer, config.clone());

    // Client selects an unpredictable initial DCID (RFC 9000). This DCID is also the ODCID
    // used for Initial key derivation (RFC 9001).
    let mut dcid = [0u8; crate::transport::MAX_CONN_ID_LEN];
    crate::transport::rand::rand_bytes(&mut dcid);
    conn.set_initial_dcid(crate::transport::ConnectionId::from_vec(dcid.to_vec()));

    // Attach lightweight FEC transport observer to collect ECN/ACK telemetry
    // (policy application remains optional and external)
    {
        let obs_arc = crate::fec::FecTransportObserver::new();
        let obs_trait: std::sync::Arc<dyn crate::transport::TransportObserver> = obs_arc;
        conn.set_observer(Some(obs_trait));
    }

    config.set_application_protos(&[b"h3"])?;
    // BBR3 with browser-specific tuning
    let browser_profile = crate::transport::recovery::BrowserProfile::Chrome;
    conn.recovery_mut().set_stealth_mode(false, browser_profile);

    Ok(conn)
}

pub fn accept(
    scid: &[u8],
    odcid: Option<&[u8]>,
    local: std::net::SocketAddr,
    peer: std::net::SocketAddr,
    config: &mut crate::transport::Config,
) -> Result<crate::transport::Connection, ConnectionError> {
    // Create connection with server role
    // Record ODCID for Initial key derivation (RFC 9001).
    let mut conn = crate::transport::Connection::new_server(scid, local, peer, config.clone());
    if let Some(odcid) = odcid {
        conn.set_initial_dcid(crate::transport::ConnectionId::from_vec(odcid.to_vec()));
    }
    // Attach lightweight FEC transport observer to collect ECN/ACK telemetry
    // (policy application remains optional and external)
    {
        let obs_arc = crate::fec::FecTransportObserver::new();
        let obs_trait: std::sync::Arc<dyn crate::transport::TransportObserver> = obs_arc;
        conn.set_observer(Some(obs_trait));
    }

    config.set_application_protos(&[b"h3"])?;
    // BBR3 with browser-specific tuning
    let browser_profile = crate::transport::recovery::BrowserProfile::Chrome;
    conn.recovery_mut().set_stealth_mode(false, browser_profile);

    Ok(conn)
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Header {
    pub ty: PacketType,
    pub version: u32,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub pkt_num: u64,
    pub pkt_num_len: usize,
    pub token: Option<Vec<u8>>,
    pub versions: Option<Vec<u32>>,
    pub key_phase: bool,
}

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

/// SIMD-optimized packet number encoding
pub fn encode_pkt_num(pn: u64, pn_len: usize, out: &mut [u8]) -> Result<usize, ConnectionError> {
    if out.len() < pn_len {
        return Err(ConnectionError::BufferTooShort);
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    unsafe {
        // AVX2 optimized path for 4-byte packet numbers
        if pn_len == 4
            && crate::optimize::FeatureDetector::instance()
                .has_feature(crate::optimize::CpuFeature::AVX2)
        {
            let pn_bytes = pn.to_be_bytes();
            let pn_vec = _mm_set_epi32(0, 0, 0, pn as i32);
            let shuffled = _mm_shuffle_epi8(
                pn_vec,
                _mm_set_epi8(-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3),
            );
            _mm_storeu_si32(out.as_mut_ptr() as *mut i32, shuffled);
            return Ok(4);
        }
    }

    // Fallback scalar path
    match pn_len {
        1 => {
            out[0] = pn as u8;
            Ok(1)
        }
        2 => {
            let bytes = (pn as u16).to_be_bytes();
            out[..2].copy_from_slice(&bytes);
            Ok(2)
        }
        3 => {
            out[0] = (pn >> 16) as u8;
            out[1] = (pn >> 8) as u8;
            out[2] = pn as u8;
            Ok(3)
        }
        4 => {
            let bytes = (pn as u32).to_be_bytes();
            out[..4].copy_from_slice(&bytes);
            Ok(4)
        }
        _ => Err(ConnectionError::InvalidPacket),
    }
}

/// Minimal header parsing to get PN offset and header fields
pub fn parse_header(buf: &[u8], short_dcid_len: usize) -> Result<(Header, usize), ConnectionError> {
    use crate::transport::udpfast::{likely, unlikely};
    if unlikely(buf.is_empty()) {
        return Err(ConnectionError::BufferTooShort);
    }
    let first = buf[0];
    // Validate fixed bit early
    if unlikely((first & crate::transport::packet::FIXED_BIT) == 0) {
        return Err(ConnectionError::InvalidPacket);
    }
    if likely((first & crate::transport::packet::FORM_BIT) == 0) {
        // Short header (most common in established connections)
        if unlikely(buf.len() < 1 + short_dcid_len) {
            return Err(ConnectionError::BufferTooShort);
        }
        let dcid = buf[1..1 + short_dcid_len].to_vec();
        let hdr = Header {
            ty: PacketType::Short,
            version: 0,
            dcid,
            scid: Vec::new(),
            pkt_num: 0,
            pkt_num_len: 0,
            token: None,
            versions: None,
            key_phase: (first & crate::transport::packet::KEY_PHASE_BIT) != 0,
        };
        let pn_off = 1 + short_dcid_len;
        return Ok((hdr, pn_off));
    }
    // Long header (very simplified parsing)
    if buf.len() < 7 {
        return Err(ConnectionError::BufferTooShort);
    }
    let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    let mut off = 5;
    if buf.len() < off + 1 {
        return Err(ConnectionError::BufferTooShort);
    }
    let dcid_len = buf[off] as usize;
    off += 1;
    if buf.len() < off + dcid_len + 1 {
        return Err(ConnectionError::BufferTooShort);
    }
    let dcid = buf[off..off + dcid_len].to_vec();
    off += dcid_len;
    let scid_len = buf[off] as usize;
    off += 1;
    if buf.len() < off + scid_len {
        return Err(ConnectionError::BufferTooShort);
    }
    let scid = buf[off..off + scid_len].to_vec();
    off += scid_len;
    let ty_bits = first & crate::transport::packet::TYPE_MASK;
    let ty = match (version, ty_bits) {
        (0, _) => PacketType::VersionNegotiation,
        (_, 0x00) => PacketType::Initial,
        (_, 0x10) => PacketType::ZeroRTT,
        (_, 0x20) => PacketType::Handshake,
        (_, 0x30) => PacketType::Retry,
        _ => PacketType::Initial,
    };
    let mut token = None;
    if ty == PacketType::Initial {
        let (tok_len, used) = crate::transport::varint::read_varint(&buf[off..])?;
        let tok_len = tok_len as usize;
        off += used;
        if buf.len() < off + tok_len {
            return Err(ConnectionError::BufferTooShort);
        }
        if tok_len > 0 {
            token = Some(buf[off..off + tok_len].to_vec());
        }
        off += tok_len;
    }
    let hdr = Header {
        ty,
        version,
        dcid,
        scid,
        pkt_num: 0,
        pkt_num_len: 0,
        token,
        versions: None,
        key_phase: false,
    };
    Ok((hdr, off))
}

/// Minimal header formatting to get PN offset and header fields
pub fn format_header(h: &Header, out: &mut [u8]) -> Result<usize, ConnectionError> {
    if out.is_empty() {
        return Err(ConnectionError::BufferTooShort);
    }
    match h.ty {
        PacketType::Short => {
            let mut first = crate::transport::packet::FIXED_BIT; // 0x40
            if h.key_phase {
                first |= crate::transport::packet::KEY_PHASE_BIT;
            }
            out[0] = first;
            if out.len() < 1 + h.dcid.len() {
                return Err(ConnectionError::BufferTooShort);
            }
            out[1..1 + h.dcid.len()].copy_from_slice(&h.dcid);
            Ok(1 + h.dcid.len())
        }
        PacketType::Initial | PacketType::Handshake => {
            // Long header (very simplified): [first][version:4][dcid_len:1][dcid][scid_len:1][scid]
            let mut first = FORM_BIT | FIXED_BIT; // long header with fixed bit
            first |= match h.ty {
                PacketType::Initial => 0x00,
                PacketType::Handshake => 0x20,
                _ => 0x00,
            };
            out[0] = first;
            if out.len() < 1 + 4 {
                return Err(ConnectionError::BufferTooShort);
            }
            out[1..5].copy_from_slice(&h.version.to_be_bytes());
            let mut off = 5;
            if out.len() < off + 1 {
                return Err(ConnectionError::BufferTooShort);
            }
            out[off] = h.dcid.len() as u8;
            off += 1;
            if out.len() < off + h.dcid.len() {
                return Err(ConnectionError::BufferTooShort);
            }
            out[off..off + h.dcid.len()].copy_from_slice(&h.dcid);
            off += h.dcid.len();
            if out.len() < off + 1 {
                return Err(ConnectionError::BufferTooShort);
            }
            out[off] = h.scid.len() as u8;
            off += 1;
            if out.len() < off + h.scid.len() {
                return Err(ConnectionError::BufferTooShort);
            }
            out[off..off + h.scid.len()].copy_from_slice(&h.scid);
            off += h.scid.len();
            if h.ty == PacketType::Initial {
                let token = h.token.as_deref().unwrap_or(&[]);
                off += crate::transport::varint::write_varint(token.len() as u64, &mut out[off..])?;
                if out.len() < off + token.len() {
                    return Err(ConnectionError::BufferTooShort);
                }
                out[off..off + token.len()].copy_from_slice(token);
                off += token.len();
            }
            Ok(off)
        }
        _ => Err(ConnectionError::InvalidPacket),
    }
}

/// Full RFC 9001 compliant HP/Decrypt implementation
pub fn unprotect_and_decrypt(
    crypto: &CryptoContext,
    buf: &mut [u8],
    short_dcid_len: usize,
    largest_pn_hint: u64,
) -> Result<(Header, usize, usize), ConnectionError> {
    // Parse header to get packet type and locate PN
    let (mut hdr, pn_off) = parse_header(buf, short_dcid_len)?;

    // Select inbound HP and AEAD based on packet type.
    // QUIC derives distinct header protection keys per direction; inbound should use *_open.
    let (hp, aead) = match hdr.ty {
        PacketType::Initial => (
            crypto.hp_initial_open.as_ref().or(crypto.hp_initial.as_ref()),
            crypto.open_initial.as_ref(),
        ),
        PacketType::Handshake => (
            crypto.hp_handshake_open.as_ref().or(crypto.hp_handshake.as_ref()),
            crypto.open_handshake.as_ref(),
        ),
        PacketType::ZeroRTT => {
            (crypto.hp_0rtt_open.as_ref().or(crypto.hp_0rtt.as_ref()), crypto.open_0rtt.as_ref())
        }
        PacketType::Short => {
            (crypto.hp_1rtt_open.as_ref().or(crypto.hp_1rtt.as_ref()), crypto.open_1rtt.as_ref())
        }
        _ => return Ok((hdr, pn_off, buf.len().saturating_sub(pn_off))),
    };

    // If crypto not ready, return as-is (early packets)
    let (hp, aead) = match (hp, aead) {
        (Some(h), Some(a)) => (h, a),
        _ => {
            if std::env::var("QUICFUSCATE_TRACE_TLS").is_ok() {
                eprintln!(
                    "[pkt] unprotect skip ty={:?} hp={} aead={}",
                    hdr.ty,
                    hp.is_some(),
                    aead.is_some()
                );
            }
            return Ok((hdr, pn_off, buf.len().saturating_sub(pn_off)));
        }
    };

    // Remove header protection when sample is available; otherwise accept unprotected headers.
    // Sample is taken 4 bytes after the PN offset.
    let sample_off = pn_off + 4;
    let pn_len;
    if buf.len() >= sample_off + 16 {
        let mask = hp.new_mask(&buf[sample_off..sample_off + 16]);
        if std::env::var("QUICFUSCATE_TRACE_TLS").is_ok() && hdr.ty == PacketType::Handshake {
            let s = &buf[sample_off..sample_off + 16];
            eprintln!(
                "[pkt] hp open hs sample={:02x}{:02x}{:02x}{:02x} mask={:02x}{:02x}{:02x}{:02x}{:02x}",
                s[0], s[1], s[2], s[3], mask[0], mask[1], mask[2], mask[3], mask[4]
            );
        }
        // Unmask the first byte to get PN length
        if hdr.ty == PacketType::Short {
            buf[0] ^= mask[0] & 0x1f; // Short header: 5 bits
        } else {
            buf[0] ^= mask[0] & 0x0f; // Long header: 4 bits
        }
        // Extract PN length from first byte
        pn_len = (buf[0] & 0x03) as usize + 1;
        hdr.pkt_num_len = pn_len;
        // Unmask the packet number
        for i in 0..pn_len {
            buf[pn_off + i] ^= mask[1 + i];
        }
    } else {
        // No sample available - assume header is unprotected and read PN directly.
        pn_len = (buf[0] & 0x03) as usize + 1;
        hdr.pkt_num_len = pn_len;
    }

    if buf.len() < pn_off + pn_len {
        return Err(ConnectionError::BufferTooShort);
    }

    // Decode packet number
    let mut pn = 0u64;
    for i in 0..pn_len {
        pn = (pn << 8) | buf[pn_off + i] as u64;
    }

    // Expand truncated PN using largest acknowledged
    let pn_nbits = pn_len * 8;
    let expected_pn = largest_pn_hint + 1;
    let pn_win = 1u64 << pn_nbits;
    let pn_hwin = pn_win / 2;
    let candidate = (expected_pn & !(pn_win - 1)) | pn;

    hdr.pkt_num = if candidate + pn_hwin <= expected_pn {
        candidate + pn_win
    } else if candidate > expected_pn + pn_hwin && candidate >= pn_win {
        candidate - pn_win
    } else {
        candidate
    };

    // Decrypt payload
    let aad_len = pn_off + pn_len;
    let payload_off = aad_len;
    let payload_len = buf.len() - payload_off;

    if payload_len < 16 {
        return Err(ConnectionError::BufferTooShort);
    }

    // Split buffer for AAD and payload to avoid borrow conflicts
    let (aad_buf, payload_buf) = buf.split_at_mut(aad_len);
    let aad = &aad_buf[..aad_len];

    // Decrypt in-place
    let plaintext_len = match aead.open_with_u64_counter(hdr.pkt_num, aad, payload_buf) {
        Ok(n) => n,
        Err(e) => {
            if std::env::var("QUICFUSCATE_TRACE_TLS").is_ok() {
                eprintln!(
                    "[pkt] open fail ty={:?} pn={} pn_len={} aad_len={} payload_len={}",
                    hdr.ty, hdr.pkt_num, hdr.pkt_num_len, aad_len, payload_len
                );
            }
            return Err(e);
        }
    };

    Ok((hdr, aad_len, plaintext_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_header_token_roundtrip() {
        let header = Header {
            ty: PacketType::Initial,
            version: crate::transport::PROTOCOL_VERSION,
            dcid: vec![0x11, 0x22, 0x33],
            scid: vec![0x44, 0x55],
            pkt_num: 0,
            pkt_num_len: 0,
            token: Some(vec![0x01, 0x02, 0x03, 0x04]),
            versions: None,
            key_phase: false,
        };
        let mut buf = vec![0u8; 64];
        let off = format_header(&header, &mut buf).expect("format header");
        let (parsed, parsed_off) = parse_header(&buf[..off], 0).expect("parse header");
        assert_eq!(parsed.ty, PacketType::Initial);
        assert_eq!(parsed.token, header.token);
        assert_eq!(off, parsed_off);
    }

    #[test]
    fn initial_header_empty_token_roundtrip() {
        let header = Header {
            ty: PacketType::Initial,
            version: crate::transport::PROTOCOL_VERSION,
            dcid: vec![0x01],
            scid: vec![0x02],
            pkt_num: 0,
            pkt_num_len: 0,
            token: None,
            versions: None,
            key_phase: false,
        };
        let mut buf = vec![0u8; 32];
        let off = format_header(&header, &mut buf).expect("format header");
        let (parsed, parsed_off) = parse_header(&buf[..off], 0).expect("parse header");
        assert_eq!(parsed.ty, PacketType::Initial);
        assert!(parsed.token.is_none());
        assert_eq!(off, parsed_off);
    }
}

/// Minimal header formatting to get PN offset and header fields
pub fn protect_header(
    crypto: &CryptoContext,
    buf: &mut [u8],
    pn_off: usize,
    pn_len: usize,
    pkt_type: PacketType,
) -> Result<(), ConnectionError> {
    // Select HP based on packet type
    let hp = match pkt_type {
        PacketType::Initial => crypto.hp_initial.as_ref(),
        PacketType::Handshake => crypto.hp_handshake.as_ref(),
        PacketType::ZeroRTT => crypto.hp_0rtt.as_ref(),
        PacketType::Short => crypto.hp_1rtt.as_ref(),
        _ => return Ok(()),
    };

    let hp = match hp {
        Some(h) => h,
        None => return Ok(()), // No HP available yet
    };

    // Sample is taken 4 bytes after the PN offset
    let sample_off = pn_off + 4;
    if buf.len() < sample_off + 16 {
        return Err(ConnectionError::BufferTooShort);
    }

    let mask = hp.new_mask(&buf[sample_off..sample_off + 16]);
    if std::env::var("QUICFUSCATE_TRACE_TLS").is_ok() && pkt_type == PacketType::Handshake {
        let s = &buf[sample_off..sample_off + 16];
        eprintln!(
            "[pkt] hp protect hs sample={:02x}{:02x}{:02x}{:02x} mask={:02x}{:02x}{:02x}{:02x}{:02x}",
            s[0], s[1], s[2], s[3], mask[0], mask[1], mask[2], mask[3], mask[4]
        );
    }

    // Mask the first byte
    if pkt_type == PacketType::Short {
        buf[0] ^= mask[0] & 0x1f; // Short header: 5 bits
    } else {
        buf[0] ^= mask[0] & 0x0f; // Long header: 4 bits
    }

    // Mask the packet number
    for i in 0..pn_len {
        buf[pn_off + i] ^= mask[1 + i];
    }

    Ok(())
}

/// Full encryption for outgoing packets
pub fn encrypt_and_protect(
    crypto: &CryptoContext,
    buf: &mut [u8],
    hdr_len: usize,
    pn: u64,
    pn_len: usize,
    pkt_type: PacketType,
) -> Result<usize, ConnectionError> {
    // Select AEAD based on packet type
    let aead = match pkt_type {
        PacketType::Initial => crypto.seal_initial.as_ref(),
        PacketType::Handshake => crypto.seal_handshake.as_ref(),
        PacketType::ZeroRTT => crypto.seal_0rtt.as_ref(),
        PacketType::Short => crypto.seal_1rtt.as_ref(),
        _ => return Ok(hdr_len),
    };

    let aead = match aead {
        Some(a) => a,
        None => return Ok(hdr_len), // No AEAD available yet
    };

    if hdr_len < pn_len {
        return Err(ConnectionError::InvalidPacket);
    }
    if buf.len() < hdr_len + 16 {
        return Err(ConnectionError::BufferTooShort);
    }

    // Encode packet number length (pn_len - 1) into the low 2 bits of the first header byte.
    // This is required for correct header protection removal on the peer.
    if pn_len == 0 || pn_len > 4 {
        return Err(ConnectionError::InvalidPacket);
    }
    buf[0] = (buf[0] & !PKT_NUM_MASK) | (((pn_len as u8) - 1) & PKT_NUM_MASK);

    // The packet number offset
    let pn_off = hdr_len - pn_len;

    // Encrypt payload in-place. Reserve 16 bytes for AEAD tag at the tail of the payload buffer.
    let (aad, payload) = buf.split_at_mut(hdr_len);
    let plaintext_len = payload.len().saturating_sub(16);
    let ciphertext_len = aead.seal_with_u64_counter(pn, aad, payload, plaintext_len, None)?;

    // Apply header protection
    protect_header(crypto, buf, pn_off, pn_len, pkt_type)?;

    Ok(hdr_len + ciphertext_len)
}

pub fn negotiate_version(
    scid: &[u8],
    dcid: &[u8],
    versions: &[u32],
    out: &mut [u8],
) -> Result<usize, ConnectionError> {
    let mut off = 0usize;
    if out.is_empty() {
        return Err(ConnectionError::BufferTooShort);
    }
    let first = crate::transport::rand::rand_u8() | FORM_BIT;
    out[off] = first;
    off += 1;
    if out.len() < off + 4 {
        return Err(ConnectionError::BufferTooShort);
    }
    out[off..off + 4].copy_from_slice(&0u32.to_be_bytes());
    off += 4;
    if out.len() < off + 1 + scid.len() + 1 + dcid.len() {
        return Err(ConnectionError::BufferTooShort);
    }
    out[off] = scid.len() as u8;
    off += 1;
    out[off..off + scid.len()].copy_from_slice(scid);
    off += scid.len();
    out[off] = dcid.len() as u8;
    off += 1;
    out[off..off + dcid.len()].copy_from_slice(dcid);
    off += dcid.len();
    for v in versions {
        if out.len() < off + 4 {
            return Err(ConnectionError::BufferTooShort);
        }
        out[off..off + 4].copy_from_slice(&v.to_be_bytes());
        off += 4;
    }
    Ok(off)
}

pub fn append_retry_tag(buf: &mut Vec<u8>, _odcid: &[u8], _version: u32) {
    let hdr_len = buf.len();
    let mut pseudo = Vec::with_capacity(1 + _odcid.len() + hdr_len);
    pseudo.push(_odcid.len() as u8);
    pseudo.extend_from_slice(_odcid);
    pseudo.extend_from_slice(&buf[..hdr_len]);
    const RETRY_INTEGRITY_KEY_V1: [u8; 16] = [
        0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8,
        0x4e,
    ];
    const RETRY_INTEGRITY_NONCE_V1: [u8; 12] =
        [0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb];
    let tag = crate::crypto::gcm::aes_gcm_tag_aad_only(
        &RETRY_INTEGRITY_KEY_V1,
        &RETRY_INTEGRITY_NONCE_V1,
        &pseudo,
    );
    buf.extend_from_slice(&tag);
}

pub fn verify_retry_tag(packet: &[u8], odcid: &[u8], _version: u32) -> Result<(), ConnectionError> {
    if packet.len() < 16 {
        return Err(ConnectionError::BufferTooShort);
    }
    let hdr_len = packet.len() - 16;
    let tag_in = &packet[hdr_len..];
    let mut pseudo = Vec::with_capacity(1 + odcid.len() + hdr_len);
    pseudo.push(odcid.len() as u8);
    pseudo.extend_from_slice(odcid);
    pseudo.extend_from_slice(&packet[..hdr_len]);
    const RETRY_INTEGRITY_KEY_V1: [u8; 16] = [
        0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8,
        0x4e,
    ];
    const RETRY_INTEGRITY_NONCE_V1: [u8; 12] =
        [0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb];
    let tag = crate::crypto::gcm::aes_gcm_tag_aad_only(
        &RETRY_INTEGRITY_KEY_V1,
        &RETRY_INTEGRITY_NONCE_V1,
        &pseudo,
    );
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= tag[i] ^ tag_in[i];
    }
    if diff == 0 {
        Ok(())
    } else {
        Err(ConnectionError::CryptoFail)
    }
}

/// HKDF-based key/iv derivation for AEAD from TLS secrets (RFC 9001 compliant)
pub fn derive_key_iv(secret: &[u8]) -> ([u8; 32], [u8; 12]) {
    let key_vec = crate::crypto::kdf::derive_pkt_key(secret, 32);
    let iv_vec = crate::crypto::kdf::derive_pkt_iv(secret, 12);
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_vec[..32]);
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&iv_vec[..12]);
    (key, iv)
}

/// Derive Initial secrets from destination connection ID (RFC 9001 compliant)
pub fn derive_initial_secrets(dcid: &[u8], version: u32) -> (Vec<u8>, Vec<u8>) {
    let initial_secret = crate::crypto::kdf::derive_initial_secret(dcid, version);
    let client_secret = crate::crypto::kdf::derive_client_initial_secret(&initial_secret);
    let server_secret = crate::crypto::kdf::derive_server_initial_secret(&initial_secret);
    (client_secret, server_secret)
}

/// Apply header protection mask (for encryption)
pub fn apply_hp(
    first: u8,
    pn: &mut [u8],
    sample: &[u8],
    is_long: bool,
    hp: &dyn HeaderProtector,
) -> (u8, usize) {
    let mask = hp.new_mask(sample);
    let first_new = if is_long { first ^ (mask[0] & 0x0f) } else { first ^ (mask[0] & 0x1f) };
    // PN length is encoded in the low 2 bits of the (possibly masked) first byte, plus 1
    let pn_len = ((first_new & PKT_NUM_MASK) as usize) + 1;
    for i in 0..pn_len.min(4) {
        pn[i] ^= mask[i + 1];
    }
    (first_new, pn_len)
}

/// Remove header protection mask (for decryption)
pub fn remove_hp(
    buf: &mut [u8],
    hp: &dyn HeaderProtector,
    pn_offset: usize,
) -> Result<(u8, usize), ConnectionError> {
    if buf.len() < pn_offset + 4 + 16 {
        return Err(ConnectionError::InvalidPacket);
    }

    // Sample starts 4 bytes after the packet number offset
    let sample_offset = pn_offset + 4;
    let sample = &buf[sample_offset..sample_offset + 16];

    // Generate mask
    let mask = hp.new_mask(sample);

    // Check if it's a long header packet
    let first = buf[0];
    let is_long = (first & FORM_BIT) != 0;

    // Unmask the first byte to get packet number length
    let first_unmasked = if is_long { first ^ (mask[0] & 0x0f) } else { first ^ (mask[0] & 0x1f) };

    // Get packet number length (encoded in low 2 bits + 1)
    let pn_len = ((first_unmasked & PKT_NUM_MASK) as usize) + 1;

    // Unmask the packet number
    for i in 0..pn_len.min(4) {
        if pn_offset + i < buf.len() {
            buf[pn_offset + i] ^= mask[i + 1];
        }
    }

    // Update the first byte
    buf[0] = first_unmasked;

    Ok((first_unmasked, pn_len))
}

/// Decrypt a QUIC packet payload (alternative implementation)
pub fn decrypt_payload(
    buf: &mut [u8],
    pn: u64,
    _pn_len: usize,
    hdr_len: usize,
    aead: &dyn crate::crypto::aead::AeadOpen,
) -> Result<usize, ConnectionError> {
    if buf.len() < hdr_len + 16 {
        // Need at least header + AEAD tag
        return Err(ConnectionError::InvalidPacket);
    }

    // Split buffer to avoid borrowing conflicts
    let (aad_buf, payload_buf) = buf.split_at_mut(hdr_len);
    let aad = &aad_buf[..hdr_len];

    // Decrypt in-place
    let _payload_len = payload_buf.len();
    let plaintext_len = aead.open_with_u64_counter(pn, aad, payload_buf)?;

    Ok(hdr_len + plaintext_len)
}

/// Encrypt a QUIC packet payload
pub fn encrypt_packet(
    buf: &mut [u8],
    payload_len: usize,
    pn: u64,
    hdr_len: usize,
    aead: &dyn crate::crypto::aead::AeadSeal,
) -> Result<usize, ConnectionError> {
    // Zero-copy AAD: copy header to stack buffer (eliminates heap allocation)
    const MAX_AAD_STACK: usize = 64;
    let mut aad_stack = [0u8; MAX_AAD_STACK];
    let aad: &[u8] = if hdr_len <= MAX_AAD_STACK {
        aad_stack[..hdr_len].copy_from_slice(&buf[..hdr_len]);
        &aad_stack[..hdr_len]
    } else {
        return Err(ConnectionError::InvalidPacket);
    };

    // Encrypt in-place
    let ciphertext_len = aead.seal_with_u64_counter(pn, aad, buf, hdr_len + payload_len, None)?;

    Ok(ciphertext_len)
}

/// CryptoStream manages CRYPTO frame data for each encryption level
#[derive(Default)]
pub struct CryptoStream {
    /// Send buffer for outgoing CRYPTO frames
    send_buf: Vec<u8>,
    /// Current send offset
    send_off: u64,
    /// Receive buffer for incoming CRYPTO frames (may arrive out of order)
    recv_buf: std::collections::BTreeMap<u64, Vec<u8>>,
    /// Next expected receive offset
    recv_off: u64,
    /// Maximum receive offset seen
    recv_max: u64,
}

impl CryptoStream {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue data to be sent in CRYPTO frames
    pub fn send(&mut self, data: &[u8]) {
        self.send_buf.extend_from_slice(data);
    }

    /// Get next CRYPTO frame to send (up to max_len bytes)
    pub fn next_crypto_frame(&mut self, max_len: usize) -> Option<(u64, Vec<u8>)> {
        if self.send_buf.is_empty() {
            return None;
        }

        let len = max_len.min(self.send_buf.len());
        let offset = self.send_off;
        let data = self.send_buf.drain(..len).collect();
        self.send_off += len as u64;

        Some((offset, data))
    }

    /// Receive a CRYPTO frame (may be out of order)
    pub fn recv(&mut self, offset: u64, data: Vec<u8>) -> Result<(), ConnectionError> {
        if offset + data.len() as u64 > self.recv_max + 65536 {
            // Reject data too far ahead
            return Err(ConnectionError::FlowControl);
        }

        self.recv_max = self.recv_max.max(offset + data.len() as u64);
        self.recv_buf.insert(offset, data);
        Ok(())
    }

    /// Read available contiguous data from receive buffer
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let mut written = 0;

        while written < buf.len() {
            if let Some(data) = self.recv_buf.remove(&self.recv_off) {
                let to_copy = (buf.len() - written).min(data.len());
                buf[written..written + to_copy].copy_from_slice(&data[..to_copy]);
                written += to_copy;
                self.recv_off += to_copy as u64;

                // If we didn't consume all data, put remainder back
                if to_copy < data.len() {
                    self.recv_buf.insert(self.recv_off, data[to_copy..].to_vec());
                    break;
                }
            } else {
                break;
            }
        }

        written
    }

    /// Check if there's data ready to read
    pub fn has_data(&self) -> bool {
        self.recv_buf.contains_key(&self.recv_off)
    }

    pub fn reset(&mut self) {
        self.send_buf.clear();
        self.send_off = 0;
        self.recv_buf.clear();
        self.recv_off = 0;
        self.recv_max = 0;
    }
}

// Internal TLS Cover cipher helper (ChaCha20-Poly1305 or AES-128-GCM)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsCoverCipherKind {
    ChaCha20Poly1305,
    Aes128Gcm,
}

pub(crate) enum TlsCoverCipher {
    ChaCha(ChaCha20Poly1305),
    AesGcm(AesGcm128),
}

impl TlsCoverCipher {
    #[inline(always)]
    fn seal(
        &self,
        counter: u64,
        aad: &[u8],
        buffer: &mut [u8],
        plaintext_len: usize,
    ) -> Result<usize, ConnectionError> {
        match self {
            TlsCoverCipher::ChaCha(cipher) => {
                crate::crypto::aead_legacy::AeadSeal::seal_with_u64_counter(
                    cipher,
                    counter,
                    aad,
                    buffer,
                    plaintext_len,
                    None,
                )
            }
            TlsCoverCipher::AesGcm(cipher) => tls_aead::AeadSeal::seal_with_u64_counter(
                cipher,
                counter,
                aad,
                buffer,
                plaintext_len,
                None,
            ),
        }
    }

    #[inline(always)]
    fn open(&self, counter: u64, aad: &[u8], buffer: &mut [u8]) -> Result<usize, ConnectionError> {
        match self {
            TlsCoverCipher::ChaCha(cipher) => {
                crate::crypto::aead_legacy::AeadOpen::open_with_u64_counter(
                    cipher, counter, aad, buffer,
                )
            }
            TlsCoverCipher::AesGcm(cipher) => {
                tls_aead::AeadOpen::open_with_u64_counter(cipher, counter, aad, buffer)
            }
        }
    }

    #[inline(always)]
    pub(crate) fn kind(&self) -> TlsCoverCipherKind {
        match self {
            TlsCoverCipher::ChaCha(_) => TlsCoverCipherKind::ChaCha20Poly1305,
            TlsCoverCipher::AesGcm(_) => TlsCoverCipherKind::Aes128Gcm,
        }
    }
}

// --- Crypto context with direct AEGIS integration ---
#[derive(Default)]
pub struct CryptoContext {
    // Initial/Handshake must use AES-GCM for compatibility
    pub open_initial: Option<Box<dyn crate::crypto::aead::AeadOpen + Send + Sync>>,
    pub open_handshake: Option<Box<dyn crate::crypto::aead::AeadOpen + Send + Sync>>,
    // 0-RTT and 1-RTT use CPU-selected AEAD (AEGIS-128L when hardware AES is available, otherwise MORUS).
    pub open_0rtt: Option<Box<dyn crate::crypto::aead::AeadOpen + Send + Sync>>,
    pub open_1rtt: Option<Box<dyn crate::crypto::aead::AeadOpen + Send + Sync>>,
    pub seal_initial: Option<Box<dyn crate::crypto::aead::AeadSeal + Send + Sync>>,
    pub seal_handshake: Option<Box<dyn crate::crypto::aead::AeadSeal + Send + Sync>>,
    pub seal_0rtt: Option<Box<dyn crate::crypto::aead::AeadSeal + Send + Sync>>,
    pub seal_1rtt: Option<Box<dyn crate::crypto::aead::AeadSeal + Send + Sync>>,
    pub hp_initial: Option<Box<dyn HeaderProtector + Send + Sync>>,
    pub hp_handshake: Option<Box<dyn HeaderProtector + Send + Sync>>,
    pub hp_0rtt: Option<Box<dyn HeaderProtector + Send + Sync>>,
    pub hp_1rtt: Option<Box<dyn HeaderProtector + Send + Sync>>,
    // Separate header protection keys for inbound packets.
    // QUIC derives distinct keys per direction; using a single HP key breaks interop.
    pub hp_initial_open: Option<Box<dyn HeaderProtector + Send + Sync>>,
    pub hp_handshake_open: Option<Box<dyn HeaderProtector + Send + Sync>>,
    pub hp_0rtt_open: Option<Box<dyn HeaderProtector + Send + Sync>>,
    pub hp_1rtt_open: Option<Box<dyn HeaderProtector + Send + Sync>>,
    pub read_secret_1rtt: Option<Vec<u8>>,
    pub write_secret_1rtt: Option<Vec<u8>>,
    pub zero_rtt_enabled: bool,
    seal_tls_cover: Option<TlsCoverCipher>,
    open_tls_cover: Option<TlsCoverCipher>,
    pub tls_cover_write_seq: u64,
    pub tls_cover_read_seq: u64,
    // CryptoStreams for each encryption level
    pub crypto_initial: CryptoStream,
    pub crypto_0rtt: CryptoStream,
    pub crypto_handshake: CryptoStream,
    pub crypto_application: CryptoStream,
}

impl CryptoContext {
    pub fn install_0rtt_keys(&mut self, read_secret: &[u8], write_secret: &[u8]) {
        self.zero_rtt_enabled = true;
        let (read_key, read_iv) = derive_key_iv(read_secret);
        let (write_key, write_iv) = derive_key_iv(write_secret);
        let (_, open) = select_data_aead(&read_key, &read_iv);
        let (seal, _) = select_data_aead(&write_key, &write_iv);
        self.open_0rtt = Some(open);
        self.seal_0rtt = Some(seal);
        self.hp_0rtt = Some(Box::new(crate::crypto::aead::AesHp::new(write_secret)));
    }
}

impl CryptoContext {
    pub fn set_zero_rtt_enabled(&mut self, enabled: bool) {
        self.zero_rtt_enabled = enabled;
    }

    /// Install ChaCha20-Poly1305 specifically for TLS Cover traffic.
    pub fn install_tls_cover_chacha(&mut self, key: &[u8; 32], iv: &[u8; 12]) {
        self.seal_tls_cover = Some(TlsCoverCipher::ChaCha(ChaCha20Poly1305::new(key, iv)));
        self.open_tls_cover = Some(TlsCoverCipher::ChaCha(ChaCha20Poly1305::new(key, iv)));
        self.tls_cover_write_seq = 0;
        self.tls_cover_read_seq = 0;
    }

    /// Install AES-128-GCM specifically for TLS Cover traffic.
    pub fn install_tls_cover_aes_gcm(&mut self, key: &[u8; 16], iv: &[u8; 12]) {
        self.seal_tls_cover = Some(TlsCoverCipher::AesGcm(AesGcm128::new(key, iv)));
        self.open_tls_cover = Some(TlsCoverCipher::AesGcm(AesGcm128::new(key, iv)));
        self.tls_cover_write_seq = 0;
        self.tls_cover_read_seq = 0;
    }

    #[inline]
    pub fn tls_cover_cipher_kind(&self) -> Option<TlsCoverCipherKind> {
        self.seal_tls_cover.as_ref().map(|cipher| cipher.kind())
    }

    /// Encrypt a TLS Cover record using the configured TLS Cover cipher.
    pub fn encrypt_tls_cover_record(
        &mut self,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ConnectionError> {
        let cipher = self.seal_tls_cover.as_ref().ok_or(ConnectionError::CryptoFail)?;

        let seq = self.tls_cover_write_seq;
        self.tls_cover_write_seq = self.tls_cover_write_seq.wrapping_add(1);

        let mut buffer = Vec::with_capacity(plaintext.len() + 16);
        buffer.extend_from_slice(plaintext);
        let pt_len = plaintext.len();
        buffer.resize(pt_len + 16, 0);

        let result = cipher.seal(seq, aad, buffer.as_mut_slice(), pt_len);
        match result {
            Ok(_) => match cipher {
                TlsCoverCipher::ChaCha(_) => telemetry::FAKETLS_CHACHA_OPS.inc(),
                TlsCoverCipher::AesGcm(_) => telemetry::FAKETLS_AES_GCM_OPS.inc(),
            },
            Err(_) => telemetry::FAKETLS_CIPHER_FAILURES.inc(),
        }
        result?;

        Ok(buffer)
    }

    /// Decrypt a TLS Cover record using the configured TLS Cover cipher.
    pub fn decrypt_tls_cover_record(
        &mut self,
        aad: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, ConnectionError> {
        let cipher = self.open_tls_cover.as_ref().ok_or(ConnectionError::CryptoFail)?;

        let seq = self.tls_cover_read_seq;
        self.tls_cover_read_seq = self.tls_cover_read_seq.wrapping_add(1);

        cipher.open(seq, aad, ciphertext).inspect_err(|_| telemetry::FAKETLS_CIPHER_FAILURES.inc())
    }

    /// Install AES-GCM for Initial packets (compatibility path).
    /// QUIC initial keys are direction-specific, so we accept read/write secrets separately.
    pub fn install_aes_gcm_initial(&mut self, read_secret: &[u8], write_secret: &[u8]) {
        let (rkey, riv) = derive_key_iv(read_secret);
        let (wkey, wiv) = derive_key_iv(write_secret);
        let mut k16 = [0u8; 16];
        k16.copy_from_slice(&wkey[..16]);
        self.seal_initial = Some(Box::new(AesGcm128::new(&k16, &wiv)));
        k16.copy_from_slice(&rkey[..16]);
        self.open_initial = Some(Box::new(AesGcm128::new(&k16, &riv)));
        // HP can be installed later when header protection keys are derived
    }

    /// Install AES-GCM for Handshake packets (compatibility path)
    pub fn install_aes_gcm_handshake(&mut self, secret: &[u8]) {
        let (key, iv) = derive_key_iv(secret);
        let mut k16 = [0u8; 16];
        k16.copy_from_slice(&key[..16]);
        let seal = AesGcm128::new(&k16, &iv);
        let open = AesGcm128::new(&k16, &iv);
        self.seal_handshake = Some(Box::new(seal));
        self.open_handshake = Some(Box::new(open));
        // HP can be installed later when header protection keys are derived
    }

    /// Install AES-based Header Protection for Initial packets.
    /// QUIC header protection is direction-specific, so we accept read/write secrets separately.
    pub fn install_hp_initial(&mut self, read_secret: &[u8], write_secret: &[u8]) {
        let hp_key_w = derive_hp_key(write_secret);
        let hp_key_r = derive_hp_key(read_secret);
        self.hp_initial = Some(Box::new(crate::crypto::aead::AesHp::new(&hp_key_w)));
        self.hp_initial_open = Some(Box::new(crate::crypto::aead::AesHp::new(&hp_key_r)));
    }

    /// Install AES-based Header Protection for Handshake packets
    pub fn install_hp_handshake(&mut self, secret: &[u8]) {
        let hp_key = derive_hp_key(secret);
        self.hp_handshake = Some(Box::new(crate::crypto::aead::AesHp::new(&hp_key)));
    }

    /// RFC 9001 compliant 1-RTT key update
    pub fn key_update_1rtt(&mut self) {
        if let Some(cur) = self.write_secret_1rtt.clone() {
            let next = crate::crypto::kdf::derive_next_secret(&cur);
            self.write_secret_1rtt = Some(next.clone());
            let (key, iv) = derive_key_iv(&next);
            let (seal, _open) = select_data_aead(&key, &iv);
            self.seal_1rtt = Some(seal);
            self.hp_1rtt = Some(Box::new(crate::crypto::aead::AesHp::new(&next)));
        }
        if let Some(cur) = self.read_secret_1rtt.clone() {
            let next = crate::crypto::kdf::derive_next_secret(&cur);
            self.read_secret_1rtt = Some(next.clone());
            let (key, iv) = derive_key_iv(&next);
            let (_seal, open) = select_data_aead(&key, &iv);
            self.open_1rtt = Some(open);
            self.hp_1rtt = Some(Box::new(crate::crypto::aead::AesHp::new(&next)));
        }
    }
}

// Install AEAD/HP from TLS key schedule.
impl crate::crypto::aead::KeyScheduleHooks for CryptoContext {
    fn set_read_secret(
        &mut self,
        level: crate::crypto::aead::Level,
        alg: crate::crypto::aead::Algorithm,
        secret: &[u8],
    ) {
        let (key, iv) = derive_key_iv(secret);
        match level {
            crate::crypto::aead::Level::Initial => {
                match alg {
                    crate::crypto::aead::Algorithm::AES128_GCM => {
                        let mut k16 = [0u8; 16];
                        k16.copy_from_slice(&key[..16]);
                        self.open_initial = Some(Box::new(AesGcm128::new(&k16, &iv)));
                    }
                }
                self.hp_initial = Some(Box::new(crate::crypto::aead::AesHp::new(secret)));
            }
            crate::crypto::aead::Level::Handshake => {
                match alg {
                    crate::crypto::aead::Algorithm::AES128_GCM => {
                        let mut k16 = [0u8; 16];
                        k16.copy_from_slice(&key[..16]);
                        self.open_handshake = Some(Box::new(AesGcm128::new(&k16, &iv)));
                    }
                }
                self.hp_handshake = Some(Box::new(crate::crypto::aead::AesHp::new(secret)));
            }
            crate::crypto::aead::Level::ZeroRTT => {
                if self.zero_rtt_enabled {
                    let (_, open) = select_data_aead(&key, &iv);
                    self.open_0rtt = Some(open);
                    self.hp_0rtt = Some(Box::new(crate::crypto::aead::AesHp::new(secret)));
                }
            }
            crate::crypto::aead::Level::OneRTT => {
                // Install 1-RTT read secret with CPU-based AEAD selection
                self.read_secret_1rtt = Some(secret.to_vec());
                let (_seal, open) = select_data_aead(&key, &iv);
                self.open_1rtt = Some(open);
                self.hp_1rtt = Some(Box::new(crate::crypto::aead::AesHp::new(secret)));
            }
        }
    }
    fn set_write_secret(
        &mut self,
        level: crate::crypto::aead::Level,
        alg: crate::crypto::aead::Algorithm,
        secret: &[u8],
    ) {
        let (key, iv) = derive_key_iv(secret);
        match level {
            crate::crypto::aead::Level::Initial => {
                match alg {
                    crate::crypto::aead::Algorithm::AES128_GCM => {
                        let mut k16 = [0u8; 16];
                        k16.copy_from_slice(&key[..16]);
                        self.seal_initial = Some(Box::new(AesGcm128::new(&k16, &iv)));
                    }
                }
                self.hp_initial = Some(Box::new(crate::crypto::aead::AesHp::new(secret)));
            }
            crate::crypto::aead::Level::Handshake => {
                match alg {
                    crate::crypto::aead::Algorithm::AES128_GCM => {
                        let mut k16 = [0u8; 16];
                        k16.copy_from_slice(&key[..16]);
                        self.seal_handshake = Some(Box::new(AesGcm128::new(&k16, &iv)));
                    }
                }
                self.hp_handshake = Some(Box::new(crate::crypto::aead::AesHp::new(secret)));
            }
            crate::crypto::aead::Level::ZeroRTT => {
                if self.zero_rtt_enabled {
                    let (seal, _) = select_data_aead(&key, &iv);
                    self.seal_0rtt = Some(seal);
                    self.hp_0rtt = Some(Box::new(crate::crypto::aead::AesHp::new(secret)));
                }
            }
            crate::crypto::aead::Level::OneRTT => {
                // Install 1-RTT write secret with CPU-based AEAD selection
                self.write_secret_1rtt = Some(secret.to_vec());
                let (seal, _open) = select_data_aead(&key, &iv);
                self.seal_1rtt = Some(seal);
                self.hp_1rtt = Some(Box::new(crate::crypto::aead::AesHp::new(secret)));
            }
        }
    }
}
