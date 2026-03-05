use std::collections::BTreeMap;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::ops::{Index, IndexMut};
use std::sync::Arc;
use std::time::{Duration, Instant};

// pub mod accelerate; // consolidated into crate::accelerate::transport_io
pub mod batch;
pub mod config;
pub mod connection;
pub mod frames;
pub mod h3;
pub mod packet;
pub mod pn;
pub mod recovery;
pub mod udpfast;
#[cfg(all(target_os = "linux", feature = "uring_sys"))]
pub mod uring;
pub mod xdp;

pub use crate::accelerate::transport as accel;
pub use batch::BatchProcessor;
pub use config::Config;
#[cfg(feature = "stream_ring_buffer")]
pub use connection::StreamRingBuffer;
pub use connection::{Connection, PathEvent};
pub use pn::{cid, pnspace, rand, range_buf, ranges, varint};
#[cfg(target_os = "linux")]
use std::sync::atomic::Ordering;
// use crate::crypto::aead::{AeadOpen, AeadSeal}; // use fully-qualified paths below
// use crate::transport::packet::HeaderProtector; // local trait defined below
// use crate::native;

// FEC Control Delta struct for managing FEC parameter changes
#[derive(Debug, Clone, Copy, Default)]
pub struct FecControlDelta {
    pub stream_every: Option<usize>,
    pub redundancy_ppm: Option<u32>,
    pub force_streaming: bool,
}

// ============================================================================
// Transport configuration and types
// ============================================================================

/// Maximum batch size for sendmmsg/recvmmsg - process 64 packets at once!
pub const MAX_BATCH_SIZE: usize = 64;

/// Optimal packet batch size based on L2 cache
pub const OPTIMAL_BATCH_SIZE: usize = 32;

// Core Constants

/// QUIC protocol version (v1)
pub const PROTOCOL_VERSION: u32 = 0x00000001;

/// Maximum connection ID length
pub const MAX_CONN_ID_LEN: usize = 20;
pub const MAX_PKT_NUM_LEN: usize = 4;

// Telemetry counters
// static BATCH_SENDS: AtomicUsize = AtomicUsize::new(0);
// static BATCH_RECVS: AtomicUsize = AtomicUsize::new(0);
// static PACKETS_BATCHED: AtomicUsize = AtomicUsize::new(0);

// /// Ultra-fast batch packet processor with network acceleration
// pub struct BatchProcessor {
//     /// Preallocated buffers for zero-copy batch operations
//     send_buffers: Vec<Vec<u8>>,
//     recv_buffers: Vec<Vec<u8>>,
//     /// IO vectors for sendmmsg/recvmmsg
//     #[cfg(target_os = "linux")]
//     send_msgs: Vec<libc::mmsghdr>,
//     #[cfg(target_os = "linux")]
//     recv_msgs: Vec<libc::mmsghdr>,
//     /// Batch size based on CPU features
//     batch_size: usize,
//     /// Network acceleration features
//     gso_config: Option<accelerate::UdpGsoConfig>,
//     zero_copy: Option<accelerate::ZeroCopySocket>,
//     busy_poll: Option<accelerate::BusyPollSocket>,
// }
//
// impl BatchProcessor {
//     pub fn new() -> Self {
//         let features = FeatureDetector::instance();
//
//         // Determine optimal batch size based on CPU
//         let batch_size = if features.has_avx512() {
//             MAX_BATCH_SIZE  // 64 packets with AVX-512
//         } else if features.has_avx2() {
//             OPTIMAL_BATCH_SIZE  // 32 packets with AVX2
//         } else {
//             16  // Conservative for older CPUs
//         };
//
//         log::info!("BatchProcessor: {} packet batches", batch_size);
//
//         // Preallocate buffers
//         let mut send_buffers = Vec::with_capacity(batch_size);
//         let mut recv_buffers = Vec::with_capacity(batch_size);
//
//         for _ in 0..batch_size {
//             send_buffers.push(vec![0u8; 1500]);  // MTU size
//             recv_buffers.push(vec![0u8; 1500]);
//         }
//
//         #[cfg(target_os = "linux")]
//         let (send_msgs, recv_msgs) = Self::init_mmsg_headers(batch_size);
//
//         Self {
//             send_buffers,
//             recv_buffers,
//             #[cfg(target_os = "linux")]
//             send_msgs,
//             #[cfg(target_os = "linux")]
//             recv_msgs,
//             batch_size,
//             gso_config: None,
//             zero_copy: None,
//             busy_poll: None,
//         }
//     }
//
//     #[cfg(target_os = "linux")]
//     fn init_mmsg_headers(batch_size: usize) -> (Vec<libc::mmsghdr>, Vec<libc::mmsghdr>) {
//         let mut send_msgs = Vec::with_capacity(batch_size);
//         let mut recv_msgs = Vec::with_capacity(batch_size);
//
//         for _ in 0..batch_size {
//             send_msgs.push(unsafe { std::mem::zeroed() });
//             recv_msgs.push(unsafe { std::mem::zeroed() });
//         }
//
//         (send_msgs, recv_msgs)
//     }
//
//     /// Initialize network acceleration for a socket
//     pub fn init_acceleration(&mut self, socket: &UdpSocket) -> std::io::Result<()> {
//         // Try to enable GSO
//         self.gso_config = accelerate::UdpGsoConfig::enable(socket).ok();
//
//         // Try to enable zero-copy
//         if let Ok(sock_clone) = socket.try_clone() {
//             self.zero_copy = accelerate::ZeroCopySocket::new(sock_clone).ok();
//         }
//
//         // Enable busy polling for low latency if configured
//         if std::env::var("QUICFUSCATE_BUSY_POLL").is_ok() {
//             if let Ok(sock_clone) = socket.try_clone() {
//                 self.busy_poll = accelerate::BusyPollSocket::new(sock_clone, 50).ok();
//             }
//         }
//
//         log::info!("Network acceleration initialized:");
//         log::info!("  GSO: {}", self.gso_config.as_ref().map_or(false, |g| g.enabled));
//         log::info!("  Zero-copy: {}", self.zero_copy.is_some());
//         log::info!("  Busy-poll: {}", self.busy_poll.is_some());
//
//         Ok(())
//     }
//
//     /// Batch send packets with sendmmsg and acceleration (Linux)
//     #[cfg(target_os = "linux")]
//     pub fn batch_send(&mut self, socket: i32, packets: &[(&[u8], SocketAddr)]) -> std::io::Result<usize> {
//         // Try accelerated batch send first
//         #[cfg(target_os = "linux")]
//         {
//             // Create a temporary UdpSocket from raw fd for accelerate API
//             use std::os::unix::io::FromRawFd;
//             let sock = unsafe { UdpSocket::from_raw_fd(socket) };
//
//             // Use sendmmsg through accelerate
//             let result = accelerate::send_batch(&sock, packets);
//
//             // Release socket without closing fd
//             let _ = sock.into_raw_fd();
//
//             if let Ok(sent) = result {
//                 BATCH_SENDS.fetch_add(1, Ordering::Relaxed);
//                 PACKETS_BATCHED.fetch_add(sent, Ordering::Relaxed);
//                 crate::optimize::telemetry::ZERO_COPY_SENDS.inc_by(sent as u64);
//                 return Ok(sent);
//             }
//         }
//
//         // Fallback to original implementation
//         use std::mem;
//         use std::ptr;
//
//         let batch_count = packets.len().min(self.batch_size);
//         if batch_count == 0 {
//             return Ok(0);
//         }
//
//         // Prepare messages with SIMD copy
//         for (i, (data, addr)) in packets.iter().take(batch_count).enumerate() {
//             // Use SIMD memcpy for packet data
//             let len = data.len().min(self.send_buffers[i].len());
//             SimdDispatch::memcpy_fast(&mut self.send_buffers[i][..len], data);
//
//             // Setup message header
//             let mut sa: libc::sockaddr_storage = unsafe { mem::zeroed() };
//             let sa_len = match addr {
//                 SocketAddr::V4(v4) => {
//                     let sa4 = &mut sa as *mut _ as *mut libc::sockaddr_in;
//                     unsafe {
//                         (*sa4).sin_family = libc::AF_INET as u16;
//                         (*sa4).sin_port = v4.port().to_be();
//                         (*sa4).sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
//                     }
//                     mem::size_of::<libc::sockaddr_in>()
//                 }
//                 SocketAddr::V6(v6) => {
//                     let sa6 = &mut sa as *mut _ as *mut libc::sockaddr_in6;
//                     unsafe {
//                         (*sa6).sin6_family = libc::AF_INET6 as u16;
//                         (*sa6).sin6_port = v6.port().to_be();
//                         (*sa6).sin6_addr.s6_addr = v6.ip().octets();
//                         (*sa6).sin6_flowinfo = v6.flowinfo();
//                         (*sa6).sin6_scope_id = v6.scope_id();
//                     }
//                     mem::size_of::<libc::sockaddr_in6>()
//                 }
//             };
//
//             // Setup iovec
//             let mut iov = libc::iovec {
//                 iov_base: self.send_buffers[i].as_mut_ptr() as *mut _,
//                 iov_len: len,
//             };
//
//             // Setup mmsghdr
//             self.send_msgs[i] = libc::mmsghdr {
//                 msg_hdr: libc::msghdr {
//                     msg_name: &mut sa as *mut _ as *mut _,
//                     msg_namelen: sa_len as u32,
//                     msg_iov: &mut iov,
//                     msg_iovlen: 1,
//                     msg_control: ptr::null_mut(),
//                     msg_controllen: 0,
//                     msg_flags: 0,
//                 },
//                 msg_len: 0,
//             };
//         }
//
//         // Send all packets in one syscall (non-blocking)!
//         let sent = unsafe {
//             libc::sendmmsg(
//                 socket,
//                 self.send_msgs.as_mut_ptr(),
//                 batch_count as u32,
//                 libc::MSG_DONTWAIT,
//             )
//         };
//
//         if sent < 0 {
//             return Err(std::io::Error::last_os_error());
//         }
//
//         BATCH_SENDS.fetch_add(1, Ordering::Relaxed);
//         PACKETS_BATCHED.fetch_add(sent as usize, Ordering::Relaxed);
//         crate::optimize::telemetry::ZERO_COPY_SENDS.inc_by(sent as u64);
//
//         Ok(sent as usize)
//     }
//
//     /// Batch receive packets with recvmmsg (Linux)
//     #[cfg(target_os = "linux")]
//     pub fn batch_recv(&mut self, socket: i32, timeout: Option<Duration>) -> std::io::Result<Vec<(Vec<u8>, SocketAddr)>> {
//         use std::mem;
//
//         let mut results = Vec::new();
//
//         // Setup timeout
//         let ts = timeout.map(|d| libc::timespec {
//             tv_sec: d.as_secs() as i64,
//             tv_nsec: d.subsec_nanos() as i64,
//         });
//
//         // Setup receive messages
//         for i in 0..self.batch_size {
//             let mut sa: libc::sockaddr_storage = unsafe { mem::zeroed() };
//
//             let mut iov = libc::iovec {
//                 iov_base: self.recv_buffers[i].as_mut_ptr() as *mut _,
//                 iov_len: self.recv_buffers[i].len(),
//             };
//
//             self.recv_msgs[i] = libc::mmsghdr {
//                 msg_hdr: libc::msghdr {
//                     msg_name: &mut sa as *mut _ as *mut _,
//                     msg_namelen: mem::size_of::<libc::sockaddr_storage>() as u32,
//                     msg_iov: &mut iov,
//                     msg_iovlen: 1,
//                     msg_control: std::ptr::null_mut(),
//                     msg_controllen: 0,
//                     msg_flags: 0,
//                 },
//                 msg_len: 0,
//             };
//         }
//
//         // Receive all packets in one syscall!
//         let received = unsafe {
//             libc::recvmmsg(
//                 socket,
//                 self.recv_msgs.as_mut_ptr(),
//                 self.batch_size as u32,
//                 libc::MSG_DONTWAIT,
//                 ts.as_ref().map_or(std::ptr::null(), |t| t as *const _),
//             )
//         };
//
//         if received < 0 {
//             let err = std::io::Error::last_os_error();
//             if err.kind() == std::io::ErrorKind::WouldBlock {
//                 return Ok(results);
//             }
//             return Err(err);
//         }
//
//         // Process received packets
//         for i in 0..received as usize {
//             let len = self.recv_msgs[i].msg_len as usize;
//             if len > 0 {
//                 let mut data = vec![0u8; len];
//                 // Use SIMD copy
//                 SimdDispatch::memcpy_fast(&mut data, &self.recv_buffers[i][..len]);
//
//                 // Parse address
//                 let addr = unsafe {
//                     let sa = self.recv_msgs[i].msg_hdr.msg_name as *const libc::sockaddr_storage;
//                     match (*sa).ss_family as i32 {
//                         libc::AF_INET => {
//                             let sa4 = sa as *const libc::sockaddr_in;
//                             SocketAddr::V4(std::net::SocketAddrV4::new(
//                                 std::net::Ipv4Addr::from((*sa4).sin_addr.s_addr.to_ne_bytes()),
//                                 (*sa4).sin_port.to_be(),
//                             ))
//                         }
//                         libc::AF_INET6 => {
//                             let sa6 = sa as *const libc::sockaddr_in6;
//                             SocketAddr::V6(std::net::SocketAddrV6::new(
//                                 std::net::Ipv6Addr::from((*sa6).sin6_addr.s6_addr),
//                                 (*sa6).sin6_port.to_be(),
//                                 (*sa6).sin6_flowinfo,
//                                 (*sa6).sin6_scope_id,
//                             ))
//                         }
//                         _ => continue,
//                     }
//                 };
//
//                 results.push((data, addr));
//             }
//         }
//
//         BATCH_RECVS.fetch_add(1, Ordering::Relaxed);
//         PACKETS_BATCHED.fetch_add(received as usize, Ordering::Relaxed);
//         crate::optimize::telemetry::ZERO_COPY_RECVS.inc_by(received as u64);
//
//         Ok(results)
//     }
//
//     /// Fallback for non-Linux systems
//     #[cfg(not(target_os = "linux"))]
//     pub fn batch_send(&mut self, _socket: i32, packets: &[(&[u8], SocketAddr)]) -> std::io::Result<usize> {
//         // Fallback to individual sends
//         log::debug!("Batch send not available on this platform");
//         Ok(packets.len())
//     }
//
//     #[cfg(not(target_os = "linux"))]
//     pub fn batch_recv(&mut self, _socket: i32, _timeout: Option<Duration>) -> std::io::Result<Vec<(Vec<u8>, SocketAddr)>> {
//         // Fallback to individual receives
//         log::debug!("Batch recv not available on this platform");
//         Ok(Vec::new())
//     }
// }
//
// Packet type bits are defined within the `packet` module to avoid duplication

/// Congestion control choices supported by the in-tree QUIC transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CongestionControlAlgorithm {
    Reno,
    Cubic,
    BBR,
    Ledbat,
    BBR2,
    BBR3,
}

// Duplicate struct definition removed - using the one above

impl AsRef<[u8]> for ConnectionId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// =========================================================================
// Integration Hooks (no-op unless set)
// =========================================================================

/// Observer interface for low-cost transport telemetry callbacks.
/// Not used unless explicitly set; all hooks are optional at call sites.
pub trait TransportObserver: Send + Sync {
    /// Called when an ACK frame is emitted (ack_delay in quic units)
    fn on_ack(&self, _ack_delay: u64, _ranges: &[(u64, u64)]) {}
    /// Called when a packet is received (post-decrypt)
    fn on_packet_recv(&self, _pn: u64, _pt_len: usize) {}
    /// Called when ECN counters are updated
    fn on_ecn_update(&self, _ect0: u64, _ect1: u64, _ce: u64) {}
    /// Optional policy hook to tune transport parameters based on telemetry
    fn apply_policy(&self, _conn: &mut crate::transport::Connection) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_conn_with_padding(enabled: bool, strategy: u8, max_size: usize) -> Connection {
        let mut cfg = Config::new_with_version(PROTOCOL_VERSION).unwrap();
        cfg.set_stealth_padding(enabled, strategy, max_size);
        // dummy addresses
        let local: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let peer: std::net::SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let scid = [0u8; 8];
        packet::connect(None, &scid, local, peer, &mut cfg).unwrap()
    }

    #[test]
    fn test_padding_random_bounds() {
        let conn = make_conn_with_padding(true, 1, 64);
        for _ in 0..16 {
            let v = conn.compute_stealth_padding(100, 1000);
            assert!(v <= 64);
        }
    }

    #[test]
    fn test_padding_fixed_exact_max() {
        let conn = make_conn_with_padding(true, 2, 128);
        let v = conn.compute_stealth_padding(200, 1000);
        assert_eq!(v, 128);
        // Budget caps
        let v2 = conn.compute_stealth_padding(200, 10);
        assert_eq!(v2, 10);
    }

    #[test]
    fn test_padding_adaptive_to_next_64() {
        let conn = make_conn_with_padding(true, 3, 64);
        let v = conn.compute_stealth_padding(48, 1000);
        assert_eq!(v, 16); // 48 -> pad 16 to reach 64 boundary
                           // already aligned => 0
        let v2 = conn.compute_stealth_padding(128, 1000);
        assert_eq!(v2, 0);
        // cap by max
        let v3 = conn.compute_stealth_padding(1, 8);
        assert_eq!(v3, 8);
    }

    #[test]
    fn test_padding_browser_mimic_quarter_cap() {
        let conn = make_conn_with_padding(true, 4, 100);
        for _ in 0..16 {
            let v = conn.compute_stealth_padding(500, 1000);
            assert!(v <= 25);
        }
    }
}

// Additional integrated tests to exercise transport public API used by scripts
#[cfg(test)]
mod core_extra_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn addrs() -> (SocketAddr, SocketAddr) {
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 44330);
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 44331);
        (local, peer)
    }

    #[test]
    fn connection_state_establish_teardown() {
        let (local, peer) = addrs();
        let mut cfg = Config::new_with_version(1).expect("config");
        let scid = ConnectionId::from_ref(&[0; MAX_CONN_ID_LEN]);
        let conn = packet::connect(Some("example.com"), scid.as_ref(), local, peer, &mut cfg)
            .expect("connect");
        assert!(conn.max_send_udp_payload_size() > 0);
        assert!(!conn.is_closed());
    }

    #[test]
    fn stream_multiplex_send_two_streams() {
        let (local, peer) = addrs();
        let mut cfg = Config::new_with_version(1).expect("config");
        let scid = ConnectionId::from_ref(&[1; MAX_CONN_ID_LEN]);
        let mut conn =
            packet::connect(Some("sni"), scid.as_ref(), local, peer, &mut cfg).expect("connect");
        let s1 = 1u64;
        let s2 = 3u64;
        let n1 = conn.stream_send(s1, b"hello", false).expect("stream1 send");
        let n2 = conn.stream_send(s2, b"world", true).expect("stream2 send");
        assert!(n1 > 0 && n2 > 0);
    }

    #[test]
    fn flow_control_basic_caps() {
        let (local, peer) = addrs();
        let mut cfg = Config::new_with_version(1).expect("config");
        cfg.set_initial_max_stream_data_bidi_local(1024);
        cfg.set_initial_max_stream_data_bidi_remote(1024);
        let scid = ConnectionId::from_ref(&[2; MAX_CONN_ID_LEN]);
        let mut conn =
            packet::connect(None, scid.as_ref(), local, peer, &mut cfg).expect("connect");
        let s = 7u64;
        let data = vec![0u8; 256];
        let n = conn.stream_send(s, &data, false).expect("send within window");
        assert!(n > 0);
    }

    #[test]
    fn packet_pacing_toggle() {
        let (local, peer) = addrs();
        let mut cfg = Config::new_with_version(1).expect("config");
        let scid = ConnectionId::from_ref(&[3; MAX_CONN_ID_LEN]);
        let mut conn =
            packet::connect(None, scid.as_ref(), local, peer, &mut cfg).expect("connect");
        conn.set_external_pacing(true);
        assert!(conn.external_pacing_enabled());
    }

    #[test]
    fn loss_recovery_ack_threshold() {
        let (local, peer) = addrs();
        let mut cfg = Config::new_with_version(1).expect("config");
        let scid = ConnectionId::from_ref(&[4; MAX_CONN_ID_LEN]);
        let mut conn =
            packet::connect(None, scid.as_ref(), local, peer, &mut cfg).expect("connect");
        conn.set_ack_eliciting_threshold(4);
        assert!(conn.max_send_udp_payload_size() > 0);
    }

    #[test]
    fn connection_migration_path_id_increments() {
        let (local, peer) = addrs();
        let mut cfg = Config::new_with_version(1).expect("config");
        let scid = ConnectionId::from_ref(&[5; MAX_CONN_ID_LEN]);
        let mut conn =
            packet::connect(None, scid.as_ref(), local, peer, &mut cfg).expect("connect");
        let new_local = SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 55555);
        let new_peer = SocketAddr::new(Ipv4Addr::new(10, 0, 0, 2).into(), 44444);
        let new_id = conn.migrate(new_local, new_peer).expect("migrate");
        assert!(new_id > 0);
    }

    #[test]
    fn datagram_frames_basic_send_queue_len() {
        let (local, peer) = addrs();
        let mut cfg = Config::new_with_version(1).expect("config");
        cfg.enable_dgram(8, 8);
        let scid = ConnectionId::from_ref(&[6; MAX_CONN_ID_LEN]);
        let mut conn =
            packet::connect(None, scid.as_ref(), local, peer, &mut cfg).expect("connect");
        let buf = vec![0xAB; 32];
        conn.dgram_send(&buf).expect("queue dgram");
        assert!(conn.dgram_send_queue_len() > 0);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct ConnectionId(Vec<u8>);

/// Information about a received datagram (source / destination / timestamp)
#[derive(Debug, Clone, Copy)]
pub struct RecvInfo {
    pub from: SocketAddr,
    pub to: SocketAddr,
    // Keep extensible; add ECN / timestamp if needed
    pub ecn: Option<EcnMark>,
}

/// Information about a sent datagram
#[derive(Debug, Clone, Copy)]
pub struct SendInfo {
    pub from: SocketAddr,
    pub to: SocketAddr,
    pub at: Instant,
}

impl ConnectionId {
    /// Creates a ConnectionId from a borrowed slice (owned internally).
    pub fn from_ref(data: &[u8]) -> Self {
        ConnectionId(data.to_vec())
    }

    /// Creates a ConnectionId from a Vec.
    pub fn from_vec(data: Vec<u8>) -> Self {
        ConnectionId(data)
    }

    /// Returns true if the ID is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Converts into owned Vec<u8>.
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.clone()
    }
}

/// Minimal ConnectionIdSet to track active IDs.
pub const MIN_CLIENT_INITIAL_LEN: usize = 1200;

/// Initial window size
pub const INITIAL_WINDOW: usize = 14720;

#[derive(Debug)]
pub struct Stream {
    id: u64,
    #[cfg(not(feature = "stream_ring_buffer"))]
    send_buf: Vec<u8>,
    #[cfg(not(feature = "stream_ring_buffer"))]
    recv_buf: Vec<u8>,
    #[cfg(feature = "stream_ring_buffer")]
    send_ring: StreamRingBuffer,
    #[cfg(feature = "stream_ring_buffer")]
    recv_ring: StreamRingBuffer,
    send_fin: bool,
    recv_fin: bool,
    send_off: u64,
    /// Highest byte offset observed on the receive side (flow control accounting).
    recv_off: u64,
    /// Next contiguous byte offset available for the application to read.
    recv_next: u64,
    /// Final size of the stream once FIN is received (offset + data_len).
    recv_final_size: Option<u64>,
    /// Out-of-order fragments keyed by starting offset.
    recv_frags: BTreeMap<u64, Vec<u8>>,
    priority_urgency: u8,
    priority_incremental: bool,
    // Receive-side flow control (what we allow peer to send to us)
    max_stream_data_rx: u64,
    // Send-side flow control (what peer allows us to send to them)
    max_stream_data_tx: u64,
}

/// Frame overhead constants
pub const MAX_CRYPTO_OVERHEAD: usize = 8;
pub const MAX_DGRAM_OVERHEAD: usize = 2;
pub const MAX_STREAM_OVERHEAD: usize = 12;
pub const MAX_STREAM_SIZE: u64 = 1 << 62;

// ============================================================================
// Error Types
// ============================================================================

/// QUIC packet epoch
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Epoch {
    Initial = 0,
    Handshake = 1,
    Application = 2,
}

static EPOCHS: [Epoch; 3] = [Epoch::Initial, Epoch::Handshake, Epoch::Application];

impl Epoch {
    pub fn epochs(range: std::ops::RangeInclusive<Epoch>) -> &'static [Epoch] {
        &EPOCHS[*range.start() as usize..=*range.end() as usize]
    }

    pub const fn count() -> usize {
        3
    }
}

impl From<Epoch> for usize {
    fn from(e: Epoch) -> Self {
        e as usize
    }
}

impl<T> Index<Epoch> for [T] {
    type Output = T;
    fn index(&self, index: Epoch) -> &Self::Output {
        self.index(usize::from(index))
    }
}

impl<T> IndexMut<Epoch> for [T] {
    fn index_mut(&mut self, index: Epoch) -> &mut Self::Output {
        self.index_mut(usize::from(index))
    }
}

/// QUIC packet type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketType {
    Initial,
    Retry,
    Handshake,
    ZeroRTT,
    VersionNegotiation,
    Short,
}

/// ECN marking of received UDP datagrams
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcnMark {
    Ect0,
    Ect1,
    Ce,
}

impl PacketType {
    pub fn from_epoch(e: Epoch) -> PacketType {
        match e {
            Epoch::Initial => PacketType::Initial,
            Epoch::Handshake => PacketType::Handshake,
            Epoch::Application => PacketType::Short,
        }
    }

    pub fn to_epoch(self) -> Result<Epoch, Error> {
        match self {
            PacketType::Initial => Ok(Epoch::Initial),
            PacketType::ZeroRTT => Ok(Epoch::Application),
            PacketType::Handshake => Ok(Epoch::Handshake),
            PacketType::Short => Ok(Epoch::Application),
            _ => Err(Error::InvalidPacket),
        }
    }
}

/// QUIC packet header
#[derive(Clone, PartialEq, Eq)]
pub struct Header {
    pub ty: PacketType,
    pub version: u32,
    pub dcid: ConnectionId,
    pub scid: ConnectionId,
    pub pkt_num: u64,
    pub pkt_num_len: usize,
    pub token: Option<Vec<u8>>,
    pub versions: Option<Vec<u32>>,
    pub key_phase: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    /// Operation would block
    Done,
    /// FEC error
    Fec,
    /// Generic transport backend error
    Transport,

    /// Buffer is too short
    BufferTooShort,

    /// Unknown version
    UnknownVersion,

    /// Invalid frame
    InvalidFrame,

    /// Invalid packet
    InvalidPacket,

    /// Invalid state
    InvalidState,

    /// Invalid stream state
    InvalidStreamState,

    /// Invalid transport parameter
    InvalidTransportParam,

    /// Crypto error
    CryptoFail,

    /// TLS handshake error
    TlsFail,

    /// Flow control error
    FlowControl,

    /// Stream limit error
    StreamLimit,

    /// Stream stopped
    StreamStopped,

    /// Stream was reset by peer
    StreamReset(u64, u64),

    /// Final size error
    FinalSize,

    /// Connection ID limit error
    IdLimit,

    /// Out of identifiers
    OutOfIdentifiers,

    /// Key update error
    KeyUpdate,

    /// AEAD limit reached
    AeadLimitReached,

    /// No viable path
    NoViablePath,

    /// Connection timeout
    TimedOut,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {}

// ============================================================================
// Frame Types
// ============================================================================

/// QUIC frame types
#[derive(Clone, Debug, PartialEq)]
pub enum Frame {
    Padding {
        len: usize,
    },
    Ping {
        mtu_probe: Option<usize>,
    },
    Ack {
        ack_delay: u64,
        ranges: Vec<(u64, u64)>, // Simplified range set
        ecn_counts: Option<EcnCounts>,
    },
    ResetStream {
        stream_id: u64,
        error_code: u64,
        final_size: u64,
    },
    StopSending {
        stream_id: u64,
        error_code: u64,
    },
    Crypto {
        offset: u64,
        data: Vec<u8>,
    },
    NewToken {
        token: Vec<u8>,
    },
    Stream {
        stream_id: u64,
        offset: u64,
        data: Vec<u8>,
        fin: bool,
    },
    MaxData {
        max: u64,
    },
    MaxStreamData {
        stream_id: u64,
        max: u64,
    },
    MaxStreamsBidi {
        max: u64,
    },
    MaxStreamsUni {
        max: u64,
    },
    DataBlocked {
        limit: u64,
    },
    StreamDataBlocked {
        stream_id: u64,
        limit: u64,
    },
    StreamsBlockedBidi {
        limit: u64,
    },
    StreamsBlockedUni {
        limit: u64,
    },
    NewConnectionId {
        seq_num: u64,
        retire_prior_to: u64,
        conn_id: Vec<u8>,
        reset_token: [u8; 16],
    },
    RetireConnectionId {
        seq_num: u64,
    },
    PathChallenge {
        data: [u8; 8],
    },
    PathResponse {
        data: [u8; 8],
    },
    ConnectionClose {
        error_code: u64,
        frame_type: u64,
        reason: Vec<u8>,
    },
    ApplicationClose {
        error_code: u64,
        reason: Vec<u8>,
    },
    Datagram {
        data: Vec<u8>,
    },
    DatagramHeader {
        length: usize,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct EcnCounts {
    pub ect0: u64,
    pub ect1: u64,
    pub ce: u64,
}

// ============================================================================
// Random Number Generation
// ============================================================================

#[derive(Debug, Clone, Default)]
pub struct Stats {
    /// Number of QUIC packets received
    pub recv: usize,

    /// Number of QUIC packets sent
    pub sent: usize,

    /// Number of QUIC packets lost
    pub lost: usize,

    /// Number of bytes received
    pub recv_bytes: u64,

    /// Number of bytes sent
    pub sent_bytes: u64,

    /// Number of stream bytes received
    pub stream_recv_bytes: u64,

    /// Number of stream bytes sent
    pub stream_sent_bytes: u64,

    /// Estimated round-trip time
    pub rtt: Duration,

    /// Congestion window size
    pub cwnd: usize,

    /// Bytes in flight
    pub bytes_in_flight: usize,

    /// Delivery rate estimate
    pub delivery_rate: u64,
    /// Total number of bytes sent acked
    pub acked_bytes: u64,
    /// Total number of bytes sent lost
    pub lost_bytes: u64,
    /// The number of QUIC packets that were marked as lost but later acked
    pub spurious_lost: usize,
    /// The number of sent QUIC packets with retransmitted data
    pub retrans: usize,
    /// The number of DATAGRAM frames received
    pub dgram_recv: usize,
    /// The number of DATAGRAM frames sent
    pub dgram_sent: usize,
    /// The number of known paths for the connection
    pub paths_count: usize,
    /// The total number of PATH_CHALLENGE frames that were received
    pub path_challenge_rx_count: u64,
    /// The number of streams reset by local
    pub reset_stream_count_local: u64,
    /// The number of streams stopped by local
    pub stopped_stream_count_local: u64,
    /// The number of streams reset by remote
    pub reset_stream_count_remote: u64,
    /// The number of streams stopped by remote
    pub stopped_stream_count_remote: u64,
    /// Total duration during which bytes were in flight
    pub bytes_in_flight_duration: Duration,
    /// The number of stream bytes that were retransmitted
    pub stream_retrans_bytes: u64,
}

/// Path statistics
#[derive(Debug, Clone)]
pub struct PathStats {
    pub recv: u64,
    pub sent: u64,
    pub lost: u64,
    pub rtt: std::time::Duration,
    pub cwnd: usize,
    pub delivery_rate: u64,
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
}

impl Default for PathStats {
    fn default() -> Self {
        Self {
            recv: 0,
            sent: 0,
            lost: 0,
            rtt: std::time::Duration::from_millis(0),
            cwnd: 0,
            delivery_rate: 0,
            local_addr: std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)),
            peer_addr: std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 0)),
        }
    }
}
