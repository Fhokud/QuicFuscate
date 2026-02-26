use super::{
    cid, config::Config, frames, packet, pnspace, recovery, udpfast, ConnectionId, EcnCounts,
    EcnMark, FecControlDelta, Frame, PacketType, PathStats, RecvInfo, SendInfo, Stats, Stream,
    TransportObserver, INITIAL_WINDOW, MAX_STREAM_SIZE, MIN_CLIENT_INITIAL_LEN, PROTOCOL_VERSION,
};
use std::collections::{HashMap, VecDeque};
use std::net::{Shutdown, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::optimize::{prefetch, PrefetchHint};

/// Path-related events
#[derive(Debug, Clone)]
pub enum PathEvent {
    /// New path has been created
    New(SocketAddr, SocketAddr),

    /// Path has been validated
    Validated(SocketAddr, SocketAddr),

    /// Path validation failed
    FailedValidation(SocketAddr, SocketAddr),

    /// Path has been closed
    Closed(SocketAddr, SocketAddr),

    /// Connection ID reused
    ReusedSourceConnectionId(u64, Option<(SocketAddr, SocketAddr)>, (SocketAddr, SocketAddr)),

    /// Peer migrated to new path
    PeerMigrated(SocketAddr, SocketAddr),
}

// ============================================================================
// QUIC Connection - Core Transport State Machine
// ============================================================================

/// QUIC connection
pub struct Connection {
    // Internal state (simplified for now)
    scid: ConnectionId,
    dcid: ConnectionId,
    /// Original Destination Connection ID (ODCID) used for Initial key derivation (RFC 9001).
    /// Client: this is the initial DCID it chose for the first Initial packet.
    /// Server: this is the DCID observed in the first client Initial packet.
    initial_dcid: ConnectionId,
    is_server: bool,
    is_established: bool,
    is_closed: bool,
    is_draining: bool,
    streams: HashMap<u64, Stream>,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    config: Config,
    stats: Stats,
    #[cfg(not(feature = "zero_copy_dgram"))]
    dgram_recv_queue: VecDeque<Vec<u8>>,
    #[cfg(not(feature = "zero_copy_dgram"))]
    dgram_send_queue: VecDeque<Vec<u8>>,
    #[cfg(feature = "zero_copy_dgram")]
    dgram_recv_queue: VecDeque<DatagramBuffer>,
    #[cfg(feature = "zero_copy_dgram")]
    dgram_send_queue: VecDeque<DatagramBuffer>,
    #[cfg(feature = "zero_copy_dgram")]
    dgram_pool: Arc<crate::optimize::MemoryPool>,
    dgram_send_max_size: usize,
    timeout_count: u32,
    rtt: Duration,
    cwnd: usize,
    bytes_in_flight: usize,
    path_id: u64,
    path_events: VecDeque<PathEvent>,
    source_cids: cid::ConnectionIdSet,
    dest_cids: cid::ConnectionIdSet,
    pkt_spaces: [pnspace::PktNumSpace; 3],
    next_send_pn_by_space: [u64; 3],
    // Current key phase (short header KEY_PHASE bit). Header bit only; no rotation here.
    key_phase: bool,
    readable_streams: VecDeque<u64>,
    writable_streams: VecDeque<u64>,
    local_error: Option<crate::error::ConnectionError>,
    peer_error: Option<crate::error::ConnectionError>,
    trace_id: String,
    retired_scids: VecDeque<ConnectionId>,
    bytes_in_flight_started: Option<Instant>,
    // Basic flow-control (local receive limits)
    // Receive-side connection window (what we allow peer to send)
    conn_max_data: u64,
    conn_bytes_recvd: u64,
    // Send-side connection window (what peer allows us to send)
    peer_max_data: u64,

    // Unified TLS provider (rustls + optional TLS Cover)
    tls_provider: Option<Box<dyn crate::tls_provider::QuicTlsProvider>>,
    conn_bytes_sent: u64,
    pending_control: VecDeque<Frame>,
    // Crypto context (AEAD/HP) hooks for header and payload processing
    crypto: Arc<parking_lot::RwLock<packet::CryptoContext>>,
    // ECN counters (for ACK ECN section)
    ecn_ect0: u64,
    ecn_ect1: u64,
    ecn_ce: u64,
    // Recovery / CC
    recovery: crate::transport::recovery::Recovery,
    // Deep FEC integration hooks (transport-level hints only; core applies)
    fec_batch_size: usize,
    fec_redundancy_factor: f32,
    fec_escalation_threshold: f32,
    fec_ctrl_delta: FecControlDelta,
    // Recovery callback feedback counters for live FEC adaptation wiring.
    fec_cb_sent_packets: Arc<std::sync::atomic::AtomicU64>,
    fec_cb_lost_packets: Arc<std::sync::atomic::AtomicU64>,
    fec_cb_sent_bytes: Arc<std::sync::atomic::AtomicU64>,
    fec_cb_lost_bytes: Arc<std::sync::atomic::AtomicU64>,
    // Sent packet accounting: PN -> bytes (Application epoch)
    sent_bytes_by_pn: std::collections::HashMap<u64, usize>,
    // Stealth timing: next eligible send time (if timing obfuscation enabled)
    next_send_at: Option<Instant>,
    // Optional observer for external modules (Stealth/Brain) to tap into telemetry
    observer: Option<Arc<dyn TransportObserver>>,
    // Optional HTTP/3 connection bound to this QUIC transport
    h3: Option<crate::transport::h3::Connection>,
}

#[cfg(feature = "zero_copy_dgram")]
struct DatagramBuffer {
    data: crate::optimize::AlignedBox<[u8]>,
    len: usize,
    pool: Arc<crate::optimize::MemoryPool>,
}

#[cfg(feature = "zero_copy_dgram")]
impl Drop for DatagramBuffer {
    fn drop(&mut self) {
        // Buffer returns to pool automatically via AlignedBox Drop
        // Pool reference kept for potential future explicit return logic
        let _ = &self.pool;
    }
}

#[cfg(feature = "stream_ring_buffer")]
#[derive(Debug)]
pub struct StreamRingBuffer {
    buffer: Box<[u8; 65536]>, // Fixed 64KB ring
    head: usize,
    tail: usize,
    size: usize,
}

#[cfg(feature = "stream_ring_buffer")]
impl StreamRingBuffer {
    #[inline(always)]
    fn new() -> Self {
        Self { buffer: Box::new([0u8; 65536]), head: 0, tail: 0, size: 0 }
    }

    #[inline(always)]
    fn write(&mut self, data: &[u8]) -> usize {
        let capacity = self.buffer.len();
        let available = capacity - self.size;
        let to_write = data.len().min(available);

        for &b in data.iter().take(to_write) {
            self.buffer[self.tail] = b;
            self.tail = (self.tail + 1) & (capacity - 1); // Fast modulo for power of 2
        }
        self.size += to_write;
        to_write
    }

    #[inline(always)]
    fn read(&mut self, buf: &mut [u8]) -> usize {
        let to_read = buf.len().min(self.size);
        for out in buf.iter_mut().take(to_read) {
            *out = self.buffer[self.head];
            self.head = (self.head + 1) & (self.buffer.len() - 1);
        }
        self.size -= to_read;
        to_read
    }

    #[inline(always)]
    fn len(&self) -> usize {
        self.size
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.size == 0
    }
}

impl Connection {
    /// Set the ODCID used for Initial key derivation (RFC 9001).
    ///
    /// For clients this also initializes the current destination CID used in the first Initial
    /// packet. For servers the current destination CID is learned from the peer's SCID when the
    /// first packet is received.
    pub(crate) fn set_initial_dcid(&mut self, dcid: ConnectionId) {
        self.initial_dcid = dcid.clone();
        if !self.is_server {
            self.dcid = dcid;
        }
    }

    /// Set the current destination CID (what we put into outgoing DCID fields).
    pub(crate) fn set_destination_cid(&mut self, dcid: ConnectionId) {
        self.dcid = dcid;
        self.dest_cids.insert(&self.dcid);
    }

    /// Opportunistic drain of MSG_ZEROCOPY completion inbox (Linux only).
    /// Keeps kernel/userland completion queues tidy without coupling to send path.
    #[inline(always)]
    fn zerocopy_tick(&mut self) {
        #[cfg(target_os = "linux")]
        {
            let batch = std::env::var("QUICFUSCATE_ZC_DRAIN_BATCH")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(16);
            // Drain and ignore return; detailed accounting is handled in udpfast and CQ paths.
            let _events = crate::transport::uring::try_drain_zerocopy_events(batch);
            let _ = _events; // silence unused var in release
        }
        #[cfg(not(target_os = "linux"))]
        {
            // no-op on non-Linux
        }
    }
    pub(crate) fn new_with_role(
        scid: &[u8],
        local: SocketAddr,
        peer: SocketAddr,
        config: Config,
        is_server: bool,
    ) -> Self {
        let dgram_send_max_size = config.max_udp_payload_size as usize;
        let initial_max_data = config.initial_max_data;
        let mut conn = Self {
            scid: ConnectionId::from_vec(scid.to_vec()),
            dcid: ConnectionId::default(),
            initial_dcid: ConnectionId::default(),
            is_server,
            is_established: false,
            is_closed: false,
            is_draining: false,
            streams: HashMap::new(),
            local_addr: local,
            peer_addr: peer,
            config,
            stats: Stats::default(),
            #[cfg(not(feature = "zero_copy_dgram"))]
            dgram_recv_queue: VecDeque::new(),
            #[cfg(not(feature = "zero_copy_dgram"))]
            dgram_send_queue: VecDeque::new(),
            #[cfg(feature = "zero_copy_dgram")]
            dgram_recv_queue: VecDeque::new(),
            #[cfg(feature = "zero_copy_dgram")]
            dgram_send_queue: VecDeque::new(),
            #[cfg(feature = "zero_copy_dgram")]
            dgram_pool: crate::optimize::global_pool(),
            dgram_send_max_size,
            timeout_count: 0,
            rtt: Duration::from_millis(0),
            cwnd: INITIAL_WINDOW,
            bytes_in_flight: 0,
            path_id: 0,
            path_events: VecDeque::new(),
            source_cids: cid::ConnectionIdSet::new(),
            dest_cids: cid::ConnectionIdSet::new(),
            pkt_spaces: [
                pnspace::PktNumSpace::default(),
                pnspace::PktNumSpace::default(),
                pnspace::PktNumSpace::default(),
            ],
            next_send_pn_by_space: [0, 0, 0],
            key_phase: false,
            readable_streams: VecDeque::new(),
            writable_streams: VecDeque::new(),
            local_error: None,
            peer_error: None,
            trace_id: String::new(),
            retired_scids: VecDeque::new(),
            bytes_in_flight_started: None,
            conn_max_data: initial_max_data,
            conn_bytes_recvd: 0,
            peer_max_data: initial_max_data,
            tls_provider: None,
            conn_bytes_sent: 0,
            pending_control: VecDeque::new(),
            crypto: Arc::new(parking_lot::RwLock::new(packet::CryptoContext::default())),
            ecn_ect0: 0,
            ecn_ect1: 0,
            ecn_ce: 0,
            recovery: recovery::Recovery::new(INITIAL_WINDOW, dgram_send_max_size),
            fec_batch_size: 8,
            fec_redundancy_factor: 0.10,
            fec_escalation_threshold: 0.05,
            fec_ctrl_delta: FecControlDelta::default(),
            fec_cb_sent_packets: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            fec_cb_lost_packets: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            fec_cb_sent_bytes: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            fec_cb_lost_bytes: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            sent_bytes_by_pn: HashMap::new(),
            next_send_at: None,
            observer: None,
            h3: None,
        };
        conn.install_recovery_fec_callbacks();
        conn
    }

    pub(crate) fn new_client(
        scid: &[u8],
        local: SocketAddr,
        peer: SocketAddr,
        config: Config,
    ) -> Self {
        Self::new_with_role(scid, local, peer, config, false)
    }

    pub(crate) fn new_server(
        scid: &[u8],
        local: SocketAddr,
        peer: SocketAddr,
        config: Config,
    ) -> Self {
        Self::new_with_role(scid, local, peer, config, true)
    }

    /// Public wrapper to enable QUIC DATAGRAM queues via config
    pub fn enable_datagrams(&mut self, recv_q: usize, send_q: usize) {
        self.config.enable_dgram(recv_q, send_q);
    }
    pub fn dgram_pool_or_global(&self) -> Arc<crate::optimize::MemoryPool> {
        #[cfg(feature = "zero_copy_dgram")]
        {
            self.dgram_pool.clone()
        }
        #[cfg(not(feature = "zero_copy_dgram"))]
        {
            crate::optimize::global_pool()
        }
    }
    fn total_send_buffered_bytes(&self) -> usize {
        #[cfg(not(feature = "stream_ring_buffer"))]
        return self.streams.values().map(|s| s.send_buf.len()).sum();
        #[cfg(feature = "stream_ring_buffer")]
        return self.streams.values().map(|s| s.send_ring.len()).sum();
    }

    // ============================================================================
    // Real-TLS Integration Methods
    // ============================================================================

    /// Enable unified TLS provider (rustls + optional TLS Cover)
    pub fn enable_tls(&mut self, profile_name: &str) -> Result<(), crate::error::ConnectionError> {
        log::info!("Enabling unified TLS provider with profile: {}", profile_name);

        // TLS provider must operate on the same CryptoContext as the transport,
        // otherwise secrets would never be installed into the packet protection keys.
        let crypto_arc = self.crypto.clone();

        // Create unified provider (rustls + optional TLS Cover)
        let provider = crate::tls_provider::create_provider(
            crate::tls_provider::ProviderStrategy::Unified,
            self.is_server,
            crypto_arc.clone(),
        )?;

        // Store provider
        self.tls_provider = Some(provider);

        if let Some(provider_ref) = self.tls_provider.as_ref() {
            log::info!("Unified TLS provider enabled: {}", provider_ref.provider_name());
        } else {
            return Err(crate::error::ConnectionError::InvalidState);
        }

        // Install Initial secrets/HP from DCID for early Long Header encryption.
        // QUIC initial keys are direction-specific:
        // - Client: write=client_secret, read=server_secret
        // - Server: write=server_secret, read=client_secret
        // RFC 9001: Initial secrets derive from the Destination Connection ID in the first Initial.
        // Use the recorded ODCID if available (server accepts it from the first client packet).
        let initial_dcid = if !self.initial_dcid.is_empty() {
            self.initial_dcid.as_ref()
        } else {
            self.dcid.as_ref()
        };
        let (client_secret, server_secret) =
            packet::derive_initial_secrets(initial_dcid, self.config.version);
        {
            let (read_secret, write_secret) = if self.is_server {
                (client_secret.as_slice(), server_secret.as_slice())
            } else {
                (server_secret.as_slice(), client_secret.as_slice())
            };
            let mut crypto = self.crypto.write();
            crypto.install_aes_gcm_initial(read_secret, write_secret);
            crypto.install_hp_initial(read_secret, write_secret);
        }

        Ok(())
    }

    /// Configure TLS provider with a specific profile and SNI.
    pub fn configure_tls(
        &mut self,
        profile: &crate::tls_provider::TlsProfile,
        sni: &str,
    ) -> Result<(), crate::error::ConnectionError> {
        if let Some(provider) = &mut self.tls_provider {
            provider.configure(profile)?;
            if !sni.is_empty() {
                provider.set_server_name(sni)?;
            }
            // Optionally enable 0-RTT when desired
            let _ = provider.enable_0rtt();
        }
        Ok(())
    }

    /// Process TLS handshake with optional real-time CH override
    pub fn do_tls_handshake(
        &mut self,
        override_template: Option<&str>,
    ) -> Result<bool, crate::error::ConnectionError> {
        if let Some(provider) = &mut self.tls_provider {
            // Apply real-time CH override if specified and supported
            if let Some(template_name) = override_template {
                if provider.supports_ch_override() {
                    // Create simple template bytes (TLS Cover will handle the details)
                    let template_bytes = template_name.as_bytes();
                    provider.apply_ch_override(template_bytes)?;
                }
            }

            // Check handshake completion
            let done = provider.handshake_complete();
            if done {
                // If ALPN negotiated HTTP/3, enable H3 binding
                if let Some(alpn) = provider.alpn() {
                    if alpn.starts_with("h3") {
                        let _ = self.enable_h3();
                    }
                }
            }
            Ok(done)
        } else {
            // No TLS provider configured, consider handshake complete
            Ok(true)
        }
    }

    /// Returns true when the TLS provider reports handshake completion.
    /// This is intentionally distinct from transport liveness/establishment.
    pub fn tls_handshake_complete(&self) -> bool {
        self.tls_provider.as_ref().map(|p| p.handshake_complete()).unwrap_or(true)
    }

    /// Enable HTTP/3 connection bound to this transport (idempotent)
    pub fn enable_h3(&mut self) -> Result<(), crate::transport::h3::Error> {
        if self.h3.is_some() {
            return Ok(());
        }
        let cfg = crate::transport::h3::Config::new()
            .map_err(|_| crate::transport::h3::Error::InternalError)?;
        let h3c = crate::transport::h3::Connection::with_transport(self, &cfg)?;
        self.h3 = Some(h3c);
        Ok(())
    }

    /// Establish a MASQUE CONNECT-UDP stream via HTTP/3, returns stream id
    pub fn masque_connect_udp(
        &mut self,
        proxy_authority: &str,
        target_host_port: &str,
    ) -> Result<u64, crate::transport::h3::Error> {
        if self.h3.is_none() {
            self.enable_h3()?;
        }
        // Temporarily take ownership to avoid aliasing &mut borrows
        let Some(mut h3c) = self.h3.take() else {
            return Err(crate::transport::h3::Error::InternalError);
        };
        let res = h3c.connect_udp(self, proxy_authority, target_host_port);
        self.h3 = Some(h3c);
        res
    }

    /// Enable MASQUE DATAGRAM context on an existing CONNECT-UDP stream
    pub fn masque_enable_datagram(
        &mut self,
        stream_id: u64,
    ) -> Result<u64, crate::transport::h3::Error> {
        if self.h3.is_none() {
            self.enable_h3()?;
        }
        let Some(mut h3c) = self.h3.take() else {
            return Err(crate::transport::h3::Error::InternalError);
        };
        let res = h3c.enable_masque_datagram(self, stream_id);
        self.h3 = Some(h3c);
        res
    }

    /// Send one MASQUE UDP payload as QUIC DATAGRAM (Flow-ID implicit)
    pub fn masque_send_datagram(
        &mut self,
        stream_id: u64,
        udp_payload: &[u8],
    ) -> Result<(), crate::transport::h3::Error> {
        if self.h3.is_none() {
            self.enable_h3()?;
        }
        let Some(mut h3c) = self.h3.take() else {
            return Err(crate::transport::h3::Error::InternalError);
        };
        let res = h3c.send_masque_datagram(self, stream_id, udp_payload);
        self.h3 = Some(h3c);
        res
    }

    /// Try to receive one MASQUE DATAGRAM; returns (flow_id, payload)
    pub fn masque_try_recv_datagram(&mut self) -> Option<(u64, Vec<u8>)> {
        if let Some(mut h3c) = self.h3.take() {
            let out = h3c.try_recv_masque_datagram(self);
            self.h3 = Some(h3c);
            out
        } else {
            None
        }
    }

    /// Process incoming CRYPTO frame
    pub fn process_crypto_frame(
        &mut self,
        level: crate::tls_provider::Level,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<(), crate::error::ConnectionError> {
        if let Some(provider) = &mut self.tls_provider {
            // CRYPTO frames can arrive out-of-order. Buffer and drain contiguous handshake bytes
            // before feeding into the TLS provider.
            let mut chunks: Vec<Vec<u8>> = Vec::new();
            {
                let mut crypto = self.crypto.write();
                let stream = match level {
                    crate::tls_provider::Level::Initial => &mut crypto.crypto_initial,
                    crate::tls_provider::Level::Handshake => &mut crypto.crypto_handshake,
                    _ => &mut crypto.crypto_application,
                };
                stream.recv(offset, data)?;
                let mut tmp = [0u8; 2048];
                while stream.has_data() {
                    let n = stream.read(&mut tmp);
                    if n == 0 {
                        break;
                    }
                    chunks.push(tmp[..n].to_vec());
                }
            }

            for chunk in chunks {
                provider.provide_quic_data(level, &chunk)?;
            }
            // Install any newly derived secrets into the shared CryptoContext.
            // Without this, the transport would never transition to 1-RTT and application streams
            // (including HTTP/3 HEADERS carrying x-qf-auth) would stall behind the handshake gate.
            provider.poll_secrets_and_install(&self.crypto)?;
        } else {
            // Store in crypto stream for later processing
            let mut crypto = self.crypto.write();
            let stream = match level {
                crate::tls_provider::Level::Initial => &mut crypto.crypto_initial,
                crate::tls_provider::Level::Handshake => &mut crypto.crypto_handshake,
                _ => &mut crypto.crypto_application,
            };
            stream.recv(offset, data)?;
        }

        Ok(())
    }

    /// Get next CRYPTO frame to send
    pub fn next_crypto_frame(
        &mut self,
        level: crate::tls_provider::Level,
        max_len: usize,
    ) -> Option<(u64, Vec<u8>)> {
        if let Some(provider) = &mut self.tls_provider {
            provider.next_crypto_frame(level, max_len)
        } else {
            let mut crypto = self.crypto.write();
            let stream = match level {
                crate::tls_provider::Level::Initial => &mut crypto.crypto_initial,
                crate::tls_provider::Level::Handshake => &mut crypto.crypto_handshake,
                _ => &mut crypto.crypto_application,
            };
            stream.next_crypto_frame(max_len)
        }
    }

    /// Switch TLS profile dynamically (real-time CHO)
    pub fn switch_tls_profile(
        &mut self,
        profile_name: &str,
    ) -> Result<(), crate::error::ConnectionError> {
        if self.tls_provider.is_some() {
            log::info!("Switching TLS profile to: {}", profile_name);

            // Re-enable with new profile
            self.enable_tls(profile_name)?;
        }

        Ok(())
    }

    // ============================================================================
    // Packet Processing Methods
    // ============================================================================

    /// Processes incoming packet
    #[inline(always)]
    pub fn recv(
        &mut self,
        buf: &mut [u8],
        info: &RecvInfo,
    ) -> Result<usize, crate::error::ConnectionError> {
        use crate::error::ConnectionError;
        use udpfast::unlikely;
        if unlikely(buf.is_empty()) {
            return Err(ConnectionError::BufferTooShort);
        }

        // Opportunistic zerocopy completion drain (process completions from prior sends)
        self.zerocopy_tick();

        // Prefetch buffer for better cache utilization
        unsafe {
            prefetch(buf.as_ptr(), PrefetchHint::T0);
            if buf.len() > 64 {
                prefetch(buf.as_ptr().add(64), PrefetchHint::T0);
            }
        }

        // Pre-parse header to determine space and largest PN hint.
        // For short headers, DCID length is the local SCID length (the peer routes to our CID).
        let short_dcid_len = self.scid.as_ref().len();
        let (pre_ty, largest_hint) = match packet::parse_header(buf, short_dcid_len) {
            Ok((hdr_native, _)) => {
                let t = match hdr_native.ty {
                    packet::PacketType::Initial => PacketType::Initial,
                    packet::PacketType::Retry => PacketType::Retry,
                    packet::PacketType::Handshake => PacketType::Handshake,
                    packet::PacketType::ZeroRTT => PacketType::ZeroRTT,
                    packet::PacketType::VersionNegotiation => PacketType::VersionNegotiation,
                    packet::PacketType::Short => PacketType::Short,
                };
                let idx = match t {
                    PacketType::Initial => 0,
                    PacketType::Handshake => 1,
                    _ => 2,
                };
                (t, self.pkt_spaces[idx].largest_recv.unwrap_or(0))
            }
            Err(_) => (PacketType::Short, 0),
        };

        // Retry verification (no payload decrypt)
        if let PacketType::Retry = pre_ty {
            let odcid = if !self.initial_dcid.is_empty() {
                self.initial_dcid.as_ref()
            } else {
                self.dcid.as_ref()
            };
            if let Err(e) = packet::verify_retry_tag(&buf[..], odcid, self.config.version) {
                self.local_error = Some(e);
            }
            // For Retry we do not parse further.
            self.stats.recv += 1;
            self.stats.recv_bytes += buf.len() as u64;
            return Ok(buf.len());
        }

        // Try to unprotect+decrypt using installed secrets.
        // Important: keep the lock scope tight so we can mutably borrow `self` later (e.g. CRYPTO frames).
        let (hdr_native, aad_len, pt_len) = {
            let crypto_ref_for_rx = self.crypto.read();
            match packet::unprotect_and_decrypt(
                &crypto_ref_for_rx,
                buf,
                short_dcid_len,
                largest_hint,
            ) {
                Ok(v) => v,
                Err(e) => {
                    self.local_error = Some(e);
                    if let Some(err) = self.local_error.clone() {
                        return Err(err);
                    }
                    return Err(ConnectionError::InvalidState);
                }
            }
        };
        let pkt_ty = match hdr_native.ty {
            packet::PacketType::Initial => PacketType::Initial,
            packet::PacketType::Retry => PacketType::Retry,
            packet::PacketType::Handshake => PacketType::Handshake,
            packet::PacketType::ZeroRTT => PacketType::ZeroRTT,
            packet::PacketType::VersionNegotiation => PacketType::VersionNegotiation,
            packet::PacketType::Short => PacketType::Short,
        };

        // Learn peer CID from the first long-header packets.
        // - Server: outgoing DCID must be the client's SCID.
        // - Client: after receiving a server packet, outgoing DCID becomes the server's SCID.
        if hdr_native.ty != packet::PacketType::Short && !hdr_native.scid.is_empty() {
            if self.is_server {
                if self.dcid.is_empty() {
                    self.set_destination_cid(ConnectionId::from_vec(hdr_native.scid.clone()));
                }
                if self.initial_dcid.is_empty() && !hdr_native.dcid.is_empty() {
                    self.initial_dcid = ConnectionId::from_vec(hdr_native.dcid.clone());
                }
            } else {
                // Client: only rotate away from the initial placeholder DCID once we have a peer SCID.
                if self.dcid.is_empty() || self.dcid == self.initial_dcid {
                    self.set_destination_cid(ConnectionId::from_vec(hdr_native.scid.clone()));
                }
            }
        }
        // Observer hook: notify after header processed and payload length known
        if let Some(obs) = &self.observer {
            obs.on_packet_recv(hdr_native.pkt_num, pt_len);
        }
        // Key phase handling (simplified rotation: synced to received short-header bit).
        if pkt_ty == PacketType::Short
            && hdr_native.pkt_num_len > 0
            && hdr_native.key_phase != self.key_phase
        {
            // Update key phase bit; an actual key update would be triggered here if needed.
            self.key_phase = hdr_native.key_phase;
        }
        let space_idx = match pkt_ty {
            PacketType::Initial => 0,
            PacketType::Handshake => 1,
            _ => 2,
        };
        // Duplicate PN detection: if already observed, count and return.
        if hdr_native.pkt_num_len > 0 {
            if self.pkt_spaces[space_idx].contains(hdr_native.pkt_num) {
                let len = aad_len.saturating_add(pt_len).min(buf.len());
                self.stats.recv += 1;
                self.stats.recv_bytes += len as u64;
                return Ok(len);
            }
            self.pkt_spaces[space_idx].on_packet_recv(
                hdr_native.pkt_num,
                self.config.max_ack_delay,
                self.config.ack_eliciting_threshold,
            );
        }

        // Parse frames from decrypted payload region
        let mut off = aad_len;
        let end = aad_len.saturating_add(pt_len).min(buf.len());
        let mut ack_eliciting = false;
        while off < end {
            // Prefetch next bytes to accelerate frame parsing
            unsafe {
                let ahead = core::cmp::min(off + 64, end);
                crate::fec::prefetch_data(buf.as_ptr().add(ahead));
            }
            match frames::from_bytes(&buf[off..end], pkt_ty) {
                Ok((frame, used)) => {
                    if used == 0 {
                        break;
                    }
                    off += used;
                    // Minimal: handle accounting for Stream/Crypto sizes
                    // 0-RTT must not carry CRYPTO frames (simplified gate).
                    if pkt_ty == PacketType::ZeroRTT && matches!(frame, Frame::Crypto { .. }) {
                        continue;
                    }
                    match frame {
                        Frame::Stream { stream_id, offset, data, fin } => {
                            ack_eliciting = true;
                            self.stats.stream_recv_bytes += data.len() as u64;
                            if !self.readable_streams.contains(&stream_id) {
                                self.readable_streams.push_back(stream_id);
                            }
                            // Flow-control tracking
                            let s = self.streams.entry(stream_id).or_insert_with(|| Stream {
                                id: stream_id,
                                #[cfg(not(feature = "stream_ring_buffer"))]
                                send_buf: Vec::new(),
                                #[cfg(not(feature = "stream_ring_buffer"))]
                                recv_buf: Vec::new(),
                                #[cfg(feature = "stream_ring_buffer")]
                                send_ring: StreamRingBuffer::new(),
                                #[cfg(feature = "stream_ring_buffer")]
                                recv_ring: StreamRingBuffer::new(),
                                send_fin: false,
                                recv_fin: false,
                                send_off: 0,
                                recv_off: 0,
                                recv_next: 0,
                                recv_final_size: None,
                                recv_frags: std::collections::BTreeMap::new(),
                                priority_urgency: 3,
                                priority_incremental: false,
                                max_stream_data_rx: self.config.initial_max_stream_data_bidi_local,
                                max_stream_data_tx: self.config.initial_max_stream_data_bidi_remote,
                            });
                            let end = offset.saturating_add(data.len() as u64);
                            // Track highest received offset for flow control accounting.
                            s.recv_off = s.recv_off.max(end);
                            self.conn_bytes_recvd =
                                self.conn_bytes_recvd.saturating_add(data.len() as u64);

                            // Store fragment for ordered delivery.
                            if !data.is_empty() {
                                let mut start = offset;
                                if start < s.recv_next {
                                    let drop = (s.recv_next - start) as usize;
                                    if drop < data.len() {
                                        start = s.recv_next;
                                        s.recv_frags.insert(start, data[drop..].to_vec());
                                    }
                                } else {
                                    s.recv_frags.insert(start, data);
                                }
                            }

                            // FIN denotes the final size of the stream (offset + data_len).
                            if fin {
                                match s.recv_final_size {
                                    None => s.recv_final_size = Some(end),
                                    Some(prev) if prev == end => {}
                                    Some(_) => {
                                        self.local_error =
                                            Some(crate::error::ConnectionError::FinalSize);
                                    }
                                }
                            }

                            // Drain contiguous fragments into the receive buffer/ring.
                            loop {
                                let next = s.recv_next;
                                // Normalize any fragment that overlaps `next` by re-keying.
                                if let Some((&start, _)) = s.recv_frags.range(..=next).next_back() {
                                    if start < next {
                                        if let Some(mut frag) = s.recv_frags.remove(&start) {
                                            let start_end = start.saturating_add(frag.len() as u64);
                                            if start_end <= next {
                                                continue;
                                            }
                                            let skip = (next - start) as usize;
                                            frag.drain(..skip);
                                            s.recv_frags.insert(next, frag);
                                            continue;
                                        }
                                    }
                                }

                                let Some(frag) = s.recv_frags.remove(&next) else {
                                    break;
                                };

                                #[cfg(not(feature = "stream_ring_buffer"))]
                                {
                                    s.recv_buf.extend_from_slice(&frag);
                                    s.recv_next = s.recv_next.saturating_add(frag.len() as u64);
                                }
                                #[cfg(feature = "stream_ring_buffer")]
                                {
                                    let written = s.recv_ring.write(&frag);
                                    s.recv_next = s.recv_next.saturating_add(written as u64);
                                    if written < frag.len() {
                                        // Keep remainder for later to avoid truncation.
                                        s.recv_frags.insert(s.recv_next, frag[written..].to_vec());
                                        break;
                                    }
                                }
                            }

                            if let Some(final_size) = s.recv_final_size {
                                if s.recv_next >= final_size {
                                    s.recv_fin = true;
                                }
                            }
                            // If exceeding current stream window, flag flow control (minimal handling)
                            if s.recv_off > s.max_stream_data_rx {
                                self.local_error = Some(crate::error::ConnectionError::FlowControl);
                            } else if s.recv_off * 4 >= s.max_stream_data_rx * 3 {
                                // Grow stream window and queue MAX_STREAM_DATA
                                let new_max =
                                    (s.max_stream_data_rx.saturating_mul(2)).min(MAX_STREAM_SIZE);
                                s.max_stream_data_rx = new_max;
                                self.pending_control
                                    .push_back(Frame::MaxStreamData { stream_id, max: new_max });
                            }
                            if self.conn_bytes_recvd * 4 >= self.conn_max_data * 3 {
                                // Grow connection window and queue MAX_DATA
                                let new_max =
                                    self.conn_max_data.saturating_mul(2).min(MAX_STREAM_SIZE);
                                self.conn_max_data = new_max;
                                self.pending_control.push_back(Frame::MaxData { max: new_max });
                            }
                        }
                        Frame::MaxData { max } => {
                            // Peer increased our send window
                            self.peer_max_data = max;
                        }
                        Frame::MaxStreamData { stream_id, max } => {
                            // Peer increased per-stream send window
                            let s = self.streams.entry(stream_id).or_insert_with(|| Stream {
                                id: stream_id,
                                #[cfg(not(feature = "stream_ring_buffer"))]
                                send_buf: Vec::new(),
                                #[cfg(not(feature = "stream_ring_buffer"))]
                                recv_buf: Vec::new(),
                                #[cfg(feature = "stream_ring_buffer")]
                                send_ring: StreamRingBuffer::new(),
                                #[cfg(feature = "stream_ring_buffer")]
                                recv_ring: StreamRingBuffer::new(),
                                send_fin: false,
                                recv_fin: false,
                                send_off: 0,
                                recv_off: 0,
                                recv_next: 0,
                                recv_final_size: None,
                                recv_frags: std::collections::BTreeMap::new(),
                                priority_urgency: 3,
                                priority_incremental: false,
                                max_stream_data_rx: self.config.initial_max_stream_data_bidi_local,
                                max_stream_data_tx: self.config.initial_max_stream_data_bidi_remote,
                            });
                            s.max_stream_data_tx = max;
                        }
                        Frame::ConnectionClose { .. } => {}
                        Frame::PathChallenge { .. } => {
                            ack_eliciting = true;
                            self.stats.path_challenge_rx_count =
                                self.stats.path_challenge_rx_count.saturating_add(1);
                        }
                        Frame::Datagram { data } => {
                            ack_eliciting = true;
                            self.stats.dgram_recv += 1;
                            if !self.is_dgram_recv_queue_full() {
                                #[cfg(not(feature = "zero_copy_dgram"))]
                                self.dgram_recv_queue.push_back(data);
                                #[cfg(feature = "zero_copy_dgram")]
                                {
                                    let mut buf = self.dgram_pool.alloc();
                                    let len = data.len().min(buf.len());
                                    buf[..len].copy_from_slice(&data[..len]);
                                    self.dgram_recv_queue.push_back(DatagramBuffer {
                                        data: buf,
                                        len,
                                        pool: self.dgram_pool.clone(),
                                    });
                                }
                            }
                        }
                        Frame::Ack { ranges, .. } => {
                            // Sum acked bytes based on the PN->byte map.
                            let now = Instant::now();
                            let mut acked_total = 0usize;
                            let mut acked_remove = Vec::new();
                            let mut lost_remove = Vec::new();
                            let largest_acked = ranges
                                .iter()
                                .filter_map(|(_, end)| end.checked_sub(1))
                                .max()
                                .unwrap_or(0);
                            let packet_threshold = 3u64;
                            for (&pn, &sz) in self.sent_bytes_by_pn.iter() {
                                if ranges.iter().any(|(s, e)| pn >= *s && pn < *e) {
                                    acked_total = acked_total.saturating_add(sz);
                                    acked_remove.push(pn);
                                } else if pn.saturating_add(packet_threshold) <= largest_acked {
                                    lost_remove.push((pn, sz));
                                }
                            }
                            for pn in acked_remove {
                                self.sent_bytes_by_pn.remove(&pn);
                            }
                            let mut lost_total = 0usize;
                            for (pn, sz) in lost_remove {
                                self.sent_bytes_by_pn.remove(&pn);
                                self.recovery.on_loss_packet(pn, sz, now);
                                lost_total = lost_total.saturating_add(sz);
                                self.stats.lost = self.stats.lost.saturating_add(1);
                                self.stats.lost_bytes =
                                    self.stats.lost_bytes.saturating_add(sz as u64);
                            }
                            if acked_total > 0 {
                                self.recovery.on_ack(acked_total, now);
                                self.stats.acked_bytes =
                                    self.stats.acked_bytes.saturating_add(acked_total as u64);
                                self.cwnd = self.recovery.cwnd;
                            } else if lost_total > 0 {
                                self.cwnd = self.recovery.cwnd;
                            }
                        }
                        Frame::Crypto { offset, data } => {
                            let lvl = match pkt_ty {
                                PacketType::Initial => crate::tls_provider::Level::Initial,
                                PacketType::Handshake => crate::tls_provider::Level::Handshake,
                                _ => crate::tls_provider::Level::Application,
                            };
                            let _ = self.process_crypto_frame(lvl, offset, data);
                            ack_eliciting = true;
                        }
                        Frame::Ping { .. } => {
                            ack_eliciting = true;
                        }
                        Frame::ResetStream { .. } => {
                            // Transport-level RST indicator
                            crate::optimize::telemetry::STEALTH_SIGNAL_RST
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            ack_eliciting = true;
                        }
                        Frame::StopSending { .. } => {
                            // Transport-level stop-sending treated as soft RST indicator
                            crate::optimize::telemetry::STEALTH_SIGNAL_RST
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            ack_eliciting = true;
                        }
                        Frame::NewToken { .. }
                        | Frame::MaxStreamsBidi { .. }
                        | Frame::MaxStreamsUni { .. }
                        | Frame::DataBlocked { .. }
                        | Frame::StreamDataBlocked { .. }
                        | Frame::StreamsBlockedBidi { .. }
                        | Frame::StreamsBlockedUni { .. }
                        | Frame::NewConnectionId { .. }
                        | Frame::RetireConnectionId { .. }
                        | Frame::PathResponse { .. } => {
                            ack_eliciting = true;
                        }
                        _ => {}
                    }
                }
                Err(_) => {
                    break;
                }
            }
        }
        if ack_eliciting {
            self.pkt_spaces[space_idx].note_ack_eliciting();
        }

        // Update ECN counters for ACK ECN section (per-datagram)
        if let Some(mark) = info.ecn {
            match mark {
                EcnMark::Ect0 => self.ecn_ect0 = self.ecn_ect0.saturating_add(1),
                EcnMark::Ect1 => self.ecn_ect1 = self.ecn_ect1.saturating_add(1),
                EcnMark::Ce => self.ecn_ce = self.ecn_ce.saturating_add(1),
            }
            if let Some(obs) = &self.observer {
                obs.on_ecn_update(self.ecn_ect0, self.ecn_ect1, self.ecn_ce);
            }
        }
        // Update connection state
        let len = end;
        self.stats.recv += 1;
        self.stats.recv_bytes += len as u64;
        if !self.is_established && self.stats.recv > 0 && self.stats.sent > 0 {
            self.is_established = true;
        }
        Ok(len)
    }

    /// Generates outgoing packet
    #[inline(always)]
    pub fn send(
        &mut self,
        out: &mut [u8],
    ) -> Result<(usize, SendInfo), crate::error::ConnectionError> {
        use crate::error::ConnectionError;
        use udpfast::unlikely;
        if unlikely(out.len() < MIN_CLIENT_INITIAL_LEN) {
            return Err(ConnectionError::BufferTooShort);
        }
        // Congestion gate: only send if within cwnd budget
        if !self.recovery.can_send(self.dgram_send_max_size) {
            return Err(ConnectionError::Done);
        }

        // Opportunistic zerocopy completion drain (handle completions from previous sends)
        self.zerocopy_tick();

        // TLS provider may derive new secrets during write-side progression. Poll here so
        // handshake completion and key installation are not dependent on receiving more CRYPTO.
        if let Some(provider) = &mut self.tls_provider {
            provider.poll_secrets_and_install(&self.crypto)?;
        }

        let handshake_incomplete =
            self.tls_provider.as_ref().map(|p| !p.handshake_complete()).unwrap_or(false);

        // If TLS handshake not complete, attempt to send Initial/Handshake packet with CRYPTO frame
        if handshake_incomplete {
            let (has_initial, has_handshake) = {
                let crypto = self.crypto.read();
                (crypto.seal_initial.is_some(), crypto.seal_handshake.is_some())
            };
            // Try Initial first (when applicable), then Handshake. This avoids stalling if
            // Initial keys are installed but there is no pending Initial CRYPTO, while Handshake
            // CRYPTO is ready.
            for pkt_ty in [PacketType::Initial, PacketType::Handshake] {
                if matches!(pkt_ty, PacketType::Initial) && !has_initial {
                    continue;
                }
                if matches!(pkt_ty, PacketType::Handshake) && !has_handshake {
                    continue;
                }

                let token = if matches!(pkt_ty, PacketType::Initial) {
                    self.config.initial_token.clone()
                } else {
                    None
                };
                let base_hdr = packet::Header {
                    ty: match pkt_ty {
                        PacketType::Initial => packet::PacketType::Initial,
                        PacketType::Retry => packet::PacketType::Retry,
                        PacketType::Handshake => packet::PacketType::Handshake,
                        PacketType::ZeroRTT => packet::PacketType::ZeroRTT,
                        PacketType::VersionNegotiation => packet::PacketType::VersionNegotiation,
                        PacketType::Short => packet::PacketType::Short,
                    },
                    version: PROTOCOL_VERSION,
                    dcid: self.dcid.to_vec(),
                    scid: self.scid.to_vec(),
                    pkt_num: 0,
                    pkt_num_len: 0,
                    token,
                    versions: None,
                    key_phase: false,
                };
                let hdr_len_wo_pn = packet::format_header(&base_hdr, out)?;
                let space_idx = match pkt_ty {
                    PacketType::Initial => 0,
                    PacketType::Handshake => 1,
                    _ => 2,
                };
                let pn = self.next_send_pn_by_space[space_idx];
                let pn_len = if pn < (1 << 8) {
                    1
                } else if pn < (1 << 16) {
                    2
                } else if pn < (1 << 24) {
                    3
                } else {
                    4
                };
                if out.len() < hdr_len_wo_pn + pn_len {
                    return Err(ConnectionError::BufferTooShort);
                }
                let mut tmp = [0u8; 4];
                packet::encode_pkt_num(pn, pn_len, &mut tmp[..pn_len])?;
                out[hdr_len_wo_pn..hdr_len_wo_pn + pn_len].copy_from_slice(&tmp[..pn_len]);
                let header_len = hdr_len_wo_pn + pn_len;
                let mut off = header_len;

                let (lvl, max_len) = match pkt_ty {
                    PacketType::Initial => {
                        (crate::tls_provider::Level::Initial, out.len() - off - 16)
                    }
                    PacketType::Handshake => {
                        (crate::tls_provider::Level::Handshake, out.len() - off - 16)
                    }
                    _ => (crate::tls_provider::Level::Application, out.len() - off - 16),
                };
                if max_len < 32 {
                    continue;
                }
                let Some((crypto_off, data)) = self.next_crypto_frame(lvl, max_len) else {
                    continue;
                };

                if let Some((ack_delay, ack_ranges)) =
                    self.pkt_spaces[space_idx].take_ack(self.config.ack_delay_exponent)
                {
                    let ack = Frame::Ack { ack_delay, ranges: ack_ranges, ecn_counts: None };
                    let need = frames::wire_len(&ack);
                    if out.len() >= off + need + 16 {
                        off += frames::to_bytes(&ack, &mut out[off..])?;
                    }
                }
                let ping = Frame::Ping { mtu_probe: None };
                let _ = frames::to_bytes(&ping, &mut out[off..])?;
                off += 1;
                let frame = Frame::Crypto { offset: crypto_off, data };
                let written = frames::to_bytes(&frame, &mut out[off..])?;
                off += written;

                let pn_off = hdr_len_wo_pn;
                let sample_min = pn_off + 4 + packet::SAMPLE_LEN;
                let mut target_total = header_len + 16;
                if sample_min > target_total {
                    target_total = sample_min;
                }
                // Ensure we can actually carry the frames we already wrote, plus the AEAD tag.
                // sample_min only guarantees enough ciphertext for header protection sampling,
                // but we may have already written more plaintext than that budget.
                let frames_min_total = off.saturating_add(16);
                if frames_min_total > target_total {
                    target_total = frames_min_total;
                }
                if matches!(pkt_ty, PacketType::Initial) && MIN_CLIENT_INITIAL_LEN > target_total {
                    target_total = MIN_CLIENT_INITIAL_LEN;
                }
                if out.len() < target_total {
                    return Err(ConnectionError::BufferTooShort);
                }
                let target_off = target_total - 16;
                if off < target_off {
                    let pad_len = target_off - off;
                    let pad = Frame::Padding { len: pad_len };
                    let _ = frames::to_bytes(&pad, &mut out[off..])?;
                }

                if std::env::var("QUICFUSCATE_TRACE_TLS").is_ok() {
                    eprintln!(
                        "[send] role={} ty={:?} space={} pn={} pn_len={} hdr_len={} total={}",
                        if self.is_server { "server" } else { "client" },
                        pkt_ty,
                        space_idx,
                        pn,
                        pn_len,
                        header_len,
                        target_total
                    );
                }

                let used = {
                    let crypto = self.crypto.read();
                    packet::encrypt_and_protect(
                        &crypto,
                        &mut out[..target_total],
                        header_len,
                        pn,
                        pn_len,
                        match pkt_ty {
                            PacketType::Initial => packet::PacketType::Initial,
                            PacketType::Retry => packet::PacketType::Retry,
                            PacketType::Handshake => packet::PacketType::Handshake,
                            PacketType::ZeroRTT => packet::PacketType::ZeroRTT,
                            PacketType::VersionNegotiation => {
                                packet::PacketType::VersionNegotiation
                            }
                            PacketType::Short => packet::PacketType::Short,
                        },
                    )?
                };
                self.next_send_pn_by_space[space_idx] =
                    self.next_send_pn_by_space[space_idx].wrapping_add(1);
                self.stats.sent += 1;
                self.stats.sent_bytes += used as u64;
                if !self.is_established && self.stats.recv > 0 && self.stats.sent > 0 {
                    self.is_established = true;
                }
                return Ok((
                    used,
                    SendInfo { at: Instant::now(), from: self.local_addr, to: self.peer_addr },
                ));
            }

            return Err(ConnectionError::Done);
        }
        // Stealth timing gate (disabled when external pacing is active)
        if self.config.stealth_timing_enabled && !self.config.external_pacing {
            let now = Instant::now();
            if let Some(next) = self.next_send_at {
                if now < next {
                    return Err(ConnectionError::Done);
                }
            }
        }
        // Build short header prefix with DCID; we'll append PN bytes next
        let base_hdr = packet::Header {
            ty: packet::PacketType::Short,
            version: 0,
            dcid: self.dcid.to_vec(),
            scid: self.scid.to_vec(),
            pkt_num: 0,
            pkt_num_len: 0,
            token: None,
            versions: None,
            key_phase: false,
        };
        let hdr_len = packet::format_header(&base_hdr, out)?; // first byte + DCID
        let dcid_end = 1 + self.dcid.as_ref().len();
        // Decide packet number and length
        let pn = self.next_send_pn_by_space[2];
        let pn_len = if pn < (1 << 8) {
            1
        } else if pn < (1 << 16) {
            2
        } else if pn < (1 << 24) {
            3
        } else {
            4
        };
        if out.len() < hdr_len + pn_len {
            return Err(ConnectionError::BufferTooShort);
        }
        // Write truncated PN (big-endian) before encryption
        {
            let mut tmp = [0u8; 4];
            packet::encode_pkt_num(pn, pn_len, &mut tmp[..pn_len])?;
            out[dcid_end..dcid_end + pn_len].copy_from_slice(&tmp[..pn_len]);
        }
        let pn_off = dcid_end;
        let mut off = pn_off + pn_len;

        // Some TLS implementations (including rustls QUIC) can emit post-handshake data in the
        // application space. While the handshake is still in progress, prefer sending those
        // CRYPTO frames before other application traffic.
        if handshake_incomplete {
            let max_len = out.len().saturating_sub(off + 16);
            if max_len >= 32 {
                if let Some((crypto_off, data)) =
                    self.next_crypto_frame(crate::tls_provider::Level::Application, max_len)
                {
                    let frame = Frame::Crypto { offset: crypto_off, data };
                    let need = frames::wire_len(&frame);
                    if out.len() >= off + need + 16 {
                        off += frames::to_bytes(&frame, &mut out[off..])?;
                    }
                }
            }
        }

        // Flush pending control frames first (MAX_DATA / MAX_STREAM_DATA)
        while let Some(ctrl) = self.pending_control.front().cloned() {
            let need = frames::wire_len(&ctrl);
            // Leave space for AEAD tag (16 bytes) if we will encrypt
            let tag_reserve = if self.crypto.read().seal_1rtt.is_some() { 16 } else { 0 };
            if out.len() >= off + need + tag_reserve {
                off += frames::to_bytes(&ctrl, &mut out[off..])?;
                self.pending_control.pop_front();
            } else {
                break;
            }
        }
        // If we have anything to ack, emit an ACK frame
        // Prefer Application epoch for outgoing short header ACKs
        if let Some((ack_delay, ack_ranges)) =
            self.pkt_spaces[2].take_ack(self.config.ack_delay_exponent)
        {
            let ecn = if self.ecn_ect0 | self.ecn_ect1 | self.ecn_ce > 0 {
                Some(EcnCounts { ect0: self.ecn_ect0, ect1: self.ecn_ect1, ce: self.ecn_ce })
            } else {
                None
            };
            let ack = Frame::Ack { ack_delay, ranges: ack_ranges, ecn_counts: ecn };
            let need = frames::wire_len(&ack);
            let tag_reserve = if self.crypto.read().seal_1rtt.is_some() { 16 } else { 0 };
            let mut ack_written = false;
            if out.len() >= off + need + tag_reserve {
                off += frames::to_bytes(&ack, &mut out[off..])?;
                ack_written = true;
            }
            if ack_written {
                if let Some(obs) = &self.observer {
                    if let Frame::Ack { ranges, .. } = &ack {
                        obs.on_ack(ack_delay, ranges);
                    }
                }
                // Reset ECN counters after emitting ACK with ECN
                if matches!(&ack, Frame::Ack { ecn_counts: Some(_), .. }) {
                    self.ecn_ect0 = 0;
                    self.ecn_ect1 = 0;
                    self.ecn_ce = 0;
                }
                // Telemetry: record effective ACK delay in microseconds (ack_delay << exponent)
                let exp = self.config.ack_delay_exponent.min(20);
                let ack_delay_us = ack_delay << exp;
                crate::telemetry::ACK_DELAY_LAST_US
                    .store(ack_delay_us, std::sync::atomic::Ordering::Relaxed);
                // Allow observer to apply transport policy based on latest telemetry
                // Clone Arc to avoid borrow conflict when passing &mut self
                if let Some(obs) = self.observer.as_ref().cloned() {
                    obs.apply_policy(self);
                }
            }
        }
        // Try to flush one writable stream
        if let Some(stream_id) = self.writable_streams.front().copied() {
            // Carry payload for FEC out of the mutable borrow scope to avoid borrow conflicts
            if let Some(s) = self.streams.get_mut(&stream_id) {
                // Determine available bytes depending on buffer implementation
                let available = {
                    #[cfg(not(feature = "stream_ring_buffer"))]
                    {
                        s.send_buf.len()
                    }
                    #[cfg(feature = "stream_ring_buffer")]
                    {
                        s.send_ring.len()
                    }
                };
                if available > 0 {
                    // Estimate header overhead for stream frame
                    let header_overhead = 1
                        + crate::transport::varint::varint_len(stream_id)
                        + crate::transport::varint::varint_len(s.send_off)
                        + 2;
                    let tag_reserve = if self.crypto.read().seal_1rtt.is_some() { 16 } else { 0 };
                    if off + header_overhead + tag_reserve < out.len() {
                        // Prefetch stream payload buffer to speed up copy/read
                        #[cfg(not(feature = "stream_ring_buffer"))]
                        if !s.send_buf.is_empty() {
                            unsafe {
                                crate::fec::prefetch_data(s.send_buf.as_ptr());
                            }
                        }
                        let max_body = out.len() - off - header_overhead - tag_reserve;
                        // Respect sender flow control
                        let conn_avail =
                            self.peer_max_data.saturating_sub(self.conn_bytes_sent) as usize;
                        let stream_avail = s.max_stream_data_tx.saturating_sub(s.send_off) as usize;
                        let send_avail = conn_avail.min(stream_avail);
                        if send_avail == 0 {
                            self.pending_control
                                .push_back(Frame::DataBlocked { limit: self.peer_max_data });
                            self.pending_control.push_back(Frame::StreamDataBlocked {
                                stream_id,
                                limit: s.max_stream_data_tx,
                            });
                            return Err(ConnectionError::Done);
                        }
                        let body_len = std::cmp::min(max_body, available.min(send_avail));
                        // Build frame payload depending on buffer implementation
                        #[cfg(not(feature = "stream_ring_buffer"))]
                        let data_vec = s.send_buf[..body_len].to_vec();
                        #[cfg(feature = "stream_ring_buffer")]
                        let data_vec = {
                            let mut v = vec![0u8; body_len];
                            let read = s.send_ring.read(&mut v[..]);
                            if read < body_len {
                                v.truncate(read);
                            }
                            v
                        };
                        let data_len = data_vec.len();
                        let fin_now = {
                            #[cfg(not(feature = "stream_ring_buffer"))]
                            {
                                s.send_fin && body_len == available
                            }
                            #[cfg(feature = "stream_ring_buffer")]
                            {
                                s.send_fin && s.send_ring.is_empty()
                            }
                        };
                        let frame = Frame::Stream {
                            stream_id: s.id,
                            offset: s.send_off,
                            data: data_vec,
                            fin: fin_now,
                        };
                        let written = frames::to_bytes(&frame, &mut out[off..])?;
                        off += written;
                        s.send_off += data_len as u64;
                        #[cfg(not(feature = "stream_ring_buffer"))]
                        {
                            s.send_buf.drain(0..data_len);
                        }
                        self.conn_bytes_sent = self.conn_bytes_sent.saturating_add(data_len as u64);
                        self.stats.stream_sent_bytes += data_len as u64;
                        // FEC feeding removed (Core-FEC handles redundancy outside transport)
                        let emptied = {
                            #[cfg(not(feature = "stream_ring_buffer"))]
                            {
                                s.send_buf.is_empty()
                            }
                            #[cfg(feature = "stream_ring_buffer")]
                            {
                                s.send_ring.is_empty()
                            }
                        };
                        if emptied && fin_now {
                            self.writable_streams.retain(|&id| id != stream_id);
                        }
                    }
                }
            }
        }
        // FEC feed removed (handled by core)

        // Flush one DATAGRAM frame if space allows
        if let Some(front) = self.dgram_send_queue.front() {
            // type (1) + length (2) + data
            #[cfg(not(feature = "zero_copy_dgram"))]
            let need = 1 + 2 + front.len();
            #[cfg(feature = "zero_copy_dgram")]
            let need = 1 + 2 + front.len;
            let tag_reserve = if self.crypto.read().seal_1rtt.is_some() { 16 } else { 0 };
            if off + need + tag_reserve <= out.len() {
                #[cfg(not(feature = "zero_copy_dgram"))]
                {
                    let Some(front_owned) = self.dgram_send_queue.pop_front() else {
                        return Err(ConnectionError::Done);
                    };
                    // Prefetch datagram payload buffer before encode
                    unsafe {
                        crate::fec::prefetch_data(front_owned.as_ptr());
                    }
                    let frame = Frame::Datagram { data: front_owned };
                    match frames::to_bytes(&frame, &mut out[off..]) {
                        Ok(written) => {
                            off += written;
                        }
                        Err(e) => {
                            if let Frame::Datagram { data } = frame {
                                self.dgram_send_queue.push_front(data);
                            }
                            return Err(e);
                        }
                    }
                }
                #[cfg(feature = "zero_copy_dgram")]
                {
                    let frame = Frame::Datagram { data: front.data[..front.len].to_vec() };
                    let written = frames::to_bytes(&frame, &mut out[off..])?;
                    off += written;
                    // Remove from queue after encoding
                    let _ = self.dgram_send_queue.pop_front();
                }
            }
        }

        // Stealth padding before sealing (so padding is authenticated and encrypted)
        if self.config.stealth_padding_enabled {
            let ad_len = pn_off + pn_len;
            let pt_len_now = off.saturating_sub(ad_len);
            let tag_reserve = if self.crypto.read().seal_1rtt.is_some() { 16 } else { 0 };
            let avail = out.len().saturating_sub(off + tag_reserve);
            if avail > 0 {
                let pad_len = self.compute_stealth_padding(pt_len_now, avail);
                if pad_len > 0 {
                    let pad = Frame::Padding { len: pad_len };
                    let written = frames::to_bytes(&pad, &mut out[off..])?;
                    off += written;
                }
            }
        }

        // If we have AEAD secrets, seal payload and apply header protection.
        // Prefer 1-RTT sealer, otherwise fall back to 0-RTT.
        let crypto_guard = self.crypto.read();
        if let Some(seal) = crypto_guard.seal_1rtt.as_deref().or(crypto_guard.seal_0rtt.as_deref())
        {
            // Associated data is header (first byte + DCID + PN)
            let ad_len = pn_off + pn_len;
            // Seal in place using disjoint slices for AD and payload
            let (ad_slice, rest) = out.split_at_mut(ad_len);
            let pt_len = off.saturating_sub(ad_len);
            let sealed_len = seal.seal_with_u64_counter(pn, ad_slice, rest, pt_len, None)?;
            off = ad_len + sealed_len; // include tag
                                       // Apply header protection using sample starting at pn_off + 4
            let hp = if crypto_guard.seal_1rtt.is_some() {
                crypto_guard.hp_1rtt.as_deref()
            } else {
                crypto_guard.hp_0rtt.as_deref().or(crypto_guard.hp_1rtt.as_deref())
            };
            if let Some(hp) = hp {
                // Only apply header protection if the actual packet length contains the sample.
                // `out.len()` is the caller-provided capacity and may be far larger than the
                // bytes we wrote into this packet.
                if off >= pn_off + 4 + packet::SAMPLE_LEN {
                    let sample = &out[pn_off + 4..pn_off + 4 + packet::SAMPLE_LEN];
                    // Original first byte: fixed bit + PN len-1 (+ KeyPhase ggf.)
                    let mut first_orig = 0x40 | (((pn_len as u8) - 1) & 0x03);
                    if self.key_phase {
                        first_orig |= packet::KEY_PHASE_BIT;
                    }
                    // XOR-mask first and PN bytes
                    let mask = hp.new_mask(sample);
                    // first
                    let protected_first = first_orig ^ (mask[0] & 0x1f);
                    out[0] = protected_first;
                    // pn bytes
                    for i in 0..pn_len {
                        out[pn_off + i] ^= mask[i + 1];
                    }
                } else {
                    // If sample not available due to tiny payload, leave header unprotected
                    out[0] = (0x40 | (((pn_len as u8) - 1) & 0x03))
                        | if self.key_phase { packet::KEY_PHASE_BIT } else { 0 };
                }
            } else {
                // No HP: write original first byte (no key phase)
                out[0] = (0x40 | (((pn_len as u8) - 1) & 0x03))
                    | if self.key_phase { packet::KEY_PHASE_BIT } else { 0 };
            }
            // Advance send PN
            self.next_send_pn_by_space[2] = self.next_send_pn_by_space[2].wrapping_add(1);
        } else {
            // No AEAD configured: keep plaintext header/payload
            out[0] = (0x40 | (((pn_len as u8) - 1) & 0x03))
                | if self.key_phase { packet::KEY_PHASE_BIT } else { 0 };
        }

        // Mark bytes-in-flight timing start if we actually wrote payload beyond header
        if off > (pn_off + pn_len) && self.bytes_in_flight_started.is_none() {
            self.bytes_in_flight_started = Some(Instant::now());
        }
        // Maintain minimal paths_count
        self.stats.paths_count = 1;

        // Legacy transport-level FEC removed

        // Stealth-friendly: do not force 1200-byte minimum for short-header packets
        let total = off;
        let info = SendInfo { from: self.local_addr, to: self.peer_addr, at: Instant::now() };
        self.stats.sent += 1;
        self.stats.sent_bytes += total as u64;
        if !self.is_established && self.stats.recv > 0 && self.stats.sent > 0 {
            self.is_established = true;
        }
        // Update recovery bytes-in-flight and mirror cwnd
        self.recovery.on_packet_sent(pn, total, Instant::now());
        // Track sent bytes by packet number for precise ACK accounting
        self.sent_bytes_by_pn.insert(pn, total);
        self.cwnd = self.recovery.cwnd;
        // Schedule next send time if timing obfuscation is enabled
        if self.config.stealth_timing_enabled && !self.config.external_pacing {
            let max_jitter_us = crate::brain::timing_jitter_hint_us()
                .unwrap_or(self.config.stealth_timing_max_jitter_us);
            if max_jitter_us > 0 {
                let jitter = crate::transport::rand::rand_u64_uniform(max_jitter_us as u64 + 1);
                let next = Instant::now() + Duration::from_micros(jitter);
                self.next_send_at = Some(next);
            }
        }
        Ok((total, info))
    }

    /// Compute stealth padding length given current plaintext payload length and budget.
    #[inline(always)]
    pub(crate) fn compute_stealth_padding(&self, cur_pt_len: usize, budget: usize) -> usize {
        if !self.config.stealth_padding_enabled {
            return 0;
        }
        let max = self.config.stealth_padding_max_size.min(budget);
        if max == 0 {
            return 0;
        }
        match self.config.stealth_padding_strategy {
            // 1 = Random [0..=max]
            1 => crate::transport::rand::rand_u64_uniform((max as u64).saturating_add(1)) as usize,
            // 2 = Fixed (always pad up to max budget)
            2 => max,
            // 3 = Adaptive (pad up to next 64B boundary, capped by max)
            3 => {
                let g = self.config.stealth_adaptive_granularity.max(1) as usize;
                let rem = cur_pt_len % g;
                if rem == 0 {
                    0
                } else {
                    std::cmp::min(g - rem, max)
                }
            }
            // 4 = BrowserMimic: bias profile to small values; bucket depends on bias
            4 => {
                let (bucket_div, samples) = match self.config.stealth_mimic_bias {
                    1 => (8usize, 3), // very small (Safari/iOS)
                    2 => (6usize, 2), // small (Firefox/Linux)
                    4 => (5usize, 2), // mobile (Android)
                    _ => (4usize, 2), // default (Chromium/Windows)
                };
                let bucket = (max / bucket_div).max(1) as u64;
                let mut val = crate::transport::rand::rand_u64_uniform(bucket + 1);
                for _ in 1..samples {
                    let r = crate::transport::rand::rand_u64_uniform(bucket + 1);
                    if r < val {
                        val = r;
                    }
                }
                std::cmp::min(val as usize, max)
            }
            _ => 0,
        }
    }

    /// Returns the current key phase (short header KEY_PHASE bit).
    pub fn key_phase(&self) -> bool {
        self.key_phase
    }

    /// Sets the key phase bit for the short header (header signal only, no key rotation).
    pub fn set_key_phase_bit(&mut self, enabled: bool) {
        self.key_phase = enabled;
    }

    /// Performs a 1-RTT key update (simplified, synced for read/write) and toggles the header bit.
    pub fn key_update(&mut self) {
        {
            let mut crypto = self.crypto.write();
            crypto.key_update_1rtt();
        }
        self.key_phase = !self.key_phase;
    }

    /// Receives data from a stream
    #[inline(always)]
    pub fn stream_recv(
        &mut self,
        stream_id: u64,
        buf: &mut [u8],
    ) -> Result<(usize, bool), crate::error::ConnectionError> {
        // Receive stream data
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(crate::error::ConnectionError::InvalidStreamState(stream_id))?;

        let len: usize;
        #[cfg(not(feature = "stream_ring_buffer"))]
        {
            let l = std::cmp::min(buf.len(), stream.recv_buf.len());
            buf[..l].copy_from_slice(&stream.recv_buf[..l]);
            stream.recv_buf.drain(..l);
            len = l;
        }
        #[cfg(feature = "stream_ring_buffer")]
        {
            len = stream.recv_ring.read(buf);
        }

        #[cfg(not(feature = "stream_ring_buffer"))]
        let fin = stream.recv_fin && stream.recv_buf.is_empty();
        #[cfg(feature = "stream_ring_buffer")]
        let fin = stream.recv_fin && stream.recv_ring.is_empty();
        Ok((len, fin))
    }

    /// Sends data on a stream
    #[inline(always)]
    pub fn stream_send(
        &mut self,
        stream_id: u64,
        buf: &[u8],
        fin: bool,
    ) -> Result<usize, crate::error::ConnectionError> {
        // Send stream data
        // Compute connection-level pending bytes before borrowing a specific stream mutably
        let pending_conn_after = (self.conn_bytes_sent)
            .saturating_add(self.total_send_buffered_bytes() as u64)
            .saturating_add(buf.len() as u64);
        if pending_conn_after > self.peer_max_data {
            // Inform peer we are blocked by connection window
            self.pending_control.push_back(Frame::DataBlocked { limit: self.peer_max_data });
            return Err(crate::error::ConnectionError::FlowControl);
        }

        let stream = self.streams.entry(stream_id).or_insert_with(|| Stream {
            id: stream_id,
            #[cfg(not(feature = "stream_ring_buffer"))]
            send_buf: Vec::new(),
            #[cfg(not(feature = "stream_ring_buffer"))]
            recv_buf: Vec::new(),
            #[cfg(feature = "stream_ring_buffer")]
            send_ring: StreamRingBuffer::new(),
            #[cfg(feature = "stream_ring_buffer")]
            recv_ring: StreamRingBuffer::new(),
            send_fin: false,
            recv_fin: false,
            send_off: 0,
            recv_off: 0,
            recv_next: 0,
            recv_final_size: None,
            recv_frags: std::collections::BTreeMap::new(),
            priority_urgency: 3,
            priority_incremental: false,
            max_stream_data_rx: self.config.initial_max_stream_data_bidi_local,
            max_stream_data_tx: self.config.initial_max_stream_data_bidi_remote,
        });

        // Sender-side flow control checks (per-stream)
        let pending_stream_after = {
            #[cfg(not(feature = "stream_ring_buffer"))]
            {
                stream
                    .send_off
                    .saturating_add(stream.send_buf.len() as u64)
                    .saturating_add(buf.len() as u64)
            }
            #[cfg(feature = "stream_ring_buffer")]
            {
                stream
                    .send_off
                    .saturating_add(stream.send_ring.len() as u64)
                    .saturating_add(buf.len() as u64)
            }
        };
        if pending_stream_after > stream.max_stream_data_tx {
            self.pending_control.push_back(Frame::StreamDataBlocked {
                stream_id,
                limit: stream.max_stream_data_tx,
            });
            return Err(crate::error::ConnectionError::FlowControl);
        }

        if stream.send_fin {
            return Err(crate::error::ConnectionError::FinalSize);
        }
        // Append payload and mark FIN if requested
        #[cfg(not(feature = "stream_ring_buffer"))]
        stream.send_buf.extend_from_slice(buf);
        #[cfg(feature = "stream_ring_buffer")]
        {
            let written = stream.send_ring.write(buf);
            if written < buf.len() {
                return Err(crate::error::ConnectionError::InvalidState);
            }
        }
        stream.send_fin = fin;
        if !self.writable_streams.contains(&stream_id) {
            let urgency = self.streams.get(&stream_id).map(|s| s.priority_urgency).unwrap_or(3);
            let mut insert_at = None;
            for (idx, id) in self.writable_streams.iter().enumerate() {
                if let Some(s) = self.streams.get(id) {
                    if urgency < s.priority_urgency {
                        insert_at = Some(idx);
                        break;
                    }
                }
            }
            if let Some(idx) = insert_at {
                self.writable_streams.insert(idx, stream_id);
            } else {
                self.writable_streams.push_back(stream_id);
            }
        }

        Ok(buf.len())
    }

    #[inline(always)]
    pub fn dgram_recv(&mut self, buf: &mut [u8]) -> Result<usize, crate::error::ConnectionError> {
        if self.dgram_recv_queue.is_empty() {
            return Err(crate::error::ConnectionError::Done);
        }
        #[cfg(not(feature = "zero_copy_dgram"))]
        {
            let dgram =
                self.dgram_recv_queue.pop_front().ok_or(crate::error::ConnectionError::Done)?;
            let len = std::cmp::min(buf.len(), dgram.len());
            buf[..len].copy_from_slice(&dgram[..len]);
            self.stats.dgram_recv += 1;
            Ok(len)
        }
        #[cfg(feature = "zero_copy_dgram")]
        {
            let dgram =
                self.dgram_recv_queue.pop_front().ok_or(crate::error::ConnectionError::Done)?;
            let len = std::cmp::min(buf.len(), dgram.len);
            buf[..len].copy_from_slice(&dgram.data[..len]);
            self.stats.dgram_recv += 1;
            Ok(len)
        }
    }

    #[inline(always)]
    pub fn dgram_send(&mut self, buf: &[u8]) -> Result<(), crate::error::ConnectionError> {
        if buf.len() > self.dgram_send_max_size {
            return Err(crate::error::ConnectionError::InvalidState);
        }
        if self.is_dgram_send_queue_full() {
            return Err(crate::error::ConnectionError::InvalidState);
        }
        #[cfg(not(feature = "zero_copy_dgram"))]
        {
            self.dgram_send_queue.push_back(buf.to_vec());
        }
        #[cfg(feature = "zero_copy_dgram")]
        {
            let mut data = self.dgram_pool.alloc();
            let len = buf.len().min(data.len());
            data[..len].copy_from_slice(&buf[..len]);
            self.dgram_send_queue.push_back(DatagramBuffer {
                data,
                len,
                pool: self.dgram_pool.clone(),
            });
        }
        self.stats.dgram_sent += 1;
        Ok(())
    }

    pub fn dgram_recv_vec(&mut self) -> Result<Vec<u8>, crate::error::ConnectionError> {
        if self.dgram_recv_queue.is_empty() {
            return Err(crate::error::ConnectionError::Done);
        }
        #[cfg(not(feature = "zero_copy_dgram"))]
        {
            self.stats.dgram_recv += 1;
            if let Some(v) = self.dgram_recv_queue.pop_front() {
                Ok(v)
            } else {
                Err(crate::error::ConnectionError::Done)
            }
        }
        #[cfg(feature = "zero_copy_dgram")]
        {
            let Some(dgram) = self.dgram_recv_queue.pop_front() else {
                return Err(crate::error::ConnectionError::Done);
            };
            let mut vec = vec![0u8; dgram.len];
            vec.copy_from_slice(&dgram.data[..dgram.len]);
            self.stats.dgram_recv += 1;
            Ok(vec)
        }
    }

    pub fn dgram_recv_peek(
        &self,
        buf: &mut [u8],
        len: usize,
    ) -> Result<usize, crate::error::ConnectionError> {
        if self.dgram_recv_queue.is_empty() {
            return Err(crate::error::ConnectionError::Done);
        }
        #[cfg(not(feature = "zero_copy_dgram"))]
        {
            let front = &self.dgram_recv_queue[0];
            let n = std::cmp::min(len, std::cmp::min(buf.len(), front.len()));
            buf[..n].copy_from_slice(&front[..n]);
            Ok(n)
        }
        #[cfg(feature = "zero_copy_dgram")]
        {
            let front = &self.dgram_recv_queue[0];
            let n = std::cmp::min(len, std::cmp::min(buf.len(), front.len));
            buf[..n].copy_from_slice(&front.data[..n]);
            Ok(n)
        }
    }

    pub fn dgram_recv_front_len(&self) -> Option<usize> {
        #[cfg(not(feature = "zero_copy_dgram"))]
        return self.dgram_recv_queue.front().map(|v| v.len());
        #[cfg(feature = "zero_copy_dgram")]
        return self.dgram_recv_queue.front().map(|v| v.len);
    }

    pub fn dgram_recv_queue_len(&self) -> usize {
        self.dgram_recv_queue.len()
    }
    pub fn dgram_recv_queue_byte_size(&self) -> usize {
        #[cfg(not(feature = "zero_copy_dgram"))]
        return self.dgram_recv_queue.iter().map(|v| v.len()).sum();
        #[cfg(feature = "zero_copy_dgram")]
        return self.dgram_recv_queue.iter().map(|v| v.len).sum();
    }
    pub fn dgram_send_queue_len(&self) -> usize {
        self.dgram_send_queue.len()
    }
    pub fn dgram_send_queue_byte_size(&self) -> usize {
        #[cfg(not(feature = "zero_copy_dgram"))]
        return self.dgram_send_queue.iter().map(|v| v.len()).sum();
        #[cfg(feature = "zero_copy_dgram")]
        return self.dgram_send_queue.iter().map(|v| v.len).sum();
    }
    pub fn is_dgram_send_queue_full(&self) -> bool {
        let lim = self.config.dgram_send_max_queue_len;
        lim > 0 && self.dgram_send_queue.len() >= lim
    }
    pub fn is_dgram_recv_queue_full(&self) -> bool {
        let lim = self.config.dgram_recv_max_queue_len;
        lim > 0 && self.dgram_recv_queue.len() >= lim
    }
    pub fn dgram_send_vec(&mut self, buf: Vec<u8>) -> Result<(), crate::error::ConnectionError> {
        if buf.len() > self.dgram_send_max_size {
            return Err(crate::error::ConnectionError::InvalidState);
        }
        // Delegate to dgram_send so zero_copy path is handled uniformly
        let r = self.dgram_send(&buf[..]);
        // Periodic zerocopy drain
        self.zerocopy_tick();
        r
    }
    pub fn dgram_purge_outgoing<FN: Fn(&[u8]) -> bool>(&mut self, f: FN) {
        #[cfg(not(feature = "zero_copy_dgram"))]
        {
            self.dgram_send_queue.retain(|d| !f(d));
        }
        #[cfg(feature = "zero_copy_dgram")]
        {
            self.dgram_send_queue.retain(|d| !f(&d.data[..d.len]));
        }
    }
    pub fn dgram_max_writable_len(&self) -> Option<usize> {
        if self.is_dgram_send_queue_full() {
            None
        } else {
            Some(self.dgram_send_max_size)
        }
    }

    /// Returns true if the connection is established
    pub fn is_established(&self) -> bool {
        self.is_established
    }

    /// Returns true if the connection is closed
    pub fn is_closed(&self) -> bool {
        self.is_closed
    }
    /// Returns true if the connection has any readable streams
    pub fn is_readable(&self) -> bool {
        !self.readable_streams.is_empty()
    }
    /// Returns trace id (hex of scid)
    pub fn trace_id(&self) -> &str {
        &self.trace_id
    }
    /// Returns whether this is a server-side connection
    pub fn is_server(&self) -> bool {
        self.is_server
    }

    pub fn recovery_mut(&mut self) -> &mut recovery::Recovery {
        &mut self.recovery
    }

    pub fn fec_escalation_threshold(&self) -> f32 {
        self.fec_escalation_threshold
    }
    /// Whether path is validated (minimal: true for now)
    pub fn is_path_validated(&self, _from: SocketAddr, _to: SocketAddr) -> bool {
        true
    }
    /// Returns true if the connection is draining
    pub fn is_draining(&self) -> bool {
        self.is_draining
    }
    /// Returns true if the connection has timed out
    pub fn is_timed_out(&self) -> bool {
        self.timeout_count > 0
    }
    /// Returns true when a session ticket is present in config or provider state.
    pub fn is_resumed(&self) -> bool {
        let cfg_ticket = self.config.tls_session.as_ref().map(|t| !t.is_empty()).unwrap_or(false);
        let provider_ticket = self
            .tls_provider
            .as_ref()
            .and_then(|p| p.session_ticket())
            .map(|t| !t.is_empty())
            .unwrap_or(false);
        cfg_ticket || provider_ticket
    }
    /// Returns true while 0-RTT is allowed and handshake has not fully established.
    pub fn is_in_early_data(&self) -> bool {
        self.config.enable_early_data && !self.is_established && !self.is_closed
    }

    /// Returns connection statistics
    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Lightweight telemetry: ECN counters since last ACK emission
    pub fn ecn_counts(&self) -> (u64, u64, u64) {
        (self.ecn_ect0, self.ecn_ect1, self.ecn_ce)
    }

    /// Current send quantum (bytes) derived from recovery
    pub fn send_quantum(&self) -> usize {
        self.recovery.send_quantum()
    }
    /// True if we can send at least one datagram of size `sz` within cwnd
    pub fn can_send(&self, sz: usize) -> bool {
        self.bytes_in_flight.saturating_add(sz) <= self.cwnd
    }

    /// Current RTT estimate
    pub fn rtt(&self) -> Duration {
        self.rtt
    }

    /// Bytes currently considered in flight
    pub fn bytes_in_flight(&self) -> usize {
        self.bytes_in_flight
    }

    /// Estimated delivery rate (bytes/s)
    pub fn delivery_rate(&self) -> u64 {
        self.stats.delivery_rate
    }

    /// ACK-eliciting threshold (packets) before emitting ACK
    pub fn ack_eliciting_threshold(&self) -> u64 {
        self.config.ack_eliciting_threshold
    }

    /// Whether external pacing is enabled (internal sleeps disabled)
    pub fn external_pacing_enabled(&self) -> bool {
        self.config.external_pacing
    }

    /// Set or clear the transport observer (integration hook)
    pub fn set_observer(&mut self, obs: Option<Arc<dyn TransportObserver>>) {
        self.observer = obs;
    }

    fn install_recovery_fec_callbacks(&mut self) {
        let sent_pkts = Arc::clone(&self.fec_cb_sent_packets);
        let lost_pkts = Arc::clone(&self.fec_cb_lost_packets);
        let sent_bytes = Arc::clone(&self.fec_cb_sent_bytes);
        let lost_bytes = Arc::clone(&self.fec_cb_lost_bytes);
        self.recovery.set_fec_callbacks(
            move |_pn, bytes| {
                sent_pkts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                sent_bytes.fetch_add(bytes as u64, std::sync::atomic::Ordering::Relaxed);
            },
            move |_pn, bytes| {
                lost_pkts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                lost_bytes.fetch_add(bytes as u64, std::sync::atomic::Ordering::Relaxed);
            },
        );
    }
    /// Adjust ACK-eliciting threshold at runtime
    pub fn set_ack_eliciting_threshold(&mut self, thr: u64) {
        self.config.ack_eliciting_threshold = thr.max(1);
    }
    /// Toggle external pacing controller at runtime
    pub fn set_external_pacing(&mut self, v: bool) {
        self.config.external_pacing = v;
    }
    /// Adjust streaming FEC emission interval (AdaptiveFec only)
    pub fn set_fec_stream_every(&mut self, every: usize) {
        self.fec_ctrl_delta.stream_every = Some(every.clamp(1, 32));
    }
    /// Enable/disable stealth timing and set max jitter
    pub fn set_stealth_timing(&mut self, enabled: bool, max_jitter_us: u32) {
        self.config.stealth_timing_enabled = enabled;
        self.config.stealth_timing_max_jitter_us = max_jitter_us;
    }
    /// Set adaptive padding granularity (>=1)
    pub fn set_stealth_adaptive_granularity(&mut self, gran: u16) {
        self.config.stealth_adaptive_granularity = if gran == 0 { 1 } else { gran };
    }
    /// Set browser mimic bias (1..=4)
    pub fn set_stealth_mimic_bias(&mut self, bias: u8) {
        self.config.stealth_mimic_bias = match bias {
            1..=4 => bias,
            _ => 3,
        };
    }
    /// Adjust stealth padding parameters at runtime
    pub fn set_stealth_padding(&mut self, enabled: bool, strategy: u8, max_size: usize) {
        self.config.stealth_padding_enabled = enabled;
        self.config.stealth_padding_strategy = strategy;
        self.config.stealth_padding_max_size = max_size;
    }
    /// Adjust recovery batch size (SIMD batching) to trade CPU vs. robustness
    pub fn set_fec_batch_size(&mut self, size: usize) {
        self.recovery.set_batch_size(size);
        self.fec_batch_size = size;
    }
    /// Set FEC redundancy factor (0.0..=2.0)
    pub fn set_fec_redundancy_factor(&mut self, f: f32) {
        self.fec_redundancy_factor = f.clamp(0.0, 2.0);
    }
    /// Configure CC stealth profile to shape pacing like common browsers
    pub fn set_cc_stealth_profile(
        &mut self,
        enabled: bool,
        profile: crate::transport::recovery::BrowserProfile,
    ) {
        self.recovery.set_stealth_mode(enabled, profile);
    }
    /// Force AdaptiveFec into streaming mode for minimal latency
    pub fn force_fec_streaming(&mut self) {
        self.fec_ctrl_delta.force_streaming = true;
    }
    /// Set redundancy hint in parts-per-million on AdaptiveFec (if present)
    pub fn set_fec_redundancy_ppm(&mut self, ppm: u32) {
        self.fec_ctrl_delta.redundancy_ppm = Some(ppm);
    }

    /// Take and clear pending FEC control delta (to be consumed by core FEC)
    pub fn take_fec_control_delta(&mut self) -> FecControlDelta {
        let d = self.fec_ctrl_delta;
        self.fec_ctrl_delta = FecControlDelta::default();
        d
    }

    /// Take and reset recovery callback feedback counters.
    pub fn take_fec_callback_feedback(&self) -> (u64, u64, u64, u64) {
        (
            self.fec_cb_sent_packets.swap(0, std::sync::atomic::Ordering::Relaxed),
            self.fec_cb_lost_packets.swap(0, std::sync::atomic::Ordering::Relaxed),
            self.fec_cb_sent_bytes.swap(0, std::sync::atomic::Ordering::Relaxed),
            self.fec_cb_lost_bytes.swap(0, std::sync::atomic::Ordering::Relaxed),
        )
    }

    /// Returns the negotiated ALPN protocol
    pub fn application_proto(&self) -> &[u8] {
        b"h3"
    }

    /// Returns the source connection ID
    pub fn source_id(&self) -> &ConnectionId {
        &self.scid
    }

    /// Returns the destination connection ID
    pub fn destination_id(&self) -> &ConnectionId {
        // Touch dest_cids to maintain active use (e.g., for CID rotation/migration readiness)
        let _ = self.dest_cids.contains(&self.dcid);
        &self.dcid
    }
    /// Issues a new source connection ID (minimal: inserts into set)
    pub fn new_scid(&mut self, cid: &ConnectionId) -> Result<(), crate::error::ConnectionError> {
        self.source_cids.insert(cid);
        Ok(())
    }
    /// Returns all source IDs (minimal: only current scid)
    pub fn source_ids(&self) -> impl Iterator<Item = &ConnectionId> {
        std::iter::once(&self.scid)
    }
    /// Peer streams left (bidi)
    pub fn peer_streams_left_bidi(&self) -> u64 {
        self.config.initial_max_streams_bidi
    }
    /// Peer streams left (uni)
    pub fn peer_streams_left_uni(&self) -> u64 {
        self.config.initial_max_streams_uni
    }

    /// Closes the connection
    pub fn close(
        &mut self,
        app: bool,
        err: u64,
        reason: &[u8],
    ) -> Result<(), crate::error::ConnectionError> {
        self.is_closed = true;
        self.is_draining = true;
        self.local_error = Some(crate::error::ConnectionError::ApplicationClosed);
        // Emit Close frame into control queue.
        if app {
            self.pending_control
                .push_back(Frame::ApplicationClose { error_code: err, reason: reason.to_vec() });
        } else {
            // frame_type=0 (unknown) in minimal implementation
            self.pending_control.push_back(Frame::ConnectionClose {
                error_code: err,
                frame_type: 0,
                reason: reason.to_vec(),
            });
        }
        Ok(())
    }

    /// Returns the connection timeout
    pub fn timeout(&self) -> Option<Duration> {
        Some(Duration::from_millis(30000))
    }
    pub fn timeout_instant(&self) -> Option<Instant> {
        self.timeout().map(|d| Instant::now() + d)
    }

    /// Handles timeout
    pub fn on_timeout(&mut self) {
        // Handle connection timeout
        self.timeout_count += 1;

        // Retransmit lost packets
        for stream in self.streams.values_mut() {
            let has_pending = {
                #[cfg(not(feature = "stream_ring_buffer"))]
                {
                    !stream.send_buf.is_empty()
                }
                #[cfg(feature = "stream_ring_buffer")]
                {
                    !stream.send_ring.is_empty()
                }
            };
            if has_pending {
                // Mark for retransmission
                self.stats.lost += 1;
            }
        }

        // Update RTT estimate
        self.rtt = self.rtt.saturating_add(Duration::from_millis(100));
        self.recovery.update_rtt(self.rtt);
        // Treat timeout as loss of in-flight bytes (coarse approximation)
        if self.bytes_in_flight > 0 {
            let lost = self.bytes_in_flight;
            self.recovery.on_loss(lost, Instant::now());
            self.stats.lost = self.stats.lost.saturating_add(1);
            self.stats.lost_bytes = self.stats.lost_bytes.saturating_add(lost as u64);
            self.cwnd = self.recovery.cwnd;
            self.bytes_in_flight = 0;
        }
        // Update bytes in flight duration (mock)
        if let Some(start) = self.bytes_in_flight_started.take() {
            self.stats.bytes_in_flight_duration = self
                .stats
                .bytes_in_flight_duration
                .saturating_add(Instant::now().saturating_duration_since(start));
        }
        // Switch into draining on timeout.
        self.is_draining = true;
    }
    /// Returns last peer error if any
    pub fn peer_error(&self) -> Option<&crate::error::ConnectionError> {
        self.peer_error.as_ref()
    }
    /// Returns last local error if any
    pub fn local_error(&self) -> Option<&crate::error::ConnectionError> {
        self.local_error.as_ref()
    }

    /// Server name (SNI) from TLS provider
    pub fn server_name(&self) -> Option<&str> {
        self.tls_provider.as_ref().and_then(|p| p.server_name_get())
    }
    /// Peer leaf certificate DER (from TLS provider)
    pub fn peer_cert(&self) -> Option<Vec<u8>> {
        self.tls_provider.as_ref().and_then(|p| p.peer_cert())
    }
    /// Peer certificate chain DER (from TLS provider)
    pub fn peer_cert_chain(&self) -> Option<Vec<Vec<u8>>> {
        self.tls_provider.as_ref().and_then(|p| p.peer_cert_chain())
    }
    /// TLS session ticket for resumption (from TLS provider)
    pub fn session(&self) -> Option<Vec<u8>> {
        self.tls_provider.as_ref().and_then(|p| p.session_ticket())
    }
    /// Peer transport parameters (not tracked in this transport layer)
    pub fn peer_transport_params(&self) -> Option<&()> {
        None
    }

    /// Stream priority
    pub fn stream_priority(
        &mut self,
        stream_id: u64,
        _urgency: u8,
        _incremental: bool,
    ) -> Result<(), crate::error::ConnectionError> {
        let _stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(crate::error::ConnectionError::InvalidStreamState(stream_id))?;
        _stream.priority_urgency = _urgency;
        _stream.priority_incremental = _incremental;

        if self.writable_streams.contains(&stream_id) {
            self.writable_streams.retain(|&id| id != stream_id);
            let mut insert_at = None;
            for (idx, id) in self.writable_streams.iter().enumerate() {
                if let Some(s) = self.streams.get(id) {
                    if _urgency < s.priority_urgency {
                        insert_at = Some(idx);
                        break;
                    }
                }
            }
            if let Some(idx) = insert_at {
                self.writable_streams.insert(idx, stream_id);
            } else {
                self.writable_streams.push_back(stream_id);
            }
        }
        Ok(())
    }

    pub fn stream_shutdown(
        &mut self,
        _stream_id: u64,
        _direction: Shutdown,
        _err: u64,
    ) -> Result<(), crate::error::ConnectionError> {
        Ok(())
    }

    pub fn stream_capacity(&self, _stream_id: u64) -> Result<usize, crate::error::ConnectionError> {
        Ok(65536)
    }

    pub fn stream_readable(&self, _stream_id: u64) -> bool {
        self.readable_streams.contains(&_stream_id)
    }

    pub fn stream_writable(&self, _stream_id: u64, _len: usize) -> bool {
        self.writable_streams.contains(&_stream_id)
    }

    pub fn stream_finished(&self, _stream_id: u64) -> bool {
        if let Some(s) = self.streams.get(&_stream_id) {
            #[cfg(not(feature = "stream_ring_buffer"))]
            {
                s.send_fin && s.send_buf.is_empty()
            }
            #[cfg(feature = "stream_ring_buffer")]
            {
                s.send_fin && s.send_ring.is_empty()
            }
        } else {
            false
        }
    }

    pub fn readable(&self) -> impl Iterator<Item = u64> + '_ {
        self.readable_streams.iter().copied()
    }

    pub fn writable(&self) -> impl Iterator<Item = u64> + '_ {
        self.writable_streams.iter().copied()
    }

    pub fn stream_readable_next(&mut self) -> Option<u64> {
        if self.readable_streams.is_empty() {
            None
        } else {
            self.readable_streams.pop_front()
        }
    }

    pub fn stream_writable_next(&mut self) -> Option<u64> {
        if self.writable_streams.is_empty() {
            None
        } else {
            self.writable_streams.pop_front()
        }
    }

    pub fn max_send_udp_payload_size(&self) -> usize {
        self.dgram_send_max_size
    }

    /// Path migration
    pub fn migrate(
        &mut self,
        local: SocketAddr,
        peer: SocketAddr,
    ) -> Result<u64, crate::error::ConnectionError> {
        // Migrate to new path
        let _old_local = self.local_addr;
        let old_peer = self.peer_addr;
        self.local_addr = local;
        self.peer_addr = peer;
        self.path_id += 1;

        // Reset congestion control
        self.cwnd = INITIAL_WINDOW;
        self.bytes_in_flight = 0;
        // Emit path events
        self.path_events.push_back(PathEvent::New(local, peer));
        self.path_events.push_back(PathEvent::Validated(local, peer));
        self.path_events.push_back(PathEvent::PeerMigrated(old_peer, peer));

        Ok(self.path_id)
    }
    /// Change only the local address (migrate source path)
    pub fn migrate_source(
        &mut self,
        local: SocketAddr,
    ) -> Result<u64, crate::error::ConnectionError> {
        let _old_local = self.local_addr;
        self.local_addr = local;
        self.path_id += 1;
        self.path_events.push_back(PathEvent::New(local, self.peer_addr));
        self.path_events.push_back(PathEvent::Validated(local, self.peer_addr));
        Ok(self.path_id)
    }
    /// Probe a path and emit path lifecycle events for observers/control-plane.
    pub fn probe_path(
        &mut self,
        from: SocketAddr,
        to: SocketAddr,
    ) -> Result<(), crate::error::ConnectionError> {
        if from == to {
            return Err(crate::error::ConnectionError::InvalidState);
        }

        self.path_events.push_back(PathEvent::New(from, to));
        self.path_events.push_back(PathEvent::Validated(from, to));
        if self.peer_addr != to {
            self.path_events.push_back(PathEvent::PeerMigrated(self.peer_addr, to));
        }
        self.path_id = self.path_id.wrapping_add(1);
        Ok(())
    }

    pub fn path_stats(&self) -> impl Iterator<Item = PathStats> {
        std::iter::once(PathStats {
            recv: self.stats.recv_bytes,
            sent: self.stats.sent_bytes,
            lost: self.stats.lost as u64,
            rtt: self.rtt,
            cwnd: self.cwnd,
            delivery_rate: self.stats.delivery_rate,
            local_addr: self.local_addr,
            peer_addr: self.peer_addr,
        })
    }
    // Pacing / Congestion / Release hooks
    pub fn get_next_release_time(&self) -> Option<Instant> {
        if !self.config.pacing {
            return None;
        }

        let now = Instant::now();
        if let Some(next) = self.next_send_at {
            if next > now {
                return Some(next);
            }
        }

        let rate_bps = self.recovery.get_pacing_rate().or(self.config.max_pacing_rate)?;
        if rate_bps == 0 || self.bytes_in_flight == 0 {
            return Some(now);
        }

        let release_delay_us =
            ((self.bytes_in_flight as u128) * 1_000_000u128 / rate_bps as u128).max(1) as u64;
        Some(now + Duration::from_micros(release_delay_us))
    }
    pub fn gcongestion_enabled(&self) -> bool {
        true
    }
    pub fn pacing_enabled(&self) -> bool {
        self.config.pacing
    }

    pub fn send_on_path(
        &mut self,
        out: &mut [u8],
        _to: SocketAddr,
    ) -> Result<(usize, SendInfo), crate::error::ConnectionError> {
        self.send(out)
    }

    /// Returns the next path event, if any
    pub fn path_event_next(&mut self) -> Option<PathEvent> {
        // Return next path event
        if self.path_events.is_empty() {
            None
        } else {
            self.path_events.pop_front()
        }
    }
    /// Active SCIDs count (minimal: 1)
    pub fn active_scids(&self) -> usize {
        1
    }
    /// SCIDs left to issue (minimal: 0)
    pub fn scids_left(&self) -> usize {
        0
    }
    /// Retire a DCID by sequence (minimal: record in retired_scids)
    pub fn retire_dcid(&mut self, _dcid_seq: u64) -> Result<(), crate::error::ConnectionError> {
        self.retired_scids.push_back(self.scid.clone());
        Ok(())
    }
    /// Iterate paths (minimal: return peer addr once)
    pub fn paths_iter(&self, _from: SocketAddr) -> impl Iterator<Item = SocketAddr> {
        std::iter::once(self.peer_addr)
    }
    /// Send an ACK-eliciting frame hint (mark ACK needed)
    pub fn send_ack_eliciting(&mut self) -> Result<(), crate::error::ConnectionError> {
        self.pkt_spaces[2].ack_elicited = true;
        Ok(())
    }
    /// Send ACK-eliciting on a path (ignored in minimal impl)
    pub fn send_ack_eliciting_on_path(
        &mut self,
        _from: SocketAddr,
    ) -> Result<(), crate::error::ConnectionError> {
        self.send_ack_eliciting()
    }
    /// Retired scids count
    pub fn retired_scids(&self) -> usize {
        self.retired_scids.len()
    }
    /// Next retired scid if any
    pub fn retired_scid_next(&mut self) -> Option<ConnectionId> {
        if self.retired_scids.is_empty() {
            None
        } else {
            self.retired_scids.pop_front()
        }
    }
    /// Available dcids (minimal: 0)
    pub fn available_dcids(&self) -> usize {
        0
    }
}
