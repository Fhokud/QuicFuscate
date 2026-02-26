// Copyright (c) 2024, The QuicFuscate Project Authors.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following disclaimer
//       in the documentation and/or other materials provided with the
//       distribution.
//
//     * Neither the name of the copyright holder nor the names of its
//       contributors may be used to endorse or promote products derived from
//       this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! # Core Connection Manager
//!
//! This module provides the central `QuicFuscateConnection` struct, which
//! orchestrates the crypto, FEC, and stealth modules to manage a full
//! QUIC connection lifecycle.

use crate::accelerate::transport::{self as transport_accel, CongestionSample};
#[cfg(feature = "orchestrator")]
use crate::brain::DeepIntegrationOrchestrator;
use crate::brain::{intelligent_stealth_level_hint, CombinedObserver, StealthBrain};
use crate::crypto::{CipherSuiteSelector, CryptoManager};
use crate::fec::{AdaptiveFec, FecConfig, FecPacket, FecTransportObserver};
use crate::optimize::xdp_socket::XdpSocket;
use crate::optimize::{OptimizationManager, OptimizeConfig};
use crate::stealth::{ServerPushTriggerReason, StealthConfig, StealthManager, StealthMode};
use std::sync::Arc;
#[cfg(feature = "orchestrator")]
use std::sync::OnceLock;
// unused on current code path; keep import minimal
use crate::telemetry;
use crate::transport::h3::NameValue; // for Header.name()/value()
use log::{debug, info, warn};
use std::collections::VecDeque;
use std::time::Instant;

#[cfg(feature = "orchestrator")]
static ORCHESTRATOR: OnceLock<Arc<DeepIntegrationOrchestrator>> = OnceLock::new();
use std::net::SocketAddr;

// Type aliases to simplify handler types
type CapsuleHandler = Arc<std::sync::Mutex<Box<dyn FnMut(u64, &[u8]) + Send>>>;
type DatagramHandler = Arc<std::sync::Mutex<Box<dyn FnMut(&[u8]) + Send>>>;

/// Parameters for creating a new QuicFuscateConnection.
pub struct ConnectionParams {
    pub conn: Box<crate::transport::Connection>,
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub host_header: String,
    pub sni_host: Option<String>,
    pub qkey_auth_token_hex: Option<String>,
    pub stealth_manager: Arc<StealthManager>,
    pub optimization_manager: Arc<OptimizationManager>,
    pub xdp_socket: Option<crate::optimize::xdp_socket::XdpSocket>,
    pub fec_config: FecConfig,
}

/// Represents a single QuicFuscate connection and manages its state.
pub struct QuicFuscateConnection {
    pub conn: Box<crate::transport::Connection>,
    pub peer_addr: SocketAddr,
    local_addr: SocketAddr,
    host_header: String,
    qkey_auth_token_hex: Option<String>,

    // Core Modules
    _crypto_selector: CipherSuiteSelector,
    fec: AdaptiveFec,

    // Stealth & Optimization Modules
    stealth_manager: Arc<StealthManager>,
    optimization_manager: Arc<OptimizationManager>,

    // State
    stats: ConnectionStats,
    packet_id_counter: u64,
    // The outgoing buffer now holds fully formed FEC packets, ready for direct sending.
    // This eliminates the serialization overhead entirely.
    outgoing_fec_packets: VecDeque<FecPacket>,
    xdp_socket: Option<XdpSocket>,
    h3_conn: Option<crate::transport::h3::Connection>,
    last_telemetry: std::time::Instant,
    // Observer for transport telemetry -> FEC/ACK policy coupling.
    transport_observer: Arc<FecTransportObserver>,
    masque_cb: Option<CapsuleHandler>,
    masque_datagram_cb: Option<DatagramHandler>,
    masque_control_cb: Option<CapsuleHandler>,
    masque_stream_id: Option<u64>,
    fec_last_report_sent: u64,
    fec_last_report_lost: u64,
    #[cfg(feature = "orchestrator")]
    runtime_cpu_percent: u32,
    #[cfg(feature = "orchestrator")]
    runtime_memory_pressure: u32,
    tls_ch_override_template: Option<String>,

    // Async Stealth Scheduler State
    next_packet_release: Option<std::time::Instant>,
}

/// Tracks performance and reliability metrics for a connection.
#[derive(Debug)]
pub struct ConnectionStats {
    pub rtt: f32,
    pub loss_rate: f32,
    pub packets_sent: u64,
    pub packets_lost: u64,
    pub congestion_cwnd: u64,
    pub congestion_bytes_in_flight: u64,
    pub congestion_delivery_rate: u64,
    pub congestion_lost: u64,
    pub congestion_score: u64,
    congestion_samples: VecDeque<CongestionSample>,
}

impl Default for ConnectionStats {
    fn default() -> Self {
        Self {
            rtt: 0.0,
            loss_rate: 0.0,
            packets_sent: 0,
            packets_lost: 0,
            congestion_cwnd: 0,
            congestion_bytes_in_flight: 0,
            congestion_delivery_rate: 0,
            congestion_lost: 0,
            congestion_score: 0,
            congestion_samples: VecDeque::with_capacity(transport_accel::CONGESTION_WINDOW_SIZE),
        }
    }
}

impl ConnectionStats {
    fn update_congestion(&mut self, sample: CongestionSample) {
        if self.congestion_samples.len() == transport_accel::CONGESTION_WINDOW_SIZE {
            self.congestion_samples.pop_front();
        }
        self.congestion_samples.push_back(sample);
        let summary =
            transport_accel::aggregate_congestion(self.congestion_samples.make_contiguous());
        self.congestion_cwnd = summary.total_cwnd;
        self.congestion_bytes_in_flight = summary.total_bytes_in_flight;
        self.congestion_delivery_rate = summary.total_delivery_rate;
        self.congestion_lost = summary.total_lost_packets;
        self.congestion_score = summary.congestion_score;
    }
}

impl QuicFuscateConnection {
    /// Creates a new client connection.
    #[allow(clippy::too_many_arguments)]
    pub fn new_client(
        server_name: &str,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        mut config: crate::transport::Config,
        stealth_config: StealthConfig,
        fec_config: FecConfig,
        opt_cfg: OptimizeConfig,
        qkey_auth_token_hex: Option<String>,
        use_utls: bool,
    ) -> Result<Self, String> {
        let crypto_manager = Arc::new(CryptoManager::new());
        let optimization_manager = Arc::new(OptimizationManager::from_cfg(opt_cfg));
        let stealth_manager = Arc::new(StealthManager::new(
            stealth_config,
            optimization_manager.clone(),
            crypto_manager.clone(),
        ));

        if use_utls {
            stealth_manager.apply_utls_profile(&mut config, None);
        }

        // Each client connection should use a fresh, unpredictable SCID to avoid linkability.
        let mut scid_bytes = [0u8; crate::transport::MAX_CONN_ID_LEN];
        crate::transport::rand::rand_bytes(&mut scid_bytes);
        let scid = crate::transport::ConnectionId::from_ref(&scid_bytes);

        let (sni, host_header) = stealth_manager.get_connection_headers(server_name);

        let conn = crate::transport::packet::connect(
            Some(&sni),
            scid.as_ref(),
            local_addr,
            remote_addr,
            &mut config,
        )
        .map_err(|e| format!("Failed to create QUIC connection: {}", e))?;

        let xdp_socket = optimization_manager.create_xdp_socket(local_addr, remote_addr);
        Ok(Self::new(ConnectionParams {
            conn: Box::new(conn),
            local_addr,
            peer_addr: remote_addr,
            host_header,
            sni_host: Some(sni),
            qkey_auth_token_hex,
            stealth_manager,
            optimization_manager,
            xdp_socket,
            fec_config,
        }))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_server(
        scid: &crate::transport::ConnectionId,
        odcid: Option<&crate::transport::ConnectionId>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        config: &mut crate::transport::Config,
        stealth_config: StealthConfig,
        fec_config: FecConfig,
        opt_cfg: OptimizeConfig,
    ) -> Result<Self, String> {
        let crypto_manager = Arc::new(CryptoManager::new());
        let optimization_manager = Arc::new(OptimizationManager::from_cfg(opt_cfg));
        let stealth_manager = Arc::new(StealthManager::new(
            stealth_config,
            optimization_manager.clone(),
            crypto_manager.clone(),
        ));

        let conn = crate::transport::packet::accept(
            scid.as_ref(),
            odcid.as_ref().map(|id| id.as_ref()),
            local_addr,
            remote_addr,
            config,
        )
        .map_err(|e| format!("Failed to accept QUIC connection: {}", e))?;

        let xdp_socket = optimization_manager.create_xdp_socket(local_addr, remote_addr);

        Ok(Self::new(ConnectionParams {
            conn: Box::new(conn),
            local_addr,
            peer_addr: remote_addr,
            host_header: String::new(),
            sni_host: None,
            qkey_auth_token_hex: None,
            stealth_manager,
            optimization_manager,
            xdp_socket,
            fec_config,
        }))
    }

    fn new(params: ConnectionParams) -> Self {
        let obs = FecTransportObserver::new();
        let mut s = Self {
            conn: params.conn,
            peer_addr: params.peer_addr,
            local_addr: params.local_addr,
            host_header: params.host_header,
            qkey_auth_token_hex: params.qkey_auth_token_hex,
            _crypto_selector: CipherSuiteSelector::new(),
            fec: AdaptiveFec::new(params.fec_config),
            stealth_manager: params.stealth_manager,
            optimization_manager: params.optimization_manager,
            stats: ConnectionStats::default(),
            packet_id_counter: 0,
            outgoing_fec_packets: VecDeque::new(),
            xdp_socket: params.xdp_socket,
            h3_conn: None,
            last_telemetry: std::time::Instant::now(),
            transport_observer: obs.clone(),
            masque_cb: None,
            masque_datagram_cb: None,
            masque_control_cb: None,
            masque_stream_id: None,
            fec_last_report_sent: 0,
            fec_last_report_lost: 0,
            #[cfg(feature = "orchestrator")]
            runtime_cpu_percent: 0,
            #[cfg(feature = "orchestrator")]
            runtime_memory_pressure: 0,
            tls_ch_override_template: std::env::var("QUICFUSCATE_TLS_CH_OVERRIDE_TEMPLATE")
                .ok()
                .and_then(|v| {
                    let trimmed = v.trim();
                    if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed.to_string())
                    }
                }),
            next_packet_release: None,
        };
        s.fec.enable_simd_acceleration();
        // Attach observers to transport for live telemetry callbacks
        // Combine FEC observer with StealthBrain when enabled (default on, disable via QUICFUSCATE_BRAIN=0|false)
        let obs_dyn: Arc<dyn crate::transport::TransportObserver> = obs.clone();
        let brain_enabled = std::env::var("QUICFUSCATE_BRAIN")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true);
        if brain_enabled {
            let brain = StealthBrain::new_default();
            let brain_dyn: Arc<dyn crate::transport::TransportObserver> = brain.clone();
            let combined = CombinedObserver::new(vec![obs_dyn.clone(), brain_dyn]);
            let combined_dyn: Arc<dyn crate::transport::TransportObserver> = combined.clone();
            s.conn.set_observer(Some(combined_dyn));
        } else {
            s.conn.set_observer(Some(obs_dyn));
        }

        // Enable and configure RealTLS (always on, including Performance mode)
        // Map stealth fingerprint to TLS profile and apply SNI from fronting
        let _ = s.conn.enable_tls("unified");
        let fp = s.stealth_manager.current_fingerprint();
        let mut tls_prof = crate::qftls::profile_from_fingerprint(&fp);
        if let Some(ref sni) = params.sni_host {
            tls_prof.sni = Some(sni.clone());
        }
        let sni_str = tls_prof.sni.as_deref().unwrap_or(s.host_header.as_str());
        let _ = s.conn.configure_tls(&tls_prof, sni_str);

        // Initialize DeepIntegrationOrchestrator if feature enabled
        #[cfg(feature = "orchestrator")]
        {
            let orchestrator_enabled = std::env::var("QUICFUSCATE_ORCHESTRATOR")
                .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
                .unwrap_or(true);
            if orchestrator_enabled {
                let orchestrator = DeepIntegrationOrchestrator::new(
                    crate::brain::StealthBrainConfig::from_env(),
                    1024,  // pool capacity
                    65536, // block size
                );
                // Store globally for later use in HTTP/3 loop.
                let _ = ORCHESTRATOR.set(orchestrator);
                info!("DeepIntegrationOrchestrator activated for advanced coordination");
                // Enable Server Push coordination in Intelligent mode (brain will throttle)
                if matches!(s.stealth_manager.mode(), StealthMode::Intelligent) {
                    if let Some(orch) = ORCHESTRATOR.get() {
                        orch.enable_server_push(true);
                    }
                }
            }
        }

        s
    }

    fn inject_qkey_auth_header(&self, headers: &mut Vec<crate::transport::h3::Header>) {
        let Some(token) = self.qkey_auth_token_hex.as_deref() else {
            return;
        };
        let token = token.trim();
        if token.is_empty() {
            return;
        }
        headers.retain(|h| h.name() != b"x-qf-auth");
        headers.push(crate::transport::h3::Header::new(b"x-qf-auth", token.as_bytes()));
    }

    #[cfg(feature = "orchestrator")]
    fn update_orchestrator_resource_signals(&mut self) {
        use sysinfo::ProcessesToUpdate;

        let mut sys = sysinfo::System::new_all();
        let Ok(pid) = sysinfo::get_current_pid() else {
            return;
        };
        sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
        sys.refresh_memory();
        if let Some(proc_) = sys.process(pid) {
            self.runtime_cpu_percent = proc_.cpu_usage().round().clamp(0.0, 100.0) as u32;
            let total = sys.total_memory();
            let used = proc_.memory();
            self.runtime_memory_pressure = if total > 0 {
                ((used as f64 * 100.0) / total as f64).round().clamp(0.0, 100.0) as u32
            } else {
                0
            };
        }
    }

    fn ensure_masque_tunnel(
        &mut self,
        host: &str,
    ) -> Result<Option<u64>, crate::transport::h3::Error> {
        if !self.stealth_manager.masque_preferred() {
            return Ok(None);
        }

        if let Some(sid) = self.masque_stream_id {
            return Ok(Some(sid));
        }

        let Some(proxy) = self.stealth_manager.masque_proxy() else {
            return Ok(None);
        };

        let target = format!("{}:443", host);
        let Some(ref mut h3) = self.h3_conn else {
            return Ok(None);
        };

        let sid = h3.connect_udp(&mut self.conn, &proxy, &target)?;
        debug!("MASQUE CONNECT-UDP opened (proxy={}, target={})", proxy, target);
        crate::telemetry::MASQUE_ACTIVE.store(1, std::sync::atomic::Ordering::Relaxed);

        let _ = h3.enable_masque_datagram(&mut self.conn, sid);
        if let Err(e) = h3.register_datagram_context(&mut self.conn, sid, 1, 0) {
            warn!("MASQUE DATAGRAM context registration failed: {:?}", e);
        } else {
            debug!("MASQUE DATAGRAM enabled (flow-id=1, ctx=0)");
        }

        self.masque_stream_id = Some(sid);
        Ok(Some(sid))
    }

    fn intelligent_level(&self) -> u32 {
        if matches!(self.stealth_manager.mode(), StealthMode::Intelligent) {
            intelligent_stealth_level_hint()
        } else {
            0
        }
    }

    fn sync_intelligent_runtime_controls(&self, intelligent_level: u32) {
        if !matches!(self.stealth_manager.mode(), StealthMode::Intelligent) {
            return;
        }
        self.stealth_manager.maybe_escalate_masque_intelligent();
        if intelligent_level == 0 {
            self.stealth_manager.enable_server_push_runtime(false, None);
            return;
        }
        let intensity = if intelligent_level >= 2 { 0.9 } else { 0.65 };
        self.stealth_manager.enable_server_push_runtime(true, Some(intensity));
    }

    fn estimate_server_push_cover_bytes(
        base_path: &str,
        promises_created: usize,
        intensity: f32,
    ) -> u64 {
        if promises_created == 0 {
            return 0;
        }
        let per_promise = 280u64
            .saturating_add(base_path.len() as u64)
            .saturating_add((intensity.clamp(0.0, 1.0) * 180.0) as u64);
        per_promise.saturating_mul(promises_created as u64)
    }

    /// Processes an incoming raw buffer, parsing it into an FEC packet and handling recovery.
    /// This now avoids any serialization overhead.
    pub fn recv(&mut self, data: &[u8]) -> Result<usize, crate::error::ConnectionError> {
        let mut block = self.optimization_manager.alloc_block();
        let len = if let Some(ref mut xdp) = self.xdp_socket {
            match xdp.recv(&mut block) {
                Ok(l) => l,
                Err(e) => {
                    self.optimization_manager.free_block(block);
                    return Err(crate::error::ConnectionError::Transport(e.to_string()));
                }
            }
        } else {
            if data.len() > block.len() {
                // Avoid silent truncation; return a clear error and recycle the block.
                self.optimization_manager.free_block(block);
                return Err(crate::error::ConnectionError::BufferTooShort);
            }
            let copy_len = data.len();
            block[..copy_len].copy_from_slice(&data[..copy_len]);
            copy_len
        };

        // Hand over the pooled block directly without extra allocation.
        let fec_packet = FecPacket::new(
            self.packet_id_counter,
            Some(block),
            len,
            true,
            None,
            0,
            self.optimization_manager.memory_pool().clone(),
        );
        // Ensure unique IDs for subsequent packets
        self.packet_id_counter = self.packet_id_counter.wrapping_add(1);

        let recovered_packets = self.fec.on_receive(fec_packet).map_err(|e| {
            crate::error::ConnectionError::Transport(format!("FEC decoding failed: {}", e))
        })?;

        for mut packet in recovered_packets {
            if let Some(ref mut data_box) = packet.data {
                let data: &mut [u8] = &mut data_box[..packet.data_len];
                // Deobfuscate payload if enabled
                self.stealth_manager.process_incoming_packet(data, self.peer_addr);

                // Process the reconstructed QUIC packet
                let recv_info = crate::transport::RecvInfo {
                    from: self.peer_addr,
                    to: self.local_addr,
                    ecn: None,
                };
                if let Err(e) = self.conn.recv(data, &recv_info) {
                    // Log error, but continue processing other recovered packets
                    debug!("transport::recv failed (possible probe): {}", e); // demoted to debug to reduce noise

                    // REALITY FALLBACK
                    // Forward invalid/failed packets to upstream proxy
                    self.stealth_manager.handle_fallback(data, self.peer_addr);
                }
            }
        }

        self.conn
            .do_tls_handshake(self.tls_ch_override_template.as_deref())
            .map_err(|e| crate::error::ConnectionError::Transport(e.to_string()))?;

        Ok(len)
    }

    /// Prepares QUIC packets for sending, wraps them in FEC, and buffers them.
    /// This has been completely refactored to eliminate serialization and copies.
    pub fn send(&mut self, buf: &mut [u8]) -> Result<usize, crate::error::ConnectionError> {
        let now = Instant::now();
        let established = self.conn.is_established();
        self.conn
            .do_tls_handshake(self.tls_ch_override_template.as_deref())
            .map_err(|e| crate::error::ConnectionError::Transport(e.to_string()))?;

        // --- REALITY FALLBACK RESPONSE POLLING ---
        // Check if there are any responses from upstream to send back (bypass stealth scheduler)
        if let Some(resp) = self.stealth_manager.poll_fallback() {
            if let Some(ref mut xdp) = self.xdp_socket {
                xdp.send(&[&resp.data])
                    .map_err(|e| crate::error::ConnectionError::Transport(e.to_string()))?;
                return Ok(resp.data.len());
            } else {
                if buf.len() < resp.data.len() {
                    return Err(crate::error::ConnectionError::BufferTooShort);
                }
                buf[..resp.data.len()].copy_from_slice(&resp.data);
                return Ok(resp.data.len());
            }
        }

        // --- ASYNC STEALTH SCHEDULER ---
        // If we are currently throttled by the StealthManager (Brain), yield immediately.
        //
        // Production invariant:
        // Never delay Initial/Handshake flights. Delaying them can stall the connection setup and
        // makes short-lived clients (like E2E) time out. Stealth timing only applies post-handshake.
        if !established {
            self.next_packet_release = None;
        } else if let Some(release_time) = self.next_packet_release {
            if now < release_time {
                // Determine remainder for specialized pollers if needed
                // let rem = release_time.duration_since(now);
                return Ok(0); // WouldBlock / Yield
            }
            // Timer expired, clear block and proceed
            self.next_packet_release = None;
        }

        // If there are buffered FEC packets, send one directly.
        if let Some(packet) = self.outgoing_fec_packets.pop_front() {
            let len = if let Some(ref mut xdp) = self.xdp_socket {
                // Prefer zero-copy from pooled buffer when available; otherwise materialize.
                if let Some(ref data) = packet.data {
                    let slice = &data[..packet.data_len];
                    xdp.send(&[slice])
                        .map_err(|e| crate::error::ConnectionError::Transport(e.to_string()))?;
                    packet.data_len
                } else {
                    let raw_len = packet.to_raw(buf)?;
                    xdp.send(&[&buf[..raw_len]])
                        .map_err(|e| crate::error::ConnectionError::Transport(e.to_string()))?;
                    raw_len
                }
            } else {
                packet.to_raw(buf)?
            };
            // Drop handles pool recycling automatically.
            return Ok(len);
        }

        // Otherwise, generate a new QUIC packet using a pooled buffer.
        let mut send_buffer = self.optimization_manager.alloc_block();
        let (write, _send_info) = match self.conn.send(&mut send_buffer) {
            Ok(v) => v,
            Err(crate::error::ConnectionError::Done) => {
                // No packet currently pending is a normal state for polling loops.
                drop(send_buffer);
                return Ok(0);
            }
            Err(crate::error::ConnectionError::BufferTooShort) => {
                drop(send_buffer);
                return Err(crate::error::ConnectionError::BufferTooShort);
            }
            Err(e) => {
                // The buffer is recycled automatically via FecPacket Drop.
                drop(send_buffer);
                return Err(crate::error::ConnectionError::Transport(e.to_string()));
            }
        };

        if write == 0 {
            // The buffer is recycled automatically via Drop.
            drop(send_buffer);
            return Ok(0);
        }

        // The buffer may be larger than the written data; the length is tracked separately.
        // Stealth padding may be applied by the transport configuration; do not mutate the
        // sealed datagram here to preserve AEAD integrity and FEC compatibility.

        // Obfuscate payload if enabled (includes timing/flow shaping)
        // NON-BLOCKING: If delay needed, we schedule it and yield zero bytes.
        let delay_opt = self.stealth_manager.process_outgoing_packet(&mut send_buffer[..write]);

        // Create a systematic FEC packet, passing ownership of the buffer.
        let fec_packet = FecPacket::new(
            self.packet_id_counter,
            Some(send_buffer),
            write,
            false,
            None,
            0,
            // Use the same pool the buffer was allocated from to avoid cross-pool leaks
            self.optimization_manager.memory_pool().clone(),
        );
        self.packet_id_counter += 1;

        // Pass to FEC encoder to get original + repair packets.
        // The encoder now directly populates the outgoing queue.
        for pkt in self.fec.on_send(fec_packet) {
            self.outgoing_fec_packets.push_back(pkt);
        }

        // If the StealthManager requested a delay, enforce it NOW.
        // We have already buffered the packets in `outgoing_fec_packets`.
        // We set the timer and return 0 (Yield). The next call to send() will check the timer.
        if established {
            if let Some(delay) = delay_opt {
                let release_at = now + delay;
                self.next_packet_release = Some(release_at);
                return Ok(0); // Yield immediately, do not send the just-generated packets yet.
            }
        }

        // Pop the first packet from the buffer to send it now.
        if let Some(packet) = self.outgoing_fec_packets.pop_front() {
            let len = if let Some(ref mut xdp) = self.xdp_socket {
                if let Some(ref data) = packet.data {
                    let slice = &data[..packet.data_len];
                    xdp.send(&[slice])
                        .map_err(|e| crate::error::ConnectionError::Transport(e.to_string()))?;
                    packet.data_len
                } else {
                    let raw_len = packet.to_raw(buf)?;
                    xdp.send(&[&buf[..raw_len]])
                        .map_err(|e| crate::error::ConnectionError::Transport(e.to_string()))?;
                    raw_len
                }
            } else {
                packet.to_raw(buf)?
            };
            // Drop handles pool recycling automatically.
            Ok(len)
        } else {
            Ok(0)
        }
    }

    /// Handles connection migration to a new network path.
    /// Triggers connection migration to a new peer address.
    ///
    /// The underlying QUIC connection will attempt to validate the new path
    /// and switch over once validation succeeds. Any error is returned so the
    /// caller can react accordingly.
    pub fn migrate_connection(
        &mut self,
        new_peer: SocketAddr,
    ) -> Result<u64, crate::transport::Error> {
        // Initiate path migration using the transport API. The local address remains
        // unchanged, but a new peer address is supplied. The transport handles sending
        // the probing packets required for validation.
        self.xdp_socket = self.optimization_manager.create_xdp_socket(self.local_addr, new_peer);
        if let Some(ref mut xdp) = self.xdp_socket {
            let _ = xdp.update_remote(new_peer);
            telemetry!(telemetry::XDP_ACTIVE.store(1, std::sync::atomic::Ordering::Relaxed));
        } else {
            telemetry!(telemetry::XDP_ACTIVE.store(0, std::sync::atomic::Ordering::Relaxed));
        }

        let res = self
            .conn
            .migrate(self.local_addr, new_peer)
            .map_err(|_| crate::transport::Error::NoViablePath);
        if res.is_ok() {
            telemetry!(telemetry::PATH_MIGRATIONS.inc());
        }
        res
    }

    /// Returns the Host header that should be used for HTTP requests when domain
    /// fronting is active.
    pub fn host_header(&self) -> &str {
        &self.host_header
    }

    /// Returns the stealth manager for dynamic profile updates.
    pub fn stealth_manager(&self) -> Arc<StealthManager> {
        self.stealth_manager.clone()
    }

    /// Initializes the HTTP/3 connection if it hasn't been created yet.
    pub fn init_http3(&mut self) -> Result<(), crate::transport::h3::Error> {
        if self.h3_conn.is_none() {
            // Enable a modest QPACK dynamic table to improve compression.
            let mut h3_cfg = crate::transport::h3::Config::new()
                .map_err(|_| crate::transport::h3::Error::InternalError)?;
            // Select capacities based on the active persona.
            let fp = self.stealth_manager.current_fingerprint();
            match fp.browser {
                crate::stealth::BrowserProfile::Chrome | crate::stealth::BrowserProfile::Edge => {
                    h3_cfg.set_qpack_max_table_capacity(64u64 * 1024u64);
                    h3_cfg.set_qpack_blocked_streams(16u64);
                }
                crate::stealth::BrowserProfile::Firefox => {
                    h3_cfg.set_qpack_max_table_capacity(32u64 * 1024u64);
                    h3_cfg.set_qpack_blocked_streams(8u64);
                }
                crate::stealth::BrowserProfile::Safari => {
                    h3_cfg.set_qpack_max_table_capacity(32u64 * 1024u64);
                    h3_cfg.set_qpack_blocked_streams(8u64);
                }
            }

            let h3 = crate::transport::h3::Connection::with_transport(&mut self.conn, &h3_cfg)?;
            let mut h3 = h3;
            // Persona QPACK Index-Policy setzen
            match fp.browser {
                crate::stealth::BrowserProfile::Chrome | crate::stealth::BrowserProfile::Edge => {
                    h3.set_qpack_index_policy(&[
                        b":authority",
                        b":path",
                        b":method",
                        b"content-type",
                        b"accept-encoding",
                        b"user-agent",
                        b"accept",
                        b"cache-control",
                    ]);
                }
                crate::stealth::BrowserProfile::Firefox => {
                    h3.set_qpack_index_policy(&[
                        b":authority",
                        b":path",
                        b":method",
                        b"content-type",
                        b"accept-language",
                    ]);
                }
                crate::stealth::BrowserProfile::Safari => {
                    h3.set_qpack_index_policy(&[
                        b":authority",
                        b":path",
                        b":method",
                        b"content-type",
                    ]);
                }
            }
            self.h3_conn = Some(h3);
            // Notify the compression layer about the persona (dictionary selection).
            let fp = self.stealth_manager.current_fingerprint();
            let persona = format!("{:?}/{:?}", fp.browser, fp.os);
            crate::compress::set_current_persona(&persona);
        }
        Ok(())
    }

    /// Sends a masqueraded HTTP/3 GET request using the stealth manager.
    pub fn send_http3_request(&mut self, path: &str) -> Result<(), crate::error::ConnectionError> {
        self.init_http3()?;
        let intelligent_level = self.intelligent_level();
        self.sync_intelligent_runtime_controls(intelligent_level);
        let prefer_masque = self.stealth_manager.masque_preferred() || intelligent_level >= 1;
        if prefer_masque && !self.stealth_manager.masque_preferred() {
            self.stealth_manager.set_masque_preferred(true);
        }
        if matches!(self.stealth_manager.mode(), StealthMode::Intelligent) && prefer_masque {
            crate::optimize::telemetry::STEALTH_SIGNAL_RTT_SPIKES
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        // If escalated and MASQUE is available, opportunistically CONNECT-UDP first.
        if prefer_masque {
            let host = self.host_header.clone();
            match self.ensure_masque_tunnel(&host) {
                Ok(Some(_)) => {}
                Ok(None) => {}
                Err(e) => {
                    crate::telemetry::MASQUE_ACTIVE.store(0, std::sync::atomic::Ordering::Relaxed);
                    warn!("MASQUE CONNECT-UDP open failed: {:?}", e);
                }
            }
        }
        let host = self.host_header.as_str();
        let mut headers =
            self.stealth_manager.get_http3_header_list(host, path).unwrap_or_else(|| {
                vec![
                    crate::transport::h3::Header::new(b":method", b"GET"),
                    crate::transport::h3::Header::new(b":scheme", b"https"),
                    crate::transport::h3::Header::new(b":authority", host.as_bytes()),
                    crate::transport::h3::Header::new(b":path", path.as_bytes()),
                ]
            });
        self.inject_qkey_auth_header(&mut headers);

        if let Some(ref mut h3) = self.h3_conn {
            let start = std::time::Instant::now();
            if let Err(e) = h3.send_request(&mut self.conn, &headers, true) {
                crate::optimize::telemetry::STEALTH_SIGNAL_RST
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Err(e.into());
            }
            info!("HTTP/3 request sent in {} ms", start.elapsed().as_millis());
        }
        Ok(())
    }

    /// Initializes HTTP/3 if not yet initialized and returns a writable POST stream id.
    pub fn open_http3_stream_post(
        &mut self,
        path: &str,
    ) -> Result<u64, crate::error::ConnectionError> {
        self.init_http3()?;
        let host = self.host_header.as_str();
        let mut headers =
            self.stealth_manager.get_http3_header_list(host, path).unwrap_or_default();
        // Ensure POST headers present
        headers.retain(|h| h.name() != b":method" && h.name() != b":path");
        headers.insert(0, crate::transport::h3::Header::new(b":path", path.as_bytes()));
        headers.insert(0, crate::transport::h3::Header::new(b":authority", host.as_bytes()));
        headers.insert(0, crate::transport::h3::Header::new(b":scheme", b"https"));
        headers.insert(0, crate::transport::h3::Header::new(b":method", b"POST"));
        self.inject_qkey_auth_header(&mut headers);
        if let Some(ref mut h3) = self.h3_conn {
            let sid = h3.send_request(&mut self.conn, &headers, false)?; // keep stream open
            return Ok(sid);
        }
        Err("h3 not initialized".into())
    }

    /// Sends a HTTP/3 request body chunk on an existing stream.
    pub fn http3_send_body_chunk(
        &mut self,
        stream_id: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<(), crate::error::ConnectionError> {
        let intelligent_level = self.intelligent_level();
        self.sync_intelligent_runtime_controls(intelligent_level);
        let prefer_masque = self.stealth_manager.masque_preferred() || intelligent_level >= 1;
        if prefer_masque && !self.stealth_manager.masque_preferred() {
            self.stealth_manager.set_masque_preferred(true);
        }
        // Preferred MASQUE path for UDP-like payload forwarding.
        if !data.is_empty() && prefer_masque {
            let host = self.host_header.clone();
            match self.ensure_masque_tunnel(&host) {
                Ok(Some(sid)) => {
                    if let Some(ref mut h3) = self.h3_conn {
                        match h3.send_masque_datagram(&mut self.conn, sid, data) {
                            Ok(()) => return Ok(()),
                            Err(e) => {
                                warn!(
                                    "MASQUE datagram send failed, falling back to H3 body: {:?}",
                                    e
                                );
                            }
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => warn!("MASQUE tunnel setup failed, falling back to H3 body: {:?}", e),
            }
        }

        if let Some(ref mut h3) = self.h3_conn {
            h3.send_body(&mut self.conn, stream_id, data, fin)?;
            Ok(())
        } else {
            Err("h3 not initialized".into())
        }
    }

    /// Sends one UDP payload over the active MASQUE DATAGRAM tunnel.
    pub fn send_masque_udp_payload(
        &mut self,
        payload: &[u8],
    ) -> Result<(), crate::error::ConnectionError> {
        self.init_http3()?;
        let host = self.host_header.clone();
        let Some(sid) = self.ensure_masque_tunnel(&host)? else {
            return Err("masque tunnel unavailable".into());
        };
        if let Some(ref mut h3) = self.h3_conn {
            h3.send_masque_datagram(&mut self.conn, sid, payload)?;
            Ok(())
        } else {
            Err("h3 not initialized".into())
        }
    }

    /// Polls HTTP/3 events and prints received data.
    pub fn poll_http3(&mut self) -> Result<(), crate::error::ConnectionError> {
        if self.h3_conn.is_none() && self.conn.is_established() {
            let _ = self.init_http3();
        }
        if let Some(ref mut h3) = self.h3_conn {
            let start = std::time::Instant::now();
            loop {
                let intelligent_level =
                    if matches!(self.stealth_manager.mode(), StealthMode::Intelligent) {
                        intelligent_stealth_level_hint()
                    } else {
                        0
                    };
                if matches!(self.stealth_manager.mode(), StealthMode::Intelligent) {
                    self.stealth_manager.maybe_escalate_masque_intelligent();
                    if intelligent_level == 0 {
                        self.stealth_manager.enable_server_push_runtime(false, None);
                    } else {
                        let intensity = if intelligent_level >= 2 { 0.9 } else { 0.65 };
                        self.stealth_manager.enable_server_push_runtime(true, Some(intensity));
                    }
                }
                // Opportunistically emit cover traffic when due (rate-limited, persona-shaped)
                if let Some(headers) = self.stealth_manager.cover_headers_due() {
                    if let Err(e) = h3.send_request(&mut self.conn, &headers, true) {
                        crate::optimize::telemetry::STEALTH_SIGNAL_RST
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        warn!("Cover traffic send failed: {:?}", e);
                    } else {
                        debug!("Cover traffic request emitted");
                    }
                }

                // Intelligent mode: brain decides when to enable runtime Server Push
                if matches!(self.stealth_manager.mode(), StealthMode::Intelligent) {
                    #[cfg(feature = "orchestrator")]
                    {
                        if intelligent_level >= 1 {
                            if let Some(orchestrator) = ORCHESTRATOR.get() {
                                let stats = self.conn.stats();
                                let sent = stats.sent as u64;
                                let lost = stats.lost as u64;
                                let loss_rate_permille = if sent > 0 {
                                    (((lost.saturating_mul(1000)) / sent).min(1000)) as u32
                                } else {
                                    0
                                };
                                let delivery_rate_bps = self
                                    .conn
                                    .delivery_rate()
                                    .max(self.stats.congestion_delivery_rate);
                                let stealth_active = !matches!(
                                    self.stealth_manager.mode(),
                                    StealthMode::Performance | StealthMode::Off
                                );
                                orchestrator.update_runtime_signals(
                                    loss_rate_permille,
                                    self.runtime_cpu_percent,
                                    self.runtime_memory_pressure,
                                    delivery_rate_bps,
                                    stealth_active,
                                );
                            }
                            if let Some(orchestrator) = ORCHESTRATOR.get() {
                                if orchestrator.should_trigger_server_push() {
                                    let mut intensity = orchestrator.get_server_push_intensity();
                                    if intelligent_level >= 2 {
                                        intensity = intensity.max(0.9);
                                    }
                                    self.stealth_manager
                                        .enable_server_push_runtime(true, Some(intensity));
                                }
                            }
                        } else {
                            self.stealth_manager.enable_server_push_runtime(false, None);
                        }
                    }
                }
                // Whenever due (config or runtime enabled), emit a Server Push burst
                if self.stealth_manager.should_trigger_server_push() {
                    if let Some((base_path, intensity)) =
                        self.stealth_manager.get_server_push_config()
                    {
                        match h3.generate_stealth_cover_burst(&base_path) {
                            Ok(ids) => {
                                let stats = self.conn.stats();
                                let sent = stats.sent as u64;
                                let lost = stats.lost as u64;
                                let loss_rate_permille = if sent > 0 {
                                    (((lost.saturating_mul(1000)) / sent).min(1000)) as u32
                                } else {
                                    0
                                };
                                let reason = if loss_rate_permille >= 50 {
                                    ServerPushTriggerReason::Loss
                                } else if intelligent_level >= 1 {
                                    ServerPushTriggerReason::Gating
                                } else {
                                    ServerPushTriggerReason::Time
                                };
                                let total_bytes = Self::estimate_server_push_cover_bytes(
                                    &base_path,
                                    ids.len(),
                                    intensity,
                                );
                                self.stealth_manager.update_server_push_state(
                                    ids.len(),
                                    total_bytes,
                                    reason,
                                );
                                debug!("Server Push burst emitted: {} promises", ids.len());
                            }
                            Err(e) => warn!("Server Push burst generation failed: {:?}", e),
                        }
                    }
                }
                match h3.poll(&mut self.conn) {
                    Ok(Some((_stream_id, crate::transport::h3::Event::Headers { list, .. }))) => {
                        let mut status_opt: Option<u16> = None;
                        for h in &list {
                            if h.name() == b":status" {
                                if let Ok(s) = std::str::from_utf8(h.value()) {
                                    status_opt = s.parse::<u16>().ok();
                                }
                            }
                        }
                        if let Some(st) = status_opt {
                            if !(200..300).contains(&st) {
                                warn!("H3 non-2xx status: {}", st);
                            }
                        }
                        for h in list {
                            debug!(
                                "{}: {}",
                                String::from_utf8_lossy(h.name()),
                                String::from_utf8_lossy(h.value())
                            );
                        }
                    }
                    Ok(Some((stream_id, crate::transport::h3::Event::Data))) => {
                        let mut buf = [0; 4096];
                        while let Ok(read) = h3.recv_body(&mut self.conn, stream_id, &mut buf) {
                            let data = &buf[..read];
                            debug!("Received {} bytes on stream {}", read, stream_id);
                            debug!("{}", String::from_utf8_lossy(data));
                        }
                    }
                    Ok(Some((
                        sid,
                        crate::transport::h3::Event::MasqueCapsule { capsule_type, payload },
                    ))) => {
                        // On first capsule, optionally send an establishment ACK.
                        if !h3.masque_established(sid) {
                            h3.mark_masque_established(sid);
                            let ack = crate::transport::h3::Connection::encode_capsule(
                                0x02,
                                b"established",
                            );
                            let _ = h3.send_capsule(&mut self.conn, sid, &ack, false);
                        }
                        if capsule_type == 0x00 {
                            if let Some(cb) = &self.masque_datagram_cb {
                                if let Ok(mut f) = cb.lock() {
                                    (f)(&payload[..]);
                                }
                            } else if let Some(cb) = &self.masque_cb {
                                if let Ok(mut f) = cb.lock() {
                                    (f)(capsule_type, &payload[..]);
                                }
                            }
                        } else if capsule_type == 0x21 {
                            // compressed UDP capsule (no dict)
                            // attempt decompress and route as datagram
                            let pool = self.optimization_manager.memory_pool();
                            if let Some((blk, used)) =
                                crate::compress::CompressionManager::new(Default::default())
                                    .decompress_to_pool(&pool, &payload)
                            {
                                if let Some(cb) = &self.masque_datagram_cb {
                                    if let Ok(mut f) = cb.lock() {
                                        (f)(&blk[..used]);
                                    }
                                } else if let Some(cb) = &self.masque_cb {
                                    if let Ok(mut f) = cb.lock() {
                                        (f)(0x00, &blk[..used]);
                                    }
                                }
                                pool.free(blk);
                            }
                        } else if capsule_type == 0x22 {
                            // dict-compressed UDP capsule
                            if payload.len() >= 9 && payload[0] == 0x5D {
                                // parse id fields from payload header
                                let mut hb = [0u8; 2];
                                hb.copy_from_slice(&payload[1..3]);
                                let hash = u16::from_be_bytes(hb);
                                let mut vb = [0u8; 2];
                                vb.copy_from_slice(&payload[3..5]);
                                let ver = u16::from_be_bytes(vb);
                                if let Some(dict) = crate::compress::get_dict_by_id(hash, ver) {
                                    let pool = self.optimization_manager.memory_pool();
                                    if let Some((blk, used)) = crate::compress::decompress_with_dict(
                                        &pool, &payload, &dict,
                                    ) {
                                        if let Some(cb) = &self.masque_datagram_cb {
                                            if let Ok(mut f) = cb.lock() {
                                                (f)(&blk[..used]);
                                            }
                                        } else if let Some(cb) = &self.masque_cb {
                                            if let Ok(mut f) = cb.lock() {
                                                (f)(0x00, &blk[..used]);
                                            }
                                        }
                                        pool.free(blk);
                                    }
                                }
                            }
                        } else if let Some(cb) = &self.masque_control_cb {
                            if let Ok(mut f) = cb.lock() {
                                (f)(capsule_type, &payload[..]);
                            }
                        } else if let Some(cb) = &self.masque_cb {
                            if let Ok(mut f) = cb.lock() {
                                (f)(capsule_type, &payload[..]);
                            }
                        }
                    }

                    Ok(Some((_id, crate::transport::h3::Event::Reset(err)))) => {
                        crate::optimize::telemetry::STEALTH_SIGNAL_RST
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        warn!("H3 stream reset: {:?}", err);
                    }
                    Ok(Some((_id, crate::transport::h3::Event::PriorityUpdate))) => {
                        debug!("H3 priority update received");
                    }
                    Ok(Some((_id, crate::transport::h3::Event::GoAway))) => {
                        info!("H3 GOAWAY received");
                    }
                    Ok(Some((_id, crate::transport::h3::Event::Finished))) => {}
                    Ok(Some((
                        _id,
                        crate::transport::h3::Event::PushPromise { push_id, headers },
                    ))) => {
                        info!(
                            "Received stealth push promise {} with {} headers",
                            push_id,
                            headers.len()
                        );
                    }
                    Ok(None) => break,
                    Err(crate::transport::h3::Error::Done) => break,
                    Err(e) => return Err(e.into()),
                }
                // Opportunistically receive QUIC DATAGRAMs for MASQUE and forward to callbacks.
                if self.stealth_manager.masque_datagram_enabled() {
                    while let Some((_fid, pl)) = h3.try_recv_masque_datagram(&mut self.conn) {
                        if let Some(cb) = &self.masque_datagram_cb {
                            if let Ok(mut f) = cb.lock() {
                                (f)(&pl[..]);
                            }
                        } else if let Some(cb) = &self.masque_cb {
                            if let Ok(mut f) = cb.lock() {
                                (f)(0x00, &pl[..]);
                            }
                        }
                    }
                }
            }
            debug!("HTTP/3 events processed in {} ms", start.elapsed().as_millis());
        }
        Ok(())
    }

    /// Polls HTTP/3 events and forwards received HEADERS/DATA frames to the provided sinks.
    pub fn poll_http3_with_headers<FH, FB>(
        &mut self,
        mut on_headers: FH,
        mut on_body: FB,
    ) -> Result<(), crate::error::ConnectionError>
    where
        FH: FnMut(u64, &[crate::transport::h3::Header]),
        FB: FnMut(u64, &[u8]),
    {
        if self.h3_conn.is_none() && self.conn.is_established() {
            let _ = self.init_http3();
        }
        if let Some(ref mut h3) = self.h3_conn {
            let start = std::time::Instant::now();
            loop {
                let intelligent_level =
                    if matches!(self.stealth_manager.mode(), StealthMode::Intelligent) {
                        intelligent_stealth_level_hint()
                    } else {
                        0
                    };
                if matches!(self.stealth_manager.mode(), StealthMode::Intelligent) {
                    self.stealth_manager.maybe_escalate_masque_intelligent();
                    if intelligent_level == 0 {
                        self.stealth_manager.enable_server_push_runtime(false, None);
                    } else {
                        let intensity = if intelligent_level >= 2 { 0.9 } else { 0.65 };
                        self.stealth_manager.enable_server_push_runtime(true, Some(intensity));
                    }
                }
                // Intelligent mode: enable runtime Server Push via brain advice
                if matches!(self.stealth_manager.mode(), StealthMode::Intelligent) {
                    #[cfg(feature = "orchestrator")]
                    {
                        if intelligent_level >= 1 {
                            if let Some(orchestrator) = ORCHESTRATOR.get() {
                                let stats = self.conn.stats();
                                let sent = stats.sent as u64;
                                let lost = stats.lost as u64;
                                let loss_rate_permille = if sent > 0 {
                                    (((lost.saturating_mul(1000)) / sent).min(1000)) as u32
                                } else {
                                    0
                                };
                                let delivery_rate_bps = self
                                    .conn
                                    .delivery_rate()
                                    .max(self.stats.congestion_delivery_rate);
                                let stealth_active = !matches!(
                                    self.stealth_manager.mode(),
                                    StealthMode::Performance | StealthMode::Off
                                );
                                orchestrator.update_runtime_signals(
                                    loss_rate_permille,
                                    self.runtime_cpu_percent,
                                    self.runtime_memory_pressure,
                                    delivery_rate_bps,
                                    stealth_active,
                                );
                            }
                            if let Some(orchestrator) = ORCHESTRATOR.get() {
                                if orchestrator.should_trigger_server_push() {
                                    let mut intensity = orchestrator.get_server_push_intensity();
                                    if intelligent_level >= 2 {
                                        intensity = intensity.max(0.9);
                                    }
                                    self.stealth_manager
                                        .enable_server_push_runtime(true, Some(intensity));
                                }
                            }
                        } else {
                            self.stealth_manager.enable_server_push_runtime(false, None);
                        }
                    }
                }
                // Emit Server Push burst if due (config or runtime)
                if self.stealth_manager.should_trigger_server_push() {
                    if let Some((base_path, intensity)) =
                        self.stealth_manager.get_server_push_config()
                    {
                        match h3.generate_stealth_cover_burst(&base_path) {
                            Ok(ids) => {
                                let stats = self.conn.stats();
                                let sent = stats.sent as u64;
                                let lost = stats.lost as u64;
                                let loss_rate_permille = if sent > 0 {
                                    (((lost.saturating_mul(1000)) / sent).min(1000)) as u32
                                } else {
                                    0
                                };
                                let reason = if loss_rate_permille >= 50 {
                                    ServerPushTriggerReason::Loss
                                } else if intelligent_level >= 1 {
                                    ServerPushTriggerReason::Gating
                                } else {
                                    ServerPushTriggerReason::Time
                                };
                                let total_bytes = Self::estimate_server_push_cover_bytes(
                                    &base_path,
                                    ids.len(),
                                    intensity,
                                );
                                self.stealth_manager.update_server_push_state(
                                    ids.len(),
                                    total_bytes,
                                    reason,
                                );
                                debug!("Server Push burst emitted: {} promises", ids.len());
                            }
                            Err(e) => warn!("Server Push burst generation failed: {:?}", e),
                        }
                    }
                }
                match h3.poll(&mut self.conn) {
                    Ok(Some((sid, crate::transport::h3::Event::Headers { list, .. }))) => {
                        on_headers(sid, &list);
                    }
                    Ok(Some((sid, crate::transport::h3::Event::Data))) => {
                        let mut buf = [0; 65535];
                        while let Ok(read) = h3.recv_body(&mut self.conn, sid, &mut buf) {
                            if read == 0 {
                                break;
                            }
                            on_body(sid, &buf[..read]);
                        }
                    }
                    Ok(Some((_id, crate::transport::h3::Event::Reset(_)))) => {
                        crate::optimize::telemetry::STEALTH_SIGNAL_RST
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    Ok(Some((_id, _ev))) => { /* ignore */ }
                    Ok(None) => break,
                    Err(crate::transport::h3::Error::Done) => break,
                    Err(e) => return Err(e.into()),
                }
            }
            debug!("HTTP/3 events processed in {} ms", start.elapsed().as_millis());
        }
        Ok(())
    }

    /// Polls HTTP/3 events and forwards received DATA frames to the provided sink.
    pub fn poll_http3_with<F>(
        &mut self,
        mut on_body: F,
    ) -> Result<(), crate::error::ConnectionError>
    where
        F: FnMut(&[u8]),
    {
        self.poll_http3_with_headers(|_sid, _headers| {}, |_sid, data| on_body(data))?;
        Ok(())
    }

    /// Poll HTTP/3 events and forward MASQUE capsules to provided callback.
    pub fn poll_http3_capsules_with<F>(
        &mut self,
        mut on_capsule: F,
    ) -> Result<(), crate::error::ConnectionError>
    where
        F: FnMut(u64, &[u8]),
    {
        self.init_http3()?;
        if let Some(ref mut h3) = self.h3_conn {
            loop {
                match h3.poll(&mut self.conn) {
                    Ok(Some((
                        _sid,
                        crate::transport::h3::Event::MasqueCapsule { capsule_type, payload },
                    ))) => {
                        on_capsule(capsule_type, &payload);
                    }
                    Ok(Some((_sid, _ev))) => { /* ignore other events */ }
                    Ok(None) => break,
                    Err(crate::transport::h3::Error::Done) => break,
                    Err(e) => return Err(e.into()),
                }
            }
        }
        Ok(())
    }

    /// Register a MASQUE capsule callback to be invoked during poll_http3().
    pub fn set_masque_capsule_handler(&mut self, handler: Option<CapsuleHandler>) {
        self.masque_cb = handler;
    }

    /// Register a MASQUE datagram (0x00) handler
    pub fn set_masque_datagram_handler(&mut self, handler: Option<DatagramHandler>) {
        self.masque_datagram_cb = handler;
    }

    /// Register a MASQUE control capsule handler (non-0x00)
    pub fn set_masque_control_handler(&mut self, handler: Option<CapsuleHandler>) {
        self.masque_control_cb = handler;
    }

    /// Returns true if a MASQUE CONNECT-UDP flow is currently registered.
    pub fn masque_flow_active(&self) -> bool {
        self.h3_conn.as_ref().map(|h| h.masque_flow_active()).unwrap_or(false)
    }

    /// Update internal state, e.g., FEC mode based on statistics.
    pub fn update_state(&mut self) {
        // Update stats
        let stats = self.conn.stats();
        self.stats.packets_sent = stats.sent as u64;
        self.stats.rtt =
            self.conn.path_stats().next().map(|ps| ps.rtt.as_secs_f32()).unwrap_or(0.0);
        self.stats.packets_lost = stats.lost as u64;
        self.stats.loss_rate =
            if stats.sent > 0 { stats.lost as f32 / stats.sent as f32 } else { 0.0 };
        self.stats.update_congestion(CongestionSample::from_transport_stats(stats));

        if self.last_telemetry.elapsed() >= std::time::Duration::from_secs(1) {
            telemetry!(telemetry::update_memory_usage());
            telemetry!(telemetry::flush());
            #[cfg(feature = "orchestrator")]
            self.update_orchestrator_resource_signals();
            self.last_telemetry = std::time::Instant::now();
        }

        // Handle path events for connection migration
        while let Some(event) = self.conn.path_event_next() {
            match event {
                crate::transport::PathEvent::New(local, peer) => {
                    info!("New path detected: {local}->{peer}");
                }
                crate::transport::PathEvent::Validated(local, peer) => {
                    info!("Path validated: {local}->{peer}");
                    self.peer_addr = peer;
                    self.local_addr = local;
                    if let Some(ref mut xdp) = self.xdp_socket {
                        if let Err(e) = xdp.reconfigure(local, peer) {
                            warn!("XDP reconfigure failed: {e}");
                            self.xdp_socket =
                                self.optimization_manager.create_xdp_socket(local, peer);
                        }
                    } else {
                        self.xdp_socket = self.optimization_manager.create_xdp_socket(local, peer);
                    }
                    telemetry!(telemetry::PATH_MIGRATIONS.inc());
                }
                crate::transport::PathEvent::FailedValidation(local, peer) => {
                    warn!("Path validation failed: {local}->{peer}");
                }
                crate::transport::PathEvent::Closed(local, peer) => {
                    info!("Path closed: {local}->{peer}");
                }
                crate::transport::PathEvent::ReusedSourceConnectionId(seq, old, new) => {
                    info!("CID {seq} reused from {old:?} to {new:?}");
                }
                crate::transport::PathEvent::PeerMigrated(local, peer) => {
                    info!("Peer migrated: {local}->{peer}");
                    self.peer_addr = peer;
                    self.local_addr = local;
                    if let Some(ref mut xdp) = self.xdp_socket {
                        if let Err(e) = xdp.reconfigure(local, peer) {
                            warn!("XDP reconfigure failed: {e}");
                            self.xdp_socket =
                                self.optimization_manager.create_xdp_socket(local, peer);
                        }
                    } else {
                        self.xdp_socket = self.optimization_manager.create_xdp_socket(local, peer);
                    }
                    telemetry!(telemetry::PATH_MIGRATIONS.inc());
                }
            }
        }

        if self.masque_flow_active() {
            crate::telemetry::MASQUE_ACTIVE.store(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            crate::telemetry::MASQUE_ACTIVE.store(0, std::sync::atomic::Ordering::Relaxed);
            self.masque_stream_id = None;
        }

        // Apply dynamic ACK/ECN policy (observer holds locks briefly).
        self.transport_observer.apply_policy(&mut self.conn);
        // Opportunistic FEC streaming interval from observer (independent of brain)
        let ivl = self.transport_observer.compute_streaming_interval() as usize;
        if (1..=32).contains(&ivl) {
            self.conn.set_fec_stream_every(ivl);
        }

        // Consume FEC control deltas from transport and apply to core AdaptiveFec
        let delta = self.conn.take_fec_control_delta();
        if let Some(every) = delta.stream_every {
            self.fec.set_stream_every(every);
        }
        if delta.force_streaming {
            self.fec.force_streaming_mode();
        }
        if let Some(ppm) = delta.redundancy_ppm {
            self.fec.set_redundancy_ppm(ppm);
        }

        // Drive AdaptiveFec loss estimator using callback feedback first, then transport deltas.
        let (cb_sent_pkts, cb_lost_pkts, _cb_sent_bytes, _cb_lost_bytes) =
            self.conn.take_fec_callback_feedback();
        if cb_sent_pkts > 0 || cb_lost_pkts > 0 {
            let total_obs = cb_sent_pkts.saturating_add(cb_lost_pkts).max(cb_lost_pkts);
            self.fec.report_loss(
                cb_lost_pkts.min(usize::MAX as u64) as usize,
                total_obs.min(usize::MAX as u64) as usize,
            );
        } else {
            let sent_total = self.stats.packets_sent;
            let lost_total = self.stats.packets_lost;
            let sent_delta = sent_total.saturating_sub(self.fec_last_report_sent);
            let lost_delta = lost_total.saturating_sub(self.fec_last_report_lost);
            if sent_delta > 0 {
                self.fec.report_loss(
                    lost_delta.min(usize::MAX as u64) as usize,
                    sent_delta.min(usize::MAX as u64) as usize,
                );
                self.fec_last_report_sent = sent_total;
                self.fec_last_report_lost = lost_total;
            }
        }
    }

    /// Returns the current estimated RTT in milliseconds.
    pub fn rtt_ms(&self) -> f32 {
        self.stats.rtt
    }

    /// Returns the current estimated packet loss rate in [0.0, 1.0].
    pub fn loss_rate(&self) -> f32 {
        self.stats.loss_rate
    }

    /// Returns current stealth mode for this connection.
    pub fn stealth_mode(&self) -> StealthMode {
        self.stealth_manager.mode()
    }

    /// Returns the effective TLS SNI currently configured on the live transport connection.
    pub fn server_name(&self) -> Option<String> {
        self.conn.server_name().map(|name| name.to_string())
    }
}
