//! QuicFuscate Client Implementation
//!
//! This module provides the production-ready client implementation with:
//! - TUN device integration
//! - QUIC connection management
//! - Packet I/O pipeline
//! - Stealth and FEC processing
//!
//! # Architecture
//!
//! ```text
//! Client packet flow:
//! - Outbound: TUN -> Stealth -> FEC -> QUIC
//! - Inbound:  QUIC -> FEC -> Stealth -> TUN
//! ```

mod backend;
mod connection;
#[cfg(test)]
mod integration;
mod io_driver;
pub mod killswitch;
mod pipeline;
pub mod platform;
pub mod profile;
pub mod quality;
mod runtime;
mod subsystems;

pub use backend::*;
pub use connection::*;
pub use io_driver::*;
pub use killswitch::KillSwitch;
pub use pipeline::*;
pub use profile::{Profile, ProfileError, ProfileManager};
pub use quality::{BandwidthTracker, Quality, QualityTracker};
pub use runtime::*;

use socket2::SockRef;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use crate::engine::{EngineConfig, EngineError, EngineState};
use crate::interface::{TunConfig, TunInterface};
use crate::optimize::MemoryPool;

/// Client runtime handle for the VPN client.
///
/// This struct manages all client subsystems and provides
/// a clean interface for the Engine layer.
pub struct ClientRuntime {
    /// Configuration
    config: EngineConfig,
    /// Memory pool for zero-copy I/O
    pool: Arc<MemoryPool>,
    /// TUN interface handle
    tun: Option<Arc<parking_lot::Mutex<TunInterface>>>,
    /// QUIC connection handle
    connection: Option<ClientConnection>,
    /// UDP socket
    socket: Option<Arc<UdpSocket>>,
    /// Subsystem handles
    subsystems: Option<ClientSubsystems>,
    /// Tokio runtime handle
    runtime: Option<runtime::SharedRuntime>,
    /// I/O driver
    io_driver: Option<Arc<IoDriver>>,
    /// I/O task handles
    io_handles: Vec<JoinHandle<()>>,
    /// Shutdown signal
    shutdown: Arc<AtomicBool>,
    /// Current state
    state: ClientState,
}

/// Client subsystem handles (initialized during start).
pub struct ClientSubsystems {
    /// Stealth manager for obfuscation
    pub stealth: Arc<crate::stealth::StealthManager>,
    /// FEC codec for error correction
    pub fec: Arc<std::sync::Mutex<FecCodec>>,
}

/// FEC codec wrapper for the client.
#[allow(dead_code)]
pub struct FecCodec {
    inner: parking_lot::Mutex<crate::fec::AdaptiveFec>,
    packet_id: std::sync::atomic::AtomicU64,
}

impl FecCodec {
    pub fn new(config: crate::engine::FecSection) -> Self {
        let initial_mode = match config.mode {
            crate::engine::FecMode::Off => crate::fec::FecMode::Zero,
            crate::engine::FecMode::Auto => crate::fec::FecMode::Normal,
            crate::engine::FecMode::Manual => crate::fec::FecMode::Normal,
        };
        let force_on = matches!(config.mode, crate::engine::FecMode::Manual);
        let mut window_sizes = std::collections::HashMap::new();
        window_sizes.insert(crate::fec::FecMode::Zero, 0);
        window_sizes.insert(crate::fec::FecMode::Light, config.window_excellent);
        window_sizes.insert(crate::fec::FecMode::Normal, config.window_good);
        window_sizes.insert(crate::fec::FecMode::Medium, config.window_fair);
        window_sizes.insert(crate::fec::FecMode::Strong, config.window_poor);
        window_sizes.insert(crate::fec::FecMode::Extreme, 100);
        window_sizes.insert(crate::fec::FecMode::Streaming, config.stream_every);

        let fec_config = crate::fec::FecConfig {
            initial_mode,
            window_sizes,
            lambda: 0.15,
            burst_window: 16,
            hysteresis: if config.enable_hysteresis { 0.1 } else { 0.0 },
            pid: crate::fec::PidConfig { kp: 1.2, ki: 0.5, kd: 0.1 },
            force_on,
            kalman_enabled: config.enable_kalman,
            kalman_q: 0.001,
            kalman_r: 0.01,
        };

        Self {
            inner: parking_lot::Mutex::new(crate::fec::AdaptiveFec::new(fec_config)),
            packet_id: std::sync::atomic::AtomicU64::new(0),
        }
    }

    #[allow(dead_code)]
    pub fn encode(&self, data: &[u8]) -> Vec<u8> {
        self.encode_packets(data).into_iter().next().unwrap_or_default()
    }

    #[allow(dead_code)]
    pub fn decode(&self, data: &[u8]) -> Vec<u8> {
        self.decode_packets(data).into_iter().next().unwrap_or_default()
    }

    pub fn encode_packets(&self, data: &[u8]) -> Vec<Vec<u8>> {
        let mut fec = self.inner.lock();
        let mem_pool = fec.memory_pool().clone();
        let id = self.packet_id.fetch_add(1, Ordering::Relaxed);
        let mut block = mem_pool.alloc();
        let len = data.len().min(block.len());
        block[..len].copy_from_slice(&data[..len]);
        let packet = crate::fec::FecPacket::new(id, Some(block), len, true, None, 0, mem_pool);
        let mut out = Vec::new();
        for pkt in fec.on_send(packet) {
            if let Some(data) = pkt.data.as_ref() {
                out.push(data[..pkt.data_len].to_vec());
            }
        }
        out
    }

    pub fn decode_packets(&self, data: &[u8]) -> Vec<Vec<u8>> {
        let mut fec = self.inner.lock();
        let mem_pool = fec.memory_pool().clone();
        let mut block = mem_pool.alloc();
        let len = data.len().min(block.len());
        block[..len].copy_from_slice(&data[..len]);
        let packet = crate::fec::FecPacket::new(0, Some(block), len, true, None, 0, mem_pool);
        match fec.on_receive(packet) {
            Ok(pkts) => pkts
                .into_iter()
                .filter_map(|pkt| pkt.data.as_ref().map(|data| data[..pkt.data_len].to_vec()))
                .collect(),
            Err(_) => Vec::new(),
        }
    }
}

/// Internal client state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientState {
    Stopped,
    Starting,
    Running,
    Connected,
    Stopping,
    Error,
}

impl From<ClientState> for EngineState {
    fn from(state: ClientState) -> Self {
        match state {
            ClientState::Stopped => EngineState::Stopped,
            ClientState::Starting => EngineState::Starting,
            ClientState::Running => EngineState::Running,
            ClientState::Connected => EngineState::Connected,
            ClientState::Stopping => EngineState::Stopping,
            ClientState::Error => EngineState::Error,
        }
    }
}

impl ClientRuntime {
    /// Create a new client runtime from configuration.
    pub fn new(config: EngineConfig) -> Result<Self, EngineError> {
        // Create memory pool
        let pool_bytes = config.optimization.memory_pool_size;
        let block_size = config.optimization.memory_pool_alignment.max(2048);
        let mut capacity = pool_bytes / block_size;
        if capacity == 0 {
            capacity = 1;
        }
        let pool = Arc::new(MemoryPool::new(capacity, block_size));

        Ok(Self {
            config,
            pool,
            tun: None,
            connection: None,
            socket: None,
            subsystems: None,
            runtime: None,
            io_driver: None,
            io_handles: Vec::new(),
            shutdown: Arc::new(AtomicBool::new(false)),
            state: ClientState::Stopped,
        })
    }

    /// Start the client runtime (opens TUN, initializes subsystems).
    pub fn start(&mut self) -> Result<(), EngineError> {
        if self.state != ClientState::Stopped {
            return Err(EngineError::InvalidState(self.state.into(), "start (not stopped)"));
        }

        self.state = ClientState::Starting;
        self.shutdown.store(false, Ordering::SeqCst);

        if let Err(e) = crate::interface::validate_tun_runtime_requirements() {
            self.state = ClientState::Error;
            return Err(EngineError::Tun(format!("{:?}", e)));
        }

        // Open TUN interface
        let tun_config = TunConfig {
            name: if self.config.interface.tun_name.is_empty() {
                None
            } else {
                Some(self.config.interface.tun_name.clone())
            },
            ip: self.config.interface.tun_ip,
            netmask: self.config.interface.tun_netmask,
            mtu: self.config.interface.tun_mtu,
            zero_copy: self.config.interface.zero_copy,
        };

        let tun = match TunInterface::open(tun_config, self.pool.clone()) {
            Ok(tun) => tun,
            Err(e) => {
                self.state = ClientState::Error;
                return Err(EngineError::Tun(format!("{:?}", e)));
            }
        };

        log::info!("TUN interface opened: {}", tun.name());
        self.tun = Some(Arc::new(parking_lot::Mutex::new(tun)));

        // Initialize subsystems
        self.subsystems = match subsystems::init_subsystems(&self.config) {
            Ok(subsystems) => Some(subsystems),
            Err(e) => {
                self.tun = None;
                self.state = ClientState::Error;
                return Err(e);
            }
        };

        if self.runtime.is_none() {
            let runtime = match runtime::create_shared_runtime(&runtime::RuntimeConfig::default()) {
                Ok(rt) => rt,
                Err(e) => {
                    self.subsystems = None;
                    self.tun = None;
                    self.state = ClientState::Error;
                    return Err(EngineError::Internal(format!("Runtime init failed: {}", e)));
                }
            };
            self.runtime = Some(runtime);
        }

        self.state = ClientState::Running;
        log::info!("Client runtime started");

        Ok(())
    }

    /// Stop the client runtime.
    pub fn stop(&mut self) -> Result<(), EngineError> {
        if self.state == ClientState::Stopped {
            return Ok(());
        }
        if self.state == ClientState::Connected {
            let _ = self.disconnect();
        }

        self.state = ClientState::Stopping;
        self.shutdown.store(true, Ordering::SeqCst);

        // Close connection first
        if let Some(mut conn) = self.connection.take() {
            conn.close(0, b"Client shutdown");
            log::info!("QUIC connection closed");
        }
        self.socket = None;
        self.io_handles.clear();
        self.io_driver = None;

        // Close subsystems
        self.subsystems = None;

        // Close TUN
        if let Some(tun) = self.tun.take() {
            let name = tun.lock().name().to_string();
            log::info!("Closing TUN interface: {}", name);
        }

        self.state = ClientState::Stopped;
        log::info!("Client runtime stopped");

        Ok(())
    }

    /// Connect to the remote server.
    pub fn connect(&mut self) -> Result<(), EngineError> {
        if self.state != ClientState::Running {
            return Err(EngineError::InvalidState(self.state.into(), "connect (must be running)"));
        }

        // Create QUIC connection
        let conn = ClientConnection::connect(&self.config)?;
        let local_addr = conn.local_addr();
        let remote_addr = conn.peer_addr();
        self.connection = Some(conn);

        let runtime = self
            .runtime
            .as_ref()
            .ok_or_else(|| EngineError::Internal("Runtime not initialized".to_string()))?
            .clone();
        // `tokio::net::UdpSocket::from_std` requires an active runtime context.
        // The engine API is sync, so we must enter our runtime explicitly.
        let _rt_guard = runtime.enter();

        let io_config = IoDriverConfig::default();
        let std_socket = std::net::UdpSocket::bind(local_addr)
            .map_err(|e| EngineError::Io(format!("UDP bind failed: {}", e)))?;
        std_socket
            .set_nonblocking(true)
            .map_err(|e| EngineError::Io(format!("UDP nonblocking failed: {}", e)))?;
        let sock_ref = SockRef::from(&std_socket);
        let _ = sock_ref.set_recv_buffer_size(io_config.socket_buffer_size);
        let _ = sock_ref.set_send_buffer_size(io_config.socket_buffer_size);
        std_socket
            .connect(remote_addr)
            .map_err(|e| EngineError::Io(format!("UDP connect failed: {}", e)))?;
        let socket = UdpSocket::from_std(std_socket)
            .map_err(|e| EngineError::Io(format!("UDP setup failed: {}", e)))?;
        let socket = Arc::new(socket);
        self.socket = Some(socket.clone());

        let io_driver = Arc::new(IoDriver::new(io_config));
        self.io_driver = Some(io_driver.clone());
        let tun = self
            .tun
            .as_ref()
            .ok_or_else(|| EngineError::Tun("TUN not initialized".to_string()))?
            .clone();
        let shared_conn = self
            .connection
            .as_ref()
            .ok_or_else(|| EngineError::Connection("Connection not initialized".to_string()))?
            .shared();

        let outbound = runtime.spawn({
            let io_driver = io_driver.clone();
            let tun = tun.clone();
            let conn = shared_conn.clone();
            let socket = socket.clone();
            async move {
                let _ = io_driver.run_outbound(tun, conn, socket).await;
            }
        });
        let inbound = runtime.spawn({
            let io_driver = io_driver.clone();
            let tun = tun.clone();
            let conn = shared_conn.clone();
            let socket = socket.clone();
            async move {
                let _ = io_driver.run_inbound(tun, conn, socket).await;
            }
        });
        self.io_handles = vec![outbound, inbound];

        self.state = ClientState::Connected;
        log::info!("Connected to server");

        Ok(())
    }

    /// Disconnect from the server.
    pub fn disconnect(&mut self) -> Result<(), EngineError> {
        if self.state != ClientState::Connected {
            return Err(EngineError::InvalidState(
                self.state.into(),
                "disconnect (must be connected)",
            ));
        }

        if let Some(io) = &self.io_driver {
            io.shutdown();
        }
        if let Some(rt) = self.runtime.as_ref() {
            let handles = std::mem::take(&mut self.io_handles);
            rt.block_on(async move {
                for handle in handles {
                    let _ = handle.await;
                }
            });
        }
        if let Some(mut conn) = self.connection.take() {
            conn.close(0, b"Disconnect requested");
            log::info!("Disconnected from server");
        }
        self.socket = None;
        self.io_driver = None;

        self.state = ClientState::Running;
        Ok(())
    }

    /// Check if connected.
    pub fn is_connected(&self) -> bool {
        self.state == ClientState::Connected && self.connection.is_some()
    }

    /// Check whether the transport handshake is fully established.
    pub fn is_handshake_established(&self) -> bool {
        if self.state != ClientState::Connected {
            return false;
        }
        self.connection.as_ref().map(|conn| conn.is_established()).unwrap_or(false)
    }

    /// Get connection reference (if connected).
    pub fn connection(&self) -> Option<&ClientConnection> {
        self.connection.as_ref()
    }

    /// Get mutable connection reference.
    pub fn connection_mut(&mut self) -> Option<&mut ClientConnection> {
        self.connection.as_mut()
    }

    /// Get current state.
    pub fn state(&self) -> ClientState {
        self.state
    }

    /// Get TUN interface name (if open).
    pub fn tun_name(&self) -> Option<String> {
        self.tun.as_ref().map(|t| t.lock().name().to_string())
    }

    /// Get memory pool reference.
    pub fn pool(&self) -> &Arc<MemoryPool> {
        &self.pool
    }

    /// Get shutdown signal.
    pub fn shutdown_signal(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }

    /// Check if shutdown was requested.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Get subsystems reference (if initialized).
    pub fn subsystems(&self) -> Option<&ClientSubsystems> {
        self.subsystems.as_ref()
    }

    /// Get TUN handle (if open).
    pub fn tun(&self) -> Option<Arc<parking_lot::Mutex<TunInterface>>> {
        self.tun.clone()
    }
}

impl Drop for ClientRuntime {
    fn drop(&mut self) {
        if self.state != ClientState::Stopped {
            let _ = self.stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_runtime_new() {
        let config = EngineConfig::default();
        let runtime = ClientRuntime::new(config);
        assert!(runtime.is_ok());
    }

    // Note: TUN tests require root/admin privileges
    // They are tested in integration tests
}
