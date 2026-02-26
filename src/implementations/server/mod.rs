//! QuicFuscate Server Implementation
//!
//! This module provides the production-ready server implementation with:
//! - Multi-client connection handling
//! - Session management
//! - IP pool allocation
//! - NAT/routing configuration
//!
//! # Architecture
//!
//! ```text
//! Server flow:
//! - Accept QUIC connections
//! - Track sessions and assign IPs
//! - Route traffic via TUN and (optionally) NAT/routing on the host
//! ```

mod accept;
pub mod admin;
pub mod admin_http;
pub mod admin_logs;
mod ip_pool;
mod limits;
pub mod metrics;
pub mod qkey_registry;
mod routing;
mod session;
pub mod systemd;

pub use accept::*;
pub use admin::{AdminCommand, AdminHandler, AdminResponse, DefaultAdminHandler};
pub use admin_http::{AdminHttpHandler, AdminHttpServer};
pub use ip_pool::*;
pub use limits::*;
pub use metrics::{GlobalMetricsServer, Metrics};
pub use routing::*;
pub use session::*;

use parking_lot::RwLock;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use crate::engine::{EngineConfig, EngineError};
use crate::interface::{TunConfig, TunInterface};
use crate::optimize::MemoryPool;

/// Server configuration (extends EngineConfig).
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// Listen address
    pub listen: SocketAddr,
    /// Maximum concurrent clients
    pub max_clients: usize,
    /// Client session timeout (seconds)
    pub client_timeout_secs: u64,
    /// IP pool start
    pub ip_pool_start: Ipv4Addr,
    /// IP pool end
    pub ip_pool_end: Ipv4Addr,
    /// Server TUN IP
    pub server_ip: Ipv4Addr,
    /// Server netmask
    pub server_netmask: Ipv4Addr,
    /// DNS servers to push
    pub dns_servers: Vec<Ipv4Addr>,
    /// WAN interface for NAT
    pub wan_interface: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 4433)),
            max_clients: 100,
            client_timeout_secs: 3600,
            ip_pool_start: Ipv4Addr::new(10, 8, 0, 2),
            ip_pool_end: Ipv4Addr::new(10, 8, 0, 254),
            server_ip: Ipv4Addr::new(10, 8, 0, 1),
            server_netmask: Ipv4Addr::new(255, 255, 255, 0),
            dns_servers: vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)],
            wan_interface: "eth0".to_string(),
        }
    }
}

/// Server runtime handle.
pub struct ServerRuntime {
    /// Engine configuration
    engine_config: EngineConfig,
    /// Server-specific configuration
    server_config: ServerConfig,
    /// Memory pool
    pool: Arc<MemoryPool>,
    /// TUN interface
    tun: Option<TunInterface>,
    /// Session manager
    sessions: Arc<RwLock<SessionManager>>,
    /// IP pool
    ip_pool: Arc<parking_lot::Mutex<IpPool>>,
    /// Rate limiter (only used when rate_limiter feature is enabled)
    #[allow(dead_code)]
    rate_limiter: Arc<RateLimiter>,
    /// Connection limiter
    connection_limiter: Arc<parking_lot::Mutex<ConnectionLimiter>>,
    /// Routing manager
    routing: Option<RoutingManager>,
    /// Shutdown signal
    shutdown: Arc<AtomicBool>,
    /// Server state
    state: ServerState,
    /// Statistics
    stats: Arc<ServerStats>,
}

/// Server state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerState {
    Stopped,
    Starting,
    Running,
    Stopping,
}

/// Server statistics.
#[derive(Debug, Default)]
pub struct ServerStats {
    pub total_connections: AtomicU64,
    pub active_connections: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub packets_in: AtomicU64,
    pub packets_out: AtomicU64,
    pub connections_rejected: AtomicU64,
    pub packets_rate_limited: AtomicU64,
}

impl ServerRuntime {
    /// Create a new server runtime.
    pub fn new(
        engine_config: EngineConfig,
        server_config: ServerConfig,
    ) -> Result<Self, EngineError> {
        // Create memory pool
        let pool_bytes = engine_config.optimization.memory_pool_size;
        let block_size = engine_config.optimization.memory_pool_alignment.max(2048);
        let mut capacity = pool_bytes / block_size;
        if capacity == 0 {
            capacity = 1;
        }
        let pool = Arc::new(MemoryPool::new(capacity, block_size));

        // Create IP pool
        let ip_pool = Arc::new(parking_lot::Mutex::new(IpPool::new(
            server_config.ip_pool_start,
            server_config.ip_pool_end,
        )));

        // Create session manager
        let sessions = Arc::new(RwLock::new(SessionManager::new(server_config.max_clients)));

        // Create rate limiter
        let rate_limiter = Arc::new(RateLimiter::new(RateLimitConfig::default()));

        // Create connection limiter
        let connection_limiter = Arc::new(parking_lot::Mutex::new(
            ConnectionLimiter::new(3), // Max 3 connections per IP
        ));

        Ok(Self {
            engine_config,
            server_config,
            pool,
            tun: None,
            sessions,
            ip_pool,
            rate_limiter,
            connection_limiter,
            routing: None,
            shutdown: Arc::new(AtomicBool::new(false)),
            state: ServerState::Stopped,
            stats: Arc::new(ServerStats::default()),
        })
    }

    /// Start the server.
    pub fn start(&mut self) -> Result<(), EngineError> {
        if self.state != ServerState::Stopped {
            return Err(EngineError::InvalidState(
                crate::engine::EngineState::Running,
                "start (already running)",
            ));
        }

        self.state = ServerState::Starting;
        self.shutdown.store(false, Ordering::SeqCst);

        if let Err(e) = crate::interface::validate_tun_runtime_requirements() {
            self.state = ServerState::Stopped;
            return Err(EngineError::Tun(format!("{:?}", e)));
        }

        // Open TUN interface
        let tun_config = TunConfig {
            name: Some("qfserver0".to_string()),
            ip: self.engine_config.interface.tun_ip.or(Some(self.server_config.server_ip.into())),
            netmask: self
                .engine_config
                .interface
                .tun_netmask
                .or(Some(self.server_config.server_netmask.into())),
            mtu: self.engine_config.interface.tun_mtu,
            zero_copy: self.engine_config.interface.zero_copy,
        };

        let tun = match TunInterface::open(tun_config, self.pool.clone()) {
            Ok(tun) => tun,
            Err(e) => {
                self.state = ServerState::Stopped;
                return Err(EngineError::Tun(format!("{:?}", e)));
            }
        };

        log::info!("Server TUN interface opened: {}", tun.name());
        self.tun = Some(tun);

        // Setup routing (Linux only)
        #[cfg(target_os = "linux")]
        {
            let routing = RoutingManager::new(
                "qfserver0".to_string(),
                self.server_config.server_ip,
                self.server_config.server_netmask,
                self.server_config.wan_interface.clone(),
            );

            if let Err(e) = routing.setup() {
                log::warn!("Failed to setup routing: {:?}", e);
                // Continue without routing - might be set up externally
            } else {
                self.routing = Some(routing);
            }
        }

        self.state = ServerState::Running;
        log::info!("Server started on {}", self.server_config.listen);

        Ok(())
    }

    /// Stop the server.
    pub fn stop(&mut self) -> Result<(), EngineError> {
        if self.state == ServerState::Stopped {
            return Ok(());
        }

        self.state = ServerState::Stopping;
        self.shutdown.store(true, Ordering::SeqCst);

        // Close all sessions
        {
            let mut sessions = self.sessions.write();
            let session_ids: Vec<_> = sessions.all_session_ids();
            for id in session_ids {
                sessions.remove(id);
            }
        }

        // Teardown routing
        if let Some(routing) = self.routing.take() {
            if let Err(e) = routing.teardown() {
                log::warn!("Failed to teardown routing: {:?}", e);
            }
        }

        // Close TUN
        if let Some(tun) = self.tun.take() {
            log::info!("Closing server TUN: {}", tun.name());
            drop(tun);
        }

        self.state = ServerState::Stopped;
        log::info!("Server stopped");

        Ok(())
    }

    /// Handle new client connection.
    pub fn accept_client(&self, remote_addr: SocketAddr) -> Result<SessionId, AcceptError> {
        // Check connection limit per IP
        {
            let limiter = self.connection_limiter.lock();
            if !limiter.check(remote_addr.ip()) {
                self.stats.connections_rejected.fetch_add(1, Ordering::Relaxed);
                return Err(AcceptError::TooManyConnectionsPerIp);
            }
        }

        // Check total session limit
        {
            let sessions = self.sessions.read();
            if sessions.len() >= self.server_config.max_clients {
                self.stats.connections_rejected.fetch_add(1, Ordering::Relaxed);
                return Err(AcceptError::MaxClientsReached);
            }
        }

        // Allocate IP
        let client_ip = {
            let mut pool = self.ip_pool.lock();
            pool.allocate().ok_or(AcceptError::IpPoolExhausted)?
        };

        // Create session
        let session = Session::new(remote_addr, client_ip, self.server_config.client_timeout_secs);
        let session_id = session.id();

        // Register session
        {
            let mut sessions = self.sessions.write();
            sessions.add(session)?;
        }

        // Track connection per IP
        {
            let mut limiter = self.connection_limiter.lock();
            limiter.add(remote_addr.ip());
        }

        self.stats.total_connections.fetch_add(1, Ordering::Relaxed);
        self.stats.active_connections.fetch_add(1, Ordering::Relaxed);

        log::info!("Client connected: {} -> {}", remote_addr, client_ip);

        Ok(session_id)
    }

    /// Remove client session.
    pub fn remove_client(&self, session_id: SessionId) {
        let session = {
            let mut sessions = self.sessions.write();
            sessions.remove(session_id)
        };

        if let Some(session) = session {
            // Release IP
            {
                let mut pool = self.ip_pool.lock();
                pool.release(session.client_ip());
            }

            // Remove from connection limiter
            {
                let mut limiter = self.connection_limiter.lock();
                limiter.remove(session.remote_addr().ip());
            }

            self.stats.active_connections.fetch_sub(1, Ordering::Relaxed);

            log::info!(
                "Client disconnected: {} (IP: {})",
                session.remote_addr(),
                session.client_ip()
            );
        }
    }

    /// Get server state.
    pub fn state(&self) -> ServerState {
        self.state
    }

    /// Get server statistics.
    pub fn stats(&self) -> &ServerStats {
        &self.stats
    }

    /// Get session count.
    pub fn session_count(&self) -> usize {
        self.sessions.read().len()
    }

    /// Check if shutdown was requested.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Get shutdown signal.
    pub fn shutdown_signal(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }

    /// Check packet rate for a session (DoS protection).
    /// Returns Ok(()) if within limits, Err if rate limited.
    /// Only active when `rate_limiter` feature is enabled.
    #[cfg(feature = "rate_limiter")]
    pub fn check_packet_rate(&self, session_id: SessionId) -> Result<(), PacketRateLimitError> {
        // Check packet rate
        if !self.rate_limiter.check_packet(session_id.as_u64()) {
            self.stats.packets_rate_limited.fetch_add(1, Ordering::Relaxed);
            return Err(PacketRateLimitError::RateExceeded(0));
        }
        Ok(())
    }

    /// Record packet for rate limiting (must be called after successful processing).
    /// Only active when `rate_limiter` feature is enabled.
    #[cfg(feature = "rate_limiter")]
    pub fn record_packet(&self, session_id: SessionId, bytes: usize) {
        // Record bytes for byte-rate limiting (if enabled)
        let _ = self.rate_limiter.check_bytes(session_id.as_u64(), bytes as u64);
    }
}

impl Drop for ServerRuntime {
    fn drop(&mut self) {
        if self.state != ServerState::Stopped {
            let _ = self.stop();
        }
    }
}

/// Errors when accepting a client.
#[derive(Debug, Clone)]
pub enum AcceptError {
    MaxClientsReached,
    TooManyConnectionsPerIp,
    IpPoolExhausted,
    SessionError(String),
}

impl std::fmt::Display for AcceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcceptError::MaxClientsReached => write!(f, "Maximum clients reached"),
            AcceptError::TooManyConnectionsPerIp => write!(f, "Too many connections from this IP"),
            AcceptError::IpPoolExhausted => write!(f, "IP pool exhausted"),
            AcceptError::SessionError(e) => write!(f, "Session error: {}", e),
        }
    }
}

impl std::error::Error for AcceptError {}

impl From<SessionError> for AcceptError {
    fn from(e: SessionError) -> Self {
        AcceptError::SessionError(e.to_string())
    }
}

/// Errors when rate limiting is triggered.
#[derive(Debug, Clone)]
pub enum PacketRateLimitError {
    SessionNotFound,
    RateExceeded(usize), // tokens remaining when rejected
}

impl std::fmt::Display for PacketRateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketRateLimitError::SessionNotFound => {
                write!(f, "Session not found for rate limiting")
            }
            PacketRateLimitError::RateExceeded(tokens) => {
                write!(f, "Rate limit exceeded ({} tokens remaining)", tokens)
            }
        }
    }
}

impl std::error::Error for PacketRateLimitError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config_default() {
        let config = ServerConfig::default();
        assert_eq!(config.max_clients, 100);
        assert_eq!(config.server_ip, Ipv4Addr::new(10, 8, 0, 1));
    }

    #[test]
    fn test_server_runtime_new() {
        let engine_config = EngineConfig::default();
        let server_config = ServerConfig::default();
        let runtime = ServerRuntime::new(engine_config, server_config);
        assert!(runtime.is_ok());
    }
}
