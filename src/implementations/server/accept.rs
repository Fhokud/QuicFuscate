//! Production-grade accept loop for QuicFuscate server.
//!
//! Handles incoming QUIC connections with:
//! - Backpressure when at capacity
//! - Graceful shutdown with drain timeout
//! - Per-IP connection limits
//! - Metrics collection

use parking_lot::RwLock;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

/// Accept loop configuration.
#[derive(Clone, Debug)]
pub struct AcceptConfig {
    /// Maximum pending connections in backlog
    pub backlog_size: usize,
    /// Timeout for accepting a single connection
    pub accept_timeout: Duration,
    /// Backpressure delay when at capacity
    pub backpressure_delay: Duration,
    /// Maximum connections from same IP
    pub max_per_ip: usize,
    /// Drain timeout on shutdown
    pub drain_timeout: Duration,
}

impl Default for AcceptConfig {
    fn default() -> Self {
        Self {
            backlog_size: 128,
            accept_timeout: Duration::from_secs(5),
            backpressure_delay: Duration::from_millis(100),
            max_per_ip: 5,
            drain_timeout: Duration::from_secs(30),
        }
    }
}

/// Accept loop statistics.
#[derive(Debug, Default)]
pub struct AcceptStats {
    /// Total connections accepted
    pub accepted: AtomicU64,
    /// Connections rejected (at capacity)
    pub rejected_capacity: AtomicU64,
    /// Connections rejected (per-IP limit)
    pub rejected_per_ip: AtomicU64,
    /// Connections rejected (rate limited)
    pub rejected_rate: AtomicU64,
    /// Current queue depth
    pub queue_depth: AtomicU64,
}

impl AcceptStats {
    /// Get a snapshot of current stats.
    pub fn snapshot(&self) -> AcceptStatsSnapshot {
        AcceptStatsSnapshot {
            accepted: self.accepted.load(Ordering::Relaxed),
            rejected_capacity: self.rejected_capacity.load(Ordering::Relaxed),
            rejected_per_ip: self.rejected_per_ip.load(Ordering::Relaxed),
            rejected_rate: self.rejected_rate.load(Ordering::Relaxed),
            queue_depth: self.queue_depth.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of accept statistics.
#[derive(Debug, Clone)]
pub struct AcceptStatsSnapshot {
    pub accepted: u64,
    pub rejected_capacity: u64,
    pub rejected_per_ip: u64,
    pub rejected_rate: u64,
    pub queue_depth: u64,
}

/// Per-IP connection tracker.
#[derive(Debug, Default)]
pub struct IpConnectionTracker {
    connections: std::collections::HashMap<std::net::IpAddr, usize>,
}

impl IpConnectionTracker {
    /// Check if IP can accept new connection.
    pub fn can_accept(&self, ip: std::net::IpAddr, max_per_ip: usize) -> bool {
        self.connections.get(&ip).is_none_or(|&count| count < max_per_ip)
    }

    /// Increment connection count for IP.
    pub fn increment(&mut self, ip: std::net::IpAddr) {
        *self.connections.entry(ip).or_insert(0) += 1;
    }

    /// Decrement connection count for IP.
    pub fn decrement(&mut self, ip: std::net::IpAddr) {
        if let Some(count) = self.connections.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.connections.remove(&ip);
            }
        }
    }

    /// Get connection count for IP.
    pub fn count(&self, ip: std::net::IpAddr) -> usize {
        self.connections.get(&ip).copied().unwrap_or(0)
    }

    /// Total tracked IPs.
    pub fn unique_ips(&self) -> usize {
        self.connections.len()
    }
}

/// Production accept loop handler.
pub struct AcceptLoop {
    config: AcceptConfig,
    stats: Arc<AcceptStats>,
    ip_tracker: Arc<RwLock<IpConnectionTracker>>,
    shutdown: Arc<AtomicBool>,
}

impl AcceptLoop {
    /// Create a new accept loop.
    pub fn new(config: AcceptConfig) -> Self {
        Self {
            config,
            stats: Arc::new(AcceptStats::default()),
            ip_tracker: Arc::new(RwLock::new(IpConnectionTracker::default())),
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Get stats reference.
    pub fn stats(&self) -> &Arc<AcceptStats> {
        &self.stats
    }

    /// Get IP tracker reference.
    pub fn ip_tracker(&self) -> &Arc<RwLock<IpConnectionTracker>> {
        &self.ip_tracker
    }

    /// Check if shutdown was requested.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Request graceful shutdown.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Get shutdown signal for sharing.
    pub fn shutdown_signal(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }

    /// Check if we should accept a connection from given address.
    pub fn should_accept(
        &self,
        addr: SocketAddr,
        current_connections: usize,
        max_connections: usize,
    ) -> AcceptDecision {
        // Check shutdown
        if self.is_shutdown() {
            return AcceptDecision::Reject(RejectReason::Shutdown);
        }

        // Check global capacity
        if current_connections >= max_connections {
            self.stats.rejected_capacity.fetch_add(1, Ordering::Relaxed);
            return AcceptDecision::Backpressure;
        }

        // Check per-IP limit
        let ip = addr.ip();
        if !self.ip_tracker.read().can_accept(ip, self.config.max_per_ip) {
            self.stats.rejected_per_ip.fetch_add(1, Ordering::Relaxed);
            return AcceptDecision::Reject(RejectReason::PerIpLimit);
        }

        AcceptDecision::Accept
    }

    /// Record accepted connection.
    pub fn record_accepted(&self, addr: SocketAddr) {
        self.stats.accepted.fetch_add(1, Ordering::Relaxed);
        self.ip_tracker.write().increment(addr.ip());

        // Record to global metrics
        crate::instrumentation::global()
            .server
            .connections_accepted
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record connection closed.
    pub fn record_closed(&self, addr: SocketAddr) {
        self.ip_tracker.write().decrement(addr.ip());
    }

    /// Get backpressure delay.
    pub fn backpressure_delay(&self) -> Duration {
        self.config.backpressure_delay
    }

    /// Get drain timeout.
    pub fn drain_timeout(&self) -> Duration {
        self.config.drain_timeout
    }

    /// Run the accept loop (UDP socket version).
    ///
    /// This is a low-level loop that receives UDP packets and processes
    /// initial QUIC handshakes. For full QUIC connection handling, use
    /// with `ServerRuntime`.
    pub async fn run_udp_receiver(
        &self,
        socket: &UdpSocket,
        packet_handler: impl Fn(&[u8], SocketAddr) -> bool,
    ) -> std::io::Result<()> {
        let mut buf = vec![0u8; 65535];

        while !self.is_shutdown() {
            match tokio::time::timeout(self.config.accept_timeout, socket.recv_from(&mut buf)).await
            {
                Ok(Ok((len, addr))) => {
                    self.stats.queue_depth.fetch_add(1, Ordering::Relaxed);

                    // Process packet
                    let accepted = packet_handler(&buf[..len], addr);

                    if accepted {
                        self.stats.accepted.fetch_add(1, Ordering::Relaxed);
                    }

                    self.stats.queue_depth.fetch_sub(1, Ordering::Relaxed);
                }
                Ok(Err(e)) => {
                    log::warn!("Accept loop recv error: {}", e);
                }
                Err(_) => {
                    // Timeout - check shutdown and continue
                }
            }
        }

        log::info!("Accept loop shutting down, draining for {:?}", self.config.drain_timeout);

        // Drain phase - accept remaining connections with timeout
        let drain_deadline = tokio::time::Instant::now() + self.config.drain_timeout;
        while tokio::time::Instant::now() < drain_deadline {
            match tokio::time::timeout(Duration::from_millis(100), socket.recv_from(&mut buf)).await
            {
                Ok(Ok((len, addr))) => {
                    packet_handler(&buf[..len], addr);
                }
                _ => break,
            }
        }

        log::info!("Accept loop shutdown complete");
        Ok(())
    }
}

/// Decision for accepting a connection.
#[derive(Debug, Clone, PartialEq)]
pub enum AcceptDecision {
    Accept,
    Backpressure,
    Reject(RejectReason),
}

/// Reason for rejecting a connection.
#[derive(Debug, Clone, PartialEq)]
pub enum RejectReason {
    Shutdown,
    PerIpLimit,
    RateLimited,
    Banned,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accept_config_default() {
        let config = AcceptConfig::default();
        assert_eq!(config.max_per_ip, 5);
        assert_eq!(config.backlog_size, 128);
    }

    #[test]
    fn test_ip_tracker() {
        let mut tracker = IpConnectionTracker::default();
        let ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();

        assert!(tracker.can_accept(ip, 3));
        tracker.increment(ip);
        tracker.increment(ip);
        tracker.increment(ip);
        assert!(!tracker.can_accept(ip, 3));

        tracker.decrement(ip);
        assert!(tracker.can_accept(ip, 3));
    }

    #[test]
    fn test_accept_decision() {
        let config = AcceptConfig { max_per_ip: 2, ..Default::default() };
        let accept_loop = AcceptLoop::new(config);
        let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();

        // First connection - accept
        assert_eq!(accept_loop.should_accept(addr, 0, 100), AcceptDecision::Accept);
        accept_loop.record_accepted(addr);

        // Second connection - accept
        assert_eq!(accept_loop.should_accept(addr, 1, 100), AcceptDecision::Accept);
        accept_loop.record_accepted(addr);

        // Third connection from same IP - reject
        assert_eq!(
            accept_loop.should_accept(addr, 2, 100),
            AcceptDecision::Reject(RejectReason::PerIpLimit)
        );
    }

    #[test]
    fn test_capacity_backpressure() {
        let accept_loop = AcceptLoop::new(AcceptConfig::default());
        let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();

        // At capacity - backpressure
        assert_eq!(accept_loop.should_accept(addr, 100, 100), AcceptDecision::Backpressure);
    }

    #[test]
    fn test_shutdown_reject() {
        let accept_loop = AcceptLoop::new(AcceptConfig::default());
        let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();

        accept_loop.shutdown();
        assert_eq!(
            accept_loop.should_accept(addr, 0, 100),
            AcceptDecision::Reject(RejectReason::Shutdown)
        );
    }
}
