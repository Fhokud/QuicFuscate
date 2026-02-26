//! Prometheus metrics for QuicFuscate server.
//!
//! Exports metrics in Prometheus text format at /metrics endpoint.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Server metrics collector.
#[derive(Debug)]
pub struct Metrics {
    // Connection metrics
    pub clients_active: AtomicU64,
    pub clients_total: AtomicU64,
    pub connections_rejected: AtomicU64,

    // Traffic metrics
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub packets_in: AtomicU64,
    pub packets_out: AtomicU64,

    // Stealth metrics
    pub stealth_http3_active: AtomicU64,
    pub stealth_tls13_active: AtomicU64,

    // FEC metrics
    pub fec_packets_encoded: AtomicU64,
    pub fec_packets_decoded: AtomicU64,
    pub fec_packets_recovered: AtomicU64,

    // Error metrics
    pub auth_failed: AtomicU64,
    pub rate_limited: AtomicU64,

    // Uptime (set once at start)
    start_time: std::time::Instant,
}

impl Metrics {
    /// Create new metrics collector.
    pub fn new() -> Self {
        Self {
            clients_active: AtomicU64::new(0),
            clients_total: AtomicU64::new(0),
            connections_rejected: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            packets_in: AtomicU64::new(0),
            packets_out: AtomicU64::new(0),
            stealth_http3_active: AtomicU64::new(0),
            stealth_tls13_active: AtomicU64::new(0),
            fec_packets_encoded: AtomicU64::new(0),
            fec_packets_decoded: AtomicU64::new(0),
            fec_packets_recovered: AtomicU64::new(0),
            auth_failed: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
            start_time: std::time::Instant::now(),
        }
    }

    /// Get uptime in seconds.
    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Export as Prometheus text format.
    pub fn export(&self) -> String {
        let mut out = String::new();

        // Server info
        out.push_str("# HELP quicfuscate_up Server is up\n");
        out.push_str("# TYPE quicfuscate_up gauge\n");
        out.push_str("quicfuscate_up 1\n\n");

        out.push_str("# HELP quicfuscate_uptime_seconds Server uptime\n");
        out.push_str("# TYPE quicfuscate_uptime_seconds counter\n");
        out.push_str(&format!("quicfuscate_uptime_seconds {}\n\n", self.uptime_secs()));

        // Clients
        out.push_str("# HELP quicfuscate_clients_active Current active clients\n");
        out.push_str("# TYPE quicfuscate_clients_active gauge\n");
        out.push_str(&format!(
            "quicfuscate_clients_active {}\n\n",
            self.clients_active.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP quicfuscate_clients_total Total clients connected\n");
        out.push_str("# TYPE quicfuscate_clients_total counter\n");
        out.push_str(&format!(
            "quicfuscate_clients_total {}\n\n",
            self.clients_total.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP quicfuscate_connections_rejected Rejected connections\n");
        out.push_str("# TYPE quicfuscate_connections_rejected counter\n");
        out.push_str(&format!(
            "quicfuscate_connections_rejected {}\n\n",
            self.connections_rejected.load(Ordering::Relaxed)
        ));

        // Traffic
        out.push_str("# HELP quicfuscate_bytes_in_total Total bytes received\n");
        out.push_str("# TYPE quicfuscate_bytes_in_total counter\n");
        out.push_str(&format!(
            "quicfuscate_bytes_in_total {}\n\n",
            self.bytes_in.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP quicfuscate_bytes_out_total Total bytes sent\n");
        out.push_str("# TYPE quicfuscate_bytes_out_total counter\n");
        out.push_str(&format!(
            "quicfuscate_bytes_out_total {}\n\n",
            self.bytes_out.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP quicfuscate_packets_in_total Total packets received\n");
        out.push_str("# TYPE quicfuscate_packets_in_total counter\n");
        out.push_str(&format!(
            "quicfuscate_packets_in_total {}\n\n",
            self.packets_in.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP quicfuscate_packets_out_total Total packets sent\n");
        out.push_str("# TYPE quicfuscate_packets_out_total counter\n");
        out.push_str(&format!(
            "quicfuscate_packets_out_total {}\n\n",
            self.packets_out.load(Ordering::Relaxed)
        ));

        // Stealth
        out.push_str("# HELP quicfuscate_stealth_http3_active Clients using HTTP/3 stealth\n");
        out.push_str("# TYPE quicfuscate_stealth_http3_active gauge\n");
        out.push_str(&format!(
            "quicfuscate_stealth_http3_active {}\n\n",
            self.stealth_http3_active.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP quicfuscate_stealth_tls13_active Clients using TLS 1.3 stealth\n");
        out.push_str("# TYPE quicfuscate_stealth_tls13_active gauge\n");
        out.push_str(&format!(
            "quicfuscate_stealth_tls13_active {}\n\n",
            self.stealth_tls13_active.load(Ordering::Relaxed)
        ));

        // FEC
        out.push_str("# HELP quicfuscate_fec_packets_encoded FEC encoded packets\n");
        out.push_str("# TYPE quicfuscate_fec_packets_encoded counter\n");
        out.push_str(&format!(
            "quicfuscate_fec_packets_encoded {}\n\n",
            self.fec_packets_encoded.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP quicfuscate_fec_packets_decoded FEC decoded packets\n");
        out.push_str("# TYPE quicfuscate_fec_packets_decoded counter\n");
        out.push_str(&format!(
            "quicfuscate_fec_packets_decoded {}\n\n",
            self.fec_packets_decoded.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP quicfuscate_fec_packets_recovered FEC recovered packets\n");
        out.push_str("# TYPE quicfuscate_fec_packets_recovered counter\n");
        out.push_str(&format!(
            "quicfuscate_fec_packets_recovered {}\n\n",
            self.fec_packets_recovered.load(Ordering::Relaxed)
        ));

        // Errors
        out.push_str("# HELP quicfuscate_auth_failed_total Authentication failures\n");
        out.push_str("# TYPE quicfuscate_auth_failed_total counter\n");
        out.push_str(&format!(
            "quicfuscate_auth_failed_total {}\n\n",
            self.auth_failed.load(Ordering::Relaxed)
        ));

        out.push_str("# HELP quicfuscate_rate_limited_total Rate limited connections\n");
        out.push_str("# TYPE quicfuscate_rate_limited_total counter\n");
        out.push_str(&format!(
            "quicfuscate_rate_limited_total {}\n",
            self.rate_limited.load(Ordering::Relaxed)
        ));

        out
    }

    /// Export as JSON for health endpoint.
    pub fn export_health(&self) -> String {
        format!(
            r#"{{"status":"ok","version":"{}","uptime":{},"clients":{}}}"#,
            env!("CARGO_PKG_VERSION"),
            self.uptime_secs(),
            self.clients_active.load(Ordering::Relaxed)
        )
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Metrics HTTP server.
pub struct MetricsServer {
    addr: std::net::SocketAddr,
    metrics: Arc<Metrics>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
}

impl MetricsServer {
    /// Create a new metrics server.
    pub fn new(port: u16, metrics: Arc<Metrics>) -> Self {
        Self {
            addr: std::net::SocketAddr::from(([0, 0, 0, 0], port)),
            metrics,
            shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Get shutdown signal.
    pub fn shutdown_signal(&self) -> Arc<std::sync::atomic::AtomicBool> {
        self.shutdown.clone()
    }

    /// Shutdown the server.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Run the metrics server.
    pub async fn run(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        log::info!("Metrics server listening on http://{}", self.addr);

        while !self.shutdown.load(Ordering::Relaxed) {
            match tokio::time::timeout(tokio::time::Duration::from_millis(100), listener.accept())
                .await
            {
                Ok(Ok((mut socket, _addr))) => {
                    let mut buf = [0u8; 1024];
                    let _ = socket.read(&mut buf).await;

                    let request = String::from_utf8_lossy(&buf);

                    // Parse request path
                    let response = if request.contains("GET /metrics") {
                        let body = self.metrics.export();
                        format!(
                            "HTTP/1.1 200 OK\r\n\
                             Content-Type: text/plain; version=0.0.4\r\n\
                             Content-Length: {}\r\n\
                             \r\n\
                             {}",
                            body.len(),
                            body
                        )
                    } else if request.contains("GET /health") {
                        let body = self.metrics.export_health();
                        format!(
                            "HTTP/1.1 200 OK\r\n\
                             Content-Type: application/json\r\n\
                             Content-Length: {}\r\n\
                             \r\n\
                             {}",
                            body.len(),
                            body
                        )
                    } else {
                        "HTTP/1.1 404 Not Found\r\n\
                         Content-Length: 0\r\n\
                         \r\n"
                            .to_string()
                    };

                    let _ = socket.write_all(response.as_bytes()).await;
                }
                Ok(Err(e)) => {
                    log::warn!("Metrics server accept error: {}", e);
                }
                Err(_) => {
                    // Timeout, check shutdown
                }
            }
        }

        log::info!("Metrics server stopped");
        Ok(())
    }
}

/// Metrics HTTP server using global instrumentation.
///
/// This server reads from the global metrics registry at `crate::instrumentation::global()`.
pub struct GlobalMetricsServer {
    addr: std::net::SocketAddr,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
}

impl GlobalMetricsServer {
    /// Create a new global metrics server.
    pub fn new(port: u16) -> Self {
        Self {
            addr: std::net::SocketAddr::from(([0, 0, 0, 0], port)),
            shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Get shutdown signal.
    pub fn shutdown_signal(&self) -> Arc<std::sync::atomic::AtomicBool> {
        self.shutdown.clone()
    }

    /// Shutdown the server.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Run the metrics server.
    pub async fn run(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        log::info!("Global metrics server listening on http://{}", self.addr);

        while !self.shutdown.load(Ordering::Relaxed) {
            match tokio::time::timeout(tokio::time::Duration::from_millis(100), listener.accept())
                .await
            {
                Ok(Ok((mut socket, _addr))) => {
                    let mut buf = [0u8; 1024];
                    let _ = socket.read(&mut buf).await;

                    let request = String::from_utf8_lossy(&buf);
                    let global = crate::instrumentation::global();

                    // Parse request path
                    let response = if request.contains("GET /metrics") {
                        let body = global.export_prometheus();
                        format!(
                            "HTTP/1.1 200 OK\r\n\
                             Content-Type: text/plain; version=0.0.4\r\n\
                             Content-Length: {}\r\n\
                             \r\n\
                             {}",
                            body.len(),
                            body
                        )
                    } else if request.contains("GET /health") {
                        let body = global.export_health();
                        format!(
                            "HTTP/1.1 200 OK\r\n\
                             Content-Type: application/json\r\n\
                             Content-Length: {}\r\n\
                             \r\n\
                             {}",
                            body.len(),
                            body
                        )
                    } else {
                        "HTTP/1.1 404 Not Found\r\n\
                         Content-Length: 0\r\n\
                         \r\n"
                            .to_string()
                    };

                    let _ = socket.write_all(response.as_bytes()).await;
                }
                Ok(Err(e)) => {
                    log::warn!("Global metrics server accept error: {}", e);
                }
                Err(_) => {
                    // Timeout, check shutdown
                }
            }
        }

        log::info!("Global metrics server stopped");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_export() {
        let metrics = Metrics::new();
        metrics.clients_active.store(42, Ordering::Relaxed);
        metrics.bytes_in.store(1_000_000, Ordering::Relaxed);

        let output = metrics.export();
        assert!(output.contains("quicfuscate_up 1"));
        assert!(output.contains("quicfuscate_clients_active 42"));
        assert!(output.contains("quicfuscate_bytes_in_total 1000000"));
    }

    #[test]
    fn test_health_export() {
        let metrics = Metrics::new();
        metrics.clients_active.store(10, Ordering::Relaxed);

        let output = metrics.export_health();
        assert!(output.contains("\"status\":\"ok\""));
        assert!(output.contains("\"clients\":10"));
    }
}
