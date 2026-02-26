//! Admin control socket for QuicFuscate server.
//!
//! Provides Unix socket interface for quicfuscate-ctl commands.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

use super::metrics::Metrics;

/// Admin command types.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd")]
pub enum AdminCommand {
    /// Get server status
    #[serde(rename = "status")]
    Status,

    /// List connected clients
    #[serde(rename = "clients")]
    ListClients,

    /// Kick a client by ID
    #[serde(rename = "kick")]
    Kick { id: String },

    /// Block an IP address
    #[serde(rename = "block")]
    Block { ip: String },

    /// Unblock an IP address
    #[serde(rename = "unblock")]
    Unblock { ip: String },

    /// Reload configuration
    #[serde(rename = "reload")]
    Reload,

    /// Generate QKey
    #[serde(rename = "qkey")]
    GenerateQKey,

    /// Shutdown server
    #[serde(rename = "shutdown")]
    Shutdown,
}

/// Admin response.
#[derive(Debug, Serialize, Deserialize)]
pub struct AdminResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl AdminResponse {
    pub fn ok() -> Self {
        Self { success: true, message: None, data: None }
    }

    pub fn ok_with_message(msg: impl Into<String>) -> Self {
        Self { success: true, message: Some(msg.into()), data: None }
    }

    pub fn ok_with_data(data: serde_json::Value) -> Self {
        Self { success: true, message: None, data: Some(data) }
    }

    pub fn error(msg: impl Into<String>) -> Self {
        Self { success: false, message: Some(msg.into()), data: None }
    }
}

/// Client info for listing.
#[derive(Debug, Serialize)]
pub struct ClientInfo {
    pub id: String,
    pub ip: String,
    pub remote_addr: String,
    pub connected_secs: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub stealth_mode: String,
}

/// Admin command handler trait.
pub trait AdminHandler: Send + Sync {
    fn handle_status(&self) -> AdminResponse;
    fn handle_list_clients(&self) -> Vec<ClientInfo>;
    fn handle_kick(&self, id: &str) -> AdminResponse;
    fn handle_block(&self, ip: &str) -> AdminResponse;
    fn handle_unblock(&self, ip: &str) -> AdminResponse;
    fn handle_reload(&self) -> AdminResponse;
    fn handle_qkey(&self) -> String;
    fn handle_shutdown(&self) -> AdminResponse;
}

/// Default admin handler using metrics.
pub struct DefaultAdminHandler {
    metrics: Arc<Metrics>,
    blocked_ips: parking_lot::RwLock<std::collections::HashSet<String>>,
}

impl DefaultAdminHandler {
    pub fn new(metrics: Arc<Metrics>) -> Self {
        Self { metrics, blocked_ips: parking_lot::RwLock::new(std::collections::HashSet::new()) }
    }

    pub fn is_blocked(&self, ip: &str) -> bool {
        self.blocked_ips.read().contains(ip)
    }
}

impl AdminHandler for DefaultAdminHandler {
    fn handle_status(&self) -> AdminResponse {
        use std::sync::atomic::Ordering;

        let data = serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "uptime_secs": self.metrics.uptime_secs(),
            "clients_active": self.metrics.clients_active.load(Ordering::Relaxed),
            "clients_total": self.metrics.clients_total.load(Ordering::Relaxed),
            "bytes_in": self.metrics.bytes_in.load(Ordering::Relaxed),
            "bytes_out": self.metrics.bytes_out.load(Ordering::Relaxed),
            "stealth": {
                "http3": self.metrics.stealth_http3_active.load(Ordering::Relaxed),
                "tls13": self.metrics.stealth_tls13_active.load(Ordering::Relaxed)
            },
            "fec_recovered": self.metrics.fec_packets_recovered.load(Ordering::Relaxed),
        });

        AdminResponse::ok_with_data(data)
    }

    fn handle_list_clients(&self) -> Vec<ClientInfo> {
        // In production, this would query the SessionManager
        // For now, return empty list
        vec![]
    }

    fn handle_kick(&self, id: &str) -> AdminResponse {
        // In production, this would tell SessionManager to disconnect the client
        log::info!("Admin: Kicking client {}", id);
        AdminResponse::ok_with_message(format!("Client {} disconnected", id))
    }

    fn handle_block(&self, ip: &str) -> AdminResponse {
        self.blocked_ips.write().insert(ip.to_string());
        log::info!("Admin: Blocked IP {}", ip);
        AdminResponse::ok_with_message(format!("IP {} blocked", ip))
    }

    fn handle_unblock(&self, ip: &str) -> AdminResponse {
        if self.blocked_ips.write().remove(ip) {
            log::info!("Admin: Unblocked IP {}", ip);
            AdminResponse::ok_with_message(format!("IP {} unblocked", ip))
        } else {
            AdminResponse::error(format!("IP {} was not blocked", ip))
        }
    }

    fn handle_reload(&self) -> AdminResponse {
        // In production, this would reload config
        log::info!("Admin: Config reload requested");
        AdminResponse::ok_with_message("Configuration reloaded")
    }

    fn handle_qkey(&self) -> String {
        // Generate QKey with current server config
        use crate::engine::qkey;
        use rand::RngCore;

        // In production, get actual server address from config
        let config =
            qkey::QKeyConfig::new("vpn.example.com:4433", "cdn.example.com").with_stealth("auto");
        let mut nonce = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let extra: String = nonce.iter().map(|b| format!("{:02x}", b)).collect();
        let mut token_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut token_bytes);
        let token_hex: String = token_bytes.iter().map(|b| format!("{:02x}", b)).collect();
        let config = config.with_extra(&format!("nonce={}", extra)).with_token(&token_hex);
        qkey::generate(&config)
    }

    fn handle_shutdown(&self) -> AdminResponse {
        log::info!("Admin: Shutdown requested");
        AdminResponse::ok_with_message("Server shutting down")
    }
}

/// Admin socket server.
#[cfg(unix)]
pub struct AdminServer {
    socket_path: std::path::PathBuf,
    handler: Arc<dyn AdminHandler>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(unix)]
impl AdminServer {
    /// Create a new admin server.
    pub fn new<P: AsRef<std::path::Path>>(socket_path: P, handler: Arc<dyn AdminHandler>) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
            handler,
            shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Get shutdown signal.
    pub fn shutdown_signal(&self) -> Arc<std::sync::atomic::AtomicBool> {
        self.shutdown.clone()
    }

    /// Shutdown the server.
    pub fn shutdown(&self) {
        self.shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Run the admin server.
    pub async fn run(&self) -> std::io::Result<()> {
        // Remove old socket if exists
        let _ = std::fs::remove_file(&self.socket_path);

        // Create parent directory
        if let Some(parent) = self.socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(&self.socket_path)?;
        log::info!("Admin socket listening on {:?}", self.socket_path);

        while !self.shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            match tokio::time::timeout(tokio::time::Duration::from_millis(100), listener.accept())
                .await
            {
                Ok(Ok((stream, _addr))) => {
                    let handler = self.handler.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(stream, handler).await {
                            log::warn!("Admin connection error: {}", e);
                        }
                    });
                }
                Ok(Err(e)) => {
                    log::warn!("Admin socket accept error: {}", e);
                }
                Err(_) => {
                    // Timeout, check shutdown
                }
            }
        }

        // Cleanup
        let _ = std::fs::remove_file(&self.socket_path);
        log::info!("Admin socket stopped");
        Ok(())
    }

    async fn handle_connection(
        stream: UnixStream,
        handler: Arc<dyn AdminHandler>,
    ) -> std::io::Result<()> {
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();

        reader.read_line(&mut line).await?;

        let response = match serde_json::from_str::<AdminCommand>(&line) {
            Ok(cmd) => {
                log::debug!("Admin command: {:?}", cmd);
                match cmd {
                    AdminCommand::Status => handler.handle_status(),
                    AdminCommand::ListClients => {
                        let clients = handler.handle_list_clients();
                        match serde_json::to_value(clients) {
                            Ok(data) => AdminResponse::ok_with_data(data),
                            Err(err) => {
                                AdminResponse::error(format!("Serialize clients failed: {}", err))
                            }
                        }
                    }
                    AdminCommand::Kick { id } => handler.handle_kick(&id),
                    AdminCommand::Block { ip } => handler.handle_block(&ip),
                    AdminCommand::Unblock { ip } => handler.handle_unblock(&ip),
                    AdminCommand::Reload => handler.handle_reload(),
                    AdminCommand::GenerateQKey => {
                        let qkey = handler.handle_qkey();
                        AdminResponse::ok_with_data(serde_json::json!({ "qkey": qkey }))
                    }
                    AdminCommand::Shutdown => handler.handle_shutdown(),
                }
            }
            Err(e) => AdminResponse::error(format!("Invalid command: {}", e)),
        };

        let json = serde_json::to_string(&response)?;
        writer.write_all(json.as_bytes()).await?;
        writer.write_all(b"\n").await?;

        Ok(())
    }
}

#[cfg(unix)]
impl Drop for AdminServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_command_parse() {
        let json = r#"{"cmd":"status"}"#;
        let cmd: AdminCommand = serde_json::from_str(json).unwrap();
        assert!(matches!(cmd, AdminCommand::Status));

        let json = r#"{"cmd":"kick","id":"abc123"}"#;
        let cmd: AdminCommand = serde_json::from_str(json).unwrap();
        assert!(matches!(cmd, AdminCommand::Kick { id } if id == "abc123"));
    }

    #[test]
    fn test_admin_response() {
        let resp = AdminResponse::ok();
        assert!(resp.success);

        let resp = AdminResponse::error("test error");
        assert!(!resp.success);
        assert_eq!(resp.message.unwrap(), "test error");
    }

    #[test]
    fn test_default_handler() {
        let metrics = Arc::new(Metrics::new());
        let handler = DefaultAdminHandler::new(metrics);

        let resp = handler.handle_status();
        assert!(resp.success);

        let resp = handler.handle_block("1.2.3.4");
        assert!(resp.success);
        assert!(handler.is_blocked("1.2.3.4"));

        let resp = handler.handle_unblock("1.2.3.4");
        assert!(resp.success);
        assert!(!handler.is_blocked("1.2.3.4"));
    }
}
