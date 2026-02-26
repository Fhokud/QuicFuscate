use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

// "Too Big To Block" Targets
const TARGETS: &[&str] = &[
    "1.1.1.1:443", // Cloudflare
    "8.8.8.8:443", // Google
    "9.9.9.9:443", // Quad9
];

/// Represents a raw response packet that needs to be relayed back to the scanner.
pub struct FallbackResponse {
    pub target: SocketAddr,
    pub data: Vec<u8>,
}

/// Manages reverse proxy sessions for active probes.
/// When a probe is detected (invalid auth), we transparently forward it to a legitimate upstream.
/// The response is captured and sent back to the scanner, providing a cryptographically valid
/// proof that we are a standard QUIC server (e.g., Cloudflare/Google).
pub struct RealityProxy {
    // Channel to send responses back to the main server loop
    tx: mpsc::Sender<FallbackResponse>,
    // Session map: Scanner IP -> Session Handle
    sessions: Mutex<HashMap<SocketAddr, SessionHandle>>,
    // Round-robin target selector
    target_idx: AtomicUsize,
    // Upstream targets (env override supported)
    targets: Vec<String>,
}

struct SessionHandle {
    last_active: Instant,
    sender: mpsc::Sender<Vec<u8>>, // Send packets TO upstream task
}

impl RealityProxy {
    pub fn new(tx: mpsc::Sender<FallbackResponse>) -> Self {
        Self {
            tx,
            sessions: Mutex::new(HashMap::new()),
            target_idx: AtomicUsize::new(0),
            targets: load_targets(),
        }
    }

    /// Selects a rugged upstream target.
    fn select_target(&self) -> String {
        let idx = self.target_idx.fetch_add(1, Ordering::Relaxed);
        self.targets[idx % self.targets.len()].clone()
    }

    #[cfg(feature = "rust-tests")]
    pub fn select_target_for_tests(&self) -> String {
        self.select_target()
    }

    /// Handles a potential probe packet.
    /// If a session exists, forwards it. If not, creates a new session.
    pub fn forward_probe(&self, packet: &[u8], source: SocketAddr) {
        let mut sessions = self.sessions.lock();

        // Prune old sessions (lazy cleanup)
        // In a real high-perf scenario, use a separate cleanup task or timing wheel.
        // For stealth fallback (low volume), simple probabilistic prune is fine.
        if sessions.len() > 100 && rand::random::<u8>() < 10 {
            sessions.retain(|_, v| v.last_active.elapsed() < Duration::from_secs(60));
        }

        if let Some(session) = sessions.get_mut(&source) {
            session.last_active = Instant::now();
            let _ = session.sender.try_send(packet.to_vec());
        } else {
            // New Probe Session
            let target_addr_str = self.select_target();
            log::info!(
                "Reality Proxy: Forwarding new probe from {} to {}",
                source,
                target_addr_str
            );

            let (pkt_tx, mut pkt_rx) = mpsc::channel::<Vec<u8>>(32);
            let response_tx = self.tx.clone();
            let source_copy = source;

            // Spawn lightweight proxy task
            tokio::spawn(async move {
                // Ephemeral local socket for upstream communication
                let upstream = match UdpSocket::bind("0.0.0.0:0").await {
                    Ok(s) => s,
                    Err(e) => {
                        log::error!("RealityProxy: Failed to bind ephemeral socket: {}", e);
                        return;
                    }
                };

                if let Err(e) = upstream.connect(&target_addr_str).await {
                    log::error!(
                        "RealityProxy: Failed to connect to target {}: {}",
                        target_addr_str,
                        e
                    );
                    return;
                }

                // Initial packet forward
                // Note: We swallow the first packet logic here by putting it in the session map loop?
                // Actually, we must process the triggering packet immediately.
                // But since we are in the spawn block, we can't access `packet` easily unless cloned before.
                // Strategy: The session creation pushes to pkt_tx. The Loop reads pkt_rx.

                let mut buf = [0u8; 2048];

                loop {
                    tokio::select! {
                        // Forward FROM Main Server TO Upstream
                        Some(data) = pkt_rx.recv() => {
                            if let Err(e) = upstream.send(&data).await {
                                log::debug!("RealityProxy: Upstream send fail: {}", e);
                                break;
                            }
                        }

                        // Forward FROM Upstream TO Scanner
                        Ok(len) = upstream.recv(&mut buf) => {
                            let resp = FallbackResponse {
                                target: source_copy,
                                data: buf[..len].to_vec(),
                            };
                            if response_tx.send(resp).await.is_err() {
                                break;
                            }
                        }

                        // Timeout inactive sessions
                        _ = tokio::time::sleep(Duration::from_secs(30)) => {
                            break;
                        }
                    }
                }
            });

            // Send the first packet immediately via the new channel
            let _ = pkt_tx.try_send(packet.to_vec());

            sessions.insert(source, SessionHandle { last_active: Instant::now(), sender: pkt_tx });
        }
    }
}

fn load_targets() -> Vec<String> {
    if let Ok(raw) = std::env::var("QUICFUSCATE_REALITY_TARGETS") {
        let parsed: Vec<String> = raw
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        if !parsed.is_empty() {
            return parsed;
        }
    }
    TARGETS.iter().map(|s| s.to_string()).collect()
}
