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

/// Deterministic cleanup interval - sweep stale sessions every 60 seconds.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
/// Force immediate cleanup when session count exceeds this threshold.
const MAX_SESSIONS: usize = 10_000;
/// Session TTL - evict entries inactive for longer than this.
const SESSION_TTL: Duration = Duration::from_secs(300);

/// Represents a raw response packet that needs to be relayed back to the scanner.
pub struct FallbackResponse {
    /// Original scanner address to send the response back to.
    pub target: SocketAddr,
    /// Raw upstream response payload to relay.
    pub data: Vec<u8>,
}

/// Manages reverse proxy sessions for active probes.
/// When a probe is detected (invalid auth), we transparently forward it to a legitimate upstream.
/// The response is captured and sent back to the scanner so the observable path resembles a
/// legitimate upstream service instead of exposing the forked server directly.
pub struct RealityProxy {
    // Channel to send responses back to the main server loop
    tx: mpsc::Sender<FallbackResponse>,
    // Session map: Scanner IP -> Session Handle
    sessions: Mutex<HashMap<SocketAddr, SessionHandle>>,
    // Round-robin target selector
    target_idx: AtomicUsize,
    // Upstream targets (env override supported)
    targets: Vec<String>,
    // Deterministic cleanup tracker
    last_cleanup: Mutex<Instant>,
}

struct SessionHandle {
    last_active: Instant,
    sender: mpsc::Sender<Vec<u8>>,     // Send packets TO upstream task
    task: tokio::task::JoinHandle<()>, // Tracked proxy task handle
}

impl RealityProxy {
    /// Create a new reality proxy with the given response channel.
    pub fn new(tx: mpsc::Sender<FallbackResponse>) -> Self {
        Self {
            tx,
            sessions: Mutex::new(HashMap::new()),
            target_idx: AtomicUsize::new(0),
            targets: load_targets(),
            last_cleanup: Mutex::new(Instant::now()),
        }
    }

    /// Selects a rugged upstream target.
    fn select_target(&self) -> String {
        let idx = self.target_idx.fetch_add(1, Ordering::Relaxed);
        self.targets[idx % self.targets.len()].clone()
    }

    /// Test-only accessor for the target selection logic.
    #[cfg(feature = "rust-tests")]
    pub fn select_target_for_tests(&self) -> String {
        self.select_target()
    }

    /// Handles a potential probe packet.
    /// If a session exists, forwards it. If not, creates a new session.
    pub fn forward_probe(&self, packet: &[u8], source: SocketAddr) {
        let mut sessions = self.sessions.lock();

        // Deterministic session cleanup: time-based interval or capacity pressure.
        {
            let mut last = self.last_cleanup.lock();
            if last.elapsed() > CLEANUP_INTERVAL || sessions.len() > MAX_SESSIONS {
                let before = sessions.len();
                sessions.retain(|_, v| {
                    let keep = v.last_active.elapsed() < SESSION_TTL;
                    if !keep {
                        v.task.abort();
                    }
                    keep
                });
                let evicted = before.saturating_sub(sessions.len());
                if evicted > 0 {
                    log::debug!(
                        "Reality Proxy: evicted {} stale sessions ({} remaining)",
                        evicted,
                        sessions.len()
                    );
                }
                *last = Instant::now();
            }
        }

        if let Some(session) = sessions.get_mut(&source) {
            session.last_active = Instant::now();
            if let Err(e) = session.sender.try_send(packet.to_vec()) {
                log::debug!(
                    "Reality Proxy: failed to enqueue probe packet for existing session {}: {}",
                    source,
                    e
                );
            }
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

            // Spawn lightweight proxy task (JoinHandle tracked in SessionHandle)
            let task = tokio::spawn(async move {
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
            if let Err(e) = pkt_tx.try_send(packet.to_vec()) {
                log::debug!(
                    "Reality Proxy: failed to enqueue first probe packet for session {}: {}",
                    source,
                    e
                );
            }

            sessions.insert(
                source,
                SessionHandle { last_active: Instant::now(), sender: pkt_tx, task },
            );
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proxy() -> (RealityProxy, mpsc::Receiver<FallbackResponse>) {
        let (tx, rx) = mpsc::channel(64);
        (RealityProxy::new(tx), rx)
    }

    #[test]
    fn target_rotation_is_round_robin() {
        let (proxy, _rx) = make_proxy();
        let t0 = proxy.select_target();
        let t1 = proxy.select_target();
        let t2 = proxy.select_target();
        // After 3 targets we wrap around
        let t3 = proxy.select_target();
        assert_eq!(t0, TARGETS[0]);
        assert_eq!(t1, TARGETS[1]);
        assert_eq!(t2, TARGETS[2]);
        assert_eq!(t3, TARGETS[0], "should wrap around");
    }

    #[test]
    fn default_targets_are_populated() {
        let targets = load_targets();
        assert_eq!(targets.len(), 3);
        assert!(targets.contains(&"1.1.1.1:443".to_string()));
        assert!(targets.contains(&"8.8.8.8:443".to_string()));
        assert!(targets.contains(&"9.9.9.9:443".to_string()));
    }

    #[test]
    fn session_creation_on_new_source() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async {
            let (proxy, _rx) = make_proxy();
            let source: SocketAddr = "10.0.0.1:12345".parse().expect("parse addr");
            proxy.forward_probe(b"test-probe", source);
            // Session should exist now
            let sessions = proxy.sessions.lock();
            assert_eq!(sessions.len(), 1);
            assert!(sessions.contains_key(&source));
        });
    }

    #[test]
    fn same_source_reuses_session() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async {
            let (proxy, _rx) = make_proxy();
            let source: SocketAddr = "10.0.0.2:54321".parse().expect("parse addr");
            proxy.forward_probe(b"probe-1", source);
            proxy.forward_probe(b"probe-2", source);
            let sessions = proxy.sessions.lock();
            assert_eq!(sessions.len(), 1, "same source should reuse session");
        });
    }

    #[test]
    fn different_sources_create_separate_sessions() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async {
            let (proxy, _rx) = make_proxy();
            let s1: SocketAddr = "10.0.0.1:1111".parse().expect("addr1");
            let s2: SocketAddr = "10.0.0.2:2222".parse().expect("addr2");
            proxy.forward_probe(b"probe-a", s1);
            proxy.forward_probe(b"probe-b", s2);
            let sessions = proxy.sessions.lock();
            assert_eq!(sessions.len(), 2);
        });
    }

    #[test]
    fn constants_are_reasonable() {
        const { assert!(MAX_SESSIONS >= 1000, "MAX_SESSIONS too low") };
        const { assert!(SESSION_TTL.as_secs() >= 60, "SESSION_TTL too short") };
        const { assert!(CLEANUP_INTERVAL.as_secs() >= 10, "CLEANUP_INTERVAL too short") };
    }
}
