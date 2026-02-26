//! Session management for the server.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Unique session identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionId(u64);

impl SessionId {
    fn new() -> Self {
        use std::sync::atomic::AtomicU64;
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::SeqCst))
    }

    /// Returns the underlying numeric session identifier.
    #[inline]
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Session-{}", self.0)
    }
}

/// Client session.
#[derive(Debug)]
pub struct Session {
    id: SessionId,
    remote_addr: SocketAddr,
    client_ip: Ipv4Addr,
    created_at: Instant,
    timeout: Duration,
    stats: Arc<SessionStats>,
}

/// Session statistics (interior mutable via atomics).
#[derive(Debug, Default)]
pub struct SessionStats {
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub packets_sent: AtomicU64,
    pub packets_received: AtomicU64,
}

impl SessionStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
        self.packets_received.fetch_add(1, Ordering::Relaxed);
    }
}

impl Session {
    /// Create a new session.
    pub fn new(remote_addr: SocketAddr, client_ip: Ipv4Addr, timeout_secs: u64) -> Self {
        Self {
            id: SessionId::new(),
            remote_addr,
            client_ip,
            created_at: Instant::now(),
            timeout: Duration::from_secs(timeout_secs),
            stats: Arc::new(SessionStats::new()),
        }
    }

    /// Get session ID.
    pub fn id(&self) -> SessionId {
        self.id
    }

    /// Get remote address.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Get assigned client IP.
    pub fn client_ip(&self) -> Ipv4Addr {
        self.client_ip
    }

    /// Get session uptime.
    pub fn uptime(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Check if session has expired.
    pub fn is_expired(&self) -> bool {
        self.timeout.as_secs() > 0 && self.created_at.elapsed() > self.timeout
    }

    /// Get session stats.
    pub fn stats(&self) -> &Arc<SessionStats> {
        &self.stats
    }
}

/// Session manager.
pub struct SessionManager {
    sessions: HashMap<SessionId, Session>,
    by_client_ip: HashMap<Ipv4Addr, SessionId>,
    by_remote_addr: HashMap<SocketAddr, SessionId>,
    max_sessions: usize,
}

impl SessionManager {
    /// Create a new session manager.
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: HashMap::new(),
            by_client_ip: HashMap::new(),
            by_remote_addr: HashMap::new(),
            max_sessions,
        }
    }

    /// Add a session.
    pub fn add(&mut self, session: Session) -> Result<SessionId, SessionError> {
        if self.sessions.len() >= self.max_sessions {
            return Err(SessionError::MaxSessionsReached);
        }

        let id = session.id;
        let client_ip = session.client_ip;
        let remote_addr = session.remote_addr;

        self.sessions.insert(id, session);
        self.by_client_ip.insert(client_ip, id);
        self.by_remote_addr.insert(remote_addr, id);

        // Record metrics
        crate::instrumentation::global().server.session_created();
        crate::instrumentation::global().server.client_connected();

        Ok(id)
    }

    /// Remove a session.
    pub fn remove(&mut self, id: SessionId) -> Option<Session> {
        if let Some(session) = self.sessions.remove(&id) {
            self.by_client_ip.remove(&session.client_ip);
            self.by_remote_addr.remove(&session.remote_addr);

            // Record metrics
            crate::instrumentation::global().server.client_disconnected();

            Some(session)
        } else {
            None
        }
    }

    /// Get session by ID.
    pub fn get(&self, id: SessionId) -> Option<&Session> {
        self.sessions.get(&id)
    }

    /// Get session by client IP.
    pub fn get_by_client_ip(&self, ip: Ipv4Addr) -> Option<&Session> {
        self.by_client_ip.get(&ip).and_then(|id| self.sessions.get(id))
    }

    /// Get session by remote address.
    pub fn get_by_remote_addr(&self, addr: SocketAddr) -> Option<&Session> {
        self.by_remote_addr.get(&addr).and_then(|id| self.sessions.get(id))
    }

    /// Get all session IDs.
    pub fn all_session_ids(&self) -> Vec<SessionId> {
        self.sessions.keys().copied().collect()
    }

    /// Get session count.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Remove expired sessions, returning their IDs.
    pub fn cleanup_expired(&mut self) -> Vec<SessionId> {
        let expired: Vec<_> =
            self.sessions.iter().filter(|(_, s)| s.is_expired()).map(|(id, _)| *id).collect();

        for id in &expired {
            self.remove(*id);
        }

        expired
    }
}

/// Session errors.
#[derive(Debug, Clone)]
pub enum SessionError {
    MaxSessionsReached,
    NotFound,
    AlreadyExists,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::MaxSessionsReached => write!(f, "Maximum sessions reached"),
            SessionError::NotFound => write!(f, "Session not found"),
            SessionError::AlreadyExists => write!(f, "Session already exists"),
        }
    }
}

impl std::error::Error for SessionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session =
            Session::new("127.0.0.1:12345".parse().unwrap(), Ipv4Addr::new(10, 8, 0, 2), 3600);

        assert_eq!(session.client_ip(), Ipv4Addr::new(10, 8, 0, 2));
        assert!(!session.is_expired());
    }

    #[test]
    fn test_session_manager() {
        let mut mgr = SessionManager::new(100);

        let session =
            Session::new("127.0.0.1:12345".parse().unwrap(), Ipv4Addr::new(10, 8, 0, 2), 3600);
        let id = session.id();

        mgr.add(session).unwrap();
        assert_eq!(mgr.len(), 1);

        let found = mgr.get_by_client_ip(Ipv4Addr::new(10, 8, 0, 2));
        assert!(found.is_some());
        assert_eq!(found.unwrap().id(), id);

        mgr.remove(id);
        assert_eq!(mgr.len(), 0);
    }
}
