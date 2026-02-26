//! Rate limiting and connection limiting for the server.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Rate limit configuration.
#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    /// Maximum packets per second per client
    pub max_pps: u64,
    /// Maximum bytes per second per client (0 = unlimited)
    pub max_bps: u64,
    /// Bucket refill interval
    pub refill_interval: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_pps: 10_000,
            max_bps: 0, // Unlimited
            refill_interval: Duration::from_secs(1),
        }
    }
}

/// Token bucket for rate limiting.
struct TokenBucket {
    tokens: u64,
    max_tokens: u64,
    last_refill: Instant,
    refill_rate: u64,
    refill_interval: Duration,
}

impl TokenBucket {
    fn new(max_tokens: u64, refill_interval: Duration) -> Self {
        Self {
            tokens: max_tokens,
            max_tokens,
            last_refill: Instant::now(),
            refill_rate: max_tokens,
            refill_interval,
        }
    }

    fn consume(&mut self, amount: u64) -> bool {
        self.refill();

        if self.tokens >= amount {
            self.tokens -= amount;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);

        if elapsed >= self.refill_interval {
            let intervals = elapsed.as_secs_f64() / self.refill_interval.as_secs_f64();
            let refill_amount = (intervals * self.refill_rate as f64) as u64;

            self.tokens = (self.tokens + refill_amount).min(self.max_tokens);
            self.last_refill = now;
        }
    }
}

/// Rate limiter using token buckets.
pub struct RateLimiter {
    config: RateLimitConfig,
    packet_buckets: parking_lot::Mutex<HashMap<u64, TokenBucket>>,
    byte_buckets: parking_lot::Mutex<HashMap<u64, TokenBucket>>,
}

impl RateLimiter {
    /// Create a new rate limiter.
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            packet_buckets: parking_lot::Mutex::new(HashMap::new()),
            byte_buckets: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// Check if a packet is allowed (by session ID).
    pub fn check_packet(&self, session_id: u64) -> bool {
        let mut buckets = self.packet_buckets.lock();
        let bucket = buckets
            .entry(session_id)
            .or_insert_with(|| TokenBucket::new(self.config.max_pps, self.config.refill_interval));
        let allowed = bucket.consume(1);

        if !allowed {
            crate::instrumentation::global().server.rate_limit_hit();
        }

        allowed
    }

    /// Check if bytes are allowed (by session ID).
    pub fn check_bytes(&self, session_id: u64, bytes: u64) -> bool {
        if self.config.max_bps == 0 {
            return true; // Unlimited
        }

        let mut buckets = self.byte_buckets.lock();
        let bucket = buckets
            .entry(session_id)
            .or_insert_with(|| TokenBucket::new(self.config.max_bps, self.config.refill_interval));
        bucket.consume(bytes)
    }

    /// Remove a session's buckets.
    pub fn remove_session(&self, session_id: u64) {
        self.packet_buckets.lock().remove(&session_id);
        self.byte_buckets.lock().remove(&session_id);
    }
}

/// Connection limiter per IP address.
pub struct ConnectionLimiter {
    max_per_ip: usize,
    connections: HashMap<IpAddr, usize>,
}

impl ConnectionLimiter {
    /// Create a new connection limiter.
    pub fn new(max_per_ip: usize) -> Self {
        Self { max_per_ip, connections: HashMap::new() }
    }

    /// Check if a new connection from this IP is allowed.
    pub fn check(&self, ip: IpAddr) -> bool {
        self.connections.get(&ip).map(|&count| count < self.max_per_ip).unwrap_or(true)
    }

    /// Add a connection for this IP.
    pub fn add(&mut self, ip: IpAddr) {
        *self.connections.entry(ip).or_insert(0) += 1;
    }

    /// Remove a connection for this IP.
    pub fn remove(&mut self, ip: IpAddr) {
        if let Some(count) = self.connections.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.connections.remove(&ip);
            }
        }
    }

    /// Get connection count for an IP.
    pub fn count(&self, ip: IpAddr) -> usize {
        self.connections.get(&ip).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter() {
        let config =
            RateLimitConfig { max_pps: 10, max_bps: 0, refill_interval: Duration::from_secs(1) };
        let limiter = RateLimiter::new(config);

        // Should allow first 10 packets
        for _ in 0..10 {
            assert!(limiter.check_packet(1));
        }

        // 11th should fail
        assert!(!limiter.check_packet(1));
    }

    #[test]
    fn test_connection_limiter() {
        let mut limiter = ConnectionLimiter::new(2);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        assert!(limiter.check(ip));
        limiter.add(ip);
        assert!(limiter.check(ip));
        limiter.add(ip);
        assert!(!limiter.check(ip)); // Limit reached

        limiter.remove(ip);
        assert!(limiter.check(ip)); // Can add again
    }
}
