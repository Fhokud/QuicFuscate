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

#[cfg(feature = "rate_limiter")]
fn parse_rate_limit_env_u64(key: &str) -> Option<u64> {
    match std::env::var(key) {
        Ok(raw) => match raw.trim().parse::<u64>() {
            Ok(v) => Some(v),
            Err(e) => {
                log::warn!("Invalid {}='{}': {}", key, raw, e);
                None
            }
        },
        Err(_) => None,
    }
}

#[cfg(feature = "rate_limiter")]
pub fn load_rate_limit_config_from_env() -> RateLimitConfig {
    let mut cfg = RateLimitConfig::default();

    if let Some(v) = parse_rate_limit_env_u64("QUICFUSCATE_RATE_LIMIT_PPS") {
        if v == 0 {
            log::warn!("Ignoring QUICFUSCATE_RATE_LIMIT_PPS=0 (must be >= 1)");
        } else {
            cfg.max_pps = v;
        }
    }
    if let Some(v) = parse_rate_limit_env_u64("QUICFUSCATE_RATE_LIMIT_BPS") {
        cfg.max_bps = v;
    }
    if let Some(ms) = parse_rate_limit_env_u64("QUICFUSCATE_RATE_LIMIT_REFILL_MS") {
        if ms == 0 {
            log::warn!("Ignoring QUICFUSCATE_RATE_LIMIT_REFILL_MS=0 (must be >= 1)");
        } else {
            cfg.refill_interval = Duration::from_millis(ms);
        }
    }

    log::info!(
        "Server rate limiter config: max_pps={}, max_bps={}, refill_ms={}",
        cfg.max_pps,
        cfg.max_bps,
        cfg.refill_interval.as_millis()
    );

    cfg
}

/// Token bucket for rate limiting.
struct TokenBucket {
    tokens: u64,
    max_tokens: u64,
    last_refill: Instant,
    last_seen: Instant,
    refill_rate: u64,
    refill_interval: Duration,
}

impl TokenBucket {
    fn new(max_tokens: u64, refill_interval: Duration) -> Self {
        Self {
            tokens: max_tokens,
            max_tokens,
            last_refill: Instant::now(),
            last_seen: Instant::now(),
            refill_rate: max_tokens,
            refill_interval,
        }
    }

    fn consume(&mut self, amount: u64) -> bool {
        let now = Instant::now();
        self.last_seen = now;
        self.refill(now);

        if self.tokens >= amount {
            self.tokens -= amount;
            true
        } else {
            false
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.duration_since(self.last_refill);

        if elapsed >= self.refill_interval {
            let refill_interval_us = self.refill_interval.as_micros();
            let refill_amount = if refill_interval_us > 0 {
                let refill = (elapsed.as_micros() * self.refill_rate as u128) / refill_interval_us;
                // Saturate to u64 range
                if refill > u64::MAX as u128 {
                    u64::MAX
                } else {
                    refill as u64
                }
            } else {
                self.max_tokens
            };

            self.tokens = (self.tokens + refill_amount).min(self.max_tokens);
            self.last_refill = now;
        }
    }

    fn is_idle(&self, now: Instant, max_idle: Duration) -> bool {
        now.duration_since(self.last_seen) >= max_idle
    }
}

/// Rate limiter using token buckets.
pub struct RateLimiter {
    config: RateLimitConfig,
    packet_buckets: parking_lot::Mutex<HashMap<RateLimitKey, TokenBucket>>,
    byte_buckets: parking_lot::Mutex<HashMap<RateLimitKey, TokenBucket>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum RateLimitKey {
    Session(u64),
    Ip(IpAddr),
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
        self.check_packet_key(RateLimitKey::Session(session_id))
    }

    /// Check if a packet is allowed (by source IP).
    pub fn check_packet_ip(&self, ip: IpAddr) -> bool {
        self.check_packet_key(RateLimitKey::Ip(ip))
    }

    fn check_packet_key(&self, key: RateLimitKey) -> bool {
        let mut buckets = self.packet_buckets.lock();
        let bucket = buckets
            .entry(key)
            .or_insert_with(|| TokenBucket::new(self.config.max_pps, self.config.refill_interval));
        let allowed = bucket.consume(1);

        if !allowed {
            crate::instrumentation::global().server.rate_limit_hit();
        }

        allowed
    }

    /// Check if bytes are allowed (by session ID).
    pub fn check_bytes(&self, session_id: u64, bytes: u64) -> bool {
        self.check_bytes_key(RateLimitKey::Session(session_id), bytes)
    }

    /// Check if bytes are allowed (by source IP).
    pub fn check_bytes_ip(&self, ip: IpAddr, bytes: u64) -> bool {
        self.check_bytes_key(RateLimitKey::Ip(ip), bytes)
    }

    fn check_bytes_key(&self, key: RateLimitKey, bytes: u64) -> bool {
        if self.config.max_bps == 0 {
            return true; // Unlimited
        }

        let mut buckets = self.byte_buckets.lock();
        let bucket = buckets
            .entry(key)
            .or_insert_with(|| TokenBucket::new(self.config.max_bps, self.config.refill_interval));
        let allowed = bucket.consume(bytes);
        if !allowed {
            crate::instrumentation::global().server.rate_limit_hit();
        }
        allowed
    }

    /// Remove a session's buckets.
    pub fn remove_session(&self, session_id: u64) {
        self.packet_buckets.lock().remove(&RateLimitKey::Session(session_id));
        self.byte_buckets.lock().remove(&RateLimitKey::Session(session_id));
    }

    /// Remove an IP's buckets.
    pub fn remove_ip(&self, ip: IpAddr) {
        self.packet_buckets.lock().remove(&RateLimitKey::Ip(ip));
        self.byte_buckets.lock().remove(&RateLimitKey::Ip(ip));
    }

    /// Prune idle session buckets to bound memory growth under churn/spoofing.
    pub fn prune_idle(&self, max_idle: Duration) {
        let now = Instant::now();
        self.packet_buckets.lock().retain(|_, bucket| !bucket.is_idle(now, max_idle));
        self.byte_buckets.lock().retain(|_, bucket| !bucket.is_idle(now, max_idle));
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

    #[test]
    fn test_rate_limiter_prune_idle_resets_stale_bucket() {
        let config =
            RateLimitConfig { max_pps: 1, max_bps: 0, refill_interval: Duration::from_secs(1) };
        let limiter = RateLimiter::new(config);

        assert!(limiter.check_packet(7));
        assert!(!limiter.check_packet(7));

        std::thread::sleep(Duration::from_millis(20));
        limiter.prune_idle(Duration::from_millis(5));

        // Bucket was pruned and recreated, so one packet is allowed again.
        assert!(limiter.check_packet(7));
    }

    #[test]
    fn test_rate_limiter_ip_keys_are_isolated() {
        let config =
            RateLimitConfig { max_pps: 1, max_bps: 0, refill_interval: Duration::from_secs(1) };
        let limiter = RateLimiter::new(config);
        let ip1: IpAddr = "1.2.3.4".parse().unwrap();
        let ip2: IpAddr = "5.6.7.8".parse().unwrap();

        assert!(limiter.check_packet_ip(ip1));
        assert!(!limiter.check_packet_ip(ip1));

        assert!(limiter.check_packet_ip(ip2));
        assert!(!limiter.check_packet_ip(ip2));
    }
}
