use core::cmp::min;
use core::time::Duration;
use std::time::Instant;
// Minimal xoshiro256++ RNG for pacing jitter (non-cryptographic)
struct Xoshiro256pp {
    s: [u64; 4],
}

impl Xoshiro256pp {
    fn from_seed(mut seed: [u8; 32]) -> Self {
        // anti-fingerprinting: mix with monotonic time and addr of self (as noise)
        let now = std::time::Instant::now();
        let t = now.elapsed().as_nanos() as u64;
        for i in 0..4 {
            let o = i * 8;
            let v = u64::from_le_bytes([
                seed[o],
                seed[o + 1],
                seed[o + 2],
                seed[o + 3],
                seed[o + 4],
                seed[o + 5],
                seed[o + 6],
                seed[o + 7],
            ]);
            let m = v ^ (t.rotate_left((i * 11) as u32));
            seed[o..o + 8].copy_from_slice(&m.to_le_bytes());
        }
        let mut s = [0u64; 4];
        for (i, elem) in s.iter_mut().enumerate() {
            let o = i * 8;
            *elem = u64::from_le_bytes([
                seed[o],
                seed[o + 1],
                seed[o + 2],
                seed[o + 3],
                seed[o + 4],
                seed[o + 5],
                seed[o + 6],
                seed[o + 7],
            ]);
            if *elem == 0 {
                *elem = 0x9e3779b97f4a7c15u64 ^ (t.wrapping_add(i as u64));
            }
        }
        Self { s }
    }
    #[inline(always)]
    fn rotl(x: u64, k: u32) -> u64 {
        x.rotate_left(k)
    }
    #[inline(always)]
    fn next_u64(&mut self) -> u64 {
        let result = Self::rotl(self.s[0].wrapping_add(self.s[3]), 23).wrapping_add(self.s[0]);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = Self::rotl(self.s[3], 45);
        result
    }
    #[inline(always)]
    fn next_f64(&mut self) -> f64 {
        // map 53 random bits into [0,1)
        const DEN: f64 = (1u64 << 53) as f64;
        ((self.next_u64() >> 11) as f64) / DEN
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Bbr3, // Primary algorithm with all optimizations
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bbr3State {
    Startup,
    Drain,
    ProbeBw,
    ProbeRtt,
}

pub struct Bbr3 {
    state: Bbr3State,
    pacing_rate: u64,
    pacing_gain: f64,
    cwnd_gain: f64,
    btlbw: u64, // bottleneck bandwidth
    min_rtt: Duration,
    // Stealth integration
    stealth_mode: bool,
    browser_profile: BrowserProfile,
    flow_shaper_active: bool,
    timing_jitter_us: u32,
    // FEC integration
    fec_callback: Option<std::sync::Arc<dyn Fn(u64, usize) + Send + Sync>>, // on_packet_sent
    loss_callback: Option<std::sync::Arc<dyn Fn(u64, usize) + Send + Sync>>, // on_packet_lost
    probe_rtt_done_stamp: Option<Instant>,
    probe_rtt_round_done: bool,
    packet_conservation: bool,
    prior_cwnd: usize,
    full_bw_reached: bool,
    full_bw_count: u32,
    // Hardware acceleration
    batch_size: usize,
    numa_node: usize,
    cycle_index: usize,
    cycle_stamp: Instant,
    ack_epoch_acked: usize,
    extra_acked: usize,
    epoch_start: bool,
    idle_restart: bool,
    probe_rtt_min_us: u64,
    probe_rtt_min_stamp: Instant,
    delivered: u64,
    delivered_time: Instant,
    app_limited: u64,
    round_count: u64,
    round_start: bool,
    next_round_delivered: u64,
    rng: Xoshiro256pp,
}

#[derive(Debug, Clone, Copy)]
pub enum BrowserProfile {
    Chrome,
    Firefox,
    Safari,
    Edge,
}

impl Bbr3 {
    pub fn new(now: Instant) -> Self {
        // seed RNG from OS entropy
        let mut seed = [0u8; 32];
        let _ = getrandom::getrandom(&mut seed); // best-effort; if it fails seed remains zeros and is mixed
        Self {
            state: Bbr3State::Startup,
            pacing_rate: 0,
            pacing_gain: 2.77, // high gain for startup
            cwnd_gain: 2.0,
            btlbw: 0,
            min_rtt: Duration::from_millis(100),
            // Stealth defaults
            stealth_mode: false,
            browser_profile: BrowserProfile::Chrome,
            flow_shaper_active: false,
            timing_jitter_us: 0,
            // FEC defaults
            fec_callback: None,
            loss_callback: None,
            probe_rtt_done_stamp: None,
            probe_rtt_round_done: false,
            packet_conservation: false,
            prior_cwnd: 0,
            full_bw_reached: false,
            full_bw_count: 0,
            batch_size: 16, // Default batch for SIMD
            numa_node: 0,
            cycle_index: 0,
            cycle_stamp: now,
            ack_epoch_acked: 0,
            extra_acked: 0,
            epoch_start: false,
            idle_restart: false,
            probe_rtt_min_us: 200_000, // 200ms
            probe_rtt_min_stamp: now,
            delivered: 0,
            delivered_time: now,
            app_limited: 0,
            round_count: 0,
            round_start: false,
            next_round_delivered: 0,
            rng: Xoshiro256pp::from_seed(seed),
        }
    }

    // Browser-specific pacing gains
    const CHROME_GAINS: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];
    const FIREFOX_GAINS: [f64; 8] = [1.20, 0.80, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];
    const SAFARI_GAINS: [f64; 8] = [1.15, 0.85, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];

    fn get_probe_gains(&self) -> &[f64; 8] {
        match self.browser_profile {
            BrowserProfile::Chrome | BrowserProfile::Edge => &Self::CHROME_GAINS,
            BrowserProfile::Firefox => &Self::FIREFOX_GAINS,
            BrowserProfile::Safari => &Self::SAFARI_GAINS,
        }
    }
    const MIN_RTT_WIN: Duration = Duration::from_secs(10);
    const PROBE_RTT_DURATION: Duration = Duration::from_millis(200);
    const STARTUP_GROWTH_TARGET: f64 = 1.25;
    const BW_PROBE_UP_ROUNDS: u64 = 3;

    pub fn set_stealth_mode(&mut self, enabled: bool, profile: BrowserProfile) {
        self.stealth_mode = enabled;
        self.browser_profile = profile;
        if enabled {
            // Adjust pacing for stealth
            self.timing_jitter_us = match profile {
                BrowserProfile::Chrome => 750,
                BrowserProfile::Firefox => 1000,
                BrowserProfile::Safari => 500,
                BrowserProfile::Edge => 750,
            };
        } else {
            self.timing_jitter_us = 0;
        }
    }

    pub fn set_fec_callbacks<F1, F2>(&mut self, on_sent: F1, on_lost: F2)
    where
        F1: Fn(u64, usize) + Send + Sync + 'static,
        F2: Fn(u64, usize) + Send + Sync + 'static,
    {
        self.fec_callback = Some(std::sync::Arc::new(on_sent));
        self.loss_callback = Some(std::sync::Arc::new(on_lost));
    }
}

pub struct Recovery {
    pub cwnd: usize,
    pub ssthresh: usize,
    pub bytes_in_flight: usize,
    pub rtt: Duration,
    pub pto_count: u32,
    pub loss_time: Option<Instant>,
    pub hystart: bool,
    pub pacing: bool,
    mss: usize,
    loss_acked: f32,
    loss_lost: f32,
    loss_alpha: f32,
    // BBR3 is the only algorithm now
    bbr3: Bbr3,
    // Memory pool for zero-copy
    mem_pool: std::sync::Arc<crate::optimize::MemoryPool>,
}

impl Recovery {
    pub fn new(initial_cwnd: usize, mss: usize) -> Self {
        Self {
            cwnd: initial_cwnd,
            ssthresh: usize::MAX / 2,
            bytes_in_flight: 0,
            rtt: Duration::from_millis(100),
            pto_count: 0,
            loss_time: None,
            hystart: true,
            pacing: true,
            mss: mss.max(1),
            loss_acked: 0.0,
            loss_lost: 0.0,
            loss_alpha: 0.1,
            bbr3: Bbr3::new(Instant::now()),
            mem_pool: crate::optimize::global_pool(),
        }
    }

    pub fn with_memory_pool(
        initial_cwnd: usize,
        mss: usize,
        pool: std::sync::Arc<crate::optimize::MemoryPool>,
    ) -> Self {
        let mut s = Self::new(initial_cwnd, mss);
        s.mem_pool = pool;
        s
    }

    pub fn set_stealth_mode(&mut self, enabled: bool, profile: BrowserProfile) {
        self.bbr3.set_stealth_mode(enabled, profile);
    }

    pub fn set_fec_callbacks<F1, F2>(&mut self, on_sent: F1, on_lost: F2)
    where
        F1: Fn(u64, usize) + Send + Sync + 'static,
        F2: Fn(u64, usize) + Send + Sync + 'static,
    {
        self.bbr3.set_fec_callbacks(on_sent, on_lost);
    }

    fn on_ack_bbr3(&mut self, acked_bytes: usize, now: Instant) {
        let bbr = &mut self.bbr3;
        // Update delivery rate
        bbr.delivered += acked_bytes as u64;
        bbr.delivered_time = now;

        // Track ack epoch for proper BBR accounting
        bbr.ack_epoch_acked += acked_bytes;
        // Capture epoch start if a new round began (set by on_packet_sent)
        if bbr.round_start {
            bbr.epoch_start = true;
        }
        let delivery_rate = if now > bbr.delivered_time {
            let elapsed = now.duration_since(bbr.delivered_time).as_secs_f64();
            if elapsed > 0.0 {
                (bbr.delivered as f64 / elapsed) as u64
            } else {
                bbr.btlbw
            }
        } else {
            bbr.btlbw
        };

        // Update bottleneck bandwidth estimate
        if delivery_rate > bbr.btlbw {
            bbr.btlbw = delivery_rate;
            bbr.full_bw_count = 0;
        } else {
            bbr.full_bw_count += 1;
            if bbr.full_bw_count >= Bbr3::BW_PROBE_UP_ROUNDS as u32 {
                bbr.full_bw_reached = true;
            }
        }

        // Growth tracking in STARTUP against target
        if matches!(bbr.state, Bbr3State::Startup) {
            let old = bbr.btlbw.max(1);
            if (delivery_rate as f64) >= (old as f64) * Bbr3::STARTUP_GROWTH_TARGET {
                bbr.round_count = 0;
            }
        }

        // State machine
        match bbr.state {
            Bbr3State::Startup => {
                if bbr.full_bw_reached {
                    bbr.state = Bbr3State::Drain;
                    bbr.pacing_gain = 0.35; // drain queue
                    bbr.cwnd_gain = 2.0;
                    // Packet conservation during drain
                    bbr.packet_conservation = true;
                }
            }
            Bbr3State::Drain => {
                if self.bytes_in_flight <= (bbr.btlbw as f64 * bbr.min_rtt.as_secs_f64()) as usize {
                    bbr.state = Bbr3State::ProbeBw;
                    bbr.cycle_index = 0;
                    bbr.cycle_stamp = now;
                    bbr.pacing_gain = bbr.get_probe_gains()[0];
                    bbr.cwnd_gain = 2.0;
                    bbr.packet_conservation = false;
                }
            }
            Bbr3State::ProbeBw => {
                // Cycle through gain phases
                if now.duration_since(bbr.cycle_stamp) > bbr.min_rtt {
                    let next_index = (bbr.cycle_index + 1) % 8;
                    bbr.cycle_index = next_index;
                    bbr.pacing_gain = bbr.get_probe_gains()[next_index];
                    bbr.cycle_stamp = now;
                }

                // Check if should probe RTT
                if now.duration_since(bbr.probe_rtt_min_stamp)
                    > std::cmp::max(Bbr3::MIN_RTT_WIN, Duration::from_micros(bbr.probe_rtt_min_us))
                {
                    bbr.state = Bbr3State::ProbeRtt;
                    bbr.prior_cwnd = self.cwnd;
                    bbr.probe_rtt_done_stamp = Some(now + Bbr3::PROBE_RTT_DURATION);
                }
            }
            Bbr3State::ProbeRtt => {
                self.cwnd = self.mss * 4; // minimal cwnd
                if let Some(done_stamp) = bbr.probe_rtt_done_stamp {
                    if now >= done_stamp {
                        bbr.state = Bbr3State::ProbeBw;
                        self.cwnd = bbr.prior_cwnd;
                        bbr.probe_rtt_min_stamp = now;
                        bbr.probe_rtt_round_done = true;
                    }
                }
            }
        }

        // Apply flow shaper if requested (slight pacing dampening)
        if bbr.flow_shaper_active && bbr.pacing_gain > 0.1 {
            bbr.pacing_gain *= 0.98;
        }

        // Update cwnd based on gain, include extra_acked burst adaptation
        // Compute extra_acked as bytes ACKed above current cwnd in this epoch
        bbr.extra_acked = bbr.ack_epoch_acked.saturating_sub(self.cwnd);
        let burst_boost = ((bbr.extra_acked / self.mss).min(4)) * self.mss; // cap boost
        let mut target_cwnd =
            (bbr.cwnd_gain * bbr.btlbw as f64 * bbr.min_rtt.as_secs_f64()) as usize + burst_boost;
        if bbr.epoch_start {
            // One-shot gentle increase at epoch start, then clear flag
            target_cwnd = target_cwnd.saturating_add(self.mss);
            bbr.epoch_start = false;
        }
        self.cwnd = std::cmp::max(target_cwnd, self.mss * 4);

        // Update pacing rate with stealth jitter
        // Add tiny NUMA-based bias to distribute pacing jitter sources
        let numa_bias = 1.0 + ((bbr.numa_node as f64 % 4.0) * 0.0025);
        let base_rate = (bbr.pacing_gain * bbr.btlbw as f64 * numa_bias) as u64;
        // Detect idle restart and ensure sane pacing
        if self.bytes_in_flight == 0 {
            bbr.idle_restart = true;
        } else if bbr.idle_restart {
            // Reset to neutral pacing on first ACK after idle
            bbr.pacing_gain = bbr.pacing_gain.max(1.0);
            bbr.idle_restart = false;
        }
        if bbr.stealth_mode && bbr.timing_jitter_us > 0 {
            // Add browser-specific jitter via xoshiro256++ (stable, non-crypto)
            let jitter = (bbr.timing_jitter_us as f64 / 1_000_000.0) * base_rate as f64;
            bbr.pacing_rate = (base_rate as f64 + jitter * (bbr.rng.next_f64() - 0.5)) as u64;
        } else {
            bbr.pacing_rate = base_rate;
        }
    }

    pub fn get_pacing_rate(&self) -> Option<u64> {
        if self.bbr3.pacing_rate > 0 {
            Some(self.bbr3.pacing_rate)
        } else {
            None
        }
    }

    /// Smoothed loss rate based on ACK/loss updates.
    #[inline(always)]
    pub fn get_loss_rate(&self) -> f32 {
        let total = self.loss_acked + self.loss_lost;
        if total <= f32::EPSILON {
            0.0
        } else {
            (self.loss_lost / total).clamp(0.0, 1.0)
        }
    }

    pub fn get_batch_size(&self) -> usize {
        self.bbr3.batch_size
    }

    pub fn set_batch_size(&mut self, size: usize) {
        self.bbr3.batch_size = size.clamp(1, 64); // Clamp to reasonable range
    }

    #[inline(always)]
    pub fn on_packet_sent(&mut self, pkt_num: u64, sent_bytes: usize, now: Instant) {
        self.bytes_in_flight += sent_bytes;

        // Track delivery info for BBR
        self.bbr3.delivered += sent_bytes as u64;
        self.bbr3.delivered_time = now;

        // Check if we're starting a new round
        if self.bbr3.delivered >= self.bbr3.next_round_delivered {
            self.bbr3.round_count += 1;
            self.bbr3.round_start = true;
            self.bbr3.next_round_delivered = self.bbr3.delivered + self.cwnd as u64;
        } else {
            self.bbr3.round_start = false;
        }

        // Update app-limited state
        if self.bytes_in_flight < self.cwnd / 2 {
            self.bbr3.app_limited = self.bbr3.delivered;
        }

        // FEC callback
        if let Some(ref cb) = self.bbr3.fec_callback {
            cb(pkt_num, sent_bytes);
        }
    }

    pub fn on_ack(&mut self, acked_bytes: usize, now: Instant) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(acked_bytes);
        // BBR3 is always active
        self.on_ack_bbr3(acked_bytes, now);
        let decay = 1.0 - self.loss_alpha;
        self.loss_acked = self.loss_acked * decay + acked_bytes as f32;
        self.loss_lost *= decay;
    }

    pub fn on_loss(&mut self, lost_bytes: usize, now: Instant) {
        self.on_loss_packet(0, lost_bytes, now);
    }

    pub fn on_loss_packet(&mut self, packet_num: u64, lost_bytes: usize, now: Instant) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);

        // FEC loss callback if configured
        if let Some(ref cb) = self.bbr3.loss_callback {
            cb(packet_num, lost_bytes);
        }

        let decay = 1.0 - self.loss_alpha;
        self.loss_acked *= decay;
        self.loss_lost = self.loss_lost * decay + lost_bytes as f32;

        self.loss_time = Some(now);
        self.pto_count = self.pto_count.saturating_add(1);
    }

    pub fn update_rtt(&mut self, rtt: Duration) {
        self.rtt = rtt;
        // Update BBR3 min_rtt
        if rtt < self.bbr3.min_rtt {
            self.bbr3.min_rtt = rtt;
            self.bbr3.probe_rtt_min_stamp = Instant::now();
        }
    }

    pub fn max_release_into_future(&self) -> usize {
        self.cwnd.saturating_sub(self.bytes_in_flight)
    }

    pub fn pto_deadline(&self, now: Instant) -> Instant {
        let base = Duration::from_millis(200);
        let pto = self.rtt.saturating_mul(2) + base;
        let backoff = 1u32 << self.pto_count.min(8);
        now + pto * backoff
    }

    pub fn send_quantum(&self) -> usize {
        min(self.cwnd, 3 * self.mss)
    }

    pub fn can_send(&self, sz: usize) -> bool {
        self.bytes_in_flight.saturating_add(sz) <= self.cwnd
    }
}

#[cfg(test)]
mod tests {
    use super::Recovery;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    #[test]
    fn test_fec_callbacks_receive_live_packet_metadata() {
        let mut recovery = Recovery::new(12_000, 1200);
        let sent_pkt = Arc::new(AtomicU64::new(0));
        let sent_bytes = Arc::new(AtomicUsize::new(0));
        let lost_pkt = Arc::new(AtomicU64::new(u64::MAX));
        let lost_bytes = Arc::new(AtomicUsize::new(0));

        let sent_pkt_cb = Arc::clone(&sent_pkt);
        let sent_bytes_cb = Arc::clone(&sent_bytes);
        let lost_pkt_cb = Arc::clone(&lost_pkt);
        let lost_bytes_cb = Arc::clone(&lost_bytes);

        recovery.set_fec_callbacks(
            move |pn, bytes| {
                sent_pkt_cb.store(pn, Ordering::Relaxed);
                sent_bytes_cb.store(bytes, Ordering::Relaxed);
            },
            move |pn, bytes| {
                lost_pkt_cb.store(pn, Ordering::Relaxed);
                lost_bytes_cb.store(bytes, Ordering::Relaxed);
            },
        );

        let now = Instant::now();
        recovery.on_packet_sent(42, 1200, now);
        recovery.on_loss_packet(42, 1200, now);
        assert_eq!(sent_pkt.load(Ordering::Relaxed), 42);
        assert_eq!(sent_bytes.load(Ordering::Relaxed), 1200);
        assert_eq!(lost_pkt.load(Ordering::Relaxed), 42);
        assert_eq!(lost_bytes.load(Ordering::Relaxed), 1200);

        // Legacy loss API should continue to route through packet-based callback with packet_num=0.
        recovery.on_loss(777, now);
        assert_eq!(lost_pkt.load(Ordering::Relaxed), 0);
        assert_eq!(lost_bytes.load(Ordering::Relaxed), 777);
    }
}
