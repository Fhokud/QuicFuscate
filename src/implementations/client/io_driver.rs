//! Async I/O driver for client packet processing.
//!
//! This module implements the bidirectional packet flow:
//! - TUN -> Stealth -> FEC -> QUIC (outbound)
//! - QUIC -> FEC -> Stealth -> TUN (inbound)

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::core::QuicFuscateConnection;
use crate::engine::EngineError;
use crate::interface::{FastpathMode, TunInterface};

#[inline]
fn profile_prefers_wide_batches(profile: crate::optimize::CpuProfile) -> bool {
    use crate::optimize::CpuProfile;
    matches!(
        profile,
        CpuProfile::X86_P2a
            | CpuProfile::X86_P2b
            | CpuProfile::X86_P3a
            | CpuProfile::X86_P3b
            | CpuProfile::X86_P3c
            | CpuProfile::X86_P3d
            | CpuProfile::X86_P3e
            | CpuProfile::X86_P4a
            | CpuProfile::X86_P4b
            | CpuProfile::ARM_A2
            | CpuProfile::Apple_M
            | CpuProfile::RVV
    )
}

/// I/O driver configuration.
#[derive(Clone, Debug)]
pub struct IoDriverConfig {
    /// UDP socket buffer size
    pub socket_buffer_size: usize,
    /// Channel buffer size for packet queues
    pub channel_buffer_size: usize,
    /// Maximum packets per batch
    pub batch_size: usize,
    /// Poll interval in microseconds for non-blocking reads
    pub poll_interval_us: u64,
}

impl Default for IoDriverConfig {
    fn default() -> Self {
        Self {
            socket_buffer_size: 2 * 1024 * 1024, // 2 MB
            channel_buffer_size: 1024,
            batch_size: 64,
            poll_interval_us: 100,
        }
    }
}

/// I/O driver statistics.
#[derive(Debug, Default)]
pub struct IoDriverStats {
    pub tun_packets_read: AtomicU64,
    pub tun_packets_written: AtomicU64,
    pub udp_packets_sent: AtomicU64,
    pub udp_packets_received: AtomicU64,
    pub errors: AtomicU64,
}

impl IoDriverStats {
    pub fn snapshot(&self) -> IoDriverStatsSnapshot {
        IoDriverStatsSnapshot {
            tun_packets_read: self.tun_packets_read.load(Ordering::Relaxed),
            tun_packets_written: self.tun_packets_written.load(Ordering::Relaxed),
            udp_packets_sent: self.udp_packets_sent.load(Ordering::Relaxed),
            udp_packets_received: self.udp_packets_received.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct IoDriverStatsSnapshot {
    pub tun_packets_read: u64,
    pub tun_packets_written: u64,
    pub udp_packets_sent: u64,
    pub udp_packets_received: u64,
    pub errors: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(target_os = "linux")]
enum OutboundDispatch {
    SendmmsgBatch,
    UringPerPacket,
    SocketPerPacket,
}

#[inline]
#[cfg(target_os = "linux")]
fn resolve_outbound_dispatch(mode: FastpathMode, _queued: usize) -> OutboundDispatch {
    if !mode.allows_uring() && _queued > 1 {
        return OutboundDispatch::SendmmsgBatch;
    }
    if mode.allows_uring() {
        OutboundDispatch::UringPerPacket
    } else {
        OutboundDispatch::SocketPerPacket
    }
}

#[cfg(target_os = "linux")]
trait IoHotpathAdapter: Send + Sync {
    fn sendmmsg_batch(&self, socket_fd: i32, payloads: &[&[u8]]) -> Result<usize, String>;
    fn try_send_connected(&self, socket_fd: i32, payload: &[u8]) -> Result<Option<usize>, String>;
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct SystemIoHotpathAdapter;

#[cfg(target_os = "linux")]
impl IoHotpathAdapter for SystemIoHotpathAdapter {
    fn sendmmsg_batch(&self, socket_fd: i32, payloads: &[&[u8]]) -> Result<usize, String> {
        crate::optimize::zc_batch::sendmmsg(socket_fd, payloads)
    }

    fn try_send_connected(&self, socket_fd: i32, payload: &[u8]) -> Result<Option<usize>, String> {
        crate::transport::uring::try_send_connected(socket_fd, payload)
    }
}

#[cfg(target_os = "linux")]
fn try_sendmmsg_batch(
    adapter: &dyn IoHotpathAdapter,
    socket_fd: i32,
    dispatch: OutboundDispatch,
    payloads: &[&[u8]],
) -> Result<usize, String> {
    if !matches!(dispatch, OutboundDispatch::SendmmsgBatch) {
        return Ok(0);
    }
    Ok(adapter.sendmmsg_batch(socket_fd, payloads)?.min(payloads.len()))
}

#[cfg(target_os = "linux")]
fn try_send_uring_packet(
    adapter: &dyn IoHotpathAdapter,
    socket_fd: i32,
    dispatch: OutboundDispatch,
    payload: &[u8],
) -> Result<bool, String> {
    if !matches!(dispatch, OutboundDispatch::UringPerPacket) {
        return Ok(false);
    }
    match adapter.try_send_connected(socket_fd, payload)? {
        Some(n) if n == payload.len() => Ok(true),
        _ => Ok(false),
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HotpathPerfThresholds {
    pub max_copy_bytes_per_packet: u64,
    pub min_sendmmsg_packets_per_call: u64,
    pub max_batch_drain_ratio_ppm: u64,
}

impl Default for HotpathPerfThresholds {
    fn default() -> Self {
        Self {
            max_copy_bytes_per_packet: 65_535,
            min_sendmmsg_packets_per_call: 2,
            max_batch_drain_ratio_ppm: 1_000_000, // <= 1 extra drained packet per first packet
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HotpathPerfCounters {
    pub udp_packets_received: u64,
    pub io_copy_ops: u64,
    pub io_copy_bytes: u64,
    pub batch_drain_packets: u64,
    pub sendmmsg_calls: u64,
    pub sendmmsg_packets: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HotpathBenchmarkScenario {
    pub payload_bytes: usize,
    pub batch_size: usize,
    pub iterations: usize,
}

pub const HOTPATH_BENCHMARK_SET: [HotpathBenchmarkScenario; 3] = [
    HotpathBenchmarkScenario { payload_bytes: 512, batch_size: 32, iterations: 20_000 },
    HotpathBenchmarkScenario { payload_bytes: 1200, batch_size: 64, iterations: 20_000 },
    HotpathBenchmarkScenario { payload_bytes: 1400, batch_size: 128, iterations: 10_000 },
];

pub fn evaluate_hotpath_perf_smoke(
    counters: HotpathPerfCounters,
    thresholds: HotpathPerfThresholds,
) -> Result<(), &'static str> {
    if counters.io_copy_ops > 0
        && (counters.io_copy_bytes / counters.io_copy_ops) > thresholds.max_copy_bytes_per_packet
    {
        return Err("copy bytes per packet exceeds threshold");
    }

    if counters.sendmmsg_calls > 0
        && (counters.sendmmsg_packets / counters.sendmmsg_calls)
            < thresholds.min_sendmmsg_packets_per_call
    {
        return Err("sendmmsg batch utilization below threshold");
    }

    if counters.udp_packets_received > 0 {
        let ratio_ppm =
            counters.batch_drain_packets.saturating_mul(1_000_000) / counters.udp_packets_received;
        if ratio_ppm > thresholds.max_batch_drain_ratio_ppm {
            return Err("batch drain ratio exceeds threshold");
        }
    }

    Ok(())
}

/// Async I/O driver handle.
pub struct IoDriver {
    config: IoDriverConfig,
    shutdown: Arc<AtomicBool>,
    stats: Arc<IoDriverStats>,
    #[cfg(target_os = "linux")]
    fastpath_mode: FastpathMode,
    #[cfg(target_os = "linux")]
    hotpath_adapter: Arc<dyn IoHotpathAdapter>,
    wide_batch_cpu: bool,
}

impl IoDriver {
    #[inline]
    fn normalized_batch_size(&self) -> usize {
        let cap = if self.wide_batch_cpu { 256 } else { 128 };
        self.config.batch_size.clamp(1, cap)
    }

    /// Create a new I/O driver.
    pub fn new(config: IoDriverConfig) -> Self {
        let fastpath_mode = FastpathMode::from_env();
        #[cfg(target_os = "linux")]
        let hotpath_adapter: Arc<dyn IoHotpathAdapter> = Arc::new(SystemIoHotpathAdapter);
        let profile = crate::optimize::FeatureDetector::instance().profile();
        crate::optimize::telemetry::publish_cpu_profile_mask(profile);
        let wide_batch_cpu = profile_prefers_wide_batches(profile);
        if matches!(fastpath_mode, FastpathMode::Xdp) {
            log::info!(
                "QUICFUSCATE_FASTPATH=xdp requested; async client io_driver uses UDP/uring path and will fallback to UDP socket"
            );
        }
        Self {
            config,
            shutdown: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(IoDriverStats::default()),
            #[cfg(target_os = "linux")]
            fastpath_mode,
            #[cfg(target_os = "linux")]
            hotpath_adapter,
            wide_batch_cpu,
        }
    }

    #[cfg(all(target_os = "linux", test))]
    fn with_hotpath_adapter(
        config: IoDriverConfig,
        hotpath_adapter: Arc<dyn IoHotpathAdapter>,
    ) -> Self {
        let mut driver = Self::new(config);
        driver.hotpath_adapter = hotpath_adapter;
        driver
    }

    /// Get shutdown signal.
    pub fn shutdown_signal(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }

    /// Request shutdown.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Get stats reference.
    pub fn stats(&self) -> &Arc<IoDriverStats> {
        &self.stats
    }

    /// Run the outbound loop (TUN -> QUIC).
    ///
    /// Reads packets from TUN, processes through Stealth/FEC, sends via UDP.
    pub async fn run_outbound(
        &self,
        tun: Arc<parking_lot::Mutex<TunInterface>>,
        conn: Arc<parking_lot::Mutex<QuicFuscateConnection>>,
        socket: Arc<UdpSocket>,
    ) -> Result<(), EngineError> {
        let mut send_buf = vec![0u8; 65535];
        let batch_cap = self.normalized_batch_size();
        let mut batch_payloads: Vec<Vec<u8>> =
            (0..batch_cap).map(|_| Vec::with_capacity(2048)).collect();
        #[cfg(target_os = "linux")]
        let mut batch_refs: Vec<&[u8]> = Vec::with_capacity(batch_cap);

        while !self.shutdown.load(Ordering::Relaxed) {
            // Read from TUN - returns (block, len)
            // Note: TUN read is blocking, so in production we'd use async TUN
            let read_result = {
                let tun_guard = tun.lock();
                tun_guard.read_block()
            };
            match read_result {
                Ok((block, len)) if len > 0 => {
                    self.stats.tun_packets_read.fetch_add(1, Ordering::Relaxed);

                    {
                        let mut conn_guard = conn.lock();
                        if let Err(e) = conn_guard.conn.dgram_send(&block[..len]) {
                            log::warn!("Datagram queue error: {:?}", e);
                            self.stats.errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }

                    let mut queued = 0usize;
                    while queued < batch_cap {
                        let written = {
                            let mut conn_guard = conn.lock();
                            match conn_guard.send(&mut send_buf) {
                                Ok(0) => break,
                                Ok(written) => written,
                                Err(e) => {
                                    log::debug!("Connection send done: {:?}", e);
                                    break;
                                }
                            }
                        };
                        let slot = &mut batch_payloads[queued];
                        slot.clear();
                        slot.extend_from_slice(&send_buf[..written]);
                        crate::optimize::telemetry::IO_DRIVER_COPY_OPS
                            .fetch_add(1, Ordering::Relaxed);
                        crate::optimize::telemetry::IO_DRIVER_COPY_BYTES
                            .fetch_add(written as u64, Ordering::Relaxed);
                        queued += 1;
                    }

                    if queued == 0 {
                        continue;
                    }

                    #[cfg(target_os = "linux")]
                    let dispatch = resolve_outbound_dispatch(self.fastpath_mode, queued);
                    #[cfg(target_os = "linux")]
                    let mut already_sent = 0usize;
                    #[cfg(not(target_os = "linux"))]
                    let already_sent = 0usize;
                    #[cfg(target_os = "linux")]
                    {
                        use std::os::fd::AsRawFd;
                        let socket_fd = socket.as_raw_fd();
                        if matches!(dispatch, OutboundDispatch::SendmmsgBatch) {
                            batch_refs.clear();
                            for payload in batch_payloads.iter().take(queued) {
                                batch_refs.push(payload.as_slice());
                            }
                            match try_sendmmsg_batch(
                                self.hotpath_adapter.as_ref(),
                                socket_fd,
                                dispatch,
                                &batch_refs,
                            ) {
                                Ok(n) => {
                                    already_sent = n.min(queued);
                                    crate::optimize::telemetry::IO_DRIVER_SENDMMSG_CALLS
                                        .fetch_add(1, Ordering::Relaxed);
                                    crate::optimize::telemetry::IO_DRIVER_SENDMMSG_PACKETS
                                        .fetch_add(already_sent as u64, Ordering::Relaxed);
                                }
                                Err(e) => {
                                    log::debug!("sendmmsg batch fallback: {}", e);
                                }
                            }
                        }
                    }

                    for payload in batch_payloads.iter().take(queued).skip(already_sent) {
                        #[cfg(target_os = "linux")]
                        let mut sent_ok = false;
                        #[cfg(not(target_os = "linux"))]
                        let sent_ok = false;
                        #[cfg(target_os = "linux")]
                        {
                            use std::os::fd::AsRawFd;
                            let socket_fd = socket.as_raw_fd();
                            if matches!(dispatch, OutboundDispatch::UringPerPacket) {
                                match try_send_uring_packet(
                                    self.hotpath_adapter.as_ref(),
                                    socket_fd,
                                    dispatch,
                                    payload,
                                ) {
                                    Ok(true) => {
                                        sent_ok = true;
                                    }
                                    Ok(false) => {}
                                    Err(e) => {
                                        log::debug!("io_uring connected send fallback: {}", e);
                                    }
                                }
                            } else if matches!(dispatch, OutboundDispatch::SocketPerPacket) {
                                crate::optimize::telemetry::URING_FALLBACKS.inc();
                            }
                        }

                        if !sent_ok {
                            if let Err(e) = socket.send(payload).await {
                                log::warn!("UDP send error: {}", e);
                                self.stats.errors.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                        }

                        {
                            self.stats.udp_packets_sent.fetch_add(1, Ordering::Relaxed);
                            let global = crate::instrumentation::global();
                            global.transport.record_bytes_out(payload.len() as u64);
                            global.transport.record_packet_out();
                        }
                    }
                    for payload in batch_payloads.iter().take(already_sent) {
                        self.stats.udp_packets_sent.fetch_add(1, Ordering::Relaxed);
                        let global = crate::instrumentation::global();
                        global.transport.record_bytes_out(payload.len() as u64);
                        global.transport.record_packet_out();
                    }
                }
                Ok(_) => {
                    // No TUN data. Still flush pending transport packets (handshake/acks/pto)
                    // so short-lived and no-tun clients can complete connection setup.
                    let idle_write = {
                        let mut conn_guard = conn.lock();
                        conn_guard.send(&mut send_buf).ok()
                    };
                    if let Some(written) = idle_write {
                        if written > 0 {
                            if let Err(e) = socket.send(&send_buf[..written]).await {
                                log::warn!("UDP send error (idle flush): {}", e);
                                self.stats.errors.fetch_add(1, Ordering::Relaxed);
                            } else {
                                self.stats.udp_packets_sent.fetch_add(1, Ordering::Relaxed);
                                let global = crate::instrumentation::global();
                                global.transport.record_bytes_out(written as u64);
                                global.transport.record_packet_out();
                                continue;
                            }
                        }
                    }
                    tokio::time::sleep(tokio::time::Duration::from_micros(
                        self.config.poll_interval_us,
                    ))
                    .await;
                }
                Err(_e) => {
                    // TUN read error (for example WouldBlock in no-tun mode). Keep transport alive.
                    let idle_write = {
                        let mut conn_guard = conn.lock();
                        conn_guard.send(&mut send_buf).ok()
                    };
                    if let Some(written) = idle_write {
                        if written > 0 {
                            if let Err(e) = socket.send(&send_buf[..written]).await {
                                log::warn!("UDP send error (error-path flush): {}", e);
                                self.stats.errors.fetch_add(1, Ordering::Relaxed);
                            } else {
                                self.stats.udp_packets_sent.fetch_add(1, Ordering::Relaxed);
                                let global = crate::instrumentation::global();
                                global.transport.record_bytes_out(written as u64);
                                global.transport.record_packet_out();
                                continue;
                            }
                        }
                    }
                    tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
                }
            }
        }

        Ok(())
    }

    /// Run the inbound loop (QUIC -> TUN).
    ///
    /// Receives packets from UDP, processes through FEC/Stealth, writes to TUN.
    pub async fn run_inbound(
        &self,
        tun: Arc<parking_lot::Mutex<TunInterface>>,
        conn: Arc<parking_lot::Mutex<QuicFuscateConnection>>,
        socket: Arc<UdpSocket>,
    ) -> Result<(), EngineError> {
        let mut recv_buf = vec![0u8; 65535];
        let mut stream_buf = vec![0u8; 65535];
        let batch_cap = self.normalized_batch_size();
        let mut inbound_batch: Vec<Vec<u8>> =
            (0..batch_cap).map(|_| Vec::with_capacity(2048)).collect();

        while !self.shutdown.load(Ordering::Relaxed) {
            // Async receive from UDP. We cannot block forever here, otherwise
            // shutdown would hang while waiting for a packet.
            let recv = tokio::time::timeout(
                tokio::time::Duration::from_millis(200),
                socket.recv(&mut recv_buf),
            )
            .await;
            match recv {
                Err(_) => {
                    continue;
                }
                Ok(Err(e)) => {
                    if e.kind() != std::io::ErrorKind::WouldBlock {
                        log::warn!("UDP recv error: {}", e);
                        self.stats.errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Ok(Ok(len)) if len > 0 => {
                    let mut queued = 0usize;
                    inbound_batch[queued].clear();
                    inbound_batch[queued].extend_from_slice(&recv_buf[..len]);
                    crate::optimize::telemetry::IO_DRIVER_COPY_OPS.fetch_add(1, Ordering::Relaxed);
                    crate::optimize::telemetry::IO_DRIVER_COPY_BYTES
                        .fetch_add(len as u64, Ordering::Relaxed);
                    queued += 1;

                    while queued < batch_cap {
                        match socket.try_recv(&mut recv_buf) {
                            Ok(more) if more > 0 => {
                                inbound_batch[queued].clear();
                                inbound_batch[queued].extend_from_slice(&recv_buf[..more]);
                                crate::optimize::telemetry::IO_DRIVER_COPY_OPS
                                    .fetch_add(1, Ordering::Relaxed);
                                crate::optimize::telemetry::IO_DRIVER_COPY_BYTES
                                    .fetch_add(more as u64, Ordering::Relaxed);
                                queued += 1;
                            }
                            Ok(_) => break,
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(e) => {
                                log::debug!("UDP try_recv batch stop: {}", e);
                                self.stats.errors.fetch_add(1, Ordering::Relaxed);
                                break;
                            }
                        }
                    }
                    if queued > 1 {
                        crate::optimize::telemetry::IO_DRIVER_BATCH_DRAIN_PACKETS
                            .fetch_add((queued - 1) as u64, Ordering::Relaxed);
                    }

                    for payload in inbound_batch.iter().take(queued) {
                        self.stats.udp_packets_received.fetch_add(1, Ordering::Relaxed);

                        // Global metrics
                        let global = crate::instrumentation::global();
                        global.transport.record_bytes_in(payload.len() as u64);
                        global.transport.record_packet_in();

                        {
                            let mut conn_guard = conn.lock();
                            if let Err(e) = conn_guard.recv(payload) {
                                log::debug!("Connection recv error: {:?}", e);
                                self.stats.errors.fetch_add(1, Ordering::Relaxed);
                            }
                        }

                        loop {
                            let read_len = {
                                let mut conn_guard = conn.lock();
                                match conn_guard.conn.dgram_recv(&mut stream_buf) {
                                    Ok(read_len) if read_len > 0 => read_len,
                                    Ok(_) => break,
                                    Err(crate::error::ConnectionError::Done) => break,
                                    Err(e) => {
                                        log::debug!("Datagram recv error: {:?}", e);
                                        break;
                                    }
                                }
                            };

                            let mut tun_guard = tun.lock();
                            if let Err(e) = tun_guard.write_packet(&stream_buf[..read_len]) {
                                log::warn!("TUN write error: {:?}", e);
                                self.stats.errors.fetch_add(1, Ordering::Relaxed);
                            } else {
                                self.stats.tun_packets_written.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
                Ok(Ok(_)) => {
                    // No data
                }
            }
        }

        Ok(())
    }
}

/// Packet channel for inter-task communication.
#[allow(dead_code)]
pub struct PacketChannel {
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
}

impl PacketChannel {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(buffer_size: usize) -> (mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>) {
        mpsc::channel(buffer_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_io_driver_config_default() {
        let config = IoDriverConfig::default();
        assert_eq!(config.batch_size, 64);
        assert_eq!(config.channel_buffer_size, 1024);
    }

    #[test]
    fn test_io_driver_stats() {
        let stats = IoDriverStats::default();
        stats.tun_packets_read.fetch_add(10, Ordering::Relaxed);
        stats.udp_packets_sent.fetch_add(5, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.tun_packets_read, 10);
        assert_eq!(snapshot.udp_packets_sent, 5);
    }

    #[test]
    fn test_io_driver_shutdown() {
        let driver = IoDriver::new(IoDriverConfig::default());
        assert!(!driver.shutdown.load(Ordering::Relaxed));
        driver.shutdown();
        assert!(driver.shutdown.load(Ordering::Relaxed));
    }

    #[test]
    fn test_fastpath_mode_parse() {
        assert_eq!(FastpathMode::parse("off"), FastpathMode::Off);
        assert_eq!(FastpathMode::parse("uring"), FastpathMode::Uring);
        assert_eq!(FastpathMode::parse("xdp"), FastpathMode::Xdp);
        assert_eq!(FastpathMode::parse("auto"), FastpathMode::Auto);
        assert_eq!(FastpathMode::parse("unknown"), FastpathMode::Auto);
    }

    #[test]
    fn test_fastpath_mode_allows_uring() {
        assert!(FastpathMode::Uring.allows_uring());
        assert!(FastpathMode::Auto.allows_uring());
        assert!(!FastpathMode::Off.allows_uring());
        assert!(!FastpathMode::Xdp.allows_uring());
    }

    #[test]
    fn test_normalized_batch_size_bounds() {
        let d0 = IoDriver::new(IoDriverConfig { batch_size: 0, ..IoDriverConfig::default() });
        assert_eq!(d0.normalized_batch_size(), 1);

        let d1 = IoDriver::new(IoDriverConfig { batch_size: 64, ..IoDriverConfig::default() });
        assert_eq!(d1.normalized_batch_size(), 64);

        let d2 = IoDriver::new(IoDriverConfig { batch_size: 1024, ..IoDriverConfig::default() });
        assert!(matches!(d2.normalized_batch_size(), 128 | 256));
    }

    #[test]
    fn test_resolve_outbound_dispatch_paths() {
        #[cfg(target_os = "linux")]
        {
            assert_eq!(
                resolve_outbound_dispatch(FastpathMode::Uring, 8),
                OutboundDispatch::UringPerPacket
            );
            assert_eq!(
                resolve_outbound_dispatch(FastpathMode::Auto, 8),
                OutboundDispatch::UringPerPacket
            );
            assert_eq!(
                resolve_outbound_dispatch(FastpathMode::Off, 1),
                OutboundDispatch::SocketPerPacket
            );
            #[cfg(target_os = "linux")]
            assert_eq!(
                resolve_outbound_dispatch(FastpathMode::Off, 8),
                OutboundDispatch::SendmmsgBatch
            );
        }
    }

    #[cfg(target_os = "linux")]
    struct MockHotpathAdapter {
        sendmmsg_result: std::sync::Mutex<Result<usize, String>>,
        uring_result: std::sync::Mutex<Result<Option<usize>, String>>,
        sendmmsg_calls: AtomicU64,
        uring_calls: AtomicU64,
    }

    #[cfg(target_os = "linux")]
    impl MockHotpathAdapter {
        fn new(
            sendmmsg_result: Result<usize, String>,
            uring_result: Result<Option<usize>, String>,
        ) -> Self {
            Self {
                sendmmsg_result: std::sync::Mutex::new(sendmmsg_result),
                uring_result: std::sync::Mutex::new(uring_result),
                sendmmsg_calls: AtomicU64::new(0),
                uring_calls: AtomicU64::new(0),
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl IoHotpathAdapter for MockHotpathAdapter {
        fn sendmmsg_batch(&self, _socket_fd: i32, _payloads: &[&[u8]]) -> Result<usize, String> {
            self.sendmmsg_calls.fetch_add(1, Ordering::Relaxed);
            self.sendmmsg_result.lock().map_err(|e| e.to_string())?.clone()
        }

        fn try_send_connected(
            &self,
            _socket_fd: i32,
            _payload: &[u8],
        ) -> Result<Option<usize>, String> {
            self.uring_calls.fetch_add(1, Ordering::Relaxed);
            self.uring_result.lock().map_err(|e| e.to_string())?.clone()
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_try_sendmmsg_batch_uses_adapter_and_caps_result() {
        let adapter = MockHotpathAdapter::new(Ok(99), Ok(None));
        let payloads = vec![&b"one"[..], &b"two"[..], &b"three"[..]];

        let sent = try_sendmmsg_batch(&adapter, 0, OutboundDispatch::SendmmsgBatch, &payloads)
            .expect("sendmmsg");

        assert_eq!(sent, payloads.len());
        assert_eq!(adapter.sendmmsg_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_try_sendmmsg_batch_skips_non_sendmmsg_dispatch() {
        let adapter = MockHotpathAdapter::new(Ok(1), Ok(None));
        let payloads = vec![&b"one"[..], &b"two"[..]];

        let sent = try_sendmmsg_batch(&adapter, 0, OutboundDispatch::SocketPerPacket, &payloads)
            .expect("sendmmsg");

        assert_eq!(sent, 0);
        assert_eq!(adapter.sendmmsg_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_try_send_uring_packet_requires_full_datagram_send() {
        let payload = b"payload";
        let adapter_ok = MockHotpathAdapter::new(Ok(0), Ok(Some(payload.len())));
        let sent = try_send_uring_packet(&adapter_ok, 0, OutboundDispatch::UringPerPacket, payload)
            .expect("uring send");
        assert!(sent);

        let adapter_partial = MockHotpathAdapter::new(Ok(0), Ok(Some(payload.len() - 1)));
        let sent =
            try_send_uring_packet(&adapter_partial, 0, OutboundDispatch::UringPerPacket, payload)
                .expect("uring send");
        assert!(!sent);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_with_hotpath_adapter_uses_custom_adapter() {
        let custom_impl = Arc::new(MockHotpathAdapter::new(Ok(2), Ok(None)));
        let custom: Arc<dyn IoHotpathAdapter> = custom_impl.clone();
        let driver = IoDriver::with_hotpath_adapter(IoDriverConfig::default(), custom);
        let payloads = vec![&b"one"[..], &b"two"[..]];
        let sent = try_sendmmsg_batch(
            driver.hotpath_adapter.as_ref(),
            0,
            OutboundDispatch::SendmmsgBatch,
            &payloads,
        )
        .expect("sendmmsg");
        assert_eq!(sent, 2);
        assert_eq!(custom_impl.sendmmsg_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_hotpath_perf_smoke_thresholds_pass() {
        let counters = HotpathPerfCounters {
            udp_packets_received: 100,
            io_copy_ops: 100,
            io_copy_bytes: 120_000,
            batch_drain_packets: 80,
            sendmmsg_calls: 10,
            sendmmsg_packets: 40,
        };
        assert!(evaluate_hotpath_perf_smoke(counters, HotpathPerfThresholds::default()).is_ok());
    }

    #[test]
    fn test_hotpath_perf_smoke_thresholds_reject_bad_sendmmsg_ratio() {
        let counters = HotpathPerfCounters {
            udp_packets_received: 100,
            io_copy_ops: 100,
            io_copy_bytes: 120_000,
            batch_drain_packets: 80,
            sendmmsg_calls: 10,
            sendmmsg_packets: 10,
        };
        let err = evaluate_hotpath_perf_smoke(counters, HotpathPerfThresholds::default())
            .expect_err("expected sendmmsg utilization rejection");
        assert_eq!(err, "sendmmsg batch utilization below threshold");
    }

    #[test]
    fn test_hotpath_benchmark_set_is_ordered_and_nonzero() {
        assert_eq!(HOTPATH_BENCHMARK_SET.len(), 3);
        for scenario in HOTPATH_BENCHMARK_SET {
            assert!(scenario.payload_bytes > 0);
            assert!(scenario.batch_size > 0);
            assert!(scenario.iterations > 0);
        }
        assert!(HOTPATH_BENCHMARK_SET[0].payload_bytes <= HOTPATH_BENCHMARK_SET[1].payload_bytes);
        assert!(HOTPATH_BENCHMARK_SET[1].payload_bytes <= HOTPATH_BENCHMARK_SET[2].payload_bytes);
    }

    #[test]
    fn test_profile_prefers_wide_batches_mapping() {
        assert!(profile_prefers_wide_batches(crate::optimize::CpuProfile::X86_P2a));
        assert!(profile_prefers_wide_batches(crate::optimize::CpuProfile::ARM_A2));
        assert!(!profile_prefers_wide_batches(crate::optimize::CpuProfile::X86_P0a));
        assert!(!profile_prefers_wide_batches(crate::optimize::CpuProfile::Scalar));
    }

    #[test]
    fn test_new_driver_publishes_cpu_profile_mask() {
        crate::optimize::telemetry::CPU_FEATURE_MASK.store(0, Ordering::Relaxed);
        let profile = crate::optimize::FeatureDetector::instance().profile();
        let expected = crate::optimize::telemetry::cpu_profile_mask(profile);
        let _driver = IoDriver::new(IoDriverConfig::default());
        assert_eq!(crate::optimize::telemetry::CPU_FEATURE_MASK.load(Ordering::Relaxed), expected);
    }
}
