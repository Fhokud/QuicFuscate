use clap::{Parser, Subcommand};
use log::{error, info, warn};
use quicfuscate::app_config::AppConfig;
use quicfuscate::core::QuicFuscateConnection;
use quicfuscate::error::ConnectionError;
#[cfg(feature = "benches")]
use quicfuscate::fec::FecPacket;
use quicfuscate::fec::{AdaptiveFec, FecConfig, FecMode};
#[cfg(unix)]
use quicfuscate::implementations::server::admin::{
    AdminHandler, AdminResponse, AdminServer, ClientInfo,
};
use quicfuscate::implementations::server::admin_http::{
    AdminAuth, AdminHttpHandler, AdminHttpServer,
};
use quicfuscate::implementations::server::metrics::Metrics;
use quicfuscate::optimize::OptimizationManager;
use quicfuscate::optimize::OptimizeConfig;
#[cfg(unix)]
use quicfuscate::optimize::ZeroCopyBuffer;
use quicfuscate::stealth::StealthConfig;
use quicfuscate::stealth::TlsClientHelloSpoofer;
use quicfuscate::stealth::{BrowserProfile, FingerprintProfile, OsProfile};
use quicfuscate::transport::h3::NameValue;
// use quicfuscate::transport::CongestionControlAlgorithm; // imported where needed
use quicfuscate::telemetry;
use std::cell::Cell;
use std::collections::HashMap;
#[cfg(feature = "benches")]
use std::collections::VecDeque;
use std::net::ToSocketAddrs;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};
#[cfg(feature = "benches")]
use std::time::Instant;
use tokio::io::Interest;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration, MissedTickBehavior};

static ADMIN_LOG_BUFFER: OnceLock<
    Arc<quicfuscate::implementations::server::admin_logs::AdminLogBuffer>,
> = OnceLock::new();

const BUILTIN_FRONTING_SNI_ALLOWLIST: &[&str] = &[
    "cdn.cloudflare.com",
    "cloudflare-dns.com",
    "one.one.one.one",
    "warp.plus",
    "workers.dev",
    "cdn.fastly.net",
    "fastly.com",
    "fastlylb.net",
    "fsly.net",
    "akamaized.net",
    "akamai.net",
    "akamaihd.net",
    "akamaitechnologies.com",
    "edgesuite.net",
    "cloudfront.net",
    "amazonaws.com",
    "aws.amazon.com",
    "awsstatic.com",
    "googleapis.com",
    "googleusercontent.com",
    "googlevideo.com",
    "gstatic.com",
    "google.com",
    "azureedge.net",
    "azure.microsoft.com",
    "windows.net",
    "msecnd.net",
    "stackpathdns.com",
    "stackpathcdn.com",
    "bootstrapcdn.com",
    "kxcdn.com",
    "keycdn.com",
    "b-cdn.net",
    "bunnycdn.com",
    "incapdns.net",
    "imperva.com",
];
const DF_SNI_MODE_FIXED: &str = "fixed";
const DF_SNI_MODE_AUTO_ROTATING: &str = "auto_rotating";
const DEFAULT_RUNTIME_SNI_HOST: &str = "cdn.cloudflare.com";
const DEFAULT_RUNTIME_URL: &str = "https://cloudflare-dns.com/";

fn require_qkey_for_new_clients(_registry_has_entries: bool) -> bool {
    true
}

fn is_valid_sni_host(value: &str) -> bool {
    let s = value.trim();
    if s.is_empty() {
        return false;
    }
    if s.chars().any(char::is_whitespace) {
        return false;
    }
    if s.contains(':') {
        return false;
    }
    if s.contains('/') || s.contains('?') || s.contains('#') || s.contains('@') {
        return false;
    }
    true
}

fn normalize_sni_host(value: &str) -> Option<String> {
    let lower = value.trim().to_ascii_lowercase();
    if is_valid_sni_host(&lower) {
        Some(lower)
    } else {
        None
    }
}

fn extract_host_from_endpoint(endpoint: &str) -> Option<String> {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        return normalize_sni_host(host);
    }
    if let Some((host, _port)) = trimmed.rsplit_once(':') {
        if !host.is_empty() {
            return normalize_sni_host(host);
        }
    }
    normalize_sni_host(trimmed)
}

#[derive(Debug, Clone)]
struct QKeyDomainFrontingPolicy {
    qkey_sni: String,
    extra_json: String,
}

fn resolve_qkey_domain_fronting_policy(
    front_domain: &[String],
    listen_addr: &str,
    requested_strategy: Option<&str>,
    requested_domain: Option<&str>,
    nonce_hex: &str,
) -> Result<QKeyDomainFrontingPolicy, String> {
    let allowlist: Vec<String> =
        BUILTIN_FRONTING_SNI_ALLOWLIST.iter().map(|d| (*d).to_string()).collect();
    let default_domain =
        allowlist.first().cloned().ok_or_else(|| "Missing SNI allowlist defaults".to_string())?;
    let mode_raw = requested_strategy.unwrap_or("").trim().to_ascii_lowercase();
    let mode = if mode_raw.is_empty()
        || mode_raw == "auto"
        || mode_raw == "rotating"
        || mode_raw == DF_SNI_MODE_AUTO_ROTATING
    {
        DF_SNI_MODE_AUTO_ROTATING
    } else if mode_raw == DF_SNI_MODE_FIXED {
        DF_SNI_MODE_FIXED
    } else {
        return Err(
            "Invalid Domain Fronting [SNI] strategy. Valid: fixed, auto_rotating".to_string()
        );
    };
    let server_host = extract_host_from_endpoint(listen_addr);

    if mode == DF_SNI_MODE_FIXED {
        let requested = requested_domain
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| "Domain Fronting [SNI] fixed mode requires a domain".to_string())?;
        let domain = normalize_sni_host(requested)
            .ok_or_else(|| "Invalid Domain Fronting [SNI] domain".to_string())?;
        if !allowlist.iter().any(|v| v == &domain) {
            return Err("Domain Fronting [SNI] domain is not allowlisted".to_string());
        }
        let domain_for_json = domain.clone();
        return Ok(QKeyDomainFrontingPolicy {
            qkey_sni: domain,
            extra_json: serde_json::json!({
                "nonce": nonce_hex,
                "df_sni_mode": DF_SNI_MODE_FIXED,
                "df_sni_domain": domain_for_json,
                "server_host": server_host,
            })
            .to_string(),
        });
    }

    let mut pool: Vec<String> = front_domain
        .iter()
        .filter_map(|raw| normalize_sni_host(raw))
        .filter(|raw| allowlist.iter().any(|v| v == raw))
        .collect();
    if pool.is_empty() {
        pool = allowlist;
    }
    let qkey_sni = pool.first().cloned().unwrap_or(default_domain);
    Ok(QKeyDomainFrontingPolicy {
        qkey_sni,
        extra_json: serde_json::json!({
            "nonce": nonce_hex,
            "df_sni_mode": DF_SNI_MODE_AUTO_ROTATING,
            "df_sni_pool": pool,
            "server_host": server_host,
        })
        .to_string(),
    })
}

#[cfg(test)]
mod qkey_auth_tests {
    use super::*;
    use quicfuscate::engine::qkey;
    use quicfuscate::implementations::server::qkey_registry::qkey_id as registry_qkey_id;

    #[test]
    fn require_qkey_for_new_clients_is_strict_by_default() {
        assert!(require_qkey_for_new_clients(false));
        assert!(require_qkey_for_new_clients(true));
    }

    #[test]
    fn engine_qkey_id_matches_registry_qkey_id() {
        let cfg = qkey::QKeyConfig::new("127.0.0.1:4433", DEFAULT_RUNTIME_SNI_HOST)
            .with_stealth("auto")
            .with_fec("auto")
            .with_token("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let qkey_value = qkey::generate(&cfg);
        assert_eq!(qkey::id(&qkey_value), registry_qkey_id(&qkey_value));
    }
}

#[derive(Clone)]
struct ClientSnapshot {
    connected_at: std::time::Instant,
    bytes_in: u64,
    bytes_out: u64,
    stealth_mode: String,
}

enum AdminAction {
    Kick(String),
    Reload,
    Shutdown,
}

#[cfg(unix)]
async fn recv_connected_datagram(
    socket: &tokio::net::UdpSocket,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    use std::io::{Error, ErrorKind};
    loop {
        socket.ready(Interest::READABLE).await?;
        let mut slice = [&mut buf[..]];
        let mut zc = ZeroCopyBuffer::new_mut(&mut slice);
        let rc = zc.recv(socket.as_raw_fd());
        if rc >= 0 {
            return Ok(rc as usize);
        }
        let err = Error::last_os_error();
        if err.kind() == ErrorKind::WouldBlock {
            continue;
        } else {
            return Err(err);
        }
    }
}

#[cfg(not(unix))]
async fn recv_connected_datagram(
    socket: &tokio::net::UdpSocket,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    loop {
        socket.ready(Interest::READABLE).await?;
        match socket.try_recv(buf) {
            Ok(len) => return Ok(len),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

#[cfg(unix)]
async fn recv_datagram_from(
    socket: &tokio::net::UdpSocket,
    buf: &mut [u8],
) -> std::io::Result<(usize, std::net::SocketAddr)> {
    loop {
        socket.ready(Interest::READABLE).await?;
        let mut slice = [&mut buf[..]];
        let mut zc = ZeroCopyBuffer::new_mut(&mut slice);
        match zc.recv_from(socket.as_raw_fd()) {
            Ok((rc, addr)) if rc >= 0 => return Ok((rc as usize, addr)),
            Ok((_, _)) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "negative recv_from result",
                ))
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

#[cfg(not(unix))]
async fn recv_datagram_from(
    socket: &tokio::net::UdpSocket,
    buf: &mut [u8],
) -> std::io::Result<(usize, std::net::SocketAddr)> {
    loop {
        socket.ready(Interest::READABLE).await?;
        match socket.try_recv_from(buf) {
            Ok(result) => return Ok(result),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

#[cfg(unix)]
async fn send_connected_datagram(
    socket: &tokio::net::UdpSocket,
    data: &[u8],
) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};

    #[cfg(all(target_os = "linux", feature = "uring_sys"))]
    {
        use std::os::unix::io::AsRawFd;
        match quicfuscate::transport::uring::try_send_connected(socket.as_raw_fd(), data) {
            Ok(Some(len)) => {
                if len == data.len() {
                    return Ok(());
                } else {
                    return Err(Error::new(
                        ErrorKind::WriteZero,
                        "partial datagram send (io_uring)",
                    ));
                }
            }
            Ok(None) => { /* fall back to standard path */ }
            Err(err) => {
                if err.kind() != ErrorKind::WouldBlock {
                    log::debug!("io_uring connected send fallback: {}", err);
                }
            }
        }
    }

    loop {
        socket.ready(Interest::WRITABLE).await?;
        let zc = ZeroCopyBuffer::new(&[data]);
        let rc = zc.send(socket.as_raw_fd());
        if rc >= 0 {
            if rc as usize == data.len() {
                return Ok(());
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "partial datagram send",
                ));
            }
        }
        let err = Error::last_os_error();
        if err.kind() == ErrorKind::WouldBlock {
            continue;
        } else {
            return Err(err);
        }
    }
}

#[cfg(not(unix))]
async fn send_connected_datagram(
    socket: &tokio::net::UdpSocket,
    data: &[u8],
) -> std::io::Result<()> {
    loop {
        socket.ready(Interest::WRITABLE).await?;
        match socket.try_send(data) {
            Ok(len) if len == data.len() => return Ok(()),
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "partial datagram send",
                ))
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

#[cfg(unix)]
async fn send_datagram_to(
    socket: &tokio::net::UdpSocket,
    addr: &std::net::SocketAddr,
    data: &[u8],
) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};

    #[cfg(all(target_os = "linux", feature = "uring_sys"))]
    {
        use std::os::unix::io::AsRawFd;
        match quicfuscate::transport::uring::try_send_to(socket.as_raw_fd(), addr, data) {
            Ok(Some(len)) => {
                if len == data.len() {
                    return Ok(());
                } else {
                    return Err(Error::new(
                        ErrorKind::WriteZero,
                        "partial datagram send (io_uring)",
                    ));
                }
            }
            Ok(None) => { /* fall back to standard path */ }
            Err(err) => {
                if err.kind() != ErrorKind::WouldBlock {
                    log::debug!("io_uring send_to fallback: {}", err);
                }
            }
        }
    }

    loop {
        socket.ready(Interest::WRITABLE).await?;
        let zc = ZeroCopyBuffer::new(&[data]);
        let rc = zc.send_to(socket.as_raw_fd(), *addr);
        if rc >= 0 {
            if rc as usize == data.len() {
                return Ok(());
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "partial datagram send_to",
                ));
            }
        }
        let err = Error::last_os_error();
        if err.kind() == ErrorKind::WouldBlock {
            continue;
        } else {
            return Err(err);
        }
    }
}

async fn flush_connected_outgoing(
    socket: &tokio::net::UdpSocket,
    conn: &mut QuicFuscateConnection,
    out: &mut [u8],
) -> std::io::Result<()> {
    loop {
        match conn.send(out) {
            Ok(len) if len > 0 => {
                telemetry!(quicfuscate::telemetry::BYTES_SENT.inc_by(len as u64));
                send_connected_datagram(socket, &out[..len]).await?;
            }
            Ok(_) => break,
            Err(ConnectionError::Done) => break,
            Err(e) => {
                log::error!("Send failed: {:?}", e);
                break;
            }
        }
    }
    Ok(())
}

async fn flush_server_outgoing(
    socket: &tokio::net::UdpSocket,
    addr: &std::net::SocketAddr,
    conn: &mut QuicFuscateConnection,
    out: &mut [u8],
    metrics: &Metrics,
) -> std::io::Result<(u64, u64)> {
    let mut bytes_sent = 0u64;
    let mut packets_sent = 0u64;
    loop {
        match conn.send(out) {
            Ok(len) if len > 0 => {
                telemetry!(quicfuscate::telemetry::BYTES_SENT.inc_by(len as u64));
                metrics.bytes_out.fetch_add(len as u64, Ordering::Relaxed);
                metrics.packets_out.fetch_add(1, Ordering::Relaxed);
                bytes_sent = bytes_sent.saturating_add(len as u64);
                packets_sent = packets_sent.saturating_add(1);
                send_datagram_to(socket, addr, &out[..len]).await?;
            }
            Ok(_) => break,
            Err(ConnectionError::Done) => break,
            Err(e) => {
                log::error!("Send failed to {}: {:?}", addr, e);
                break;
            }
        }
    }
    Ok((bytes_sent, packets_sent))
}

#[cfg(not(unix))]
async fn send_datagram_to(
    socket: &tokio::net::UdpSocket,
    addr: &std::net::SocketAddr,
    data: &[u8],
) -> std::io::Result<()> {
    loop {
        socket.ready(Interest::WRITABLE).await?;
        match socket.try_send_to(data, addr) {
            Ok(len) if len == data.len() => return Ok(()),
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "partial datagram send_to",
                ))
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tokio_udp_tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    async fn bind_pair() -> std::io::Result<(tokio::net::UdpSocket, tokio::net::UdpSocket)> {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let server_addr = server.local_addr()?;
        let client_addr = client.local_addr()?;
        client.connect(server_addr).await?;
        server.connect(client_addr).await?;
        Ok((server, client))
    }

    #[tokio::test]
    async fn zero_copy_connected_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let (server, client) = bind_pair().await?;
        let payload = b"tokio-connected";
        send_connected_datagram(&client, payload).await?;
        let mut buf = [0u8; 64];
        let len =
            timeout(Duration::from_secs(1), recv_connected_datagram(&server, &mut buf)).await??;
        assert_eq!(&buf[..len], payload);
        Ok(())
    }

    #[tokio::test]
    async fn zero_copy_unconnected_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let server_addr = server.local_addr()?;
        let client_addr = client.local_addr()?;

        let payload = b"tokio-unconnected";
        send_datagram_to(&client, &server_addr, payload).await?;
        let mut buf = [0u8; 64];
        let (len, from) =
            timeout(Duration::from_secs(1), recv_datagram_from(&server, &mut buf)).await??;
        assert_eq!(from, client_addr);
        assert_eq!(&buf[..len], payload);
        Ok(())
    }
}
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
    /// Enable telemetry metrics
    #[arg(long, global = true)]
    telemetry: bool,
    #[command(subcommand)]
    command: Commands,
}

// Common helper to insert unified benchmark metadata fields
#[cfg(feature = "benches")]
fn insert_bench_metadata(
    map: &mut serde_json::Map<String, serde_json::Value>,
    bench_name: &str,
    items: usize,
    payload_bytes: usize,
    warmup: usize,
    duration_secs: f64,
) {
    use serde_json::json;
    map.insert("bench_name".into(), json!(bench_name));
    map.insert("items".into(), json!(items));
    map.insert("payload_bytes".into(), json!(payload_bytes));
    map.insert("warmup".into(), json!(warmup));
    map.insert("duration_ms".into(), json!((duration_secs * 1000.0).max(0.0)));
    let rate = if duration_secs > 0.0 { (items as f64) / duration_secs } else { 0.0 };
    map.insert("rate_ops".into(), json!(rate));
    map.insert("os".into(), json!(std::env::consts::OS));
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    map.insert("timestamp".into(), json!(ts));
    map.insert("git_rev".into(), json!(option_env!("QUICFUSCATE_GIT_REV").unwrap_or("n/a")));
    map.insert("cpu_model".into(), json!(option_env!("QUICFUSCATE_CPU_MODEL").unwrap_or("n/a")));
    map.insert("rustc".into(), json!(option_env!("QUICFUSCATE_RUSTC_VERSION").unwrap_or("n/a")));
}

#[cfg(feature = "benches")]
fn run_fec_bench(
    packets: usize,
    payload: usize,
    mode: FecMode,
    pool_capacity: usize,
    block_size: usize,
    warmup: usize,
    json: bool,
) -> std::io::Result<()> {
    if payload == 0 || payload > block_size {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "payload must be > 0 and <= block_size",
        ));
    }
    let bench_once = |parallel: bool| -> (f64, usize) {
        // configure env toggle used by fec emit path
        std::env::set_var("QUICFUSCATE_FEC_PARALLEL", if parallel { "1" } else { "0" });
        let opt = OptimizationManager::new_with_config(pool_capacity, block_size, false);
        let mem_pool = opt.memory_pool();
        let cfg = FecConfig { initial_mode: mode, ..Default::default() };
        // fresh FEC per run for fairness
        let mut fec = AdaptiveFec::new(cfg);
        let mut out = VecDeque::with_capacity(256);

        // small helper to make packet with payload bytes; id increments
        let mut id: u64 = 1;
        let make_pkt = |id: u64| -> FecPacket {
            let mut block = opt.alloc_block();
            if !block.is_empty() {
                block[0] = 1;
            }
            let len = payload.min(block.len());
            if len > 8 {
                block[1] = (id & 0xff) as u8;
                block[2] = ((id >> 8) & 0xff) as u8;
                block[3] = ((id >> 16) & 0xff) as u8;
                block[4] = ((id >> 24) & 0xff) as u8;
            }
            FecPacket::new(id, Some(block), len, true, None, 0, mem_pool.clone())
        };

        // optional warmup
        for _ in 0..warmup {
            let p = make_pkt(id);
            id += 1;
            for pkt in fec.on_send(p) {
                out.push_back(pkt);
            }
            // drain emitted to keep memory bounded
            while let Some(_q) = out.pop_front() {}
        }

        let start = Instant::now();
        for _ in 0..packets {
            let p = make_pkt(id);
            id += 1;
            for pkt in fec.on_send(p) {
                out.push_back(pkt);
            }
            while let Some(_q) = out.pop_front() {}
        }
        let elapsed = start.elapsed().as_secs_f64();
        // clear env to avoid side-effects on caller
        if parallel {
            std::env::set_var("QUICFUSCATE_FEC_PARALLEL", "0");
        }
        (elapsed, packets)
    };

    let (t_seq, n_seq) = bench_once(false);
    let (t_par, n_par) = bench_once(true);

    if json {
        let mut map = serde_json::Map::new();
        insert_bench_metadata(&mut map, "fec-bench", packets, payload, warmup, t_seq);
        map.insert("mode".into(), serde_json::json!(format!("{:?}", mode).to_lowercase()));
        map.insert("seq_seconds".into(), serde_json::json!(t_seq));
        map.insert("par_seconds".into(), serde_json::json!(t_par));
        map.insert("seq_pps".into(), serde_json::json!((n_seq as f64 / t_seq).max(0.0)));
        map.insert("par_pps".into(), serde_json::json!((n_par as f64 / t_par).max(0.0)));
        println!("{}", serde_json::Value::Object(map));
    } else {
        println!("[FEC-BENCH] packets={}, payload={}B, mode={:?}", packets, payload, mode);
        println!(" sequential: {:.3}s  ({:.0} pkt/s)", t_seq, (n_seq as f64 / t_seq).round());
        println!("   parallel: {:.3}s  ({:.0} pkt/s)", t_par, (n_par as f64 / t_par).round());
        if t_par > 0.0 {
            println!(" speedup: {:.2}x", (t_seq / t_par));
        }
    }
    Ok(())
}

#[cfg(feature = "benches")]
#[derive(Copy, Clone, Debug, Eq, PartialEq, clap::ValueEnum)]
enum CryptoMode {
    #[clap(name = "fnv1a")]
    Fnv1a,
    #[clap(name = "xor")]
    Xor,
    #[clap(name = "rolling")]
    Rolling,
}

#[cfg(feature = "benches")]
fn run_pool_bench(
    iterations: usize,
    payload: usize,
    pool_capacity: usize,
    block_size: usize,
    warmup: usize,
    json: bool,
) -> std::io::Result<()> {
    if payload == 0 || payload > block_size {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "payload must be > 0 and <= block_size",
        ));
    }
    let opt = OptimizationManager::new_with_config(pool_capacity, block_size, false);
    let start_once = |iters: usize| -> f64 {
        let mut touched: u64 = 0;
        let t0 = Instant::now();
        for i in 0..iters {
            let mut b = opt.alloc_block();
            let sz = payload.min(b.len());
            if sz > 0 {
                b[0] = 0xAA;
            }
            // deterministic touches
            for j in (0..sz).step_by(64) {
                b[j] ^= ((i as u8).wrapping_add(j as u8)) ^ 0x5A;
                touched = touched.wrapping_add(b[j] as u64);
            }
            drop(b);
        }
        let _ = touched; // avoid optimization
        t0.elapsed().as_secs_f64()
    };

    // warmup
    if warmup > 0 {
        let _ = start_once(warmup);
    }
    let elapsed = start_once(iterations);

    if json {
        let mut map = serde_json::Map::new();
        insert_bench_metadata(&mut map, "pool-bench", iterations, payload, warmup, elapsed);
        map.insert("pool_capacity".into(), serde_json::json!(pool_capacity));
        map.insert("block_size".into(), serde_json::json!(block_size));
        println!("{}", serde_json::Value::Object(map));
    } else {
        let rate = if elapsed > 0.0 { iterations as f64 / elapsed } else { 0.0 };
        println!(
            "[POOL-BENCH] iters={}, payload={}B, pool_cap={}, block={}B",
            iterations, payload, pool_capacity, block_size
        );
        println!(" elapsed: {:.3}s  ({:.0} ops/s)", elapsed, rate.round());
    }
    Ok(())
}

#[cfg(feature = "benches")]
fn run_crypto_bench(
    iterations: usize,
    payload: usize,
    mode: CryptoMode,
    warmup: usize,
    json: bool,
) -> std::io::Result<()> {
    if payload == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "payload must be > 0"));
    }

    // deterministic input generator (LCG)
    let mut seed: u64 = 0x9E3779B97F4A7C15;
    let mut make_buf = || {
        let mut v = vec![0u8; payload];
        for (i, x) in v.iter_mut().enumerate() {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            *x = (seed >> 32) as u8 ^ (i as u8);
        }
        v
    };

    let mutate = |buf: &mut [u8], idx: usize, mode: CryptoMode| -> u64 {
        let mut acc: u64 = 0xcbf29ce484222325; // FNV offset
        match mode {
            CryptoMode::Fnv1a => {
                for &b in buf.iter() {
                    acc ^= b as u64;
                    acc = acc.wrapping_mul(0x100000001b3);
                }
            }
            CryptoMode::Xor => {
                let k = ((idx as u8).wrapping_mul(0x5D)) ^ 0xA5;
                for x in buf.iter_mut() {
                    *x ^= k;
                    acc = acc.wrapping_add(*x as u64);
                }
            }
            CryptoMode::Rolling => {
                let mut s: u8 = (idx as u8).wrapping_add(0x33);
                for x in buf.iter_mut() {
                    s = s.rotate_left(1).wrapping_add(*x);
                    *x = x.rotate_left(1) ^ s;
                    acc = acc.wrapping_mul(131).wrapping_add(*x as u64);
                }
            }
        }
        acc
    };

    let mut run = |iters: usize| -> (f64, u64) {
        let mut checksum: u64 = 0;
        let t0 = Instant::now();
        for i in 0..iters {
            let mut buf = make_buf();
            checksum ^= mutate(&mut buf, i, mode);
        }
        let sec = t0.elapsed().as_secs_f64();
        (sec, checksum)
    };

    if warmup > 0 {
        let _ = run(warmup);
    }
    let (elapsed, checksum) = run(iterations);

    if json {
        let mut map = serde_json::Map::new();
        insert_bench_metadata(&mut map, "crypto-bench", iterations, payload, warmup, elapsed);
        map.insert("mode".into(), serde_json::json!(format!("{:?}", mode).to_lowercase()));
        map.insert("checksum".into(), serde_json::json!(format!("0x{:016x}", checksum)));
        println!("{}", serde_json::Value::Object(map));
    } else {
        let rate = if elapsed > 0.0 { iterations as f64 / elapsed } else { 0.0 };
        println!("[CRYPTO-BENCH] iters={}, payload={}B, mode={:?}", iterations, payload, mode);
        println!(
            " elapsed: {:.3}s  ({:.0} ops/s) checksum=0x{:016x}",
            elapsed,
            rate.round(),
            checksum
        );
    }
    Ok(())
}

#[cfg(feature = "benches")]
fn run_net_bench(
    iterations: usize,
    payload: usize,
    warmup: usize,
    json: bool,
) -> std::io::Result<()> {
    if payload == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "payload must be > 0"));
    }

    let mut seed: u64 = 0xD6E8FEB86659FD93;
    let mut gen_packet = || {
        let mut v = vec![0u8; payload];
        for (i, x) in v.iter_mut().enumerate() {
            seed ^= seed << 7;
            seed ^= seed >> 9;
            *x = (seed as u8).wrapping_add(i as u8);
        }
        v
    };

    let mut pipe: VecDeque<Vec<u8>> = VecDeque::with_capacity(1024);
    let mut run = |iters: usize, pipe: &mut VecDeque<Vec<u8>>| -> (f64, usize) {
        let mut moved = 0usize;
        let t0 = Instant::now();
        for _ in 0..iters {
            // enqueue
            pipe.push_back(gen_packet());
            // process stage: copy into scratch then drop
            if let Some(pkt) = pipe.pop_front() {
                let mut scratch = vec![0u8; pkt.len()];
                scratch.copy_from_slice(&pkt);
                moved += scratch.len();
            }
        }
        (t0.elapsed().as_secs_f64(), moved)
    };

    if warmup > 0 {
        let _ = run(warmup, &mut pipe);
        pipe.clear();
    }
    let (elapsed, moved) = run(iterations, &mut pipe);

    if json {
        let mut map = serde_json::Map::new();
        insert_bench_metadata(&mut map, "net-bench", iterations, payload, warmup, elapsed);
        map.insert("bytes_moved".into(), serde_json::json!(moved));
        println!("{}", serde_json::Value::Object(map));
    } else {
        let rate = if elapsed > 0.0 { iterations as f64 / elapsed } else { 0.0 };
        println!("[NET-BENCH] iters={}, payload={}B", iterations, payload);
        println!(" elapsed: {:.3}s  ({:.0} ops/s) bytes_moved={} ", elapsed, rate.round(), moved);
    }
    Ok(())
}

/// Congestion control algorithms selectable via CLI
#[derive(Copy, Clone, Debug, Eq, PartialEq, clap::ValueEnum)]
enum CcAlgorithm {
    #[clap(name = "reno")]
    Reno,
    #[clap(name = "cubic")]
    Cubic,
    #[clap(name = "bbr")]
    Bbr,
    #[clap(name = "bbr2")]
    Bbr2,
    #[clap(name = "bbr2_gcongestion")]
    Bbr2Gcongestion,
}

impl From<CcAlgorithm> for quicfuscate::transport::CongestionControlAlgorithm {
    fn from(cc: CcAlgorithm) -> Self {
        match cc {
            CcAlgorithm::Reno => quicfuscate::transport::CongestionControlAlgorithm::Reno,
            CcAlgorithm::Cubic => quicfuscate::transport::CongestionControlAlgorithm::Cubic,
            CcAlgorithm::Bbr => quicfuscate::transport::CongestionControlAlgorithm::BBR,
            CcAlgorithm::Bbr2 | CcAlgorithm::Bbr2Gcongestion => {
                quicfuscate::transport::CongestionControlAlgorithm::BBR2
            }
        }
    }
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Runs the client
    Client {
        /// The remote server address to connect to
        #[clap(long, required = true)]
        remote: String,

        /// Local UDP address to bind
        #[clap(long, default_value = "0.0.0.0:0")]
        local: String,

        /// The URL to request
        #[clap(short, long, default_value = "https://cloudflare-dns.com/")]
        url: String,

        /// Browser fingerprint profile (chrome, firefox, opera, brave)
        #[clap(long, value_enum, default_value_t = BrowserProfile::Chrome)]
        profile: BrowserProfile,

        /// Operating system for the profile (windows, macos, linux, ios, android)
        #[clap(long, value_enum, default_value_t = OsProfile::Windows)]
        os: OsProfile,

        /// Comma separated list of profiles to cycle through
        #[clap(long, value_delimiter = ',')]
        profile_seq: Option<Vec<String>>,

        /// Interval in seconds for profile switching
        #[clap(long, default_value_t = 0)]
        profile_interval: u64,

        /// Initial FEC mode
        #[clap(long, value_enum, default_value = "zero")]
        fec_mode: FecMode,

        /// Memory pool capacity (number of blocks)
        #[clap(long, default_value_t = 1024)]
        pool_capacity: usize,

        /// Memory pool block size in bytes
        #[clap(long, default_value_t = 4096)]
        pool_block: usize,

        // XDP removed - using native UDP/io_uring fast paths
        /// Path to a unified TOML configuration file
        #[clap(long, value_name = "PATH")]
        config: Option<PathBuf>,

        /// Path to a TOML file with Adaptive FEC settings
        #[clap(long, value_name = "PATH")]
        fec_config: Option<PathBuf>,

        /// Custom DNS-over-HTTPS provider URL
        #[clap(long, default_value = "https://cloudflare-dns.com/dns-query")]
        doh_provider: String,

        /// Domain used for fronting (can be specified multiple times)
        #[clap(long, value_delimiter = ',')]
        front_domain: Vec<String>,
        /// CA file for peer verification
        #[clap(long, value_name = "PATH")]
        ca_file: Option<PathBuf>,
        /// Disable uTLS and use regular TLS
        #[clap(long)]
        no_utls: bool,
        /// Show TLS debug information
        #[clap(long)]
        debug_tls: bool,
        /// List available browser fingerprints
        #[clap(long)]
        list_fingerprints: bool,
        /// Enable certificate validation when connecting to the server
        #[clap(long)]
        verify_peer: bool,

        /// Disable DNS over HTTPS
        #[clap(long)]
        disable_doh: bool,

        /// Disable domain fronting
        #[clap(long)]
        disable_fronting: bool,

        /// Disable XOR obfuscation
        #[clap(long)]
        disable_xor: bool,

        /// Disable HTTP/3 masquerading
        #[clap(long)]
        disable_http3: bool,

        /// Congestion control algorithm
        #[clap(long, value_enum, default_value = "bbr2")]
        cc_algorithm: CcAlgorithm,

        /// Enable TUN bridging (experimental): send TUN frames over HTTP/3
        #[clap(long)]
        tun: bool,
        /// TUN interface name (optional)
        #[clap(long)]
        tun_name: Option<String>,
        /// TUN MTU
        #[clap(long)]
        tun_mtu: Option<u16>,
        /// TUN IP address
        #[clap(long)]
        tun_ip: Option<String>,
        /// TUN netmask
        #[clap(long)]
        tun_netmask: Option<String>,
    },
    /// Runs the server
    Server {
        /// The address to listen on
        #[clap(short, long, default_value = "127.0.0.1:4433")]
        listen: String,

        /// Path to the certificate file
        #[clap(short, long, required = true)]
        cert: PathBuf,

        /// Path to the private key file
        #[clap(short, long, required = true)]
        key: PathBuf,

        /// Browser fingerprint profile used for connections
        #[clap(long, value_enum, default_value_t = BrowserProfile::Chrome)]
        profile: BrowserProfile,

        /// Operating system for the profile (windows, macos, linux, ios, android)
        #[clap(long, value_enum, default_value_t = OsProfile::Windows)]
        os: OsProfile,

        /// Comma separated list of profiles to cycle through
        #[clap(long, value_delimiter = ',')]
        profile_seq: Option<Vec<String>>,

        /// Interval in seconds for profile switching
        #[clap(long, default_value_t = 0)]
        profile_interval: u64,

        /// Initial FEC mode
        #[clap(long, value_enum, default_value = "zero")]
        fec_mode: FecMode,

        /// Memory pool capacity (number of blocks)
        #[clap(long, default_value_t = 1024)]
        pool_capacity: usize,

        /// Memory pool block size in bytes
        #[clap(long, default_value_t = 4096)]
        pool_block: usize,

        // XDP removed - using native UDP/io_uring fast paths
        /// Path to a unified TOML configuration file
        #[clap(long, value_name = "PATH")]
        config: Option<PathBuf>,

        /// Path to a TOML file with Adaptive FEC settings
        #[clap(long, value_name = "PATH")]
        fec_config: Option<PathBuf>,

        /// Custom DNS-over-HTTPS provider URL
        #[clap(long, default_value = "https://cloudflare-dns.com/dns-query")]
        doh_provider: String,

        /// Domain used for fronting (can be specified multiple times)
        #[clap(long, value_delimiter = ',')]
        front_domain: Vec<String>,

        /// Disable DNS over HTTPS
        #[clap(long)]
        disable_doh: bool,

        /// Disable domain fronting
        #[clap(long)]
        disable_fronting: bool,

        /// Disable XOR obfuscation
        #[clap(long)]
        disable_xor: bool,

        /// Disable HTTP/3 masquerading
        #[clap(long)]
        disable_http3: bool,

        /// Congestion control algorithm
        #[clap(long, value_enum, default_value = "bbr2")]
        cc_algorithm: CcAlgorithm,

        /// Enable TUN bridging (experimental): write received frames to TUN
        #[clap(long)]
        tun: bool,
        /// TUN interface name (optional)
        #[clap(long)]
        tun_name: Option<String>,
        /// TUN MTU
        #[clap(long)]
        tun_mtu: Option<u16>,
        /// TUN IP address
        #[clap(long)]
        tun_ip: Option<String>,
        /// TUN netmask
        #[clap(long)]
        tun_netmask: Option<String>,

        /// Admin control socket (unix only)
        #[clap(long, value_name = "PATH")]
        admin_socket: Option<PathBuf>,

        /// Metrics HTTP port (optional)
        #[clap(long)]
        metrics_port: Option<u16>,

        /// Admin web server bind address (e.g. 127.0.0.1:9000)
        #[clap(long)]
        admin_web: Option<std::net::SocketAddr>,

        /// Admin web static root (default: assets/web-admin)
        #[clap(long, value_name = "PATH", default_value = "assets/web-admin")]
        admin_web_root: PathBuf,

        /// Admin web username (required when --admin-web is set)
        #[clap(long)]
        admin_web_user: Option<String>,

        /// Admin web password (required when --admin-web is set)
        #[clap(long)]
        admin_web_password: Option<String>,

        /// Default QKey TTL in seconds (0 disables expiration)
        #[clap(long)]
        qkey_ttl_secs: Option<u64>,

        /// QKey registry store path (defaults near config or ./config/local/qkeys.json)
        #[clap(long, value_name = "PATH")]
        qkey_store: Option<PathBuf>,
    },
    #[clap(hide = true)]
    CrossFadeSim {},
    #[clap(hide = true)]
    HighLossSim {},
    #[clap(hide = true)]
    OptimizeProbe {},
    #[clap(hide = true)]
    XdpSmoke {},
    #[cfg(feature = "benches")]
    #[clap(hide = true)]
    /// Internal FEC benchmark harness (sequential vs parallel)
    FecBench {
        /// Number of source packets to send during the measured run
        #[clap(long, alias = "iterations", default_value_t = 8192)]
        packets: usize,
        /// Payload size per packet (bytes)
        #[clap(long, default_value_t = 1200)]
        payload: usize,
        /// Initial FEC mode/window profile to benchmark
        #[clap(long, value_enum, default_value = "normal")]
        mode: FecMode,
        /// Memory pool capacity (blocks)
        #[clap(long, default_value_t = 1024)]
        pool_capacity: usize,
        /// Memory pool block size (bytes)
        #[clap(long, default_value_t = 4096)]
        block_size: usize,
        /// Warm-up packet count (not timed)
        #[clap(long, default_value_t = 0)]
        warmup: usize,
        /// Print machine-readable JSON summary
        #[clap(long)]
        json: bool,
    },
    #[cfg(feature = "benches")]
    #[clap(hide = true)]
    /// Internal Memory Pool micro-benchmark
    PoolBench {
        /// Total iterations to perform (alias: --packets)
        #[clap(long, alias = "packets", default_value_t = 200_000)]
        iterations: usize,
        /// Bytes to touch per allocation
        #[clap(long, default_value_t = 1200)]
        payload: usize,
        /// Memory pool capacity (blocks)
        #[clap(long, default_value_t = 1024)]
        pool_capacity: usize,
        /// Memory pool block size (bytes)
        #[clap(long, default_value_t = 4096)]
        block_size: usize,
        /// Warm-up iterations (not timed)
        #[clap(long, default_value_t = 0)]
        warmup: usize,
        /// Print machine-readable JSON summary
        #[clap(long)]
        json: bool,
    },
    #[cfg(feature = "benches")]
    #[clap(hide = true)]
    /// Internal Crypto/Encode micro-benchmark
    CryptoBench {
        /// Total iterations to perform (alias: --packets)
        #[clap(long, alias = "packets", default_value_t = 200_000)]
        iterations: usize,
        /// Payload size per iteration (bytes)
        #[clap(long, default_value_t = 1200)]
        payload: usize,
        /// Hash/encode mode
        #[clap(long, value_enum, default_value = "fnv1a")]
        mode: CryptoMode,
        /// Warm-up iterations (not timed)
        #[clap(long, default_value_t = 0)]
        warmup: usize,
        /// Print machine-readable JSON summary
        #[clap(long)]
        json: bool,
    },
    #[cfg(feature = "benches")]
    #[clap(hide = true)]
    /// Internal synthetic networking micro-benchmark
    NetBench {
        /// Total iterations to perform (alias: --packets)
        #[clap(long, alias = "packets", default_value_t = 100_000)]
        iterations: usize,
        /// Payload size per synthetic packet (bytes)
        #[clap(long, default_value_t = 1200)]
        payload: usize,
        /// Warm-up iterations (not timed)
        #[clap(long, default_value_t = 0)]
        warmup: usize,
        /// Print machine-readable JSON summary
        #[clap(long)]
        json: bool,
    },
    #[clap(hide = true)]
    /// Internal capability probe for system diagnostics
    Capabilities {
        /// Print machine-readable JSON (recommended)
        #[clap(long)]
        json: bool,
    },
}

#[tokio::main(flavor = "multi_thread", worker_threads = 8)]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    let admin_log_buffer =
        Arc::new(quicfuscate::implementations::server::admin_logs::AdminLogBuffer::new(4096));
    let _ = ADMIN_LOG_BUFFER.set(admin_log_buffer.clone());
    if cli.verbose {
        std::env::set_var("RUST_LOG", "info");
    }
    {
        use std::io::Write;
        // We keep the env_logger filter permissive (Trace) and let runtime mode changes
        // control effective verbosity via log::set_max_level.
        let mut builder = env_logger::Builder::new();
        builder.filter_level(log::LevelFilter::Trace);
        let buf = admin_log_buffer.clone();
        builder.format(move |fmt, record| {
            let msg = format!("{}", record.args());
            buf.push(record.level(), &msg);
            writeln!(fmt, "[{}] {}", record.level(), msg)
        });
        builder.init();
    }
    // Default runtime verbosity. Server and Admin UI may override via persisted log mode.
    log::set_max_level(log::LevelFilter::Info);

    // One-time validation of consolidated in-memory profiles.
    // Logs warnings for any profile that doesn't pass the sanity checks.
    {
        // Validate profiles using stealth module's TlsClientHelloSpoofer
        let results = quicfuscate::stealth::TlsClientHelloSpoofer::available_profiles()
            .into_iter()
            .map(|(b, o)| {
                // Simple validation - check if we can generate a ClientHello
                let ch =
                    quicfuscate::stealth::tls_cover::TlsCover::generate_client_hello(b, o, None);
                let res: Result<(), String> =
                    if ch.len() > 100 { Ok(()) } else { Err("ClientHello too short".into()) };
                (b, o, res)
            })
            .collect::<Vec<_>>();
        let mut failures = 0usize;
        for (b, o, res) in results {
            if let Err(e) = res {
                failures += 1;
                warn!("profile validation failed for {:?}/{:?}: {}", b, o, e);
            }
        }
        if failures > 0 {
            warn!("{} profile(s) had validation issues; proceeding with best-effort.", failures);
        } else {
            info!("All consolidated browser profiles passed validation.");
        }
    }
    if cli.telemetry {
        use quicfuscate::telemetry_metrics::TELEMETRY_ENABLED;
        TELEMETRY_ENABLED.store(true, Ordering::Relaxed);
        // Spawn minimal telemetry HTTP server at /telemetry
        quicfuscate::metrics::spawn_telemetry_server();
    }

    match cli.command {
        Commands::Client {
            remote,
            local,
            url,
            profile,
            os,
            profile_seq,
            profile_interval,
            fec_mode,
            pool_capacity,
            pool_block,
            config,
            fec_config,
            doh_provider,
            front_domain,
            ca_file,
            no_utls,
            debug_tls,
            list_fingerprints,
            verify_peer,
            disable_doh,
            disable_fronting,
            disable_xor,
            disable_http3,
            cc_algorithm,
            tun,
            tun_name,
            tun_mtu,
            tun_ip,
            tun_netmask,
        } => {
            run_client(
                remote.as_str(),
                local.as_str(),
                url.as_str(),
                profile,
                os,
                &profile_seq,
                profile_interval,
                fec_mode,
                pool_capacity,
                pool_block,
                &config,
                &fec_config,
                doh_provider.as_str(),
                &front_domain,
                &ca_file,
                no_utls,
                debug_tls,
                list_fingerprints,
                verify_peer,
                disable_doh,
                disable_fronting,
                disable_xor,
                disable_http3,
                cc_algorithm,
                tun,
                tun_name,
                tun_mtu,
                tun_ip,
                tun_netmask,
            )
            .await?;
        }
        Commands::Server {
            listen,
            cert,
            key,
            profile,
            os,
            profile_seq,
            profile_interval,
            fec_mode,
            pool_capacity,
            pool_block,
            config,
            fec_config,
            doh_provider,
            front_domain,
            disable_doh,
            disable_fronting,
            disable_xor,
            disable_http3,
            cc_algorithm,
            tun,
            tun_name,
            tun_mtu,
            tun_ip,
            tun_netmask,
            admin_socket,
            metrics_port,
            admin_web,
            admin_web_root,
            admin_web_user,
            admin_web_password,
            qkey_ttl_secs,
            qkey_store,
        } => {
            run_server(
                listen.as_str(),
                cert.as_path(),
                key.as_path(),
                profile,
                os,
                &profile_seq,
                profile_interval,
                fec_mode,
                pool_capacity,
                pool_block,
                &config,
                &fec_config,
                doh_provider.as_str(),
                &front_domain,
                disable_doh,
                disable_fronting,
                disable_xor,
                disable_http3,
                cc_algorithm,
                tun,
                tun_name,
                tun_mtu,
                tun_ip,
                tun_netmask,
                admin_socket,
                metrics_port,
                admin_web,
                admin_web_root,
                admin_web_user,
                admin_web_password,
                qkey_ttl_secs,
                qkey_store,
            )
            .await?;
        }
        Commands::CrossFadeSim {} => {
            run_crossfade_sim()?;
        }
        Commands::HighLossSim {} => {
            run_high_loss_sim()?;
        }
        Commands::OptimizeProbe {} => {
            run_optimize_probe()?;
        }
        Commands::XdpSmoke {} => {
            // XDP smoke test removed
        }
        #[cfg(feature = "benches")]
        Commands::FecBench { packets, payload, mode, pool_capacity, block_size, warmup, json } => {
            run_fec_bench(packets, payload, mode, pool_capacity, block_size, warmup, json)?;
        }
        #[cfg(feature = "benches")]
        Commands::PoolBench { iterations, payload, pool_capacity, block_size, warmup, json } => {
            run_pool_bench(iterations, payload, pool_capacity, block_size, warmup, json)?;
        }
        #[cfg(feature = "benches")]
        Commands::CryptoBench { iterations, payload, mode, warmup, json } => {
            run_crypto_bench(iterations, payload, mode, warmup, json)?;
        }
        #[cfg(feature = "benches")]
        Commands::NetBench { iterations, payload, warmup, json } => {
            run_net_bench(iterations, payload, warmup, json)?;
        }
        Commands::Capabilities { json: _ } => {
            let _json = serde_json::json!({
                "fec_bench": cfg!(feature = "benches"),
                "pool_bench": cfg!(feature = "benches"),
                "crypto_bench": cfg!(feature = "benches"),
                "net_bench": cfg!(feature = "benches"),
            });
            println!("{}", _json);
        }
    }

    use quicfuscate::telemetry_metrics::TELEMETRY_ENABLED;
    if TELEMETRY_ENABLED.load(Ordering::Relaxed) {
        quicfuscate::telemetry::flush();
    }
    Ok(())
}

fn parse_profile_entry(entry: &str, default_os: OsProfile) -> Option<FingerprintProfile> {
    let parts: Vec<&str> = entry.split('@').collect();
    let browser_part = parts.first()?;
    let browser = match browser_part.parse() {
        Ok(b) => b,
        Err(_) => {
            warn!("Invalid browser profile: {}", browser_part);
            return None;
        }
    };
    let os = if let Some(os_part) = parts.get(1) {
        match os_part.parse() {
            Ok(o) => o,
            Err(_) => {
                warn!("Invalid OS profile: {}", os_part);
                return None;
            }
        }
    } else {
        default_os
    };
    let fp = FingerprintProfile::new(browser, os);
    if fp.client_hello.is_none() {
        warn!("No ClientHello found for {}@{}", browser_part, format!("{:?}", os).to_lowercase());
        return None;
    }
    Some(fp)
}

fn run_crossfade_sim() -> std::io::Result<()> {
    println!("[legacy] Cross-fade simulation starting...");
    let opt = OptimizationManager::new();
    let _mem_pool = opt.memory_pool();
    let mut fec = AdaptiveFec::new(FecConfig::default());
    let mut last_mode = fec.current_mode();
    println!(" initial mode: {:?}", last_mode);

    let phases: &[(usize, usize, usize)] = &[
        (0, 100, 16),  // clean
        (10, 100, 16), // light loss
        (30, 100, 24), // moderate
        (50, 100, 24), // heavy
        (10, 100, 16), // recover
    ];
    for (lost, total, iters) in phases {
        for _ in 0..*iters {
            fec.report_loss(*lost, *total);
            let m = fec.current_mode();
            if m != last_mode || fec.is_transitioning() {
                println!(
                    " mode: {:?}  transitioning: {}  (loss={}/{})",
                    m,
                    fec.is_transitioning(),
                    lost,
                    total
                );
                last_mode = m;
            }
        }
    }
    println!("[legacy] Cross-fade simulation complete. final mode: {:?}", last_mode);
    Ok(())
}

fn run_high_loss_sim() -> std::io::Result<()> {
    println!("[legacy] High-loss simulation starting...");
    let opt = OptimizationManager::new();
    let _mem_pool = opt.memory_pool();
    let mut fec = AdaptiveFec::new(FecConfig::default());
    let mut last_mode = fec.current_mode();
    println!(" initial mode: {:?}", last_mode);
    for _ in 0..64 {
        fec.report_loss(70, 100);
        let m = fec.current_mode();
        if m != last_mode || fec.is_transitioning() {
            println!(" mode: {:?}  transitioning: {}", m, fec.is_transitioning());
            last_mode = m;
        }
    }
    println!("[legacy] High-loss simulation complete. final mode: {:?}", last_mode);
    Ok(())
}

fn run_optimize_probe() -> std::io::Result<()> {
    println!("[legacy] Optimization probe starting...");
    let opt = OptimizationManager::new_with_config(64, 4096, false);
    println!(" xdp_available={} xdp_enabled={}", opt.is_xdp_available(), opt.is_xdp_enabled());
    // Exercise the memory pool
    let b1 = opt.alloc_block();
    let b2 = opt.alloc_block();
    println!(" allocated two blocks: {} + {} bytes", b1.len(), b2.len());
    // Touch memory to exercise NUMA moves where applicable
    let mut b1 = b1;
    let mut b2 = b2;
    if !b1.is_empty() {
        b1[0] = 1;
    }
    if !b2.is_empty() {
        b2[0] = 2;
    }
    opt.free_block(b1);
    opt.free_block(b2);
    // Adjust capacity dynamically
    let pool = opt.memory_pool();
    pool.set_capacity(128);
    println!(" pool capacity adjusted to 128 (probe)");
    println!("[legacy] Optimization probe complete.");
    Ok(())
}

// XDP smoke test removed - AF_XDP no longer supported
#[allow(clippy::too_many_arguments)]
async fn run_client(
    remote_addr_str: &str,
    local_addr_str: &str,
    url: &str,
    profile: BrowserProfile,
    os: OsProfile,
    profile_seq: &Option<Vec<String>>,
    profile_interval: u64,
    fec_mode: FecMode,
    pool_capacity: usize,
    pool_block: usize,
    config: &Option<PathBuf>,
    fec_config: &Option<PathBuf>,
    doh_provider: &str,
    front_domain: &[String],
    ca_file: &Option<PathBuf>,
    no_utls: bool,
    debug_tls: bool,
    list_fingerprints: bool,
    verify_peer: bool,
    disable_doh: bool,
    disable_fronting: bool,
    disable_xor: bool,
    disable_http3: bool,
    cc_algorithm: CcAlgorithm,
    tun_enable: bool,
    tun_name: Option<String>,
    tun_mtu: Option<u16>,
    tun_ip: Option<String>,
    tun_netmask: Option<String>,
) -> std::io::Result<()> {
    let config_path = config.as_ref();
    if list_fingerprints {
        info!("Available browser fingerprints:");
        for (b, o) in TlsClientHelloSpoofer::available_profiles() {
            info!("- {}@{}", format!("{:?}", b).to_lowercase(), format!("{:?}", o).to_lowercase());
        }
        return Ok(());
    }

    let server_addr = remote_addr_str.to_socket_addrs()?.next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "Server address not found")
    })?;

    let local_addr = local_addr_str.to_socket_addrs()?.next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "Local address invalid")
    })?;

    let std_socket = std::net::UdpSocket::bind(local_addr)?;
    std_socket.connect(server_addr)?;
    std_socket.set_nonblocking(true)?;
    let socket = tokio::net::UdpSocket::from_std(std_socket)?;

    info!("Client connecting to {}", server_addr);

    let (mut fec_cfg, mut stealth_config, opt_cfg) = if let Some(cfg) = config_path {
        match AppConfig::from_file(cfg) {
            Ok(c) => {
                if let Err(e) = c.validate() {
                    warn!("Config validation failed: {}", e);
                }
                (c.fec, c.stealth, c.optimize)
            }
            Err(e) => {
                error!("Failed to load config {}: {}", cfg.display(), e);
                (FecConfig::default(), StealthConfig::default(), OptimizeConfig::default())
            }
        }
    } else {
        let fec = if let Some(path) = fec_config {
            match FecConfig::from_file(path) {
                Ok(cfg) => {
                    if let Err(e) = cfg.validate() {
                        warn!("FEC config validation failed: {}", e);
                    }
                    cfg
                }
                Err(e) => {
                    error!("Failed to load FEC config {}: {}", path.display(), e);
                    FecConfig::default()
                }
            }
        } else {
            FecConfig::default()
        };
        (fec, StealthConfig::default(), OptimizeConfig::default())
    };
    // Precedence: config file can specify `adaptive_fec.initial_mode`.
    // CLI `--fec-mode` overrides only when explicitly non-zero, otherwise keep config.
    if config_path.is_none() || fec_mode != FecMode::Zero {
        fec_cfg.initial_mode = fec_mode;
    }

    let mut config = match quicfuscate::transport::Config::new_with_version(
        quicfuscate::transport::PROTOCOL_VERSION,
    ) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create transport config: {}", e);
            return Err(std::io::Error::other("transport config init failed"));
        }
    };
    // Apply selected congestion control algorithm
    // Map CLI CcAlgorithm to transport::CongestionControlAlgorithm
    let cca = match cc_algorithm {
        CcAlgorithm::Reno => quicfuscate::transport::CongestionControlAlgorithm::Reno,
        CcAlgorithm::Cubic => quicfuscate::transport::CongestionControlAlgorithm::Cubic,
        CcAlgorithm::Bbr => quicfuscate::transport::CongestionControlAlgorithm::BBR,
        CcAlgorithm::Bbr2 | CcAlgorithm::Bbr2Gcongestion => {
            quicfuscate::transport::CongestionControlAlgorithm::BBR2
        }
    };
    config.set_cc_algorithm(cca);
    if let Err(e) =
        config.set_application_protos(&[b"hq-interop", b"h3-29", b"h3-28", b"h3-27", b"http/0.9"])
    {
        warn!("Failed to set application protos: {}", e);
    }
    config.set_max_idle_timeout(30000);
    config.set_max_recv_udp_payload_size(1460);
    config.set_max_send_udp_payload_size(1200);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.verify_peer(verify_peer);
    if debug_tls {
        config.log_keys();
    }
    if let Some(path) = ca_file {
        match path.to_str() {
            Some(s) => {
                if let Err(e) = config.load_verify_locations_from_file(s) {
                    error!("Failed to load CA file {}: {}", path.display(), e);
                }
            }
            None => {
                error!("CA file path is not valid UTF-8: {}", path.display());
            }
        }
    }

    let url_parsed = match url::Url::parse(url) {
        Ok(u) => u,
        Err(e1) => {
            warn!("Invalid URL '{}': {}. Falling back to {}", url, e1, DEFAULT_RUNTIME_URL);
            match url::Url::parse(DEFAULT_RUNTIME_URL) {
                Ok(u2) => u2,
                Err(e2) => {
                    error!("Fallback URL parse failed: {}", e2);
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "invalid URL",
                    ));
                }
            }
        }
    };
    // Profile direkt setzen
    stealth_config.initial_browser = profile;
    stealth_config.initial_os = os;
    stealth_config.enable_doh = !disable_doh;
    stealth_config.doh_provider.clear();
    stealth_config.doh_provider.push_str(doh_provider);
    stealth_config.enable_domain_fronting = !disable_fronting;
    stealth_config.fronting_domains = front_domain.to_vec();
    stealth_config.enable_xor_obfuscation = !disable_xor;
    stealth_config.enable_http3_masquerading = !disable_http3;
    telemetry!(quicfuscate::telemetry_metrics::STEALTH_BROWSER_PROFILE
        .set(stealth_config.initial_browser as i64));
    telemetry!(
        quicfuscate::telemetry_metrics::STEALTH_OS_PROFILE.set(stealth_config.initial_os as i64)
    );

    let host = url_parsed.host_str().unwrap_or(DEFAULT_RUNTIME_SNI_HOST);
    let opt_params = if config_path.is_some() {
        OptimizeConfig {
            pool_capacity: opt_cfg.pool_capacity,
            block_size: opt_cfg.block_size,
            enable_xdp: opt_cfg.enable_xdp,
        }
    } else {
        OptimizeConfig { pool_capacity, block_size: pool_block, enable_xdp: false }
    };
    let mut conn = match QuicFuscateConnection::new_client(
        host,
        local_addr,
        server_addr,
        config,
        stealth_config.clone(),
        fec_cfg,
        opt_params,
        None,
        !no_utls,
    ) {
        Ok(c) => c,
        Err(e) => {
            error!("failed to create client connection: {}", e);
            return Err(std::io::Error::other("client connection init failed"));
        }
    };

    let profiles: Vec<FingerprintProfile> = match profile_seq {
        Some(seq) => seq.iter().filter_map(|s| parse_profile_entry(s, os)).collect(),
        None => vec![FingerprintProfile::new(profile, os)],
    };

    if profile_interval > 0 && profiles.is_empty() {
        error!("No valid profiles supplied with --profile-seq");
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid profile sequence",
        ));
    }

    if profile_interval > 0 && profiles.len() > 1 {
        let sm = conn.stealth_manager();
        sm.start_profile_rotation(profiles, std::time::Duration::from_secs(profile_interval));
    }

    let mut buf = [0; 65535];
    let mut out = [0; 65535];

    // Send initial packet
    if let Ok(len) = conn.send(&mut out) {
        if len > 0 {
            telemetry!(quicfuscate::telemetry::BYTES_SENT.inc_by(len as u64));
            if let Err(e) = send_connected_datagram(&socket, &out[..len]).await {
                error!("Failed to send initial packet: {}", e);
            } else {
                info!("Sent initial packet of size {}", len);
            }
        }
    }

    let mut request_sent = false;

    // Optional TUN bridging setup
    let (tun_rx, mut h3_stream_id): (Option<std::sync::mpsc::Receiver<Vec<u8>>>, Option<u64>) =
        if tun_enable {
            let tcfg = quicfuscate::interface::TunConfig {
                name: tun_name,
                ip: tun_ip.and_then(|s| s.parse().ok()),
                netmask: tun_netmask.and_then(|s| s.parse().ok()),
                mtu: tun_mtu.unwrap_or(1500),
                ..Default::default()
            };
            let optm = OptimizationManager::from_cfg(opt_params);
            let pool = optm.memory_pool();
            match quicfuscate::interface::TunInterface::open(tcfg, pool.clone()) {
                Ok(tun) => {
                    // Spawn a blocking reader thread that forwards TUN frames into a channel
                    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
                    std::thread::spawn(move || {
                        loop {
                            match tun.read_block() {
                                Ok((block, len)) if len > 0 => {
                                    let mut v = vec![0u8; len];
                                    v.copy_from_slice(&block[..len]);
                                    let _ = tx.send(v);
                                    // block freed when dropped
                                }
                                Ok(_) => {}
                                Err(_) => break,
                            }
                        }
                    });
                    (Some(rx), None)
                }
                Err(e) => {
                    warn!("TUN open failed: {:?}", e);
                    (None, None)
                }
            }
        } else {
            (None, None)
        };
    let mut housekeeping = interval(Duration::from_millis(5));
    housekeeping.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Shutdown signal received");
                let _ = conn.conn.close(true, 0x0, b"ctrl_c");
                break;
            }
            recv_res = recv_connected_datagram(&socket, &mut buf) => {
                match recv_res {
                    Ok(len) => {
                        telemetry!(quicfuscate::telemetry::BYTES_RECEIVED.inc_by(len as u64));
                        if let Err(e) = conn.recv(&buf[..len]) {
                            error!("QUIC recv failed: {:?}", e);
                        } else if let Err(e) =
                            flush_connected_outgoing(&socket, &mut conn, &mut out).await
                        {
                            warn!("Failed to send response packet: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("Failed to read from socket: {}", e);
                    }
                }
            }
            _ = housekeeping.tick() => {
                if conn.conn.is_established() && !request_sent {
                    match conn.send_http3_request(url_parsed.path()) {
                        Ok(_) => {
                            request_sent = true;
                        }
                        Err(e) => {
                            warn!("HTTP/3 request failed: {:?}", e);
                        }
                    }
                }

                if tun_enable {
                    if h3_stream_id.is_none() {
                        match conn.open_http3_stream_post("/tun") {
                            Ok(sid) => { h3_stream_id = Some(sid); }
                            Err(e) => { warn!("open_http3_stream_post failed: {:?}", e); }
                        }
                    }
                    if let (Some(ref rx), Some(sid)) = (&tun_rx, h3_stream_id) {
                        for _ in 0..16 {
                            match rx.try_recv() {
                                Ok(frame) => {
                                    if let Err(e) = conn.http3_send_body_chunk(sid, &frame, false) {
                                        warn!("http3_send_body_chunk failed: {:?}", e);
                                        break;
                                    }
                                }
                                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                                Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
                            }
                        }
                    }
                    let _ = conn.poll_http3_with(|_data| {
                        // client-side downlink to TUN could be added by writing to the interface
                    });
                } else if let Err(e) = conn.poll_http3() {
                    warn!("HTTP/3 error: {:?}", e);
                }

                if let Err(e) = flush_connected_outgoing(&socket, &mut conn, &mut out).await {
                    warn!("Failed to flush outgoing packets: {}", e);
                }

                conn.update_state();
                info!(
                    "client stats: RTT {:.0} ms, Loss {:.2}%",
                    conn.rtt_ms(),
                    conn.loss_rate() * 100.0
                );
                conn.conn.on_timeout();
                tokio::task::yield_now().await;
            }
        }
    }

    Ok(())
}

fn apply_transport_overrides_from_toml(
    cfg_path: &Path,
    contents: &str,
    transport: &mut quicfuscate::transport::Config,
) {
    let overrides = match parse_transport_overrides_from_toml(contents) {
        Ok(o) => o,
        Err(e) => {
            warn!("transport overrides ignored (invalid values, {}): {}", cfg_path.display(), e);
            return;
        }
    };

    if let Some(algo) = overrides.cc_algorithm {
        transport.set_cc_algorithm(algo);
    }
    if let Some(mtu) = overrides.mtu {
        transport.set_max_send_udp_payload_size(mtu);
    }
    if let Some(pacing) = overrides.enable_pacing {
        transport.enable_pacing(pacing);
    }
}

#[derive(Default)]
struct TransportOverrides {
    cc_algorithm: Option<quicfuscate::transport::CongestionControlAlgorithm>,
    mtu: Option<usize>,
    enable_pacing: Option<bool>,
}

fn parse_transport_overrides_from_toml(contents: &str) -> Result<TransportOverrides, String> {
    let doc: toml::Value =
        toml::from_str(contents).map_err(|e| format!("TOML parse failed: {}", e))?;
    let Some(tbl) = doc.get("transport").and_then(|v| v.as_table()) else {
        return Ok(TransportOverrides::default());
    };

    let mut out = TransportOverrides::default();

    if let Some(v) = tbl.get("cc_algorithm") {
        let raw =
            v.as_str().ok_or_else(|| "transport.cc_algorithm must be a string".to_string())?;
        let name = raw.trim().to_lowercase();
        let algo = match name.as_str() {
            "reno" => Some(quicfuscate::transport::CongestionControlAlgorithm::Reno),
            "cubic" => Some(quicfuscate::transport::CongestionControlAlgorithm::Cubic),
            "bbr" => Some(quicfuscate::transport::CongestionControlAlgorithm::BBR),
            "bbr2" | "bbr2_gcongestion" => {
                Some(quicfuscate::transport::CongestionControlAlgorithm::BBR2)
            }
            "bbr3" => Some(quicfuscate::transport::CongestionControlAlgorithm::BBR3),
            "ledbat" => Some(quicfuscate::transport::CongestionControlAlgorithm::Ledbat),
            _ => None,
        };
        let Some(algo) = algo else {
            return Err(format!("transport.cc_algorithm '{}' is not supported", raw));
        };
        out.cc_algorithm = Some(algo);
    }

    if let Some(v) = tbl.get("mtu") {
        let mtu = v.as_integer().ok_or_else(|| "transport.mtu must be an integer".to_string())?;
        if mtu <= 0 {
            return Err("transport.mtu must be > 0".to_string());
        }
        // QUIC minimum payload is 1200. We allow jumbo frames for LAN.
        if !(1200..=9000).contains(&mtu) {
            return Err("transport.mtu must be between 1200 and 9000".to_string());
        }
        out.mtu = Some(mtu as usize);
    }

    if let Some(v) = tbl.get("enable_pacing") {
        let pacing =
            v.as_bool().ok_or_else(|| "transport.enable_pacing must be a boolean".to_string())?;
        out.enable_pacing = Some(pacing);
    }

    Ok(out)
}

fn apply_transport_overrides_from_file(
    cfg_path: &Path,
    transport: &mut quicfuscate::transport::Config,
) {
    match std::fs::read_to_string(cfg_path) {
        Ok(contents) => apply_transport_overrides_from_toml(cfg_path, &contents, transport),
        Err(e) => warn!("transport overrides ignored (read failed, {}): {}", cfg_path.display(), e),
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_runtime_stealth_overrides(
    sc: &mut StealthConfig,
    profile: BrowserProfile,
    os: OsProfile,
    disable_doh: bool,
    doh_provider: &str,
    disable_fronting: bool,
    front_domain: &[String],
    disable_xor: bool,
    disable_http3: bool,
) {
    sc.initial_browser = profile;
    sc.initial_os = os;
    sc.enable_doh = !disable_doh;
    sc.doh_provider.clear();
    sc.doh_provider.push_str(doh_provider);
    sc.enable_domain_fronting = !disable_fronting;
    sc.fronting_domains = front_domain.to_vec();
    sc.enable_xor_obfuscation = !disable_xor;
    sc.enable_http3_masquerading = !disable_http3;
    telemetry!(
        quicfuscate::telemetry_metrics::STEALTH_BROWSER_PROFILE.set(sc.initial_browser as i64)
    );
    telemetry!(quicfuscate::telemetry_metrics::STEALTH_OS_PROFILE.set(sc.initial_os as i64));
}

#[allow(clippy::too_many_arguments)]
fn apply_runtime_config_reload(
    cfg_path: &Path,
    fec_mode_override: FecMode,
    transport: &mut quicfuscate::transport::Config,
    fec_cfg_shared: &Arc<Mutex<FecConfig>>,
    opt_params_shared: &Arc<Mutex<OptimizeConfig>>,
    stealth_config: &Arc<Mutex<StealthConfig>>,
    profile: BrowserProfile,
    os: OsProfile,
    disable_doh: bool,
    doh_provider: &str,
    disable_fronting: bool,
    front_domain: &[String],
    disable_xor: bool,
    disable_http3: bool,
) -> Result<(), String> {
    let contents =
        std::fs::read_to_string(cfg_path).map_err(|e| format!("Config read failed: {}", e))?;
    let cfg = quicfuscate::interface::app_config::AppConfig::from_toml(&contents)
        .map_err(|e| format!("Config parse failed: {}", e))?;

    cfg.validate().map_err(|e| format!("Config validation failed: {}", e))?;
    parse_transport_overrides_from_toml(&contents)?;

    let mut fec = cfg.fec;
    if fec_mode_override != FecMode::Zero {
        fec.initial_mode = fec_mode_override;
    }

    {
        let mut guard = fec_cfg_shared.lock().unwrap_or_else(|e| e.into_inner());
        *guard = fec;
    }
    {
        let mut guard = opt_params_shared.lock().unwrap_or_else(|e| e.into_inner());
        *guard = OptimizeConfig {
            pool_capacity: cfg.optimize.pool_capacity,
            block_size: cfg.optimize.block_size,
            enable_xdp: cfg.optimize.enable_xdp,
        };
    }
    {
        let mut guard = stealth_config.lock().unwrap_or_else(|e| e.into_inner());
        *guard = cfg.stealth;
        apply_runtime_stealth_overrides(
            &mut guard,
            profile,
            os,
            disable_doh,
            doh_provider,
            disable_fronting,
            front_domain,
            disable_xor,
            disable_http3,
        );
    }

    apply_transport_overrides_from_toml(cfg_path, &contents, transport);
    Ok(())
}

#[cfg(test)]
mod runtime_reload_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn write_temp_config(contents: &str) -> std::path::PathBuf {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "qf-reload-test-{}-{}-{}",
            std::process::id(),
            id,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_millis()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("server.toml");
        std::fs::write(&path, contents).expect("write config");
        path
    }

    #[test]
    fn runtime_config_reload_updates_shared_state_and_transport_overrides() {
        let cfg_path = write_temp_config(
            r#"
[fec]
mode = "manual"
initial_mode = "light"
window_good = 10
window_fair = 30
window_poor = 50

[stealth]
mode = "max"
enable_doh = true
doh_provider = "https://example.invalid/dns-query"
enable_domain_fronting = true
enable_http3_masquerading = true
enable_xor_obfuscation = true

[optimization]
memory_pool_size = 7274496

[transport]
mtu = 1400
cc_algorithm = "cubic"
enable_pacing = false
"#,
        );

        let fec_shared = Arc::new(Mutex::new(FecConfig::default()));
        let opt_shared = Arc::new(Mutex::new(OptimizeConfig::default()));
        let stealth_shared = Arc::new(Mutex::new(StealthConfig::default()));
        let mut transport = quicfuscate::transport::Config::new_with_version(
            quicfuscate::transport::PROTOCOL_VERSION,
        )
        .expect("transport config");

        // Keep runtime overrides strict to prove merge behavior.
        let front_domains = vec!["front.example".to_string()];
        apply_runtime_config_reload(
            &cfg_path,
            FecMode::Strong, // CLI override should win over config's "light"
            &mut transport,
            &fec_shared,
            &opt_shared,
            &stealth_shared,
            BrowserProfile::Chrome,
            OsProfile::MacOS,
            true, // disable DoH
            "runtime-doh",
            true, // disable fronting
            &front_domains,
            true, // disable xor
            true, // disable http3 masquerade
        )
        .expect("reload ok");

        let fec = fec_shared.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(fec.initial_mode, FecMode::Strong);

        let opt = *opt_shared.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(opt.pool_capacity, 111);
        assert_eq!(opt.block_size, 65_536);

        let sc = stealth_shared.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert_eq!(sc.initial_browser, BrowserProfile::Chrome);
        assert_eq!(sc.initial_os, OsProfile::MacOS);
        assert!(!sc.enable_doh);
        assert_eq!(sc.doh_provider, "runtime-doh");
        assert!(!sc.enable_domain_fronting);
        assert_eq!(sc.fronting_domains, front_domains);
        assert!(!sc.enable_xor_obfuscation);
        assert!(!sc.enable_http3_masquerading);

        assert_eq!(transport.max_udp_payload_size(), 1400);
        assert_eq!(
            transport.cc_algorithm(),
            quicfuscate::transport::CongestionControlAlgorithm::Cubic
        );
        assert!(!transport.pacing_enabled());
    }

    #[test]
    fn runtime_config_reload_rejects_invalid_transport_section() {
        let cfg_path = write_temp_config(
            r#"
[fec]
mode = "auto"
initial_mode = "normal"

[stealth]
mode = "auto"

[optimization]
memory_pool_size = 655360

[transport]
mtu = 100
"#,
        );

        let fec_shared = Arc::new(Mutex::new(FecConfig::default()));
        let opt_shared = Arc::new(Mutex::new(OptimizeConfig::default()));
        let stealth_shared = Arc::new(Mutex::new(StealthConfig::default()));
        let mut transport = quicfuscate::transport::Config::new_with_version(
            quicfuscate::transport::PROTOCOL_VERSION,
        )
        .expect("transport config");
        let before = transport.max_udp_payload_size();

        let err = apply_runtime_config_reload(
            &cfg_path,
            FecMode::Zero,
            &mut transport,
            &fec_shared,
            &opt_shared,
            &stealth_shared,
            BrowserProfile::Chrome,
            OsProfile::MacOS,
            false,
            "runtime-doh",
            false,
            &[],
            false,
            false,
        )
        .unwrap_err();
        assert!(err.to_ascii_lowercase().contains("transport.mtu"));
        assert_eq!(transport.max_udp_payload_size(), before);
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_server(
    listen_addr: &str,
    cert_path: &Path,
    key_path: &Path,
    profile: BrowserProfile,
    os: OsProfile,
    profile_seq: &Option<Vec<String>>,
    profile_interval: u64,
    fec_mode: FecMode,
    pool_capacity: usize,
    pool_block: usize,
    config: &Option<PathBuf>,
    fec_config: &Option<PathBuf>,
    doh_provider: &str,
    front_domain: &[String],
    disable_doh: bool,
    disable_fronting: bool,
    disable_xor: bool,
    disable_http3: bool,
    cc_algorithm: CcAlgorithm,
    tun_enable: bool,
    tun_name: Option<String>,
    tun_mtu: Option<u16>,
    tun_ip: Option<String>,
    tun_netmask: Option<String>,
    admin_socket: Option<PathBuf>,
    metrics_port: Option<u16>,
    admin_web: Option<std::net::SocketAddr>,
    admin_web_root: PathBuf,
    admin_web_user: Option<String>,
    admin_web_password: Option<String>,
    qkey_ttl_secs: Option<u64>,
    qkey_store: Option<PathBuf>,
) -> std::io::Result<()> {
    let config_path = config.as_ref();
    let admin_log_buffer = ADMIN_LOG_BUFFER.get().cloned().unwrap_or_else(|| {
        Arc::new(quicfuscate::implementations::server::admin_logs::AdminLogBuffer::new(4096))
    });

    // Apply persisted logging mode as early as possible to honor privacy expectations.
    let initial_logging_mode = config_path
        .map(|p| p.with_extension("logging.json"))
        .and_then(|p| std::fs::read_to_string(&p).ok())
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v.get("mode").and_then(|m| m.as_str().map(String::from)))
        .unwrap_or_else(|| "normal".to_string());
    match initial_logging_mode.as_str() {
        "no-log" => {
            admin_log_buffer.clear();
            log::set_max_level(log::LevelFilter::Off);
        }
        "minimal" => log::set_max_level(log::LevelFilter::Warn),
        "verbose" => log::set_max_level(log::LevelFilter::Trace),
        _ => log::set_max_level(log::LevelFilter::Info),
    }

    let std_socket = std::net::UdpSocket::bind(listen_addr)?;
    std_socket.set_nonblocking(true)?;
    let socket = tokio::net::UdpSocket::from_std(std_socket)?;
    info!("Server listening on {}", listen_addr);
    let metrics = Arc::new(Metrics::new());
    let (admin_actions_tx, mut admin_actions_rx) = mpsc::unbounded_channel::<AdminAction>();
    let mut admin_shutdown: Option<Arc<std::sync::atomic::AtomicBool>> = None;
    let mut admin_web_shutdown: Option<Arc<std::sync::atomic::AtomicBool>> = None;
    let mut metrics_shutdown: Option<Arc<std::sync::atomic::AtomicBool>> = None;

    let client_snapshots: Arc<Mutex<HashMap<std::net::SocketAddr, ClientSnapshot>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let blocked_ips_path = config_path.map(|p| p.with_extension("blocked.json"));
    let initial_blocked: std::collections::HashSet<String> = blocked_ips_path
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
        .map(|v| v.into_iter().collect())
        .unwrap_or_default();
    if !initial_blocked.is_empty() {
        log::info!("Loaded {} blocked IPs from disk", initial_blocked.len());
    }
    let blocked_ips: Arc<parking_lot::RwLock<std::collections::HashSet<String>>> =
        Arc::new(parking_lot::RwLock::new(initial_blocked));
    let qkey_ttl_secs = match qkey_ttl_secs {
        Some(0) => None,
        Some(v) => Some(v),
        None => match std::env::var("QUICFUSCATE_QKEY_TTL_SECS") {
            Ok(raw) => match raw.trim().parse::<u64>() {
                Ok(0) => None,
                Ok(v) => Some(v),
                Err(e) => {
                    log::warn!("Invalid QUICFUSCATE_QKEY_TTL_SECS '{}': {}", raw, e);
                    None
                }
            },
            Err(_) => None,
        },
    };
    let qkey_store_path = qkey_store.or_else(|| {
        config_path
            .map(|path| path.with_extension("qkeys.json"))
            .or_else(|| Some(PathBuf::from("config/local/qkeys.json")))
    });
    let qkey_registry: Arc<Mutex<QKeyRegistry>> =
        Arc::new(Mutex::new(QKeyRegistry::new(200, qkey_store_path, qkey_ttl_secs)));

    #[cfg(unix)]
    struct ServerAdminHandler {
        metrics: Arc<Metrics>,
        blocked_ips: Arc<parking_lot::RwLock<std::collections::HashSet<String>>>,
        client_snapshots: Arc<Mutex<HashMap<std::net::SocketAddr, ClientSnapshot>>>,
        actions: mpsc::UnboundedSender<AdminAction>,
        listen_addr: String,
        front_domain: Vec<String>,
        qkeys: Arc<Mutex<QKeyRegistry>>,
    }

    #[cfg(unix)]
    impl AdminHandler for ServerAdminHandler {
        fn handle_status(&self) -> AdminResponse {
            use std::sync::atomic::Ordering;
            let data = serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "uptime_secs": self.metrics.uptime_secs(),
                "clients_active": self.metrics.clients_active.load(Ordering::Relaxed),
                "clients_total": self.metrics.clients_total.load(Ordering::Relaxed),
                "bytes_in": self.metrics.bytes_in.load(Ordering::Relaxed),
                "bytes_out": self.metrics.bytes_out.load(Ordering::Relaxed),
            });
            AdminResponse::ok_with_data(data)
        }

        fn handle_list_clients(&self) -> Vec<ClientInfo> {
            let now = std::time::Instant::now();
            let guard = match self.client_snapshots.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            guard
                .iter()
                .map(|(addr, c)| ClientInfo {
                    id: addr.to_string(),
                    ip: addr.ip().to_string(),
                    remote_addr: addr.to_string(),
                    connected_secs: now.duration_since(c.connected_at).as_secs(),
                    bytes_in: c.bytes_in,
                    bytes_out: c.bytes_out,
                    stealth_mode: c.stealth_mode.clone(),
                })
                .collect()
        }

        fn handle_kick(&self, id: &str) -> AdminResponse {
            let _ = self.actions.send(AdminAction::Kick(id.to_string()));
            AdminResponse::ok_with_message(format!("Client {} scheduled for disconnect", id))
        }

        fn handle_block(&self, ip: &str) -> AdminResponse {
            self.blocked_ips.write().insert(ip.to_string());
            AdminResponse::ok_with_message(format!("IP {} blocked", ip))
        }

        fn handle_unblock(&self, ip: &str) -> AdminResponse {
            if self.blocked_ips.write().remove(ip) {
                AdminResponse::ok_with_message(format!("IP {} unblocked", ip))
            } else {
                AdminResponse::error(format!("IP {} was not blocked", ip))
            }
        }

        fn handle_reload(&self) -> AdminResponse {
            let _ = self.actions.send(AdminAction::Reload);
            AdminResponse::ok_with_message("Configuration reload scheduled")
        }

        fn handle_qkey(&self) -> String {
            use quicfuscate::engine::qkey;
            use rand::RngCore;
            let mut nonce = [0u8; 8];
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            let nonce_hex: String = nonce.iter().map(|b| format!("{:02x}", b)).collect();
            let policy = resolve_qkey_domain_fronting_policy(
                &self.front_domain,
                &self.listen_addr,
                Some(DF_SNI_MODE_AUTO_ROTATING),
                None,
                &nonce_hex,
            )
            .unwrap_or_else(|e| {
                log::warn!("QKey SNI policy fallback engaged: {}", e);
                QKeyDomainFrontingPolicy {
                    qkey_sni: BUILTIN_FRONTING_SNI_ALLOWLIST[0].to_string(),
                    extra_json: serde_json::json!({
                        "nonce": nonce_hex,
                        "df_sni_mode": DF_SNI_MODE_AUTO_ROTATING,
                        "df_sni_pool": [BUILTIN_FRONTING_SNI_ALLOWLIST[0]],
                    })
                    .to_string(),
                }
            });
            let mut token_bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut token_bytes);
            let token_hex = hex_from_bytes(&token_bytes);
            let config = qkey::QKeyConfig::new(&self.listen_addr, &policy.qkey_sni)
                .with_stealth("auto")
                .with_extra(&policy.extra_json)
                .with_token(&token_hex);
            let qkey_value = qkey::generate(&config);
            let mut registry = self.qkeys.lock().unwrap_or_else(|e| e.into_inner());
            if let Err(e) = registry.insert(qkey_value.clone(), token_hex, None) {
                log::warn!("qkey registry insert failed: {}", e);
            }
            qkey_value
        }

        fn handle_shutdown(&self) -> AdminResponse {
            let _ = self.actions.send(AdminAction::Shutdown);
            AdminResponse::ok_with_message("Shutdown scheduled")
        }
    }

    use quicfuscate::implementations::server::qkey_registry::{QKeyRecord, QKeyRegistry};

    struct ServerAdminHttpHandler {
        metrics: Arc<Metrics>,
        blocked_ips: Arc<parking_lot::RwLock<std::collections::HashSet<String>>>,
        blocked_ips_path: Option<PathBuf>,
        client_snapshots: Arc<Mutex<HashMap<std::net::SocketAddr, ClientSnapshot>>>,
        actions: mpsc::UnboundedSender<AdminAction>,
        listen_addr: String,
        front_domain: Vec<String>,
        config_path: Option<PathBuf>,
        qkeys: Arc<Mutex<QKeyRegistry>>,
        logging_mode: Arc<parking_lot::RwLock<String>>,
        log_buffer: Arc<quicfuscate::implementations::server::admin_logs::AdminLogBuffer>,
    }

    fn persist_blocked_ips(path: &Path, ips: &std::collections::HashSet<String>) {
        let mut sorted: Vec<&String> = ips.iter().collect();
        sorted.sort();
        if let Ok(bytes) = serde_json::to_vec_pretty(&sorted) {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Err(e) = atomic_write_file(path, &bytes, Some(0o600)) {
                log::warn!("blocked IPs persist failed: {}", e);
            }
        }
    }

    fn hex_from_bytes(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{:02x}", byte));
        }
        out
    }

    fn atomic_write_text(path: &Path, contents: &str, mode: Option<u32>) -> std::io::Result<()> {
        atomic_write_file(path, contents.as_bytes(), mode)
    }

    fn atomic_write_file(path: &Path, bytes: &[u8], mode: Option<u32>) -> std::io::Result<()> {
        use rand::RngCore;
        use std::fs::File;
        use std::io::Write;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut nonce = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let mut suffix = String::from(".tmp-");
        for b in nonce {
            let _ = std::fmt::Write::write_fmt(&mut suffix, format_args!("{:02x}", b));
        }

        let tmp_path = path.with_file_name(format!(
            "{}{}",
            path.file_name().and_then(|s| s.to_str()).unwrap_or("file"),
            suffix
        ));

        let mut f = File::create(&tmp_path)?;
        f.write_all(bytes)?;
        f.sync_all()?;

        std::fs::rename(&tmp_path, path)?;

        #[cfg(unix)]
        if let Some(mode) = mode {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
        }

        Ok(())
    }

    impl AdminHttpHandler for ServerAdminHttpHandler {
        fn handle_status(&self) -> AdminResponse {
            use std::sync::atomic::Ordering;
            let data = serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "uptime_secs": self.metrics.uptime_secs(),
                "clients_active": self.metrics.clients_active.load(Ordering::Relaxed),
                "clients_total": self.metrics.clients_total.load(Ordering::Relaxed),
                "bytes_in": self.metrics.bytes_in.load(Ordering::Relaxed),
                "bytes_out": self.metrics.bytes_out.load(Ordering::Relaxed),
                "listen": self.listen_addr,
                "config_writable": self.config_path.is_some(),
            });
            AdminResponse::ok_with_data(data)
        }

        fn handle_list_clients(&self) -> Vec<ClientInfo> {
            let now = std::time::Instant::now();
            let guard = match self.client_snapshots.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            guard
                .iter()
                .map(|(addr, c)| ClientInfo {
                    id: addr.to_string(),
                    ip: addr.ip().to_string(),
                    remote_addr: addr.to_string(),
                    connected_secs: now.duration_since(c.connected_at).as_secs(),
                    bytes_in: c.bytes_in,
                    bytes_out: c.bytes_out,
                    stealth_mode: c.stealth_mode.clone(),
                })
                .collect()
        }

        fn handle_kick(&self, id: &str) -> AdminResponse {
            let _ = self.actions.send(AdminAction::Kick(id.to_string()));
            AdminResponse::ok_with_message(format!("Client {} scheduled for disconnect", id))
        }

        fn handle_block(&self, ip: &str) -> AdminResponse {
            self.blocked_ips.write().insert(ip.to_string());
            if let Some(path) = self.blocked_ips_path.as_ref() {
                persist_blocked_ips(path, &self.blocked_ips.read());
            }
            AdminResponse::ok_with_message(format!("IP {} blocked", ip))
        }

        fn handle_unblock(&self, ip: &str) -> AdminResponse {
            if self.blocked_ips.write().remove(ip) {
                if let Some(path) = self.blocked_ips_path.as_ref() {
                    persist_blocked_ips(path, &self.blocked_ips.read());
                }
                AdminResponse::ok_with_message(format!("IP {} unblocked", ip))
            } else {
                AdminResponse::error(format!("IP {} was not blocked", ip))
            }
        }

        fn handle_list_blocked_ips(&self) -> AdminResponse {
            let mut ips: Vec<String> = self.blocked_ips.read().iter().cloned().collect();
            ips.sort();
            AdminResponse::ok_with_data(serde_json::json!({ "ips": ips }))
        }

        fn handle_reload(&self) -> AdminResponse {
            let _ = self.actions.send(AdminAction::Reload);
            AdminResponse::ok_with_message("Configuration reload scheduled")
        }

        fn handle_qkey(
            &self,
            req: quicfuscate::implementations::server::admin_http::IssueQKeyRequest,
        ) -> AdminResponse {
            use quicfuscate::engine::qkey;
            use rand::RngCore;
            let name =
                req.name.as_deref().map(str::trim).filter(|v| !v.is_empty()).map(str::to_string);
            if let Some(ref n) = name {
                if n.chars().count() > 64 {
                    return AdminResponse::error("QKey name too long (max 64 chars)");
                }
                if n.chars().any(|ch| ch.is_control()) {
                    return AdminResponse::error("QKey name contains invalid characters");
                }
            }
            let mut nonce = [0u8; 8];
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            let nonce_hex: String = nonce.iter().map(|b| format!("{:02x}", b)).collect();
            let sni_policy = match resolve_qkey_domain_fronting_policy(
                &self.front_domain,
                &self.listen_addr,
                req.sni_strategy.as_deref(),
                req.sni_domain.as_deref(),
                &nonce_hex,
            ) {
                Ok(v) => v,
                Err(e) => return AdminResponse::error(e),
            };
            let mut token_bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut token_bytes);
            let token_hex = hex_from_bytes(&token_bytes);
            let stealth_raw = req
                .stealth
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .unwrap_or("auto");
            let stealth = match stealth_raw.to_ascii_lowercase().as_str() {
                "auto" => "auto",
                "max" => "max",
                "manual" => "manual",
                "off" => "off",
                _ => {
                    return AdminResponse::error(
                        "Invalid stealth preset. Valid: auto, max, manual, off",
                    )
                }
            };
            let fec_raw =
                req.fec.as_deref().map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("auto");
            let fec = match fec_raw.to_ascii_lowercase().as_str() {
                "auto" => "auto",
                "on" | "manual" => "manual",
                "off" => "off",
                _ => return AdminResponse::error("Invalid fec preset. Valid: auto, on, off"),
            };
            let remote = if let Some(port) = req.port {
                let endpoint = self.listen_addr.trim();
                if endpoint.is_empty() {
                    return AdminResponse::error("Server listen address is empty");
                }
                if let Ok(sock) = endpoint.parse::<std::net::SocketAddr>() {
                    match sock {
                        std::net::SocketAddr::V4(v4) => format!("{}:{}", v4.ip(), port),
                        std::net::SocketAddr::V6(v6) => format!("[{}]:{}", v6.ip(), port),
                    }
                } else if endpoint.starts_with('[') {
                    match endpoint.find(']') {
                        Some(end) => format!("{}:{}", &endpoint[..=end], port),
                        None => return AdminResponse::error("Invalid server listen address"),
                    }
                } else if let Some((host, _)) = endpoint.rsplit_once(':') {
                    if host.is_empty() {
                        return AdminResponse::error("Invalid server listen address");
                    }
                    format!("{}:{}", host, port)
                } else {
                    format!("{}:{}", endpoint, port)
                }
            } else {
                self.listen_addr.clone()
            };
            let config = qkey::QKeyConfig::new(&remote, &sni_policy.qkey_sni)
                .with_stealth(stealth)
                .with_fec(fec)
                .with_extra(&sni_policy.extra_json)
                .with_token(&token_hex);
            let qkey_value = qkey::generate(&config);
            let mut registry = self.qkeys.lock().unwrap_or_else(|e| e.into_inner());
            let entry = match registry.insert_with_ttl(
                qkey_value.clone(),
                token_hex,
                req.ttl_seconds,
                name,
            ) {
                Ok(e) => e,
                Err(e) => return AdminResponse::error(format!("QKey store failed: {}", e)),
            };
            AdminResponse::ok_with_data(serde_json::json!({
                "qkey": qkey_value,
                "created_at": entry.created_at,
                "expires_at": entry.expires_at,
            }))
        }

        fn handle_shutdown(&self) -> AdminResponse {
            let _ = self.actions.send(AdminAction::Shutdown);
            AdminResponse::ok_with_message("Shutdown scheduled")
        }

        fn handle_list_qkeys(&self) -> AdminResponse {
            let mut registry = self.qkeys.lock().unwrap_or_else(|e| e.into_inner());
            AdminResponse::ok_with_data(serde_json::json!({ "keys": registry.list() }))
        }

        fn handle_revoke_qkey(&self, id: &str) -> AdminResponse {
            let mut registry = self.qkeys.lock().unwrap_or_else(|e| e.into_inner());
            if registry.revoke(id) {
                AdminResponse::ok_with_message("QKey revoked")
            } else {
                AdminResponse::error("QKey not found")
            }
        }

        fn handle_read_config(&self) -> AdminResponse {
            let Some(path) = self.config_path.as_ref() else {
                return AdminResponse::error("Config path not set");
            };
            match std::fs::read_to_string(path) {
                Ok(contents) => {
                    AdminResponse::ok_with_data(serde_json::json!({ "config": contents }))
                }
                Err(e) => AdminResponse::error(format!("Config read failed: {}", e)),
            }
        }

        fn handle_write_config(&self, contents: &str) -> AdminResponse {
            let Some(path) = self.config_path.as_ref() else {
                return AdminResponse::error("Config path not set");
            };
            match quicfuscate::interface::app_config::AppConfig::from_toml(contents) {
                Ok(cfg) => {
                    if let Err(e) = cfg.validate() {
                        return AdminResponse::error(format!("Config validation failed: {}", e));
                    }
                }
                Err(e) => {
                    return AdminResponse::error(format!("Config parse failed: {}", e));
                }
            };
            if let Err(e) = parse_transport_overrides_from_toml(contents) {
                return AdminResponse::error(format!("Config validation failed: {}", e));
            }
            match atomic_write_text(path, contents, Some(0o600)) {
                Ok(()) => {
                    let _ = self.actions.send(AdminAction::Reload);
                    AdminResponse::ok_with_message("Config saved and reload scheduled")
                }
                Err(e) => AdminResponse::error(format!("Config write failed: {}", e)),
            }
        }

        fn handle_metrics_text(&self) -> String {
            self.metrics.export()
        }

        fn handle_metrics_json(&self) -> AdminResponse {
            use std::sync::atomic::Ordering;
            AdminResponse::ok_with_data(serde_json::json!({
                "metrics": {
                    "quicfuscate_up": 1,
                    "quicfuscate_uptime_seconds": self.metrics.uptime_secs(),
                    "quicfuscate_clients_active": self.metrics.clients_active.load(Ordering::Relaxed),
                    "quicfuscate_clients_total": self.metrics.clients_total.load(Ordering::Relaxed),
                    "quicfuscate_connections_rejected": self.metrics.connections_rejected.load(Ordering::Relaxed),
                    "quicfuscate_bytes_in_total": self.metrics.bytes_in.load(Ordering::Relaxed),
                    "quicfuscate_bytes_out_total": self.metrics.bytes_out.load(Ordering::Relaxed),
                    "quicfuscate_packets_in_total": self.metrics.packets_in.load(Ordering::Relaxed),
                    "quicfuscate_packets_out_total": self.metrics.packets_out.load(Ordering::Relaxed),
                    "quicfuscate_stealth_http3_active": self.metrics.stealth_http3_active.load(Ordering::Relaxed),
                    "quicfuscate_stealth_tls13_active": self.metrics.stealth_tls13_active.load(Ordering::Relaxed),
                    "quicfuscate_fec_packets_encoded": self.metrics.fec_packets_encoded.load(Ordering::Relaxed),
                    "quicfuscate_fec_packets_decoded": self.metrics.fec_packets_decoded.load(Ordering::Relaxed),
                    "quicfuscate_fec_packets_recovered": self.metrics.fec_packets_recovered.load(Ordering::Relaxed),
                    "quicfuscate_auth_failed_total": self.metrics.auth_failed.load(Ordering::Relaxed),
                    "quicfuscate_rate_limited_total": self.metrics.rate_limited.load(Ordering::Relaxed),
                }
            }))
        }

        fn handle_get_logging_config(&self) -> AdminResponse {
            let mode = self.logging_mode.read();
            AdminResponse::ok_with_data(serde_json::json!({ "mode": mode.as_str() }))
        }

        fn handle_set_logging_config(&self, mode: &str) -> AdminResponse {
            let valid = ["verbose", "normal", "minimal", "no-log"];
            if !valid.contains(&mode) {
                return AdminResponse::error(format!(
                    "Invalid logging mode '{}'. Valid: {:?}",
                    mode, valid
                ));
            }
            *self.logging_mode.write() = mode.to_string();

            // Dynamically enforce log level - no-log kills ALL output
            let level = match mode {
                "no-log" => log::LevelFilter::Off,
                "minimal" => log::LevelFilter::Warn,
                "normal" => log::LevelFilter::Info,
                "verbose" => log::LevelFilter::Trace,
                _ => log::LevelFilter::Info,
            };
            log::set_max_level(level);

            if mode == "no-log" {
                self.log_buffer.clear();
            }

            // Persist to config file if available
            if let Some(path) = self.config_path.as_ref() {
                let logging_cfg_path = path.with_extension("logging.json");
                let payload = serde_json::json!({ "mode": mode });
                if let Ok(bytes) = serde_json::to_vec_pretty(&payload) {
                    if let Some(parent) = logging_cfg_path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    if let Err(e) = atomic_write_file(&logging_cfg_path, &bytes, Some(0o600)) {
                        // Only log if we're not in no-log mode (we might have just set Off)
                        if mode != "no-log" {
                            log::warn!("logging config write failed: {}", e);
                        }
                    }
                }
            }
            AdminResponse::ok_with_message(format!("Logging mode set to '{}'", mode))
        }

        fn handle_get_logs(&self, cursor: u64) -> AdminResponse {
            // In no-log mode, return empty
            let mode = self.logging_mode.read();
            let mode_str = mode.as_str();
            if mode_str == "no-log" {
                return AdminResponse::ok_with_data(serde_json::json!({
                    "lines": [],
                    "cursor": 0,
                    "mode": "no-log"
                }));
            }
            let (lines, new_cursor) = self.log_buffer.since(cursor, mode_str, 600);
            AdminResponse::ok_with_data(serde_json::json!({
                "lines": lines.iter().map(|l| serde_json::json!({
                    "ts": l.ts,
                    "level": l.level,
                    "msg": l.msg,
                })).collect::<Vec<_>>(),
                "cursor": new_cursor,
                "mode": mode_str
            }))
        }

        fn handle_clear_logs(&self) -> AdminResponse {
            self.log_buffer.clear();
            AdminResponse::ok_with_message("Logs cleared")
        }
    }

    if let Some(port) = metrics_port {
        let server = quicfuscate::implementations::server::metrics::MetricsServer::new(
            port,
            metrics.clone(),
        );
        metrics_shutdown = Some(server.shutdown_signal());
        tokio::spawn(async move {
            if let Err(e) = server.run().await {
                log::warn!("metrics server failed: {}", e);
            }
        });
    }

    #[cfg(unix)]
    if let Some(path) = admin_socket {
        let handler = ServerAdminHandler {
            metrics: metrics.clone(),
            blocked_ips: blocked_ips.clone(),
            client_snapshots: client_snapshots.clone(),
            actions: admin_actions_tx.clone(),
            listen_addr: listen_addr.to_string(),
            front_domain: front_domain.to_vec(),
            qkeys: qkey_registry.clone(),
        };
        let server = AdminServer::new(path, Arc::new(handler));
        admin_shutdown = Some(server.shutdown_signal());
        tokio::spawn(async move {
            if let Err(e) = server.run().await {
                log::warn!("admin server failed: {}", e);
            }
        });
    }
    #[cfg(not(unix))]
    let _ = admin_socket;

    if let Some(addr) = admin_web {
        let admin_user = admin_web_user
            .or_else(|| std::env::var("QUICFUSCATE_ADMIN_USER").ok())
            .and_then(|u| if u.trim().is_empty() { None } else { Some(u) })
            .unwrap_or_else(|| "admin".to_string());
        let admin_password = admin_web_password
            .or_else(|| std::env::var("QUICFUSCATE_ADMIN_PASSWORD").ok())
            .and_then(|p| if p.is_empty() { None } else { Some(p) })
            .unwrap_or_else(|| "123".to_string());
        let logging_mode = Arc::new(parking_lot::RwLock::new(initial_logging_mode));
        let handler = ServerAdminHttpHandler {
            metrics: metrics.clone(),
            blocked_ips: blocked_ips.clone(),
            blocked_ips_path: blocked_ips_path.clone(),
            client_snapshots: client_snapshots.clone(),
            actions: admin_actions_tx.clone(),
            listen_addr: listen_addr.to_string(),
            front_domain: front_domain.to_vec(),
            config_path: config_path.cloned(),
            qkeys: qkey_registry.clone(),
            logging_mode,
            log_buffer: admin_log_buffer.clone(),
        };
        let requires_password_change = admin_user == "admin" && admin_password == "123";
        let auth = AdminAuth::new(admin_user, admin_password, requires_password_change);
        let auth_path = config_path
            .and_then(|p| p.parent().map(|dir| dir.join("admin-auth.json")))
            .unwrap_or_else(|| std::path::PathBuf::from("config/local/admin-auth.json"));
        let server = AdminHttpServer::new(
            addr,
            admin_web_root,
            Some(auth),
            Some(auth_path),
            Arc::new(handler),
        );
        admin_web_shutdown = Some(server.shutdown_signal());
        std::thread::spawn(move || {
            if let Err(e) = server.run() {
                log::warn!("admin web server failed: {}", e);
            }
        });
    }

    let (mut fec_cfg, stealth_cfg, opt_cfg) = if let Some(cfg) = config_path {
        match AppConfig::from_file(cfg) {
            Ok(c) => {
                if let Err(e) = c.validate() {
                    warn!("Config validation failed: {}", e);
                }
                (c.fec, c.stealth, c.optimize)
            }
            Err(e) => {
                error!("Failed to load config {}: {}", cfg.display(), e);
                (FecConfig::default(), StealthConfig::default(), OptimizeConfig::default())
            }
        }
    } else {
        let fec = if let Some(path) = fec_config {
            match FecConfig::from_file(path) {
                Ok(cfg) => {
                    if let Err(e) = cfg.validate() {
                        warn!("FEC config validation failed: {}", e);
                    }
                    cfg
                }
                Err(e) => {
                    error!("Failed to load FEC config {}: {}", path.display(), e);
                    FecConfig::default()
                }
            }
        } else {
            FecConfig::default()
        };
        (fec, StealthConfig::default(), OptimizeConfig::default())
    };
    // Precedence: config file can specify `adaptive_fec.initial_mode`.
    // CLI `--fec-mode` overrides only when explicitly non-zero, otherwise keep config.
    if config_path.is_none() || fec_mode != FecMode::Zero {
        fec_cfg.initial_mode = fec_mode;
    }
    let fec_cfg_shared = Arc::new(Mutex::new(fec_cfg));

    let mut config = match quicfuscate::transport::Config::new_with_version(
        quicfuscate::transport::PROTOCOL_VERSION,
    ) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create server transport config: {}", e);
            return Err(std::io::Error::other("server transport config init failed"));
        }
    };
    // Apply selected congestion control algorithm
    let cca2 = match cc_algorithm {
        CcAlgorithm::Reno => quicfuscate::transport::CongestionControlAlgorithm::Reno,
        CcAlgorithm::Cubic => quicfuscate::transport::CongestionControlAlgorithm::Cubic,
        CcAlgorithm::Bbr => quicfuscate::transport::CongestionControlAlgorithm::BBR,
        CcAlgorithm::Bbr2 | CcAlgorithm::Bbr2Gcongestion => {
            quicfuscate::transport::CongestionControlAlgorithm::BBR2
        }
    };
    config.set_cc_algorithm(cca2);
    let cert_str = match cert_path.to_str() {
        Some(s) => s,
        None => {
            error!("Certificate path is not valid UTF-8: {}", cert_path.display());
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid certificate path",
            ));
        }
    };
    if let Err(e) = config.load_cert_chain_from_pem_file(cert_str) {
        error!("Failed to load server cert {}: {}", cert_path.display(), e);
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid certificate path",
        ));
    }

    let key_str = match key_path.to_str() {
        Some(s) => s,
        None => {
            error!("Private key path is not valid UTF-8: {}", key_path.display());
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid private key path",
            ));
        }
    };
    if let Err(e) = config.load_priv_key_from_pem_file(key_str) {
        error!("Failed to load server key {}: {}", key_path.display(), e);
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid private key path",
        ));
    }

    // Ensure the TLS provider uses the server's configured cert/key.
    quicfuscate::qftls::set_tls_cert_key_paths(cert_str, key_str);
    if let Err(e) =
        config.set_application_protos(&[b"hq-interop", b"h3-29", b"h3-28", b"h3-27", b"http/0.9"])
    {
        warn!("Failed to set application protos: {}", e);
    }
    config.set_max_idle_timeout(30000);
    config.set_max_recv_udp_payload_size(1460);
    config.set_max_send_udp_payload_size(1200);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);

    if let Some(cfg_path) = config_path.as_ref() {
        apply_transport_overrides_from_file(cfg_path, &mut config);
    }

    #[derive(Clone)]
    struct QKeyAuthState {
        expected_token_sha256: String,
        authed: bool,
        connected_at: std::time::Instant,
    }

    let mut clients: HashMap<std::net::SocketAddr, QuicFuscateConnection> = HashMap::new();
    let mut qkey_auth: HashMap<Vec<u8>, QKeyAuthState> = HashMap::new();
    let mut buf = [0; 65535];
    let mut out = [0; 1460];
    let stealth_config = Arc::new(Mutex::new(stealth_cfg));
    {
        let mut sc = match stealth_config.lock() {
            Ok(g) => g,
            Err(p) => {
                warn!("stealth_config mutex poisoned; recovering inner state");
                p.into_inner()
            }
        };
        apply_runtime_stealth_overrides(
            &mut sc,
            profile,
            os,
            disable_doh,
            doh_provider,
            disable_fronting,
            front_domain,
            disable_xor,
            disable_http3,
        );
    }
    let opt_params = if config_path.is_some() {
        OptimizeConfig {
            pool_capacity: opt_cfg.pool_capacity,
            block_size: opt_cfg.block_size,
            enable_xdp: opt_cfg.enable_xdp,
        }
    } else {
        OptimizeConfig { pool_capacity, block_size: pool_block, enable_xdp: false }
    };
    let opt_params_shared = Arc::new(Mutex::new(opt_params));

    let profiles: Vec<FingerprintProfile> = match profile_seq {
        Some(seq) => seq.iter().filter_map(|s| parse_profile_entry(s, os)).collect(),
        None => vec![FingerprintProfile::new(profile, os)],
    };

    if profile_interval > 0 && profiles.is_empty() {
        error!("No valid profiles supplied with --profile-seq");
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid profile sequence",
        ));
    }

    if profile_interval > 0 && profiles.len() > 1 {
        let cfg = stealth_config.clone();
        // Use a dedicated runtime for profile rotation.
        tokio::task::spawn(async move {
            let mut idx = 0usize;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(profile_interval)).await;
                idx = (idx + 1) % profiles.len();
                let mut guard = match cfg.lock() {
                    Ok(g) => g,
                    Err(p) => {
                        warn!("stealth_config mutex poisoned; recovering inner state");
                        p.into_inner()
                    }
                };
                // Apply the profile directly.
                guard.initial_browser = profiles[idx].browser;
                guard.initial_os = profiles[idx].os;
            }
        });
    }

    // Optional TUN interface for downlink frames from client
    let server_tun: Option<quicfuscate::interface::TunInterface> = if tun_enable {
        let tcfg = quicfuscate::interface::TunConfig {
            name: tun_name,
            ip: tun_ip.and_then(|s| s.parse().ok()),
            netmask: tun_netmask.and_then(|s| s.parse().ok()),
            mtu: tun_mtu.unwrap_or(1500),
            ..Default::default()
        };
        let opt_cfg = match opt_params_shared.lock() {
            Ok(g) => *g,
            Err(p) => *p.into_inner(),
        };
        let optm = OptimizationManager::from_cfg(opt_cfg);
        match quicfuscate::interface::TunInterface::open(tcfg, optm.memory_pool()) {
            Ok(t) => Some(t),
            Err(e) => {
                warn!("server TUN open failed: {:?}", e);
                None
            }
        }
    } else {
        None
    };

    let mut housekeeping = interval(Duration::from_millis(5));
    housekeeping.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            Some(action) = admin_actions_rx.recv() => {
                match action {
                    AdminAction::Kick(id) => {
                        if let Ok(addr) = id.parse::<std::net::SocketAddr>() {
                            if let Some(mut conn) = clients.remove(&addr) {
                                let conn_id = conn.conn.source_id().as_ref().to_vec();
                                let _ = conn.conn.close(true, 0x0, b"admin_kick");
                                qkey_auth.remove(&conn_id);
                            }
                            if let Ok(mut guard) = client_snapshots.lock() {
                                guard.remove(&addr);
                            }
                            metrics.clients_active.store(clients.len() as u64, Ordering::Relaxed);
                        }
                    }
                    AdminAction::Reload => {
                        if let Some(cfg_path) = config_path.as_ref() {
                            if let Err(e) = apply_runtime_config_reload(
                                cfg_path,
                                fec_mode,
                                &mut config,
                                &fec_cfg_shared,
                                &opt_params_shared,
                                &stealth_config,
                                profile,
                                os,
                                disable_doh,
                                doh_provider,
                                disable_fronting,
                                front_domain,
                                disable_xor,
                                disable_http3,
                            ) {
                                warn!("Config reload failed: {}", e);
                            }
                        } else {
                            warn!("Config reload requested but no config path is set");
                        }
                    }
                    AdminAction::Shutdown => {
                        info!("Admin shutdown requested");
                        if let Some(sig) = admin_shutdown.take() {
                            sig.store(true, Ordering::SeqCst);
                        }
                        if let Some(sig) = admin_web_shutdown.take() {
                            sig.store(true, Ordering::SeqCst);
                        }
                        if let Some(sig) = metrics_shutdown.take() {
                            sig.store(true, Ordering::SeqCst);
                        }
                        for conn in clients.values_mut() {
                            let _ = conn.conn.close(true, 0x0, b"admin_shutdown");
                        }
                        break;
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Shutdown signal received");
                if let Some(sig) = admin_shutdown.take() {
                    sig.store(true, Ordering::SeqCst);
                }
                if let Some(sig) = admin_web_shutdown.take() {
                    sig.store(true, Ordering::SeqCst);
                }
                if let Some(sig) = metrics_shutdown.take() {
                    sig.store(true, Ordering::SeqCst);
                }
                for conn in clients.values_mut() {
                    let _ = conn.conn.close(true, 0x0, b"ctrl_c");
                }
                break;
            }
            recv_res = recv_datagram_from(&socket, &mut buf) => {
                match recv_res {
                    Ok((len, from)) => {
                        telemetry!(quicfuscate::telemetry::BYTES_RECEIVED.inc_by(len as u64));
                        metrics.bytes_in.fetch_add(len as u64, Ordering::Relaxed);
                        metrics.packets_in.fetch_add(1, Ordering::Relaxed);

                        let ip_str = from.ip().to_string();
                        if blocked_ips.read().contains(&ip_str) {
                            metrics.connections_rejected.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }

                        // Best-effort path-churn handling: if packets arrive from a new source
                        // address but carry a DCID that maps to an existing connection, re-key
                        // the runtime maps from old address to the new one.
                        if !clients.contains_key(&from) {
                            let migrated_from = quicfuscate::transport::packet::parse_header(
                                &buf[..len],
                                0,
                            )
                            .ok()
                            .and_then(|(hdr, _)| {
                                clients.iter().find_map(|(addr, conn)| {
                                    if conn.conn.source_id().as_ref() == hdr.dcid.as_slice() {
                                        Some(*addr)
                                    } else {
                                        None
                                    }
                                })
                            });
                            if let Some(old_addr) = migrated_from {
                                if old_addr != from {
                                    if let Some(conn) = clients.remove(&old_addr) {
                                        clients.insert(from, conn);
                                    }
                                    if let Ok(mut guard) = client_snapshots.lock() {
                                        if let Some(snapshot) = guard.remove(&old_addr) {
                                            guard.insert(from, snapshot);
                                        }
                                    }
                                    quicfuscate::telemetry::QKEY_PATH_REBIND_TOTAL.inc();
                                    info!("Client path updated: {} -> {}", old_addr, from);
                                }
                            }
                        }

                        use std::collections::hash_map::Entry;
                        let mut clients_len = clients.len();
                        let conn = match clients.entry(from) {
                            Entry::Occupied(entry) => entry.into_mut(),
                            Entry::Vacant(entry) => {
                                // New connection must start with an Initial carrying the client's ODCID.
                                // We need the ODCID for RFC 9001 Initial key derivation and, if enabled,
                                // the token for QKey selection.
                                let (mut initial_hdr, _) = match quicfuscate::transport::packet::parse_header(&buf[..len], 0) {
                                    Ok(v) => v,
                                    Err(_) => {
                                        metrics.connections_rejected.fetch_add(1, Ordering::Relaxed);
                                        continue;
                                    }
                                };
                                if initial_hdr.ty != quicfuscate::transport::packet::PacketType::Initial {
                                    metrics.connections_rejected.fetch_add(1, Ordering::Relaxed);
                                    continue;
                                }
                                let odcid = quicfuscate::transport::ConnectionId::from_vec(
                                    std::mem::take(&mut initial_hdr.dcid),
                                );
                                let initial_token = initial_hdr.token.take();

                                let require_qkey = require_qkey_for_new_clients({
                                    let mut registry =
                                        qkey_registry.lock().unwrap_or_else(|e| e.into_inner());
                                    registry.has_entries()
                                });
                                let mut qkey_record: Option<QKeyRecord> = None;
                                let mut pending_qkey_auth_state: Option<QKeyAuthState> = None;
                                if require_qkey {
                                    let token = match initial_token {
                                        Some(token) if !token.is_empty() => token,
                                        _ => {
                                            metrics.connections_rejected.fetch_add(1, Ordering::Relaxed);
                                            continue;
                                        }
                                    };
                                        let record = {
                                            let mut registry = qkey_registry.lock().unwrap_or_else(|e| e.into_inner());
                                            registry.lookup_initial_id_token(&token)
                                        };
                                    let Some(record) = record else {
                                        metrics.connections_rejected.fetch_add(1, Ordering::Relaxed);
                                        continue;
                                    };
                                    pending_qkey_auth_state = Some(QKeyAuthState {
                                        expected_token_sha256: record.token_sha256.clone(),
                                        authed: false,
                                        connected_at: std::time::Instant::now(),
                                    });
                                    qkey_record = Some(record);
                                }
                                info!("New client connected: {}", from);
                                // Each server connection should use a fresh, unpredictable SCID.
                                let mut scid_bytes = [0u8; quicfuscate::transport::MAX_CONN_ID_LEN];
                                quicfuscate::transport::rand::rand_bytes(&mut scid_bytes);
                                let scid = quicfuscate::transport::ConnectionId::from_ref(&scid_bytes);
                                let cfg = match stealth_config.lock() {
                                    Ok(g) => g,
                                    Err(p) => {
                                        warn!(
                                            "stealth_config mutex poisoned; recovering inner state"
                                        );
                                        p.into_inner()
                                    }
                                }
                                .clone();
                                let mut conn_stealth_cfg = cfg;
                                let mut conn_fec_cfg = match fec_cfg_shared.lock() {
                                    Ok(g) => g.clone(),
                                    Err(p) => p.into_inner().clone(),
                                };
                                if let Some(ref record) = qkey_record {
                                    // Enforce server-side policy from the issued key.
                                    if let Some(mode_raw) = record.stealth.as_deref() {
                                        let m = mode_raw.trim().to_ascii_lowercase();
                                        let mapped = match m.as_str() {
                                            "off" => Some(quicfuscate::stealth::StealthMode::Off),
                                            "max" => Some(quicfuscate::stealth::StealthMode::AntiDpi),
                                            "manual" => Some(quicfuscate::stealth::StealthMode::Manual),
                                            _ => None,
                                        };
                                        if let Some(mapped) = mapped {
                                            conn_stealth_cfg.mode = mapped;
                                            apply_runtime_stealth_overrides(
                                                &mut conn_stealth_cfg,
                                                profile,
                                                os,
                                                disable_doh,
                                                doh_provider,
                                                disable_fronting,
                                                front_domain,
                                                disable_xor,
                                                disable_http3,
                                            );
                                        }
                                    }
                                    if let Some(fec_raw) = record.fec.as_deref() {
                                        // QKey "manual" is treated as "FEC On" with robust defaults.
                                        if fec_raw.trim().eq_ignore_ascii_case("manual") {
                                            conn_fec_cfg.initial_mode = quicfuscate::fec::FecMode::Normal;
                                            conn_fec_cfg.force_on = true;
                                        }
                                    }
                                }
                                    match QuicFuscateConnection::new_server(
                                    &scid,
                                    Some(&odcid),
                                    socket.local_addr().unwrap_or_else(|e| {
                                        error!(
                                            "socket.local_addr() failed: {} - using unspecified address",
                                            e
                                        );
                                        std::net::SocketAddr::from(([0, 0, 0, 0], 0))
                                    }),
                                    from,
                                    &mut config,
                                    conn_stealth_cfg,
                                    conn_fec_cfg,
                                    match opt_params_shared.lock() {
                                        Ok(g) => *g,
                                        Err(p) => *p.into_inner(),
                                    },
                                ) {
                                    Ok(conn) => {
                                        metrics.clients_total.fetch_add(1, Ordering::Relaxed);
                                        clients_len += 1;
                                        if let Some(state) = pending_qkey_auth_state.take() {
                                            let conn_id = conn.conn.source_id().as_ref().to_vec();
                                            qkey_auth.insert(conn_id, state);
                                        }
                                        entry.insert(conn)
                                    }
                                    Err(e) => {
                                        error!("failed to create server connection: {}", e);
                                        continue;
                                    }
                                }
                            }
                        };
                        metrics.clients_active.store(clients_len as u64, Ordering::Relaxed);

                            {
                                let mut snapshots_guard = match client_snapshots.lock() {
                                    Ok(g) => g,
                                    Err(p) => p.into_inner(),
                                };
                                let snap =
                                    snapshots_guard.entry(from).or_insert_with(|| ClientSnapshot {
                                        connected_at: std::time::Instant::now(),
                                        bytes_in: 0,
                                        bytes_out: 0,
                                        stealth_mode: format!("{:?}", conn.stealth_mode()),
                                    });
                                snap.bytes_in = snap.bytes_in.saturating_add(len as u64);
                                snap.stealth_mode = format!("{:?}", conn.stealth_mode());
                            }

                        if let Err(e) = conn.recv(&buf[..len]) {
                            error!("QUIC recv failed: {:?}", e);
                        }

                            // HTTP/3: always poll and, if a QKey is required, enforce auth via an
                            // encrypted header (post-handshake).
                            let tun_ref = server_tun.as_ref();
                            let conn_id = conn.conn.source_id().as_ref().to_vec();
                            let require_auth = qkey_auth.contains_key(&conn_id);
                            let qkey_auth_view = &qkey_auth;
                            let authed =
                                Cell::new(qkey_auth.get(&conn_id).map(|s| s.authed).unwrap_or(true));
                            let should_close: Cell<Option<&'static [u8]>> = Cell::new(None);

                            let _ = conn.poll_http3_with_headers(
                                |_sid, headers| {
                                    let Some(expected) = qkey_auth_view
                                        .get(&conn_id)
                                        .map(|s| s.expected_token_sha256.as_str())
                                    else {
                                        return;
                                    };
                                    if authed.get() {
                                        return;
                                    }
                                    let mut provided: Option<&[u8]> = None;
                                    for h in headers {
                                        if h.name().eq_ignore_ascii_case(b"x-qf-auth") {
                                            provided = Some(h.value());
                                            break;
                                        }
                                    }
                                    let Some(provided) = provided else {
                                        should_close.set(Some(b"missing_qkey_auth"));
                                        return;
                                    };
                                    let provided = match std::str::from_utf8(provided) {
                                        Ok(s) => s.trim(),
                                        Err(_) => {
                                            should_close.set(Some(b"invalid_qkey_auth"));
                                            return;
                                        }
                                    };
                                    let provided_hash = match quicfuscate::implementations::server::qkey_registry::token_sha256_hex_from_token_hex(provided) {
                                        Some(h) => h,
                                        None => {
                                            should_close.set(Some(b"invalid_qkey_auth"));
                                            return;
                                        }
                                    };
                                    if provided_hash.eq_ignore_ascii_case(expected.trim()) {
                                        authed.set(true);
                                    } else {
                                        should_close.set(Some(b"invalid_qkey_auth"));
                                    }
                                },
                                |_sid, data| {
                                    // If a QKey is required, do not forward anything until authed.
                                    if require_auth && !authed.get() {
                                        return;
                                    }
                                    if tun_enable {
                                        if let Some(t) = tun_ref {
                                            let _ = t.write(data);
                                        }
                                    }
                                },
                            );

                            if require_auth {
                                if let Some(state) = qkey_auth.get_mut(&conn_id) {
                                    state.authed = authed.get();
                                }
                            }

                            if let Some(reason) = should_close.get() {
                                metrics.connections_rejected.fetch_add(1, Ordering::Relaxed);
                                quicfuscate::telemetry::QKEY_AUTH_FAIL_TOTAL.inc();
                                let _ = conn.conn.close(true, 0x0, reason);
                                qkey_auth.remove(&conn_id);
                            }

                            match flush_server_outgoing(&socket, &from, conn, &mut out, &metrics).await
                            {
                            Ok((bytes_out, _packets_out)) => {
                                if bytes_out > 0 {
                                    if let Ok(mut guard) = client_snapshots.lock() {
                                        if let Some(snap) = guard.get_mut(&from) {
                                            snap.bytes_out = snap.bytes_out.saturating_add(bytes_out);
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Failed to send packet to {}: {}", from, e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to read from socket: {}", e);
                    }
                }
            }
                _ = housekeeping.tick() => {
                    let addresses: Vec<_> = clients.keys().cloned().collect();
                    for addr in addresses {
                        if let Some(conn) = clients.get_mut(&addr) {
                        match flush_server_outgoing(&socket, &addr, conn, &mut out, &metrics).await {
                            Ok((bytes_out, _packets_out)) => {
                                if bytes_out > 0 {
                                    if let Ok(mut guard) = client_snapshots.lock() {
                                        if let Some(snap) = guard.get_mut(&addr) {
                                            snap.bytes_out = snap.bytes_out.saturating_add(bytes_out);
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Failed to flush packets to {}: {}", addr, e);
                            }
                        }
                        conn.update_state();
                        info!(
                            "client {} stats: RTT {:.0} ms, Loss {:.2}%",
                            addr,
                            conn.rtt_ms(),
                            conn.loss_rate() * 100.0
                        );
                            conn.conn.on_timeout();
                        }
                    }
                    // Enforce a strict QKey auth deadline for connections that require it.
                    // The public QKey id is visible in the Initial header, but the secret token must
                    // be provided post-handshake via encrypted HTTP/3 headers.
                    {
                        let mut timed_out_conn_ids: Vec<Vec<u8>> = Vec::new();
                        for conn in clients.values() {
                            let conn_id = conn.conn.source_id().as_ref().to_vec();
                            if let Some(state) = qkey_auth.get(&conn_id) {
                                if !state.authed
                                    && state.connected_at.elapsed() > Duration::from_secs(5)
                                {
                                    timed_out_conn_ids.push(conn_id);
                                }
                            }
                        }
                        for conn_id in timed_out_conn_ids {
                            for conn in clients.values_mut() {
                                if conn.conn.source_id().as_ref() == conn_id.as_slice() {
                                    metrics.connections_rejected.fetch_add(1, Ordering::Relaxed);
                                    quicfuscate::telemetry::QKEY_AUTH_FAIL_TOTAL.inc();
                                    let _ = conn.conn.close(true, 0x0, b"qkey_auth_timeout");
                                    break;
                                }
                            }
                            qkey_auth.remove(&conn_id);
                        }
                    }
                    clients.retain(|_, conn| !conn.conn.is_closed());
                    qkey_auth.retain(|conn_id, _| {
                        clients
                            .values()
                            .any(|conn| conn.conn.source_id().as_ref() == conn_id.as_slice())
                    });
                    metrics.clients_active.store(clients.len() as u64, Ordering::Relaxed);
                    if let Ok(mut guard) = client_snapshots.lock() {
                        guard.retain(|addr, _| clients.contains_key(addr));
                    }
                    tokio::task::yield_now().await;
                }
        }
    }

    Ok(())
}
