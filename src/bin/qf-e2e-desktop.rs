//! Headless desktop-style E2E client.
//!
//! Uses the EngineConfig path (same as GUI) to validate QKey parsing,
//! token propagation, connect, stats snapshot, and clean disconnect.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use quicfuscate::engine::{
    qkey, EngineConfig, EngineState, FecMode, QuicFuscateEngine, StealthMode,
};
use quicfuscate::interface::{register_tun_factory, TunConfig, TunDevice};

fn parse_args() -> Result<(String, u64, u64, bool), String> {
    let mut qkey_value: Option<String> = None;
    let mut timeout_ms: u64 = 8000;
    let mut hold_ms: u64 = 1500;
    let mut no_tun = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--qkey" => qkey_value = args.next(),
            "--timeout-ms" => {
                if let Some(v) = args.next() {
                    timeout_ms = v.parse::<u64>().unwrap_or(timeout_ms);
                }
            }
            "--hold-ms" => {
                if let Some(v) = args.next() {
                    hold_ms = v.parse::<u64>().unwrap_or(hold_ms);
                }
            }
            "--no-tun" => {
                no_tun = true;
            }
            "--help" | "-h" => {
                println!(
                    "Usage: qf-e2e-desktop --qkey QKEY [--timeout-ms MS] [--hold-ms MS] [--no-tun]"
                );
                std::process::exit(0);
            }
            other => return Err(format!("Unknown arg: {other}")),
        }
    }

    let qkey_value = qkey_value.ok_or_else(|| "missing --qkey".to_string())?;
    Ok((qkey_value, timeout_ms, hold_ms, no_tun))
}

fn map_stealth_mode(value: &str) -> StealthMode {
    match value.trim().to_ascii_lowercase().as_str() {
        "off" => StealthMode::Off,
        "max" | "anti-dpi" | "antidpi" => StealthMode::Max,
        "manual" => StealthMode::Manual,
        _ => StealthMode::Auto,
    }
}

fn map_fec_mode(value: &str) -> FecMode {
    match value.trim().to_ascii_lowercase().as_str() {
        "off" => FecMode::Off,
        "manual" => FecMode::Manual,
        _ => FecMode::Auto,
    }
}

struct NullTun {
    name: String,
    mtu: u16,
    next_emit: Mutex<Instant>,
}

impl TunDevice for NullTun {
    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }

    fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let now = Instant::now();
        let mut next_emit = match self.next_emit.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if now >= *next_emit {
            let probe = b"qf-e2e-desktop-no-tun-probe";
            let len = probe.len().min(buf.len());
            buf[..len].copy_from_slice(&probe[..len]);
            *next_emit = now + Duration::from_millis(10);
            return Ok(len);
        }
        Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, "no-tun mode"))
    }

    fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (qkey_value, timeout_ms, hold_ms, no_tun) = parse_args().map_err(|e| {
        eprintln!("{e}");
        e
    })?;

    if no_tun {
        let _ = register_tun_factory(Box::new(|cfg: &TunConfig| {
            let name = cfg.name.clone().unwrap_or_else(|| "qf-null0".to_string());
            Ok(Box::new(NullTun { name, mtu: cfg.mtu, next_emit: Mutex::new(Instant::now()) }))
        }));
    }

    let qk = qkey::parse(&qkey_value).map_err(|e| format!("QKey parse failed: {e}"))?;

    let mut cfg = EngineConfig::default();
    cfg.connection.remote = qk.remote.clone();
    cfg.connection.sni = qk.sni.clone();
    cfg.connection.qkey_token = qk.token.clone();
    cfg.connection.qkey_id = Some(qkey::id(&qkey_value));

    if let Some(ref stealth) = qk.stealth {
        cfg.stealth.mode = map_stealth_mode(stealth);
    }
    if let Some(ref fec) = qk.fec {
        cfg.fec.mode = map_fec_mode(fec);
    }

    let mut engine = QuicFuscateEngine::new(cfg).map_err(|e| format!("engine init failed: {e}"))?;
    if let Err(e) = engine.start() {
        let msg = format!("{e}");
        if msg.contains("PermissionDenied") || msg.contains("Operation not permitted") {
            eprintln!("SKIP: TUN permission denied");
            std::process::exit(2);
        }
        return Err(format!("engine start failed: {msg}").into());
    }
    engine.connect().map_err(|e| format!("engine connect failed: {e}"))?;

    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    while engine.state() != EngineState::Connected {
        if Instant::now() > deadline {
            return Err(format!("timeout waiting for connected state ({timeout_ms}ms)").into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let stats = engine.stats();
    println!(
        "connected bytes_sent={} packets_sent={} bytes_received={} packets_received={}",
        stats.bytes_sent, stats.packets_sent, stats.bytes_received, stats.packets_received
    );

    if hold_ms > 0 {
        std::thread::sleep(Duration::from_millis(hold_ms));
    }

    engine.disconnect().map_err(|e| format!("engine disconnect failed: {e}"))?;
    engine.stop().map_err(|e| format!("engine stop failed: {e}"))?;
    println!("disconnected");
    Ok(())
}
