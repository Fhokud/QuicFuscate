use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use quicfuscate::brain::{StealthBrain, StealthBrainConfig};
use quicfuscate::transport::TransportObserver;
use quicfuscate::transport::{self, packet};

fn main() {
    // Initialize env_logger if present to show trace/info logs
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace"))
        .try_init();

    // Build a minimal QUIC connection to pass into Brain
    let (local, peer) = (
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 44330),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 44331),
    );
    let mut cfg = transport::Config::new_with_version(1).expect("config");
    let scid = transport::ConnectionId::from_ref(&[0; transport::MAX_CONN_ID_LEN]);
    let mut conn =
        packet::connect(Some("example"), scid.as_ref(), local, peer, &mut cfg).expect("connect");

    // Parse CLI args (very simple)
    let mut iters: usize = 50;
    let mut sleep_ms: u64 = 10;
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i + 1 < args.len() {
        match args[i].as_str() {
            "--iters" => {
                iters = args[i + 1].parse().unwrap_or(iters);
                i += 2;
            }
            "--jitter" => {
                // e.g., 5ms
                let s = &args[i + 1];
                if s.ends_with("ms") {
                    sleep_ms = s.trim_end_matches("ms").parse().unwrap_or(sleep_ms);
                }
                i += 2;
            }
            _ => {
                i += 1;
            }
        }
    }

    let brain_cfg = StealthBrainConfig::from_env();
    let brain = StealthBrain::new(brain_cfg);

    // Synthetic telemetry loop: feed acks and ECN deltas, then let policy apply
    for step in 0..iters {
        let ack_delay_us = 1000 + ((step * 73) % 7000) as u64; // vary a bit
        brain.on_ack(ack_delay_us, &[]);

        let ect0 = (step as u64) % 5;
        let ect1 = 0;
        let ce = if step % 10 == 0 { 1 } else { 0 };
        brain.on_ecn_update(ect0, ect1, ce);

        // This will emit a trace! line with policy summary (ack_thr, pacing, ivl, jitter, etc.)
        brain.apply_policy(&mut conn);

        std::thread::sleep(Duration::from_millis(sleep_ms));
    }

    println!("DONE brain_probe");
}
