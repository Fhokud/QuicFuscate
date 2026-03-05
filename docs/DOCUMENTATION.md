# QuicFuscate Technical Documentation

**Status**: This document is the canonical technical reference and reflects the current runtime behavior.

## Introduction & Purpose
QuicFuscate is a high-performance QUIC-based VPN designed for strong censorship resilience. By combining modern transport, cryptography, hybrid adaptive forward error correction (FEC), and a cohesive stealth stack, the system delivers reliable, high-throughput connectivity under adversarial network conditions.

This document provides comprehensive technical documentation for the system architecture, modules, and implementation details in Rust.

### Quick Index (Fast Paths)
- Runtime architecture and module map: [Architecture at a Glance](#architecture-at-a-glance)
- Stealth behavior and mode matrix: [Obfuscation-Modes Overview](#obfuscation-modes-overview)
- TLS provider behavior and controls: [Unified TLS Provider (RealTLS + TLS Cover)](#unified-tls-provider-realtls--tls-cover)
- FEC runtime controls and tuning: [FEC Operations Guide](#fec-operations-guide)
- CLI operation and server/client flows: [Usage](#usage)
- Full config schema and env overrides: [Configuration Reference (Full)](#configuration-reference-full)
- Embedded API contracts: [Engine Control Plane (embedded orchestration)](#engine-control-plane-embedded-orchestration)
- Script entrypoints and suites: [Scripts Reference (Authoritative)](#scripts-reference-authoritative)

### Architecture at a Glance
- Modular Rust crate with focused modules:
  - `src/core.rs`: QUIC I/O and session management; maintains rolling `ConnectionStats` including VNNI-accelerated congestion aggregation (`aggregate_congestion`) for cwnd, bytes-in-flight and loss score.
  - `src/crypto.rs`: AEAD and handshake glue
  - `src/fec.rs`: Encoder/decoder/adaptive/GF tables
  - `src/stealth.rs`: DoH, HTTP/3 masquerading, TLS Cover, domain fronting, QPACK helpers, active probe detection, runtime Server Push cover coordination
  - `src/reality.rs`: Reality Fallback (Xray-style reverse proxy for active probe mitigation)
  - `src/interface.rs`: Cross-platform TUN interface
  - `src/transport.rs`: Transport module root with focused submodules in `src/transport/` (packet, recovery, io_uring, frames, h3, xdp, udpfast, connection)
  - HTTP/3 streams: `fin_received` flag tracks stream completion for deterministic GC in `poll()`
  - UDP fast paths: GSO/GRO on Linux, sendmmsg/recvmmsg batching (Linux) + sendmsg_x batching (macOS), MSG_ZEROCOPY with completion tracking
  - `src/brain.rs`: StealthBrain adaptive policy engine (ACK/timing/padding/FEC/MASQUE hints) and transport observer
- `src/profile.rs`: Public `Aegis128Profile` adapter mapped to `simd::CryptoAeadPlan`
  - `src/engine/`: Embedded control plane (`QuicFuscateEngine`, `EngineConfig`, `EngineCommand`, `EngineEvent`, `EngineStats`) for programmatic runtime orchestration
  - `src/compress.rs`: Compression manager (zstd-only) with adaptive policy, telemetry-backed decisions, and optional dictionaries
  - `src/qftls.rs`: Unified TLS provider combining RealTLS (rustls) and TLS Cover
  - `src/instrumentation.rs`: Global runtime metrics and health export surfaces (`/metrics`, `/health`)
  - `src/implementations/server/metrics.rs`: Server metrics runtime and HTTP endpoint wiring
  - `src/optimize/`: Optimization submodules now live under `src/optimize/*` and are re-exported through `src/accelerate.rs` to keep the public `accelerate::*` API stable.
  - TLS fingerprint sourcing follows the canonical "Unified TLS Provider (RealTLS + TLS Cover) -> Fingerprint Source Model".
  - Unified configuration via `config/quicfuscate.toml`; environment overrides through `QUICFUSCATE_*`
  - Modular script-based architecture with dedicated scripts for each functionality
- Organized script directories: `scripts/tests/build/`, `scripts/benchmarks/`, `scripts/tests/audits/`, `scripts/tests/`, `scripts/tests/utils/`, `scripts/tests/analysis/`, `scripts/tests/lib/`
- Individual scripts for specific tasks: build management, benchmarking, testing, auditing, and utilities

- Developer Harness: `src/harness.rs` provides a central CLI used by scripts. Unit tests still exist in the codebase, but the harness is the main entry point for scripted internal tooling.
- Desktop App: `apps/desktop` (Tauri 2 + React/TypeScript + HeroUI + Jotai + Framer Motion) provides the native desktop client with tunnel management, settings, logs, and hardware detection. State is persisted via Tauri `invoke` commands with debounced writes.
- Web admin: `apps/web-admin-ui` (React + HeroUI + Jotai + Framer Motion) builds into `assets/web-admin/` via `scripts/build/build-web-admin.sh`. Provides dashboard, configuration, QKey management, and logging views.
- QKey: server-issued connection key string (`QKey-...`) that embeds connection parameters (remote, SNI), optional policy presets (stealth/FEC), and a bearer token. QKeys are generated in the Web Admin UI and must be treated like passwords.
- Admin control plane: `src/implementations/server/admin_http.rs` and `src/implementations/server/qkey_registry.rs` provide server-authoritative QKey issuance/revocation, persistence, and runtime policy enforcement surfaces.
- Desktop: imports QKeys (paste/import), persists them per tunnel locally, and uses them for connect/disconnect. The desktop UI does not generate server-issued QKeys and does not render them after import.

#### Engine Control Plane (embedded orchestration)
`quicfuscate::engine::QuicFuscateEngine` is the canonical embedding entrypoint for non-CLI integrations. It owns the aggregated `EngineConfig`, selects `ClientRuntime` or `ServerRuntime` via `engine.mode`, tracks lifecycle in `EngineState`, and emits `EngineStats` snapshots for host applications.

Control and observability are explicit through typed channels:

- `EngineCommand`: `Start`, `Stop`, `Connect`, `Disconnect`, `Reconnect`, runtime overrides (`SetStealthMode`, `SetFecMode`, `SetCongestionControl`, `SetTrafficPadding`, `SetTimingObfuscation`, `SetZeroRtt`), and diagnostics/state queries (`GetTunCapabilities`, `GetState`, `GetStats`).
- `EngineEvent`: `StateChanged`, `Connected`, `Disconnected`, `Error`, `StatsUpdated`, `StealthEscalated`.

This keeps CLI and embedded control planes aligned on one runtime mutation path.

### Cohesive Stealth Stack (Hard to Classify)
All stealth components share one active browser/OS profile for coherence. The active profile can be rotated on an interval using `--profile-seq` and `--profile-interval`:
- TLS: RealTLS via rustls with optional TLS Cover that generates byte-perfect ClientHello templates and TLS frames from the active profile (no external uTLS/FFI)
- HTTP/3/QPACK: ALPN, header sets, and framing align with common web traffic patterns
- Domain Fronting: decouples visible SNI from origin; rotations across vetted front domains diversify exposure
- DoH and XOR Obfuscation: hides DNS lookups and disrupts payload regularity post-encryption
- Active Probe Detection + Reality Fallback: probe-like traffic is detected and, when required, relayed via `RealityProxy` to preserve realistic upstream behavior under active scanning
- Server Push Cover Traffic: profile-coherent HTTP/3 PUSH_PROMISE and DATA bursts are emitted with runtime intensity controls during stealth escalation
- StealthBrain Coordination: telemetry-driven policy updates synchronize ACK strategy, timing gates, padding behavior, MASQUE preference, and FEC hints
This unity yields a homogeneous, believable fingerprint that remains difficult to reliably classify by DPI systems.

#### Stealth Padding & Timing Obfuscation
- Padding is applied just before AEAD sealing in `transport::Connection::send()` to ensure full authentication and confidentiality.
- Strategies (configurable via `StealthConfig` -> wired into `transport::Config.set_stealth_padding`):
  - Random (0..=max), Fixed (up to `max`), Adaptive (to next 64-byte boundary), BrowserMimic (small skew up to ~`max/4`).
- Mode defaults:
  - Stealth: Adaptive with a small cap (`max_padding_size = 86`) - low overhead, smooths packet sizes.
  - Anti-DPI: BrowserMimic with larger cap (`max_padding_size = 256`).
- Timing obfuscation (Anti-DPI default): per-packet random jitter (us) gated in `transport::Config.set_stealth_timing`; enforced as a send gate in `Connection::send()`.
- Hardware integration: On GFNI-capable x86 policies, `accelerate::stealth::add_tls_padding` activates a GFNI-based padding generator that also feeds `StealthManager::apply_padding`; fallbacks (AVX2/SSE2/Scalar) remain unchanged and telemetry (`STEALTH_PADDING_GFNI_OPS`) counts the generated bytes.

#### HTTP/3 Client Hints & sec-fetch
- `stealth::Http3Masquerade` emits realistic `sec-ch-ua`, `sec-ch-ua-platform`, `sec-ch-ua-mobile` and navigation headers `sec-fetch-{dest,mode,site,user}` plus `upgrade-insecure-requests: 1`.
- `sec-ch-ua` major versions are derived from the active `User-Agent` to maintain internal consistency per browser/OS profile.

### Unified TLS Provider (RealTLS + TLS Cover)
- Real TLS: implemented via rustls in `src/qftls.rs` with `CombinedProvider` orchestrating both RealTLS and TLS Cover - supports `--verify-peer`, `--ca-file`, and ALPN negotiation for HTTP/3.
- TLS Cover: cover provider in `qftls::CombinedProvider` is enabled by default and can be disabled with `QUICFUSCATE_TLS_COVER=0`. `StealthConfig.use_tls_cover` (TOML alias: `use_tls_cover_extras`) enables TLS Cover extras in the stealth manager (ticket manager and cert chain emulator) but does not control the cover provider. Cipher selection is automatic (`auto`) and prefers AES-128-GCM when hardware AES (AESNI/VAES/SVE AES) is available, otherwise falls back to ChaCha20-Poly1305. On x86 the ChaCha keystream dispatches AVX-512 -> AVX2 -> AVX -> SSE4.1/SSSE3 -> Scalar with telemetry (`CHACHA20_X4_AVX2_OPS`, `CHACHA20_X4_AVX_OPS`, `CHACHA20_X4_SSE41_OPS`, `CHACHA20_X4_SCALAR_OPS`). Override via `QUICFUSCATE_TLS_COVER_CIPHER=auto|chacha|aes`.
- Unification: `qftls::CombinedProvider` manages a single interface that can overlay TLS Cover on top of RealTLS negotiation, preserving wire realism while retaining security semantics.
- Risk/Tradeoff: enabling TLS Cover increases cover-byte volume and per-packet processing work.
- Certificate tooling: development certificates enabled by feature `dev-certs` (rcgen); production uses PEM chain via `--cert/--key` (server) and CA bundle via `--ca-file` (client).
- Session management: internal session cache for 0-RTT resumption (size-limited, not user-configurable).
  - Risk/Tradeoff: 0-RTT can permit replay of early data; restrict to idempotent operations.

#### Fingerprint Source Model
- Primary runtime path: deterministic in-memory ClientHello synthesis via `TlsClientHelloSpoofer` from `BrowserProfile` and `OsProfile`.
- Optional external path: top-level `browser_profiles/*.chlo` or `*.chlo.b64` dumps for strict byte-level replay and audit/regression workflows.
- Injection path: selected ClientHello bytes are injected natively through transport configuration (`set_custom_tls`) and then cached in memory.
- Operational rule: external dumps are optional; runtime operation remains available without on-disk profile artifacts.

#### Environment Controls
- `QUICFUSCATE_TLS_COVER=0|1` - enable or disable the TLS Cover provider in `qftls` (default: enabled, set to `0` to disable).
- `QUICFUSCATE_USE_TLS_COVER_EXTRAS=0|1` (alias: `QUICFUSCATE_USE_TLS_COVER`) - enable TLS Cover extras in `StealthManager` (ticket manager and cert emulator); does not control the cover provider (default follows active stealth preset: on for `off|performance|base|stealth|anti-dpi|intelligent`, off for `manual` unless explicitly set).
- `QUICFUSCATE_STEALTH_MODE=off|performance|base|stealth|anti-dpi|intelligent|manual` - selects the stealth baseline; `qftls` uses it to run TLS Cover in performance mode for `off|performance|base`.
- `QUICFUSCATE_TLS_COVER_PROFILE=chrome|firefox|safari|edge|random` - select TLS Cover browser profile.
- `QUICFUSCATE_TLS_COVER_CIPHER=auto|chacha|aes` - control TLS Cover cipher (auto prefers AES-128-GCM when hardware AES is detected, else ChaCha20-Poly1305).
- `QUICFUSCATE_TLS_COVER_ULTRA=1` - enable the ultra TLS Cover profile variant (ECH-grease and padding).
- `QUICFUSCATE_TLS_COVER_ROTATE=1` - currently log-only (no rotation implementation).
- `QUICFUSCATE_TLS_COVER_TELEMETRY=1` - currently log-only (no extra telemetry output).
- `QUICFUSCATE_CHACHA20_X4=auto|avx2|avx|sse|scalar` - override the TLS Cover ChaCha20 backend for diagnostics.
- `QUICFUSCATE_PQ_HYBRID=1` - PQ-hybrid toggle; inactive in the standard build unless a dedicated `pq` feature build is enabled.
- `QUICFUSCATE_ALLOW_INVALID_CERTS=1|true|yes|on` - accept invalid peer certificates (development/testing only).
- `QUICFUSCATE_TLS_CH_OVERRIDE_TEMPLATE=<name>` - forward a ClientHello override template to TLS providers that support CH overrides.
- `QUICFUSCATE_TRACE_TLS=1` - enable additional TLS handshake/key-change diagnostic logging in qftls and transport packet parsing.

Example (RealTLS configuration)
```rust
use quicfuscate::transport::Config;

let mut cfg = Config::new_with_version(quicfuscate::transport::PROTOCOL_VERSION).expect("cfg");
cfg.set_application_protos(&[b"hq-interop", b"h3-29", b"h3-28", b"h3-27", b"http/0.9"]).ok();
cfg.verify_peer(true);
cfg.load_verify_locations_from_file("/etc/ssl/certs/ca-bundle.crt").ok();
// Server side
cfg.load_cert_chain_from_pem_file("tls-cert.pem").expect("cert");
cfg.load_priv_key_from_pem_file("tls-key.pem").expect("key");
// Optional TLS key logging for debugging
cfg.log_keys();
```

#### Zstd FFI (unsafe_rust) + Sweetspot Defaults

- Feature flag: `compression_zstd_ffi` (optional; default OFF). Build example:
  - `cargo build --features "unsafe_rust,compression_zstd_ffi"`
- When enabled, `src/optimize/unsafe.rs::unsafe_compress` uses native `zstd-sys` with per-call tuning for maximum throughput and low CPU.
- The default mode is a single "sweetspot" profile optimized for network payloads (good ratio at very low CPU). Heuristics (length -> (level, workers, target_block)):
  - `<= 8 KiB` -> `(2, 0, 16 KiB)`
  - `<= 64 KiB` -> `(3, 1, 64 KiB)`
  - `<= 256 KiB` -> `(3, clamp(cpus/4, 1..2), 128 KiB)`
  - `> 256 KiB` -> `(4, clamp(cpus/2, 2..4), 256 KiB)`
  - `cpus` is the available parallelism (logical cores). `clamp(a, x..y)` is bounded to `[x, y]`.
- Manual override (global): set once via environment to force a fixed configuration regardless of payload size:
  - `QUICFUSCATE_ZSTD_MODE=manual`
  - `QUICFUSCATE_ZSTD_LEVEL=<int>` (default 3)
  - `QUICFUSCATE_ZSTD_WORKERS=<int>` (default 2)
  - `QUICFUSCATE_ZSTD_TARGET_BLOCK=<bytes>` (default 65536)
- Optional tuning (FFI path only):
  - `QUICFUSCATE_ZSTD_STRATEGY=fast|dfast|greedy|lazy2|btopt`
  - `QUICFUSCATE_ZSTD_WINDOW_LOG=<int>`
  - `QUICFUSCATE_ZSTD_CHECKSUM=0|1`
  - `QUICFUSCATE_ZSTD_CONTENTSIZE=0|1`
- Additional initialization hints (FFI path; applied at compressor creation):
  - `ZSTD_c_nbWorkers` is also set from `QUICFUSCATE_ZSTD_WORKERS` if present.
  - `ZSTD_c_targetCBlockSize` is set from `QUICFUSCATE_ZSTD_TARGET_BLOCK` if present.
- Safe fallback behavior: If `compression_zstd_ffi` is OFF, the "unsafe" path transparently uses the safe `zstd` crate under the same headers/mode, so behavior stays consistent across builds.

##### Headers and Compatibility
- Basic frame (no dictionary): `0x5A` + 4B big-endian original length, followed by zstd data.
- Dictionary frame: `0x5D` + 2B dict hash + 2B dict version + 4B big-endian original length, followed by zstd data.
- `UnsafeCompressor::compress_direct()` and `UnsafeDecompressor::decompress_direct()` read/write the same headers as `compress.rs` helpers for full interchangeability.

##### Dictionary Training and Lookup
- Training: `compress.rs::maybe_train()` periodically builds dictionaries from submitted samples and persists them to `dict_cache/`.
- Lookup: `get_dict_by_id(hash, version)` resolves bytes at runtime; the unsafe decompressor prefers the supplied dictionary but falls back to cache lookup by id.

##### Streaming Compression API
- Unsafe FFI path:
  - `UnsafeCompressor::compress_streaming(&self, src)` streams via `ZSTD_compressStream2` with `targetCBlockSize` to reduce end-to-end latency on large inputs.
  - `UnsafeCompressor::compress_auto(&self, src)` automatically selects between direct/streaming based on `QUICFUSCATE_ZSTD_STREAM_MIN` (default: 262,144 bytes).
  - Header semantics are identical to direct: `0x5A` (no dict) or `0x5D` (with dict-ID: 2B hash, 2B version, then 4B length).
- Safe path (`src/compress.rs`):
  - `CompressionManager::compress_to_pool()` automatically uses the streaming encoder (`zstd::stream::Encoder`) above the threshold.
  - No API change; behavior is compatible, header remains `0x5A` in the safe path.

Example (unsafe FFI path):
```rust
use quicfuscate::optimize::unsafe_compress::UnsafeCompressor;
use std::sync::Arc;

let comp = UnsafeCompressor::new(Arc::clone(&pool), None, 3);
// Autogating per ENV: QUICFUSCATE_ZSTD_STREAM_MIN (bytes)
let pkt = unsafe { comp.compress_auto(payload)? };
```

#### Provider API (Unified)
```rust
use quicfuscate::qftls::{create_provider, ProviderStrategy};
use parking_lot::RwLock;
use std::sync::Arc;

let crypto = Arc::new(RwLock::new(quicfuscate::transport::packet::CryptoContext::default()));
let provider = create_provider(ProviderStrategy::Unified, false, crypto)?;
```

### Obfuscation-Modes Overview

The stealth stack offers multiple modes balancing performance and cover traffic. Domain fronting is enabled in Performance, Stealth, Anti-DPI, and Intelligent; it is disabled in Off. When `fronting_domains` is empty and fronting is enabled, the built-in ultra-stealth domain set is used.

Preset layer vs runtime layer:

| Source | Input | Runtime mapping |
|---|---|---|
| Engine config (`engine.stealth.mode`) | `off` | `StealthMode::Off` |
| Engine config (`engine.stealth.mode`) | `auto` | `StealthConfig::stealth()` baseline |
| Engine config (`engine.stealth.mode`) | `max` | `StealthConfig::anti_dpi()` baseline |
| Engine config (`engine.stealth.mode`) | `manual` | `StealthConfig::manual()` baseline |
| QKey/Admin preset (`stealth`) | `off` | enforced as `StealthMode::Off` |
| QKey/Admin preset (`stealth`) | `max` | enforced as `StealthMode::AntiDpi` |
| QKey/Admin preset (`stealth`) | `manual` | enforced as `StealthMode::Manual` |
| QKey/Admin preset (`stealth`) | `auto` | no forced override, runtime baseline remains active |
| Runtime/env aliases | `base|performance` | mapped to the same performance-focused baseline |
| Runtime/env aliases | `dynamic|intelligent` | mapped to intelligent escalation baseline |

Obfuscation-Modes - Matrix & Tuning (on = enabled, off = disabled, values shown when relevant)

| Feature | Performance | Stealth | Anti-DPI | Intelligent |
|---|---:|---:|---:|---:|
| Domain Fronting | on | on | on | on |
| HTTP/3 Masquerading | on | on | on | on |
| QPACK Headers | off | on | on | off (dynamic) |
| XOR Obfuscation | off | on | on | off (dynamic) |
| Traffic Padding | off | Adaptive (max 86) | BrowserMimic (max 256) | off (dynamic) |
| Timing Obfuscation | off | 750 us default | 3000 us default | off (dynamic) |
| Flow Shaper and Dummy Retransmits | off | off | on | off (dynamic) |
| Fingerprint Rotation | off | off | 300 s | off (dynamic) |
| Server Push Cover | off | off | on | off (dynamic) |
| Real-time Choke | off | off | on (10 Mbps, 500 ms) | off (dynamic) |
| DNS-over-HTTPS | on | on | on | on |
| TLS Cover provider | on* | on* | on* | on* |
| MASQUE Manager | on | on | on | on |
| MASQUE Preferred | off | off | on (high stealth) | off (dynamic) |
| Cover Traffic Interval | 5 s | 5 s | 5 s (tightened on escalation) | 5 s (dynamic) |

Notes:
- Active probing detection is enabled in Stealth, Anti-DPI, and Intelligent; Performance keeps overhead minimal with the detector disabled. Intelligent starts like Performance and can escalate toward Anti-DPI features on probe signals.
- `sec-ch-ua*` hints are emitted only for Chromium family (Chrome/Edge); Firefox and Safari typically omit them.
- * TLS Cover provider is enabled by default across modes and can be disabled with `QUICFUSCATE_TLS_COVER=0`. `StealthConfig.use_tls_cover` (TOML alias: `use_tls_cover_extras`) only controls TLS Cover extras (ticket manager and cert emulator).
- Risk/Tradeoff: domain fronting behavior depends on current upstream provider policy and regional filtering rules.
- Risk/Tradeoff: MASQUE cover paths require compatible CONNECT-UDP availability on the selected route.

#### Stealth Modes - Semantics
- Off: no stealth; DoH, fronting, HTTP/3 masquerading, XOR, padding, timing, and QPACK are disabled.
- Performance: DoH on; domain fronting on; HTTP/3 masquerading on; XOR off; no padding; no timing obfuscation; QPACK headers off; rotation off.
- Stealth: DoH on; fronting on; HTTP/3 masquerading on; XOR on; QPACK headers on; adaptive padding (max 86); timing obfuscation on (default 750 us); rotation off.
- Anti-DPI: DoH on; fronting on (ultra list); HTTP/3 masquerading on; XOR on; QPACK headers on; BrowserMimic padding (max 256); timing obfuscation on (default 3000 us); flow shaper enabled; rotation on (300 s); server push cover enabled; real-time choke enabled (10 Mbps, 500 ms).
- Intelligent: starts like Performance; dynamic escalation on probe signals; can enable Anti-DPI features at runtime.
- Manual: all knobs as configured in TOML or env; no automatic escalation.

#### Real-Time Rate Choke
- Token bucket shaping with `choke_target_mbps` and `choke_burst_ms` limits instantaneous bitrate without heavy CPU overhead.
- When enabled, the Stealth layer sets `Config.set_external_pacing(true)` and injects sleeps only when necessary, avoiding jitter amplification.
- Anti-DPI mode uses defaults of 10 Mbps and 500 ms. During probe escalation the rate choker can tighten to 100 Mbps and 8 ms, or 50 Mbps and 12 ms when already in Anti-DPI mode.

#### Probe Escalation (runtime)
- Escalation triggers on active probe detection when `dynamic_enabled` is true or when padding is enabled (Stealth).
- Escalation window lasts 20 minutes and tightens cover traffic interval to 2500 ms (or 2000 ms if already in Anti-DPI).
- MASQUE is marked preferred only when the manager is enabled and initialized.
- Rate choker is tightened to 100 Mbps and 8 ms (or 50 Mbps and 12 ms when already in Anti-DPI).
- Server push cover traffic is enabled at runtime during escalation.

### StealthBrain Runtime Control

The StealthBrain module (`src/brain.rs`) implements sophisticated ACK policy optimization using machine learning techniques for adaptive transport behavior. It observes telemetry and applies transport/stealth actuators conservatively with step limiting:

Runtime wiring is cohesive rather than feature-isolated:

- `StealthManager` enforces mode/profile policy on stealth actuators.
- `StealthBrain` is attached via `CombinedObserver` and continuously translates transport signals into ACK/timing/FEC hints.
- `DeepIntegrationOrchestrator` (feature `orchestrator`) contributes cross-signal heuristics for escalation and cover-traffic coordination.
- Profile-derived `stealth_mode`/`fec_mode` preferences are replayed through the same runtime mutation surface used by live intelligent control.

#### StealthBrain Core Components
- **`StealthBrain`**: Main orchestrator with epsilon-greedy bandit for ACK policy selection
- **`CombinedObserver`**: Multi-observer pattern allowing attachment of multiple `TransportObserver` instances
- **`StealthBrainConfig`**: Configuration with ACK bounds, exploration probability, and cooldown parameters

#### Operational Parameters
- Inputs: ACK delay (short/long EWMA), inter-arrival (IAT) histograms, size histograms, ECN (ECT0/ECT1/CE), delivery rate, reorder ratio.
- ACK policy: epsilon-greedy bandit chooses thresholds from {2, 3, 4, 8}; step limiting moves by at most +/-1 per change, clamped to `[ack_min, ack_max]`.
- Jitter hints: derived from deviation between short/long ACK EWMAs; +/-10% dithering; applied via `set_stealth_timing(true, jitter_us)` when pacing is off.
- External pacing: toggled in concert with the rate choker and escalation; avoids double sleeps (pacing on => jitter gate off).
- Padding shaping: BrowserMimic bias `1..4` and adaptive granularity (`32|64|128`) -> `Config.set_stealth_mimic_bias()` / `set_stealth_adaptive_granularity()`.
- FEC hints: updates `fec_interval_hint()` (packets) and redundancy PPM to steer encoder cadence without hard coupling.
- Cooldowns: changes respect `policy_cooldown_ms`; exploration bounded by `explore_prob` and current CE ratio.

#### Brain Configuration
```rust
use quicfuscate::brain::{StealthBrain, StealthBrainConfig};

let cfg = StealthBrainConfig {
    ack_min: 2,
    ack_max: 8,
    explore_prob: 0.1,
    policy_cooldown_ms: 200,
    jitter_dither_pct: 10,
    ack_ewma_alpha_short: 0.25,
    ack_ewma_alpha_long: 0.95,
    ..Default::default()
};

let brain = StealthBrain::new(cfg);
```

#### Server Push Cover Traffic (feature `orchestrator`)
The StealthBrain module includes advanced Server Push Cover Traffic coordination for enhanced stealth:

```rust
use quicfuscate::brain::DeepIntegrationOrchestrator;

// Enable Server Push Cover Traffic
let orchestrator = DeepIntegrationOrchestrator::new(
    brain_config,
    pool_capacity,
    block_size
);

// Enable server push based on network conditions
orchestrator.enable_server_push(true);

// Brain automatically determines when to trigger push
if orchestrator.should_trigger_server_push() {
    let intensity = orchestrator.get_server_push_intensity();
    // Intensity ranges from 0.0 to 1.0 based on:
    // - Loss rate
    // - Bandwidth availability
    // - Current ACK policy
    // - Jitter requirements
}
```

**Server Push Heuristics:**
- Triggers when ACK delay > 15ms (high latency detected)
- Increases intensity with loss rate (0-5% loss -> 0.3 intensity, >10% -> 0.8)
- Bandwidth-aware: scales with available bandwidth
- Cooldown period prevents excessive pushing
- Integrates with FEC hints for coordinated redundancy
- Resource gating: avoids cover bursts when CPU/memory are under pressure

#### Global Hints System
The StealthBrain module provides global atomic hints for coordination between modules:

- **FEC_INTERVAL_HINT_PKTS**: Controls streaming FEC repair interval in packets
- **FEC_REDUNDANCY_PPM**: Parts-per-million redundancy hint for FEC encoder
- **TIMING_JITTER_HINT_US**: Microsecond timing jitter hints for stealth layer

```rust
use quicfuscate::brain::{fec_interval_hint, timing_jitter_hint_us};

// Check for current FEC interval hint from brain
if let Some(interval_hint) = fec_interval_hint() {
    println!("Brain suggests FEC interval of {} packets", interval_hint);
}

// Check for current timing jitter hint
if let Some(jitter_hint) = timing_jitter_hint_us() {
    println!("Brain suggests {}us timing jitter", jitter_hint);
}
```

#### Combined Observer Pattern
The module implements a multi-observer pattern for aggregating telemetry from multiple sources:

```rust
use quicfuscate::brain::CombinedObserver;
use std::sync::Arc;

// Create multiple observers and combine them
let observers = vec![
    Arc::new(stealth_brain) as Arc<dyn TransportObserver>,
    Arc::new(fec_observer) as Arc<dyn TransportObserver>,
    // Additional observers...
];

let combined_observer = CombinedObserver::new(observers);
```

#### Active Probing Escalation & MASQUE Preference

- Terminology used below:
  - **MASQUE enabled**: manager creation is allowed by mode policy or ENV override.
  - **MASQUE preferred**: policy bit requests CONNECT-UDP path first for outbound requests.
  - **MASQUE active**: a CONNECT-UDP flow is established and tracked by HTTP/3 state.

- On active probing, the stealth stack escalates to a hardened window (~20 minutes):
  - Adds extra pacing (1-3 ms per packet; 3-7 ms in Anti-DPI) in addition to existing timing gates.
  - Tightens cover-traffic cadence (default 5 s to 2.5 s; 2.0 s in Anti-DPI) with realistic GET/HEAD mix.
  - Marks MASQUE as preferred while escalated, but only if MASQUE is enabled and the manager is initialized.
  - Automatically clears after the escalation window (interval reset to 5 s, MASQUE preference cleared).
- Mode specifics:
  - Anti-DPI: MASQUE is enabled by default; MASQUE remains preferred while escalated.
  - Stealth: MASQUE is disabled by default; temporarily behaves like Anti-DPI during escalation.
  - Manual or env overrides can force MASQUE in any mode (see Environment Variable Overrides).

#### Reality Fallback (Xray-style Reverse Proxy)

When an active probe is detected (invalid QUIC authentication, suspicious packets), returning silence or "Connection Refused" exposes the server as a VPN. The Reality Fallback module (`src/reality.rs`) mitigates this by transparently forwarding probe packets to a legitimate upstream target and relaying the response back to the scanner.

**Architecture:**
- **`RealityProxy`**: Manages ephemeral proxy sessions per scanner IP, spawns lightweight async tasks for each session.
- **`FallbackResponse`**: Encapsulates upstream response data for relay back to the scanner.
- **Targets (Round-Robin)**: `1.1.1.1:443` (Cloudflare), `8.8.8.8:443` (Google), `9.9.9.9:443` (Quad9) - "Too Big To Block" IPs. Override via `QUICFUSCATE_REALITY_TARGETS=host:port,...`.
- **Session Timeout**: 30 seconds of inactivity; lazy pruning when session count exceeds 100.

**Integration:**
- `core::recv()`: On `transport::recv()` error (auth failure), calls `stealth_manager.handle_fallback(packet, source)`.
- `core::send()`: Prioritizes `stealth_manager.poll_fallback()` responses (bypasses Stealth Scheduler) to reply instantly with upstream data.
- `stealth::StealthManager`: Holds `reality_proxy: Option<Arc<RealityProxy>>` (enabled when `dynamic_enabled = true`) and `fallback_rx: mpsc::Receiver<FallbackResponse>`.

**Effect:** The scanner receives a cryptographically valid QUIC/TLS response from Cloudflare or Google, making the server indistinguishable from a standard web service.

#### DoH Multi-Provider Rotation

DNS-over-HTTPS now supports multiple providers with automatic round-robin rotation and fallback:
- **Providers**: Cloudflare (`cloudflare-dns.com`), Quad9 (`dns.quad9.net`), Google (`dns.google`), NextDNS (`dns.nextdns.io`).
- **Mechanism**: `DOH_PROVIDERS` array with `DOH_PROVIDER_INDEX` atomic counter for rotation; `resolve_doh_multi()` tries next on failure.
- **Telemetry**: `DOH_QUERIES_TOTAL`, `DOH_FAILURES_TOTAL` counters.

#### Async Stealth Scheduler (Non-Blocking)

The stealth timing system has been fully refactored to eliminate blocking `std::thread::sleep()`:
- `stealth::StealthManager::process_outgoing_packet()` returns `Option<Duration>` delay instead of blocking.
- `core::QuicFuscateConnection` maintains `next_packet_release: Option<Instant>`.
- `send()` checks `next_packet_release`; if `now < release_time`, returns `Ok(0)` (yield) without blocking the reactor.
- When delay expires, clears the block and proceeds to flush `outgoing_fec_packets`.

### Compression Module

The compression module (`src/compress.rs`) provides adaptive zstd payload compression with intelligent policy control:

#### Compression Core Components
- **`CompressionManager`**: Main compression orchestrator with CPU-profile aware zstd tuning (threads, target block sizes, long-distance matching)
- **`CompressionConfig`**: Configuration with minimum length thresholds and compression levels
- **`CompressionPolicy`**: Runtime policy control for adaptive compression decisions
- **`CompressionAnalysis`**: SIMD-powered preprocessing (ASCII/newline/null/high-bit counters + chunk hashing) feeding telemetry (`COMPRESS_PREPROC_*`) and influencing encoder tuning.

#### Supported Algorithms
- **zstd** only (levels 1-22), with optional dictionary training
  - Dictionaries trained from samples (best-effort) and cached on disk
  - Dictionary cache directory via `QUICFUSCATE_DICT_DIR` (default: `dict_cache/`)

#### Usage Example
```rust
use quicfuscate::compress::{CompressionManager, CompressionConfig};
use quicfuscate::optimize::OptimizationManager;

let mgr = CompressionManager::new(CompressionConfig::default());
let pool = OptimizationManager::new().memory_pool();
if let Some((block, used)) = mgr.compress_to_pool(&pool, payload) {
    // send &block[..used]
}
```

#### Adaptive Compression
- Decision gates combine length threshold, link speed, RTT and loss:
  - `min_len` (default 256 bytes)
  - Slow link heuristic (<10 Mbps) or high RTT (>80 ms)
  - Loss gate (<15% to avoid CPU burn during heavy loss)
- Lightweight textuality heuristic (`looks_textual`) uses `accelerate::count_ascii_printable` (SSE2/NEON) for the ASCII ratio and an entropy estimator.

#### Compression Telemetry
The module includes comprehensive metrics for performance monitoring:

- **Compression ratio tracking**: Real-time compression effectiveness metrics
- **Algorithm performance**: Per-algorithm timing and efficiency measurements
- **Dictionary effectiveness**: Metrics on dictionary-based compression gains
- **Adaptive decision logging**: Track decision-making process for optimization

```rust
use quicfuscate::compress::CompressionTelemetry;

let telemetry = CompressionTelemetry::current();
println!("Compression ratio: {:.2}%", telemetry.avg_compression_ratio * 100.0);
println!("Bytes compressed: {}", telemetry.bytes_compressed);
println!("Time spent: {}ms", telemetry.compression_time_ms);
```

### Performance Architecture & Hardware Acceleration

#### SIMD Feature Detection & Dispatch
Centralized CPU feature detection with comprehensive SIMD support:
- **x86_64**: RDRAND, RDSEED, AES-NI, VAES, PCLMULQDQ, SSE2, SSSE3, AVX, AVX2, FMA, AVX512-F/CD/BW/DQ/VL, GFNI
- **aarch64**: AES, PMULL, SHA2, SHA3, NEON, SVE (autodetect), SVE2
- **Feature mapping to CPU profiles**:
  - `X86_P0`: SSE2, AESNI
  - `X86_P1a`: SSE2, AESNI, PCLMULQDQ
  - `X86_P1b`: +AVX, RDRAND, RDSEED
  - `X86_P1f`: +F16C
  - `X86_P2a`: +AVX2, BMI1/2, LZCNT
  - `X86_P2b`: +RDRAND, RDSEED, FMA
  - `X86_P3a`: +AVX512F/CD
  - `X86_P3b`: +AVX512_BW/DQ/VL
  - `X86_P3c`: +VAES, VPCLMULQDQ
  - `X86_P3d`: +GFNI, GFNI+VAES+PCLMUL
  - `X86_P3e`: +AMX-TILE, AMX-INT8
  - `X86_P4a`: +AVX10.1-256 (requires Cargo feature `avx10_preview`; inherits AVX2/AVX-512 kernels, telemetry `SIMD_USAGE_AVX10_256`)
  - `X86_P4b`: +AVX10.1-512 (requires Cargo feature `avx10_preview`; inherits AVX-512 kernels, telemetry `SIMD_USAGE_AVX10_512`)
  - `ARM_A0`: NEON, AES, PMULL
  - `ARM_A1a`: +SHA2
  - `ARM_A1b`: +SHA3
  - `ARM_A1c`: +SVE
  - `ARM_A1d`: +SVE2
  - `ARM_A2`: +SVE-BF16

- **PMULL**: Polynomial multiplication for GHASH

```rust
use quicfuscate::optimize::{SimdPolicy, Avx512Gfni, Sve2};

// Central feature detection and dispatch: selects optimal code paths per CPU (x86: SSE2/AVX2/AVX-512; ARM: NEON), with safe scalar fallbacks
let policy: Box<dyn SimdPolicy> = if cpu_supports_avx512gfni() {
    Box::new(Avx512Gfni)
} else if cpu_supports_sve2() {
    Box::new(Sve2)
} else {
    Box::new(Scalar) // Safe fallback
};
```

#### SIMD Gap Status
 - **Crypto (Poly1305 wide reduction ARM)**: Done - `mac_sve2_block_wide` provides the 256-bit carry chain on `ARM_A2`/Apple M.
 - **FEC (AMX-INT8 Wiedemann)**: Done - `simd::amx::matmul_gf256_amx` processes 16x64 GF(256) blocks, planner gating & telemetry active, scalar fallback intact.
 - **Utility (RVV)**: Infrastructure for RISC-V Vector (`RVV`) and additional iterator backends are not active in the current build.

#### Accelerate Module (Re-export)
`accelerate.rs` is now a thin re-export layer for the optimize submodules. All implementation lives under `src/optimize/` while the public API stays stable under `accelerate::*` paths.
The accelerate surface still consolidates acceleration primitives across subsystems:

##### Network I/O Acceleration (transport_io submodule)
- **UDP GSO/GRO**: Generic Segmentation/Receive Offload for reduced syscall overhead
- **sendmmsg/recvmmsg**: Batched syscalls for efficient packet processing on Linux
- **sendmsg_x (macOS)**: Batched UDP send syscall when available; falls back to per-message sendmsg when rejected
- **MSG_ZEROCOPY**: Zero-copy transmission for large buffers (Linux >=4.14)
- **SO_BUSY_POLL**: Busy polling for ultra-low latency
- **NIC Parallelism**: RSS/RPS/RFS configuration for multi-core systems

```rust
use quicfuscate::accelerate::transport_io::{UdpGsoConfig, ZeroCopySocket, BusyPollSocket};

// Enable UDP GSO for segmentation offload
let gso_config = UdpGsoConfig::enable(&udp_socket)?;

// Use zero-copy socket for large payloads
let zerocopy_socket = ZeroCopySocket::new(udp_socket)?;

// Configure busy polling for low latency
let busy_poll_socket = BusyPollSocket::new(udp_socket, 50)?; // 50 microseconds
```

##### Random Number Generation (random submodule)
- **RDRAND/RDSEED**: Hardware-accelerated random generation for cryptographic security
- **AES-CTR DRBG**: AES-based Deterministic Random Bit Generator (20x faster than software)
- **Vectorized random generation**: Fill arrays 8x faster with SIMD

```rust
use quicfuscate::accelerate::random::{random_u64, random_bytes_secure, AesCtrDrbg};

// Fast random with hardware acceleration
let val = random_u64();

// Secure random with RDSEED if available
let mut buf = [0u8; 32];
random_bytes_secure(&mut buf);

// AES-CTR DRBG for high-performance random generation
let mut drbg = AesCtrDrbg::new(&[0x42; 32]);
let mut array = [0u32; 1024];
drbg.fill_bytes(&mut array);
```

##### Sorting Acceleration (sort submodule)
- **AVX2/AVX512 sorting networks**: 5x faster u32/f32 sorting with SIMD
- **Radix sort for large arrays**: Optimized for performance
- **Fast argsort**: Index-based sorting 3x faster

```rust
use quicfuscate::accelerate::sort::{sort_u32, sort_f32, argsort};

let mut data = vec![5, 2, 8, 1, 9];
sort_u32(&mut data);

let mut f_data = vec![5.0, 2.3, 8.1, 1.7, 9.2];
sort_f32(&mut f_data);

let indices = argsort(&data);
```

##### String Acceleration (string submodule)
- **SIMD string comparison**: ~8x faster (AVX2/AVX512 on x86, NEON/SVE2 on ARM)
- **Fast string search**: ~10x faster via AVX512 bitmap (x86) or SVE2 predicates (ARM)
- **UTF-8 validation**: dedicated SVE2 kernels validate ASCII fast paths vectorized; NEON fallback
- **Integer parsing**: ~3x faster via BMI2 PEXT (x86) or SVE2 UDOT (ARM)
- **Base64 encode/decode**: AVX2 (encode/decode) plus SSE4.1 decoder on x86 and NEON/SVE2 on ARM deliver ~4-6x speedup

```rust
use quicfuscate::accelerate::string::{string_equals, string_contains, validate_utf8, parse_u64, base64_encode};

let a = "hello world";
let b = "hello world";
assert!(string_equals(a, b));

assert!(string_contains("hello world", "world"));

let utf8_bytes = b"hello \xCE\x93\xCE\xB5\xCE\xB9\xCE\xB1 \xCF\x83\xCE\xB1\xCF\x82";
assert!(validate_utf8(utf8_bytes));

let num = parse_u64("12345").unwrap();
let encoded = base64_encode(b"hello world");
```

##### Brain Acceleration (brain submodule)
- **AVX2/FMA/SVE2 statistical computations**: 4-5x faster mean, variance, correlation
- **Matrix multiplication**: AMX/AVX512F on x86 and dedicated SVE2 Gather/`svmla` on ARM
- **Apple Silicon AMX**: optimized matrix operations
- **Moving averages**: AVX-512/AVX2 (x86) & NEON (ARM/Apple M) sliding windows with telemetry-tracked scalar fallback
- **Histogram decay & Jensen-Shannon divergence**: x86 uses AVX-512/AVX2/SSE4.1 fixed-point pipelines, ARM uses NEON/SVE2; backend selection is visible via `BRAIN_HISTOGRAM_{AVX512,AVX2,SSE,NEON,SVE2,SCALAR}_OPS`, and parity is validated by `scripts/tests/rust/rt-brain-histogram.rs` and `scripts/tests/rust/rt-simd-selfcheck.rs`.

```rust
use quicfuscate::accelerate::brain::{compute_statistics, compute_correlation, matrix_multiply, moving_average};

// Fast statistical computations
let data = vec![1.0, 2.0, 3.0, 4.0, 5.0];
let (mean, variance) = compute_statistics(&data);

// Correlation between two series
let x = vec![1.0, 2.0, 3.0, 4.0, 5.0];
let y = vec![2.1, 3.9, 6.1, 8.0, 9.9];
let corr = compute_correlation(&x, &y);

// Matrix multiplication with hardware acceleration
let a = vec![1.0, 2.0, 3.0, 4.0];  // 2x2 matrix
let b = vec![5.0, 6.0, 7.0, 8.0];  // 2x2 matrix
let mut c = vec![0.0; 4];           // Result 2x2 matrix
matrix_multiply(&a, &b, &mut c, 2, 2, 2);

// Moving average with sliding window
let avg = moving_average(&data, 3);
```

##### Iterator Reductions (iter submodule)
- **SIMD-backed sums**: `sum_f32`, `sum_u32`, `sum_u64` dispatch across AVX-512/AVX2/NEON with scalar fallback and telemetry (`ITER_SUM_*`).

```rust
use quicfuscate::accelerate::iter;

let floats = vec![1.0_f32, 2.5, -3.25];
let total = iter::sum_f32(&floats);

let small = vec![1_u32, 2, 3, 4];
let total_u32 = iter::sum_u32(&small);

let big = vec![1_u64 << 40, 7];
let total_u64 = iter::sum_u64(&big);
```

##### Stealth Acceleration (stealth submodule)
- **Accelerated string operations**: SIMD-optimized string processing for header manipulation
- **Fast pattern matching**: High-speed pattern matching for header field detection
- **Optimized encryption routines**: Accelerated cryptographic operations for obfuscation
- **Persona cookies & referers**: `AsciiSimdBackend` orchestrates SSE2/AVX2/NEON decimal/hex formatter LUTs and bulk copies so `Http3Masquerade::generate_realistic_cookies_at` / `generate_realistic_referer_for` assemble strings without scalar push-loops while preserving deterministic fallbacks.
- **Persona header templates**: `Http3Masquerade::generate_headers` applies `PersonaTemplate` batches (Safari/Firefox Title-Case & Chrome/Edge Chromium stack) using `AsciiSimdBackend` + `Header::from_parts` to eliminate per-header `Vec::push` loops.

##### Transport Acceleration (transport submodule)
- **Optimized packet processing**: High-speed packet serialization/deserialization
- **Accelerated frame handling**: SIMD-enhanced frame encoding/decoding
- **ACK-Range Merging**: `transport::frames::canonical_ack_blocks` uses a VL-scaling SVE2 merge kernel (predicate + `svmaxv_u64`) on ARM_A2; all other profiles use the proven scalar path.
- **Varint/Header Dispatch**: `transport::pn::{write_varint,read_varint}` and `simd::transport::validate_header` prioritize AVX-512 -> AVX2 -> SSE2 (x86) or SVE2 -> NEON (ARM) and retain the existing error paths.
- **Fast connection management**: Optimized connection state handling

##### Memory Acceleration (memory submodule)
- **Fast allocation/deallocation**: Optimized memory management routines
- **Cache-efficient allocators**: Memory allocators optimized for cache locality
- **Batched operations**: Optimized batch memory operations
```

#### Memory Pool Architecture
- **Zero-copy memory pools**: Reduces allocation overhead and improves cache locality
- **NUMA-aware allocation**: Optimizes for multi-socket systems with node affinity
- **Huge page support**: 2MB/1GB page allocation for reduced TLB pressure
- **Thread-local caches**: Minimizes contention on high-concurrency systems
- **Const-size structures**: Fixed-size containers for lock-free operations
- **Prefetch optimization**: Proactive memory loading to reduce cache misses

```rust
use quicfuscate::optimize::{MemoryPool, ConstBuffer, ConstRingBuffer, LockFreePacketQueue, PrefetchManager};

// Create a memory pool with configurable parameters
let pool = MemoryPool::new(1024, 65536)?; // 1024 blocks of 64KB each

// Fixed-size structures for lock-free operations
let buffer: ConstBuffer<4096> = ConstBuffer::new();
let ring: ConstRingBuffer<Packet, 1024> = ConstRingBuffer::new();
let queue: LockFreePacketQueue<Packet> = LockFreePacketQueue::with_capacity(10000);

// Prefetch manager for proactive memory loading
let mut prefetcher = PrefetchManager::new();
prefetcher.prefetch_data(data);
```

#### Zero-Copy Memory Architecture

**Memory Pool:**
- Zero-copy memory pool with tunables (`--pool-capacity`, `--pool-block`)
- NUMA-aware allocation with node affinity
- Huge pages support (2MB/1GB) for TLB optimization
- Thread-local caching to minimize contention
- Minimum block size is clamped to 2048 bytes for safety; mismatch-sized blocks are dropped on return to preserve invariants.

**Const-Size Structures:**
```rust
use quicfuscate::optimize::{
    ConstBuffer, ConstRingBuffer, ConstPacketPool, AlignedBuffer
};

// Const-size buffer for zero-copy operations
let buffer: ConstBuffer<4096> = ConstBuffer::new();

// Lock-free ring buffer for packet queuing
let ring: ConstRingBuffer<Packet, 1024> = ConstRingBuffer::new();

// Pre-allocated packet pool
let pool: ConstPacketPool<256, 1500> = ConstPacketPool::new();

// SIMD-aligned buffer (64-byte cache line)
let aligned: AlignedBuffer<8192> = AlignedBuffer::new();
```

**Lock-Free Packet Queue:**
```rust
use quicfuscate::optimize::LockFreePacketQueue;

let queue: LockFreePacketQueue<Packet> = 
    LockFreePacketQueue::with_capacity(10000);

// Backpressure support
if !queue.try_enqueue(packet) {
    // Queue full, apply backpressure
    apply_flow_control();
}
```

#### Platform-Specific Optimizations
- **Linux**: io_uring for async I/O, SO_ZEROCOPY, MSG_ZEROCOPY
- **Windows**: WSASend with scatter-gather, IOCP
- **macOS**: kqueue, Grand Central Dispatch
- Batched processing keeps hot loops in cache
- XDP (AF_XDP) is available as an optional Linux fast path when enabled and supported; runtime falls back to native UDP/io_uring paths when AF_XDP is unavailable.
- Optional io_uring UDP Fast Path (Linux) with optional kernel zero-copy (SO_ZEROCOPY/MSG_ZEROCOPY)
- Linux ARM: io_uring send path uses NEON/SVE2 prefetch and DMB fences around submit/completion

##### Zero-Copy Completion Bridging (Linux)

To decouple the producer (send path) from the consumer (completion processing), QuicFuscate employs a lightweight bridging mechanism for MSG_ZEROCOPY completions:

- Producer notification
  - `src/accelerate.rs::transport_io::ZeroCopySocket::register_zerocopy_completion()` forwards successful sends to `src/transport/uring.rs::notify_zerocopy_completion(fd, bytes)`.
  - This enqueues a `ZeroCopyEvent { fd, bytes, ts_ns }` into a lock-free global inbox.

- Consumer draining
  - The transport layer periodically drains the inbox via `try_drain_zerocopy_events(max)` (Linux-only).
  - Drains occur opportunistically on send and receive paths inside `src/transport/udpfast.rs`.
  - Additionally, the kernel \`MSG_ERRQUEUE\` is drained best-effort for zerocopy notifications (fallback/complement to userland inbox).

- Environment switch
  - `QUICFUSCATE_ZC_DRAIN_BATCH` (default: `16`) controls the drain batch size used by opportunistic drains in connection-level ticks.

- Telemetry
  - Local counters (udpfast): `ZC_COMPLETIONS`, `ZC_COMPLETED_BYTES`.
  - Global counters (optimize::telemetry): `ZC_COMPLETIONS_TOTAL`, `ZC_COMPLETED_BYTES_TOTAL`.
  - These can be exported by existing metrics sinks alongside other performance indicators.

This design keeps the hot send paths minimal and non-blocking while allowing the runtime to process completions deterministically during normal I/O activity.

#### Prefetch and Memory Optimization
The accelerate module includes sophisticated prefetch and memory optimization techniques accessible through the transport I/O submodule:

- **Adaptive prefetching**: Adjusts prefetch distance based on memory access patterns
- **Cache-aware algorithms**: Optimize data layout for L1/L2/L3 cache efficiency  
- **Non-temporal stores**: Bypass cache for large data copies to avoid cache pollution (ARM NEON implementation)
- **Memory access pattern prediction**: Predicts and preloads data based on access patterns

```rust
use quicfuscate::accelerate::transport_io::memcpy_non_temporal_arm;

// On ARM systems, use non-temporal stores for large copies to avoid cache pollution
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
pub(crate) unsafe fn memcpy_non_temporal_arm(dst: &mut [u8], src: &[u8], len: usize) {
    use std::arch::aarch64::*;
    let mut i = 0usize;
    // Prefetch distance tuned conservatively
    const PF_DIST: usize = 256;

    while i + 64 <= len {
        // Prefetch ahead to reduce cache pollution
        if i + PF_DIST < len {
            core::arch::asm!(
                "prfm pldl1keep, [{ptr}]",
                ptr = in(reg) src.as_ptr().add(i + PF_DIST),
                options(nostack, preserves_flags)
            );
        }

        // Load 64 bytes and store
        let a0 = vld1q_u8(src.as_ptr().add(i));
        let a1 = vld1q_u8(src.as_ptr().add(i + 16));
        let a2 = vld1q_u8(src.as_ptr().add(i + 32));
        let a3 = vld1q_u8(src.as_ptr().add(i + 48));

        vst1q_u8(dst.as_mut_ptr().add(i), a0);
        vst1q_u8(dst.as_mut_ptr().add(i + 16), a1);
        vst1q_u8(dst.as_mut_ptr().add(i + 32), a2);
        vst1q_u8(dst.as_mut_ptr().add(i + 48), a3);

        i += 64;
    }

    // Remainder copy
    while i < len {
        *dst.get_unchecked_mut(i) = *src.get_unchecked(i);
        i += 1;
    }
}
```

### TUN Interface (Cross-Platform)

The `interface.rs` module provides a high-performance, cross-platform TUN interface that integrates with QuicFuscate's memory pool for zero-copy I/O.

#### Capability & fastpath runtime API

Runtime probing should be performed before starting client/server data paths:

- `tun_capabilities()` reports whether built-in backends are available, whether an external factory was registered, and whether zero-copy/FD-level features are supported on the active platform.
- `validate_tun_runtime_requirements()` returns early, actionable startup errors when no usable TUN backend exists for the current build/runtime combination.
- `FastpathMode` is selected via `QUICFUSCATE_FASTPATH=off|uring|xdp|auto`.
- `FastpathMode::allows_uring()` is used by runtime wiring to gate io_uring paths deterministically.

#### Platform-Specific Implementations

**Linux (`LinuxTun`):**
```rust
pub struct LinuxTun {
    name: Arc<str>,
    fd: RawFd,
    mtu: u16,
}
```
- TUN device creation via `ioctl(TUNSETIFF)` with IFF_TUN | IFF_NO_PI flags
- Direct file descriptor I/O via `libc::read`/`libc::write` with EINTR retry
- Automatic cleanup in Drop trait
- No intermediate buffering
- MTU configuration support

**macOS (`MacTun`):**
```rust
pub struct MacTun {
    fd: RawFd,
    name: Arc<str>,
    mtu: u16,
}
```
- utun device creation via `socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)`
- 4-byte AF header handling with `libc::readv`/`libc::writev` using iovecs
- Scatter-gather I/O eliminates header copying
- Control socket configuration via `ioctl(CTLIOCGINFO)`
- Automatic cleanup in Drop trait

**Windows/iOS:**
- External TUN factory pattern via `OnceLock<Box<dyn TunDeviceFactory>>`
- Platform-specific implementation injected at startup
- Clear error messages if factory not registered

### Cryptography Design (AEAD-First, Efficient by Construction)
- AEAD choices: AEGIS-128L/X (round-based, excellent when hardware AES is available) and MORUS-1280-128 (lightweight and fast on SIMD)
- Constant-time glue and strict nonce/tag checks on hot paths
- Perfect Forward Secrecy via ephemeral X25519; optional post-quantum experiments are feature-gated and inactive in the standard build profile
- Runtime selection via FeatureDetector and `simd::planner` (CryptoAeadPlan) chooses the AEAD implementation best suited to the host CPU for maximum practical Gbps

#### AEAD Policy and Implementation Status
- AEGIS implementation is fully internal in `src/crypto.rs`; there are no active references to external AEGIS forks.
- Supported cipher suites: `Aegis128L`, `Aegis128X4`, `Aegis128X8`, and `Morus1280_128`.
- Fallback policy: only `Morus1280_128` is retained.
- Runtime selection:
  - If hardware AES is available (AES-NI on x86_64) and VAES batching is available, select `Aegis128X8`; otherwise select `Aegis128X4`.
  - If hardware AES is available (AES+NEON on aarch64), select `Aegis128X4`.
  - If hardware AES is not available, fall back to `Morus1280_128`.
- aarch64 currently selects `Aegis128X4`; an SVE2 AES batching backend for the AEGIS update step is not enabled in the current build profile.
- Testing: see `scripts/tests/suites/test-crypto.sh` and the comprehensive test runner. Edge cases (including non-32-byte payloads) are validated to ensure tag verification parity between encrypt/decrypt.

#### GHASH Acceleration (AES-GCM)
- Runtime dispatch selects the fastest GHASH implementation:
  - x86_64: PCLMULQDQ path with Karatsuba carry-less multiplication and reduction modulo `x^128 + x^7 + x^2 + x + 1`; falls back to an SSE4.1/SSSE3 nibble kernel when CLMUL hardware is absent (`GHASH_SSE_OPS`).
  - aarch64: PMULL path (prefers `sve_pmull` if available, otherwise falls back to NEON) is enabled by default; can be disabled via `QUICFUSCATE_GHASH_PMULL=0|false|off`. For non-16-byte-aligned inputs, the software path takes over to ensure parity.
  - Fallback: byte-position table approach (16x256 lookups) avoids per-nibble `mul_x4` cascades and accelerates the SSE4.1/SSSE3 path.
- Correctness
  - Software vs. hardware path parity is verified by unit tests in `src/crypto.rs`.
  - AES-GCM tag derivation (`aes_gcm_tag_aad_only`) uses the selected GHASH seamlessly. `QUICFUSCATE_GHASH=auto|vpclmul|pclmul|sse|scalar` allows targeted backend verification (tests use `__test_set_ghash_override`).
  

### FEC Design (Stability Under Loss)

#### Core Architecture
- **Hybrid design**: Adaptive RLNC + Tetrys-like streaming with automatic mode switching
- **Auto-Mode**: Switches based on observed loss/RTT (bounded by `hysteresis`, smoothed by `lambda`)
- **Telemetry**: Track mode switches via `fec_mode`, `fec_mode_switch_total`

#### FEC Modes

**RLNC (Random Linear Network Coding):**
- Sliding-window systematic encoding
- Sources remain intact; repairs emitted when window full
- Window cleared after emission to bound latency
- Configurable window size for loss/latency tradeoff

**Streaming (Tetrys-like):**
- Emits 1 repair per N sources
- `QUICFUSCATE_FEC_STREAM_EVERY`: Overrides repair cadence (min 1; default computed from CPU profile)
- Aggressive profiles can use N=1 for maximum redundancy

#### Galois Field Implementations

**GF(2^8) - 8-bit Galois Field:**
- Bit-sliced implementation for cache efficiency
- SIMD-accelerated multiply-accumulate
- Wiedemann solver support
- Lookup tables for small operations
- SSSE3 nibble LUT slice multiply covers x86 SSSE3 profiles (`FEC_SSSE3_OPS` telemetry); AVX2/GFNI paths record `FEC_AVX2_GF_OPS`/`FEC_GFNI_OPS`.
- VBMI2 nibble gather kernel (`gf16_mul_slice_vbmi2`) drives `FEC_GF16_VBMI2_OPS`; processes 32xu16 per iteration via `_mm512_permutex2var_epi16` tables. Planner selects it for `X86_P3c+`; scalar fallback remains for residual CPUs. Throughput characteristics remain hardware-dependent and are validated on target systems.
- AVX-512 GFNI matrix multiply (`matrix_multiply_avx512`) now streams 64-byte stripes via `_mm512_gf2p8mul_epi8`, recording `FEC_GFNI_OPS`; CPUs without GFNI fall back automatically to the AVX2 FMA kernel.
- NEON and SVE2 slice kernels share nibble tables with adaptive prefetch; `FEC_NEON_OPS` and `FEC_SVE2_OPS` counters expose runtime usage.

**GF(2^16) - 16-bit Galois Field:**
- AVX2-optimized nibble paths (x86_64)
- NEON-optimized paths (ARM)
- High-throughput MatMul operations
- Consistent byte-width policy

#### Decoder Architecture

**Sparse Gaussian Elimination:**
- Minimal-NNZ (Non-Zero) pivot selection
- Early repair detection
- Progressive decoding support
- Memory-efficient sparse matrices

**Wiedemann Solver (GF(2^8)):**
- Block-Wiedemann with Berlekamp-Massey on per-byte slices.
- Parallel per-byte solving via Rayon.
- Falls back to Gaussian elimination when Wiedemann fails.

#### Runtime Control Loop (Transport <-> FEC)

Runtime adaptation is applied continuously in the connection loop:

- `transport::Connection::take_fec_control_delta()` provides transport-level control deltas each tick.
- The connection updates `AdaptiveFec` (`set_stream_every`, `force_streaming_mode`, `set_redundancy_ppm`) before the next encode path.
- Loss accounting feeds `AdaptiveFec::report_loss()` from transport callback counters and connection statistics.

This is the convergence point where transport feedback, StealthBrain hints, and FEC policy remain synchronized during live traffic.

#### Congestion Control Algorithms

QuicFuscate supports multiple congestion control algorithms:

```rust
pub enum CongestionControlAlgorithm {
    Reno,     // Classic TCP Reno
    Cubic,    // CUBIC (default Linux)
    BBR,      // BBR (Google)
    BBR2,     // BBR2 (recommended)
}
```

**CLI Usage:**
```bash
# Client with BBR2
quicfuscate client --remote server:4433 --cc-algorithm bbr2

# Server with CUBIC
quicfuscate server --listen 0.0.0.0:4433 --cc-algorithm cubic
```

**Characteristics:**
- **Reno**: Conservative, loss-based
- **Cubic**: Aggressive, loss-based, good for high BDP
- **BBR**: Model-based, minimizes bufferbloat
- **BBR2**: Improved BBR with better fairness

### FEC Modes & Algorithms (Current)
- Modes: `Zero`, `Light`, `Normal`, `Medium`, `Strong`, `Extreme`, `Ultra`, `Fountain`, `Streaming`.
- RLNC (GF(2^8)/GF(2^16))
  - Encoder: sliding window, systematic; repair generation via linear combinations with non-zero deterministic coefficients.
  - GF(2^16) path uses nibble (4-bit) operations; coefficients stored big-endian (2 bytes each); Cauchy-style matrix ensures invertibility.
- Wiedemann (large-k decoder)
  - Bitsliced multi-lane MatVec with internal heuristics for projection/lanes.
  - Verification path checks `A_k * X == B` on a small sample and falls back to Gauss on mismatch.
- Streaming (Tetrys-like)
  - Emits 1 repair per `N` sources; `QUICFUSCATE_FEC_STREAM_EVERY` overrides cadence (min 1; default computed from CPU profile).
- Seamless transitions
  - Cross-fade over `cross_fade_packets` with a `transition_buffer`; maintains continuity while changing `k`/mode.

SIMD & Parallelism
- SIMD levels auto-detected: `SSE2`, `AVX2`, `AVX512`, `NEON` (fallback: scalar). Parallel chunking for large payloads.
- Runtime overrides are documented in the FEC Operations Guide.

Wire Format (DATAGRAM)
```text
[0xF1, 0xEC][is_systematic:1][base_id:8][coeff_len:2][coeffs:..][payload:..]
```
Coefficients encode GF width (1 byte for GF(2^8), 2 bytes for GF(2^16)); all buffers come from `MemoryPool` and are returned on drop.

Mode Selection & Hysteresis
- Selection heuristic (loss-driven):
  - avg_loss < 0.001 -> Zero (ZeroEncoder: absolute zero overhead, counter only, ~2ns/packet)
  - < 0.02 -> Light (GF4: ~4x faster than GF8, ~5% overhead)
  - < 0.10 -> Normal (GF8: balanced)
  - < 0.25 -> Strong (AdaptRS)
  - < 0.50 -> Extreme (GF16)
  - else -> Fountain (LT Codes)
- Hysteresis & stability:
  - Minimum dwell time between switches (`~200 ms` except for fast paths like Streaming/Normal)
  - Switch only if `|avg_loss - last_avg| >= switch_threshold` (relaxes for Streaming/Normal)
  - Cross-fade transitions over `cross_fade_packets` with a `transition_buffer` to preserve continuity

#### Transport Integration (DATAGRAM Ingress/Egress)
- Repairs are transported over QUIC DATAGRAM frames (`Frame::Datagram`) using a compact, self-describing wire format:

  ````text
  [0xF1, 0xEC]        // Magic for demultiplexing FEC payloads
  [is_systematic:1]   // 1 byte: 1=systematic, 0=repair
  [base_id:8]         // u64 BE: sender's current window anchor (e.g., last source id)
  [coeff_len:2]       // u16 BE: bytes following as coefficients
  [coeffs:coeff_len]  // optional, present iff coeff_len>0 (GF(2^8): k bytes; GF(2^16): 2*k bytes)
  [payload:..]        // raw packet payload (length = datagram_len - header)
  ````

- Egress
  - The encoder serializes repairs via `FecPacket::to_stream_raw()` and enqueues them as DATAGRAMs if size <= `dgram_send_max_size`.
  - Emission policy is adaptive: base interval from `QUICFUSCATE_FEC_STREAM_EVERY` (default computed from CPU profile), escalation under loss and ECN-CE.

- Ingress
  - The receiver recognizes FEC DATAGRAMs by the 2-byte Magic. Parsing uses `FecPacket::from_stream_raw()` with zero-copy buffers from the global `MemoryPool`.
  - Parsed packets are fed into the streaming decoder; reconstructed systematics are surfaced to the application as regular DATAGRAMs.

- Semantics & Safety
  - `base_id` stabilizes window alignment across ends; `coeff_len` encodes bytes (GF-specific width must be respected by producers/consumers).
  - All buffers are owned and returned to the pool on drop; the transport avoids moving out of pooled buffers in hot paths (borrow-safe).

### Code Layout
QuicFuscate uses a consolidated Rust layout that keeps hot paths explicit and auditable while optimizing safety, performance, and maintainability.

#### Source File Coverage (Exact Path Index)
The sections above describe architecture and behavior. This index maps exact `src/` file paths to their concrete runtime responsibility to keep this document exhaustive and drift-resistant.

Core crate and entrypoints:
- `src/lib.rs` - crate root, module exports/re-exports, compatibility aliases (`tls_provider`, telemetry aliases), public type surface.
- `src/main.rs` - CLI wiring, client/server runtime bootstrap, hidden diagnostic/bench commands, admin and telemetry process wiring.
- `src/time_source.rs` - injectable time abstraction (`TimeSource`) with test install guard.

Binary entrypoints:
- `src/bin/harness.rs` - script-facing harness entrypoint (`quicfuscate::harness::run_from_env()`).
- `src/bin/qf-e2e-client.rs` - headless QKey-based E2E client for admin/web flows.
- `src/bin/qf-e2e-desktop.rs` - headless desktop-style Engine E2E probe (connect/stats/disconnect).
- `src/bin/quicfuscate-ctl.rs` - Unix admin socket CLI (`status`, `clients`, `kick`, `block`, `reload`, `qkey`, `shutdown`).

Engine module (`src/engine/`):
- `src/engine/mod.rs` - engine module root and public exports.
- `src/engine/config.rs` - typed engine config schema, enums, validation, builder.
- `src/engine/engine.rs` - `QuicFuscateEngine`, lifecycle/state machine, commands/events/stats callbacks.
- `src/engine/qkey.rs` - QKey generation/parsing/id derivation and error types.

Production implementations root:
- `src/implementations/mod.rs` - implementation namespace for client/server production runtimes.

Client implementation (`src/implementations/client/`):
- `src/implementations/client/mod.rs` - `ClientRuntime`, state machine, subsystem composition.
- `src/implementations/client/backend.rs` - unified cross-platform client backend API and state/stats/error model.
- `src/implementations/client/connection.rs` - client connection wrapper around `QuicFuscateConnection`.
- `src/implementations/client/integration.rs` - integration test scaffolding (`MockServer`, `TestClient`, `TestHarness`).
- `src/implementations/client/io_driver.rs` - async packet hotpath driver and performance counters/thresholds.
- `src/implementations/client/killswitch.rs` - platform kill-switch lifecycle and backend execution.
- `src/implementations/client/pipeline.rs` - inbound/outbound pipeline stages and pipeline error/stat types.
- `src/implementations/client/profile.rs` - profile persistence/load/save and profile manager.
- `src/implementations/client/quality.rs` - connection quality and bandwidth tracking utilities.
- `src/implementations/client/runtime.rs` - Tokio runtime creation/shared runtime helpers.
- `src/implementations/client/subsystems.rs` - subsystem initialization glue.
- `src/implementations/client/platform/mod.rs` - platform abstraction root and platform selection.
- `src/implementations/client/platform/traits.rs` - platform backend trait contracts (TUN/routes/DNS/privileges).
- `src/implementations/client/platform/linux.rs` - Linux platform backend.
- `src/implementations/client/platform/macos.rs` - macOS platform backend.
- `src/implementations/client/platform/windows.rs` - Windows platform backend.

Server implementation (`src/implementations/server/`):
- `src/implementations/server/mod.rs` - `ServerRuntime`, server state/stats, orchestration root.
- `src/implementations/server/accept.rs` - production accept loop, per-IP limits/backpressure/reject reasons.
- `src/implementations/server/admin.rs` - Unix admin socket protocol and handler contracts.
- `src/implementations/server/admin_http.rs` - HTTP admin server, auth/session API, config and QKey endpoints.
- `src/implementations/server/admin_logs.rs` - in-memory admin log buffer and line model.
- `src/implementations/server/ip_pool.rs` - server-side tunnel IP allocation pool.
- `src/implementations/server/limits.rs` - rate limiting and connection limiting primitives.
- `src/implementations/server/metrics.rs` - metrics registries and HTTP metrics servers.
- `src/implementations/server/qkey_registry.rs` - persistent QKey records, ids, token hash management.
- `src/implementations/server/routing.rs` - routing/NAT/forwarding integration and WAN interface detection.
- `src/implementations/server/session.rs` - session ids, session state and session manager.
- `src/implementations/server/systemd.rs` - systemd-oriented service/unit integration helpers.

Optimize submodules (`src/optimize/`):
- `src/optimize/brain.rs` - optimize helpers used by brain/statistical hotpaths.
- `src/optimize/compress.rs` - compression-oriented acceleration primitives.
- `src/optimize/crypto/mod.rs` - optimize crypto namespace root.
- `src/optimize/crypto/aegis.rs` - AEGIS acceleration kernels.
- `src/optimize/crypto/morus.rs` - MORUS acceleration kernels.
- `src/optimize/crypto/planner.rs` - crypto backend planning and dispatch helpers.
- `src/optimize/iter.rs` - SIMD-backed reduction helpers.
- `src/optimize/memory.rs` - memory pool and allocation tuning internals.
- `src/optimize/random.rs` - random generation acceleration paths.
- `src/optimize/sort.rs` - SIMD sort/argsort helpers.
- `src/optimize/stealth.rs` - stealth acceleration helpers.
- `src/optimize/string.rs` - string/text acceleration helpers.
- `src/optimize/telemetry.rs` - global telemetry counters and snapshot/export helpers.
- `src/optimize/transport.rs` - transport acceleration helpers.
- `src/optimize/udp.rs` - UDP fastpath helper layer.
- `src/optimize/x86_sse2.rs` - x86 SSE2-specific compatibility and helper kernels.

SIMD submodules (`src/simd/`):
- `src/simd/arm_stream.rs` - ARM stream-oriented SIMD helpers.
- `src/simd/arm_varint.rs` - ARM varint SIMD helpers.
- `src/simd/x86_ack.rs` - x86 ACK-related SIMD helper path.
- `src/simd/x86_header.rs` - x86 header parse/validate SIMD helper path.

Transport submodules (`src/transport/`):
- `src/transport/config.rs` - transport configuration surface.
- `src/transport/connection.rs` - core transport connection state machine and send/recv path.
- `src/transport/frames.rs` - frame encoders/decoders and canonical ACK block logic.
- `src/transport/h3.rs` - HTTP/3 state machine (streams, QPACK, events, MASQUE wiring).
- `src/transport/packet.rs` - QUIC packet parse/build, encryption/decryption glue.
- `src/transport/pn.rs` - packet number and varint helpers.
- `src/transport/recovery.rs` - loss detection/recovery controller.
- `src/transport/batch.rs` - batched IO helpers.
- `src/transport/xdp.rs` - XDP/fastpath compatibility layer and runtime gating.

### Governance Overview
- Cross-cutting engineering principles and policies: see "Governance (Canonical)".
- Contributions: see `docs/CONTRIBUTING.md` for guidelines and PR requirements.
- Linux-only verification tracks: Linux-specific tests and fast-path benchmarks are retained as optional reference tracks.
- Runtime/implementation depth for stealth, transport, optimization, and FEC belongs to the dedicated technical sections below.

## Documentation Index (Aggregated)
This section points to technical documentation and READMEs living under `docs/`. It does not cover the GitHub root README.

Key pointers:
- Usage and suite quickstart - see "Usage".
- Governance and deterministic workflow - see "Governance (Canonical)".
- Example configuration - see "Configuration Reference (Full)".

---
## Usage

### Script-Based Operations
Execute specific functionality using dedicated scripts organized in purpose-built directories:

Common examples:
```bash
./scripts/tests/build/build-check.sh
./scripts/tests/utils/util-run-full-suite.sh
./scripts/tests/suites/test-core.sh
./scripts/tests/suites/test-crypto.sh
./scripts/tests/utils/util-e2e-verify-all.sh
```

Each script is self-contained and handles specific functionality. Scripts can be combined for complex workflows or executed individually for targeted operations. Use environment variables like `QUICFUSCATE_BROWSER` and `QUICFUSCATE_OS` to override the active fingerprint profile.

All scripts include a unified, minimal help handler accessible via `-h`, `--help`, or `help`. It prints `Usage: <script>` together with the first `# Description:` line found in the script, then exits early with code `0` and no side effects.

### TUN interface example (feature-gated)
The TUN example is gated behind the Cargo feature `tun-tests` to avoid impacting default builds. Use the following command:
```bash
# Run example demonstrating factory registration
cargo run --features tun-tests --example tun_factory_example
```

Notes:
- The example integrates with `MemoryPool` to exercise zero-copy paths.

### Scripts Reference (Authoritative)
This section is the authoritative build/packaging script reference in this document. Script-produced artifacts are written to `scripts/out/<category>/` (including build-release artifacts under `scripts/out/build/...`).
For the broader script inventory and repository-wide file index, use `docs/MAP.md`.

#### Build and Packaging (`scripts/build/`)
- `build-web-admin.sh` - Builds `apps/web-admin-ui` and publishes bundle to `assets/web-admin/`.
- `build-server-bundle.sh` - Produces a server bundle into `scripts/out/build/` for deployment packaging.

### Release Scope
- Distribution model: source-first release (open-source code distribution).
- Signed desktop binaries are not part of the shipped source artifact set.
- Updater integration exists in code and remains disabled in shipped source builds unless signed artifacts are provided.

### Release Security Audit Baseline

Audit command evidence:
- `cargo clippy --workspace --all-targets -- -D warnings` -> pass.
- `cargo test --workspace --all-targets` -> pass.
- `cd apps/web-admin-ui && bun run test:unit && bun run check` -> pass.
- `cd apps/desktop && bun run test:unit && bun run check` -> pass.
- `cargo audit --json > scripts/out/tests/cargo-audit.json` -> pass (`vuln_count=0`, `warnings_count=0`).
- `cd apps/desktop/src-tauri && cargo check && cargo clippy --all-targets && cargo audit --json` -> `check`/`clippy` pass; audit reports 18 informational transitive advisories (`17 unmaintained`, `1 unsound`) in the Tauri desktop dependency chain with `vulnerabilities.found=false` (`count=0`).
- `./scripts/tests/audits/audit-all-comprehensive.sh` -> executed; policy report flags high unsafe and unwrap counts and exits non-zero by design when findings exist.

Attack surface and control mapping:
- Admin authentication and session surface:
  - controls: Argon2 hashes, `HttpOnly` cookies, `SameSite=Strict`, secure-cookie behavior tied to HTTPS forwarding, per-IP failed-login throttling and lockout, password-change lock (`423`) paths, same-origin POST validation (`Origin` must match `Host` when present), and per-session CSRF token checks on authenticated POST routes.
  - verification: `implementations::server::admin_http` tests for lockout, throttling, cookie flags, lock removal, and cross-origin POST rejection.
- QKey issuance and revocation surface:
  - controls: strict QKey parsing and canonicalization, stable token IDs, TTL normalization, revoke path validation, persisted registry constraints, and runtime auth-state rebind on source-address churn by DCID/source-id matching.
  - verification: `implementations::server::qkey_registry` tests, admin HTTP QKey API tests, and `qkey_auth_tests::engine_qkey_id_matches_registry_qkey_id`.
- Engine connect-state surface:
  - controls: `engine.connect()` is handshake-aware and only sets `Connected` after runtime handshake establishment within a bounded timeout.
  - verification: `engine::engine::tests::test_engine_connect_disconnect`.
- Static admin asset serving:
  - controls: traversal rejection and SPA-safe fallback routing.
  - verification: `static_assets_rejects_path_traversal_with_403`, `static_assets_serves_index_for_spa_routes`.
- Desktop IPC command surface:
  - controls: typed command payload validation, failure-path tests for connect and state persistence, keychain-backed secret storage path.
  - verification: desktop unit tests in `apps/desktop/src`.

Probe detection telemetry review:
- Counters are emitted in telemetry export and wired to runtime paths:
  - `quicfuscate_stealth_probe_detected_total`
  - `quicfuscate_stealth_probe_switch_total`
  - `quicfuscate_stealth_probe_fake_total`
  - `quicfuscate_stealth_probe_block_total`
  - `quicfuscate_stealth_mode_escalated_total`
- Validation coverage:
  - deterministic probe suite: `cargo test --release --features rust-tests --test rt-probe-detection -- --nocapture`
  - suite wrapper with optional soak loop: `./scripts/tests/suites/test-probe-detection.sh --fast --soak-iters 2`
- Operational alert guideline (initial release baseline):
  - investigate if `quicfuscate_stealth_mode_escalated_total` increases repeatedly in short windows.
  - investigate if `quicfuscate_stealth_probe_detected_total` rises without matching network pressure events.

Security findings table:
| Severity | Finding | Impact | Status | Owner |
|---|---|---|---|---|
| medium | Comprehensive audit script reports many `unsafe` blocks | higher review burden for memory-sensitive paths | accepted with controls | core runtime |
| medium | Comprehensive audit script reports many `unwrap` call sites | potential panic if assumptions are broken | accepted with controls | core runtime |
| low | Updater/signature enforcement not active in source-first release | no binary auto-update trust chain in shipped source artifacts | out of current artifact scope | desktop release |

Current release constraints:
- No signed desktop binaries are provided.
- Updater runtime is integrated but disabled in shipped source builds without signing.

### Threat Model

Assets:
- Server private key and runtime secret material.
- Admin credentials, cookies, and lockout state.
- QKey token registry and revocation state.
- Desktop local tunnel state and keychain-backed secrets.
- Build and release metadata for the current source-first distribution path.

Trust boundaries:
- Public QUIC ingress boundary.
- Admin HTTP/API boundary.
- Desktop local process and IPC boundary.
- Local filesystem persistence boundary.

Primary threat scenarios:
- Brute-force and credential stuffing on admin login.
- Session theft and cookie misuse behind misconfigured proxies.
- QKey abuse, replay attempts, or unauthorized issuance.
- Config tampering through malformed admin API payloads.
- Active-probe pressure and stealth-profile misclassification.
- Desktop local misuse through invalid tunnel or secret inputs.

Threat to mitigation mapping:
- Brute-force and stuffing -> per-IP failed-login limits and 429 lock paths.
- Session misuse -> secure cookie flags, strict SameSite, explicit forwarded-proto checks.
- QKey abuse -> strict parser, canonical IDs, revoke support, disk persistence constraints.
- Config tampering -> schema and payload validation plus explicit rejection status codes.
- Probe pressure -> adaptive stealth/FEC controls plus deterministic test suites.
- Desktop misuse -> typed validators, migration sanitization, and failure-path tests.

Residual threat profile:
- False positives in probe-detection paths under extreme jitter/loss remain part of the validation stream.
- Signed update-channel threats are outside the current source-first artifact scope.

### Deployment Hardening Guide

Server hardening baseline:
- Bind admin HTTP only to trusted interfaces or localhost.
- Enforce firewall rules for QUIC and admin ports; deny all unused inbound paths.
- Run service under dedicated non-root user with minimal filesystem permissions.
- Restrict `config/` and persistent state paths to owner-only access.
- Configure log rotation and retention; avoid logging sensitive token material.
- Back up config and QKey registry on controlled intervals with encrypted storage.

Admin UI hardening baseline:
- Put admin UI behind HTTPS termination in production.
- Ensure forwarded-proto headers are set correctly by the trusted proxy.
- Rotate default admin credentials on first bootstrap.
- Operate IP blocklist with explicit review and rollback procedure.

Desktop hardening baseline:
- Keep updater disabled for source-first builds.
- Store secrets in OS keychain path where available.
- Keep local state sanitized on load and persist only normalized structures.
- Prefer fixed window constraints and explicit close behavior for predictable UX.

Operational hardening:
- Pre-release smoke: run clippy/tests/UI checks and record outputs in `scripts/out/tests/`.
- Incident response: immediate revoke of affected QKeys, rotate admin password, restart service, verify telemetry counters.
- Rollback: restore previous config and QKey registry backup, restart, re-run smoke checks.

Verification commands:
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace --all-targets`
- `cd apps/web-admin-ui && bun run test:unit && bun run check`
- `cd apps/desktop && bun run test:unit && bun run check`
- `cargo audit --json > scripts/out/tests/cargo-audit.json`

#### Build (`scripts/tests/build/`)
- `build-release.sh` - Release build with native optimizations (LTO, codegen-units=1, strip)
- `build-debug.sh` - Debug build with debuginfo
- `build-check.sh` - Format, Clippy, compile checks, test/bench compilation
- `build-clippy-matrix.sh` - Clippy feature-matrix sweep (aligns with CI variants)
- `build-dev-tools.sh` - Tooling checks (format, clippy, docs, feature combos, binary size)
- `build-env-doctor.sh` - Environment/Toolchain diagnostics

#### Analysis (`scripts/tests/analysis/`)
- `analysis-coverage-summary.sh` - Coverage summary (JSON/text)
- `analysis-dead-code-report.sh` - Dead code report (JSON/text)
- `analysis-scripts-quality.sh` - Script quality/static consistency checks
- `analysis-suite-matrix.sh` - Test/benchmark suite matrix report generation

#### Library (`scripts/tests/lib/`)
- `lib-common.sh` - Shared helpers (logging, JSON, env detection)

#### Library (`scripts/lib/`)
- `lib-common.sh` - Shared shell helpers used by top-level build and utility scripts.

#### Tests (`scripts/tests/`)
**Suites (`scripts/tests/suites/`)**
- `test-core.sh` - Core integration tests (CLI/telemetry/profile/qftls/reality/config)
- `test-profile-overrides.sh` - Deterministic profile override parity tests
- `test-profile-fuzz-parity.sh` - Fuzz-style parity tests (scalar vs SIMD) with forced profiles
- `test-fec.sh` - FEC suite (all modes + GF16/GF8/Wiedemann/Partial/Adaptive/Stress; add `--refactor` / `--refactor-only` for structural invariants)
- `test-fec-simulation.sh` - FEC simulation under varied loss/threads/mode matrices
- `test-fec-e2e-loss.sh` - Deterministic FEC E2E loss matrix using seeded `fec_sim` runs and explicit ratio thresholds
- `test-stealth.sh` - Stealth suite (browser/OS profiles, padding, DoH, H3 masquerade, rotation)
- `test-stealth-brain.sh` - StealthBrain ACK policy optimization tests
- `test-probe-detection.sh` - Active-probe validation (detector invariants, reality fallback rotation, optional stealth pressure path)
- `test-crypto.sh` - Crypto suite (AEGIS/MORUS/AES-GCM/ChaCha20/HKDF/CT operations)
- `test-transport.sh` - Transport suite (varint/frames/loss/BBR/0-RTT/migration/DATAGRAM; io_uring on Linux)
- `test-optimization.sh` - Optimize suite (MemoryPool/NUMA/HugePages/SIMD/prefetch/zero-copy) + SIMD/accelerate fixtures (`--features rust-tests,simd-selfcheck`; override via `CARGO_FEATURES`)
- `test-security-fuzzing.sh` - Security & fuzzing (ASAN/MSAN/UBSAN, fuzz targets, concurrency, `rt-property-suite` via proptest)
- `test-performance-regression.sh` - Performance regression with baseline comparison
- `test-e2e-integration.sh` - E2E scenarios (client/server, FEC, stealth, full-stack)
- `test-e2e.sh` - End-to-end integration tests with real network scenarios
- `test-e2e-admin-web.sh` - Admin web E2E (login/status/config/qkey + headless QKey connect via `qf-e2e-client` and `qf-e2e-desktop`)
- `test-desktop-webadmin-rust-integration.sh` - Cross-surface desktop/web-admin/core integration contract checks
> Note: `test-all.sh` was archived; run suites sequentially or use `util-run-full-suite.sh` which delegates to the individual suite scripts.

**Fuzzing (cargo-fuzz, optional)**
- Tooling: `cargo install cargo-fuzz` (requires a nightly Rust toolchain for fuzz runs).
- Targets live under `scripts/tests/fuzz/fuzz_targets/` and are wired in `scripts/tests/fuzz/Cargo.toml`.
- Seed corpora live under `scripts/tests/fuzz/seeds/<target>/`.
- List targets: `cd scripts/tests/fuzz && cargo fuzz list`
- Run a target: `cd scripts/tests/fuzz && cargo fuzz run packet_parsing`
- Runtime corpus/crash/target outputs are centralized under `scripts/out/tests/<run>/fuzz/...` by `scripts/tests/suites/test-security-fuzzing.sh`.
- Local paths `scripts/tests/fuzz/corpus/` and `scripts/tests/fuzz/artifacts/` are not part of the runtime output workflow.
- Seed dedupe utility: `scripts/tests/utils/util-fuzz-seed-curate.sh` (per-target SHA-256 deduplication).

**Fast runs (`scripts/tests/fast/`)**
- `test-fast-crypto.sh` - Fast crypto sanity (TLS Cover parity + Wiedemann scalar telemetry)
- `test-fast-fec.sh` - Fast FEC sanity (GF8/GF16 + benches compile)

**Quick validation profile (macOS / Apple Silicon)**
- Fast confidence pass:
  - `scripts/tests/fast/test-fast-crypto.sh`
- Telemetry counter snapshot:
  - `cargo test --features rust-tests --test rt-telemetry-counters -- telemetry_counters_snapshot --nocapture`
- Optional longer micro-benchmark refresh:
  - `scripts/benchmarks/micro/micro-crypto-all.sh --fast`

**Smoke (`scripts/tests/smoke/`)**
- `smoke-avx10.sh` - AVX10.1 feature detection + targeted SIMD self-checks & microbench capture (skips when hardware absent; run with `cargo --features avx10_preview`)
- `smoke-sve2.sh` - SVE2 smoke (self-check + telemetry + stream parse)
- `smoke-ui-frontends.sh` - Frontend smoke pass for desktop/web-admin build-level sanity

**Rust test helpers (`scripts/tests/rust/`)**
- Parity and telemetry-only Rust fixtures used by suites/smoke
- `rt-security-suite` covers security suite patterns (malformed input, overflow, concurrency, protocol abuse, crypto/FEC properties) for `test-security-fuzzing.sh`.
- `rt-profile-overrides` validates `QUICFUSCATE_PROFILE_OVERRIDE` parity between scalar and SIMD paths.
- `rt-profile-fuzz-parity` runs randomized parity checks across scalar and SIMD fast paths.

> Note: Linux fast paths (io_uring datagram send, MASQUE DATAGRAM) are runtime-gated and auto-enable when the kernel exposes the required syscalls. macOS tooling still skips these checks by default-run targeted Linux smoke suites when touching transport or MASQUE code paths.

> AVX10 rollout: Once real AVX10.1 hardware is available, build with `cargo --features avx10_preview` and run `./scripts/tests/smoke/smoke-avx10.sh --require --output-dir <artifacts>`, archive the generated logs (profile + bench CSVs), and update this document with validated results.

#### Benchmarks (`scripts/benchmarks/`)
**Suites (`scripts/benchmarks/suites/`)**
- `bench-orchestrator.sh` - Orchestrates benchmark matrix; writes `manifest.json`, `summary.txt`, and per-suite logs under `scripts/out/benchmarks/`
- `bench-fec.sh` - FEC benchmarks (encoder/decoder/Wiedemann/GF16/parallelization)
- `bench-fec-simulation.sh` - FEC performance under simulated network conditions
- `bench-crypto.sh` - Extended crypto benchmarks with all cipher suites
- `bench-transport.sh` - Transport benchmarks (packet/varint/frames/streams; io_uring on Linux)
- `bench-optimization.sh` - Memory/NUMA/HugePages/SIMD/prefetch/zero-copy
- `bench-stealth.sh` - Stealth module performance (padding, masquerading, obfuscation)
- `bench-stealth-brain.sh` - StealthBrain ACK policy optimization benchmarks
- `bench-compression.sh` - Compression microbenchmarks (`examples/compress_bench.rs`) for text and binary payloads with JSON output
- `bench-qpack-encode.sh` - QPACK encode benchmark harness
- `bench-profile-transport-fastpaths.sh` - Transport profiling (Tokio vs io_uring)
- `bench-nightly.sh` - Ordered nightly bench runner

**Micro (`scripts/benchmarks/micro/`)**
- `micro-crypto-all.sh`, `micro-aes-block.sh`, `micro-aes-gcm.sh`, `micro-ghash.sh`, `micro-chacha-x4.sh`, `micro-udpfast-throughput.sh`
  - Micro JSON output: each script writes `<name>.json` with a `meta` object (e.g., `iters`, `sizes`, `batch`, `bind`, `remote`) plus per-command entries.

**Smoke (`scripts/benchmarks/smoke/`)**
- `smoke-fec-quick.sh` - Quick FEC smoke tests for rapid validation

**Wrappers (`scripts/benchmarks/wrappers/`)**
- `wrap-crypto.sh`, `wrap-fec.sh` (canonical wrappers)

#### Audits (`scripts/tests/audits/`)
- `audit-all-comprehensive.sh` - Consolidated audit (security/dependencies/quality/performance) with clear exit codes
- `audit-readiness-gates.sh` - Readiness gate checks for release and CI quality thresholds

#### Utils (`scripts/tests/utils/`)
- `util-run-full-suite.sh`
- TLS utilities: `util-tls-generate-sha256-sidecars.sh`, `util-tls-diff-profiles.sh`, `util-tls-export-active-profile.sh`, `util-tls-list-profiles.sh`, `util-tls-profile-head.sh`, `util-tls-show-active-env.sh`
- E2E profile utilities: `util-e2e-decode-all-profiles.sh`, `util-e2e-verify-all.sh`, `util-e2e-verify-current.sh`
 
General utilities (`scripts/utils/`):
- `util-analyze-codebase.sh`, `util-check-quality.sh`, `util-release-source-package.sh`
- `util-cleanup-workspace.sh` - primary cleanup entrypoint (`--safe|--full`, `--keep-releases N`, optional `--cargo-clean`)
- `util-dev-uis-start.sh`, `util-dev-uis-stop.sh` - start/stop local frontend dev servers with PID tracking under `scripts/out/run/dev-uis`
- `util-run-local-ui.sh`, `util-stop-local-ui.sh` - local stack orchestration helpers for UI + server workflows

#### Artifacts (`scripts/out/`)
- Bench/test scripts write timestamped artifacts here, e.g., `scripts/out/<category>/<script>-<timestamp>/` with JSON + logs.
- `scripts/out/` is intentionally gitignored and remains the canonical runtime/build/test artifact sink.
  Exported JSON reports originate from the individual suite scripts; `util-run-full-suite.sh` aggregates test runs, and benchmark suites emit their own summaries.

**JSON schema (suite results)**
```json
{
  "schema": "<suite-schema-id>",
  "tool": "quicfuscate",
  "suite": "test-crypto",
  "timestamp": "2026-01-25T12:34:56-08:00",
  "system": {
    "os": "Darwin",
    "arch": "arm64",
    "cpu_cores": 8,
    "memory_gb": "16.0"
  },
  "items": [
    {"cmd": "cargo test --release ...", "rc": 0, "duration_sec": 12}
  ]
}
```

**JSON schema (micro benches)**
- Each micro script writes `<name>.json` with a leading `meta` object and per-command entries.
```json
{
  "schema": "<bench-schema-id>",
  "tool": "quicfuscate",
  "suite": "micro-aes-block",
  "timestamp": "2026-01-25T12:34:56-08:00",
  "system": { "os": "Darwin", "arch": "arm64", "cpu_cores": 8, "memory_gb": "16.0" },
  "items": [
    {"meta": {"iters": 1000, "sizes": "256B 1KiB 16KiB 1MiB"}},
    {"cmd": "cargo run --release ...", "rc": 0, "duration_sec": 3}
  ]
}
```

Compile-time bench metadata (feature `benches`):
- `QUICFUSCATE_GIT_REV`, `QUICFUSCATE_CPU_MODEL`, `QUICFUSCATE_RUSTC_VERSION` are read via `option_env!` at build time and embedded in the JSON output.

#### Benchmarking Scripts - Guide
Performance measurements are consolidated via the individual benchmark suites (optionally coordinated with `bench-orchestrator.sh`). All scripts detect OS/Arch/features (Linux: io_uring; XDP compatibility mode) and export reports (text/JSON) to `scripts/out/<category>/`.

**Tooling status**
- Tooling naming and structure finalized: tests use `test-*.sh`, benchmarks use `bench-*.sh`, micro benches use `micro-*.sh`, wrappers use `wrap-*.sh`.
- `test-fec.sh` handles `--refactor` directly.
Notes:
- Build runs automatically in release mode with native flags.
- JSON exports include `time`/`throughput` per sub-benchmark.
- Comparison blocks (FEC/Crypto) summarize key metrics.

Microbench CLI (example harness): `bitpack <bw> <vals> <iters>`, `bitunpack <bw> <vals> <iters>`, `qpack-enc <bytes> <iters>`, `qpack-dec <bytes> <iters>`, `popcnt <bytes> <iters>`. Coverage: NEON bitpack (1-8 bit widths) with SVE2 wrapper, NEON/SVE2 QPACK encode/decode wrappers, NEON core popcount (`vcntq_u8` + horizontal sum).



#### Environment-driven benchmark controls
Benchmark scripts do not define a shared benchmark env interface. Use the runtime env
overrides documented elsewhere (for example `QUICFUSCATE_FEC_KERNEL`, `QUICFUSCATE_RAYON_THREADS`,
`QUICFUSCATE_MADVISE_HUGEPAGE`, `QUICFUSCATE_NUMA_POLICY`) when invoking the benches. Script-specific
flags are documented in each `bench-*.sh` header.

#### Script Organization

All scripts live under `scripts/` and are categorized in lowercase:
- `scripts/tests/build/`
- `scripts/benchmarks/`
- `scripts/tests/audits/`
- `scripts/tests/`
- `scripts/tests/utils/`

Each category contains focused runners with consistent naming and robust error handling.
Naming uses lowercase kebab-case with a category prefix (e.g., `test-crypto.sh`, `test-fast-fec.sh`, `micro-ghash.sh`, `wrap-crypto.sh`).

#### Upstream Utilities
The active QUIC stack is maintained in-tree as a QuicFuscate-adapted code lineage. There is no build-time dependency on upstream quiche and no `libs/` workflows; all scripts operate solely against `src/`.

### Building Binaries (macOS, Linux, Windows)

Platform builds are executed from `src/` via consolidated scripts under `scripts/tests/build/`:

- `./scripts/tests/build/build-release.sh` - Release build (optional Linux fast paths via `--features "uring_sys zero_copy_dgram"` or the grouped `optimized` feature)
- `./scripts/tests/build/build-debug.sh` - Debug build
- `./scripts/tests/build/build-check.sh` - Format/Clippy/Compile/Test/Bench compilation
- `./scripts/tests/build/build-dev-tools.sh` - Tooling/feature checks, binary size analysis

Artifacts are copied to `scripts/out/build/<run>/release-<timestamp>/` by `build-release.sh`.

#### TLS Profile Sidecars (Generating and Verifying)
These utilities are only relevant if you maintain external base64 ClientHello dumps (for example in `browser_profiles/`). The runtime does not require on-disk profiles because it generates ClientHello bytes in memory.

- Generate sidecars snapshot: `./scripts/tests/utils/util-tls-generate-sha256-sidecars.sh` (writes to `scripts/out/utils/.../sidecars/`)
- Verify all profiles: `./scripts/tests/utils/util-e2e-verify-all.sh` (optional `--sidecars-dir <scripts/out/.../sidecars>` to verify snapshot sidecars)

Tool detection and portability
- Base64: The utilities auto-detect the correct decode flag at runtime (GNU `base64 -d`; BSD or macOS `base64 -D`) and always read input via stdin.
- Hashing: Uses `shasum -a 256` when available, otherwise `sha256sum`. Only the first whitespace-delimited field (hex digest) is compared.
- Locations: External dumps are discovered under top-level `browser_profiles/` (preferred). Sidecars are written next to the dumps.

Tips
- Use `./scripts/tests/utils/util-e2e-verify-current.sh` to validate only the active profile, selected via `QUICFUSCATE_BROWSER` and `QUICFUSCATE_OS` (optional `--sidecars-dir`).
- The decode and verify helpers operate locally and do not perform any network I/O.

### Client

  ```
  quicfuscate client \
    --remote 203.0.113.1:4433 \
    --local 127.0.0.1:1080 \
    --profile chrome \
    --os windows \
    --cc-algorithm cubic \
    --front-domain cdn.example.com \
    --verify-peer \
    --config ./config/quicfuscate.toml
  ```

Telemetry metrics are disabled by default. Launch the binary with `--telemetry` to enable internal counters and expose a local snapshot at `/telemetry` through `metrics::spawn_telemetry_server()` (bind address `QUICFUSCATE_METRICS_ADDR`, default `127.0.0.1:9898`), or call `optimize::telemetry::telemetry_snapshot_text()` programmatically.

#### Telemetry Metrics
Telemetry metrics exposed by `optimize::telemetry::telemetry_snapshot_text()` include:

**MASQUE/Transport:**
- `quicfuscate_masque_capsule_00_total`, `quicfuscate_masque_capsule_21_total`, `quicfuscate_masque_capsule_22_total`

**Compression Module:**
- `quicfuscate_compress_attempts_total`, `quicfuscate_compress_success_total`
- `quicfuscate_compress_bytes_in_total`, `quicfuscate_compress_bytes_out_total`

**Memory/Pool:**
- `quicfuscate_body_pool_allocs_total`, `quicfuscate_mem_pool_hits_tls_total`, `quicfuscate_mem_pool_hits_queue_total`
- `quicfuscate_mem_pool_alloc_grow_total`, `quicfuscate_mem_pool_alloc_ephemeral_total`

**SIMD/Performance:**
- `quicfuscate_simd_usage_avx2_total`, `quicfuscate_simd_usage_avx512_total`

#### Client Runtime Orchestration

`implementations::client::ClientRuntime` wires the production client execution path:

- `ProfileManager` (QKey-derived profile preferences and replay),
- zero-copy `MemoryPool`,
- optional `TunInterface`,
- `StealthManager`,
- `AdaptiveFec`,
- `IoDriver`,
- optional `KillSwitch`,
- shared Tokio runtime state.

`KillSwitch` is implemented in `implementations::client::killswitch` with platform-native firewall backends (Linux iptables, macOS pfctl, Windows netsh) and lifecycle hooks (`on_vpn_connected` / `on_vpn_disconnected`) to enforce fail-closed routing when configured.

Packet flow is unified across CLI and embedded paths:

- outbound: `TUN -> Stealth -> FEC -> QUIC`
- inbound: `QUIC -> FEC decode/recovery -> Stealth unwrap -> TUN`

`--profile-seq` and `--profile-interval` feed the same runtime control path used by command/API overrides.

### Server

  ```
  quicfuscate server \
    --listen 0.0.0.0:4433 \
    --cert ./tls-cert.pem \
    --key ./tls-key.pem \
    --profile firefox \
    --os linux \
    --cc-algorithm bbr2 \
    --config ./config/quicfuscate.toml
  ```

Ensure certificate and key are valid PEM files. Use `CTRL+C` to gracefully stop the process.

Use the `--config` flag to load a unified TOML file containing FEC, stealth and optimization settings. See the section "Configuration Reference (Full)" for details.

#### Server Runtime Orchestration

`implementations::server::ServerRuntime` owns the active server data/control plane and combines:

- engine/server configuration domains,
- memory pool and transport runtime,
- TUN bridging,
- session manager and IP pool allocation,
- NAT/routing management,
- rate/connection limiters,
- admin HTTP surfaces,
- telemetry/metrics export surfaces.

This ensures the standalone server binary and embedded control-plane integrations share one runtime behavior model.
 
Server Options (selected):

```
    --tun                   Enable TUN bridging (optional)
    --tun-name <name>       TUN interface name
    --tun-mtu <mtu>         TUN MTU (default 1500)
    --tun-ip <addr>         TUN IP address
    --tun-netmask <addr>    TUN netmask
    --admin-socket <path>   Unix admin socket (status/clients/kick/block/reload/qkey/shutdown)
    --admin-web <addr>      HTTP admin web bind address (e.g. 127.0.0.1:9000)
    --admin-web-root <dir>  Static root for the web admin bundle (default: assets/web-admin)
    --admin-web-user <user> Admin username (or env QUICFUSCATE_ADMIN_USER)
    --admin-web-password <pass> Admin password (or env QUICFUSCATE_ADMIN_PASSWORD)
    --qkey-ttl-secs <secs> Default QKey TTL in seconds (0 disables expiration; env QUICFUSCATE_QKEY_TTL_SECS)
    --qkey-store <path> QKey registry store path (recommended: /var/lib/quicfuscate/qkeys.json)
    --metrics-port <port>   Metrics HTTP port (text format at /metrics)
```

### Desktop App (Tauri 2)

The desktop client lives in `apps/desktop/` and provides a native GUI for tunnel management, settings, logs, and hardware detection.
Current status: early beta for desktop delivery. Core tunnel operations are functional; desktop packaging/signing hardening and some platform-specific release tracks remain in progress.

**Stack:**
- Runtime: Tauri 2 (Rust sidecar with webview)
- Frontend: React 19 + TypeScript, Vite, TailwindCSS
- Components: HeroUI (NextUI successor)
- State: Jotai atoms (`apps/desktop/src/stores/atoms.ts`, `types.ts`)
- Animations: Framer Motion (tab transitions, layout animations)

**Views:**
- **Tunnels**: List of configured tunnels with live state indicators (active/inactive/activating), real-time stats (latency, loss, throughput, uptime, stealth mode, FEC mode), connect/disconnect actions, and an add-tunnel dialog.
- **Settings**: Three-tab layout (General, Connection, Hardware) with server-authoritative connection policy:
  - Stealth and FEC are displayed as server-driven values from the active QKey policy.
  - No local client override is applied for Stealth/FEC policy.
  - General tab includes startup policy (`autoConnectOnLaunch`, `startAtLogin` preference) and updater policy/channel toggles.
  - Updater state panel exposes deterministic no-update, update-available, download/install progress, and signature-failure states.
  - Hardware tab detects CPU SIMD features via Tauri `invoke("detect_cpu_features")`.
- **Logs**: Scrollable log viewer with level-colored entries (error/warn/info/debug/trace), auto-scroll, and clear functionality.
- **About**: Version and system information.

**Engine Polling:**
- Status poller (500 ms): fetches `engine_status` and updates tunnel state map via `tunnelsRef` (ref-based to avoid interval re-creation on tunnel list changes).
- Stats poller (900 ms): fetches `engine_stats` for the active tunnel (latency, loss, bytes, packets, uptime, stealth/FEC mode).
- Logs poller (350 ms): incremental log fetch via `engine_logs_since` with cursor tracking; ring-buffers at 2000 entries.

**Persistence:**
- State (tunnels, settings, selected tunnel) is loaded on startup via `invoke("load_state")` and saved on change via `invoke("save_state")` with a 450 ms debounce timer to avoid excessive disk writes.

**Build:**
```bash
cd apps/desktop && bun install && bun run tauri build
```

**Window Model:**
- The production desktop window is fixed to `920 x 640` in `apps/desktop/src-tauri/tauri.conf.json` with `resizable: false`, `minWidth: 920`, and `minHeight: 640`.

**Tray and Startup Behavior:**
- Closing the main window hides it instead of exiting; runtime continues in tray.
- Tray menu exposes status, active tunnel summary, connect/disconnect, open/hide app, auto-connect-on-launch toggle, start-at-login preference toggle, and quit.
- Auto-connect-on-launch reads persisted desktop settings and attempts connection on startup when enabled.
- Start-at-login persists user preference and is wired to OS auto-start registration via the desktop runtime plugin.

**Updater Integration (source-first):**
- Updater plugin path is integrated but runtime-gated behind `QUICFUSCATE_DESKTOP_UPDATER_ACTIVE`.
- Default is disabled; signed artifacts are required before enabling update delivery in shipped binaries.
- Desktop UI includes updater policy/status so no-update, available, download/install, and signature-failure states are explicit.

**Verification (frontend):**
```bash
cd apps/desktop && bun run check
cd apps/desktop && bun run test:unit
```

### Web Admin (React)

The web admin UI is a React app built from `apps/web-admin-ui/`. Build and copy the bundle into
`assets/web-admin/` before starting the server with `--admin-web`:

```
scripts/build/build-web-admin.sh
```

The bundle output layout is `assets/web-admin/index.html` plus `assets/web-admin/assets/*` (JS/CSS).
Keep `--admin-web-root` pointing at `assets/web-admin` so `/assets/...` paths resolve correctly.

Admin HTTP contract notes:
- JSON endpoints respond with `AdminResponse { success, message, data }` and `/api/clients` is wrapped.
- Admin API failures return appropriate HTTP error statuses (`4xx`/`5xx`) while keeping the same `AdminResponse` envelope (`success: false`, optional `message`/`data`).
- `/api/qkey` is `POST` only, accepts `{ stealth, fec, ttl_seconds }` (presets + optional TTL), and returns `{ qkey, created_at, expires_at }` in `data`.
- `/api/qkeys` returns entries with `created_at` and optional `expires_at` (expired entries are pruned).
- QKey strings include the embedded token field and are validated in the admin contract test.
- `/api/clients/{id}/kick` is supported as an alias for `/api/kick`.
- `/api/status` includes `config_writable` for UI gating.
- `/api/config/logging` (`GET`/`POST`): read and set logging mode (verbose/normal/minimal/no-log).
- `/api/logs?cursor=<n>` (`GET`): incremental log retrieval with cursor-based pagination.
- `/api/admin/auth` (`GET`/`POST`): authenticated users can query `requires_password_change` and rotate admin credentials (`current_password`, optional `new_username`, optional `new_password`); updates persist to `admin-auth.json`, clear active sessions, and rotate CSRF/session material.
- `QUICFUSCATE_TRUST_PROXY=1|true` makes admin HTTP resolve client IPs from `X-Forwarded-For`/`X-Real-Ip`; default remains socket peer address.
- Oversized admin HTTP payloads are rejected with 413.
- Auth uses `POST /api/login` to issue a session cookie and `POST /api/logout` to clear it.
- Install/update endpoints are not exposed in the admin HTTP API.

#### Stack:
- Frontend: React 19 + TypeScript, Vite, TailwindCSS
- Components: HeroUI (Modal), custom controls (`Segmented`, `PillToggle`, `Toggle`, `Btn`, `TextInput`)
- State: Jotai atoms (`apps/web-admin-ui/src/stores/atoms.ts`)
- API: Typed fetch wrappers (`apps/web-admin-ui/src/api.ts`) with `ApiError` class and automatic 401/403 -> auth-required flow
- Animations: Framer Motion (tab transitions, glass-morphism segmented controls)

#### Views:
- **Dashboard**: Server status (version, uptime, bytes in/out, listen address), active clients with kick/block actions, blocked IP management (block/unblock), and Prometheus-style metrics display. Auto-refreshes status/clients every 5 s and metrics/blocked IPs every 15 s.
- **Configuration**: Split presets/transport panel with deterministic policy controls:
  - Stealth preset: `Auto`, `Performance`, `Stealth`, `AntiDPI`, `Manual`, `Off`
  - Manual stealth mode expands inline and exposes per-feature toggles (domain fronting, HTTP3 masquerading, XOR, TLS Cover, QPACK headers, padding, timing obfuscation, protocol mimicry, DoH)
  - FEC preset: `Auto` or `Off`
  - Transport controls: congestion control algorithm and MTU validation (1200-9000)
  - Unsaved-changes warning on page leave, explicit Save/Reset, and pacing pinned on in config writes
- **QKeys**: Generate server-issued QKeys with optional display name, copy the generated credential, list issued keys, single revoke, and bulk revoke for selected keys. TTL is not exposed in the admin UI flow.
- **Logs**: Real-time log viewer with configurable logging mode (verbose/normal/minimal/no-log). No-Log suppresses all server log output and the UI stops polling logs. Logs are fetched incrementally via cursor-based pagination.
- **Settings**: Admin access and security: change username and password. Weak credentials (for example `admin/123`) are detected and the UI warns until changed.

#### Authentication:
- Login modal with username/password fields (empty by default).
- On 401/403 API responses, the UI automatically shows the login modal via `authRequiredAtom`.
- If the server reports `requires_password_change` (or returns HTTP `423`), the UI enters a password-change-locked state: Settings remains accessible while configuration/QKey mutation flows are blocked until the password is changed.
- Rate-limited auth updates (HTTP `429`) are surfaced as error banners without dropping the current session.

#### Verification (frontend)
Typecheck + build:
```bash
cd apps/web-admin-ui && bun run check
```

E2E UI tests (Playwright):
```bash
cd apps/web-admin-ui && bun run test:e2e
```

Notes:
- The Playwright config uses `reuseExistingServer: true` in local runs, so tests will reuse an already running dev server on `http://localhost:1430` when present.

#### Server-Side Persistence

The admin HTTP server persists the following state to JSON files derived from the main config path:
- **Blocked IPs** (`<config>.blocked.json`): loaded on startup, written on every block/unblock action.
- **Logging mode** (`<config>.logging.json`): loaded on startup, written on every mode change. When set to `no-log`, the server immediately calls `log::set_max_level(LevelFilter::Off)` to suppress all runtime logging output including to stderr and syslog.
- **QKey registry** (`--qkey-store` or `<config>.qkeys.json`): loaded on startup, written on generate/revoke.
- **Admin auth** (`<config_dir>/admin-auth.json`): Argon2 PHC string (`password_phc`) with `updated_at` timestamp and `requires_password_change`. File permissions set to `0o600` on Unix. Loaded on startup; written on credential change.
- Repository-local fallback paths (when no explicit `--config`/`--qkey-store` parent applies): `config/local/qkeys.json` and `config/local/admin-auth.json`.

#### No-Log Enforcement

When the logging mode is set to `no-log` (via API or persisted config):
- `log::set_max_level(LevelFilter::Off)` is called immediately, suppressing all `log::*` macro output.
- This is enforced both at startup (if the persisted mode is `no-log`) and at runtime (when the mode is changed via `/api/config/logging`).
- Other modes map to: `minimal` -> `Warn`, `normal` -> `Info`, `verbose` -> `Trace`.

#### Login Rate-Limiting

The admin HTTP server enforces IP-based login rate limiting to prevent brute-force attacks:
- Maximum 5 failed login attempts per IP address.
- 60-second lockout window after exceeding the limit.
- Locked IPs receive HTTP 429 ("Too many login attempts. Try again later.").
- Successful login clears the failure counter for that IP.
- Failed attempts are pruned automatically after the lockout window expires.

#### SPA Fallback

The static file server implements SPA (Single Page Application) fallback: when a non-API `GET` request does not match a static file, the server serves `index.html` instead of returning 404. This enables browser refresh on client-side routes like `/logs` or `/configuration`.

#### Session Cookie Security

Session cookies are hardened with the following attributes:
- `HttpOnly`: prevents JavaScript access (XSS mitigation).
- `SameSite=Strict`: prevents CSRF by restricting cross-origin cookie sending.
- `Secure`: set dynamically when the request arrives over HTTPS.
- `Max-Age`: matches the session TTL (12 hours).
- Session tokens are 32 bytes of `OsRng` entropy, base64url-encoded.
- Sessions are pruned on every access; credential changes invalidate all active sessions.

Then run the server:

```
quicfuscate server --admin-web 127.0.0.1:9000 --admin-web-user <USER> --admin-web-password <PASS>
```

### Linux Install Script (systemd)

Preferred Linux install flow uses the scripts under `scripts/`:
- installer: `scripts/install/install-server-linux.sh`
- systemd unit template: `scripts/install/quicfuscate-server.service`
- server config template: `config/server-linux.default.toml`

FHS paths used by the installer:
- config: `/etc/quicfuscate/quicfuscate.toml`
- env (admin creds, bind, paths): `/etc/quicfuscate/quicfuscate.env`
- web assets: `/usr/share/quicfuscate/admin-web`
- state (QKey registry): `/var/lib/quicfuscate/qkeys.json` (via `quicfuscate server --qkey-store`)

Installer flow is `scripts/install/install-server-linux.sh` together with `scripts/install/quicfuscate-server.service`.

Idempotency behavior of `scripts/install/install-server-linux.sh`:
- Existing `quicfuscate.toml` is preserved (created only if missing).
- Existing `quicfuscate.env` is preserved (created only if missing).
- Existing `qkeys.json` is preserved (created only if missing).
- Binary, assets, and unit template are reinstalled safely on reruns.
- `systemctl daemon-reload` is called on every install run.

#### Reverse Proxy (Admin Web)

The admin panel is typically bound to localhost (`127.0.0.1:9000`) and exposed through a TLS reverse proxy.

Nginx example:
```nginx
server {
    listen 443 ssl http2;
    server_name admin.example.com;

    ssl_certificate     /etc/letsencrypt/live/admin.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/admin.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:9000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

Caddy example:
```caddy
admin.example.com {
    reverse_proxy 127.0.0.1:9000
}
```

#### Health Checks (Server Deployments)

Service-level checks:
```bash
systemctl is-active quicfuscate.service
systemctl --no-pager --full status quicfuscate.service
journalctl -u quicfuscate.service -n 100 --no-pager
```

Socket/listener checks:
```bash
ss -lntup | rg quicfuscate
```

Admin API checks (session-based; Basic Auth is not accepted):
```bash
curl -fsS -c /tmp/qf-cookie -H 'Content-Type: application/json' \
  -X POST -d '{"username":"admin","password":"YOUR_PASSWORD"}' \
  http://127.0.0.1:9000/api/login
curl -fsS -b /tmp/qf-cookie http://127.0.0.1:9000/api/status
curl -fsS -b /tmp/qf-cookie http://127.0.0.1:9000/api/metrics
```

### Admin CLI (quicfuscate-ctl)

`quicfuscate-ctl` talks to the Unix admin socket exposed by `--admin-socket`. It uses
`/var/run/quicfuscate/ctl.sock` by default and can be overridden via `QUICFUSCATE_CTL_SOCKET`.

Examples:

```
quicfuscate-ctl status
QUICFUSCATE_CTL_SOCKET=/tmp/quicfuscate.sock quicfuscate-ctl clients
```

### Stealth Options (server)

```
    --front-domain <d>     Domain used for fronting (repeatable or comma-separated)
    --doh-provider <url>   Custom DNS-over-HTTPS resolver
    --disable-doh          Disable DNS over HTTPS
    --disable-fronting     Disable domain fronting
    --disable-xor          Disable XOR obfuscation
    --disable-http3        Disable HTTP/3 masquerading
    --profile-seq <list>   Comma-separated browser@os entries to cycle (e.g., chrome@windows,firefox@linux)
    --profile-interval <s> Interval in seconds for profile switching
```

Profile rotation allows QuicFuscate to periodically switch the active browser/OS fingerprint to diversify observable characteristics on the wire.

### Performance Options

```
    --cc-algorithm <alg>    Congestion control: reno|cubic|bbr|bbr2|bbr2_gcongestion (default: bbr2)
```

### Client Options

```
    --local <addr>          Local UDP bind address (default: 0.0.0.0:0)
    --url <url>             URL used by the client (default: https://cloudflare-dns.com/)
    --tun                   Enable TUN bridging (optional)
    --tun-name <name>       TUN interface name
    --tun-mtu <mtu>         TUN MTU (default 1500)
    --tun-ip <addr>         TUN IP address
    --tun-netmask <addr>    TUN netmask
```

### TUN Bridging over HTTP/3

QuicFuscate can bridge a TUN interface by encapsulating frames in HTTP/3 streams:

- Client: when `--tun` is set, a blocking reader thread forwards frames into an H3 stream; zero-copy pool integration minimizes allocations.
- Server: with `--tun`, downlink frames received via H3 are written to a TUN interface (when available on the platform) or dropped with a warning.
- Platform support (interface.rs):
  - Linux/Android: `/dev/net/tun` via `TUNSETIFF` (IFF_TUN | IFF_NO_PI)
  - macOS: `utun` (PF_SYSTEM/SYSPROTO_CONTROL), 4-byte AF header using readv/writev
  - Windows/iOS: pluggable via `register_tun_factory` (features `tun-windows`, `tun-ios`)
  - Other Unix: external factory via trait injection
  - All use the shared `MemoryPool` for zero-copy slices where possible.

### Real TLS Fingerprints

This section is an operational view; canonical behavior is defined in "Unified TLS Provider (RealTLS + TLS Cover) -> Fingerprint Source Model".

QuicFuscate performs native TLS handshake profile injection using deterministic in-memory ClientHello synthesis selected by `--profile` and `--os`. Runtime operation does not require on-disk profile dumps.

Generated ClientHello bytes are cached in memory for reuse across connections.

If you maintain external profile dumps for audit/regression purposes, place them under `browser_profiles/` and use the TLS utilities to inspect and verify them.
Example:
```bash
./scripts/tests/utils/util-tls-list-profiles.sh
./scripts/tests/utils/util-tls-generate-sha256-sidecars.sh
./scripts/tests/utils/util-e2e-verify-all.sh
```

#### Available Browser/OS Profiles

The following consolidated profiles are available and validated at startup:

| Browser | OS |
|---|---|
| Chrome | Windows, MacOS, Linux, Android, iOS |
| Firefox | Windows, MacOS, Linux, Android |
| Safari | MacOS, iOS |
| Edge | Windows, MacOS, Linux, Android |

Notes
- `--profile` and `--os` select the active pair. For rotation, use `--profile-seq` and `--profile-interval`.
- Each profile harmonizes UA string, Accept-Language, cipher suites and QUIC transport parameters (max data/streams, idle timeout).

### TLS Cover Exchange

TLS Cover is a lightweight synthetic exchange for stealth shaping and traffic realism. It derives ClientHello-like output from the active fingerprint profile and emits synthesized reply artifacts with shorter message sizing than a full handshake.

TLS Cover is optional and does not replace native TLS security semantics.

To force TLS Cover via the configuration file add:

```toml
[stealth]
use_tls_cover = true
```

### Server Push Cover Traffic (HTTP/3)

QuicFuscate generates realistic HTTP/3 Server Push traffic to mask real flows. This feature is governed by `StealthConfig` and transport H3 internals.

- Configuration (Stealth):
  - `enable_server_push_cover`: enable/disable cover traffic.
  - `server_push_intensity`: 0.0-1.0 scaling for burst size/frequency.
  - `server_push_base_path`: base URI path for pushed resources (e.g., `/assets`).
  - `server_push_burst_interval`: minimum seconds between bursts.
- Generation (Transport):
  - `create_server_push_promise()` and `generate_stealth_cover_burst()` synthesize push promises with realistic content types.
  - Payloads: generated CSS, JS and small image blobs with deterministic variability to evade static signatures.
  - State: maintains `next_push_id`, tracks open push streams, and injects cover DATA frames interleaved with real traffic.
- Telemetry: MASQUE/cover traffic counters under `optimize::telemetry::*` record bytes and capsule usage (when applicable).

Example (runtime behavior)
```text
Anti-DPI escalates -> enable_server_push_cover=true, intensity~0.8, burst_interval=15 s.
Transport emits PUSH_PROMISE and DATA with CSS/JS payloads across multiple streams.
```

#### Cover Burst Example

```rust
use quicfuscate::transport;

// Assume an established transport connection `conn` and a configured H3 connection
let mut cfg = transport::Config::new().expect("config");
let mut h3 = transport::h3::Connection::with_transport(&mut conn, &cfg).expect("h3");

// Generate a burst of realistic cover pushes under /assets
let push_ids: Vec<u64> = h3.generate_stealth_cover_burst("/assets").expect("cover burst");

// Typical content-types generated per push:
//  - text/css (CSS)
//  - application/javascript (JS)
//  - image/jpeg or image/png (images)

// Application may continue polling events; pushed streams carry DATA frames with the cover payloads.
```

#### Handling Server Push Events

```rust
use quicfuscate::transport::h3::{Connection as H3, Event};

fn poll_h3_events(h3: &mut H3, conn: &mut quicfuscate::transport::Connection) {
    while let Ok(Some(ev)) = h3.poll(conn) {
        match ev {
            Event::PushPromise { push_id, headers } => {
                // Observe pushed resource headers for realism
                for h in &headers { log::debug!("push {}: {:?} -> {:?}", push_id, h.name(), h.value()); }
            }
            Event::Data => {
                // Read DATA frames for active/pushed streams internally
            }
            _ => {}
        }
    }
}
```

### MASQUE CONNECT-UDP

The HTTP/3 stack supports MASQUE CONNECT-UDP for stealth tunneling.

- Streams: establishes CONNECT-UDP control streams; keeps them open for duration of the tunnel.
- DATAGRAM: registers Flow-ID/Context-ID; sends UDP payloads over QUIC DATAGRAM frames.
- Capsules: encodes/decodes MASQUE capsules using varints.
  - Common types observed in telemetry: `0x00` (DATAGRAM), `0x21`, `0x22` (implementation-specific control/data hints).
- QPACK: MASQUE headers use QPACK with dynamic table; preferred indexing keys are set via `set_qpack_index_policy()`.
- Telemetry: `MASQUE_BYTES_SENT`, `MASQUE_BYTES_RECEIVED`, and capsule counters per type.

Notes
- Stealth and Anti-DPI can enable MASQUE. Performance keeps MASQUE not preferred by default.
- "Preferred" only changes path selection order. "Active" requires a successful CONNECT-UDP flow.
- CONNECT-UDP paths integrate seamlessly with cover traffic and domain fronting.
- If you maintain external profile dumps, `scripts/tests/utils/util-tls-export-active-profile.sh` exports them under `scripts/out/utils/.../profiles/` by default (or a caller-provided `--output-dir`) for regression tracking.

#### MASQUE Roundtrip Example

```rust
use quicfuscate::transport::h3::{Header, qpack};

// Minimal, reproducible header set
let headers = vec![
    Header::new(b":method", b"GET"),
    Header::new(b":scheme", b"https"),
    Header::new(b":authority", b"example.com"),
    Header::new(b":path", b"/"),
    Header::new(b"accept-encoding", b"gzip, deflate, br"),
];

// Encode
let mut enc = qpack::Encoder::with_capacity(1024);
enc.set_index_policy(&[b":method", b":scheme", b":authority", b":path", b"accept-encoding"]);
let mut buf = vec![0u8; 1024];
let n = enc.encode(&headers, &mut buf).expect("encode");
let payload = &buf[..n];

// Decode
let mut dec = qpack::Decoder::with_capacity(1024);
let decoded = dec.decode(payload).expect("decode");

assert_eq!(decoded.len(), headers.len());
for (a, b) in decoded.iter().zip(headers.iter()) {
    assert_eq!(a.name(),  b.name());
    assert_eq!(a.value(), b.value());
}
```

### HTTP/3 Masquerade Headers API (QPACK)

- __StealthManager::get_http3_masquerade_headers(host, path) -> Option<Vec<u8>>__
  - On x86 profiles the Huffman stage dispatches to AVX2/SSSE3 kernels; other platforms use the scalar fallback.
  - Returns a QPACK-encoded header block as `Vec<u8>`.
  - Encodes into a pooled buffer first and then materializes an exact-sized `Vec`, returning the pool block afterwards.
  - On pooled-buffer failure increments `telemetry::STEALTH_QPACK_POOL_FALLBACKS` (telemetry counter: `stealth_qpack_pool_fallback_total`) and re-encodes using a heap `Vec`.
  - Ownership: the caller fully owns the returned `Vec`.

- __StealthManager::get_http3_masquerade_headers_boxed(host, path) -> Option<(AlignedBox<[u8]>, usize, bool pooled)>__
  - Returns an aligned buffer (`AlignedBox<[u8]>`), the valid length (`usize`), and a flag `pooled`.
  - `pooled == true`: buffer comes from the internal pool and must be returned via `StealthManager::free_pooled_block`.
  - `pooled == false`: aligned fallback allocation (64-byte alignment); drop when no longer needed.
  - On pooled-buffer failure increments `telemetry::STEALTH_QPACK_POOL_FALLBACKS` (telemetry counter: `stealth_qpack_pool_fallback_total`).

- __StealthManager::free_pooled_block(block: AlignedBox<[u8]>)__
  - Only return buffers that originated from the pool (`pooled == true`). Do not call this for aligned fallback buffers.

Notes:
- Telemetry export is disabled by default; enable via `--telemetry` (see "Telemetry Metrics").
- A structural header list is also available via `StealthManager::get_http3_header_list(..)`.

Additional helpers:
- __StealthManager::masque_preferred() -> bool__
  - Indicates whether MASQUE should be preferred for outgoing requests (set during probe-escalation; also affected by ENV override).
- __StealthManager::get_masque_connect_headers(proxy, target) -> Option<Vec<Header>>__
  - Builds CONNECT-UDP headers for use with a MASQUE proxy. Returns `None` when MASQUE is not enabled or manager initialization is absent.

Cover Traffic integration:
- __StealthManager::cover_headers_due() -> Option<Vec<Header>>__
  - Returns a small, persona-shaped GET/HEAD header set when due (rate-limited by the scheduler).
- `core::QuicFuscateConnection::poll_http3()` opportunistically calls `cover_headers_due()` on each poll iteration and sends a cover request when returned.

#### Pseudo-Headers & Typical Header Set
- Pseudo-headers in fixed order: `:method`, `:scheme`, `:authority`, `:path`.
- Realistic profile-driven headers (excerpt):
  - `user-agent`, `accept`, `accept-language`, `accept-encoding: gzip, deflate, br`
  - Chromium: `sec-ch-ua`, `sec-ch-ua-mobile`, `sec-ch-ua-platform`, `sec-fetch-site`, `sec-fetch-mode`, `sec-fetch-dest`, `upgrade-insecure-requests`
  - Referer: depends on fronting/navigation (e.g., search portal or same-origin)

#### Index Policy (Dynamic Table)
- The QPACK encoder carries a preferred index policy (`set_index_policy`) to prioritize common names for better compression.
- Default seeds (when capacity allows): `content-type` (CSS/JS/JSON/JPEG/PNG), `cache-control`, `accept-encoding`, `accept`, `x-cdn-cache`.

#### Encoding Behavior (internal)
- Fully static indexed entry: `0x80 | index`
- Static name, literal value (Huffman): `0x40 | index` followed by string (Huffman)
- Dynamic indexed entry (name+value): `0xA0 <varint index>`
- Literal name+value: `0x20 <name> <value>` (strings Huffman-encoded)

Illustration (simplified)
```text
[:method=GET]        -> 0x80 | idx(":method=GET")
[:scheme=https]      -> 0x80 | idx(":scheme=https")
[:authority=host]    -> 0x40 | idx(":authority") <huff(host)>
[:path=/p]           -> 0x40 | idx(":path") <huff("/p")>
[accept-encoding=...]-> 0x80 | idx("accept-encoding=gzip, deflate, br")
[user-agent=...]     -> 0x20 <huff("user-agent")> <huff(UA)>
```

#### QPACK Roundtrip Example (encode -> decode)

```rust
use quicfuscate::transport::h3::{Header, qpack};

// Minimal, reproducible header set
let headers = vec![
    Header::new(b":method", b"GET"),
    Header::new(b":scheme", b"https"),
    Header::new(b":authority", b"example.com"),
    Header::new(b":path", b"/"),
    Header::new(b"accept-encoding", b"gzip, deflate, br"),
];

// Encode
let mut enc = qpack::Encoder::with_capacity(1024);
enc.set_index_policy(&[b":method", b":scheme", b":authority", b":path", b"accept-encoding"]);
let mut buf = vec![0u8; 1024];
let n = enc.encode(&headers, &mut buf).expect("encode");
let payload = &buf[..n];

// Decode
let mut dec = qpack::Decoder::with_capacity(1024);
let decoded = dec.decode(payload).expect("decode");

assert_eq!(decoded.len(), headers.len());
for (a, b) in decoded.iter().zip(headers.iter()) {
    assert_eq!(a.name(),  b.name());
    assert_eq!(a.value(), b.value());
}
```

### Domain Fronting API (allocation-free getters)

- __DomainFrontingManager::get_fronted_domain_ref(&self) -> &str__
  - Returns the current front domain as a string slice without allocation.
- __DomainFrontingManager::random_domain_ref(&self) -> &str__
  - Returns a random front domain as a string slice without allocation.

Notes:
- Existing methods (`get_fronted_domain`, `random_domain`) remain for backward compatibility.
- Internally, domains are stored as `Arc<[String]>` to reduce cloning and enable zero-copy access.

### Configuration Reference (Full)

For the complete, commented runtime configuration with all canonical sections and defaults, see `config/quicfuscate.toml`.

### Environment Variable Overrides

At runtime you can override selected stealth options without changing the config file. The following variables are recognized (case-insensitive values where applicable):

**Core Stealth:**
- `QUICFUSCATE_BROWSER`: `chrome|firefox|safari|edge`
- `QUICFUSCATE_OS`: `windows|linux|macos|ios|android`
- `QUICFUSCATE_STEALTH_MODE`: `off|performance|base|stealth|anti-dpi|intelligent|manual` (aliases: `antidpi`, `stealthmax`, `stealth-max`, `dynamic`)
- `QUICFUSCATE_USE_TLS_COVER_EXTRAS` (alias: `QUICFUSCATE_USE_TLS_COVER`): `0|1|true|false` - enables TLS Cover extras in `StealthManager` (ticket manager and cert emulator)
- `QUICFUSCATE_TLS_COVER_PROFILE`: `chrome|firefox|safari|edge|random`
- `QUICFUSCATE_TLS_COVER_CIPHER`: `auto|chacha|aes`
- `QUICFUSCATE_TLS_COVER_ULTRA`: `0|1|true|false`
- `QUICFUSCATE_DOH`: `0|1|true|false`
- `QUICFUSCATE_DOH_PROVIDER`: URL

**Compression Module (current):**
- `QUICFUSCATE_COMPRESS`: `0|1|false|true` - Enable/disable compression
- `QUICFUSCATE_COMPRESS_MIN`: integer - Minimum payload size for compression (bytes)
- `QUICFUSCATE_COMPRESS_LEVEL`: `1-22` - zstd compression level
- `QUICFUSCATE_COMPRESS_ALLOW`: comma-separated content-types to allow (e.g., `text/*,application/json`)
- `QUICFUSCATE_COMPRESS_DENY`: comma-separated content-types to deny (e.g., `image/*,video/*`)
- `QUICFUSCATE_BODYPOOL_CAP`: integer - Body pool capacity (blocks)
- `QUICFUSCATE_BODYPOOL_BLOCK`: integer - Body pool block size (bytes)
- `QUICFUSCATE_DICT_DIR`: path - Dictionary cache directory

**MASQUE controls:**
- `QUICFUSCATE_MASQUE_ENABLE`: `0|1|true|false` - Create MASQUE manager even outside Anti-DPI.
- `QUICFUSCATE_MASQUE_PROXY`: hostname of the MASQUE proxy (e.g., `masque.example.com`).
- `QUICFUSCATE_MASQUE_DATAGRAM`: `0|1|true|false` - Override MASQUE DATAGRAM handling (`1` forces on, `0` disables). Default: auto-enable after manager initialization and CONNECT-UDP flow setup.

**StealthBrain Module (new):**
- `QUICFUSCATE_BRAIN_ACK_MAX`: integer - Maximum ACK threshold (default from code)
- `QUICFUSCATE_BRAIN_JITTER_MAX_US`: integer - Max jitter in microseconds
- `QUICFUSCATE_BRAIN_SIZE_BINS`: integer (8..64) - Histogram size bins
- `QUICFUSCATE_BRAIN_IAT_BINS`: integer (8..64) - Histogram inter-arrival bins
- `QUICFUSCATE_BRAIN_PROBE_MAX_PER_MIN`: integer (<=30)
- `QUICFUSCATE_BRAIN_PROBE_COOLDOWN_MS`: integer - Probe cooldown in ms
- `QUICFUSCATE_BRAIN_POLICY_COOLDOWN_MS`: integer - Policy cooldown in ms
- `QUICFUSCATE_BRAIN_EXPLORE`: float (0.0..0.25) - Exploration probability
- `QUICFUSCATE_BRAIN_HIST_DECAY`: float (0.80..0.999)
- `QUICFUSCATE_BRAIN_PAD_MAX_LOW`: integer (16..512)
- `QUICFUSCATE_BRAIN_PAD_MAX_HIGH`: integer (>= low, <=2048)

**TLS Provider (qftls):**
- `QUICFUSCATE_ALLOW_INVALID_CERTS=1|true|yes|on` - Accept invalid peer certificates (development/testing only)
- `QUICFUSCATE_TLS_CH_OVERRIDE_TEMPLATE=<name>` - Forward ClientHello template override names to providers that support `supports_ch_override()`
- `QUICFUSCATE_TRACE_TLS=1` - Enable additional TLS handshake/key-change diagnostics in qftls/transport

**Global toggles:**
- `QUICFUSCATE_BRAIN=0|1|false|true` - Enable StealthBrain transport observer coupling (default: enabled)
- `QUICFUSCATE_ORCHESTRATOR=0|1|false|true` - Enable DeepIntegrationOrchestrator when feature is compiled (default: enabled)
- `QUICFUSCATE_RAYON_THREADS=<n>` - Cap Rayon global thread pool used for parallel FEC kernels

**Telemetry server:**
- `QUICFUSCATE_METRICS_ADDR` - `host:port` for the `--telemetry` HTTP endpoint (default: `127.0.0.1:9898`).

**Transport and IO (advanced):**
- `QUICFUSCATE_BUSY_POLL` - presence enables busy polling on supported Linux batch paths.
- `QUICFUSCATE_ZEROCOPY` - `0|1|true|false` to enable MSG_ZEROCOPY on Linux send paths (default: off).
- `QUICFUSCATE_ZC_DRAIN_BATCH` - integer; number of zerocopy completion events drained per tick (default: `16`).
- `QUICFUSCATE_FASTPATH` - `off|uring|xdp|auto` (default: `auto`).
- `QUICFUSCATE_URING_QUEUE_DEPTH` - integer (32..1024, default: `256`).
- `QUICFUSCATE_URING_ZEROCOPY` - `0|1|true|false` (default: off).
- `QUICFUSCATE_URING_REGISTER_BUFFERS` - `0|1|true|false` (default: off).
- `QUICFUSCATE_URING_MULTISHOT` - `0|1|true|false` (default: off).
- `QUICFUSCATE_XDP_BATCH` - integer cap for XDP batch size (default: `8`).

#### Memory Pool (Optimization) Environment Overrides

- `QUICFUSCATE_POOL_CAPACITY` - Initial pool capacity (blocks). Default: `512`.
- `QUICFUSCATE_POOL_BLOCK_SIZE` - Block size in bytes. Default: `65536` (64 KiB). A minimum of `2048` bytes is enforced.
- `QUICFUSCATE_POOL_HARD_MAX_CAP` - Hard upper limit for capacity growth (DoS guard). Default: unlimited.
- `QUICFUSCATE_POOL_AUTO_TUNE` - `0|1|false|true` to enable auto-tuner. Default: `true`.
- `QUICFUSCATE_POOL_MIN_CAP` - Minimum capacity for auto-tuner. Default: `64`.
- `QUICFUSCATE_POOL_MAX_CAP` - Maximum capacity for auto-tuner. Default: `4096`.
- `QUICFUSCATE_POOL_TICK_MS` - Auto-tuner tick duration in milliseconds. Default: `1000`.
- `QUICFUSCATE_POOL_UTIL_HIGH` - Utilization percent that triggers growth (default: `80`).
- `QUICFUSCATE_POOL_UTIL_LOW` - Utilization percent that triggers shrink (default: `30`).
- `QUICFUSCATE_TLS_HIGH` - TLS cache size under high utilization (default: `48`).
- `QUICFUSCATE_TLS_LOW` - TLS cache size under low utilization (default: `24`).
- `QUICFUSCATE_POOL_ADAPTIVE_BLOCK` - `0|1|false|true` to enable adaptive block sizing (default: `true`). If enabled, block size is selected from MTU hints: `<=1500 -> 4096`, `<=9000 -> 16384`, otherwise `65536`.
- `QUICFUSCATE_MTU_HINT` - Integer hint for typical link MTU used by adaptive block sizing (default: `1500`).
- `QUICFUSCATE_TLS_CACHE` - Per-thread TLS cache size for pooled blocks (default: `32`).
- `QUICFUSCATE_POOL_DEBUG_SLACK` / `QUICFUSCATE_POOL_DEBUG_GRACE` - Debug-only invariants slack to reduce spurious warnings under bursty workloads.
- `QUICFUSCATE_MADVISE_HUGEPAGE` - `0|1|false|true` to disable or enable MADV_HUGEPAGE hints on Linux (default: `true`).
- `QUICFUSCATE_NUMA_POLICY` - `local|interleave|preferred:<n>` for NUMA placement on Linux (default: `local`).

Notes:
- The pool growth is clamped by `QUICFUSCATE_POOL_HARD_MAX_CAP`. When the limit is reached,
  ephemeral blocks are allocated without mutating pool counters (prevents counter skew under DoS).
- Debug builds assert pool invariants (`in_use <= capacity`, `available <= capacity`).

**Stealth fine-tuning (runtime overrides):**
- `QUICFUSCATE_STEALTH_PADDING_MAX`: positive integer; caps per-packet padding in bytes
- `QUICFUSCATE_STEALTH_PADDING_STRATEGY`: `random|fixed|adaptive|browser|browser-mimic` (aliases: `1|2|3|4`)
- `QUICFUSCATE_STEALTH_JITTER_US`: non-negative integer microseconds; `0` disables timing gate
- `QUICFUSCATE_STEALTH_ADAPTIVE_GRAN`: positive integer bytes; adaptive padding granularity (default `64`)
- `QUICFUSCATE_STEALTH_MIMIC_BIAS`: `1|2|3|4` or `very_small|small|default|mobile|safari|firefox|android|chromium|chrome|edge` (browser or OS-shaped bias for BrowserMimic)
- `QUICFUSCATE_XOR`: `0|1|true|false`
- `QUICFUSCATE_FRONTING`: `0|1|true|false`
- `QUICFUSCATE_QPACK`: `0|1|true|false`
- `QUICFUSCATE_STEALTH_DYNAMIC`: `0|1|true|false` - enable dynamic escalation and de-escalation
- `QUICFUSCATE_CHOKE_ENABLE`: `0|1|true|false` - enable real-time rate choke
- `QUICFUSCATE_CHOKE_TARGET_MBPS`: integer - target Mbps for rate choke
- `QUICFUSCATE_CHOKE_BURST_MS`: integer - allowed burst window in milliseconds
- `QUICFUSCATE_ACK_THRESHOLD`: integer - override transport ACK threshold used by StealthBrain coupling
- `QUICFUSCATE_ACK_MAX_DELAY_MS`: integer - override transport max ACK delay
- `QUICFUSCATE_EXTERNAL_PACING`: `0|1|true|false` - force external pacing in transport

### Mode Presets (ENV)

For quick switching between modes at runtime without editing TOML, source one of the presets:

Note: Select modes via TOML configuration using `StealthConfig::from_mode()` or environment variables like `QUICFUSCATE_STEALTH_MODE`.

Notes:
- Presets set `QUICFUSCATE_*` variables for the current shell only. They do not modify configuration files.
- You can override any single knob after sourcing a preset, e.g. `export QUICFUSCATE_STEALTH_JITTER_US=1000`.

#### FEC Environment Variable Overrides

See "FEC Operations Guide -> Environment controls (runtime)" for the authoritative list and semantics of FEC runtime variables. This section intentionally avoids duplication.

Example:

```bash
export QUICFUSCATE_BROWSER=firefox
export QUICFUSCATE_OS=linux
export QUICFUSCATE_DOH_PROVIDER=https://dns.google/dns-query
export QUICFUSCATE_FRONTING=true
```

### Standard Configuration

The following setup provides a good starting point on most systems:

```
quicfuscate client \
  --remote 203.0.113.1:4433 \
  --profile chrome \
  --front-domain cdn.example.com \
  --pool-capacity 1024 \
  --pool-block 4096 \

```

```
quicfuscate server \
  --listen 0.0.0.0:4433 \
  --cert ./tls-cert.pem \
  --key ./tls-key.pem \
  --profile chrome \
  --pool-capacity 1024 \
  --pool-block 4096 \

```

### Connection Migration

To migrate an established connection to a new local port, call `migrate_connection` on the active session:

```rust
let new_addr = "127.0.0.1:0".parse().unwrap();
let path_id = conn.migrate_connection(new_addr).unwrap();
println!("migrated to path {path_id}");
```

The library records successful migrations via the `path_migrations_total` telemetry counter.

---
## Governance (Canonical)

### QuicFuscate Governance and Deterministic Workflow
Canonical cross-cutting engineering principles, policies, and deterministic offline-first workflow.

#### Principles and Policies
- Security: AEAD-only; strict nonce/tag checks.
- Stealth: TLS Cover + RealTLS (rustls) and HTTP/3/QPACK mirror real browsers (JA3/JA4). Domain fronting coherence.
- Performance: centralized CPU feature detection and dispatch; SIMD and zero-copy where safe.
- Modularity: single sources of truth; avoid duplication and scattered hot-paths.
- Determinism: offline, script-driven workflows; reproducible builds/benches; stable telemetry schemas; no secrets in logs.
- Documentation equals implementation.

#### Deterministic Offline Workflow
- Modular script architecture under `scripts/{build,tests,benchmarks,audits,utils}/`.
- Individual scripts for specific operations with clear separation of concerns.
- E2E TLS fingerprint checks integrated (decode/verify via shell-based actions; sidecar generation via utils).
- Artifacts under `scripts/out/<category>/`; deterministic timestamps and seeds.

#### QA Gates and Ownership
Security/Stealth/Performance/Reliability/Documentation gates are enforced in the project workflow.

## FEC Operations Guide

This section is the operational reference for runtime FEC controls, practical tuning, and the most relevant telemetry counters.
Use these overrides only when you need deterministic policy behavior beyond default auto-adaptation.

### Environment controls (runtime)
- `QUICFUSCATE_FEC_PARTIAL`: `0|1|true|false` - controls partial recovery emission (default: enabled).
- `QUICFUSCATE_FEC_LAZY`: `0|1|true|false` - lazy decoder gating (default: enabled).
- `QUICFUSCATE_FEC_INTERLEAVE`: `0|1|true|false` - enable interleaving for burst protection (default: enabled).
- `QUICFUSCATE_FEC_INTERLEAVE_DEPTH`: integer `1..8` - depth for interleaving (default: `4` when `k > 16`, else `1`).
- `QUICFUSCATE_FEC_DECODER`: `auto|gauss|wiedemann` - force decoder family; `auto` selects by `k` threshold.
- `QUICFUSCATE_FEC_WIEDEMANN_K`: integer (default `256`) - threshold for enabling Wiedemann at large `k`.
- `QUICFUSCATE_FEC_STREAM_EVERY`: integer `N` (min `1`) - streaming cadence override; computed from CPU profile when unset.
- `QUICFUSCATE_FEC_AUTO_STREAM`: `0|1|true|false` - allow Streaming mode in auto switch (default: enabled).
- `QUICFUSCATE_FEC_AUTO_GF4`: `0|1|true|false` - allow GF4 for ultra-low loss in auto (default: enabled).
- `QUICFUSCATE_FEC_SWITCH_THRESH`: float `0.0..1.0` - mode switch threshold (default: `0.02`).
- `QUICFUSCATE_FEC_SWITCH_MIN_UP_MS`: integer milliseconds (default: `120`) - minimum dwell time before Auto-Mode may escalate to a higher FEC tier.
- `QUICFUSCATE_FEC_SWITCH_MIN_DOWN_MS`: integer milliseconds (default: `450`) - minimum dwell time before Auto-Mode may de-escalate to a lower FEC tier.
- `QUICFUSCATE_FEC_FOUNTAIN_WINDOW`: integer - window size when switching to Fountain (default: `2048`).
- `QUICFUSCATE_FEC_EXTREME_WINDOW`: integer - window size for extreme loss escalation (default: `1024`).
- `QUICFUSCATE_FOUNTAIN_SYMBOL`: integer bytes - fountain symbol size (default: `MTU_HINT-80`, fallback `1500`, clamp `600..16384`).
- `QUICFUSCATE_RS_LOSS`: float - loss hint for AdaptiveRS (default: `0.0`).
- `QUICFUSCATE_RS_LATENCY_MS`: float - latency hint for AdaptiveRS (default: `5.0`).
- `QUICFUSCATE_RS_BW_MBPS`: float - bandwidth hint for AdaptiveRS (default: `1000.0`).
- `QUICFUSCATE_KALMAN_Q`: float - process noise override (default: `0.001`).
- `QUICFUSCATE_KALMAN_R`: float - measurement noise override (default: `0.01`).
- `QUICFUSCATE_PROFILE`: `mobile|server|desktop` - transport profile override for FEC observer.
- `QUICFUSCATE_MTU_HINT`: integer - used by fountain symbol sizing and memory pool sizing.
- `QUICFUSCATE_RAYON_THREADS`: integer - cap Rayon thread pool used by parallel FEC paths.
- `QUICFUSCATE_FEC_KERNEL`: `scalar|avx512vbmi2|avx512|avx2|neon|sve2` - override SIMD kernel selection for GF16 bitslice.

Notes:
- The runtime may set `QUICFUSCATE_FEC_STREAM_BURST`, `QUICFUSCATE_FEC_PARALLEL`, `QUICFUSCATE_WM_BITSLICE`, `QUICFUSCATE_WM_LANE_PAR`, `QUICFUSCATE_WM_LANES`, and `QUICFUSCATE_WM_U` internally during auto tuning; there is no manual override read path in the current code.

Examples (manual tuning):

```bash
# Low-loss emphasis (efficient)
export QUICFUSCATE_FEC_DECODER=gauss
export QUICFUSCATE_FEC_STREAM_EVERY=3
export QUICFUSCATE_FEC_INTERLEAVE=1
export QUICFUSCATE_FEC_LAZY=1

# High-loss emphasis (robust)
export QUICFUSCATE_FEC_DECODER=wiedemann
export QUICFUSCATE_FEC_STREAM_EVERY=1
export QUICFUSCATE_FEC_INTERLEAVE_DEPTH=4
export QUICFUSCATE_FEC_FOUNTAIN_WINDOW=2048
```

### Telemetry quick reference
Exported telemetry metrics (via `optimize::telemetry::telemetry_snapshot_text()`):

- ACK delay mimicry
  - `quicfuscate_ack_delay_bucket_le_1ms_total`
  - `quicfuscate_ack_delay_bucket_le_4ms_total`
  - `quicfuscate_ack_delay_bucket_le_16ms_total`
  - `quicfuscate_ack_delay_bucket_le_64ms_total`
  - `quicfuscate_ack_delay_bucket_le_256ms_total`
  - `quicfuscate_ack_delay_bucket_gt_256ms_total`
  - `quicfuscate_ack_delay_last_us`

- Pacing / choke accounting
  - `quicfuscate_choked_bytes_total`
  - `quicfuscate_choke_sleep_ms_total`

- MASQUE capsules
  - `quicfuscate_masque_capsule_00_total`
  - `quicfuscate_masque_capsule_21_total`
  - `quicfuscate_masque_capsule_22_total`

- Compression
  - `quicfuscate_compress_attempts_total`
  - `quicfuscate_compress_success_total`
  - `quicfuscate_compress_bytes_in_total`
  - `quicfuscate_compress_bytes_out_total`

- Memory/Pool
  - `quicfuscate_body_pool_allocs_total`
  - `quicfuscate_mem_pool_hits_tls_total`
  - `quicfuscate_mem_pool_hits_queue_total`
  - `quicfuscate_mem_pool_alloc_grow_total`
  - `quicfuscate_mem_pool_alloc_ephemeral_total`

- SIMD usage (counters)
  - `quicfuscate_simd_usage_avx2_total`
  - `quicfuscate_simd_usage_avx512_total`

#### Telemetry HTTP endpoints

Telemetry and metrics endpoints are exposed by different runtime surfaces:

- `GET /telemetry`: text snapshot from `optimize::telemetry` served by `src/metrics.rs` (`spawn_telemetry_server`, bind via `QUICFUSCATE_METRICS_ADDR`, default `127.0.0.1:9898`).
- `GET /metrics` and `GET /health`: server metrics/health exposed by `implementations::server::metrics::MetricsServer` when server metrics are enabled.

`GlobalMetricsServer` (same module) can expose `instrumentation::global()` exports for embedded/custom deployments, but is not started by default in the CLI server path.

#### Server `/metrics` families (default server runtime)

The default server metrics endpoint (`implementations::server::metrics::Metrics::export`) includes:

- `quicfuscate_up`, `quicfuscate_uptime_seconds`
- `quicfuscate_clients_active`, `quicfuscate_clients_total`, `quicfuscate_connections_rejected`
- `quicfuscate_bytes_in_total`, `quicfuscate_bytes_out_total`, `quicfuscate_packets_in_total`, `quicfuscate_packets_out_total`
- `quicfuscate_stealth_http3_active`, `quicfuscate_stealth_tls13_active`
- `quicfuscate_fec_packets_encoded`, `quicfuscate_fec_packets_decoded`, `quicfuscate_fec_packets_recovered`
- `quicfuscate_auth_failed_total`, `quicfuscate_rate_limited_total`

#### Global instrumentation metric families (optional/embedded)

`instrumentation::GlobalMetrics` extends the optimize snapshot with runtime-wide families, including:

- Server lifecycle: `quicfuscate_up`, `quicfuscate_uptime_seconds`, `quicfuscate_clients_active`, `quicfuscate_clients_total`, `quicfuscate_connections_accepted`, `quicfuscate_connections_rejected`, `quicfuscate_sessions_created`, `quicfuscate_sessions_expired`, `quicfuscate_auth_failed`, `quicfuscate_rate_limited`.
- Transport activity: `quicfuscate_bytes_in`, `quicfuscate_bytes_out`, `quicfuscate_packets_in`, `quicfuscate_packets_out`, `quicfuscate_packets_lost`, `quicfuscate_rtt_avg_ms`, `quicfuscate_loss_rate`.
- Stealth/FEC state: `quicfuscate_stealth_http3`, `quicfuscate_stealth_tls13`, `quicfuscate_padding_bytes`, `quicfuscate_fec_encoded`, `quicfuscate_fec_decoded`, `quicfuscate_fec_recovered`, `quicfuscate_fec_recovery_rate`, `quicfuscate_fec_redundancy`.

#### Telemetry environment controls (runtime)

- `QUICFUSCATE_ACK_THRESHOLD`: override ACK-eliciting threshold in stealth ACK behavior.
- `QUICFUSCATE_ACK_MAX_DELAY_MS`: override max ACK delay in milliseconds for stealth ACK scheduling.
- `QUICFUSCATE_EXTERNAL_PACING`: enable external pacing mode for pacing/choke paths.

Telemetry collection/export is runtime-surface driven (`--telemetry` / metrics endpoints). There is no standalone `QUICFUSCATE_TELEMETRY_ENABLED` runtime read path in the current code.

#### Telemetry access and operational interpretation

- ACK delay buckets model browser-like ACK timing distributions and can be used to validate profile behavior under different network conditions.
- Choke counters (`choked_bytes`, `choke_sleep_ms`) quantify pacing pressure and allow correlation with throughput/latency trade-offs.
- FEC gauges/counters should be interpreted together (`mode`, `window`, `loss_rate`, switch counters) to distinguish stable operation from adaptation churn.
- Compression and SIMD counters provide backend-selection and efficiency visibility without changing data-plane behavior.

### Operational hints
- Rayon thread pool sizing (parallel repairs)
  - Parallel generation uses the global Rayon pool. To cap threads, set `QUICFUSCATE_RAYON_THREADS=<n>` before launch.
  - There is no runtime toggle for parallel vs sequential in the current code; selection is internal.
  - In async deployments (Tokio), avoid oversubscription: choose `<n>` near the number of physical cores or the Tokio worker count when CPU contention is observed.
  - Measure with `--telemetry` and watch `quicfuscate_fec_window`, `quicfuscate_fec_mode_switches_total`, and throughput counters when adjusting.

- Hysteresis and loss smoothing (mode stability)
  - `hysteresis` dampens mode flapping; larger values reduce oscillation on jittery links. Typical range: `0.01-0.03`.
  - `lambda` (EMA factor) near `1.0` reacts quickly to current loss; smaller values increase smoothing. Tests use `lambda=1.0` to trigger fast path deterministically.

- Streaming cadence trade-off
  - Lower `QUICFUSCATE_FEC_STREAM_EVERY` improves recovery latency but increases overhead; default is computed from CPU profile (often 1-3). Tests often use `1` for clear recovery behavior.

- Disturbance handling
  - The controller reacts to change-points (CUSUM) by escalating to streaming and, when necessary, increasing the FEC window (`QUICFUSCATE_FEC_EXTREME_WINDOW`).
  - Auto-Mode resets to efficient profiles once stability returns (EMA/variance gates).

- Telemetry for tuning
  - Enable `--telemetry` and monitor `quicfuscate_fec_mode_switches_total`, `quicfuscate_fec_window`, `quicfuscate_fec_loss_rate`, and switch-reason counters (`quicfuscate_fec_switch_reason_*_total`) during tuning iterations.

Notes
- `QUICFUSCATE_FEC_STREAM_EVERY` is read once per `AdaptiveFec::new`. Use a new instance to pick up changes.
- Telemetry updates are no-ops unless telemetry is enabled at runtime; exporting is handled by the `telemetry` module.

### Test-only Environment Overrides
These env vars are only read under `#[cfg(test)]` or with the `rust-tests` feature; they are not part of the runtime contract:
- `QUICFUSCATE_MORUS` - force MORUS plan selection.
- `QUICFUSCATE_CIPHER` - override `CipherSuiteSelector` in tests.
- `QUICFUSCATE_PROFILE_OVERRIDE` - override CPU profile selection in tests.
- `QUICFUSCATE_GF16_TEST_ITERS` - iteration count for GF16 consistency tests.
- `QUICFUSCATE_FEC_ADAPT_RS` - toggles adaptive RS fixtures in tests; no runtime read path.
- `QUICFUSCATE_TEST_UNSET` - used only by EnvGuard tests.

## Build & Dependencies (Current)

There is no external vendor workflow. All functionality (transport, stealth, FEC, crypto) is implemented under `src/` and built with Cargo. CI uses `.github/workflows/ci.yml` exclusively.

Build/runtime behavior for TLS fingerprint inputs is documented in the unified TLS section; see "Unified TLS Provider (RealTLS + TLS Cover) -> Fingerprint Source Model".

### AEGIS
- Integrated internally in `src/crypto.rs`; validated via integration tests in `scripts/tests/rust/rt-baseline-oracles.rs`.
- Workflow: develop -> test -> clippy. Deterministic, offline; run in repo root.
- Data-plane AEAD selection can be overridden via config (`[crypto] aead_preference` / `force_aead`); Initial/Handshake remain AES-128-GCM for QUIC long-header compatibility.
- `src/profile.rs` keeps `Aegis128Profile` public and converts to/from `simd::CryptoAeadPlan` via `select()`/`select_for_len()` helpers.

We do not list the crate's file structure exhaustively; instead we focus on the essential aspects and how to run the tests.

#### Rationale & Changes
- Why:
  - AEAD-first design with strong performance (AEGIS-128L) and constant-time tag verification.
  - Security behavior: on authentication failure (wrong tag/AD/nonce) an error is returned; no plaintext is produced.
  - Fully internal AEGIS implementation (no external wrappers/dependencies).
- What:
  - Internal implementation in `src/crypto.rs`: `Aegis128L`, `Aegis128X4`, `Aegis128X8`.
  - Tests: `scripts/tests/rust/rt-baseline-oracles.rs` covers AEGIS-128L roundtrip and tamper rejection for baseline vectors.
  - Tooling: central runner `./scripts/tests/suites/test-crypto.sh` executes crypto tests and Clippy with strict `-D warnings`.
    - Manual invocation (equivalent in repo root):
      - `cargo test`
      - `cargo clippy -- -D warnings`

#### Overview and Quick Start
Use the dedicated test script to run crypto tests and Clippy locally:

```bash
./scripts/tests/suites/test-crypto.sh
cargo test
```

#### Step-by-Step Guide
1. Install prerequisites: latest stable Rust with cargo.
2. Run the test script: `./scripts/tests/suites/test-crypto.sh`.
3. Manual invocation (in repo root):
   - `cargo test`
   - `cargo clippy -- -D warnings`

#### Integration Guidelines and Optimization Strategy
- Use internal AEADs via `CipherSuiteSelector` in `src/crypto.rs`; no external wrappers required.
- On tag failure: constant-time verify -> error; no plaintext is emitted.
- Keep cipher concerns isolated; avoid mixing AEGIS logic into transport code.
- Keep performance- and safety-critical crypto changes covered by `scripts/tests/suites/test-crypto.sh`.

### Accelerate Module Integration
The accelerate module provides comprehensive hardware acceleration for multiple subsystems:

#### SIMD Policy Dispatch (Accelerate Module)
```rust
use quicfuscate::optimize::{SimdPolicy, dispatch, CpuFeature};
use quicfuscate::accelerate::brain::{compute_statistics, compute_correlation, matrix_multiply};

// Dispatch to optimal SIMD implementation based on CPU features
if FeatureDetector::instance().has_feature(CpuFeature::AVX512F) {
    // Use AVX-512 optimized paths
    let result = unsafe { compute_statistics_avx2_fma(data) };
} else if FeatureDetector::instance().has_feature(CpuFeature::AVX2) {
    // Use AVX2 optimized paths
    let result = unsafe { compute_statistics_avx2_fma(data) };
} else {
    // Use scalar fallback
    let result = compute_statistics(data);
}

// Hosts advertising AVX10.1 (with Cargo feature `avx10_preview`) automatically
// surface as AVX2/AVX-512 capable here. `FeatureDetector` tracks them
// independently via `SIMD_USAGE_AVX10_256`/`SIMD_USAGE_AVX10_512`, so adoption is
// observable without touching call sites while preserving safe defaults when the
// preview flag is disabled.
```

#### Performance Metrics for Acceleration
- **Performance counters**: Track SIMD utilization and performance gains
- **Feature detection caching**: Efficient CPU feature detection with thread-safe caching
- **Runtime dispatch optimization**: Minimize overhead of selecting optimal implementations

```rust
use quicfuscate::optimize::telemetry;

// Access acceleration telemetry
let simd_usage = telemetry::get_simd_usage();
println!("AVX2 usage: {}", simd_usage.avx2_calls);
println!("AVX-512 usage: {}", simd_usage.avx512_calls);
```

#### Hardware Acceleration Topology (Kernel Map)

- `src/optimize.rs`
  - FeatureDetector (CPU features -> `CpuProfile`)
  - Central SIMD dispatch helpers (`SimdDispatch`), MemoryPool, telemetry
  - ARM: `xor_repeating_key_32` provides a dedicated SVE2 kernel with key rotation; NEON serves as fallback
- `src/simd.rs`
  - Acceleration planner (`planner::AccelerationPlanner`) with per-domain plans
  - CryptoAeadPlan (LAesni/LNeon/Morus by default; wider plans exist but are not selected by default)
  - QPACK Huffman encoding/decoding: runtime dispatch includes AVX2 (x86), NEON (ARM) and an SVE2 wrapper (encode/decode) with scalar fallback
  - QUIC varint encode/decode & header validation dispatch: SVE2 (VL-scalable predicates) -> NEON -> scalar; `transport::pn` uses these paths directly.
  - Bitstream pack/unpack: NEON fast paths for bit widths 1-8; SVE2 wrapper routes to NEON.
  - Core popcount: NEON (`vcntq_u8` + horizontal sum); SVE2 wrapper present.
- `src/accelerate.rs`
  - Thin re-export of `src/optimize/*` (transport_io, random, iter, sort, string, compress, brain, stealth, transport, memory). Implementations and telemetry live in optimize modules; accelerate paths remain stable.
- `src/fec.rs`
  - RLNC/Streaming encoders/decoders using `simd::galois` (GFNI/AVX2/NEON/SVE2/SSSE3)
  - Adaptive decoder policy: Gaussian elimination for small systems (<32 equations), Wiedemann for larger sparse systems with Gauss fallback
  - Feature `fec_advanced` enables Wiedemann/Berlekamp-Massey and bitsliced GF multiplication on ARM NEON; Berlekamp-Massey now has a VL-aware SVE2 path (`FEC_BERLEKAMP_SVE2_OPS` telemetry), otherwise falls back to NEON/scalar.
  - SVE2-aware matrix multiply uses real VL-SVE2 XOR-stores; SSSE3 dispatch added (`matrix_multiply_ssse3`) falling back to scalar only for `X86_P0a`.
- `src/crypto.rs`
  - AEAD glue; consumes FeatureDetector/plan at instantiation for runtime selection
- MORUS-1280-128 scalar and SIMD backends are instrumented via `MORUS1280_SCALAR_OPS`, `MORUS1280_SSE2_OPS`, `MORUS1280_SSSE3_OPS`, `MORUS1280_SSE41_OPS`, `MORUS1280_SSE42_OPS`, and `MORUS1280_NEON_OPS`.
  - ChaCha20-Poly1305: ChaCha keystream SIMD XOR (SSE4.1/SSSE3->AVX->AVX2->AVX-512, NEON & SVE2), Poly1305 MAC dispatch (SSE2/AVX2/AVX-512, NEON/SVE2)
  - AES-128-GCM: `Aes128Ctx` caches round keys once; CTR uses 4-lane AESNI/AESE batches, SSSE3 hosts use SIMD fallback (`aes128_encrypt_block_ssse3`, `ctr_xor_ssse3`, telemetry `AES_BLOCK_SSSE3_OPS`/`AES_CTR_SSSE3_OPS`), NEON/SVE2 use AESE/PMULL paths, and non-SIMD CPUs use the scalar T-Table.
  - SHA-256/HMAC: `Sha256Plan` streams 64-byte blocks zero-copy into the `sha2-asm::compress256` backend (batch size 1 for AVX2, 2 for VNNI), places T0/T1 prefetches ahead and prioritizes AVX2/VNNI -> SHA-NI -> NEON/SVE2. Telemetry logs all paths (`SHA256_*`, `HMAC_SHA256_*`).

### Core Traits Architecture

#### Engine and Runtime Control Types

The canonical cross-layer runtime contracts are exposed through the Engine and observer systems:

- `engine::EngineCommand` and `engine::EngineEvent` provide typed control-plane mutations and status/event delivery.
- `engine::EngineState` and `engine::EngineStats` are the authoritative lifecycle and runtime metric surfaces for embedding integrations.
- `brain::DeepIntegrationOrchestrator` coordinates server-push and adaptive control hints when orchestrator coupling is enabled.

Representative API surface:

```rust
pub enum EngineCommand {
    Start,
    Stop,
    Connect,
    Disconnect,
    Reconnect,
    SetStealthMode(StealthMode),
    SetFecMode(FecMode),
    SetCongestionControl(CongestionControlAlgorithm),
    SetTrafficPadding(bool),
    SetTimingObfuscation(bool),
    SetZeroRtt(bool),
    GetTunCapabilities,
    GetState,
    GetStats,
}

pub enum EngineEvent {
    StateChanged(EngineState),
    Connected,
    Disconnected(DisconnectReason),
    Error(EngineError),
    StatsUpdated(EngineStats),
    StealthEscalated { level: String },
}
```

#### Transport Observer Pattern

```rust
pub trait TransportObserver: Send + Sync {
    fn on_ack(&self, ack_delay: u64, ranges: &[(u64,u64)]) {}
    fn on_packet_recv(&self, packet_size: usize) {}
    fn on_packet_sent(&self, packet_size: usize) {}
    fn on_loss_detected(&self, packets_lost: u64) {}
    fn on_ecn(&self, ect0: u64, ect1: u64, ce: u64) {}
    fn on_rtt(&self, latest: u32, smoothed: u32, min: u32, var: u32) {}
}
```

`FecTransportObserver` is the production observer used for transport-to-FEC coupling. It samples ACK/loss/ECN signals, maintains ACK-delay smoothing, applies profile-aware threshold/pacing adjustments, and feeds interval/redundancy hints into transport FEC control hooks (`set_fec_*` and `take_fec_control_delta()`), keeping `AdaptiveFec` synchronized with live transport conditions.

#### TLS Provider Interface
```rust
pub trait QuicTlsProvider: Send + Sync {
    fn configure(&mut self, profile: &TlsProfile) -> Result<(), ConnectionError>;
    fn set_server_name(&mut self, name: &str) -> Result<(), ConnectionError>;
    fn provide_quic_data(&mut self, level: Level, data: &[u8]) -> Result<(), ConnectionError>;
    fn next_crypto_frame(&mut self, level: Level, max_len: usize) -> Option<(u64, Vec<u8>)>;
    fn poll_secrets_and_install(&mut self, crypto: &Arc<RwLock<CryptoContext>>) -> Result<(), ConnectionError>;
    fn handshake_complete(&self) -> bool;
    fn alpn(&self) -> Option<&str>;
    fn peer_cert(&self) -> Option<Vec<u8>>;
    fn enable_0rtt(&mut self) -> Result<(), ConnectionError>;
    fn get_0rtt_keys(&self) -> Option<(Vec<u8>, Vec<u8>)>;
    fn export_keying_material(&self, label: &[u8], context: &[u8], length: usize) -> Result<Vec<u8>, ConnectionError>;
    fn get_quic_transport_params(&self) -> Vec<u8>;
    fn set_peer_transport_params(&mut self, params: &[u8]) -> Result<(), ConnectionError>;
    fn key_update(&mut self) -> Result<(), ConnectionError>;
    fn provider_name(&self) -> &str;
    fn supports_ch_override(&self) -> bool;
    fn apply_ch_override(&mut self, template: &[u8]) -> Result<(), ConnectionError>;
}

#### TUN Device Abstraction

See `src/interface.rs` for platform-specific implementations and factory registration details.
```rust
pub trait TunDevice: Send + Sync {
    fn name(&self) -> &str;
    fn mtu(&self) -> u16;
    fn read(&self, buf: &mut [u8]) -> io::Result<usize>;
    fn write(&self, buf: &[u8]) -> io::Result<usize>;
}
```

#### SIMD Policy Dispatch (Trait Layer)

```rust
pub trait SimdPolicy: Any {
    fn as_any(&self) -> &dyn Any;
}
// Select best implementation at runtime via optimize::dispatch() or dispatch_bitslice().
```

#### AEAD Cipher Traits

```rust
pub trait AeadOpen {
    fn open_with_u64_counter(
        &self, 
        counter: u64, 
        ad: &[u8], 
        buf: &mut [u8]
    ) -> Result<usize, ConnectionError>;
}

pub trait AeadSeal {
    fn seal_with_u64_counter(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
        len: usize,
        extra_in: Option<&[u8]>
    ) -> Result<usize, ConnectionError>;
}

pub trait HeaderProtector {
    fn apply(&self, sample: &[u8], mask: &mut [u8]);
    fn remove(&self, sample: &[u8], mask: &mut [u8]);
    fn new_mask(&self, sample: &[u8]) -> [u8; 5];
}

pub trait KeyScheduleHooks {
    fn set_read_secret(&mut self, level: Level, alg: Algorithm, secret: &[u8]);
    fn set_write_secret(&mut self, level: Level, alg: Algorithm, secret: &[u8]);
}

#### Buffer Management Traits

```rust
pub trait BufFactory: Clone + Default + Debug {
    type Buf: Clone + Debug + AsRef<[u8]>;
    fn buf_from_slice(buf: &[u8]) -> Self::Buf;
}

pub trait BufSplit {
    fn split_at(&mut self, at: usize) -> Self;
    fn try_add_prefix(&mut self, prefix: &[u8]) -> bool;
}

pub trait NameValue {
    fn name(&self) -> &[u8];
    fn value(&self) -> &[u8];
}
```

### Module Integration Examples

#### StealthBrain Integration with Transport
```rust
use quicfuscate::brain::{StealthBrain, CombinedObserver};
use quicfuscate::transport::Connection;
use std::sync::Arc;

// Create StealthBrain with configuration
let brain = Arc::new(StealthBrain::new(Default::default()));

// Create combined observer for multiple telemetry sources
let observer = CombinedObserver::new();
observer.add_observer(brain.clone());
observer.add_observer(fec_observer);

// Attach to transport connection
let mut conn = Connection::new_with_observer(config, observer)?;

// Brain automatically optimizes ACK policy based on network conditions
```

#### Compression Integration
```rust
use quicfuscate::compress::{CompressionManager, CompressionPolicy};

// Create compression manager
let compress = CompressionManager::new(Default::default());

// Set adaptive policy
let policy = CompressionPolicy {
    enabled: true,
    min_len: 1024,
    level: 6,  // Balance speed vs ratio
};

// Apply to payload before encryption
let compressed = compress.compress_with_policy(&payload, &policy)?;
```

#### Unified TLS Provider Usage
```rust
use quicfuscate::qftls::{create_provider, ProviderStrategy};
use std::sync::{Arc};
use parking_lot::RwLock;

let crypto = Arc::new(RwLock::new(quicfuscate::transport::packet::CryptoContext::default()));
let mut provider = create_provider(ProviderStrategy::Unified, is_server, crypto)?;
// provider now drives QUIC CRYPTO frames (RealTLS) and optional TLS Cover internally
```

#### Build System
- Pure Cargo build; no external system dependencies beyond the Rust toolchain.
- AEGIS and MORUS are implemented under `src/crypto.rs` and are part of the core build.

#### Custom TLS Hooks
Not applicable. AEGIS is a symmetric AEAD and does not expose TLS handshake hooks.

#### Browser Fingerprints
See "Unified TLS Provider (RealTLS + TLS Cover) -> Fingerprint Source Model" for canonical runtime and optional external-dump behavior.

#### Advanced Optimizations
- Crypto hotpaths use target-feature gated intrinsics (`aes`, `sse2`, `avx2`, `vaes`, `neon`); runtime dispatch via `cpufeatures` selects the best backend.
- AEGIS/MORUS implementations include unsafe blocks for SIMD lanes where necessary; all sensitive operations remain constant-time by design.
- Transport/H3 uses zero-copy iovecs, io_uring fast paths (feature `uring_sys`) and aligned pools (`MemoryPool`) for minimal copies. The runtime now calls `transport::uring::try_send_connected/try_send_to` before falling back to `sendmsg`, enabling io_uring datagram sends automatically on capable Linux kernels.
- Stealth hotpaths (header/QPACK building, XOR obfuscation) prefer SIMD kernels with safe scalar fallback; mutex/atomic usage is minimized in hotpaths.

#### Feature Matrix (Crypto)
- Cargo features:
  - `client` (default): client runtime build.
  - `server` (default): server runtime build (enables `rcgen` for dev cert workflows).
  - `rust-tests`: enables test-only env overrides (see "Test-only Environment Overrides").
  - `benches`: enables benchmark-only binaries and harnesses.

Examples
```bash
cargo test
cargo build --release
```

#### Runtime Dispatch (Selector)

At runtime, the data-plane AEAD plan is selected based on CPU features (via `cpufeatures` and the internal `FeatureDetector`):

```rust
use quicfuscate::simd::CryptoAeadPlan;

let plan = CryptoAeadPlan::select();
let selected = match plan {
    CryptoAeadPlan::LAesni => "aegis-128x8",
    CryptoAeadPlan::LNeon => "aegis-128x4",
    CryptoAeadPlan::Morus => "morus-1280-128",
};
```

Benchmarks
- Script: `./scripts/benchmarks/suites/bench-crypto.sh` - runs crypto micro-benchmarks across modes and exports results to `scripts/out/benchmarks/`.
- Optional (feature-gated): build with `--features benches` to run the `crypto-bench` subcommand.

#### Automated Build and CI/CD
- The general CI workflow `ci.yml` runs Clippy and workspace tests.

#### Local Development Workflow
- Use `cargo test` for unit/integration tests and the suite scripts under `scripts/tests/suites/` for end-to-end coverage.

#### Maintenance
- Track upstream changes; maintain constant-time implementations; integrate upstream test vectors where applicable.
- Keep crypto changes minimal and well-isolated; extend test vectors and suite coverage when touching hot paths.

---

### Core Module Functions

#### HTTP/3 Polling Functions
```rust
use quicfuscate::core::QuicFuscateConnection;

// Poll with custom body handler
conn.poll_http3_with(|stream_id, data| {
    println!("Stream {}: {} bytes", stream_id, data.len());
})?;

// Poll MASQUE capsules with handler
conn.poll_http3_capsules_with(|capsule_type, data| {
    match capsule_type {
        0x00 => handle_datagram(data),
        0x21 => handle_control(data),
        _ => {}
    }
})?;
```

#### MASQUE Handler Registration
```rust
// Set capsule handler
conn.set_masque_capsule_handler(Some(Arc::new(Mutex::new(
    Box::new(|capsule| {
        process_capsule(capsule);
    })
))));

// Set datagram handler  
conn.set_masque_datagram_handler(Some(Arc::new(Mutex::new(
    Box::new(|data| {
        process_datagram(data);
    })
))));

// Set control handler
conn.set_masque_control_handler(Some(Arc::new(Mutex::new(
    Box::new(|control| {
        process_control(control);
    })
))));
```

#### Connection Management Functions
```rust
use quicfuscate::core::QuicFuscateConnection;

// Migrate connection to new local address
let new_addr = "127.0.0.1:0".parse().unwrap();
let path_id = conn.migrate_connection(new_addr)?;

// Check connection state
if conn.is_established() {
    println!("Connection is active");
}

// Get connection statistics
let stats = conn.get_stats();
println!("RTT: {}ms, Delivery rate: {}bps", 
         stats.rtt.as_millis(), 
         stats.delivery_rate);

// Register transport observers
conn.add_transport_observer(Arc::new(stealth_brain));
```

## Configuration

QuicFuscate uses a unified TOML configuration file for runtime settings. The canonical source is `config/quicfuscate.toml`.
This section stays intentionally quick-start oriented. Full key-by-key schema, defaults, and environment overrides are documented in "Configuration Reference (Full)".

### Quick Start Configurations

#### Minimal (Performance Focus)
```toml
[stealth]
mode = "off"

[fec]
mode = "off"
```

#### Balanced (Default)
```toml
[stealth]
mode = "stealth"

[fec]
mode = "auto"
```

#### Maximum Stealth
```toml
[stealth]
mode = "anti-dpi"

[fec]
mode = "auto"

[stealth.fingerprint_rotation]
enabled = true
mode = "all"
```

### Preset Guidance

- Minimal - prioritize lowest overhead and disable stealth/FEC extras.
- Balanced - default operational baseline for mixed latency/loss environments.
- Maximum Stealth - anti-DPI posture with rotation and adaptive recovery enabled.

For full stealth-mode semantics and all `[stealth]` keys, use:
- "Obfuscation-Modes Overview" and "Stealth Modes - Semantics"
- "Configuration Reference (Full)"

### Advanced Stealth Components

#### Cover Traffic Scheduler
```rust
pub struct CoverTrafficScheduler {
    target_domain: String,
    interval_ms: u64,
    request_types: Vec<RequestType>,
}

// Generates realistic browser traffic patterns
let scheduler = CoverTrafficScheduler::new(
    "example.com",
    5000,  // 5 second interval
    vec![RequestType::GET, RequestType::HEAD]
);
```

#### Active Probe Detection
```rust
pub struct ActiveProbeDetector {
    patterns: Vec<ProbePattern>,
    detection_history: HashMap<IpAddr, Vec<Instant>>,
    response_mode: ProbeResponseMode,
}

// Detects and responds to DPI probes
let detector = ActiveProbeDetector::new();
if detector.is_probe(&packet) {
    detector.generate_response(ProbeResponseMode::FakeResponse);
}
```

#### Flow Shaping
```rust
pub struct FlowShaper {
    jitter_min_ms: u32,
    jitter_max_ms: u32,
    dummy_retransmit_probability: f32,
    bandwidth_limit_mbps: Option<u32>,
}

// Advanced traffic shaping
let shaper = FlowShaper::new()
    .with_jitter(10, 50)  // 10-50ms jitter
    .with_dummy_retransmits(0.05)  // 5% dummy packets
    .with_bandwidth_limit(100);  // 100 Mbps cap
```

#### MASQUE Tunnel Management
```rust
pub struct MasqueTunnel {
    tunnel_id: String,
    proxy_url: String,
    target: SocketAddr,
    state: TunnelState,
}

// CONNECT-UDP tunnel setup
let tunnel = MasqueTunnel::connect(
    "https://masque-proxy.example.com",
    target_addr
)?;
```

### Advanced TLS Features

#### Certificate Chain Emulation
```rust
use quicfuscate::qftls::CertChainEmulator;

let cert_chain = CertChainEmulator::generate(
    vec!["cdn.example.com".to_string()],
    90 // Validity days
);
```
- 2-3 level certificate chain
- ECDSA-P256 + SHA-256
- Realistic SANs
- 60-90 days validity

#### Session Tickets & Resumption
```rust
use quicfuscate::stealth::SessionTicketManager;

let ticket_mgr = SessionTicketManager::new(
    2,    // Max tickets
    7200  // Lifetime in seconds
);
```
- 1-2 NewSessionTicket records
- PSK with realistic ages
- Timer jitter for authenticity
- Automatic 0-RTT resumption support

#### ECH GREASE
- Encrypted Client Hello GREASE
- Modern browser behavior
- 64 Bytes GREASE Data

### Fingerprint Rotation

#### Configuration
```toml
[stealth.fingerprint_rotation]
enabled = true
interval_secs = 180  # 3 minutes
mode = "slots"  # fixed, slots, all
profile_slots = [
    ["chrome", "windows"],
    ["firefox", "macos"],
    ["safari", "ios"],
]
```

#### Rotation Modes
- **Fixed**: single profile, no rotation
- **Slots**: rotate through configured slots (up to 3)
- **All**: rotate through all available profiles

### Browser Profile

Available combinations:
- **Windows**: Chrome, Firefox, Edge
- **macOS**: Safari, Chrome, Firefox, Edge
- **Linux**: Chrome, Firefox
- **Android**: Chrome, Firefox, Edge
- **iOS**: Safari, Chrome

### Traffic Obfuscation

#### Padding Strategies
1. **Random**: randomized padding `0..=max_size`
2. **Fixed**: fixed padding up to `max_size`
3. **Adaptive**: adaptive padding based on size and granularity
4. **BrowserMimic**: profile-biased padding using the mimic bias and granularity knobs

### Domain Fronting

Curated domain sets are defined in `CdnProvider` and `DomainFrontingManager::ultra_stealth` in `src/stealth.rs`. When fronting is enabled and no domains are configured, the ultra-stealth set is used.

### Performance Optimizations

#### SIMD XOR Obfuscation
- SSE2 on x86_64: 32-byte chunks
- NEON on aarch64: 32-byte chunks
- Fallback: Byte-wise XOR

#### Zero-Copy Operations
- In-place Obfuscation/Deobfuscation
- Pooled memory for HTTP/3 headers
- Aligned buffers for SIMD

## Production Configuration
When deploying QuicFuscate in a production environment you may enable telemetry
and export metrics through your own endpoint:

- Start the binary with `--telemetry` to activate counters, then periodically
  call `optimize::telemetry::telemetry_snapshot_text()` and serve the result via
  your HTTP endpoint (or use the built-in `/telemetry` endpoint).
- Increase the `MemoryPool` capacity to match expected traffic volume.
- Configure a reliable DoH provider in `StealthConfig` for consistent DNS
  resolution.
- Use `FecConfig::from_file` to tune window sizes and PID constants for your
  network conditions.

### Telemetry HowTo
- Enable telemetry via CLI: start with `--telemetry` to activate counters.
- Exporting metrics: call `optimize::telemetry::telemetry_snapshot_text()` to obtain a plain text snapshot, or use the built-in `/telemetry` endpoint.
- Integration: serve the snapshot via your own HTTP endpoint or exporter; call `telemetry::flush()` to emit a one-off snapshot to logs.

### XDP Configuration
AF_XDP is an optional Linux fast path. When `OptimizeConfig.enable_xdp` is enabled and the host supports AF_XDP, the runtime initializes an XDP socket path; otherwise it falls back to native UDP/io_uring transport paths.

### Command Line Interface (Clap Subcommands)

QuicFuscate provides a comprehensive CLI with multiple subcommands for different operational modes and internal utilities:

### Main Subcommands

Global CLI flags (all commands):
- `--verbose` - enables verbose logging initialization.
- `--telemetry` - enables runtime telemetry metrics export surfaces.

#### **`client`** - Runs the QuicFuscate client
**Required Options:**
- `--remote`: Server address to connect to

**Network Options:**
- `--local`: Local UDP address (default: 0.0.0.0:0)
- `--url`: URL to request (default: https://cloudflare-dns.com/)
- `--cc-algorithm`: Congestion control (reno, cubic, bbr, bbr2, bbr2_gcongestion) [default: bbr2]

**Stealth Options:**
- `--profile`: Browser fingerprint (chrome, firefox, safari, edge) [default: chrome]
- `--os`: Operating system (windows, macos, linux, ios, android) [default: windows]
- `--profile-seq`: Comma-separated profiles for rotation
- `--profile-interval`: Rotation interval in seconds
- `--doh-provider`: DNS-over-HTTPS URL (default: https://cloudflare-dns.com/dns-query)
- `--front-domain`: Domain fronting targets (comma-separated)

- `--disable-doh`: Disable DNS over HTTPS
- `--disable-fronting`: Disable domain fronting
- `--disable-xor`: Disable XOR obfuscation
- `--disable-http3`: Disable HTTP/3 masquerading

Note: TLS provider selection and fingerprinting are internal.

**TLS/Debug (client only):**
- `--verify-peer` - validate server certificate
- `--ca-file <PATH>` - CA file for verification
- `--no-utls` - disable uTLS and use standard TLS
- `--debug-tls` - dump TLS keys for debugging
- `--list-fingerprints` - list available browser fingerprints

**FEC Options:**
- `--fec-mode`: Initial FEC mode (zero, light, normal, medium, strong, extreme, ultra, fountain, streaming) [default: zero]
- `--fec-config`: Path to FEC configuration TOML

**Memory Options:**
- `--pool-capacity`: Memory pool capacity (default: 1024)
- `--pool-block`: Block size in bytes (default: 4096)

**TUN Options:**
- `--tun`: Enable TUN bridging
- `--tun-name`: TUN interface name
- `--tun-mtu`: TUN MTU
- `--tun-ip`: TUN IP address
- `--tun-netmask`: TUN netmask

**Configuration:**
- `--config`: Path to unified TOML configuration

#### **`server`** - Runs the QuicFuscate server
**Required Options:**
- `--cert`: Certificate file path
- `--key`: Private key file path

**Network Options:**
- `--listen`: Listen address (default: 127.0.0.1:4433)
- `--cc-algorithm`: Congestion control (reno, cubic, bbr, bbr2, bbr2_gcongestion) [default: bbr2]
  - Note: Additional algorithms exist internally in `transport::CongestionControlAlgorithm` (e.g., `Ledbat`, `BBR3`) but are not exposed via CLI.

**Other options mirror the client subcommand**

#### Hidden Diagnostic Subcommands  
- **`cross-fade-sim`** - cross-fade simulation for FEC mode transitions
- **`high-loss-sim`** - High packet loss simulation for testing resilience
- **`optimize-probe`** - Internal capability probe for system diagnostics
- **`capabilities`** - System capability detection and feature availability
- **`xdp-smoke`** - XDP smoke test (compatibility no-op)

#### Benchmark Subcommands (feature-gated `--features benches`)
- `fec-bench` - FEC benchmark (sequential vs parallel)
  - Options: `--packets|--iterations`, `--payload`, `--mode <FecMode>`, `--pool-capacity`, `--block-size`, `--warmup`, `--json`
- `pool-bench` - Memory pool micro-benchmark
  - Options: `--iterations|--packets`, `--payload`, `--pool-capacity`, `--block-size`, `--warmup`, `--json`
- `crypto-bench` - Crypto/encode micro-benchmark
  - Options: `--iterations`, `--payload`, `--mode {fnv1a|xor|rolling}`, `--warmup`, `--json`
- `net-bench` - Synthetic networking micro-benchmark
  - Options: `--iterations`, `--payload`, `--warmup`, `--json`

### Crypto Benchmark Modes

The `crypto-bench` subcommand supports different hashing/encoding modes:

```rust
pub enum CryptoMode {
    Fnv1a,   // FNV-1a hash
    Xor,     // XOR encoding
    Rolling, // Rolling hash
}
```

**Usage:**
```bash
# Benchmark FNV-1a hashing
quicfuscate crypto-bench --mode fnv1a --iterations 1000000

# Benchmark XOR encoding
quicfuscate crypto-bench --mode xor --payload 4096

# Benchmark rolling hash
quicfuscate crypto-bench --mode rolling --warmup 1000
```

### Clap Value Enums
- **`BrowserProfile`** - Browser fingerprint profiles (Chrome, Firefox, Safari, Edge)
- **`OsProfile`** - Operating system profiles (Windows, macOS, Linux, iOS, Android)
- **`FecMode`** - Forward Error Correction modes (Zero, Light, Normal, Medium, Strong, Extreme, Ultra, Fountain, Streaming)
- **`CryptoMode`** - Cryptographic operation modes (Fnv1a, Xor, Rolling)

### Common Configuration Options
Both client and server subcommands support extensive configuration:
- Browser and OS fingerprinting profiles with rotation capabilities
- FEC mode selection and memory pool tuning
- UDP/io_uring fast paths (XDP socket stub present but disabled)
- Stealth features: DoH, domain fronting, XOR obfuscation, HTTP/3 masquerading
- TOML configuration file support
- TLS debugging and certificate validation options

## Static Policy Checks
To validate security and stealth policies without performing a build, use the dedicated audit and utility scripts:

- **TLS Profile Validation**:
  - `./scripts/tests/utils/util-e2e-decode-all-profiles.sh` - Decode and sanity-check all CHLO files
  - `./scripts/tests/utils/util-e2e-verify-all.sh` - Verify all profiles match their SHA256 sidecars (`--sidecars-dir` supported)
  - `./scripts/tests/utils/util-e2e-verify-current.sh` - Verify active `${QUICFUSCATE_BROWSER}/${QUICFUSCATE_OS}` profile (`--sidecars-dir` supported)

- **Static Code Hardening**:
  - `./scripts/tests/audits/audit-all-comprehensive.sh` - Consolidated audit (unsafe patterns, deps, quality)

- **TLS Profile Management**:
  - `./scripts/tests/utils/util-tls-list-profiles.sh` - List all available TLS profiles
  - `./scripts/tests/utils/util-tls-generate-sha256-sidecars.sh` - Generate SHA256 checksums snapshot under `scripts/out/utils/.../sidecars/`
  - `./scripts/tests/utils/util-tls-show-active-env.sh` - Display current TLS environment settings

These checks are deterministic, offline, and fast, designed to integrate into an entirely local workflow. All scripts are organized in the `scripts/` directory with clear categorization by purpose.
