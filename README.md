**Quick Links:** [Documentation](./docs/DOCUMENTATION.md) | [Contributing](./docs/CONTRIBUTING.md) | [Scripts Reference](./docs/DOCUMENTATION.md#scripts-reference-authoritative) | [Configuration](./config/quicfuscate.toml) | [License](./docs/LICENSE)

<br><br>

<div align="center">
  <img src="assets/logo/QuicFuscate.png" alt="QuicFuscate Logo" width="300">

  [![Build](https://img.shields.io/badge/Build-Passing-brightgreen?style=for-the-badge&logo=github)](https://github.com/Christopher-Schulze/QuicFuscate/actions)
  [![Rust](https://img.shields.io/badge/Rust-1.93+-000000?style=for-the-badge&logo=rust)](https://www.rust-lang.org/)
  [![QUIC](https://img.shields.io/badge/QUIC-Protocol-009DFF?style=for-the-badge&logo=internet-explorer)](https://datatracker.ietf.org/doc/html/rfc9000)
  [![HTTP/3](https://img.shields.io/badge/HTTP-3-FF6B6B?style=for-the-badge&logo=internet-explorer)](https://en.wikipedia.org/wiki/HTTP/3)
  [![Obfuscation](https://img.shields.io/badge/Obfuscation-Enabled-6A5ACD?style=for-the-badge)](#stealth-techniques)
  [![DPI-Resistant](https://img.shields.io/badge/DPI-Resistant-FF8C00?style=for-the-badge)](#stealth-techniques)
  [![FEC](https://img.shields.io/badge/FEC-RLNC%2BTetrys-9F7AEA?style=for-the-badge)](https://en.wikipedia.org/wiki/Forward_error_correction)
  [![AEGIS-128](https://img.shields.io/badge/Encryption-AEGIS--128-2F855A?style=for-the-badge)](https://en.wikipedia.org/wiki/AEGIS)
  [![MORUS-1280](https://img.shields.io/badge/Encryption-MORUS--1280--128-2B6CB0?style=for-the-badge)](https://en.wikipedia.org/wiki/MORUS_(cipher))
  [![SIMD](https://img.shields.io/badge/SIMD-Optimized-FFA500?style=for-the-badge&logo=cpu)](https://en.wikipedia.org/wiki/SIMD)
</div>

## Introduction
QuicFuscate aims to deliver a state-of-the-art, QUIC-based VPN that maximizes efficiency and performance while being highly resilient to network censorship. By fusing modern transport, cryptography, a hybrid adaptive forward error correction (FEC) design, and a cohesive stealth stack, the system enables reliable, high-throughput connectivity under adversarial conditions. The project supports democratic values by facilitating open access to information and freedom of speech.

## Highlights
- State-of-the-art censorship resistance with coherent browser-grade fingerprints
  (Native TLS handshake profile injection/TLS Cover, HTTP/3 QPACK header shaping, MASQUE tunneling, domain fronting, DoH, XOR)
- Adaptive SIMD dispatch (AVX2/AVX-512/NEON) with runtime CPU feature detection for optimal performance paths
- AEAD selection at runtime (AEGIS-128L/X, MORUS-1280-128) aligned to CPU features; 
  PFS by default; optional post-quantum handshake
- Hybrid FEC (Adaptive RLNC + Tetrys-like Streaming) with zero-overhead at 0% loss; escalates seamlessly under loss up to Wiedemann (GF(2^8), bitsliced, multi-U/block-BM with Rayon parallelization) and streaming burst (1 repair per N sources, partial-recovery toggle, SIMD-optimized GF(2^16) nibble paths)
- Zero-copy I/O with tunable memory pool, optional io_uring UDP fast path (Linux), and XDP compatibility mode; selectable congestion control (Reno/CUBIC/BBR/BBR2/BBR2-G) and 0-RTT
- Active-probe mitigation with detector-driven escalation and Reality fallback proxying to avoid protocol disclosure under active scans
- Adaptive StealthBrain control loop for ACK policy, timing/padding shaping, MASQUE preference hints, and FEC interval/redundancy hints
- HTTP/3 Server Push cover traffic with profile-coherent bursts and runtime intensity control during stealth escalation
- Adaptive payload compression (zstd policy engine) with optional dictionary paths and telemetry-backed decisioning
- Server-authoritative control plane: Admin Web/API issues and revokes QKeys; server-side enforcement applies embedded stealth/FEC policy at runtime
- Modular script suite: dedicated shell scripts for build/utils, tests (incl. optional fuzz), 
  optional TLS fingerprint dump verification for audit/regression (external base64 dumps), benchmarks (Criterion, FEC CSV),
  TLS utilities, and in-tree QUIC stack tooling (no upstream quiche build dependency)
- Desktop client policy is server-authoritative by design: Stealth/FEC policy comes from issued QKeys and is displayed in the client without local override drift

## Table of Contents
- [Core Features](#core-features)
- [Architecture Overview](#architecture-overview)
- [Project Status](#project-status)
  - [Surface Maturity](#surface-maturity)
  - [Code Layout](#code-layout)
- [Technical Specifications](#technical-specifications)
- [Build Instructions](#build-instructions)
  - [Running the tests](#running-the-tests)
- [Command-Line Usage](#command-line-usage)
- [Continuous Integration](#continuous-integration)
- [Releases](#releases)
- [Contributing](#contributing)
- [License](#license)
- [Important Notice](#important-notice)

## Core Features

### Stealth Techniques
- **Curated Browser Fingerprints**: Out-of-the-box deterministic in-memory ClientHello synthesis for curated browser/OS combinations (Chrome, Firefox, Safari, Edge), with no on-disk profile requirement for runtime operation<br>
- **Native TLS handshake profile injection + TLS Cover**: Applies native fingerprint-aligned TLS profiles and can emit a lightweight synthetic TLS Cover exchange for stealth traffic shaping<br>
- **Domain Fronting**: Masks traffic by routing through trusted CDN providers
  - Rotates across vetted provider domains to decouple the visible SNI from the true origin<br>
  - Risk/Tradeoff: effectiveness depends on current provider policy and regional filtering behavior<br>
- **HTTP/3 Masquerading**: Disguises traffic as standard HTTP/3 web traffic
  - Aligns ALPN, header sets, and framing to common web patterns<br>
- **MASQUE Tunneling**: Uses HTTP/3 CONNECT-UDP/capsule flows as an additional cover-path transport
  - Improves tunnel-path realism while staying aligned with the active browser profile<br>
  - Risk/Tradeoff: requires a compatible CONNECT-UDP path on the selected proxy route<br>
- **Traffic Obfuscation**: XOR-based payload-context obfuscation to reduce pattern regularity
  - Sealed QUIC datagrams remain unmodified to preserve AEAD/FEC integrity; toggleable via CLI/config<br>
- **TLS Profile Cache**: Generated ClientHello bytes are cached in memory for reuse across connections<br>
- **DNS-over-HTTPS (DoH)**: Resolves DNS via HTTPS to hide queries from on-path resolvers<br>
- **QPACK Header Shaping**: Encodes realistic HTTP/3 headers with QPACK for indistinguishable request patterns<br>
- **Active Probe Detection + Reality Fallback**: Detects probe-like traffic patterns and relays suspicious flows through a legitimate upstream path to preserve realistic network behavior under active scanning<br>
- **Server Push Cover Traffic**: Emits realistic HTTP/3 PUSH_PROMISE/DATA cover bursts with configurable intensity, base path, and burst interval for traffic-shaping realism<br>
- **Profile Cycling**: Optional rotation across browser/OS profiles on an interval to diversify observable fingerprints<br>
- **Cross-Layer Profile Coherence**: One active browser/OS profile coordinates TLS handshake injection, HTTP/3/QPACK shaping, MASQUE behavior, and fronting decisions for a homogeneous observable fingerprint<br>
- **Spin Bit Controls**: Configuration-level controls exist; runtime wiring is currently partial and intentionally gated

Native TLS handshake profile injection (RealTLS) is the primary cryptographic handshake path.
TLS Cover is a lightweight synthetic cover exchange for stealth shaping and traffic realism and does not replace native TLS security semantics.
When TLS Cover is disabled, the stack continues to use native TLS handshake profile injection only.
Risk/Tradeoff: enabling TLS Cover adds extra cover-byte volume and processing overhead.

### Next-Gen Hardware-Accelerated AEAD Cryptography
- **AEGIS-128L**: Authenticated encryption with hardware acceleration when AES instructions are available<br>
- **AEGIS-128X4 / AEGIS-128X8**: Unrolled AEGIS-128 variants selected automatically on AES hardware (x86_64 selects X8 when VAES batching is available, otherwise X4; aarch64 selects X4)<br>
- **MORUS-1280-128**: Authenticated encryption with a portable SIMD-friendly design for hosts without hardware AES<br>
- **Perfect Forward Secrecy**: ephemeral key exchange; past sessions remain safe if long-term keys leak<br>
- **Post-Quantum Ready**: Optional Kyber/Dilithium handshake support<br>
- **Nonce Discipline & Constant-Time Glue**: Per-packet nonce handling and constant-time hot-path glue reduce side-channel exposure under load<br>
Runtime AEAD selection: a dispatcher selects AEGIS-128X8 on x86_64 when VAES batching is available, otherwise it selects AEGIS-128X4 on x86_64 (AES-NI). On aarch64 (AES+NEON) it selects AEGIS-128X4. Without hardware AES it selects MORUS-1280-128. See "Cryptography Design" in ./docs/DOCUMENTATION.md.<br>
AEGIS-128L and MORUS-1280-128 are modern, high-assurance AEAD ciphers; runtime selection leverages hardware acceleration where available to sustain high throughput.

### Adaptive FEC & Recovery
- **Hybrid RLNC + Streaming (Tetrys-like)**: Systematic sliding-window coding keeps source packets intact and emits repairs when the active window reaches the configured threshold<br>
- **SIMD GF Arithmetic**: Bit-sliced GF(2^8)/GF(2^16) cores with consistent byte widths across encoder/decoder and optional GF(2^16) nibble paths for high-throughput recovery<br>
- **Advanced Decoder Paths**: Sparse elimination (minimal-NNZ pivot), early repair recovery, and optional Wiedemann/block-BM acceleration for difficult loss patterns<br>
- **Adaptive Mode Switching**: Auto-Mode balances overhead versus delivery probability, keeps a zero-mode fast path at 0% loss, and enables burst-capable streaming under sustained loss/jitter<br>
- **Operational Controls**: Repair cadence (1 repair per N sources), partial recovery, and parallel repair generation are configurable; defaults and tuning are documented in the [FEC Operations Guide](./docs/DOCUMENTATION.md#fec-operations-guide)<br>
- **Outcome**: High stability on lossy/high-jitter paths with minimal overhead under clean network conditions

### Adaptive Runtime Intelligence (StealthBrain)
- **Telemetry-Driven Policy Engine**: Consumes ACK delay windows, ECN, delivery/loss dynamics, IAT/size divergence, and reorder signals to adapt transport and stealth behavior in real time<br>
- **ACK Policy Optimization**: Uses epsilon-greedy threshold selection with cooldowns and step limits to stabilize responsiveness without oscillation<br>
- **Cross-Layer Hints**: Emits timing, padding granularity, MASQUE preference, and FEC interval/redundancy hints for coordinated runtime adaptation<br>
- **Escalation Coordination**: Integrates probe-pressure signals with stealth escalation gates and cover-traffic behavior to keep observables coherent under stress

### Server-Authoritative Control Plane (QKey + Admin Web)
- **QKey Issuance & Revocation**: Admin Web/API manages server-issued QKeys with stable identifiers, token verification, and persistence controls<br>
- **Embedded Policy Enforcement**: Stealth/FEC policy from issued QKeys is enforced server-side at runtime (no client-side drift from authoritative policy)<br>
- **Operational Surface**: Admin endpoints expose status, configuration, and QKey operations while desktop clients consume issued keys for controlled connect/disconnect workflows

### Performance Optimizations
- **Runtime CPU Dispatch**: Central feature detection selects optimal SIMD/crypto paths per host (x86/ARM) with safe scalar fallback where required<br>
- **SIMD Acceleration**: ARM NEON and x86 AVX2/AVX-512 optimizations
  - Hot loops (FEC arithmetic, crypto glue) vectorized where safe for multi-Gbps throughput<br>
- **Bit-Sliced GF Multiplication**: Faster FEC arithmetic via dedicated AVX2/AVX512/NEON kernels
  - Field ops implemented with bit-slicing and tableless strategies to minimize cache pressure<br>
- **Vectorized XOR Fast Path**: 32-byte key path with runtime dispatch and safe scalar fallback for other sizes/alignments
- **Batched Processing**: QUIC I/O and FEC arithmetic are processed in cache-hot batches to maximize throughput<br>
- **Adaptive Compression (zstd Policy)**: Runtime compression decisions use payload size and link signals (RTT/loss/bandwidth), with optional dictionary-based paths and telemetry counters<br>
- **Zero-Copy Architecture**: Minimizes memory allocations for maximum throughput
  - Lock-free buffer pool with tunables `--pool-capacity` and `--pool-block`<br>
- **UDP Fast Path**: Portable batching (sendmmsg/recvmmsg), GSO/GRO (Linux), and optional io_uring path for reduced syscall overhead; XDP is currently maintained as a compatibility mode<br>
- **Tunable Memory Pool**: Pre-allocated buffers for zero-copy I/O; adjust capacity/block size per workload<br>
- **Connection Multiplexing**: Multiple streams over a single connection<br>
- **0-RTT Handshake**: Reduced latency for subsequent connections<br>
  - Risk/Tradeoff: 0-RTT payloads can be replayed; use only for idempotent operations<br>
- **Telemetry Hooks**: Throughput, latency, and repair-efficiency counters expose operational tuning signals

For a full technical deep dive (architecture, cryptography internals, FEC operations, telemetry, and deployment guidance), see [docs/DOCUMENTATION.md](./docs/DOCUMENTATION.md).

## Architecture Overview

```mermaid
flowchart LR
  apps["Applications\nDesktop | Web Admin | CLI | Embedded Engine API"]
  core["core.rs\nSession orchestration"]
  transport["transport/\nconnection, packet, recovery, udpfast, uring, xdp, h3"]
  stealth["stealth.rs + qftls.rs\nStealth, Native TLS profile injection, TLS Cover"]
  data["crypto.rs + fec.rs\nAEAD, key exchange, adaptive RLNC + streaming"]
  control["brain.rs + reality.rs + engine/\nPolicy loop, probe fallback, control-plane API"]
  runtime["implementations/ + optimize/\nRuntime wiring, SIMD, memory, telemetry"]

  apps --> core
  core --> transport
  core --> stealth
  core --> data
  core --> control
  core --> runtime
  runtime --> transport
```

## Project Status

The protocol core is entirely written in Rust, with companion desktop and web-admin applications under `apps/`.
Development focuses on hardening, operational validation, and release readiness across all surfaces.

### Surface Maturity
- **Protocol core (`src/`)**: release-ready for source-first distribution.
- **Desktop app (`apps/desktop`)**: feature-complete pre-production surface (Tauri 2 + React 19 + TypeScript + TailwindCSS); in-repo functionality and tests are in place, with controlled operational validation.
- **Web admin (`apps/web-admin-ui`)**: feature-complete pre-production surface (React 19 + TypeScript + TailwindCSS); in-repo functionality and tests are in place, with controlled operational validation.

### Code Layout
QuicFuscate uses a clean, modular, consolidated layout:
- `src/core.rs` (QUIC session and I/O), `src/crypto.rs` (AEAD and handshake glue),
- `src/fec.rs` (encoder/decoder/adaptive/GF tables inline),
- `src/stealth.rs` (DoH, HTTP/3 masquerading, TLS Cover, domain fronting, QPACK helpers, active-probe detection, server-push cover runtime controls).
- `src/reality.rs` (probe-time fallback proxying that preserves realistic upstream responses under active scanning).
- `src/qftls.rs` (unified RealTLS rustls provider + optional TLS Cover orchestration).
- `src/engine/` (embedded control plane API: lifecycle, commands/events, stats, runtime orchestration).
- `src/implementations/` (client/server runtime wiring, admin HTTP, QKey registry, platform integration).
- `src/optimize/` (CPU/SIMD dispatch, memory/telemetry/perf-focused acceleration modules).
The project is built as a single Rust crate that exposes a library and one CLI binary (`quicfuscate` with `client` and `server` subcommands).
The transport subsystem uses `src/transport.rs` as the module root and focused submodules under `src/transport/` (`connection.rs`, `packet.rs`, `frames.rs`, `recovery.rs`, `udpfast.rs`, `xdp.rs`, `uring.rs`).
This layout improves safety, performance, and maintainability.

## Technical Specifications

| Component           | Technology                                                                 |
|---------------------|----------------------------------------------------------------------------|
| Transport Protocol  | QUIC / HTTP/3                                                              |
| Encryption          | AEGIS-128L/X, MORUS-1280-128                                               |
| Key Exchange        | X25519; optional PQ experiments (Kyber/Dilithium) behind feature flags     |
| Error Correction    | Hybrid Adaptive FEC (RLNC + Streaming)                                     |
| Stealth/Obfuscation | Native TLS handshake profile injection (RealTLS), TLS Cover, HTTP/3/QPACK shaping, MASQUE tunneling, domain fronting, DoH, XOR, adaptive padding/timing/protocol mimicry, active-probe detection + Reality fallback, server-push cover traffic |
| Adaptive Intelligence | StealthBrain policy engine (ACK/timing/padding/FEC/MASQUE coordination) |
| Control Plane       | Server-authoritative QKey lifecycle (issue/revoke/persist), Admin Web/API policy enforcement |
| Compression         | Adaptive zstd policy (signal-aware compression decisions, optional dictionary path) |
| Platforms           | Linux, macOS, Windows                                                      |
| Architecture        | x86_64, ARM64                                                              |
| Performance         | High-throughput, hardware-adaptive fast paths (SIMD + batching + zero-copy) |

## Build Instructions

The Rust protocol core builds with pure Cargo. No external C toolchains, vendored libraries or `QUICHE_PATH` are required for the core build.
For release-ready local builds, run the Rust core workflow and both app workflows.

### Rust core

Build the crate using Cargo:

```bash
# Debug build
cargo build

# Optimized release build
cargo build --release
```

### Web Admin UI

```bash
cd apps/web-admin-ui
bun install
bun run check
bun run build
```

### Desktop App

```bash
cd apps/desktop
bun install
bun run check
bun run build

# Optional native bundle/signing pipeline step
bun run tauri build
```

QuicFuscate works out of the box with deterministic in-memory ClientHello synthesis for curated browser/OS profiles. External `.chlo`/`.chlo.b64` dumps under `browser_profiles/` are optional and intended for audit/regression workflows.

### Running the tests

Execute the test suite with Cargo:

```bash
cargo test --features rust-tests
```

Troubleshooting:
- If a build fails, detailed logs (from build script hooks) can be found under `scripts/out/<category>/`.
- All scripts in `scripts/*` provide a unified minimal help handler via `-h`, `--help`, or `help`. It prints `Usage: <script>` and the first `# Description:` line, then exits with code `0` without side effects.

## Command-Line Usage

The single binary `quicfuscate` provides two user-facing subcommands: `client` and `server`.

Show help:

```bash
quicfuscate --help
quicfuscate client --help
quicfuscate server --help
```

Global flags:

```
  -v, --verbose          Enable verbose logging
      --telemetry        Enable telemetry snapshot on 127.0.0.1:9898 by default (GET /telemetry)
```
Runtime behavior can be tuned via CLI flags and `QUICFUSCATE_*` environment variables.

Top runtime environment variables (quick reference):

```
  QUICFUSCATE_METRICS_ADDR         Telemetry bind address (default 127.0.0.1:9898)
  QUICFUSCATE_STEALTH_MODE         Stealth baseline (off|performance|base|stealth|anti-dpi|intelligent|manual)
  QUICFUSCATE_TLS_COVER            TLS Cover provider gate (0|1)
  QUICFUSCATE_USE_TLS_COVER_EXTRAS TLS Cover extras gate in StealthManager (0|1)
  QUICFUSCATE_FEC_STREAM_EVERY     Streaming FEC cadence override
  QUICFUSCATE_FASTPATH             Transport fast path policy (off|uring|xdp|auto)
  QUICFUSCATE_RAYON_THREADS        Parallel worker cap for FEC paths
  QUICFUSCATE_DESKTOP_UPDATER_ACTIVE Desktop updater runtime activation gate
```

Full environment-variable reference: [docs/DOCUMENTATION.md - Configuration Reference (Full)](./docs/DOCUMENTATION.md#configuration-reference-full).

#### Configuration

Full, commented configuration: see `./config/quicfuscate.toml`.

Typical client example:

```bash
quicfuscate client \
  --remote 203.0.113.1:4433 \
  --local 127.0.0.1:1080 \
  --profile chrome \
  --cc-algorithm cubic \
  --front-domain cdn.example.com \
  --verify-peer \
  --config ./config/quicfuscate.toml
```
Enable `--telemetry` to expose a telemetry snapshot on 127.0.0.1:9898 by default (GET /telemetry).
Override bind address via `QUICFUSCATE_METRICS_ADDR`.

Typical server example:

```bash
quicfuscate server \
  --listen 0.0.0.0:4433 \
  --cert ./server.crt \
  --key ./server.key \
  --profile firefox \
  --cc-algorithm bbr2 \
  --config ./config/quicfuscate.toml
```

Important flags (selection):

```
  --no-utls               Disable uTLS and use regular TLS
  --verify-peer           Validate the server certificate
  --ca-file <path>        CA file for verification (client only)
  --debug-tls             Show TLS debug information
  --list-fingerprints     List built-in browser/OS fingerprint profiles (runtime-ready, no external dump required)
  --fec-mode <mode>       Initial FEC mode (zero|light|normal|medium|strong|extreme|ultra|fountain|streaming)
  --fec-config <path>     Load Adaptive FEC settings from TOML
  --doh-provider <url>    Custom DNS-over-HTTPS resolver
  --front-domain <d>      Domain used for fronting (repeatable or comma-separated)
  --disable-doh           Disable DNS over HTTPS
  --disable-fronting      Disable domain fronting
  --disable-xor           Disable XOR obfuscation
  --disable-http3         Disable HTTP/3 masquerading
  --profile-seq <list>    Comma-separated browser@os to cycle (e.g., chrome@windows,firefox@linux)
  --profile-interval <s>  Interval in seconds for profile switching
  --cc-algorithm <alg>    Congestion control: reno|cubic|bbr|bbr2|bbr2_gcongestion (default: bbr2)
```

FEC mode mapping note:
- CLI `--fec-mode` accepts canonical values (`zero|light|normal|medium|strong|extreme|ultra|fountain|streaming`).
- In config/admin/QKey policy surfaces, aliases map as `off -> zero` and `on|auto|dynamic -> normal`.
## Continuous Integration

GitHub Actions build and test the project on Linux, macOS and Windows with pure Cargo.
Workflows also perform static analysis (clippy + cppcheck) and upload release binaries as artifacts. See `.github/workflows/ci.yml`.

Build and test commands are listed above. To reproduce CI-specific static checks locally run:

```bash
cargo clippy --all-targets -- -D warnings
cppcheck --error-exitcode=1 -q src
```

## Releases

This project is published as a source-first open-source release.
Users build from source using the documented Rust and Bun workflows.

Signed binary distribution and automatic updates are not part of the current source-first release scope.
They require signing credentials and CI secret management to be available.

Desktop updater behavior in this release:
- Integrated but disabled by default.
- Runtime activation gate: `QUICFUSCATE_DESKTOP_UPDATER_ACTIVE=true`.
- Keep disabled for source-first release builds without signed artifacts.

Binary distribution requirements:
- A signing and notarization pipeline is required (macOS/Windows, optional Linux package signing).
- Updater activation in shipped builds requires end-to-end verified signature validation.
- Signed release assets and update metadata are published through GitHub Releases.

Security and hardening references for this release:
- Release security audit snapshot, threat model, and deployment hardening guide: `docs/DOCUMENTATION.md`
- Release scope and distribution policy: [Release Scope](./docs/DOCUMENTATION.md#release-scope)
- Architecture and release wiring map: `docs/MAP.md`

Known limitations in this source-first release:
- No signed desktop binaries are shipped yet.
- Desktop updater remains disabled by default until signed artifacts are available.

Release packaging helper:
```bash
./scripts/utils/util-release-source-package.sh
```
This creates a clean source archive under `scripts/out/releases/source/` and excludes transient artifacts.

## Contributing

We welcome contributions from the community. Please read our guidelines before opening an issue or pull request:

- Start here: [CONTRIBUTING.md](./docs/CONTRIBUTING.md)
- Follow the consolidated module layout (`src/core.rs`, `src/crypto.rs`, `src/fec.rs`, `src/stealth.rs`) and keep documentation changes in `docs/DOCUMENTATION.md`
- Ensure CI, linters, and the static hardening audit pass locally before proposing changes
- Update `config/quicfuscate.toml` and user-facing docs when behavior or flags change

## License

This project is licensed under the MIT License. You are free to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, subject to the terms of the MIT License. 

See [LICENSE](./docs/LICENSE) for details.

## Important Notice

This software is provided "as is" without any warranties. The developers assume no responsibility for any damage caused by the use of this software. Use at your own risk.
