//! # Optimization Module
//!
//! This module provides a framework for runtime CPU feature detection and
//! function dispatching to select the best hardware-accelerated implementation.
//! It also includes foundational structures for zero-copy operations and memory pooling.

use cpufeatures;
// CPU features re-export removed - use cpufeatures directly
use crossbeam_queue::{ArrayQueue, SegQueue};
pub mod brain;
pub mod compress;
pub mod crypto;
pub mod iter;
pub mod memory;
pub mod random;
pub mod sort;
pub mod stealth;
pub mod string;
pub mod telemetry;
pub mod transport;
pub mod udp;

// ============================================================================
// LIBC IMPORTS - Transport layer (sendmsg, recvmsg)
// ============================================================================
pub use aligned_box::AlignedBox;
#[cfg(feature = "unsafe_rust")]
pub mod r#unsafe;
#[cfg(unix)]
use libc::{iovec, msghdr, recvmsg, sendmsg};
use log::{error, info, warn};
use serde::Deserialize;
#[cfg(unix)]
use smallvec::SmallVec;
use std::any::Any;
use std::cell::RefCell;
use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
// use parking_lot::RwLock; // Reserved for future use

// Modular x86 SSE2 helpers (legacy acceleration)
#[cfg(target_arch = "x86_64")]
#[path = "optimize/x86_sse2.rs"]
mod x86_sse2;
#[cfg(target_arch = "x86_64")]
use x86_sse2::xor_repeating_key32_sse2;

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug)]
enum NumaPolicy {
    Local,
    Preferred(usize),
    Interleave,
}

#[cfg(target_os = "linux")]
static NUMA_POLICY: OnceLock<NumaPolicy> = OnceLock::new();

#[cfg(target_os = "linux")]
fn resolve_numa_policy() -> NumaPolicy {
    if let Some(val) = std::env::var("QUICFUSCATE_NUMA_POLICY").ok() {
        let v = val.to_lowercase();
        if v == "local" {
            return NumaPolicy::Local;
        }
        if v == "interleave" {
            return NumaPolicy::Interleave;
        }
        if let Some(rest) = v.strip_prefix("preferred:") {
            if let Ok(n) = rest.parse::<usize>() {
                return NumaPolicy::Preferred(n);
            }
        }
    }
    NumaPolicy::Local
}

#[cfg(target_os = "linux")]
static RR_NODE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{WSARecvMsg, WSASendMsg, WSABUF, WSAMSG};

#[cfg(target_os = "linux")]
mod numa {
    use libc::{c_int, c_void, size_t};
    extern "C" {
        pub fn numa_available() -> c_int;
        pub fn numa_num_configured_nodes() -> c_int;
        pub fn numa_node_of_cpu(cpu: c_int) -> c_int;
        pub fn numa_tonode_memory(start: *mut c_void, size: size_t, node: c_int);
    }

    pub fn is_available() -> bool {
        unsafe { numa_available() >= 0 }
    }
    pub fn num_nodes() -> usize {
        if is_available() {
            unsafe { numa_num_configured_nodes() as usize }
        } else {
            1
        }
    }
    pub fn current_node() -> usize {
        if !is_available() {
            return 0;
        }
        let cpu = unsafe { libc::sched_getcpu() };
        if cpu < 0 {
            0
        } else {
            unsafe { numa_node_of_cpu(cpu) as usize }
        }
    }
    pub unsafe fn move_to_node(ptr: *mut u8, size: usize, node: usize) {
        if is_available() {
            numa_tonode_memory(ptr as *mut c_void, size as size_t, node as c_int);
        }
    }
}

impl<const N: usize> Default for ConstBuffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "windows")]
mod numa {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use windows_sys::Win32::System::SystemInformation::{
        GetCurrentThread, GetNumaHighestNodeNumber, GetNumaNodeProcessorMaskEx,
        SetThreadGroupAffinity, GROUP_AFFINITY,
    };

    static NUMA_NODES: AtomicUsize = AtomicUsize::new(0);

    pub fn is_available() -> bool {
        unsafe {
            let mut highest_node = 0u32;
            if GetNumaHighestNodeNumber(&mut highest_node) != 0 {
                NUMA_NODES.store((highest_node + 1) as usize, Ordering::Relaxed);
                highest_node > 0
            } else {
                false
            }
        }
    }

    pub fn bind_to_node(node: usize) -> Result<(), std::io::Error> {
        unsafe {
            let mut affinity: GROUP_AFFINITY = std::mem::zeroed();
            if GetNumaNodeProcessorMaskEx(node as u8, &mut affinity) == 0 {
                return Err(std::io::Error::last_os_error());
            }

            if SetThreadGroupAffinity(GetCurrentThread(), &affinity, std::ptr::null_mut()) == 0 {
                return Err(std::io::Error::last_os_error());
            }

            Ok(())
        }
    }

    pub fn num_nodes() -> usize {
        let nodes = NUMA_NODES.load(Ordering::Relaxed);
        if nodes > 0 {
            nodes
        } else if is_available() {
            NUMA_NODES.load(Ordering::Relaxed)
        } else {
            1
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod numa {
    pub fn num_nodes() -> usize {
        1
    }
    pub fn current_node() -> usize {
        0
    }
}

// ============================================================================
// MEMORY POOL
// ============================================================================

// Global Memory Pool (lazy, shared)
// ----------------------------------------------------------------------------
static GLOBAL_POOL: OnceLock<Arc<MemoryPool>> = OnceLock::new();

/// Returns a process-wide shared MemoryPool instance. Initializes lazily on
/// first use with conservative defaults.
#[inline]
pub fn global_pool() -> Arc<MemoryPool> {
    GLOBAL_POOL
        .get_or_init(|| {
            // Use larger pool for better performance
            let capacity = std::env::var("QUICFUSCATE_POOL_CAPACITY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(512); // Increased default
            let block_size = std::env::var("QUICFUSCATE_POOL_BLOCK_SIZE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(65536); // 64KB blocks for better performance
            let pool = Arc::new(MemoryPool::new(capacity, block_size));
            // Start auto-tuner thread if enabled
            MemoryPool::start_auto_tuner(Arc::clone(&pool));
            pool
        })
        .clone()
}

/// Initializes the global pool explicitly with custom parameters. Subsequent
/// calls to `global_pool()` will return this instance. Returns `false` if an
/// instance was already initialized.
pub fn init_global_pool(capacity: usize, block_size: usize) -> bool {
    GLOBAL_POOL.set(Arc::new(MemoryPool::new(capacity, block_size))).is_ok()
}

// Use cpufeatures for portable runtime detection
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]

cpufeatures::new!(
    cpuid_x86,
    "avx512f",
    "avx512bw",
    "avx512vbmi",
    "avx2",
    "avx",
    "sse2",
    "vaes",
    "aes",
    "pclmulqdq"
);
#[cfg(target_arch = "aarch64")]
cpufeatures::new!(cpuid_arm, "neon", "aes");

/// Configuration for optimization parameters passed from the CLI.
#[derive(Clone, Copy)]
pub struct OptimizeConfig {
    pub pool_capacity: usize,
    pub block_size: usize,
    pub enable_xdp: bool,
}

impl Default for OptimizeConfig {
    fn default() -> Self {
        Self { pool_capacity: 512, block_size: 65536, enable_xdp: false }
    }
}

impl OptimizeConfig {
    pub fn from_toml(s: &str) -> Result<Self, Box<dyn std::error::Error>> {
        #[derive(Deserialize)]
        struct Root {
            optimize: Option<Section>,
        }
        #[derive(Deserialize)]
        struct Section {
            pool_capacity: Option<usize>,
            block_size: Option<usize>,
            enable_xdp: Option<bool>,
        }
        let root: Root = toml::from_str(s)?;
        let sec = root.optimize.unwrap_or(Section {
            pool_capacity: None,
            block_size: None,
            enable_xdp: None,
        });
        Ok(Self {
            pool_capacity: sec.pool_capacity.unwrap_or(512),
            block_size: sec.block_size.unwrap_or(65536),
            enable_xdp: sec.enable_xdp.unwrap_or(false),
        })
    }

    pub fn from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_toml(&contents)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.pool_capacity == 0 {
            return Err("pool_capacity must be > 0".into());
        }
        if self.block_size == 0 {
            return Err("block_size must be > 0".into());
        }
        Ok(())
    }
}

// ============================================================================
// CPU FEATURE DETECTION SYSTEM
// ============================================================================

/// Complete CPU feature set for ALL platforms - MAXIMALE COVERAGE!
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuFeatures {
    // x86_64 Basic
    pub sse2: bool,
    pub sse3: bool,
    pub ssse3: bool,
    pub sse41: bool,
    pub sse42: bool,
    pub popcnt: bool,
    pub lzcnt: bool,

    // x86_64 Advanced
    pub avx: bool,
    pub avx2: bool,
    pub fma3: bool,
    pub bmi1: bool,
    pub bmi2: bool,

    // x86_64 Ultra
    pub avx512f: bool,
    pub avx512bw: bool,
    pub avx512cd: bool,
    pub avx512dq: bool,
    pub avx512vl: bool,
    pub avx512vbmi: bool,
    pub avx512vbmi2: bool,
    pub avx512vnni: bool,
    pub avx512vpopcntdq: bool,
    pub avx10_1_256: bool,
    pub avx10_1_512: bool,

    // x86_64 Next-Gen Extensions
    pub avx512bf16: bool,
    pub avx512fp16: bool,
    pub avx_vnni: bool,
    pub amx_tile: bool,
    pub amx_int8: bool,
    pub amx_bf16: bool,

    // x86_64 Crypto Specific
    pub aesni: bool,
    pub vaes: bool,
    pub vpclmulqdq: bool,
    pub sha: bool,
    pub gfni: bool,
    pub rdrand: bool,
    pub rdseed: bool,

    // ARM64 Base
    pub neon: bool,
    pub crc32: bool,
    pub atomics: bool,
    pub fp16: bool,
    pub dotprod: bool,

    // ARM64 Crypto
    pub aes: bool,
    pub pmull: bool,
    pub sha1: bool,
    pub sha2: bool,
    pub sha3: bool,
    pub sha512: bool,
    pub sm3: bool,
    pub sm4: bool,

    // ARM64 Advanced
    pub sve: bool,
    pub sve2: bool,
    pub sve_aes: bool,
    pub sve_pmull: bool,
    pub sve_bitperm: bool,

    // Apple Silicon Specific
    pub apple_amx: bool,
    pub apple_m1: bool,
    pub apple_m2: bool,
    pub apple_m3: bool,

    // RISC-V
    pub rvv: bool,
    pub rvv_zvbb: bool,
    pub rvv_zvbc: bool,
    pub rvv_zvkg: bool,

    // Cache Info
    pub l1d_cache: usize,
    pub l1i_cache: usize,
    pub l2_cache: usize,
    pub l3_cache: usize,
    pub cache_line: usize,
}

/// CPU Performance Profile for optimized dispatch
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
#[allow(non_camel_case_types)]
pub enum CpuProfile {
    // x86-64 Legacy Profiles (pre-SSE4.2)
    X86_P0a, // SSE2 baseline (no AES accel)
    X86_P0b, // SSSE3 baseline (byte-shuffle available; no AES accel)
    // x86-64 Profiles
    X86_P1a, // SSE4.2 + POPCNT + CRC32 (no crypto)
    X86_P1b, // P1a + AES-NI + PCLMUL (baseline ~2010)
    X86_P1f, // P1b + AVX (float upgrade)
    X86_P2a, // P1b + AVX2 (integer wide)
    X86_P2b, // P2a + BMI2 + LZCNT
    X86_P3a, // AVX-512F baseline
    X86_P3b, // P3a + VAES + VPCLMULQDQ
    X86_P3c, // P3b + VBMI2
    X86_P3d, // P3c + VPOPCNTDQ
    X86_P3e, // P3d + GFNI
    X86_P4a, // AVX10.1 (256-bit) baseline (no 512-bit vectors exposed)
    X86_P4b, // AVX10.1 (512-bit) baseline (full-width vectors & legacy AVX-512 reuse)

    // ARM Profiles
    ARM_A0,  // NEON baseline
    ARM_A1a, // NEON + CRC32
    ARM_A1b, // A1a + AES
    ARM_A1c, // A1b + PMULL (GCM fast)
    ARM_A1d, // A1c + SHA
    ARM_A2,  // SVE2 + optional crypto

    // Apple Silicon
    Apple_M, // NEON + Crypto + AMX

    // RISC-V
    RVV,

    // Fallback
    Scalar, // No SIMD
}

/// Ultra-comprehensive CPU feature enum for runtime detection and dispatch
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum CpuFeature {
    // x86_64 Basic Features
    SSE2,
    SSE3,
    SSSE3,
    SSE41,
    SSE42,
    AVX,
    AVX2,
    AVX512F,
    AVX512BW,
    AVX512VL,
    BMI1,
    BMI2,
    AESNI,
    PCLMULQDQ,
    RDRAND,
    RDSEED,
    SHA,

    // x86_64 Ultra Features
    VAES,
    VPCLMULQDQ,
    GFNI,
    AVX512VBMI,
    AVX512VBMI2,
    AVX512VNNI,
    AVX512BF16,
    AVX512FP16,
    AVX512CD,
    AVX512DQ,
    AVX512VPOPCNTDQ,
    AVX10_1_256,
    AVX10_1_512,
    AVXVNNI,
    AMX_TILE,
    AMX_INT8,
    AMX_BF16,

    // ARM64 Basic Features
    NEON,
    CRC32,
    ATOMICS,
    FP16,
    DOTPROD,

    // ARM64 Crypto Features
    AES,
    PMULL,
    SHA1,
    SHA2,
    SHA3,
    SHA256,
    SHA512,
    SM3,
    SM4,
    NEON_CRYPTO,

    // ARM64 SVE Features
    SVE,
    SVE2,
    SVE_AES,
    SVE_PMULL,
    SVE_BITPERM,

    // Apple Silicon Features
    APPLE_AMX,
    APPLE_M1,
    APPLE_M2,
    APPLE_M3,

    // RISC-V Features
    RVV,
    RVV_ZVBB,
    RVV_ZVBC,
    RVV_ZVKG,

    // Generic Features
    POPCNT,
    LZCNT,
    FMA3,
}

/// CPU feature detector with ULTRA-SOPHISTICATED detection!
pub struct FeatureDetector {
    features: HashSet<CpuFeature>,
    features_full: CpuFeatures,
    cache_line_size: usize,
    #[allow(dead_code)]
    has_crypto: bool,
    has_avx512: bool,
    #[allow(dead_code)]
    has_sve: bool,
    optimal_simd_width: usize,
}

static DETECTOR: std::sync::OnceLock<FeatureDetector> = std::sync::OnceLock::new();

#[cfg(any(test, feature = "rust-tests"))]
static PROFILE_OVERRIDE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[cfg(any(test, feature = "rust-tests"))]
static PROFILE_OVERRIDE_ENV: std::sync::OnceLock<Option<CpuProfile>> = std::sync::OnceLock::new();

impl FeatureDetector {
    /// Returns a static reference to the `FeatureDetector` singleton.
    /// The first call will initialize the detector.
    pub fn instance() -> &'static Self {
        DETECTOR.get_or_init(|| {
            let detector = Self::detect();

            // Log detected features for telemetry
            log::info!("CPU Features detected:");
            #[cfg(target_arch = "x86_64")]
            {
                if detector.features_full.avx512f && detector.features_full.vaes {
                    log::info!("  AVX-512 + VAES: high-throughput crypto capable");
                } else if detector.features_full.avx2 && detector.features_full.aesni {
                    log::info!("  AVX2 + AES-NI: high-throughput crypto capable");
                } else if detector.features_full.aesni {
                    log::info!("  AES-NI: accelerated crypto capable");
                }

                if detector.features_full.gfni {
                    log::info!("  GFNI: accelerated Galois field operations available");
                }

                if detector.features_full.avx512vbmi2 {
                    log::info!("  AVX-512 VBMI2: accelerated pattern matching available");
                }
            }

            #[cfg(target_arch = "aarch64")]
            {
                if detector.features_full.sve2 {
                    log::info!("  ARM SVE2: accelerated SIMD available");
                } else if detector.features_full.neon && detector.features_full.aes {
                    log::info!("  NEON + AES: accelerated crypto capable");
                }

                #[cfg(target_os = "macos")]
                if detector.features_full.apple_amx {
                    log::info!("  Apple AMX: matrix acceleration available");
                }
            }

            log::info!("  Optimal SIMD width: {} bytes", detector.optimal_simd_width);
            log::info!("  Cache line: {} bytes", detector.cache_line_size);

            detector
        })
    }

    /// Detect ALL CPU features - ULTRA COMPLETE!
    fn detect() -> Self {
        let mut features = HashSet::new();
        let mut features_full = CpuFeatures::default();
        #[cfg(target_arch = "aarch64")]
        let cache_line_size: usize = 128;
        #[cfg(not(target_arch = "aarch64"))]
        let cache_line_size: usize = 64;
        let mut optimal_simd_width = 16;

        #[cfg(target_arch = "x86_64")]
        {
            // ULTRA COMPLETE x86_64 detection
            // Include SSE2 explicitly for MORUS SIMD gating
            if is_x86_feature_detected!("sse2") {
                features.insert(CpuFeature::SSE2);
                features_full.sse2 = true;
            }
            if is_x86_feature_detected!("sse3") {
                features.insert(CpuFeature::SSE3);
                features_full.sse3 = true;
            }
            if is_x86_feature_detected!("ssse3") {
                features.insert(CpuFeature::SSSE3);
                features_full.ssse3 = true;
            }
            if is_x86_feature_detected!("sse4.1") {
                features.insert(CpuFeature::SSE41);
                features_full.sse41 = true;
            }
            if is_x86_feature_detected!("sse4.2") {
                features.insert(CpuFeature::SSE42);
                features_full.sse42 = true;
            }
            if is_x86_feature_detected!("avx") {
                features.insert(CpuFeature::AVX);
                features_full.avx = true;
            }
            if is_x86_feature_detected!("avx2") {
                features.insert(CpuFeature::AVX2);
                features_full.avx2 = true;
                optimal_simd_width = 32;
            }
            if is_x86_feature_detected!("avx512f") {
                features.insert(CpuFeature::AVX512F);
                features_full.avx512f = true;
                optimal_simd_width = 64;
            }
            if is_x86_feature_detected!("avx512bw") {
                features.insert(CpuFeature::AVX512BW);
                features_full.avx512bw = true;
            }
            if is_x86_feature_detected!("avx512vl") {
                features.insert(CpuFeature::AVX512VL);
                features_full.avx512vl = true;
            }
            if is_x86_feature_detected!("avx512vbmi") {
                features.insert(CpuFeature::AVX512VBMI);
                features_full.avx512vbmi = true;
            }
            if is_x86_feature_detected!("avx512vbmi2") {
                features.insert(CpuFeature::AVX512VBMI2);
                features_full.avx512vbmi2 = true;
            }
            if is_x86_feature_detected!("bmi1") {
                features.insert(CpuFeature::BMI1);
                features_full.bmi1 = true;
            }
            if is_x86_feature_detected!("bmi2") {
                features.insert(CpuFeature::BMI2);
                features_full.bmi2 = true;
            }
            if is_x86_feature_detected!("aes") {
                features.insert(CpuFeature::AESNI);
                features_full.aesni = true;
            }
            if is_x86_feature_detected!("pclmulqdq") {
                features.insert(CpuFeature::PCLMULQDQ);
                features_full.vpclmulqdq = is_x86_feature_detected!("vpclmulqdq");
            }
            if is_x86_feature_detected!("sha") {
                features.insert(CpuFeature::SHA);
                features_full.sha = true;
            }
            if is_x86_feature_detected!("popcnt") {
                features.insert(CpuFeature::POPCNT);
                features_full.popcnt = true;
            }
            if is_x86_feature_detected!("lzcnt") {
                features.insert(CpuFeature::LZCNT);
                features_full.lzcnt = true;
            }
            if is_x86_feature_detected!("rdrand") {
                features.insert(CpuFeature::RDRAND);
                features_full.rdrand = true;
            }
            if is_x86_feature_detected!("rdseed") {
                features.insert(CpuFeature::RDSEED);
                features_full.rdseed = true;
            }

            // ULTRA features
            // ULTRA features (runtime detection only; no cfg gates)
            if is_x86_feature_detected!("vaes") {
                features.insert(CpuFeature::VAES);
                features_full.vaes = true;
            }
            if is_x86_feature_detected!("gfni") {
                features.insert(CpuFeature::GFNI);
                features_full.gfni = true;
            }
            if is_x86_feature_detected!("vpclmulqdq") {
                features.insert(CpuFeature::VPCLMULQDQ);
                features_full.vpclmulqdq = true;
            }

            // Advanced AVX-512 features - NO COMPILE-TIME GATES!
            if is_x86_feature_detected!("avx512cd") {
                features.insert(CpuFeature::AVX512CD);
                features_full.avx512cd = true;
            }
            if is_x86_feature_detected!("avx512dq") {
                features.insert(CpuFeature::AVX512DQ);
                features_full.avx512dq = true;
            }
            if is_x86_feature_detected!("avx512vnni") {
                features.insert(CpuFeature::AVX512VNNI);
                features_full.avx512vnni = true;
            }
            if is_x86_feature_detected!("avx512vpopcntdq") {
                features.insert(CpuFeature::AVX512VPOPCNTDQ);
                features_full.avx512vpopcntdq = true;
            }

            // AVX10 detection (1.1 preview flags exposed by rustc 1.86)
            #[cfg(feature = "avx10_preview")]
            {
                let has_avx10_512 = is_x86_feature_detected!("avx10.1-512");
                if has_avx10_512 {
                    features.insert(CpuFeature::AVX10_1_512);
                    features_full.avx10_1_512 = true;
                    features_full.avx512f = true;
                    optimal_simd_width = optimal_simd_width.max(64);
                }
                let has_avx10_256 = has_avx10_512 || is_x86_feature_detected!("avx10.1-256");
                if has_avx10_256 {
                    features.insert(CpuFeature::AVX10_1_256);
                    features_full.avx10_1_256 = true;
                    features_full.avx2 = true;
                    optimal_simd_width = optimal_simd_width.max(32);
                }
            }

            // Next-Gen x86_64 Extensions - ULTRA MODERN!
            if is_x86_feature_detected!("avx512bf16") {
                features.insert(CpuFeature::AVX512BF16);
                features_full.avx512bf16 = true;
            }
            if is_x86_feature_detected!("avx512fp16") {
                features.insert(CpuFeature::AVX512FP16);
                features_full.avx512fp16 = true;
            }
            if is_x86_feature_detected!("avxvnni") {
                features.insert(CpuFeature::AVXVNNI);
                features_full.avx_vnni = true;
            }

            // AMX Tile Extensions - Intel 4th Gen Xeon and beyond!
            // Note: AMX detection requires special OS support and may not be available via is_x86_feature_detected!
            // For now, we detect based on CPU model and OS support
            if let Ok(cpuid) = std::process::Command::new("cpuid").output() {
                let output = String::from_utf8_lossy(&cpuid.stdout);
                if output.contains("AMX-TILE") || output.contains("amx_tile") {
                    features.insert(CpuFeature::AMX_TILE);
                    features_full.amx_tile = true;
                }
                if output.contains("AMX-INT8") || output.contains("amx_int8") {
                    features.insert(CpuFeature::AMX_INT8);
                    features_full.amx_int8 = true;
                }
                if output.contains("AMX-BF16") || output.contains("amx_bf16") {
                    features.insert(CpuFeature::AMX_BF16);
                    features_full.amx_bf16 = true;
                }
            }

            if is_x86_feature_detected!("fma") {
                features_full.fma3 = true;
            }

            features_full.cache_line = 64;
            features_full.l1d_cache = 32 * 1024;
            features_full.l1i_cache = 32 * 1024;
            features_full.l2_cache = 256 * 1024;
            features_full.l3_cache = 8 * 1024 * 1024;
        }

        #[cfg(target_arch = "aarch64")]
        {
            // NEON is mandatory on AArch64
            features.insert(CpuFeature::NEON);
            features_full.neon = true;

            // Platform-specific detection
            #[cfg(target_os = "macos")]
            {
                // All Apple Silicon has comprehensive crypto and SIMD extensions
                features.insert(CpuFeature::AES);
                features.insert(CpuFeature::PMULL);
                features.insert(CpuFeature::NEON_CRYPTO);
                features.insert(CpuFeature::CRC32);
                features.insert(CpuFeature::SHA1);
                features.insert(CpuFeature::SHA2);
                features.insert(CpuFeature::SHA256);
                features.insert(CpuFeature::ATOMICS);
                features.insert(CpuFeature::FP16);
                features.insert(CpuFeature::DOTPROD);
                features.insert(CpuFeature::APPLE_AMX);

                features_full.aes = true;
                features_full.pmull = true;
                features_full.sha1 = true;
                features_full.sha2 = true;
                features_full.sha2 = true;
                features_full.crc32 = true;
                features_full.atomics = true;
                features_full.fp16 = true;
                features_full.dotprod = true;
                features_full.apple_amx = true;

                // Detect specific Apple Silicon generation
                use std::process::Command;
                if let Ok(output) =
                    Command::new("sysctl").arg("-n").arg("machdep.cpu.brand_string").output()
                {
                    let brand = String::from_utf8_lossy(&output.stdout);
                    if brand.contains("M1") {
                        features_full.apple_m1 = true;
                    } else if brand.contains("M2") {
                        features_full.apple_m2 = true;
                        features_full.apple_amx = true;
                    } else if brand.contains("M3") {
                        features_full.apple_m3 = true;
                        features_full.apple_amx = true;
                        optimal_simd_width = 32; // M3 has wider SIMD
                    }
                }

                features_full.cache_line = 128;
                features_full.l1d_cache = 128 * 1024;
                features_full.l1i_cache = 192 * 1024;
                features_full.l2_cache = 4 * 1024 * 1024;
            }

            #[cfg(target_os = "linux")]
            {
                use std::fs;
                if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
                    // Crypto extensions
                    if cpuinfo.contains("aes") {
                        features.insert(CpuFeature::AES);
                        features_full.aes = true;
                    }
                    if cpuinfo.contains("pmull") {
                        features.insert(CpuFeature::PMULL);
                        features.insert(CpuFeature::NEON_CRYPTO);
                        features_full.pmull = true;
                    }

                    // SHA extensions
                    if cpuinfo.contains("sha1") {
                        features.insert(CpuFeature::SHA1);
                        features_full.sha1 = true;
                    }
                    if cpuinfo.contains("sha2") {
                        features.insert(CpuFeature::SHA2);
                        features_full.sha2 = true;
                    }
                    if cpuinfo.contains("sha256") {
                        features.insert(CpuFeature::SHA256);
                        features_full.sha2 = true;
                    }
                    if cpuinfo.contains("sha3") {
                        features.insert(CpuFeature::SHA3);
                        features_full.sha3 = true;
                    }
                    if cpuinfo.contains("sha512") {
                        features.insert(CpuFeature::SHA512);
                        features_full.sha512 = true;
                    }
                    if cpuinfo.contains("sm3") {
                        features.insert(CpuFeature::SM3);
                        features_full.sm3 = true;
                    }
                    if cpuinfo.contains("sm4") {
                        features.insert(CpuFeature::SM4);
                        features_full.sm4 = true;
                    }

                    // Other extensions
                    if cpuinfo.contains("crc32") {
                        features.insert(CpuFeature::CRC32);
                        features_full.crc32 = true;
                    }
                    if cpuinfo.contains("atomics") {
                        features.insert(CpuFeature::ATOMICS);
                        features_full.atomics = true;
                    }
                    if cpuinfo.contains("fp16") {
                        features.insert(CpuFeature::FP16);
                        features_full.fp16 = true;
                    }
                    if cpuinfo.contains("dotprod") {
                        features.insert(CpuFeature::DOTPROD);
                        features_full.dotprod = true;
                    }
                    if cpuinfo.contains("sve") && !cpuinfo.contains("sve2") {
                        features.insert(CpuFeature::SVE);
                        features_full.sve = true;
                        optimal_simd_width = 64; // SVE can be up to 2048 bits
                    }
                    if cpuinfo.contains("sve2") {
                        features.insert(CpuFeature::SVE);
                        features.insert(CpuFeature::SVE2);
                        features_full.sve = true;
                        features_full.sve2 = true;
                        optimal_simd_width = 64;
                    }
                    // SVE2 crypto extensions - with HashSet.
                    if cpuinfo.contains("sveaes") || cpuinfo.contains("sve2-aes") {
                        features_full.sve_aes = true;
                        features.insert(CpuFeature::SVE_AES);
                    }
                    if cpuinfo.contains("svepmull") || cpuinfo.contains("sve2-pmull") {
                        features_full.sve_pmull = true;
                        features.insert(CpuFeature::SVE_PMULL);
                    }
                    if cpuinfo.contains("svebitperm") || cpuinfo.contains("sve2-bitperm") {
                        features_full.sve_bitperm = true;
                        features.insert(CpuFeature::SVE_BITPERM);
                    }
                }
            }
        }

        #[cfg(target_arch = "riscv64")]
        {
            use std::arch::is_riscv_feature_detected;

            if is_riscv_feature_detected!("v") {
                features_full.rvv = true;
                features.insert(CpuFeature::RVV);
                optimal_simd_width = optimal_simd_width.max(64);
            }
            if is_riscv_feature_detected!("zvbb") {
                features_full.rvv_zvbb = true;
                features.insert(CpuFeature::RVV_ZVBB);
            }
            if is_riscv_feature_detected!("zvbc") {
                features_full.rvv_zvbc = true;
                features.insert(CpuFeature::RVV_ZVBC);
            }
            if is_riscv_feature_detected!("zvkg") {
                features_full.rvv_zvkg = true;
                features.insert(CpuFeature::RVV_ZVKG);
            }
        }

        // Determine capabilities
        let has_crypto = features.contains(&CpuFeature::AESNI)
            || features.contains(&CpuFeature::AES)
            || features.contains(&CpuFeature::VAES);

        let has_avx512 =
            features.contains(&CpuFeature::AVX512F) || features.contains(&CpuFeature::AVX10_1_512);
        let has_sve = features.contains(&CpuFeature::SVE);

        Self {
            features,
            features_full,
            cache_line_size,
            has_crypto,
            has_avx512,
            has_sve,
            optimal_simd_width,
        }
    }

    /// Get full CPU features struct
    pub fn features_full(&self) -> &CpuFeatures {
        &self.features_full
    }

    /// Get optimal SIMD width in bytes
    pub fn optimal_simd_width(&self) -> usize {
        self.optimal_simd_width
    }

    /// Determine CPU profile from detected features
    pub fn profile(&self) -> CpuProfile {
        #[cfg(any(test, feature = "rust-tests"))]
        if let Some(override_profile) = self.profile_override() {
            return override_profile;
        }

        #[cfg(target_arch = "x86_64")]
        {
            if self.has_feature(CpuFeature::AVX10_1_512) {
                return CpuProfile::X86_P4b;
            }
            if self.has_feature(CpuFeature::AVX10_1_256) {
                return CpuProfile::X86_P4a;
            }

            // Check from highest to lowest capability
            if self.has_feature(CpuFeature::AVX512F) {
                if self.has_feature(CpuFeature::GFNI) {
                    return CpuProfile::X86_P3e;
                }
                if self.has_feature(CpuFeature::AVX512VPOPCNTDQ) {
                    return CpuProfile::X86_P3d;
                }
                if self.has_feature(CpuFeature::AVX512VBMI2) {
                    return CpuProfile::X86_P3c;
                }
                if self.has_feature(CpuFeature::VAES) && self.has_feature(CpuFeature::VPCLMULQDQ) {
                    return CpuProfile::X86_P3b;
                }
                return CpuProfile::X86_P3a;
            }

            if self.has_feature(CpuFeature::AVX2) {
                if self.has_feature(CpuFeature::BMI2) {
                    return CpuProfile::X86_P2b;
                }
                return CpuProfile::X86_P2a;
            }

            if self.has_feature(CpuFeature::AVX) {
                return CpuProfile::X86_P1f;
            }

            if self.has_feature(CpuFeature::AESNI) && self.has_feature(CpuFeature::PCLMULQDQ) {
                return CpuProfile::X86_P1b;
            }

            if self.has_feature(CpuFeature::SSE42) {
                return CpuProfile::X86_P1a;
            }

            // Legacy fallbacks
            if self.has_feature(CpuFeature::SSSE3) {
                return CpuProfile::X86_P0b;
            }
            if self.has_feature(CpuFeature::SSE2) {
                return CpuProfile::X86_P0a;
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            #[cfg(target_os = "macos")]
            if self.has_feature(CpuFeature::APPLE_AMX) {
                return CpuProfile::Apple_M;
            }

            if self.has_feature(CpuFeature::SVE2) {
                return CpuProfile::ARM_A2;
            }

            if self.has_feature(CpuFeature::NEON) {
                if self.has_feature(CpuFeature::SHA256) || self.has_feature(CpuFeature::SHA512) {
                    return CpuProfile::ARM_A1d;
                }
                if self.has_feature(CpuFeature::PMULL) {
                    return CpuProfile::ARM_A1c;
                }
                if self.has_feature(CpuFeature::AES) {
                    return CpuProfile::ARM_A1b;
                }
                if self.has_feature(CpuFeature::CRC32) {
                    return CpuProfile::ARM_A1a;
                }
                return CpuProfile::ARM_A0;
            }
        }

        #[cfg(target_arch = "riscv64")]
        {
            if self.has_feature(CpuFeature::RVV) {
                return CpuProfile::RVV;
            }
        }

        CpuProfile::Scalar
    }

    #[cfg(any(test, feature = "rust-tests"))]
    fn profile_override(&self) -> Option<CpuProfile> {
        let requested = match PROFILE_OVERRIDE.load(std::sync::atomic::Ordering::Relaxed) {
            0 => *PROFILE_OVERRIDE_ENV.get_or_init(parse_profile_override_env),
            value => profile_override_from_u64(value),
        };

        let profile = requested?;

        if profile == CpuProfile::Scalar {
            return Some(profile);
        }

        if self.profile_override_supported(profile) {
            return Some(profile);
        }

        log::warn!("Profile override {:?} rejected due to missing CPU features", profile);
        None
    }

    #[cfg(any(test, feature = "rust-tests"))]
    fn profile_override_supported(&self, profile: CpuProfile) -> bool {
        match profile {
            CpuProfile::Scalar => true,
            CpuProfile::X86_P0a => self.has_feature(CpuFeature::SSE2),
            CpuProfile::X86_P0b => self.has_feature(CpuFeature::SSSE3),
            CpuProfile::X86_P1a => self.has_feature(CpuFeature::SSE42),
            CpuProfile::X86_P1b => {
                self.has_feature(CpuFeature::AESNI) && self.has_feature(CpuFeature::PCLMULQDQ)
            }
            CpuProfile::X86_P1f => self.has_feature(CpuFeature::AVX),
            CpuProfile::X86_P2a => self.has_feature(CpuFeature::AVX2),
            CpuProfile::X86_P2b => {
                self.has_feature(CpuFeature::AVX2) && self.has_feature(CpuFeature::BMI2)
            }
            CpuProfile::X86_P3a => self.has_feature(CpuFeature::AVX512F),
            CpuProfile::X86_P3b => {
                self.has_feature(CpuFeature::AVX512F)
                    && self.has_feature(CpuFeature::VAES)
                    && self.has_feature(CpuFeature::VPCLMULQDQ)
            }
            CpuProfile::X86_P3c => {
                self.has_feature(CpuFeature::AVX512F) && self.has_feature(CpuFeature::AVX512VBMI2)
            }
            CpuProfile::X86_P3d => {
                self.has_feature(CpuFeature::AVX512F)
                    && self.has_feature(CpuFeature::AVX512VPOPCNTDQ)
            }
            CpuProfile::X86_P3e => {
                self.has_feature(CpuFeature::AVX512F) && self.has_feature(CpuFeature::GFNI)
            }
            CpuProfile::X86_P4a => self.has_feature(CpuFeature::AVX10_1_256),
            CpuProfile::X86_P4b => self.has_feature(CpuFeature::AVX10_1_512),
            CpuProfile::ARM_A0 => self.has_feature(CpuFeature::NEON),
            CpuProfile::ARM_A1a => {
                self.has_feature(CpuFeature::NEON) && self.has_feature(CpuFeature::CRC32)
            }
            CpuProfile::ARM_A1b => self.has_feature(CpuFeature::AES),
            CpuProfile::ARM_A1c => {
                self.has_feature(CpuFeature::AES) && self.has_feature(CpuFeature::PMULL)
            }
            CpuProfile::ARM_A1d => {
                self.has_feature(CpuFeature::AES)
                    && self.has_feature(CpuFeature::PMULL)
                    && (self.has_feature(CpuFeature::SHA1) || self.has_feature(CpuFeature::SHA2))
            }
            CpuProfile::ARM_A2 => self.has_feature(CpuFeature::SVE2),
            CpuProfile::Apple_M => self.has_feature(CpuFeature::APPLE_AMX),
            CpuProfile::RVV => self.has_feature(CpuFeature::RVV),
        }
    }

    /// Get cache line size
    pub fn cache_line_size(&self) -> usize {
        self.cache_line_size
    }

    /// Check if AVX-512 is available
    pub fn has_avx512(&self) -> bool {
        self.has_avx512
    }

    /// Check if AVX2 is available  
    pub fn has_avx2(&self) -> bool {
        self.features_full.avx2
            || self.features.contains(&CpuFeature::AVX10_1_256)
            || self.features.contains(&CpuFeature::AVX10_1_512)
    }

    /// Checks if a specific CPU feature is supported.
    pub fn has_feature(&self, feature: CpuFeature) -> bool {
        match feature {
            CpuFeature::AVX512F => {
                self.features.contains(&CpuFeature::AVX512F)
                    || self.features.contains(&CpuFeature::AVX10_1_512)
            }
            CpuFeature::AVX2 => {
                self.features.contains(&CpuFeature::AVX2)
                    || self.features.contains(&CpuFeature::AVX10_1_256)
                    || self.features.contains(&CpuFeature::AVX10_1_512)
            }
            _ => self.features.contains(&feature),
        }
    }

    /// Checks if any of the provided features is supported.
    pub fn has_any(&self, feats: &[CpuFeature]) -> bool {
        feats.iter().any(|f| self.has_feature(*f))
    }
}

#[cfg(any(test, feature = "rust-tests"))]
fn parse_profile_override_env() -> Option<CpuProfile> {
    let raw = std::env::var("QUICFUSCATE_PROFILE_OVERRIDE").ok()?;
    parse_profile_override(&raw)
}

#[cfg(any(test, feature = "rust-tests"))]
fn parse_profile_override(value: &str) -> Option<CpuProfile> {
    let key = value.trim().to_lowercase().replace('-', "_");
    if key.is_empty() || key == "auto" || key == "detected" {
        return None;
    }
    match key.as_str() {
        "scalar" => Some(CpuProfile::Scalar),
        "x86_p0a" | "sse2" => Some(CpuProfile::X86_P0a),
        "x86_p0b" | "ssse3" => Some(CpuProfile::X86_P0b),
        "x86_p1a" | "sse4_2" | "sse42" => Some(CpuProfile::X86_P1a),
        "x86_p1b" | "aesni" => Some(CpuProfile::X86_P1b),
        "x86_p1f" | "avx" => Some(CpuProfile::X86_P1f),
        "x86_p2a" | "avx2" => Some(CpuProfile::X86_P2a),
        "x86_p2b" | "bmi2" => Some(CpuProfile::X86_P2b),
        "x86_p3a" | "avx512" => Some(CpuProfile::X86_P3a),
        "x86_p3b" => Some(CpuProfile::X86_P3b),
        "x86_p3c" => Some(CpuProfile::X86_P3c),
        "x86_p3d" => Some(CpuProfile::X86_P3d),
        "x86_p3e" => Some(CpuProfile::X86_P3e),
        "x86_p4a" | "avx10_256" => Some(CpuProfile::X86_P4a),
        "x86_p4b" | "avx10_512" => Some(CpuProfile::X86_P4b),
        "arm_a0" | "neon" => Some(CpuProfile::ARM_A0),
        "arm_a1a" => Some(CpuProfile::ARM_A1a),
        "arm_a1b" => Some(CpuProfile::ARM_A1b),
        "arm_a1c" => Some(CpuProfile::ARM_A1c),
        "arm_a1d" => Some(CpuProfile::ARM_A1d),
        "arm_a2" | "sve2" => Some(CpuProfile::ARM_A2),
        "apple_m" | "apple" => Some(CpuProfile::Apple_M),
        "rvv" => Some(CpuProfile::RVV),
        _ => None,
    }
}

#[cfg(any(test, feature = "rust-tests"))]
fn profile_override_from_u64(value: u64) -> Option<CpuProfile> {
    match value {
        1 => Some(CpuProfile::Scalar),
        2 => Some(CpuProfile::X86_P0a),
        3 => Some(CpuProfile::X86_P0b),
        4 => Some(CpuProfile::X86_P1a),
        5 => Some(CpuProfile::X86_P1b),
        6 => Some(CpuProfile::X86_P1f),
        7 => Some(CpuProfile::X86_P2a),
        8 => Some(CpuProfile::X86_P2b),
        9 => Some(CpuProfile::X86_P3a),
        10 => Some(CpuProfile::X86_P3b),
        11 => Some(CpuProfile::X86_P3c),
        12 => Some(CpuProfile::X86_P3d),
        13 => Some(CpuProfile::X86_P3e),
        14 => Some(CpuProfile::X86_P4a),
        15 => Some(CpuProfile::X86_P4b),
        16 => Some(CpuProfile::ARM_A0),
        17 => Some(CpuProfile::ARM_A1a),
        18 => Some(CpuProfile::ARM_A1b),
        19 => Some(CpuProfile::ARM_A1c),
        20 => Some(CpuProfile::ARM_A1d),
        21 => Some(CpuProfile::ARM_A2),
        22 => Some(CpuProfile::Apple_M),
        23 => Some(CpuProfile::RVV),
        _ => None,
    }
}

#[cfg(any(test, feature = "rust-tests"))]
fn profile_override_to_u64(profile: CpuProfile) -> u64 {
    match profile {
        CpuProfile::Scalar => 1,
        CpuProfile::X86_P0a => 2,
        CpuProfile::X86_P0b => 3,
        CpuProfile::X86_P1a => 4,
        CpuProfile::X86_P1b => 5,
        CpuProfile::X86_P1f => 6,
        CpuProfile::X86_P2a => 7,
        CpuProfile::X86_P2b => 8,
        CpuProfile::X86_P3a => 9,
        CpuProfile::X86_P3b => 10,
        CpuProfile::X86_P3c => 11,
        CpuProfile::X86_P3d => 12,
        CpuProfile::X86_P3e => 13,
        CpuProfile::X86_P4a => 14,
        CpuProfile::X86_P4b => 15,
        CpuProfile::ARM_A0 => 16,
        CpuProfile::ARM_A1a => 17,
        CpuProfile::ARM_A1b => 18,
        CpuProfile::ARM_A1c => 19,
        CpuProfile::ARM_A1d => 20,
        CpuProfile::ARM_A2 => 21,
        CpuProfile::Apple_M => 22,
        CpuProfile::RVV => 23,
    }
}

#[cfg(any(test, feature = "rust-tests"))]
pub fn set_profile_override_for_tests(profile: CpuProfile) -> bool {
    let detector = FeatureDetector::instance();
    if profile != CpuProfile::Scalar && !detector.profile_override_supported(profile) {
        return false;
    }
    PROFILE_OVERRIDE.store(profile_override_to_u64(profile), std::sync::atomic::Ordering::Relaxed);
    true
}

#[cfg(any(test, feature = "rust-tests"))]
pub fn clear_profile_override_for_tests() {
    PROFILE_OVERRIDE.store(0, std::sync::atomic::Ordering::Relaxed);
}

// ============================================================================
// CENTRAL SIMD SYSTEM
// ============================================================================

/// 3-Level Cache Hierarchy for optimal performance - ZENTRALE DEFINITION
pub struct CacheLevel {
    pub size: usize,
    pub line_size: usize,
    pub ways: usize,
    pub latency_cycles: usize,
}

pub struct CacheHierarchy {
    pub l1_data: CacheLevel,
    pub l1_inst: CacheLevel,
    pub l2_unified: CacheLevel,
    pub l3_shared: CacheLevel,
    pub prefetch_distance: usize,
    pub blocking_factor: usize,
}

impl CacheHierarchy {
    /// Detect cache hierarchy at runtime
    pub fn detect() -> Self {
        let features = FeatureDetector::instance().features_full();

        // Intel/AMD x86_64 typical
        #[cfg(target_arch = "x86_64")]
        if features.avx512f {
            return Self {
                l1_data: CacheLevel { size: 32768, line_size: 64, ways: 8, latency_cycles: 4 },
                l1_inst: CacheLevel { size: 32768, line_size: 64, ways: 8, latency_cycles: 4 },
                l2_unified: CacheLevel {
                    size: 1048576,
                    line_size: 64,
                    ways: 16,
                    latency_cycles: 12,
                },
                l3_shared: CacheLevel {
                    size: 16777216,
                    line_size: 64,
                    ways: 16,
                    latency_cycles: 40,
                },
                prefetch_distance: 512, // Prefetch 8 cache lines ahead
                blocking_factor: 256,   // Tile size for cache blocking
            };
        }

        // Apple Silicon M-series
        #[cfg(target_arch = "aarch64")]
        if features.apple_m1 || features.apple_m2 || features.apple_m3 {
            return Self {
                l1_data: CacheLevel { size: 131072, line_size: 128, ways: 8, latency_cycles: 3 },
                l1_inst: CacheLevel { size: 196608, line_size: 128, ways: 6, latency_cycles: 3 },
                l2_unified: CacheLevel {
                    size: 4194304,
                    line_size: 128,
                    ways: 12,
                    latency_cycles: 15,
                },
                l3_shared: CacheLevel {
                    size: 16777216,
                    line_size: 128,
                    ways: 16,
                    latency_cycles: 50,
                },
                prefetch_distance: 1024, // More aggressive prefetch
                blocking_factor: 512,    // Larger tiles for bigger caches
            };
        }

        // Default conservative
        Self {
            l1_data: CacheLevel { size: 32768, line_size: 64, ways: 4, latency_cycles: 4 },
            l1_inst: CacheLevel { size: 32768, line_size: 64, ways: 4, latency_cycles: 4 },
            l2_unified: CacheLevel { size: 262144, line_size: 64, ways: 8, latency_cycles: 12 },
            l3_shared: CacheLevel { size: 4194304, line_size: 64, ways: 16, latency_cycles: 40 },
            prefetch_distance: 256,
            blocking_factor: 128,
        }
    }

    /// Calculate optimal tile size for matrix operations
    pub fn optimal_tile_size(&self, element_size: usize) -> usize {
        // Use 1/2 of L1 cache for working set
        let working_set = self.l1_data.size / 2;
        let elements = working_set / element_size;
        // Square root for square tiles
        (elements as f64).sqrt() as usize
    }
}

// ============================================================================
// SIMD DISPATCH - DUPLICATE MODULE REMOVED!
// ============================================================================

/// SIMD operations dispatcher - selects optimal implementation at runtime
pub struct SimdDispatch;

impl SimdDispatch {
    /// XOR blocks with optimal SIMD - up to 64 bytes at once!
    #[inline(always)]
    pub fn xor_blocks(dst: &mut [u8], src: &[u8]) {
        let features = FeatureDetector::instance().features_full();

        #[cfg(target_arch = "x86_64")]
        unsafe {
            if features.avx512f {
                telemetry::AVX512_OPS.inc();
                return Self::xor_blocks_avx512(dst, src);
            }
            if features.avx2 {
                telemetry::AVX2_OPS.inc();
                return Self::xor_blocks_avx2(dst, src);
            }
            // SSE2 removed - fallback to scalar
            // Baseline is SSE4.2 but we only have AVX2/AVX512 SIMD implementations
        }

        #[cfg(target_arch = "aarch64")]
        unsafe {
            if features.sve2 {
                telemetry::SVE2_OPS.inc();
                return Self::xor_blocks_sve2(dst, src);
            }
            if features.neon {
                telemetry::NEON_OPS.inc();
                return Self::xor_blocks_neon(dst, src);
            }
        }

        telemetry::SCALAR_OPS.inc();
        Self::xor_blocks_scalar(dst, src);
    }

    /// Ultra-fast memcpy with SIMD
    #[inline(always)]
    pub fn memcpy_fast(dst: &mut [u8], src: &[u8]) {
        let len = dst.len().min(src.len());

        #[cfg(target_arch = "x86_64")]
        unsafe {
            let features = FeatureDetector::instance().features_full();
            if features.avx512f && len >= 64 {
                return Self::memcpy_avx512(dst, src, len);
            }
            if features.avx2 && len >= 32 {
                return Self::memcpy_avx2(dst, src, len);
            }
        }

        dst[..len].copy_from_slice(&src[..len]);
    }

    /// Prefetch data into cache
    #[cfg_attr(feature = "aggressive_inline", inline(always))]
    pub fn prefetch_read(data: &[u8]) {
        if !data.is_empty() {
            unsafe {
                prefetch(data.as_ptr(), PrefetchHint::T0);
            }
        }
    }

    /// Population count with optimal instruction
    #[inline(always)]
    pub fn popcnt(data: &[u8]) -> usize {
        let mut count = 0;

        #[cfg(target_arch = "x86_64")]
        {
            let features = FeatureDetector::instance().features_full();
            if features.popcnt {
                for chunk in data.chunks_exact(8) {
                    let val = u64::from_le_bytes(chunk.try_into().unwrap());
                    count += val.count_ones() as usize;
                }
                for &byte in data.chunks_exact(8).remainder() {
                    count += byte.count_ones() as usize;
                }
                return count;
            }
        }

        // Fallback
        for &byte in data {
            count += byte.count_ones() as usize;
        }
        count
    }

    // x86_64 implementations
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512f")]
    unsafe fn xor_blocks_avx512(dst: &mut [u8], src: &[u8]) {
        use std::arch::x86_64::*;

        let len = dst.len().min(src.len());
        let mut i = 0;

        // Process 64-byte chunks
        while i + 64 <= len {
            let a = _mm512_loadu_si512(dst[i..].as_ptr() as *const __m512i);
            let b = _mm512_loadu_si512(src[i..].as_ptr() as *const __m512i);
            let c = _mm512_xor_si512(a, b);
            _mm512_storeu_si512(dst[i..].as_mut_ptr() as *mut __m512i, c);
            i += 64;
        }

        // Process remainder with AVX2
        while i + 32 <= len {
            let a = _mm256_loadu_si256(dst[i..].as_ptr() as *const __m256i);
            let b = _mm256_loadu_si256(src[i..].as_ptr() as *const __m256i);
            let c = _mm256_xor_si256(a, b);
            _mm256_storeu_si256(dst[i..].as_mut_ptr() as *mut __m256i, c);
            i += 32;
        }

        // Process remainder scalar
        while i < len {
            dst[i] ^= src[i];
            i += 1;
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn xor_blocks_avx2(dst: &mut [u8], src: &[u8]) {
        use std::arch::x86_64::*;

        let len = dst.len().min(src.len());
        let mut i = 0;

        // Process 32-byte chunks
        while i + 32 <= len {
            let a = _mm256_loadu_si256(dst[i..].as_ptr() as *const __m256i);
            let b = _mm256_loadu_si256(src[i..].as_ptr() as *const __m256i);
            let c = _mm256_xor_si256(a, b);
            _mm256_storeu_si256(dst[i..].as_mut_ptr() as *mut __m256i, c);
            i += 32;
        }

        // Process remainder with SSE2
        while i + 16 <= len {
            let a = _mm_loadu_si128(dst[i..].as_ptr() as *const __m128i);
            let b = _mm_loadu_si128(src[i..].as_ptr() as *const __m128i);
            let c = _mm_xor_si128(a, b);
            _mm_storeu_si128(dst[i..].as_mut_ptr() as *mut __m128i, c);
            i += 16;
        }

        while i < len {
            dst[i] ^= src[i];
            i += 1;
        }
    }

    // SSE2 xor_blocks removed - baseline is SSE4.2

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx512f")]
    unsafe fn memcpy_avx512(dst: &mut [u8], src: &[u8], len: usize) {
        use std::arch::x86_64::*;

        let mut i = 0;
        while i + 64 <= len {
            let data = _mm512_loadu_si512(src[i..].as_ptr() as *const __m512i);
            _mm512_storeu_si512(dst[i..].as_mut_ptr() as *mut __m512i, data);
            i += 64;
        }

        // Copy remainder
        if i < len {
            dst[i..len].copy_from_slice(&src[i..len]);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn memcpy_avx2(dst: &mut [u8], src: &[u8], len: usize) {
        use std::arch::x86_64::*;

        let mut i = 0;
        while i + 32 <= len {
            let data = _mm256_loadu_si256(src[i..].as_ptr() as *const __m256i);
            _mm256_storeu_si256(dst[i..].as_mut_ptr() as *mut __m256i, data);
            i += 32;
        }

        if i < len {
            dst[i..len].copy_from_slice(&src[i..len]);
        }
    }

    // ARM64 implementations
    #[cfg(target_arch = "aarch64")]
    unsafe fn xor_blocks_neon(dst: &mut [u8], src: &[u8]) {
        use std::arch::aarch64::*;

        let len = dst.len().min(src.len());
        let mut i = 0;

        while i + 16 <= len {
            let a = vld1q_u8(dst[i..].as_ptr());
            let b = vld1q_u8(src[i..].as_ptr());
            let c = veorq_u8(a, b);
            vst1q_u8(dst[i..].as_mut_ptr(), c);
            i += 16;
        }

        while i < len {
            dst[i] ^= src[i];
            i += 1;
        }
    }

    #[cfg(target_arch = "aarch64")]
    unsafe fn xor_blocks_sve2(dst: &mut [u8], src: &[u8]) {
        #[cfg(target_feature = "sve2")]
        {
            use std::arch::aarch64::*;

            let len = dst.len().min(src.len());
            let mut offset = 0usize;

            while offset < len {
                let pg = svwhilelt_b8(offset as u64, len as u64);
                let dst_chunk = svld1_u8(pg, dst.as_ptr().add(offset));
                let src_chunk = svld1_u8(pg, src.as_ptr().add(offset));
                let xor_chunk = sveor_u8_z(pg, dst_chunk, src_chunk);
                svst1_u8(pg, dst.as_mut_ptr().add(offset), xor_chunk);
                offset += svcntb() as usize;
            }
            return;
        }

        Self::xor_blocks_neon(dst, src);
    }

    // Scalar fallback
    fn xor_blocks_scalar(dst: &mut [u8], src: &[u8]) {
        let len = dst.len().min(src.len());
        for i in 0..len {
            dst[i] ^= src[i];
        }
    }
}

/// Represents the execution policy for SIMD operations.
pub trait SimdPolicy: Any {
    fn as_any(&self) -> &dyn Any;
}

/// Marker struct for AVX-512 execution.
pub struct Avx512;
impl SimdPolicy for Avx512 {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Marker struct for AVX2 execution.
pub struct Avx2;
impl SimdPolicy for Avx2 {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Marker struct for SSE2 execution.
pub struct Sse2;
impl SimdPolicy for Sse2 {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// SSE2 marker removed - baseline is SSE4.2

/// Marker struct for PCLMULQDQ execution.
pub struct Pclmulqdq;
impl SimdPolicy for Pclmulqdq {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Marker struct for ARM NEON execution.
pub struct Neon;
impl SimdPolicy for Neon {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Marker struct for AVX512GFNI execution (Galois Field New Instructions).
pub struct Avx512Gfni;
impl SimdPolicy for Avx512Gfni {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Marker struct for AVX512VBMI2 execution.
pub struct Avx512Vbmi2;
impl SimdPolicy for Avx512Vbmi2 {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Marker struct for ARM SVE2 execution.
pub struct Sve2;
impl SimdPolicy for Sve2 {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Marker struct for ARM SVE execution.
pub struct Sve;
impl SimdPolicy for Sve {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Marker struct for ARM NEON Crypto execution.
pub struct NeonCrypto;
impl SimdPolicy for NeonCrypto {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Marker struct for scalar (non-SIMD) execution.
pub struct Scalar;
impl SimdPolicy for Scalar {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Dispatches to the best available SIMD implementation at runtime.
/// The policies are ordered from most to least performant.
pub fn dispatch<F, R>(f: F) -> R
where
    F: Fn(&dyn SimdPolicy) -> R,
{
    let detector = FeatureDetector::instance();
    let has_avx10_512 = detector.features.contains(&CpuFeature::AVX10_1_512);
    let has_avx10_256 = detector.features.contains(&CpuFeature::AVX10_1_256);
    let has_avx512 = has_avx10_512 || detector.features.contains(&CpuFeature::AVX512F);
    let has_avx2 = detector.features.contains(&CpuFeature::AVX2) || has_avx10_256 || has_avx10_512;

    // Priority order: GFNI > VBMI2 > VBMI > AVX2 > SSE2 > SVE2 > SVE > NEON
    if has_avx512 && detector.has_feature(CpuFeature::GFNI) {
        telemetry::SIMD_USAGE_AVX512.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if has_avx10_512 {
            telemetry::SIMD_USAGE_AVX10_512.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        f(&Avx512Gfni)
    } else if has_avx512 && detector.has_feature(CpuFeature::AVX512VBMI2) {
        telemetry::SIMD_USAGE_AVX512.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if has_avx10_512 {
            telemetry::SIMD_USAGE_AVX10_512.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        f(&Avx512Vbmi2)
    } else if has_avx512 && detector.has_feature(CpuFeature::AVX512VBMI) {
        telemetry::SIMD_USAGE_AVX512.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if has_avx10_512 {
            telemetry::SIMD_USAGE_AVX10_512.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        f(&Avx512)
    } else if has_avx2 {
        telemetry::SIMD_USAGE_AVX2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if has_avx10_512 {
            telemetry::SIMD_USAGE_AVX10_512.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else if has_avx10_256 {
            telemetry::SIMD_USAGE_AVX10_256.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        f(&Avx2)
    // SSE2 removed - fallback directly to scalar
    } else if detector.has_feature(CpuFeature::PCLMULQDQ) {
        f(&Pclmulqdq)
    } else if detector.has_feature(CpuFeature::SVE2) {
        telemetry::SIMD_USAGE_NEON.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        f(&Sve2)
    } else if detector.has_feature(CpuFeature::SVE) {
        telemetry::SIMD_USAGE_NEON.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        f(&Sve)
    } else if detector.has_feature(CpuFeature::NEON_CRYPTO) {
        telemetry::SIMD_USAGE_NEON.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        f(&NeonCrypto)
    } else if detector.has_feature(CpuFeature::NEON) {
        telemetry::SIMD_USAGE_NEON.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        f(&Neon)
    } else {
        telemetry::SIMD_USAGE_SCALAR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        f(&Scalar)
    }
}

/// Dispatches specifically for GF bitsliced operations. AVX-512/AVX2/SSE2 and
/// the ARM NEON/SVE2 families are considered; all other architectures fall back
/// to scalar code.
static FEC_KERNEL_OVERRIDE: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

#[cfg(test)]
static TEST_FEC_KERNEL_OVERRIDE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

#[cfg(test)]
pub fn __test_set_fec_kernel_override(val: Option<&str>) {
    let mut g = TEST_FEC_KERNEL_OVERRIDE.lock().unwrap();
    *g = val.map(|s| s.to_lowercase());
}

pub fn dispatch_bitslice<F, R>(mut f: F) -> R
where
    F: FnMut(&dyn SimdPolicy) -> R,
{
    let detector = FeatureDetector::instance();

    // Resolve optional runtime override (test override takes precedence)
    let ov: Option<String> = {
        #[cfg(test)]
        {
            if let Some(s) = TEST_FEC_KERNEL_OVERRIDE.lock().unwrap().clone() {
                Some(s)
            } else {
                FEC_KERNEL_OVERRIDE
                    .get_or_init(|| {
                        std::env::var("QUICFUSCATE_FEC_KERNEL").ok().map(|v| v.to_lowercase())
                    })
                    .clone()
            }
        }
        #[cfg(not(test))]
        {
            FEC_KERNEL_OVERRIDE
                .get_or_init(|| {
                    std::env::var("QUICFUSCATE_FEC_KERNEL").ok().map(|v| v.to_lowercase())
                })
                .clone()
        }
    };

    // If a valid override is present and supported, honor it; otherwise, warn and fall back
    if let Some(ref mode) = ov {
        match mode.as_str() {
            "ref" | "scalar" => {
                return f(&Scalar);
            }
            "avx512vbmi2" => {
                if detector.has_feature(CpuFeature::AVX512F)
                    && detector.has_feature(CpuFeature::AVX512VBMI2)
                    && detector.has_feature(CpuFeature::AVX512BW)
                {
                    return f(&Avx512Vbmi2);
                } else {
                    warn!(
                        "QUICFUSCATE_FEC_KERNEL=avx512vbmi2 requested but unsupported; falling back to auto"
                    );
                }
            }
            "avx512" => {
                if detector.has_feature(CpuFeature::AVX512F)
                    && detector.has_feature(CpuFeature::AVX512VBMI)
                    && detector.has_feature(CpuFeature::PCLMULQDQ)
                {
                    return f(&Avx512);
                } else {
                    warn!("QUICFUSCATE_FEC_KERNEL=avx512 requested but unsupported; falling back to auto");
                }
            }
            "avx2" => {
                if detector.has_feature(CpuFeature::AVX2)
                    && detector.has_feature(CpuFeature::PCLMULQDQ)
                {
                    return f(&Avx2);
                } else {
                    warn!("QUICFUSCATE_FEC_KERNEL=avx2 requested but unsupported; falling back to auto");
                }
            }
            "neon" => {
                if detector.has_feature(CpuFeature::NEON)
                    && detector.has_feature(CpuFeature::NEON_CRYPTO)
                {
                    return f(&Neon);
                } else {
                    warn!("QUICFUSCATE_FEC_KERNEL=neon requested but unsupported; falling back to auto");
                }
            }
            "sve2" => {
                if detector.has_feature(CpuFeature::SVE2) {
                    return f(&Sve2);
                } else {
                    warn!("QUICFUSCATE_FEC_KERNEL=sve2 requested but unsupported; falling back to auto");
                }
            }
            other => {
                warn!("Unknown QUICFUSCATE_FEC_KERNEL='{}'; falling back to auto", other);
            }
        }
    }

    // Default automatic selection path (unchanged ordering)
    if detector.has_feature(CpuFeature::AVX512F)
        && detector.has_feature(CpuFeature::AVX512VBMI2)
        && detector.has_feature(CpuFeature::AVX512BW)
    {
        f(&Avx512Vbmi2)
    } else if detector.has_feature(CpuFeature::AVX512F)
        && detector.has_feature(CpuFeature::AVX512VBMI)
        && detector.has_feature(CpuFeature::PCLMULQDQ)
    {
        f(&Avx512)
    } else if detector.has_feature(CpuFeature::AVX2) && detector.has_feature(CpuFeature::PCLMULQDQ)
    {
        f(&Avx2)
    } else if detector.has_feature(CpuFeature::SSE2) {
        f(&Sse2)
    } else if detector.has_feature(CpuFeature::SVE2) {
        f(&Sve2)
    } else if detector.has_feature(CpuFeature::NEON)
        && detector.has_feature(CpuFeature::NEON_CRYPTO)
    {
        f(&Neon)
    } else {
        f(&Scalar)
    }
}

/// Helper to return a short, human-readable tag of the active bitslice policy.
pub fn bitslice_policy_tag(p: &dyn SimdPolicy) -> &'static str {
    if p.as_any().is::<Avx512Vbmi2>() {
        "avx512vbmi2"
    } else if p.as_any().is::<Avx512>() {
        "avx512"
    } else if p.as_any().is::<Avx2>() {
        "avx2"
    } else if p.as_any().is::<Sse2>() {
        "sse2"
    } else if p.as_any().is::<Sve2>() {
        "sve2"
    } else if p.as_any().is::<Neon>() {
        "neon"
    } else {
        "scalar"
    }
}

// (tests consolidated below)

#[cfg(test)]
fn with_override<T>(val: Option<&str>, f: impl FnOnce() -> T) -> T {
    __test_set_fec_kernel_override(val);
    let out = f();
    __test_set_fec_kernel_override(None);
    out
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::{bitslice_policy_tag, dispatch_bitslice, with_override};
    use crate::simd::{CpuFeature, FeatureDetector};

    #[test]
    fn override_ref_selects_scalar() {
        let tag = with_override(Some("ref"), || {
            dispatch_bitslice(|p| bitslice_policy_tag(p).to_string())
        });
        assert_eq!(tag, "scalar");
    }

    #[test]
    fn override_invalid_value_graceful_fallback() {
        let tag = with_override(Some("definitely-not-a-kernel"), || {
            dispatch_bitslice(|p| bitslice_policy_tag(p).to_string())
        });
        let allowed = ["avx512", "avx2", "sse2", "sve2", "neon", "scalar"];
        assert!(allowed.contains(&tag.as_str()), "unexpected policy tag: {}", tag);
    }

    #[test]
    fn override_avx2_best_effort() {
        let det = FeatureDetector::instance();
        let tag = with_override(Some("avx2"), || {
            dispatch_bitslice(|p| bitslice_policy_tag(p).to_string())
        });
        if det.has_feature(CpuFeature::AVX2) && det.has_feature(CpuFeature::PCLMULQDQ) {
            assert_eq!(tag, "avx2");
        } else {
            let allowed = ["avx512", "avx2", "sse2", "sve2", "neon", "scalar"];
            assert!(allowed.contains(&tag.as_str()));
        }
    }

    #[test]
    fn override_avx512_best_effort() {
        let det = FeatureDetector::instance();
        let tag = with_override(Some("avx512"), || {
            dispatch_bitslice(|p| bitslice_policy_tag(p).to_string())
        });
        if det.has_feature(CpuFeature::AVX512F)
            && det.has_feature(CpuFeature::AVX512VBMI)
            && det.has_feature(CpuFeature::PCLMULQDQ)
        {
            assert_eq!(tag, "avx512");
        } else {
            let allowed = ["avx512", "avx2", "sse2", "sve2", "neon", "scalar"];
            assert!(allowed.contains(&tag.as_str()));
        }
    }

    #[test]
    fn override_neon_best_effort() {
        let det = FeatureDetector::instance();
        let tag = with_override(Some("neon"), || {
            dispatch_bitslice(|p| bitslice_policy_tag(p).to_string())
        });
        if det.has_feature(CpuFeature::NEON) && det.has_feature(CpuFeature::NEON_CRYPTO) {
            assert_eq!(tag, "neon");
        } else {
            let allowed = ["avx512", "avx2", "sse2", "sve2", "neon", "scalar"];
            assert!(allowed.contains(&tag.as_str()));
        }
    }

    #[test]
    fn override_sve2_best_effort() {
        let det = FeatureDetector::instance();
        let tag = with_override(Some("sve2"), || {
            dispatch_bitslice(|p| bitslice_policy_tag(p).to_string())
        });
        if det.has_feature(CpuFeature::SVE2) {
            assert_eq!(tag, "sve2");
        } else {
            let allowed = ["avx512", "avx2", "sse2", "sve2", "neon", "scalar"];
            assert!(allowed.contains(&tag.as_str()));
        }
    }
}

//
// Foundational Structures for Global Optimizations
//

/// A high-performance, thread-safe memory pool for fixed-size blocks.
/// This implementation uses a concurrent queue to manage free blocks,
/// minimizing lock contention and fragmentation.
#[derive(Debug)]
pub struct MemoryPool {
    pools: Vec<Arc<SegQueue<AlignedBox<[u8]>>>>,
    block_size: usize,
    num_nodes: usize,
    capacity: AtomicUsize,
    in_use: AtomicUsize,
    available: AtomicUsize,
}

impl MemoryPool {
    #[inline]
    fn tls_limit_cell() -> &'static AtomicUsize {
        static TLS_LIMIT_RUNTIME: OnceLock<AtomicUsize> = OnceLock::new();
        TLS_LIMIT_RUNTIME.get_or_init(|| {
            let default = std::env::var("QUICFUSCATE_TLS_CACHE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(32);
            AtomicUsize::new(default)
        })
    }
    // Thread-local small cache of blocks to reduce contention on queues
    thread_local! {
        static TLS_CACHE: RefCell<Vec<AlignedBox<[u8]>>> = const { RefCell::new(Vec::new()) };
    }

    #[inline]
    fn hard_max_cap() -> usize {
        std::env::var("QUICFUSCATE_POOL_HARD_MAX_CAP")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(usize::MAX)
    }

    #[inline]
    fn tls_limit() -> usize {
        Self::tls_limit_cell().load(Ordering::Relaxed)
    }

    #[inline]
    #[allow(dead_code)]
    fn set_tls_limit(new_limit: usize) {
        Self::tls_limit_cell().store(new_limit, Ordering::Relaxed);
    }

    #[inline]
    fn bump_tls_limit(suggested: usize) {
        let cell = Self::tls_limit_cell();
        let cur = cell.load(Ordering::Relaxed);
        if suggested != cur {
            cell.store(suggested, Ordering::Relaxed);
        }
    }

    #[inline]
    fn flush_tls_to_queue(&self, node: usize, max: usize) {
        Self::TLS_CACHE.with(|c| {
            let mut cache = c.borrow_mut();
            let limit = Self::tls_limit();
            let len = cache.len();
            if len > limit {
                let mut to_flush = core::cmp::min(len - limit, max);
                if let Some(q) = self.pools.get(node) {
                    while to_flush > 0 {
                        if let Some(b) = cache.pop() {
                            q.push(b);
                        } else {
                            break;
                        }
                        to_flush -= 1;
                    }
                }
            }
        });
    }

    /// Creates a new memory pool with a specified capacity and block size.
    /// All allocated blocks are 64-byte aligned.
    pub fn new(capacity: usize, block_size: usize) -> Self {
        // Adaptive block size based on traffic profile and enforce a sane lower bound
        let mut block_size = Self::adaptive_block_size(block_size);
        if block_size < 2048 {
            block_size = 2048;
        }
        let nodes = numa::num_nodes();
        let mut pools = Vec::with_capacity(nodes);
        for n in 0..nodes {
            let node_cap = capacity / nodes + if n < capacity % nodes { 1 } else { 0 };
            let q = Arc::new(SegQueue::new());
            for _ in 0..node_cap {
                q.push(Self::alloc_numa_block(block_size, n));
            }
            pools.push(q);
        }
        let pool = Self {
            pools,
            block_size,
            num_nodes: nodes,
            capacity: AtomicUsize::new(capacity),
            in_use: AtomicUsize::new(0),
            available: AtomicUsize::new(capacity),
        };
        // Telemetry init
        crate::optimize::telemetry::MEM_POOL_CAPACITY.store(capacity as u64, Ordering::Relaxed);
        crate::optimize::telemetry::MEM_POOL_BLOCK_SIZE.store(block_size as u64, Ordering::Relaxed);
        pool.update_metrics();
        pool
    }

    #[cfg(debug_assertions)]
    #[inline(always)]
    fn check_invariants(&self) {
        if cfg!(test) {
            return;
        }
        use std::thread;
        let cap = self.capacity.load(Ordering::Acquire);
        let in_use = self.in_use.load(Ordering::Acquire);
        let avail = self.available.load(Ordering::Acquire);
        // Allow transient slack due to non-atomic pair updates of (available,in_use)
        // Make slack configurable for stress-heavy tests; default increased conservatively.
        let slack: usize = std::env::var("QUICFUSCATE_POOL_DEBUG_SLACK")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(256);
        let grace: usize = std::env::var("QUICFUSCATE_POOL_DEBUG_GRACE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(64);
        if in_use > cap.saturating_add(slack).saturating_add(grace)
            || avail > cap.saturating_add(slack).saturating_add(grace)
        {
            // Re-read once to avoid transient races
            thread::yield_now();
            let cap2 = self.capacity.load(Ordering::SeqCst);
            let in_use2 = self.in_use.load(Ordering::SeqCst);
            let avail2 = self.available.load(Ordering::SeqCst);
            if in_use2 > cap2.saturating_add(slack).saturating_add(grace)
                || avail2 > cap2.saturating_add(slack).saturating_add(grace)
            {
                // One more short backoff for extremely bursty updates
                thread::yield_now();
                let cap3 = self.capacity.load(Ordering::SeqCst);
                let in_use3 = self.in_use.load(Ordering::SeqCst);
                let avail3 = self.available.load(Ordering::SeqCst);
                if in_use3 > cap3.saturating_add(slack).saturating_add(grace).saturating_add(1) {
                    log::warn!(
                      target: "memory_pool",
                      "in_use {} > capacity {} (after retry2, slack={}, grace={}, +1)",
                      in_use3, cap3, slack, grace
                    );
                }
                if avail3 > cap3.saturating_add(slack).saturating_add(grace).saturating_add(1) {
                    log::warn!(
                      target: "memory_pool",
                      "available {} > capacity {} (after retry2, slack={}, grace={}, +1)",
                      avail3, cap3, slack, grace
                    );
                }
            }
        }
    }
    #[cfg(not(debug_assertions))]
    #[inline(always)]
    fn check_invariants(&self) {}

    #[inline]
    fn dec_available(&self) {
        use std::sync::atomic::Ordering;
        let mut cur = self.available.load(Ordering::Acquire);
        while cur > 0 {
            match self.available.compare_exchange_weak(
                cur,
                cur - 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(next) => cur = next,
            }
        }
    }

    #[inline]
    fn inc_in_use(&self) {
        self.in_use.fetch_add(1, Ordering::Relaxed);
    }
    /// Allocate a 64-byte aligned block bound to the given NUMA node.
    fn alloc_numa_block(block_size: usize, node: usize) -> AlignedBox<[u8]> {
        // Use manual aligned allocation to guarantee exact length = block_size.
        let layout = match std::alloc::Layout::from_size_align(block_size.max(1), 64) {
            Ok(l) => l,
            Err(le) => {
                error!(
                    "Invalid allocation layout: {} bytes, 64B: {}. Falling back to minimal alignment.",
                    block_size, le
                );
                let min_align = core::mem::align_of::<u8>().max(1);
                // Safety: we clamp size to at least 1
                unsafe {
                    std::alloc::Layout::from_size_align_unchecked(block_size.max(1), min_align)
                }
            }
        };
        let ptr = unsafe { std::alloc::alloc(layout) };
        if ptr.is_null() {
            // Standard behavior on OOM
            std::alloc::handle_alloc_error(layout);
        }
        // Zero-initialize for deterministic tests and safety
        unsafe { std::ptr::write_bytes(ptr, 0u8, block_size) };
        let slice = unsafe { std::slice::from_raw_parts_mut(ptr, block_size) };
        // SAFETY: ptr was allocated with the given layout; aligned_box will track layout for dealloc
        let block = unsafe { AlignedBox::<[u8]>::from_raw_parts(slice, layout) };
        // Hint huge pages on Linux if enabled
        #[cfg(target_os = "linux")]
        unsafe {
            let hp = std::env::var("QUICFUSCATE_MADVISE_HUGEPAGE")
                .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
                .unwrap_or(true);
            if hp {
                let _ = libc::madvise(
                    block.as_mut_ptr() as *mut libc::c_void,
                    block_size,
                    libc::MADV_HUGEPAGE,
                );
            }
        }
        #[cfg(target_os = "linux")]
        unsafe {
            if numa::is_available() {
                let policy = *NUMA_POLICY.get_or_init(resolve_numa_policy);
                let nodes = numa::num_nodes().max(1);
                let target = match policy {
                    NumaPolicy::Local => node,
                    NumaPolicy::Preferred(n) => n % nodes,
                    NumaPolicy::Interleave => RR_NODE.fetch_add(1, Ordering::Relaxed) % nodes,
                };
                numa::move_to_node(block.as_mut_ptr(), block_size, target);
                // telemetry hint for policy
                crate::optimize::telemetry::MEM_POOL_NUMA_POLICY.store(
                    match policy {
                        NumaPolicy::Local => 0,
                        NumaPolicy::Preferred(_) => 1,
                        NumaPolicy::Interleave => 2,
                    },
                    Ordering::Relaxed,
                );
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = node; // silence unused parameter warning on non-Linux
        }
        block
    }

    /// Returns the configured block size of the pool.
    #[inline]
    pub fn block_size(&self) -> usize {
        self.block_size
    }

    fn grow(&self, new_capacity: usize) {
        let limit = Self::hard_max_cap();
        let target = core::cmp::min(new_capacity, limit);
        while self.capacity.load(Ordering::Relaxed) < target {
            for (n, q) in self.pools.iter().enumerate() {
                if self.capacity.load(Ordering::Relaxed) >= target {
                    break;
                }
                q.push(Self::alloc_numa_block(self.block_size, n));
                self.available.fetch_add(1, Ordering::Relaxed);
                self.capacity.fetch_add(1, Ordering::Relaxed);
            }
        }
        // telemetry!(telemetry::MEM_POOL_CAPACITY.store(self.capacity.load(Ordering::Relaxed) as u64, Ordering::Relaxed));
        self.update_metrics();
        self.check_invariants();
    }

    fn update_metrics(&self) {
        let cap = self.capacity.load(Ordering::Relaxed);
        let in_use = self.in_use.load(Ordering::Relaxed);
        let avail = self.available.load(Ordering::Relaxed);
        crate::optimize::telemetry::MEM_POOL_IN_USE.store(in_use as u64, Ordering::Relaxed);
        let usage_bytes = in_use.saturating_mul(self.block_size) as u64;
        crate::optimize::telemetry::MEM_POOL_USAGE_BYTES.store(usage_bytes, Ordering::Relaxed);
        let total = in_use.saturating_add(avail);
        let _frag = cap.saturating_sub(total);
        // Fragmentation not tracked precisely; leave default 0
        let util =
            if cap == 0 { 0 } else { (in_use.saturating_mul(100).saturating_div(cap)) as u64 };
        crate::optimize::telemetry::MEM_POOL_UTILIZATION.store(util, Ordering::Relaxed);
    }

    pub fn refresh_metrics(&self) {
        self.update_metrics();
    }

    /// Allocates a 64-byte aligned memory block from the pool.
    /// If the pool is empty, a new block is created.
    #[inline(always)]
    pub fn alloc(&self) -> AlignedBox<[u8]> {
        // Fast-path: check TLS cache first
        if let Some(b) = Self::TLS_CACHE.with(|c| c.borrow_mut().pop()) {
            // Validate size; drop foreign/mismatched blocks
            if b.len() == self.block_size {
                crate::optimize::telemetry::MEM_POOL_HITS_TLS.inc();
                self.dec_available();
                self.inc_in_use();
                // Warm cache for caller
                unsafe { prefetch(b.as_ptr(), PrefetchHint::T0) };
                return b;
            } else {
                // Remove from available as it left TLS, but do not count as in-use
                self.dec_available();
                // Drop mismatched block; continue to slow-path to obtain a correct block
            }
        }

        // Slow-path: try queue, create if needed
        self.alloc_cold()
    }

    /// Allocates an aligned buffer and copies data from the provided slice
    pub fn alloc_from_slice(&self, data: &[u8]) -> AlignedBox<[u8]> {
        let mut buf = self.alloc();
        let copy_len = data.len().min(buf.len());
        buf[..copy_len].copy_from_slice(&data[..copy_len]);
        // Resize the box to match the actual data length if possible
        // For now, just return the full buffer - callers should track actual length
        buf
    }

    #[cold]
    #[inline(never)]
    fn alloc_cold(&self) -> AlignedBox<[u8]> {
        let node = numa::current_node() % self.num_nodes;
        // Opportunistically flush some TLS cache back to the global queue
        // to reduce long-term TLS growth under bursty patterns
        self.flush_tls_to_queue(node, 8);
        if let Some(queue) = self.pools.get(node) {
            if let Some(b) = queue.pop() {
                crate::optimize::telemetry::MEM_POOL_HITS_QUEUE.inc();
                self.dec_available();
                self.in_use.fetch_add(1, Ordering::Relaxed);
                self.update_metrics();
                self.check_invariants();
                // telemetry!(telemetry::update_memory_usage());
                // Prefetch freshly popped memory to warm cache for the caller
                unsafe { prefetch(b.as_ptr(), PrefetchHint::T0) };
                return b;
            }
        }
        // Opportunistically steal from other NUMA queues to reduce growth pressure
        if self.num_nodes > 1 {
            for off in 1..self.num_nodes {
                let idx = (node + off) % self.num_nodes;
                if let Some(q) = self.pools.get(idx) {
                    if let Some(b) = q.pop() {
                        // Treat as regular queue hit
                        self.dec_available();
                        self.in_use.fetch_add(1, Ordering::Relaxed);
                        self.update_metrics();
                        self.check_invariants();
                        unsafe { prefetch(b.as_ptr(), PrefetchHint::T0) };
                        return b;
                    }
                }
            }
        }
        // Attempt growth respecting hard cap
        let cap_now = self.capacity.load(Ordering::Relaxed);
        let limit = Self::hard_max_cap();
        if cap_now < limit {
            let mut target = cap_now.saturating_mul(2);
            if target == 0 {
                target = 1;
            }
            if target > limit {
                target = limit;
            }
            self.grow(target);
            // Try again after growth
            if let Some(queue) = self.pools.get(node) {
                if let Some(b) = queue.pop() {
                    crate::optimize::telemetry::MEM_POOL_ALLOC_GROW.inc();
                    self.available.fetch_sub(1, Ordering::Relaxed);
                    self.in_use.fetch_add(1, Ordering::Relaxed);
                    self.update_metrics();
                    self.check_invariants();
                    unsafe { prefetch(b.as_ptr(), PrefetchHint::T0) };
                    return b;
                }
            }
        }
        // Hard-cap reached or still no blocks: allocate a new block and account it as pooled
        // (checked-out). This maintains invariants for free() without needing origin tags.
        let cap_now = self.capacity.load(Ordering::Relaxed);
        let limit2 = Self::hard_max_cap();
        if cap_now < limit2 {
            let b = Self::alloc_numa_block(self.block_size, node);
            self.capacity.fetch_add(1, Ordering::Relaxed);
            self.in_use.fetch_add(1, Ordering::Relaxed);
            self.update_metrics();
            self.check_invariants();
            return b;
        }
        // If we are strictly at the hard cap, we cannot grow. As a last resort, allocate
        // an ephemeral block but do not touch counters; free() will drop it if pool is full.
        crate::optimize::telemetry::MEM_POOL_ALLOC_EPHEMERAL.inc();
        {
            let b = Self::alloc_numa_block(self.block_size, node);
            unsafe { prefetch(b.as_ptr(), PrefetchHint::T0) };
            b
        }
    }

    /// Returns a memory block to the pool.
    /// If the pool is full, the block is dropped.
    #[inline(always)]
    pub fn free(&self, mut block: AlignedBox<[u8]>) {
        // Drop foreign/mismatched sized blocks instead of re-caching them
        if block.len() != self.block_size {
            // Do not touch counters: block did not originate from this pool's accounting
            return;
        }
        // Zeroize efficiently; allows vectorized memset
        block.as_mut().fill(0);
        // Try to place into TLS cache
        let limit = Self::tls_limit();
        let can_push_tls = Self::TLS_CACHE.with(|c| c.borrow().len() < limit);
        if can_push_tls {
            Self::TLS_CACHE.with(|c| c.borrow_mut().push(block));
            self.available.fetch_add(1, Ordering::Relaxed);
            self.in_use.fetch_sub(1, Ordering::Relaxed);
            self.update_metrics();
            self.check_invariants();
            return;
        }
        // Fallback: return to global pool queue
        let node = numa::current_node() % self.num_nodes;
        if self.available.load(Ordering::Relaxed) < self.capacity.load(Ordering::Relaxed) {
            if let Some(q) = self.pools.get(node) {
                q.push(block);
            }
            self.available.fetch_add(1, Ordering::Relaxed);
        }
        self.in_use.fetch_sub(1, Ordering::Relaxed);
        self.update_metrics();
        self.check_invariants();
        // telemetry!(telemetry::update_memory_usage());
    }

    /// Adjusts the maximum number of cached blocks at runtime.
    pub fn set_capacity(&self, new_capacity: usize) {
        let current = self.capacity.load(Ordering::Relaxed);
        let limit = Self::hard_max_cap();
        let clamped = core::cmp::min(new_capacity, limit);
        if clamped > current {
            self.grow(clamped);
        } else {
            // shrink: drop excess blocks
            let mut diff = current - clamped;
            while diff > 0 && self.available.load(Ordering::Relaxed) > 0 {
                for q in &self.pools {
                    if diff == 0 {
                        break;
                    }
                    if q.pop().is_some() {
                        self.available.fetch_sub(1, Ordering::Relaxed);
                        self.capacity.fetch_sub(1, Ordering::Relaxed);
                        diff -= 1;
                    }
                }
                if diff == 0 {
                    break;
                }
            }
        }
        // telemetry!(telemetry::MEM_POOL_CAPACITY.store(self.capacity.load(Ordering::Relaxed) as u64, Ordering::Relaxed));
        self.update_metrics();
        // telemetry!(telemetry::update_memory_usage());
        self.check_invariants();
    }

    /// Background auto-tuner: periodically adjusts capacity based on usage.
    /// Controlled by env QUICFUSCATE_POOL_AUTO_TUNE (default true),
    /// QUICFUSCATE_POOL_MIN_CAP, QUICFUSCATE_POOL_MAX_CAP, QUICFUSCATE_POOL_TICK_MS.
    /// Determine optimal block size based on ENV hints and MTU
    fn adaptive_block_size(requested: usize) -> usize {
        if let Ok(v) = std::env::var("QUICFUSCATE_POOL_ADAPTIVE_BLOCK") {
            if v == "0" || v.eq_ignore_ascii_case("false") {
                return requested;
            }
        }
        // Auto-tune based on common MTU patterns
        let mtu_hint = std::env::var("QUICFUSCATE_MTU_HINT")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(1500);
        if mtu_hint <= 1500 {
            // Standard Ethernet: use 4KB blocks
            4096
        } else if mtu_hint <= 9000 {
            // Jumbo frames: use 16KB blocks
            16384
        } else {
            // High-speed datacenter: use 64KB blocks
            65536
        }
    }

    pub fn start_auto_tuner(pool: Arc<MemoryPool>) {
        static STARTED: OnceLock<()> = OnceLock::new();
        let enabled = std::env::var("QUICFUSCATE_POOL_AUTO_TUNE")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true);
        if !enabled {
            return;
        }
        let _ = STARTED.get_or_init(|| {
            std::thread::spawn(move || {
                let min_cap = std::env::var("QUICFUSCATE_POOL_MIN_CAP")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(64);
                let max_cap = std::env::var("QUICFUSCATE_POOL_MAX_CAP")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(4096);
                let tick_ms = std::env::var("QUICFUSCATE_POOL_TICK_MS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(1000u64);
                loop {
                    // Allow runtime-configurable utilization thresholds
                    let util_high = std::env::var("QUICFUSCATE_POOL_UTIL_HIGH")
                        .ok()
                        .and_then(|v| v.parse::<usize>().ok())
                        .map(|v| v.clamp(5, 95))
                        .unwrap_or(80);
                    let util_low = std::env::var("QUICFUSCATE_POOL_UTIL_LOW")
                        .ok()
                        .and_then(|v| v.parse::<usize>().ok())
                        .map(|v| v.clamp(1, 89))
                        .unwrap_or(30);
                    // Ensure logical ordering
                    let (util_low, util_high) = if util_low + 5 >= util_high {
                        (util_high.saturating_sub(10).max(1), util_high)
                    } else {
                        (util_low, util_high)
                    };

                    let tls_high = std::env::var("QUICFUSCATE_TLS_HIGH")
                        .ok()
                        .and_then(|v| v.parse::<usize>().ok())
                        .unwrap_or(48);
                    let tls_low = std::env::var("QUICFUSCATE_TLS_LOW")
                        .ok()
                        .and_then(|v| v.parse::<usize>().ok())
                        .unwrap_or(24);

                    let cap = pool.capacity.load(Ordering::Relaxed);
                    let in_use = pool.in_use.load(Ordering::Relaxed);
                    let util = if cap > 0 { (in_use * 100) / cap } else { 0 };
                    let mut target = cap;
                    if util > util_high {
                        target = core::cmp::min(cap.saturating_mul(2), max_cap);
                        // Under high utilization, raise TLS cache to reduce contention
                        MemoryPool::bump_tls_limit(tls_high);
                    } else if util < util_low {
                        target = core::cmp::max(cap / 2, min_cap);
                        // Under low utilization, shrink TLS cache for footprint
                        MemoryPool::bump_tls_limit(tls_low);
                    }
                    if target != cap {
                        pool.set_capacity(target);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(tick_ms));
                }
            });
        });
    }
}

/// A buffer designed for zero-copy vectored I/O operations using `sendmsg`.
/// This allows sending data from multiple non-contiguous memory regions
/// in a single system call, avoiding intermediate copies.
#[cfg(unix)]
pub struct ZeroCopyBuffer<'a> {
    iovecs: SmallVec<[iovec; 4]>,
    _marker: std::marker::PhantomData<&'a [u8]>,
}

#[cfg(unix)]
impl<'a> ZeroCopyBuffer<'a> {
    /// Creates a new `ZeroCopyBuffer` from a slice of byte slices.
    pub fn new(buffers: &[&'a [u8]]) -> Self {
        let mut iovecs: SmallVec<[iovec; 4]> = SmallVec::with_capacity(buffers.len());
        for buf in buffers {
            iovecs.push(iovec { iov_base: buf.as_ptr() as *mut libc::c_void, iov_len: buf.len() });
        }
        Self { iovecs, _marker: std::marker::PhantomData }
    }

    /// Creates a new `ZeroCopyBuffer` from mutable slices for receiving.
    pub fn new_mut(buffers: &mut [&'a mut [u8]]) -> Self {
        let mut iovecs: SmallVec<[iovec; 4]> = SmallVec::with_capacity(buffers.len());
        for buf in buffers.iter_mut() {
            iovecs.push(iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            });
        }
        Self { iovecs, _marker: std::marker::PhantomData }
    }

    /// Sends the data using `sendmsg` for true zero-copy transmission.
    pub fn send(&self, fd: RawFd) -> isize {
        let msg = msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: self.iovecs.as_ptr() as *mut _,
            msg_iovlen: self.iovecs.len() as _,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        unsafe { sendmsg(fd, &msg, 0) }
    }

    /// Attempts Linux SO_ZEROCOPY + MSG_ZEROCOPY send. Falls back to send() on error.
    #[cfg(target_os = "linux")]
    pub fn send_zero_copy(&self, fd: RawFd) -> isize {
        use std::sync::OnceLock as LocalOnce;
        static WANT_ZC: LocalOnce<bool> = LocalOnce::new();
        let want = *WANT_ZC.get_or_init(|| {
            std::env::var("QUICFUSCATE_ZEROCOPY")
                .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
                .unwrap_or(false)
        });
        if !want {
            return self.send(fd);
        }
        unsafe {
            // Enable SO_ZEROCOPY once per socket
            const SO_ZEROCOPY_CONST: libc::c_int = 60; // Linux
            let one: libc::c_int = 1;
            let r = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                SO_ZEROCOPY_CONST,
                &one as *const _ as *const libc::c_void,
                core::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            let msg = msghdr {
                msg_name: std::ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: self.iovecs.as_ptr() as *mut _,
                msg_iovlen: self.iovecs.len() as _,
                msg_control: std::ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            };
            const MSG_ZEROCOPY_CONST: libc::c_int = 0x4000000; // Linux
            let rc = libc::sendmsg(fd, &msg, MSG_ZEROCOPY_CONST);
            if rc < 0 {
                return sendmsg(fd, &msg, 0);
            }
            rc
        }
    }

    /// Sends the data to the specified address using `sendmsg`.
    pub fn send_to(&self, fd: RawFd, addr: SocketAddr) -> isize {
        use socket2::SockAddr;
        let sockaddr = SockAddr::from(addr);
        let msg = msghdr {
            msg_name: sockaddr.as_ptr() as *mut _,
            msg_namelen: sockaddr.len(),
            msg_iov: self.iovecs.as_ptr() as *mut _,
            msg_iovlen: self.iovecs.len() as _,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        unsafe { sendmsg(fd, &msg, 0) }
    }

    /// Receives data using `recvmsg` into the buffers.
    pub fn recv(&mut self, fd: RawFd) -> isize {
        let mut msg = msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: self.iovecs.as_mut_ptr(),
            msg_iovlen: self.iovecs.len() as _,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        unsafe { recvmsg(fd, &mut msg, 0) }
    }

    /// Receives data and returns the sender address.
    pub fn recv_from(&mut self, fd: RawFd) -> io::Result<(isize, SocketAddr)> {
        use socket2::SockAddr;
        unsafe {
            SockAddr::try_init(|storage, len| {
                let mut msg = msghdr {
                    msg_name: storage.cast(),
                    msg_namelen: *len,
                    msg_iov: self.iovecs.as_mut_ptr(),
                    msg_iovlen: self.iovecs.len() as _,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                };
                let ret = recvmsg(fd, &mut msg, 0);
                if ret < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    *len = msg.msg_namelen;
                    Ok(ret)
                }
            })
            .and_then(|(ret, addr)| {
                addr.as_socket().map(|sock| (ret, sock)).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "Invalid socket address")
                })
            })
        }
    }

    /// Returns the total length represented by all iovecs.
    pub fn len(&self) -> usize {
        self.iovecs.iter().map(|iov| iov.iov_len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.iovecs.is_empty()
    }

    pub fn as_iovecs(&self) -> &[iovec] {
        &self.iovecs
    }
}

#[cfg(unix)]
impl Drop for ZeroCopyBuffer<'_> {
    fn drop(&mut self) {
        self.iovecs.clear();
    }
}

// Linux-only batching helpers for UDP I/O using sendmmsg/recvmmsg
#[cfg(target_os = "linux")]
pub mod zc_batch {
    use libc::{mmsghdr, sockaddr, socklen_t};

    pub fn sendmmsg(fd: RawFd, packets: &[&[u8]]) -> io::Result<usize> {
        let mut iovecs: Vec<iovec> = Vec::with_capacity(packets.len());
        let mut msgs: Vec<mmsghdr> = Vec::with_capacity(packets.len());
        for p in packets {
            iovecs.push(iovec { iov_base: p.as_ptr() as *mut libc::c_void, iov_len: p.len() });
        }
        for i in 0..packets.len() {
            let iov_ptr = &mut iovecs[i] as *mut iovec;
            let msg = mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: std::ptr::null_mut::<sockaddr>() as *mut libc::c_void,
                    msg_namelen: 0 as socklen_t,
                    msg_iov: iov_ptr,
                    msg_iovlen: 1,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                msg_len: 0,
            };
            msgs.push(msg);
        }
        let rc = unsafe { libc::sendmmsg(fd, msgs.as_mut_ptr(), msgs.len() as u32, 0) };
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(rc as usize)
        }
    }

    pub fn recvmmsg(fd: RawFd, bufs: &mut [&mut [u8]]) -> io::Result<usize> {
        let mut iovecs: Vec<iovec> = Vec::with_capacity(bufs.len());
        let mut msgs: Vec<mmsghdr> = Vec::with_capacity(bufs.len());
        for b in bufs.iter_mut() {
            iovecs.push(iovec { iov_base: b.as_mut_ptr() as *mut libc::c_void, iov_len: b.len() });
        }
        for i in 0..bufs.len() {
            let iov_ptr = &mut iovecs[i] as *mut iovec;
            let msg = mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: std::ptr::null_mut::<sockaddr>() as *mut libc::c_void,
                    msg_namelen: 0 as socklen_t,
                    msg_iov: iov_ptr,
                    msg_iovlen: 1,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                msg_len: 0,
            };
            msgs.push(msg);
        }
        let rc = unsafe {
            libc::recvmmsg(fd, msgs.as_mut_ptr(), msgs.len() as u32, 0, std::ptr::null_mut())
        };
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(rc as usize)
        }
    }
}

#[cfg(windows)]
pub struct ZeroCopyBuffer<'a> {
    bufs: Vec<WSABUF>,
    _marker: std::marker::PhantomData<&'a [u8]>,
}

#[cfg(windows)]
impl<'a> ZeroCopyBuffer<'a> {
    pub fn new(buffers: &[&'a [u8]]) -> Self {
        let bufs = buffers
            .iter()
            .map(|b| WSABUF { len: b.len() as u32, buf: b.as_ptr() as *mut i8 })
            .collect();
        Self { bufs, _marker: std::marker::PhantomData }
    }

    pub fn new_mut(buffers: &mut [&'a mut [u8]]) -> Self {
        let bufs = buffers
            .iter_mut()
            .map(|b| WSABUF { len: b.len() as u32, buf: b.as_mut_ptr() as *mut i8 })
            .collect();
        Self { bufs, _marker: std::marker::PhantomData }
    }

    pub fn send(&self, sock: windows_sys::Win32::Networking::WinSock::SOCKET) -> i32 {
        let mut msg = WSAMSG {
            name: core::ptr::null_mut(),
            namelen: 0,
            lpBuffers: self.bufs.as_ptr() as *mut _,
            dwBufferCount: self.bufs.len() as u32,
            Control: WSABUF { len: 0, buf: core::ptr::null_mut() },
            dwFlags: 0,
        };
        let mut sent: u32 = 0;
        unsafe { WSASendMsg(sock, &msg, 0, &mut sent, core::ptr::null_mut(), None) };
        sent as i32
    }

    pub fn send_to(
        &self,
        sock: windows_sys::Win32::Networking::WinSock::SOCKET,
        addr: SocketAddr,
    ) -> i32 {
        use socket2::SockAddr;
        let sockaddr = SockAddr::from(addr);
        let mut msg = WSAMSG {
            name: sockaddr.as_ptr() as *mut _,
            namelen: sockaddr.len(),
            lpBuffers: self.bufs.as_ptr() as *mut _,
            dwBufferCount: self.bufs.len() as u32,
            Control: WSABUF { len: 0, buf: core::ptr::null_mut() },
            dwFlags: 0,
        };
        let mut sent: u32 = 0;
        unsafe { WSASendMsg(sock, &msg, 0, &mut sent, core::ptr::null_mut(), None) };
        sent as i32
    }

    pub fn recv(&mut self, sock: windows_sys::Win32::Networking::WinSock::SOCKET) -> i32 {
        let mut msg = WSAMSG {
            name: core::ptr::null_mut(),
            namelen: 0,
            lpBuffers: self.bufs.as_mut_ptr(),
            dwBufferCount: self.bufs.len() as u32,
            Control: WSABUF { len: 0, buf: core::ptr::null_mut() },
            dwFlags: 0,
        };
        let mut recvd: u32 = 0;
        unsafe { WSARecvMsg(sock, &mut msg, &mut recvd, core::ptr::null_mut(), None) };
        recvd as i32
    }

    pub fn recv_from(
        &mut self,
        sock: windows_sys::Win32::Networking::WinSock::SOCKET,
    ) -> io::Result<(i32, SocketAddr)> {
        use socket2::SockAddr;
        use windows_sys::Win32::Networking::WinSock::SOCKADDR_STORAGE;
        let mut storage: SOCKADDR_STORAGE = unsafe { core::mem::zeroed() };
        let mut msg = WSAMSG {
            name: &mut storage as *mut _ as *mut _,
            namelen: core::mem::size_of::<SOCKADDR_STORAGE>() as u32,
            lpBuffers: self.bufs.as_mut_ptr(),
            dwBufferCount: self.bufs.len() as u32,
            Control: WSABUF { len: 0, buf: core::ptr::null_mut() },
            dwFlags: 0,
        };
        let mut recvd: u32 = 0;
        let ret = unsafe { WSARecvMsg(sock, &mut msg, &mut recvd, core::ptr::null_mut(), None) };
        if ret == 0 {
            let addr = unsafe {
                match SockAddr::from_raw_parts(&storage as *const _ as *const _, msg.namelen)
                    .as_socket()
                {
                    Some(a) => a,
                    None => {
                        error!("WSARecvMsg returned no socket address - using unspecified address");
                        std::net::SocketAddr::from(([0, 0, 0, 0], 0))
                    }
                }
            };
            Ok((recvd as i32, addr))
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn len(&self) -> usize {
        self.bufs.iter().map(|b| b.len as usize).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.bufs.is_empty()
    }
}

#[cfg(windows)]
impl<'a> Drop for ZeroCopyBuffer<'a> {
    fn drop(&mut self) {
        self.bufs.clear();
    }
}

/// Singleton manager for runtime optimizations.
#[derive(Clone)]
pub struct OptimizationManager {
    memory_pool: Arc<MemoryPool>,
    xdp_available: bool,
    use_xdp: bool,
}

impl OptimizationManager {
    /// Creates a new optimization manager.
    pub fn new() -> Self {
        let supported = xdp_socket::XdpSocket::is_supported();
        info!("XDP available: {}", supported);
        let enabled = supported;
        crate::telemetry::XDP_ACTIVE.store(enabled as u64, std::sync::atomic::Ordering::Relaxed);
        Self {
            memory_pool: Arc::new(MemoryPool::new(1024, 4096)),
            xdp_available: supported,
            use_xdp: enabled,
        }
    }

    pub fn new_with_config(capacity: usize, block_size: usize, enable_xdp: bool) -> Self {
        let supported = xdp_socket::XdpSocket::is_supported();
        info!("XDP available: {}", supported);
        let enabled = enable_xdp && supported;
        crate::telemetry::XDP_ACTIVE.store(enabled as u64, std::sync::atomic::Ordering::Relaxed);
        Self {
            memory_pool: Arc::new(MemoryPool::new(capacity, block_size)),
            xdp_available: supported,
            use_xdp: enabled,
        }
    }

    pub fn from_cfg(cfg: OptimizeConfig) -> Self {
        Self::new_with_config(cfg.pool_capacity, cfg.block_size, cfg.enable_xdp)
    }

    pub fn alloc_block(&self) -> AlignedBox<[u8]> {
        self.memory_pool.alloc()
    }

    pub fn free_block(&self, block: AlignedBox<[u8]>) {
        self.memory_pool.free(block);
    }

    pub fn is_xdp_available(&self) -> bool {
        self.xdp_available
    }

    pub fn is_xdp_enabled(&self) -> bool {
        self.use_xdp
    }

    pub fn memory_pool(&self) -> Arc<MemoryPool> {
        Arc::clone(&self.memory_pool)
    }

    pub fn create_xdp_socket(
        &self,
        bind: SocketAddr,
        remote: SocketAddr,
    ) -> Option<xdp_socket::XdpSocket> {
        if !self.xdp_available || !self.use_xdp {
            crate::telemetry::XDP_ACTIVE.store(0, std::sync::atomic::Ordering::Relaxed);
            return None;
        }

        match xdp_socket::XdpSocket::new(bind, remote) {
            Ok(sock) => {
                crate::telemetry::XDP_ACTIVE.store(1, std::sync::atomic::Ordering::Relaxed);
                Some(sock)
            }
            Err(e) => {
                info!("XDP init failed, falling back to UDP: {}", e);
                crate::telemetry::XDP_FALLBACKS.inc();
                crate::telemetry::XDP_ACTIVE.store(0, std::sync::atomic::Ordering::Relaxed);
                Some(xdp_socket::XdpSocket::new_udp(bind, remote).ok()?)
            }
        }
    }
}

impl Default for OptimizationManager {
    fn default() -> Self {
        Self::new()
    }
}

/// XDP Socket module for high-performance packet I/O
pub mod xdp_socket {
    #[cfg(unix)]
    use super::ZeroCopyBuffer;
    #[cfg(unix)]
    use std::io::{self, Error};
    #[cfg(unix)]
    use std::net::SocketAddr;
    #[cfg(unix)]
    use std::os::unix::io::{AsRawFd, RawFd};

    #[cfg(target_os = "linux")]
    use thiserror::Error;

    #[cfg(target_os = "linux")]
    use {
        afxdp::{
            buf_mmap::BufMmap,
            mmap_area::{MmapArea, MmapAreaOptions},
            socket::{Socket, SocketOptions, SocketRx, SocketTx},
            umem::{Umem, UmemCompletionQueue, UmemFillQueue},
            PENDING_LEN,
        },
        arraydeque::{ArrayDeque, Wrapping},
        libbpf_sys::{XSK_RING_CONS__DEFAULT_NUM_DESCS, XSK_RING_PROD__DEFAULT_NUM_DESCS},
        std::sync::Arc,
    };

    #[cfg(target_os = "linux")]
    struct XdpState {
        rx: SocketRx<'static, [u8; 2048]>,
        tx: SocketTx<'static, [u8; 2048]>,
        fq: UmemFillQueue<'static, [u8; 2048]>,
        cq: UmemCompletionQueue<'static, [u8; 2048]>,
        pool: Vec<BufMmap<'static, [u8; 2048]>>,
        pending: ArrayDeque<[BufMmap<'static, [u8; 2048]>; PENDING_LEN], Wrapping>,
    }

    #[cfg(target_os = "linux")]
    pub struct XdpSocket {
        udp: std::net::UdpSocket,
        state: Option<XdpState>,
    }

    #[cfg(unix)]
    pub struct XdpSocket {
        socket: std::net::UdpSocket,
    }

    #[cfg(not(unix))]
    pub struct XdpSocket;

    #[cfg(target_os = "linux")]
    #[derive(Debug, Error)]
    pub enum XdpInitError {
        #[error("memory map failed")]
        Mmap,
        #[error("invalid ring size")]
        InvalidRing,
        #[error("umem setup failed: {0}")]
        Umem(#[source] io::Error),
        #[error("socket creation failed: {0}")]
        Socket(#[source] io::Error),
        #[error("kernel does not support AF_XDP")]
        Unsupported,
    }

    #[cfg(target_os = "linux")]
    fn is_unsupported(err: &io::Error) -> bool {
        matches!(
            err.raw_os_error(),
            Some(libc::ENOSYS)
                | Some(libc::EOPNOTSUPP)
                | Some(libc::EPERM)
                | Some(libc::EINVAL)
                | Some(libc::ENODEV)
                | Some(libc::EAFNOSUPPORT)
        )
    }

    #[cfg(target_os = "linux")]
    impl From<afxdp::mmap_area::MmapError> for XdpInitError {
        fn from(_e: afxdp::mmap_area::MmapError) -> Self {
            XdpInitError::Mmap
        }
    }

    #[cfg(target_os = "linux")]
    impl From<afxdp::umem::UmemNewError> for XdpInitError {
        fn from(e: afxdp::umem::UmemNewError) -> Self {
            match e {
                afxdp::umem::UmemNewError::RingNotPowerOfTwo => XdpInitError::InvalidRing,
                afxdp::umem::UmemNewError::Create(err) => {
                    if is_unsupported(&err) {
                        XdpInitError::Unsupported
                    } else {
                        XdpInitError::Umem(err)
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl From<afxdp::socket::SocketNewError> for XdpInitError {
        fn from(e: afxdp::socket::SocketNewError) -> Self {
            match e {
                afxdp::socket::SocketNewError::RingNotPowerOfTwo => XdpInitError::InvalidRing,
                afxdp::socket::SocketNewError::Create(err) => {
                    if is_unsupported(&err) {
                        XdpInitError::Unsupported
                    } else {
                        XdpInitError::Socket(err)
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn init_state(iface: &str) -> Result<XdpState, XdpInitError> {
        const BUF_NUM: usize = 4096;
        const BUF_LEN: usize = 2048;
        let (area, mut bufs) =
            MmapArea::new(BUF_NUM, BUF_LEN, MmapAreaOptions { huge_tlb: false })?;
        let (umem, mut cq, mut fq) =
            Umem::new(area, XSK_RING_CONS__DEFAULT_NUM_DESCS, XSK_RING_PROD__DEFAULT_NUM_DESCS)?;
        let (_socket, rx, tx) = Socket::new(
            umem.clone(),
            iface,
            0,
            XSK_RING_CONS__DEFAULT_NUM_DESCS,
            XSK_RING_PROD__DEFAULT_NUM_DESCS,
            SocketOptions::default(),
        )?;
        let _ = fq.fill(&mut bufs, bufs.len());
        Ok(XdpState { rx, tx, fq, cq, pool: bufs, pending: ArrayDeque::new() })
    }

    #[cfg(target_os = "linux")]
    fn infer_iface(addr: &SocketAddr) -> String {
        if let Ok(iface) = std::env::var("XDP_IFACE") {
            return iface;
        }
        if addr.ip().is_loopback() {
            "lo".to_string()
        } else {
            "eth0".to_string()
        }
    }

    #[cfg(target_os = "linux")]
    impl XdpSocket {
        pub fn new_udp(bind: SocketAddr, remote: SocketAddr) -> io::Result<Self> {
            let socket = std::net::UdpSocket::bind(bind)?;
            socket.connect(remote)?;
            socket.set_nonblocking(true)?;
            crate::telemetry::XDP_ACTIVE.store(0, std::sync::atomic::Ordering::Relaxed);
            Ok(Self { udp: socket, state: None })
        }

        pub fn new(bind: SocketAddr, remote: SocketAddr) -> io::Result<Self> {
            let udp = std::net::UdpSocket::bind(bind)?;
            udp.connect(remote)?;
            udp.set_nonblocking(true)?;

            let iface = infer_iface(&bind);
            match init_state(&iface) {
                Ok(state) => {
                    crate::telemetry::XDP_ACTIVE.store(1, std::sync::atomic::Ordering::Relaxed);
                    Ok(Self { udp, state: Some(state) })
                }
                Err(XdpInitError::Unsupported) => {
                    crate::telemetry::XDP_FALLBACKS.inc();
                    crate::telemetry::XDP_ACTIVE.store(0, std::sync::atomic::Ordering::Relaxed);
                    Ok(Self { udp, state: None })
                }
                Err(e) => {
                    crate::telemetry::XDP_FALLBACKS.inc();
                    crate::telemetry::XDP_ACTIVE.store(0, std::sync::atomic::Ordering::Relaxed);
                    log::warn!("XDP initialization failed: {e}");
                    Ok(Self { udp, state: None })
                }
            }
        }

        pub fn reconfigure(&mut self, bind: SocketAddr, remote: SocketAddr) -> io::Result<()> {
            self.state.take();
            let udp = std::net::UdpSocket::bind(bind)?;
            udp.connect(remote)?;
            udp.set_nonblocking(true)?;

            let iface = infer_iface(&bind);
            match init_state(&iface) {
                Ok(state) => {
                    self.udp = udp;
                    self.state = Some(state);
                    crate::telemetry::XDP_ACTIVE.store(1, std::sync::atomic::Ordering::Relaxed);
                    Ok(())
                }
                Err(XdpInitError::Unsupported) => {
                    crate::telemetry::XDP_FALLBACKS.inc();
                    crate::telemetry::XDP_ACTIVE.store(0, std::sync::atomic::Ordering::Relaxed);
                    self.udp = udp;
                    Ok(())
                }
                Err(e) => {
                    crate::telemetry::XDP_FALLBACKS.inc();
                    crate::telemetry::XDP_ACTIVE.store(0, std::sync::atomic::Ordering::Relaxed);
                    log::warn!("XDP reconfigure failed: {e}");
                    self.udp = udp;
                    Ok(())
                }
            }
        }

        fn fd(&self) -> RawFd {
            self.udp.as_raw_fd()
        }

        pub fn send(&mut self, buffers: &[&[u8]]) -> io::Result<usize> {
            use std::time::Instant;
            if let Some(state) = self.state.as_mut() {
                let start = Instant::now();
                if let Some(mut b) = state.pool.pop() {
                    let len = buffers.iter().map(|b| b.len()).sum::<usize>();
                    let data = buffers[0];
                    let copy_len = len.min(b.data.len());
                    b.data[..copy_len].copy_from_slice(&data[..copy_len]);
                    b.set_len(copy_len as u16);
                    let _ = state.pending.push_back(b);
                    // Adaptive batch size based on pending depth (cap via env)
                    let cap = std::env::var("QUICFUSCATE_XDP_BATCH")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(8usize);
                    let to_send = core::cmp::min(state.pending.len(), core::cmp::max(1, cap));
                    // Telemetry: queue depth
                    crate::optimize::telemetry::XDP_THROUGHPUT.set(state.pending.len() as i64);
                    let result = state.tx.try_send(&mut state.pending, to_send);
                    let sent = result.unwrap_or(0);
                    let _ = state.cq.service(&mut state.pool, sent);
                    if sent == 1 {
                        // telemetry!(telemetry::XDP_BYTES_SENT.inc_by(copy_len as u64));
                        // telemetry!(telemetry::XDP_SEND_LATENCY.inc_by(start.elapsed().as_micros() as u64));
                        let tput = (copy_len as u64 * 8 * 1_000_000)
                            / start.elapsed().as_micros().max(1) as u64;
                        // telemetry!(telemetry::XDP_THROUGHPUT.set((tput / 1_000_000) as i64));
                        return Ok(copy_len);
                    } else if result.is_err() {
                        crate::telemetry::XDP_FALLBACKS.inc();
                        crate::telemetry::XDP_ACTIVE.store(0, std::sync::atomic::Ordering::Relaxed);
                        self.state = None;
                    }
                    state.pool.extend(state.pending.drain(..));
                }
            }
            let zc = ZeroCopyBuffer::new(buffers);
            let ret = zc.send(self.fd());
            if ret < 0 {
                Err(Error::last_os_error())
            } else {
                // telemetry!(telemetry::BYTES_SENT.inc_by(ret as u64));
                Ok(ret as usize)
            }
        }

        pub fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            use std::time::Instant;
            if let Some(state) = self.state.as_mut() {
                let start = Instant::now();
                let mut recvq: ArrayDeque<[BufMmap<[u8; 2048]>; PENDING_LEN], Wrapping> =
                    ArrayDeque::new();
                match state.rx.try_recv(&mut recvq, 1, [0u8; 2048]) {
                    Ok(n) if n > 0 => {
                        if let Some(mut b) = recvq.pop_front() {
                            let len = b.get_len() as usize;
                            let copy_len = len.min(buf.len());
                            buf[..copy_len].copy_from_slice(&b.data[..copy_len]);
                            let mut temp = vec![b];
                            let _ = state.fq.fill(&mut temp, 1);
                            // telemetry!(telemetry::XDP_BYTES_RECEIVED.inc_by(copy_len as u64));
                            // telemetry!(telemetry::XDP_RECV_LATENCY.inc_by(start.elapsed().as_micros() as u64));
                            let tput = (copy_len as u64 * 8 * 1_000_000)
                                / start.elapsed().as_micros().max(1) as u64;
                            // telemetry!(telemetry::XDP_THROUGHPUT.set((tput / 1_000_000) as i64));
                            return Ok(copy_len);
                        }
                    }
                    Err(_) => {
                        crate::telemetry::XDP_FALLBACKS.inc();
                        crate::telemetry::XDP_ACTIVE.store(0, std::sync::atomic::Ordering::Relaxed);
                        self.state = None;
                    }
                    _ => {}
                }
            }
            let mut slice = [&mut buf[..]];
            let mut zc = ZeroCopyBuffer::new_mut(&mut slice);
            let ret = zc.recv(self.fd());
            if ret < 0 {
                Err(Error::last_os_error())
            } else {
                // telemetry!(telemetry::BYTES_RECEIVED.inc_by(ret as u64));
                Ok(ret as usize)
            }
        }

        pub fn update_remote(&mut self, remote: SocketAddr) -> io::Result<()> {
            self.udp.connect(remote)
        }

        pub fn is_active(&self) -> bool {
            self.state.is_some()
        }

        /// Batch send multiple datagrams via sendmmsg (fallback to loop on error)
        pub fn send_batch(&self, packets: &[&[u8]]) -> io::Result<usize> {
            match zc_batch::sendmmsg(self.fd(), packets) {
                Ok(n) => Ok(n),
                Err(_) => {
                    // Fallback
                    let mut sent = 0usize;
                    for p in packets {
                        let zc = ZeroCopyBuffer::new(core::slice::from_ref(p));
                        let rc = zc.send(self.fd());
                        if rc < 0 {
                            return Err(Error::last_os_error());
                        }
                        sent += 1;
                    }
                    Ok(sent)
                }
            }
        }

        /// Batch receive multiple datagrams via recvmmsg (fallback to single recv)
        pub fn recv_batch(&mut self, bufs: &mut [&mut [u8]]) -> io::Result<usize> {
            match zc_batch::recvmmsg(self.fd(), bufs) {
                Ok(n) if n > 0 => Ok(n),
                _ => {
                    if bufs.is_empty() {
                        return Ok(0);
                    }
                    let mut zc = ZeroCopyBuffer::new_mut(core::slice::from_mut(&mut bufs[0]));
                    let rc = zc.recv(self.fd());
                    if rc < 0 {
                        Err(Error::last_os_error())
                    } else {
                        Ok(1)
                    }
                }
            }
        }
    }

    #[cfg(unix)]
    impl XdpSocket {
        pub fn new(bind_addr: SocketAddr, remote_addr: SocketAddr) -> io::Result<Self> {
            let socket = std::net::UdpSocket::bind(bind_addr)?;
            socket.connect(remote_addr)?;
            socket.set_nonblocking(true)?;
            crate::telemetry::XDP_ACTIVE.store(0, std::sync::atomic::Ordering::Relaxed);
            Ok(Self { socket })
        }

        pub fn new_udp(bind_addr: SocketAddr, remote_addr: SocketAddr) -> io::Result<Self> {
            Self::new(bind_addr, remote_addr)
        }

        pub fn is_active(&self) -> bool {
            false
        }

        fn fd(&self) -> RawFd {
            self.socket.as_raw_fd()
        }

        pub fn send(&self, buffers: &[&[u8]]) -> io::Result<usize> {
            #[cfg(target_os = "linux")]
            {
                if buffers.len() > 1 {
                    // Try batch send first
                    match zc_batch::sendmmsg(self.fd(), buffers) {
                        Ok(n) if n > 0 => {
                            let bytes: usize = buffers.iter().take(n).map(|b| b.len()).sum();
                            return Ok(bytes);
                        }
                        _ => { /* fall through to single sendmsg */ }
                    }
                }
            }
            let zc = ZeroCopyBuffer::new(buffers);
            let ret = zc.send(self.fd());
            if ret < 0 {
                Err(Error::last_os_error())
            } else {
                Ok(ret as usize)
            }
        }

        pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            let mut slice = [&mut buf[..]];
            let mut zc = ZeroCopyBuffer::new_mut(&mut slice);
            let ret = zc.recv(self.fd());
            if ret < 0 {
                Err(Error::last_os_error())
            } else {
                // telemetry!(telemetry::BYTES_RECEIVED.inc_by(ret as u64));
                Ok(ret as usize)
            }
        }

        pub fn update_remote(&self, remote: SocketAddr) -> io::Result<()> {
            self.socket.connect(remote)
        }

        pub fn reconfigure(
            &mut self,
            bind_addr: SocketAddr,
            remote_addr: SocketAddr,
        ) -> io::Result<()> {
            let socket = std::net::UdpSocket::bind(bind_addr)?;
            socket.connect(remote_addr)?;
            socket.set_nonblocking(true)?;
            self.socket = socket;
            Ok(())
        }
    }

    #[cfg(not(unix))]
    impl XdpSocket {
        pub fn new(_bind: SocketAddr, _remote: SocketAddr) -> io::Result<Self> {
            use std::io::ErrorKind;
            Err(Error::new(ErrorKind::Other, "XDP sockets not supported"))
        }

        pub fn update_remote(&self, _remote: SocketAddr) -> io::Result<()> {
            use std::io::ErrorKind;
            Err(Error::new(ErrorKind::Other, "XDP sockets not supported"))
        }

        pub fn reconfigure(&mut self, _bind: SocketAddr, _remote: SocketAddr) -> io::Result<()> {
            use std::io::ErrorKind;
            Err(Error::new(ErrorKind::Other, "XDP sockets not supported"))
        }

        pub fn new_udp(_bind: SocketAddr, _remote: SocketAddr) -> io::Result<Self> {
            use std::io::ErrorKind;
            Err(Error::new(ErrorKind::Other, "XDP sockets not supported"))
        }

        pub fn is_active(&self) -> bool {
            false
        }
    }

    impl XdpSocket {
        pub fn is_supported() -> bool {
            false
        }
    }
}

// ============================================================================
// ZEROCOPY - Ultra-optimized kernel bypass
// ============================================================================

pub mod zerocopy {
    use libc;
    use std::net::{SocketAddr, UdpSocket};
    use std::sync::Arc;

    /// MSG_ZEROCOPY flag for Linux 5.0+
    #[cfg(target_os = "linux")]
    const MSG_ZEROCOPY: libc::c_int = 0x4000000;
    #[cfg(not(target_os = "linux"))]
    #[allow(dead_code)]
    const MSG_ZEROCOPY: libc::c_int = 0;
    const ZEROCOPY_THRESHOLD: usize = 10240;

    pub struct ZeroCopySocket {
        sock: Arc<UdpSocket>,
        enabled: bool,
        profile: super::CpuProfile,
    }

    impl ZeroCopySocket {
        pub fn new(sock: UdpSocket) -> Self {
            let detector = super::FeatureDetector::instance();
            let profile = detector.profile();

            // Enable zerocopy based on profile
            let enabled = match profile {
                // High-end: always enable
                super::CpuProfile::X86_P3a
                | super::CpuProfile::X86_P3b
                | super::CpuProfile::X86_P3c
                | super::CpuProfile::X86_P3d
                | super::CpuProfile::X86_P3e
                | super::CpuProfile::X86_P4a
                | super::CpuProfile::X86_P4b => true,

                // Mid-range: enable for large packets
                super::CpuProfile::X86_P2a
                | super::CpuProfile::X86_P2b
                | super::CpuProfile::Apple_M => true,

                // Low-end: disable to save CPU
                _ => false,
            };

            Self { sock: Arc::new(sock), enabled, profile }
        }

        #[inline(always)]
        pub fn send_zerocopy(&self, data: &[u8], addr: SocketAddr) -> std::io::Result<usize> {
            // Profile-optimized thresholds
            let threshold = match self.profile {
                super::CpuProfile::X86_P3a
                | super::CpuProfile::X86_P3b
                | super::CpuProfile::X86_P3c
                | super::CpuProfile::X86_P3d
                | super::CpuProfile::X86_P3e
                | super::CpuProfile::X86_P4a
                | super::CpuProfile::X86_P4b => 4096, // Aggressive

                super::CpuProfile::X86_P2a | super::CpuProfile::X86_P2b => 8192, // Balanced

                _ => ZEROCOPY_THRESHOLD, // Conservative
            };

            if !self.enabled || data.len() < threshold {
                return self.sock.send_to(data, addr);
            }

            unsafe { self.send_zerocopy_impl(data, addr) }
        }

        #[cfg(target_os = "linux")]
        unsafe fn send_zerocopy_impl(
            &self,
            data: &[u8],
            addr: SocketAddr,
        ) -> std::io::Result<usize> {
            let mut msg: libc::msghdr = std::mem::zeroed();
            let iov = libc::iovec { iov_base: data.as_ptr() as *mut _, iov_len: data.len() };

            // Convert SocketAddr to sockaddr
            let (addr_ptr, addr_len) = match addr {
                SocketAddr::V4(v4) => {
                    let mut sa: libc::sockaddr_in = std::mem::zeroed();
                    sa.sin_family = libc::AF_INET as libc::sa_family_t;
                    sa.sin_port = v4.port().to_be();
                    sa.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
                    (
                        &sa as *const _ as *const libc::sockaddr,
                        std::mem::size_of_val(&sa) as libc::socklen_t,
                    )
                }
                SocketAddr::V6(v6) => {
                    let mut sa: libc::sockaddr_in6 = std::mem::zeroed();
                    sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                    sa.sin6_port = v6.port().to_be();
                    sa.sin6_flowinfo = v6.flowinfo();
                    sa.sin6_addr.s6_addr = v6.ip().octets();
                    sa.sin6_scope_id = v6.scope_id();
                    (
                        &sa as *const _ as *const libc::sockaddr,
                        std::mem::size_of_val(&sa) as libc::socklen_t,
                    )
                }
            };

            msg.msg_name = addr_ptr as *mut _;
            msg.msg_namelen = addr_len;
            msg.msg_iov = &iov as *const _ as *mut _;
            msg.msg_iovlen = 1;

            // GSO for packet batching
            let mut control = [0u8; 64];
            let mut cmsg_buf = std::mem::align_to::<_, libc::cmsghdr>(control.as_mut_slice()).1;

            if !cmsg_buf.is_empty() {
                let cmsg = &mut cmsg_buf[0] as *mut libc::cmsghdr;
                (*cmsg).cmsg_level = libc::SOL_UDP;
                (*cmsg).cmsg_type = libc::UDP_SEGMENT;
                (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as u32) as usize;

                // Profile-optimized GSO size
                let gso_size: u16 = match self.profile {
                    super::CpuProfile::X86_P3a
                    | super::CpuProfile::X86_P3b
                    | super::CpuProfile::X86_P3c
                    | super::CpuProfile::X86_P3d
                    | super::CpuProfile::X86_P3e
                    | super::CpuProfile::X86_P4a
                    | super::CpuProfile::X86_P4b => 1400, // Jumbo
                    _ => 1200, // Standard QUIC
                };

                let data_ptr = libc::CMSG_DATA(cmsg) as *mut u16;
                *data_ptr = gso_size;

                msg.msg_control = control.as_mut_ptr() as *mut _;
                msg.msg_controllen = (*cmsg).cmsg_len;
            }

            // Send with MSG_ZEROCOPY + MSG_DONTWAIT
            let flags = MSG_ZEROCOPY | libc::MSG_DONTWAIT;
            let sent = libc::sendmsg(self.sock.as_raw_fd(), &msg, flags);

            if sent < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    return Ok(0);
                }
                return Err(err);
            }

            Ok(sent as usize)
        }

        #[cfg(not(target_os = "linux"))]
        unsafe fn send_zerocopy_impl(
            &self,
            data: &[u8],
            addr: SocketAddr,
        ) -> std::io::Result<usize> {
            // Fallback for non-Linux
            self.sock.send_to(data, addr)
        }
    }
}

// ============================================================================
// Memory Pool Implementation
// ============================================================================

pub mod simd {
    // use super::telemetry; // Unused
    use super::{FeatureDetector, SimdDispatch};

    // ========================================================================
    // CORE OPS - Generic SIMD operations used across modules
    // ========================================================================
    pub mod core {
        use super::super::telemetry;
        use super::super::{FeatureDetector, SimdDispatch};

        /// Central XOR blocks implementation - used by FEC, Crypto, everywhere!
        #[inline(always)]
        pub fn xor_blocks(dst: &mut [u8], src: &[u8]) {
            SimdDispatch::xor_blocks(dst, src);
        }

        /// Central fast memcpy - used by Transport, everywhere!
        #[inline(always)]
        pub fn memcpy_fast(dst: &mut [u8], src: &[u8]) {
            SimdDispatch::memcpy_fast(dst, src);
        }

        /// Central prefetch - optimizes cache usage everywhere!
        #[inline(always)]
        pub fn prefetch_read(data: &[u8]) {
            SimdDispatch::prefetch_read(data);
        }

        /// Central population count - used for statistics, pattern matching
        #[inline(always)]
        pub fn popcnt(data: &[u8]) -> usize {
            SimdDispatch::popcnt(data)
        }

        /// Ultra-fast CRC32 computation with hardware acceleration
        #[inline(always)]
        pub fn crc32(data: &[u8], initial: u32) -> u32 {
            let features = FeatureDetector::instance().features_full();

            #[cfg(target_arch = "x86_64")]
            if features.sse42 {
                return unsafe { crc32_sse42(data, initial) };
            }

            #[cfg(target_arch = "aarch64")]
            if features.crc32 {
                return unsafe { crc32_armv8(data, initial) };
            }

            crc32_scalar(data, initial)
        }

        /// XOR payload with a repeating 32-byte key using optimal SIMD.
        /// The key must have length 32.
        #[inline(always)]
        pub fn xor_repeating_key_32(dst: &mut [u8], key32: &[u8; 32]) {
            let features = FeatureDetector::instance().features_full();

            #[cfg(target_arch = "x86_64")]
            unsafe {
                if features.avx2 {
                    return xor_repeating_key32_avx2(dst, key32);
                }
                if features.sse2 {
                    return xor_repeating_key32_sse2(dst, key32);
                }
            }

            #[cfg(target_arch = "aarch64")]
            unsafe {
                if features.sve2 {
                    return xor_repeating_key32_sve2(dst, key32);
                }
                if features.neon {
                    return xor_repeating_key32_neon(dst, key32);
                }
            }

            // Scalar fallback
            let mut i = 0usize;
            let n = dst.len();
            while i < n {
                let take = (n - i).min(32);
                for j in 0..take {
                    dst[i + j] ^= key32[j];
                }
                i += take;
            }
        }

        /// XOR payload with a repeating key of arbitrary length and start offset.
        #[inline(always)]
        pub fn xor_repeating_key(dst: &mut [u8], key: &[u8], start: usize) {
            if key.is_empty() || dst.is_empty() {
                return;
            }

            if key.len() == 32 && start.is_multiple_of(32) {
                if let Ok(k32) = <&[u8; 32]>::try_from(key) {
                    xor_repeating_key_32(dst, k32);
                    return;
                }
            }

            let features = FeatureDetector::instance().features_full();
            let start_mod = start % key.len();

            #[cfg(target_arch = "x86_64")]
            unsafe {
                if features.avx2 {
                    xor_repeating_key_generic_avx2(dst, key, start_mod);
                    return;
                }
                if features.sse2 {
                    xor_repeating_key_generic_sse2(dst, key, start_mod);
                    return;
                }
            }

            #[cfg(target_arch = "aarch64")]
            unsafe {
                if features.sve2 {
                    xor_repeating_key_generic_sve2(dst, key, start_mod);
                    return;
                }
                if features.neon {
                    xor_repeating_key_generic_neon(dst, key, start_mod);
                    return;
                }
            }

            xor_repeating_key_scalar(dst, key, start_mod);
        }

        // x86_64 backends
        #[cfg(target_arch = "x86_64")]
        #[target_feature(enable = "avx2")]
        unsafe fn xor_repeating_key32_avx2(dst: &mut [u8], key32: &[u8; 32]) {
            use std::arch::x86_64::*;
            let key_vec = _mm256_loadu_si256(key32.as_ptr() as *const __m256i);
            let mut i = 0usize;
            let n = dst.len();
            while i + 32 <= n {
                let data = _mm256_loadu_si256(dst.as_ptr().add(i) as *const __m256i);
                let result = _mm256_xor_si256(data, key_vec);
                _mm256_storeu_si256(dst.as_mut_ptr().add(i) as *mut __m256i, result);
                i += 32;
            }
            while i < n {
                *dst.get_unchecked_mut(i) ^= key32[i % 32];
                i += 1;
            }
        }

        #[cfg(target_arch = "x86_64")]
        #[target_feature(enable = "sse2")]
        unsafe fn xor_repeating_key32_sse2(dst: &mut [u8], key32: &[u8; 32]) {
            use std::arch::x86_64::*;
            let key_low = _mm_loadu_si128(key32.as_ptr() as *const __m128i);
            let key_high = _mm_loadu_si128(key32.as_ptr().add(16) as *const __m128i);
            let mut i = 0usize;
            let n = dst.len();
            while i + 32 <= n {
                let data_low = _mm_loadu_si128(dst.as_ptr().add(i) as *const __m128i);
                let data_high = _mm_loadu_si128(dst.as_ptr().add(i + 16) as *const __m128i);
                let result_low = _mm_xor_si128(data_low, key_low);
                let result_high = _mm_xor_si128(data_high, key_high);
                _mm_storeu_si128(dst.as_mut_ptr().add(i) as *mut __m128i, result_low);
                _mm_storeu_si128(dst.as_mut_ptr().add(i + 16) as *mut __m128i, result_high);
                i += 32;
            }
            while i < n {
                *dst.get_unchecked_mut(i) ^= key32[i % 32];
                i += 1;
            }
        }

        // aarch64 backend
        #[cfg(target_arch = "aarch64")]
        #[target_feature(enable = "neon")]
        unsafe fn xor_repeating_key32_neon(dst: &mut [u8], key32: &[u8; 32]) {
            xor_repeating_key_generic_neon(dst, key32, 0);
        }

        #[cfg(target_arch = "aarch64")]
        unsafe fn xor_repeating_key32_sve2(dst: &mut [u8], key32: &[u8; 32]) {
            #[cfg(target_feature = "sve2")]
            {
                xor_repeating_key32_sve2_impl(dst, key32);
                return;
            }

            #[cfg(not(target_feature = "sve2"))]
            {
                xor_repeating_key32_neon(dst, key32);
            }
        }

        #[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
        #[target_feature(enable = "sve2")]
        unsafe fn xor_repeating_key32_sve2_impl(dst: &mut [u8], key32: &[u8; 32]) {
            xor_repeating_key_generic_sve2_impl(dst, key32, 0);
        }

        #[cfg(target_arch = "x86_64")]
        #[target_feature(enable = "avx2")]
        unsafe fn xor_repeating_key_generic_avx2(dst: &mut [u8], key: &[u8], start: usize) {
            use std::arch::x86_64::*;

            debug_assert!(!key.is_empty());
            let key_len = key.len();
            let mut idx = start % key_len;
            let mut i = 0usize;
            let mut key_buf = [0u8; 32];

            while i + 32 <= dst.len() {
                for lane in key_buf.iter_mut() {
                    *lane = *key.get_unchecked(idx);
                    idx += 1;
                    if idx == key_len {
                        idx = 0;
                    }
                }

                let key_vec = _mm256_loadu_si256(key_buf.as_ptr() as *const __m256i);
                let data_vec = _mm256_loadu_si256(dst.as_ptr().add(i) as *const __m256i);
                let result = _mm256_xor_si256(data_vec, key_vec);
                _mm256_storeu_si256(dst.as_mut_ptr().add(i) as *mut __m256i, result);

                i += 32;
            }

            while i < dst.len() {
                *dst.get_unchecked_mut(i) ^= *key.get_unchecked(idx);
                idx += 1;
                if idx == key_len {
                    idx = 0;
                }
                i += 1;
            }
        }

        #[cfg(target_arch = "x86_64")]
        #[target_feature(enable = "sse2")]
        unsafe fn xor_repeating_key_generic_sse2(dst: &mut [u8], key: &[u8], start: usize) {
            use std::arch::x86_64::*;

            debug_assert!(!key.is_empty());
            let key_len = key.len();
            let mut idx = start % key_len;
            let mut i = 0usize;
            let mut key_buf = [0u8; 16];

            while i + 16 <= dst.len() {
                for lane in key_buf.iter_mut() {
                    *lane = *key.get_unchecked(idx);
                    idx += 1;
                    if idx == key_len {
                        idx = 0;
                    }
                }

                let key_vec = _mm_loadu_si128(key_buf.as_ptr() as *const __m128i);
                let data_vec = _mm_loadu_si128(dst.as_ptr().add(i) as *const __m128i);
                let result = _mm_xor_si128(data_vec, key_vec);
                _mm_storeu_si128(dst.as_mut_ptr().add(i) as *mut __m128i, result);

                i += 16;
            }

            while i < dst.len() {
                *dst.get_unchecked_mut(i) ^= *key.get_unchecked(idx);
                idx += 1;
                if idx == key_len {
                    idx = 0;
                }
                i += 1;
            }
        }

        #[cfg(target_arch = "aarch64")]
        #[target_feature(enable = "neon")]
        unsafe fn xor_repeating_key_generic_neon(dst: &mut [u8], key: &[u8], start: usize) {
            use std::arch::aarch64::*;

            debug_assert!(!key.is_empty());
            let key_len = key.len();
            let mut idx = start % key_len;
            let mut i = 0usize;
            let mut key_buf = [0u8; 16];

            while i + 16 <= dst.len() {
                for lane in key_buf.iter_mut() {
                    *lane = *key.get_unchecked(idx);
                    idx += 1;
                    if idx == key_len {
                        idx = 0;
                    }
                }

                let key_vec = vld1q_u8(key_buf.as_ptr());
                let data_vec = vld1q_u8(dst.as_ptr().add(i));
                let result = veorq_u8(data_vec, key_vec);
                vst1q_u8(dst.as_mut_ptr().add(i), result);

                i += 16;
            }

            while i < dst.len() {
                *dst.get_unchecked_mut(i) ^= *key.get_unchecked(idx);
                idx += 1;
                if idx == key_len {
                    idx = 0;
                }
                i += 1;
            }
        }

        #[cfg(target_arch = "aarch64")]
        unsafe fn xor_repeating_key_generic_sve2(dst: &mut [u8], key: &[u8], start: usize) {
            #[cfg(target_feature = "sve2")]
            {
                xor_repeating_key_generic_sve2_impl(dst, key, start);
                return;
            }

            #[cfg(not(target_feature = "sve2"))]
            {
                xor_repeating_key_generic_neon(dst, key, start);
            }
        }

        #[cfg(all(target_arch = "aarch64", target_feature = "sve2"))]
        #[target_feature(enable = "sve2")]
        unsafe fn xor_repeating_key_generic_sve2_impl(dst: &mut [u8], key: &[u8], start: usize) {
            use std::arch::aarch64::*;

            debug_assert!(!key.is_empty());

            const MAX_SVE_BYTES: usize = 256;
            let len = dst.len();
            let vl = svcntb() as usize;
            debug_assert!(vl <= MAX_SVE_BYTES);

            let key_len = key.len();
            let mut idx = start % key_len;
            let mut offset = 0usize;
            let mut key_buf = [0u8; MAX_SVE_BYTES];

            while offset < len {
                let remaining = len - offset;
                let take = remaining.min(vl);
                let pg = svwhilelt_b8(0, take as u64);

                for lane in 0..take {
                    key_buf[lane] = *key.get_unchecked(idx);
                    idx += 1;
                    if idx == key_len {
                        idx = 0;
                    }
                }

                let key_vec = svld1_u8(pg, key_buf.as_ptr());
                let data_vec = svld1_u8(pg, dst.as_ptr().add(offset));
                let result = sveor_u8_m(pg, data_vec, key_vec);
                svst1_u8(pg, dst.as_mut_ptr().add(offset), result);

                offset += take;
            }
        }

        #[inline(always)]
        fn xor_repeating_key_scalar(dst: &mut [u8], key: &[u8], start: usize) {
            let key_len = key.len();
            let mut idx = start % key_len;
            for byte in dst.iter_mut() {
                *byte ^= key[idx];
                idx += 1;
                if idx == key_len {
                    idx = 0;
                }
            }
        }

        /// Ultra-fast CRC32 with SSE4.2 hardware acceleration (x86_64)
        #[cfg(target_arch = "x86_64")]
        #[target_feature(enable = "sse4.2")]
        #[inline]
        unsafe fn crc32_sse42(data: &[u8], mut crc: u32) -> u32 {
            use std::arch::x86_64::*;

            crc = !crc; // CRC32 uses inverted initial value
            let mut i = 0;
            let len = data.len();

            // Process 8 bytes at a time with CRC32 instruction
            while i + 8 <= len {
                let chunk = u64::from_le_bytes([
                    data[i],
                    data[i + 1],
                    data[i + 2],
                    data[i + 3],
                    data[i + 4],
                    data[i + 5],
                    data[i + 6],
                    data[i + 7],
                ]);
                crc = _mm_crc32_u64(crc as u64, chunk) as u32;
                i += 8;
            }

            // Process 4 bytes
            if i + 4 <= len {
                let chunk = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
                crc = _mm_crc32_u32(crc, chunk);
                i += 4;
            }

            // Process remaining bytes
            while i < len {
                crc = _mm_crc32_u8(crc, data[i]);
                i += 1;
            }

            telemetry::CRC32_SSE42_OPS.inc();
            !crc // Return with final inversion
        }

        /// Ultra-fast CRC32 with ARMv8 CRC32 instructions (aarch64)
        #[cfg(target_arch = "aarch64")]
        #[target_feature(enable = "crc")]
        unsafe fn crc32_armv8(data: &[u8], mut crc: u32) -> u32 {
            use std::arch::aarch64::*;

            crc = !crc; // CRC32 uses inverted initial value
            let mut i = 0;
            let len = data.len();

            // Process 8 bytes at a time with CRC32X instruction
            while i + 8 <= len {
                let chunk = u64::from_le_bytes([
                    data[i],
                    data[i + 1],
                    data[i + 2],
                    data[i + 3],
                    data[i + 4],
                    data[i + 5],
                    data[i + 6],
                    data[i + 7],
                ]);
                crc = __crc32d(crc, chunk);
                i += 8;
            }

            // Process 4 bytes
            if i + 4 <= len {
                let chunk = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
                crc = __crc32w(crc, chunk);
                i += 4;
            }

            // Process 2 bytes
            if i + 2 <= len {
                let chunk = u16::from_le_bytes([data[i], data[i + 1]]);
                crc = __crc32h(crc, chunk);
                i += 2;
            }

            // Process remaining byte
            if i < len {
                crc = __crc32b(crc, data[i]);
            }

            telemetry::CRC32_ARM_OPS.inc();
            !crc // Return with final inversion
        }

        /// Scalar CRC32 fallback implementation
        #[inline(always)]
        fn crc32_scalar(data: &[u8], mut crc: u32) -> u32 {
            // CRC32 polynomial: 0x04C11DB7 (Ethernet, PNG, etc.)
            const CRC32_TABLE: [u32; 256] = generate_crc32_table();

            crc = !crc; // CRC32 uses inverted initial value

            for &byte in data {
                let table_idx = ((crc ^ byte as u32) & 0xFF) as usize;
                crc = (crc >> 8) ^ CRC32_TABLE[table_idx];
            }

            telemetry::CRC32_SCALAR_OPS.inc();
            !crc // Return with final inversion
        }

        /// Generate CRC32 lookup table at compile time
        const fn generate_crc32_table() -> [u32; 256] {
            let mut table = [0u32; 256];
            let mut i = 0;

            while i < 256 {
                let mut crc = i as u32;
                let mut j = 0;

                while j < 8 {
                    if crc & 1 != 0 {
                        crc = (crc >> 1) ^ 0xEDB88320; // Reversed polynomial
                    } else {
                        crc >>= 1;
                    }
                    j += 1;
                }

                table[i] = crc;
                i += 1;
            }

            table
        }
    }

    /// Central memcpy with prefetch - used by Transport module
    #[inline(always)]
    pub fn memcpy_prefetch(dst: &mut [u8], src: &[u8]) {
        SimdDispatch::memcpy_fast(dst, src);
    }

    // ========================================================================
    // GALOIS FIELD OPS - For FEC (Reed-Solomon, etc.)
    // ========================================================================
    pub mod galois {
        #[cfg(target_arch = "x86_64")]
        use super::super::telemetry;
        #[allow(unused_imports)]
        use super::FeatureDetector;
        /// GF(2^8) multiplication with best available SIMD
        #[inline(always)]
        pub fn gf_mul(a: &[u8], b: u8, dst: &mut [u8]) {
            let features = FeatureDetector::instance().features_full();

            #[cfg(target_arch = "x86_64")]
            if features.gfni && features.avx512f {
                return unsafe { gf_mul_avx512_gfni(a, b, dst) };
            }

            #[cfg(target_arch = "x86_64")]
            if features.avx2 {
                return unsafe { gf_mul_avx2(a, b, dst) };
            }

            #[cfg(target_arch = "aarch64")]
            if features.sve2 {
                return unsafe { gf_mul_sve2(a, b, dst) };
            }

            #[cfg(target_arch = "aarch64")]
            if features.neon {
                return unsafe { gf_mul_neon(a, b, dst) };
            }

            gf_mul_scalar(a, b, dst);
        }

        /// GF(2^8) multiplication with AVX-512 GFNI - 15x faster!
        #[cfg(target_arch = "x86_64")]
        #[target_feature(enable = "avx512f")]
        #[target_feature(enable = "gfni")]
        #[inline]
        unsafe fn gf_mul_avx512_gfni(a: &[u8], b: u8, dst: &mut [u8]) {
            use std::arch::x86_64::*;

            let b_broadcast = _mm512_set1_epi8(b as i8);
            let len = a.len().min(dst.len());
            let mut i = 0;

            // Process 64 bytes at once with AVX-512 GFNI
            while i + 64 <= len {
                let data = _mm512_loadu_si512(a[i..].as_ptr() as *const __m512i);
                let result = _mm512_gf2p8mul_epi8(data, b_broadcast);
                _mm512_storeu_si512(dst[i..].as_mut_ptr() as *mut __m512i, result);
                i += 64;
            }

            // Handle remainder
            while i < len {
                dst[i] = gf_mul_byte(a[i], b);
                i += 1;
            }

            telemetry::FEC_AVX512_OPS.inc();
        }

        /// GF(2^8) multiplication with AVX2 - 5x faster with correct galois field arithmetic
        #[cfg(target_arch = "x86_64")]
        #[target_feature(enable = "avx2")]
        unsafe fn gf_mul_avx2(a: &[u8], b: u8, dst: &mut [u8]) {
            use std::arch::x86_64::*;

            let len = a.len().min(dst.len());
            let mut i = 0;

            // Precompute GF multiplication tables for multiplier b
            let mut lo_table = [0u8; 16];
            let mut hi_table = [0u8; 16];

            for j in 0..16 {
                lo_table[j] = gf_mul_byte(j as u8, b);
                hi_table[j] = gf_mul_byte((j << 4) as u8, b);
            }

            // Load lookup tables into AVX2 registers
            let lo_lut =
                _mm256_broadcastsi128_si256(_mm_loadu_si128(lo_table.as_ptr() as *const __m128i));
            let hi_lut =
                _mm256_broadcastsi128_si256(_mm_loadu_si128(hi_table.as_ptr() as *const __m128i));
            let nibble_mask = _mm256_set1_epi8(0x0F);

            // Process 32 bytes at once
            while i + 32 <= len {
                let data = _mm256_loadu_si256(a[i..].as_ptr() as *const __m256i);

                // Split into low and high nibbles
                let lo_nibbles = _mm256_and_si256(data, nibble_mask);
                let hi_nibbles = _mm256_and_si256(_mm256_srli_epi16(data, 4), nibble_mask);

                // Table lookup for both nibbles
                let lo_result = _mm256_shuffle_epi8(lo_lut, lo_nibbles);
                let hi_result = _mm256_shuffle_epi8(hi_lut, hi_nibbles);

                // XOR the results (GF addition)
                let result = _mm256_xor_si256(lo_result, hi_result);
                _mm256_storeu_si256(dst[i..].as_mut_ptr() as *mut __m256i, result);
                i += 32;
            }

            // Process remainder with scalar
            while i < len {
                dst[i] = gf_mul_byte(a[i], b);
                i += 1;
            }

            telemetry::FEC_AVX2_OPS.inc();
        }

        /// Scalar GF multiplication fallback
        #[inline(always)]
        fn gf_mul_scalar(a: &[u8], b: u8, dst: &mut [u8]) {
            for i in 0..a.len().min(dst.len()) {
                dst[i] = gf_mul_byte(a[i], b);
            }
        }

        /// Shared NEON implementation used by both NEON and SVE2 frontends.
        #[cfg(target_arch = "aarch64")]
        #[target_feature(enable = "neon")]
        unsafe fn gf_mul_neon_impl(a: &[u8], b: u8, dst: &mut [u8]) {
            use std::arch::aarch64::*;

            let len = a.len().min(dst.len());
            let mut i = 0;

            // Precompute GF multiplication tables for multiplier b
            let mut lo_table = [0u8; 16];
            let mut hi_table = [0u8; 16];

            for j in 0..16 {
                lo_table[j] = gf_mul_byte(j as u8, b);
                hi_table[j] = gf_mul_byte((j << 4) as u8, b);
            }

            // Load lookup tables into NEON registers
            let lo_lut = vld1q_u8(lo_table.as_ptr());
            let hi_lut = vld1q_u8(hi_table.as_ptr());
            let nibble_mask = vdupq_n_u8(0x0F);

            // Process 16 bytes at once with NEON
            while i + 16 <= len {
                let data = vld1q_u8(a[i..].as_ptr());

                // Split into low and high nibbles
                let lo_nibbles = vandq_u8(data, nibble_mask);
                let hi_nibbles = vandq_u8(vshrq_n_u8(data, 4), nibble_mask);

                // Table lookup for both nibbles using NEON table lookup
                let lo_result = vqtbl1q_u8(lo_lut, lo_nibbles);
                let hi_result = vqtbl1q_u8(hi_lut, hi_nibbles);

                // XOR the results (GF addition)
                let result = veorq_u8(lo_result, hi_result);
                vst1q_u8(dst[i..].as_mut_ptr(), result);
                i += 16;
            }

            // Process remainder with scalar
            while i < len {
                dst[i] = gf_mul_byte(a[i], b);
                i += 1;
            }
        }

        /// GF(2^8) multiplication with NEON - 8x faster than scalar!
        #[cfg(target_arch = "aarch64")]
        #[target_feature(enable = "neon")]
        unsafe fn gf_mul_neon(a: &[u8], b: u8, dst: &mut [u8]) {
            gf_mul_neon_impl(a, b, dst);
            crate::optimize::telemetry::FEC_NEON_OPS.inc();
        }

        /// GF(2^8) multiplication with SVE2 - scalable vector processing!
        #[cfg(target_arch = "aarch64")]
        unsafe fn gf_mul_sve2(a: &[u8], b: u8, dst: &mut [u8]) {
            #[cfg(target_feature = "sve2")]
            {
                use std::arch::aarch64::*;

                let len = core::cmp::min(a.len(), dst.len());
                let mut offset = 0usize;
                let poly = svdup_n_u8(0x1B);
                let msb_mask = svdup_n_u8(0x80);
                let zero = svdup_n_u8(0);

                while offset < len {
                    let pg = svwhilelt_b8(offset as u64, len as u64);
                    let mut multiplicand = svld1_u8(pg, a.as_ptr().add(offset));
                    let mut acc = svdup_n_u8(0);
                    let mut factor = b;

                    for _ in 0..8 {
                        if (factor & 1) != 0 {
                            acc = sveor_u8_m(pg, acc, acc, multiplicand);
                        }

                        let high_bits =
                            svcmpne_u8(pg, svand_u8_z(pg, multiplicand, msb_mask), zero);
                        let doubled = svadd_u8_x(pg, multiplicand, multiplicand);
                        let reduced = sveor_u8_m(high_bits, doubled, doubled, poly);
                        multiplicand = reduced;
                        factor >>= 1;
                    }

                    svst1_u8(pg, dst.as_mut_ptr().add(offset), acc);
                    offset += svcntb() as usize;
                }

                crate::optimize::telemetry::FEC_SVE2_OPS.inc();
                return;
            }

            gf_mul_neon(a, b, dst)
        }

        /// Single byte GF multiplication
        #[inline(always)]
        fn gf_mul_byte(a: u8, b: u8) -> u8 {
            let mut result = 0u8;
            let mut aa = a;
            let mut bb = b;

            while bb != 0 {
                if bb & 1 != 0 {
                    result ^= aa;
                }
                let hi_bit = aa & 0x80;
                aa <<= 1;
                if hi_bit != 0 {
                    aa ^= 0x1B; // AES polynomial
                }
                bb >>= 1;
            }
            result
        }
    }

    // ========================================================================
    // CRYPTO OPS - For AEGIS, AES, ChaCha, etc.
    // ========================================================================
    pub mod crypto {
        #[cfg(target_arch = "x86_64")]
        use std::sync::{Mutex, OnceLock};
        // use super::telemetry; // Unused
        #[allow(unused_imports)]
        use super::FeatureDetector;

        #[cfg(target_arch = "x86_64")]
        static CHACHA20_X4_OVERRIDE: OnceLock<Option<String>> = OnceLock::new();
        #[cfg(target_arch = "x86_64")]
        static TEST_CHACHA20_X4_OVERRIDE: Mutex<Option<String>> = Mutex::new(None);

        #[cfg(target_arch = "x86_64")]
        pub fn __test_set_chacha20_x4_override(val: Option<&str>) {
            let mut guard = TEST_CHACHA20_X4_OVERRIDE.lock().unwrap();
            *guard = val.map(|s| s.to_lowercase());
        }

        #[cfg(target_arch = "x86_64")]
        #[inline(always)]
        fn chacha20_x4_override() -> Option<String> {
            if let Some(mode) = TEST_CHACHA20_X4_OVERRIDE.lock().unwrap().clone() {
                return Some(mode);
            }

            CHACHA20_X4_OVERRIDE
                .get_or_init(|| {
                    std::env::var("QUICFUSCATE_CHACHA20_X4").ok().map(|v| v.to_lowercase())
                })
                .clone()
        }

        #[inline(always)]
        fn chacha20_blocks_x4_scalar(
            key: &[u8; 32],
            nonce: &[u8; 12],
            counter: u32,
        ) -> [[u8; 64]; 4] {
            use crate::crypto::chacha::chacha20_block;
            [
                chacha20_block(key, counter, nonce),
                chacha20_block(key, counter.wrapping_add(1), nonce),
                chacha20_block(key, counter.wrapping_add(2), nonce),
                chacha20_block(key, counter.wrapping_add(3), nonce),
            ]
        }

        /// AES round with best available SIMD
        #[inline(always)]
        pub fn aes_round(state: &mut [u8; 16], round_key: &[u8; 16]) {
            #[cfg(all(target_arch = "x86_64", target_feature = "vaes"))]
            {
                let features = FeatureDetector::instance().features_full();
                if features.avx512f {
                    return unsafe { aes_round_vaes(state, round_key) };
                }
            }

            #[cfg(all(target_arch = "x86_64", target_feature = "aes"))]
            {
                let features = FeatureDetector::instance().features_full();
                if features.aes {
                    return unsafe { aes_round_aesni(state, round_key) };
                }
            }

            aes_round_scalar(state, round_key);
        }

        /// ChaCha20 XOR (stream cipher) with centralized SIMD XOR writeback.
        /// WARNING: For TLS Cover/bench only. Not used for payload encryption per policy.
        #[inline(always)]
        pub fn chacha20_xor_in_place(
            dst: &mut [u8],
            key: &[u8; 32],
            nonce: &[u8; 12],
            counter: u32,
        ) {
            use crate::crypto::chacha::chacha20_block;
            let mut ctr = counter;
            let n = dst.len();
            let mut i = 0usize;
            while i < n {
                let block = chacha20_block(key, ctr, nonce);
                ctr = ctr.wrapping_add(1);
                let take = (n - i).min(64);
                unsafe {
                    xor_slice_simd(&mut dst[i..i + take], &block[..take]);
                }
                i += take;
            }
        }

        /// Produce 4 ChaCha20 keystream blocks starting at `counter`..`counter+3`.
        /// Runtime-Dispatch hook present; currently uses 4x scalar fallback for correctness.
        /// For TLS Cover/bench only.
        #[inline(always)]
        pub fn chacha20_blocks_x4(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [[u8; 64]; 4] {
            let features = FeatureDetector::instance().features_full();
            #[cfg(target_arch = "x86_64")]
            if let Some(mode) = chacha20_x4_override() {
                match mode.as_str() {
                    "scalar" | "ref" => {
                        crate::optimize::telemetry::CHACHA20_X4_SCALAR_OPS.inc();
                        return chacha20_blocks_x4_scalar(key, nonce, counter);
                    }
                    "auto" => {
                        // fall back to standard detection without warning
                    }
                    "avx2" => {
                        if features.avx2 {
                            crate::optimize::telemetry::CHACHA20_X4_AVX2_OPS.inc();
                            return unsafe { chacha20_blocks_x4_avx2(key, nonce, counter) };
                        }
                        log::warn!("CHACHA20_X4 override requested AVX2 but feature unavailable; falling back");
                    }
                    "avx" => {
                        if features.avx {
                            crate::optimize::telemetry::CHACHA20_X4_AVX_OPS.inc();
                            return unsafe { chacha20_blocks_x4_avx(key, nonce, counter) };
                        }
                        log::warn!("CHACHA20_X4 override requested AVX but feature unavailable; falling back");
                    }
                    "sse" | "sse41" | "ssse3" => {
                        if features.sse41 && features.ssse3 {
                            crate::optimize::telemetry::CHACHA20_X4_SSE41_OPS.inc();
                            return unsafe { chacha20_blocks_x4_sse41(key, nonce, counter) };
                        }
                        log::warn!(
                            "CHACHA20_X4 override requested SSE4.1/SSSE3 but feature unavailable; falling back"
                        );
                    }
                    other => {
                        log::warn!("unknown CHACHA20_X4 override '{}'; ignoring", other);
                    }
                }
            }
            #[cfg(target_arch = "x86_64")]
            {
                if features.avx2 {
                    crate::optimize::telemetry::CHACHA20_X4_AVX2_OPS.inc();
                    return unsafe { chacha20_blocks_x4_avx2(key, nonce, counter) };
                } else if features.avx {
                    crate::optimize::telemetry::CHACHA20_X4_AVX_OPS.inc();
                    return unsafe { chacha20_blocks_x4_avx(key, nonce, counter) };
                } else if features.sse41 && features.ssse3 {
                    crate::optimize::telemetry::CHACHA20_X4_SSE41_OPS.inc();
                    return unsafe { chacha20_blocks_x4_sse41(key, nonce, counter) };
                }
            }
            #[cfg(target_arch = "aarch64")]
            {
                if features.neon {
                    crate::optimize::telemetry::CHACHA20_X4_NEON_OPS.inc();
                    return unsafe { chacha20_blocks_x4_neon(key, nonce, counter) };
                }
            }
            // Fallback scalar 4x
            crate::optimize::telemetry::CHACHA20_X4_SCALAR_OPS.inc();
            chacha20_blocks_x4_scalar(key, nonce, counter)
        }

        /// Produce 16 ChaCha20 keystream blocks (AVX-512) starting at `counter`..`counter+15`.
        /// Falls back to scalar generation if AVX-512F is unavailable.
        #[inline(always)]
        pub fn chacha20_blocks_x16(
            key: &[u8; 32],
            nonce: &[u8; 12],
            counter: u32,
        ) -> [[u8; 64]; 16] {
            #[cfg(target_arch = "x86_64")]
            {
                let features = FeatureDetector::instance().features_full();
                if features.avx512f {
                    return unsafe { chacha20_blocks_x16_avx512(key, nonce, counter) };
                }
            }
            // Fallback scalar 16x
            use crate::crypto::chacha::chacha20_block;
            [
                chacha20_block(key, counter.wrapping_add(0), nonce),
                chacha20_block(key, counter.wrapping_add(1), nonce),
                chacha20_block(key, counter.wrapping_add(2), nonce),
                chacha20_block(key, counter.wrapping_add(3), nonce),
                chacha20_block(key, counter.wrapping_add(4), nonce),
                chacha20_block(key, counter.wrapping_add(5), nonce),
                chacha20_block(key, counter.wrapping_add(6), nonce),
                chacha20_block(key, counter.wrapping_add(7), nonce),
                chacha20_block(key, counter.wrapping_add(8), nonce),
                chacha20_block(key, counter.wrapping_add(9), nonce),
                chacha20_block(key, counter.wrapping_add(10), nonce),
                chacha20_block(key, counter.wrapping_add(11), nonce),
                chacha20_block(key, counter.wrapping_add(12), nonce),
                chacha20_block(key, counter.wrapping_add(13), nonce),
                chacha20_block(key, counter.wrapping_add(14), nonce),
                chacha20_block(key, counter.wrapping_add(15), nonce),
            ]
        }

        #[cfg(target_arch = "x86_64")]
        #[target_feature(enable = "avx512f")]
        unsafe fn chacha20_blocks_x16_avx512(
            key: &[u8; 32],
            nonce: &[u8; 12],
            counter: u32,
        ) -> [[u8; 64]; 16] {
            use std::arch::x86_64::*;

            // Constants
            let c0 = _mm512_set1_epi32(0x61707865u32 as i32);
            let c1 = _mm512_set1_epi32(0x3320646eu32 as i32);
            let c2 = _mm512_set1_epi32(0x79622d32u32 as i32);
            let c3 = _mm512_set1_epi32(0x6b206574u32 as i32);

            // Key broadcast per word
            let load_u32 = |i: usize| -> i32 {
                i32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]])
            };
            let k0 = _mm512_set1_epi32(load_u32(0));
            let k1 = _mm512_set1_epi32(load_u32(1));
            let k2 = _mm512_set1_epi32(load_u32(2));
            let k3 = _mm512_set1_epi32(load_u32(3));
            let k4 = _mm512_set1_epi32(load_u32(4));
            let k5 = _mm512_set1_epi32(load_u32(5));
            let k6 = _mm512_set1_epi32(load_u32(6));
            let k7 = _mm512_set1_epi32(load_u32(7));

            // Nonce broadcast
            let n0 =
                _mm512_set1_epi32(i32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]));
            let n1 =
                _mm512_set1_epi32(i32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]));
            let n2 =
                _mm512_set1_epi32(i32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]));

            // Counter lanes [ctr..ctr+15]
            let mut ctr_arr = [0i32; 16];
            for i in 0..16 {
                ctr_arr[i] = counter.wrapping_add(i as u32) as i32;
            }
            let ctrv = _mm512_loadu_si512(ctr_arr.as_ptr() as *const __m512i);

            // State vectors (SOA across 16 blocks)
            let mut x0 = c0;
            let mut x1 = c1;
            let mut x2 = c2;
            let mut x3 = c3;
            let mut x4 = k0;
            let mut x5 = k1;
            let mut x6 = k2;
            let mut x7 = k3;
            let mut x8 = k4;
            let mut x9 = k5;
            let mut x10 = k6;
            let mut x11 = k7;
            let mut x12 = ctrv;
            let mut x13 = n0;
            let mut x14 = n1;
            let mut x15 = n2;

            // Save initial state
            let (i0, i1, i2, i3, i4, i5, i6, i7, i8, i9, i10, i11, i12s, i13s, i14s, i15s) =
                (x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15);

            #[inline(always)]
            unsafe fn rotl32(v: __m512i, n: i32) -> __m512i {
                let n = ((n as u32) & 31) as i32;
                if n == 0 {
                    return v;
                }
                let cnt = _mm_cvtsi32_si128(n);
                let l = _mm512_sll_epi32(v, cnt);
                let r = _mm512_srl_epi32(v, _mm_cvtsi32_si128(32 - n));
                _mm512_or_si512(l, r)
            }
            #[inline(always)]
            unsafe fn qr(a: &mut __m512i, b: &mut __m512i, c: &mut __m512i, d: &mut __m512i) {
                *a = _mm512_add_epi32(*a, *b);
                *d = _mm512_xor_si512(*d, *a);
                *d = rotl32(*d, 16);
                *c = _mm512_add_epi32(*c, *d);
                *b = _mm512_xor_si512(*b, *c);
                *b = rotl32(*b, 12);
                *a = _mm512_add_epi32(*a, *b);
                *d = _mm512_xor_si512(*d, *a);
                *d = rotl32(*d, 8);
                *c = _mm512_add_epi32(*c, *d);
                *b = _mm512_xor_si512(*b, *c);
                *b = rotl32(*b, 7);
            }

            // 10 double rounds
            for _ in 0..10 {
                // Column rounds
                qr(&mut x0, &mut x4, &mut x8, &mut x12);
                qr(&mut x1, &mut x5, &mut x9, &mut x13);
                qr(&mut x2, &mut x6, &mut x10, &mut x14);
                qr(&mut x3, &mut x7, &mut x11, &mut x15);
                // Diagonal rounds
                qr(&mut x0, &mut x5, &mut x10, &mut x15);
                qr(&mut x1, &mut x6, &mut x11, &mut x12);
                qr(&mut x2, &mut x7, &mut x8, &mut x13);
                qr(&mut x3, &mut x4, &mut x9, &mut x14);
            }

            // Feed-forward
            x0 = _mm512_add_epi32(x0, i0);
            x1 = _mm512_add_epi32(x1, i1);
            x2 = _mm512_add_epi32(x2, i2);
            x3 = _mm512_add_epi32(x3, i3);
            x4 = _mm512_add_epi32(x4, i4);
            x5 = _mm512_add_epi32(x5, i5);
            x6 = _mm512_add_epi32(x6, i6);
            x7 = _mm512_add_epi32(x7, i7);
            x8 = _mm512_add_epi32(x8, i8);
            x9 = _mm512_add_epi32(x9, i9);
            x10 = _mm512_add_epi32(x10, i10);
            x11 = _mm512_add_epi32(x11, i11);
            x12 = _mm512_add_epi32(x12, i12s);
            x13 = _mm512_add_epi32(x13, i13s);
            x14 = _mm512_add_epi32(x14, i14s);
            x15 = _mm512_add_epi32(x15, i15s);

            // Serialize 16 lanes into 16 blocks
            let mut out = [[0u8; 64]; 16];
            let mut tmp: [i32; 16] = [0; 16];
            macro_rules! store_lane {
                ($vec:expr, $w:expr) => {{
                    _mm512_storeu_si512(tmp.as_mut_ptr() as *mut __m512i, $vec);
                    for l in 0..16 {
                        let bytes = (tmp[l] as u32).to_le_bytes();
                        out[l][($w * 4)..($w * 4 + 4)].copy_from_slice(&bytes);
                    }
                }};
            }
            store_lane!(x0, 0);
            store_lane!(x1, 1);
            store_lane!(x2, 2);
            store_lane!(x3, 3);
            store_lane!(x4, 4);
            store_lane!(x5, 5);
            store_lane!(x6, 6);
            store_lane!(x7, 7);
            store_lane!(x8, 8);
            store_lane!(x9, 9);
            store_lane!(x10, 10);
            store_lane!(x11, 11);
            store_lane!(x12, 12);
            store_lane!(x13, 13);
            store_lane!(x14, 14);
            store_lane!(x15, 15);
            out
        }

        #[cfg(target_arch = "x86_64")]
        #[inline(always)]
        unsafe fn chacha20_blocks_x4_sse_core(
            key: &[u8; 32],
            nonce: &[u8; 12],
            counter: u32,
        ) -> [[u8; 64]; 4] {
            use std::arch::x86_64::*;
            // Load constants
            let c0 = _mm_set1_epi32(0x61707865u32 as i32);
            let c1 = _mm_set1_epi32(0x3320646eu32 as i32);
            let c2 = _mm_set1_epi32(0x79622d32u32 as i32);
            let c3 = _mm_set1_epi32(0x6b206574u32 as i32);
            // Load key into 8 words (k0..k7), broadcast across 4 lanes by packing elements per lane
            let load_u32 = |i: usize| -> i32 {
                i32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]])
            };
            let k0 = _mm_set1_epi32(load_u32(0));
            let k1 = _mm_set1_epi32(load_u32(1));
            let k2 = _mm_set1_epi32(load_u32(2));
            let k3 = _mm_set1_epi32(load_u32(3));
            let k4 = _mm_set1_epi32(load_u32(4));
            let k5 = _mm_set1_epi32(load_u32(5));
            let k6 = _mm_set1_epi32(load_u32(6));
            let k7 = _mm_set1_epi32(load_u32(7));
            // Nonce
            let n0 = _mm_set1_epi32(i32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]));
            let n1 = _mm_set1_epi32(i32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]));
            let n2 = _mm_set1_epi32(i32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]));
            // Counter lanes
            let ctr0 = _mm_set_epi32(
                (counter + 3) as i32,
                (counter + 2) as i32,
                (counter + 1) as i32,
                counter as i32,
            );

            // State words (SOA across 4 blocks)
            let mut x0 = c0;
            let mut x1 = c1;
            let mut x2 = c2;
            let mut x3 = c3;
            let mut x4 = k0;
            let mut x5 = k1;
            let mut x6 = k2;
            let mut x7 = k3;
            let mut x8 = k4;
            let mut x9 = k5;
            let mut x10 = k6;
            let mut x11 = k7;
            let mut x12 = ctr0;
            let mut x13 = n0;
            let mut x14 = n1;
            let mut x15 = n2;

            // Save initial state for feed-forward
            let (i0, i1, i2, i3, i4, i5, i6, i7, i8, i9, i10, i11, i12s, i13s, i14s, i15s) =
                (x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15);

            #[inline(always)]
            unsafe fn rotl32(v: __m128i, n: i32) -> __m128i {
                use std::arch::x86_64::*;
                let n = ((n as u32) & 31) as i32;
                if n == 0 {
                    return v;
                }
                let cnt = _mm_cvtsi32_si128(n);
                let l = _mm_sll_epi32(v, cnt);
                let r = _mm_srl_epi32(v, _mm_cvtsi32_si128(32 - n));
                _mm_or_si128(l, r)
            }
            #[inline(always)]
            unsafe fn qr(a: &mut __m128i, b: &mut __m128i, c: &mut __m128i, d: &mut __m128i) {
                use std::arch::x86_64::*;
                *a = _mm_add_epi32(*a, *b);
                *d = _mm_xor_si128(*d, *a);
                *d = rotl32(*d, 16);
                *c = _mm_add_epi32(*c, *d);
                *b = _mm_xor_si128(*b, *c);
                *b = rotl32(*b, 12);
                *a = _mm_add_epi32(*a, *b);
                *d = _mm_xor_si128(*d, *a);
                *d = rotl32(*d, 8);
                *c = _mm_add_epi32(*c, *d);
                *b = _mm_xor_si128(*b, *c);
                *b = rotl32(*b, 7);
            }
            // 10 double rounds
            for _ in 0..10 {
                // Column rounds
                qr(&mut x0, &mut x4, &mut x8, &mut x12);
                qr(&mut x1, &mut x5, &mut x9, &mut x13);
                qr(&mut x2, &mut x6, &mut x10, &mut x14);
                qr(&mut x3, &mut x7, &mut x11, &mut x15);
                // Diagonal rounds
                qr(&mut x0, &mut x5, &mut x10, &mut x15);
                qr(&mut x1, &mut x6, &mut x11, &mut x12);
                qr(&mut x2, &mut x7, &mut x8, &mut x13);
                qr(&mut x3, &mut x4, &mut x9, &mut x14);
            }
            // Feed-forward
            x0 = _mm_add_epi32(x0, i0);
            x1 = _mm_add_epi32(x1, i1);
            x2 = _mm_add_epi32(x2, i2);
            x3 = _mm_add_epi32(x3, i3);
            x4 = _mm_add_epi32(x4, i4);
            x5 = _mm_add_epi32(x5, i5);
            x6 = _mm_add_epi32(x6, i6);
            x7 = _mm_add_epi32(x7, i7);
            x8 = _mm_add_epi32(x8, i8);
            x9 = _mm_add_epi32(x9, i9);
            x10 = _mm_add_epi32(x10, i10);
            x11 = _mm_add_epi32(x11, i11);
            x12 = _mm_add_epi32(x12, i12s);
            x13 = _mm_add_epi32(x13, i13s);
            x14 = _mm_add_epi32(x14, i14s);
            x15 = _mm_add_epi32(x15, i15s);

            // Serialize per-lane into 4 blocks of 64 bytes
            let mut out = [[0u8; 64]; 4];
            // helper to store a vector into 4 u32 words for each lane index l
            macro_rules! store_lane {
                ($vec:expr, $w:expr) => {{
                    let mut tmp = [0i32; 4];
                    _mm_storeu_si128(tmp.as_mut_ptr() as *mut __m128i, $vec);
                    for l in 0..4 {
                        let bytes = (tmp[l] as u32).to_le_bytes();
                        out[l][($w * 4)..($w * 4 + 4)].copy_from_slice(&bytes);
                    }
                }};
            }
            store_lane!(x0, 0);
            store_lane!(x1, 1);
            store_lane!(x2, 2);
            store_lane!(x3, 3);
            store_lane!(x4, 4);
            store_lane!(x5, 5);
            store_lane!(x6, 6);
            store_lane!(x7, 7);
            store_lane!(x8, 8);
            store_lane!(x9, 9);
            store_lane!(x10, 10);
            store_lane!(x11, 11);
            store_lane!(x12, 12);
            store_lane!(x13, 13);
            store_lane!(x14, 14);
            store_lane!(x15, 15);
            out
        }

        #[cfg(target_arch = "x86_64")]
        #[target_feature(enable = "avx2")]
        unsafe fn chacha20_blocks_x4_avx2(
            key: &[u8; 32],
            nonce: &[u8; 12],
            counter: u32,
        ) -> [[u8; 64]; 4] {
            chacha20_blocks_x4_sse_core(key, nonce, counter)
        }

        #[cfg(target_arch = "x86_64")]
        #[target_feature(enable = "avx", enable = "sse4.1", enable = "ssse3")]
        unsafe fn chacha20_blocks_x4_avx(
            key: &[u8; 32],
            nonce: &[u8; 12],
            counter: u32,
        ) -> [[u8; 64]; 4] {
            chacha20_blocks_x4_sse_core(key, nonce, counter)
        }

        #[cfg(target_arch = "x86_64")]
        #[target_feature(enable = "sse4.1", enable = "ssse3")]
        unsafe fn chacha20_blocks_x4_sse41(
            key: &[u8; 32],
            nonce: &[u8; 12],
            counter: u32,
        ) -> [[u8; 64]; 4] {
            chacha20_blocks_x4_sse_core(key, nonce, counter)
        }

        #[cfg(target_arch = "aarch64")]
        #[target_feature(enable = "neon")]
        unsafe fn chacha20_blocks_x4_neon(
            key: &[u8; 32],
            nonce: &[u8; 12],
            counter: u32,
        ) -> [[u8; 64]; 4] {
            use std::arch::aarch64::*;
            // Constants
            let c0 = vdupq_n_u32(0x61707865);
            let c1 = vdupq_n_u32(0x3320646e);
            let c2 = vdupq_n_u32(0x79622d32);
            let c3 = vdupq_n_u32(0x6b206574);
            // Key
            let k = |i: usize| {
                u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]])
            };
            let k0 = vdupq_n_u32(k(0));
            let k1 = vdupq_n_u32(k(1));
            let k2 = vdupq_n_u32(k(2));
            let k3 = vdupq_n_u32(k(3));
            let k4 = vdupq_n_u32(k(4));
            let k5 = vdupq_n_u32(k(5));
            let k6 = vdupq_n_u32(k(6));
            let k7 = vdupq_n_u32(k(7));
            // Nonce
            let n0 = vdupq_n_u32(u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]));
            let n1 = vdupq_n_u32(u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]));
            let n2 = vdupq_n_u32(u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]));
            // Counter lanes: [ctr,ctr+1,ctr+2,ctr+3]
            let ctr_vec = vld1q_u32(
                [
                    counter,
                    counter.wrapping_add(1),
                    counter.wrapping_add(2),
                    counter.wrapping_add(3),
                ]
                .as_ptr(),
            );

            let mut x0 = c0;
            let mut x1 = c1;
            let mut x2 = c2;
            let mut x3 = c3;
            let mut x4 = k0;
            let mut x5 = k1;
            let mut x6 = k2;
            let mut x7 = k3;
            let mut x8 = k4;
            let mut x9 = k5;
            let mut x10 = k6;
            let mut x11 = k7;
            let mut x12 = ctr_vec;
            let mut x13 = n0;
            let mut x14 = n1;
            let mut x15 = n2;
            // Save initial
            let (i0, i1, i2, i3, i4, i5, i6, i7, i8, i9, i10, i11, i12, i13, i14, i15) =
                (x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15);

            #[inline(always)]
            unsafe fn qr(
                a: &mut uint32x4_t,
                b: &mut uint32x4_t,
                c: &mut uint32x4_t,
                d: &mut uint32x4_t,
            ) {
                // rotl32(x,16)
                *a = vaddq_u32(*a, *b);
                *d = veorq_u32(*d, *a);
                *d = vorrq_u32(vshlq_n_u32(*d, 16), vshrq_n_u32(*d, 16));
                // rotl32(x,12)
                *c = vaddq_u32(*c, *d);
                *b = veorq_u32(*b, *c);
                *b = vorrq_u32(vshlq_n_u32(*b, 12), vshrq_n_u32(*b, 20));
                // rotl32(x,8)
                *a = vaddq_u32(*a, *b);
                *d = veorq_u32(*d, *a);
                *d = vorrq_u32(vshlq_n_u32(*d, 8), vshrq_n_u32(*d, 24));
                // rotl32(x,7)
                *c = vaddq_u32(*c, *d);
                *b = veorq_u32(*b, *c);
                *b = vorrq_u32(vshlq_n_u32(*b, 7), vshrq_n_u32(*b, 25));
            }
            for _ in 0..10 {
                // double rounds
                qr(&mut x0, &mut x4, &mut x8, &mut x12);
                qr(&mut x1, &mut x5, &mut x9, &mut x13);
                qr(&mut x2, &mut x6, &mut x10, &mut x14);
                qr(&mut x3, &mut x7, &mut x11, &mut x15);
                qr(&mut x0, &mut x5, &mut x10, &mut x15);
                qr(&mut x1, &mut x6, &mut x11, &mut x12);
                qr(&mut x2, &mut x7, &mut x8, &mut x13);
                qr(&mut x3, &mut x4, &mut x9, &mut x14);
            }
            // Feed-forward
            x0 = vaddq_u32(x0, i0);
            x1 = vaddq_u32(x1, i1);
            x2 = vaddq_u32(x2, i2);
            x3 = vaddq_u32(x3, i3);
            x4 = vaddq_u32(x4, i4);
            x5 = vaddq_u32(x5, i5);
            x6 = vaddq_u32(x6, i6);
            x7 = vaddq_u32(x7, i7);
            x8 = vaddq_u32(x8, i8);
            x9 = vaddq_u32(x9, i9);
            x10 = vaddq_u32(x10, i10);
            x11 = vaddq_u32(x11, i11);
            x12 = vaddq_u32(x12, i12);
            x13 = vaddq_u32(x13, i13);
            x14 = vaddq_u32(x14, i14);
            x15 = vaddq_u32(x15, i15);
            // Serialize
            let mut out = [[0u8; 64]; 4];
            let mut tmp: [u32; 4] = [0; 4];
            macro_rules! store {
                ($v:expr,$w:expr) => {{
                    vst1q_u32(tmp.as_mut_ptr(), $v);
                    for l in 0..4 {
                        let b = tmp[l].to_le_bytes();
                        out[l][($w * 4)..($w * 4 + 4)].copy_from_slice(&b);
                    }
                }};
            }
            store!(x0, 0);
            store!(x1, 1);
            store!(x2, 2);
            store!(x3, 3);
            store!(x4, 4);
            store!(x5, 5);
            store!(x6, 6);
            store!(x7, 7);
            store!(x8, 8);
            store!(x9, 9);
            store!(x10, 10);
            store!(x11, 11);
            store!(x12, 12);
            store!(x13, 13);
            store!(x14, 14);
            store!(x15, 15);
            out
        }

        /// SIMD-accelerated XOR of two byte slices (dst ^= src), supports any length.
        #[inline(always)]
        unsafe fn xor_slice_simd(dst: &mut [u8], src: &[u8]) {
            debug_assert_eq!(dst.len(), src.len());
            let len = dst.len();
            let mut i = 0usize;
            let features = FeatureDetector::instance().features_full();

            #[cfg(target_arch = "x86_64")]
            {
                if features.avx2 {
                    use std::arch::x86_64::*;
                    while i + 32 <= len {
                        let a = _mm256_loadu_si256(dst.as_ptr().add(i) as *const __m256i);
                        let b = _mm256_loadu_si256(src.as_ptr().add(i) as *const __m256i);
                        let r = _mm256_xor_si256(a, b);
                        _mm256_storeu_si256(dst.as_mut_ptr().add(i) as *mut __m256i, r);
                        i += 32;
                    }
                } else if features.sse2 {
                    use std::arch::x86_64::*;
                    while i + 16 <= len {
                        let a = _mm_loadu_si128(dst.as_ptr().add(i) as *const __m128i);
                        let b = _mm_loadu_si128(src.as_ptr().add(i) as *const __m128i);
                        let r = _mm_xor_si128(a, b);
                        _mm_storeu_si128(dst.as_mut_ptr().add(i) as *mut __m128i, r);
                        i += 16;
                    }
                }
            }

            #[cfg(target_arch = "aarch64")]
            {
                if features.neon {
                    use std::arch::aarch64::*;
                    while i + 16 <= len {
                        let a = vld1q_u8(dst.as_ptr().add(i));
                        let b = vld1q_u8(src.as_ptr().add(i));
                        let r = veorq_u8(a, b);
                        vst1q_u8(dst.as_mut_ptr().add(i), r);
                        i += 16;
                    }
                }
            }

            while i < len {
                *dst.get_unchecked_mut(i) ^= *src.get_unchecked(i);
                i += 1;
            }
        }

        /// AES round with AES-NI
        #[cfg(all(target_arch = "x86_64", target_feature = "aes"))]
        #[inline(always)]
        unsafe fn aes_round_aesni(state: &mut [u8; 16], round_key: &[u8; 16]) {
            use std::arch::x86_64::*;

            let s = _mm_loadu_si128(state.as_ptr() as *const __m128i);
            let k = _mm_loadu_si128(round_key.as_ptr() as *const __m128i);
            let result = _mm_aesenc_si128(s, k);
            _mm_storeu_si128(state.as_mut_ptr() as *mut __m128i, result);
        }

        /// VAES for parallel AES rounds (AVX-512)
        #[cfg(all(target_arch = "x86_64", target_feature = "vaes"))]
        #[inline(always)]
        unsafe fn aes_round_vaes(state: &mut [u8; 16], round_key: &[u8; 16]) {
            // Fallback to AES-NI for single block
            aes_round_aesni(state, round_key);
        }

        /// Scalar AES round fallback
        fn aes_round_scalar(state: &mut [u8; 16], round_key: &[u8; 16]) {
            for i in 0..16 {
                state[i] ^= round_key[i];
            }
        }
    }

    // ========================================================================
    // PATTERN OPS - For stealth pattern matching
    // ========================================================================
    pub mod pattern {
        // use super::telemetry; // Unused
        #[allow(unused_imports)]
        use super::FeatureDetector;

        /// String search with best available SIMD
        #[inline(always)]
        pub fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
            #[cfg(all(target_arch = "x86_64", target_feature = "avx512vbmi2"))]
            {
                let features = FeatureDetector::instance().features_full();
                if features.avx512f {
                    return unsafe { find_pattern_vbmi2(haystack, needle) };
                }
            }

            #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
            {
                let features = FeatureDetector::instance().features_full();
                if features.avx2 {
                    return unsafe { find_pattern_avx2(haystack, needle) };
                }
            }

            find_pattern_scalar(haystack, needle)
        }

        /// String search with AVX-512 VBMI2
        #[cfg(all(target_arch = "x86_64", target_feature = "avx512vbmi2"))]
        #[inline(always)]
        unsafe fn find_pattern_vbmi2(haystack: &[u8], needle: &[u8]) -> Option<usize> {
            // Fallback to scalar for now
            find_pattern_scalar(haystack, needle)
        }

        /// String search with AVX2
        #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
        #[inline(always)]
        unsafe fn find_pattern_avx2(haystack: &[u8], needle: &[u8]) -> Option<usize> {
            // Fallback to scalar for now
            find_pattern_scalar(haystack, needle)
        }

        /// Scalar pattern search fallback  
        fn find_pattern_scalar(haystack: &[u8], needle: &[u8]) -> Option<usize> {
            haystack.windows(needle.len()).position(|window| window == needle)
        }
    }

    // ========================================================================
    // NEURAL OPS - For brain AI operations
    // ========================================================================
    pub mod neural {
        // use super::telemetry; // Unused
        #[allow(unused_imports)]
        use super::FeatureDetector;

        /// Dot product with best available SIMD
        #[inline(always)]
        pub fn dot_product(a: &[f32], b: &[f32]) -> f32 {
            #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
            {
                let features = FeatureDetector::instance().features_full();
                if features.avx512f {
                    return unsafe { dot_product_avx512(a, b) };
                }
            }

            #[cfg(all(target_arch = "x86_64", target_feature = "fma"))]
            {
                let features = FeatureDetector::instance().features_full();
                if features.fma {
                    return unsafe { dot_product_avx2(a, b) };
                }
            }

            dot_product_scalar(a, b)
        }

        /// Dot product with AVX-512
        #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
        #[inline(always)]
        unsafe fn dot_product_avx512(a: &[f32], b: &[f32]) -> f32 {
            use std::arch::x86_64::*;

            let len = a.len().min(b.len());
            let mut sum = _mm512_setzero_ps();
            let chunks = len / 16;

            for i in 0..chunks {
                let va = _mm512_loadu_ps(a[i * 16..].as_ptr());
                let vb = _mm512_loadu_ps(b[i * 16..].as_ptr());
                sum = _mm512_fmadd_ps(va, vb, sum);
            }

            // Horizontal sum
            _mm512_reduce_add_ps(sum)
        }

        /// Dot product with AVX2 + FMA
        #[cfg(all(target_arch = "x86_64", target_feature = "fma"))]
        #[inline(always)]
        unsafe fn dot_product_avx2(a: &[f32], b: &[f32]) -> f32 {
            use std::arch::x86_64::*;

            let len = a.len().min(b.len());
            let mut sum = _mm256_setzero_ps();
            let chunks = len / 8;

            for i in 0..chunks {
                let va = _mm256_loadu_ps(a[i * 8..].as_ptr());
                let vb = _mm256_loadu_ps(b[i * 8..].as_ptr());
                sum = _mm256_fmadd_ps(va, vb, sum);
            }

            // Horizontal sum
            let sum_array: [f32; 8] = std::mem::transmute(sum);
            sum_array.iter().sum()
        }

        /// Scalar dot product fallback
        fn dot_product_scalar(a: &[f32], b: &[f32]) -> f32 {
            a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
        }
    }

    // ========================================================================
    // COMPRESSION OPS - For zstd, entropy coding
    // ========================================================================
    pub mod compress {
        #[cfg(target_arch = "x86_64")]
        use super::super::telemetry;
        use super::FeatureDetector;

        /// Ultra-fast entropy histogram with best available SIMD acceleration
        #[inline(always)]
        pub fn histogram(data: &[u8]) -> [u32; 256] {
            let features = FeatureDetector::instance().features_full();

            #[cfg(target_arch = "x86_64")]
            {
                if features.avx512vbmi2 && features.avx512bw {
                    return unsafe { histogram_avx512_vbmi2(data) };
                }
                if features.avx512bw {
                    return unsafe { histogram_avx512(data) };
                }
                if features.avx2 {
                    return unsafe { histogram_avx2(data) };
                }
            }

            #[cfg(target_arch = "aarch64")]
            {
                if features.sve2 {
                    return unsafe { histogram_sve2(data) };
                }
                if features.neon {
                    return unsafe { histogram_neon(data) };
                }
            }

            histogram_scalar(data)
        }

        /// Ultra-fast byte pattern search with best available SIMD
        #[inline(always)]
        pub fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
            if needle.is_empty() || needle.len() > haystack.len() {
                return None;
            }

            let features = FeatureDetector::instance().features_full();

            #[cfg(target_arch = "x86_64")]
            {
                if features.avx512vbmi2 && needle.len() <= 64 {
                    return unsafe { find_pattern_avx512_vbmi2(haystack, needle) };
                }
                if features.avx2 && needle.len() <= 32 {
                    return unsafe { find_pattern_avx2(haystack, needle) };
                }
            }

            #[cfg(target_arch = "aarch64")]
            {
                if features.sve2 {
                    return unsafe { find_pattern_sve2(haystack, needle) };
                }
                if features.neon && needle.len() <= 16 {
                    return unsafe { find_pattern_neon(haystack, needle) };
                }
            }

            find_pattern_scalar(haystack, needle)
        }

        /// Ultra-fast histogram with AVX-512 VBMI2 - 64 bytes at once!
        #[cfg(target_arch = "x86_64")]
        #[target_feature(enable = "avx512f,avx512bw,avx512vbmi2")]
        #[inline]
        unsafe fn histogram_avx512_vbmi2(data: &[u8]) -> [u32; 256] {
            use std::arch::x86_64::*;

            let mut hist = [0u32; 256];
            let mut i = 0;
            let len = data.len();

            // Process 64 bytes at once with AVX-512
            while i + 64 <= len {
                let chunk = _mm512_loadu_si512(data.as_ptr().add(i) as *const __m512i);

                let mut tmp = [0u8; 64];
                _mm512_storeu_si512(tmp.as_mut_ptr() as *mut __m512i, chunk);
                for &byte_val in &tmp {
                    hist[byte_val as usize] += 1;
                }

                i += 64;
            }

            // Process remaining bytes
            while i < len {
                hist[data[i] as usize] += 1;
                i += 1;
            }

            telemetry::PATTERN_AVX512_VBMI2_OPS.inc();
            hist
        }

        /// Fast histogram with AVX-512 - 64 bytes at once
        #[cfg(target_arch = "x86_64")]
        #[target_feature(enable = "avx512f,avx512bw")]
        #[inline]
        unsafe fn histogram_avx512(data: &[u8]) -> [u32; 256] {
            use std::arch::x86_64::*;

            let mut hist = [0u32; 256];
            let mut i = 0;
            let len = data.len();

            // Process 64 bytes at once
            while i + 64 <= len {
                let chunk = _mm512_loadu_si512(data.as_ptr().add(i) as *const __m512i);

                let mut tmp = [0u8; 64];
                _mm512_storeu_si512(tmp.as_mut_ptr() as *mut __m512i, chunk);
                for &byte_val in &tmp {
                    hist[byte_val as usize] += 1;
                }

                i += 64;
            }

            // Process remaining bytes
            while i < len {
                hist[data[i] as usize] += 1;
                i += 1;
            }

            telemetry::PATTERN_AVX512_OPS.inc();
            hist
        }

        /// Optimized histogram with AVX2 - 32 bytes at once
        #[cfg(target_arch = "x86_64")]
        #[target_feature(enable = "avx2")]
        #[inline]
        unsafe fn histogram_avx2(data: &[u8]) -> [u32; 256] {
            use std::arch::x86_64::*;

            let mut hist = [0u32; 256];
            let mut i = 0;
            let len = data.len();

            // Process 32 bytes at once
            while i + 32 <= len {
                let chunk = _mm256_loadu_si256(data.as_ptr().add(i) as *const __m256i);

                // _mm256_extract_epi8 requires an immediate index. Store and count bytes from memory.
                let mut tmp = [0u8; 32];
                _mm256_storeu_si256(tmp.as_mut_ptr() as *mut __m256i, chunk);
                for b in tmp {
                    hist[b as usize] += 1;
                }

                i += 32;
            }

            // Process remaining bytes
            while i < len {
                hist[data[i] as usize] += 1;
                i += 1;
            }

            telemetry::PATTERN_AVX2_OPS.inc();
            hist
        }

        /// Ultra-fast histogram with ARM SVE2 - scalable vector width!
        #[cfg(target_arch = "aarch64")]
        unsafe fn histogram_sve2(data: &[u8]) -> [u32; 256] {
            #[cfg(target_feature = "sve2")]
            {
                use std::arch::aarch64::*;

                let mut hist = [0u32; 256];
                let len = data.len();
                let vl = svcntb() as usize;
                let mut offset = 0usize;
                let mut tmp = [0u8; 256];

                debug_assert!(vl <= tmp.len());

                while offset < len {
                    let pg = svwhilelt_b8(offset as u64, len as u64);
                    let vec = svld1_u8(pg, data.as_ptr().add(offset));
                    svst1_u8(pg, tmp.as_mut_ptr(), vec);

                    let active = usize::min(vl, len.saturating_sub(offset));
                    for idx in 0..active {
                        hist[tmp[idx] as usize] += 1;
                    }

                    offset += vl;
                }

                crate::optimize::telemetry::PATTERN_SVE2_OPS.inc();
                return hist;
            }

            histogram_neon(data)
        }

        /// Fast histogram with ARM NEON - 16 bytes at once
        #[cfg(target_arch = "aarch64")]
        #[target_feature(enable = "neon")]
        unsafe fn histogram_neon(data: &[u8]) -> [u32; 256] {
            use std::arch::aarch64::*;

            let mut hist = [0u32; 256];
            let mut i = 0;
            let len = data.len();

            // Process 16 bytes at once
            while i + 16 <= len {
                let chunk = vld1q_u8(data.as_ptr().add(i));
                // Store to a temporary array to avoid const lane index restriction
                let mut tmp: [u8; 16] = [0u8; 16];
                vst1q_u8(tmp.as_mut_ptr(), chunk);
                for &b in &tmp {
                    hist[b as usize] += 1;
                }
                i += 16;
            }

            // Process remaining bytes
            while i < len {
                hist[data[i] as usize] += 1;
                i += 1;
            }

            crate::optimize::telemetry::PATTERN_NEON_OPS.inc();
            hist
        }

        /// Ultra-fast pattern search with AVX-512 VBMI2 - up to 64-byte patterns!
        #[cfg(target_arch = "x86_64")]
        #[target_feature(enable = "avx512f,avx512bw,avx512vbmi2")]
        #[inline]
        unsafe fn find_pattern_avx512_vbmi2(haystack: &[u8], needle: &[u8]) -> Option<usize> {
            use std::arch::x86_64::*;

            if needle.len() > 64 || needle.is_empty() {
                return find_pattern_scalar(haystack, needle);
            }

            let needle_len = needle.len();
            let haystack_len = haystack.len();

            // Create needle pattern vectors
            let mut needle_vec = [0u8; 64];
            needle_vec[..needle_len].copy_from_slice(needle);
            let needle_512 = _mm512_loadu_si512(needle_vec.as_ptr() as *const __m512i);

            let mut i = 0;
            while i + 64 <= haystack_len {
                let haystack_chunk = _mm512_loadu_si512(haystack.as_ptr().add(i) as *const __m512i);

                // Use VBMI2 for efficient comparison and match detection
                let cmp_mask = _mm512_cmpeq_epi8_mask(haystack_chunk, needle_512);

                if cmp_mask != 0 {
                    // Found potential match, verify with scalar comparison
                    for j in 0..64 {
                        if i + j + needle_len <= haystack_len {
                            if &haystack[i + j..i + j + needle_len] == needle {
                                telemetry::PATTERN_AVX512_VBMI2_OPS.inc();
                                return Some(i + j);
                            }
                        }
                    }
                }

                i += 64;
            }

            // Check remaining bytes with scalar
            while i + needle_len <= haystack_len {
                if &haystack[i..i + needle_len] == needle {
                    telemetry::PATTERN_AVX512_VBMI2_OPS.inc();
                    return Some(i);
                }
                i += 1;
            }

            None
        }

        /// Fast pattern search with AVX2 - up to 32-byte patterns
        #[cfg(target_arch = "x86_64")]
        #[target_feature(enable = "avx2")]
        #[inline]
        unsafe fn find_pattern_avx2(haystack: &[u8], needle: &[u8]) -> Option<usize> {
            use std::arch::x86_64::*;

            if needle.len() > 32 || needle.is_empty() {
                return find_pattern_scalar(haystack, needle);
            }

            let needle_len = needle.len();
            let haystack_len = haystack.len();

            // For short patterns, use first byte matching with AVX2
            if needle_len == 1 {
                let needle_first = _mm256_set1_epi8(needle[0] as i8);
                let mut i = 0;

                while i + 32 <= haystack_len {
                    let haystack_chunk =
                        _mm256_loadu_si256(haystack.as_ptr().add(i) as *const __m256i);
                    let cmp_result = _mm256_cmpeq_epi8(haystack_chunk, needle_first);
                    let mask = _mm256_movemask_epi8(cmp_result);

                    if mask != 0 {
                        for bit in 0..32 {
                            if (mask & (1 << bit)) != 0 {
                                telemetry::PATTERN_AVX2_OPS.inc();
                                return Some(i + bit);
                            }
                        }
                    }
                    i += 32;
                }
            }

            // For longer patterns, use scalar verification after first byte match
            let mut i = 0;
            while i + needle_len <= haystack_len {
                if &haystack[i..i + needle_len] == needle {
                    telemetry::PATTERN_AVX2_OPS.inc();
                    return Some(i);
                }
                i += 1;
            }

            None
        }

        /// Ultra-fast pattern search with ARM SVE2 - scalable vector patterns
        #[cfg(target_arch = "aarch64")]
        unsafe fn find_pattern_sve2(haystack: &[u8], needle: &[u8]) -> Option<usize> {
            #[cfg(target_feature = "sve2")]
            {
                use std::arch::aarch64::*;

                crate::optimize::telemetry::PATTERN_SVE2_OPS.inc();

                let nlen = needle.len();
                if nlen == 0 {
                    return Some(0);
                }
                if nlen > haystack.len() {
                    return None;
                }

                let hlen = haystack.len();
                let vl = svcntb() as usize;
                let mut offset = 0usize;

                if nlen == 1 {
                    let needle_val = svdup_n_u8(needle[0]);
                    let pg_all = svptrue_b8();

                    while offset + vl <= hlen {
                        let chunk = svld1_u8(pg_all, haystack.as_ptr().add(offset));
                        let matches = svcmpeq_u8(pg_all, chunk, needle_val);

                        if svptest_any(pg_all, matches) {
                            for lane in 0..vl {
                                if offset + lane < hlen && haystack[offset + lane] == needle[0] {
                                    return Some(offset + lane);
                                }
                            }
                        }
                        offset += vl;
                    }

                    while offset < hlen {
                        if haystack[offset] == needle[0] {
                            return Some(offset);
                        }
                        offset += 1;
                    }

                    return None;
                }

                let first_byte = svdup_n_u8(needle[0]);
                let pg_all = svptrue_b8();

                while offset + vl <= hlen {
                    let chunk = svld1_u8(pg_all, haystack.as_ptr().add(offset));
                    let matches = svcmpeq_u8(pg_all, chunk, first_byte);

                    if svptest_any(pg_all, matches) {
                        for lane in 0..vl {
                            let pos = offset + lane;
                            if pos + nlen <= hlen && &haystack[pos..pos + nlen] == needle {
                                return Some(pos);
                            }
                        }
                    }
                    offset += vl;
                }

                while offset + nlen <= hlen {
                    if &haystack[offset..offset + nlen] == needle {
                        return Some(offset);
                    }
                    offset += 1;
                }

                return None;
            }

            find_pattern_neon(haystack, needle)
        }

        /// Fast pattern search with ARM NEON - up to 16-byte patterns
        #[cfg(target_arch = "aarch64")]
        #[target_feature(enable = "neon")]
        unsafe fn find_pattern_neon(haystack: &[u8], needle: &[u8]) -> Option<usize> {
            use std::arch::aarch64::*;

            if needle.len() > 16 || needle.is_empty() {
                return find_pattern_scalar(haystack, needle);
            }

            let needle_len = needle.len();
            let haystack_len = haystack.len();

            // For single byte patterns, use NEON comparison
            if needle_len == 1 {
                let needle_first = vdupq_n_u8(needle[0]);
                let mut i = 0;

                while i + 16 <= haystack_len {
                    let haystack_chunk = vld1q_u8(haystack.as_ptr().add(i));
                    let cmp_result = vceqq_u8(haystack_chunk, needle_first);

                    // Check if any bytes matched
                    let mask = vget_lane_u64(
                        vreinterpret_u64_u8(vqmovn_u16(vreinterpretq_u16_u8(cmp_result))),
                        0,
                    );
                    if mask != 0 {
                        for bit in 0..16 {
                            if i + bit < haystack_len && haystack[i + bit] == needle[0] {
                                crate::optimize::telemetry::PATTERN_NEON_OPS.inc();
                                return Some(i + bit);
                            }
                        }
                    }
                    i += 16;
                }
            }

            // For longer patterns, use scalar verification
            let mut i = 0;
            while i + needle_len <= haystack_len {
                if haystack[i..i + needle_len] == *needle {
                    crate::optimize::telemetry::PATTERN_NEON_OPS.inc();
                    return Some(i);
                }
                i += 1;
            }

            None
        }

        /// Scalar pattern search fallback
        fn find_pattern_scalar(haystack: &[u8], needle: &[u8]) -> Option<usize> {
            if needle.is_empty() {
                return Some(0);
            }

            let needle_len = needle.len();
            let haystack_len = haystack.len();

            for i in 0..=(haystack_len.saturating_sub(needle_len)) {
                if haystack[i..i + needle_len] == *needle {
                    crate::optimize::telemetry::PATTERN_SCALAR_OPS.inc();
                    return Some(i);
                }
            }

            None
        }

        /// Scalar entropy histogram fallback
        fn histogram_scalar(data: &[u8]) -> [u32; 256] {
            let mut hist = [0u32; 256];
            for &byte in data {
                hist[byte as usize] += 1;
            }
            crate::optimize::telemetry::PATTERN_SCALAR_OPS.inc();
            hist
        }
    }
}

// ========================================================================
// SIMD UNSAFE BACKEND RE-EXPORTS - Parallele unsafe Implementierungen
// ========================================================================

/// Re-export unsafe SIMD operations from `optimize::unsafe` for parallel unsafe backends
pub mod unsafe_simd {

    /// Unsafe GF(2^8) multiplication with AVX2 - re-exported from `optimize::unsafe`
    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    #[cfg(feature = "unsafe_rust")]
    pub unsafe fn gf256_mul_avx2(
        dst: &mut [u8],
        src: &[u8],
        multiplier: u8,
        table: &crate::optimize::r#unsafe::simd_gf::Gf256LookupTable,
    ) {
        crate::optimize::r#unsafe::simd_gf::gf256_mul_avx2(dst, src, multiplier, table);
        telemetry::SIMD_GF_OPS.inc();
    }

    /// Unsafe XOR blocks with AVX-512 - re-exported from `optimize::unsafe`
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    #[inline(always)]
    #[cfg(feature = "unsafe_rust")]
    pub unsafe fn xor_blocks_avx512(dst: &mut [u8], src: &[u8]) {
        crate::optimize::r#unsafe::simd_gf::xor_blocks_avx512(dst, src);
        telemetry::SIMD_XOR_OPS.inc();
    }

    /// Unsafe XOR blocks with AVX2 - re-exported from `optimize::unsafe`
    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    #[cfg(feature = "unsafe_rust")]
    pub unsafe fn xor_blocks_avx2(dst: &mut [u8], src: &[u8]) {
        crate::optimize::r#unsafe::simd_gf::xor_blocks_avx2(dst, src);
        telemetry::SIMD_XOR_OPS.inc();
    }

    /// Unsafe memory pool operations - re-exported from `optimize::unsafe`
    #[cfg(feature = "unsafe_rust")]
    pub use crate::optimize::r#unsafe::{UnsafeMemoryPool, UnsafePacket};

    /// Unsafe compression operations - re-exported from `optimize::unsafe`
    #[cfg(feature = "unsafe_rust")]
    pub use crate::optimize::r#unsafe::unsafe_compress::UnsafeCompressor;
}

// ========================================================================
// 3-LEVEL CACHE HIERARCHY - Erweiterte Performance-Optimierungen
// ========================================================================

/// Cache hierarchy singleton for global access
static CACHE_HIERARCHY: OnceLock<CacheHierarchy> = OnceLock::new();

/// Get global cache hierarchy instance
pub fn global_cache_hierarchy() -> &'static CacheHierarchy {
    CACHE_HIERARCHY.get_or_init(CacheHierarchy::detect)
}

// Consolidated telemetry module for performance monitoring
// Const-size optimizations with compile-time guarantees
use std::mem::MaybeUninit;

// ===== Cross-Platform Prefetch Hints =====
/// Hint type for cache prefetching.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrefetchHint {
    /// Hint the line into the closest cache (L1).
    T0,
    /// Hint the line into the next cache level (L2).
    T1,
    /// Non-temporal hint for streaming access.
    Nta,
}

/// Issue a best-effort hardware prefetch for the supplied pointer.
///
/// # Safety
/// `ptr` must be non-null and point to readable memory for the duration of
/// the call. Passing invalid addresses, or addresses that alias mutable data
/// being actively written elsewhere, results in undefined behaviour.
#[cfg_attr(feature = "aggressive_inline", inline(always))]
pub unsafe fn prefetch(ptr: *const u8, hint: PrefetchHint) {
    #[cfg(feature = "prefetch")]
    unsafe {
        prefetch_impl(ptr, hint);
    }
    #[cfg(not(feature = "prefetch"))]
    {
        let _ = ptr;
        let _ = hint;
    }
}

#[cfg(feature = "prefetch")]
#[cfg_attr(feature = "aggressive_inline", inline(always))]
unsafe fn prefetch_impl(ptr: *const u8, hint: PrefetchHint) {
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::{_mm_prefetch, _MM_HINT_NTA, _MM_HINT_T0, _MM_HINT_T1};
        let mode = match hint {
            PrefetchHint::T0 => _MM_HINT_T0,
            PrefetchHint::T1 => _MM_HINT_T1,
            PrefetchHint::Nta => _MM_HINT_NTA,
        };
        _mm_prefetch(ptr as *const i8, mode);
    }

    #[cfg(all(target_arch = "aarch64", any(target_os = "ios", target_os = "android")))]
    unsafe {
        core::arch::asm!(
            "prfm pldl1keep, [{ptr}]",
            ptr = in(reg) ptr,
            options(nostack, preserves_flags)
        );
        let _ = hint;
    }

    #[cfg(all(target_arch = "aarch64", not(any(target_os = "ios", target_os = "android"))))]
    {
        let _ = hint;
        let _ = core::ptr::read_volatile(ptr);
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = ptr;
        let _ = hint;
    }
}

/// Const-size buffer for zero-copy operations
pub struct ConstBuffer<const N: usize> {
    data: [u8; N],
    len: usize,
}

impl<const N: usize> ConstBuffer<N> {
    pub const fn new() -> Self {
        Self { data: [0; N], len: 0 }
    }

    #[inline(always)]
    pub fn clear(&mut self) {
        if self.len > 0 {
            self.data[..self.len].fill(0);
        }
        self.len = 0;
    }

    #[inline(always)]
    pub fn write(&mut self, data: &[u8]) -> usize {
        let to_write = data.len().min(N - self.len);
        self.data[self.len..self.len + to_write].copy_from_slice(&data[..to_write]);
        self.len += to_write;
        to_write
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

/// Const-size ring buffer for lock-free operations
pub struct ConstRingBuffer<T, const N: usize> {
    buffer: [MaybeUninit<T>; N],
    head: usize,
    tail: usize,
}

impl<T, const N: usize> Default for ConstRingBuffer<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> ConstRingBuffer<T, N> {
    pub const fn new() -> Self {
        Self { buffer: unsafe { MaybeUninit::uninit().assume_init() }, head: 0, tail: 0 }
    }

    #[inline(always)]
    pub fn push(&mut self, item: T) -> bool {
        let next_tail = (self.tail + 1) % N;
        if next_tail == self.head {
            return false;
        }
        unsafe {
            self.buffer[self.tail].as_mut_ptr().write(item);
        }
        self.tail = next_tail;
        true
    }

    #[inline(always)]
    pub fn pop(&mut self) -> Option<T> {
        if self.head == self.tail {
            return None;
        }
        let item = unsafe { self.buffer[self.head].as_ptr().read() };
        self.head = (self.head + 1) % N;
        Some(item)
    }
}

/// Const-size packet pool
pub struct ConstPacketPool<const N: usize, const SIZE: usize> {
    packets: [ConstBuffer<SIZE>; N],
    free_list: ConstRingBuffer<usize, N>,
    in_use: [bool; N],
}

impl<const N: usize, const SIZE: usize> Default for ConstPacketPool<N, SIZE> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize, const SIZE: usize> ConstPacketPool<N, SIZE> {
    pub fn new() -> Self {
        let mut pool = Self {
            packets: [(); N].map(|_| ConstBuffer::new()),
            free_list: ConstRingBuffer::new(),
            in_use: [false; N],
        };
        for i in 0..N {
            pool.free_list.push(i);
        }
        pool
    }

    #[inline(always)]
    pub fn alloc(&mut self) -> Option<&mut ConstBuffer<SIZE>> {
        self.free_list.pop().map(|idx| {
            if idx < N {
                self.in_use[idx] = true;
            }
            let buf = &mut self.packets[idx];
            buf.clear();
            buf
        })
    }

    #[inline(always)]
    pub fn free(&mut self, buffer: &ConstBuffer<SIZE>) {
        let ptr = buffer as *const _ as usize;
        let base = self.packets.as_ptr() as usize;
        let entry_size = std::mem::size_of::<ConstBuffer<SIZE>>();
        let end = base + entry_size * N;
        if ptr < base || ptr >= end {
            return;
        }
        let idx = (ptr - base) / entry_size;
        if idx >= N {
            return;
        }
        if !self.in_use[idx] {
            return;
        }
        self.in_use[idx] = false;
        let _ = self.free_list.push(idx);
    }
}

/// Const-size SIMD-aligned buffer
#[repr(align(64))]
pub struct AlignedBuffer<const N: usize> {
    data: [u8; N],
}

impl<const N: usize> Default for AlignedBuffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> AlignedBuffer<N> {
    pub const fn new() -> Self {
        Self { data: [0; N] }
    }

    #[inline(always)]
    pub fn as_ptr(&self) -> *const u8 {
        self.data.as_ptr()
    }

    #[inline(always)]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }
}

// ============================================================================
// Lock-free data structures from lock_free.rs
// ============================================================================

/// Lock-free packet queue with backpressure
pub struct LockFreePacketQueue<T> {
    queue: Arc<SegQueue<T>>,
    size: Arc<AtomicUsize>,
    max_size: usize,
}

impl<T> LockFreePacketQueue<T> {
    pub fn new(max_size: usize) -> Self {
        Self { queue: Arc::new(SegQueue::new()), size: Arc::new(AtomicUsize::new(0)), max_size }
    }

    pub fn push(&self, item: T) -> bool {
        if self.size.load(Ordering::Acquire) >= self.max_size {
            return false;
        }
        self.queue.push(item);
        self.size.fetch_add(1, Ordering::Release);
        true
    }

    pub fn pop(&self) -> Option<T> {
        if let Some(item) = self.queue.pop() {
            self.size.fetch_sub(1, Ordering::Release);
            Some(item)
        } else {
            None
        }
    }

    pub fn len(&self) -> usize {
        self.size.load(Ordering::Acquire)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Lock-free bounded MPMC queue
pub struct BoundedQueue<T> {
    queue: Arc<ArrayQueue<T>>,
}

impl<T> BoundedQueue<T> {
    pub fn new(capacity: usize) -> Self {
        Self { queue: Arc::new(ArrayQueue::new(capacity)) }
    }

    pub fn push(&self, item: T) -> Result<(), T> {
        self.queue.push(item)
    }

    pub fn pop(&self) -> Option<T> {
        self.queue.pop()
    }
}

/// Lock-free stream buffer for zero-copy operations
pub struct LockFreeStreamBuffer {
    chunks: Arc<SegQueue<Vec<u8>>>,
    read_pos: Arc<AtomicUsize>,
    write_pos: Arc<AtomicUsize>,
    capacity: Arc<AtomicUsize>,
}

impl LockFreeStreamBuffer {
    pub fn new() -> Self {
        Self {
            chunks: Arc::new(SegQueue::new()),
            read_pos: Arc::new(AtomicUsize::new(0)),
            write_pos: Arc::new(AtomicUsize::new(0)),
            capacity: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn write(&self, data: Vec<u8>) {
        let len = data.len();
        self.chunks.push(data);
        self.write_pos.fetch_add(len, Ordering::Release);
        self.capacity.fetch_add(1, Ordering::Release);
    }

    pub fn read(&self) -> Option<Vec<u8>> {
        if let Some(chunk) = self.chunks.pop() {
            let len = chunk.len();
            self.read_pos.fetch_add(len, Ordering::Release);
            self.capacity.fetch_sub(1, Ordering::Release);
            Some(chunk)
        } else {
            None
        }
    }

    pub fn available(&self) -> usize {
        self.write_pos.load(Ordering::Acquire) - self.read_pos.load(Ordering::Acquire)
    }
}

impl Default for LockFreeStreamBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Lock-free memory pool with NUMA awareness
pub struct LockFreeMemoryPool {
    pools: Vec<Arc<SegQueue<Vec<u8>>>>,
    block_size: usize,
    numa_nodes: usize,
}

impl LockFreeMemoryPool {
    pub fn new(block_size: usize, blocks_per_node: usize) -> Self {
        let numa_nodes = numa::num_nodes();
        let mut pools = Vec::with_capacity(numa_nodes);

        for _node in 0..numa_nodes {
            let pool = Arc::new(SegQueue::new());
            for _ in 0..blocks_per_node {
                let block = vec![0u8; block_size];
                #[cfg(target_os = "linux")]
                unsafe {
                    numa::move_to_node(block.as_ptr() as *mut _, block_size, _node);
                }
                pool.push(block);
            }
            pools.push(pool);
        }

        Self { pools, block_size, numa_nodes }
    }

    pub fn alloc(&self) -> Vec<u8> {
        let node = numa::current_node() % self.numa_nodes;
        if let Some(block) = self.pools[node].pop() {
            return block;
        }

        for pool in &self.pools {
            if let Some(block) = pool.pop() {
                return block;
            }
        }

        vec![0u8; self.block_size]
    }

    pub fn free(&self, mut block: Vec<u8>) {
        if block.capacity() != self.block_size {
            return;
        }

        block.clear();
        block.resize(self.block_size, 0);

        let node = numa::current_node() % self.numa_nodes;
        self.pools[node].push(block);
    }
}

/// Atomic statistics collector (lock-free)
pub struct AtomicStats {
    pub packets_sent: AtomicUsize,
    pub packets_recv: AtomicUsize,
    pub bytes_sent: AtomicUsize,
    pub bytes_recv: AtomicUsize,
    pub errors: AtomicUsize,
}

impl Default for AtomicStats {
    fn default() -> Self {
        Self::new()
    }
}

impl AtomicStats {
    pub fn new() -> Self {
        Self {
            packets_sent: AtomicUsize::new(0),
            packets_recv: AtomicUsize::new(0),
            bytes_sent: AtomicUsize::new(0),
            bytes_recv: AtomicUsize::new(0),
            errors: AtomicUsize::new(0),
        }
    }

    pub fn record_send(&self, bytes: usize) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_recv(&self, bytes: usize) {
        self.packets_recv.fetch_add(1, Ordering::Relaxed);
        self.bytes_recv.fetch_add(bytes, Ordering::Relaxed);
    }
}

#[cfg(any())]
pub mod telemetry {

    use lazy_static::lazy_static;
    use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

    // Global Zerocopy telemetry (Linux-only producers increment; always defined for simplicity)
    // Total number of MSG_ZEROCOPY completion notifications observed.
    pub static ZC_COMPLETIONS_TOTAL: AtomicU64 = AtomicU64::new(0);
    // Total bytes reported as completed by zerocopy notifications (best-effort).
    pub static ZC_COMPLETED_BYTES_TOTAL: AtomicU64 = AtomicU64::new(0);
    // Batch send attempts using zerocopy-capable fast paths (sendmmsg/sendmsg_x).
    pub static ZEROCOPY_SEND_CALLS: AtomicU64 = AtomicU64::new(0);
    // Fallbacks when batched zerocopy send is unavailable or rejected.
    pub static ZEROCOPY_SEND_FALLBACKS: AtomicU64 = AtomicU64::new(0);

    // TLS provider gauge: 0 = rustls-only, 1 = rustls+tls-cover (unified)
    pub static TLS_PROVIDER_KIND: SafeGauge = SafeGauge::new();

    // HTTP/3 metrics
    pub static H3_FRAMES: AtomicU64 = AtomicU64::new(0);
    pub static H3_HEADERS: AtomicU64 = AtomicU64::new(0);
    pub static H3_DATA_BYTES: AtomicU64 = AtomicU64::new(0);
    pub static H3_ERRORS: AtomicU64 = AtomicU64::new(0);

    // MASQUE state gauge: 0 = inactive, 1 = active (CONNECT-UDP established)
    pub static MASQUE_ACTIVE: AtomicU64 = AtomicU64::new(0);

    // AEGIS plan gauge:
    // 0 = MORUS (fallback), 1 = AEGIS-128L, 4 = AEGIS-128X4 (unrolled), 8 = AEGIS-128X8 (unrolled)
    pub static AEGIS_PLAN: AtomicU64 = AtomicU64::new(0);

    // MASQUE hint from Brain: 0 = no preference, 1 = prefer MASQUE path
    pub static MASQUE_HINT: AtomicU64 = AtomicU64::new(0);

    // IP/TUN telemetry
    pub static IP_V4_PACKETS: AtomicU64 = AtomicU64::new(0);
    pub static IP_V6_PACKETS: AtomicU64 = AtomicU64::new(0);
    pub static IP_TOS_SUM: AtomicU64 = AtomicU64::new(0);
    pub static IP_TOS_SAMPLES: AtomicU64 = AtomicU64::new(0);

    // Stealth path signals for Intelligent escalation heuristics
    pub static STEALTH_SIGNAL_RTT_SPIKES: AtomicU64 = AtomicU64::new(0);
    pub static STEALTH_SIGNAL_ECN_CE: AtomicU64 = AtomicU64::new(0);
    pub static STEALTH_SIGNAL_RST: AtomicU64 = AtomicU64::new(0);
    pub static STEALTH_SIGNAL_TOS_ANOM: AtomicU64 = AtomicU64::new(0);
    pub static STEALTH_SIGNAL_OTHER: AtomicU64 = AtomicU64::new(0);

    /// Export a subset of metrics in a plain text telemetry format.
    /// This intentionally covers the most relevant hot-path counters to keep overhead minimal.
    pub fn export_telemetry_text() -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        let get = |v: &AtomicU64| v.load(Ordering::Relaxed);

        // Zero-copy totals
        let _ = writeln!(out, "quicfuscate_zc_completions_total {}", get(&ZC_COMPLETIONS_TOTAL));
        let _ = writeln!(
            out,
            "quicfuscate_zc_completed_bytes_total {}",
            get(&ZC_COMPLETED_BYTES_TOTAL)
        );
        let _ =
            writeln!(out, "quicfuscate_zerocopy_send_calls_total {}", get(&ZEROCOPY_SEND_CALLS));
        let _ = writeln!(
            out,
            "quicfuscate_zerocopy_send_fallbacks_total {}",
            get(&ZEROCOPY_SEND_FALLBACKS)
        );

        // Memory Pool metrics
        let _ = writeln!(out, "quicfuscate_mem_pool_capacity {}", get(&MEM_POOL_CAPACITY));
        let _ = writeln!(out, "quicfuscate_mem_pool_in_use {}", get(&MEM_POOL_IN_USE));
        let _ = writeln!(out, "quicfuscate_mem_pool_usage_bytes {}", get(&MEM_POOL_USAGE_BYTES));
        let _ = writeln!(
            out,
            "quicfuscate_mem_pool_utilization_percent {}",
            get(&MEM_POOL_UTILIZATION)
        );
        let _ =
            writeln!(out, "quicfuscate_mem_pool_block_size_bytes {}", get(&MEM_POOL_BLOCK_SIZE));

        // SIMD usage summary
        let _ = writeln!(out, "quicfuscate_simd_usage_avx512 {}", get(&SIMD_USAGE_AVX512));
        let _ = writeln!(out, "quicfuscate_simd_usage_avx2 {}", get(&SIMD_USAGE_AVX2));
        let _ = writeln!(out, "quicfuscate_simd_usage_avx10_256 {}", get(&SIMD_USAGE_AVX10_256));
        let _ = writeln!(out, "quicfuscate_simd_usage_avx10_512 {}", get(&SIMD_USAGE_AVX10_512));
        let _ = writeln!(out, "quicfuscate_simd_usage_neon {}", get(&SIMD_USAGE_NEON));
        let _ = writeln!(out, "quicfuscate_simd_usage_scalar {}", get(&SIMD_USAGE_SCALAR));
        let _ = writeln!(out, "quicfuscate_simd_usage_rvv {}", get(&SIMD_USAGE_RVV));
        #[cfg(target_arch = "x86_64")]
        let _ = writeln!(
            out,
            "quicfuscate_stealth_padding_gfni_bytes {}",
            STEALTH_PADDING_GFNI_OPS.get()
        );
        let _ =
            writeln!(out, "quicfuscate_congestion_vnni_batches {}", CONGESTION_VNNI_BATCHES.get());
        let _ =
            writeln!(out, "quicfuscate_congestion_avx2_batches {}", CONGESTION_AVX2_BATCHES.get());
        let _ =
            writeln!(out, "quicfuscate_congestion_neon_batches {}", CONGESTION_NEON_BATCHES.get());

        // TLS provider
        let _ = writeln!(out, "quicfuscate_tls_provider_kind {}", TLS_PROVIDER_KIND.get());

        // TLS Cover cipher usage
        let _ = writeln!(out, "quicfuscate_tls-cover_chacha_ops {}", FAKETLS_CHACHA_OPS.get());
        let _ = writeln!(out, "quicfuscate_tls-cover_aes_gcm_ops {}", FAKETLS_AES_GCM_OPS.get());
        let _ = writeln!(
            out,
            "quicfuscate_tls-cover_cipher_failures {}",
            FAKETLS_CIPHER_FAILURES.get()
        );
        let _ = writeln!(out, "quicfuscate_aes_block_aesni_ops {}", AES_BLOCK_AESNI_OPS.get());
        let _ = writeln!(out, "quicfuscate_aes_block_vaes_ops {}", AES_BLOCK_VAES_OPS.get());
        let _ = writeln!(out, "quicfuscate_aes_block_aese_ops {}", AES_BLOCK_AESE_OPS.get());
        let _ = writeln!(out, "quicfuscate_aes_block_ssse3_ops {}", AES_BLOCK_SSSE3_OPS.get());
        let _ = writeln!(out, "quicfuscate_aes_block_sve_ops {}", AES_BLOCK_SVE_OPS.get());
        let _ = writeln!(
            out,
            "quicfuscate_aes_block_neon_table_ops {}",
            AES_BLOCK_NEON_TABLE_OPS.get()
        );
        let _ = writeln!(out, "quicfuscate_aes_block_scalar_ops {}", AES_BLOCK_SCALAR_OPS.get());
        let _ = writeln!(out, "quicfuscate_sha256_avx2_ops {}", SHA256_AVX2_OPS.get());
        let _ = writeln!(out, "quicfuscate_sha256_vnni_ops {}", SHA256_VNNI_OPS.get());
        let _ = writeln!(out, "quicfuscate_sha256_sha_ops {}", SHA256_SHA_OPS.get());
        let _ = writeln!(out, "quicfuscate_sha256_neon_ops {}", SHA256_NEON_OPS.get());
        let _ = writeln!(out, "quicfuscate_sha256_sve2_ops {}", SHA256_SVE2_OPS.get());
        let _ = writeln!(out, "quicfuscate_sha256_scalar_ops {}", SHA256_SCALAR_OPS.get());
        let _ = writeln!(out, "quicfuscate_hmac_sha256_avx2_ops {}", HMAC_SHA256_AVX2_OPS.get());
        let _ = writeln!(out, "quicfuscate_hmac_sha256_vnni_ops {}", HMAC_SHA256_VNNI_OPS.get());
        let _ = writeln!(out, "quicfuscate_hmac_sha256_sha_ops {}", HMAC_SHA256_SHA_OPS.get());
        let _ = writeln!(out, "quicfuscate_hmac_sha256_neon_ops {}", HMAC_SHA256_NEON_OPS.get());
        let _ = writeln!(out, "quicfuscate_hmac_sha256_sve2_ops {}", HMAC_SHA256_SVE2_OPS.get());
        let _ =
            writeln!(out, "quicfuscate_hmac_sha256_scalar_ops {}", HMAC_SHA256_SCALAR_OPS.get());
        let _ = writeln!(out, "quicfuscate_chacha20_x4_avx2_ops {}", CHACHA20_X4_AVX2_OPS.get());
        let _ = writeln!(out, "quicfuscate_chacha20_x4_avx_ops {}", CHACHA20_X4_AVX_OPS.get());
        let _ = writeln!(out, "quicfuscate_chacha20_x4_sse41_ops {}", CHACHA20_X4_SSE41_OPS.get());
        let _ = writeln!(out, "quicfuscate_chacha20_x4_neon_ops {}", CHACHA20_X4_NEON_OPS.get());
        let _ =
            writeln!(out, "quicfuscate_chacha20_x4_scalar_ops {}", CHACHA20_X4_SCALAR_OPS.get());
        let _ = writeln!(out, "quicfuscate_aes_ctr_aesni_ops {}", AES_CTR_AESNI_OPS.get());
        let _ = writeln!(out, "quicfuscate_aes_ctr_aese_ops {}", AES_CTR_AESE_OPS.get());
        let _ = writeln!(out, "quicfuscate_aes_ctr_sve_ops {}", AES_CTR_SVE_OPS.get());
        let _ = writeln!(out, "quicfuscate_aes_ctr_ssse3_ops {}", AES_CTR_SSSE3_OPS.get());
        let _ = writeln!(out, "quicfuscate_aes_ctr_scalar_ops {}", AES_CTR_SCALAR_OPS.get());
        let _ = writeln!(out, "quicfuscate_rng_aes_ctr_ops {}", RNG_AES_CTR_OPS.get());
        let _ = writeln!(out, "quicfuscate_poly1305_avx512_ops {}", POLY1305_AVX512_OPS.get());
        let _ = writeln!(out, "quicfuscate_poly1305_avx2_ops {}", POLY1305_AVX2_OPS.get());
        let _ = writeln!(out, "quicfuscate_poly1305_sse2_ops {}", POLY1305_SSE2_OPS.get());
        let _ = writeln!(out, "quicfuscate_poly1305_sve_ops {}", POLY1305_SVE_OPS.get());
        let _ = writeln!(out, "quicfuscate_poly1305_neon_ops {}", POLY1305_NEON_OPS.get());
        let _ = writeln!(out, "quicfuscate_poly1305_scalar_ops {}", POLY1305_SCALAR_OPS.get());
        let _ =
            writeln!(out, "quicfuscate_iter_sum_f32_avx512_ops {}", ITER_SUM_F32_AVX512_OPS.get());
        let _ = writeln!(out, "quicfuscate_iter_sum_f32_avx2_ops {}", ITER_SUM_F32_AVX2_OPS.get());
        let _ = writeln!(out, "quicfuscate_iter_sum_f32_neon_ops {}", ITER_SUM_F32_NEON_OPS.get());
        let _ =
            writeln!(out, "quicfuscate_iter_sum_f32_scalar_ops {}", ITER_SUM_F32_SCALAR_OPS.get());
        let _ = writeln!(out, "quicfuscate_iter_sum_f32_rvv_ops {}", ITER_SUM_F32_RVV_OPS.get());
        let _ =
            writeln!(out, "quicfuscate_iter_sum_u32_avx512_ops {}", ITER_SUM_U32_AVX512_OPS.get());
        let _ = writeln!(out, "quicfuscate_iter_sum_u32_avx2_ops {}", ITER_SUM_U32_AVX2_OPS.get());
        let _ = writeln!(out, "quicfuscate_iter_sum_u32_neon_ops {}", ITER_SUM_U32_NEON_OPS.get());
        let _ =
            writeln!(out, "quicfuscate_iter_sum_u32_scalar_ops {}", ITER_SUM_U32_SCALAR_OPS.get());
        let _ = writeln!(out, "quicfuscate_iter_sum_u32_rvv_ops {}", ITER_SUM_U32_RVV_OPS.get());
        let _ =
            writeln!(out, "quicfuscate_iter_sum_u64_avx512_ops {}", ITER_SUM_U64_AVX512_OPS.get());
        let _ = writeln!(out, "quicfuscate_iter_sum_u64_avx2_ops {}", ITER_SUM_U64_AVX2_OPS.get());
        let _ = writeln!(out, "quicfuscate_iter_sum_u64_neon_ops {}", ITER_SUM_U64_NEON_OPS.get());
        let _ =
            writeln!(out, "quicfuscate_iter_sum_u64_scalar_ops {}", ITER_SUM_U64_SCALAR_OPS.get());
        let _ = writeln!(out, "quicfuscate_iter_sum_u64_rvv_ops {}", ITER_SUM_U64_RVV_OPS.get());
        let _ = writeln!(out, "quicfuscate_wiedemann_usage {}", WIEDEMANN_USAGE.get());
        let _ = writeln!(out, "quicfuscate_wiedemann_amx_ops {}", WIEDEMANN_AMX_OPS.get());
        let _ = writeln!(out, "quicfuscate_wiedemann_scalar_ops {}", WIEDEMANN_SCALAR_OPS.get());

        // MASQUE
        let _ = writeln!(out, "quicfuscate_masque_active {}", get(&MASQUE_ACTIVE));
        let _ = writeln!(out, "quicfuscate_masque_hint {}", get(&MASQUE_HINT));

        // AEGIS plan
        let _ = writeln!(out, "quicfuscate_aegis_plan {}", get(&AEGIS_PLAN));

        // Plan selection metrics
        let _ = writeln!(out, "quicfuscate_plan_decisions_total {}", PLAN_DECISIONS_TOTAL.get());
        let _ =
            writeln!(out, "quicfuscate_plan_decisions_default {}", PLAN_DECISIONS_DEFAULT.get());
        let _ = writeln!(out, "quicfuscate_plan_decisions_len {}", PLAN_DECISIONS_LEN.get());
        let _ = writeln!(out, "quicfuscate_plan_select_l_total {}", PLAN_DECISIONS_L.get());
        let _ =
            writeln!(out, "quicfuscate_plan_select_neon_l_total {}", PLAN_DECISIONS_NEON_L.get());
        let _ = writeln!(out, "quicfuscate_plan_select_morus_total {}", PLAN_DECISIONS_MORUS.get());

        // Compression decision metrics
        let _ = writeln!(
            out,
            "quicfuscate_compress_decisions_total {}",
            COMPRESS_DECISIONS_TOTAL.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_compress_decisions_allow {}",
            COMPRESS_DECISIONS_ALLOW.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_compress_decisions_skip_len {}",
            COMPRESS_DECISIONS_SKIP_LEN.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_compress_decisions_skip_loss {}",
            COMPRESS_DECISIONS_SKIP_LOSS.get()
        );
        let _ = writeln!(
            out,
            "quicfuscate_compress_decisions_skip_profile {}",
            COMPRESS_DECISIONS_SKIP_PROFILE.get()
        );

        // GHASH backend metrics
        let _ = writeln!(out, "quicfuscate_ghash_pclmul_ops {}", GHASH_PCLMUL_OPS.get());
        let _ = writeln!(out, "quicfuscate_ghash_vpclmul_ops {}", GHASH_VPCLMUL_OPS.get());
        let _ = writeln!(out, "quicfuscate_ghash_pmull_ops {}", GHASH_PMULL_OPS.get());
        let _ = writeln!(out, "quicfuscate_ghash_neon_ops {}", GHASH_NEON_OPS.get());
        let _ = writeln!(out, "quicfuscate_ghash_sse_ops {}", GHASH_SSE_OPS.get());

        // GHASH scalar fallback metrics
        let _ = writeln!(out, "quicfuscate_ghash_scalar_ops_total {}", GHASH_SCALAR_OPS.get());
        let _ = writeln!(out, "quicfuscate_ghash_scalar_calls_total {}", GHASH_SCALAR_CALLS.get());
        let _ = writeln!(out, "quicfuscate_ghash_scalar_bytes_total {}", GHASH_SCALAR_BYTES.get());

        // H3
        let _ = writeln!(out, "quicfuscate_h3_frames_total {}", get(&H3_FRAMES));
        let _ = writeln!(out, "quicfuscate_h3_headers_total {}", get(&H3_HEADERS));
        let _ = writeln!(out, "quicfuscate_h3_data_bytes_total {}", get(&H3_DATA_BYTES));
        let _ = writeln!(out, "quicfuscate_h3_errors_total {}", get(&H3_ERRORS));

        // IP/TUN
        let _ = writeln!(out, "quicfuscate_ip_v4_packets_total {}", get(&IP_V4_PACKETS));
        let _ = writeln!(out, "quicfuscate_ip_v6_packets_total {}", get(&IP_V6_PACKETS));
        let _ = writeln!(out, "quicfuscate_ip_tos_sum {}", get(&IP_TOS_SUM));
        let _ = writeln!(out, "quicfuscate_ip_tos_samples {}", get(&IP_TOS_SAMPLES));

        // Stealth signals
        let _ = writeln!(
            out,
            "quicfuscate_stealth_signal_rtt_spikes_total {}",
            get(&STEALTH_SIGNAL_RTT_SPIKES)
        );
        let _ = writeln!(
            out,
            "quicfuscate_stealth_signal_ecn_ce_total {}",
            get(&STEALTH_SIGNAL_ECN_CE)
        );
        let _ = writeln!(out, "quicfuscate_stealth_signal_rst_total {}", get(&STEALTH_SIGNAL_RST));
        let _ = writeln!(
            out,
            "quicfuscate_stealth_signal_tos_anom_total {}",
            get(&STEALTH_SIGNAL_TOS_ANOM)
        );
        let _ =
            writeln!(out, "quicfuscate_stealth_signal_other_total {}", get(&STEALTH_SIGNAL_OTHER));

        out
    }

    pub struct SafeGauge(AtomicI64);
    impl SafeGauge {
        pub const fn new() -> Self {
            Self(AtomicI64::new(0))
        }
        pub fn set(&self, val: i64) {
            self.0.store(val, Ordering::Relaxed);
        }
        pub fn get(&self) -> i64 {
            self.0.load(Ordering::Relaxed)
        }
    }
    impl Default for SafeGauge {
        fn default() -> Self {
            Self::new()
        }
    }

    pub struct Counter(AtomicU64);
    impl Counter {
        pub const fn new() -> Self {
            Counter(AtomicU64::new(0))
        }
        pub fn inc(&self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_by(&self, val: u64) {
            self.0.fetch_add(val, Ordering::Relaxed);
        }
        pub fn get(&self) -> u64 {
            self.0.load(Ordering::Relaxed)
        }
    }
    impl Default for Counter {
        fn default() -> Self {
            Self::new()
        }
    }

    lazy_static! {
        // Unsafe operation metrics
        pub static ref UNSAFE_POOL_CREATED: Counter = Counter::new();
        pub static ref UNSAFE_POOL_CAPACITY: AtomicU64 = AtomicU64::new(0);
        pub static ref UNSAFE_ALLOC_CALLS: Counter = Counter::new();
        pub static ref UNSAFE_FREE_CALLS: Counter = Counter::new();
        pub static ref UNSAFE_TLS_HITS: Counter = Counter::new();
        pub static ref UNSAFE_GLOBAL_HITS: Counter = Counter::new();
        pub static ref UNSAFE_FALLBACK_ALLOCS: Counter = Counter::new();
        pub static ref UNSAFE_DEALLOCS: Counter = Counter::new();

        // SIMD operation metrics
        pub static ref SIMD_GF_OPS: Counter = Counter::new();
        pub static ref SIMD_XOR_OPS: Counter = Counter::new();
        pub static ref SIMD_PREFETCH_OPS: Counter = Counter::new();

        // Unsafe compression metrics
        pub static ref UNSAFE_COMPRESS_CALLS: Counter = Counter::new();
        pub static ref UNSAFE_COMPRESS_FAILURES: Counter = Counter::new();
        pub static ref UNSAFE_COMPRESS_BYTES_IN: Counter = Counter::new();
        pub static ref UNSAFE_COMPRESS_BYTES_OUT: Counter = Counter::new();

        // Entropy calculation metrics
        pub static ref ENTROPY_CALCULATIONS: Counter = Counter::new();
        pub static ref ENTROPY_SIMD_USED: Counter = Counter::new();

        // Zero-copy transport metrics
        pub static ref ZERO_COPY_SENDS: Counter = Counter::new();
        pub static ref ZERO_COPY_RECVS: Counter = Counter::new();
        pub static ref IOSLICE_OPERATIONS: Counter = Counter::new();

        // FEC SIMD metrics
        pub static ref FEC_SIMD_ENCODE: Counter = Counter::new();
        pub static ref FEC_SIMD_DECODE: Counter = Counter::new();
        pub static ref FEC_AVX2_OPS: Counter = Counter::new();
        pub static ref BRAIN_HISTOGRAM_AVX512_OPS: Counter = Counter::new();
        pub static ref BRAIN_HISTOGRAM_AVX2_OPS: Counter = Counter::new();
        pub static ref BRAIN_HISTOGRAM_SSE_OPS: Counter = Counter::new();
        pub static ref BRAIN_HISTOGRAM_NEON_OPS: Counter = Counter::new();
        pub static ref BRAIN_HISTOGRAM_SVE2_OPS: Counter = Counter::new();
        pub static ref BRAIN_HISTOGRAM_SCALAR_OPS: Counter = Counter::new();

        // Plan selection metrics
        pub static ref PLAN_DECISIONS_TOTAL: Counter = Counter::new();
        pub static ref PLAN_DECISIONS_DEFAULT: Counter = Counter::new();
        pub static ref PLAN_DECISIONS_LEN: Counter = Counter::new();
        pub static ref PLAN_DECISIONS_L: Counter = Counter::new();
        pub static ref PLAN_DECISIONS_NEON_L: Counter = Counter::new();
        pub static ref PLAN_DECISIONS_MORUS: Counter = Counter::new();

        // Compression decision metrics
        pub static ref COMPRESS_DECISIONS_TOTAL: Counter = Counter::new();
        pub static ref COMPRESS_DECISIONS_ALLOW: Counter = Counter::new();
        pub static ref COMPRESS_DECISIONS_SKIP_LEN: Counter = Counter::new();
        pub static ref COMPRESS_DECISIONS_SKIP_LOSS: Counter = Counter::new();
        pub static ref COMPRESS_DECISIONS_SKIP_PROFILE: Counter = Counter::new();

        // GHASH scalar fallback metrics
        pub static ref GHASH_SCALAR_CALLS: Counter = Counter::new();
        pub static ref GHASH_SCALAR_BYTES: Counter = Counter::new();
        pub static ref FEC_AVX512_OPS: Counter = Counter::new();
        pub static ref FEC_GF16_VBMI2_OPS: Counter = Counter::new();
        pub static ref FEC_NEON_OPS: Counter = Counter::new();
        pub static ref FEC_SVE2_OPS: Counter = Counter::new();
        pub static ref FEC_BERLEKAMP_SVE2_OPS: Counter = Counter::new();

        // SIMD operation counters
        pub static ref AVX512_OPS: Counter = Counter::new();
        pub static ref AVX2_OPS: Counter = Counter::new();
        // SSE2_OPS removed - baseline is SSE4.2
        pub static ref NEON_OPS: Counter = Counter::new();
        pub static ref SVE2_OPS: Counter = Counter::new();
        pub static ref SCALAR_OPS: Counter = Counter::new();

        // AES block backend usage
        pub static ref AES_BLOCK_AESNI_OPS: Counter = Counter::new();
        pub static ref AES_BLOCK_VAES_OPS: Counter = Counter::new();
        pub static ref AES_BLOCK_AESE_OPS: Counter = Counter::new();
        pub static ref AES_BLOCK_SSSE3_OPS: Counter = Counter::new();
        pub static ref AES_BLOCK_SVE_OPS: Counter = Counter::new();
        pub static ref AES_BLOCK_NEON_TABLE_OPS: Counter = Counter::new();
        pub static ref AES_BLOCK_SCALAR_OPS: Counter = Counter::new();
        pub static ref SHA256_AVX2_OPS: Counter = Counter::new();
        pub static ref SHA256_VNNI_OPS: Counter = Counter::new();
        pub static ref SHA256_SHA_OPS: Counter = Counter::new();
        pub static ref SHA256_NEON_OPS: Counter = Counter::new();
        pub static ref SHA256_SVE2_OPS: Counter = Counter::new();
        pub static ref SHA256_SCALAR_OPS: Counter = Counter::new();
        pub static ref HMAC_SHA256_AVX2_OPS: Counter = Counter::new();
        pub static ref HMAC_SHA256_VNNI_OPS: Counter = Counter::new();
        pub static ref HMAC_SHA256_SHA_OPS: Counter = Counter::new();
        pub static ref HMAC_SHA256_NEON_OPS: Counter = Counter::new();
        pub static ref HMAC_SHA256_SVE2_OPS: Counter = Counter::new();
        pub static ref HMAC_SHA256_SCALAR_OPS: Counter = Counter::new();

        // GHASH backend usage
        pub static ref GHASH_PCLMUL_OPS: Counter = Counter::new();
        pub static ref GHASH_VPCLMUL_OPS: Counter = Counter::new();
        pub static ref GHASH_PMULL_OPS: Counter = Counter::new();
        pub static ref GHASH_NEON_OPS: Counter = Counter::new();
        pub static ref GHASH_SSE_OPS: Counter = Counter::new();
        pub static ref GHASH_SCALAR_OPS: Counter = Counter::new();

        // ChaCha20 4-way usage
        pub static ref CHACHA20_X4_AVX2_OPS: Counter = Counter::new();
        pub static ref CHACHA20_X4_AVX_OPS: Counter = Counter::new();
        pub static ref CHACHA20_X4_SSE41_OPS: Counter = Counter::new();
        pub static ref CHACHA20_X4_NEON_OPS: Counter = Counter::new();
        pub static ref CHACHA20_X4_SCALAR_OPS: Counter = Counter::new();

        // CRC32 hardware acceleration usage
        pub static ref CRC32_SSE42_OPS: Counter = Counter::new();
        pub static ref CRC32_ARM_OPS: Counter = Counter::new();
        pub static ref CRC32_SCALAR_OPS: Counter = Counter::new();

        // FEC SIMD operation counters for new paths
        pub static ref FEC_AVX2_GF_OPS: Counter = Counter::new();
        pub static ref FEC_SSSE3_OPS: Counter = Counter::new();
        pub static ref FEC_GFNI_OPS: Counter = Counter::new();

        // GF(2^16) SIMD operation counters for Extreme/Ultra FEC modes
        pub static ref GF16_VPCLMUL_OPS: Counter = Counter::new();
        pub static ref GF16_PCLMUL_OPS: Counter = Counter::new();
        pub static ref GF16_PMULL_OPS: Counter = Counter::new();
        // Pattern matching and histogram SIMD operation counters
        pub static ref PATTERN_AVX512_VBMI2_OPS: Counter = Counter::new();
        pub static ref PATTERN_AVX512_OPS: Counter = Counter::new();
        pub static ref PATTERN_AVX2_OPS: Counter = Counter::new();
        pub static ref PATTERN_NEON_OPS: Counter = Counter::new();
        pub static ref PATTERN_SVE2_OPS: Counter = Counter::new();
        pub static ref PATTERN_SCALAR_OPS: Counter = Counter::new();

        // Performance improvement metrics
        pub static ref UNSAFE_SPEEDUP_FACTOR: AtomicU64 = AtomicU64::new(100);
        pub static ref UNSAFE_LATENCY_REDUCTION_US: AtomicU64 = AtomicU64::new(0);
        pub static ref UNSAFE_THROUGHPUT_GBPS: AtomicU64 = AtomicU64::new(0);
        pub static ref CRYPTO_PROFILE: AtomicU64 = AtomicU64::new(0);

        // AEGIS batched operations counter
        pub static ref AEGIS_BATCH_OPS: AtomicU64 = AtomicU64::new(0);

        // XDP metrics
        pub static ref XDP_ACTIVE: AtomicU64 = AtomicU64::new(0);
        pub static ref XDP_FALLBACKS: Counter = Counter::new();
        pub static ref XDP_BYTES_SENT: Counter = Counter::new();
        pub static ref XDP_BYTES_RECEIVED: Counter = Counter::new();
        pub static ref XDP_SEND_LATENCY: Counter = Counter::new();
        pub static ref XDP_RECV_LATENCY: Counter = Counter::new();
        pub static ref XDP_THROUGHPUT: SafeGauge = SafeGauge::new();

        // Memory pool metrics
        pub static ref MEM_POOL_CAPACITY: AtomicU64 = AtomicU64::new(0);
        pub static ref MEM_POOL_BLOCK_SIZE: AtomicU64 = AtomicU64::new(0);
        pub static ref MEM_POOL_IN_USE: AtomicU64 = AtomicU64::new(0);
        pub static ref MEM_POOL_USAGE_BYTES: AtomicU64 = AtomicU64::new(0);
        pub static ref MEM_POOL_FRAGMENTATION: AtomicU64 = AtomicU64::new(0);
        pub static ref MEM_POOL_UTILIZATION: AtomicU64 = AtomicU64::new(0);
        // 0=Local, 1=Preferred, 2=Interleave
        pub static ref MEM_POOL_NUMA_POLICY: AtomicU64 = AtomicU64::new(0);

        // SIMD metrics
        pub static ref SIMD_ACTIVE: AtomicU64 = AtomicU64::new(0);
        pub static ref SIMD_USAGE_AVX2: AtomicU64 = AtomicU64::new(0);
        pub static ref SIMD_USAGE_AVX512: AtomicU64 = AtomicU64::new(0);
        pub static ref SIMD_USAGE_AVX10_256: AtomicU64 = AtomicU64::new(0);
        pub static ref SIMD_USAGE_AVX10_512: AtomicU64 = AtomicU64::new(0);
        // Some modules still report SSE2 usage; keep a counter for compatibility
        pub static ref SIMD_USAGE_SSE2: AtomicU64 = AtomicU64::new(0);
        pub static ref SIMD_USAGE_NEON: AtomicU64 = AtomicU64::new(0);
        pub static ref SIMD_USAGE_SCALAR: AtomicU64 = AtomicU64::new(0);
        pub static ref SIMD_USAGE_RVV: AtomicU64 = AtomicU64::new(0);
        pub static ref ARGSORT_AVX2_OPS: Counter = Counter::new();
        pub static ref ARGSORT_NEON_OPS: Counter = Counter::new();
        pub static ref ARGSORT_FALLBACK_OPS: Counter = Counter::new();
        pub static ref MOVING_AVG_AVX512_OPS: Counter = Counter::new();
        pub static ref MOVING_AVG_AVX2_OPS: Counter = Counter::new();
        pub static ref MOVING_AVG_NEON_OPS: Counter = Counter::new();
        pub static ref MOVING_AVG_SSE_OPS: Counter = Counter::new();
        pub static ref MOVING_AVG_SCALAR_OPS: Counter = Counter::new();
        pub static ref FAKETLS_CHACHA_OPS: Counter = Counter::new();
        pub static ref FAKETLS_AES_GCM_OPS: Counter = Counter::new();
        pub static ref FAKETLS_CIPHER_FAILURES: Counter = Counter::new();
        pub static ref AES_CTR_AESNI_OPS: Counter = Counter::new();
        pub static ref AES_CTR_AESE_OPS: Counter = Counter::new();
        pub static ref AES_CTR_SVE_OPS: Counter = Counter::new();
        pub static ref AES_CTR_SSSE3_OPS: Counter = Counter::new();
        pub static ref AES_CTR_SCALAR_OPS: Counter = Counter::new();
        pub static ref RNG_AES_CTR_OPS: Counter = Counter::new();
        pub static ref POLY1305_AVX512_OPS: Counter = Counter::new();
        pub static ref POLY1305_AVX2_OPS: Counter = Counter::new();
        pub static ref POLY1305_SSE2_OPS: Counter = Counter::new();
        pub static ref POLY1305_SVE_OPS: Counter = Counter::new();
        pub static ref POLY1305_NEON_OPS: Counter = Counter::new();
        pub static ref POLY1305_SCALAR_OPS: Counter = Counter::new();
        pub static ref ITER_SUM_F32_AVX512_OPS: Counter = Counter::new();
        pub static ref ITER_SUM_F32_AVX2_OPS: Counter = Counter::new();
        pub static ref ITER_SUM_F32_SSE_OPS: Counter = Counter::new();
        pub static ref ITER_SUM_F32_NEON_OPS: Counter = Counter::new();
        pub static ref ITER_SUM_F32_SVE_OPS: Counter = Counter::new();
        pub static ref ITER_SUM_F32_RVV_OPS: Counter = Counter::new();
        pub static ref ITER_SUM_F32_SCALAR_OPS: Counter = Counter::new();
        pub static ref ITER_SUM_U32_AVX512_OPS: Counter = Counter::new();
        pub static ref ITER_SUM_U32_AVX2_OPS: Counter = Counter::new();
        pub static ref ITER_SUM_U32_SSE_OPS: Counter = Counter::new();
        pub static ref ITER_SUM_U32_NEON_OPS: Counter = Counter::new();
        pub static ref ITER_SUM_U32_SVE_OPS: Counter = Counter::new();
        pub static ref ITER_SUM_U32_RVV_OPS: Counter = Counter::new();
        pub static ref ITER_SUM_U32_SCALAR_OPS: Counter = Counter::new();
        pub static ref ITER_SUM_U64_AVX512_OPS: Counter = Counter::new();
        pub static ref ITER_SUM_U64_AVX2_OPS: Counter = Counter::new();
        pub static ref ITER_SUM_U64_SSE_OPS: Counter = Counter::new();
        pub static ref ITER_SUM_U64_NEON_OPS: Counter = Counter::new();
        pub static ref ITER_SUM_U64_SVE_OPS: Counter = Counter::new();
        pub static ref ITER_SUM_U64_RVV_OPS: Counter = Counter::new();
        pub static ref ITER_SUM_U64_SCALAR_OPS: Counter = Counter::new();

        // CPU features
        pub static ref CPU_FEATURE_MASK: AtomicI64 = AtomicI64::new(0);

        // General metrics
        pub static ref MEMORY_USAGE_BYTES: AtomicU64 = AtomicU64::new(0);
        pub static ref BYTES_SENT: Counter = Counter::new();
        pub static ref BYTES_RECEIVED: Counter = Counter::new();

        // FEC metrics
        pub static ref DECODING_TIME_MS: AtomicU64 = AtomicU64::new(0);
        pub static ref WIEDEMANN_USAGE: Counter = Counter::new();
        pub static ref WIEDEMANN_AMX_OPS: Counter = Counter::new();
        pub static ref WIEDEMANN_SCALAR_OPS: Counter = Counter::new();
        pub static ref FEC_MODE: AtomicU64 = AtomicU64::new(0);
        pub static ref LOSS_RATE: AtomicU64 = AtomicU64::new(0);
        pub static ref FEC_MODE_SWITCHES: AtomicU64 = AtomicU64::new(0);
        pub static ref FEC_WINDOW: AtomicU64 = AtomicU64::new(0);
        pub static ref FEC_OVERFLOWS: AtomicU64 = AtomicU64::new(0);
        pub static ref DNS_ERRORS: AtomicU64 = AtomicU64::new(0);
        // Additional FEC gauges
        pub static ref FEC_EMITTED_QUEUE: AtomicU64 = AtomicU64::new(0);
        pub static ref FOUNTAIN_PROGRESS: AtomicU64 = AtomicU64::new(0); // progress*1_000_000
        pub static ref FOUNTAIN_SYMBOL_SIZE: AtomicU64 = AtomicU64::new(0);
        pub static ref FEC_EMITTED_UNIQUE: AtomicU64 = AtomicU64::new(0);
        pub static ref FEC_EMITTED_ORDER_DEPTH: AtomicU64 = AtomicU64::new(0);

        // Lazy decoding telemetry: repairs skipped when no loss detected
        pub static ref FEC_LAZY_SKIPPED: AtomicU64 = AtomicU64::new(0);
        // Interleaving telemetry: repairs generated across interleaved blocks
        pub static ref FEC_INTERLEAVE_REPAIRS: AtomicU64 = AtomicU64::new(0);
        // Ultra-Zero-Mode: upgrades from zero encoder/decoder to real FEC on loss detection
        pub static ref ZERO_MODE_UPGRADES: AtomicU64 = AtomicU64::new(0);

        // Stealth metrics
        pub static ref STEALTH_DOH: AtomicU64 = AtomicU64::new(0);
        pub static ref STEALTH_FRONTING: AtomicU64 = AtomicU64::new(0);
        pub static ref STEALTH_XOR: AtomicU64 = AtomicU64::new(0);
        pub static ref STEALTH_PADDING_GFNI_OPS: Counter = Counter::new();
        // HTTP/3 Server Push telemetry
        pub static ref STEALTH_PUSH_PROMISES: Counter = Counter::new();
        pub static ref STEALTH_PUSH_BYTES: AtomicU64 = AtomicU64::new(0);
        // Congestion aggregation telemetry
        pub static ref CONGESTION_VNNI_BATCHES: Counter = Counter::new();
        pub static ref CONGESTION_AVX2_BATCHES: Counter = Counter::new();
        pub static ref CONGESTION_NEON_BATCHES: Counter = Counter::new();

        // MASQUE metrics
        pub static ref MASQUE_BYTES_SENT: Counter = Counter::new();
        pub static ref MASQUE_BYTES_RECEIVED: Counter = Counter::new();
        pub static ref MASQUE_CAPSULE_00: Counter = Counter::new();
        pub static ref MASQUE_CAPSULE_21: Counter = Counter::new();
        pub static ref MASQUE_CAPSULE_22: Counter = Counter::new();
        pub static ref MASQUE_CAPSULE_00_BYTES: Counter = Counter::new();
        pub static ref MASQUE_CAPSULE_21_BYTES: Counter = Counter::new();
        pub static ref MASQUE_CAPSULE_22_BYTES: Counter = Counter::new();

        // Profile metrics
        pub static ref STEALTH_BROWSER_PROFILE: SafeGauge = SafeGauge::new();
        pub static ref STEALTH_OS_PROFILE: SafeGauge = SafeGauge::new();

        // io_uring metrics (Linux-only fast path)
        pub static ref URING_ACTIVE: AtomicU64 = AtomicU64::new(0);
        pub static ref URING_SEND_ATTEMPTS: Counter = Counter::new();
        pub static ref URING_FALLBACKS: Counter = Counter::new();
        pub static ref URING_BYTES_SENT: Counter = Counter::new();
        pub static ref URING_BYTES_RECEIVED: Counter = Counter::new();
        pub static ref URING_SUBMISSIONS: Counter = Counter::new();
        pub static ref URING_COMPLETIONS: Counter = Counter::new();
        pub static ref URING_ERRORS: Counter = Counter::new();
        pub static ref URING_QUEUE_DEPTH: SafeGauge = SafeGauge::new();

        // ACK delay telemetry (transport-level)
        pub static ref ACK_DELAY_LAST_US: AtomicU64 = AtomicU64::new(0);
        pub static ref ACK_DELAY_BUCKET_LE_1MS: Counter = Counter::new();
        pub static ref ACK_DELAY_BUCKET_LE_4MS: Counter = Counter::new();
        pub static ref ACK_DELAY_BUCKET_LE_16MS: Counter = Counter::new();
        pub static ref ACK_DELAY_BUCKET_LE_64MS: Counter = Counter::new();
        pub static ref ACK_DELAY_BUCKET_LE_256MS: Counter = Counter::new();
        pub static ref ACK_DELAY_BUCKET_GT_256MS: Counter = Counter::new();

        // Choke/pacing telemetry (stealth-level)
        pub static ref CHOKE_SLEEP_MS: Counter = Counter::new();
        pub static ref CHOKED_BYTES: Counter = Counter::new();

        // Compression telemetry
        pub static ref COMPRESS_ATTEMPTS: Counter = Counter::new();
        pub static ref COMPRESS_SUCCESS: Counter = Counter::new();
        pub static ref COMPRESS_TRUNCATIONS: Counter = Counter::new();
        pub static ref COMPRESS_DICT_USED: Counter = Counter::new();
        pub static ref COMPRESS_BYTES_OUT: Counter = Counter::new();
        pub static ref COMPRESS_BYTES_IN: Counter = Counter::new();
        pub static ref ENTROPY_TEXTUAL_SEEN: Counter = Counter::new();
        pub static ref ENTROPY_SKIP: Counter = Counter::new();
        pub static ref COMPRESS_PREPROC_CALLS: Counter = Counter::new();
        pub static ref COMPRESS_PREPROC_TEXTUAL: Counter = Counter::new();
        pub static ref COMPRESS_PREPROC_BINARY: Counter = Counter::new();
        pub static ref COMPRESS_PREPROC_ASCII_BYTES: Counter = Counter::new();
        pub static ref COMPRESS_PREPROC_HIGH_BYTES: Counter = Counter::new();
        pub static ref COMPRESS_PREPROC_NEWLINES: Counter = Counter::new();
        pub static ref COMPRESS_PREPROC_NULLS: Counter = Counter::new();
        pub static ref COMPRESS_PREPROC_CHUNKS: Counter = Counter::new();
        pub static ref COMPRESS_PREPROC_CHUNK_REPEATS: Counter = Counter::new();

        // Body pool telemetry
        pub static ref BODY_POOL_BLOCK_SIZE: AtomicU64 = AtomicU64::new(0);
        pub static ref BODY_POOL_CAPACITY: AtomicU64 = AtomicU64::new(0);
        pub static ref BODY_POOL_ALLOCS: Counter = Counter::new();
    }

    // Split RS metrics into a separate block to avoid macro recursion limit
    lazy_static! {
        // Adaptive RS telemetry
        pub static ref RS_ENC_TIME_NS: AtomicU64 = AtomicU64::new(0);
        pub static ref RS_DEC_TIME_NS: AtomicU64 = AtomicU64::new(0);
        pub static ref RS_REPAIR_EMITTED: AtomicU64 = AtomicU64::new(0);
        pub static ref RS_RECOVERED: AtomicU64 = AtomicU64::new(0);
        pub static ref RS_OVERHEAD_PPM: AtomicU64 = AtomicU64::new(0); // (n-k)/k in ppm
        pub static ref RS_WINDOW_K: AtomicU64 = AtomicU64::new(0);
        pub static ref RS_WINDOW_N: AtomicU64 = AtomicU64::new(0);
        pub static ref RS_GF_SIZE: AtomicU64 = AtomicU64::new(0);

        // Memory pool hit/miss telemetry (separate block to reduce macro size)
        pub static ref MEM_POOL_HITS_TLS: Counter = Counter::new();
        pub static ref MEM_POOL_HITS_QUEUE: Counter = Counter::new();
        pub static ref MEM_POOL_ALLOC_GROW: Counter = Counter::new();
        pub static ref MEM_POOL_ALLOC_EPHEMERAL: Counter = Counter::new();
    }

    /// Emit a simple telemetry text snapshot for core counters.
    pub fn telemetry_snapshot_text() -> String {
        let mut s = String::new();
        // MASQUE Kapseln
        s.push_str("# TYPE quicfuscate_masque_capsule_00_total counter\n");
        s.push_str(&format!("quicfuscate_masque_capsule_00_total {}\n", MASQUE_CAPSULE_00.get()));
        s.push_str("# TYPE quicfuscate_masque_capsule_21_total counter\n");
        s.push_str(&format!("quicfuscate_masque_capsule_21_total {}\n", MASQUE_CAPSULE_21.get()));
        s.push_str("# TYPE quicfuscate_masque_capsule_22_total counter\n");
        s.push_str(&format!("quicfuscate_masque_capsule_22_total {}\n", MASQUE_CAPSULE_22.get()));

        // Kompression
        s.push_str("# TYPE quicfuscate_compress_attempts_total counter\n");
        s.push_str(&format!("quicfuscate_compress_attempts_total {}\n", COMPRESS_ATTEMPTS.get()));
        s.push_str("# TYPE quicfuscate_compress_success_total counter\n");
        s.push_str(&format!("quicfuscate_compress_success_total {}\n", COMPRESS_SUCCESS.get()));
        s.push_str("# TYPE quicfuscate_compress_bytes_in_total counter\n");
        s.push_str(&format!("quicfuscate_compress_bytes_in_total {}\n", COMPRESS_BYTES_IN.get()));
        s.push_str("# TYPE quicfuscate_compress_bytes_out_total counter\n");
        s.push_str(&format!("quicfuscate_compress_bytes_out_total {}\n", COMPRESS_BYTES_OUT.get()));
        s.push_str("# TYPE quicfuscate_compress_preproc_calls_total counter\n");
        s.push_str(&format!(
            "quicfuscate_compress_preproc_calls_total {}\n",
            COMPRESS_PREPROC_CALLS.get()
        ));
        s.push_str("# TYPE quicfuscate_compress_preproc_textual_total counter\n");
        s.push_str(&format!(
            "quicfuscate_compress_preproc_textual_total {}\n",
            COMPRESS_PREPROC_TEXTUAL.get()
        ));
        s.push_str("# TYPE quicfuscate_compress_preproc_binary_total counter\n");
        s.push_str(&format!(
            "quicfuscate_compress_preproc_binary_total {}\n",
            COMPRESS_PREPROC_BINARY.get()
        ));
        s.push_str("# TYPE quicfuscate_compress_preproc_ascii_bytes_total counter\n");
        s.push_str(&format!(
            "quicfuscate_compress_preproc_ascii_bytes_total {}\n",
            COMPRESS_PREPROC_ASCII_BYTES.get()
        ));
        s.push_str("# TYPE quicfuscate_compress_preproc_newlines_total counter\n");
        s.push_str(&format!(
            "quicfuscate_compress_preproc_newlines_total {}\n",
            COMPRESS_PREPROC_NEWLINES.get()
        ));
        s.push_str("# TYPE quicfuscate_compress_preproc_nulls_total counter\n");
        s.push_str(&format!(
            "quicfuscate_compress_preproc_nulls_total {}\n",
            COMPRESS_PREPROC_NULLS.get()
        ));
        s.push_str("# TYPE quicfuscate_compress_preproc_high_bytes_total counter\n");
        s.push_str(&format!(
            "quicfuscate_compress_preproc_high_bytes_total {}\n",
            COMPRESS_PREPROC_HIGH_BYTES.get()
        ));
        s.push_str("# TYPE quicfuscate_compress_preproc_chunks_total counter\n");
        s.push_str(&format!(
            "quicfuscate_compress_preproc_chunks_total {}\n",
            COMPRESS_PREPROC_CHUNKS.get()
        ));
        s.push_str("# TYPE quicfuscate_compress_preproc_chunk_repeats_total counter\n");
        s.push_str(&format!(
            "quicfuscate_compress_preproc_chunk_repeats_total {}\n",
            COMPRESS_PREPROC_CHUNK_REPEATS.get()
        ));

        // Pools
        s.push_str("# TYPE quicfuscate_body_pool_allocs_total counter\n");
        s.push_str(&format!("quicfuscate_body_pool_allocs_total {}\n", BODY_POOL_ALLOCS.get()));
        s.push_str("# TYPE quicfuscate_mem_pool_hits_tls_total counter\n");
        s.push_str(&format!("quicfuscate_mem_pool_hits_tls_total {}\n", MEM_POOL_HITS_TLS.get()));
        s.push_str("# TYPE quicfuscate_mem_pool_hits_queue_total counter\n");
        s.push_str(&format!(
            "quicfuscate_mem_pool_hits_queue_total {}\n",
            MEM_POOL_HITS_QUEUE.get()
        ));
        s.push_str("# TYPE quicfuscate_mem_pool_alloc_grow_total counter\n");
        s.push_str(&format!(
            "quicfuscate_mem_pool_alloc_grow_total {}\n",
            MEM_POOL_ALLOC_GROW.get()
        ));
        s.push_str("# TYPE quicfuscate_mem_pool_alloc_ephemeral_total counter\n");
        s.push_str(&format!(
            "quicfuscate_mem_pool_alloc_ephemeral_total {}\n",
            MEM_POOL_ALLOC_EPHEMERAL.get()
        ));

        // CPU/Features (Gauges)
        s.push_str("# TYPE quicfuscate_simd_usage_avx2_total counter\n");
        s.push_str(&format!(
            "quicfuscate_simd_usage_avx2_total {}\n",
            SIMD_USAGE_AVX2.load(Ordering::Relaxed)
        ));
        s.push_str("# TYPE quicfuscate_simd_usage_avx512_total counter\n");
        s.push_str(&format!(
            "quicfuscate_simd_usage_avx512_total {}\n",
            SIMD_USAGE_AVX512.load(Ordering::Relaxed)
        ));
        s.push_str("# TYPE quicfuscate_simd_usage_avx10_256_total counter\n");
        s.push_str(&format!(
            "quicfuscate_simd_usage_avx10_256_total {}\n",
            SIMD_USAGE_AVX10_256.load(Ordering::Relaxed)
        ));
        s.push_str("# TYPE quicfuscate_simd_usage_avx10_512_total counter\n");
        s.push_str(&format!(
            "quicfuscate_simd_usage_avx10_512_total {}\n",
            SIMD_USAGE_AVX10_512.load(Ordering::Relaxed)
        ));
        s
    }

    // Static counters
    pub static PACKETS_SENT: Counter = Counter::new();
    pub static PACKETS_RECEIVED: Counter = Counter::new();
    pub static PACKETS_LOST: Counter = Counter::new();
    pub static PATH_MIGRATIONS: Counter = Counter::new();
    pub static FEC_PACKETS_ENCODED: Counter = Counter::new();
    pub static FEC_PACKETS_DECODED: Counter = Counter::new();
    pub static FEC_PACKETS_RECOVERED: Counter = Counter::new();
    pub static ENCODED_PACKETS: Counter = Counter::new();
    pub static DECODED_PACKETS: Counter = Counter::new();
    pub static DECODED_PARTIAL_PACKETS: Counter = Counter::new();
    pub static STEALTH_QPACK_POOL_FALLBACKS: Counter = Counter::new();
    pub static STEALTH_HEADERS_GENERATED: Counter = Counter::new();
    pub static XDP_PACKETS_SENT: Counter = Counter::new();
    pub static XDP_PACKETS_RECEIVED: Counter = Counter::new();

    pub fn update_memory_usage() {
        use sysinfo::ProcessesToUpdate;
        let mut sys = sysinfo::System::new_all();
        if let Ok(pid) = sysinfo::get_current_pid() {
            sys.refresh_processes(ProcessesToUpdate::All, true);
            if let Some(proc_) = sys.process(pid) {
                let mem = proc_.memory();
                MEMORY_USAGE_BYTES.store(mem * 1024, Ordering::Relaxed);
            }
        }
    }

    pub fn flush() {
        if TELEMETRY_ENABLED.load(Ordering::Relaxed) {
            update_memory_usage();
            let pool = crate::optimize::global_pool();
            pool.refresh_metrics();
        }
    }

    // TELEMETRY_ENABLED flag for compatibility
    use std::sync::atomic::AtomicBool;
    pub static TELEMETRY_ENABLED: AtomicBool = AtomicBool::new(false);

    #[macro_export]
    macro_rules! telemetry {
        ($expr:expr) => {
            $expr
        };
    }
}
