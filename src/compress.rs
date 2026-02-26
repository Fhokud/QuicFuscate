use crate::accelerate::compress::classify as classify_bytes;
use crate::optimize::{CpuProfile, FeatureDetector, MemoryPool};
use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};
use zstd::stream::raw::CParameter;

pub struct CompressionConfig {
    pub min_len: usize,
    pub max_level: i32,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self { min_len: 256, max_level: 5 }
    }
}

pub struct CompressionManager {
    cfg: CompressionConfig,
}

#[derive(Clone, Debug, Default)]
pub struct CompressionAnalysis {
    pub len: usize,
    pub ascii_bytes: u32,
    pub newline_bytes: u32,
    pub carriage_bytes: u32,
    pub tab_bytes: u32,
    pub null_bytes: u32,
    pub high_bytes: u32,
    pub entropy_bits_per_byte: f64,
    pub chunk_total: u32,
    pub chunk_repeated: u32,
    pub chunk_max_bin: u32,
}

impl CompressionAnalysis {
    pub fn ascii_ratio(&self) -> f32 {
        if self.len == 0 {
            return 0.0;
        }
        self.ascii_bytes as f32 / self.len as f32
    }

    pub fn newline_ratio(&self) -> f32 {
        if self.len == 0 {
            return 0.0;
        }
        (self.newline_bytes + self.carriage_bytes) as f32 / self.len as f32
    }

    pub fn null_ratio(&self) -> f32 {
        if self.len == 0 {
            return 0.0;
        }
        self.null_bytes as f32 / self.len as f32
    }

    pub fn high_ratio(&self) -> f32 {
        if self.len == 0 {
            return 0.0;
        }
        self.high_bytes as f32 / self.len as f32
    }

    pub fn chunk_repeat_ratio(&self) -> f32 {
        if self.chunk_total == 0 {
            return 0.0;
        }
        self.chunk_repeated as f32 / self.chunk_total as f32
    }

    pub fn chunk_skew(&self) -> f32 {
        if self.chunk_total == 0 {
            return 0.0;
        }
        self.chunk_max_bin as f32 / self.chunk_total as f32
    }

    pub fn is_textual(&self) -> bool {
        if self.len == 0 {
            return false;
        }
        let ascii = self.ascii_ratio();
        if ascii >= 0.75 {
            return true;
        }
        let entropy = self.entropy_bits_per_byte;
        let newline = self.newline_ratio();
        let high = self.high_ratio();

        (entropy <= 7.0 && ascii >= 0.55 && high <= 0.35)
            || (newline >= 0.01 && ascii >= 0.5 && high <= 0.4)
    }

    pub fn record_telemetry(&self) {
        use crate::optimize::telemetry;

        telemetry::COMPRESS_PREPROC_CALLS.inc();
        telemetry::COMPRESS_PREPROC_ASCII_BYTES.inc_by(self.ascii_bytes as u64);
        telemetry::COMPRESS_PREPROC_NEWLINES
            .inc_by((self.newline_bytes + self.carriage_bytes) as u64);
        telemetry::COMPRESS_PREPROC_NULLS.inc_by(self.null_bytes as u64);
        telemetry::COMPRESS_PREPROC_HIGH_BYTES.inc_by(self.high_bytes as u64);
        telemetry::COMPRESS_PREPROC_CHUNKS.inc_by(self.chunk_total as u64);
        telemetry::COMPRESS_PREPROC_CHUNK_REPEATS.inc_by(self.chunk_repeated as u64);

        if self.is_textual() {
            telemetry::COMPRESS_PREPROC_TEXTUAL.inc();
        } else {
            telemetry::COMPRESS_PREPROC_BINARY.inc();
        }
    }

    pub fn from_sample(data: &[u8], sample_len: usize) -> Self {
        let slice = if data.len() > sample_len { &data[..sample_len] } else { data };
        Self::from_slice(slice, false)
    }

    pub fn from_full(data: &[u8]) -> Self {
        Self::from_slice(data, true)
    }

    fn from_slice(data: &[u8], compute_chunks: bool) -> Self {
        if data.is_empty() {
            return Self::default();
        }

        let counters = classify_bytes(data);
        let entropy = estimate_entropy_bits_per_byte(data);
        let (chunk_total, chunk_repeated, chunk_max_bin) =
            if compute_chunks { compute_chunk_metrics(data) } else { (0, 0, 0) };

        CompressionAnalysis {
            len: counters.len,
            ascii_bytes: counters.ascii_printable,
            newline_bytes: counters.newline,
            carriage_bytes: counters.carriage_return,
            tab_bytes: counters.tab,
            null_bytes: counters.nulls,
            high_bytes: counters.high_bytes,
            entropy_bits_per_byte: entropy,
            chunk_total,
            chunk_repeated,
            chunk_max_bin,
        }
    }
}

impl CompressionManager {
    pub fn new(cfg: CompressionConfig) -> Self {
        Self { cfg }
    }

    /// Heuristic: compress only if size >= min_len and link conditions favor it.
    /// Note: Entropy checks require access to payload bytes; callers may use
    /// `looks_textual()` prior to calling when data is available.
    pub fn should_compress(&self, len: usize, rtt_ms: f32, loss: f32, bw_bps: u64) -> bool {
        crate::optimize::telemetry::COMPRESS_DECISIONS_TOTAL.inc();
        if len < self.cfg.min_len {
            crate::optimize::telemetry::COMPRESS_DECISIONS_SKIP_LEN.inc();
            return false;
        }
        // Prefer compression on slower links or high RTT, avoid on high loss.
        let slow_link = bw_bps > 0 && bw_bps < 10_000_000; // <10 Mbps
        let high_rtt = rtt_ms > 80.0;
        let loss_gate = loss < 0.15; // save CPU on very lossy links
        if !loss_gate {
            crate::optimize::telemetry::COMPRESS_DECISIONS_SKIP_LOSS.inc();
            return false;
        }
        let allow = slow_link || high_rtt;
        if allow {
            crate::optimize::telemetry::COMPRESS_DECISIONS_ALLOW.inc();
            true
        } else {
            crate::optimize::telemetry::COMPRESS_DECISIONS_SKIP_PROFILE.inc();
            false
        }
    }

    /// Lightweight textuality heuristic with centralized SIMD entropy calculation.
    pub fn looks_textual(data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        let analysis = CompressionAnalysis::from_sample(data, 1024);
        if analysis.is_textual() {
            crate::optimize::telemetry::ENTROPY_TEXTUAL_SEEN.inc();
            true
        } else {
            crate::optimize::telemetry::ENTROPY_SKIP.inc();
            false
        }
    }

    /// Compress using zstd (multi-threaded when available) into a pooled block; returns (block, used)
    pub fn compress_to_pool(
        &self,
        pool: &Arc<MemoryPool>,
        data: &[u8],
    ) -> Option<(aligned_box::AlignedBox<[u8]>, usize)> {
        crate::optimize::telemetry::COMPRESS_ATTEMPTS.inc();
        let analysis = CompressionAnalysis::from_full(data);
        analysis.record_telemetry();
        let mut out = pool.alloc();
        crate::optimize::telemetry::BODY_POOL_ALLOCS.inc();
        // Reserve space for a simple header: 1 byte magic + 4 bytes orig len
        if out.len() < 5 {
            return None;
        }
        out[0] = 0x5A; // 'Z'
        let orig_len = data.len() as u32;
        crate::optimize::telemetry::COMPRESS_BYTES_IN.inc_by(orig_len as u64);
        out[1..5].copy_from_slice(&orig_len.to_be_bytes());
        let dst = &mut out[5..];
        // Auto-gate: use streaming encoder for large payloads to reduce latency.
        let mut encoder = match zstd::stream::Encoder::new(Vec::new(), self.cfg.max_level) {
            Ok(enc) => enc,
            Err(_) => return None,
        };
        self.tune_encoder(&mut encoder, data.len(), &analysis);
        if encoder.write_all(data).is_err() {
            return None;
        }
        let z = match encoder.finish() {
            Ok(buf) => buf,
            Err(_) => return None,
        };
        // Do not allow truncation: only copy if result fits.
        if z.len() > dst.len() {
            // Not enough space in current block - signal caller to skip compression.
            return None;
        }
        dst[..z.len()].copy_from_slice(&z[..]);
        crate::optimize::telemetry::COMPRESS_SUCCESS.inc();
        crate::optimize::telemetry::COMPRESS_BYTES_OUT.inc_by(z.len() as u64);
        Some((out, 5 + z.len()))
    }

    fn tune_encoder(
        &self,
        encoder: &mut zstd::stream::Encoder<'_, Vec<u8>>,
        input_len: usize,
        analysis: &CompressionAnalysis,
    ) {
        tune_encoder_with_analysis(encoder, input_len, analysis, self.cfg.max_level);
    }

    /// Decompress a pooled buffer created by compress_to_pool
    pub fn decompress_to_pool(
        &self,
        pool: &Arc<MemoryPool>,
        data: &[u8],
    ) -> Option<(aligned_box::AlignedBox<[u8]>, usize)> {
        if data.len() < 5 || data[0] != 0x5A {
            return None;
        }
        let mut len_buf = [0u8; 4];
        len_buf.copy_from_slice(&data[1..5]);
        let orig_len = u32::from_be_bytes(len_buf) as usize;
        let mut out = pool.alloc();
        if out.len() < orig_len {
            return None;
        }
        match zstd::decode_all(&data[5..]) {
            Ok(z) => {
                let n = z.len().min(out.len());
                out[..n].copy_from_slice(&z[..n]);
                Some((out, n))
            }
            Err(_) => None,
        }
    }
}

fn tune_encoder_with_analysis(
    encoder: &mut zstd::stream::Encoder<'_, Vec<u8>>,
    input_len: usize,
    analysis: &CompressionAnalysis,
    max_level: i32,
) {
    let threads = std::thread::available_parallelism().map(|v| v.get()).unwrap_or(1);
    if threads > 1 && input_len >= 64 * 1024 {
        let workers = threads.min(8) as u32;
        let _ = encoder.set_parameter(CParameter::NbWorkers(workers));
    }

    let textual = analysis.is_textual();
    if input_len >= 128 * 1024 || analysis.chunk_repeat_ratio() >= 0.35 {
        let _ = encoder.set_parameter(CParameter::EnableLongDistanceMatching(true));
    }

    let profile = FeatureDetector::instance().profile();
    match profile {
        CpuProfile::X86_P3a
        | CpuProfile::X86_P3b
        | CpuProfile::X86_P3c
        | CpuProfile::X86_P3d
        | CpuProfile::X86_P3e
        | CpuProfile::X86_P4a
        | CpuProfile::X86_P4b => {
            // Wider vectors benefit from larger target block sizes
            let _ = encoder.set_parameter(CParameter::TargetLength(8192));
        }
        CpuProfile::X86_P2a | CpuProfile::X86_P2b => {
            let target = if textual { 4096 } else { 6144 };
            let _ = encoder.set_parameter(CParameter::TargetLength(target));
        }
        CpuProfile::ARM_A2 | CpuProfile::Apple_M => {
            let target = if textual { 3072 } else { 4096 };
            let _ = encoder.set_parameter(CParameter::TargetLength(target));
        }
        _ => {
            let target = if textual { 2048 } else { 3072 };
            let _ = encoder.set_parameter(CParameter::TargetLength(target));
        }
    }

    if textual && analysis.null_ratio() < 0.01 {
        let _ = encoder.set_parameter(CParameter::CompressionLevel(max_level.max(6)));
    }
}

#[derive(Clone, Debug)]
pub struct CompressionPolicy {
    pub enabled: bool,
    pub min_len: usize,
    pub level: i32,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

impl Default for CompressionPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            min_len: 256,
            level: 5,
            allow: vec!["text/*".into(), "application/json".into()],
            deny: vec![
                "image/*".into(),
                "video/*".into(),
                "audio/*".into(),
                "application/zip".into(),
            ],
        }
    }
}

static GLOBAL_POLICY: OnceLock<Mutex<CompressionPolicy>> = OnceLock::new();

pub fn global_policy() -> CompressionPolicy {
    GLOBAL_POLICY
        .get_or_init(|| Mutex::new(CompressionPolicy::from_env()))
        .lock()
        .unwrap_or_else(|p| {
            // Recover from poisoned mutex
            p.into_inner()
        })
        .clone()
}

pub fn set_global_policy(pol: CompressionPolicy) {
    if let Some(m) = GLOBAL_POLICY.get() {
        if let Ok(mut g) = m.lock() {
            *g = pol;
        }
    } else {
        let _ = GLOBAL_POLICY.set(Mutex::new(pol));
    }
}

impl CompressionPolicy {
    pub fn from_env() -> Self {
        let mut p = CompressionPolicy::default();
        if let Ok(v) = std::env::var("QUICFUSCATE_COMPRESS") {
            p.enabled = !(v == "0" || v.eq_ignore_ascii_case("false"));
        }
        if let Ok(v) = std::env::var("QUICFUSCATE_COMPRESS_MIN") {
            if let Ok(n) = v.parse() {
                p.min_len = n;
            }
        }
        if let Ok(v) = std::env::var("QUICFUSCATE_COMPRESS_LEVEL") {
            if let Ok(n) = v.parse() {
                p.level = n;
            }
        }
        if let Ok(v) = std::env::var("QUICFUSCATE_COMPRESS_ALLOW") {
            p.allow = v
                .split(',')
                .filter_map(|s| {
                    let trimmed = s.trim();
                    if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed.to_owned())
                    }
                })
                .collect();
        }
        if let Ok(v) = std::env::var("QUICFUSCATE_COMPRESS_DENY") {
            p.deny = v
                .split(',')
                .filter_map(|s| {
                    let trimmed = s.trim();
                    if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed.to_owned())
                    }
                })
                .collect();
        }
        p
    }
}

// -------------------- Persona + ContentClass Mapping --------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ContentClass {
    Json,
    Html,
    Css,
    Js,
    Text,
}

#[derive(Clone, Debug)]
struct PersonaState {
    name: String,
}

static PERSONA: OnceLock<Mutex<PersonaState>> = OnceLock::new();

pub fn set_current_persona(name: &str) {
    load_all_dicts_from_dir();
    if let Some(m) = PERSONA.get() {
        if let Ok(mut p) = m.lock() {
            p.name.clear();
            p.name.push_str(name);
            return;
        }
    }
    let _ = PERSONA.set(Mutex::new(PersonaState { name: name.to_owned() }));
}

fn current_persona() -> String {
    PERSONA
        .get_or_init(|| Mutex::new(PersonaState { name: "default".into() }))
        .lock()
        .map(|p| p.name.clone())
        .unwrap_or_else(|_| "default".into())
}

pub fn classify_content_type(ct: &str) -> ContentClass {
    let lc = ct.to_ascii_lowercase();
    if lc.contains("application/json") {
        return ContentClass::Json;
    }
    if lc.contains("text/html") {
        return ContentClass::Html;
    }
    if lc.contains("text/css") {
        return ContentClass::Css;
    }
    if lc.contains("application/javascript") || lc.contains("text/javascript") {
        return ContentClass::Js;
    }
    ContentClass::Text
}

// -------------------- Dictionary Registry --------------------

#[derive(Default)]
struct DictEntry {
    dict: Option<Vec<u8>>, // trained dict bytes
    version: u32,
    samples: Vec<Vec<u8>>, // training samples reservoir
}

type DictKey = (String, ContentClass);
static DICT_REG: OnceLock<Mutex<HashMap<DictKey, DictEntry>>> = OnceLock::new();
type DictId = (u16, u16); // (hash, version)
static DICT_INDEX: OnceLock<Mutex<HashMap<DictId, Vec<u8>>>> = OnceLock::new();

fn dicts() -> std::sync::MutexGuard<'static, HashMap<DictKey, DictEntry>> {
    DICT_REG.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap_or_else(|p| p.into_inner())
}

fn dict_index() -> std::sync::MutexGuard<'static, HashMap<DictId, Vec<u8>>> {
    DICT_INDEX.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap_or_else(|p| p.into_inner())
}

pub fn submit_sample(ct: &str, data: &[u8]) {
    let class = classify_content_type(ct);
    let persona = current_persona();
    let mut reg = dicts();
    let e = reg.entry((persona, class)).or_default();
    // Cap sample size per entry.
    let take = data.len().min(4096);
    e.samples.push(data[..take].to_vec());
    // Reservoir limitieren
    if e.samples.len() > 200 {
        e.samples.remove(0);
    }
}

pub fn maybe_train(ct: &str) {
    let class = classify_content_type(ct);
    let persona = current_persona();
    let mut reg = dicts();
    if let Some(e) = reg.get_mut(&(persona, class)) {
        if e.dict.is_some() {
            return;
        }
        if e.samples.len() < 40 {
            return;
        }
        let dict_size = 32 * 1024; // 32KiB
                                   // zstd::dict::from_samples API (best-effort)
        let samples: Vec<&[u8]> = e.samples.iter().map(|v| v.as_slice()).collect();
        match zstd::dict::from_samples(&samples, dict_size) {
            Ok(bytes) => {
                let mut hash: u16 = 0u16;
                for b in bytes.iter().take(64) {
                    hash = hash.wrapping_mul(257).wrapping_add(*b as u16);
                }
                e.dict = Some(bytes.clone());
                e.version = e.version.wrapping_add(1);
                dict_index().insert((hash, e.version as u16), bytes.clone());
                let _ = persist_dict(&current_persona(), class, e.version, &bytes, hash);
                e.samples.clear();
            }
            Err(_) => { /* Training failed; retry later. */ }
        }
    }
}

pub fn get_dict(ct: &str) -> Option<(Vec<u8>, u32)> {
    let class = classify_content_type(ct);
    let persona = current_persona();
    let reg = dicts();
    reg.get(&(persona, class)).and_then(|e| e.dict.as_ref().map(|d| (d.clone(), e.version)))
}

pub fn get_dict_by_id(hash: u16, version: u16) -> Option<Vec<u8>> {
    dict_index().get(&(hash, version)).cloned()
}

/// Calculate entropy from histogram using Shannon formula
fn calculate_entropy_from_histogram(histogram: &[u32; 256], total_len: usize) -> f64 {
    if total_len == 0 {
        return 0.0;
    }

    let mut entropy = 0.0;
    let total = total_len as f64;

    for &count in histogram.iter() {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Fallback entropy estimation for compatibility
pub(crate) fn estimate_entropy_bits_per_byte(data: &[u8]) -> f64 {
    // Use the central SIMD histogram implementation
    let histogram = crate::optimize::simd::compress::histogram(data);
    calculate_entropy_from_histogram(&histogram, data.len())
}

fn compute_chunk_metrics(data: &[u8]) -> (u32, u32, u32) {
    const CHUNK: usize = 64;
    if data.is_empty() {
        return (0, 0, 0);
    }

    let mut bins = [0u32; 8];
    let mut total = 0u32;
    let mut repeated = 0u32;
    let mut prev_hash = None;

    let mut offset = 0usize;
    while offset < data.len() {
        let end = (offset + CHUNK).min(data.len());
        let mut hash: u32 = 0x811C_9DC5;
        for &byte in &data[offset..end] {
            hash = hash.rotate_left(5) ^ (byte as u32);
        }
        let bin = (hash & 7) as usize;
        bins[bin] = bins[bin].saturating_add(1);
        if let Some(prev) = prev_hash {
            if prev == hash {
                repeated = repeated.saturating_add(1);
            }
        }
        prev_hash = Some(hash);
        total = total.saturating_add(1);
        offset += CHUNK;
    }

    let max_bin = bins.into_iter().max().unwrap_or(0);
    (total, repeated, max_bin)
}

// -------------------- Zstd with dictionary --------------------

pub fn compress_with_dict(
    _pool: &Arc<MemoryPool>,
    data: &[u8],
    level: i32,
    dict_bytes: &[u8],
    dict_version: u32,
) -> Option<(aligned_box::AlignedBox<[u8]>, usize)> {
    use std::io::Write;
    crate::optimize::telemetry::COMPRESS_ATTEMPTS.inc();
    let analysis = CompressionAnalysis::from_full(data);
    analysis.record_telemetry();
    let mut out = body_pool().alloc(); // prefer large blocks
    crate::optimize::telemetry::BODY_POOL_ALLOCS.inc();
    // Header: 1 byte magic (0x5D) + 2 bytes dict id hash + 2 bytes version + 4 bytes orig len
    if out.len() < 9 {
        return None;
    }
    out[0] = 0x5D; // ']' marker
                   // naive id-hash (not security-critical):
    let mut hash: u16 = 0u16;
    for b in dict_bytes.iter().take(64) {
        hash = hash.wrapping_mul(257).wrapping_add(*b as u16);
    }
    out[1..3].copy_from_slice(&hash.to_be_bytes());
    out[3..5].copy_from_slice(&(dict_version as u16).to_be_bytes());
    let orig_len = data.len() as u32;
    out[5..9].copy_from_slice(&orig_len.to_be_bytes());
    let dst = &mut out[9..];
    // EncoderDictionary
    let mut enc = zstd::stream::Encoder::with_dictionary(Vec::new(), level, dict_bytes).ok()?;
    tune_encoder_with_analysis(&mut enc, data.len(), &analysis, level);
    enc.write_all(data).ok()?;
    let z = enc.finish().ok()?;
    let n = z.len().min(dst.len());
    dst[..n].copy_from_slice(&z[..n]);
    if n < z.len() {
        crate::optimize::telemetry::COMPRESS_TRUNCATIONS.inc();
    }
    crate::optimize::telemetry::COMPRESS_SUCCESS.inc();
    crate::optimize::telemetry::COMPRESS_DICT_USED.inc();
    crate::optimize::telemetry::COMPRESS_BYTES_IN.inc_by(orig_len as u64);
    crate::optimize::telemetry::COMPRESS_BYTES_OUT.inc_by(n as u64);
    Some((out, 9 + n))
}

pub fn decompress_with_dict(
    _pool: &Arc<MemoryPool>,
    data: &[u8],
    dict_bytes: &[u8],
) -> Option<(aligned_box::AlignedBox<[u8]>, usize)> {
    if data.len() < 9 || data[0] != 0x5D {
        return None;
    }
    let mut len_buf = [0u8; 4];
    len_buf.copy_from_slice(&data[5..9]);
    let orig_len = u32::from_be_bytes(len_buf) as usize;
    // Decoder with dictionary bytes.
    let mut dec = zstd::stream::Decoder::with_dictionary(&data[9..], dict_bytes).ok()?;
    let mut out = body_pool().alloc();
    if out.len() < orig_len {
        return None;
    }
    use std::io::Read;
    let n = dec.read(&mut out[..orig_len]).ok()?;
    Some((out, n))
}

// -------------------- Large Body Pool --------------------

static BODY_POOL: OnceLock<Arc<MemoryPool>> = OnceLock::new();
pub fn body_pool() -> Arc<MemoryPool> {
    BODY_POOL
        .get_or_init(|| {
            let cap = std::env::var("QUICFUSCATE_BODYPOOL_CAP")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(256);
            let blk = std::env::var("QUICFUSCATE_BODYPOOL_BLOCK")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(64 * 1024);
            // Telemetry
            crate::optimize::telemetry::BODY_POOL_BLOCK_SIZE
                .store(blk as u64, std::sync::atomic::Ordering::Relaxed);
            crate::optimize::telemetry::BODY_POOL_CAPACITY
                .store(cap as u64, std::sync::atomic::Ordering::Relaxed);
            Arc::new(MemoryPool::new(cap, blk))
        })
        .clone()
}

// -------------------- Persistenz: Dictionaries auf Disk --------------------

use std::path::PathBuf;
fn dict_dir() -> PathBuf {
    std::env::var("QUICFUSCATE_DICT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("dict_cache"))
}

fn class_str(c: ContentClass) -> &'static str {
    match c {
        ContentClass::Json => "json",
        ContentClass::Html => "html",
        ContentClass::Css => "css",
        ContentClass::Js => "js",
        ContentClass::Text => "text",
    }
}

fn persist_dict(
    persona: &str,
    class: ContentClass,
    version: u32,
    bytes: &[u8],
    hash: u16,
) -> std::io::Result<()> {
    use std::fs;
    let dir = dict_dir();
    fs::create_dir_all(&dir)?;
    let fname = format!(
        "{}_{}_v{}_h{:04x}.zdict",
        persona.replace('/', "-"),
        class_str(class),
        version,
        hash
    );
    let path = dir.join(fname);
    fs::write(path, bytes)
}

static DICT_LOADED: OnceLock<()> = OnceLock::new();
fn load_all_dicts_from_dir() {
    let _ = DICT_LOADED.get_or_init(|| {
        use std::fs;
        let dir = dict_dir();
        if let Ok(rd) = fs::read_dir(&dir) {
            for e in rd.flatten() {
                if let Ok(md) = e.metadata() {
                    if !md.is_file() {
                        continue;
                    }
                }
                let p = e.path();
                if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                    // pattern: persona_class_v{ver}_h{hash}.zdict
                    if let Some((ver, hash)) = parse_ver_hash(name) {
                        if let Ok(bytes) = fs::read(&p) {
                            dict_index().insert((hash, ver), bytes);
                        }
                    }
                }
            }
        }
    });
}

fn parse_ver_hash(name: &str) -> Option<(u16, u16)> {
    // find segments v#### (decimal) and h#### (hex) in name
    let mut v_opt: Option<u16> = None;
    let mut h_opt: Option<u16> = None;
    for part in name.split('_') {
        if let Some(rest) = part.strip_prefix('v') {
            if let Ok(n) = rest.trim_end_matches(|c: char| !c.is_ascii_digit()).parse::<u16>() {
                v_opt = Some(n);
            }
        } else if let Some(rest) = part.strip_prefix('h') {
            let cleaned = rest.trim_end_matches(|c: char| !c.is_ascii_hexdigit());
            if let Ok(n) = u16::from_str_radix(cleaned, 16) {
                h_opt = Some(n);
            }
        }
    }
    match (v_opt, h_opt) {
        (Some(v), Some(h)) => Some((v, h)),
        _ => None,
    }
}

#[inline]
pub fn mime_matches(pattern: &str, value: &str) -> bool {
    if let Some(pos) = pattern.find('/') {
        let (pt, ps) = pattern.split_at(pos);
        let ps = &ps[1..];
        if let Some(pos2) = value.find('/') {
            let (vt, vs) = value.split_at(pos2);
            let vs = &vs[1..];
            return (pt == vt || pt == "*")
                && (ps == vs
                    || ps == "*"
                    || (ps.ends_with("*") && vs.starts_with(&ps[..ps.len() - 1])));
        }
    }
    pattern == value
}

// -------------------- Entropy estimator --------------------
// DUPLICATE REMOVED - estimate_entropy_bits_per_byte is already defined earlier.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_gating_text_vs_binary() {
        // Text: ASCII-heavy
        let text = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\nHello World!";
        assert!(CompressionManager::looks_textual(text));
        // Binary: pseudo-random
        let mut bin = [0u8; 256];
        for (i, byte) in bin.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(37).rotate_left(1);
        }
        assert!(!CompressionManager::looks_textual(&bin));
    }
}
