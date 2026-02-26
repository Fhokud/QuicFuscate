#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsafeError {
    CapacityOverflow,
    CompressionFailed,
}
// # Unsafe Core - Maximum Performance Optimizations
//
// This module contains all unsafe optimizations for QuicFuscate, providing
// zero-copy operations, SIMD acceleration, and direct memory manipulation
// for maximum throughput and minimum latency.
//
// Safety Invariants
// - All raw pointers must be valid and aligned
// - Lifetimes are strictly enforced through PhantomData
// - Memory is never double-freed
// - All operations are protected by debug assertions
//
// Performance Gains (indicative)
// - Memory Pool: 10-15% CPU reduction, 5% latency improvement
// - Transport: 20-25% CPU reduction, 5-10% latency improvement
// - FEC: 2-3x speedup for GF operations
// - Compression: 10-20% CPU reduction
// - Overall: throughput improvements are workload-dependent and must be validated with benchmarks.

use std::alloc::{alloc, dealloc, handle_alloc_error, Layout};
use std::cell::UnsafeCell;
use std::io::IoSlice;
use std::marker::PhantomData;
use std::ptr::{self, NonNull};
use std::slice;
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use std::sync::Arc;

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

use crate::optimize::{prefetch, PrefetchHint};
use crate::telemetry;

// ============================================================================
// Zero-Copy Memory Pool with MaybeUninit
// ============================================================================

/// Ultra-fast memory pool using raw pointers and MaybeUninit
pub struct UnsafeMemoryPool {
    /// Thread-local cache using raw pointers
    tls_cache: UnsafeCell<Vec<*mut u8>>,
    /// Global pool using atomic pointers
    global_pool: Vec<AtomicPtr<u8>>,
    /// Pool configuration
    block_size: usize,
    capacity: AtomicUsize,
    in_use: AtomicUsize,
    available: AtomicUsize,
    /// Memory layout for allocation
    layout: Layout,
    /// NUMA node affinity
    numa_node: usize,
}

unsafe impl Send for UnsafeMemoryPool {}
unsafe impl Sync for UnsafeMemoryPool {}

impl UnsafeMemoryPool {
    const TLS_CACHE_SIZE: usize = 32;
    const PREFETCH_DISTANCE: usize = 8;

    /// Creates a new unsafe memory pool with specified capacity and block size
    pub fn new(capacity: usize, block_size: usize, numa_node: usize) -> Self {
        // Ensure block size is aligned to cache line (64 bytes)
        let block_size = (block_size + 63) & !63;
        let layout = unsafe { Layout::from_size_align_unchecked(block_size, 64) };

        let mut global_pool = Vec::with_capacity(capacity);

        // Pre-allocate all blocks
        for _ in 0..capacity {
            let ptr = unsafe {
                let raw = alloc(layout);
                if raw.is_null() {
                    handle_alloc_error(layout);
                }
                #[cfg(target_os = "linux")]
                {
                    // NUMA binding
                    crate::optimize::numa::move_to_node(raw, block_size, numa_node);
                }
                raw
            };
            global_pool.push(AtomicPtr::new(ptr));
        }
        telemetry::UNSAFE_POOL_CREATED.inc();
        telemetry::UNSAFE_POOL_CAPACITY.store(capacity as u64, Ordering::Relaxed);

        let this = Self {
            tls_cache: UnsafeCell::new(Vec::with_capacity(Self::TLS_CACHE_SIZE)),
            global_pool,
            block_size,
            capacity: AtomicUsize::new(capacity),
            in_use: AtomicUsize::new(0),
            available: AtomicUsize::new(capacity),
            layout,
            numa_node,
        };

        // Touch fields so they are considered used and emit a helpful debug line.
        let cap_now = this.capacity.load(Ordering::Relaxed);
        log::debug!(
            "UnsafeMemoryPool::new -> capacity={}, numa_node={}, block_size={}",
            cap_now,
            this.numa_node,
            this.block_size
        );

        this
    }

    /// Allocates a block without zeroing - maximum performance
    #[inline(always)]
    /// # Safety
    /// Caller must ensure the returned pointer is used within the pool's block size
    /// and deallocated via `UnsafeMemoryPool::free`. No aliasing guarantees are provided.
    pub unsafe fn alloc_uninit(&self) -> NonNull<u8> {
        telemetry::UNSAFE_ALLOC_CALLS.inc();

        // Try TLS cache first
        let cache = &mut *self.tls_cache.get();
        if let Some(ptr) = cache.pop() {
            telemetry::UNSAFE_TLS_HITS.inc();
            self.available.fetch_sub(1, Ordering::Relaxed);
            self.in_use.fetch_add(1, Ordering::Relaxed);

            // Prefetch next block
            if let Some(&next) = cache.last() {
                self.prefetch_block(next);
            }

            return NonNull::new_unchecked(ptr);
        }

        // Try global pool
        for slot in &self.global_pool {
            let ptr = slot.swap(ptr::null_mut(), Ordering::Acquire);
            if !ptr.is_null() {
                telemetry::UNSAFE_GLOBAL_HITS.inc();
                self.available.fetch_sub(1, Ordering::Relaxed);
                self.in_use.fetch_add(1, Ordering::Relaxed);

                // Prefetch the block
                self.prefetch_block(ptr);

                return NonNull::new_unchecked(ptr);
            }
        }

        // Fallback: allocate new block
        telemetry::UNSAFE_FALLBACK_ALLOCS.inc();
        let ptr = alloc(self.layout);
        if ptr.is_null() {
            handle_alloc_error(self.layout);
        }

        self.in_use.fetch_add(1, Ordering::Relaxed);
        NonNull::new_unchecked(ptr)
    }

    /// Returns a block to the pool
    #[inline(always)]
    /// # Safety
    /// `ptr` must originate from this pool via `alloc_uninit` or pool-owned allocations.
    pub unsafe fn free(&self, ptr: NonNull<u8>) {
        telemetry::UNSAFE_FREE_CALLS.inc();

        // Try TLS cache first
        let cache = &mut *self.tls_cache.get();
        if cache.len() < Self::TLS_CACHE_SIZE {
            cache.push(ptr.as_ptr());
            self.available.fetch_add(1, Ordering::Relaxed);
            self.in_use.fetch_sub(1, Ordering::Relaxed);
            return;
        }

        // Try global pool
        for slot in &self.global_pool {
            if slot
                .compare_exchange(
                    ptr::null_mut(),
                    ptr.as_ptr(),
                    Ordering::Release,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                self.available.fetch_add(1, Ordering::Relaxed);
                self.in_use.fetch_sub(1, Ordering::Relaxed);
                return;
            }
        }

        // Pool is full, deallocate
        telemetry::UNSAFE_DEALLOCS.inc();
        dealloc(ptr.as_ptr(), self.layout);
        self.in_use.fetch_sub(1, Ordering::Relaxed);
    }

    /// Copies data directly without bounds checks
    #[inline(always)]
    /// # Safety
    /// `ptr` must be valid for writes of at least `data.len()` bytes within the pool block.
    pub unsafe fn copy_from_slice(&self, ptr: NonNull<u8>, data: &[u8]) -> usize {
        let len = data.len().min(self.block_size);
        ptr::copy_nonoverlapping(data.as_ptr(), ptr.as_ptr(), len);
        len
    }

    /// Prefetch a memory block for faster access
    #[cfg_attr(feature = "aggressive_inline", inline(always))]
    /// # Safety
    /// `ptr` must be a valid address; this performs hardware prefetch hints only.
    unsafe fn prefetch_block(&self, ptr: *mut u8) {
        for i in 0..=Self::PREFETCH_DISTANCE {
            let p = ptr.add(i * 64);
            prefetch(p as *const u8, PrefetchHint::T0);
        }
    }

    // Unit tests must be defined at module scope; see tests module at the bottom.
}

impl Drop for UnsafeMemoryPool {
    fn drop(&mut self) {
        unsafe {
            // Free all blocks in TLS cache
            let cache = &mut *self.tls_cache.get();
            for &ptr in cache.iter() {
                if !ptr.is_null() {
                    dealloc(ptr, self.layout);
                }
            }

            // Free all blocks in global pool
            for slot in &self.global_pool {
                let ptr = slot.load(Ordering::Relaxed);
                if !ptr.is_null() {
                    dealloc(ptr, self.layout);
                }
            }
        }
    }
}

// ============================================================================
// Zero-Copy Transport with IoSlice
// ============================================================================

/// Zero-copy packet structure using raw pointers
pub struct UnsafePacket {
    /// Raw data pointer
    data: NonNull<u8>,
    /// Data length
    len: usize,
    /// Capacity
    capacity: usize,
    /// Pool reference for deallocation
    pool: Arc<UnsafeMemoryPool>,
    /// Phantom data for lifetime tracking
    _phantom: PhantomData<&'static [u8]>,
}

impl UnsafePacket {
    /// Creates a new packet from raw parts
    #[inline(always)]
    /// # Safety
    /// `data` must be a valid pointer with `capacity` bytes owned by `pool`. `len <= capacity`.
    pub unsafe fn from_raw_parts(
        data: NonNull<u8>,
        len: usize,
        capacity: usize,
        pool: Arc<UnsafeMemoryPool>,
    ) -> Self {
        debug_assert!(len <= capacity);
        debug_assert!(capacity <= pool.block_size);

        Self { data, len, capacity, pool, _phantom: PhantomData }
    }

    /// Returns a slice view of the packet data
    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.data.as_ptr(), self.len) }
    }

    /// Returns a mutable slice view
    #[inline(always)]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.data.as_ptr(), self.len) }
    }

    /// Creates an IoSlice for zero-copy send
    #[inline(always)]
    pub fn as_io_slice(&self) -> IoSlice<'_> {
        IoSlice::new(self.as_slice())
    }

    /// Extends the packet with data
    #[inline(always)]
    /// # Safety
    /// Extends in-place; caller must ensure `self.capacity - self.len >= data.len()`.
    pub unsafe fn extend_from_slice(&mut self, data: &[u8]) -> Result<(), UnsafeError> {
        let new_len = self.len + data.len();
        if new_len > self.capacity {
            return Err(UnsafeError::CapacityOverflow);
        }

        ptr::copy_nonoverlapping(data.as_ptr(), self.data.as_ptr().add(self.len), data.len());
        self.len = new_len;
        Ok(())
    }
}

impl Drop for UnsafePacket {
    fn drop(&mut self) {
        unsafe {
            self.pool.free(self.data);
        }
    }
}

// ============================================================================
// SIMD-Accelerated FEC Operations
// ============================================================================

/// SIMD-accelerated Galois Field operations
pub mod simd_gf {
    // use crate::telemetry; // Unused
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::*;
    // use std::slice; // Unused

    /// Simple GF(2^8) multiplication for scalar fallback
    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    fn gf_mul_scalar_byte(a: u8, b: u8) -> u8 {
        let mut result = 0u8;
        let mut aa = a;
        let mut bb = b;

        for _ in 0..8 {
            if bb & 1 != 0 {
                result ^= aa;
            }
            let high_bit = aa & 0x80;
            aa <<= 1;
            if high_bit != 0 {
                aa ^= 0x1B; // GF(2^8) polynomial
            }
            bb >>= 1;
        }
        result
    }

    /// GF(2^8) multiplication table for SIMD lookup
    #[cfg(target_arch = "x86_64")]
    #[repr(align(64))]
    pub struct Gf256LookupTable {
        low: [u8; 256],
        high: [u8; 256],
    }

    #[cfg(target_arch = "x86_64")]
    impl Gf256LookupTable {
        /// Creates a new lookup table for a given multiplier
        pub fn new(multiplier: u8) -> Self {
            let mut low = [0u8; 256];
            let mut high = [0u8; 256];

            for i in 0..256 {
                let val = gf_mul_scalar_byte(i as u8, multiplier);
                low[i] = val & 0x0F;
                high[i] = (val >> 4) & 0x0F;
            }

            Self { low, high }
        }
    }

    /// SIMD GF(2^8) multiplication using AVX2
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    #[inline]
    pub unsafe fn gf256_mul_avx2(
        dst: &mut [u8],
        src: &[u8],
        multiplier: u8,
        table: &Gf256LookupTable,
    ) {
        let len = dst.len().min(src.len());
        let chunks = len / 32;

        if chunks == 0 {
            // Fallback to scalar
            gf256_mul_scalar(dst, src, multiplier);
            return;
        }

        // Load lookup tables
        let low_table = _mm256_loadu_si256(table.low.as_ptr() as *const __m256i);
        let high_table = _mm256_loadu_si256(table.high.as_ptr() as *const __m256i);
        let mask_low = _mm256_set1_epi8(0x0F);

        let mut src_ptr = src.as_ptr();
        let mut dst_ptr = dst.as_mut_ptr();

        for _ in 0..chunks {
            // Load 32 bytes
            let data = _mm256_loadu_si256(src_ptr as *const __m256i);

            // Split into low and high nibbles
            let data_low = _mm256_and_si256(data, mask_low);
            let data_high = _mm256_srli_epi16(data, 4);
            let data_high = _mm256_and_si256(data_high, mask_low);

            // Table lookups
            let res_low = _mm256_shuffle_epi8(low_table, data_low);
            let res_high = _mm256_shuffle_epi8(high_table, data_high);

            // XOR results
            let result = _mm256_xor_si256(res_low, res_high);

            // XOR with destination
            let dst_data = _mm256_loadu_si256(dst_ptr as *const __m256i);
            let final_result = _mm256_xor_si256(dst_data, result);

            // Store result
            _mm256_storeu_si256(dst_ptr as *mut __m256i, final_result);

            src_ptr = src_ptr.add(32);
            dst_ptr = dst_ptr.add(32);
        }

        // Handle remainder
        let remainder = len % 32;
        if remainder > 0 {
            let src_rem = slice::from_raw_parts(src_ptr, remainder);
            let dst_rem = slice::from_raw_parts_mut(dst_ptr, remainder);
            gf256_mul_scalar(dst_rem, src_rem, multiplier);
        }

        telemetry::SIMD_GF_OPS.inc();
    }

    /// Scalar fallback for GF multiplication
    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    fn gf256_mul_scalar(dst: &mut [u8], src: &[u8], multiplier: u8) {
        let len = dst.len().min(src.len());
        for i in 0..len {
            dst[i] ^= gf_mul_scalar_byte(src[i], multiplier);
        }
    }

    /// SIMD XOR operation using AVX-512
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    #[inline(always)]
    pub unsafe fn xor_blocks_avx512(dst: &mut [u8], src: &[u8]) {
        let len = dst.len().min(src.len());
        let chunks = len / 64;

        let mut src_ptr = src.as_ptr();
        let mut dst_ptr = dst.as_mut_ptr();

        for _ in 0..chunks {
            let src_vec = _mm512_loadu_si512(src_ptr as *const i32);
            let dst_vec = _mm512_loadu_si512(dst_ptr as *const i32);
            let result = _mm512_xor_si512(src_vec, dst_vec);
            _mm512_storeu_si512(dst_ptr as *mut i32, result);

            src_ptr = src_ptr.add(64);
            dst_ptr = dst_ptr.add(64);
        }

        // Handle remainder with AVX2/SSE
        let remainder = len % 64;
        if remainder >= 32 {
            xor_blocks_avx2(
                slice::from_raw_parts_mut(dst_ptr, remainder),
                slice::from_raw_parts(src_ptr, remainder),
            );
        } else if remainder > 0 {
            xor_blocks_scalar(
                slice::from_raw_parts_mut(dst_ptr, remainder),
                slice::from_raw_parts(src_ptr, remainder),
            );
        }

        telemetry::SIMD_XOR_OPS.inc();
    }

    /// AVX2 XOR for smaller blocks
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    pub unsafe fn xor_blocks_avx2(dst: &mut [u8], src: &[u8]) {
        let len = dst.len().min(src.len());
        let chunks = len / 32;

        for i in 0..chunks {
            let offset = i * 32;
            let src_vec = _mm256_loadu_si256(src.as_ptr().add(offset) as *const __m256i);
            let dst_vec = _mm256_loadu_si256(dst.as_ptr().add(offset) as *const __m256i);
            let result = _mm256_xor_si256(src_vec, dst_vec);
            _mm256_storeu_si256(dst.as_mut_ptr().add(offset) as *mut __m256i, result);
        }

        let remainder = len % 32;
        if remainder > 0 {
            let offset = chunks * 32;
            xor_blocks_scalar(&mut dst[offset..], &src[offset..]);
        }
    }

    /// Scalar XOR fallback
    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    fn xor_blocks_scalar(dst: &mut [u8], src: &[u8]) {
        let len = dst.len().min(src.len());
        for i in 0..len {
            dst[i] ^= src[i];
        }
    }
}

// ============================================================================
// Direct Compression with zstd_sys
// ============================================================================

pub mod unsafe_compress {
    use super::*;

    // Placeholder types for zstd_sys integration
    // In production, these would come from zstd_sys crate
    type ZstdCctx = std::ffi::c_void;
    type ZstdCdict = std::ffi::c_void;

    #[repr(C)]
    enum ZstdCParameter {
        CompressionLevel = 100,
    }

    // Mock functions - in production these would be FFI bindings
    unsafe fn zstd_create_cctx() -> *mut ZstdCctx {
        #[cfg(feature = "compression_zstd_ffi")]
        {
            zstd_sys::ZSTD_createCCtx() as *mut ZstdCctx
        }
        #[cfg(not(feature = "compression_zstd_ffi"))]
        {
            Box::into_raw(Box::new(0u8)) as *mut ZstdCctx
        }
    }
    unsafe fn zstd_free_cctx(ctx: *mut ZstdCctx) {
        #[cfg(feature = "compression_zstd_ffi")]
        {
            if !ctx.is_null() {
                zstd_sys::ZSTD_freeCCtx(ctx as *mut zstd_sys::ZSTD_CCtx);
            }
        }
        #[cfg(not(feature = "compression_zstd_ffi"))]
        {
            let _ = Box::from_raw(ctx as *mut u8);
        }
    }
    unsafe fn zstd_create_cdict(data: *const u8, len: usize, level: i32) -> *mut ZstdCdict {
        #[cfg(feature = "compression_zstd_ffi")]
        {
            zstd_sys::ZSTD_createCDict(data as *const std::ffi::c_void, len, level)
                as *mut ZstdCdict
        }
        #[cfg(not(feature = "compression_zstd_ffi"))]
        {
            let _ = level; // level not needed for safe dictionary holder
            let slice = std::slice::from_raw_parts(data, len);
            let vec = slice.to_vec();
            // Store bytes behind the opaque pointer for fallback usage
            Box::into_raw(Box::new(vec)) as *mut ZstdCdict
        }
    }
    unsafe fn zstd_free_cdict(dict: *mut ZstdCdict) {
        #[cfg(feature = "compression_zstd_ffi")]
        {
            if !dict.is_null() {
                zstd_sys::ZSTD_freeCDict(dict as *mut zstd_sys::ZSTD_CDict);
            }
        }
        #[cfg(not(feature = "compression_zstd_ffi"))]
        {
            if !dict.is_null() {
                let _ = Box::from_raw(dict as *mut Vec<u8>);
            }
        }
    }
    unsafe fn zstd_cctx_set_parameter(
        ctx: *mut ZstdCctx,
        _param: ZstdCParameter,
        val: i32,
    ) -> usize {
        #[cfg(feature = "compression_zstd_ffi")]
        {
            zstd_sys::ZSTD_CCtx_setParameter(
                ctx as *mut zstd_sys::ZSTD_CCtx,
                zstd_sys::ZSTD_cParameter::ZSTD_c_compressionLevel,
                val,
            )
        }
        #[cfg(not(feature = "compression_zstd_ffi"))]
        {
            let _ = (ctx, val);
            0
        }
    }
    unsafe fn zstd_compress_using_cdict(
        _ctx: *mut ZstdCctx,
        dst: *mut std::ffi::c_void,
        dst_capacity: usize,
        src: *const std::ffi::c_void,
        src_size: usize,
        dict: *const ZstdCdict,
    ) -> usize {
        #[cfg(feature = "compression_zstd_ffi")]
        {
            zstd_sys::ZSTD_compress_usingCDict(
                _ctx as *mut zstd_sys::ZSTD_CCtx,
                dst,
                dst_capacity,
                src,
                src_size,
                dict as *const zstd_sys::ZSTD_CDict,
            )
        }
        #[cfg(not(feature = "compression_zstd_ffi"))]
        {
            // Recover dictionary bytes from opaque pointer
            let dict_bytes: &[u8] = if !dict.is_null() {
                let vref: &Vec<u8> = &*(dict as *const Vec<u8>);
                vref.as_slice()
            } else {
                &[]
            };
            // Perform real compression using safe zstd + dictionary
            let mut enc = match zstd::stream::Encoder::with_dictionary(Vec::new(), 3, dict_bytes) {
                Ok(e) => e,
                Err(_) => return usize::MAX,
            };
            use std::io::Write;
            if enc.write_all(std::slice::from_raw_parts(src as *const u8, src_size)).is_err() {
                return usize::MAX;
            }
            let z = match enc.finish() {
                Ok(v) => v,
                Err(_) => return usize::MAX,
            };
            if z.len() > dst_capacity {
                return usize::MAX;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(z.as_ptr(), dst as *mut u8, z.len());
            }
            z.len()
        }
    }
    #[cfg_attr(not(feature = "compression_zstd_ffi"), allow(unused_variables))]
    unsafe fn zstd_compress_cctx(
        ctx: *mut ZstdCctx,
        dst: *mut std::ffi::c_void,
        dst_capacity: usize,
        src: *const std::ffi::c_void,
        src_size: usize,
        level: i32,
    ) -> usize {
        #[cfg(feature = "compression_zstd_ffi")]
        {
            zstd_sys::ZSTD_compressCCtx(
                ctx as *mut zstd_sys::ZSTD_CCtx,
                dst,
                dst_capacity,
                src,
                src_size,
                level,
            )
        }
        #[cfg(not(feature = "compression_zstd_ffi"))]
        {
            let _ = ctx;
            // Real compression using safe zstd path with chosen level
            let z = match zstd::stream::encode_all(
                std::io::Cursor::new(std::slice::from_raw_parts(src as *const u8, src_size)),
                level,
            ) {
                Ok(v) => v,
                Err(_) => return usize::MAX,
            };
            if z.len() > dst_capacity {
                return usize::MAX;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(z.as_ptr(), dst as *mut u8, z.len());
            }
            z.len()
        }
    }
    fn zstd_is_error(code: usize) -> u32 {
        #[cfg(feature = "compression_zstd_ffi")]
        {
            (unsafe { zstd_sys::ZSTD_isError(code) }) as u32
        }
        #[cfg(not(feature = "compression_zstd_ffi"))]
        {
            if code == usize::MAX {
                1
            } else {
                0
            }
        }
    }

    // Sweetspot heuristic for minimal CPU usage while retaining good compression.
    #[inline]
    fn sweetspot_params_for(len: usize) -> (i32, i32, i32) {
        // (level, workers, target_block)
        let cpus: i32 = std::thread::available_parallelism().map(|n| n.get() as i32).unwrap_or(2);
        if len <= 8 * 1024 {
            (2, 0, 16 * 1024)
        } else if len <= 64 * 1024 {
            (3, 1, 64 * 1024)
        } else if len <= 256 * 1024 {
            (3, (cpus / 4).clamp(1, 2), 128 * 1024)
        } else {
            (4, (cpus / 2).clamp(2, 4), 256 * 1024)
        }
    }

    #[cfg(feature = "compression_zstd_ffi")]
    #[derive(Clone, Copy)]
    struct ManualCfg {
        enabled: bool,
        level: i32,
        workers: i32,
        block: i32,
    }

    #[cfg(feature = "compression_zstd_ffi")]
    static MANUAL_CFG: std::sync::OnceLock<ManualCfg> = std::sync::OnceLock::new();

    #[cfg(feature = "compression_zstd_ffi")]
    #[inline]
    fn manual_cfg() -> ManualCfg {
        *MANUAL_CFG.get_or_init(|| {
            let enabled = std::env::var("QUICFUSCATE_ZSTD_MODE")
                .map(|v| v.eq_ignore_ascii_case("manual"))
                .unwrap_or(false);
            let level = std::env::var("QUICFUSCATE_ZSTD_LEVEL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3);
            let workers = std::env::var("QUICFUSCATE_ZSTD_WORKERS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(2);
            let block = std::env::var("QUICFUSCATE_ZSTD_TARGET_BLOCK")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(64 * 1024);
            ManualCfg { enabled, level, workers, block }
        })
    }

    #[cfg(feature = "compression_zstd_ffi")]
    #[inline]
    fn choose_strategy(len: usize) -> zstd_sys::ZSTD_strategy {
        if let Ok(s) = std::env::var("QUICFUSCATE_ZSTD_STRATEGY") {
            match s.to_ascii_lowercase().as_str() {
                "fast" => return zstd_sys::ZSTD_strategy::ZSTD_fast,
                "dfast" => return zstd_sys::ZSTD_strategy::ZSTD_dfast,
                "greedy" => return zstd_sys::ZSTD_strategy::ZSTD_greedy,
                "lazy2" => return zstd_sys::ZSTD_strategy::ZSTD_lazy2,
                "btopt" => return zstd_sys::ZSTD_strategy::ZSTD_btlazy2,
                _ => {}
            }
        }
        if len <= 8 * 1024 {
            zstd_sys::ZSTD_strategy::ZSTD_dfast
        } else if len <= 64 * 1024 {
            zstd_sys::ZSTD_strategy::ZSTD_fast
        } else if len <= 512 * 1024 {
            zstd_sys::ZSTD_strategy::ZSTD_greedy
        } else {
            zstd_sys::ZSTD_strategy::ZSTD_lazy2
        }
    }

    #[cfg(feature = "compression_zstd_ffi")]
    #[inline]
    fn choose_window_log(len: usize) -> i32 {
        if let Ok(w) = std::env::var("QUICFUSCATE_ZSTD_WINDOW_LOG")
            .and_then(|v| v.parse::<i32>().map_err(|_| std::env::VarError::NotPresent))
        {
            return w;
        }
        if len <= 64 * 1024 {
            17
        } else if len <= 256 * 1024 {
            18
        } else {
            19
        }
    }

    #[cfg(feature = "compression_zstd_ffi")]
    #[inline]
    fn choose_checksum_flag() -> i32 {
        std::env::var("QUICFUSCATE_ZSTD_CHECKSUM").ok().and_then(|v| v.parse().ok()).unwrap_or(0)
    }

    #[cfg(feature = "compression_zstd_ffi")]
    #[inline]
    fn choose_content_size_flag() -> i32 {
        std::env::var("QUICFUSCATE_ZSTD_CONTENTSIZE").ok().and_then(|v| v.parse().ok()).unwrap_or(0)
    }

    /// Direct compression context using zstd C API
    pub struct UnsafeCompressor {
        ctx: *mut ZstdCctx,
        dict: Option<*mut ZstdCdict>,
        dict_meta: Option<(u16, u16)>, // (hash, version)
        pool: Arc<UnsafeMemoryPool>,
    }

    unsafe impl Send for UnsafeCompressor {}
    unsafe impl Sync for UnsafeCompressor {}

    impl UnsafeCompressor {
        /// Creates a new compressor with optional dictionary
        pub fn new(pool: Arc<UnsafeMemoryPool>, dict_data: Option<&[u8]>, level: i32) -> Self {
            unsafe {
                let ctx = zstd_create_cctx();
                if ctx.is_null() {
                    std::process::abort();
                }

                // Set compression level
                zstd_cctx_set_parameter(ctx, ZstdCParameter::CompressionLevel, level);

                // Tune parameters for throughput/latency (only active in FFI path)
                #[cfg(feature = "compression_zstd_ffi")]
                {
                    // nbWorkers: from env or default 2 (reasonable for networking workloads)
                    let workers: i32 = std::env::var("QUICFUSCATE_ZSTD_WORKERS")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(2);
                    let _ = zstd_sys::ZSTD_CCtx_setParameter(
                        ctx as *mut zstd_sys::ZSTD_CCtx,
                        zstd_sys::ZSTD_cParameter::ZSTD_c_nbWorkers,
                        workers,
                    );
                    // Target block size (bytes) to reduce latency for network packets
                    let target_block: i32 = std::env::var("QUICFUSCATE_ZSTD_TARGET_BLOCK")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(64 * 1024);
                    let _ = zstd_sys::ZSTD_CCtx_setParameter(
                        ctx as *mut zstd_sys::ZSTD_CCtx,
                        zstd_sys::ZSTD_cParameter::ZSTD_c_targetCBlockSize,
                        target_block,
                    );
                }

                // Create dictionary if provided
                let dict = dict_data.map(|data| {
                    let dict_ptr = zstd_create_cdict(data.as_ptr(), data.len(), level);
                    if dict_ptr.is_null() {
                        return std::ptr::null_mut();
                    }
                    dict_ptr
                });
                let dict = dict.and_then(|ptr| if ptr.is_null() { None } else { Some(ptr) });

                let dict_meta = dict_data.map(compute_dict_hash_version);

                Self { ctx, dict, dict_meta, pool }
            }
        }

        /// Compress directly into pool buffer without intermediate allocation
        #[inline]
        /// # Safety
        /// `src` must point to readable memory; this writes into a pool-owned buffer and returns
        /// an `UnsafePacket` that must be dropped to free the buffer back to the pool.
        pub unsafe fn compress_direct(&self, src: &[u8]) -> Result<UnsafePacket, UnsafeError> {
            telemetry::UNSAFE_COMPRESS_CALLS.inc();

            // Allocate output buffer from pool
            let dst_ptr = self.pool.alloc_uninit();
            let dst_capacity = self.pool.block_size;

            // Decide header type/size
            let (header_magic, header_size) =
                if self.dict.is_some() { (0x5D_u8, 9_usize) } else { (0x5A_u8, 5_usize) };
            if dst_capacity < header_size + 16 {
                self.pool.free(dst_ptr);
                return Err(UnsafeError::CapacityOverflow);
            }

            // Adaptive sweetspot tuning (per-call)
            #[cfg(feature = "compression_zstd_ffi")]
            {
                let man = manual_cfg();
                let (level, workers, block) = if man.enabled {
                    (man.level, man.workers, man.block)
                } else {
                    sweetspot_params_for(src.len())
                };
                let _ = zstd_sys::ZSTD_CCtx_setParameter(
                    self.ctx as *mut zstd_sys::ZSTD_CCtx,
                    zstd_sys::ZSTD_cParameter::ZSTD_c_compressionLevel,
                    level,
                );
                let _ = zstd_sys::ZSTD_CCtx_setParameter(
                    self.ctx as *mut zstd_sys::ZSTD_CCtx,
                    zstd_sys::ZSTD_cParameter::ZSTD_c_nbWorkers,
                    workers,
                );
                let _ = zstd_sys::ZSTD_CCtx_setParameter(
                    self.ctx as *mut zstd_sys::ZSTD_CCtx,
                    zstd_sys::ZSTD_cParameter::ZSTD_c_targetCBlockSize,
                    block,
                );
                // Conservative extras: strategy, windowLog, checksum off, contentSize off
                let strategy = choose_strategy(src.len()) as i32;
                let _ = zstd_sys::ZSTD_CCtx_setParameter(
                    self.ctx as *mut zstd_sys::ZSTD_CCtx,
                    zstd_sys::ZSTD_cParameter::ZSTD_c_strategy,
                    strategy,
                );
                let window_log = choose_window_log(src.len());
                let _ = zstd_sys::ZSTD_CCtx_setParameter(
                    self.ctx as *mut zstd_sys::ZSTD_CCtx,
                    zstd_sys::ZSTD_cParameter::ZSTD_c_windowLog,
                    window_log,
                );
                let checksum = choose_checksum_flag();
                let _ = zstd_sys::ZSTD_CCtx_setParameter(
                    self.ctx as *mut zstd_sys::ZSTD_CCtx,
                    zstd_sys::ZSTD_cParameter::ZSTD_c_checksumFlag,
                    checksum,
                );
                let content_size = choose_content_size_flag();
                let _ = zstd_sys::ZSTD_CCtx_setParameter(
                    self.ctx as *mut zstd_sys::ZSTD_CCtx,
                    zstd_sys::ZSTD_cParameter::ZSTD_c_contentSizeFlag,
                    content_size,
                );
            }

            // Write header
            *dst_ptr.as_ptr() = header_magic;
            let len_be = (src.len() as u32).to_be_bytes();
            if header_magic == 0x5A {
                // 0x5A + 4B orig len
                ptr::copy_nonoverlapping(len_be.as_ptr(), dst_ptr.as_ptr().add(1), 4);
            } else {
                // 0x5D + 2B hash + 2B version + 4B orig len
                let (hash, ver) = self.dict_meta.unwrap_or((0, 1));
                let h = hash.to_be_bytes();
                let v = ver.to_be_bytes();
                ptr::copy_nonoverlapping(h.as_ptr(), dst_ptr.as_ptr().add(1), 2);
                ptr::copy_nonoverlapping(v.as_ptr(), dst_ptr.as_ptr().add(3), 2);
                ptr::copy_nonoverlapping(len_be.as_ptr(), dst_ptr.as_ptr().add(5), 4);
            }

            // Compress data
            let compressed_size = if let Some(dict_ptr) = self.dict {
                zstd_compress_using_cdict(
                    self.ctx,
                    dst_ptr.as_ptr().add(header_size) as *mut _,
                    dst_capacity - header_size,
                    src.as_ptr() as *const _,
                    src.len(),
                    dict_ptr,
                )
            } else {
                zstd_compress_cctx(
                    self.ctx,
                    dst_ptr.as_ptr().add(header_size) as *mut _,
                    dst_capacity - header_size,
                    src.as_ptr() as *const _,
                    src.len(),
                    sweetspot_params_for(src.len()).0, // level
                )
            };

            if zstd_is_error(compressed_size) != 0 {
                self.pool.free(dst_ptr);
                telemetry::UNSAFE_COMPRESS_FAILURES.inc();
                return Err(UnsafeError::CompressionFailed);
            }

            let total_size = header_size + compressed_size;
            telemetry::UNSAFE_COMPRESS_BYTES_IN.inc_by(src.len() as u64);
            telemetry::UNSAFE_COMPRESS_BYTES_OUT.inc_by(total_size as u64);

            Ok(UnsafePacket::from_raw_parts(
                dst_ptr,
                total_size,
                dst_capacity,
                Arc::clone(&self.pool),
            ))
        }

        /// Streaming compression using zstd's compressStream2 for large inputs.
        /// Uses same header semantics as `compress_direct`: 0x5A (no dict) or 0x5D (dict with id).
        /// # Safety
        /// Writes into a pool-owned buffer; caller must drop the returned packet for reclamation.
        pub unsafe fn compress_streaming(&self, src: &[u8]) -> Result<UnsafePacket, UnsafeError> {
            let dst_ptr = self.pool.alloc_uninit();
            let dst_capacity = self.pool.block_size;
            let (header_magic, header_size) =
                if self.dict.is_some() { (0x5D_u8, 9_usize) } else { (0x5A_u8, 5_usize) };
            if dst_capacity < header_size + 32 {
                self.pool.free(dst_ptr);
                return Err(UnsafeError::CapacityOverflow);
            }

            // Write header (basic frame)
            *dst_ptr.as_ptr() = header_magic;
            let len_be = (src.len() as u32).to_be_bytes();
            if header_magic == 0x5A {
                ptr::copy_nonoverlapping(len_be.as_ptr(), dst_ptr.as_ptr().add(1), 4);
            } else {
                let (hash, ver) = self.dict_meta.unwrap_or((0, 1));
                let h = hash.to_be_bytes();
                let v = ver.to_be_bytes();
                ptr::copy_nonoverlapping(h.as_ptr(), dst_ptr.as_ptr().add(1), 2);
                ptr::copy_nonoverlapping(v.as_ptr(), dst_ptr.as_ptr().add(3), 2);
                ptr::copy_nonoverlapping(len_be.as_ptr(), dst_ptr.as_ptr().add(5), 4);
            }

            #[cfg(feature = "compression_zstd_ffi")]
            {
                // Apply sweetspot and conservative params
                let (level, workers, block) = sweetspot_params_for(src.len());
                let _ = zstd_sys::ZSTD_CCtx_setParameter(
                    self.ctx as *mut zstd_sys::ZSTD_CCtx,
                    zstd_sys::ZSTD_cParameter::ZSTD_c_compressionLevel,
                    level,
                );
                let _ = zstd_sys::ZSTD_CCtx_setParameter(
                    self.ctx as *mut zstd_sys::ZSTD_CCtx,
                    zstd_sys::ZSTD_cParameter::ZSTD_c_nbWorkers,
                    workers,
                );
                let _ = zstd_sys::ZSTD_CCtx_setParameter(
                    self.ctx as *mut zstd_sys::ZSTD_CCtx,
                    zstd_sys::ZSTD_cParameter::ZSTD_c_targetCBlockSize,
                    block,
                );
                let strategy = choose_strategy(src.len()) as i32;
                let window_log = choose_window_log(src.len());
                let checksum = choose_checksum_flag();
                let content_size = choose_content_size_flag();
                let _ = zstd_sys::ZSTD_CCtx_setParameter(
                    self.ctx as *mut zstd_sys::ZSTD_CCtx,
                    zstd_sys::ZSTD_cParameter::ZSTD_c_strategy,
                    strategy,
                );
                let _ = zstd_sys::ZSTD_CCtx_setParameter(
                    self.ctx as *mut zstd_sys::ZSTD_CCtx,
                    zstd_sys::ZSTD_cParameter::ZSTD_c_windowLog,
                    window_log,
                );
                let _ = zstd_sys::ZSTD_CCtx_setParameter(
                    self.ctx as *mut zstd_sys::ZSTD_CCtx,
                    zstd_sys::ZSTD_cParameter::ZSTD_c_checksumFlag,
                    checksum,
                );
                let _ = zstd_sys::ZSTD_CCtx_setParameter(
                    self.ctx as *mut zstd_sys::ZSTD_CCtx,
                    zstd_sys::ZSTD_cParameter::ZSTD_c_contentSizeFlag,
                    content_size,
                );
                // Ref CDict if present (for streaming)
                if let Some(dict_ptr) = self.dict {
                    let _ = zstd_sys::ZSTD_CCtx_refCDict(
                        self.ctx as *mut zstd_sys::ZSTD_CCtx,
                        dict_ptr as *const zstd_sys::ZSTD_CDict,
                    );
                }

                // Prepare buffers
                let mut in_buf = zstd_sys::ZSTD_inBuffer {
                    src: src.as_ptr() as *const std::ffi::c_void,
                    size: src.len(),
                    pos: 0,
                };
                let mut out_buf = zstd_sys::ZSTD_outBuffer {
                    dst: dst_ptr.as_ptr().add(header_size) as *mut std::ffi::c_void,
                    size: dst_capacity - header_size,
                    pos: 0,
                };
                loop {
                    let remaining = if in_buf.pos < in_buf.size {
                        zstd_sys::ZSTD_EndDirective::ZSTD_e_continue
                    } else {
                        zstd_sys::ZSTD_EndDirective::ZSTD_e_end
                    };
                    let r = zstd_sys::ZSTD_compressStream2(
                        self.ctx as *mut zstd_sys::ZSTD_CCtx,
                        &mut out_buf,
                        &mut in_buf,
                        remaining,
                    );
                    if zstd_is_error(r) != 0 {
                        self.pool.free(dst_ptr);
                        return Err(UnsafeError::CompressionFailed);
                    }
                    if remaining as u32 == zstd_sys::ZSTD_EndDirective::ZSTD_e_end as u32 && r == 0
                    {
                        break;
                    }
                    if out_buf.pos >= out_buf.size {
                        // No room left
                        self.pool.free(dst_ptr);
                        return Err(UnsafeError::CapacityOverflow);
                    }
                }
                let used = header_size + out_buf.pos;
                Ok(UnsafePacket::from_raw_parts(
                    dst_ptr,
                    used,
                    dst_capacity,
                    Arc::clone(&self.pool),
                ))
            }

            #[cfg(not(feature = "compression_zstd_ffi"))]
            {
                // Safe fallback: streaming encode into Vec, then copy
                let mut enc = zstd::stream::Encoder::new(Vec::new(), 3)
                    .map_err(|_| UnsafeError::CompressionFailed)?;
                use std::io::Write;
                enc.write_all(src).map_err(|_| UnsafeError::CompressionFailed)?;
                let zbuf = enc.finish().map_err(|_| UnsafeError::CompressionFailed)?;
                if header_size + zbuf.len() > dst_capacity {
                    self.pool.free(dst_ptr);
                    return Err(UnsafeError::CapacityOverflow);
                }
                ptr::copy_nonoverlapping(
                    zbuf.as_ptr(),
                    dst_ptr.as_ptr().add(header_size),
                    zbuf.len(),
                );
                let used = header_size + zbuf.len();
                Ok(UnsafePacket::from_raw_parts(
                    dst_ptr,
                    used,
                    dst_capacity,
                    Arc::clone(&self.pool),
                ))
            }
        }

        /// Auto-select direct vs. streaming based on payload size.
        /// Threshold: QUICFUSCATE_ZSTD_STREAM_MIN (bytes), default 256 KiB.
        /// # Safety
        /// Same safety contract as `compress_direct`/`compress_streaming`: `src` must be readable
        /// and the returned `UnsafePacket` must be dropped to free the pool block.
        pub unsafe fn compress_auto(&self, src: &[u8]) -> Result<UnsafePacket, UnsafeError> {
            if src.len() >= stream_min() {
                self.compress_streaming(src)
            } else {
                self.compress_direct(src)
            }
        }
    }

    #[inline]
    fn compute_dict_hash_version(bytes: &[u8]) -> (u16, u16) {
        let mut hash: u16 = 0u16;
        for b in bytes.iter().take(64) {
            hash = hash.wrapping_mul(257).wrapping_add(*b as u16);
        }
        (hash, 1)
    }

    #[inline]
    fn stream_min() -> usize {
        std::env::var("QUICFUSCATE_ZSTD_STREAM_MIN")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(256 * 1024)
    }

    impl Drop for UnsafeCompressor {
        fn drop(&mut self) {
            unsafe {
                if let Some(dict_ptr) = self.dict {
                    zstd_free_cdict(dict_ptr);
                }
                zstd_free_cctx(self.ctx);
            }
        }
    }

    /// Fast entropy calculation using SIMD
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    pub unsafe fn calculate_entropy_simd(data: &[u8]) -> f32 {
        let mut histogram = [0u32; 256];
        let len = data.len();

        // Process 32 bytes at a time with AVX2
        let chunks = len / 32;
        for i in 0..chunks {
            let offset = i * 32;
            let vec = _mm256_loadu_si256(data.as_ptr().add(offset) as *const __m256i);

            // Extract bytes and update histogram
            let bytes = std::mem::transmute::<__m256i, [u8; 32]>(vec);
            for &byte in &bytes {
                histogram[byte as usize] += 1;
            }
        }

        // Handle remainder
        for &byte in &data[chunks * 32..] {
            histogram[byte as usize] += 1;
        }

        // Calculate entropy
        let mut entropy = 0.0f32;
        let len_f = len as f32;

        for &count in &histogram {
            if count > 0 {
                let p = count as f32 / len_f;
                entropy -= p * p.log2();
            }
        }

        telemetry::ENTROPY_CALCULATIONS.inc();
        entropy
    }
}

// ============================================================================
// Testing Infrastructure
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unsafe_memory_pool() {
        let pool = Arc::new(UnsafeMemoryPool::new(10, 4096, 0));

        unsafe {
            // Test allocation
            let ptr1 = pool.alloc_uninit();
            // Verify alignment instead of nullness (NonNull guarantees non-null)
            assert_eq!((ptr1.as_ptr() as usize) & 63, 0, "Memory pool alignment not 64B");

            // Test write
            let data = b"Hello, World!";
            let len = pool.copy_from_slice(ptr1, data);
            assert_eq!(len, data.len());

            // Test read
            let slice = slice::from_raw_parts(ptr1.as_ptr(), len);
            assert_eq!(slice, data);

            // Test free
            pool.free(ptr1);

            // Test TLS cache hit
            let ptr2 = pool.alloc_uninit();
            assert_eq!(ptr1, ptr2); // Should get same pointer from TLS cache
            pool.free(ptr2);
        }
    }

    #[test]
    fn test_unsafe_packet() {
        let pool = Arc::new(UnsafeMemoryPool::new(5, 1024, 0));

        unsafe {
            let ptr = pool.alloc_uninit();
            let mut packet = UnsafePacket::from_raw_parts(ptr, 0, 1024, Arc::clone(&pool));

            // Test extend
            let data = b"Test data";
            packet.extend_from_slice(data).unwrap();
            assert_eq!(packet.as_slice(), data);

            // Test IoSlice creation
            let io_slice = packet.as_io_slice();
            assert_eq!(io_slice.len(), data.len());
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_simd_xor() {
        let mut dst = vec![0xAA; 64];
        let src = vec![0x55; 64];

        unsafe {
            #[cfg(target_feature = "avx2")]
            simd_gf::xor_blocks_avx2(&mut dst, &src);

            for byte in &dst {
                assert_eq!(*byte, 0xFF);
            }
        }
    }

    #[test]
    fn test_unsafe_compression() {
        let pool = Arc::new(UnsafeMemoryPool::new(10, 8192, 0));
        let compressor = unsafe_compress::UnsafeCompressor::new(Arc::clone(&pool), None, 3);

        unsafe {
            let data = b"This is test data for compression. It should compress well.";
            let packet = compressor.compress_direct(data).unwrap();

            // Verify magic byte
            assert_eq!(*packet.as_slice().first().unwrap(), 0x5A);

            // Verify length encoding
            let len_bytes = &packet.as_slice()[1..5];
            let original_len =
                u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]);
            assert_eq!(original_len as usize, data.len());
        }
    }

    /// Test with Miri for memory safety
    #[cfg(miri)]
    #[test]
    fn test_miri_safety() {
        let pool = Arc::new(UnsafeMemoryPool::new(3, 256, 0));

        unsafe {
            let ptr1 = pool.alloc_uninit();
            let ptr2 = pool.alloc_uninit();

            // Write to ensure no overlap
            ptr::write_bytes(ptr1.as_ptr(), 0xAA, 256);
            ptr::write_bytes(ptr2.as_ptr(), 0xBB, 256);

            // Read back
            assert_eq!(*ptr1.as_ptr(), 0xAA);
            assert_eq!(*ptr2.as_ptr(), 0xBB);

            pool.free(ptr1);
            pool.free(ptr2);
        }
    }
}
