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
pub static TUN_FASTPATH_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
pub static TUN_FASTPATH_URING_SUCCESS: AtomicU64 = AtomicU64::new(0);
pub static TUN_FASTPATH_URING_FALLBACKS: AtomicU64 = AtomicU64::new(0);
pub static TUN_FASTPATH_DIRECT_WRITES: AtomicU64 = AtomicU64::new(0);
pub static TUN_REQUIREMENT_REJECTS: AtomicU64 = AtomicU64::new(0);
pub static TUN_CONFIG_REJECTS: AtomicU64 = AtomicU64::new(0);
pub static TUN_PERMISSION_REJECTS: AtomicU64 = AtomicU64::new(0);

// Stealth path signals for Intelligent escalation heuristics
pub static STEALTH_SIGNAL_RTT_SPIKES: AtomicU64 = AtomicU64::new(0);
pub static STEALTH_SIGNAL_ECN_CE: AtomicU64 = AtomicU64::new(0);
pub static STEALTH_SIGNAL_RST: AtomicU64 = AtomicU64::new(0);
pub static STEALTH_SIGNAL_TOS_ANOM: AtomicU64 = AtomicU64::new(0);
pub static STEALTH_SIGNAL_OTHER: AtomicU64 = AtomicU64::new(0);
pub static SERVER_PUSH_BURSTS_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static SERVER_PUSH_TOTAL_COVER_BYTES: AtomicU64 = AtomicU64::new(0);
pub static SERVER_PUSH_BURSTS_LAST_MINUTE: AtomicU64 = AtomicU64::new(0);
pub static SERVER_PUSH_CURRENT_INTENSITY_PPM: AtomicU64 = AtomicU64::new(0);
pub static SERVER_PUSH_TRIGGER_LOSS_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static SERVER_PUSH_TRIGGER_TIME_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static SERVER_PUSH_TRIGGER_GATING_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Export a subset of metrics in a plain text telemetry format.
/// This intentionally covers the most relevant hot-path counters to keep overhead minimal.
pub fn export_telemetry_text() -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let get = |v: &AtomicU64| v.load(Ordering::Relaxed);

    // Zero-copy totals
    let _ = writeln!(out, "quicfuscate_zc_completions_total {}", get(&ZC_COMPLETIONS_TOTAL));
    let _ =
        writeln!(out, "quicfuscate_zc_completed_bytes_total {}", get(&ZC_COMPLETED_BYTES_TOTAL));
    let _ = writeln!(out, "quicfuscate_zerocopy_send_calls_total {}", get(&ZEROCOPY_SEND_CALLS));
    let _ = writeln!(
        out,
        "quicfuscate_zerocopy_send_fallbacks_total {}",
        get(&ZEROCOPY_SEND_FALLBACKS)
    );
    let _ = writeln!(out, "quicfuscate_xdp_active {}", get(&XDP_ACTIVE));

    // Memory Pool metrics
    let _ = writeln!(out, "quicfuscate_mem_pool_capacity {}", get(&MEM_POOL_CAPACITY));
    let _ = writeln!(out, "quicfuscate_mem_pool_in_use {}", get(&MEM_POOL_IN_USE));
    let _ = writeln!(out, "quicfuscate_mem_pool_usage_bytes {}", get(&MEM_POOL_USAGE_BYTES));
    let _ =
        writeln!(out, "quicfuscate_mem_pool_utilization_percent {}", get(&MEM_POOL_UTILIZATION));
    let _ = writeln!(out, "quicfuscate_mem_pool_block_size_bytes {}", get(&MEM_POOL_BLOCK_SIZE));

    // SIMD usage summary
    let _ = writeln!(out, "quicfuscate_simd_usage_avx512 {}", get(&SIMD_USAGE_AVX512));
    let _ = writeln!(out, "quicfuscate_simd_usage_avx2 {}", get(&SIMD_USAGE_AVX2));
    let _ = writeln!(out, "quicfuscate_simd_usage_avx10_256 {}", get(&SIMD_USAGE_AVX10_256));
    let _ = writeln!(out, "quicfuscate_simd_usage_avx10_512 {}", get(&SIMD_USAGE_AVX10_512));
    let _ = writeln!(out, "quicfuscate_simd_usage_neon {}", get(&SIMD_USAGE_NEON));
    let _ = writeln!(out, "quicfuscate_simd_usage_sve2 {}", get(&SIMD_USAGE_SVE2));
    let _ = writeln!(out, "quicfuscate_simd_usage_scalar {}", get(&SIMD_USAGE_SCALAR));
    let _ = writeln!(out, "quicfuscate_simd_usage_rvv {}", get(&SIMD_USAGE_RVV));
    let _ = writeln!(out, "quicfuscate_simd_active {}", get(&SIMD_ACTIVE));
    let _ =
        writeln!(out, "quicfuscate_cpu_feature_mask {}", CPU_FEATURE_MASK.load(Ordering::Relaxed));
    #[cfg(target_arch = "x86_64")]
    let _ =
        writeln!(out, "quicfuscate_stealth_padding_gfni_bytes {}", STEALTH_PADDING_GFNI_OPS.get());
    let _ = writeln!(out, "quicfuscate_congestion_vnni_batches {}", CONGESTION_VNNI_BATCHES.get());
    let _ = writeln!(out, "quicfuscate_congestion_avx2_batches {}", CONGESTION_AVX2_BATCHES.get());
    let _ = writeln!(out, "quicfuscate_congestion_neon_batches {}", CONGESTION_NEON_BATCHES.get());

    // TLS provider
    let _ = writeln!(out, "quicfuscate_tls_provider_kind {}", TLS_PROVIDER_KIND.get());

    // TLS Cover cipher usage
    let _ = writeln!(out, "quicfuscate_tls-cover_chacha_ops {}", FAKETLS_CHACHA_OPS.get());
    let _ = writeln!(out, "quicfuscate_tls-cover_aes_gcm_ops {}", FAKETLS_AES_GCM_OPS.get());
    let _ =
        writeln!(out, "quicfuscate_tls-cover_cipher_failures {}", FAKETLS_CIPHER_FAILURES.get());
    let _ = writeln!(out, "quicfuscate_aes_block_aesni_ops {}", AES_BLOCK_AESNI_OPS.get());
    let _ = writeln!(out, "quicfuscate_aes_block_vaes_ops {}", AES_BLOCK_VAES_OPS.get());
    let _ = writeln!(out, "quicfuscate_aes_block_aese_ops {}", AES_BLOCK_AESE_OPS.get());
    let _ = writeln!(out, "quicfuscate_aes_block_ssse3_ops {}", AES_BLOCK_SSSE3_OPS.get());
    let _ = writeln!(out, "quicfuscate_aes_block_sve_ops {}", AES_BLOCK_SVE_OPS.get());
    let _ =
        writeln!(out, "quicfuscate_aes_block_neon_table_ops {}", AES_BLOCK_NEON_TABLE_OPS.get());
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
    let _ = writeln!(out, "quicfuscate_hmac_sha256_scalar_ops {}", HMAC_SHA256_SCALAR_OPS.get());
    let _ = writeln!(out, "quicfuscate_chacha20_x4_avx2_ops {}", CHACHA20_X4_AVX2_OPS.get());
    let _ = writeln!(out, "quicfuscate_chacha20_x4_avx_ops {}", CHACHA20_X4_AVX_OPS.get());
    let _ = writeln!(out, "quicfuscate_chacha20_x4_sse41_ops {}", CHACHA20_X4_SSE41_OPS.get());
    let _ = writeln!(out, "quicfuscate_chacha20_x4_neon_ops {}", CHACHA20_X4_NEON_OPS.get());
    let _ = writeln!(out, "quicfuscate_chacha20_x4_scalar_ops {}", CHACHA20_X4_SCALAR_OPS.get());
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
    let _ = writeln!(out, "quicfuscate_iter_sum_f32_avx512_ops {}", ITER_SUM_F32_AVX512_OPS.get());
    let _ = writeln!(out, "quicfuscate_iter_sum_f32_avx2_ops {}", ITER_SUM_F32_AVX2_OPS.get());
    let _ = writeln!(out, "quicfuscate_iter_sum_f32_neon_ops {}", ITER_SUM_F32_NEON_OPS.get());
    let _ = writeln!(out, "quicfuscate_iter_sum_f32_scalar_ops {}", ITER_SUM_F32_SCALAR_OPS.get());
    let _ = writeln!(out, "quicfuscate_iter_sum_f32_rvv_ops {}", ITER_SUM_F32_RVV_OPS.get());
    let _ = writeln!(out, "quicfuscate_iter_sum_u32_avx512_ops {}", ITER_SUM_U32_AVX512_OPS.get());
    let _ = writeln!(out, "quicfuscate_iter_sum_u32_avx2_ops {}", ITER_SUM_U32_AVX2_OPS.get());
    let _ = writeln!(out, "quicfuscate_iter_sum_u32_neon_ops {}", ITER_SUM_U32_NEON_OPS.get());
    let _ = writeln!(out, "quicfuscate_iter_sum_u32_scalar_ops {}", ITER_SUM_U32_SCALAR_OPS.get());
    let _ = writeln!(out, "quicfuscate_iter_sum_u32_rvv_ops {}", ITER_SUM_U32_RVV_OPS.get());
    let _ = writeln!(out, "quicfuscate_iter_sum_u64_avx512_ops {}", ITER_SUM_U64_AVX512_OPS.get());
    let _ = writeln!(out, "quicfuscate_iter_sum_u64_avx2_ops {}", ITER_SUM_U64_AVX2_OPS.get());
    let _ = writeln!(out, "quicfuscate_iter_sum_u64_neon_ops {}", ITER_SUM_U64_NEON_OPS.get());
    let _ = writeln!(out, "quicfuscate_iter_sum_u64_scalar_ops {}", ITER_SUM_U64_SCALAR_OPS.get());
    let _ = writeln!(out, "quicfuscate_iter_sum_u64_rvv_ops {}", ITER_SUM_U64_RVV_OPS.get());
    let _ = writeln!(out, "quicfuscate_wiedemann_usage {}", WIEDEMANN_USAGE.get());
    let _ = writeln!(out, "quicfuscate_wiedemann_amx_ops {}", WIEDEMANN_AMX_OPS.get());
    let _ = writeln!(out, "quicfuscate_wiedemann_scalar_ops {}", WIEDEMANN_SCALAR_OPS.get());
    let _ = writeln!(out, "quicfuscate_fec_mode {}", get(&FEC_MODE));
    let _ = writeln!(out, "quicfuscate_fec_loss_rate {}", get(&LOSS_RATE));
    let _ = writeln!(out, "quicfuscate_fec_mode_switches_total {}", get(&FEC_MODE_SWITCHES));
    let _ = writeln!(out, "quicfuscate_fec_window {}", get(&FEC_WINDOW));
    let _ = writeln!(
        out,
        "quicfuscate_fec_switch_reason_adaptive_total {}",
        get(&FEC_SWITCH_REASON_ADAPTIVE)
    );
    let _ = writeln!(
        out,
        "quicfuscate_fec_switch_reason_force_on_total {}",
        get(&FEC_SWITCH_REASON_FORCE_ON)
    );
    let _ = writeln!(
        out,
        "quicfuscate_fec_switch_reason_extreme_total {}",
        get(&FEC_SWITCH_REASON_EXTREME)
    );
    let _ = writeln!(
        out,
        "quicfuscate_fec_switch_reason_disturbance_total {}",
        get(&FEC_SWITCH_REASON_DISTURBANCE)
    );

    // MASQUE
    let _ = writeln!(out, "quicfuscate_masque_active {}", get(&MASQUE_ACTIVE));
    let _ = writeln!(out, "quicfuscate_masque_hint {}", get(&MASQUE_HINT));

    // AEGIS plan
    let _ = writeln!(out, "quicfuscate_aegis_plan {}", get(&AEGIS_PLAN));

    // Plan selection metrics
    let _ = writeln!(out, "quicfuscate_plan_decisions_total {}", PLAN_DECISIONS_TOTAL.get());
    let _ = writeln!(out, "quicfuscate_plan_decisions_default {}", PLAN_DECISIONS_DEFAULT.get());
    let _ = writeln!(out, "quicfuscate_plan_decisions_len {}", PLAN_DECISIONS_LEN.get());
    let _ = writeln!(out, "quicfuscate_plan_select_l_total {}", PLAN_DECISIONS_L.get());
    let _ = writeln!(out, "quicfuscate_plan_select_neon_l_total {}", PLAN_DECISIONS_NEON_L.get());
    let _ = writeln!(out, "quicfuscate_plan_select_morus_total {}", PLAN_DECISIONS_MORUS.get());
    let _ = writeln!(out, "quicfuscate_morus1280_scalar_ops {}", MORUS1280_SCALAR_OPS.get());
    let _ = writeln!(out, "quicfuscate_morus1280_sse2_ops {}", MORUS1280_SSE2_OPS.get());
    let _ = writeln!(out, "quicfuscate_morus1280_ssse3_ops {}", MORUS1280_SSSE3_OPS.get());
    let _ = writeln!(out, "quicfuscate_morus1280_sse41_ops {}", MORUS1280_SSE41_OPS.get());
    let _ = writeln!(out, "quicfuscate_morus1280_sse42_ops {}", MORUS1280_SSE42_OPS.get());
    let _ = writeln!(out, "quicfuscate_morus1280_neon_ops {}", MORUS1280_NEON_OPS.get());

    // Compression decision metrics
    let _ =
        writeln!(out, "quicfuscate_compress_decisions_total {}", COMPRESS_DECISIONS_TOTAL.get());
    let _ =
        writeln!(out, "quicfuscate_compress_decisions_allow {}", COMPRESS_DECISIONS_ALLOW.get());
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
    let _ =
        writeln!(out, "quicfuscate_tun_fastpath_attempts_total {}", get(&TUN_FASTPATH_ATTEMPTS));
    let _ = writeln!(
        out,
        "quicfuscate_tun_fastpath_uring_success_total {}",
        get(&TUN_FASTPATH_URING_SUCCESS)
    );
    let _ = writeln!(
        out,
        "quicfuscate_tun_fastpath_uring_fallbacks_total {}",
        get(&TUN_FASTPATH_URING_FALLBACKS)
    );
    let _ = writeln!(
        out,
        "quicfuscate_tun_fastpath_direct_writes_total {}",
        get(&TUN_FASTPATH_DIRECT_WRITES)
    );
    let _ = writeln!(
        out,
        "quicfuscate_tun_requirement_rejects_total {}",
        get(&TUN_REQUIREMENT_REJECTS)
    );
    let _ = writeln!(out, "quicfuscate_tun_config_rejects_total {}", get(&TUN_CONFIG_REJECTS));
    let _ =
        writeln!(out, "quicfuscate_tun_permission_rejects_total {}", get(&TUN_PERMISSION_REJECTS));
    let _ = writeln!(out, "quicfuscate_io_driver_copy_ops_total {}", get(&IO_DRIVER_COPY_OPS));
    let _ = writeln!(out, "quicfuscate_io_driver_copy_bytes_total {}", get(&IO_DRIVER_COPY_BYTES));
    let _ = writeln!(
        out,
        "quicfuscate_io_driver_batch_drain_packets_total {}",
        get(&IO_DRIVER_BATCH_DRAIN_PACKETS)
    );
    let _ = writeln!(
        out,
        "quicfuscate_io_driver_sendmmsg_calls_total {}",
        get(&IO_DRIVER_SENDMMSG_CALLS)
    );
    let _ = writeln!(
        out,
        "quicfuscate_io_driver_sendmmsg_packets_total {}",
        get(&IO_DRIVER_SENDMMSG_PACKETS)
    );

    // Stealth signals
    let _ = writeln!(
        out,
        "quicfuscate_stealth_signal_rtt_spikes_total {}",
        get(&STEALTH_SIGNAL_RTT_SPIKES)
    );
    let _ =
        writeln!(out, "quicfuscate_stealth_signal_ecn_ce_total {}", get(&STEALTH_SIGNAL_ECN_CE));
    let _ = writeln!(out, "quicfuscate_stealth_signal_rst_total {}", get(&STEALTH_SIGNAL_RST));
    let _ = writeln!(
        out,
        "quicfuscate_stealth_signal_tos_anom_total {}",
        get(&STEALTH_SIGNAL_TOS_ANOM)
    );
    let _ = writeln!(out, "quicfuscate_stealth_signal_other_total {}", get(&STEALTH_SIGNAL_OTHER));
    let _ =
        writeln!(out, "quicfuscate_server_push_bursts_total {}", get(&SERVER_PUSH_BURSTS_TOTAL));
    let _ = writeln!(
        out,
        "quicfuscate_server_push_total_cover_bytes {}",
        get(&SERVER_PUSH_TOTAL_COVER_BYTES)
    );
    let _ = writeln!(
        out,
        "quicfuscate_server_push_bursts_last_minute {}",
        get(&SERVER_PUSH_BURSTS_LAST_MINUTE)
    );
    let _ = writeln!(
        out,
        "quicfuscate_server_push_current_intensity_ppm {}",
        get(&SERVER_PUSH_CURRENT_INTENSITY_PPM)
    );
    let _ = writeln!(
        out,
        "quicfuscate_server_push_trigger_loss_total {}",
        get(&SERVER_PUSH_TRIGGER_LOSS_TOTAL)
    );
    let _ = writeln!(
        out,
        "quicfuscate_server_push_trigger_time_total {}",
        get(&SERVER_PUSH_TRIGGER_TIME_TOTAL)
    );
    let _ = writeln!(
        out,
        "quicfuscate_server_push_trigger_gating_total {}",
        get(&SERVER_PUSH_TRIGGER_GATING_TOTAL)
    );
    let _ =
        writeln!(out, "quicfuscate_stealth_probe_detected_total {}", STEALTH_PROBE_DETECTED.get());
    let _ = writeln!(out, "quicfuscate_stealth_probe_switch_total {}", STEALTH_PROBE_SWITCH.get());
    let _ = writeln!(out, "quicfuscate_stealth_probe_fake_total {}", STEALTH_PROBE_FAKE.get());
    let _ = writeln!(out, "quicfuscate_stealth_probe_block_total {}", STEALTH_PROBE_BLOCK.get());
    let _ =
        writeln!(out, "quicfuscate_stealth_mode_escalated_total {}", STEALTH_MODE_ESCALATED.get());
    let _ = writeln!(
        out,
        "quicfuscate_stealth_intelligent_transitions_total {}",
        STEALTH_INTELLIGENT_TRANSITIONS_TOTAL.get()
    );
    let _ = writeln!(
        out,
        "quicfuscate_stealth_intelligent_reason_loss_total {}",
        STEALTH_INTELLIGENT_REASON_LOSS.get()
    );
    let _ = writeln!(
        out,
        "quicfuscate_stealth_intelligent_reason_jitter_total {}",
        STEALTH_INTELLIGENT_REASON_JITTER.get()
    );
    let _ = writeln!(
        out,
        "quicfuscate_stealth_intelligent_reason_timeout_total {}",
        STEALTH_INTELLIGENT_REASON_TIMEOUT.get()
    );
    let _ = writeln!(
        out,
        "quicfuscate_stealth_intelligent_reason_retransmit_total {}",
        STEALTH_INTELLIGENT_REASON_RETRANSMIT.get()
    );
    let _ = writeln!(
        out,
        "quicfuscate_stealth_intelligent_reason_probe_total {}",
        STEALTH_INTELLIGENT_REASON_PROBE.get()
    );
    let _ = writeln!(
        out,
        "quicfuscate_stealth_intelligent_deescalations_total {}",
        STEALTH_INTELLIGENT_DEESCALATIONS_TOTAL.get()
    );
    let _ = writeln!(
        out,
        "quicfuscate_stealth_ascii_simd_avx2_bytes_total {}",
        STEALTH_ASCII_SIMD_AVX2_BYTES.get()
    );
    let _ = writeln!(
        out,
        "quicfuscate_stealth_ascii_simd_sse2_bytes_total {}",
        STEALTH_ASCII_SIMD_SSE2_BYTES.get()
    );
    let _ = writeln!(
        out,
        "quicfuscate_stealth_ascii_simd_neon_bytes_total {}",
        STEALTH_ASCII_SIMD_NEON_BYTES.get()
    );
    let _ = writeln!(
        out,
        "quicfuscate_stealth_ascii_scalar_bytes_total {}",
        STEALTH_ASCII_SCALAR_BYTES.get()
    );
    let _ = writeln!(out, "quicfuscate_admin_csrf_reject_total {}", ADMIN_CSRF_REJECT_TOTAL.get());
    let _ =
        writeln!(out, "quicfuscate_admin_origin_reject_total {}", ADMIN_ORIGIN_REJECT_TOTAL.get());
    let _ = writeln!(out, "quicfuscate_qkey_auth_fail_total {}", QKEY_AUTH_FAIL_TOTAL.get());
    let _ = writeln!(out, "quicfuscate_qkey_path_rebind_total {}", QKEY_PATH_REBIND_TOTAL.get());
    let _ = writeln!(
        out,
        "quicfuscate_engine_handshake_timeout_total {}",
        ENGINE_HANDSHAKE_TIMEOUT_TOTAL.get()
    );

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
    pub static ref MORUS1280_SCALAR_OPS: Counter = Counter::new();
    pub static ref MORUS1280_SSE2_OPS: Counter = Counter::new();
    pub static ref MORUS1280_SSSE3_OPS: Counter = Counter::new();
    pub static ref MORUS1280_SSE41_OPS: Counter = Counter::new();
    pub static ref MORUS1280_SSE42_OPS: Counter = Counter::new();
    pub static ref MORUS1280_NEON_OPS: Counter = Counter::new();

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
    pub static ref SIMD_USAGE_SVE2: AtomicU64 = AtomicU64::new(0);
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
    pub static ref IO_DRIVER_COPY_OPS: AtomicU64 = AtomicU64::new(0);
    pub static ref IO_DRIVER_COPY_BYTES: AtomicU64 = AtomicU64::new(0);
    pub static ref IO_DRIVER_BATCH_DRAIN_PACKETS: AtomicU64 = AtomicU64::new(0);
    pub static ref IO_DRIVER_SENDMMSG_CALLS: AtomicU64 = AtomicU64::new(0);
    pub static ref IO_DRIVER_SENDMMSG_PACKETS: AtomicU64 = AtomicU64::new(0);

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
    pub static ref FEC_SWITCH_REASON_ADAPTIVE: AtomicU64 = AtomicU64::new(0);
    pub static ref FEC_SWITCH_REASON_FORCE_ON: AtomicU64 = AtomicU64::new(0);
    pub static ref FEC_SWITCH_REASON_EXTREME: AtomicU64 = AtomicU64::new(0);
    pub static ref FEC_SWITCH_REASON_DISTURBANCE: AtomicU64 = AtomicU64::new(0);
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
    s.push_str(&format!("quicfuscate_mem_pool_hits_queue_total {}\n", MEM_POOL_HITS_QUEUE.get()));
    s.push_str("# TYPE quicfuscate_mem_pool_alloc_grow_total counter\n");
    s.push_str(&format!("quicfuscate_mem_pool_alloc_grow_total {}\n", MEM_POOL_ALLOC_GROW.get()));
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
    s.push_str("# TYPE quicfuscate_simd_usage_sve2_total counter\n");
    s.push_str(&format!(
        "quicfuscate_simd_usage_sve2_total {}\n",
        SIMD_USAGE_SVE2.load(Ordering::Relaxed)
    ));
    s.push_str("# TYPE quicfuscate_cpu_feature_mask gauge\n");
    s.push_str(&format!(
        "quicfuscate_cpu_feature_mask {}\n",
        CPU_FEATURE_MASK.load(Ordering::Relaxed)
    ));
    s
}

const CPU_MASK_SSE2: i64 = 1 << 0;
const CPU_MASK_SSSE3: i64 = 1 << 1;
const CPU_MASK_SSE42: i64 = 1 << 2;
const CPU_MASK_AVX: i64 = 1 << 3;
const CPU_MASK_AVX2: i64 = 1 << 4;
const CPU_MASK_AVX512: i64 = 1 << 5;
const CPU_MASK_VAES: i64 = 1 << 6;
const CPU_MASK_GFNI: i64 = 1 << 7;
const CPU_MASK_AVX10_256: i64 = 1 << 8;
const CPU_MASK_AVX10_512: i64 = 1 << 9;
const CPU_MASK_NEON: i64 = 1 << 10;
const CPU_MASK_AES: i64 = 1 << 11;
const CPU_MASK_PMULL: i64 = 1 << 12;
const CPU_MASK_SVE2: i64 = 1 << 13;
const CPU_MASK_APPLE_AMX: i64 = 1 << 14;
const CPU_MASK_RVV: i64 = 1 << 15;
const CPU_MASK_SCALAR: i64 = 1 << 16;

pub fn cpu_profile_mask(profile: crate::optimize::CpuProfile) -> i64 {
    use crate::optimize::CpuProfile;
    match profile {
        CpuProfile::X86_P0a => CPU_MASK_SSE2,
        CpuProfile::X86_P0b => CPU_MASK_SSE2 | CPU_MASK_SSSE3,
        CpuProfile::X86_P1a => CPU_MASK_SSE2 | CPU_MASK_SSSE3 | CPU_MASK_SSE42,
        CpuProfile::X86_P1b => CPU_MASK_SSE2 | CPU_MASK_SSSE3 | CPU_MASK_SSE42 | CPU_MASK_AES,
        CpuProfile::X86_P1f => {
            CPU_MASK_SSE2 | CPU_MASK_SSSE3 | CPU_MASK_SSE42 | CPU_MASK_AES | CPU_MASK_AVX
        }
        CpuProfile::X86_P2a | CpuProfile::X86_P2b => {
            CPU_MASK_SSE2
                | CPU_MASK_SSSE3
                | CPU_MASK_SSE42
                | CPU_MASK_AES
                | CPU_MASK_AVX
                | CPU_MASK_AVX2
        }
        CpuProfile::X86_P3a => {
            CPU_MASK_SSE2
                | CPU_MASK_SSSE3
                | CPU_MASK_SSE42
                | CPU_MASK_AES
                | CPU_MASK_AVX
                | CPU_MASK_AVX2
                | CPU_MASK_AVX512
        }
        CpuProfile::X86_P3b | CpuProfile::X86_P3c | CpuProfile::X86_P3d => {
            CPU_MASK_SSE2
                | CPU_MASK_SSSE3
                | CPU_MASK_SSE42
                | CPU_MASK_AES
                | CPU_MASK_AVX
                | CPU_MASK_AVX2
                | CPU_MASK_AVX512
                | CPU_MASK_VAES
        }
        CpuProfile::X86_P3e => {
            CPU_MASK_SSE2
                | CPU_MASK_SSSE3
                | CPU_MASK_SSE42
                | CPU_MASK_AES
                | CPU_MASK_AVX
                | CPU_MASK_AVX2
                | CPU_MASK_AVX512
                | CPU_MASK_VAES
                | CPU_MASK_GFNI
        }
        CpuProfile::X86_P4a => {
            CPU_MASK_SSE2
                | CPU_MASK_SSSE3
                | CPU_MASK_SSE42
                | CPU_MASK_AES
                | CPU_MASK_AVX
                | CPU_MASK_AVX2
                | CPU_MASK_AVX10_256
        }
        CpuProfile::X86_P4b => {
            CPU_MASK_SSE2
                | CPU_MASK_SSSE3
                | CPU_MASK_SSE42
                | CPU_MASK_AES
                | CPU_MASK_AVX
                | CPU_MASK_AVX2
                | CPU_MASK_AVX512
                | CPU_MASK_AVX10_256
                | CPU_MASK_AVX10_512
        }
        CpuProfile::ARM_A0 | CpuProfile::ARM_A1a => CPU_MASK_NEON,
        CpuProfile::ARM_A1b => CPU_MASK_NEON | CPU_MASK_AES,
        CpuProfile::ARM_A1c | CpuProfile::ARM_A1d => CPU_MASK_NEON | CPU_MASK_AES | CPU_MASK_PMULL,
        CpuProfile::ARM_A2 => CPU_MASK_NEON | CPU_MASK_AES | CPU_MASK_PMULL | CPU_MASK_SVE2,
        CpuProfile::Apple_M => CPU_MASK_NEON | CPU_MASK_AES | CPU_MASK_PMULL | CPU_MASK_APPLE_AMX,
        CpuProfile::RVV => CPU_MASK_RVV,
        CpuProfile::Scalar => CPU_MASK_SCALAR,
    }
}

pub fn publish_cpu_profile_mask(profile: crate::optimize::CpuProfile) -> i64 {
    let mask = cpu_profile_mask(profile);
    CPU_FEATURE_MASK.store(mask, Ordering::Relaxed);
    mask
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
pub static STEALTH_PROBE_DETECTED: Counter = Counter::new();
pub static STEALTH_PROBE_SWITCH: Counter = Counter::new();
pub static STEALTH_PROBE_FAKE: Counter = Counter::new();
pub static STEALTH_PROBE_BLOCK: Counter = Counter::new();
pub static STEALTH_MODE_ESCALATED: Counter = Counter::new();
pub static STEALTH_INTELLIGENT_TRANSITIONS_TOTAL: Counter = Counter::new();
pub static STEALTH_INTELLIGENT_REASON_LOSS: Counter = Counter::new();
pub static STEALTH_INTELLIGENT_REASON_JITTER: Counter = Counter::new();
pub static STEALTH_INTELLIGENT_REASON_TIMEOUT: Counter = Counter::new();
pub static STEALTH_INTELLIGENT_REASON_RETRANSMIT: Counter = Counter::new();
pub static STEALTH_INTELLIGENT_REASON_PROBE: Counter = Counter::new();
pub static STEALTH_INTELLIGENT_DEESCALATIONS_TOTAL: Counter = Counter::new();
pub static STEALTH_ASCII_SIMD_AVX2_BYTES: Counter = Counter::new();
pub static STEALTH_ASCII_SIMD_SSE2_BYTES: Counter = Counter::new();
pub static STEALTH_ASCII_SIMD_NEON_BYTES: Counter = Counter::new();
pub static STEALTH_ASCII_SCALAR_BYTES: Counter = Counter::new();
pub static ADMIN_CSRF_REJECT_TOTAL: Counter = Counter::new();
pub static ADMIN_ORIGIN_REJECT_TOTAL: Counter = Counter::new();
pub static QKEY_AUTH_FAIL_TOTAL: Counter = Counter::new();
pub static QKEY_PATH_REBIND_TOTAL: Counter = Counter::new();
pub static ENGINE_HANDSHAKE_TIMEOUT_TOTAL: Counter = Counter::new();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimize::CpuProfile;

    #[test]
    fn cpu_profile_mask_monotonic_x86_path() {
        let p0 = cpu_profile_mask(CpuProfile::X86_P0a);
        let p2 = cpu_profile_mask(CpuProfile::X86_P2b);
        let p3 = cpu_profile_mask(CpuProfile::X86_P3e);
        let p4 = cpu_profile_mask(CpuProfile::X86_P4b);

        assert_ne!(p0 & CPU_MASK_SSE2, 0);
        assert_ne!(p2 & CPU_MASK_AVX2, 0);
        assert_ne!(p3 & CPU_MASK_GFNI, 0);
        assert_ne!(p4 & CPU_MASK_AVX10_512, 0);
        assert_eq!(p0 & CPU_MASK_AVX2, 0);
        assert_eq!(p0 & CPU_MASK_AVX512, 0);
    }

    #[test]
    fn publish_cpu_profile_mask_updates_gauge() {
        CPU_FEATURE_MASK.store(0, Ordering::Relaxed);
        let expected = cpu_profile_mask(CpuProfile::ARM_A2);
        let published = publish_cpu_profile_mask(CpuProfile::ARM_A2);
        assert_eq!(published, expected);
        assert_eq!(CPU_FEATURE_MASK.load(Ordering::Relaxed), expected);
    }

    #[test]
    fn cpu_profile_mask_covers_all_profiles() {
        let profiles = [
            CpuProfile::X86_P0a,
            CpuProfile::X86_P0b,
            CpuProfile::X86_P1a,
            CpuProfile::X86_P1b,
            CpuProfile::X86_P1f,
            CpuProfile::X86_P2a,
            CpuProfile::X86_P2b,
            CpuProfile::X86_P3a,
            CpuProfile::X86_P3b,
            CpuProfile::X86_P3c,
            CpuProfile::X86_P3d,
            CpuProfile::X86_P3e,
            CpuProfile::X86_P4a,
            CpuProfile::X86_P4b,
            CpuProfile::ARM_A0,
            CpuProfile::ARM_A1a,
            CpuProfile::ARM_A1b,
            CpuProfile::ARM_A1c,
            CpuProfile::ARM_A1d,
            CpuProfile::ARM_A2,
            CpuProfile::Apple_M,
            CpuProfile::RVV,
            CpuProfile::Scalar,
        ];
        for profile in profiles {
            let mask = cpu_profile_mask(profile);
            assert_ne!(mask, 0, "mask must be non-zero for {:?}", profile);
        }
    }

    #[test]
    fn server_push_metrics_exported_in_telemetry_text() {
        SERVER_PUSH_BURSTS_TOTAL.store(7, Ordering::Relaxed);
        SERVER_PUSH_TOTAL_COVER_BYTES.store(12345, Ordering::Relaxed);
        SERVER_PUSH_BURSTS_LAST_MINUTE.store(3, Ordering::Relaxed);
        SERVER_PUSH_CURRENT_INTENSITY_PPM.store(650_000, Ordering::Relaxed);
        SERVER_PUSH_TRIGGER_LOSS_TOTAL.store(2, Ordering::Relaxed);
        SERVER_PUSH_TRIGGER_TIME_TOTAL.store(4, Ordering::Relaxed);
        SERVER_PUSH_TRIGGER_GATING_TOTAL.store(1, Ordering::Relaxed);

        let out = export_telemetry_text();
        assert!(out.contains("quicfuscate_server_push_bursts_total 7"));
        assert!(out.contains("quicfuscate_server_push_total_cover_bytes 12345"));
        assert!(out.contains("quicfuscate_server_push_bursts_last_minute 3"));
        assert!(out.contains("quicfuscate_server_push_current_intensity_ppm 650000"));
        assert!(out.contains("quicfuscate_server_push_trigger_loss_total 2"));
        assert!(out.contains("quicfuscate_server_push_trigger_time_total 4"));
        assert!(out.contains("quicfuscate_server_push_trigger_gating_total 1"));
    }
}
