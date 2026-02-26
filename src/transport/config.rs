use super::{CongestionControlAlgorithm, PROTOCOL_VERSION};

// ============================================================================

/// QUIC connection configuration
#[derive(Clone)]
pub struct Config {
    pub(crate) version: u32,
    pub(crate) cc_algorithm: CongestionControlAlgorithm,
    pub(crate) application_protos: Vec<Vec<u8>>,
    pub(crate) max_idle_timeout: u64,
    pub(crate) max_udp_payload_size: u64,
    pub(crate) initial_max_data: u64,
    pub(crate) initial_max_stream_data_bidi_local: u64,
    pub(crate) initial_max_stream_data_bidi_remote: u64,
    pub(crate) initial_max_stream_data_uni: u64,
    pub(crate) initial_max_streams_bidi: u64,
    pub(crate) initial_max_streams_uni: u64,
    pub(crate) ack_delay_exponent: u64,
    pub(crate) max_ack_delay: u64,
    pub(crate) disable_active_migration: bool,
    pub(crate) enable_early_data: bool,

    // TLS configuration (simplified)
    pub(crate) verify_peer: bool,
    pub(crate) grease: bool,

    // Certificate paths
    pub(crate) cert_chain_path: Option<String>,
    pub(crate) priv_key_path: Option<String>,
    // Parity fields
    pub(crate) dgram_recv_max_queue_len: usize,
    pub(crate) dgram_send_max_queue_len: usize,
    pub(crate) path_challenge_recv_max_queue_len: usize,
    pub(crate) max_connection_window: u64,
    pub(crate) max_stream_window: u64,
    pub(crate) max_amplification_factor: usize,
    pub(crate) send_capacity_factor: f64,
    pub(crate) pmtu_discovery_enabled: bool,
    pub(crate) disable_dcid_reuse: bool,
    pub(crate) track_unknown_transport_params: Option<usize>,
    // Real-TLS knobs
    pub(crate) chlo_template: Option<Vec<u8>>,
    pub(crate) tls_grease_disabled: bool,
    pub(crate) deterministic_hello_enabled: bool,
    // Pacing / Hystart / Initial CWND
    pub(crate) pacing: bool,
    pub(crate) max_pacing_rate: Option<u64>,
    pub(crate) hystart: bool,
    pub(crate) initial_congestion_window_packets: usize,
    // Optional: TLS/QLog knobs (parity stubs)
    pub(crate) keylog_enabled: bool,
    pub(crate) qlog_config: Option<(String, String, String, u32)>,
    pub(crate) ticket_key: Option<Vec<u8>>,
    pub(crate) tls_session: Option<Vec<u8>>,
    pub(crate) simd_enabled: bool,
    pub(crate) custom_bbr_settings: Option<Vec<u8>>,
    pub(crate) active_connection_id_limit: u64,
    pub(crate) stateless_reset_token: Option<[u8; 16]>,
    pub(crate) initial_token: Option<Vec<u8>>,
    // Stealth padding knobs (set by StealthManager)
    pub(crate) stealth_padding_enabled: bool,
    pub(crate) stealth_padding_strategy: u8, // 0=off,1=random,2=fixed,3=adaptive,4=browser-mimic
    pub(crate) stealth_padding_max_size: usize,
    // Stealth timing knobs
    pub(crate) stealth_timing_enabled: bool,
    pub(crate) stealth_timing_max_jitter_us: u32,
    // Adaptive padding granularity (bytes), default 64
    pub(crate) stealth_adaptive_granularity: u16,
    // BrowserMimic bias code: 1=very small (Safari/iOS), 2=small (Firefox/Linux), 3=default (Chromium/Windows), 4=mobile (Android)
    pub(crate) stealth_mimic_bias: u8,
    // ACK policy: number of ack-eliciting packets before sending ACK (Chrome-like tuning)
    pub(crate) ack_eliciting_threshold: u64,
    // When true, pacing/timing is controlled externally (e.g., StealthManager/RateChoker)
    // and the internal stealth timing gate should not schedule sleeps.
    pub(crate) external_pacing: bool,
}

impl Config {
    /// Creates a new config with the given version
    pub fn new_with_version(version: u32) -> Result<Self, crate::error::ConnectionError> {
        if version != PROTOCOL_VERSION {
            return Err(crate::error::ConnectionError::UnknownVersion);
        }

        Ok(Self {
            version,
            cc_algorithm: CongestionControlAlgorithm::BBR2,
            application_protos: Vec::new(),
            max_idle_timeout: 30000,
            max_udp_payload_size: 1200,
            initial_max_data: 10485760,
            initial_max_stream_data_bidi_local: 1048576,
            initial_max_stream_data_bidi_remote: 1048576,
            initial_max_stream_data_uni: 1048576,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
            ack_delay_exponent: 3,
            max_ack_delay: 25,
            disable_active_migration: false,
            enable_early_data: false,
            verify_peer: true,
            grease: true,
            cert_chain_path: None,
            priv_key_path: None,
            dgram_recv_max_queue_len: 0,
            dgram_send_max_queue_len: 0,
            path_challenge_recv_max_queue_len: 3,
            max_connection_window: 24 * 1024 * 1024,
            max_stream_window: 6 * 1024 * 1024,
            max_amplification_factor: 3,
            send_capacity_factor: 1.0,
            pmtu_discovery_enabled: false,
            disable_dcid_reuse: false,
            track_unknown_transport_params: None,
            chlo_template: None,
            tls_grease_disabled: false,
            deterministic_hello_enabled: false,
            pacing: true,
            max_pacing_rate: None,
            hystart: true,
            initial_congestion_window_packets: 10,
            keylog_enabled: false,
            qlog_config: None,
            ticket_key: None,
            tls_session: None,
            simd_enabled: true,
            custom_bbr_settings: None,
            active_connection_id_limit: 8,
            stateless_reset_token: None,
            initial_token: None,
            stealth_padding_enabled: false,
            stealth_padding_strategy: 0,
            stealth_padding_max_size: 0,
            stealth_timing_enabled: false,
            stealth_timing_max_jitter_us: 0,
            stealth_adaptive_granularity: 64,
            stealth_mimic_bias: 3,
            ack_eliciting_threshold: 2,
            external_pacing: false,
        })
    }

    /// Sets the congestion control algorithm
    pub fn set_cc_algorithm(&mut self, algo: CongestionControlAlgorithm) {
        self.cc_algorithm = algo;
    }
    pub fn set_cc_algorithm_name(
        &mut self,
        name: &str,
    ) -> Result<(), crate::error::ConnectionError> {
        self.cc_algorithm = match name.to_lowercase().as_str() {
            "reno" => CongestionControlAlgorithm::Reno,
            "cubic" => CongestionControlAlgorithm::Cubic,
            "bbr" => CongestionControlAlgorithm::BBR,
            "bbr2" => CongestionControlAlgorithm::BBR2,
            "bbr3" => CongestionControlAlgorithm::BBR3,
            "ledbat" => CongestionControlAlgorithm::Ledbat,
            _ => return Err(crate::error::ConnectionError::InvalidState),
        };
        Ok(())
    }

    /// Sets the list of supported application protocols
    pub fn set_application_protos(
        &mut self,
        protos: &[&[u8]],
    ) -> Result<(), crate::error::ConnectionError> {
        self.application_protos = protos.iter().map(|p| p.to_vec()).collect();
        Ok(())
    }
    pub fn set_application_protos_wire_format(
        &mut self,
        _wire: &[u8],
    ) -> Result<(), crate::error::ConnectionError> {
        Ok(())
    }

    /// Sets the maximum idle timeout
    pub fn set_max_idle_timeout(&mut self, v: u64) {
        self.max_idle_timeout = v;
    }

    /// Sets the maximum UDP payload size
    pub fn set_max_recv_udp_payload_size(&mut self, v: usize) {
        self.max_udp_payload_size = v as u64;
    }

    /// Sets the maximum UDP payload size for sending
    pub fn set_max_send_udp_payload_size(&mut self, v: usize) {
        self.max_udp_payload_size = v as u64;
    }
    // duplicate removed: set_max_recv_udp_payload_size

    /// Sets the initial maximum data
    pub fn set_initial_max_data(&mut self, v: u64) {
        self.initial_max_data = v;
    }

    /// Sets the initial maximum stream data for bidirectional streams (local)
    pub fn set_initial_max_stream_data_bidi_local(&mut self, v: u64) {
        self.initial_max_stream_data_bidi_local = v;
    }

    /// Sets the initial maximum stream data for bidirectional streams (remote)
    pub fn set_initial_max_stream_data_bidi_remote(&mut self, v: u64) {
        self.initial_max_stream_data_bidi_remote = v;
    }

    /// Sets the initial maximum stream data for unidirectional streams
    pub fn set_initial_max_stream_data_uni(&mut self, v: u64) {
        self.initial_max_stream_data_uni = v;
    }

    // Introspection helpers (used by tests and admin tooling).
    pub fn max_udp_payload_size(&self) -> u64 {
        self.max_udp_payload_size
    }

    pub fn cc_algorithm(&self) -> CongestionControlAlgorithm {
        self.cc_algorithm
    }

    pub fn pacing_enabled(&self) -> bool {
        self.pacing
    }

    pub fn send_capacity_factor(&self) -> f64 {
        self.send_capacity_factor
    }

    pub fn pmtu_discovery_enabled(&self) -> bool {
        self.pmtu_discovery_enabled
    }

    pub fn simd_enabled(&self) -> bool {
        self.simd_enabled
    }

    pub fn custom_bbr_settings(&self) -> Option<&[u8]> {
        self.custom_bbr_settings.as_deref()
    }

    /// Sets the initial maximum number of bidirectional streams
    pub fn set_initial_max_streams_bidi(&mut self, v: u64) {
        self.initial_max_streams_bidi = v;
    }

    /// Sets the initial maximum number of unidirectional streams
    pub fn set_initial_max_streams_uni(&mut self, v: u64) {
        self.initial_max_streams_uni = v;
    }

    /// Sets the ACK delay exponent
    pub fn set_ack_delay_exponent(&mut self, v: u64) {
        self.ack_delay_exponent = v;
    }

    /// Sets the maximum ACK delay
    pub fn set_max_ack_delay(&mut self, v: u64) {
        self.max_ack_delay = v;
    }

    /// Sets whether to disable active migration
    pub fn set_disable_active_migration(&mut self, v: bool) {
        self.disable_active_migration = v;
    }
    pub fn set_max_amplification_factor(&mut self, v: usize) {
        self.max_amplification_factor = v;
    }
    pub fn set_send_capacity_factor(&mut self, v: f64) {
        // Keep the range conservative to avoid pathological send bursts.
        self.send_capacity_factor = v.clamp(0.1, 16.0);
    }
    pub fn discover_pmtu(&mut self, discover: bool) {
        self.pmtu_discovery_enabled = discover;
    }
    pub fn set_path_challenge_recv_max_queue_len(&mut self, v: usize) {
        self.path_challenge_recv_max_queue_len = v;
    }
    pub fn set_max_connection_window(&mut self, v: u64) {
        self.max_connection_window = v;
    }
    pub fn set_max_stream_window(&mut self, v: u64) {
        self.max_stream_window = v;
    }
    pub fn set_disable_dcid_reuse(&mut self, v: bool) {
        self.disable_dcid_reuse = v;
    }
    pub fn enable_track_unknown_transport_parameters(&mut self, size: usize) {
        self.track_unknown_transport_params = Some(size);
    }
    pub fn enable_dgram(&mut self, recv_q: usize, send_q: usize) {
        self.dgram_recv_max_queue_len = recv_q;
        self.dgram_send_max_queue_len = send_q;
    }
    pub fn enable_pacing(&mut self, v: bool) {
        self.pacing = v;
    }
    pub fn set_max_pacing_rate(&mut self, v: u64) {
        self.max_pacing_rate = Some(v);
    }
    pub fn enable_hystart(&mut self, v: bool) {
        self.hystart = v;
    }
    pub fn set_initial_congestion_window_packets(&mut self, packets: usize) {
        self.initial_congestion_window_packets = packets;
    }

    /// Enables or disables early data
    pub fn enable_early_data(&mut self) {
        self.enable_early_data = true;
    }

    /// Sets whether to verify the peer
    pub fn set_verify(&mut self, v: bool) {
        self.verify_peer = v;
    }
    pub fn verify_peer(&mut self, verify: bool) {
        self.verify_peer = verify;
    }

    /// Sets whether to send GREASE values
    pub fn set_grease(&mut self, v: bool) {
        self.grease = v;
    }
    pub fn grease(&mut self, v: bool) {
        self.grease = v;
    }

    /// Loads certificate chain from file
    pub fn load_cert_chain_from_pem_file(
        &mut self,
        path: &str,
    ) -> Result<(), crate::error::ConnectionError> {
        self.cert_chain_path = Some(path.to_string());
        Ok(())
    }

    /// Loads private key from file
    pub fn load_priv_key_from_pem_file(
        &mut self,
        path: &str,
    ) -> Result<(), crate::error::ConnectionError> {
        self.priv_key_path = Some(path.to_string());
        Ok(())
    }
    pub fn load_verify_locations_from_file(
        &mut self,
        _file: &str,
    ) -> Result<(), crate::error::ConnectionError> {
        Ok(())
    }
    pub fn load_verify_locations_from_directory(
        &mut self,
        _dir: &str,
    ) -> Result<(), crate::error::ConnectionError> {
        Ok(())
    }
    // Real-TLS API
    pub fn set_chlo_template(&mut self, tmpl: &[u8]) -> Result<(), crate::error::ConnectionError> {
        self.chlo_template = Some(tmpl.to_vec());
        Ok(())
    }
    pub fn disable_tls_grease(&mut self, disabled: bool) {
        self.tls_grease_disabled = disabled;
    }
    pub fn set_deterministic_hello(&mut self, enabled: bool) {
        self.deterministic_hello_enabled = enabled;
    }
    pub fn log_keys(&mut self) {
        self.keylog_enabled = true;
    }
    pub fn set_ticket_key(&mut self, _key: &[u8]) -> Result<(), crate::error::ConnectionError> {
        if _key.is_empty() {
            return Err(crate::error::ConnectionError::InvalidState);
        }
        self.ticket_key = Some(_key.to_vec());
        Ok(())
    }
    // duplicate removed: enable_early_data
    pub fn set_custom_tls(&mut self, hello: &[u8]) {
        self.chlo_template = Some(hello.to_vec());
    }
    pub fn enable_simd(&mut self) {
        self.simd_enabled = true;
    }
    // qlog / keylog / session (Stubs)
    pub fn set_keylog(&mut self, enabled: bool) {
        self.keylog_enabled = enabled;
    }
    pub fn set_qlog(
        &mut self,
        path: &str,
        title: &str,
        desc: &str,
    ) -> Result<(), crate::error::ConnectionError> {
        self.set_qlog_with_level(path, title, desc, 0)
    }
    pub fn set_qlog_with_level(
        &mut self,
        path: &str,
        title: &str,
        desc: &str,
        level: u32,
    ) -> Result<(), crate::error::ConnectionError> {
        self.qlog_config = Some((path.to_string(), title.to_string(), desc.to_string(), level));
        Ok(())
    }
    pub fn qlog_streamer(&self) -> Option<()> {
        self.qlog_config.as_ref().map(|_| ())
    }
    pub fn set_session(&mut self, ticket: &[u8]) {
        self.tls_session = Some(ticket.to_vec());
    }
    // Handshake-specific setters (stubs call the base setters)
    pub fn set_initial_congestion_window_packets_in_handshake(&mut self, v: usize) {
        self.set_initial_congestion_window_packets(v);
    }
    pub fn set_hystart_in_handshake(&mut self, v: bool) {
        self.enable_hystart(v);
    }
    pub fn set_pacing_in_handshake(&mut self, v: bool) {
        self.enable_pacing(v);
    }
    pub fn set_max_pacing_rate_in_handshake(&mut self, v: u64) {
        self.set_max_pacing_rate(v);
    }
    pub fn set_max_send_udp_payload_size_in_handshake(&mut self, v: usize) {
        self.set_max_send_udp_payload_size(v);
    }
    pub fn set_send_capacity_factor_in_handshake(&mut self, v: u64) {
        self.set_send_capacity_factor(v as f64);
    }
    pub fn set_discover_pmtu_in_handshake(&mut self, v: bool) {
        self.discover_pmtu(v);
    }
    pub fn set_max_idle_timeout_in_handshake(&mut self, v: u64) {
        self.set_max_idle_timeout(v);
    }
    pub fn set_initial_max_streams_bidi_in_handshake(&mut self, v: u64) {
        self.initial_max_streams_bidi = v;
    }
    pub fn set_initial_max_streams_uni_in_handshake(&mut self, v: u64) {
        self.initial_max_streams_uni = v;
    }
    pub fn set_cc_algorithm_in_handshake(&mut self, algo: CongestionControlAlgorithm) {
        self.set_cc_algorithm(algo);
    }
    pub fn set_cc_algorithm_name_in_handshake(
        &mut self,
        name: &str,
    ) -> Result<(), crate::error::ConnectionError> {
        self.set_cc_algorithm_name(name)
    }
    pub fn set_custom_bbr_settings_in_handshake(&mut self, s: &[u8]) {
        self.custom_bbr_settings = if s.is_empty() { None } else { Some(s.to_vec()) };
    }
    // Misc
    pub fn set_active_connection_id_limit(&mut self, v: u64) {
        self.active_connection_id_limit = v;
    }
    pub fn set_stateless_reset_token(&mut self, token: [u8; 16]) {
        self.stateless_reset_token = Some(token);
    }

    pub fn set_initial_token(&mut self, token: Option<Vec<u8>>) {
        self.initial_token = token;
    }
    // Stealth padding setters
    pub fn set_stealth_padding(&mut self, enabled: bool, strategy: u8, max_size: usize) {
        self.stealth_padding_enabled = enabled;
        self.stealth_padding_strategy = strategy;
        self.stealth_padding_max_size = max_size;
    }
    // Stealth timing setter
    pub fn set_stealth_timing(&mut self, enabled: bool, max_jitter_us: u32) {
        self.stealth_timing_enabled = enabled;
        self.stealth_timing_max_jitter_us = max_jitter_us;
    }
    pub fn set_stealth_adaptive_granularity(&mut self, gran: u16) {
        self.stealth_adaptive_granularity = if gran == 0 { 1 } else { gran };
    }
    pub fn set_stealth_mimic_bias(&mut self, bias: u8) {
        self.stealth_mimic_bias = match bias {
            1..=4 => bias,
            _ => 3,
        };
    }
    /// Sets ACK-eliciting threshold (packets) before emitting ACK
    pub fn set_ack_eliciting_threshold(&mut self, thr: u64) {
        self.ack_eliciting_threshold = thr.max(1);
    }
    /// Disables internal stealth timing sleeps when true (external controller active)
    pub fn set_external_pacing(&mut self, v: bool) {
        self.external_pacing = v;
    }

    // duplicate removed: load_verify_locations_from_directory
}
