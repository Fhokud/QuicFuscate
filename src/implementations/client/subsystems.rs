//! Subsystem initialization and management.

use std::sync::Arc;

use crate::engine::{EngineConfig, EngineError};

use super::{ClientSubsystems, FecCodec};

pub fn init_subsystems(config: &EngineConfig) -> Result<ClientSubsystems, EngineError> {
    let stealth = init_stealth(config)?;
    let fec = Arc::new(std::sync::Mutex::new(FecCodec::new(config.fec.clone())));
    Ok(ClientSubsystems { stealth, fec })
}

fn init_stealth(config: &EngineConfig) -> Result<Arc<crate::stealth::StealthManager>, EngineError> {
    use crate::crypto::CryptoManager;
    use crate::optimize::OptimizationManager;
    use crate::stealth::{StealthConfig, StealthManager};

    let stealth_config = StealthConfig {
        enable_domain_fronting: config.stealth.enable_domain_fronting,
        enable_http3_masquerading: config.stealth.enable_http3_masquerading,
        enable_xor_obfuscation: config.stealth.enable_xor_obfuscation,
        use_tls_cover: config.stealth.use_tls_cover,
        use_qpack_headers: config.stealth.use_qpack_headers,
        enable_traffic_padding: config.stealth.enable_traffic_padding,
        enable_timing_obfuscation: config.stealth.enable_timing_obfuscation,
        enable_protocol_mimicry: config.stealth.enable_protocol_mimicry,
        enable_doh: config.stealth.enable_doh,
        doh_provider: config.stealth.doh_provider.clone(),
        max_padding_size: config.stealth.max_padding_size,
        fronting_domains: config.stealth.fronting_domains.clone(),
        ..Default::default()
    };

    let opt_mgr = Arc::new(OptimizationManager::new());
    let crypto_mgr = Arc::new(CryptoManager::new());

    Ok(Arc::new(StealthManager::new(stealth_config, opt_mgr, crypto_mgr)))
}
