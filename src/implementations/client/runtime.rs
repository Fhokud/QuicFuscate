//! Tokio runtime management for the client.

use std::sync::Arc;
use tokio::runtime::{Builder, Runtime};

/// Runtime configuration for the client.
#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    /// Number of worker threads (0 = auto)
    pub worker_threads: usize,
    /// Thread name prefix
    pub thread_name: String,
    /// Enable I/O driver
    pub enable_io: bool,
    /// Enable time driver
    pub enable_time: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            worker_threads: 0,
            thread_name: "qf-client".to_string(),
            enable_io: true,
            enable_time: true,
        }
    }
}

/// Creates a tokio runtime with the given configuration.
pub fn create_runtime(config: &RuntimeConfig) -> std::io::Result<Runtime> {
    let mut builder = if config.worker_threads == 1 {
        Builder::new_current_thread()
    } else {
        let mut mt = Builder::new_multi_thread();
        if config.worker_threads > 0 {
            mt.worker_threads(config.worker_threads);
        }
        mt
    };

    builder.thread_name(&config.thread_name);

    if config.enable_io {
        builder.enable_io();
    }
    if config.enable_time {
        builder.enable_time();
    }

    builder.build()
}

/// Shared runtime handle for async operations.
pub type SharedRuntime = Arc<Runtime>;

/// Create a shared runtime.
pub fn create_shared_runtime(config: &RuntimeConfig) -> std::io::Result<SharedRuntime> {
    Ok(Arc::new(create_runtime(config)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_runtime_default() {
        let config = RuntimeConfig::default();
        let runtime = create_runtime(&config);
        assert!(runtime.is_ok());
    }

    #[test]
    fn test_create_runtime_single_thread() {
        let config = RuntimeConfig { worker_threads: 1, ..Default::default() };
        let runtime = create_runtime(&config);
        assert!(runtime.is_ok());
    }
}
