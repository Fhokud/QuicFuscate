#![cfg(feature = "rust-tests")]

use quicfuscate::reality::RealityProxy;
use std::sync::Mutex;
use tokio::sync::mpsc;

static ENV_LOCK: Mutex<()> = Mutex::new(());

struct EnvGuard(Option<String>);
impl EnvGuard {
    fn set(key: &str, val: &str) -> Self {
        let prev = std::env::var(key).ok();
        std::env::set_var(key, val);
        EnvGuard(prev)
    }
    fn clear(key: &str) -> Self {
        let prev = std::env::var(key).ok();
        std::env::remove_var(key);
        EnvGuard(prev)
    }
}
impl Drop for EnvGuard {
    fn drop(&mut self) {
        if let Some(prev) = self.0.take() {
            std::env::set_var("QUICFUSCATE_REALITY_TARGETS", prev);
        } else {
            std::env::remove_var("QUICFUSCATE_REALITY_TARGETS");
        }
    }
}

#[test]
fn reality_targets_rotate_from_env() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let _g = EnvGuard::set("QUICFUSCATE_REALITY_TARGETS", "127.0.0.1:10001,127.0.0.1:10002");
    let (tx, _rx) = mpsc::channel(1);
    let proxy = RealityProxy::new(tx);

    let a = proxy.select_target_for_tests();
    let b = proxy.select_target_for_tests();
    let c = proxy.select_target_for_tests();

    assert_eq!(a, "127.0.0.1:10001");
    assert_eq!(b, "127.0.0.1:10002");
    assert_eq!(c, "127.0.0.1:10001");
}

#[test]
fn reality_targets_use_default_list_when_env_missing() {
    let _lock = ENV_LOCK.lock().expect("env lock");
    let _g = EnvGuard::clear("QUICFUSCATE_REALITY_TARGETS");
    let (tx, _rx) = mpsc::channel(1);
    let proxy = RealityProxy::new(tx);

    let a = proxy.select_target_for_tests();
    let b = proxy.select_target_for_tests();
    let c = proxy.select_target_for_tests();

    assert_eq!(a, "1.1.1.1:443");
    assert_eq!(b, "8.8.8.8:443");
    assert_eq!(c, "9.9.9.9:443");
}
