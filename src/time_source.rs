use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Instant, SystemTime};

pub trait TimeSource: Send + Sync {
    fn now_instant(&self) -> Instant;
    fn now_system(&self) -> SystemTime;
}

#[derive(Debug, Default)]
pub struct SystemTimeSource;

impl TimeSource for SystemTimeSource {
    fn now_instant(&self) -> Instant {
        Instant::now()
    }

    fn now_system(&self) -> SystemTime {
        SystemTime::now()
    }
}

fn time_source_cell() -> &'static RwLock<Arc<dyn TimeSource>> {
    static CELL: OnceLock<RwLock<Arc<dyn TimeSource>>> = OnceLock::new();
    CELL.get_or_init(|| RwLock::new(Arc::new(SystemTimeSource)))
}

pub fn now_instant() -> Instant {
    let guard = time_source_cell().read().unwrap_or_else(|e| e.into_inner());
    guard.now_instant()
}

pub fn now_system() -> SystemTime {
    let guard = time_source_cell().read().unwrap_or_else(|e| e.into_inner());
    guard.now_system()
}

#[cfg(test)]
pub struct TimeSourceTestGuard {
    previous: Arc<dyn TimeSource>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
impl Drop for TimeSourceTestGuard {
    fn drop(&mut self) {
        let mut guard = time_source_cell().write().expect("time source poisoned");
        *guard = self.previous.clone();
    }
}

#[cfg(test)]
pub fn install_for_test(source: Arc<dyn TimeSource>) -> TimeSourceTestGuard {
    static TEST_LOCK: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
    let lock = TEST_LOCK
        .get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .expect("time source test lock poisoned");
    let mut guard = time_source_cell().write().expect("time source poisoned");
    let previous = guard.clone();
    *guard = source;
    TimeSourceTestGuard { previous, _lock: lock }
}
