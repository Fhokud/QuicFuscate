use crate::secrets::SecretStore;
use crate::{hydrate_state_for_runtime, redact_state_for_disk, PersistedState};
use quicfuscate::rng::fill_secure_or_abort;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tauri::Manager;

pub trait StateStore: Send + Sync {
    fn state_path(&self, app: &tauri::AppHandle) -> Result<PathBuf, String>;
    fn save_state(
        &self,
        app: &tauri::AppHandle,
        state: PersistedState,
        store: &dyn SecretStore,
    ) -> Result<PathBuf, String>;
    fn load_state(
        &self,
        app: &tauri::AppHandle,
        store: &dyn SecretStore,
    ) -> Result<Option<PersistedState>, String>;
}

#[derive(Default)]
pub struct FileStateStore;

impl FileStateStore {
    pub fn new() -> Self {
        Self
    }

    fn atomic_write_json(&self, path: &Path, json: &str) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }

        let mut nonce = [0u8; 8];
        fill_secure_or_abort(&mut nonce, "state_store::atomic_write_json");
        let mut suffix = String::from(".tmp-");
        for b in nonce {
            let _ = std::fmt::Write::write_fmt(&mut suffix, format_args!("{:02x}", b));
        }
        let tmp = path.with_file_name(format!(
            "{}{}",
            path.file_name().and_then(|s| s.to_str()).unwrap_or("file"),
            suffix
        ));

        let mut file = File::create(&tmp).map_err(|e| e.to_string())?;
        file.write_all(json.as_bytes()).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }

        Ok(())
    }

    fn corrupt_state_path(&self, path: &Path) -> PathBuf {
        let mut nonce = [0u8; 4];
        fill_secure_or_abort(&mut nonce, "state_store::corrupt_state_path");
        let mut suffix = format!(".corrupt-{}", now_ms());
        for b in nonce {
            let _ = std::fmt::Write::write_fmt(&mut suffix, format_args!("-{:02x}", b));
        }
        path.with_file_name(format!(
            "{}{}",
            path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("desktop_state.json"),
            suffix
        ))
    }

    pub(crate) fn save_state_to_path(
        &self,
        path: &Path,
        state: PersistedState,
        store: &dyn SecretStore,
    ) -> Result<(), String> {
        let redacted = redact_state_for_disk(state, store);
        let json = serde_json::to_string_pretty(&redacted).map_err(|e| e.to_string())?;
        self.atomic_write_json(path, &json)
    }

    pub(crate) fn load_state_from_path(
        &self,
        path: &Path,
        store: &dyn SecretStore,
    ) -> Result<Option<PersistedState>, String> {
        if !path.exists() {
            return Ok(None);
        }
        let data = std::fs::read_to_string(path).map_err(|e| e.to_string())?;

        let process = |raw: &str| -> Result<(PersistedState, String), String> {
            let state = serde_json::from_str::<PersistedState>(raw)
                .map_err(|e| format!("State parse failed: {}", e))?;
            let runtime = hydrate_state_for_runtime(state, store);
            let disk = redact_state_for_disk(runtime.clone(), store);
            let json = serde_json::to_string_pretty(&disk).map_err(|e| e.to_string())?;
            Ok((runtime, json))
        };

        let (runtime, json) = match process(&data) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("State parse failed: {}", e);
                let dst = self.corrupt_state_path(path);
                if std::fs::rename(path, &dst).is_ok() {
                    log::warn!("State file was corrupted and was renamed to {:?}", dst);
                } else {
                    log::warn!("State file was corrupted but could not be renamed");
                }
                return Ok(None);
            }
        };

        let _ = self.atomic_write_json(path, &json);
        Ok(Some(runtime))
    }
}

impl StateStore for FileStateStore {
    fn state_path(&self, app: &tauri::AppHandle) -> Result<PathBuf, String> {
        let dir = app
            .path()
            .app_config_dir()
            .map_err(|e| format!("Cannot determine app config dir: {}", e))?;
        Ok(dir.join("desktop_state.json"))
    }

    fn save_state(
        &self,
        app: &tauri::AppHandle,
        state: PersistedState,
        store: &dyn SecretStore,
    ) -> Result<PathBuf, String> {
        let path = self.state_path(app)?;
        self.save_state_to_path(&path, state, store)?;
        Ok(path)
    }

    fn load_state(
        &self,
        app: &tauri::AppHandle,
        store: &dyn SecretStore,
    ) -> Result<Option<PersistedState>, String> {
        let path = self.state_path(app)?;
        self.load_state_from_path(&path, store)
    }
}

pub fn default_store() -> Arc<dyn StateStore> {
    Arc::new(FileStateStore::new())
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
