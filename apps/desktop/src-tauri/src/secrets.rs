use std::sync::Arc;

#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use std::sync::Mutex;

pub trait SecretStore: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<String>, String>;
    fn set(&self, key: &str, value: &str) -> Result<(), String>;
    fn delete(&self, key: &str) -> Result<(), String>;
}

pub struct KeyringSecretStore {
    service: String,
}

impl KeyringSecretStore {
    pub fn new(service: &str) -> Self {
        Self { service: service.to_string() }
    }

    fn entry(&self, key: &str) -> Result<keyring::Entry, String> {
        // We store the entire QKey string as a single secret per tunnel id.
        // `key` must be stable across app restarts and unique per tunnel.
        keyring::Entry::new(&self.service, key).map_err(|e| e.to_string())
    }
}

impl SecretStore for KeyringSecretStore {
    fn get(&self, key: &str) -> Result<Option<String>, String> {
        let entry = self.entry(key)?;
        match entry.get_password() {
            Ok(v) => Ok(Some(v)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    fn set(&self, key: &str, value: &str) -> Result<(), String> {
        let entry = self.entry(key)?;
        entry.set_password(value).map_err(|e| e.to_string())
    }

    fn delete(&self, key: &str) -> Result<(), String> {
        let entry = self.entry(key)?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }
}

pub fn default_store() -> Arc<dyn SecretStore> {
    Arc::new(KeyringSecretStore::new("quicfuscate.desktop"))
}

#[cfg(test)]
#[derive(Default)]
pub struct MemorySecretStore {
    inner: Mutex<HashMap<String, String>>,
}

#[cfg(test)]
impl MemorySecretStore {
    pub fn new() -> Self {
        Self { inner: Mutex::new(HashMap::new()) }
    }
}

#[cfg(test)]
impl SecretStore for MemorySecretStore {
    fn get(&self, key: &str) -> Result<Option<String>, String> {
        Ok(self.inner.lock().map_err(|e| e.to_string())?.get(key).cloned())
    }

    fn set(&self, key: &str, value: &str) -> Result<(), String> {
        self.inner.lock().map_err(|e| e.to_string())?.insert(key.to_string(), value.to_string());
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<(), String> {
        self.inner.lock().map_err(|e| e.to_string())?.remove(key);
        Ok(())
    }
}
