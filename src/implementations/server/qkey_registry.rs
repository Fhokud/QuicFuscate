use std::path::{Path, PathBuf};

/// Public, stable QKey id used as the QUIC Initial token.
///
/// This is not a secret. Authentication is enforced separately by verifying the per-QKey token
/// post-handshake.
pub fn qkey_id(qkey: &str) -> String {
    let trimmed = qkey.trim();
    // Canonicalize prefix case for stability (copy/paste often changes casing).
    let canonical = if trimmed
        .get(..crate::engine::qkey::QKEY_PREFIX.len())
        .map(|p| p.eq_ignore_ascii_case(crate::engine::qkey::QKEY_PREFIX))
        .unwrap_or(false)
    {
        let rest = trimmed.get(crate::engine::qkey::QKEY_PREFIX.len()..).unwrap_or("");
        if trimmed.starts_with(crate::engine::qkey::QKEY_PREFIX) {
            trimmed.to_string()
        } else {
            format!("{}{}", crate::engine::qkey::QKEY_PREFIX, rest)
        }
    } else {
        trimmed.to_string()
    };
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let hex = format!("{:x}", hasher.finalize());
    hex.chars().take(12).collect()
}

pub fn qkey_token_hex_from_qkey(qkey: &str) -> Option<String> {
    let trimmed = qkey.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(cfg) = crate::engine::qkey::parse(trimmed) {
        if let Some(token) = cfg.token {
            let token = token.trim().to_lowercase();
            if token.len() == 64 && token.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                return Some(token);
            }
        }
    }
    None
}

#[derive(Clone, serde::Serialize)]
pub struct QKeyEntry {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qkey: Option<String>,
    pub created_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stealth: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fec: Option<String>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct QKeyRecord {
    #[serde(default)]
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    // Deprecated: we no longer persist secrets at rest. Kept for backwards compatible loading.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub qkey: String,
    // Deprecated: legacy plaintext token (hex). Kept for backwards compatible loading.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub token: String,
    /// SHA-256 of the 32-byte QKey token. This is the capability verifier (post-handshake).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub token_sha256: String,
    /// Optional per-key policy overrides. "auto" means no override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stealth: Option<String>,
    /// Optional per-key policy overrides. "auto" means no override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fec: Option<String>,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub expires_at: Option<u64>,
}

pub struct QKeyRegistry {
    pub entries: Vec<QKeyRecord>,
    max_entries: usize,
    path: Option<PathBuf>,
    default_ttl_secs: Option<u64>,
}

impl QKeyRegistry {
    pub fn new(max_entries: usize, path: Option<PathBuf>, default_ttl_secs: Option<u64>) -> Self {
        let mut registry = Self { entries: Vec::new(), max_entries, path, default_ttl_secs };
        registry.load();
        registry
    }

    pub fn load(&mut self) {
        let Some(path) = self.path.as_ref() else {
            return;
        };
        let bytes = match std::fs::read(path) {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                log::warn!("qkey registry load failed ({}): {}", path.display(), e);
                return;
            }
        };
        let mut entries: Vec<QKeyRecord> = match serde_json::from_slice(&bytes) {
            Ok(list) => list,
            Err(e) => {
                log::warn!("qkey registry parse failed ({}): {}", path.display(), e);
                return;
            }
        };
        let mut seen = std::collections::HashSet::new();
        let mut filtered = Vec::new();
        let mut migrated = false;
        for mut entry in entries.drain(..) {
            let has_legacy_qkey = !entry.qkey.trim().is_empty();

            // If a legacy QKey is present, require that it is parseable. This protects us from
            // persisting corrupt/tampered secrets and also lets us extract the token and policy.
            let parsed = if has_legacy_qkey {
                match crate::engine::qkey::parse(entry.qkey.trim()) {
                    Ok(cfg) => Some(cfg),
                    Err(_) => continue,
                }
            } else {
                None
            };

            if has_legacy_qkey {
                // For legacy entries we can still derive a stable id from the full QKey.
                // This also deduplicates entries that were persisted with incorrect ids.
                let id = qkey_id(entry.qkey.trim());
                if entry.id != id {
                    entry.id = id;
                    migrated = true;
                }
            } else if entry.id.trim().is_empty() {
                continue;
            }

            // Prefer new storage. If missing, derive from legacy token or the embedded token.
            if entry.token_sha256.trim().is_empty() {
                let mut token_hex: Option<String> = None;
                if !entry.token.trim().is_empty() {
                    token_hex = Some(entry.token.trim().to_lowercase());
                } else if let Some(cfg) = parsed.as_ref() {
                    if let Some(ref token) = cfg.token {
                        token_hex = Some(token.trim().to_lowercase());
                    }
                }
                let Some(token_hex) = token_hex else {
                    continue;
                };
                let Some(hash_hex) = token_sha256_hex_from_token_hex(&token_hex) else {
                    continue;
                };
                entry.token_sha256 = hash_hex;
                migrated = true;
            }

            // If no policy is stored, extract it from the legacy QKey.
            if entry.stealth.is_none() || entry.fec.is_none() {
                if let Some(parsed) = parsed.as_ref() {
                    let (stealth, fec) = policy_from_parsed_qkey(parsed);
                    if entry.stealth.is_none() && stealth.is_some() {
                        entry.stealth = stealth;
                        migrated = true;
                    }
                    if entry.fec.is_none() && fec.is_some() {
                        entry.fec = fec;
                        migrated = true;
                    }
                }
            }

            if entry.created_at == 0 {
                entry.created_at = current_epoch_secs();
                migrated = true;
            }

            // Redact legacy plaintext token from persisted storage (best effort migration).
            if !entry.token.is_empty() {
                entry.token.clear();
                migrated = true;
            }

            if !seen.insert(entry.id.clone()) {
                continue;
            }
            filtered.push(entry);
        }
        if filtered.len() > self.max_entries {
            let excess = filtered.len() - self.max_entries;
            filtered.drain(0..excess);
        }
        let before = filtered.len();
        let now = current_epoch_secs();
        filtered.retain(|entry| !is_expired(entry.expires_at, now));
        let removed = before != filtered.len();
        self.entries = filtered;
        if removed || migrated {
            self.persist();
        }
    }

    pub fn insert(
        &mut self,
        qkey: String,
        token_hex: String,
        name: Option<String>,
    ) -> Result<QKeyEntry, String> {
        self.insert_with_ttl(qkey, token_hex, None, name)
    }

    pub fn insert_with_ttl(
        &mut self,
        qkey: String,
        token_hex: String,
        ttl_seconds: Option<u64>,
        name: Option<String>,
    ) -> Result<QKeyEntry, String> {
        self.prune_expired();
        let id = qkey_id(&qkey);
        if let Some(existing) = self.entries.iter().find(|e| e.id == id).cloned() {
            return Ok(QKeyEntry {
                id: existing.id,
                name: existing.name,
                qkey: if existing.qkey.is_empty() { None } else { Some(existing.qkey) },
                created_at: existing.created_at,
                expires_at: existing.expires_at,
                stealth: existing.stealth,
                fec: existing.fec,
            });
        }
        let parsed = crate::engine::qkey::parse(qkey.trim()).ok();
        let (stealth, fec) = parsed.as_ref().map(policy_from_parsed_qkey).unwrap_or((None, None));
        let token_hex = token_hex.trim().to_lowercase();
        let token_sha256 = match token_sha256_hex_from_token_hex(&token_hex) {
            Some(h) => h,
            None => return Err("Invalid QKey token (expected 64 hex chars)".to_string()),
        };
        let expires_at = compute_expiry(ttl_seconds.or(self.default_ttl_secs));
        let record = QKeyRecord {
            id,
            name,
            qkey,
            token: String::new(),
            token_sha256,
            stealth,
            fec,
            created_at: current_epoch_secs(),
            expires_at,
        };
        self.entries.push(record.clone());
        if self.entries.len() > self.max_entries {
            let excess = self.entries.len() - self.max_entries;
            self.entries.drain(0..excess);
        }
        self.persist();
        Ok(QKeyEntry {
            id: record.id,
            name: record.name,
            qkey: if record.qkey.is_empty() { None } else { Some(record.qkey) },
            created_at: record.created_at,
            expires_at: record.expires_at,
            stealth: record.stealth,
            fec: record.fec,
        })
    }

    pub fn list(&mut self) -> Vec<QKeyEntry> {
        self.prune_expired();
        self.entries
            .iter()
            .cloned()
            .map(|entry| QKeyEntry {
                id: entry.id,
                name: entry.name,
                qkey: if entry.qkey.is_empty() { None } else { Some(entry.qkey) },
                created_at: entry.created_at,
                expires_at: entry.expires_at,
                stealth: entry.stealth,
                fec: entry.fec,
            })
            .collect()
    }

    pub fn revoke(&mut self, id: &str) -> bool {
        self.prune_expired();
        let before = self.entries.len();
        self.entries.retain(|entry| entry.id != id);
        let changed = before != self.entries.len();
        if changed {
            self.persist();
        }
        changed
    }

    pub fn record_for_id_token(&mut self, token: &[u8]) -> Option<QKeyRecord> {
        self.lookup_initial_id_token(token)
    }

    /// Look up a record by Initial packet token value, which must be a 12-char
    /// QKey identifier (case-insensitive hex).
    pub fn lookup_initial_id_token(&mut self, token: &[u8]) -> Option<QKeyRecord> {
        let id = normalize_initial_id_token(token)?;
        self.prune_expired();
        self.entries.iter().find(|entry| entry.id == id).cloned()
    }

    pub fn has_entries(&mut self) -> bool {
        self.prune_expired();
        !self.entries.is_empty()
    }

    fn prune_expired(&mut self) {
        let before = self.entries.len();
        let now = current_epoch_secs();
        self.entries.retain(|entry| !is_expired(entry.expires_at, now));
        if before != self.entries.len() {
            self.persist();
        }
    }

    fn persist(&self) {
        let Some(path) = self.path.as_ref() else {
            return;
        };
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                log::warn!("qkey registry mkdir failed ({}): {}", parent.display(), e);
                return;
            }
        }
        let payload = match serde_json::to_vec_pretty(&self.entries) {
            Ok(data) => data,
            Err(e) => {
                log::warn!("qkey registry serialize failed: {}", e);
                return;
            }
        };
        if let Err(e) = atomic_write_file(path, &payload, Some(0o600)) {
            log::warn!("qkey registry write failed ({}): {}", path.display(), e);
        }
    }
}

fn normalize_initial_id_token(token: &[u8]) -> Option<String> {
    let id = std::str::from_utf8(token).ok()?.trim();
    if id.len() != 12 {
        return None;
    }
    if !id.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(id.to_ascii_lowercase())
}

fn current_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn token_sha256_hex_from_token_hex(token_hex: &str) -> Option<String> {
    let token_hex = token_hex.trim();
    if token_hex.len() != 64 {
        return None;
    }
    if !token_hex.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    // Hash the canonical (lowercased) hex string. We do not need to decode to bytes for security.
    // The token is already a random 32-byte capability; this hash is only to avoid storing it at rest.
    let canonical = token_hex.to_ascii_lowercase();
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    Some(format!("{:x}", hasher.finalize()))
}

fn policy_from_parsed_qkey(
    cfg: &crate::engine::qkey::QKeyConfig,
) -> (Option<String>, Option<String>) {
    let stealth = cfg
        .stealth
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
        .and_then(|s| if s == "auto" { None } else { Some(s) });
    let fec = cfg
        .fec
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
        .and_then(|s| if s == "auto" { None } else { Some(s) });
    (stealth, fec)
}

fn compute_expiry(ttl_seconds: Option<u64>) -> Option<u64> {
    let ttl = match ttl_seconds {
        Some(0) | None => return None,
        Some(v) => v,
    };
    Some(current_epoch_secs().saturating_add(ttl))
}

fn is_expired(expires_at: Option<u64>, now: u64) -> bool {
    matches!(expires_at, Some(ts) if ts <= now)
}

fn atomic_write_file(path: &Path, bytes: &[u8], mode: Option<u32>) -> std::io::Result<()> {
    use std::io::Write;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("file");
    let tmp_name = format!(".{file_name}.tmp-{}", fastrand::u64(..));
    let tmp_path = parent.join(tmp_name);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    {
        let mut f =
            std::fs::OpenOptions::new().create(true).truncate(true).write(true).open(&tmp_path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }

    #[cfg(unix)]
    if let Some(mode) = mode {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(mode));
    }

    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::qkey;

    fn mk_token_hex(ch: char) -> String {
        std::iter::repeat_n(ch, 64).collect()
    }

    fn mk_qkey_with_token(token_hex: &str) -> String {
        let cfg = qkey::QKeyConfig::new("127.0.0.1:4433", "example.com")
            .with_stealth("auto")
            .with_fec("auto")
            .with_token(token_hex);
        qkey::generate(&cfg)
    }

    fn mk_temp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let salt = fastrand::u64(..);
        p.push(format!("quicfuscate-test-{name}-{salt}.json"));
        p
    }

    fn read_records(path: &Path) -> Vec<QKeyRecord> {
        let bytes = std::fs::read(path).expect("read test file");
        serde_json::from_slice::<Vec<QKeyRecord>>(&bytes).expect("parse json")
    }

    #[test]
    fn insert_and_lookup_by_initial_id_token() {
        let token_hex = mk_token_hex('a');
        let qkey_value = mk_qkey_with_token(&token_hex);
        let id = qkey_id(&qkey_value);
        let token_sha = token_sha256_hex_from_token_hex(&token_hex).expect("sha");

        let mut reg = QKeyRegistry::new(200, None, None);
        reg.insert(qkey_value.clone(), token_hex.clone(), None).expect("insert");

        let got = reg.lookup_initial_id_token(id.as_bytes()).expect("record must exist");
        assert_eq!(got.id, id);
        assert_eq!(got.qkey, qkey_value);
        assert!(got.token.is_empty());
        assert_eq!(got.token_sha256, token_sha);

        assert!(reg.lookup_initial_id_token(b"").is_none());
        assert!(reg.lookup_initial_id_token(b"unknown").is_none());
    }

    #[test]
    fn qkey_id_is_stable_across_prefix_case_and_whitespace() {
        let token_hex = mk_token_hex('f');
        let qkey_value = mk_qkey_with_token(&token_hex);
        let rest = qkey_value
            .trim()
            .strip_prefix(crate::engine::qkey::QKEY_PREFIX)
            .expect("generated key has prefix");
        let pasted = format!("  {}{}  ", crate::engine::qkey::QKEY_PREFIX.to_lowercase(), rest);
        assert_eq!(qkey_id(&qkey_value), qkey_id(&pasted));
    }

    #[test]
    fn prunes_expired_records() {
        let token_hex = mk_token_hex('b');
        let qkey_value = mk_qkey_with_token(&token_hex);
        let id = qkey_id(&qkey_value);

        let mut reg = QKeyRegistry::new(200, None, None);
        reg.insert(qkey_value, token_hex, None).expect("insert");
        assert_eq!(reg.entries.len(), 1);

        let now = current_epoch_secs();
        reg.entries[0].expires_at = Some(now.saturating_sub(1));

        assert!(reg.lookup_initial_id_token(id.as_bytes()).is_none());
        assert!(reg.list().is_empty());
    }

    #[test]
    fn lookup_initial_id_token_rejects_non_hex_and_too_short_values() {
        let token_hex = mk_token_hex('a');
        let qkey_value = mk_qkey_with_token(&token_hex);
        let id = qkey_id(&qkey_value);

        let mut reg = QKeyRegistry::new(200, None, None);
        reg.insert(qkey_value, token_hex, None).expect("insert");
        assert!(reg.lookup_initial_id_token(id.to_uppercase().as_bytes()).is_some());
        assert!(reg.lookup_initial_id_token(b"").is_none());
        assert!(reg.lookup_initial_id_token(b"abc").is_none());
        assert!(reg.lookup_initial_id_token(b"a1b2c3d4e5f6g7").is_none());
    }

    #[test]
    fn revoke_persists_to_disk() {
        let path = mk_temp_path("qkeys-revoke");
        let _ = std::fs::remove_file(&path);

        let token_hex = mk_token_hex('c');
        let qkey_value = mk_qkey_with_token(&token_hex);
        let id = qkey_id(&qkey_value);

        {
            let mut reg = QKeyRegistry::new(200, Some(path.clone()), None);
            reg.insert(qkey_value, token_hex, None).expect("insert");
        }

        let before = read_records(&path);
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].id, id);

        {
            let mut reg = QKeyRegistry::new(200, Some(path.clone()), None);
            assert!(reg.revoke(&id));
        }

        let after = read_records(&path);
        assert_eq!(after.len(), 0);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_filters_invalid_and_repairs_missing_fields() {
        let path = mk_temp_path("qkeys-load");
        let _ = std::fs::remove_file(&path);

        let token_hex = mk_token_hex('d');
        let qkey_value = mk_qkey_with_token(&token_hex);
        let id = qkey_id(&qkey_value);
        let now = current_epoch_secs();

        let records = vec![
            QKeyRecord {
                id: "wrong".to_string(),
                name: None,
                qkey: qkey_value.clone(),
                token: "".to_string(),
                token_sha256: "".to_string(),
                stealth: None,
                fec: None,
                created_at: now,
                expires_at: None,
            },
            QKeyRecord {
                id: "expired".to_string(),
                name: None,
                qkey: qkey_value.clone(),
                token: token_hex.clone(),
                token_sha256: "".to_string(),
                stealth: None,
                fec: None,
                created_at: now,
                expires_at: Some(now.saturating_sub(1)),
            },
            QKeyRecord {
                id: "".to_string(),
                name: None,
                qkey: "".to_string(),
                token: "".to_string(),
                token_sha256: "".to_string(),
                stealth: None,
                fec: None,
                created_at: now,
                expires_at: None,
            },
            QKeyRecord {
                id: "bad".to_string(),
                name: None,
                qkey: "QKey-not-a-real-qkey".to_string(),
                token: mk_token_hex('e'),
                token_sha256: "".to_string(),
                stealth: None,
                fec: None,
                created_at: now,
                expires_at: None,
            },
            QKeyRecord {
                id: id.clone(),
                name: None,
                qkey: qkey_value.clone(),
                token: token_hex.clone(),
                token_sha256: "".to_string(),
                stealth: None,
                fec: None,
                created_at: now,
                expires_at: None,
            },
        ];

        let bytes = serde_json::to_vec_pretty(&records).expect("serialize");
        std::fs::write(&path, bytes).expect("write test file");

        let reg = QKeyRegistry::new(200, Some(path.clone()), None);
        assert_eq!(reg.entries.len(), 1);
        assert_eq!(reg.entries[0].id, id);
        assert_eq!(reg.entries[0].qkey, qkey_value);
        assert!(reg.entries[0].token.is_empty());
        assert!(!reg.entries[0].token_sha256.is_empty());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn qkey_token_hex_extraction_is_stable_and_lowercased() {
        let token_hex = "A".repeat(64);
        let qkey_value = mk_qkey_with_token(&token_hex);
        let lower = qkey_token_hex_from_qkey(&qkey_value).expect("token");
        assert_eq!(lower, "a".repeat(64));

        let mut pasted = qkey_value.clone();
        if let Some(rest) = pasted.strip_prefix(crate::engine::qkey::QKEY_PREFIX) {
            pasted = format!("{}{}", crate::engine::qkey::QKEY_PREFIX.to_lowercase(), rest);
        }
        let lower2 = qkey_token_hex_from_qkey(&pasted).expect("token");
        assert_eq!(lower2, "a".repeat(64));
    }

    #[test]
    fn token_sha256_hex_validation_rejects_bad_inputs() {
        assert!(token_sha256_hex_from_token_hex("").is_none());
        assert!(token_sha256_hex_from_token_hex("abc").is_none());
        assert!(token_sha256_hex_from_token_hex(&"g".repeat(64)).is_none());
        assert!(token_sha256_hex_from_token_hex(&"a".repeat(63)).is_none());
        assert!(token_sha256_hex_from_token_hex(&"a".repeat(65)).is_none());
        assert!(token_sha256_hex_from_token_hex(&"A".repeat(64)).is_some());
    }

    #[test]
    fn insert_with_ttl_applies_expiry_and_zero_means_no_expiry() {
        let mut reg = QKeyRegistry::new(200, None, Some(90));

        let t1 = mk_token_hex('1');
        let q1 = mk_qkey_with_token(&t1);
        let e1 = reg.insert_with_ttl(q1, t1, Some(60), None).expect("insert ttl");
        let now = current_epoch_secs();
        let exp = e1.expires_at.expect("expires");
        assert!(exp >= now + 55 && exp <= now + 65);

        let t2 = mk_token_hex('2');
        let q2 = mk_qkey_with_token(&t2);
        let e2 = reg.insert_with_ttl(q2, t2, Some(0), None).expect("insert no expiry");
        assert!(e2.expires_at.is_none());
    }

    #[test]
    fn insert_with_default_ttl_is_used_when_request_ttl_missing() {
        let mut reg = QKeyRegistry::new(200, None, Some(120));
        let token_hex = mk_token_hex('3');
        let qkey_value = mk_qkey_with_token(&token_hex);
        let e = reg.insert(qkey_value, token_hex, None).expect("insert");
        let now = current_epoch_secs();
        let exp = e.expires_at.expect("default expiry");
        assert!(exp >= now + 115 && exp <= now + 125);
    }

    #[test]
    fn max_entries_evicts_oldest_records() {
        let mut reg = QKeyRegistry::new(2, None, None);

        let t1 = mk_token_hex('4');
        let q1 = mk_qkey_with_token(&t1);
        let e1 = reg.insert(q1, t1, None).expect("insert 1");

        let t2 = mk_token_hex('5');
        let q2 = mk_qkey_with_token(&t2);
        let e2 = reg.insert(q2, t2, None).expect("insert 2");

        let t3 = mk_token_hex('6');
        let q3 = mk_qkey_with_token(&t3);
        let e3 = reg.insert(q3, t3, None).expect("insert 3");

        let ids: Vec<String> = reg.list().into_iter().map(|e| e.id).collect();
        assert_eq!(ids.len(), 2);
        assert!(!ids.contains(&e1.id));
        assert!(ids.contains(&e2.id));
        assert!(ids.contains(&e3.id));
    }
}
