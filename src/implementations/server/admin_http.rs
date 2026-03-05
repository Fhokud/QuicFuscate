//! HTTP admin server for web dashboard control.
//!
//! Serves static web assets and exposes a JSON API backed by an AdminHttpHandler.

use argon2::Argon2;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, RwLock,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::admin::{AdminResponse, ClientInfo};

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_USERNAME_CHARS: usize = 64;
const MAX_PASSWORD_BYTES: usize = 256;
const SESSION_COOKIE: &str = "qf_admin_session";
const SESSION_TTL_SECS: u64 = 12 * 60 * 60;
const CSRF_TOKEN_BYTES: usize = 16;
const CSRF_TOKEN_HEADER: &str = "X-CSRF-Token";
const CSRF_NONCE_HEADER: &str = "X-CSRF-Nonce";
const MAX_REPLAY_FINGERPRINTS: usize = 128;
const MAX_QKEY_TTL_SECS: u64 = 60 * 60 * 24 * 365 * 10; // 10 years
const ADMIN_CSP: &str = "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; font-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'none'";

#[derive(Clone, Debug)]
pub struct AdminAuth {
    user: String,
    password_phc: String,
    requires_password_change: bool,
}

impl AdminAuth {
    pub fn new(user: String, password: String, requires_password_change: bool) -> Self {
        let password_phc = hash_password(&password);
        Self { user, password_phc, requires_password_change }
    }

    fn verify(&self, user: &str, password: &str) -> bool {
        if self.user != user {
            return false;
        }
        verify_password(&self.password_phc, password)
    }

    fn user(&self) -> &str {
        self.user.as_str()
    }

    fn requires_password_change(&self) -> bool {
        self.requires_password_change
    }

    fn verify_password_only(&self, password: &str) -> bool {
        verify_password(&self.password_phc, password)
    }

    fn set_credentials(&mut self, new_user: String, new_password: String) {
        self.user = new_user;
        self.password_phc = hash_password(&new_password);
        self.requires_password_change = false;
    }

    fn set_username(&mut self, new_user: String) {
        self.user = new_user;
        // Intentionally keep password hash and requires_password_change unchanged.
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AdminAuthFile {
    user: String,
    password_phc: String,
    #[serde(default)]
    requires_password_change: bool,
    #[serde(default)]
    updated_at: u64,
}

fn load_auth_file(path: &Path) -> Option<AdminAuth> {
    let bytes = std::fs::read(path).ok()?;
    let file: AdminAuthFile = serde_json::from_slice(&bytes).ok()?;
    if file.user.trim().is_empty() || file.password_phc.trim().is_empty() {
        return None;
    }
    Some(AdminAuth {
        user: file.user,
        password_phc: file.password_phc,
        requires_password_change: file.requires_password_change,
    })
}

fn persist_auth_file(path: &Path, auth: &AdminAuth) {
    let payload = AdminAuthFile {
        user: auth.user.clone(),
        password_phc: auth.password_phc.clone(),
        requires_password_change: auth.requires_password_change,
        updated_at: current_epoch_secs(),
    };
    let bytes = match serde_json::to_vec_pretty(&payload) {
        Ok(b) => b,
        Err(e) => {
            log::warn!("admin auth serialize failed: {}", e);
            return;
        }
    };
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            log::warn!("admin auth mkdir failed ({}): {}", parent.display(), e);
            return;
        }
    }
    if let Err(e) = atomic_write_file(path, &bytes) {
        log::warn!("admin auth write failed ({}): {}", path.display(), e);
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
}

fn atomic_write_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::fs::File;
    use std::io::Write;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut nonce = [0u8; 8];
    OsRng.fill_bytes(&mut nonce);
    let mut tmp_name = String::from(".tmp-");
    for b in nonce {
        let _ = std::fmt::Write::write_fmt(&mut tmp_name, format_args!("{:02x}", b));
    }

    let tmp_path = path.with_file_name(format!(
        "{}{}",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("file"),
        tmp_name
    ));

    let mut f = File::create(&tmp_path)?;
    f.write_all(bytes)?;
    f.sync_all()?;

    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

fn current_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

struct LoginRateLimiter {
    attempts: HashMap<String, (u32, Instant)>,
    max_attempts: u32,
    lockout: Duration,
}

impl LoginRateLimiter {
    fn new(max_attempts: u32, lockout_secs: u64) -> Self {
        Self { attempts: HashMap::new(), max_attempts, lockout: Duration::from_secs(lockout_secs) }
    }

    fn is_locked(&mut self, ip: &str) -> bool {
        self.prune();
        if let Some((count, _)) = self.attempts.get(ip) {
            *count >= self.max_attempts
        } else {
            false
        }
    }

    fn record_failure(&mut self, ip: &str) {
        let entry = self.attempts.entry(ip.to_string()).or_insert((0, Instant::now()));
        entry.0 += 1;
        entry.1 = Instant::now();
    }

    fn clear(&mut self, ip: &str) {
        self.attempts.remove(ip);
    }

    fn prune(&mut self) {
        let cutoff = self.lockout;
        self.attempts.retain(|_, (_, ts)| ts.elapsed() < cutoff);
    }

    fn retry_after_secs(&mut self, ip: &str) -> Option<u64> {
        self.prune();
        let (count, last) = self.attempts.get(ip)?;
        if *count < self.max_attempts {
            return None;
        }
        let elapsed = last.elapsed();
        let rem = self.lockout.checked_sub(elapsed).unwrap_or_else(|| Duration::from_secs(0));
        Some(rem.as_secs().max(1))
    }
}

struct SessionStore {
    sessions: HashMap<String, SessionRecord>,
    ttl: Duration,
}

#[derive(Debug)]
struct SessionRecord {
    expires_at: Instant,
    csrf_token: String,
    replay_fingerprints: Vec<u64>,
}

impl SessionStore {
    fn new(ttl: Duration) -> Self {
        Self { sessions: HashMap::new(), ttl }
    }

    fn create(&mut self) -> (String, String) {
        self.prune();
        let mut buf = [0u8; 32];
        OsRng.fill_bytes(&mut buf);
        let id = URL_SAFE_NO_PAD.encode(buf);

        let mut token = [0u8; CSRF_TOKEN_BYTES];
        OsRng.fill_bytes(&mut token);
        let mut csrf_token = String::with_capacity(token.len() * 2);
        for b in token {
            let _ = std::fmt::Write::write_fmt(&mut csrf_token, format_args!("{:02x}", b));
        }

        let expires_at = Instant::now() + self.ttl;
        self.sessions.insert(
            id.clone(),
            SessionRecord {
                expires_at,
                csrf_token: csrf_token.clone(),
                replay_fingerprints: Vec::new(),
            },
        );
        (id, csrf_token)
    }

    fn is_valid(&mut self, id: &str) -> bool {
        self.prune();
        if let Some(record) = self.sessions.get_mut(id) {
            if record.expires_at > Instant::now() {
                record.expires_at = Instant::now() + self.ttl;
                return true;
            }
        }
        false
    }

    fn csrf_token(&mut self, id: &str) -> Option<String> {
        self.prune();
        let record = self.sessions.get_mut(id)?;
        if record.expires_at <= Instant::now() {
            return None;
        }
        record.expires_at = Instant::now() + self.ttl;
        Some(record.csrf_token.clone())
    }

    fn validate_post_guard(
        &mut self,
        id: &str,
        csrf_token: &str,
        replay_fingerprint: u64,
        enforce_replay_guard: bool,
    ) -> Result<(), &'static str> {
        self.prune();
        if let Some(record) = self.sessions.get_mut(id) {
            if record.expires_at <= Instant::now() {
                return Err("Invalid CSRF token");
            }
            if !constant_time_token_eq(&record.csrf_token, csrf_token) {
                return Err("Invalid CSRF token");
            }
            if enforce_replay_guard {
                if record.replay_fingerprints.contains(&replay_fingerprint) {
                    return Err("Replay request detected");
                }
                record.replay_fingerprints.push(replay_fingerprint);
                if record.replay_fingerprints.len() > MAX_REPLAY_FINGERPRINTS {
                    let excess = record.replay_fingerprints.len() - MAX_REPLAY_FINGERPRINTS;
                    record.replay_fingerprints.drain(0..excess);
                }
            }
            record.expires_at = Instant::now() + self.ttl;
            return Ok(());
        }
        Err("Invalid CSRF token")
    }

    fn remove(&mut self, id: &str) {
        self.sessions.remove(id);
    }

    fn clear_all(&mut self) {
        self.sessions.clear();
    }

    fn prune(&mut self) {
        let now = Instant::now();
        self.sessions.retain(|_, record| record.expires_at > now);
    }
}

/// HTTP admin handler interface.
pub trait AdminHttpHandler: Send + Sync {
    fn handle_status(&self) -> AdminResponse;
    fn handle_list_clients(&self) -> Vec<ClientInfo>;
    fn handle_kick(&self, id: &str) -> AdminResponse;
    fn handle_block(&self, ip: &str) -> AdminResponse;
    fn handle_unblock(&self, ip: &str) -> AdminResponse;
    fn handle_list_blocked_ips(&self) -> AdminResponse;
    fn handle_reload(&self) -> AdminResponse;
    fn handle_qkey(&self, req: IssueQKeyRequest) -> AdminResponse;
    fn handle_list_qkeys(&self) -> AdminResponse;
    fn handle_revoke_qkey(&self, id: &str) -> AdminResponse;
    fn handle_shutdown(&self) -> AdminResponse;
    fn handle_read_config(&self) -> AdminResponse;
    fn handle_write_config(&self, contents: &str) -> AdminResponse;
    fn handle_metrics_text(&self) -> String;
    fn handle_metrics_json(&self) -> AdminResponse;
    fn handle_get_logging_config(&self) -> AdminResponse;
    fn handle_set_logging_config(&self, mode: &str) -> AdminResponse;
    fn handle_get_logs(&self, cursor: u64) -> AdminResponse;
    fn handle_clear_logs(&self) -> AdminResponse;
}

/// HTTP admin server.
pub struct AdminHttpServer {
    addr: SocketAddr,
    web_root: PathBuf,
    auth: Option<Arc<RwLock<AdminAuth>>>,
    auth_path: Option<PathBuf>,
    handler: Arc<dyn AdminHttpHandler>,
    shutdown: Arc<AtomicBool>,
    sessions: Arc<Mutex<SessionStore>>,
    rate_limiter: Arc<Mutex<LoginRateLimiter>>,
}

impl AdminHttpServer {
    pub fn new(
        addr: SocketAddr,
        web_root: PathBuf,
        auth: Option<AdminAuth>,
        auth_path: Option<PathBuf>,
        handler: Arc<dyn AdminHttpHandler>,
    ) -> Self {
        let auth_loaded = auth_path.as_ref().and_then(|p| load_auth_file(p.as_path()));
        let auth = auth_loaded.or(auth);
        let auth = auth.map(|a| Arc::new(RwLock::new(a)));
        if let (Some(path), Some(auth_ref)) = (auth_path.as_ref(), auth.as_ref()) {
            if std::fs::metadata(path).is_err() {
                if let Ok(guard) = auth_ref.read() {
                    persist_auth_file(path, &guard);
                }
            }
        }
        Self {
            addr,
            web_root,
            auth,
            auth_path,
            handler,
            shutdown: Arc::new(AtomicBool::new(false)),
            sessions: Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(
                SESSION_TTL_SECS,
            )))),
            rate_limiter: Arc::new(Mutex::new(LoginRateLimiter::new(5, 60))),
        }
    }

    pub fn shutdown_signal(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }

    pub fn run(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.addr)?;
        log::info!("admin web server listening on http://{}", self.addr);

        for stream in listener.incoming() {
            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }
            let stream = match stream {
                Ok(s) => s,
                Err(e) => {
                    log::warn!("admin web accept error: {}", e);
                    continue;
                }
            };
            let handler = self.handler.clone();
            let web_root = self.web_root.clone();
            let auth = self.auth.clone();
            let auth_path = self.auth_path.clone();
            let shutdown = self.shutdown.clone();
            let sessions = self.sessions.clone();
            let rate_limiter = self.rate_limiter.clone();
            std::thread::spawn(move || {
                if shutdown.load(Ordering::Relaxed) {
                    return;
                }
                if let Err(e) = handle_connection(
                    stream,
                    &web_root,
                    auth,
                    auth_path,
                    sessions,
                    rate_limiter,
                    handler,
                ) {
                    log::warn!("admin web request error: {}", e);
                }
            });
        }
        Ok(())
    }
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[derive(Deserialize)]
struct IdPayload {
    id: String,
}

#[derive(Deserialize)]
struct IpPayload {
    ip: String,
}

#[derive(Deserialize)]
struct ConfigPayload {
    config: String,
}

#[derive(Deserialize)]
struct QKeyRevokePayload {
    id: String,
}

#[derive(Deserialize)]
struct LoggingModePayload {
    mode: String,
}

#[derive(Deserialize)]
struct QKeyCreatePayload {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    ttl_seconds: Option<u64>,
    #[serde(default)]
    stealth: Option<String>,
    #[serde(default)]
    fec: Option<String>,
    #[serde(default)]
    sni_strategy: Option<String>,
    #[serde(default)]
    sni_domain: Option<String>,
}

#[derive(Clone, Debug)]
pub struct IssueQKeyRequest {
    pub name: Option<String>,
    pub port: Option<u16>,
    pub ttl_seconds: Option<u64>,
    pub stealth: Option<String>,
    pub fec: Option<String>,
    pub sni_strategy: Option<String>,
    pub sni_domain: Option<String>,
}

fn normalize_ttl(ttl_seconds: Option<u64>) -> Option<u64> {
    match ttl_seconds {
        Some(0) | None => None,
        Some(v) => Some(v),
    }
}

fn normalize_qkey_id(raw: &str) -> Option<String> {
    let id = raw.trim();
    if id.len() != 12 {
        return None;
    }
    if !id.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(id.to_ascii_lowercase())
}

fn sanitize_asset_path(req_path: &str) -> Option<PathBuf> {
    let mut path = req_path;
    if let Some(idx) = path.find('?') {
        path = &path[..idx];
    }
    if let Some(idx) = path.find('#') {
        path = &path[..idx];
    }
    let rel = if path == "/" { "index.html" } else { path.trim_start_matches('/') };
    if rel.is_empty() {
        return None;
    }
    let mut out = PathBuf::new();
    for comp in Path::new(rel).components() {
        match comp {
            Component::Normal(s) => out.push(s),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(out)
}

fn handle_connection(
    mut stream: TcpStream,
    web_root: &Path,
    auth: Option<Arc<RwLock<AdminAuth>>>,
    auth_path: Option<PathBuf>,
    sessions: Arc<Mutex<SessionStore>>,
    rate_limiter: Arc<Mutex<LoginRateLimiter>>,
    handler: Arc<dyn AdminHttpHandler>,
) -> std::io::Result<()> {
    let req = match read_request(&mut stream) {
        Ok(req) => req,
        Err(e) => {
            let msg = e.to_string();
            let (status, body) = if msg.contains("Payload too large") {
                (413, "Payload Too Large")
            } else if msg.contains("Headers too large") {
                (431, "Request Header Fields Too Large")
            } else {
                (400, "Bad Request")
            };
            let _ = respond_text(&mut stream, status, body);
            return Ok(());
        }
    };
    let peer = stream.peer_addr().ok();

    if req.path.starts_with("/api/") {
        if req.path == "/api/login" {
            return handle_login(&mut stream, req, auth.as_ref(), sessions, rate_limiter, peer);
        }
        if req.path == "/api/logout" {
            return handle_logout(&mut stream, &req, auth.as_ref(), &sessions, peer);
        }
        if !authorize(&req, auth.as_ref(), &sessions) {
            return respond_json(&mut stream, 401, &AdminResponse::error("Unauthorized"));
        }

        if req.path == "/api/csrf" {
            if req.method != "GET" {
                return respond_text(&mut stream, 405, "Method Not Allowed");
            }
            let Some(csrf_token) = csrf_token_for_request(&req, &sessions) else {
                return respond_json(&mut stream, 401, &AdminResponse::error("Unauthorized"));
            };
            return respond_json_with_headers(
                &mut stream,
                200,
                &AdminResponse::ok(),
                vec![(CSRF_TOKEN_HEADER.to_string(), csrf_token)],
            );
        }

        if auth.is_some() && req.method == "POST" {
            if let Some(csrf_error) = validate_csrf_request(&req, &sessions) {
                return respond_json(&mut stream, 403, &AdminResponse::error(csrf_error));
            }
        }
        if let Some(auth_ref) = auth.as_ref() {
            let requires_pw_change =
                auth_ref.read().map(|guard| guard.requires_password_change()).unwrap_or(false);
            if requires_pw_change && req.path != "/api/admin/auth" && req.path != "/api/logout" {
                return respond_json(
                    &mut stream,
                    423,
                    &AdminResponse::error("Password change required"),
                );
            }
        }
        if req.path == "/api/admin/auth" {
            return handle_admin_auth(
                &mut stream,
                req,
                auth,
                auth_path.as_deref(),
                &sessions,
                rate_limiter,
                peer,
            );
        }
        return handle_api(&mut stream, req, handler, peer);
    }

    if req.method != "GET" {
        return respond_text(&mut stream, 405, "Method Not Allowed");
    }

    let Some(rel_path) = sanitize_asset_path(&req.path) else {
        return respond_text(&mut stream, 403, "Forbidden");
    };
    let full_path = web_root.join(rel_path);
    if full_path.is_file() {
        let rel = full_path.strip_prefix(web_root).unwrap_or(&full_path);
        let is_index = rel == Path::new("index.html");
        let is_asset =
            rel.components().next().and_then(|c| c.as_os_str().to_str()) == Some("assets");
        let cache = if is_index {
            "no-store"
        } else if is_asset {
            "public, max-age=31536000, immutable"
        } else {
            "no-store"
        };
        let extra = vec![("Cache-Control".to_string(), cache.to_string())];
        return respond_file_with_headers(&mut stream, &full_path, &extra);
    }
    // SPA fallback: serve index.html for non-file routes (browser refresh on /logs etc.)
    let index = web_root.join("index.html");
    if index.is_file() {
        let extra = vec![("Cache-Control".to_string(), "no-store".to_string())];
        return respond_file_with_headers(&mut stream, &index, &extra);
    }
    respond_text(&mut stream, 404, "Not Found")
}

fn authorize(
    req: &HttpRequest,
    auth: Option<&Arc<RwLock<AdminAuth>>>,
    sessions: &Arc<Mutex<SessionStore>>,
) -> bool {
    let Some(_expected) = auth else {
        return true;
    };
    let Some(session_id) = get_cookie(req, SESSION_COOKIE) else {
        return false;
    };
    let mut store = sessions.lock().unwrap_or_else(|e| e.into_inner());
    store.is_valid(&session_id)
}

fn csrf_token_for_request(
    req: &HttpRequest,
    sessions: &Arc<Mutex<SessionStore>>,
) -> Option<String> {
    let session_id = get_cookie(req, SESSION_COOKIE)?;
    let mut store = sessions.lock().unwrap_or_else(|e| e.into_inner());
    store.csrf_token(&session_id)
}

#[derive(Deserialize)]
struct LoginPayload {
    username: String,
    password: String,
}

fn format_peer(peer: Option<SocketAddr>) -> String {
    peer.map(|addr| addr.ip().to_string()).unwrap_or_else(|| "-".to_string())
}

fn trust_proxy_enabled() -> bool {
    std::env::var("QUICFUSCATE_TRUST_PROXY")
        .map(|v| v.trim() == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn header_value<'a>(req: &'a HttpRequest, name: &str) -> Option<&'a str> {
    req.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

fn first_forwarded_ip(raw: &str) -> Option<String> {
    // "client, proxy1, proxy2"
    let first = raw.split(',').next()?.trim();
    let first = first.trim_matches('"');
    let ip: std::net::IpAddr = first.parse().ok()?;
    Some(ip.to_string())
}

fn client_ip_for_rate_limit(peer: Option<SocketAddr>, req: &HttpRequest) -> String {
    if trust_proxy_enabled() {
        if let Some(v) = header_value(req, "x-forwarded-for").and_then(first_forwarded_ip) {
            return v;
        }
        if let Some(v) = header_value(req, "x-real-ip").and_then(first_forwarded_ip) {
            return v;
        }
    }
    format_peer(peer)
}

fn limiter_key(prefix: &str, ip: &str) -> String {
    format!("{}:{}", prefix, ip)
}

fn normalize_ip_for_policy(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Canonicalize so block/unblock semantics match runtime `from.ip().to_string()`.
    trimmed.parse::<std::net::IpAddr>().ok().map(|ip| ip.to_string())
}

fn normalize_socket_addr(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed.parse::<std::net::SocketAddr>().ok().map(|addr| addr.to_string())
}

fn log_action(peer: Option<SocketAddr>, action: &str, detail: &str, success: bool) {
    let peer = format_peer(peer);
    if success {
        log::info!("admin action={} detail={} peer={} status=ok", action, detail, peer);
    } else {
        log::warn!("admin action={} detail={} peer={} status=err", action, detail, peer);
    }
}

fn handle_login(
    stream: &mut TcpStream,
    req: HttpRequest,
    auth: Option<&Arc<RwLock<AdminAuth>>>,
    sessions: Arc<Mutex<SessionStore>>,
    rate_limiter: Arc<Mutex<LoginRateLimiter>>,
    peer: Option<SocketAddr>,
) -> std::io::Result<()> {
    let Some(auth) = auth else {
        return respond_json(stream, 500, &AdminResponse::error("Authentication not configured"));
    };
    if req.method != "POST" {
        return respond_text(stream, 405, "Method Not Allowed");
    }
    let peer_ip = client_ip_for_rate_limit(peer, &req);
    let key = limiter_key("login", &peer_ip);
    // Rate limit check
    {
        let mut limiter = rate_limiter.lock().unwrap_or_else(|e| e.into_inner());
        if limiter.is_locked(&key) {
            log_action(peer, "login", &format!("ip={} RATE_LIMITED", peer_ip), false);
            let retry_after = limiter.retry_after_secs(&key).unwrap_or(60);
            return respond_json_with_headers(
                stream,
                429,
                &AdminResponse::error("Too many login attempts. Try again later."),
                vec![("Retry-After".to_string(), retry_after.to_string())],
            );
        }
    }
    let payload: LoginPayload = match serde_json::from_slice(&req.body) {
        Ok(p) => p,
        Err(_) => return respond_json(stream, 400, &AdminResponse::error("Invalid JSON")),
    };
    let username = payload.username.trim();
    if username.chars().count() > MAX_USERNAME_CHARS {
        return respond_json(stream, 400, &AdminResponse::error("Username too long"));
    }
    if payload.password.len() > MAX_PASSWORD_BYTES {
        return respond_json(stream, 400, &AdminResponse::error("Password too long"));
    }
    let ok =
        auth.read().map(|guard| guard.verify(username, payload.password.as_str())).unwrap_or(false);
    if !ok {
        let mut limiter = rate_limiter.lock().unwrap_or_else(|e| e.into_inner());
        limiter.record_failure(&key);
        log_action(peer, "login", &format!("user={}", username), false);
        return respond_json(stream, 401, &AdminResponse::error("Invalid credentials"));
    }
    // Success: clear rate limit for this IP
    {
        let mut limiter = rate_limiter.lock().unwrap_or_else(|e| e.into_inner());
        limiter.clear(&key);
    }
    let mut store = sessions.lock().unwrap_or_else(|e| e.into_inner());
    let (session_id, csrf_token) = store.create();
    let cookie = build_session_cookie(&session_id, &req);
    log_action(peer, "login", &format!("user={}", username), true);
    let requires_password_change =
        auth.read().map(|guard| guard.requires_password_change()).unwrap_or(false);
    respond_json_with_headers(
        stream,
        200,
        &AdminResponse::ok_with_data(serde_json::json!({
            "user": payload.username,
            "requires_password_change": requires_password_change,
        })),
        vec![("Set-Cookie".to_string(), cookie), (CSRF_TOKEN_HEADER.to_string(), csrf_token)],
    )
}

fn handle_logout(
    stream: &mut TcpStream,
    req: &HttpRequest,
    auth: Option<&Arc<RwLock<AdminAuth>>>,
    sessions: &Arc<Mutex<SessionStore>>,
    peer: Option<SocketAddr>,
) -> std::io::Result<()> {
    if auth.is_none() {
        return respond_admin_json(stream, &AdminResponse::ok_with_message("Logged out"));
    }
    if let Some(session_id) = get_cookie(req, SESSION_COOKIE) {
        let mut store = sessions.lock().unwrap_or_else(|e| e.into_inner());
        store.remove(&session_id);
    }
    let cookie = build_expired_cookie(req);
    log_action(peer, "logout", "-", true);
    respond_json_with_headers(
        stream,
        200,
        &AdminResponse::ok_with_message("Logged out"),
        vec![("Set-Cookie".to_string(), cookie)],
    )
}

#[derive(Deserialize)]
struct AdminAuthUpdatePayload {
    #[serde(default)]
    new_username: Option<String>,
    current_password: String,
    #[serde(default)]
    new_password: Option<String>,
}

fn handle_admin_auth(
    stream: &mut TcpStream,
    req: HttpRequest,
    auth: Option<Arc<RwLock<AdminAuth>>>,
    auth_path: Option<&Path>,
    sessions: &Arc<Mutex<SessionStore>>,
    rate_limiter: Arc<Mutex<LoginRateLimiter>>,
    peer: Option<SocketAddr>,
) -> std::io::Result<()> {
    let Some(auth) = auth else {
        return respond_json(stream, 500, &AdminResponse::error("Authentication not configured"));
    };

    if req.method == "GET" {
        let payload = auth
            .read()
            .map(|guard| {
                serde_json::json!({
                    "user": guard.user(),
                    "requires_password_change": guard.requires_password_change(),
                })
            })
            .unwrap_or_else(
                |_| serde_json::json!({ "user": "admin", "requires_password_change": false }),
            );
        return respond_admin_json(stream, &AdminResponse::ok_with_data(payload));
    }

    if req.method != "POST" {
        return respond_text(stream, 405, "Method Not Allowed");
    }

    let payload: AdminAuthUpdatePayload = match serde_json::from_slice(&req.body) {
        Ok(p) => p,
        Err(_) => return respond_json(stream, 400, &AdminResponse::error("Invalid JSON")),
    };
    if payload.current_password.len() > MAX_PASSWORD_BYTES {
        return respond_json(
            stream,
            400,
            &AdminResponse::error("Password too long (max 256 chars)"),
        );
    }

    if payload.new_username.is_none() && payload.new_password.is_none() {
        return respond_json(stream, 400, &AdminResponse::error("No update requested"));
    }

    // Rate limit admin-auth attempts (password changes) to slow brute forcing.
    // This uses the same limiter state as login, but with a separate key namespace.
    let peer_ip = client_ip_for_rate_limit(peer, &req);
    let key = limiter_key("admin-auth", &peer_ip);
    {
        let mut limiter = rate_limiter.lock().unwrap_or_else(|e| e.into_inner());
        if limiter.is_locked(&key) {
            log_action(peer, "admin-auth", &format!("ip={} RATE_LIMITED", peer_ip), false);
            let retry_after = limiter.retry_after_secs(&key).unwrap_or(60);
            return respond_json_with_headers(
                stream,
                429,
                &AdminResponse::error("Too many attempts. Try again later."),
                vec![("Retry-After".to_string(), retry_after.to_string())],
            );
        }
    }

    let new_password = payload.new_password;
    if let Some(ref pw) = new_password {
        if pw.len() < 6 {
            return respond_json(
                stream,
                400,
                &AdminResponse::error("Password too short (min 6 chars)"),
            );
        }
    }

    let (old_user, verified) = auth
        .read()
        .map(|guard| {
            (
                guard.user().to_string(),
                guard.verify_password_only(payload.current_password.as_str()),
            )
        })
        .unwrap_or_else(|_| ("-".to_string(), false));
    if !verified {
        let mut limiter = rate_limiter.lock().unwrap_or_else(|e| e.into_inner());
        limiter.record_failure(&key);
        log_action(peer, "admin-auth", &format!("user={}", old_user), false);
        return respond_json(stream, 401, &AdminResponse::error("Invalid credentials"));
    }

    // Success: clear rate limiter for this key.
    {
        let mut limiter = rate_limiter.lock().unwrap_or_else(|e| e.into_inner());
        limiter.clear(&key);
    }

    let new_user = payload.new_username.as_deref().unwrap_or(old_user.as_str()).trim().to_string();
    if new_user.is_empty() {
        return respond_json(stream, 400, &AdminResponse::error("Username cannot be empty"));
    }
    if new_user.chars().count() > MAX_USERNAME_CHARS {
        return respond_json(
            stream,
            400,
            &AdminResponse::error("Username too long (max 64 chars)"),
        );
    }
    if new_user.chars().any(|c| c.is_control()) {
        return respond_json(
            stream,
            400,
            &AdminResponse::error("Username contains invalid characters"),
        );
    }

    {
        let mut guard = auth.write().unwrap_or_else(|e| e.into_inner());
        if let Some(pw) = new_password {
            if pw.len() > MAX_PASSWORD_BYTES {
                return respond_json(
                    stream,
                    400,
                    &AdminResponse::error("Password too long (max 256 chars)"),
                );
            }
            guard.set_credentials(new_user, pw);
        } else {
            // Username-only update: keep password hash and requires_password_change.
            guard.set_username(new_user);
        }
        if let Some(path) = auth_path {
            persist_auth_file(path, &guard);
        }
    }

    {
        let mut store = sessions.lock().unwrap_or_else(|e| e.into_inner());
        store.clear_all();
    }

    let cookie = build_expired_cookie(&req);
    log_action(peer, "admin-auth", &format!("user={}", old_user), true);
    respond_json_with_headers(
        stream,
        200,
        &AdminResponse::ok_with_message("Admin credentials updated"),
        vec![("Set-Cookie".to_string(), cookie)],
    )
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Mutex, OnceLock};
    use std::thread;

    #[derive(Clone)]
    struct TestHandler;

    impl AdminHttpHandler for TestHandler {
        fn handle_status(&self) -> AdminResponse {
            AdminResponse::ok()
        }
        fn handle_list_clients(&self) -> Vec<ClientInfo> {
            vec![]
        }
        fn handle_kick(&self, _id: &str) -> AdminResponse {
            AdminResponse::ok()
        }
        fn handle_block(&self, _ip: &str) -> AdminResponse {
            AdminResponse::ok()
        }
        fn handle_unblock(&self, _ip: &str) -> AdminResponse {
            AdminResponse::ok()
        }
        fn handle_list_blocked_ips(&self) -> AdminResponse {
            AdminResponse::ok()
        }
        fn handle_reload(&self) -> AdminResponse {
            AdminResponse::ok()
        }
        fn handle_qkey(&self, _req: IssueQKeyRequest) -> AdminResponse {
            AdminResponse::ok()
        }
        fn handle_list_qkeys(&self) -> AdminResponse {
            AdminResponse::ok()
        }
        fn handle_revoke_qkey(&self, _id: &str) -> AdminResponse {
            AdminResponse::ok()
        }
        fn handle_shutdown(&self) -> AdminResponse {
            AdminResponse::ok()
        }
        fn handle_read_config(&self) -> AdminResponse {
            AdminResponse::ok_with_data(serde_json::json!({ "config": "[x]\n" }))
        }
        fn handle_write_config(&self, _contents: &str) -> AdminResponse {
            AdminResponse::ok()
        }
        fn handle_metrics_text(&self) -> String {
            String::new()
        }
        fn handle_metrics_json(&self) -> AdminResponse {
            AdminResponse::ok_with_data(serde_json::json!({ "metrics": {} }))
        }
        fn handle_get_logging_config(&self) -> AdminResponse {
            AdminResponse::ok_with_data(serde_json::json!({ "mode": "normal" }))
        }
        fn handle_set_logging_config(&self, _mode: &str) -> AdminResponse {
            AdminResponse::ok()
        }
        fn handle_get_logs(&self, _cursor: u64) -> AdminResponse {
            AdminResponse::ok_with_data(serde_json::json!({ "lines": [], "cursor": 0 }))
        }
        fn handle_clear_logs(&self) -> AdminResponse {
            AdminResponse::ok_with_message("Logs cleared")
        }
    }

    fn read_all(mut s: TcpStream) -> String {
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).to_string()
    }

    fn parse_status(resp: &str) -> u16 {
        resp.lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|c| c.parse::<u16>().ok())
            .unwrap_or(0)
    }

    fn parse_set_cookie(resp: &str) -> Option<String> {
        for line in resp.lines() {
            if line.to_lowercase().starts_with("set-cookie:") {
                return Some(line.split_once(':')?.1.trim().to_string());
            }
        }
        None
    }

    fn parse_csrf_token(resp: &str) -> Option<String> {
        parse_header(resp, CSRF_TOKEN_HEADER)
    }

    fn parse_header(resp: &str, name: &str) -> Option<String> {
        let needle = format!("{}:", name.to_ascii_lowercase());
        for line in resp.lines() {
            let lower = line.to_ascii_lowercase();
            if lower.starts_with(&needle) {
                return Some(line.split_once(':')?.1.trim().to_string());
            }
        }
        None
    }

    fn cookie_header_from_set_cookie(set_cookie: &str) -> Option<String> {
        // Keep only "name=value"
        let pair = set_cookie.split(';').next()?.trim();
        if pair.is_empty() {
            return None;
        }
        Some(format!("Cookie: {}", pair))
    }

    fn send_req(addr: std::net::SocketAddr, raw: &str) -> String {
        let mut s = TcpStream::connect(addr).expect("connect");
        s.write_all(raw.as_bytes()).expect("write");
        s.shutdown(std::net::Shutdown::Write).ok();
        read_all(s)
    }

    fn spawn_server(
        listener: TcpListener,
        n: usize,
        web_root: std::path::PathBuf,
        auth: Option<Arc<RwLock<AdminAuth>>>,
        sessions: Arc<Mutex<SessionStore>>,
        rate_limiter: Arc<Mutex<LoginRateLimiter>>,
        handler: Arc<dyn AdminHttpHandler>,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            for _ in 0..n {
                let (stream, _) = listener.accept().expect("accept");
                let _ = handle_connection(
                    stream,
                    &web_root,
                    auth.clone(),
                    None,
                    sessions.clone(),
                    rate_limiter.clone(),
                    handler.clone(),
                );
            }
        })
    }

    fn with_trust_proxy_env<T>(enabled: bool, f: impl FnOnce() -> T) -> T {
        // Environment variables are process-global. Guard tests that mutate
        // QUICFUSCATE_TRUST_PROXY so parallel test execution cannot race.
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard =
            ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner());

        let prev = std::env::var("QUICFUSCATE_TRUST_PROXY").ok();
        if enabled {
            std::env::set_var("QUICFUSCATE_TRUST_PROXY", "1");
        } else {
            std::env::remove_var("QUICFUSCATE_TRUST_PROXY");
        }
        let out = f();
        match prev {
            Some(v) => std::env::set_var("QUICFUSCATE_TRUST_PROXY", v),
            None => std::env::remove_var("QUICFUSCATE_TRUST_PROXY"),
        }
        out
    }

    #[test]
    fn client_ip_for_rate_limit_uses_peer_when_proxy_not_trusted() {
        with_trust_proxy_env(false, || {
            let req = HttpRequest {
                method: "GET".to_string(),
                path: "/api/status".to_string(),
                headers: vec![("x-forwarded-for".to_string(), "1.2.3.4".to_string())],
                body: Vec::new(),
            };
            let peer: SocketAddr = "127.0.0.1:5555".parse().expect("peer");
            assert_eq!(client_ip_for_rate_limit(Some(peer), &req), "127.0.0.1");
        });
    }

    #[test]
    fn client_ip_for_rate_limit_uses_x_forwarded_for_when_trusted() {
        with_trust_proxy_env(true, || {
            let req = HttpRequest {
                method: "GET".to_string(),
                path: "/api/status".to_string(),
                headers: vec![("x-forwarded-for".to_string(), "1.2.3.4, 5.6.7.8".to_string())],
                body: Vec::new(),
            };
            let peer: SocketAddr = "127.0.0.1:5555".parse().expect("peer");
            assert_eq!(client_ip_for_rate_limit(Some(peer), &req), "1.2.3.4");
        });
    }

    #[test]
    fn client_ip_for_rate_limit_ignores_invalid_forwarded_ip_and_falls_back_to_peer() {
        with_trust_proxy_env(true, || {
            let req = HttpRequest {
                method: "GET".to_string(),
                path: "/api/status".to_string(),
                headers: vec![("x-forwarded-for".to_string(), "not-an-ip".to_string())],
                body: Vec::new(),
            };
            let peer: SocketAddr = "127.0.0.1:5555".parse().expect("peer");
            assert_eq!(client_ip_for_rate_limit(Some(peer), &req), "127.0.0.1");
        });
    }

    #[test]
    fn session_cookie_is_secure_only_for_https_forwarded_proto() {
        with_trust_proxy_env(true, || {
            let base = HttpRequest {
                method: "GET".to_string(),
                path: "/".to_string(),
                headers: vec![],
                body: Vec::new(),
            };
            let https = HttpRequest {
                headers: vec![("x-forwarded-proto".to_string(), "https".to_string())],
                ..base
            };
            let http = HttpRequest {
                method: "GET".to_string(),
                path: "/".to_string(),
                headers: vec![("x-forwarded-proto".to_string(), "http".to_string())],
                body: Vec::new(),
            };

            let c1 = build_session_cookie("sid", &https);
            assert!(c1.contains("HttpOnly"));
            assert!(c1.contains("SameSite=Strict"));
            assert!(c1.contains("; Secure"));

            let c2 = build_session_cookie("sid", &http);
            assert!(!c2.contains("; Secure"));
        });
    }

    #[test]
    fn expired_cookie_is_secure_only_for_https_forwarded_proto() {
        with_trust_proxy_env(true, || {
            let base = HttpRequest {
                method: "GET".to_string(),
                path: "/".to_string(),
                headers: vec![],
                body: Vec::new(),
            };
            let https = HttpRequest {
                headers: vec![("x-forwarded-proto".to_string(), "https".to_string())],
                ..base
            };
            let http = HttpRequest {
                method: "GET".to_string(),
                path: "/".to_string(),
                headers: vec![("x-forwarded-proto".to_string(), "http".to_string())],
                body: Vec::new(),
            };

            let c1 = build_expired_cookie(&https);
            assert!(c1.contains("HttpOnly"));
            assert!(c1.contains("SameSite=Strict"));
            assert!(c1.contains("; Secure"));
            assert!(c1.contains("Max-Age=0"));
            assert!(c1.contains("Expires="));

            let c2 = build_expired_cookie(&http);
            assert!(!c2.contains("; Secure"));
        });
    }

    #[test]
    fn get_cookie_parses_from_cookie_header() {
        let req = HttpRequest {
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: vec![("cookie".to_string(), "a=1; qf_admin_session=xyz; b=2".to_string())],
            body: Vec::new(),
        };
        assert_eq!(get_cookie(&req, "qf_admin_session").as_deref(), Some("xyz"));
        assert_eq!(get_cookie(&req, "missing"), None);
    }

    #[test]
    fn get_cookie_parses_from_multiple_cookie_headers() {
        let req = HttpRequest {
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: vec![
                ("cookie".to_string(), "a=1".to_string()),
                ("cookie".to_string(), "qf_admin_session=xyz; b=2".to_string()),
            ],
            body: Vec::new(),
        };
        assert_eq!(get_cookie(&req, "qf_admin_session").as_deref(), Some("xyz"));
    }

    #[test]
    fn login_rate_limit_returns_429_on_6th_failed_attempt() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();

        let web_root = std::env::temp_dir();
        let auth = Some(Arc::new(RwLock::new(AdminAuth::new(
            "admin".to_string(),
            "123".to_string(),
            false,
        ))));
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(3600))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);

        let _thr = spawn_server(listener, 6, web_root, auth, sessions, rate, handler);

        let body = r#"{"username":"admin","password":"wrong"}"#;
        let req = || {
            format!(
                "POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
                body.len(),
                body
            )
        };
        for _ in 0..5 {
            let resp = send_req(addr, &req());
            assert_eq!(parse_status(&resp), 401);
        }
        let resp = send_req(addr, &req());
        assert_eq!(parse_status(&resp), 429);
        let ra = parse_header(&resp, "Retry-After").expect("Retry-After");
        assert!(ra.parse::<u64>().unwrap_or(0) > 0);
    }

    #[test]
    fn admin_auth_rate_limit_returns_429_on_6th_failed_attempt() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();

        let web_root = std::env::temp_dir();
        let auth = Some(Arc::new(RwLock::new(AdminAuth::new(
            "admin".to_string(),
            "123".to_string(),
            false,
        ))));
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(3600))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);

        // 1 login + 6 admin-auth attempts
        let _thr = spawn_server(listener, 7, web_root, auth.clone(), sessions, rate, handler);

        let login_body = r#"{"username":"admin","password":"123"}"#;
        let login_req = format!(
            "POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
            login_body.len(),
            login_body
        );
        let login_resp = send_req(addr, &login_req);
        assert_eq!(parse_status(&login_resp), 200);
        let set_cookie = parse_set_cookie(&login_resp).expect("set-cookie");
        let cookie_header = cookie_header_from_set_cookie(&set_cookie).expect("cookie header");
        let csrf_token = parse_csrf_token(&login_resp).expect("csrf token");
        let csrf_header = format!("{}: {}", CSRF_TOKEN_HEADER, csrf_token);

        let body = r#"{"current_password":"wrong","new_password":"abcdef"}"#;
        let mk = || {
            format!(
                "POST /api/admin/auth HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n{}\r\n{}\r\n\r\n{}",
                body.len(),
                cookie_header,
                csrf_header,
                body
            )
        };

        for _ in 0..5 {
            let resp = send_req(addr, &mk());
            assert_eq!(parse_status(&resp), 401);
        }
        let resp = send_req(addr, &mk());
        assert_eq!(parse_status(&resp), 429);
        let ra = parse_header(&resp, "Retry-After").expect("Retry-After");
        assert!(ra.parse::<u64>().unwrap_or(0) > 0);
    }

    #[test]
    fn html_responses_include_csp_but_json_does_not() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();

        let web_root = {
            let mut dir = std::env::temp_dir();
            dir.push(format!(
                "qf-admin-http-csp-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_else(|_| Duration::from_secs(0))
                    .as_millis()
            ));
            std::fs::create_dir_all(&dir).expect("mkdir");
            std::fs::write(dir.join("index.html"), "<html><body>ok</body></html>")
                .expect("write index");
            dir
        };
        let auth = None;
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(3600))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);

        // 1 request for "/" and 1 request for "/api/status"
        let _thr = spawn_server(listener, 2, web_root, auth, sessions, rate, handler);

        let html = send_req(addr, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert_eq!(parse_status(&html), 200);
        assert!(parse_header(&html, "Content-Security-Policy").is_some());

        let json = send_req(addr, "GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert_eq!(parse_status(&json), 200);
        assert!(parse_header(&json, "Content-Security-Policy").is_none());
    }

    #[test]
    fn metrics_json_endpoint_returns_json_payload() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();

        let web_root = std::env::temp_dir();
        let auth = None;
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(3600))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);

        let _thr = spawn_server(listener, 1, web_root, auth, sessions, rate, handler);

        let json = send_req(addr, "GET /api/metrics/json HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert_eq!(parse_status(&json), 200);
        assert!(json.contains("\"metrics\""));
    }

    #[test]
    fn qkey_ttl_too_large_returns_400() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();

        let web_root = std::env::temp_dir();
        let auth = None;
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(3600))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);

        // 1 request for "/api/qkey"
        let _thr = spawn_server(listener, 1, web_root, auth, sessions, rate, handler);

        let body = format!(r#"{{"ttl_seconds":{}}}"#, MAX_QKEY_TTL_SECS + 1);
        let req = format!(
            "POST /api/qkey HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 400);
        assert!(resp.contains("TTL too large"));
    }

    #[test]
    fn qkey_create_rejects_invalid_json() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();

        let web_root = std::env::temp_dir();
        let auth = None;
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(3600))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);

        let _thr = spawn_server(listener, 1, web_root, auth, sessions, rate, handler);

        let body = "{not_json";
        let req = format!(
            "POST /api/qkey HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 400);
        assert!(resp.contains("Invalid JSON"));
    }

    #[test]
    fn block_rejects_invalid_ip() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();

        let web_root = std::env::temp_dir();
        let auth = None;
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(3600))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);

        let _thr = spawn_server(listener, 1, web_root, auth, sessions, rate, handler);

        let body = r#"{"ip":"not-an-ip"}"#;
        let req = format!(
            "POST /api/block HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 400);
        assert!(resp.contains("Invalid IP"));
    }

    #[test]
    fn block_rejects_invalid_json() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();

        let web_root = std::env::temp_dir();
        let auth = None;
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(3600))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);

        let _thr = spawn_server(listener, 1, web_root, auth, sessions, rate, handler);

        let body = "{not_json";
        let req = format!(
            "POST /api/block HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 400);
        assert!(resp.contains("Invalid JSON"));
    }

    #[test]
    fn unblock_rejects_invalid_json() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();

        let web_root = std::env::temp_dir();
        let auth = None;
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(3600))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);

        let _thr = spawn_server(listener, 1, web_root, auth, sessions, rate, handler);

        let body = "{not_json";
        let req = format!(
            "POST /api/unblock HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 400);
        assert!(resp.contains("Invalid JSON"));
    }

    #[test]
    fn kick_rejects_invalid_client_id() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();

        let web_root = std::env::temp_dir();
        let auth = None;
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(3600))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);

        let _thr = spawn_server(listener, 1, web_root, auth, sessions, rate, handler);

        let body = r#"{"id":"not-a-socket-addr"}"#;
        let req = format!(
            "POST /api/kick HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 400);
        assert!(resp.contains("Invalid client id"));
    }

    #[test]
    fn qkey_revoke_rejects_invalid_id() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();

        let web_root = std::env::temp_dir();
        let auth = None;
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(3600))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);

        let _thr = spawn_server(listener, 1, web_root, auth, sessions, rate, handler);

        let body = r#"{"id":"not-a-qkey-id"}"#;
        let req = format!(
            "POST /api/qkeys/revoke HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 400);
        assert!(resp.contains("Invalid QKey id"));
    }

    #[test]
    fn qkey_revoke_rejects_missing_id() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();

        let web_root = std::env::temp_dir();
        let auth = None;
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(3600))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);

        let _thr = spawn_server(listener, 1, web_root, auth, sessions, rate, handler);

        let body = r#"{"id":"   "}"#;
        let req = format!(
            "POST /api/qkeys/revoke HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 400);
        assert!(resp.contains("Missing QKey id"));
    }

    #[test]
    fn config_write_rejects_invalid_json() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();

        let web_root = std::env::temp_dir();
        let auth = None;
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(3600))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);

        let _thr = spawn_server(listener, 1, web_root, auth, sessions, rate, handler);

        let body = "{not_json";
        let req = format!(
            "POST /api/config HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 400);
        assert!(resp.contains("Invalid JSON"));
    }

    #[test]
    fn config_write_rejects_empty_config() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();

        let web_root = std::env::temp_dir();
        let auth = None;
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(3600))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);

        let _thr = spawn_server(listener, 1, web_root, auth, sessions, rate, handler);

        let body = r#"{"config":"   "}"#;
        let req = format!(
            "POST /api/config HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 400);
        assert!(resp.contains("Empty config"));
    }

    #[test]
    fn logging_config_rejects_invalid_json() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();

        let web_root = std::env::temp_dir();
        let auth = None;
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(3600))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);

        let _thr = spawn_server(listener, 1, web_root, auth, sessions, rate, handler);

        let body = "{not_json";
        let req = format!(
            "POST /api/config/logging HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 400);
        assert!(resp.contains("Invalid JSON"));
    }

    #[test]
    fn qkey_revoke_accepts_uppercase_hex_id() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();

        let web_root = std::env::temp_dir();
        let auth = None;
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(3600))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);

        let _thr = spawn_server(listener, 1, web_root, auth, sessions, rate, handler);

        let body = r#"{"id":"A1B2C3D4E5F6"}"#;
        let req = format!(
            "POST /api/qkeys/revoke HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 200);
    }

    #[test]
    fn secure_cookie_is_set_only_for_forwarded_https() {
        with_trust_proxy_env(true, || {
            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
            let addr = listener.local_addr().unwrap();

            let web_root = std::env::temp_dir();
            let auth = Some(Arc::new(RwLock::new(AdminAuth::new(
                "admin".to_string(),
                "123".to_string(),
                false,
            ))));
            let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(3600))));
            let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
            let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);

            // 2 login requests
            let _thr = spawn_server(listener, 2, web_root, auth, sessions, rate, handler);

            let body = r#"{"username":"admin","password":"123"}"#;
            let mk = |proto: Option<&str>| {
                let extra =
                    proto.map(|p| format!("X-Forwarded-Proto: {}\r\n", p)).unwrap_or_default();
                format!(
                    "POST /api/login HTTP/1.1\r\nHost: localhost\r\n{}Content-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
                    extra,
                    body.len(),
                    body
                )
            };

            let http = send_req(addr, &mk(None));
            assert_eq!(parse_status(&http), 200);
            let set_cookie = parse_set_cookie(&http).expect("set-cookie");
            assert!(!set_cookie.to_ascii_lowercase().contains("secure"));

            let https = send_req(addr, &mk(Some("https")));
            assert_eq!(parse_status(&https), 200);
            let set_cookie = parse_set_cookie(&https).expect("set-cookie");
            assert!(set_cookie.to_ascii_lowercase().contains("secure"));
        });
    }

    #[test]
    fn password_change_lock_returns_423_for_api_except_admin_auth() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();

        let web_root = std::env::temp_dir();
        let auth = Some(Arc::new(RwLock::new(AdminAuth::new(
            "admin".to_string(),
            "123".to_string(),
            true,
        ))));
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(3600))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);

        // 1 login + 2 API calls
        let _thr = spawn_server(listener, 3, web_root, auth.clone(), sessions, rate, handler);

        let login_body = r#"{"username":"admin","password":"123"}"#;
        let login_req = format!(
            "POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
            login_body.len(),
            login_body
        );
        let login_resp = send_req(addr, &login_req);
        assert_eq!(parse_status(&login_resp), 200);
        let set_cookie = parse_set_cookie(&login_resp).expect("set-cookie");
        let cookie_header = cookie_header_from_set_cookie(&set_cookie).expect("cookie header");
        let _csrf_token = parse_csrf_token(&login_resp).expect("csrf token");

        let cfg_req = format!(
            "GET /api/config HTTP/1.1\r\nHost: localhost\r\n{}\
\r\n\r\n",
            cookie_header
        );
        let cfg_resp = send_req(addr, &cfg_req);
        assert_eq!(parse_status(&cfg_resp), 423);

        let auth_req = format!(
            "GET /api/admin/auth HTTP/1.1\r\nHost: localhost\r\n{}\
\r\n\r\n",
            cookie_header
        );
        let auth_resp = send_req(addr, &auth_req);
        assert_eq!(parse_status(&auth_resp), 200);
    }

    #[test]
    fn password_change_lock_allows_logout_and_clears_session() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();

        let web_root = std::env::temp_dir();
        let auth = Some(Arc::new(RwLock::new(AdminAuth::new(
            "admin".to_string(),
            "123".to_string(),
            true,
        ))));
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(3600))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);

        // login + logout + config (old cookie should be invalid)
        let _thr = spawn_server(listener, 3, web_root, auth.clone(), sessions, rate, handler);

        let login_body = r#"{"username":"admin","password":"123"}"#;
        let login_req = format!(
            "POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
            login_body.len(),
            login_body
        );
        let login_resp = send_req(addr, &login_req);
        assert_eq!(parse_status(&login_resp), 200);
        let set_cookie = parse_set_cookie(&login_resp).expect("set-cookie");
        let cookie_header = cookie_header_from_set_cookie(&set_cookie).expect("cookie header");
        let csrf_token = parse_csrf_token(&login_resp).expect("csrf token");

        let logout_req = format!(
            "POST /api/logout HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n{}\r\n{}: {}\r\n\r\n",
            cookie_header,
            CSRF_TOKEN_HEADER,
            csrf_token,
        );
        let logout_resp = send_req(addr, &logout_req);
        assert_eq!(parse_status(&logout_resp), 200);

        // Old cookie must no longer authorize.
        let cfg_req = format!(
            "GET /api/config HTTP/1.1\r\nHost: localhost\r\n{}\
\r\n\r\n",
            cookie_header
        );
        let cfg_resp = send_req(addr, &cfg_req);
        assert_eq!(parse_status(&cfg_resp), 401);
    }

    #[test]
    fn admin_auth_allows_username_only_update_without_new_password_and_preserves_lock_flag() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();

        let web_root = std::env::temp_dir();
        let auth =
            Arc::new(RwLock::new(AdminAuth::new("admin".to_string(), "123".to_string(), true)));
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(3600))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);

        // login + username update + auth status (GET)
        let _thr = spawn_server(listener, 3, web_root, Some(auth.clone()), sessions, rate, handler);

        let login_body = r#"{"username":"admin","password":"123"}"#;
        let login_req = format!(
            "POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
            login_body.len(),
            login_body
        );
        let login_resp = send_req(addr, &login_req);
        assert_eq!(parse_status(&login_resp), 200);
        let set_cookie = parse_set_cookie(&login_resp).expect("set-cookie");
        let cookie_header = cookie_header_from_set_cookie(&set_cookie).expect("cookie header");
        let csrf_token = parse_csrf_token(&login_resp).expect("csrf token");
        let csrf_header = format!("{}: {}", CSRF_TOKEN_HEADER, csrf_token);

        let body = r#"{"current_password":"123","new_username":"root"}"#;
        let update_req = format!(
            "POST /api/admin/auth HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n{}\
\r\n{}\
\r\n\r\n{}",
            body.len(),
            cookie_header,
            csrf_header,
            body
        );
        let update_resp = send_req(addr, &update_req);
        assert_eq!(parse_status(&update_resp), 200);

        // Sessions are cleared and lock flag must remain true because no password was changed.
        let auth_req = format!(
            "GET /api/admin/auth HTTP/1.1\r\nHost: localhost\r\n{}\
\r\n\r\n",
            cookie_header
        );
        let auth_resp = send_req(addr, &auth_req);
        assert_eq!(parse_status(&auth_resp), 401);

        let guard = auth.read().unwrap_or_else(|e| e.into_inner());
        assert_eq!(guard.user(), "root");
        assert!(guard.requires_password_change());
    }

    #[test]
    fn admin_auth_rejects_username_too_long() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();

        let web_root = std::env::temp_dir();
        let auth = Some(Arc::new(RwLock::new(AdminAuth::new(
            "admin".to_string(),
            "123".to_string(),
            false,
        ))));
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(3600))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);

        let _thr = spawn_server(listener, 2, web_root, auth, sessions, rate, handler);

        let login_body = r#"{"username":"admin","password":"123"}"#;
        let login_req = format!(
            "POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
            login_body.len(),
            login_body
        );
        let login_resp = send_req(addr, &login_req);
        assert_eq!(parse_status(&login_resp), 200);
        let set_cookie = parse_set_cookie(&login_resp).expect("set-cookie");
        let cookie_header = cookie_header_from_set_cookie(&set_cookie).expect("cookie header");
        let csrf_token = parse_csrf_token(&login_resp).expect("csrf token");
        let csrf_header = format!("{}: {}", CSRF_TOKEN_HEADER, csrf_token);

        let too_long_user = "u".repeat(65);
        let body =
            format!("{{\"current_password\":\"123\",\"new_username\":\"{}\"}}", too_long_user);
        let update_req = format!(
            "POST /api/admin/auth HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n{}\
\r\n{}\
\r\n\r\n{}",
            body.len(),
            cookie_header,
            csrf_header,
            body
        );
        let update_resp = send_req(addr, &update_req);
        assert_eq!(parse_status(&update_resp), 400);
        assert!(
            update_resp.contains("Username too long")
                || update_resp.contains("Invalid JSON")
                || update_resp.contains("Invalid CSRF")
                || update_resp.contains("Missing CSRF token"),
            "unexpected admin/auth response: {update_resp}"
        );
    }

    #[test]
    fn admin_auth_post_rejects_missing_csrf_token() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();

        let web_root = std::env::temp_dir();
        let auth = Some(Arc::new(RwLock::new(AdminAuth::new(
            "admin".to_string(),
            "123".to_string(),
            false,
        ))));
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(3600))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);

        let _thr = spawn_server(listener, 2, web_root, auth.clone(), sessions, rate, handler);

        let login_body = r#"{"username":"admin","password":"123"}"#;
        let login_req = format!(
            "POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
            login_body.len(),
            login_body
        );
        let login_resp = send_req(addr, &login_req);
        assert_eq!(parse_status(&login_resp), 200);
        let set_cookie = parse_set_cookie(&login_resp).expect("set-cookie");
        let cookie_header = cookie_header_from_set_cookie(&set_cookie).expect("cookie header");

        let body = r#"{"current_password":"123","new_password":"abcdef"}"#;
        let req = format!(
            "POST /api/admin/auth HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n{}\r\n\r\n{}\r\n",
            body.len(),
            cookie_header,
            body
        );
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 403);
        assert!(resp.contains("Missing CSRF token"));
    }

    #[test]
    fn admin_auth_post_rejects_invalid_csrf_token() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();

        let web_root = std::env::temp_dir();
        let auth = Some(Arc::new(RwLock::new(AdminAuth::new(
            "admin".to_string(),
            "123".to_string(),
            false,
        ))));
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(3600))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);

        let _thr = spawn_server(listener, 2, web_root, auth.clone(), sessions, rate, handler);

        let login_body = r#"{"username":"admin","password":"123"}"#;
        let login_req = format!(
            "POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
            login_body.len(),
            login_body
        );
        let login_resp = send_req(addr, &login_req);
        assert_eq!(parse_status(&login_resp), 200);
        let set_cookie = parse_set_cookie(&login_resp).expect("set-cookie");
        let cookie_header = cookie_header_from_set_cookie(&set_cookie).expect("cookie header");

        let body = r#"{"current_password":"123","new_password":"abcdef"}"#;
        let csrf_header = format!("{}: {}", CSRF_TOKEN_HEADER, "g".repeat(CSRF_TOKEN_BYTES * 2));
        let req = format!(
            "POST /api/admin/auth HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n{}\r\n{}\r\n\r\n{}\r\n",
            body.len(),
            cookie_header,
            csrf_header,
            body
        );
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 403);
        assert!(resp.contains("Invalid CSRF token"));
    }

    #[test]
    fn admin_auth_post_rejects_cross_origin_request() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();

        let web_root = std::env::temp_dir();
        let auth = Some(Arc::new(RwLock::new(AdminAuth::new(
            "admin".to_string(),
            "123".to_string(),
            false,
        ))));
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(3600))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);

        let _thr = spawn_server(listener, 2, web_root, auth.clone(), sessions, rate, handler);

        let login_body = r#"{"username":"admin","password":"123"}"#;
        let login_req = format!(
            "POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
            login_body.len(),
            login_body
        );
        let login_resp = send_req(addr, &login_req);
        assert_eq!(parse_status(&login_resp), 200);
        let set_cookie = parse_set_cookie(&login_resp).expect("set-cookie");
        let cookie_header = cookie_header_from_set_cookie(&set_cookie).expect("cookie header");
        let csrf_token = parse_csrf_token(&login_resp).expect("csrf token");
        let csrf_header = format!("{}: {}", CSRF_TOKEN_HEADER, csrf_token);

        let body = r#"{"current_password":"123","new_password":"abcdef"}"#;
        let req = format!(
            "POST /api/admin/auth HTTP/1.1\r\nHost: localhost\r\nOrigin: https://evil.example\r\nContent-Length: {}\r\nContent-Type: application/json\r\n{}\r\n{}\r\n\r\n{}\r\n",
            body.len(),
            cookie_header,
            csrf_header,
            body
        );
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 403);
        assert!(resp.contains("Invalid Origin"));
    }

    #[test]
    fn post_replay_is_rejected_for_same_origin_browser_request() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();

        let web_root = std::env::temp_dir();
        let auth = Some(Arc::new(RwLock::new(AdminAuth::new(
            "admin".to_string(),
            "123".to_string(),
            false,
        ))));
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(3600))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);

        let _thr = spawn_server(listener, 3, web_root, auth.clone(), sessions, rate, handler);

        let login_body = r#"{"username":"admin","password":"123"}"#;
        let login_req = format!(
            "POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
            login_body.len(),
            login_body
        );
        let login_resp = send_req(addr, &login_req);
        assert_eq!(parse_status(&login_resp), 200);
        let set_cookie = parse_set_cookie(&login_resp).expect("set-cookie");
        let cookie_header = cookie_header_from_set_cookie(&set_cookie).expect("cookie header");
        let csrf_token = parse_csrf_token(&login_resp).expect("csrf token");
        let csrf_header = format!("{}: {}", CSRF_TOKEN_HEADER, csrf_token);

        let body = r#"{"config":"test = true"}"#;
        let req = format!(
            "POST /api/config HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n{}\r\n{}\r\n\r\n{}\r\n",
            body.len(),
            cookie_header,
            csrf_header,
            body
        );
        let first = send_req(addr, &req);
        assert_eq!(parse_status(&first), 200);

        let second = send_req(addr, &req);
        assert_eq!(parse_status(&second), 403);
        assert!(second.contains("Replay request detected"));
    }

    #[test]
    fn admin_auth_rejects_username_with_control_characters() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();

        let web_root = std::env::temp_dir();
        let auth = Some(Arc::new(RwLock::new(AdminAuth::new(
            "admin".to_string(),
            "123".to_string(),
            false,
        ))));
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(3600))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);

        let _thr = spawn_server(listener, 2, web_root, auth, sessions, rate, handler);

        let login_body = r#"{"username":"admin","password":"123"}"#;
        let login_req = format!(
            "POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
            login_body.len(),
            login_body
        );
        let login_resp = send_req(addr, &login_req);
        assert_eq!(parse_status(&login_resp), 200);
        let set_cookie = parse_set_cookie(&login_resp).expect("set-cookie");
        let cookie_header = cookie_header_from_set_cookie(&set_cookie).expect("cookie header");
        let csrf_token = parse_csrf_token(&login_resp).expect("csrf token");
        let csrf_header = format!("{}: {}", CSRF_TOKEN_HEADER, csrf_token);

        let body = r#"{"current_password":"123","new_username":"root\nx"}"#;
        let update_req = format!(
            "POST /api/admin/auth HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n{}\
\r\n{}\
\r\n\r\n{}",
            body.len(),
            cookie_header,
            csrf_header,
            body
        );
        let update_resp = send_req(addr, &update_req);
        assert_eq!(parse_status(&update_resp), 400);
        assert!(update_resp.contains("Username contains invalid characters"));
    }

    #[test]
    fn admin_auth_rejects_password_too_short() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();

        let web_root = std::env::temp_dir();
        let auth = Some(Arc::new(RwLock::new(AdminAuth::new(
            "admin".to_string(),
            "123".to_string(),
            false,
        ))));
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(3600))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);

        let _thr = spawn_server(listener, 2, web_root, auth, sessions, rate, handler);

        let login_body = r#"{"username":"admin","password":"123"}"#;
        let login_req = format!(
            "POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
            login_body.len(),
            login_body
        );
        let login_resp = send_req(addr, &login_req);
        assert_eq!(parse_status(&login_resp), 200);
        let set_cookie = parse_set_cookie(&login_resp).expect("set-cookie");
        let cookie_header = cookie_header_from_set_cookie(&set_cookie).expect("cookie header");
        let csrf_token = parse_csrf_token(&login_resp).expect("csrf token");
        let csrf_header = format!("{}: {}", CSRF_TOKEN_HEADER, csrf_token);

        let body = r#"{"current_password":"123","new_password":"abcde"}"#;
        let update_req = format!(
            "POST /api/admin/auth HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n{}\
\r\n{}\
\r\n\r\n{}",
            body.len(),
            cookie_header,
            csrf_header,
            body
        );
        let update_resp = send_req(addr, &update_req);
        assert_eq!(parse_status(&update_resp), 400);
        assert!(update_resp.contains("Password too short"));
    }

    #[test]
    fn admin_auth_rejects_password_too_long() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();

        let web_root = std::env::temp_dir();
        let auth = Some(Arc::new(RwLock::new(AdminAuth::new(
            "admin".to_string(),
            "123".to_string(),
            false,
        ))));
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(3600))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);

        let _thr = spawn_server(listener, 2, web_root, auth, sessions, rate, handler);

        let login_body = r#"{"username":"admin","password":"123"}"#;
        let login_req = format!(
            "POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
            login_body.len(),
            login_body
        );
        let login_resp = send_req(addr, &login_req);
        assert_eq!(parse_status(&login_resp), 200);
        let set_cookie = parse_set_cookie(&login_resp).expect("set-cookie");
        let cookie_header = cookie_header_from_set_cookie(&set_cookie).expect("cookie header");
        let csrf_token = parse_csrf_token(&login_resp).expect("csrf token");
        let csrf_header = format!("{}: {}", CSRF_TOKEN_HEADER, csrf_token);

        let long_pw = "x".repeat(257);
        let body = format!("{{\"current_password\":\"123\",\"new_password\":\"{}\"}}", long_pw);
        let update_req = format!(
            "POST /api/admin/auth HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n{}\
\r\n{}\
\r\n\r\n{}",
            body.len(),
            cookie_header,
            csrf_header,
            body
        );
        let update_resp = send_req(addr, &update_req);
        assert_eq!(parse_status(&update_resp), 400);
        assert!(update_resp.contains("Password too long"));
    }

    #[test]
    fn password_change_lock_is_removed_after_admin_auth_update_and_relogin() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();

        let web_root = std::env::temp_dir();
        let auth = Some(Arc::new(RwLock::new(AdminAuth::new(
            "admin".to_string(),
            "123".to_string(),
            true,
        ))));
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(3600))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);

        // login + admin/auth update + config(old cookie) + login(new pw) + config(new cookie)
        let _thr = spawn_server(listener, 5, web_root, auth.clone(), sessions, rate, handler);

        let login1_body = r#"{"username":"admin","password":"123"}"#;
        let login1_req = format!(
            "POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
            login1_body.len(),
            login1_body
        );
        let login1_resp = send_req(addr, &login1_req);
        assert_eq!(parse_status(&login1_resp), 200);
        let set_cookie1 = parse_set_cookie(&login1_resp).expect("set-cookie");
        let cookie_header1 = cookie_header_from_set_cookie(&set_cookie1).expect("cookie header");
        let csrf_token1 = parse_csrf_token(&login1_resp).expect("csrf token");
        let csrf_header1 = format!("{}: {}", CSRF_TOKEN_HEADER, csrf_token1);

        let update_body = r#"{"current_password":"123","new_password":"abcdef"}"#;
        let update_req = format!(
            "POST /api/admin/auth HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n{}\
\r\n{}\
\r\n\r\n{}",
            update_body.len(),
            cookie_header1,
            csrf_header1,
            update_body
        );
        let update_resp = send_req(addr, &update_req);
        assert_eq!(parse_status(&update_resp), 200);

        // All sessions are cleared as part of the credential update.
        let cfg_old_req =
            format!("GET /api/config HTTP/1.1\r\nHost: localhost\r\n{}\r\n\r\n", cookie_header1);
        let cfg_old_resp = send_req(addr, &cfg_old_req);
        assert_eq!(parse_status(&cfg_old_resp), 401);

        let login2_body = r#"{"username":"admin","password":"abcdef"}"#;
        let login2_req = format!(
            "POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
            login2_body.len(),
            login2_body
        );
        let login2_resp = send_req(addr, &login2_req);
        assert_eq!(parse_status(&login2_resp), 200);
        let set_cookie2 = parse_set_cookie(&login2_resp).expect("set-cookie");
        let cookie_header2 = cookie_header_from_set_cookie(&set_cookie2).expect("cookie header");

        // Lock must be gone now: config should be readable.
        let cfg_new_req =
            format!("GET /api/config HTTP/1.1\r\nHost: localhost\r\n{}\r\n\r\n", cookie_header2);
        let cfg_new_resp = send_req(addr, &cfg_new_req);
        assert_eq!(parse_status(&cfg_new_resp), 200);
    }

    #[test]
    fn password_change_lock_does_not_leak_to_unauthorized_callers() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();

        let web_root = std::env::temp_dir();
        let auth = Some(Arc::new(RwLock::new(AdminAuth::new(
            "admin".to_string(),
            "123".to_string(),
            true,
        ))));
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(3600))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);

        // Single unauthorized API call.
        let _thr = spawn_server(listener, 1, web_root, auth.clone(), sessions, rate, handler);

        let cfg_req = "GET /api/config HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let cfg_resp = send_req(addr, cfg_req);
        assert_eq!(parse_status(&cfg_resp), 401);
    }

    #[test]
    fn login_rate_limit_is_cleared_on_successful_login() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();

        let web_root = std::env::temp_dir();
        let auth = Some(Arc::new(RwLock::new(AdminAuth::new(
            "admin".to_string(),
            "123".to_string(),
            false,
        ))));
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(3600))));
        // Use a small threshold to make the test short and deterministic.
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(2, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);

        // 1st fail, 1 success, then 3 fails (last one should be 429).
        let _thr = spawn_server(listener, 5, web_root, auth, sessions, rate, handler);

        let mk = |body: &str| {
            format!(
                "POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
                body.len(),
                body
            )
        };

        let fail = mk(r#"{"username":"admin","password":"wrong"}"#);
        let ok = mk(r#"{"username":"admin","password":"123"}"#);

        let r1 = send_req(addr, &fail);
        assert_eq!(parse_status(&r1), 401);

        // Success should clear rate limiter for this IP.
        let r2 = send_req(addr, &ok);
        assert_eq!(parse_status(&r2), 200);

        // After clearing, we should get two more 401s before a 429.
        let r3 = send_req(addr, &fail);
        assert_eq!(parse_status(&r3), 401);
        let r4 = send_req(addr, &fail);
        assert_eq!(parse_status(&r4), 401);
        let r5 = send_req(addr, &fail);
        assert_eq!(parse_status(&r5), 429);
    }

    #[test]
    fn login_response_includes_requires_password_change_flag() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();

        let web_root = std::env::temp_dir();
        let auth = Some(Arc::new(RwLock::new(AdminAuth::new(
            "admin".to_string(),
            "123".to_string(),
            true,
        ))));
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(3600))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);

        let thr = spawn_server(listener, 1, web_root, auth, sessions, rate, handler);

        let body = r#"{"username":"admin","password":"123"}"#;
        let req = format!(
            "POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 200);
        assert!(parse_csrf_token(&resp).is_some());
        assert!(resp.contains("\"requires_password_change\":true"));

        thr.join().expect("server thread");
    }

    #[test]
    fn login_and_admin_auth_rate_limits_are_separate_namespaces() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();

        let web_root = std::env::temp_dir();
        let auth = Some(Arc::new(RwLock::new(AdminAuth::new(
            "admin".to_string(),
            "123".to_string(),
            false,
        ))));
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(3600))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(2, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);

        // login(ok) + login(fail) + login(fail) + login(429) + admin-auth(fail) + admin-auth(fail) + admin-auth(429)
        let thr = spawn_server(listener, 7, web_root, auth, sessions, rate, handler);

        let mk_login = |pw: &str| {
            let body = format!(r#"{{"username":"admin","password":"{}"}}"#, pw);
            format!(
                "POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
                body.len(),
                body
            )
        };

        let ok = send_req(addr, &mk_login("123"));
        assert_eq!(parse_status(&ok), 200);
        let set_cookie = parse_set_cookie(&ok).expect("set-cookie");
        let cookie_header = cookie_header_from_set_cookie(&set_cookie).expect("cookie header");
        let csrf_token = parse_csrf_token(&ok).expect("csrf token");
        let csrf_header = format!("{}: {}", CSRF_TOKEN_HEADER, csrf_token);

        let fail = send_req(addr, &mk_login("wrong"));
        assert_eq!(parse_status(&fail), 401);
        let fail2 = send_req(addr, &mk_login("wrong"));
        assert_eq!(parse_status(&fail2), 401);

        // Third failure should be rate limited (429).
        let limited = send_req(addr, &mk_login("wrong"));
        assert_eq!(parse_status(&limited), 429);

        let mk_admin_auth = |current_pw: &str| {
            let body = format!(r#"{{"current_password":"{}","new_username":"root"}}"#, current_pw);
            format!(
                "POST /api/admin/auth HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nContent-Type: application/json\r\n{}\
\r\n{}\
\r\n\r\n{}",
                body.len(),
                cookie_header,
                csrf_header,
                body
            )
        };

        // Admin auth uses a separate key namespace and should not be 429 yet.
        let a1 = send_req(addr, &mk_admin_auth("wrong"));
        assert_eq!(parse_status(&a1), 401);
        let a2 = send_req(addr, &mk_admin_auth("wrong"));
        assert_eq!(parse_status(&a2), 401);
        let a3 = send_req(addr, &mk_admin_auth("wrong"));
        assert_eq!(parse_status(&a3), 429);

        thr.join().expect("server thread");
    }

    #[test]
    fn static_assets_rejects_path_traversal_with_403() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let web_root = {
            let root = std::env::temp_dir()
                .join(format!("qf-admin-webroot-traversal-{}", current_epoch_secs()));
            let _ = std::fs::create_dir_all(&root);
            let index = root.join("index.html");
            let _ = std::fs::write(&index, "<html>ok</html>");
            root
        };

        let auth = None;
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(60))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);
        let _thr = spawn_server(listener, 1, web_root, auth, sessions, rate, handler);

        // Attempt to escape web_root via parent directory traversal.
        let req = "GET /../Cargo.toml HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let resp = send_req(addr, req);
        assert_eq!(parse_status(&resp), 403);
    }

    #[test]
    fn static_assets_serves_index_for_spa_routes() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let web_root = {
            let root =
                std::env::temp_dir().join(format!("qf-admin-webroot-spa-{}", current_epoch_secs()));
            let _ = std::fs::create_dir_all(&root);
            let index = root.join("index.html");
            let _ = std::fs::write(&index, "<html>index</html>");
            root
        };

        let auth = None;
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(60))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);
        let _thr = spawn_server(listener, 1, web_root, auth, sessions, rate, handler);

        // Non-file route should fall back to index.html (SPA refresh support).
        let req = "GET /logs HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let resp = send_req(addr, req);
        assert_eq!(parse_status(&resp), 200);
        assert!(resp.contains("<html>index</html>"));
    }

    #[test]
    fn oversized_payload_returns_413() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let web_root = std::env::temp_dir();
        let auth = None;
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(60))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);
        let _thr = spawn_server(listener, 1, web_root, auth, sessions, rate, handler);

        let req = format!(
            "POST /api/qkey HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        );
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 413);
    }

    #[test]
    fn oversized_headers_return_431() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let web_root = std::env::temp_dir();
        let auth = None;
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(60))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);
        let _thr = spawn_server(listener, 1, web_root, auth, sessions, rate, handler);

        let large_header_value = "a".repeat(MAX_HEADER_BYTES + 128);
        let req =
            format!("GET / HTTP/1.1\r\nHost: localhost\r\nX-Fill: {}\r\n\r\n", large_header_value);
        let resp = send_req(addr, &req);
        assert_eq!(parse_status(&resp), 431);
    }

    #[test]
    fn invalid_content_length_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let web_root = std::env::temp_dir();
        let auth = None;
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(60))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);
        let _thr = spawn_server(listener, 1, web_root, auth, sessions, rate, handler);

        let req = "POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Length: nope\r\n\r\n{}";
        let resp = send_req(addr, req);
        assert_eq!(parse_status(&resp), 400);
    }

    #[test]
    fn duplicate_content_length_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let web_root = std::env::temp_dir();
        let auth = None;
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(60))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);
        let _thr = spawn_server(listener, 1, web_root, auth, sessions, rate, handler);

        let req = "POST /api/login HTTP/1.1\r\n\
Host: localhost\r\n\
Content-Length: 1\r\n\
Content-Length: 1\r\n\r\n{}";
        let resp = send_req(addr, req);
        assert_eq!(parse_status(&resp), 400);
    }

    #[test]
    fn request_body_shorter_than_content_length_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let web_root = std::env::temp_dir();
        let auth = None;
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(60))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);
        let _thr = spawn_server(listener, 1, web_root, auth, sessions, rate, handler);

        let req = "POST /api/login HTTP/1.1\r\n\
Host: localhost\r\n\
Content-Length: 20\r\n\
Content-Type: application/json\r\n\r\n\
{\"username\":\"ad";
        let resp = send_req(addr, req);
        assert_eq!(parse_status(&resp), 400);
    }

    #[test]
    fn invalid_http_version_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let web_root = std::env::temp_dir();
        let auth = None;
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(60))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);
        let _thr = spawn_server(listener, 1, web_root, auth, sessions, rate, handler);

        let req = "GET / HTTP/2.0\r\nHost: localhost\r\n\r\n";
        let resp = send_req(addr, req);
        assert_eq!(parse_status(&resp), 400);
    }

    #[test]
    fn invalid_http_version_schema_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let web_root = std::env::temp_dir();
        let auth = None;
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(60))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);
        let _thr = spawn_server(listener, 1, web_root, auth, sessions, rate, handler);

        let req = "GET / FTP/1.0\r\nHost: localhost\r\n\r\n";
        let resp = send_req(addr, req);
        assert_eq!(parse_status(&resp), 400);
    }

    #[test]
    fn invalid_request_line_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let web_root = std::env::temp_dir();
        let auth = None;
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(60))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);
        let _thr = spawn_server(listener, 1, web_root, auth, sessions, rate, handler);

        let req = "BADLINE\r\nHost: localhost\r\n\r\n";
        let resp = send_req(addr, req);
        assert_eq!(parse_status(&resp), 400);
    }

    #[test]
    fn invalid_method_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let web_root = std::env::temp_dir();
        let auth = None;
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(60))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);
        let _thr = spawn_server(listener, 1, web_root, auth, sessions, rate, handler);

        let req = "GE T / HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let resp = send_req(addr, req);
        assert_eq!(parse_status(&resp), 400);
    }

    #[test]
    fn invalid_path_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let web_root = std::env::temp_dir();
        let auth = None;
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(60))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);
        let _thr = spawn_server(listener, 1, web_root, auth, sessions, rate, handler);

        let req = "GET api/status HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let resp = send_req(addr, req);
        assert_eq!(parse_status(&resp), 400);
    }

    #[test]
    fn invalid_backslash_in_path_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");

        let web_root = std::env::temp_dir();
        let auth = None;
        let sessions = Arc::new(Mutex::new(SessionStore::new(Duration::from_secs(60))));
        let rate = Arc::new(Mutex::new(LoginRateLimiter::new(5, 60)));
        let handler: Arc<dyn AdminHttpHandler> = Arc::new(TestHandler);
        let _thr = spawn_server(listener, 1, web_root, auth, sessions, rate, handler);

        let req = "GET /api\\status HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let resp = send_req(addr, req);
        assert_eq!(parse_status(&resp), 400);
    }

    #[test]
    fn login_rate_limit_prunes_old_attempts_without_sleep() {
        let mut limiter = LoginRateLimiter::new(5, 60);
        let ip = "127.0.0.1";
        for _ in 0..5 {
            limiter.record_failure(ip);
        }
        assert!(limiter.is_locked(ip));

        // Force the timestamp into the past beyond lockout. This avoids sleeping and
        // makes prune behavior deterministic.
        if let Some((_count, ts)) = limiter.attempts.get_mut(ip) {
            *ts = Instant::now() - Duration::from_secs(61);
        } else {
            panic!("missing attempts entry");
        }
        assert!(!limiter.is_locked(ip));
    }

    #[test]
    fn normalize_ttl_maps_zero_and_none_to_none() {
        assert_eq!(normalize_ttl(None), None);
        assert_eq!(normalize_ttl(Some(0)), None);
        assert_eq!(normalize_ttl(Some(1)), Some(1));
        assert_eq!(normalize_ttl(Some(MAX_QKEY_TTL_SECS)), Some(MAX_QKEY_TTL_SECS));
    }

    #[test]
    fn normalize_qkey_id_trims_and_lowercases() {
        assert_eq!(normalize_qkey_id("  A1B2C3D4E5F6  "), Some("a1b2c3d4e5f6".to_string()));
        assert_eq!(normalize_qkey_id("short"), None);
        assert_eq!(normalize_qkey_id("a1b2c3d4e5f6aa"), None);
        assert_eq!(normalize_qkey_id("a1b2c3d4e5g6"), None);
    }
}

fn handle_api(
    stream: &mut TcpStream,
    req: HttpRequest,
    handler: Arc<dyn AdminHttpHandler>,
    peer: Option<SocketAddr>,
) -> std::io::Result<()> {
    if req.method == "POST" {
        if let Some(id) =
            req.path.strip_prefix("/api/clients/").and_then(|rest| rest.strip_suffix("/kick"))
        {
            let raw = id.trim();
            if raw.is_empty() {
                return respond_json(stream, 400, &AdminResponse::error("Missing client id"));
            }
            let Some(id) = normalize_socket_addr(raw) else {
                return respond_json(stream, 400, &AdminResponse::error("Invalid client id"));
            };
            let resp = handler.handle_kick(&id);
            log_action(peer, "kick", &format!("id={}", id), resp.success);
            return respond_admin_json(stream, &resp);
        }
    }
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/api/status") => respond_admin_json(stream, &handler.handle_status()),
        ("GET", "/api/clients") => {
            let clients = handler.handle_list_clients();
            respond_json(
                stream,
                200,
                &AdminResponse::ok_with_data(
                    serde_json::to_value(clients).unwrap_or_else(|_| serde_json::json!([])),
                ),
            )
        }
        ("GET", "/api/blocked") => respond_admin_json(stream, &handler.handle_list_blocked_ips()),
        ("GET", "/api/config") => respond_admin_json(stream, &handler.handle_read_config()),
        ("GET", "/api/metrics") => respond_text(stream, 200, &handler.handle_metrics_text()),
        ("GET", "/api/metrics/json") => respond_admin_json(stream, &handler.handle_metrics_json()),
        ("GET", "/api/qkeys") => respond_admin_json(stream, &handler.handle_list_qkeys()),
        ("POST", "/api/kick") => {
            let payload: IdPayload = match serde_json::from_slice(&req.body) {
                Ok(p) => p,
                Err(_) => return respond_json(stream, 400, &AdminResponse::error("Invalid JSON")),
            };
            let raw = payload.id.trim();
            if raw.is_empty() {
                return respond_json(stream, 400, &AdminResponse::error("Missing client id"));
            }
            let Some(id) = normalize_socket_addr(raw) else {
                return respond_json(stream, 400, &AdminResponse::error("Invalid client id"));
            };
            let resp = handler.handle_kick(&id);
            log_action(peer, "kick", &format!("id={}", id), resp.success);
            respond_admin_json(stream, &resp)
        }
        ("POST", "/api/block") => {
            let payload: IpPayload = match serde_json::from_slice(&req.body) {
                Ok(p) => p,
                Err(_) => return respond_json(stream, 400, &AdminResponse::error("Invalid JSON")),
            };
            let Some(ip) = normalize_ip_for_policy(&payload.ip) else {
                return respond_json(stream, 400, &AdminResponse::error("Invalid IP"));
            };
            let resp = handler.handle_block(&ip);
            log_action(peer, "block", &format!("ip={}", ip), resp.success);
            respond_admin_json(stream, &resp)
        }
        ("POST", "/api/unblock") => {
            let payload: IpPayload = match serde_json::from_slice(&req.body) {
                Ok(p) => p,
                Err(_) => return respond_json(stream, 400, &AdminResponse::error("Invalid JSON")),
            };
            let Some(ip) = normalize_ip_for_policy(&payload.ip) else {
                return respond_json(stream, 400, &AdminResponse::error("Invalid IP"));
            };
            let resp = handler.handle_unblock(&ip);
            log_action(peer, "unblock", &format!("ip={}", ip), resp.success);
            respond_admin_json(stream, &resp)
        }
        ("POST", "/api/reload") => {
            let resp = handler.handle_reload();
            log_action(peer, "reload", "-", resp.success);
            respond_admin_json(stream, &resp)
        }
        ("POST", "/api/qkey") => {
            let payload: QKeyCreatePayload = if req.body.is_empty() {
                QKeyCreatePayload {
                    name: None,
                    port: None,
                    ttl_seconds: None,
                    stealth: None,
                    fec: None,
                    sni_strategy: None,
                    sni_domain: None,
                }
            } else {
                match serde_json::from_slice(&req.body) {
                    Ok(p) => p,
                    Err(_) => {
                        return respond_json(stream, 400, &AdminResponse::error("Invalid JSON"))
                    }
                }
            };
            if let Some(ttl) = payload.ttl_seconds {
                // Avoid absurd TTLs and keep behavior deterministic across frontends.
                if ttl > MAX_QKEY_TTL_SECS {
                    return respond_json(
                        stream,
                        400,
                        &AdminResponse::error(format!(
                            "TTL too large (max {} seconds)",
                            MAX_QKEY_TTL_SECS
                        )),
                    );
                }
            }
            if let Some(port) = payload.port {
                if port == 0 {
                    return respond_json(
                        stream,
                        400,
                        &AdminResponse::error("Port must be between 1 and 65535"),
                    );
                }
            }
            let req = IssueQKeyRequest {
                name: payload.name,
                port: payload.port,
                ttl_seconds: normalize_ttl(payload.ttl_seconds),
                stealth: payload.stealth,
                fec: payload.fec,
                sni_strategy: payload.sni_strategy,
                sni_domain: payload.sni_domain,
            };
            let resp = handler.handle_qkey(req);
            log_action(peer, "qkey", "-", resp.success);
            respond_admin_json(stream, &resp)
        }
        ("POST", "/api/qkeys/revoke") => {
            let payload: QKeyRevokePayload = match serde_json::from_slice(&req.body) {
                Ok(p) => p,
                Err(_) => return respond_json(stream, 400, &AdminResponse::error("Invalid JSON")),
            };
            if payload.id.trim().is_empty() {
                return respond_json(stream, 400, &AdminResponse::error("Missing QKey id"));
            }
            let Some(id) = normalize_qkey_id(&payload.id) else {
                return respond_json(stream, 400, &AdminResponse::error("Invalid QKey id"));
            };
            let resp = handler.handle_revoke_qkey(&id);
            log_action(peer, "qkey-revoke", &format!("id={}", id), resp.success);
            respond_admin_json(stream, &resp)
        }
        ("POST", "/api/shutdown") => {
            if !admin_shutdown_enabled() {
                return respond_text(stream, 404, "Not Found");
            }
            let resp = handler.handle_shutdown();
            log_action(peer, "shutdown", "-", resp.success);
            respond_admin_json(stream, &resp)
        }
        ("POST", "/api/config") => {
            let payload: ConfigPayload = match serde_json::from_slice(&req.body) {
                Ok(p) => p,
                Err(_) => return respond_json(stream, 400, &AdminResponse::error("Invalid JSON")),
            };
            if payload.config.trim().is_empty() {
                return respond_json(stream, 400, &AdminResponse::error("Empty config"));
            }
            let resp = handler.handle_write_config(&payload.config);
            log_action(peer, "config", &format!("bytes={}", payload.config.len()), resp.success);
            respond_admin_json(stream, &resp)
        }
        ("GET", "/api/config/logging") => {
            respond_admin_json(stream, &handler.handle_get_logging_config())
        }
        ("POST", "/api/config/logging") => {
            let payload: LoggingModePayload = match serde_json::from_slice(&req.body) {
                Ok(p) => p,
                Err(_) => return respond_json(stream, 400, &AdminResponse::error("Invalid JSON")),
            };
            let resp = handler.handle_set_logging_config(&payload.mode);
            log_action(peer, "logging", &format!("mode={}", payload.mode), resp.success);
            respond_admin_json(stream, &resp)
        }
        ("GET", "/api/logs") | ("GET", "/api/logs?") => {
            respond_admin_json(stream, &handler.handle_get_logs(0))
        }
        ("GET", path) if path.starts_with("/api/logs?") => {
            let cursor = path
                .split('?')
                .nth(1)
                .and_then(|qs| {
                    qs.split('&')
                        .find(|p| p.starts_with("cursor="))
                        .and_then(|p| p.strip_prefix("cursor="))
                        .and_then(|v| v.parse::<u64>().ok())
                })
                .unwrap_or(0);
            respond_admin_json(stream, &handler.handle_get_logs(cursor))
        }
        ("POST", "/api/logs/clear") => {
            let resp = handler.handle_clear_logs();
            // Keep clear behavior strict: successful clear must leave live buffer empty.
            // Only log failures for diagnostics.
            if !resp.success {
                log_action(peer, "logs-clear", "-", false);
            }
            respond_admin_json(stream, &resp)
        }
        _ => respond_text(stream, 404, "Not Found"),
    }
}

fn respond_json<T: Serialize>(
    stream: &mut TcpStream,
    status: u16,
    body: &T,
) -> std::io::Result<()> {
    let payload = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    respond_bytes(stream, status, "application/json", &payload)
}

fn respond_admin_json(stream: &mut TcpStream, body: &AdminResponse) -> std::io::Result<()> {
    respond_json(stream, admin_response_status(body), body)
}

fn respond_json_with_headers<T: Serialize>(
    stream: &mut TcpStream,
    status: u16,
    body: &T,
    headers: Vec<(String, String)>,
) -> std::io::Result<()> {
    let payload = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    respond_bytes_with_headers(stream, status, "application/json", &payload, &headers)
}

fn respond_text(stream: &mut TcpStream, status: u16, body: &str) -> std::io::Result<()> {
    respond_bytes(stream, status, "text/plain; charset=utf-8", body.as_bytes())
}

fn respond_file_with_headers(
    stream: &mut TcpStream,
    path: &Path,
    headers: &[(String, String)],
) -> std::io::Result<()> {
    let mime = match path.extension().and_then(|s| s.to_str()).unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript",
        "wasm" => "application/wasm",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        _ => "application/octet-stream",
    };
    let data = std::fs::read(path)?;
    respond_bytes_with_headers(stream, 200, mime, &data, headers)
}

fn respond_bytes(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    respond_bytes_with_headers(stream, status, content_type, body, &[])
}

fn respond_bytes_with_headers(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
    headers: &[(String, String)],
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        423 => "Locked",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        _ => "Unknown",
    };
    let status_line = format!("{} {}", status, reason);
    let mut header = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        status_line,
        content_type,
        body.len()
    );
    header.push_str("X-Content-Type-Options: nosniff\r\n");
    header.push_str("X-Frame-Options: DENY\r\n");
    header.push_str("Referrer-Policy: no-referrer\r\n");
    header.push_str(
        "Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()\r\n",
    );
    header.push_str("Cross-Origin-Opener-Policy: same-origin\r\n");
    header.push_str("Cross-Origin-Resource-Policy: same-origin\r\n");
    if content_type.starts_with("text/html") {
        header.push_str("Content-Security-Policy: ");
        header.push_str(ADMIN_CSP);
        header.push_str("\r\n");
    }
    for (key, value) in headers {
        header.push_str(key);
        header.push_str(": ");
        header.push_str(value);
        header.push_str("\r\n");
    }
    header.push_str("\r\n");
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    Ok(())
}

fn read_request(stream: &mut TcpStream) -> std::io::Result<HttpRequest> {
    let mut buf = Vec::with_capacity(8192);
    let mut temp = [0u8; 1024];
    let mut header_end = None;
    while header_end.is_none() && buf.len() < MAX_HEADER_BYTES {
        let n = stream.read(&mut temp)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&temp[..n]);
        header_end = find_header_end(&buf);
    }
    let header_end = match header_end {
        Some(pos) => pos,
        None => {
            let msg = if buf.len() >= MAX_HEADER_BYTES {
                "Headers too large"
            } else {
                "Invalid HTTP request"
            };
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, msg));
        }
    };
    let (head, rest) = buf.split_at(header_end);
    let head_str = std::str::from_utf8(head)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid headers"))?;
    let mut lines = head_str.split("\r\n");
    let request_line = lines.next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "Missing request line")
    })?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().filter(|s| !s.is_empty()).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "Missing request method")
    })?;
    if !is_valid_http_token(method) {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid method"));
    }
    let path = parts.next().filter(|s| !s.is_empty()).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "Missing request path")
    })?;
    let version = parts.next().filter(|s| !s.is_empty()).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "Missing HTTP version")
    })?;
    if parts.next().is_some() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid HTTP request"));
    }
    if !version.starts_with("HTTP/") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid HTTP version schema",
        ));
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Unsupported HTTP version",
        ));
    }
    let method = method.to_string();
    let path = path.to_string();
    if !is_valid_request_path(&path) {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid request path"));
    }
    let mut headers = Vec::new();
    let mut content_len = 0usize;
    let mut saw_content_len = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid header"));
        }
        let (k, v) = line.split_once(':').ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid header")
        })?;
        let key = k.trim().to_string();
        let val = v.trim().to_string();
        if !is_valid_header_name(&key) {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid header"));
        }
        if key.eq_ignore_ascii_case("content-length") {
            if saw_content_len {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Invalid Content-Length",
                ));
            }
            saw_content_len = true;
            let parsed = val.parse::<usize>().map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid Content-Length")
            })?;
            content_len = parsed;
        }
        headers.push((key, val));
    }
    let mut body = rest.to_vec();
    if content_len > MAX_BODY_BYTES {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Payload too large"));
    }
    if body.len() < content_len {
        let to_read = content_len - body.len();
        let mut extra = vec![0u8; to_read];
        stream.read_exact(&mut extra).map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                return std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Incomplete request body",
                );
            }
            e
        })?;
        body.extend_from_slice(&extra);
    } else if body.len() > content_len {
        body.truncate(content_len);
    }
    Ok(HttpRequest { method, path, headers, body })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|pos| pos + 4)
}

fn is_valid_header_name(name: &str) -> bool {
    is_valid_http_token(name)
}

fn is_valid_http_token(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    for ch in value.bytes() {
        let is_alpha_num = ch.is_ascii_alphanumeric();
        let is_tchar_special = matches!(
            ch,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        );
        if !(is_alpha_num || is_tchar_special) {
            return false;
        }
    }
    true
}

fn is_valid_request_path(path: &str) -> bool {
    if !path.starts_with('/') {
        return false;
    }
    if path.contains('\u{0000}') {
        return false;
    }
    if path.contains("\\") {
        return false;
    }
    if path.chars().any(|c| c.is_control()) {
        return false;
    }
    true
}

fn get_cookie(req: &HttpRequest, name: &str) -> Option<String> {
    for (k, v) in &req.headers {
        if k.eq_ignore_ascii_case("cookie") {
            for part in v.split(';') {
                let trimmed = part.trim();
                if let Some(value) = trimmed.strip_prefix(name).and_then(|v| v.strip_prefix('=')) {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

fn build_session_cookie(session_id: &str, req: &HttpRequest) -> String {
    let mut cookie = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
        SESSION_COOKIE, session_id, SESSION_TTL_SECS
    );
    if is_secure_request(req) {
        cookie.push_str("; Secure");
    }
    cookie
}

fn build_expired_cookie(req: &HttpRequest) -> String {
    let mut cookie = format!(
        "{}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
        SESSION_COOKIE
    );
    if is_secure_request(req) {
        cookie.push_str("; Secure");
    }
    cookie
}

fn is_secure_request(req: &HttpRequest) -> bool {
    if !trust_proxy_enabled() {
        return false;
    }
    req.headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("x-forwarded-proto") && v.eq_ignore_ascii_case("https")
    })
}

fn admin_shutdown_enabled() -> bool {
    std::env::var("QUICFUSCATE_ENABLE_ADMIN_SHUTDOWN")
        .map(|v| v.trim() == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn admin_response_status(resp: &AdminResponse) -> u16 {
    if resp.success {
        return 200;
    }
    let msg = resp.message.as_deref().unwrap_or("").to_ascii_lowercase();
    if msg.contains("not found") {
        404
    } else if msg.contains("invalid") || msg.contains("missing") {
        400
    } else if msg.contains("conflict") || msg.contains("already") || msg.contains("exists") {
        409
    } else {
        400
    }
}

fn normalize_csrf_token(raw: &str) -> Option<String> {
    let token = raw.trim();
    if token.len() != CSRF_TOKEN_BYTES * 2 {
        return None;
    }
    if !token.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(token.to_ascii_lowercase())
}

fn constant_time_token_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let mut diff: u8 = 0;
    let mut i = 0usize;
    let len = left.len().max(right.len());
    while i < len {
        let a = left.get(i).copied().unwrap_or(0);
        let b = right.get(i).copied().unwrap_or(0);
        diff |= a ^ b;
        i += 1;
    }
    if left.len() != right.len() {
        diff |= 1;
    }
    diff == 0
}

fn request_replay_fingerprint(req: &HttpRequest, csrf_token: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    req.method.hash(&mut hasher);
    req.path.hash(&mut hasher);
    req.body.hash(&mut hasher);
    csrf_token.hash(&mut hasher);
    if let Some(nonce) = header_value(req, CSRF_NONCE_HEADER) {
        nonce.hash(&mut hasher);
    }
    hasher.finish()
}

fn validate_csrf_request(
    req: &HttpRequest,
    sessions: &Arc<Mutex<SessionStore>>,
) -> Option<&'static str> {
    if req.method != "POST" {
        return None;
    }
    if !is_same_origin_request(req) {
        crate::telemetry::ADMIN_ORIGIN_REJECT_TOTAL.inc();
        crate::telemetry::ADMIN_CSRF_REJECT_TOTAL.inc();
        return Some("Invalid Origin");
    }

    let Some(session_id) = get_cookie(req, SESSION_COOKIE) else {
        crate::telemetry::ADMIN_CSRF_REJECT_TOTAL.inc();
        return Some("Missing session");
    };

    let raw_token = match header_value(req, CSRF_TOKEN_HEADER) {
        Some(v) => v,
        None => {
            crate::telemetry::ADMIN_CSRF_REJECT_TOTAL.inc();
            return Some("Missing CSRF token");
        }
    };

    let Some(token) = normalize_csrf_token(raw_token) else {
        crate::telemetry::ADMIN_CSRF_REJECT_TOTAL.inc();
        return Some("Invalid CSRF token");
    };

    let has_origin_header = header_value(req, "origin").is_some();
    let replay_fingerprint = request_replay_fingerprint(req, &token);
    let mut store = sessions.lock().unwrap_or_else(|e| e.into_inner());
    match store.validate_post_guard(&session_id, &token, replay_fingerprint, has_origin_header) {
        Ok(()) => None,
        Err(msg) => {
            crate::telemetry::ADMIN_CSRF_REJECT_TOTAL.inc();
            Some(msg)
        }
    }
}

fn is_same_origin_request(req: &HttpRequest) -> bool {
    let Some(origin_raw) = header_value(req, "origin") else {
        // Non-browser clients often do not set Origin.
        return true;
    };
    let origin = origin_raw.trim();
    if origin.eq_ignore_ascii_case("null") {
        return false;
    }
    let Some((_, rest)) = origin.split_once("://") else {
        return false;
    };
    let origin_host = rest.split('/').next().unwrap_or("").trim();
    if origin_host.is_empty() {
        return false;
    }
    let host = match header_value(req, "host") {
        Some(v) => v.trim(),
        None => return false,
    };
    origin_host.eq_ignore_ascii_case(host)
}

fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    match argon2.hash_password(password.as_bytes(), &salt) {
        Ok(hash) => hash.to_string(),
        Err(e) => {
            log::warn!("admin password hash failed: {}", e);
            String::new()
        }
    }
}

fn verify_password(password_phc: &str, password: &str) -> bool {
    if password.len() > MAX_PASSWORD_BYTES {
        return false;
    }
    let Ok(parsed) = PasswordHash::new(password_phc) else {
        return false;
    };
    Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
}
